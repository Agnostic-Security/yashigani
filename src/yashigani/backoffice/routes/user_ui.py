"""
Yashigani Backoffice — Phase 2 user-plane routes (OWUI replacement).

Serves the 4.0 user SPA and data endpoints consumed by the shared ApiClient
(shared-layer-spec §2).  ALL routes in this file enforce `require_user_session`
(RISK-100) — admin-plane never touches these paths.

Routes
------
  GET  /chat                — user SPA entry point (returns ui4/chat.html)
  GET  /workflows           — no-code workflow composer (returns ui4/workflows.html)
  GET  /user/agents         — list available agents (user-visible fields only)
  GET  /user/budget         — caller's own budget usage
  GET  /user/memory         — per-user memory entries (Phase-3 Letta stub)
  POST /user/documents      — file upload → doc-OPA verdict (RISK-112)

SoD contract (RISK-100):
  - Every /user/* and /chat endpoint depends on ``require_user_session``.
  - ``require_user_session`` reads ONLY __Host-yashigani_session; rejects
    admin sessions with 403 wrong_plane.
  - The admin-plane session type is NEVER used on this plane.

Upload hardening (RISK-112):
  - Filename path-traversal guard (reject .. / \\ / null bytes; basename only).
  - Size cap: YASHIGANI_USER_UPLOAD_MAX_MB (default 10 MB).
  - Content-type declaration must be in the allowed set; unknown content-type
    claims are rejected pre-pipeline (defence-in-depth; the pipeline also sniffs
    magic bytes and fail-closes on mismatch).
  - Routed into the EXISTING DocumentInspectionPipeline sandbox — no duplicate
    extraction logic.

Last updated: 2026-06-27T00:00:00+00:00
"""
from __future__ import annotations

import base64
import binascii
import logging
import math
import os
import pathlib
import posixpath
from typing import Optional

import httpx

from fastapi import APIRouter, HTTPException, Request, UploadFile, status
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from pydantic import BaseModel

from yashigani.backoffice.middleware import (
    UserSession,
    _USER_SESSION_COOKIE,
)
from yashigani.backoffice.state import backoffice_state
from yashigani.common.error_envelope import safe_error_envelope

logger = logging.getLogger(__name__)

router = APIRouter()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Allowed content-type declarations for user uploads (defence-in-depth pre-check;
# the pipeline also sniffs magic bytes and fail-closes on mismatch — F8).
_ALLOWED_DECLARED_MIMES: frozenset[str] = frozenset({
    "text/plain",
    "text/csv",
    "application/csv",
    "application/pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/octet-stream",  # generic binary — pipeline sniff is authoritative
})

# File-extension → declared MIME normalization table.
# Only used when the client provides no Content-Type (browser file upload).
_EXT_TO_MIME: dict[str, str] = {
    ".txt":  "text/plain",
    ".csv":  "text/csv",
    ".pdf":  "application/pdf",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}

_DEFAULT_MAX_UPLOAD_MB: int = 10
_BYTES_PER_MB: int = 1024 * 1024


# ---------------------------------------------------------------------------
# JSON upload body (shared-layer-spec §2; ApiClient.mutate sends JSON base64)
# ---------------------------------------------------------------------------

class DocumentUploadBody(BaseModel):
    """
    JSON body for POST /user/documents (RISK-112).

    The 4.0 user UI sends the file as base64-encoded JSON (never as multipart)
    so that the audited ApiClient.mutate (same-origin credentials, X-Yashigani-Plane
    header) is used throughout — not a raw <form> or fetch(multipart).

    Fields
    ------
    filename      : original filename from the browser File object (may include
                    spaces / Unicode — the server guards it via _guard_filename).
    content_type  : MIME declared by the browser (File.type || 'application/octet-stream').
    content_base64: standard base64 of the file bytes (from FileReader.readAsDataURL,
                    data-URL prefix stripped by the UI before sending).
    route         : doc-OPA route key (see DocumentInspectionPipeline).
    pseudonymize_mode: 'A' (default) or 'B'.
    """

    filename: str
    content_type: str
    content_base64: str
    route: str = "ingress-upload"
    pseudonymize_mode: str = "A"


def _user_upload_max_bytes() -> int:
    """Read YASHIGANI_USER_UPLOAD_MAX_MB (default 10). Clamped 1–100 MB."""
    try:
        val = int(os.environ.get("YASHIGANI_USER_UPLOAD_MAX_MB", str(_DEFAULT_MAX_UPLOAD_MB)))
    except (ValueError, TypeError):
        val = _DEFAULT_MAX_UPLOAD_MB
    return max(1, min(val, 100)) * _BYTES_PER_MB


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _guard_filename(name: str) -> str:
    """
    Filename path-traversal guard (RISK-112 / CWE-22).

    Rejects filenames that:
      - Contain null bytes (null-byte injection).
      - Contain path separators (/ or \\) — multi-component paths.
      - Consist solely of dots (.. traversal).
      - Are empty after normalisation.

    Returns the BASENAME only (strips any directory component a client may
    sneak in despite the above checks).

    Raises HTTPException 422 on any violation.
    """
    if not name:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_filename", "message": "Filename must not be empty."},
        )

    # Null-byte injection guard
    if "\x00" in name:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_filename", "message": "Filename contains null bytes."},
        )

    # Path-separator check BEFORE basename extraction (belt-and-braces)
    if "/" in name or "\\" in name:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "invalid_filename",
                "message": "Filename must not contain path separators.",
            },
        )

    # Strip to basename (posixpath is safe on all platforms)
    safe = posixpath.basename(name)

    # Reject pure-dot names (., .., ...)
    if not safe or safe.lstrip(".") == "":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "invalid_filename",
                "message": "Filename must not be a dot-only path component.",
            },
        )

    # Limit total filename length (defence-in-depth; ext4/APFS cap is 255)
    if len(safe) > 255:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_filename", "message": "Filename exceeds 255 characters."},
        )

    return safe


def _check_allowed_mime(declared: str, safe_filename: str) -> str:
    """
    Core MIME allowlist check (pure-string, RISK-112).

    Normalises the declared MIME (strip charset params, lowercase), falls back
    to extension-derived MIME when the client sent nothing useful, then rejects
    any MIME not in _ALLOWED_DECLARED_MIMES.

    Separated from _resolve_declared_mime so the JSON body handler can call it
    directly with a plain string. _resolve_declared_mime remains as a thin
    wrapper for backward-compatibility with existing callers / contract tests.
    """
    declared = declared.split(";")[0].strip().lower() if declared else ""
    if not declared or declared == "application/octet-stream":
        # Derive from extension if the client sent no useful Content-Type
        ext = pathlib.Path(safe_filename).suffix.lower()
        declared = _EXT_TO_MIME.get(ext, "application/octet-stream")

    if declared not in _ALLOWED_DECLARED_MIMES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "unsupported_content_type",
                "message": (
                    f"Declared content-type '{declared}' is not supported. "
                    "Supported types: txt, csv, pdf, docx, xlsx, pptx."
                ),
            },
        )

    return declared


def _resolve_declared_mime(upload: UploadFile, safe_filename: str) -> str:
    """
    Resolve the declared MIME from the upload's Content-Type header,
    falling back to extension-derived MIME, falling back to
    'application/octet-stream' (authoritative decision is the pipeline sniff).

    Rejects unknown (non-allowlisted) declared MIME claims immediately so the
    pipeline never sees content that is obviously wrong-typed.

    NOTE: This wrapper exists for backward-compatibility with the contract tests
    (CT-112-6) which call it directly with an UploadFile mock.  New code that
    has a plain string should call _check_allowed_mime() instead.
    """
    declared = (upload.content_type or "")
    return _check_allowed_mime(declared, safe_filename)


def _build_pipeline(audit_context: Optional[dict] = None):
    """Construct a DocumentInspectionPipeline using the existing config.

    RESTART-013 gap #5: wires the REAL tamper-evident audit chain
    (``backoffice_state.audit_writer``) instead of a bare ``logger.info`` —
    executes the rego's ever-present ``audit_document_decision`` obligation.
    ``audit_context`` is the mutable dict the caller updates with
    ``identity_id``/``tenant``/``obligations`` (see documents/audit_bridge.py)."""
    from yashigani.documents.audit_bridge import make_document_audit_callback
    from yashigani.documents.config import DocumentEnforcementConfig

    cfg = DocumentEnforcementConfig.from_env()
    registry = cfg.build_registry()
    _audit = make_document_audit_callback(
        backoffice_state.audit_writer, surface="user-upload", context=audit_context,
    )

    from yashigani.documents.pipeline import DocumentInspectionPipeline
    return DocumentInspectionPipeline(registry=registry, on_audit=_audit)


def _resolve_caller_identity_id(session) -> str:
    """Resolve the caller's canonical Yashigani identity_id ("idnt_...") for the
    RESTART-013 gap #4 per-user document-policy dimension.

    Best-effort: mirrors the resolution already used by ``user_chat_proxy``
    (``id_registry.get_by_account_id``). Returns "" when the registry is
    absent or no identity is linked — the caller then only matches GLOBAL
    (identity_id == "") policies, exactly as before this feature existed."""
    id_registry = backoffice_state.identity_registry
    if id_registry is None:
        return ""
    try:
        identity = id_registry.get_by_account_id(session.account_id)
        if identity:
            return str(identity.get("identity_id", "") or "")
    except Exception as exc:
        logger.debug("_resolve_caller_identity_id: lookup failed: %s", exc)
    return ""


def _install_tenant() -> str:
    return os.environ.get("YASHIGANI_TENANT_ID", "default").strip() or "default"


# ---------------------------------------------------------------------------
# Page route — /chat
# ---------------------------------------------------------------------------

@router.get("/chat", include_in_schema=False)
async def user_chat_page(request: Request):
    """
    Serve the 4.0 user SPA entry point (RISK-100 user side).

    Cookie-presence guard: if __Host-yashigani_session is absent, redirect to
    /login?next=/chat.  The server-side session validity check happens per-API-
    call via require_user_session; the guard here is a lightweight pre-flight
    that avoids serving the SPA shell to unauthenticated clients (mirrors the
    /admin/ pattern — see app.py admin_dashboard_page).

    The Admin session IS rejected: if the request carries an admin-only cookie
    (user cookie has admin token → account_tier == "admin") the user lands on
    /chat then the first API call returns 403 wrong_plane.  The SPA surfaces
    this to the user with a ys-toast and a link to /admin/.
    """
    token = request.cookies.get(_USER_SESSION_COOKIE)
    if not token:
        return RedirectResponse(url="/login?next=/chat", status_code=302)

    return _serve_user_page("chat.html", "chat")


def _serve_user_page(filename: str, page_key: str) -> HTMLResponse:
    """Serve a 4.0 user-plane SPA entry point from ui4/user/.

    Shared by /chat, /agents and /builder. The cookie pre-flight is done by the
    caller; this helper only resolves + reads the static shell, returning a 500
    structured error if the page has not been deployed.
    """
    _static_dir = pathlib.Path(__file__).parents[2] / "backoffice" / "static"
    page = _static_dir / "ui4" / "user" / filename
    if not page.exists():
        logger.error("user page %r not found at %s", page_key, page)
        raise HTTPException(
            status_code=500,
            detail={"error": "user_ui_unavailable", "message": "User UI not deployed yet."},
        )
    return HTMLResponse(page.read_text(encoding="utf-8"))


@router.get("/agents", include_in_schema=False)
async def user_agents_page(request: Request):
    """Serve the 4.0 agent-management surface (form-based agent builder).

    Same cookie pre-flight + plane discipline as /chat (RISK-100). The page
    drives the BOLA-enforced /user/agents, /user/skills and /user/memories
    routes through the audited ApiClient (sessionKind:'user').
    """
    if not request.cookies.get(_USER_SESSION_COOKIE):
        return RedirectResponse(url="/login?next=/agents", status_code=302)
    return _serve_user_page("agents.html", "agents")


@router.get("/builder", include_in_schema=False)
async def user_builder_page(request: Request):
    """Serve the 4.0 visual (Drawflow) agent builder surface.

    Same cookie pre-flight + plane discipline as /chat (RISK-100). The canvas
    emits an agent-template spec and POSTs it to /user/agents.
    """
    if not request.cookies.get(_USER_SESSION_COOKIE):
        return RedirectResponse(url="/login?next=/builder", status_code=302)
    return _serve_user_page("builder.html", "builder")


@router.get("/workflows", include_in_schema=False)
async def user_workflows_page(request: Request):
    """Serve the 4.0 no-code workflow composer surface.

    Same cookie pre-flight + plane discipline as /chat (RISK-100). The user
    describes a workflow in plain language with @-handles (agents, personas,
    MCPs, APIs); the page drives the BOLA-enforced /user/mentions and
    /user/workflows* routes through the audited ApiClient (sessionKind:'user').
    Nothing is committed/scheduled without the user's explicit "Add workflow"
    click (human-in-the-loop, EU AI Act Art.14).
    """
    if not request.cookies.get(_USER_SESSION_COOKIE):
        return RedirectResponse(url="/login?next=/workflows", status_code=302)
    return _serve_user_page("workflows.html", "workflows")


# ---------------------------------------------------------------------------
# Data endpoints — /user/*
# All require UserSession (RISK-100).
# ---------------------------------------------------------------------------

@router.get("/user/agents")
async def user_list_agents(session: UserSession):
    """
    List agents available to the authenticated user.

    Returns the subset of active agents from the registry with user-visible
    fields only (agent_id, name, protocol, status, groups).  Never returns
    PSK tokens or admin-only fields.

    OPA routing decisions (which model an agent points at, etc.) are NOT
    exposed here — the UI uses the gateway /v1/models endpoint for that.
    Users chat by sending to /v1/chat/completions with ``model=@<agent_name>``.
    """
    registry = backoffice_state.agent_registry
    if registry is None:
        # Community tier without a registry — return empty; not an error.
        return {"agents": []}

    try:
        agents = registry.list_all()
    except Exception as exc:
        logger.warning("user_list_agents: registry.list_all() failed: %s", exc)
        return {"agents": []}

    user_view = [
        {
            "agent_id": a.get("agent_id", ""),
            "name": a.get("name", ""),
            "protocol": a.get("protocol", "openai"),
            "status": a.get("status", "unknown"),
            "groups": list(a.get("groups", [])),
        }
        for a in agents
        if a.get("status", "") == "active"
    ]
    return {"agents": user_view}


@router.get("/user/budget")
async def user_budget(session: UserSession):
    """
    Return the calling user's own budget usage.

    Resolves the caller's Yashigani identity_id from the identity registry
    (keyed on the session account_id / email), then queries the budget enforcer
    for their cloud-provider token usage.

    Falls back to ``{"configured": false}`` when the budget enforcer is not
    wired (community deploy without budget enforcement).
    """
    # Try to resolve the caller's Yashigani identity.
    identity_id: Optional[str] = None
    id_registry = backoffice_state.identity_registry
    if id_registry is not None:
        try:
            # Identity slugs are derived from the local-part of the user's email
            # (v2.23.4 derivation algorithm).  session.account_id is a UUID, not
            # the slug — resolve via email if available.
            account_email = getattr(session, "email", None) or ""
            if account_email:
                slug = account_email.split("@")[0].lower() if "@" in account_email else account_email
                identity = id_registry.get_by_slug(slug)
                if identity:
                    identity_id = identity.get("identity_id")
        except Exception as exc:
            logger.debug("user_budget: identity resolution failed: %s", exc)

    # Query budget enforcer if available.
    from yashigani.backoffice.routes.budget import _state as _budget_state

    enforcer = _budget_state.budget_enforcer
    if enforcer is None or identity_id is None:
        return {
            "configured": False,
            "identity_id": identity_id,
            "providers": [],
            "note": "Budget enforcement not configured for this deployment.",
        }

    try:
        providers_usage = []
        for provider in ("cloud", "ollama", "*"):
            try:
                allocation = enforcer.get_allocation(identity_id, provider)
                if allocation is None:
                    continue
                budget_state = enforcer.check(identity_id, provider, tokens=0)
                providers_usage.append({
                    "provider": provider,
                    "used": budget_state.used,
                    "total": budget_state.total,
                    "pct": budget_state.pct,
                    "signal": budget_state.signal.value if hasattr(budget_state.signal, "value") else str(budget_state.signal),
                })
            except Exception:
                continue  # provider not configured — skip silently
        return {
            "configured": True,
            "identity_id": identity_id,
            "providers": providers_usage,
        }
    except Exception as exc:
        logger.warning("user_budget: enforcer query failed: %s", exc)
        return {
            "configured": False,
            "identity_id": identity_id,
            "providers": [],
            "note": "Budget query failed; contact an administrator.",
        }


@router.get("/user/models")
async def user_models(session: UserSession):
    """
    Return the models and agents available to the calling user.

    Resolution logic (Track B1 / effective-allowed-models):
      1. Resolve the caller's Yashigani identity from the identity registry
         (tries account_id directly, then slug derived from email local-part).
      2. Call resolve_effective_allowed_models with the live allocation + alias
         stores to compute the caller's effective allowlist.
      3. Filter the alias store to aliases NOT denied for this caller.
      4. Append active agents from the registry (user-visible fields only).

    Returns:
      ``{"models": [{alias, provider, model, force_local}], "agents": [...]}``

    Falls back gracefully at every step: missing stores / identity / registry
    return an empty list rather than raising, so the user UI still renders.
    """
    from yashigani.models.effective import resolve_effective_allowed_models

    alias_store = backoffice_state.model_alias_store
    alloc_store = backoffice_state.model_allocation_store
    agent_registry = backoffice_state.agent_registry

    # --- Resolve identity (best-effort; None → unrestricted) ---
    identity: Optional[dict] = None
    id_registry = backoffice_state.identity_registry
    if id_registry is not None:
        try:
            identity = id_registry.get(session.account_id)
            if identity is None and "@" in session.account_id:
                slug = session.account_id.split("@")[0].lower()
                identity = id_registry.get_by_slug(slug)
        except Exception as exc:
            logger.debug("user_models: identity resolution failed: %s", exc)

    # --- Effective model allowlist ---
    try:
        effective = resolve_effective_allowed_models(identity, alloc_store, alias_store)
    except Exception as exc:
        logger.warning("user_models: effective model resolution failed: %s", exc)
        from yashigani.models.effective import EffectiveModels
        effective = EffectiveModels()

    # --- Build model list ---
    models: list[dict] = []
    if alias_store is not None:
        try:
            for alias_name, alias in alias_store.list_all().items():
                if not effective.is_model_denied(alias_name):
                    models.append({
                        "alias": alias_name,
                        "provider": getattr(alias, "provider", ""),
                        "model": getattr(alias, "model", ""),
                        "force_local": bool(getattr(alias, "force_local", False)),
                    })
        except Exception as exc:
            logger.warning("user_models: alias store list failed: %s", exc)

    # --- Active agents (user-visible fields only) ---
    agents: list[dict] = []
    if agent_registry is not None:
        try:
            for a in agent_registry.list_all():
                if a.get("status") == "active":
                    agents.append({
                        "agent_id": a.get("agent_id", ""),
                        "name": a.get("name", ""),
                        "protocol": a.get("protocol", "openai"),
                    })
        except Exception as exc:
            logger.warning("user_models: agent registry list failed: %s", exc)

    return {"models": models, "agents": agents}


@router.get("/user/memory")
async def user_memory(session: UserSession):
    """
    Return the calling user's per-identity memory entries.

    Phase 3 stub — Letta per-user isolation is built in Phase 3 (NHI/SVID
    mesh + per-user Letta container, RISK-107).  Until that lands this
    endpoint returns a structured empty response with a note so the UI can
    render a 'Memory not yet configured' state without an error.

    Phase 3 will replace this with a call to the per-user Letta client.
    """
    return {
        "configured": False,
        "entries": [],
        "note": (
            "Per-user memory isolation is built in Phase 3 (NHI/SVID mesh). "
            "Until then, memory is shared via the Letta service — see /admin/ "
            "for configuration."
        ),
    }


# ---------------------------------------------------------------------------
# File upload — POST /user/documents (RISK-112)
# ---------------------------------------------------------------------------

@router.post("/user/documents")
async def user_upload_document(
    session: UserSession,
    upload: DocumentUploadBody,
):
    """
    Upload a document for doc-OPA evaluation (RISK-112).

    Accepts JSON body ``{filename, content_type, content_base64, route?,
    pseudonymize_mode?}`` — matches what the 4.0 shared-layer ApiClient.mutate
    sends (shared-layer-spec §2). The file bytes are base64-encoded by the
    browser before sending (FileReader.readAsDataURL, data-URL prefix stripped).

    Hardening (pre-pipeline guards, defence-in-depth):
      1. Filename path-traversal guard: null bytes, path separators, dot-only
         names rejected; result clamped to POSIX basename (CWE-22).
      2. Size cap: YASHIGANI_USER_UPLOAD_MAX_MB (default 10 MB); the decoded
         byte length is checked after base64 decode; 413 if exceeded.
      3. Declared content-type must be in the allowed set (unknown MIME →
         422 before the pipeline runs).

    Pipeline:
      Routes into the EXISTING DocumentInspectionPipeline sandbox — same path
      as POST /admin/documents/inspect.  The pipeline performs the authoritative
      magic-byte sniff (F8 polyglot guard) and fail-closes on mismatch or
      unsupported format.

    Returns:
      Structured verdict compatible with ApiClient.decode() / ys-verdict-banner
      (RISK-105): action + decision_codes + user_alert + blocked at top level.
      Never returns raw PII values or the correspondence-table map handle.
    """
    from yashigani.documents.config import is_document_enforcement_enabled
    from yashigani.documents.pipeline import (
        DISPOSITION_BLOCK,
        DISPOSITION_LOG,
        DISPOSITION_PSEUDONYMIZE,
        DISPOSITION_REDACT,
    )
    from yashigani.documents.opa_decision import evaluate_document_decision

    route = upload.route
    pseudonymize_mode = upload.pseudonymize_mode

    # Validate route and pseudonymize_mode
    if route not in ("ingress-upload", "egress-mcp-result", "json-attachment", "any"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_route", "message": f"Unknown route: {route!r}"},
        )
    if pseudonymize_mode not in ("A", "B"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_pseudonymize_mode"},
        )

    if not is_document_enforcement_enabled():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "document_enforcement_disabled",
                "message": "Document enforcement is not enabled on this deployment.",
            },
        )

    # --- Guard 1: filename path-traversal ---
    safe_filename = _guard_filename(upload.filename or "upload")

    # --- Guard 2: base64 decode + size cap ---
    max_bytes = _user_upload_max_bytes()
    # Pre-check: reject obviously oversized base64 before decoding (DoS guard).
    # base64 inflates by ~4/3; cap the raw string at ceil(max_bytes * 4/3) + 16.
    _b64_limit = math.ceil(max_bytes * 4 / 3) + 16
    if len(upload.content_base64) > _b64_limit:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail={
                "error": "file_too_large",
                "message": (
                    f"File exceeds the {max_bytes // _BYTES_PER_MB} MB upload limit. "
                    "Split the document or contact an administrator to raise the cap."
                ),
                "max_bytes": max_bytes,
            },
        )
    try:
        data = base64.b64decode(upload.content_base64, validate=False)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_base64", "message": "content_base64 is not valid base64."},
        ) from exc

    if len(data) > max_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail={
                "error": "file_too_large",
                "message": (
                    f"File exceeds the {max_bytes // _BYTES_PER_MB} MB upload limit. "
                    "Split the document or contact an administrator to raise the cap."
                ),
                "max_bytes": max_bytes,
            },
        )

    # --- Guard 3: content-type declaration ---
    declared_mime = _check_allowed_mime(upload.content_type or "", safe_filename)

    # --- Route to pipeline ---
    import uuid as _uuid
    request_id = f"user-doc-{session.account_id[:8]}-{_uuid.uuid4().hex[:8]}-{safe_filename}"

    # RESTART-013 gap #4 — resolve the caller's canonical identity_id so a
    # per-user REDACT/PSEUDONYMIZE policy can bind to THIS caller specifically.
    # "" (unresolved) still works — only global policies match, unchanged.
    caller_identity_id = _resolve_caller_identity_id(session)
    # RESTART-013 gap #5 — mutable audit context (see documents/audit_bridge.py).
    _audit_ctx: dict = {"identity_id": caller_identity_id, "tenant": _install_tenant()}

    try:
        pipeline = _build_pipeline(audit_context=_audit_ctx)
    except Exception as exc:
        logger.error("user_upload_document: pipeline init failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "pipeline_unavailable",
                "message": "Document inspection pipeline unavailable.",
            },
        ) from exc

    try:
        # First pass: LOG (enumerate matches, build OPA input)
        enum_result = pipeline.inspect(
            data=data,
            declared_mime=declared_mime,
            request_id=request_id,
            requested_action=DISPOSITION_LOG,
            pseudonymize_mode=pseudonymize_mode,
            requester_identity=session.account_id,
            tenant=_install_tenant(),
        )
    except Exception as exc:
        envelope, _ = safe_error_envelope(exc, public_message="document inspection failed")
        raise HTTPException(status_code=500, detail=envelope)

    # OPA decision (same flow as admin inspect_document)
    opa_input = enum_result.opa_input
    if opa_input is None:
        decision: dict = {
            "action": DISPOSITION_BLOCK,
            "policy_id": "DOC-ENFORCE-001",
            "code": "DOCUMENT_BLOCKED",
            "user_message": (
                "This file was held because it could not be safely cleared: "
                + (enum_result.block_reason or "policy block")
            ),
        }
    else:
        decision = await evaluate_document_decision(
            backoffice_state.opa_url,
            opa_input,
            route=route,
            pseudonymize_mode=pseudonymize_mode,
            identity_id=caller_identity_id,
        )

    # RESTART-013 gap #5 — obligations now known; the second pipeline.inspect()
    # call below (if any) records them in its audit event via _audit_ctx.
    _audit_ctx["obligations"] = decision.get("obligations", [])

    opa_action = decision.get("action", DISPOSITION_BLOCK)

    # Second pass: apply the OPA-decided action (skip for LOG — first pass IS the result)
    if opa_action == DISPOSITION_LOG or opa_input is None:
        result = enum_result
    else:
        try:
            result = pipeline.inspect(
                data=data,
                declared_mime=declared_mime,
                request_id=request_id,
                requested_action=opa_action,
                pseudonymize_mode=decision.get("pseudonymize_mode", pseudonymize_mode),
                requester_identity=session.account_id,
                tenant=_install_tenant(),
            )
        except Exception as exc:
            envelope, _ = safe_error_envelope(exc, public_message="document action failed")
            raise HTTPException(status_code=500, detail=envelope)

    _is_blocked = result.disposition == DISPOSITION_BLOCK
    _user_alert = (
        {
            "code": decision.get("code", "DOCUMENT_BLOCKED"),
            "policy_id": decision.get("policy_id", "DOC-ENFORCE-001"),
            "user_message": decision.get(
                "user_message",
                "This file was held because it could not be safely cleared: "
                + (result.block_reason or "policy block"),
            ),
        }
        if _is_blocked
        else None
    )

    return {
        "request_id": request_id,
        "filename": safe_filename,
        "disposition": result.disposition,
        "detected_format": result.detected_format,
        "match_count": len(result.matches),
        # Top-level structured verdict fields read by ApiClient.decode()
        # (decodeVerdict) + ys-verdict-banner (RISK-105).  Never embedded in
        # or parsed from message text — these are server-minted structured fields.
        "action": opa_action,
        "blocked": _is_blocked,
        "decision_codes": [],          # no orchestration codes for doc-upload
        "user_alert": _user_alert,
        # opa_decision kept for backward compat with admin-plane callers.
        "opa_decision": {
            "action": opa_action,
            "policy_id": decision.get("policy_id"),
            "code": decision.get("code"),
        },
        # processed_content: RESTART-013 gap #3 fix. The pipeline's second pass
        # (REDACT/PSEUDONYMIZE) rewrites the document into
        # ``result.forward_bytes`` — previously computed and then discarded
        # (hardcoded None). Base64-encoded (this is a JSON body, matching the
        # request's own content_base64 convention) so the caller can actually
        # receive the transformed file instead of only its verdict metadata.
        # None for BLOCK (nothing to forward) and for LOG (the disposition
        # carries the ORIGINAL bytes unchanged — no transform occurred, so
        # there is nothing new to hand back beyond what the caller already
        # has).
        "processed_content": (
            base64.b64encode(result.forward_bytes).decode("ascii")
            if opa_action in (DISPOSITION_REDACT, DISPOSITION_PSEUDONYMIZE)
            and result.forward_bytes is not None
            else None
        ),
    }


# ---------------------------------------------------------------------------
# FIND-4.0-CHAT-001 — Trusted-forwarder chat proxy
# ---------------------------------------------------------------------------
# The 4.0 ui4 chat sends requests using the session cookie, but the gateway
# mesh requires an Authorization: Bearer header.  Forwarding the user's API
# key to the browser is explicitly off-limits (RISK-100 class).
#
# Solution: a UserSession-gated backoffice proxy that:
#   1. Validates the caller's user-tier session (cookie, server-side).
#   2. Adds the per-install internal bearer  (YASHIGANI_INTERNAL_BEARER).
#   3. Resolves the caller's Yashigani identity_id (idnt_ PK) from the
#      identity registry via session.account_id → identity:account:{id} →
#      identity_id.  Forwards as X-Yashigani-Identity-Id: <idnt_...>.
#      The gateway honours this header ONLY when the internal bearer is
#      present (spoofing defence: without the bearer the header is ignored;
#      Caddy also strips it at the public edge).
#      FAIL-CLOSED: if no identity_id can be resolved (registry down or no
#      account→identity mapping) the proxy returns 503/403 rather than
#      forwarding the account UUID as an email (the original FIND-4.0-CHAT-001
#      residual that let email leak into the gateway's slug resolver).
#   4. Streams the gateway SSE response back to the browser unchanged.
#
# The user's API key never leaves the server; the browser sees only the
# session cookie and the SSE event stream.  Verdict / block events arrive in
# the stream structured tail exactly as with direct gateway access.
#
# Security:
#   - UserSession dependency: rejects admin sessions (wrong_plane) and
#     unauthenticated requests (401).
#   - YASHIGANI_INTERNAL_BEARER absent → 503 at request time (fail-closed).
#   - identity_registry unavailable → 503 (fail-closed, not degraded).
#   - account_id not linked to an identity_id → 403 (user must log in once
#     to populate the identity:account index, or admin must provision them).
#   - All gateway errors (4xx/5xx) are forwarded verbatim so the browser
#     can render the correct verdict banner.
#
# FIND-4.0-CHAT-001 / AUDIT-GAP: this proxy is the sole path for browser
# chat; direct /v1/chat/completions from the browser 401s (correct).
# ---------------------------------------------------------------------------

_GATEWAY_STREAM_TIMEOUT_S = 300  # 5-minute timeout for streaming responses

# Header name must match the constant in gateway/openai_router.py.
# Caddy MUST strip this at the public edge (Su's Caddyfile task).
_YASHIGANI_IDENTITY_ID_HEADER = "X-Yashigani-Identity-Id"


@router.post("/user/chat/completions")
async def user_chat_proxy(request: Request, session: UserSession):
    """FIND-4.0-CHAT-001 — Trusted-forwarder chat proxy.

    Accepts the session cookie, resolves the caller's Yashigani identity_id,
    adds the internal bearer + identity header, and streams the gateway SSE
    response back verbatim.  The user's API key is never exposed to the browser.

    Fail-closed: if the identity_registry is unavailable or the caller's
    account_id has no linked identity, returns 503/403 respectively.

    Body: OpenAI-compatible chat completion JSON (model, messages, …).
    Response: text/event-stream (SSE) mirrored from the gateway.
    """
    bearer = os.environ.get("YASHIGANI_INTERNAL_BEARER", "")
    if not bearer:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "chat_proxy_not_configured",
                "message": (
                    "YASHIGANI_INTERNAL_BEARER is not set — the chat proxy cannot "
                    "reach the governed gateway.  Contact your administrator."
                ),
            },
        )

    # ── Resolve caller's Yashigani identity_id (fail-closed) ────────────────
    # session.account_id is the auth accounts UUID.  The identity:account:{id}
    # Redis index maps it to the canonical idnt_ PK.  Populated by auth.py on
    # every login (idempotent).  A None result means the account has never
    # logged in since identity linking was introduced (3.1+) or the registry
    # is unavailable — both are fail-closed.
    id_registry = backoffice_state.identity_registry
    if id_registry is None:
        logger.error(
            "user_chat_proxy: identity_registry unavailable — "
            "cannot resolve identity_id for account %s (fail-closed 503)",
            session.account_id,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "identity_registry_unavailable",
                "message": (
                    "Identity service temporarily unavailable. "
                    "Try again shortly or contact your administrator."
                ),
            },
        )

    try:
        caller_identity = id_registry.get_by_account_id(session.account_id)
    except Exception as exc:
        logger.error(
            "user_chat_proxy: identity_registry.get_by_account_id(%s) raised %s — "
            "fail-closed 503",
            session.account_id, exc,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "identity_registry_error",
                "message": "Identity lookup failed. Try again shortly.",
            },
        )

    if caller_identity is None:
        logger.warning(
            "user_chat_proxy: no identity linked to account_id=%s — "
            "fail-closed 403 (account has not completed identity onboarding, "
            "or identity:account index is not yet populated for this user)",
            session.account_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "identity_not_found",
                "message": (
                    "Your Yashigani identity could not be resolved. "
                    "Please log out and log back in, or contact your administrator."
                ),
            },
        )

    identity_id = caller_identity.get("identity_id", "")
    if not identity_id or not identity_id.startswith("idnt_"):
        # Registry returned a record without a valid idnt_ PK — should not
        # happen in a well-provisioned install; fail-closed.
        logger.error(
            "user_chat_proxy: identity record for account %s has invalid "
            "identity_id %r — fail-closed 503",
            session.account_id, identity_id,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "identity_id_malformed",
                "message": "Internal identity configuration error. Contact your administrator.",
            },
        )

    gateway_base = os.environ.get("YASHIGANI_GATEWAY_MESH_URL", "http://gateway:8081/v1")
    target_url = gateway_base.rstrip("/") + "/chat/completions"

    # Read and forward the request body as-is (JSON validated by the gateway).
    try:
        body_bytes = await request.body()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_request_body", "message": str(exc)},
        )

    forward_headers = {
        "Authorization": f"Bearer {bearer}",
        # Trusted-forwarder identity: gateway resolves per-user RBAC from this
        # header on the internal-bearer path (spoofing defence: without the bearer
        # the gateway ignores this header; Caddy strips it at the public edge).
        _YASHIGANI_IDENTITY_ID_HEADER: identity_id,
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
    }

    async def _stream_gateway():
        """Async generator: iterate gateway SSE chunks and yield to client."""
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(
                connect=10.0,
                read=_GATEWAY_STREAM_TIMEOUT_S,
                write=30.0,
                pool=5.0,
            )) as client:
                async with client.stream(
                    "POST",
                    target_url,
                    content=body_bytes,
                    headers=forward_headers,
                ) as resp:
                    # Forward non-2xx as a synthetic SSE error event so the
                    # browser's onBlocked / onError handlers fire correctly.
                    if resp.status_code not in (200, 201, 206):
                        error_body = await resp.aread()
                        yield (
                            f"data: {error_body.decode('utf-8', errors='replace')}\n\n"
                        ).encode("utf-8")
                        return
                    async for chunk in resp.aiter_bytes():
                        if chunk:
                            yield chunk
        except httpx.ConnectError as exc:
            logger.error("user_chat_proxy: gateway unreachable: %s", exc)
            yield b'data: {"error":"gateway_unreachable","message":"Could not connect to the governed gateway."}\n\n'
        except Exception as exc:
            logger.error("user_chat_proxy: stream error: %s", exc)
            yield b'data: {"error":"stream_error","message":"Unexpected error streaming from gateway."}\n\n'

    return StreamingResponse(
        _stream_gateway(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # disable nginx/Caddy buffering for SSE
        },
    )
