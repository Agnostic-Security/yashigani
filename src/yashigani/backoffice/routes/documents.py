"""
Yashigani Backoffice — Document Enforcement admin routes (2.26 feature).

The demoable admin surface for the document-content OPA-enforcement feature
(plan: AgnosticSecurity/Products/Yashigani/opa_document_enforcement_plan_*.md).
This is the THIN API seam between the backoffice and the COMPLETE backend in
``src/yashigani/documents/`` — it wires the real :class:`DocumentInspectionPipeline`
(no stub) and surfaces:

  GET    /admin/documents/status                 — feature-flag state + formats
  GET    /admin/documents/policies               — list action policies
  POST   /admin/documents/policies               — add a policy (step-up)
  DELETE /admin/documents/policies/{id}          — delete a policy (step-up)
  POST   /admin/documents/inspect                — process a sample document
  GET    /admin/documents/results                — list processed-document verdicts
  GET    /admin/documents/results/{rid}          — one verdict + DataMatch[] viewer
  GET    /admin/documents/results/{rid}/table    — mode-A correspondence table (RBAC'd)
  GET    /admin/documents/results/{rid}/table.csv — table download (RBAC'd)

Feature flag (default OFF — ships dark): when
``is_document_enforcement_enabled()`` is False every endpoint returns a 200
status payload with ``enabled=false`` (status route) or 409 (mutation/inspect
routes) so the UI renders the "feature disabled" state without 500s.

Security properties enforced here (the brief's QA mandate on our own build):
  - **RBAC gate on table retrieval** — only an admin whose account is a member
    of the group named by the document's ``detokenize_rbac_role`` may retrieve
    the correspondence table (the re-identification key, GDPR Art. 4(5)).  An
    unauthorised admin gets 403 and NEVER the table rows.  The unguessable map
    handle is never returned to the client.
  - **Masked instances only** — the viewer renders ``DataMatch.instance`` which
    is ALWAYS the masked value (the pipeline never emits raw PII here).  The raw
    original values live only in the RBAC'd table, behind the gate.
  - **Output escaping is the UI's job** — match ``instance`` / ``location`` are
    derived from attacker-controlled document content, so the renderer
    (documents.js) MUST escapeHtml() them.  The route returns them as JSON
    strings (no HTML), so the escaping boundary is the browser sink.

# Last updated: 2026-06-19
"""
from __future__ import annotations

import logging
import os
import secrets

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import AdminSession, StepUpAdminSession
from yashigani.backoffice.state import backoffice_state
from yashigani.common.error_envelope import safe_error_envelope
from yashigani.documents.config import (
    DocumentEnforcementConfig,
    is_document_enforcement_enabled,
)
from yashigani.documents.field_role import is_operate_on_sensitive
from yashigani.documents.pipeline import (
    DISPOSITION_BLOCK,
    DISPOSITION_LOG,
    DISPOSITION_PSEUDONYMIZE,
    DISPOSITION_REDACT,
    DocumentInspectionPipeline,
)

logger = logging.getLogger(__name__)

router = APIRouter()


# ── Supported / parked format catalogue (plan §2 / §2.1) ──────────────────
# Committed common formats (full depth) + the parked formats that fail-closed
# to BLOCK.  Surfaced read-only so an operator can see exactly what is inspected
# vs. what is rejected.
SUPPORTED_FORMATS = [
    {"ext": "docx", "family": "OOXML-zip", "label": "Word (modern)"},
    {"ext": "xlsx", "family": "OOXML-zip", "label": "Excel (modern)"},
    {"ext": "pptx", "family": "OOXML-zip", "label": "PowerPoint (modern)"},
    {"ext": "pdf", "family": "flat / object graph", "label": "PDF (native text)"},
    {"ext": "csv", "family": "flat text", "label": "Tabular (CSV)"},
    {"ext": "txt", "family": "flat text", "label": "Plain text"},
]
PARKED_FORMATS = [
    {"ext": "doc/xls/ppt", "family": "OLE / CFB binary", "reason": "legacy binary — fail-closed BLOCK"},
    {"ext": "odt/ods/odp", "family": "OpenDocument", "reason": "second zip-XML schema — fail-closed BLOCK"},
    {"ext": "rtf", "family": "flat markup", "reason": "embeds OLE — fail-closed BLOCK"},
    {"ext": "image / scanned", "family": "OCR", "reason": "no OCR this version — fail-closed BLOCK"},
]

ACTIONS = [DISPOSITION_LOG, DISPOSITION_REDACT, DISPOSITION_PSEUDONYMIZE, DISPOSITION_BLOCK]
DATA_CLASSES = ["PII", "QI", "PHI", "PCI", "SECRET", "IP_MARKING"]
ROUTES = ["ingress-upload", "egress-mcp-result", "json-attachment", "any"]
PSEUDONYMIZE_MODES = ["A", "B"]  # A = give-user-table (default), B = internal round-trip


# ── Persistent policy store (2.26-prod) ─────────────────────────────────────
#
# The document-enforcement policy MATRIX (data_class × format × route → action)
# is persisted in :class:`DocumentPolicyStore` (Redis db/3) and pushed to OPA so
# the production rego (policy/document.rego) evaluates the operator's live
# configuration.  This REPLACES the prior in-memory stub: the routes below read
# and mutate the durable store on ``backoffice_state.document_policy_store`` and
# re-push to OPA after every mutation (same pattern as the RBAC routes).
#
# Fail-closed: when the store is not wired (dev/test without Redis) mutation
# routes 503 rather than silently mutating a phantom store.


def _policy_store():
    """Return the wired DocumentPolicyStore or raise 503 (fail-closed).

    A mutation must never appear to succeed against a store that does not exist
    — that would leave OPA and the operator's view diverged."""
    store = backoffice_state.document_policy_store
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "policy_store_unavailable",
                "message": "Document policy store not initialised (Redis db/3 unavailable).",
            },
        )
    return store


def _push_document_policies() -> None:
    """Re-push the document policy matrix to OPA after a mutation.

    Best-effort like the RBAC routes' _push_opa(): the store mutation already
    persisted to Redis; an OPA push failure is logged (and recovered by the
    startup re-sync) but does not roll back the persisted change."""
    store = backoffice_state.document_policy_store
    if store is None:
        logger.warning("_push_document_policies: store not available — skipping OPA push")
        return
    try:
        from yashigani.documents.opa_push import push_document_data
        push_document_data(store, backoffice_state.opa_url)
    except Exception as exc:
        logger.error("_push_document_policies: OPA push failed after policy mutation: %s", exc)


# Processed-document results, keyed by request_id.  Holds the full
# DocumentInspectionResult so the verdict viewer + RBAC'd table retrieval can
# read it back.  Demo-grade in-memory (request-scoped maps are TTL'd inside the
# ReplacerMap itself; this index is the gateway's hold for the demo).
_results: dict[str, object] = {}

# DP-Y-004 §3.1 GAP-2 — sequential-replay tracking: the set of request_ids
# whose correspondence table has been burned (first reveal consumed and
# ``_burn_correspondence_table`` called by the route).  When a caller hits the
# ``correspondence_table is None`` branch AND its request_id is in this set,
# the request is a sequential replay — ``_audit_handle_replay`` fires before
# the 404 so the audit log can distinguish "never had a table" from "burned
# after first reveal and then replayed."  Growth is bounded by ``_results``
# (same demo-grade in-memory lifecycle; a production deployment that migrates
# ``_results`` to Redis must migrate ``_burned`` to a shared atomic store too).
_burned: set[str] = set()


# ── Request / Response models ─────────────────────────────────────────────

class PolicyRequest(BaseModel):
    # Core matrix axes — validated against the rego's known vocabularies.
    data_class: str = Field(pattern=r"^(PII|QI|PHI|PCI|SECRET|IP_MARKING)$")
    format: str = Field(pattern=r"^(docx|xlsx|pptx|pdf|csv|txt|any)$")
    route: str = Field(pattern=r"^(ingress-upload|egress-mcp-result|json-attachment|any)$")
    action: str = Field(pattern=r"^(LOG|REDACT|PSEUDONYMIZE|BLOCK)$")
    pseudonymize_mode: str = Field(default="A", pattern=r"^(A|B)$")
    small_set_escalation: bool = Field(default=True)
    description: str = Field(min_length=1, max_length=256)
    # Self-describing decision-contract fields (unified user-alert contract,
    # matching the shape built-in policies carry: policy_id + user_message + code).
    # Required so operator-created policies surface the same layman alert at every
    # enforcement point as the built-in demo policies.
    name: str = Field(
        default="",
        max_length=128,
        description="Short human-readable label for this policy (shown in the admin UI list).",
    )
    policy_id: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[A-Z][A-Z0-9]*(-[A-Z0-9]+)+$",
        description=(
            "Stable identifier for this policy, used in the decision contract and audit events. "
            "Format: uppercase letters/digits separated by hyphens (e.g. DOC-OP-001). "
            "Must match the pattern used by built-in policies."
        ),
    )
    user_message: str = Field(
        min_length=1,
        max_length=512,
        description=(
            "Layman explanation shown to the end user when this policy triggers. "
            "Must be human-readable and free of jargon."
        ),
    )
    code: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[A-Z][A-Z0-9_]+$",
        description=(
            "Machine code carried in the decision contract (e.g. DOCUMENT_BLOCKED). "
            "Uppercase letters, digits, underscores only."
        ),
    )


class InspectRequest(BaseModel):
    # The sample content to inspect.  Demo surface: the operator pastes text or
    # uploads a small CSV/txt sample; the real gateway path feeds bytes off the
    # proxy.  Bounded length (the production path uses the byte-cap config).
    content: str = Field(min_length=1, max_length=200_000)
    filename: str = Field(default="sample.txt", min_length=1, max_length=255)
    declared_mime: str = Field(default="text/plain", max_length=128)
    requested_action: str = Field(default="LOG", pattern=r"^(LOG|REDACT|PSEUDONYMIZE|BLOCK)$")
    pseudonymize_mode: str = Field(default="A", pattern=r"^(A|B)$")
    detokenize_rbac_role: str = Field(default="doc-pseudonymize-reverser", max_length=128)
    # The routing context (matched against each policy's ``route`` in the rego).
    # 2.26: the action is decided by OPA over the matrix, so the route the
    # document is travelling on is a first-class decision input.
    route: str = Field(
        default="any", pattern=r"^(ingress-upload|egress-mcp-result|json-attachment|any)$"
    )
    # Set-scoped-salt opt-in: when set, the PSEUDONYMIZE path derives tokens under
    # the named document SET's shared salt instead of the per-file salt, so the
    # same value tokenises consistently across the set (cross-file correlation).
    # Empty (default) = per-file isolation.  The salt itself is NEVER supplied by
    # the client — the route looks it up from the operator's set store by id.
    set_id: str = Field(default="", max_length=64)


# ── Helpers ───────────────────────────────────────────────────────────────

def _require_enabled() -> None:
    """Fail-closed 409 for mutation/inspect routes when the feature is dark."""
    if not is_document_enforcement_enabled():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "document_enforcement_disabled",
                "message": "Set YASHIGANI_DOCUMENT_ENFORCEMENT_ENABLED=true to enable.",
            },
        )


def _build_pipeline() -> DocumentInspectionPipeline:
    """Construct a pipeline honouring the configured caps + the existing audit
    sink.  The pipeline calls the EXISTING PII detector internally."""
    cfg = DocumentEnforcementConfig.from_env()
    registry = cfg.build_registry()

    def _audit(event_name: str, fields: dict) -> None:
        # Reuse the gateway audit sink shape; tolerate a missing writer in
        # dev/test (the pipeline still returns the verdict).
        logger.info("document audit event: %s", event_name)

    return DocumentInspectionPipeline(registry=registry, on_audit=_audit)


def _result_summary(result) -> dict:
    """JSON-safe verdict summary for the results list (no raw values, no map).

    2.26 surfaces (demo/operator value, no secrets):
      * ``salt_scope`` — "file" (per-file isolation, default) or "set" (shared set
        salt; reduced isolation).  The scope NAME only — never the salt value.
      * ``route_local`` + ``operate_on_classes`` — the field-role routing outcome
        (an operate-on sensitive field was kept LOCAL rather than blobbed to the
        cloud).  Class names only, never values.
      * ``doc_hash`` — the per-file integrity salt recorded in the mapping header
        (NOT a secret — a hash of bytes the holder already has).  Surfaced so the
        operator can run the integrity/splice-verify and see the binding.
    """
    return {
        "request_id": result.request_id,
        "disposition": result.disposition,
        "detected_format": result.detected_format,
        "extraction_complete": result.extraction_complete,
        "match_count": len(result.matches),
        "block_reason": result.block_reason,
        "pseudonymize_mode": result.pseudonymize_mode,
        # Whether a correspondence table exists for retrieval (mode A) — the
        # table itself is NOT included here (RBAC-gated, separate endpoint).
        "has_correspondence_table": result.correspondence_table is not None,
        "detokenize_rbac_role": (
            result.correspondence_table.detokenize_rbac_role
            if result.correspondence_table is not None
            else None
        ),
        # Token salt SCOPE (never the salt value).  Default "file".
        "salt_scope": getattr(result, "salt_scope", "file"),
        # The per-file integrity salt — not a secret; backs the integrity-verify.
        "doc_hash": getattr(result, "doc_hash", None),
        # Field-role routing outcome (Laura D1): an operate-on sensitive field was
        # routed to the LOCAL model rather than blobbed to the cloud.
        "route_local": getattr(result, "route_local", False),
        "operate_on_classes": list(getattr(result, "operate_on_classes", []) or []),
    }


def _match_view(result) -> list[dict]:
    """Per-match rows for the verdict viewer.

    Each row carries the MASKED instance (never raw), the provenance/location,
    and a ``hidden`` flag when the match sits in a hidden part or METADATA — the
    "we found the secret in the file's metadata" wow-row.  ``instance`` and
    ``location`` are attacker-controlled content → the UI escapes them.
    """
    rows = []
    for m in result.matches:
        kind = m.location.split(":", 1)[0] if ":" in m.location else ""
        hidden = kind in ("METADATA", "HIDDEN", "COMMENT", "TRACKED_CHANGE", "SPEAKER_NOTE")
        rows.append(
            {
                "data_class": m.data_class,
                "qi": m.qi,
                "instance": m.instance,   # MASKED — safe to surface; UI still escapes
                "location": m.location,
                "segment_kind": kind,
                "hidden": hidden,
                # PART 2 (Laura D1): how the downstream model must USE this value.
                # REFERENCE_ONLY → safe to opaque-tokenise; OPERATE_ON → the model
                # computes on / validates it, so an operate-on SENSITIVE field is
                # kept LOCAL rather than blobbed to the cloud.  Surfaced so the
                # operator sees, per match, why a field stayed local.
                "field_role": getattr(m, "field_role", "") or "",
                "operate_on_sensitive": is_operate_on_sensitive(m.data_class),
            }
        )
    return rows


def _install_tenant() -> str:
    """Resolve this install's tenant id (G-NEW-2 / R5 — identity+TENANT binding).

    Single-tenant installs use the stable default ``"default"``; a multi-tenant
    deployment sets ``YASHIGANI_TENANT_ID`` per install.  Binding the tenant
    explicitly (rather than role-only) means a future multi-tenant deployment
    cannot open a cross-tenant de-tokenize seam — the map is minted AND retrieved
    under the same tenant, so a handle from tenant A is inert in tenant B."""
    return os.environ.get("YASHIGANI_TENANT_ID", "default").strip() or "default"


async def _admin_in_detokenize_role(account_id: str, role: str) -> bool:
    """RBAC gate: True iff ``account_id`` is a member of the group identified by
    ``role`` (the document's ``detokenize_rbac_role``).

    Matches on group ``id`` OR ``display_name`` so an operator can name the
    detokenize role either way.  Fail-closed: any store error / missing store /
    unknown account → False (deny).  This is the proof-bearing gate the brief
    mandates: an unauthorised user must NOT receive the table.

    LAURA-30-003: ``account_id`` is a UUID; ``RBACStore.get_user_groups`` keys on
    email.  Resolve the email via ``auth_service.get_account_by_id`` before the
    RBAC lookup so the gate actually fires instead of always-denying.
    """
    store = backoffice_state.rbac_store
    if store is None:
        return False
    # Resolve UUID → email via auth service (fail-closed on None auth_service).
    auth_service = backoffice_state.auth_service
    if auth_service is None:
        return False
    try:
        record = await auth_service.get_account_by_id(account_id)
    except Exception as exc:  # pragma: no cover - defensive
        logger.error("RBAC detokenize gate: account lookup failed for %s: %s", account_id, exc)
        return False
    if record is None:
        return False
    email = getattr(record, "email", None) or getattr(record, "username", None)
    if not email:
        return False
    try:
        groups = store.get_user_groups(email)
    except Exception as exc:  # pragma: no cover - defensive
        logger.error("RBAC lookup failed for detokenize gate: %s", exc)
        return False
    for g in groups:
        if g.id == role or getattr(g, "display_name", None) == role:
            return True
    return False


# ── Status / catalogue ─────────────────────────────────────────────────────

@router.get("/status")
async def document_status(session: AdminSession):
    """Feature-flag state + supported/parked format catalogue + action vocab.

    Always 200 (renders the disabled state when dark).  No mutation."""
    cfg = DocumentEnforcementConfig.from_env()
    return {
        "enabled": cfg.enabled,
        "max_document_bytes": cfg.max_document_bytes,
        "max_segments": cfg.max_segments,
        "supported_formats": SUPPORTED_FORMATS,
        "parked_formats": PARKED_FORMATS,
        "actions": ACTIONS,
        "data_classes": DATA_CLASSES,
        "routes": ROUTES,
        "pseudonymize_modes": PSEUDONYMIZE_MODES,
    }


# ── Policy configuration (Redis-backed DocumentPolicyStore + OPA re-push) ─────

@router.get("/policies")
async def list_policies(session: AdminSession):
    return {"policies": _policy_store().list_policies()}


@router.post("/policies", status_code=201)
async def create_policy(body: PolicyRequest, session: StepUpAdminSession):
    """Add an action policy (data-class × format × route → action).

    Step-up gated: mutating enforcement policy is policy-sensitive (mirrors the
    sensitivity-pattern step-up gate — a hijacked session must not silently
    neutralise document enforcement).  Persists to Redis and re-pushes the
    matrix to OPA so the production rego sees it immediately."""
    _require_enabled()
    store = _policy_store()
    try:
        policy = store.add_policy(
            data_class=body.data_class,
            format=body.format,
            route=body.route,
            action=body.action,
            pseudonymize_mode=body.pseudonymize_mode,
            small_set_escalation=body.small_set_escalation,
            description=body.description,
            name=body.name,
            policy_id=body.policy_id,
            user_message=body.user_message,
            code=body.code,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"error": "invalid_policy", "message": str(exc)})
    _push_document_policies()
    return {"status": "ok", "policy": policy}


@router.delete("/policies/{policy_id}")
async def delete_policy(policy_id: str, session: StepUpAdminSession):
    _require_enabled()
    store = _policy_store()
    if not store.remove_policy(policy_id):
        raise HTTPException(status_code=404, detail={"error": "policy_not_found"})
    _push_document_policies()
    return {"status": "ok"}


# ── Inspect a sample document (real pipeline) ──────────────────────────────

@router.post("/inspect")
async def inspect_document(body: InspectRequest, session: AdminSession):
    """Process a sample document END-TO-END THROUGH REAL OPA.

    Flow (the production decision path, not a Python stub):
      1. Extract + enumerate DataMatch[] via the REAL DocumentInspectionPipeline
         (LOG mode — enumeration only; no action applied yet).
      2. Build ``DocumentDecisionInput.to_opa_input()`` and POST it to OPA, which
         evaluates ``policy/document.rego`` against the operator's persisted
         policy matrix → returns the ``action`` (LOG/REDACT/PSEUDONYMIZE/BLOCK)
         with strongest-action precedence + small-set escalation enforced IN REGO.
      3. Apply the OPA-decided action via the pipeline (re-render etc.).

    The action is therefore computed by the ACTUAL OPA engine over the live
    matrix — not by a Python branch.  Returns the verdict summary + per-match
    viewer rows + the self-describing user alert carried from the OPA decision.
    Never returns raw values or the replacer-map handle."""
    _require_enabled()
    pipeline = _build_pipeline()
    request_id = f"doc-{len(_results) + 1}-{body.filename}"
    data_bytes = body.content.encode("utf-8", errors="replace")

    # Resolve the set-scoped salt (opt-in).  The client supplies only the set id;
    # the opaque salt is looked up from the operator's set store and NEVER echoed
    # back.  An unknown set id is a 404 (fail-closed: never silently fall back to
    # the per-file salt when the operator explicitly asked for a set — that would
    # give false cross-file-correlation assurance).
    set_salt: str | None = None
    if body.set_id:
        store = backoffice_state.document_set_store
        if store is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"error": "set_store_unavailable",
                        "message": "Document set store not initialised (Redis db/3 unavailable)."},
            )
        set_salt = store.get_salt(body.set_id)
        if set_salt is None:
            raise HTTPException(
                status_code=404,
                detail={"error": "document_set_not_found", "set_id": body.set_id},
            )

    # --- Step 1+2: enumerate, then ask REAL OPA for the action ---------------
    from yashigani.documents.opa_decision import evaluate_document_decision

    try:
        # First pass: LOG mode to enumerate matches + build the OPA input without
        # applying any transform yet (the action decision is OPA's job).
        enum_result = pipeline.inspect(
            data=data_bytes,
            declared_mime=body.declared_mime,
            request_id=request_id,
            requested_action=DISPOSITION_LOG,
            pseudonymize_mode=body.pseudonymize_mode,
            detokenize_rbac_role=body.detokenize_rbac_role,
            requester_identity=session.account_id,
            tenant=_install_tenant(),
        )
    except Exception as exc:
        envelope, _ = safe_error_envelope(exc, public_message="document inspection failed")
        raise HTTPException(status_code=500, detail=envelope)

    opa_input = enum_result.opa_input
    decision: dict
    if opa_input is None:
        # Enumeration already fail-closed (e.g. extraction incomplete) — honour it
        # as a synthetic BLOCK decision so the contract stays uniform.
        decision = {
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
            route=body.route,
            pseudonymize_mode=body.pseudonymize_mode,
        )

    opa_action = decision.get("action", DISPOSITION_BLOCK)

    # --- Step 3: apply the OPA-decided action --------------------------------
    if opa_action == DISPOSITION_LOG or opa_input is None:
        # LOG (or already fail-closed at enumeration): the first pass IS the result.
        result = enum_result
    else:
        try:
            result = pipeline.inspect(
                data=data_bytes,
                declared_mime=body.declared_mime,
                request_id=request_id,
                requested_action=opa_action,
                pseudonymize_mode=decision.get("pseudonymize_mode", body.pseudonymize_mode),
                detokenize_rbac_role=decision.get("detokenize_rbac_role", body.detokenize_rbac_role),
                set_salt=set_salt,
                requester_identity=session.account_id,
                tenant=_install_tenant(),
            )
        except Exception as exc:
            envelope, _ = safe_error_envelope(exc, public_message="document action failed")
            raise HTTPException(status_code=500, detail=envelope)

    _results[request_id] = result
    return {
        "summary": _result_summary(result),
        "matches": _match_view(result),
        # The OPA decision drives the layman alert (unified user-alert contract:
        # policy_id + user_message + code), carried straight from the rego.
        "opa_decision": {
            "action": opa_action,
            "policy_id": decision.get("policy_id"),
            "code": decision.get("code"),
            "deny": decision.get("deny", []),
            "obligations": decision.get("obligations", []),
        },
        "user_alert": (
            {
                "code": decision.get("code", "DOCUMENT_BLOCKED"),
                "policy_id": decision.get("policy_id", "DOC-ENFORCE-001"),
                "user_message": decision.get(
                    "user_message",
                    "This file was held because it could not be safely cleared: "
                    + (result.block_reason or "policy block"),
                ),
            }
            if result.disposition == DISPOSITION_BLOCK
            else None
        ),
    }


@router.get("/results")
async def list_results(session: AdminSession):
    return {"results": [_result_summary(r) for r in _results.values()]}


@router.get("/results/{request_id}")
async def get_result(request_id: str, session: AdminSession):
    result = _results.get(request_id)
    if result is None:
        raise HTTPException(status_code=404, detail={"error": "result_not_found"})
    return {"summary": _result_summary(result), "matches": _match_view(result)}


# ── Correspondence-table retrieval (mode A) — IDENTITY+TENANT GATED ─────────
#
# G-NEW-2 / R5 (crown-jewel read — reversing pseudonymisation hands back real
# PII).  Three controls stack ON TOP of Laura's role gate:
#   1. **Identity + tenant binding (BOLA/IDOR close)** — only the SAME principal
#      who minted the result, in the SAME tenant, may retrieve the table.  Role
#      membership alone is NOT sufficient: another admin's handle, or a
#      role-downgraded principal, fails closed with 403.
#   2. **Step-up (TOTP)** — the route uses ``StepUpAdminSession``, so a fresh
#      TOTP within the step-up TTL is required at the moment of retrieval (a
#      hijacked session without the second factor cannot reverse PII).
#   3. **Single-use / burn-after-read** — the table is destroyed from the result
#      index on first successful retrieval, so a leaked handle (or a replay)
#      cannot re-retrieve it.


async def _detokenize_gate(result, request_id: str, session, *, surface: str):
    """Shared fail-closed gate for the mode-A table surfaces (G-NEW-2 / R5).

    Returns the (table, role) on success.  Raises the appropriate HTTPException
    (404 / 403) on any failure, NEVER leaking the table contents.  Enforces:
    role membership AND identity+tenant binding (BOLA close).  Step-up is
    enforced by the ``StepUpAdminSession`` dependency on the calling route.

    LAURA-30-003: now async so ``_admin_in_detokenize_role`` can await the
    ``auth_service.get_account_by_id`` call needed to resolve UUID → email.
    """
    table = getattr(result, "correspondence_table", None)
    if table is None:
        # GAP-2 (DP-Y-004 §3.1) — sequential-replay detection: if this
        # request_id was previously burned (a first successful reveal already
        # consumed and burned the table), this is a sequential replay.  Emit
        # the replay audit event so the audit log can distinguish a replay from
        # a request that never had a table.  The response is still 404 — we
        # never leak that the table once existed beyond what the message says.
        if request_id in _burned:
            logger.warning(
                "detokenize SEQUENTIAL REPLAY (%s): account=%s document=%s "
                "— table previously burned; sequential replay detected (DP-Y-004 §3.1)",
                surface, session.account_id, request_id,
            )
            _audit_handle_replay(session, request_id)
        raise HTTPException(
            status_code=404,
            detail={"error": "no_correspondence_table",
                    "message": "Not a mode-A PSEUDONYMIZE result (or already retrieved — single-use)."},
        )

    # GAP-1 (DP-Y-004 §3.1) — plaintext TTL: the CorrespondenceTable carries
    # its own TTL (minted from the same ``map_ttl_s`` as the companion
    # ReplacerMap so the plaintext and the encrypted vault expire together).
    # After expiry the plaintext is invalid; proactively drop it from the
    # result so no subsequent call can retrieve it.
    # Fail-closed: ``table._expired()`` returns True when TTL metadata is
    # missing or zero (a table constructed without TTL is treated as expired,
    # never as fresh).
    if table._expired():
        result.correspondence_table = None  # proactive drop — do not retain
        logger.warning(
            "detokenize TTL EXPIRED (%s): account=%s document=%s "
            "— CorrespondenceTable past TTL; proactive drop (DP-Y-004 §3.1)",
            surface, session.account_id, request_id,
        )
        raise HTTPException(
            status_code=404,
            detail={"error": "no_correspondence_table",
                    "message": "Not a mode-A PSEUDONYMIZE result (or already retrieved — single-use)."},
        )

    role = table.detokenize_rbac_role
    # Coarse role gate (Laura) — still required.
    if not await _admin_in_detokenize_role(session.account_id, role):
        logger.warning(
            "detokenize RBAC DENIED (%s): account=%s document=%s role=%s",
            surface, session.account_id, request_id, role,
        )
        raise HTTPException(
            status_code=403,
            detail={"error": "detokenize_forbidden", "required_role": role},
        )

    # FINE identity+tenant gate (G-NEW-2 / R5 — BOLA/IDOR close).  The table is
    # bound to the requester who minted it + this install's tenant; another
    # principal's handle or a cross-tenant request fails closed.  An UNBOUND
    # table (empty owner) is treated as not-retrievable through this surface.
    # DP-Y-004: constant-time compares (secrets.compare_digest) prevent a timing
    # oracle on the owner / tenant strings — matching the CT pattern already used
    # for the ReplacerMap handle and the mode-B replacer-map path.
    owner = getattr(table, "owner_identity", "") or ""
    bound_tenant = getattr(table, "tenant", "") or ""
    this_tenant = _install_tenant()
    if (
        not owner
        or not secrets.compare_digest(owner, session.account_id)
        or not secrets.compare_digest(bound_tenant, this_tenant)
    ):
        logger.warning(
            "detokenize IDENTITY/TENANT DENIED (%s): account=%s document=%s "
            "(bound owner present=%s tenant_match=%s) — BOLA close",
            surface, session.account_id, request_id, bool(owner),
            bound_tenant == this_tenant,
        )
        raise HTTPException(
            status_code=403,
            detail={"error": "detokenize_forbidden",
                    "reason": "identity_or_tenant_mismatch"},
        )

    # DP-Y-004 — single-use capability-handle gate (atomic consumption).
    #
    # The correspondence table is the re-identification key (GDPR Art. 4(5)); per
    # DP-Y-004 §3.1 a capability handle authorises EXACTLY ONE reveal.  A handle
    # replayed within its TTL by the same authenticated principal must be rejected
    # with a distinct 409 error and audited.
    #
    # Atomicity (asyncio): there is NO ``await`` between the ``if table.consumed``
    # check and the ``table.consumed = True`` assignment below.  In a single-
    # threaded asyncio event loop, a synchronous block is non-preemptible — no
    # other coroutine can observe ``consumed=False`` and set it True in the same
    # window.  The first concurrent caller wins; the second is rejected.
    if table.consumed:
        logger.warning(
            "detokenize REPLAY REJECTED (%s): account=%s document=%s "
            "— handle already consumed (DP-Y-004 single-use gate)",
            surface, session.account_id, request_id,
        )
        _audit_handle_replay(session, request_id)
        raise HTTPException(
            status_code=409,
            detail={
                "error": "handle_already_consumed",
                "message": (
                    "This correspondence table has already been retrieved (single-use). "
                    "A capability handle authorises one reveal and is then consumed "
                    "(DP-Y-004 §3.1). No further access is possible."
                ),
            },
        )
    # Atomically mark consumed (no await above → non-preemptible in asyncio).
    table.consumed = True

    return table, role


def _audit_handle_replay(session, request_id: str) -> None:
    """Emit an audit event for a replayed (already-consumed) capability handle.

    DP-Y-004 §3.1: every replay attempt is audited — the fact of the replay,
    the acting identity, and the document reference.  The handle itself is
    NOT written to the audit record (never-logged invariant)."""
    if backoffice_state.audit_writer is None:
        return
    try:
        from yashigani.audit.schema import ConfigChangedEvent
        backoffice_state.audit_writer.write(ConfigChangedEvent(
            admin_account=session.account_id,
            setting="document_correspondence_table_replay_rejected",
            previous_value="(consumed)",
            new_value=f"document={request_id} replay=rejected single_use=enforced dp_y004=active",
        ))
    except Exception:  # pragma: no cover - audit best-effort; never break the rejection path
        logger.exception("handle-replay audit write failed for document=%s", request_id)


def _audit_table_delivery(session, request_id: str, role: str, row_count: int) -> None:
    if backoffice_state.audit_writer is None:
        return
    try:
        from yashigani.audit.schema import ConfigChangedEvent
        backoffice_state.audit_writer.write(ConfigChangedEvent(
            admin_account=session.account_id,
            setting="document_correspondence_table_delivered",
            previous_value="(sealed)",
            new_value=f"document={request_id} role={role} rows={row_count} single_use=burned",
        ))
    except Exception:  # pragma: no cover - audit best-effort
        logger.exception("table-delivery audit write failed")


def _burn_correspondence_table(result, request_id: str) -> None:
    """Single-use / burn-after-read (G-NEW-2 / R5 / DP-Y-004 §3.1).

    Destroy the correspondence table AND the underlying encrypted ReplacerMap on
    the result so a leaked handle (or a replay of this retrieval) cannot
    re-retrieve the crown jewel within the TTL.  Records ``request_id`` in
    ``_burned`` for sequential-replay detection (GAP-2 fix): a subsequent caller
    who hits ``correspondence_table is None`` for this request_id will be
    audited as a replay rather than silently returning an unrelated-miss 404.
    Idempotent."""
    try:
        result.correspondence_table = None
        _burned.add(request_id)  # GAP-2: mark burned for sequential-replay audit
        rmap = getattr(result, "replacer_map", None)
        if rmap is not None:
            rmap.destroy()
    except Exception:  # pragma: no cover - defensive; never leave a live map
        logger.exception("burn-after-read teardown failed for document=%s", request_id)


@router.get("/results/{request_id}/table")
async def get_correspondence_table(request_id: str, session: StepUpAdminSession):
    """Retrieve the mode-A token→original correspondence table — ONCE.

    IDENTITY+TENANT + STEP-UP + SINGLE-USE gated (G-NEW-2 / R5).  Only the
    principal who minted the result, in this tenant, holding a fresh step-up
    TOTP, may retrieve it — and only once (burn-after-read).  An unauthorised
    admin (wrong role, wrong identity, wrong tenant, or no step-up) gets 403/401
    and NEVER the rows.  The unguessable replacer-map handle is NEVER returned.
    Every retrieval is audited (who, which document, when).
    """
    result = _results.get(request_id)
    if result is None:
        raise HTTPException(status_code=404, detail={"error": "result_not_found"})

    table, role = await _detokenize_gate(result, request_id, session, surface="json")
    rows = [{"token": t, "original": v} for t, v in table.rows.items()]
    row_count = len(table.rows)

    # Authorised — audit, then burn (single-use) BEFORE returning so a concurrent
    # replay cannot race a second retrieval.
    logger.info(
        "correspondence table delivered: account=%s document=%s role=%s rows=%d (single-use, burned)",
        session.account_id, request_id, role, row_count,
    )
    _audit_table_delivery(session, request_id, role, row_count)
    _burn_correspondence_table(result, request_id)

    return {
        "request_id": request_id,
        "detokenize_rbac_role": role,
        "rows": rows,
    }


@router.get("/results/{request_id}/table.csv")
async def download_correspondence_table(request_id: str, session: StepUpAdminSession):
    """Download the mode-A table as CSV — same identity+tenant + step-up +
    single-use gate as the JSON endpoint (G-NEW-2 / R5)."""
    from fastapi.responses import Response

    result = _results.get(request_id)
    if result is None:
        raise HTTPException(status_code=404, detail={"error": "result_not_found"})

    table, role = await _detokenize_gate(result, request_id, session, surface="csv")
    csv_text = table.to_csv()
    row_count = len(table.rows)

    logger.info(
        "correspondence table delivered (csv): account=%s document=%s role=%s rows=%d (single-use, burned)",
        session.account_id, request_id, role, row_count,
    )
    _audit_table_delivery(session, request_id, role, row_count)
    _burn_correspondence_table(result, request_id)

    return Response(
        content=csv_text,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="correspondence-{request_id}.csv"'},
    )


# ── Integrity / splice verify (plan integrity step) ─────────────────────────
#
# Confirm a tokenised output + its mapping file belong to the SAME source
# document, and reject a cross-file splice (a token minted under a different
# document's salt).  The operator can re-run this on a processed result to SEE
# the binding hold (demo/assurance value): the result's recorded ``doc_hash`` is
# recomputed from the original bytes and every mapping token re-derives under it.


@router.get("/results/{request_id}/integrity")
async def verify_result_integrity(request_id: str, session: AdminSession):
    """Surface the integrity/splice-verify result for a processed PSEUDONYMIZE doc.

    Re-runs :meth:`DocumentInspectionPipeline.verify_integrity` over the stored
    result's correspondence mapping against the recorded per-file ``doc_hash`` —
    proving (a) the mapping binds to THIS document's salt (no wrong-file pairing)
    and (b) no foreign-salt (cross-file-splice) tokens are present.  Returns only
    the boolean verdict + the (non-secret) doc_hash + the COUNT of foreign tokens
    — never the mapping cleartext, never a salt secret.

    Only available for a mode-A PSEUDONYMIZE result (which carries a
    correspondence table to re-derive against)."""
    result = _results.get(request_id)
    if result is None:
        raise HTTPException(status_code=404, detail={"error": "result_not_found"})
    table = getattr(result, "correspondence_table", None)
    doc_hash = getattr(result, "doc_hash", None)
    if table is None or doc_hash is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "no_integrity_artefacts",
                    "message": "Integrity verify needs a mode-A PSEUDONYMIZE result with a recorded doc_hash."},
        )

    # DP-Y-004 §3.1 — plaintext TTL: the correspondence table must not be
    # readable via the integrity surface after its TTL expires.  The TTL covers
    # access, not just the table content; an expired table is dropped and a 404
    # is returned — same fail-closed posture as _detokenize_gate (GAP-1).
    if table._expired():
        setattr(result, "correspondence_table", None)  # proactive drop — do not retain
        raise HTTPException(
            status_code=404,
            detail={"error": "no_integrity_artefacts",
                    "message": "Integrity verify needs a mode-A PSEUDONYMIZE result with a recorded doc_hash."},
        )

    # Per-file-salt integrity/splice verify re-derives each token under the
    # recorded per-FILE salt (doc_hash) + the deployment secret; a foreign-salt
    # token would not re-derive (the splice rejection the operator wants to SEE).
    #
    # SET-SCOPED results: the tokens were minted under the SET salt (a secret we
    # deliberately do NOT retain on the result), so re-deriving against doc_hash
    # would falsely flag every token as foreign.  The per-file splice guarantee is
    # intentionally NOT a property of a set (the set salt spans files by design),
    # so we return an explicit "not applicable at set scope" verdict rather than a
    # misleading splice.  This keeps the surface honest (A09 logging/assurance).
    salt_scope = getattr(result, "salt_scope", "file")
    if salt_scope == "set":
        return {
            "request_id": request_id,
            "ok": None,                 # not a binary pass/fail at set scope
            "applicable": False,
            "salt_scope": "set",
            "doc_hash": doc_hash,
            "token_count": len(table.rows),
            "foreign_token_count": None,
            "detail": (
                "Per-file splice verify does not apply to a set-scoped result — "
                "the shared set salt spans files by design (reduced per-file "
                "isolation). Tokens here are NOT bound to a single document."
            ),
        }

    from yashigani.documents.token_scheme import token_matches_doc

    secret = getattr(_build_pipeline(), "_pseudonymize_secret", None)
    foreign = 0
    for token, original in table.rows.items():
        if not token_matches_doc(token, original, doc_hash, secret=secret):
            foreign += 1
    ok = foreign == 0
    return {
        "request_id": request_id,
        "ok": ok,
        "applicable": True,
        "salt_scope": salt_scope,
        # doc_hash is NOT a secret (hash of bytes the holder already has).
        "doc_hash": doc_hash,
        "token_count": len(table.rows),
        # COUNT only — never the token strings or the mapping cleartext.
        "foreign_token_count": foreign,
        "detail": (
            "Output and mapping bind to this document's salt; no spliced/foreign tokens."
            if ok else
            "SPLICE/FOREIGN-SALT DETECTED — one or more tokens do not belong to this document."
        ),
    }


# ── Document SETS — set-scoped-salt control (operator-defined) ──────────────
#
# A "set" shares a PSEUDONYMIZE salt across its member files so the SAME value
# tokenises consistently across the set (legitimate cross-file correlation).
# This REDUCES per-file isolation, so set mutation is STEP-UP gated (same bar as
# policy mutation — a hijacked session must not silently widen the salt scope).
# The salt is a high-entropy secret minted server-side; it is NEVER returned to
# the client (every response uses ``DocumentSetStore.public_view`` which redacts
# it).  Default behaviour (no set) stays per-file isolation.


class SetRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)


class SetMemberRequest(BaseModel):
    member: str = Field(min_length=1, max_length=255)


def _set_store():
    store = backoffice_state.document_set_store
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "set_store_unavailable",
                    "message": "Document set store not initialised (Redis db/3 unavailable)."},
        )
    return store


@router.get("/sets")
async def list_sets(session: AdminSession):
    """List operator-defined document sets (salt REDACTED) + the security note."""
    from yashigani.documents.set_store import SECURITY_NOTE, DocumentSetStore
    store = backoffice_state.document_set_store
    sets = [DocumentSetStore.public_view(s) for s in store.list_sets()] if store else []
    return {"sets": sets, "security_note": SECURITY_NOTE}


@router.post("/sets", status_code=201)
async def create_set(body: SetRequest, session: StepUpAdminSession):
    """Create a document set with a freshly-minted opaque shared salt (step-up).

    The salt is minted server-side (256-bit) and never returned.  Binding files
    to this set reduces per-file isolation — surfaced to the operator via the
    security note."""
    _require_enabled()
    from yashigani.documents.set_store import DocumentSetStore
    store = _set_store()
    try:
        row = store.create_set(name=body.name)
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=422, detail={"error": "invalid_set", "message": str(exc)})
    logger.info("document set created: account=%s set=%s name=%r",
                session.account_id, row["id"], row["name"])
    # public_view REDACTS the salt — the secret never leaves the gateway.
    return {"status": "ok", "set": DocumentSetStore.public_view(row)}


@router.post("/sets/{set_id}/members")
async def add_set_member(set_id: str, body: SetMemberRequest, session: StepUpAdminSession):
    """Add a document/member label to a set (step-up gated)."""
    _require_enabled()
    from yashigani.documents.set_store import DocumentSetStore
    store = _set_store()
    try:
        row = store.add_member(set_id, body.member)
    except KeyError:
        raise HTTPException(status_code=404, detail={"error": "document_set_not_found", "set_id": set_id})
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"error": "invalid_member", "message": str(exc)})
    return {"status": "ok", "set": DocumentSetStore.public_view(row)}


@router.delete("/sets/{set_id}")
async def delete_set(set_id: str, session: StepUpAdminSession):
    """Delete a document set + destroy its shared salt (step-up gated)."""
    _require_enabled()
    store = _set_store()
    if not store.remove_set(set_id):
        raise HTTPException(status_code=404, detail={"error": "document_set_not_found", "set_id": set_id})
    logger.info("document set deleted: account=%s set=%s", session.account_id, set_id)
    return {"status": "ok"}
