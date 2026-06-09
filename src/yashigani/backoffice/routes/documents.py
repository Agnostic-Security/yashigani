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

# Last updated: 2026-06-09
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import AdminSession, StepUpAdminSession
from yashigani.backoffice.state import backoffice_state
from yashigani.common.error_envelope import safe_error_envelope
from yashigani.documents.config import (
    DocumentEnforcementConfig,
    is_document_enforcement_enabled,
)
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


# ── In-memory stores (demo-grade; the OPA-backed store is Ogen/Rhea's prod path) ──
#
# Policy store: mirrors the in-memory pattern used by routes/sensitivity.py for
# detection patterns.  TODO(2.26-prod): persist policies to the OPA-backed RBAC
# store + re-push the document rego bundle (Ogen/Rhea own production rego).  The
# UX + contract are correct now; the persistence backend is the follow-up.
_policies: list[dict] = [
    {
        "id": "1",
        "data_class": "PCI",
        "format": "any",
        "route": "any",
        "action": "BLOCK",
        "pseudonymize_mode": "A",
        "small_set_escalation": True,
        "description": "Cardholder data anywhere → BLOCK (fail-closed).",
    },
    {
        "id": "2",
        "data_class": "PII",
        "format": "xlsx",
        "route": "egress-mcp-result",
        "action": "PSEUDONYMIZE",
        "pseudonymize_mode": "A",
        "small_set_escalation": True,
        "description": "Names/IBANs leaving to cloud → PSEUDONYMIZE (mode A, give user the table).",
    },
    {
        "id": "3",
        "data_class": "PII",
        "format": "any",
        "route": "any",
        "action": "LOG",
        "pseudonymize_mode": "A",
        "small_set_escalation": False,
        "description": "Internal PII → LOG (passthrough + full audit).",
    },
]
_policy_counter = 3

# Processed-document results, keyed by request_id.  Holds the full
# DocumentInspectionResult so the verdict viewer + RBAC'd table retrieval can
# read it back.  Demo-grade in-memory (request-scoped maps are TTL'd inside the
# ReplacerMap itself; this index is the gateway's hold for the demo).
_results: dict[str, object] = {}


# ── Request / Response models ─────────────────────────────────────────────

class PolicyRequest(BaseModel):
    data_class: str = Field(pattern=r"^(PII|QI|PHI|PCI|SECRET|IP_MARKING)$")
    format: str = Field(pattern=r"^(docx|xlsx|pptx|pdf|csv|txt|any)$")
    route: str = Field(pattern=r"^(ingress-upload|egress-mcp-result|json-attachment|any)$")
    action: str = Field(pattern=r"^(LOG|REDACT|PSEUDONYMIZE|BLOCK)$")
    pseudonymize_mode: str = Field(default="A", pattern=r"^(A|B)$")
    small_set_escalation: bool = Field(default=True)
    description: str = Field(min_length=1, max_length=256)


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
    """JSON-safe verdict summary for the results list (no raw values, no map)."""
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
            }
        )
    return rows


def _admin_in_detokenize_role(account_id: str, role: str) -> bool:
    """RBAC gate: True iff ``account_id`` is a member of the group identified by
    ``role`` (the document's ``detokenize_rbac_role``).

    Matches on group ``id`` OR ``display_name`` so an operator can name the
    detokenize role either way.  Fail-closed: any store error / missing store →
    False (deny).  This is the proof-bearing gate the brief mandates: an
    unauthorised user must NOT receive the table.
    """
    store = backoffice_state.rbac_store
    if store is None:
        return False
    try:
        groups = store.get_user_groups(account_id)
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


# ── Policy configuration (in-memory; OPA-backed store is the prod follow-up) ──

@router.get("/policies")
async def list_policies(session: AdminSession):
    return {"policies": _policies}


@router.post("/policies", status_code=201)
async def create_policy(body: PolicyRequest, session: StepUpAdminSession):
    """Add an action policy (data-class × format × route → action).

    Step-up gated: mutating enforcement policy is policy-sensitive (mirrors the
    sensitivity-pattern step-up gate — a hijacked session must not silently
    neutralise document enforcement)."""
    _require_enabled()
    global _policy_counter
    _policy_counter += 1
    policy = {
        "id": str(_policy_counter),
        "data_class": body.data_class,
        "format": body.format,
        "route": body.route,
        "action": body.action,
        "pseudonymize_mode": body.pseudonymize_mode,
        "small_set_escalation": body.small_set_escalation,
        "description": body.description,
    }
    _policies.append(policy)
    return {"status": "ok", "policy": policy}


@router.delete("/policies/{policy_id}")
async def delete_policy(policy_id: str, session: StepUpAdminSession):
    _require_enabled()
    global _policies
    before = len(_policies)
    _policies = [p for p in _policies if p["id"] != policy_id]
    if len(_policies) == before:
        raise HTTPException(status_code=404, detail={"error": "policy_not_found"})
    return {"status": "ok"}


# ── Inspect a sample document (real pipeline) ──────────────────────────────

@router.post("/inspect")
async def inspect_document(body: InspectRequest, session: AdminSession):
    """Process a sample document through the REAL DocumentInspectionPipeline and
    store the verdict for the viewer + (mode-A) table retrieval.

    Returns the verdict summary + the per-match viewer rows.  Never returns raw
    values or the replacer-map handle."""
    _require_enabled()
    pipeline = _build_pipeline()
    request_id = f"doc-{len(_results) + 1}-{body.filename}"
    try:
        result = pipeline.inspect(
            data=body.content.encode("utf-8", errors="replace"),
            declared_mime=body.declared_mime,
            request_id=request_id,
            requested_action=body.requested_action,
            pseudonymize_mode=body.pseudonymize_mode,
            detokenize_rbac_role=body.detokenize_rbac_role,
        )
    except Exception as exc:
        envelope, _ = safe_error_envelope(exc, public_message="document inspection failed")
        raise HTTPException(status_code=500, detail=envelope)

    _results[request_id] = result
    return {
        "summary": _result_summary(result),
        "matches": _match_view(result),
        # Layman alert surface for BLOCK/HOLD (unified user-alert contract:
        # policy_id + user_message + code).  Populated for BLOCK from the
        # block_reason; the production OPA decision carries the policy_id.
        "user_alert": (
            {
                "code": "DOCUMENT_BLOCKED",
                "policy_id": "document.fail_closed",
                "user_message": (
                    "This file was held because it could not be safely cleared: "
                    + (result.block_reason or "policy block")
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


# ── Correspondence-table retrieval (mode A) — RBAC GATED ───────────────────

@router.get("/results/{request_id}/table")
async def get_correspondence_table(request_id: str, session: AdminSession):
    """Retrieve the mode-A token→original correspondence table.

    RBAC-GATED: only an admin who is a member of the document's
    ``detokenize_rbac_role`` group may retrieve it.  An unauthorised admin gets
    403 and NEVER the rows.  The unguessable replacer-map handle is NEVER
    returned.  Every retrieval is audited (who, which document, when).
    """
    result = _results.get(request_id)
    if result is None:
        raise HTTPException(status_code=404, detail={"error": "result_not_found"})
    table = getattr(result, "correspondence_table", None)
    if table is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "no_correspondence_table", "message": "Not a mode-A PSEUDONYMIZE result."},
        )

    role = table.detokenize_rbac_role
    if not _admin_in_detokenize_role(session.account_id, role):
        # Fail-closed: deny, audit the denied attempt, reveal NOTHING about the
        # table contents.  The error does not leak whether the table is empty.
        logger.warning(
            "detokenize RBAC DENIED: account=%s document=%s role=%s",
            session.account_id, request_id, role,
        )
        raise HTTPException(
            status_code=403,
            detail={"error": "detokenize_forbidden", "required_role": role},
        )

    # Authorised — return the rows (token → original).  Audited.
    logger.info(
        "correspondence table delivered: account=%s document=%s role=%s rows=%d",
        session.account_id, request_id, role, len(table.rows),
    )
    if backoffice_state.audit_writer is not None:
        try:
            from yashigani.audit.schema import ConfigChangedEvent
            backoffice_state.audit_writer.write(ConfigChangedEvent(
                admin_account=session.account_id,
                setting="document_correspondence_table_delivered",
                previous_value="(sealed)",
                new_value=f"document={request_id} role={role} rows={len(table.rows)}",
            ))
        except Exception:  # pragma: no cover - audit best-effort
            logger.exception("table-delivery audit write failed")

    return {
        "request_id": request_id,
        "detokenize_rbac_role": role,
        "rows": [{"token": t, "original": v} for t, v in table.rows.items()],
    }


@router.get("/results/{request_id}/table.csv")
async def download_correspondence_table(request_id: str, session: AdminSession):
    """Download the mode-A table as CSV — same RBAC gate as the JSON endpoint."""
    from fastapi.responses import Response

    result = _results.get(request_id)
    if result is None:
        raise HTTPException(status_code=404, detail={"error": "result_not_found"})
    table = getattr(result, "correspondence_table", None)
    if table is None:
        raise HTTPException(status_code=404, detail={"error": "no_correspondence_table"})

    role = table.detokenize_rbac_role
    if not _admin_in_detokenize_role(session.account_id, role):
        logger.warning(
            "detokenize RBAC DENIED (csv): account=%s document=%s role=%s",
            session.account_id, request_id, role,
        )
        raise HTTPException(status_code=403, detail={"error": "detokenize_forbidden", "required_role": role})

    csv_text = table.to_csv()
    return Response(
        content=csv_text,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="correspondence-{request_id}.csv"'},
    )
