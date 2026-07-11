"""
Yashigani Backoffice — OPA Policy Assistant routes (v0.7.0).

Last updated: 2026-05-03

Natural language → RBAC JSON suggestion with admin approve/reject flow.
The assistant only generates the data document (JSON).
It never generates or modifies Rego files.

Routes:
  POST /admin/opa-assistant/suggest   — generate suggestion from NL description
  POST /admin/opa-assistant/apply     — apply a validated suggestion to OPA
  POST /admin/opa-assistant/reject    — reject a suggestion (audit log only)
  GET  /admin/opa-assistant/schema    — return RBAC document JSON schema
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import AdminSession
from yashigani.backoffice.state import backoffice_state
from yashigani.common.error_envelope import safe_error_envelope

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class SuggestRequest(BaseModel):
    description: str = Field(
        min_length=10,
        max_length=2000,
        description="Natural language description of the access control requirement.",
    )
    include_current: bool = Field(
        default=True,
        description="If true, pass the current RBAC document to the assistant as context.",
    )


class SuggestResponse(BaseModel):
    suggestion: Optional[dict] = None
    valid: bool
    error: Optional[str] = None
    # LAURA-2255-004: raw_response removed from client-facing schema.
    # Raw LLM output is logged server-side only (opa_assistant/generator.py).


class ApplyRequest(BaseModel):
    suggestion: dict = Field(description="Validated RBAC document to apply.")
    description: str = Field(
        default="",
        max_length=500,
        description="Short description of what this change does (for audit log).",
    )


class RejectRequest(BaseModel):
    reason: str = Field(default="", max_length=500)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/suggest", response_model=SuggestResponse)
async def suggest(
    body: SuggestRequest,
    session: AdminSession,
):
    """
    Generate an RBAC JSON suggestion from a natural language description.
    The suggestion must be reviewed and approved by the admin before anything changes.
    """
    from yashigani.opa_assistant.generator import OPAAssistantGenerator
    from yashigani.opa_assistant.validator import validate_rbac_document
    from yashigani.audit.schema import OPAAssistantSuggestionGeneratedEvent

    # Optionally include the current RBAC document as context
    current_doc = None
    if body.include_current and backoffice_state.rbac_store is not None:
        current_doc = backoffice_state.rbac_store.to_opa_document()

    # Resolve Ollama URL from backoffice state (defaults to standard service URL)
    ollama_url = getattr(backoffice_state, "ollama_url", "http://ollama:11434")
    generator = OPAAssistantGenerator(ollama_url=ollama_url)

    result = await generator.generate(
        description=body.description,
        current_document=current_doc,
    )

    suggestion = result.get("suggestion")
    valid = result.get("valid", False)
    error = result.get("error")

    # Validate schema if generation succeeded
    if valid and suggestion is not None:
        valid, error = validate_rbac_document(suggestion)

    # Audit
    if backoffice_state.audit_writer is not None:
        try:
            backoffice_state.audit_writer.write(
                OPAAssistantSuggestionGeneratedEvent(
                    admin_account=session.account_id,
                    description_length=len(body.description),
                    suggestion_valid=valid,
                    validation_error=error,
                )
            )
        except Exception as exc:
            logger.error("Failed to write OPAAssistantSuggestionGeneratedEvent: %s", exc)

    if not valid:
        return SuggestResponse(
            suggestion=None,
            valid=False,
            error=error or "unknown_error",
        )

    return SuggestResponse(
        suggestion=suggestion,
        valid=True,
    )


@router.post("/apply", status_code=200)
async def apply_suggestion(
    body: ApplyRequest,
    session: AdminSession,
):
    """
    Apply a validated RBAC suggestion to OPA.
    The suggestion must pass schema validation before being accepted.
    Admin must have reviewed it before calling this endpoint.
    """
    from yashigani.opa_assistant.validator import validate_rbac_document
    from yashigani.rbac.opa_push import push_rbac_data
    from yashigani.audit.schema import OPAAssistantSuggestionAppliedEvent

    # Re-validate before applying — never trust client-supplied data
    valid, error = validate_rbac_document(body.suggestion)
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_suggestion", "message": error},
        )

    groups_count = len(body.suggestion.get("groups", {}))
    users_count = len(body.suggestion.get("user_groups", {}))

    # Push to OPA
    try:
        push_rbac_data(
            store=None,
            opa_url=backoffice_state.opa_url,
            raw_document=body.suggestion,
        )
    except Exception as exc:
        logger.error("OPA assistant apply: OPA push failed: %s", exc)
        payload, _ = safe_error_envelope(exc, public_message="opa assistant unavailable", status=502)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=payload,
        )

    # Audit
    if backoffice_state.audit_writer is not None:
        try:
            backoffice_state.audit_writer.write(
                OPAAssistantSuggestionAppliedEvent(
                    admin_account=session.account_id,
                    groups_in_suggestion=groups_count,
                    users_in_suggestion=users_count,
                )
            )
        except Exception as exc:
            logger.error("Failed to write OPAAssistantSuggestionAppliedEvent: %s", exc)

    return {
        "status": "applied",
        "groups_applied": groups_count,
        "users_applied": users_count,
    }


@router.post("/reject", status_code=200)
async def reject_suggestion(
    body: RejectRequest,
    session: AdminSession,
):
    """Record that the admin rejected a suggestion. Audit log only — nothing changes."""
    from yashigani.audit.schema import OPAAssistantSuggestionRejectedEvent

    if backoffice_state.audit_writer is not None:
        try:
            backoffice_state.audit_writer.write(
                OPAAssistantSuggestionRejectedEvent(
                    admin_account=session.account_id,
                    reason=body.reason,
                )
            )
        except Exception as exc:
            logger.error("Failed to write OPAAssistantSuggestionRejectedEvent: %s", exc)

    return {"status": "rejected"}


@router.get("/schema")
async def get_schema(session: AdminSession):
    """Return the RBAC data document JSON schema for client-side validation."""
    from yashigani.opa_assistant.validator import _RBAC_SCHEMA
    return {"schema": _RBAC_SCHEMA}
