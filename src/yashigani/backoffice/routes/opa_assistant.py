"""
Yashigani Backoffice — OPA Policy Assistant routes (v4.0.0 / SEC-OPA-001).

Last updated: 2026-07-01

Supports TWO authoring modes:

  MODE A — RBAC data document (existing flow):
    POST /admin/opa-assistant/suggest      generate RBAC JSON from NL (AdminSession)
    POST /admin/opa-assistant/apply        push RBAC JSON to OPA (StepUpAdminSession)
    POST /admin/opa-assistant/reject       reject, audit log only (AdminSession)
    GET  /admin/opa-assistant/schema       RBAC document JSON schema (AdminSession)

  MODE B — Rego module authoring (NEW, SEC-OPA-001):
    POST /admin/opa-assistant/suggest-rego  NL → Rego module (AdminSession)
    POST /admin/opa-assistant/apply-rego    validate + PUT Rego to OPA (StepUpAdminSession)
    POST /admin/opa-assistant/reject-rego   reject, audit log only (AdminSession)

Security invariants (SEC-OPA-001 / ASVS V6.8.4 / EU AI Act Art.14):
  - /apply and /apply-rego both require StepUpAdminSession (fresh TOTP step-up).
  - All apply actions are written to the tamper-evident audit chain.
  - Generated Rego is VALIDATED server-side (OPA compile check) before apply.
  - Human-in-the-loop: assistant DRAFTS, admin REVIEWS, admin APPLIES. No auto-enact.
  - LAURA-2255-004: raw LLM output is logged server-side only, never returned to client.
"""
from __future__ import annotations

import logging
import re
from typing import Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import AdminSession, StepUpAdminSession
from yashigani.backoffice.state import backoffice_state
from yashigani.common.error_envelope import safe_error_envelope

logger = logging.getLogger(__name__)

router = APIRouter()

# Policy name: lowercase alpha-start, alphanumeric + underscore, 2-41 chars
_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,40}$")
_RESERVED_NAMES = {"yashigani", "rbac", "mcp", "agents", "v1_routing"}


def _validate_policy_name(name: str) -> None:
    if not _NAME_RE.match(name):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "invalid_policy_name",
                "message": (
                    "policy_name must start with a lowercase letter, "
                    "contain only lowercase letters/digits/underscores, 2-41 chars total."
                ),
            },
        )
    if name in _RESERVED_NAMES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "reserved_policy_name", "message": f"'{name}' is a reserved name."},
        )


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


# Mode B — Rego authoring

class SuggestRegoRequest(BaseModel):
    description: str = Field(
        min_length=10,
        max_length=2000,
        description="Natural language description of the policy to author.",
    )
    policy_name: str = Field(
        min_length=2,
        max_length=41,
        description=(
            "Policy slug (lowercase, underscores): becomes clients.<policy_name> in OPA. "
            "Example: 'finance_read_only'."
        ),
    )


class SuggestRegoResponse(BaseModel):
    rego: Optional[str] = None          # The generated Rego module text (NOT JSON)
    valid: bool                          # True if the Rego compiled successfully against OPA
    validation_error: Optional[str] = None
    # FIND-4.0-REGO-001: number of generation+repair attempts made (1 = first try succeeded)
    attempts: int = 1


class ApplyRegoRequest(BaseModel):
    rego: str = Field(
        min_length=10,
        max_length=32000,
        description="The Rego module text to validate and apply.",
    )
    policy_name: str = Field(
        min_length=2,
        max_length=41,
        description="Policy slug — must match the package declaration (clients.<policy_name>).",
    )
    description: str = Field(
        default="",
        max_length=500,
        description="Short description for the audit log.",
    )


class RejectRegoRequest(BaseModel):
    policy_name: str = Field(default="", max_length=41)
    reason: str = Field(default="", max_length=500)


# ---------------------------------------------------------------------------
# Mode A — RBAC data document routes (unchanged)
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
    session: StepUpAdminSession,
):
    """
    Apply a validated RBAC suggestion to OPA.
    The suggestion must pass schema validation before being accepted.
    Admin must have reviewed it before calling this endpoint.

    Requires a fresh step-up TOTP event (ASVS V6.8.4 / EU AI Act Art.14).
    Applying AI-generated policy is a consequential action — equivalent to
    policy promotion/activate which already require step-up.
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


# ---------------------------------------------------------------------------
# Mode B — Rego module authoring routes (SEC-OPA-001)
# ---------------------------------------------------------------------------

_REGO_MAX_REPAIR_ATTEMPTS = 3  # total attempts: 1 initial + up to 2 repairs


@router.post("/suggest-rego", response_model=SuggestRegoResponse)
async def suggest_rego(
    body: SuggestRegoRequest,
    session: AdminSession,
):
    """
    Generate a Rego policy module from a natural language description.

    The generated Rego follows the Yashigani decision contract:
      package clients.<policy_name>
      import rego.v1
      deny contains "..." if { ... }
      default allow := false
      allow if count(deny) == 0
      policy_id / user_message / code / decision (self-describing fields)

    The generated Rego is VALIDATED server-side (OPA compile check) before
    being returned. The admin reviews the Rego text and calls /apply-rego to
    enact it (step-up required). Nothing changes in OPA until /apply-rego.

    FIND-4.0-REGO-001: self-repair loop — if OPA compilation fails, the exact
    compiler error + the broken Rego are fed back to the LLM for a targeted
    syntax fix (up to _REGO_MAX_REPAIR_ATTEMPTS total attempts). The `attempts`
    field in the response tells the admin how many rounds were needed. If all
    attempts fail, rego=None as before, but validation_error now includes the
    attempt count so the UI can say "could not produce valid policy after N tries".
    """
    from yashigani.opa_assistant.rego_generator import RegoGenerator
    from yashigani.opa_assistant.rego_validator import validate_rego_module
    from yashigani.audit.schema import OPAAssistantRegoGeneratedEvent

    policy_name = body.policy_name.strip()
    _validate_policy_name(policy_name)

    ollama_url = getattr(backoffice_state, "ollama_url", "http://ollama:11434")
    opa_url = getattr(backoffice_state, "opa_url", None)
    generator = RegoGenerator(ollama_url=ollama_url)

    # Self-repair loop (FIND-4.0-REGO-001)
    rego_text: Optional[str] = None
    gen_error: Optional[str] = None
    compile_valid: bool = False
    compile_error: Optional[str] = None
    attempt: int = 0
    repair_context: Optional[tuple[str, str]] = None

    for attempt in range(1, _REGO_MAX_REPAIR_ATTEMPTS + 1):
        result = await generator.generate(
            description=body.description,
            policy_slug=policy_name,
            repair_context=repair_context,
        )

        rego_text = result.get("rego")
        gen_error = result.get("error")

        if not rego_text:
            # Structural generation failure — no Rego text at all.
            # No point retrying the repair path without a text to repair.
            logger.info(
                "RegoGenerator: attempt %d/%d — structural failure (%s), aborting repair",
                attempt, _REGO_MAX_REPAIR_ATTEMPTS, gen_error,
            )
            break

        # Server-side OPA compile validation
        compile_valid, compile_error = await validate_rego_module(
            rego_text,
            opa_url=opa_url,
        )

        if compile_valid:
            logger.info(
                "RegoGenerator: attempt %d/%d — compiled OK (policy=%r)",
                attempt, _REGO_MAX_REPAIR_ATTEMPTS, policy_name,
            )
            break

        # Compile failed — if we have attempts left, prepare repair context
        logger.warning(
            "RegoGenerator: attempt %d/%d — OPA compile error: %s",
            attempt, _REGO_MAX_REPAIR_ATTEMPTS, compile_error,
        )
        if attempt < _REGO_MAX_REPAIR_ATTEMPTS:
            repair_context = (compile_error or "compile error", rego_text)

    overall_valid = (rego_text is not None) and compile_valid
    final_error = compile_error or gen_error

    # Audit (tamper-evident chain — ASVS V7.1.2)
    if backoffice_state.audit_writer is not None:
        try:
            backoffice_state.audit_writer.write(
                OPAAssistantRegoGeneratedEvent(
                    admin_account=session.account_id,
                    policy_name=policy_name,
                    description_length=len(body.description),
                    rego_valid=overall_valid,
                    validation_error=final_error,
                )
            )
        except Exception as exc:
            logger.error("Failed to write OPAAssistantRegoGeneratedEvent: %s", exc)

    if not overall_valid:
        # Include attempt count in error so the UI can surface a useful message
        err_with_attempts = (
            f"after_{attempt}_attempt{'s' if attempt != 1 else ''}:"
            f"{final_error or 'generation_failed'}"
        )
        return SuggestRegoResponse(
            rego=None,
            valid=False,
            validation_error=err_with_attempts,
            attempts=attempt,
        )

    return SuggestRegoResponse(
        rego=rego_text,
        valid=True,
        validation_error=None,
        attempts=attempt,
    )


@router.post("/apply-rego", status_code=200)
async def apply_rego(
    body: ApplyRegoRequest,
    session: StepUpAdminSession,
):
    """
    Validate and apply an AI-drafted Rego policy module to OPA.

    Security invariants (SEC-OPA-001 / ASVS V6.8.4 / EU AI Act Art.14):
    - Requires fresh step-up TOTP — this is the accountable human act.
    - Re-validates the Rego via OPA compile before applying. Never applies
      unvalidated Rego regardless of client claim.
    - The applied policy lands at clients/<policy_name> in OPA.
    - The apply event is written to the tamper-evident audit chain.
    """
    from yashigani.opa_assistant.rego_validator import validate_rego_module
    from yashigani.pki.client import internal_httpx_client
    from yashigani.audit.schema import OPAAssistantRegoAppliedEvent
    import httpx as _httpx

    policy_name = body.policy_name.strip()
    _validate_policy_name(policy_name)

    # YSG-RISK-141: the docstring/field description both claim policy_name
    # "must match the package declaration" but that was never enforced —
    # a caller could pass policy_name="my_own_slug" (clean per _validate_policy_name)
    # while the Rego body declared package clients.<some_other_tenant>, silently
    # shadowing another tenant's decision document. Enforce it before validate/apply.
    from yashigani.opa_assistant.rego_package import assert_client_package_scope
    assert_client_package_scope(body.rego, policy_name)

    opa_url = getattr(backoffice_state, "opa_url", None) or "https://policy:8181"

    # Re-validate server-side — never trust client-supplied Rego
    valid, error = await validate_rego_module(body.rego, opa_url=opa_url)
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "rego_compile_error", "message": error},
        )

    # Apply: PUT to OPA at the clients/<policy_name> slot
    put_url = f"{opa_url.rstrip('/')}/v1/policies/clients/{policy_name}"
    try:
        async with internal_httpx_client(timeout=10.0) as client:
            r = await client.put(
                put_url,
                content=body.rego.encode("utf-8"),
                headers={"Content-Type": "text/plain"},
            )
        if r.status_code not in (200, 204):
            logger.error("apply-rego: OPA PUT returned %d for policy %r", r.status_code, policy_name)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail={"error": "opa_apply_failed", "status": r.status_code},
            )
    except _httpx.RequestError as exc:
        logger.error("apply-rego: OPA PUT failed for policy %r: %s", policy_name, exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"error": "opa_unreachable", "message": str(exc)},
        )

    # Audit
    if backoffice_state.audit_writer is not None:
        try:
            backoffice_state.audit_writer.write(
                OPAAssistantRegoAppliedEvent(
                    admin_account=session.account_id,
                    policy_name=policy_name,
                    rego_length=len(body.rego),
                )
            )
        except Exception as exc:
            logger.error("Failed to write OPAAssistantRegoAppliedEvent: %s", exc)

    return {"status": "applied", "policy_name": policy_name}


@router.post("/reject-rego", status_code=200)
async def reject_rego(
    body: RejectRegoRequest,
    session: AdminSession,
):
    """Record that admin rejected an AI-drafted Rego module. Audit log only."""
    from yashigani.audit.schema import OPAAssistantRegoRejectedEvent

    if backoffice_state.audit_writer is not None:
        try:
            backoffice_state.audit_writer.write(
                OPAAssistantRegoRejectedEvent(
                    admin_account=session.account_id,
                    policy_name=body.policy_name,
                    reason=body.reason,
                )
            )
        except Exception as exc:
            logger.error("Failed to write OPAAssistantRegoRejectedEvent: %s", exc)

    return {"status": "rejected"}
