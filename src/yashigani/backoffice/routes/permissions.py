"""
Yashigani Backoffice — Unified Permission Grant admin API (Phase 8).

Manages grants by (subject, resource_type, resource_id, value) against the
unified PermissionStore (yashigani.permissions).

Resource types
--------------
    mcp_server        boolean allow  deny-by-default (blast-radius)
    external_api      boolean allow  deny-by-default (blast-radius)
    cloud_model       boolean allow  deny-by-default (blast-radius); INV-2: allow=True MUST carry opa_policy_ref
    agent             boolean allow  deny-by-default (blast-radius)
    browser_capability tri-state  (managed here + legacy /admin/api/capability-policy)

Scope: org | group | user | agent

Routes
------
    GET    /admin/api/permissions/grants/{scope}/{scope_id}/{resource_type}
        List all grants for (scope, scope_id, resource_type).

    PUT    /admin/api/permissions/grants/{scope}/{scope_id}/{resource_type}/{resource_id}
        Create or update a boolean grant.  Step-up required.
        Rejects cloud_model allow=True without opa_policy_ref (INV-2).

    DELETE /admin/api/permissions/grants/{scope}/{scope_id}/{resource_type}/{resource_id}
        Delete a boolean grant.  Step-up required.

    GET    /admin/api/permissions/effective
        Resolve effective grant for a subject after org-ceiling.
        Query: resource_type, resource_id, org_id, user_id?, agent_id?, group_ids?

    GET    /admin/api/permissions/declarations
        List pending agent manifest declarations not yet granted at org level.

    POST   /admin/api/permissions/declarations
        Submit a pending declaration (egress_allow host, MCP server, cloud model).

    POST   /admin/api/permissions/declarations/{resource_type}/{resource_id}/approve
        Approve a declaration.  Creates the org-level grant.  Human-accountable act.
        Step-up required.

    DELETE /admin/api/permissions/declarations/{resource_type}/{resource_id}
        Reject / remove a pending declaration without granting.  Step-up required.

Auth
----
    GET endpoints:   AdminSession (same as /admin/api/capability-policy and /admin/rbac).
    Write endpoints: StepUpAdminSession (high-value mutation; grants access to resources).
    SPIFFE:          Enforced by SpiffePeerCertMiddleware on the whole backoffice app.
    OPA:             NOT gated — admin plane is not OPA-adjudicated by design.

Audit (Phase 9)
---------------
    Every create/update/delete/approve emits PERMISSION_GRANT_CHANGED to the
    SHA-384 tamper-evident hash chain (NOT plain logs).  Never swallowed.

API↔WebUI parity
-----------------
    Every capability exposed here is reachable from the API.  The WebUI (Phase 10)
    will consume this contract 1:1; no capability exists only in the UI.

Last updated: 2026-06-28T00:00:00+00:00
"""
from __future__ import annotations

import datetime
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator

from yashigani.backoffice.middleware import AdminSession, StepUpAdminSession
from yashigani.backoffice.state import backoffice_state
from yashigani.permissions.model import (
    BLAST_RADIUS_TYPES,
    BooleanGrantValue,
    GrantValidationError,
    ResourceType,
    RESOURCE_TYPE_VALUES,
    validate_boolean_grant,
    validate_resource_type,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# ---------------------------------------------------------------------------
# Valid scope kinds for the admin API
# ---------------------------------------------------------------------------

_VALID_SCOPES = frozenset({"org", "group", "user", "agent"})


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class BooleanGrantBody(BaseModel):
    """
    Request body for PUT /grants/{scope}/{scope_id}/{resource_type}/{resource_id}.

    For blast-radius types (mcp_server, external_api, cloud_model, agent):
        allow:         True = explicitly permit, False = explicitly deny/narrow
        opa_policy_ref: REQUIRED when resource_type=cloud_model AND allow=True (INV-2)

    browser_capability is not supported via this endpoint for boolean values;
    use /admin/api/capability-policy for tri-state browser capability management.
    """

    allow: bool = Field(description="True = permit, False = deny/narrow")
    opa_policy_ref: Optional[str] = Field(
        default=None,
        description=(
            "OPA policy reference governing usage decisions. "
            "REQUIRED for cloud_model + allow=True (INV-2). "
            "Example: 'yashigani/cloud_model/gpt4o'."
        ),
    )


class DeclarationBody(BaseModel):
    """
    Request body for POST /declarations — submit a pending declaration.

    A declaration records that an agent or operator is requesting org-level
    access to a resource.  Approval (POST /declarations/.../approve) is the
    human-accountable step that creates the grant.
    """

    resource_type: str = Field(description=f"One of: {sorted(RESOURCE_TYPE_VALUES)}")
    resource_id: str = Field(
        min_length=1,
        max_length=256,
        description="Resource identifier (server_id, host, model_name, agent_id, capability_name)",
    )
    declared_by: str = Field(
        min_length=1,
        max_length=256,
        description=(
            "Who is declaring this need. "
            "Convention: 'agent:<id>' or the admin account_id. "
            "Free-form but must be non-empty."
        ),
    )
    justification: str = Field(
        default="",
        max_length=1024,
        description="Short human-readable reason why access is needed.",
    )

    @field_validator("resource_type")
    @classmethod
    def _validate_resource_type(cls, v: str) -> str:
        if v not in RESOURCE_TYPE_VALUES:
            raise ValueError(
                f"resource_type must be one of {sorted(RESOURCE_TYPE_VALUES)}"
            )
        return v

    @field_validator("resource_id")
    @classmethod
    def _validate_resource_id(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("resource_id must not be blank")
        return v


class ApproveDeclarationBody(BaseModel):
    """
    Request body for POST /declarations/{resource_type}/{resource_id}/approve.

    For blast-radius types:
        allow:         Typically True for approval.
        opa_policy_ref: REQUIRED when resource_type=cloud_model AND allow=True (INV-2).
    """

    allow: bool = Field(
        default=True,
        description="True = grant org-level permit, False = grant explicit org-level deny.",
    )
    opa_policy_ref: Optional[str] = Field(
        default=None,
        description="REQUIRED for cloud_model + allow=True (INV-2).",
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_perm_store():
    """Resolve the PermissionStore from backoffice_state.  HTTP 503 if not ready."""
    cap_store = getattr(backoffice_state, "capability_policy_store", None)
    if cap_store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "permission_store_not_configured"},
        )
    perm_store = getattr(cap_store, "perm_store", None)
    if perm_store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "permission_store_not_configured"},
        )
    return perm_store


def _parse_scope(scope: str) -> str:
    """Validate scope string.  HTTP 422 on invalid."""
    if scope not in _VALID_SCOPES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={
                "error": "invalid_scope",
                "message": f"scope must be one of {sorted(_VALID_SCOPES)}",
            },
        )
    return scope


def _parse_resource_type(resource_type: str) -> ResourceType:
    """Validate and parse resource_type string.  HTTP 422 on invalid."""
    try:
        return validate_resource_type(resource_type)
    except GrantValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={"error": "invalid_resource_type", "message": str(exc)},
        )


def _grant_to_dict(resource_id: str, grant: BooleanGrantValue) -> dict:
    return {
        "resource_id": resource_id,
        "allow": grant.allow,
        "opa_policy_ref": grant.opa_policy_ref,
    }


def _emit_grant_audit(
    admin_account: str,
    resource_type: ResourceType,
    resource_id: str,
    scope: str,
    scope_id: str,
    change_type: str,  # "set" | "deleted" | "approved"
    grant_value: dict,
) -> None:
    """
    Write a PERMISSION_GRANT_CHANGED event to the tamper-evident SHA-384
    hash chain.  Never swallowed silently — logs on failure.

    NIST AU-2 / AU-12 / SOC 2 CC6.1 / CMMC AU.L2-3.3.2 / ASVS V4.1.3.
    """
    try:
        from yashigani.audit.schema import PermissionGrantChangedEvent, EventType
        writer = backoffice_state.audit_writer
        assert writer is not None  # set unconditionally at startup
        writer.write(PermissionGrantChangedEvent(
            event_type=EventType.PERMISSION_GRANT_CHANGED,
            admin_account=admin_account,
            resource_type=resource_type.value,
            resource_id=resource_id,
            scope=scope,
            scope_id=scope_id,
            change_type=change_type,
            grant_value=grant_value,
        ))
    except Exception as exc:
        logger.error(
            "perm-api: audit write FAILED for %s %s/%s/%s/%s — %s",
            change_type, scope, scope_id, resource_type.value, resource_id, exc,
        )


def _now_iso() -> str:
    return datetime.datetime.now(tz=datetime.timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Grant CRUD routes
# ---------------------------------------------------------------------------

@router.get(
    "/grants/{scope}/{scope_id}/{resource_type}",
    summary="List grants for (scope, scope_id, resource_type)",
    tags=["permissions"],
)
async def list_grants(
    scope: str,
    scope_id: str,
    resource_type: str,
    session: AdminSession,
):
    """
    Return all grants for the given scope tier + resource_type.

    scope:         org | group | user | agent
    scope_id:      org_id, group_id, identity_id (idnt_{12hex} — NOT email), or agent_id
    resource_type: mcp_server | external_api | cloud_model | agent | browser_capability

    For blast-radius types, returns a list of {resource_id, allow, opa_policy_ref}.
    browser_capability is listed as a stub (use /admin/api/capability-policy for full control).
    """
    _parse_scope(scope)
    rt = _parse_resource_type(resource_type)
    store = _get_perm_store()

    if rt not in BLAST_RADIUS_TYPES:
        # browser_capability — list via existing browser_cap interface
        if rt == ResourceType.BROWSER_CAPABILITY:
            if scope == "org":
                policy = store.get_browser_cap_org_policy(scope_id)
            else:
                policy = store.get_browser_cap_partial(scope, scope_id)
            return {
                "scope": scope,
                "scope_id": scope_id,
                "resource_type": resource_type,
                "grants": [
                    {"resource_id": cap, "value": s.value, "allow_list": s.allow_list}
                    for cap, s in sorted(policy.items())
                ],
            }
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={"error": "unsupported_resource_type", "message": f"Unsupported: {resource_type}"},
        )

    grants = store.list_boolean_grants(rt, scope, scope_id)
    return {
        "scope": scope,
        "scope_id": scope_id,
        "resource_type": resource_type,
        "grants": [_grant_to_dict(rid, g) for rid, g in grants],
    }


@router.put(
    "/grants/{scope}/{scope_id}/{resource_type}/{resource_id}",
    summary="Create or update a boolean grant",
    tags=["permissions"],
)
async def put_grant(
    scope: str,
    scope_id: str,
    resource_type: str,
    resource_id: str,
    body: BooleanGrantBody,
    session: StepUpAdminSession,
):
    """
    Create or update a boolean grant for
    (scope, scope_id, resource_type, resource_id).

    Enforces INV-2: cloud_model allow=True MUST carry a non-empty opa_policy_ref.
    Rejects browser_capability (use /admin/api/capability-policy instead).

    Requires step-up (fresh TOTP within YASHIGANI_STEPUP_TTL_SECONDS).
    """
    _parse_scope(scope)
    rt = _parse_resource_type(resource_type)
    store = _get_perm_store()

    # INV-UID: user-scope grants MUST use identity_id (idnt_{12hex}).
    # Email/slug keys are never accepted after 3.1 UID unification.
    if scope == "user":
        if not scope_id.startswith("idnt_"):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={
                    "error": "invalid_scope_id",
                    "message": (
                        "user scope_id must be an identity_id (idnt_{12hex}). "
                        "Email and slug are not accepted. Obtain identity_id from "
                        "GET /admin/api/identities."
                    ),
                },
            )
        _id_reg = getattr(backoffice_state, "identity_registry", None)
        if _id_reg is not None:
            try:
                # BLOCK-2 fix: use get(scope_id) — the real by-identity_id lookup.
                # get_by_identity_id does not exist on IdentityRegistry.
                _exists = _id_reg.get(scope_id)
                if _exists is None:
                    raise HTTPException(
                        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                        detail={
                            "error": "unknown_identity_id",
                            "message": (
                                f"No identity found for scope_id={scope_id!r}. "
                                "Obtain the correct identity_id from GET /admin/api/identities."
                            ),
                        },
                    )
            except HTTPException:
                raise
            except Exception as _reg_exc:
                # Registry/Redis unavailable — fail-closed: reject the write.
                # A silently-accepted grant for a nonexistent identity_id is
                # indistinguishable from a typo'd DENY that silently allows.
                logger.warning(
                    "permissions: identity_registry unavailable during existence "
                    "check for %r — rejecting grant write fail-closed: %s",
                    scope_id, _reg_exc,
                )
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail={
                        "error": "identity_registry_unavailable",
                        "message": (
                            "Cannot verify identity_id — identity registry is "
                            "temporarily unavailable. Retry when the service is healthy."
                        ),
                    },
                )

    if rt not in BLAST_RADIUS_TYPES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={
                "error": "browser_capability_not_supported_here",
                "message": (
                    "browser_capability grants are managed via "
                    "/admin/api/capability-policy — not this endpoint."
                ),
            },
        )

    value = BooleanGrantValue(allow=body.allow, opa_policy_ref=body.opa_policy_ref)
    try:
        validate_boolean_grant(rt, value)
    except GrantValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={"error": "inv2_opa_policy_ref_required", "message": str(exc)},
        )

    try:
        store.set_boolean_grant(rt, scope, scope_id, resource_id, value)
    except GrantValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={"error": "grant_validation_failed", "message": str(exc)},
        )

    grant_value = value.to_dict()
    _emit_grant_audit(
        admin_account=session.account_id,
        resource_type=rt,
        resource_id=resource_id,
        scope=scope,
        scope_id=scope_id,
        change_type="set",
        grant_value=grant_value,
    )

    return {
        "scope": scope,
        "scope_id": scope_id,
        "resource_type": resource_type,
        "resource_id": resource_id,
        **grant_value,
    }


@router.delete(
    "/grants/{scope}/{scope_id}/{resource_type}/{resource_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a boolean grant",
    tags=["permissions"],
)
async def delete_grant(
    scope: str,
    scope_id: str,
    resource_type: str,
    resource_id: str,
    session: StepUpAdminSession,
):
    """
    Delete a boolean grant.

    Returns 204 whether or not the grant existed (idempotent).
    Requires step-up (fresh TOTP within YASHIGANI_STEPUP_TTL_SECONDS).
    """
    _parse_scope(scope)
    rt = _parse_resource_type(resource_type)
    store = _get_perm_store()

    # INV-UID: user-scope grants MUST use identity_id (idnt_{12hex}).
    if scope == "user":
        if not scope_id.startswith("idnt_"):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={
                    "error": "invalid_scope_id",
                    "message": (
                        "user scope_id must be an identity_id (idnt_{12hex}). "
                        "Email and slug are not accepted."
                    ),
                },
            )

    if rt not in BLAST_RADIUS_TYPES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={
                "error": "browser_capability_not_supported_here",
                "message": "Use /admin/api/capability-policy for browser_capability.",
            },
        )

    existed = store.delete_boolean_grant(rt, scope, scope_id, resource_id)
    _emit_grant_audit(
        admin_account=session.account_id,
        resource_type=rt,
        resource_id=resource_id,
        scope=scope,
        scope_id=scope_id,
        change_type="deleted",
        grant_value={"existed": existed},
    )


# ---------------------------------------------------------------------------
# Effective resolution
# ---------------------------------------------------------------------------

@router.get(
    "/effective",
    summary="Resolve effective grant for a subject after org-ceiling",
    tags=["permissions"],
)
async def get_effective(
    session: AdminSession,
    resource_type: str = Query(..., description="Resource type to resolve"),
    resource_id: str = Query(..., description="Resource identifier"),
    org_id: str = Query(default="default", description="Organisation ID (ceiling)"),
    user_id: Optional[str] = Query(
        default=None,
        description=(
            "identity_id (idnt_{12hex}) from the identity registry to resolve for "
            "(user scope). NOT email or slug — those are not accepted after 3.1 UID "
            "unification. Obtain the identity_id from GET /admin/api/identities. "
            "Use agent_id for agent-scope preview. Mutually exclusive with agent_id."
        ),
    ),
    agent_id: Optional[str] = Query(
        default=None,
        description=(
            "Agent ID to resolve for (agent scope). "
            "Mutually exclusive with user_id."
        ),
    ),
    group_ids: Optional[str] = Query(
        default=None,
        description="Comma-separated group IDs for the principal",
    ),
):
    """
    Resolve the effective permission for a subject + resource after applying
    the org-ceiling rules (INV-1 / INV-3).

    Uses the same resolver as the gateway enforcement path.

    Returns the effective_allow value and the full resolution breakdown
    (org grant, group grants, principal grant).

    Supply user_id (stable slug, NOT email) for human-user previews,
    agent_id for agent-scope previews.
    Supplying both is an error (422 ambiguous_principal).

    Email is NOT an authz key — user grants are keyed by user_id.
    """
    rt = _parse_resource_type(resource_type)
    store = _get_perm_store()

    if rt not in BLAST_RADIUS_TYPES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={
                "error": "browser_capability_not_supported_here",
                "message": "Use /admin/api/capability-policy/effective for browser_capability.",
            },
        )

    # Determine principal_scope + principal_id from the admin's preview request.
    # user_id → user scope; agent_id → agent scope; neither → org+group only.
    # If both are supplied, reject (422) — ambiguous request.
    if user_id and agent_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={
                "error": "ambiguous_principal",
                "message": "Provide user_id OR agent_id, not both.",
            },
        )
    if user_id:
        _preview_scope: Optional[str] = "user"
        _preview_id: Optional[str] = user_id
    elif agent_id:
        _preview_scope = "agent"
        _preview_id = agent_id
    else:
        _preview_scope = None
        _preview_id = None

    parsed_groups: list[str] = []
    if group_ids:
        parsed_groups = [g.strip() for g in group_ids.split(",") if g.strip()]

    # Gather raw grant values for the resolution breakdown
    org_grant = store.get_boolean_grant(rt, "org", org_id, resource_id)
    group_grants: list[dict] = []
    for gid in parsed_groups:
        gg = store.get_boolean_grant(rt, "group", gid, resource_id)
        if gg is not None:
            group_grants.append({"group_id": gid, **gg.to_dict()})

    # Collect principal-scope grant for the response
    principal_grant = None
    if _preview_scope in ("user", "agent") and _preview_id:
        pg = store.get_boolean_grant(rt, _preview_scope, _preview_id, resource_id)
        if pg is not None:
            principal_grant = {
                "scope": _preview_scope,
                "scope_id": _preview_id,
                **pg.to_dict(),
            }

    from yashigani.permissions.resolver import resolve_boolean_grant
    effective = resolve_boolean_grant(
        rt,
        resource_id,
        org_id=org_id,
        group_ids=parsed_groups,
        principal_scope=_preview_scope,
        principal_id=_preview_id,
        store=store,
    )

    return {
        "resource_type": resource_type,
        "resource_id": resource_id,
        "org_id": org_id,
        "principal_scope": _preview_scope,
        "principal_id": _preview_id,
        "group_ids": parsed_groups,
        "effective_allow": effective,
        "resolution_path": {
            "org_grant": org_grant.to_dict() if org_grant is not None else None,
            "group_grants": group_grants,
            "principal_grant": principal_grant,
            # Backward-compat alias: user_grant mirrors principal_grant for user scope
            "user_grant": principal_grant if _preview_scope == "user" else None,
            "effective": effective,
        },
    }


# ---------------------------------------------------------------------------
# Declare→approve routes
# ---------------------------------------------------------------------------

@router.get(
    "/declarations",
    summary="List pending agent manifest declarations not yet granted",
    tags=["permissions"],
)
async def list_declarations(
    session: AdminSession,
    resource_type: Optional[str] = Query(
        default=None,
        description="Filter by resource_type (optional)",
    ),
):
    """
    Return all pending declarations that have not yet been approved
    (i.e. no org-level grant exists for the resource).

    A declaration records that an agent or operator has identified a resource
    (MCP server, external API host, cloud model, etc.) that needs org-level
    access.  An admin must review and approve (POST /declarations/.../approve)
    to create the actual grant — this is the human-accountable act per the
    EU AI Act Art.14 human-in-the-loop requirement.
    """
    store = _get_perm_store()

    rt_filter: Optional[ResourceType] = None
    if resource_type is not None:
        rt_filter = _parse_resource_type(resource_type)

    pending = store.get_pending_declarations(rt_filter)

    # Annotate each with whether an org grant already exists
    from yashigani.permissions.resolver import DEFAULT_ORG_ID
    org_id = DEFAULT_ORG_ID
    result = []
    for decl in pending:
        try:
            rt = ResourceType(decl["resource_type"])
            if rt in BLAST_RADIUS_TYPES:
                org_grant = store.get_boolean_grant(rt, "org", org_id, decl["resource_id"])
                org_grant_exists = org_grant is not None
            else:
                org_grant_exists = False  # browser_capability handled differently
        except Exception:
            org_grant_exists = False
        result.append({**decl, "org_grant_exists": org_grant_exists})

    return {"pending": result, "count": len(result)}


@router.post(
    "/declarations",
    status_code=status.HTTP_201_CREATED,
    summary="Submit a pending declaration",
    tags=["permissions"],
)
async def create_declaration(
    body: DeclarationBody,
    session: AdminSession,
):
    """
    Record a pending declaration for (resource_type, resource_id).

    This does NOT create a grant.  An admin must call
    POST /declarations/{resource_type}/{resource_id}/approve to approve it.

    Typical callers:
      - Admin submitting a request for a new cloud model or external API
      - Gateway/seeder auto-declaring a resource that needs explicit org approval
      - Agent manifest processing (egress_allow hosts, declared MCP servers)

    Per EU AI Act Art.14: the system proposes; a human (admin) decides.
    """
    rt = _parse_resource_type(body.resource_type)
    store = _get_perm_store()

    store.declare_pending(
        resource_type=rt,
        resource_id=body.resource_id,
        declared_by=body.declared_by,
        justification=body.justification,
        declared_at=_now_iso(),
    )

    return {
        "resource_type": rt.value,
        "resource_id": body.resource_id,
        "declared_by": body.declared_by,
        "justification": body.justification,
        "status": "pending",
    }


@router.post(
    "/declarations/{resource_type}/{resource_id}/approve",
    summary="Approve a pending declaration — creates org-level grant",
    tags=["permissions"],
)
async def approve_declaration(
    resource_type: str,
    resource_id: str,
    body: ApproveDeclarationBody,
    session: StepUpAdminSession,
):
    """
    Approve a pending declaration.  This is the HUMAN-ACCOUNTABLE ACT:
    - Creates an org-level boolean grant for (resource_type, resource_id).
    - Removes the declaration from the pending queue.
    - Emits PERMISSION_GRANT_CHANGED to the SHA-384 tamper-evident audit chain.

    Enforces INV-2: cloud_model allow=True MUST carry opa_policy_ref.
    Requires step-up (fresh TOTP within YASHIGANI_STEPUP_TTL_SECONDS).

    EU AI Act Art.14: AI recommends (via declaration), human decides (this endpoint).
    The admin's identity is the logged accountable act in the audit chain.
    """
    rt = _parse_resource_type(resource_type)
    store = _get_perm_store()

    if rt not in BLAST_RADIUS_TYPES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={
                "error": "browser_capability_not_supported_here",
                "message": "browser_capability approvals are managed via /admin/api/capability-policy.",
            },
        )

    value = BooleanGrantValue(allow=body.allow, opa_policy_ref=body.opa_policy_ref)
    try:
        validate_boolean_grant(rt, value)
    except GrantValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={"error": "inv2_opa_policy_ref_required", "message": str(exc)},
        )

    from yashigani.permissions.resolver import DEFAULT_ORG_ID
    org_id = DEFAULT_ORG_ID

    try:
        store.set_boolean_grant(rt, "org", org_id, resource_id, value)
    except GrantValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={"error": "grant_validation_failed", "message": str(exc)},
        )

    # Remove the declaration from pending queue (idempotent if not present)
    declaration_removed = store.remove_pending_declaration(rt, resource_id)

    grant_value = value.to_dict()
    _emit_grant_audit(
        admin_account=session.account_id,
        resource_type=rt,
        resource_id=resource_id,
        scope="org",
        scope_id=org_id,
        change_type="approved",
        grant_value=grant_value,
    )

    return {
        "approved": True,
        "resource_type": rt.value,
        "resource_id": resource_id,
        "grant_created": {
            "scope": "org",
            "scope_id": org_id,
            **grant_value,
        },
        "declaration_removed": declaration_removed,
        "actor": session.account_id,
    }


@router.delete(
    "/declarations/{resource_type}/{resource_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Reject / remove a pending declaration without granting",
    tags=["permissions"],
)
async def reject_declaration(
    resource_type: str,
    resource_id: str,
    session: StepUpAdminSession,
):
    """
    Reject and remove a pending declaration.  No grant is created.

    Returns 204 whether or not the declaration existed (idempotent).
    Requires step-up (fresh TOTP within YASHIGANI_STEPUP_TTL_SECONDS).
    """
    rt = _parse_resource_type(resource_type)
    store = _get_perm_store()
    store.remove_pending_declaration(rt, resource_id)
