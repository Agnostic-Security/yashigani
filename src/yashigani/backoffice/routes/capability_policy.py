"""
Yashigani Backoffice — Capability Policy admin API.

Admin-configurable browser Permissions-Policy scoped like RBAC
(org / per-group / per-user).

Scope precedence (highest → lowest):
    user override  >  most-restrictive group  >  org policy  >  BASELINE (immutable)

Routes (all require an active admin session):
    GET  /admin/api/capability-policy
        Return the DEFAULT ORG policy (org_id = YASHIGANI_ORG_ID, default "default").
    PUT  /admin/api/capability-policy
        Set the DEFAULT ORG policy (all 5 capabilities required).
    GET  /admin/api/capability-policy/orgs/{org_id}
        Return a specific org's policy (all 5 capabilities).
    PUT  /admin/api/capability-policy/orgs/{org_id}
        Set a specific org's policy (all 5 capabilities required).
    DELETE /admin/api/capability-policy/orgs/{org_id}
        Delete a specific org's policy (resolver falls back to BASELINE).
    GET  /admin/api/capability-policy/groups/{group_id}
        Return group override (partial).
    PUT  /admin/api/capability-policy/groups/{group_id}
        Set group override (partial — any subset of 5 capabilities).
    DELETE /admin/api/capability-policy/groups/{group_id}
        Delete group override.
    GET  /admin/api/capability-policy/users/{user}
        Return user override (partial).
    PUT  /admin/api/capability-policy/users/{user}
        Set user override (partial).
    DELETE /admin/api/capability-policy/users/{user}
        Delete user override.
    GET  /admin/api/capability-policy/effective?user=...
        Preview the fully-resolved policy for a user (all 4 tiers applied).

Every mutation emits a CAPABILITY_POLICY_CHANGED audit event to the
tamper-evident SHA-384 hash chain (NOT plain app logs).

Auth: AdminSession (mirrors /admin/rbac pattern exactly — no step-up).
SPIFFE: enforced by the app-level SpiffePeerCertMiddleware.

Last updated: 2026-06-27T00:00:00+00:00
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator

from yashigani.backoffice.middleware import AdminSession
from yashigani.backoffice.state import backoffice_state
from yashigani.capability_policy.model import (
    CAPABILITY_NAMES,
    CAPABILITY_VALUES,
    MAX_ALLOW_LIST_ENTRIES,
    CapabilitySetting,
    CapabilityPolicySet,
    validate_policy_set,
    ValidationError as CapabilityValidationError,
)
from yashigani.capability_policy.resolver import DEFAULT_ORG_ID

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class CapabilitySettingIn(BaseModel):
    """Per-capability setting supplied by the admin."""

    value: str = Field(
        description="'off' | 'self' | 'allow_list'",
    )
    allow_list: list[str] = Field(
        default_factory=list,
        description="HTTPS origins (only used when value='allow_list'). "
                    f"Max {MAX_ALLOW_LIST_ENTRIES} entries.",
    )

    @field_validator("value")
    @classmethod
    def _validate_value(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in CAPABILITY_VALUES:
            raise ValueError(
                f"value must be one of {sorted(CAPABILITY_VALUES)}"
            )
        return v

    @field_validator("allow_list", mode="before")
    @classmethod
    def _validate_allow_list(cls, v) -> list:
        if not isinstance(v, list):
            raise ValueError("allow_list must be a list")
        if len(v) > MAX_ALLOW_LIST_ENTRIES:
            raise ValueError(
                f"allow_list may contain at most {MAX_ALLOW_LIST_ENTRIES} entries"
            )
        return v


# A policy body maps capability names to their settings.
# We use dict[str, CapabilitySettingIn] via a Pydantic model wrapper so
# FastAPI can validate and document the request body cleanly.

class CapabilityPolicyBody(BaseModel):
    """
    A (possibly partial) map of capability names → settings.

    For org PUT all 5 capabilities must be present.
    For group/user PUTs any subset is accepted.
    """
    camera: Optional[CapabilitySettingIn] = None
    microphone: Optional[CapabilitySettingIn] = None
    geolocation: Optional[CapabilitySettingIn] = None
    display_capture: Optional[CapabilitySettingIn] = Field(
        default=None, alias="display-capture"
    )
    fullscreen: Optional[CapabilitySettingIn] = None

    model_config = {"populate_by_name": True}

    def to_capability_dict(self) -> dict[str, CapabilitySetting]:
        """Convert to {capability_name: CapabilitySetting} dropping absent fields."""
        mapping = {
            "camera": self.camera,
            "microphone": self.microphone,
            "geolocation": self.geolocation,
            "display-capture": self.display_capture,
            "fullscreen": self.fullscreen,
        }
        result: dict[str, CapabilitySetting] = {}
        for cap_name, setting_in in mapping.items():
            if setting_in is not None:
                result[cap_name] = CapabilitySetting(
                    value=setting_in.value,
                    allow_list=list(setting_in.allow_list),
                )
        return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_store():
    store = getattr(backoffice_state, "capability_policy_store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "capability_policy_store_not_configured"},
        )
    return store


def _policy_set_to_response(policy: dict[str, CapabilitySetting]) -> dict:
    """Convert a CapabilityPolicySet or partial dict to API response format."""
    return {cap: setting.to_dict() for cap, setting in sorted(policy.items())}


def _validate_and_raise(policy: dict, *, require_all: bool) -> None:
    """Validate and convert HTTP 422 on failure."""
    try:
        validate_policy_set(policy, require_all=require_all)
    except CapabilityValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={"error": "invalid_capability_policy", "message": str(exc)},
        )


def _emit_audit(
    admin_account: str,
    scope: str,
    scope_id: str,
    change_type: str,
    capabilities_changed: list[str],
) -> None:
    """Write a CAPABILITY_POLICY_CHANGED event to the tamper-evident audit chain."""
    try:
        from yashigani.audit.schema import CapabilityPolicyChangedEvent, EventType
        assert backoffice_state.audit_writer is not None  # set unconditionally at startup
        backoffice_state.audit_writer.write(CapabilityPolicyChangedEvent(
            event_type=EventType.CAPABILITY_POLICY_CHANGED,
            admin_account=admin_account,
            scope=scope,
            scope_id=scope_id,
            change_type=change_type,
            capabilities_changed=sorted(capabilities_changed),
        ))
    except Exception as exc:
        logger.error("cap_policy: audit write failed: %s", exc)


# ---------------------------------------------------------------------------
# Default ORG policy routes  (manages YASHIGANI_ORG_ID — "default" in single-instance)
# ---------------------------------------------------------------------------

@router.get(
    "",
    summary="Get the default org capability-policy",
    tags=["capability-policy"],
)
async def get_org_policy(session: AdminSession):
    """
    Return the org-level Permissions-Policy for the default org
    (all 5 capabilities guaranteed).
    """
    store = _get_store()
    policy = store.get_org(DEFAULT_ORG_ID)
    return {"org_id": DEFAULT_ORG_ID, "org": _policy_set_to_response(policy)}


@router.put(
    "",
    summary="Set the default org capability-policy",
    tags=["capability-policy"],
)
async def set_org_policy(
    body: CapabilityPolicyBody,
    session: AdminSession,
):
    """
    Overwrite the org-level Permissions-Policy for the default org.
    All 5 capabilities must be supplied.
    """
    store = _get_store()
    policy = body.to_capability_dict()
    _validate_and_raise(policy, require_all=True)
    store.set_org(DEFAULT_ORG_ID, policy)
    _emit_audit(
        admin_account=session.account_id,
        scope="org",
        scope_id=DEFAULT_ORG_ID,
        change_type="set",
        capabilities_changed=list(policy.keys()),
    )
    return {"org_id": DEFAULT_ORG_ID, "org": _policy_set_to_response(policy)}


# ---------------------------------------------------------------------------
# Addressable ORG policy routes  (GET/PUT/DELETE /orgs/{org_id})
# ---------------------------------------------------------------------------

@router.get(
    "/orgs/{org_id}",
    summary="Get capability-policy for a specific org",
    tags=["capability-policy"],
)
async def get_org_by_id(org_id: str, session: AdminSession):
    """
    Return the Permissions-Policy for *org_id* (all 5 capabilities guaranteed).
    In single-instance, only the default org (YASHIGANI_ORG_ID) exists.
    """
    store = _get_store()
    policy = store.get_org(org_id)
    return {"org_id": org_id, "org": _policy_set_to_response(policy)}


@router.put(
    "/orgs/{org_id}",
    summary="Set capability-policy for a specific org",
    tags=["capability-policy"],
)
async def set_org_by_id(
    org_id: str,
    body: CapabilityPolicyBody,
    session: AdminSession,
):
    """
    Overwrite the org-level Permissions-Policy for *org_id*.
    All 5 capabilities must be supplied.
    """
    store = _get_store()
    policy = body.to_capability_dict()
    _validate_and_raise(policy, require_all=True)
    store.set_org(org_id, policy)
    _emit_audit(
        admin_account=session.account_id,
        scope="org",
        scope_id=org_id,
        change_type="set",
        capabilities_changed=list(policy.keys()),
    )
    return {"org_id": org_id, "org": _policy_set_to_response(policy)}


@router.delete(
    "/orgs/{org_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete capability-policy for a specific org",
    tags=["capability-policy"],
)
async def delete_org_by_id(org_id: str, session: AdminSession):
    """
    Remove the org policy for *org_id*.
    After deletion, the resolver falls back to the immutable BASELINE (self×5).
    """
    store = _get_store()
    store.delete_org(org_id)
    _emit_audit(
        admin_account=session.account_id,
        scope="org",
        scope_id=org_id,
        change_type="deleted",
        capabilities_changed=list(CAPABILITY_NAMES),
    )


# ---------------------------------------------------------------------------
# Group override routes
# ---------------------------------------------------------------------------

@router.get(
    "/groups/{group_id}",
    summary="Get per-group capability-policy override",
    tags=["capability-policy"],
)
async def get_group(group_id: str, session: AdminSession):
    """Return the partial group override. Empty dict if no override is set."""
    store = _get_store()
    overrides = store.get_group(group_id)
    return {"group_id": group_id, "overrides": _policy_set_to_response(overrides)}


@router.put(
    "/groups/{group_id}",
    summary="Set per-group capability-policy override",
    tags=["capability-policy"],
)
async def set_group(
    group_id: str,
    body: CapabilityPolicyBody,
    session: AdminSession,
):
    """
    Set (or replace) a partial group override.
    Only the capabilities present in the body are stored; unset capabilities
    inherit from the org policy at resolution time.
    """
    store = _get_store()
    policy = body.to_capability_dict()
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={"error": "empty_policy", "message": "At least one capability must be set"},
        )
    _validate_and_raise(policy, require_all=False)
    store.set_group(group_id, policy)
    _emit_audit(
        admin_account=session.account_id,
        scope="group",
        scope_id=group_id,
        change_type="set",
        capabilities_changed=list(policy.keys()),
    )
    return {"group_id": group_id, "overrides": _policy_set_to_response(policy)}


@router.delete(
    "/groups/{group_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete per-group capability-policy override",
    tags=["capability-policy"],
)
async def delete_group(group_id: str, session: AdminSession):
    """Remove the group override entirely. The group will fall back to org policy."""
    store = _get_store()
    store.delete_group(group_id)
    _emit_audit(
        admin_account=session.account_id,
        scope="group",
        scope_id=group_id,
        change_type="deleted",
        capabilities_changed=list(CAPABILITY_NAMES),
    )


# ---------------------------------------------------------------------------
# User override routes
# ---------------------------------------------------------------------------

@router.get(
    "/users/{user}",
    summary="Get per-user capability-policy override",
    tags=["capability-policy"],
)
async def get_user(user: str, session: AdminSession):
    """Return the partial user override. Empty dict if no override is set."""
    store = _get_store()
    overrides = store.get_user(user)
    return {"user": user, "overrides": _policy_set_to_response(overrides)}


@router.put(
    "/users/{user}",
    summary="Set per-user capability-policy override",
    tags=["capability-policy"],
)
async def set_user(
    user: str,
    body: CapabilityPolicyBody,
    session: AdminSession,
):
    """
    Set (or replace) a partial user override.
    Only the capabilities present in the body are stored; unset capabilities
    fall through the group / org / baseline chain at resolution time.
    """
    store = _get_store()
    policy = body.to_capability_dict()
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={"error": "empty_policy", "message": "At least one capability must be set"},
        )
    _validate_and_raise(policy, require_all=False)
    store.set_user(user, policy)
    _emit_audit(
        admin_account=session.account_id,
        scope="user",
        scope_id=user,
        change_type="set",
        capabilities_changed=list(policy.keys()),
    )
    return {"user": user, "overrides": _policy_set_to_response(policy)}


@router.delete(
    "/users/{user}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete per-user capability-policy override",
    tags=["capability-policy"],
)
async def delete_user(user: str, session: AdminSession):
    """Remove the user override entirely. The user will fall back to group / org / baseline."""
    store = _get_store()
    store.delete_user(user)
    _emit_audit(
        admin_account=session.account_id,
        scope="user",
        scope_id=user,
        change_type="deleted",
        capabilities_changed=list(CAPABILITY_NAMES),
    )


# ---------------------------------------------------------------------------
# Effective (resolved) preview
# ---------------------------------------------------------------------------

@router.get(
    "/effective",
    summary="Preview resolved capability-policy for a user",
    tags=["capability-policy"],
)
async def get_effective(
    session: AdminSession,
    user: str = Query(..., description="User email to resolve the policy for"),
):
    """
    Return the fully-resolved Permissions-Policy for *user*.

    Applies the full 4-tier precedence chain:
        user override  >  most-restrictive group override  >  org policy  >  baseline

    The org is the default org (YASHIGANI_ORG_ID).  This is the same resolver
    used by the security-headers middleware.
    Use this endpoint to preview the effective policy before pushing changes.
    """
    store = _get_store()
    rbac_store = getattr(backoffice_state, "rbac_store", None)

    from yashigani.capability_policy.resolver import resolve_policy
    effective = resolve_policy(user, rbac_store, store, org_id=DEFAULT_ORG_ID)
    return {
        "user": user,
        "org_id": DEFAULT_ORG_ID,
        "effective": _policy_set_to_response(effective),
    }
