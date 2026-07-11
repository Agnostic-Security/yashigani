"""
Yashigani Backoffice — SCIM 2.0 inbound provisioning routes.

Implements a subset of the SCIM 2.0 protocol (RFC 7643 / RFC 7644) for
inbound synchronisation from an external Identity Provider (IdP).

Supported operations:
  Users:  GET (list + filter), POST (provision), DELETE (deprovision)
  Groups: GET (list), POST (create), PATCH (add/remove members), DELETE

This is read-only from the IdP's perspective — no SCIM write-back is
performed.  All provisioning operations modify the RBACStore (Redis db/3)
and trigger an OPA data push.

Security:
  All endpoints require an admin session.  The SCIM base path is served
  on the backoffice app (port 8443) and is never exposed via Caddy.

  ACS gap #95 (injection): the SCIM filter query param is now a typed
  FastAPI Query param with max_length=256 instead of being read via
  request.query_params.get() which bypassed Pydantic validation.
  _parse_filter_email() additionally validates the extracted value
  matches the email format before accepting it.

Last updated: 2026-05-09T00:00:00+01:00
"""

from __future__ import annotations

import logging
import re
import uuid
from typing import Optional, Any

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel

from yashigani.backoffice.middleware import AdminSession
from yashigani.backoffice.state import backoffice_state
from yashigani.backoffice.routes.rbac import _push
from yashigani.rbac.model import RBACGroup
from yashigani.licensing.enforcer import (
    require_feature,
    check_end_user_limit,
    count_canonical_end_users,
    LicenseFeatureGated,
    LicenseLimitExceeded,
    license_feature_gated_response,
    license_limit_exceeded_response,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# SCIM schema URNs
_URN_USER = "urn:ietf:params:scim:schemas:core:2.0:User"
_URN_GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group"
_URN_LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
_URN_PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp"


# ---------------------------------------------------------------------------
# SCIM Pydantic models
# ---------------------------------------------------------------------------


class ScimName(BaseModel):
    formatted: Optional[str] = None
    givenName: Optional[str] = None
    familyName: Optional[str] = None


class ScimEmail(BaseModel):
    value: str
    primary: bool = True
    type: str = "work"


class ScimUserRequest(BaseModel):
    schemas: list[str] = [_URN_USER]
    userName: str
    name: Optional[ScimName] = None
    emails: Optional[list[ScimEmail]] = None
    active: bool = True


class ScimGroupMember(BaseModel):
    value: str  # group_id or user email used as $ref
    display: Optional[str] = None


class ScimGroupRequest(BaseModel):
    schemas: list[str] = [_URN_GROUP]
    displayName: str
    members: Optional[list[ScimGroupMember]] = None


class ScimPatchOperation(BaseModel):
    op: str  # "add" | "remove" | "replace"
    path: Optional[str] = None
    value: Optional[Any] = None


class ScimPatchRequest(BaseModel):
    schemas: list[str] = [_URN_PATCH]
    Operations: list[ScimPatchOperation]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_store():
    store = backoffice_state.rbac_store
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "rbac_store_not_configured"},
        )
    return store


def _resolve_identity_id_from_email(email: str, raise_on_not_found: bool = True) -> Optional[str]:
    """
    Resolve email → identity_id (idnt_{12hex}) via the identity registry.

    3.1 UID unification: RBAC store is keyed by identity_id after migration.
    SCIM callers that receive email addresses from the IdP must resolve them
    before touching the store.

    raise_on_not_found=False: returns None instead of raising 404.  Used for
    idempotency checks where "not in registry" == "not yet provisioned".

    Raises HTTPException(503) if the identity registry is unavailable.
    Raises HTTPException(404) if the email has no identity_id (and raise_on_not_found=True).
    """
    id_reg = getattr(backoffice_state, "identity_registry", None)
    if id_reg is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "identity_registry_not_configured"},
        )
    try:
        rec = id_reg.get_by_email(email)
    except Exception as exc:
        logger.warning("scim: identity registry lookup failed for email=%r: %s", email, exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "identity_registry_unavailable"},
        )
    if rec is None:
        if not raise_on_not_found:
            return None
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "identity_not_found",
                "message": (
                    f"No identity found for email={email!r}. "
                    "The user must log in at least once to obtain an identity_id "
                    "before SCIM membership can be assigned."
                ),
            },
        )
    identity_id = (
        rec.get("identity_id") if isinstance(rec, dict) else getattr(rec, "identity_id", None)
    )
    if not identity_id:
        if not raise_on_not_found:
            return None
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={
                "error": "identity_missing_id",
                "message": f"Identity record for email={email!r} has no identity_id field.",
            },
        )
    return identity_id


def _user_resource(email: str, groups: list[RBACGroup]) -> dict:
    return {
        "schemas": [_URN_USER],
        "id": email,
        "userName": email,
        "emails": [{"value": email, "primary": True, "type": "work"}],
        "groups": [{"value": g.id, "display": g.display_name} for g in groups],
        "active": True,
        "meta": {"resourceType": "User"},
    }


def _group_resource(group: RBACGroup) -> dict:
    return {
        "schemas": [_URN_GROUP],
        "id": group.id,
        "displayName": group.display_name,
        "members": [{"value": email, "display": email} for email in sorted(group.members)],
        "meta": {"resourceType": "Group"},
    }


def _list_response(resources: list[dict]) -> dict:
    return {
        "schemas": [_URN_LIST],
        "totalResults": len(resources),
        "startIndex": 1,
        "itemsPerPage": len(resources),
        "Resources": resources,
    }


_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")

# ACS gap #95 (injection): max length guard on SCIM filter value.
_SCIM_FILTER_MAX_LEN = 256


def _parse_filter_email(filter_str: str) -> Optional[str]:
    """
    Parse a simple SCIM filter: 'userName eq "user@example.com"'
    Returns the email value or None if the filter cannot be parsed or fails
    format validation.

    ACS gap #95 (injection): added email regex validation on the extracted
    value so unsanitised SCIM filter strings cannot propagate into downstream
    lookups as arbitrary strings.  The filter is not used in SQL (the store
    uses an in-memory dict), but validating the shape of the extracted value
    reduces the attack surface for future refactors and satisfies OWASP
    ASVS V5.1.1 / CWE-20 input validation requirements.
    """
    if not filter_str or len(filter_str) > _SCIM_FILTER_MAX_LEN:
        return None
    try:
        parts = filter_str.strip().split()
        if len(parts) == 3 and parts[0].lower() == "username" and parts[1].lower() == "eq":
            candidate = parts[2].strip("\"'")
            # Validate the extracted value matches email format before accepting.
            if _EMAIL_RE.match(candidate):
                return candidate
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# User endpoints
# ---------------------------------------------------------------------------


@router.get("/Users")
async def scim_list_users(
    session: AdminSession,
    filter: Optional[str] = Query(  # noqa: A002  — SCIM spec uses 'filter'
        default=None,
        description="SCIM filter expression, e.g. 'userName eq \"user@example.com\"'",
        max_length=_SCIM_FILTER_MAX_LEN,
        alias="filter",
    ),
):
    """
    List SCIM users with optional filter.

    ACS gap #95 (injection): filter is now a typed FastAPI Query param with
    max_length=256, replacing the previous raw request.query_params.get()
    which bypassed Pydantic/FastAPI input validation (OWASP ASVS V5.1.1).
    """
    store = _get_store()
    filter_param = filter or ""
    all_groups = store.list_groups()

    # Build an index: email → [group, ...]
    user_index: dict[str, list[RBACGroup]] = {}
    for group in all_groups:
        for email in group.members:
            user_index.setdefault(email, []).append(group)

    if filter_param:
        target_email = _parse_filter_email(filter_param)
        if target_email and target_email in user_index:
            resources = [_user_resource(target_email, user_index[target_email])]
        elif target_email:
            resources = []
        else:
            # Unsupported filter — return all (safe fallback)
            resources = [_user_resource(e, g) for e, g in user_index.items()]
    else:
        resources = [_user_resource(e, g) for e, g in user_index.items()]

    return _list_response(resources)


@router.post("/Users", status_code=status.HTTP_201_CREATED)
async def scim_provision_user(
    body: ScimUserRequest,
    session: AdminSession,
):
    """
    Provision a user.  If the user is already a member of groups, this is
    a no-op (idempotent).  The userName field is treated as the user's email.
    Membership is assigned separately via SCIM Group PATCH.
    """
    try:
        require_feature("scim")
    except LicenseFeatureGated as exc:
        from fastapi.responses import JSONResponse

        return JSONResponse(status_code=402, content=license_feature_gated_response(exc))
    store = _get_store()
    email = body.userName

    # 3.1 UID unification: resolve email → identity_id before querying the store.
    # raise_on_not_found=False: if the user has no identity_id yet (not yet logged
    # in), treat as "not yet provisioned" (empty groups).  The provision below will
    # still fail at add_member time if identity_id cannot be resolved.
    _scim_iid = _resolve_identity_id_from_email(email, raise_on_not_found=False)
    existing_groups = store.get_user_groups(_scim_iid) if _scim_iid else []

    # SoD-002b: reject SCIM provision if an admin account already exists with
    # this email. Admins and users must be strictly separate identity stores.
    # NIST AC-5 / SOC 2 CC6.3 / ISO 27001 A.5.16 / CMMC AC.L2-3.1.4 / ASVS V4.1.2.
    _sod002b_admin_record = None
    try:
        _auth_svc = getattr(backoffice_state, "auth_service", None)
        if _auth_svc is not None and hasattr(_auth_svc, "get_account_by_email"):
            _sod002b_admin_record = await _auth_svc.get_account_by_email(email)
            if _sod002b_admin_record is not None and _sod002b_admin_record.account_tier != "admin":
                _sod002b_admin_record = None  # only block on admin collision
        elif _auth_svc is not None:
            # Fallback: try username lookup (admin usernames are emails)
            _sod002b_admin_record = await _auth_svc.get_account(email)
            if _sod002b_admin_record is not None and _sod002b_admin_record.account_tier != "admin":
                _sod002b_admin_record = None
    except Exception as _exc:
        logger.warning("SoD-002b: admin collision check failed: %s", _exc)

    if _sod002b_admin_record is not None:
        import hashlib as _hashlib
        _email_hash = _hashlib.sha256(email.strip().lower().encode()).hexdigest()
        from yashigani.audit.schema import ScimProvisionRejectedAdminExistsEvent
        _writer = getattr(backoffice_state, "audit_writer", None)
        if _writer is not None:
            _writer.write(ScimProvisionRejectedAdminExistsEvent(
                acting_admin_account_id=session.account_id,
                email_hash=_email_hash,
            ))
        logger.warning(
            "SoD-002b: SCIM provision rejected — admin account exists for email_hash=%s",
            _email_hash,
        )
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=409,
            content={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                "detail": (
                    "An admin account already exists with this email address. "
                    "Admin and user identities must be strictly separate. "
                    "The user must register with a different email."
                ),
                "status": "409",
                "scimType": "uniqueness",
            },
        )

    # LAURA-LICENSE-03 / GROUP-2-5: enforce end-user seat limit for new SCIM
    # provisions. A user with no existing groups is being provisioned for the
    # first time — check the limit before creating. Existing members are an
    # idempotent no-op and bypass this check.
    if not existing_groups:
        try:
            check_end_user_limit(count_canonical_end_users())
        except LicenseLimitExceeded as exc:
            from fastapi.responses import JSONResponse

            return JSONResponse(
                status_code=402,
                content=license_limit_exceeded_response(exc),
            )

    return _user_resource(email, existing_groups)


@router.delete("/Users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def scim_deprovision_user(
    user_id: str,
    session: AdminSession,
):
    """
    Deprovision a user by removing them from all groups.
    user_id is treated as the user's email address.
    """
    try:
        require_feature("scim")
    except LicenseFeatureGated as exc:
        from fastapi.responses import JSONResponse

        return JSONResponse(status_code=402, content=license_feature_gated_response(exc))
    store = _get_store()
    email = user_id

    # 3.1 UID unification: resolve email → identity_id before querying the store.
    # If the user has no identity_id (never logged in), they have no RBAC groups
    # to remove — treat as idempotent success.
    _scim_iid = _resolve_identity_id_from_email(email, raise_on_not_found=False)
    if _scim_iid is None:
        return  # nothing to deprovision

    groups = store.get_user_groups(_scim_iid)
    for group in groups:
        try:
            store.remove_member(group.id, _scim_iid)
        except KeyError:
            pass

    from yashigani.audit.schema import RBACMemberEvent, EventType

    assert backoffice_state.audit_writer is not None  # set unconditionally at startup
    for group in groups:
        backoffice_state.audit_writer.write(
            RBACMemberEvent(
                event_type=EventType.RBAC_MEMBER_REMOVED,
                group_id=group.id,
                email=email,
                admin_account=f"scim:{session.account_id}",
            )
        )

    if groups:
        _push(store, f"scim:{session.account_id}")


# ---------------------------------------------------------------------------
# Group endpoints
# ---------------------------------------------------------------------------


@router.get("/Groups")
async def scim_list_groups(session: AdminSession):
    store = _get_store()
    return _list_response([_group_resource(g) for g in store.list_groups()])


@router.post("/Groups", status_code=status.HTTP_201_CREATED)
async def scim_create_group(
    body: ScimGroupRequest,
    session: AdminSession,
):
    try:
        require_feature("scim")
    except LicenseFeatureGated as exc:
        from fastapi.responses import JSONResponse

        return JSONResponse(status_code=402, content=license_feature_gated_response(exc))
    store = _get_store()

    # 3.1 UID unification: SCIM members carry email addresses from the IdP.
    # Resolve each email → identity_id (idnt_{12hex}) before storing in the group.
    # Members that cannot be resolved are skipped with a warning (fail-partial:
    # the group is still created; unresolvable members should be re-added once
    # the user logs in and obtains an identity_id).
    initial_members: set[str] = set()
    if body.members:
        for m in body.members:
            if "@" in m.value:
                _iid = _resolve_identity_id_from_email(m.value, raise_on_not_found=False)
                if _iid:
                    initial_members.add(_iid)
                else:
                    logger.warning(
                        "scim create_group: cannot resolve email=%r to identity_id "
                        "— member skipped; add them after first login.",
                        m.value,
                    )

    group = RBACGroup(
        id=str(uuid.uuid4()),
        display_name=body.displayName,
        members=initial_members,
        allowed_resources=[],  # patterns must be configured via the RBAC admin API
    )
    store.add_group(group)

    from yashigani.audit.schema import RBACGroupEvent, EventType

    assert backoffice_state.audit_writer is not None  # set unconditionally at startup
    backoffice_state.audit_writer.write(
        RBACGroupEvent(
            event_type=EventType.RBAC_GROUP_CREATED,
            group_id=group.id,
            group_name=group.display_name,
            admin_account=f"scim:{session.account_id}",
            change_detail=f"created via SCIM with {len(initial_members)} initial members",
        )
    )
    _push(store, f"scim:{session.account_id}")
    return _group_resource(group)


@router.patch("/Groups/{group_id}")
async def scim_patch_group(
    group_id: str,
    body: ScimPatchRequest,
    session: AdminSession,
):
    """
    SCIM PATCH — supports add/remove on the 'members' attribute.

    Each Operation value for 'members' must be a list of:
        [{"value": "<email>", "display": "<optional>"}, ...]
    """
    try:
        require_feature("scim")
    except LicenseFeatureGated as exc:
        from fastapi.responses import JSONResponse

        return JSONResponse(status_code=402, content=license_feature_gated_response(exc))
    store = _get_store()
    group = store.get_group(group_id)
    if group is None:
        raise HTTPException(status_code=404, detail={"error": "group_not_found"})

    added: list[str] = []
    removed: list[str] = []

    for op in body.Operations:
        op_name = op.op.lower()
        path = (op.path or "").lower()

        # Only handle the 'members' path; ignore unsupported paths silently
        if path and path != "members":
            continue

        values = op.value if isinstance(op.value, list) else [op.value] if op.value else []

        if op_name == "add":
            for item in values:
                email = item.get("value", "") if isinstance(item, dict) else str(item)
                if "@" in email:
                    # 3.1 UID unification: resolve email → identity_id before calling store.
                    _iid = _resolve_identity_id_from_email(email, raise_on_not_found=False)
                    if not _iid:
                        logger.warning(
                            "scim patch_group add: cannot resolve email=%r to identity_id — skipped",
                            email,
                        )
                        continue
                    try:
                        store.add_member(group_id, _iid)
                        added.append(email)
                    except KeyError:
                        pass

        elif op_name == "remove":
            for item in values:
                email = item.get("value", "") if isinstance(item, dict) else str(item)
                if "@" in email:
                    # 3.1 UID unification: resolve email → identity_id before calling store.
                    _iid = _resolve_identity_id_from_email(email, raise_on_not_found=False)
                    if not _iid:
                        logger.warning(
                            "scim patch_group remove: cannot resolve email=%r to identity_id — skipped",
                            email,
                        )
                        continue
                    try:
                        store.remove_member(group_id, _iid)
                        removed.append(email)
                    except KeyError:
                        pass

        elif op_name == "replace":
            # Replace replaces the full members list.
            # 3.1 UID unification: resolve all incoming emails → identity_ids.
            # group.members is now a set of identity_ids after the 3.1 migration.
            new_emails: set[str] = set()
            new_identity_ids: set[str] = set()
            for item in values:
                email = item.get("value", "") if isinstance(item, dict) else str(item)
                if "@" in email:
                    new_emails.add(email)
                    _iid = _resolve_identity_id_from_email(email, raise_on_not_found=False)
                    if _iid:
                        new_identity_ids.add(_iid)
                    else:
                        logger.warning(
                            "scim patch_group replace: cannot resolve email=%r to identity_id — skipped",
                            email,
                        )
            # Remove identity_ids no longer in the requested set
            for _iid in list(group.members - new_identity_ids):
                try:
                    store.remove_member(group_id, _iid)
                    removed.append(_iid)
                except KeyError:
                    pass
            # Add new identity_ids
            for _iid in new_identity_ids - group.members:
                try:
                    store.add_member(group_id, _iid)
                    added.append(_iid)
                except KeyError:
                    pass

    # Re-fetch after mutations
    group = store.get_group(group_id)

    from yashigani.audit.schema import RBACGroupEvent, EventType

    assert backoffice_state.audit_writer is not None  # set unconditionally at startup
    if added or removed:
        backoffice_state.audit_writer.write(
            RBACGroupEvent(
                event_type=EventType.RBAC_GROUP_UPDATED,
                group_id=group_id,
                group_name=group.display_name if group else group_id,
                admin_account=f"scim:{session.account_id}",
                change_detail=f"SCIM PATCH: +{len(added)} members, -{len(removed)} members",
            )
        )
        _push(store, f"scim:{session.account_id}")

    return _group_resource(group) if group else {}


@router.delete("/Groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
async def scim_delete_group(
    group_id: str,
    session: AdminSession,
):
    try:
        require_feature("scim")
    except LicenseFeatureGated as exc:
        from fastapi.responses import JSONResponse

        return JSONResponse(status_code=402, content=license_feature_gated_response(exc))
    store = _get_store()
    group = store.get_group(group_id)
    if group is None:
        raise HTTPException(status_code=404, detail={"error": "group_not_found"})

    store.remove_group(group_id)

    from yashigani.audit.schema import RBACGroupEvent, EventType

    assert backoffice_state.audit_writer is not None  # set unconditionally at startup
    backoffice_state.audit_writer.write(
        RBACGroupEvent(
            event_type=EventType.RBAC_GROUP_DELETED,
            group_id=group_id,
            group_name=group.display_name,
            admin_account=f"scim:{session.account_id}",
            change_detail=f"deleted via SCIM (had {len(group.members)} members)",
        )
    )
    _push(store, f"scim:{session.account_id}")
