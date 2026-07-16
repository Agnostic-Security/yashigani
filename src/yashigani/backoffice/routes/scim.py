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

import hashlib
import json
import logging
import os
import re
import uuid
from pathlib import Path
from typing import Optional, Any

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel

from yashigani.backoffice.middleware import AdminSession
from yashigani.backoffice.state import backoffice_state
from yashigani.backoffice.routes.rbac import _push
from yashigani.rbac.model import RBACGroup
from yashigani.licensing import _integrity as _mesh_integrity
from yashigani.licensing.enforcer import (
    check_end_user_limit,
    count_canonical_end_users,
    LicenseFeatureGated,
    LicenseLimitExceeded,
    LicenseTier,
    license_feature_gated_response,
    license_limit_exceeded_response,
)

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Mesh FULL-graph check (licence-hardening-v2 Phase D, 2026-07-17 —
# LAURA-V2-003 RE-VERIFY hardening). See licensing/verifier.py's
# module-level comment block above _check_mesh_full() for the full
# rationale. This is routes/scim.py's OWN independently-authored copy —
# deliberately a DIFFERENT code shape (recursion over the full peer-role
# queue) from verifier.py's for-loop, enforcer.py's list-comprehension,
# gate_middleware.py's class, sso/oidc.py's while-loop, sso/saml.py's
# functional map()/all(), and routes/sso.py's dict-comprehension, so a
# single AST/regex strip-script cannot pattern-match and remove all seven
# at once.
#
# routes/scim.py is one of SCIM's TWO real enforcement layers (the other
# being gate_middleware.py's ASGI gate) — Laura's re-verify 3-file attack
# ({verifier.py, enforcer.py, gate_middleware.py}) defeated gate_middleware
# but left THIS file's own gate as SCIM's only surviving layer; under
# Phase C's ring this file's own ring-check happened not to cover the
# touched files for that release's permutation, so it granted silently.
# Under the Phase D complete graph, this file independently checks ALL 6
# other members — including gate_middleware.py — every time.
# ---------------------------------------------------------------------------

_MESH_ROLE = "SCIM_ROUTES"
_mesh_integrity_violated = False


def _mesh_targets() -> dict:
    routes_dir = Path(__file__).parent
    pkg_dir = routes_dir.parent.parent
    licensing_dir = pkg_dir / "licensing"
    return {
        "VERIFIER": ("VERIFIER_HASH", licensing_dir / "verifier.py"),
        "ENFORCER": ("ENFORCER_HASH", licensing_dir / "enforcer.py"),
        "GATE_MIDDLEWARE": ("GATE_MIDDLEWARE_HASH", licensing_dir / "gate_middleware.py"),
        "OIDC": ("OIDC_MODULE_HASH", pkg_dir / "sso" / "oidc.py"),
        "SAML": ("SAML_MODULE_HASH", pkg_dir / "sso" / "saml.py"),
        "SSO_ROUTES": ("SSO_ROUTES_HASH", routes_dir / "sso.py"),
        "SCIM_ROUTES": ("SCIM_ROUTES_HASH", routes_dir / "scim.py"),
    }


def _verify_one_mesh_peer(role: str, targets: dict) -> bool:
    """Return True iff `role`'s live hash matches its signed value. Base
    operation for the recursive walk below."""
    const_name, path = targets[role]
    expected = getattr(_mesh_integrity, const_name, "")
    try:
        live = hashlib.sha256(path.read_bytes()).hexdigest()
    except Exception as exc:
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: mesh full-check (routes/scim.py) — "
            "could not read mesh peer role=%s (%s): %s", role, path, exc,
        )
        return False
    if live != expected:
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: mesh full-check (routes/scim.py) — "
            "mesh peer role=%s (%s) live hash mismatch (expected=%s, "
            "actual=%s) — independent detection (LAURA-V2-003 Phase D "
            "hardening)",
            role, const_name, expected[:16], live[:16],
        )
        return False
    return True


def _check_mesh_full_recursive(roles: list, targets: dict) -> bool:
    """Recursively verify each role in `roles`; True iff ALL pass."""
    if not roles:
        return True
    head, *tail = roles
    ok_here = _verify_one_mesh_peer(head, targets)
    ok_rest = _check_mesh_full_recursive(tail, targets)
    return ok_here and ok_rest


def _check_mesh_full() -> None:
    global _mesh_integrity_violated
    is_dev = os.environ.get("YASHIGANI_ENV") == "dev"
    targets = _mesh_targets()

    if _mesh_integrity.is_any_hash_placeholder() or _mesh_integrity.is_mesh_topology_placeholder():
        if not is_dev:
            _mesh_integrity_violated = True
            logger.critical(
                "LICENSE INTEGRITY VIOLATION: mesh full-check (routes/scim.py) "
                "— hash or topology constants still placeholders in a "
                "non-dev environment; hard-refusing"
            )
        return

    try:
        member_order = json.loads(_mesh_integrity.MESH_TOPOLOGY_JSON)["member_order"]
        if not isinstance(member_order, list) or sorted(member_order) != sorted(targets):
            raise ValueError("member_order is not a permutation of the 7 mesh roles")
        if member_order.count(_MESH_ROLE) != 1:
            raise ValueError("member_order missing this file's role")
        peer_roles = [role for role in member_order if role != _MESH_ROLE]
    except Exception as exc:
        _mesh_integrity_violated = True
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: mesh full-check (routes/scim.py) — "
            "MESH_TOPOLOGY_JSON malformed or missing this file's role: %s", exc,
        )
        return

    if not _check_mesh_full_recursive(peer_roles, targets):
        _mesh_integrity_violated = True


def get_mesh_integrity_status() -> bool:
    """Return True if this file's independent full-mesh check has detected
    a tampered peer (LAURA-V2-003 Phase D hardening)."""
    return _mesh_integrity_violated


def _emit_mesh_tamper_event(check_type: str, expected_hash: str, actual_hash: str) -> None:
    """Emit a tamper-evidence audit event at gate-invocation time — own
    inline copy, see gate_middleware.py's twin function for the full
    rationale (LAURA-V2-003: no shared chokepoint)."""
    try:
        from yashigani.audit.schema import LicenceIntegrityViolationEvent
        try:
            writer = getattr(backoffice_state, "audit_writer", None)
        except Exception:
            writer = None
        if writer is None:
            return
        writer.write(LicenceIntegrityViolationEvent(
            module="backoffice.routes.scim",
            check_type=check_type,
            expected_hash=expected_hash[:16],
            actual_hash=actual_hash[:16],
        ))
    except Exception:
        pass


_check_mesh_full()


def _licence_hard_gate(feature: str) -> None:
    """
    Point-of-use licence gate, route layer (LAURA-V2-001 follow-up,
    2026-07-16; Phase D full-mesh hardening, 2026-07-17).

    Deliberately does NOT call enforcer.require_feature() — see
    sso/oidc.py's `_licence_hard_gate()` docstring for the full rationale.
    SCIM has no separate provider module (unlike OIDC/SAML's oidc.py/
    saml.py), so this route-level gate plus
    licensing/gate_middleware.py's independent ASGI-level gate are the TWO
    layers for SCIM.

    Phase D (2026-07-17, LAURA-V2-003 RE-VERIFY): the integrity decision
    below comes SOLELY from `_mesh_integrity_violated` — this file's OWN
    inline full-mesh check (_check_mesh_full() above). The Phase C fallback
    (calling verifier.get_integrity_status()/enforcer.get_enforcer_
    integrity_status()) has been REMOVED, not merely supplemented — this
    file (routes/scim.py) is SCIM's LAST surviving enforcement layer once
    gate_middleware.py is also tampered (Laura's exact 3-file re-verify
    attack, {verifier.py, enforcer.py, gate_middleware.py}); under Phase C
    this file's own ring-check didn't happen to cover the touched files for
    that release's permutation, and the removed fallback was exactly the
    neutered {verifier.py, enforcer.py} pair — this file granted silently,
    fully defeating SCIM end-to-end. Never enforcer.require_feature().
    Hard-refuses (raises) on any integrity violation or missing feature;
    never silently passes on error (IMPL-03).

    HONEST CEILING (Phase D, 2026-07-17 — see gate_middleware.py's module
    docstring for the full statement): this file is now part of the 7-file
    COMPLETE graph — tampering ANY 1-6 of the 7 mesh files, including
    verifier.py+enforcer.py+gate_middleware.py together, is always caught
    by every untouched member's own full-mesh check and audited. Only a
    coordinated edit of ALL 7 removes every detector — tamper-EVIDENT and
    high-cost, not tamper-proof.
    """
    if _mesh_integrity_violated:
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: SCIM routes hard-refusing "
            "feature=%s — this file's own full-mesh check detected a "
            "tampered peer (LAURA-V2-003 Phase D hardening, no fallback to "
            "verifier.py/enforcer.py getters)",
            feature,
        )
        _emit_mesh_tamper_event("mesh_full_check_mismatch", "clean", "tampered")
        raise LicenseFeatureGated(feature=feature, tier=LicenseTier.COMMUNITY)

    try:
        from yashigani.licensing import enforcer as _enforcer
    except Exception as exc:
        logger.critical(
            "SCIM routes: could not import enforcer for license state — "
            "treating as violation and refusing (IMPL-03): %s", exc,
        )
        _emit_mesh_tamper_event("integrity_module_unavailable", "n/a", "import_failed")
        raise LicenseFeatureGated(feature=feature, tier=LicenseTier.COMMUNITY) from exc

    try:
        lic = _enforcer.get_license()
    except Exception as exc:
        logger.critical(
            "SCIM routes: enforcer.get_license() raised — treating as "
            "violation and refusing: %s", exc,
        )
        raise LicenseFeatureGated(feature=feature, tier=LicenseTier.COMMUNITY) from exc

    if not lic.has_feature(feature):
        raise LicenseFeatureGated(feature=feature, tier=lic.tier)


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
        _licence_hard_gate("scim")
    except LicenseFeatureGated as exc:
        from fastapi.responses import JSONResponse

        return JSONResponse(status_code=402, content=license_feature_gated_response(exc))
    store = _get_store()
    email = body.userName

    existing_groups = store.get_user_groups(email)

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
        _licence_hard_gate("scim")
    except LicenseFeatureGated as exc:
        from fastapi.responses import JSONResponse

        return JSONResponse(status_code=402, content=license_feature_gated_response(exc))
    store = _get_store()
    email = user_id

    groups = store.get_user_groups(email)
    for group in groups:
        try:
            store.remove_member(group.id, email)
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
        _licence_hard_gate("scim")
    except LicenseFeatureGated as exc:
        from fastapi.responses import JSONResponse

        return JSONResponse(status_code=402, content=license_feature_gated_response(exc))
    store = _get_store()

    # Extract member emails from SCIM members list
    initial_members: set[str] = set()
    if body.members:
        for m in body.members:
            # value is expected to be an email address in this implementation
            if "@" in m.value:
                initial_members.add(m.value)

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
        _licence_hard_gate("scim")
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
                    try:
                        store.add_member(group_id, email)
                        added.append(email)
                    except KeyError:
                        pass

        elif op_name == "remove":
            for item in values:
                email = item.get("value", "") if isinstance(item, dict) else str(item)
                if "@" in email:
                    try:
                        store.remove_member(group_id, email)
                        removed.append(email)
                    except KeyError:
                        pass

        elif op_name == "replace":
            # Replace replaces the full members list
            new_emails: set[str] = set()
            for item in values:
                email = item.get("value", "") if isinstance(item, dict) else str(item)
                if "@" in email:
                    new_emails.add(email)
            # Remove members no longer in the list
            for email in list(group.members - new_emails):
                try:
                    store.remove_member(group_id, email)
                    removed.append(email)
                except KeyError:
                    pass
            # Add new members
            for email in new_emails - group.members:
                try:
                    store.add_member(group_id, email)
                    added.append(email)
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
        _licence_hard_gate("scim")
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
