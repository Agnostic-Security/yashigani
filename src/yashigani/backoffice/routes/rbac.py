"""
Yashigani Backoffice — RBAC management routes.

All routes require an active admin session.
Mutations write-through to the RBACStore (Redis db/3) and immediately
push the updated data document to OPA via opa_push.push_rbac_data().
OPA push failures are logged and audited but do NOT fail the mutation —
the store is always considered authoritative.

Last updated: 2026-05-03
"""
from __future__ import annotations

import logging
import re
import uuid
from typing import Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field, field_validator

from yashigani.backoffice.middleware import AdminSession
from yashigani.backoffice.state import backoffice_state
from yashigani.rbac.model import RBACGroup, ResourcePattern, RateLimitOverride

logger = logging.getLogger(__name__)

router = APIRouter()

# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

# Ava input-validation finding: constrain ResourcePatternIn so a malformed
# pattern cannot reach the store / OPA. method must be one of a fixed allowlist
# (or "*"); path_glob is length-capped and charset-restricted to path-glob
# characters (no whitespace, control chars, or shell/regex metacharacters that
# would never appear in a legitimate MCP path pattern).
_ALLOWED_METHODS = frozenset({"*", "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"})
# Allowed path_glob characters: path segments + the supported glob tokens
# (* ? ** ) plus the usual URL path punctuation. Deliberately excludes spaces,
# quotes, backslashes, and shell/regex metacharacters.
_PATH_GLOB_RE = re.compile(r"^[A-Za-z0-9._~:@%+\-/*?{}\[\]]+$")
_PATH_GLOB_MAX = 512


class ResourcePatternIn(BaseModel):
    method: str = Field(default="*", description="HTTP method or '*' for any")
    path_glob: str = Field(
        min_length=1,
        max_length=_PATH_GLOB_MAX,
        description="Path pattern: '**', '/prefix/**', or exact path",
    )

    @field_validator("method")
    @classmethod
    def _validate_method(cls, v: str) -> str:
        vv = v.strip().upper() if v else "*"
        if vv not in _ALLOWED_METHODS:
            raise ValueError(
                f"method must be one of {sorted(_ALLOWED_METHODS)}"
            )
        return vv

    @field_validator("path_glob")
    @classmethod
    def _validate_path_glob(cls, v: str) -> str:
        vv = v.strip()
        if not vv:
            raise ValueError("path_glob must not be empty")
        if not _PATH_GLOB_RE.match(vv):
            raise ValueError(
                "path_glob contains invalid characters (allowed: path chars and "
                "glob tokens * ? ** { } [ ] ; no whitespace or shell metacharacters)"
            )
        return vv


class RateLimitOverrideIn(BaseModel):
    per_session_rps: float = Field(gt=0)
    per_session_burst: int = Field(gt=0)


class CreateGroupRequest(BaseModel):
    display_name: str = Field(min_length=1, max_length=128)
    allowed_resources: list[ResourcePatternIn] = Field(default_factory=list)
    rate_limit_override: Optional[RateLimitOverrideIn] = None


class UpdateGroupRequest(BaseModel):
    display_name: Optional[str] = Field(default=None, min_length=1, max_length=128)
    allowed_resources: Optional[list[ResourcePatternIn]] = None
    rate_limit_override: Optional[RateLimitOverrideIn] = None


class AddMemberRequest(BaseModel):
    email: str = Field(
        min_length=5,
        max_length=254,
        pattern=r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$",
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _group_to_response(group: RBACGroup) -> dict:
    return {
        "id": group.id,
        "display_name": group.display_name,
        "members": sorted(group.members),
        "allowed_resources": [r.to_dict() for r in group.allowed_resources],
        "rate_limit_override": (
            group.rate_limit_override.to_dict()
            if group.rate_limit_override is not None
            else None
        ),
    }


def _get_store():
    store = backoffice_state.rbac_store
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "rbac_store_not_configured"},
        )
    return store


def _push(store, admin_account: str) -> None:
    """Fire-and-forget OPA push. Logs and audits on failure; never raises."""
    from yashigani.rbac.opa_push import push_rbac_data
    from yashigani.audit.schema import RBACPolicyPushEvent, EventType
    opa_url = backoffice_state.opa_url
    doc = store.to_opa_document()
    groups_count = len(doc.get("groups", {}))
    users_count = len(doc.get("user_groups", {}))

    outcome = "success"
    error = ""
    try:
        push_rbac_data(store, opa_url, agent_registry=backoffice_state.agent_registry)
        try:
            from yashigani.metrics.registry import rbac_policy_push_total
            rbac_policy_push_total.labels(outcome="success").inc()
        except Exception:
            pass
    except Exception as exc:
        outcome = "failure"
        error = type(exc).__name__
        logger.error("RBAC OPA push failed: %s", exc)
        try:
            from yashigani.metrics.registry import rbac_policy_push_total
            rbac_policy_push_total.labels(outcome="failure").inc()
        except Exception:
            pass

    try:
        event = RBACPolicyPushEvent(
            event_type=EventType.RBAC_POLICY_PUSHED,
            groups_count=groups_count,
            users_count=users_count,
            admin_account=admin_account,
            outcome=outcome,
            error=error,
        )
        assert backoffice_state.audit_writer is not None  # set unconditionally at startup
        backoffice_state.audit_writer.write(event)
    except Exception as exc:
        logger.error("RBAC push audit write failed: %s", exc)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/groups")
async def list_groups(session: AdminSession):
    store = _get_store()
    return {"groups": [_group_to_response(g) for g in store.list_groups()]}


@router.post("/groups", status_code=status.HTTP_201_CREATED)
async def create_group(
    body: CreateGroupRequest,
    session: AdminSession,
):
    store = _get_store()

    override = None
    if body.rate_limit_override is not None:
        override = RateLimitOverride(
            per_session_rps=body.rate_limit_override.per_session_rps,
            per_session_burst=body.rate_limit_override.per_session_burst,
        )

    group = RBACGroup(
        id=str(uuid.uuid4()),
        display_name=body.display_name,
        allowed_resources=[
            ResourcePattern(method=r.method, path_glob=r.path_glob)
            for r in body.allowed_resources
        ],
        rate_limit_override=override,
    )
    store.add_group(group)

    from yashigani.audit.schema import RBACGroupEvent, EventType
    assert backoffice_state.audit_writer is not None  # set unconditionally at startup
    backoffice_state.audit_writer.write(RBACGroupEvent(
        event_type=EventType.RBAC_GROUP_CREATED,
        group_id=group.id,
        group_name=group.display_name,
        admin_account=session.account_id,
        change_detail=f"created with {len(group.allowed_resources)} resource patterns",
    ))
    _push(store, session.account_id)
    return _group_to_response(group)


@router.get("/groups/{group_id}")
async def get_group(group_id: str, session: AdminSession):
    store = _get_store()
    group = store.get_group(group_id)
    if group is None:
        raise HTTPException(status_code=404, detail={"error": "group_not_found"})
    return _group_to_response(group)


@router.put("/groups/{group_id}")
async def update_group(
    group_id: str,
    body: UpdateGroupRequest,
    session: AdminSession,
):
    store = _get_store()
    group = store.get_group(group_id)
    if group is None:
        raise HTTPException(status_code=404, detail={"error": "group_not_found"})

    changes = []
    if body.display_name is not None:
        group.display_name = body.display_name
        changes.append("display_name")
    if body.allowed_resources is not None:
        group.allowed_resources = [
            ResourcePattern(method=r.method, path_glob=r.path_glob)
            for r in body.allowed_resources
        ]
        changes.append(f"allowed_resources({len(group.allowed_resources)})")
    if body.rate_limit_override is not None:
        group.rate_limit_override = RateLimitOverride(
            per_session_rps=body.rate_limit_override.per_session_rps,
            per_session_burst=body.rate_limit_override.per_session_burst,
        )
        changes.append("rate_limit_override")

    store.add_group(group)  # write-through update

    from yashigani.audit.schema import RBACGroupEvent, EventType
    assert backoffice_state.audit_writer is not None  # set unconditionally at startup
    backoffice_state.audit_writer.write(RBACGroupEvent(
        event_type=EventType.RBAC_GROUP_UPDATED,
        group_id=group.id,
        group_name=group.display_name,
        admin_account=session.account_id,
        change_detail=f"updated: {', '.join(changes)}",
    ))
    _push(store, session.account_id)
    return _group_to_response(group)


@router.delete("/groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_group(group_id: str, session: AdminSession):
    store = _get_store()
    group = store.get_group(group_id)
    if group is None:
        raise HTTPException(status_code=404, detail={"error": "group_not_found"})
    store.remove_group(group_id)

    from yashigani.audit.schema import RBACGroupEvent, EventType
    assert backoffice_state.audit_writer is not None  # set unconditionally at startup
    backoffice_state.audit_writer.write(RBACGroupEvent(
        event_type=EventType.RBAC_GROUP_DELETED,
        group_id=group_id,
        group_name=group.display_name,
        admin_account=session.account_id,
        change_detail=f"deleted (had {len(group.members)} members)",
    ))
    _push(store, session.account_id)


@router.post("/groups/{group_id}/members", status_code=status.HTTP_201_CREATED)
async def add_member(
    group_id: str,
    body: AddMemberRequest,
    session: AdminSession,
):
    store = _get_store()
    try:
        store.add_member(group_id, body.email)
    except KeyError:
        raise HTTPException(status_code=404, detail={"error": "group_not_found"})

    from yashigani.audit.schema import RBACMemberEvent, EventType
    assert backoffice_state.audit_writer is not None  # set unconditionally at startup
    backoffice_state.audit_writer.write(RBACMemberEvent(
        event_type=EventType.RBAC_MEMBER_ADDED,
        group_id=group_id,
        email=body.email,
        admin_account=session.account_id,
    ))
    _push(store, session.account_id)
    return {"group_id": group_id, "email": body.email, "action": "added"}


@router.delete("/groups/{group_id}/members/{email}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(
    group_id: str,
    email: str,
    session: AdminSession,
):
    store = _get_store()
    try:
        store.remove_member(group_id, email)
    except KeyError:
        raise HTTPException(status_code=404, detail={"error": "group_not_found"})

    from yashigani.audit.schema import RBACMemberEvent, EventType
    assert backoffice_state.audit_writer is not None  # set unconditionally at startup
    backoffice_state.audit_writer.write(RBACMemberEvent(
        event_type=EventType.RBAC_MEMBER_REMOVED,
        group_id=group_id,
        email=email,
        admin_account=session.account_id,
    ))
    _push(store, session.account_id)


@router.get("/users/{email}/groups")
async def get_user_groups(email: str, session: AdminSession):
    store = _get_store()
    groups = store.get_user_groups(email)
    return {
        "email": email,
        "groups": [_group_to_response(g) for g in groups],
    }


@router.post("/policy/push")
async def force_push(session: AdminSession):
    store = _get_store()
    _push(store, session.account_id)
    doc = store.to_opa_document()
    return {
        "pushed": True,
        "groups_count": len(doc.get("groups", {})),
        "users_count": len(doc.get("user_groups", {})),
    }
