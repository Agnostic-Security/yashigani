"""
Yashigani Backoffice — Self-service user API key routes (Gap 4 / v2.23.4).

POST /me/api-key          — Issue / rotate caller's HUMAN-identity Bearer.
GET  /me/api-keys         — List current key metadata (NO plaintext).
DELETE /me/api-keys/{key_id} — Revoke a specific key.

Auth requirements:
  - Caller MUST have a session with account_tier == "user".
  - force_password_change == false AND force_totp_provision == false.
  - Fresh StepUp (TOTP verified within STEPUP_TTL_SECONDS, default 5 min).

Security invariants:
  - Plaintext token returned ONCE in POST response body ONLY. Never logged,
    never re-fetchable via GET.
  - Self-rotation: prior token immediately invalidated (grace_seconds=0).
  - Rate-limit: max 5 issuance attempts per user per hour (Redis INCR / EXPIRE).
  - account_tier == "user" guard on every route — admin or totp_provisioning
    tiers are rejected with 403.
  - identity_registry is None (community-tier) → 503.

Last updated: 2026-05-14T00:00:00+01:00
"""
from __future__ import annotations

import logging
import time

from fastapi import APIRouter, Depends, HTTPException, Request, status

from yashigani.auth.stepup import assert_fresh_stepup, STEPUP_TTL_SECONDS
from yashigani.backoffice.middleware import AnySession, get_session_store
from yashigani.backoffice.state import backoffice_state

router = APIRouter()
_log = logging.getLogger("yashigani.me")

# ---------------------------------------------------------------------------
# Rate-limit constants — max 5 issuance attempts per user per hour.
# Keyed on: me:api-key:rl:{account_id}   (Redis INCR + EXPIRE 3600)
# ---------------------------------------------------------------------------
_API_KEY_RATE_LIMIT = 5
_API_KEY_RATE_WINDOW = 3600  # 1 hour in seconds


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _require_user_session(session=Depends(get_session_store)):
    """NOT a FastAPI dependency — used internally to validate session tier."""
    pass


def _get_registry():
    registry = backoffice_state.identity_registry
    if registry is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "user_identity_registry_unavailable",
                "message": (
                    "Self-service API keys are not available on this deployment tier. "
                    "Contact your administrator."
                ),
            },
        )
    return registry


def _get_auth_service():
    svc = backoffice_state.auth_service
    if svc is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "auth_service_unavailable"},
        )
    return svc


def _assert_user_tier(session) -> None:
    """
    Reject non-user sessions with 403.
    account_tier must be exactly "user" — admin and totp_provisioning rejected.
    """
    if session.account_tier != "user":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "user_tier_required",
                "message": (
                    "This endpoint is only available to user-tier accounts. "
                    "Admin accounts must use the admin override route."
                ),
            },
        )


def _assert_account_ready(record) -> None:
    """
    Reject accounts with pending force_password_change or force_totp_provision.
    These guards prevent issuance to partially-provisioned accounts.
    """
    if record is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"error": "account_not_found"})
    if record.force_password_change:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "force_password_change_pending",
                "message": "You must change your password before issuing an API key.",
            },
        )
    if record.force_totp_provision:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "force_totp_provision_pending",
                "message": "You must complete TOTP provisioning before issuing an API key.",
            },
        )


def _check_rate_limit(account_id: str) -> None:
    """
    Enforce max 5 issuance attempts per account per hour.
    Uses Redis INCR + EXPIRE (idiomatic sliding-window approximation).
    Raises HTTP 429 on breach.
    """
    state = backoffice_state
    if state.session_store is None:
        return  # no Redis available — skip (tests may not have Redis)
    r = state.session_store._redis
    rl_key = f"me:api-key:rl:{account_id}"
    count = r.incr(rl_key)
    if count == 1:
        # First increment — set TTL for the window
        r.expire(rl_key, _API_KEY_RATE_WINDOW)
    if count > _API_KEY_RATE_LIMIT:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            headers={"Retry-After": str(_API_KEY_RATE_WINDOW)},
            detail={
                "error": "api_key_rate_limit_exceeded",
                "message": (
                    f"Maximum {_API_KEY_RATE_LIMIT} API key issuance attempts per hour. "
                    "Please wait before retrying."
                ),
                "retry_after_seconds": _API_KEY_RATE_WINDOW,
            },
        )


def _resolve_email_slug(record) -> str:
    """
    Derive slug from record email, falling back to {username}@yashigani.local.
    Mirrors _auth_email_to_slug in auth.py (Gap 3 helper).
    """
    from yashigani.backoffice.routes.auth import _auth_email_to_slug

    email = record.email
    if not email:
        email = f"{record.username}@yashigani.local"
    return _auth_email_to_slug(email)


def _get_identity_for_account(registry, record) -> dict:
    """
    Look up the HUMAN identity for the given account record by slug.
    Raises 404 if the identity has not been registered yet (Gap 3 should have
    created it at login — this is a defensive guard).
    """
    slug = _resolve_email_slug(record)
    identity = registry.get_by_slug(slug)
    if identity is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "identity_not_found",
                "message": (
                    "No API identity found for your account. "
                    "Log out and log back in to register your identity, "
                    "then retry."
                ),
            },
        )
    return identity


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/me/api-key")
async def issue_api_key(request: Request, session: AnySession):
    """
    Issue or rotate the caller's HUMAN-identity Bearer token.

    Requirements:
      - account_tier == "user"
      - force_password_change == false
      - force_totp_provision == false
      - Fresh StepUp (TOTP within last STEPUP_TTL_SECONDS seconds)

    Returns plaintext_token ONCE. User must record it — it cannot be
    retrieved again via any route.

    Prior token is immediately invalidated (no grace period on self-rotation).
    Rate-limited to 5 attempts per hour per user.
    """
    # 1. Tier guard — must be user, not admin or totp_provisioning
    _assert_user_tier(session)

    # 2. StepUp guard — TOTP must have been verified within the TTL window
    assert_fresh_stepup(session)

    # 3. Account state guards — password + TOTP not pending
    auth_svc = _get_auth_service()
    record = await auth_svc.get_account_by_id(session.account_id)
    _assert_account_ready(record)

    # 4. Rate limit — 5 attempts per hour per user
    _check_rate_limit(session.account_id)

    # 5. Registry availability
    registry = _get_registry()

    # 6. Resolve HUMAN identity (must exist — Gap 3 creates it at login)
    identity = _get_identity_for_account(registry, record)
    identity_id = identity["identity_id"]

    # 7. Check for existing key (to determine if this is a rotation)
    existing_key = backoffice_state.session_store._redis.get(
        f"identity:key:{identity_id}"
    ) if backoffice_state.session_store else None
    is_rotation = existing_key is not None

    # 8. Rotate key — grace_seconds=0 means prior token is immediately invalidated.
    plaintext_token = registry.rotate_key(identity_id, grace_seconds=0)

    # 9. Derive metadata for response (last4 never == full plaintext, just a hint)
    key_last4 = plaintext_token[-4:]

    # 10. Emit audit event
    state = backoffice_state
    if state.audit_writer is not None:
        from yashigani.audit.schema import UserApiKeyIssuedEvent
        state.audit_writer.write(UserApiKeyIssuedEvent(
            actor=session.account_id,
            identity_id=identity_id,
            key_last4=key_last4,
            rotation=is_rotation,
        ))

    _log.info(
        "User API key issued: account_id=%s identity_id=%s rotation=%s",
        session.account_id, identity_id, is_rotation,
    )

    # 11. Read back expires_at from registry for response
    reg_data = registry.get(identity_id) or {}
    expires_at = reg_data.get("api_key_expires_at", "")

    return {
        "plaintext_token": plaintext_token,
        "shown_once": True,
        "expires_at": expires_at,
        "message": "Store this token securely. It will not be shown again.",
    }


@router.get("/me/api-keys")
async def list_api_keys(session: AnySession):
    """
    Return current API key metadata for the caller.

    NEVER includes plaintext token. NEVER re-fetchable.
    Returns empty array if no key has been issued yet.
    """
    # 1. Tier guard
    _assert_user_tier(session)

    # 2. Registry availability
    registry = _get_registry()

    # 3. Resolve auth service + account record
    auth_svc = _get_auth_service()
    record = await auth_svc.get_account_by_id(session.account_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"error": "account_not_found"})

    # 4. Look up identity by slug
    slug = _resolve_email_slug(record)
    identity = registry.get_by_slug(slug)
    if identity is None:
        # No identity yet — no keys issued. Return empty list.
        return {"api_keys": []}

    identity_id = identity["identity_id"]

    # 5. Check whether a key exists for this identity
    r = backoffice_state.session_store._redis if backoffice_state.session_store else None
    key_hash = r.get(f"identity:key:{identity_id}") if r is not None else None

    if key_hash is None:
        return {"api_keys": []}

    # 6. Build metadata response — NO plaintext
    created_at = identity.get("api_key_created_at", "")
    rotated_at = identity.get("api_key_rotated_at", "")
    expires_at = identity.get("api_key_expires_at", "")
    last_seen_at = identity.get("last_seen_at", "")

    return {
        "api_keys": [
            {
                "key_id": identity_id,      # stable ID — use for DELETE
                "last4": "****",            # plaintext never stored; last4 not persisted
                "created_at": created_at,
                "rotated_at": rotated_at,
                "last_used_at": last_seen_at,
                "expires_at": expires_at,
                "status": identity.get("status", "active"),
            }
        ]
    }


@router.delete("/me/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(key_id: str, session: AnySession):
    """
    Revoke a specific API key for the caller.

    Returns 204 on success.
    403 if the key belongs to another user.
    404 if the key does not exist.
    """
    # 1. Tier guard
    _assert_user_tier(session)

    # 2. Registry availability
    registry = _get_registry()

    # 3. Resolve identity and verify ownership
    auth_svc = _get_auth_service()
    record = await auth_svc.get_account_by_id(session.account_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"error": "account_not_found"})

    slug = _resolve_email_slug(record)
    identity = registry.get_by_slug(slug)
    if identity is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": "key_not_found"})

    identity_id = identity["identity_id"]

    # 4. Ownership check — the key_id in the URL must match the caller's identity_id
    if key_id != identity_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "key_not_owned_by_caller",
                "message": "You can only revoke your own API keys.",
            },
        )

    # 5. Check key exists
    r = backoffice_state.session_store._redis if backoffice_state.session_store else None
    key_hash = r.get(f"identity:key:{identity_id}") if r is not None else None
    if key_hash is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": "key_not_found"})

    # 6. Revoke — delete current key + any grace key
    if r is not None:
        r.delete(f"identity:key:{identity_id}", f"identity:key:grace:{identity_id}")

    # 7. Audit
    state = backoffice_state
    if state.audit_writer is not None:
        from yashigani.audit.schema import UserApiKeyRevokedEvent
        state.audit_writer.write(UserApiKeyRevokedEvent(
            actor=session.account_id,
            identity_id=identity_id,
            key_id=key_id,
            revoked_by_admin=False,
        ))

    _log.info(
        "User API key revoked: account_id=%s identity_id=%s",
        session.account_id, identity_id,
    )
    # 204 — no body
