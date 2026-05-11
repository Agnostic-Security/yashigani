"""
Yashigani Backoffice — Authentication routes.
POST /auth/login            — username + password + TOTP
POST /auth/logout           — invalidate session
GET  /auth/status           — check session validity
POST /auth/password/change  — forced change on first login
POST /auth/totp/provision   — TOTP + recovery codes provisioning
POST /auth/stepup           — V6.8.4 step-up TOTP verification for high-value flows

Last updated: 2026-05-09T00:00:00+01:00
"""

from __future__ import annotations

import logging
import os
import time

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import AdminSession, AnySession, get_session_store, _SESSION_COOKIE
from yashigani.backoffice.state import backoffice_state
from yashigani.db.postgres import tenant_transaction as _pg_tenant_transaction_impl

_PLATFORM_TENANT_ID = "00000000-0000-0000-0000-000000000000"


def _pg_tenant_transaction():
    """Shorthand: open a platform-scoped transaction on the shared pool."""
    return _pg_tenant_transaction_impl(_PLATFORM_TENANT_ID)


router = APIRouter()

_TOTP_FAILURE_LIMIT = 3
_totp_failures: dict[str, int] = {}  # session_prefix → count

_log = logging.getLogger("yashigani.auth")

# ---------------------------------------------------------------------------
# Auth brute-force throttle (ASVS 6.3.5)
#
# Per-IP tracking:  3 consecutive failures from the same IP → throttle.
# Global tracking:  5 failures from ANY IP(s) within a 15-min window → throttle.
# Delay escalation: ×5 multiplier — 30s, 60s, 300s, 1500s, 7500s, cap 37500s.
# Redis keys:
#   auth:fail:ip:{ip}        — INCR on failure, EXPIRE 900
#   auth:fail:global          — INCR on failure, EXPIRE 900
#   auth:throttle:ip:{ip}    — current delay level for this IP
#   auth:throttle:global      — current delay level globally
# ---------------------------------------------------------------------------

_THROTTLE_IP_THRESHOLD = 3  # per-IP consecutive failures before throttle
_THROTTLE_GLOBAL_THRESHOLD = 5  # global failures (any IP) in 15-min window
_THROTTLE_WINDOW_SECONDS = 900  # 15-minute window for counters
_THROTTLE_BASE_DELAY = 30  # Level 1: 30 seconds
_THROTTLE_MULTIPLIER = 5  # Each level multiplies by 5  (sic — see spec)
_THROTTLE_MAX_DELAY = 37500  # Cap at 625 minutes

# Delay schedule (pre-computed for clarity):
# Level 1:     30s
# Level 2:     60s   (but spec says ×5 from 30 → 150 would be naive; spec lists
#              explicit values, so we use the explicit table)
_THROTTLE_DELAYS = [30, 60, 300, 1500, 7500, 37500]


def _get_throttle_redis():
    """Return the Redis client used by the session store (reuse existing connection)."""
    return backoffice_state.session_store._redis


def _throttle_delay_for_level(level: int) -> int:
    """Return delay in seconds for a given throttle level (1-indexed)."""
    if level <= 0:
        return 0
    idx = min(level - 1, len(_THROTTLE_DELAYS) - 1)
    return _THROTTLE_DELAYS[idx]


def _check_ip_access(client_ip: str) -> None:
    """
    Check IP allowlist and blocklist BEFORE any auth processing.
    Order: allowlist (if non-empty, reject unlisted) → blocklist → proceed.
    Supports IPv4, IPv6, and CIDR ranges.
    """
    import ipaddress

    r = _get_throttle_redis()

    # 1. Check blocklist first (permanent bans)
    if r.exists(f"auth:blocked:{client_ip}"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "ip_blocked",
                "message": "This IP has been blocked due to excessive failed authentication attempts. Contact your administrator.",
            },
        )

    # 2. Check allowlist (if non-empty, only listed IPs/CIDRs can login)
    allowlist = r.smembers("auth:allowlist")
    if allowlist:
        try:
            addr = ipaddress.ip_address(client_ip)
        except ValueError:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail={"error": "ip_not_allowed"})
        allowed = False
        for entry in allowlist:
            entry_str = entry if isinstance(entry, str) else entry.decode()
            try:
                if "/" in entry_str:
                    if addr in ipaddress.ip_network(entry_str, strict=False):
                        allowed = True
                        break
                else:
                    if addr == ipaddress.ip_address(entry_str):
                        allowed = True
                        break
            except ValueError:
                continue
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": "ip_not_allowed", "message": "Login not permitted from this IP address."},
            )


def _apply_auth_throttle(client_ip: str, response: Response) -> None:
    """
    Check per-IP and global failure counters.  If either exceeds its threshold,
    raise HTTP 429 with a ``Retry-After`` header (RFC 6585) and a user-facing
    banner message.  The caller never proceeds past this point while throttled.

    ASVS 6.3.5: brute-force mitigation via rate-limiting and account lockout.
    """
    r = _get_throttle_redis()
    ip_key = f"auth:throttle:ip:{client_ip}"
    global_key = "auth:throttle:global"
    ip_fail_key = f"auth:fail:ip:{client_ip}"
    global_fail_key = "auth:fail:global"

    # Read current failure counts and throttle levels
    pipe = r.pipeline()
    pipe.get(ip_fail_key)
    pipe.get(global_fail_key)
    pipe.get(ip_key)
    pipe.get(global_key)
    ip_fails, global_fails, ip_level, global_level = pipe.execute()

    ip_fails = int(ip_fails or 0)
    global_fails = int(global_fails or 0)
    ip_level = int(ip_level or 0)
    global_level = int(global_level or 0)

    # Determine the effective level (use the higher of ip/global)
    effective_level = max(ip_level, global_level)

    if effective_level > 0:
        delay = _throttle_delay_for_level(effective_level)
        _log.warning(
            "Auth throttle: ip=%s level=%d delay=%ds",
            client_ip,
            effective_level,
            delay,
        )
        # RFC 6585 §4 — Retry-After header on 429.
        # Set on the response object so the header is present on the HTTPException
        # response (FastAPI propagates headers set before raise).
        response.headers["Retry-After"] = str(delay)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            headers={"Retry-After": str(delay)},
            detail={
                "error": "too_many_requests",
                "retry_after_seconds": delay,
                "banner": (
                    f"Too many failed login attempts. "
                    f"Please wait {delay} second{'s' if delay != 1 else ''} before trying again."
                ),
            },
        )


def _record_auth_failure(client_ip: str) -> None:
    """Increment failure counters and escalate throttle level if thresholds are exceeded.
    After exhausting the delay escalation (level > max), permanently block the IP."""
    r = _get_throttle_redis()
    ip_fail_key = f"auth:fail:ip:{client_ip}"
    global_fail_key = "auth:fail:global"
    ip_throttle_key = f"auth:throttle:ip:{client_ip}"
    global_throttle_key = "auth:throttle:global"

    pipe = r.pipeline()
    pipe.incr(ip_fail_key)
    pipe.expire(ip_fail_key, _THROTTLE_WINDOW_SECONDS)
    pipe.incr(global_fail_key)
    pipe.expire(global_fail_key, _THROTTLE_WINDOW_SECONDS)
    results = pipe.execute()
    ip_fails = results[0]
    global_fails = results[2]

    # Escalate per-IP throttle if threshold exceeded
    if ip_fails >= _THROTTLE_IP_THRESHOLD:
        current = int(r.get(ip_throttle_key) or 0)
        new_level = current + 1
        # After max delay level → permanent block
        if new_level > len(_THROTTLE_DELAYS):
            import json

            r.set(
                f"auth:blocked:{client_ip}",
                json.dumps(
                    {
                        "blocked_at": time.time(),
                        "reason": f"Exceeded max throttle level ({len(_THROTTLE_DELAYS)}) — permanent block",
                        "ip_failures": ip_fails,
                    }
                ),
            )  # No TTL = permanent
            _log.critical("AUTH IP BLOCKED PERMANENTLY: ip=%s failures=%d", client_ip, ip_fails)
        else:
            r.set(ip_throttle_key, new_level, ex=_THROTTLE_WINDOW_SECONDS)

    # Escalate global throttle if threshold exceeded
    if global_fails >= _THROTTLE_GLOBAL_THRESHOLD:
        current = int(r.get(global_throttle_key) or 0)
        new_level = current + 1
        r.set(global_throttle_key, new_level, ex=_THROTTLE_WINDOW_SECONDS)


def _reset_ip_auth_failures(client_ip: str) -> None:
    """On successful login, reset the per-IP counter (global decays via TTL)."""
    r = _get_throttle_redis()
    r.delete(f"auth:fail:ip:{client_ip}", f"auth:throttle:ip:{client_ip}")


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1)
    totp_code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=36)


class TotpConfirmRequest(BaseModel):
    totp_code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class SelfServiceResetRequest(BaseModel):
    username: str = Field(min_length=3)
    totp_code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


@router.post("/login")
async def login(body: LoginRequest, request: Request, response: Response):
    """
    Authenticate with username + password + TOTP.
    Issues a session cookie on success.
    Returns 401 for any failure (no credential enumeration).
    Includes brute-force throttle per ASVS 6.3.5.
    """
    client_ip = request.client.host if request.client else "unknown"

    # Check order: allowlist → blocklist → throttle → auth
    _check_ip_access(client_ip)
    _apply_auth_throttle(client_ip, response)

    state = backoffice_state
    assert state.auth_service is not None  # set unconditionally at startup
    assert state.session_store is not None  # set unconditionally at startup
    assert state.audit_writer is not None  # set unconditionally at startup

    # ACS gap #95 (auth_log): emit AUTH_LOGIN_ATTEMPT before result so forensic
    # queries can reconstruct the full attempt timeline even when the outcome is
    # not yet known. CMMC AU.L2-3.3.1 / ASVS V7.2.1.
    state.audit_writer.write(_make_login_attempt_event(body.username, client_ip))

    try:
        success, record, reason = await state.auth_service.authenticate(
            body.username,
            body.password,
            body.totp_code,
            audit_writer=state.audit_writer,  # ACS gap #95: propagate for ACCOUNT_LOCKOUT
        )
    except (ValueError, TypeError):
        _record_auth_failure(client_ip)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_credentials_format"},
        )

    if not success:
        _record_auth_failure(client_ip)
        state.audit_writer.write(_make_login_event(body.username, "failure", reason))
        # QA Wave 2 Issue 7 — do NOT disclose server_time to unauthenticated
        # callers. TOTP drift diagnostics only belong in authenticated flows
        # (/auth/password/change, /auth/totp/provision/confirm) where the
        # client has already proved they own an account.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "invalid_credentials",
                "hint": "If using TOTP, ensure your device clock is synchronised.",
            },
        )

    # Success — reset per-IP failure counter (global decays via TTL)
    _reset_ip_auth_failures(client_ip)

    # LAURA-V232-003: when force_totp_provision=True, authenticate() returns
    # reason="totp_provision_required" meaning the account has NOT yet set up
    # TOTP (or has been reset). Issue a RESTRICTED session with
    # account_tier="totp_provisioning" — accepted by require_any_session
    # (for /auth/totp/provision/* and /auth/password/change) but REJECTED by
    # require_admin_session (account_tier must be "admin"). This prevents an
    # attacker from using the provisioning-state bypass to gain a full admin
    # session before completing TOTP setup.
    #
    # The client must:
    #   1. POST /auth/totp/provision/start → QR code + seed
    #   2. POST /auth/totp/provision/confirm {totp_code} → clears flag
    #   3. Log out and log in again → authenticates with full TOTP → gets admin session
    if reason == "totp_provision_required":
        session = state.session_store.create(
            account_id=record.account_id,
            account_tier="totp_provisioning",
            client_ip=client_ip,
        )
        state.audit_writer.write(_make_login_event(body.username, "totp_provision_restricted", None))
        _log.info(
            "TOTP provisioning session issued for %s (force_totp_provision=True). "
            "Full admin access blocked until TOTP is provisioned.",
            body.username,
        )
        _set_session_cookie(response, session.token, "totp_provisioning")
        return {
            "status": "totp_provision_required",
            "force_password_change": record.force_password_change,
            "force_totp_provision": True,
            "message": (
                "Your account requires TOTP provisioning before you can "
                "access admin functions. POST to /auth/totp/provision/start "
                "to begin enrolment."
            ),
        }

    # Check password age against admin-configurable policy.
    #
    # YASHIGANI_PASSWORD_MAX_AGE_DAYS — explicit override. If set, it wins.
    # YASHIGANI_PROFILE — compliance profile that sets sensible defaults:
    #     "pci"    → 90 days (PCI DSS 8.3.9)
    #     "nist"   → 0 days / no expiry (NIST 800-63B discourages rotation)
    #     unset    → 0 days / no expiry (NIST-aligned default)
    # Hard cap: 395 days (13 months). Compliance review finding #9 — PCI-scoped
    # deployments need a ≤90d option without editing code.
    max_age_env = os.getenv("YASHIGANI_PASSWORD_MAX_AGE_DAYS")
    if max_age_env is not None:
        max_age_days = int(max_age_env)
    else:
        profile = os.getenv("YASHIGANI_PROFILE", "").strip().lower()
        if profile == "pci":
            max_age_days = 90
        else:
            max_age_days = 0  # NIST-aligned default (no forced rotation)
    if max_age_days > 395:
        max_age_days = 395  # Hard cap: 13 months
    if max_age_days > 0 and hasattr(record, "password_changed_at"):
        age_days = (time.time() - record.password_changed_at) / 86400
        if age_days > max_age_days:
            record.force_password_change = True
            _log.info("Password expired: user=%s age=%d days, max=%d", record.username, int(age_days), max_age_days)

    session = state.session_store.create(
        account_id=record.account_id,
        account_tier=record.account_tier,
        client_ip=client_ip,
    )

    state.audit_writer.write(_make_login_event(body.username, "success", None))

    _set_session_cookie(response, session.token, record.account_tier)
    return {
        "status": "ok",
        "force_password_change": record.force_password_change,
        "force_totp_provision": record.force_totp_provision,
    }


@router.post("/logout")
async def logout(
    session: AdminSession,
    response: Response,
    store=Depends(get_session_store),
):
    store.invalidate(session.token)
    response.delete_cookie(_SESSION_COOKIE, path="/")
    response.delete_cookie(_USER_SESSION_COOKIE, path="/")
    # AU.L2-3.3.1 / OWASP A09: emit audit event for every auth lifecycle action.
    # All other auth outcomes (login success/failure, totp_provision, stepup,
    # self_reset) are audited; logout was the only gap (yashigani-retro#95).
    state = backoffice_state
    if state.audit_writer is not None:
        state.audit_writer.write(_make_login_event(session.account_id, "logout", None))
    return {"status": "ok"}


@router.get("/status")
async def session_status(session: AdminSession):
    return {
        "account_id": session.account_id,
        "account_tier": session.account_tier,
        "expires_at": session.expires_at,
    }


@router.post("/password/self-reset")
async def self_service_password_reset(body: SelfServiceResetRequest):
    """
    Self-service password reset — no session required.
    User proves identity via username + TOTP code, receives a new temporary password.
    ASVS V2.1: authenticated password reset without admin intervention.
    """
    state = backoffice_state
    assert state.auth_service is not None  # set unconditionally at startup
    assert state.session_store is not None  # set unconditionally at startup
    assert state.audit_writer is not None  # set unconditionally at startup
    record = await state.auth_service.get_account(body.username)

    # Same generic error for unknown user or wrong TOTP (prevent enumeration).
    # QA Wave 2 Issue 7 — self-service password reset is unauthenticated by
    # design; do NOT leak server_time to callers who have not proved identity.
    generic_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={
            "error": "invalid_credentials",
            "hint": "If using TOTP, ensure your device clock is synchronised.",
        },
    )

    if record is None or record.disabled:
        raise generic_error

    if not record.totp_secret:
        raise generic_error

    # Use the auth service's Postgres-backed replay cache so the self-service
    # path can't be abused for TOTP replay.
    # pylint: disable=protected-access
    async with _pg_tenant_transaction() as conn:
        if not await state.auth_service._verify_totp_with_replay(conn, record.totp_secret, body.totp_code):
            raise generic_error

    # TOTP valid — generate new temporary password and persist via the
    # Postgres-backed auth service so the reset survives restart (P0-2).
    from yashigani.auth.password import generate_password, hash_password

    temp_password = generate_password(36)
    try:
        # check_breach=False: temp password is system-generated, not user-chosen.
        # HIBP check applies to user-chosen passwords only (ASVS V2.1.7).
        new_hash = hash_password(temp_password, check_breach=False)
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_credentials_format"},
        )
    # Apply the new password hash + force-change flag durably.
    async with _pg_tenant_transaction() as conn:
        await conn.execute(
            "UPDATE admin_accounts SET password_hash = $1, "
            "force_password_change = true, password_changed_at = $2 "
            "WHERE username = $3",
            new_hash,
            time.time(),
            record.username,
        )

    # Invalidate all sessions
    state.session_store.invalidate_all_for_account(record.account_id)

    state.audit_writer.write(_make_login_event(body.username, "self_reset", None))
    # ACS gap #95 (auth_log): SESSIONS_INVALIDATED event for session lifecycle audit.
    state.audit_writer.write(
        _make_sessions_invalidated_event(
            admin_account=body.username,
            acting_admin="",  # self-service reset
            reason="self_reset",
        )
    )

    return {
        "status": "ok",
        "temporary_password": temp_password,
        "force_password_change": True,
        "message": "Log in with this temporary password. You will be required to change it.",
    }


@router.get("/verify")
async def verify_session(request: Request):
    """
    Caddy forward_auth endpoint. Validates the session cookie and returns
    the authenticated user's identity in response headers.
    200 + X-Forwarded-User header → Caddy proceeds with the request.
    401 → Caddy redirects to login.
    Checks both user cookie (__Host-yashigani_session) and admin cookie (__Host-yashigani_admin_session).
    """
    state = backoffice_state
    assert state.auth_service is not None  # set unconditionally at startup
    assert state.session_store is not None  # set unconditionally at startup
    token = request.cookies.get(_USER_SESSION_COOKIE) or request.cookies.get(_SESSION_COOKIE)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    session = state.session_store.get(token)
    if session is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    # Resolve account from account_id
    record = await state.auth_service.get_account_by_id(session.account_id)

    if record is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    from starlette.responses import Response as StarletteResponse

    resp = StarletteResponse(status_code=200)
    # X-Forwarded-User must be an email for Open WebUI's trusted header auth
    email = record.email or f"{record.username}@yashigani.local"
    resp.headers["X-Forwarded-User"] = email
    resp.headers["X-Forwarded-Name"] = record.username
    resp.headers["X-Forwarded-Email"] = email
    return resp


@router.post("/password/change")
async def change_password(
    body: PasswordChangeRequest,
    session: AnySession,
    response: Response,
    store=Depends(get_session_store),
):
    """Force-change password. Invalidates ALL sessions (ASVS V2.1.4)."""
    state = backoffice_state
    assert state.auth_service is not None  # set unconditionally at startup
    assert state.audit_writer is not None  # set unconditionally at startup
    # Find account by account_id
    record = await _get_record_by_id(session.account_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"error": "account_not_found"})

    from yashigani.auth.password import verify_password, hash_password, PasswordBreachedError

    if not verify_password(body.current_password, record.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"error": "invalid_current_password"})

    old_hash = record.password_hash
    old_hash_tail = old_hash[-8:] if old_hash else ""
    try:
        new_hash = hash_password(body.new_password)
    except PasswordBreachedError as exc:
        # ASVS V2.1.7: breached passwords are rejected with a clear user-facing message.
        # 422 Unprocessable Entity — the request is structurally valid but semantically rejected.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "password_breached",
                "message": str(exc),
            },
        )
    except (ValueError, TypeError):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"error": "password_rejected"})
    new_hash_tail = new_hash[-8:]

    # -- CMMC L2 IA.L2-3.5.8: password reuse history check ------------------
    from yashigani.auth.local_auth import _get_history_depth
    from yashigani.auth.password import verify_password as _verify_pw

    history_depth = _get_history_depth()
    async with _pg_tenant_transaction() as conn:
        _history_rows = await conn.fetch(
            """
            SELECT password_hash FROM password_history
            WHERE user_id = $1::uuid
            ORDER BY changed_at DESC
            LIMIT $2
            """,
            record.account_id,
            history_depth,
        )
    for _hr in _history_rows:
        if _verify_pw(body.new_password, _hr["password_hash"]):
            # Emit audit event — user_id only, never password or hash.
            from yashigani.audit.schema import PasswordReuseRejectedEvent

            try:
                _evt = PasswordReuseRejectedEvent(
                    user_id=record.account_id,
                    history_depth_checked=history_depth,
                )
                state.audit_writer.write(_evt)
            except Exception:
                _log.warning("Failed to emit PASSWORD_REUSE_REJECTED event", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "error": "password_reuse",
                    "message": (
                        f"Password has been used recently. "
                        f"Choose a password not used in the last {history_depth} change(s)."
                    ),
                },
            )

    # -- Durable update via Postgres -----------------------------------------
    import datetime as _dt

    _now_ts = _dt.datetime.now(_dt.timezone.utc)
    _now_epoch = _now_ts.timestamp()
    async with _pg_tenant_transaction() as conn:
        await conn.execute(
            "UPDATE admin_accounts SET "
            "password_hash = $1, force_password_change = false, "
            "password_changed_at = $2 WHERE username = $3",
            new_hash,
            _now_epoch,
            record.username,
        )
        # Record old hash in history.
        await conn.execute(
            """
            INSERT INTO password_history (user_id, password_hash, changed_at)
            VALUES ($1::uuid, $2, $3)
            ON CONFLICT (user_id, changed_at) DO NOTHING
            """,
            record.account_id,
            old_hash,
            _now_ts,
        )
        # Prune oldest beyond depth.
        await conn.execute(
            """
            DELETE FROM password_history
            WHERE user_id = $1::uuid
              AND changed_at NOT IN (
                  SELECT changed_at FROM password_history
                  WHERE user_id = $1::uuid
                  ORDER BY changed_at DESC
                  LIMIT $2
              )
            """,
            record.account_id,
            history_depth,
        )
    record.password_hash = new_hash
    record.force_password_change = False
    record.password_changed_at = _now_epoch

    # Invalidate ALL sessions including current (ASVS V2.1.4)
    store.invalidate_all_for_account(session.account_id)
    response.delete_cookie(_SESSION_COOKIE)

    # ACS gap #95 (auth_log): dedicated PASSWORD_CHANGED event replaces the
    # generic ConfigChangedEvent, providing cleaner forensic queries.
    # ASVS 6.3.7: hash tails for forensics / reuse detection.
    state.audit_writer.write(
        _make_password_changed_event(
            record.username,
            change_type="forced" if record.force_password_change else "self_service",
            old_hash_tail=old_hash_tail,
            new_hash_tail=new_hash_tail,
        )
    )
    # ACS gap #95 (auth_log): SESSIONS_INVALIDATED event for session lifecycle audit.
    state.audit_writer.write(
        _make_sessions_invalidated_event(
            admin_account=record.username,
            acting_admin="",  # self-service password change
            reason="password_change",
        )
    )
    return {"status": "ok", "sessions_invalidated": True, "re_authentication_required": True}


@router.post("/totp/provision/start")
async def provision_totp_start(
    session: AnySession,
):
    """
    Start TOTP enrolment for the current account.

    Generates a fresh TOTP seed + recovery codes and returns the QR code
    + provisioning URI for the client to display. Does NOT clear
    ``force_totp_provision`` — the account cannot complete authenticated
    actions until :func:`provision_totp_confirm` verifies a code derived
    from the returned seed.

    Part of the split-enrolment flow (QA Wave 2 Issue C). The previous
    atomic ``/totp/provision`` required a ``totp_code`` on the same call
    that returned the seed, which was impossible for a first-time client.
    """
    state = backoffice_state
    assert state.auth_service is not None  # set unconditionally at startup
    record = await _get_record_by_id(session.account_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": "account_not_found"})

    prov, _code_set = await state.auth_service.provision_totp_start(record.username)

    return {
        "status": "pending_confirmation",
        "qr_code_png_b64": prov.qr_code_png_b64,
        "provisioning_uri": prov.provisioning_uri,
        "recovery_codes": prov.recovery_codes,  # shown once — client must acknowledge
        "recovery_codes_count": len(prov.recovery_codes),
        "message": (
            "Scan the QR code with your authenticator app, then POST the "
            "current 6-digit code to /auth/totp/provision/confirm to "
            "complete enrolment. Store the recovery codes securely — "
            "they will not be shown again."
        ),
    }


@router.post("/totp/provision/confirm")
async def provision_totp_confirm(
    body: TotpConfirmRequest,
    session: AnySession,
):
    """
    Finalise TOTP enrolment by confirming a code generated from the seed
    returned by :func:`provision_totp_start`.

    On success the account is fully enrolled
    (``force_totp_provision=False``). On failure the seed is preserved
    so the client can retry without losing the QR code / recovery codes
    (protects against time-drift and typo retries).
    """
    state = backoffice_state
    assert state.auth_service is not None  # set unconditionally at startup
    assert state.audit_writer is not None  # set unconditionally at startup
    record = await _get_record_by_id(session.account_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": "account_not_found"})

    ok, reason = await state.auth_service.provision_totp_confirm(record.username, body.totp_code)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": reason,
                "message": (
                    "TOTP code did not match the seed issued by "
                    "/auth/totp/provision/start. Ensure your authenticator "
                    "app clock is synchronised and retry with a fresh code."
                ),
            },
        )

    state.audit_writer.write(_make_provision_event(record.username))

    return {"status": "ok", "message": "TOTP enrolment complete."}


@router.post("/totp/provision")
async def provision_totp(
    body: TotpConfirmRequest,
    session: AnySession,
    response: Response,
):
    """
    Atomic TOTP enrolment — back-compat for clients that already hold
    the seed (e.g. CLI provisioning flows where the secret is delivered
    out-of-band). Generates a fresh seed, verifies the provided code
    against it, and on success commits the enrolment in one call.

    For the first-time web-UI flow, prefer the split endpoints:
    :func:`provision_totp_start` + :func:`provision_totp_confirm`
    (QA Wave 2 Issue C).
    """
    state = backoffice_state
    assert state.auth_service is not None  # set unconditionally at startup
    assert state.audit_writer is not None  # set unconditionally at startup
    record = await _get_record_by_id(session.account_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": "account_not_found"})

    prov, _code_set = await state.auth_service.provision_totp_start(record.username)

    # Verify the user-supplied code against the freshly-stored seed.
    ok, reason = await state.auth_service.provision_totp_confirm(record.username, body.totp_code)
    if not ok:
        # Rollback — clear the newly-set seed in the durable store so the
        # account is back to its pre-call state and the client can retry
        # cleanly.
        await state.auth_service.force_totp_reprovision(record.username)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_totp_code", "message": "TOTP code did not match. Re-scan the QR code."},
        )

    state.audit_writer.write(_make_provision_event(record.username))

    return {
        "status": "ok",
        "qr_code_png_b64": prov.qr_code_png_b64,
        "provisioning_uri": prov.provisioning_uri,
        "recovery_codes": prov.recovery_codes,  # shown once — client must acknowledge
        "recovery_codes_count": len(prov.recovery_codes),
        "message": "Store these recovery codes securely. They will not be shown again.",
    }


# ---------------------------------------------------------------------------
# Step-up TOTP verification (ASVS V6.8.4)
# ---------------------------------------------------------------------------


class StepUpRequest(BaseModel):
    totp_code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


@router.post("/stepup")
async def stepup_verify(
    body: StepUpRequest,
    session: AdminSession,
    store=Depends(get_session_store),
):
    """
    Step-up TOTP verification for high-value admin flows (ASVS V6.8.4).

    The admin submits their current TOTP code.  On success, the session's
    last_totp_verified_at is updated.  The caller may then retry the
    high-value endpoint that returned step_up_required.  The verification
    window is YASHIGANI_STEPUP_TTL_SECONDS (default 300 s / 5 min).

    Security guarantees:
    - Replay prevention: codes are checked against the Postgres-backed
      used_totp_codes table (same mechanism as login TOTP).
    - Wrong code: 401, session is NOT updated, TOTP failure counter is
      incremented on the session prefix.
    - No credential enumeration: same HTTP 401 body for wrong code or
      no session.
    """
    state = backoffice_state
    assert state.auth_service is not None  # set unconditionally at startup
    assert state.audit_writer is not None  # set unconditionally at startup

    # Resolve the admin record to get the TOTP secret.
    admin_record = await state.auth_service.get_account_by_id(session.account_id)
    if admin_record is None or not admin_record.totp_secret:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "totp_not_configured"},
        )

    # Check per-session step-up failure counter (simple in-memory dict,
    # keyed on session token prefix — limits to 3 wrong codes then lock).
    session_prefix = session.token[:8]
    failure_count = _totp_failures.get(session_prefix, 0)
    if failure_count >= _TOTP_FAILURE_LIMIT:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": "stepup_attempts_exceeded",
                "message": "Too many failed step-up attempts. Please log out and log in again.",
            },
        )

    # Verify against Postgres-backed replay cache (same path as login).
    async with _pg_tenant_transaction() as conn:
        ok = await state.auth_service._verify_totp_with_replay(conn, admin_record.totp_secret, body.totp_code)

    if not ok:
        _totp_failures[session_prefix] = failure_count + 1
        state.audit_writer.write(_make_stepup_event(admin_record.username, "failure"))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "invalid_totp_code",
                "hint": "Ensure your device clock is synchronised.",
            },
        )

    # Success — record step-up timestamp in Redis session, clear failure counter.
    _totp_failures.pop(session_prefix, None)
    store.record_totp_stepup(session.token)
    state.audit_writer.write(_make_stepup_event(admin_record.username, "success"))

    from yashigani.auth.stepup import STEPUP_TTL_SECONDS

    return {
        "status": "ok",
        "stepup_verified": True,
        "ttl_seconds": STEPUP_TTL_SECONDS,
        "message": "Step-up verified. You may now retry the high-value action.",
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_USER_SESSION_COOKIE = "__Host-yashigani_session"


def _set_session_cookie(response: Response, token: str, account_tier: str = "admin") -> None:
    if account_tier == "admin":
        response.set_cookie(
            key=_SESSION_COOKIE,
            value=token,
            httponly=True,
            secure=True,
            samesite="strict",
            max_age=14400,  # 4 hours absolute
            path="/",  # __Host- prefix requires Path=/
        )
    # Always set the user-level cookie (used by forward_auth for Open WebUI)
    response.set_cookie(
        key=_USER_SESSION_COOKIE,
        value=token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=14400,
        path="/",
    )


# ---------------------------------------------------------------------------
# Admin IP access control — blocklist + allowlist (fail2ban-style)
# ---------------------------------------------------------------------------


@router.get("/blocked-ips")
async def list_blocked_ips(request: Request, session: AdminSession):
    """List permanently blocked IPs AND currently soft-throttled IPs.

    Previously only returned permanent blocks, which gave operators no
    self-visibility when they were themselves being slow-throttled
    (QA Wave 2 Issue F). Now includes:

      * ``blocked_ips`` — permanent blocks (auth:blocked:*)
      * ``throttled_ips`` — IPs with a current non-zero throttle level
        (auth:throttle:ip:* > 0), mapped to {level, delay_s, fail_count}
      * ``self`` — the caller's own IP + throttle state so an admin
        can see if they are throttled from the UI (fixes the "login
        page hangs and /auth/blocked-ips says {}" diagnostic gap)
    """
    import json

    r = _get_throttle_redis()

    # Permanent blocks (existing behaviour)
    blocked: dict = {}
    for key in r.scan_iter("auth:blocked:*"):
        ip = key.decode().split("auth:blocked:")[-1] if isinstance(key, bytes) else key.split("auth:blocked:")[-1]
        data = r.get(key)
        try:
            blocked[ip] = json.loads(data) if data else {"reason": "unknown"}
        except (json.JSONDecodeError, TypeError):
            blocked[ip] = {"reason": str(data)}

    # Soft-throttle state — every IP with a non-zero throttle level
    throttled: dict = {}
    for key in r.scan_iter("auth:throttle:ip:*"):
        key_str = key.decode() if isinstance(key, bytes) else key
        ip = key_str.split("auth:throttle:ip:")[-1]
        level_raw = r.get(key_str)
        level = int(level_raw or 0)
        if level <= 0:
            continue
        fail_raw = r.get(f"auth:fail:ip:{ip}")
        throttled[ip] = {
            "level": level,
            "delay_s": _throttle_delay_for_level(level),
            "fail_count": int(fail_raw or 0),
        }

    # Caller's own state — resolved from request headers so the admin
    # sees exactly what server-side records about their IP, even when
    # they are being throttled (non-200 paths still emit this view).
    caller_ip = request.client.host if request.client else "unknown"
    caller_level = int(r.get(f"auth:throttle:ip:{caller_ip}") or 0)
    caller_fails = int(r.get(f"auth:fail:ip:{caller_ip}") or 0)
    caller_blocked_data = r.get(f"auth:blocked:{caller_ip}")
    self_state = {
        "ip": caller_ip,
        "fail_count": caller_fails,
        "throttle_level": caller_level,
        "delay_s": _throttle_delay_for_level(caller_level) if caller_level > 0 else 0,
        "permanently_blocked": caller_blocked_data is not None,
    }

    return {
        "blocked_ips": blocked,
        "throttled_ips": throttled,
        "self": self_state,
        "total": len(blocked),
        "total_throttled": len(throttled),
    }


@router.delete("/blocked-ips/{ip}")
async def unblock_ip(ip: str, session: AdminSession):
    """Remove an IP from the permanent blocklist (admin only)."""
    r = _get_throttle_redis()
    key = f"auth:blocked:{ip}"
    if r.exists(key):
        r.delete(key)
        _log.info("Admin %s unblocked IP: %s", session.account_id, ip)
        return {"status": "ok", "unblocked": ip}
    raise HTTPException(status_code=404, detail={"error": "ip_not_found"})


@router.get("/allowed-ips")
async def list_allowed_ips(session: AdminSession):
    """List all IPs/CIDRs in the login allowlist. Empty = allow all."""
    r = _get_throttle_redis()
    entries = r.smembers("auth:allowlist")
    allowed = [e.decode() if isinstance(e, bytes) else e for e in entries]
    return {
        "allowed_ips": sorted(allowed),
        "total": len(allowed),
        "mode": "restrict" if allowed else "open (all IPs permitted)",
    }


@router.post("/allowed-ips")
async def add_allowed_ip(request: Request, session: AdminSession):
    """Add an IP or CIDR to the login allowlist. Supports IPv4 and IPv6."""
    import ipaddress

    body = await request.json()
    entry = body.get("ip", "").strip()
    if not entry:
        raise HTTPException(status_code=400, detail={"error": "ip_required"})
    # Validate IPv4/IPv6 address or network
    try:
        if "/" in entry:
            ipaddress.ip_network(entry, strict=False)
        else:
            ipaddress.ip_address(entry)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_ip", "message": f"'{entry}' is not a valid IPv4/IPv6 address or CIDR range"},
        )
    r = _get_throttle_redis()
    r.sadd("auth:allowlist", entry)
    _log.info("Admin %s added IP to allowlist: %s", session.account_id, entry)
    return {"status": "ok", "added": entry}


@router.delete("/allowed-ips/{ip_or_cidr:path}")
async def remove_allowed_ip(ip_or_cidr: str, session: AdminSession):
    """Remove an IP/CIDR from the allowlist."""
    r = _get_throttle_redis()
    removed = r.srem("auth:allowlist", ip_or_cidr)
    if removed:
        _log.info("Admin %s removed IP from allowlist: %s", session.account_id, ip_or_cidr)
        return {"status": "ok", "removed": ip_or_cidr}
    raise HTTPException(status_code=404, detail={"error": "entry_not_found"})


async def _get_record_by_id(account_id: str):
    state = backoffice_state
    if state.auth_service is None:
        return None
    return await state.auth_service.get_account_by_id(account_id)


def _make_login_event(username: str, outcome: str, reason):
    from yashigani.audit.schema import AdminLoginEvent

    return AdminLoginEvent(
        account_tier="admin",
        admin_account=username,
        outcome=outcome,
        failure_reason=reason,
    )


def _make_config_event(username: str, setting: str, prev: str, new: str):
    from yashigani.audit.schema import ConfigChangedEvent

    return ConfigChangedEvent(
        account_tier="admin",
        admin_account=username,
        setting=setting,
        previous_value=prev,
        new_value=new,
    )


def _make_provision_event(username: str):
    from yashigani.audit.schema import TotpProvisionCompletedEvent

    return TotpProvisionCompletedEvent(
        account_tier="admin",
        user_handle=username,
    )


def _make_stepup_event(username: str, outcome: str):
    from yashigani.audit.schema import AdminLoginEvent

    return AdminLoginEvent(
        account_tier="admin",
        admin_account=username,
        outcome=f"stepup_{outcome}",
        failure_reason=None if outcome == "success" else "invalid_totp",
    )


def _make_login_attempt_event(username: str, client_ip: str):
    """ACS gap #95: emit AUTH_LOGIN_ATTEMPT before auth result."""
    from yashigani.audit.schema import AuthLoginAttemptEvent

    # Mask the last octet of the IP for lower-assurance sinks.
    # IPv4: a.b.c.d → a.b.c.0   IPv6: strip last group.
    parts = client_ip.rsplit(".", 1)
    ip_prefix = f"{parts[0]}.0" if len(parts) == 2 else client_ip
    return AuthLoginAttemptEvent(
        account_tier="admin",
        admin_account=username,
        client_ip_prefix=ip_prefix,
        outcome="attempt",
    )


def _make_password_changed_event(
    username: str,
    *,
    change_type: str,
    old_hash_tail: str,
    new_hash_tail: str,
):
    """ACS gap #95: dedicated PASSWORD_CHANGED event."""
    from yashigani.audit.schema import PasswordChangedEvent

    return PasswordChangedEvent(
        account_tier="admin",
        admin_account=username,
        change_type=change_type,
        old_hash_tail=old_hash_tail,
        new_hash_tail=new_hash_tail,
        sessions_invalidated=True,
    )


def _make_sessions_invalidated_event(
    *,
    admin_account: str,
    acting_admin: str,
    reason: str,
    sessions_count: int = -1,
):
    """ACS gap #95: SESSIONS_INVALIDATED event for session lifecycle audit."""
    from yashigani.audit.schema import SessionsInvalidatedEvent

    return SessionsInvalidatedEvent(
        account_tier="admin",
        admin_account=admin_account,
        acting_admin=acting_admin,
        reason=reason,
        sessions_count=sessions_count,
    )
