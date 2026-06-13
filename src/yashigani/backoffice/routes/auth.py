"""
Yashigani Backoffice — Authentication routes.
POST /auth/login                   — username + password + TOTP (returns redirect_to for role routing)
POST /auth/logout                  — invalidate session (any session tier — single-logout fix)
GET  /auth/logout-redirect         — browser-navigable single-logout (Phase 2: OWUI signout redirect target)
GET  /auth/status                  — check session validity
GET  /auth/verify                  — Caddy forward_auth for data-plane (user sessions only)
GET  /auth/verify-admin            — Caddy forward_auth for /admin/* (admin sessions only)
GET  /auth/verify-user             — Caddy forward_auth for /app/webui and user paths (user sessions only; rejects admin)
POST /auth/password/change         — forced change on first login
POST /auth/totp/provision          — TOTP + recovery codes provisioning
POST /auth/stepup                  — V6.8.4 step-up TOTP verification for high-value flows
GET  /auth/post-login-redirect     — server-side next= validator + redirect (drift audit #6)

Phase 1 changes (2026-06-12, feat/2.25.5-auth-ingress):
  - login() now returns redirect_to ("/admin/" for admin, "/app/webui" for user) so the
    login JS can navigate role-appropriately without a separate server roundtrip.
  - logout() changed from AdminSession → AnySession: user-tier sessions were trapped
    because the admin-only guard prevented logout (the "no end-user logout" bug).
  - verify-user endpoint added: accepts user-tier sessions, explicitly rejects admin
    sessions.  Caddy uses it for the /app/webui forward_auth leg.
  - Both /auth/verify and /auth/verify-user reject admin sessions (SoD-003 preserved).

Phase 2 changes (2026-06-13, feat/2.25.5-auth-ingress):
  - logout-redirect endpoint added: GET version of logout for browser navigation.
    OWUI's WEBUI_AUTH_SIGNOUT_REDIRECT_URL points here so its logout button clears
    the Yashigani session cookie.  See Phase 2 notes.

Last updated: 2026-06-13T00:00:00+00:00
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import time

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse as _RedirectResponse
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import AdminSession, AnySession, get_session_store, _SESSION_COOKIE
from yashigani.backoffice.state import backoffice_state
from yashigani.db.postgres import tenant_transaction as _pg_tenant_transaction_impl

_PLATFORM_TENANT_ID = "00000000-0000-0000-0000-000000000000"


def _pg_tenant_transaction():
    """Shorthand: open a platform-scoped transaction on the shared pool."""
    return _pg_tenant_transaction_impl(_PLATFORM_TENANT_ID)


router = APIRouter()

# ---------------------------------------------------------------------------
# TOTP step-up failure counter (SEC-4 / ASVS V6.3.5)
#
# Migrated from module-level Python dict to Redis so the counter survives
# process restarts and is consistent across multi-replica deployments.
#
# Key:   yashigani:totp_fail:<session_prefix>
# TTL:   _TOTP_FAILURE_TTL_SECONDS (1800 s) — gives a >30-min window per
#        RFC 6238 clock-skew allowance while still expiring eventually.
# Limit: _TOTP_FAILURE_LIMIT (3) — unchanged from previous in-memory behaviour.
#
# Fail-closed: if Redis is unavailable the helper raises RuntimeError which
# the route handler converts to HTTP 503 (same fail-closed stance as login
# rate limiter).
# ---------------------------------------------------------------------------

_TOTP_FAILURE_LIMIT = 3
_TOTP_FAILURE_TTL_SECONDS = 1800  # 30-minute window; covers RFC 6238 clock skew

_log = logging.getLogger("yashigani.auth")


def _totp_fail_key(session_prefix: str) -> str:
    """Redis key for the TOTP step-up failure counter for a session prefix."""
    return f"yashigani:totp_fail:{session_prefix}"


def _totp_incr_failure(session_prefix: str) -> int:
    """
    Increment TOTP step-up failure counter for *session_prefix* and return the
    new count.  Sets TTL to _TOTP_FAILURE_TTL_SECONDS on first increment.

    Fail-closed: raises RuntimeError if Redis is unavailable.
    """
    r = _get_throttle_redis()
    key = _totp_fail_key(session_prefix)
    pipe = r.pipeline()
    pipe.incr(key)
    pipe.expire(key, _TOTP_FAILURE_TTL_SECONDS)
    results = pipe.execute()
    return int(results[0])


def _totp_get_count(session_prefix: str) -> int:
    """Return current failure count for *session_prefix* (0 if key absent)."""
    r = _get_throttle_redis()
    raw = r.get(_totp_fail_key(session_prefix))
    return int(raw) if raw else 0


def _totp_reset(session_prefix: str) -> None:
    """Delete the TOTP step-up failure counter for *session_prefix* on success."""
    r = _get_throttle_redis()
    r.delete(_totp_fail_key(session_prefix))

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
        try:
            from yashigani.metrics.registry import auth_login_attempts_total
            auth_login_attempts_total.labels(outcome="failure").inc()
        except Exception:  # noqa: BLE001 — metric must never break auth
            pass
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
        state.audit_writer.write(_make_login_event(body.username, "totp_provision_restricted", None, account_tier=record.account_tier))
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

    # Gap 3 / v2.23.4 arch-completion: register HUMAN identity before session
    # creation so a seat-limit rejection prevents session issuance (fail-closed).
    # Skips silently when identity_registry is None (community-tier).
    # Raises HTTPException(403) when the licence seat limit is exhausted.
    _register_human_identity_on_login(record, state)

    session = state.session_store.create(
        account_id=record.account_id,
        account_tier=record.account_tier,
        client_ip=client_ip,
    )

    state.audit_writer.write(_make_login_event(body.username, "success", None, account_tier=record.account_tier))
    try:
        from yashigani.metrics.registry import auth_login_attempts_total
        auth_login_attempts_total.labels(outcome="success").inc()
    except Exception:  # noqa: BLE001 — metric must never break auth
        pass

    # Phase 1 / 2.25.5-auth-ingress: single portal, role-based redirect.
    # admin → /admin/  (admin console)
    # user  → /app/webui  (placeholder until Phase 2 re-paths OWUI)
    # Any other tier (totp_provisioning is handled above) → / as safe fallback.
    if record.account_tier == "admin":
        redirect_to = "/admin/"
    elif record.account_tier == "user":
        redirect_to = "/app/webui"
    else:
        redirect_to = "/"

    _set_session_cookie(response, session.token, record.account_tier)
    return {
        "status": "ok",
        "force_password_change": record.force_password_change,
        "force_totp_provision": record.force_totp_provision,
        # role-based redirect destination for the login JS; validated server-side
        # by /auth/post-login-redirect when following the normal login flow.
        "redirect_to": redirect_to,
    }


@router.post("/logout")
async def logout(
    session: AnySession,  # Phase 1 fix: was AdminSession — user-tier sessions were trapped (no end-user logout bug)
    response: Response,
    store=Depends(get_session_store),
):
    """
    Single-logout endpoint.  Clears the session regardless of tier (admin or user).

    Phase 1 / 2.25.5-auth-ingress: changed from AdminSession → AnySession so
    user-tier accounts can reach this endpoint.  Previously a user-tier session
    received HTTP 403 from require_admin_session and was permanently trapped
    (no working end-user logout).

    Security: the session token is invalidated in Redis and BOTH cookies
    (__Host-yashigani_admin_session and __Host-yashigani_session) are cleared.
    An expired/invalidated session calling this endpoint returns HTTP 401 from
    require_any_session before reaching this handler — no unauthenticated
    session-clearing is possible.
    """
    store.invalidate(session.token)
    response.delete_cookie(_SESSION_COOKIE, path="/")
    response.delete_cookie(_USER_SESSION_COOKIE, path="/")
    # AU.L2-3.3.1 / OWASP A09: emit audit event for every auth lifecycle action.
    state = backoffice_state
    if state.audit_writer is not None:
        state.audit_writer.write(_make_login_event(session.account_id, "logout", None, account_tier=session.account_tier))
    return {"status": "ok"}


@router.get("/logout-redirect")
async def logout_redirect(
    request: Request,
    response: Response,
    store=Depends(get_session_store),
):
    """
    Browser-navigable single-logout endpoint.

    Phase 2 / 2.25.5-auth-ingress: OWUI (with WEBUI_AUTH=false) calls its own
    /api/v1/auths/signout endpoint, which — when WEBUI_AUTH_SIGNOUT_REDIRECT_URL is
    set — returns {"status": true, "redirect_url": "<url>"} to the SvelteKit client.
    The client then navigates the browser to that URL.  We point it here so clicking
    the logout button inside /app/webui actually clears the Yashigani session cookie.

    Behaviour:
      - Valid session (admin or user): invalidate in Redis, clear both cookies,
        redirect to /login.
      - No session / expired session: clear cookies defensively, redirect to /login.
        (Not a security issue: if there is nothing to invalidate, forcing the user
        back to /login is correct.)

    Security: this is a GET handler that modifies state.  The CSRF risk is accepted
    because:
      1. Logging out is not a sensitive state change (worst-case: nuisance logout).
      2. OWUI does NOT support submitting a POST form redirect via WEBUI_AUTH_SIGNOUT_REDIRECT_URL;
         it only performs a browser navigation (window.location).
      3. The action is idempotent — a forged logout just forces a re-login.
    """
    # Try to read the session token from either cookie name.
    token = (
        request.cookies.get(_USER_SESSION_COOKIE)
        or request.cookies.get(_SESSION_COOKIE)
    )

    state = backoffice_state
    if token:
        try:
            store.invalidate(token)
            if state.audit_writer is not None:
                # Resolve the account_id from the session if it is still valid.
                session_data = store.get(token)
                account_id = session_data.account_id if session_data else "unknown"
                state.audit_writer.write(
                    _make_login_event(account_id, "logout", None)
                )
        except Exception:
            # Session already expired / gone — still clear the cookies.
            pass

    redirect = _RedirectResponse(url="/login", status_code=302)
    redirect.delete_cookie(_SESSION_COOKIE, path="/")
    redirect.delete_cookie(_USER_SESSION_COOKIE, path="/")
    return redirect


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

    state.audit_writer.write(_make_login_event(body.username, "self_reset", None, account_tier=record.account_tier))
    # ACS gap #95 (auth_log): SESSIONS_INVALIDATED event for session lifecycle audit.
    state.audit_writer.write(
        _make_sessions_invalidated_event(
            admin_account=body.username,
            acting_admin="",  # self-service reset
            reason="self_reset",
            account_tier=record.account_tier,
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

    # SoD-003: admin sessions MUST NOT traverse the data plane.
    # Admins authenticate to port 8443 (backoffice) only. Any admin session
    # presented to /auth/verify (Caddy forward_auth) is categorically rejected.
    # This is layer 2 of the SoD-004 defence (layer 1 = SoD-002c in sso.py).
    # NIST AC-5 / OWASP ASVS V4.1.2 / ISO 27001 A.5.16 / v2.24.1 Iris #96.
    if session.account_tier == "admin":
        from yashigani.audit.schema import AuthVerifyRejectedAdminSessionEvent
        _client_ip = request.client.host if request.client else "unknown"
        from yashigani.auth.session import _mask_ip as _verify_mask_ip
        if state.audit_writer is not None:
            state.audit_writer.write(AuthVerifyRejectedAdminSessionEvent(
                account_id=session.account_id,
                client_ip_prefix=_verify_mask_ip(_client_ip),
            ))
        _log.warning(
            "SoD-003: /auth/verify rejected admin session account_id=%s — admins cannot use the data plane",
            session.account_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "admin_session_not_allowed_data_plane",
                "message": (
                    "Admin accounts cannot access the data plane. "
                    "If you need user-tier access, create a separate user account with a different username."
                ),
            },
        )

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


@router.get("/verify-admin")
async def verify_admin_session(request: Request):
    """
    Caddy forward_auth for ADMIN-only operator proxies (Grafana / Wazuh / Prometheus
    under /admin/*). This is the INVERSE of /auth/verify: it REQUIRES a valid admin
    session (account_tier == "admin") and rejects user-tier, provisioning-state, and
    anonymous requests.

    SoD-003 bars admins from the DATA plane (/auth/verify), but the operator
    monitoring dashboards are an ADMIN function — admins must reach them and normal
    users must not. Using /auth/verify here (the bug) rejected admins outright.
    200 + identity headers → Caddy proceeds. 401 → redirect to /admin/login.
    """
    state = backoffice_state
    assert state.auth_service is not None  # set unconditionally at startup
    assert state.session_store is not None  # set unconditionally at startup
    token = request.cookies.get(_SESSION_COOKIE)  # admin cookie only
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    session = state.session_store.get(token)
    if session is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    if session.account_tier != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "admin_session_required",
                "message": "These operator dashboards require an admin session.",
            },
        )
    record = await state.auth_service.get_account_by_id(session.account_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    from starlette.responses import Response as StarletteResponse

    resp = StarletteResponse(status_code=200)
    email = record.email or f"{record.username}@yashigani.local"
    resp.headers["X-Forwarded-User"] = email
    resp.headers["X-Forwarded-Name"] = record.username
    resp.headers["X-Forwarded-Email"] = email
    return resp


@router.get("/verify-user")
async def verify_user_session(request: Request):
    """
    Caddy forward_auth endpoint for USER paths (/app/webui and its sub-paths).

    Phase 1 / 2.25.5-auth-ingress.  The split-verify pattern:
      /auth/verify-admin → admin sessions only  (for /admin/*)
      /auth/verify       → user sessions only   (existing data-plane / OWUI catch-all)
      /auth/verify-user  → user sessions only   (this endpoint, for /app/webui)

    Accepts any authenticated SESSION with account_tier == "user".
    Rejects admin sessions with HTTP 403 (SoD preserved — admins never reach the
    user/OWUI path, even if they have a valid session).
    Rejects unauthenticated or expired sessions with HTTP 401.

    On 200: sets X-Forwarded-User/Name/Email headers for OWUI trusted-header auth.
    On 401: Caddy redirects to /login?next=<path>.
    On 403: Caddy surfaces an authorization error (not a login redirect).

    NIST AC-5 / ASVS V4.1.2 / design: auth-ingress-architecture-20260612.md
    """
    state = backoffice_state
    assert state.auth_service is not None  # set unconditionally at startup
    assert state.session_store is not None  # set unconditionally at startup

    # Accept both user cookie and admin cookie names for flexibility; the tier
    # check below enforces the actual restriction.
    token = request.cookies.get(_USER_SESSION_COOKIE) or request.cookies.get(_SESSION_COOKIE)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    session = state.session_store.get(token)
    if session is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    # Admin sessions MUST NOT access user paths.
    # This is the /app/webui-side mirror of SoD-003 (which blocks admin on /auth/verify).
    if session.account_tier == "admin":
        _log.warning(
            "verify-user: rejected admin session account_id=%s — "
            "admins cannot access user paths (/app/webui)",
            session.account_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "admin_session_not_allowed_user_path",
                "message": (
                    "Admin accounts cannot access user paths. "
                    "Use your admin console at /admin/."
                ),
            },
        )

    # Reject provisioning-state sessions (must finish TOTP enrolment first).
    if session.account_tier == "totp_provisioning":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "totp_provisioning_incomplete",
                "message": "Complete TOTP enrolment before accessing this resource.",
            },
        )

    # Only user-tier sessions proceed past this point.
    if session.account_tier != "user":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "insufficient_tier",
                "message": "This path requires a user-tier session.",
            },
        )

    record = await state.auth_service.get_account_by_id(session.account_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    from starlette.responses import Response as StarletteResponse

    resp = StarletteResponse(status_code=200)
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
            account_tier=record.account_tier,
        )
    )
    # ACS gap #95 (auth_log): SESSIONS_INVALIDATED event for session lifecycle audit.
    state.audit_writer.write(
        _make_sessions_invalidated_event(
            admin_account=record.username,
            acting_admin="",  # self-service password change
            reason="password_change",
            account_tier=record.account_tier,
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

    state.audit_writer.write(_make_provision_event(record.username, account_tier=record.account_tier))

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

    state.audit_writer.write(_make_provision_event(record.username, account_tier=record.account_tier))

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
    session: AnySession,
    store=Depends(get_session_store),
):
    """
    Step-up TOTP verification for high-value flows (ASVS V6.8.4).

    Accepts any authenticated session (admin OR regular user) so that
    user-tier accounts can satisfy the assert_fresh_stepup prerequisite
    required by POST /me/api-key.  Anonymous and expired sessions are
    rejected by the AnySession dependency before this handler runs.

    The caller submits their current TOTP code.  On success, the session's
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
    - Cross-tenant isolation: account is resolved by session.account_id
      against the platform DB; a session with a fabricated/wrong-tenant
      account_id will find no record → 403 totp_not_configured.
    - Tier scope: widened from admin-only to any-session. Admin step-up
      semantics (audit events, replay cache, failure counter) are identical.
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

    # Check per-session step-up failure counter.
    # SEC-4 / ASVS V6.3.5: migrated from module-level dict to Redis so the
    # counter survives process restarts and is consistent across replicas.
    session_prefix = session.token[:8]
    try:
        failure_count = _totp_get_count(session_prefix)
    except Exception as exc:
        # Redis unavailable — fail-closed per SOP 1 (no silent allow).
        _log.error("SEC-4: Redis unavailable for TOTP step-up counter check: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "totp_service_unavailable",
                "message": "Authentication service temporarily unavailable.",
            },
        )

    if failure_count >= _TOTP_FAILURE_LIMIT:
        # Emit lockout audit event with full forensic context.
        from yashigani.audit.schema import AdminSessionTotpLockoutEvent
        state.audit_writer.write(
            AdminSessionTotpLockoutEvent(
                account_tier=admin_record.account_tier,
                admin_account=admin_record.username,
                endpoint="/auth/stepup",
                consecutive_failures=failure_count,
            )
        )
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
        try:
            _totp_incr_failure(session_prefix)
        except Exception as exc:
            _log.error("SEC-4: Redis unavailable for TOTP failure increment: %s", exc)
            # Still reject the bad TOTP code even if we can't count it.
            # (fail-closed on the auth result; counter loss is the lesser evil)
        state.audit_writer.write(_make_stepup_event(admin_record.username, "failure", admin_record.account_tier))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "invalid_totp_code",
                "hint": "Ensure your device clock is synchronised.",
            },
        )

    # Success — record step-up timestamp in Redis session, clear failure counter.
    try:
        _totp_reset(session_prefix)
    except Exception as exc:
        _log.warning("SEC-4: Redis unavailable for TOTP counter reset: %s", exc)
        # Non-fatal: successful auth proceeds; counter will expire via TTL.
    store.record_totp_stepup(session.token)
    state.audit_writer.write(_make_stepup_event(admin_record.username, "success", admin_record.account_tier))

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
# LU-AMEND-04: Operator identity attestation token for yashigani onboard
# ---------------------------------------------------------------------------

# Short-lived operator token TTL: 15 minutes. Enough for a single onboard
# ceremony; short enough to minimise the value of a leaked token.
_OPERATOR_TOKEN_TTL_SECONDS: int = int(os.getenv("YASHIGANI_OPERATOR_TOKEN_TTL", "900"))


class OperatorTokenRequest(BaseModel):
    """Request body for POST /auth/operator-token."""

    issued_for: str = Field(
        default="",
        max_length=256,
        description="Optional free-text note describing the onboard ceremony (e.g. agent name).",
    )


@router.post("/operator-token")
async def issue_operator_token(
    body: OperatorTokenRequest,
    session: AdminSession,
    request: Request,
):
    """
    Issue a short-lived operator identity token for use with `yashigani onboard`.

    Prerequisites:
      - Active admin session (AdminSession dependency — cookie auth).
      - Fresh step-up TOTP (assert_fresh_stepup — within YASHIGANI_STEPUP_TTL_SECONDS).

    Returns a signed JWT with:
      - sub:  admin username (the issuing operator identity)
      - jti:  UUID4 (enables cross-correlation in the audit log)
      - iat:  issued-at (Unix timestamp)
      - exp:  expiry = iat + _OPERATOR_TOKEN_TTL_SECONDS
      - iss:  "yashigani.backoffice"
      - purpose: "operator-onboard"

    Security invariants:
      - Step-up required: prevents a hijacked session from silently issuing tokens.
      - Token is signed with HS256 using the caddy_internal_hmac (already available
        at runtime via /run/secrets/caddy_internal_hmac).
      - The token value is NEVER written to the audit log — only the jti and TTL.
      - Verify endpoint: GET /auth/operator-token/verify (used by the CLI).

    ASVS V7.2.1 + NIST IA-2/AU-3 + CMMC IA.L2-3.5.1/3 + SOC 2 CC6.1
    + ISO 27001 A.5.16/A.5.17 / LU-AMEND-04.
    """
    from yashigani.auth.stepup import assert_fresh_stepup

    assert_fresh_stepup(session)

    state = backoffice_state
    assert state.auth_service is not None
    assert state.audit_writer is not None

    admin_record = await state.auth_service.get_account_by_id(session.account_id)
    if admin_record is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    import uuid
    import time as _time

    import jwt as _pyjwt

    # Signing key: reuse caddy_internal_hmac (already a 32+ byte secret at runtime).
    # Fail closed if the secret file is not readable.
    _hmac_path = "/run/secrets/caddy_internal_hmac"
    try:
        with open(_hmac_path) as _f:
            _signing_key = _f.read().strip()
    except OSError:
        _log.error("LU-AMEND-04: cannot read %s — operator-token issuance refused", _hmac_path)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "signing_key_unavailable"},
        )

    _jti = str(uuid.uuid4())
    _now = int(_time.time())
    _payload = {
        "sub": admin_record.username,
        "jti": _jti,
        "iat": _now,
        "exp": _now + _OPERATOR_TOKEN_TTL_SECONDS,
        "iss": "yashigani.backoffice",
        "purpose": "operator-onboard",
        "issued_for": body.issued_for[:256],
    }
    _token = _pyjwt.encode(_payload, _signing_key, algorithm="HS256")

    from yashigani.audit.schema import OperatorTokenIssuedEvent

    state.audit_writer.write(
        OperatorTokenIssuedEvent(
            admin_account=admin_record.username,
            token_jti=_jti,
            token_ttl_seconds=_OPERATOR_TOKEN_TTL_SECONDS,
            issued_for=body.issued_for[:256],
        )
    )

    _log.info(
        "LU-AMEND-04: operator token issued by %s jti=%s ttl=%ds issued_for=%r",
        admin_record.username,
        _jti,
        _OPERATOR_TOKEN_TTL_SECONDS,
        body.issued_for[:64],
    )

    return {
        "token": _token,
        "jti": _jti,
        "expires_in": _OPERATOR_TOKEN_TTL_SECONDS,
        "token_type": "Bearer",
        "purpose": "operator-onboard",
    }


@router.get("/operator-token/verify")
async def verify_operator_token(
    request: Request,
):
    """
    Verify an operator onboard token presented in the Authorization header.

    Used by `yashigani onboard --token <tok>` to validate the token before
    proceeding with the onboard ceremony.  The CLI POSTs the agent registration
    only after this endpoint returns 200.

    Authorization: Bearer <token>

    Returns 200 + {sub, jti, exp, issued_for} on success.
    Returns 401 on invalid/expired/wrong-purpose token.
    Returns 400 if the header is absent or malformed.

    Security invariants:
      - This endpoint does NOT require an admin session cookie — it is the
        bearer-token validation surface for headless CLI callers.
      - The endpoint is on the internal backoffice path (:8443) — it is NOT
        reachable from the public Caddy edge without admin session + mTLS.
      - No audit event emitted here (verify is low-value; ONBOARD_ATTEMPTED
        in the CLI captures the full ceremony outcome).

    LU-AMEND-04 / v2.24.1.
    """
    import jwt as _pyjwt

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "missing_bearer_token"},
        )
    _raw_token = auth_header[len("Bearer "):].strip()

    _hmac_path = "/run/secrets/caddy_internal_hmac"
    try:
        with open(_hmac_path) as _f:
            _signing_key = _f.read().strip()
    except OSError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "signing_key_unavailable"},
        )

    try:
        _payload = _pyjwt.decode(
            _raw_token,
            _signing_key,
            algorithms=["HS256"],
            options={"require": ["sub", "jti", "exp", "iat", "iss", "purpose"]},
        )
    except _pyjwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "token_expired"},
        )
    except _pyjwt.InvalidTokenError as _e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_token", "detail": str(_e)},
        )

    if _payload.get("purpose") != "operator-onboard":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "wrong_token_purpose"},
        )
    if _payload.get("iss") != "yashigani.backoffice":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "wrong_token_issuer"},
        )

    return {
        "valid": True,
        "sub": _payload["sub"],
        "jti": _payload["jti"],
        "exp": _payload["exp"],
        "issued_for": _payload.get("issued_for", ""),
    }


# ---------------------------------------------------------------------------
# LU-AMEND-04: Internal onboard audit endpoint
#
# Called by the yashigani-onboard CLI to emit an ONBOARD_ATTEMPTED event after
# verifying (or not) the operator token.  Mounted at /auth/onboard-event via
# the /auth prefix in app.py.  The full path is /auth/onboard-event.
#
# Security: requires AdminSession (session cookie from the CLI --session-cookie
# flag) + X-Caddy-Verified-Secret HMAC (same Layer B gate as all direct backoffice
# calls).  No step-up required — this is an audit-write path, not a mutation.
# ---------------------------------------------------------------------------


class OnboardEventBody(BaseModel):
    """Request body for POST /auth/onboard-event."""

    identity_quality: str = Field(
        ...,
        pattern="^(attested|weak)$",
        description="'attested' when a valid token was supplied; 'weak' otherwise.",
    )
    operator_identity: str = Field(default="unknown", max_length=256)
    token_jti: str = Field(default="", max_length=64)
    agent_name: str = Field(..., max_length=256)
    agent_url: str = Field(..., max_length=512)
    client_ip: str = Field(default="", max_length=64)


@router.post("/onboard-event")
async def record_onboard_event(
    body: OnboardEventBody,
    session: AdminSession,
):
    """
    Record an ONBOARD_ATTEMPTED audit event emitted by the yashigani-onboard CLI.

    Security invariants:
      - Requires AdminSession — callers must present a valid admin session cookie.
      - identity_quality is constrained to "attested" | "weak" by Pydantic validation.
      - Raw token values are NEVER accepted in this payload.
      - Only jti (cross-reference ID) and operator_identity (sub claim) are stored.

    LU-AMEND-04 / v2.24.1.
    """
    state = backoffice_state
    assert state.audit_writer is not None

    from yashigani.audit.schema import OnboardAttemptedEvent

    state.audit_writer.write(
        OnboardAttemptedEvent(
            identity_quality=body.identity_quality,
            operator_identity=body.operator_identity,
            token_jti=body.token_jti,
            agent_name=body.agent_name,
            agent_url=body.agent_url,
            client_ip=body.client_ip,
        )
    )

    _log.info(
        "LU-AMEND-04: ONBOARD_ATTEMPTED audit event recorded "
        "identity_quality=%s operator=%s agent=%r jti=%s",
        body.identity_quality,
        body.operator_identity,
        body.agent_name,
        body.token_jti or "(none)",
    )

    return {"status": "ok", "identity_quality": body.identity_quality}


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


# ---------------------------------------------------------------------------
# drift audit finding #6 — server-side next= redirect validator
#
# The JS guard in login.js (safeNext()) runs at the client trust boundary;
# this server-side validator enforces the same rules at the HTTP trust boundary
# so that a browser with JS disabled, a headless client, or a browser quirk
# that bypasses the JS cannot exploit a reflected open redirect.
#
# Rules mirror the JS Layer 1 regex precisely (same source of truth):
#   1. Must not be empty.
#   2. Must start with exactly one `/` NOT followed by `/` or `\`.
#   3. Must not contain any `\` character (IE/Edge normalise `/\` → `//`).
#   4. Must not contain `//` after the leading `/` (protocol-relative).
#   5. Must not start with an absolute URL scheme (http:, https:, ftp:, etc.).
#   6. Must not contain `@` (URL-userinfo trick: /foo@evil.com → evil.com host).
#   7. Must not exceed 2 048 characters.
#
# On rejection: redirect to `/` + emit OPEN_REDIRECT_ATTEMPT_BLOCKED audit event.
# On acceptance: redirect to the validated path (302).
#
# References: CWE-601 / ASVS V5.1.5 / OWASP A01:2021.
# ---------------------------------------------------------------------------

# Absolute URL scheme pattern — catches http:, https:, ftp:, javascript:, etc.
_ABSOLUTE_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+\-.]*:", re.ASCII)

_NEXT_MAX_LENGTH = 2048


def _validate_next(raw: str) -> tuple[bool, str]:
    """
    Validate a next= redirect target.

    Returns (True, sanitised_path) when the value is safe to redirect to, or
    (False, reason) when the value must be rejected.

    Rules — in check order:
      empty            : empty / falsy string
      too_long         : exceeds _NEXT_MAX_LENGTH characters
      not_relative     : does not start with `/`
      double_slash     : starts with `//` or `/\\` (protocol-relative bypass)
      backslash        : contains any backslash anywhere in the string
      absolute_url     : matches an absolute URL scheme (http:, javascript:, …)
      userinfo_at      : contains `@` (URL-userinfo open redirect trick)
    """
    if not raw:
        return False, "empty"
    if len(raw) > _NEXT_MAX_LENGTH:
        return False, "too_long"
    if not raw.startswith("/"):
        # Catches https://evil.com, //evil.com without starting slash check
        if _ABSOLUTE_SCHEME_RE.match(raw):
            return False, "absolute_url"
        return False, "not_relative"
    # Starts with `/` — check for double-slash / backslash as second char.
    if len(raw) >= 2 and raw[1] in ("/", "\\"):
        return False, "double_slash"
    # Full-string backslash check (catches /path\..\ traversal attempts).
    if "\\" in raw:
        return False, "backslash"
    # Absolute-URL check (catches edge cases where the leading / was spoofed).
    if _ABSOLUTE_SCHEME_RE.match(raw):
        return False, "absolute_url"
    # @-userinfo trick: /user@evil.com is parsed as authority=user@evil.com.
    if "@" in raw:
        return False, "userinfo_at"
    return True, raw


def _hash_ip(ip: str) -> str:
    """Return SHA-256 hex digest of an IP address, first 16 chars for brevity."""
    return hashlib.sha256(ip.encode()).hexdigest()[:16]


def _sanitise_for_audit(raw: str) -> str:
    """Truncate and replace non-printable/non-ASCII chars for safe audit logging."""
    truncated = raw[:128]
    # Replace any char outside printable ASCII with '?'
    return "".join(c if 0x20 <= ord(c) < 0x7F else "?" for c in truncated)


@router.get("/post-login-redirect")
async def post_login_redirect(
    request: Request,
    next: str = Query(default="", alias="next"),
):
    """
    Server-side next= redirect validator — drift audit finding #6.

    Called by the login.js after a successful /auth/login response.
    Validates the next= parameter against the same rules as the JS safeNext()
    guard and issues a server-side 302 redirect.

    Security:
      - No session required: the browser calls this endpoint immediately after
        /auth/login sets the session cookie; the redirect itself does not require
        an existing session.  The cookie will be present on the follow-up
        navigation because it was just set.
      - On rejection: redirects to '/' and emits OPEN_REDIRECT_ATTEMPT_BLOCKED.
      - The raw `next` value is NEVER logged — only a truncated sanitised form.
      - Client IP is SHA-256 hashed (first 16 chars) in the audit record.

    ASVS V5.1.5 / CWE-601 / OWASP A01:2021.
    """
    client_ip = request.client.host if request.client else "unknown"
    ok, result = _validate_next(next)

    if not ok:
        # Emit audit event before redirecting.
        state = backoffice_state
        if state.audit_writer is not None:
            from yashigani.audit.schema import OpenRedirectAttemptBlockedEvent

            state.audit_writer.write(
                OpenRedirectAttemptBlockedEvent(
                    client_ip_hash=_hash_ip(client_ip),
                    attempted_next_truncated=_sanitise_for_audit(next),
                    reason=result,
                )
            )
        _log.warning(
            "OPEN_REDIRECT_BLOCKED: ip_hash=%s reason=%s attempted=%r",
            _hash_ip(client_ip),
            result,
            _sanitise_for_audit(next)[:64],
        )
        return _RedirectResponse(url="/", status_code=302)

    return _RedirectResponse(url=result, status_code=302)


async def _get_record_by_id(account_id: str):
    state = backoffice_state
    if state.auth_service is None:
        return None
    return await state.auth_service.get_account_by_id(account_id)


def _make_login_event(username: str, outcome: str, reason, account_tier: str = "admin"):
    """ASVS V7.3.4: account_tier reflects the actual session/record tier.

    Safe default "admin" is intentional for the pre-auth failure call site at
    login() line ~299 where authenticate() returned (False, None, reason) and
    no record is available.  All post-auth call sites MUST pass
    record.account_tier or session.account_tier explicitly.
    """
    from yashigani.audit.schema import AdminLoginEvent

    return AdminLoginEvent(
        account_tier=account_tier,
        admin_account=username,
        outcome=outcome,
        failure_reason=reason,
    )


def _make_config_event(username: str, setting: str, prev: str, new: str, account_tier: str = "admin"):
    """ASVS V7.3.4: account_tier reflects the actual session tier, not a hardcoded value.

    This helper is currently unused (callers construct ConfigChangedEvent directly),
    but the parameter is wired for defence-in-depth: if RBAC gates break, an audit
    record constructed via this helper will still record the actual tier.
    Safe default "admin" matches the admin-only routes that would use this helper.
    """
    from yashigani.audit.schema import ConfigChangedEvent

    return ConfigChangedEvent(
        account_tier=account_tier,
        admin_account=username,
        setting=setting,
        previous_value=prev,
        new_value=new,
    )


def _make_provision_event(username: str, account_tier: str = "admin"):
    """ASVS V7.3.4: account_tier reflects the actual session tier, not a hardcoded value."""
    from yashigani.audit.schema import TotpProvisionCompletedEvent

    return TotpProvisionCompletedEvent(
        account_tier=account_tier,
        user_handle=username,
    )


def _make_stepup_event(username: str, outcome: str, account_tier: str = "admin"):
    from yashigani.audit.schema import AdminLoginEvent

    return AdminLoginEvent(
        account_tier=account_tier,
        admin_account=username,
        outcome=f"stepup_{outcome}",
        failure_reason=None if outcome == "success" else "invalid_totp",
    )


def _make_login_attempt_event(username: str, client_ip: str, account_tier: str = "admin"):
    """ACS gap #95: emit AUTH_LOGIN_ATTEMPT before auth result.

    account_tier defaults to "admin" for the pre-auth call site in login() where
    the account record has not yet been fetched.  Pass record.account_tier
    explicitly wherever the record is already in scope.
    """
    from yashigani.audit.schema import AuthLoginAttemptEvent

    # Mask the last octet of the IP for lower-assurance sinks.
    # IPv4: a.b.c.d → a.b.c.0   IPv6: strip last group.
    parts = client_ip.rsplit(".", 1)
    ip_prefix = f"{parts[0]}.0" if len(parts) == 2 else client_ip
    return AuthLoginAttemptEvent(
        account_tier=account_tier,
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
    account_tier: str = "admin",
):
    """ACS gap #95: dedicated PASSWORD_CHANGED event.
    ASVS V7.3.4: account_tier reflects the actual session tier, not a hardcoded value."""
    from yashigani.audit.schema import PasswordChangedEvent

    return PasswordChangedEvent(
        account_tier=account_tier,
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
    account_tier: str = "admin",
):
    """ACS gap #95: SESSIONS_INVALIDATED event for session lifecycle audit.
    ASVS V7.3.4: account_tier reflects the actual session tier, not a hardcoded value."""
    from yashigani.audit.schema import SessionsInvalidatedEvent

    return SessionsInvalidatedEvent(
        account_tier=account_tier,
        admin_account=admin_account,
        acting_admin=acting_admin,
        reason=reason,
        sessions_count=sessions_count,
    )


# ---------------------------------------------------------------------------
# Gap 3 / v2.23.4 arch-completion: HUMAN identity registration on local-auth login
#
# SSO callbacks create a HUMAN identity in identity_registry (sso.py:271).
# Local-auth login (username + password + TOTP) did not — leaving users without
# a Bearer-issuable identity for /v1/*.  This helper closes that gap.
#
# Security invariants:
#   - Only account_tier == "user" triggers registration. admins MUST NOT be
#     registered as HUMAN identities (Gap 2 indirect separation).
#   - Idempotent: get_by_slug() check prevents duplicate entries on re-login.
#   - Seat-limit hard error: LicenseLimitExceeded → 403, login rejected.
#   - Community-tier graceful-skip: identity_registry is None → skip, allow login.
#   - Legacy account with no email: falls back to {username}@yashigani.local
#     (mirrors existing pattern at auth.py:533 / /auth/verify).  This
#     preserves backward compatibility with pre-email-as-username accounts while
#     still giving them a stable, deterministic slug.  The fallback email is
#     logged at WARNING so operators can backfill real emails during a Gap 1
#     migration.
# ---------------------------------------------------------------------------

def _auth_email_to_slug(email: str) -> str:
    """
    Derive a stable registry slug from an email address.

    B5 (2.25.5): delegates to yashigani.identity.slug.email_to_slug — the single
    canonical implementation.  All slug-derivation sites (auth.py, sso.py,
    openai_router.py, users.py, me.py) produce the SAME slug for any given email.

    e.g. dana.lee@example.com → dana-lee-example-com
    """
    from yashigani.identity.slug import email_to_slug as _canonical_slug
    return _canonical_slug(email)


def _register_human_identity_on_login(record, state) -> None:
    """
    Register a HUMAN identity in the identity_registry for a successfully
    authenticated local-auth user (account_tier == "user").

    Called BEFORE session creation in the login handler so that a seat-limit
    rejection prevents the session from being issued (fail-closed).

    Raises HTTPException(403) if the licence seat limit is exhausted.
    Silently skips if identity_registry is None (community-tier deployment).
    """
    # Only user-tier accounts get HUMAN identities.
    # Admin and totp_provisioning tiers must NOT be registered here.
    if record.account_tier != "user":
        return

    registry = getattr(state, "identity_registry", None)
    if registry is None:
        # Community-tier or pre-init: identity stack not available.
        # Preserve today's behaviour — login succeeds without Bearer identity.
        _log.warning(
            "identity_registry unavailable on login for %s — "
            "HUMAN identity not created (community-tier or pre-init); "
            "user will have no Bearer identity for /v1/*",
            record.username,
        )
        return

    from yashigani.identity.registry import IdentityKind
    from yashigani.licensing.enforcer import LicenseLimitExceeded

    # Resolve the email for the slug.  Use the record email if set; otherwise
    # fall back to the @yashigani.local synthetic email (Gap 1 legacy accounts).
    email = record.email
    if not email:
        email = f"{record.username}@yashigani.local"
        _log.warning(
            "User %s has no email set — using synthetic slug email %s for "
            "identity_registry. Backfill real email to resolve (Gap 1).",
            record.username,
            email,
        )

    slug = _auth_email_to_slug(email)

    # Idempotency guard: if already registered, check status.
    # Q3 / v2.23.4 (Tiago directive 2026-05-15): auto-reactivate on login
    # REVERTED. A suspended identity is an admin-action-only reactivation.
    # If identity is suspended/inactive:
    #   - Block the login (403)
    #   - Audit-log LOGIN_BLOCKED_SUSPENDED_IDENTITY
    #   - Do NOT reactivate, do NOT issue session
    # Admin must call POST /admin/users/{username}/reactivate (StepUp required)
    # to restore access.
    existing = registry.get_by_slug(slug)
    if existing is not None:
        identity_id = existing.get("identity_id", "")
        existing_status = existing.get("status", "active")
        if existing_status in ("suspended", "inactive"):
            # Audit-log before raising so the forensic record is present
            # even if an upstream exception handler swallows the 403.
            from yashigani.audit.schema import LoginBlockedSuspendedIdentityEvent
            _blocked_state = state
            if getattr(_blocked_state, "audit_writer", None) is not None:
                _blocked_state.audit_writer.write(LoginBlockedSuspendedIdentityEvent(
                    username=record.username,
                    identity_id=identity_id,
                    identity_status=existing_status,
                    slug=slug,
                ))
            _log.warning(
                "Q3 LOGIN BLOCKED: user=%s identity_id=%s status=%s slug=%s — "
                "admin must reactivate via POST /admin/users/%s/reactivate",
                record.username,
                identity_id,
                existing_status,
                slug,
                record.username,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "account_suspended",
                    "message": (
                        "Account suspended. Contact your administrator to restore access."
                    ),
                },
            )
        _log.debug(
            "HUMAN identity already active for %s (slug=%s, identity_id=%s) — skip re-register",
            record.username,
            slug,
            identity_id,
        )
        return

    # New user — register with HUMAN kind.
    # description carries the account_id for cross-system linkage (Gap 3 / v2.23.4).
    try:
        identity_id, _plaintext_key = registry.register(
            kind=IdentityKind.HUMAN,
            name=record.username,
            slug=slug,
            description=f"local-auth user; account_id={record.account_id}",
        )
    except LicenseLimitExceeded as exc:
        _log.warning(
            "Seat limit reached: cannot register HUMAN identity for %s "
            "(%d/%d used). Login rejected.",
            record.username,
            exc.current,
            exc.max_val,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "seat_limit_exceeded",
                "message": (
                    "The maximum number of user seats for this licence has been reached. "
                    "Contact your administrator to increase the seat limit."
                ),
                "current": exc.current,
                "max": exc.max_val,
            },
        ) from exc

    _log.info(
        "HUMAN identity registered on local-auth login: "
        "identity_id=%s slug=%s account_id=%s",
        identity_id,
        slug,
        record.account_id,
    )
