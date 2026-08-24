"""
Yashigani Backoffice — Auth middleware and dependencies.
All routes require a valid admin session. Session validated server-side.

Last updated: 2026-06-27T00:00:00+01:00
"""
from __future__ import annotations

import os
from typing import Annotated, Optional
from urllib.parse import urlsplit

from fastapi import Depends, HTTPException, status, Request

from yashigani.auth.session import SessionStore, Session
from yashigani.auth.stepup import assert_fresh_stepup

_SESSION_COOKIE = "__Host-yashigani_admin_session"
_USER_SESSION_COOKIE = "__Host-yashigani_session"

# TD-2026-07-25-04 (Ava): CSRF Origin/Referer not server-validated.
#
# State-changing methods where a forged cross-site Origin gets a
# defense-in-depth reject. GET/HEAD/OPTIONS/TRACE are read-only by HTTP
# semantics and are intentionally excluded (a cross-site GET has no
# mutating effect and browsers routinely omit Origin on top-level GET
# navigations).
_CSRF_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _configured_public_hosts() -> frozenset[str]:
    """Hostnames this backoffice deployment is reachable at, for CSRF Origin
    validation.

    Deliberately duplicates routes/webauthn_v1.py::_configured_public_hosts
    (same YASHIGANI_TLS_DOMAIN + "localhost" allowlist) rather than importing
    it — routes/ imports FROM backoffice/middleware.py, so the reverse import
    would be a backwards layering dependency. Same rationale as the
    pki/ssl_context.py::_extract_spiffe_uris duplication elsewhere in this
    codebase.
    """
    domain = os.getenv("YASHIGANI_TLS_DOMAIN", "localhost").strip().lower()
    hosts = {"localhost"}
    if domain:
        hosts.add(domain)
    return frozenset(hosts)


def _origin_is_same_site(origin: str) -> bool:
    """True if the Origin header's hostname matches this deployment's
    configured public-host allowlist (YASHIGANI_TLS_DOMAIN + "localhost").

    Deliberately hostname-only (not scheme/port): the browser's Origin
    header is only ever attacker-controlled by navigating to a DIFFERENT
    site, never by picking a different port on OUR site, so a same-hostname
    check is sufficient to reject cross-site senders without also rejecting
    legitimate same-site requests that arrive on a non-default port (e.g.
    the self-signed dev default https://localhost:8443).
    """
    try:
        parsed = urlsplit(origin)
    except ValueError:
        return False
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return False
    return hostname in _configured_public_hosts()


def _enforce_csrf_origin(request: Request) -> None:
    """ASVS V4.2.2 / CWE-352 defense-in-depth: reject state-changing,
    cookie-authenticated requests whose Origin header is PRESENT and does
    NOT match this deployment's configured host allowlist.

    Ava TD-2026-07-25-04: `POST /admin/rbac/groups` (and other admin
    mutating routes) accepted a forged `Origin: https://evil.example` and
    returned 201. Confirmed non-exploitable in practice — both session
    cookies (`__Host-yashigani_admin_session`, `__Host-yashigani_session`;
    see auth/session.py) are set `SameSite=Strict`, so no browser that
    honours SameSite ever attaches the cookie to a cross-site-initiated
    request in the first place (no cookie on the wire => no session =>
    401 from require_admin_session before this check would even matter).
    This is therefore LOW-severity belt-and-braces: an explicit
    server-side signal instead of relying solely on cookie-jar behaviour
    (e.g. a hypothetical browser/proxy bug, or an old client that ignores
    SameSite).

    Fail-CLOSED only when Origin is PRESENT and mismatched (CWE-352 requires
    an affirmative reject, not a default-allow). A request with NO Origin
    header — same-origin top-level navigations, many legitimate same-origin
    `<form>` posts, and every API-key/bearer caller (which never sends a
    session cookie and so has no CSRF surface to begin with) — is left
    entirely to the existing session-cookie checks; this function does not
    change behaviour for them.
    """
    if request.method not in _CSRF_UNSAFE_METHODS:
        return
    origin = request.headers.get("origin")
    if not origin:
        return
    if not _origin_is_same_site(origin):
        _audit_csrf_origin_rejected(request, origin)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "csrf_origin_mismatch"},
        )


def get_session_store() -> SessionStore:
    """FastAPI dependency — returns the singleton SessionStore."""
    from yashigani.backoffice.state import backoffice_state
    assert backoffice_state.session_store is not None  # set unconditionally at startup
    return backoffice_state.session_store


def _resolve_token(request: Request) -> Optional[str]:
    """Read session token from either admin or user cookie (admin-cookie preferred).

    Used by require_admin_session and require_any_session.  MUST NOT be used
    for user-plane routes — use _resolve_user_token() there (RISK-100).
    """
    return request.cookies.get(_SESSION_COOKIE) or request.cookies.get(_USER_SESSION_COOKIE)


def _resolve_user_token(request: Request) -> Optional[str]:
    """Read session token from the USER cookie EXCLUSIVELY (RISK-100 fix).

    NEVER falls back to the admin cookie.  User-plane routes that want
    cookie-exclusive resolution MUST use this helper so that an admin
    browsing to /chat cannot silently inherit their admin session into
    a user-tier route.
    """
    return request.cookies.get(_USER_SESSION_COOKIE)


def _mw_real_client_ip(request: Request) -> str:
    """Real client IP for audit keys — deliberately duplicates
    routes/auth.py::_real_client_ip (same X-Real-IP-over-X-Forwarded-For
    rationale, LAURA-3X-001) rather than importing it: routes/ imports FROM
    backoffice/middleware.py, so the reverse import would be a backwards
    layering dependency — same rationale as _configured_public_hosts above.
    """
    xri = request.headers.get("x-real-ip", "").strip()
    if xri:
        return xri.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _audit_csrf_origin_rejected(request: Request, origin: str) -> None:
    """NDC-sweep-E (2026-07-31): best-effort audit emission for
    _enforce_csrf_origin()'s deny. Runs BEFORE session resolution (called
    at the top of require_admin_session), so no account_id/session is
    available yet — path/method/origin/client_ip is the available context.
    Audit failure must NEVER block the deny.
    """
    try:
        from yashigani.backoffice.state import backoffice_state
        if backoffice_state.audit_writer is None:
            return
        from yashigani.audit.schema import CsrfOriginRejectedEvent
        from yashigani.auth.session import _mask_ip
        backoffice_state.audit_writer.write(CsrfOriginRejectedEvent(
            path=request.url.path,
            method=request.method,
            rejected_origin=origin[:256],
            client_ip_prefix=_mask_ip(_mw_real_client_ip(request)),
        ))
    except Exception:  # pragma: no cover — audit must never break the deny
        pass


def _audit_wrong_plane_admin_session(request: Request, session: Session) -> None:
    """NDC-sweep-E (2026-07-31): best-effort audit emission for
    require_user_session()'s admin-session-on-user-plane deny (wrong_plane).

    Reuses AuthVerifyRejectedAdminSessionEvent rather than minting a new
    type — this is the SAME SoD-003 shape already audited at the sibling
    /auth/verify (Caddy forward_auth) call site in routes/auth.py; this is
    just the second enforcement point for the identical rule (an admin
    session directly hitting a require_user_session-gated route, as opposed
    to the forward_auth probe). Audit failure must NEVER block the deny.
    """
    try:
        from yashigani.backoffice.state import backoffice_state
        if backoffice_state.audit_writer is None:
            return
        from yashigani.audit.schema import AuthVerifyRejectedAdminSessionEvent
        from yashigani.auth.session import _mask_ip
        backoffice_state.audit_writer.write(AuthVerifyRejectedAdminSessionEvent(
            account_id=session.account_id,
            client_ip_prefix=_mask_ip(_mw_real_client_ip(request)),
        ))
    except Exception:  # pragma: no cover — audit must never break the deny
        pass


def _audit_admin_access_denied_tier_mismatch(
    request: Request, session: Session, reason: str,
) -> None:
    """E2 (observability SOP): best-effort audit emission for a validated
    session that failed require_admin_session()'s admin-tier check. Audit
    failure must NEVER block the deny itself — the HTTPException the caller
    raises right after this is the actual security control; this is
    forensic trail only.
    """
    try:
        from yashigani.backoffice.state import backoffice_state
        if backoffice_state.audit_writer is None:
            return
        from yashigani.audit.schema import AdminAccessDeniedTierMismatchEvent
        from yashigani.auth.session import _mask_ip
        backoffice_state.audit_writer.write(AdminAccessDeniedTierMismatchEvent(
            account_id=session.account_id,
            session_account_tier=session.account_tier,
            reason=reason,
            path=request.url.path,
            method=request.method,
            client_ip_prefix=_mask_ip(_mw_real_client_ip(request)),
        ))
    except Exception:  # pragma: no cover — audit must never break the deny
        pass


def require_admin_session(
    request: Request,
    store: SessionStore = Depends(get_session_store),
) -> Session:
    """
    FastAPI dependency that enforces a valid admin session.
    Returns the Session on success, raises HTTP 401 otherwise.
    Verifies account_tier == "admin" to prevent cross-tier access.

    TD-2026-07-25-04: also enforces the CSRF Origin check (see
    _enforce_csrf_origin) for state-changing methods. Cheap check, run
    before the session-store round trip.

    E2 (observability SOP, 2026-07-31): this is the single dependency
    EVERY /admin/* route funnels through, so its two 403 branches
    (admin_password_change_required, insufficient_tier) are the
    highest-per-request-volume authorization-DENY gap in the backoffice.
    Both now emit AdminAccessDeniedTierMismatchEvent (best-effort, never
    blocks the deny). The two 401 branches above (missing/expired token)
    are AUTHENTICATION failures, not authorization denies, and are
    deliberately NOT audited here — that is AUTH_LOGIN_ATTEMPT/
    AUTH_THROTTLE_TRIGGERED territory, already covered on the login path.
    """
    _enforce_csrf_origin(request)
    token = _resolve_token(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "authentication_required"},
        )

    session = store.get(token)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "session_expired_or_invalid"},
        )

    if session.account_tier == "admin_password_change_required":
        # LAURA-411-003: a force-password-change admin session must not grant
        # full admin access.  Only /auth/password/change (require_any_session)
        # and /auth/logout (require_any_session) are reachable with this tier.
        _audit_admin_access_denied_tier_mismatch(
            request, session, "admin_password_change_required"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "admin_password_change_required",
                "message": (
                    "You must change your password before accessing admin functions. "
                    "POST to /auth/password/change to set a new password."
                ),
            },
        )

    if session.account_tier != "admin":
        _audit_admin_access_denied_tier_mismatch(
            request, session, "insufficient_tier"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "insufficient_tier"},
        )

    return session


def require_any_session(
    request: Request,
    store: SessionStore = Depends(get_session_store),
) -> Session:
    """
    FastAPI dependency that accepts any valid session (admin or user).
    Used for endpoints accessible to both tiers (password change, TOTP provision).
    """
    token = _resolve_token(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "authentication_required"},
        )

    session = store.get(token)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "session_expired_or_invalid"},
        )

    return session


AdminSession = Annotated[Session, Depends(require_admin_session)]
AnySession = Annotated[Session, Depends(require_any_session)]


def require_user_session(
    request: Request,
    store: SessionStore = Depends(get_session_store),
) -> Session:
    """
    FastAPI dependency that accepts only user-tier sessions.
    Rejects admin sessions — prevents admins from calling user-scoped endpoints
    (SoD-003 equivalent for the user plane).
    """
    token = _resolve_token(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "authentication_required"},
        )

    session = store.get(token)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "session_expired_or_invalid"},
        )

    if session.account_tier != "user":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "user_tier_required"},
        )

    return session


#: Annotated dependency alias for user-plane routes.
UserSession = Annotated[Session, Depends(require_user_session)]


def require_stepup_admin_session(
    session: Session = Depends(require_admin_session),
) -> Session:
    """
    FastAPI dependency for high-value endpoints (ASVS V6.8.4).

    Requires:
    1. A valid admin session (from require_admin_session).
    2. A fresh step-up TOTP event within YASHIGANI_STEPUP_TTL_SECONDS (default 300s).

    Raises HTTP 401 with detail.error="step_up_required" if the step-up
    is missing or expired.  The admin UI JS interceptor catches this,
    shows the TOTP modal, POSTs to /auth/stepup, then retries the
    original request.
    """
    assert_fresh_stepup(session)
    return session


#: Annotated dependency alias for high-value admin routes.
#: Apply as: `session: StepUpAdminSession` in route signatures.
StepUpAdminSession = Annotated[Session, Depends(require_stepup_admin_session)]


def require_user_session(
    request: Request,
    store: SessionStore = Depends(get_session_store),
) -> Session:
    """
    FastAPI dependency that enforces a valid USER-tier session (RISK-100).

    SECURITY INVARIANTS:
    - Reads ONLY the __Host-yashigani_session cookie (NEVER the admin cookie).
      An admin who browses to /chat has their user cookie set to the SAME
      token as the admin cookie (both set on admin login); this dependency
      then reads the user cookie, resolves the admin session, and REJECTS it
      (account_tier == "admin" → 403).  SoD preserved.
    - Rejects admin sessions with 403 (wrong_plane) so admins cannot silently
      inherit admin privilege on user-plane endpoints.
    - Rejects totp_provisioning sessions (incomplete enrolment).
    - Raises 401 when no user cookie is present or the session is expired.

    ASVS V4.1.2 / NIST AC-5 / RISK-100 user side.
    """
    token = _resolve_user_token(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "authentication_required"},
        )

    session = store.get(token)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "session_expired_or_invalid"},
        )

    if session.account_tier == "admin":
        _audit_wrong_plane_admin_session(request, session)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "wrong_plane",
                "message": (
                    "Admin accounts must use /admin/. "
                    "The /chat and /user/* paths are for user-tier accounts only."
                ),
            },
        )

    # LAURA-V400-NEW-002 (ASVS V2.1.7): block sessions issued during the
    # force_password_change flow.  These sessions are confined to
    # /auth/password/change and /auth/logout (both accept AnySession).
    # No /user/* endpoint is reachable until the password is changed and a
    # full session is issued on re-login.
    if session.account_tier == "password_change_required":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "password_change_required",
                "message": (
                    "You must change your password before accessing this resource. "
                    "POST to /auth/password/change to set a new password."
                ),
            },
        )

    if session.account_tier != "user":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "user_tier_required",
                "message": "Complete account setup before accessing this resource.",
            },
        )

    return session


#: Annotated dependency alias for user-plane routes.
#: Apply as: `session: UserSession` in route signatures.
#: Admin-plane routes MUST NEVER use this — they use AdminSession / StepUpAdminSession.
UserSession = Annotated[Session, Depends(require_user_session)]
