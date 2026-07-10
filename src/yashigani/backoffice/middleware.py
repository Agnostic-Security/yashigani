"""
Yashigani Backoffice — Auth middleware and dependencies.
All routes require a valid admin session. Session validated server-side.

Last updated: 2026-06-27T00:00:00+01:00
"""
from __future__ import annotations

from typing import Annotated, Optional

from fastapi import Depends, HTTPException, status, Request

from yashigani.auth.session import SessionStore, Session
from yashigani.auth.stepup import assert_fresh_stepup

_SESSION_COOKIE = "__Host-yashigani_admin_session"
_USER_SESSION_COOKIE = "__Host-yashigani_session"


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


def require_admin_session(
    request: Request,
    store: SessionStore = Depends(get_session_store),
) -> Session:
    """
    FastAPI dependency that enforces a valid admin session.
    Returns the Session on success, raises HTTP 401 otherwise.
    Verifies account_tier == "admin" to prevent cross-tier access.
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

    if session.account_tier != "admin":
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
