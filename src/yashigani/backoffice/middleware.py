"""
Yashigani Backoffice — Auth middleware and dependencies.
All routes require a valid admin session. Session validated server-side.

Last updated: 2026-04-27T00:00:00+01:00
"""
from __future__ import annotations

from typing import Annotated, Optional

from fastapi import Cookie, Depends, HTTPException, status, Request

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
    """Read session token from either admin or user cookie."""
    return request.cookies.get(_SESSION_COOKIE) or request.cookies.get(_USER_SESSION_COOKIE)


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
