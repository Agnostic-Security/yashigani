"""
Yashigani Backoffice — WebAuthn/FIDO2 v1 API routes.

POST /api/v1/admin/webauthn/register/start    — begin registration (requires session)
POST /api/v1/admin/webauthn/register/finish   — complete registration (requires session)
POST /api/v1/admin/webauthn/login/start       — begin authentication (PUBLIC — no session)
POST /api/v1/admin/webauthn/login/finish      — complete authentication, issue session (PUBLIC)
DELETE /api/v1/admin/webauthn/credentials/<id> — revoke credential (session + step-up)
GET /api/v1/admin/webauthn/credentials        — list credentials (requires session)

OWASP ASVS V2.8: sign_count replay protection + challenge single-use.
OWASP ASVS V6.8.4: DELETE requires step-up (TOTP re-auth within 5 min).

Recovery: if all WebAuthn credentials are lost, admin falls back to
password + TOTP (the existing /auth/login endpoint is never disabled).

Login flow detail:
  1. Admin POSTs username to /api/v1/admin/webauthn/login/start
     → backend looks up user by username, issues challenge, returns options
  2. Browser calls navigator.credentials.get(options)
  3. Admin POSTs credential response + username to /api/v1/admin/webauthn/login/finish
     → backend verifies assertion, creates admin session, sets cookie

Audit events emitted:
  WEBAUTHN_CREDENTIAL_REGISTERED — successful registration
  WEBAUTHN_LOGIN_SUCCESS          — successful WebAuthn login
  WEBAUTHN_LOGIN_FAILURE          — failed assertion (wrong key, sign_count rollback, etc.)
  WEBAUTHN_CREDENTIAL_REVOKED     — credential deleted by admin

Last updated: 2026-05-08T00:00:00+00:00
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import (
    AdminSession,
    StepUpAdminSession,
    _SESSION_COOKIE,
    get_session_store,
)
from yashigani.backoffice.state import backoffice_state
from yashigani.common.error_envelope import safe_error_envelope

# W20 fix (Iris PR #62): import auth throttle helpers so that the public
# login/start and login/finish endpoints are guarded by the same blocklist +
# account-gated progressive-delay throttle as the password login route.
# LAURA-412-CRITICAL/HIGH/MEDIUM (2026-07-19): _apply_auth_throttle /
# _reset_auth_failures now take (username, account_id) — the account-level
# bucket, keyed on the account's stable id (not a normalised username), is
# the sole gate; see auth.py's module docstring for the full rationale
# (IP-collapse under NAT/proxy/podman-pasta must not lock out a clean
# account; casefold-collision must not collapse two distinct, case-
# sensitive accounts into one bucket).  _apply_auth_throttle now performs
# an ATOMIC admit (Lua script) — every attempt is counted before any
# credential verification runs, closing the TOCTOU race a concurrent
# burst could previously exploit.  _record_auth_failure no longer exists —
# counting happens unconditionally in the atomic admit step.
#
# Captain merge-review (2026-07-19, same date): _resolve_account_id_for_bucket
# is imported SEPARATELY from this module's own _resolve_admin_id().
# _resolve_admin_id() filters `disabled=false AND account_tier='admin'` —
# correct for deciding whether the WebAuthn business logic (begin/complete
# authentication) should proceed, but WRONG for throttle-bucket keying: a
# disabled admin account or a user-tier account attempting this endpoint
# would resolve to None from _resolve_admin_id() and fall through to the
# unk: casefold-hash bucket fallback, narrowly reopening the LAURA-412-MEDIUM
# collision class for exactly those account states.
# _resolve_account_id_for_bucket() resolves ANY existing account regardless
# of tier/disabled state, so the bucket always keys on a stable account_id
# whenever the username corresponds to a real row at all.
from yashigani.backoffice.routes.auth import (
    _check_ip_access,
    _apply_auth_throttle,
    _reset_auth_failures,
    _resolve_account_id_for_bucket,
)

logger = logging.getLogger(__name__)

router = APIRouter()

_PLATFORM_TENANT_ID = "00000000-0000-0000-0000-000000000000"


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class RegisterStartRequest(BaseModel):
    credential_name: str = Field(
        default="Security Key",
        min_length=1,
        max_length=64,
        description="Human-readable label for this credential (e.g. 'YubiKey 5 Nano work').",
    )


class RegisterFinishRequest(BaseModel):
    credential_response: dict[str, Any]
    credential_name: str = Field(
        default="Security Key",
        min_length=1,
        max_length=64,
    )


class LoginStartRequest(BaseModel):
    username: str = Field(
        min_length=1,
        max_length=128,
        description="Admin username (email). Used to look up registered credentials.",
    )


class LoginFinishRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    credential_response: dict[str, Any]


# ---------------------------------------------------------------------------
# Registration (requires authenticated admin session)
# ---------------------------------------------------------------------------


@router.post(
    "/api/v1/admin/webauthn/register/start",
    tags=["webauthn"],
    summary="Begin WebAuthn credential registration",
)
async def register_start(
    body: RegisterStartRequest,
    session: AdminSession,
    request: Request,
):
    """
    Start the WebAuthn registration ceremony for a new FIDO2 credential.
    Returns PublicKeyCredentialCreationOptions for the browser.
    Caller must be authenticated (admin session cookie required).
    """
    svc = _get_pg_service()
    try:
        options_json = await svc.begin_registration(
            user_id=session.account_id,
            user_name=session.account_id,  # use account_id as display name
        )
    except Exception as exc:
        logger.error("WebAuthn register/start error for admin %s: %s", session.account_id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "webauthn_register_start_failed"},
        )

    return {"status": "ok", "options": options_json}


@router.post(
    "/api/v1/admin/webauthn/register/finish",
    tags=["webauthn"],
    summary="Complete WebAuthn credential registration",
)
async def register_finish(
    body: RegisterFinishRequest,
    session: AdminSession,
    request: Request,
):
    """
    Complete WebAuthn registration, verify attestation, and persist credential.
    Audit event: WEBAUTHN_CREDENTIAL_REGISTERED.
    """
    svc = _get_pg_service()
    try:
        origin = _expected_origin(request)
    except ValueError as exc:
        logger.warning(
            "WebAuthn register/finish rejected for admin %s — invalid origin host: %s",
            session.account_id,
            exc,
        )
        _write_audit(
            session.account_id,
            "WEBAUTHN_CREDENTIAL_REGISTERED",
            outcome="failure",
            detail="invalid_origin_host",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "webauthn_origin_not_allowed"},
        )

    try:
        credential = await svc.complete_registration(
            user_id=session.account_id,
            credential_response=body.credential_response,
            expected_origin=origin,
            credential_name=body.credential_name,
        )
    except ValueError as exc:
        logger.warning("WebAuthn register/finish failed for admin %s: %s", session.account_id, exc)
        _write_audit(
            session.account_id,
            "WEBAUTHN_CREDENTIAL_REGISTERED",
            outcome="failure",
            detail=str(exc),
        )
        payload, _ = safe_error_envelope(exc, public_message="webauthn registration failed", status=400)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=payload)
    except Exception as exc:
        logger.error("WebAuthn register/finish error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "webauthn_register_finish_failed"},
        )

    _write_audit(
        session.account_id,
        "WEBAUTHN_CREDENTIAL_REGISTERED",
        outcome="success",
        detail=f"credential_id={credential.id} name={credential.name}",
    )
    return {
        "status": "ok",
        "credential_id": credential.id,
        "name": credential.name,
        "aaguid": credential.aaguid,
        "created_at": credential.created_at.isoformat(),
    }


# ---------------------------------------------------------------------------
# Authentication (PUBLIC — admin not yet authenticated)
# ---------------------------------------------------------------------------


@router.post(
    "/api/v1/admin/webauthn/login/start",
    tags=["webauthn"],
    summary="Begin WebAuthn authentication (public endpoint)",
)
async def login_start(body: LoginStartRequest, request: Request, response: Response):
    """
    Begin the WebAuthn authentication ceremony.
    PUBLIC endpoint — does not require a session cookie.

    Looks up the admin's account_id by username, then generates a challenge.
    Returns allow_credentials list and challenge for navigator.credentials.get().

    W20 (Iris PR #62): applies the same blocklist + account-gated,
    atomically-admitted throttle as the password login route.  An
    unauthenticated DB-query endpoint without a rate gate is an invitation
    to enumerate admin usernames at scale.
    """
    client_ip = _client_ip(request)
    _check_ip_access(client_ip)

    # LAURA-412-MEDIUM (Captain merge-review): the throttle bucket keys on
    # the UNCONDITIONAL account_id (any tier, disabled or not) — this is
    # deliberately a DIFFERENT resolution from admin_id below (which is
    # admin-tier + active only, and drives the actual WebAuthn logic).
    bucket_account_id = await _resolve_account_id_for_bucket(body.username)

    # LAURA-412-HIGH: atomically admits this attempt BEFORE any DB work.
    _apply_auth_throttle(client_ip, body.username, bucket_account_id, response)

    # admin_id: the admin-tier, active-only resolution the WebAuthn business
    # logic actually needs (begin_authentication is legitimately admin-scoped).
    admin_id = await _resolve_admin_id(body.username)

    if admin_id is None:
        # Return a generic error — do not reveal whether the user exists
        # ASVS V2.1.5: enumerate-safe response
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "no_credentials_registered"},
        )

    svc = _get_pg_service()
    try:
        options_json = await svc.begin_authentication(user_id=admin_id)
    except ValueError as exc:
        # "No registered credentials" — not a server error, tell the client
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "no_credentials_registered"},
        )
    except Exception as exc:
        logger.error("WebAuthn login/start error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "webauthn_login_start_failed"},
        )

    return {"status": "ok", "options": options_json, "user_id": admin_id}


@router.post(
    "/api/v1/admin/webauthn/login/finish",
    tags=["webauthn"],
    summary="Complete WebAuthn authentication and issue session (public endpoint)",
)
async def login_finish(body: LoginFinishRequest, request: Request, response: Response):
    """
    Complete the WebAuthn authentication ceremony.
    PUBLIC endpoint — does not require a session cookie.

    On success: verifies assertion, creates admin session cookie, returns 200.
    On failure: WEBAUTHN_LOGIN_FAILURE audit event + 401.

    Audit events: WEBAUTHN_LOGIN_SUCCESS | WEBAUTHN_LOGIN_FAILURE.

    W20 (Iris PR #62): applies the same blocklist + account-gated,
    atomically-admitted throttle as login/start and the password login
    route.  Bad assertions (sign_count rollback, wrong key, bad challenge)
    were already counted by the atomic admit before the assertion was even
    checked, so automated probing still accumulates throttle delay across
    attempts (LAURA-412-HIGH: counting no longer happens after the fact).
    """
    client_ip = _client_ip(request)
    _check_ip_access(client_ip)

    # LAURA-412-MEDIUM (Captain merge-review): unconditional account_id for
    # bucket keying — see login_start / auth.py module docstring.
    bucket_account_id = await _resolve_account_id_for_bucket(body.username)

    # LAURA-412-HIGH: atomically admits this attempt BEFORE any DB query or
    # assertion verification.
    _apply_auth_throttle(client_ip, body.username, bucket_account_id, response)

    # admin_id: admin-tier, active-only — drives the actual WebAuthn logic.
    admin_id = await _resolve_admin_id(body.username)

    if admin_id is None:
        _write_audit(
            body.username,
            "WEBAUTHN_LOGIN_FAILURE",
            outcome="failure",
            detail="unknown_username",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "webauthn_login_failed"},
        )

    svc = _get_pg_service()
    try:
        origin = _expected_origin(request)
    except ValueError as exc:
        logger.warning(
            "WebAuthn login/finish rejected for %s — invalid origin host: %s",
            body.username,
            exc,
        )
        _write_audit(
            admin_id,
            "WEBAUTHN_LOGIN_FAILURE",
            outcome="failure",
            detail="invalid_origin_host",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "webauthn_login_failed"},
        )

    try:
        verified_user_id = await svc.complete_authentication(
            user_id=admin_id,
            credential_response=body.credential_response,
            expected_origin=origin,
        )
    except ValueError as exc:
        logger.warning("WebAuthn login/finish failed for %s: %s", body.username, exc)
        _write_audit(
            admin_id,
            "WEBAUTHN_LOGIN_FAILURE",
            outcome="failure",
            detail=str(exc),
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "webauthn_login_failed"},
        )
    except Exception as exc:
        logger.error("WebAuthn login/finish error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "webauthn_login_finish_failed"},
        )

    # Success: self-heal — clear both the account gate and the IP severity
    # bucket.  Use bucket_account_id (the SAME identity that was checked/
    # incremented by _apply_auth_throttle above), not admin_id — they are
    # equal in the success path here, but keeping the reset keyed on
    # whatever was actually gated is the correct invariant regardless.
    _reset_auth_failures(client_ip, body.username, bucket_account_id)

    # Issue admin session
    store = get_session_store()
    ip_addr = _client_ip(request)
    session_obj = store.create(
        account_id=admin_id,
        account_tier="admin",  # Class C: WebAuthn is admin-only by design; tier is structural.
        client_ip=ip_addr,
    )
    token = session_obj.token

    response.set_cookie(
        key=_SESSION_COOKIE,
        value=token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=14400,  # 4-hour absolute cap (matches SessionStore)
        path="/",
    )

    _write_audit(
        admin_id,
        "WEBAUTHN_LOGIN_SUCCESS",
        outcome="success",
        detail=f"username={body.username}",
    )

    return {"status": "ok", "account_id": admin_id}


# ---------------------------------------------------------------------------
# Credential management (requires session; DELETE also requires step-up)
# ---------------------------------------------------------------------------


@router.get(
    "/api/v1/admin/webauthn/credentials",
    tags=["webauthn"],
    summary="List registered WebAuthn credentials",
)
async def list_credentials(session: AdminSession):
    """List all WebAuthn credentials registered for the authenticated admin."""
    svc = _get_pg_service()
    credentials = await svc.list_credentials(user_id=session.account_id)
    return {
        "credentials": [
            {
                "id": c.id,
                "name": c.name,
                "aaguid": c.aaguid,
                "sign_count": c.sign_count,
                "created_at": c.created_at.isoformat(),
                "last_used_at": c.last_used_at.isoformat() if c.last_used_at else None,
            }
            for c in credentials
        ],
        "total": len(credentials),
        "recovery_note": (
            "If all WebAuthn credentials are lost, use password + TOTP login at /admin/login. "
            "Password+TOTP cannot be disabled while WebAuthn is configured."
        ),
    }


@router.delete(
    "/api/v1/admin/webauthn/credentials/{credential_id}",
    tags=["webauthn"],
    summary="Revoke a WebAuthn credential (step-up required)",
)
async def revoke_credential(
    credential_id: str,
    session: StepUpAdminSession,  # ASVS V6.8.4: requires fresh TOTP step-up
):
    """
    Revoke a WebAuthn credential by UUID.
    Requires a fresh TOTP step-up (within YASHIGANI_STEPUP_TTL_SECONDS, default 5 min).

    Recovery: password + TOTP login is always available as a fallback.
    Audit event: WEBAUTHN_CREDENTIAL_REVOKED.
    """
    svc = _get_pg_service()
    deleted = await svc.delete_credential(
        user_id=session.account_id,
        credential_uuid=credential_id,
    )
    if not deleted:
        _write_audit(
            session.account_id,
            "WEBAUTHN_CREDENTIAL_REVOKED",
            outcome="failure",
            detail=f"credential_id={credential_id}",
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "credential_not_found"},
        )

    _write_audit(
        session.account_id,
        "WEBAUTHN_CREDENTIAL_REVOKED",
        outcome="success",
        detail=f"credential_id={credential_id}",
    )
    return {"status": "ok", "credential_id": credential_id}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_pg_service():
    """Return the PgWebAuthnService from backoffice state, or raise 503."""
    svc = getattr(backoffice_state, "pg_webauthn_service", None)
    if svc is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "webauthn_not_configured"},
        )
    return svc


def _configured_public_hosts() -> frozenset[str]:
    """
    Return the set of hostnames (lowercased, no port) this deployment is
    permitted to present as the WebAuthn expected_origin host.

    YASHIGANI_TLS_DOMAIN is the operator's configured public domain — set
    by ``install.sh --domain``, wired into the backoffice container in both
    docker/docker-compose.yml and helm/yashigani/templates/backoffice.yaml
    (default "localhost" for the self-signed dev/demo install; see
    docker/Caddyfile.selfsigned's `default_sni {$YASHIGANI_TLS_DOMAIN}`).
    "localhost" is always permitted in addition, since Caddyfile.selfsigned
    serves its local_certs cert under that name regardless of whether an
    operator has also configured a real domain.
    """
    domain = os.getenv("YASHIGANI_TLS_DOMAIN", "localhost").strip().lower()
    hosts = {"localhost"}
    if domain:
        hosts.add(domain)
    return frozenset(hosts)


def _expected_origin(request: Request) -> str:
    """
    Derive the EXTERNAL WebAuthn origin the browser actually navigated to
    and signed into clientDataJSON — never the internal Caddy->backoffice
    upstream Host.

    LAURA/AVA-412 (2026-07-24): register/finish 400'd with
    InvalidRegistrationResponse for EVERY admin — clientDataJSON.origin was
    "https://localhost:8443" (what the browser actually signed) but this
    function previously read the raw `Host` header the backoffice PROCESS
    sees, which on the Caddy->backoffice reverse_proxy leg is the upstream
    dial address ("backoffice:8443"), not the address the browser used.

    Fix (v2, 2026-07-24 — 3rd iteration): prefer X-Forwarded-Host /
    X-Forwarded-Proto — headers Caddy now sets explicitly via `header_up
    X-Forwarded-Host {http.request.hostport}` ("set" semantics, which
    unconditionally overwrite any client-supplied X-Forwarded-Host before
    the request reaches backoffice — see docker/Caddyfile.{selfsigned,acme,
    ca} and helm/yashigani/templates/configmaps.yaml backoffice
    reverse_proxy blocks) to carry the EXTERNAL host+scheme the browser
    actually used across the proxy hop. Falls back to the raw Host header
    only for direct-to-backoffice access with no Caddy in front (local
    dev/tests).

    IMPORTANT — `{http.request.hostport}` vs `{host}`: the previous (2nd
    iteration) fix used Caddy's `{host}` placeholder, which silently STRIPS
    the port (`{host}` == `{http.request.host}`) — confirmed live: Caddy
    forwarded `X-Forwarded-Host: localhost` (no `:8443`) while the browser
    signed `origin: "https://localhost:8443"`, so the mismatch just moved
    rather than closed. `{http.request.hostport}` preserves whatever
    host:port the client actually dialled (verified against caddy v2.11.4:
    `{http.request.hostport}` always includes the port, even when it's the
    scheme's default — e.g. a client Host of "example.com:443" adapts to
    hostport "example.com:443", NOT "example.com").

    That "always includes the port, even the default one" behaviour is why
    this function does its OWN default-port normalisation below, rather
    than trusting the port verbatim: on a standard ACME install (public
    :443/:80), the BROWSER's origin string omits the default port
    (`https://example.com`, per the URL/Origin spec — browsers never
    include the scheme's default port in `location.origin`), so passing
    "https://example.com:443" straight through as expected_origin would
    reintroduce this exact bug class for every standard-port install. Only
    the self-signed dev default (:8443, a NON-default port) happens to need
    the port preserved verbatim — that case is unaffected by the
    normalisation (8443 != 443, so it's kept).

    Security: Caddy's public edge is path-routed, not host-vhosted (see
    the "Public-edge SNI defaulting" comment in Caddyfile.selfsigned —
    "single path-routed edge, no host-based vhosting"), so a client can
    present an arbitrary Host value on the wire. We therefore validate the
    derived hostname against an allowlist built from the operator's
    configured public domain (YASHIGANI_TLS_DOMAIN) plus "localhost", and
    raise (surfaced as 400/401 by the caller) rather than silently trusting
    an out-of-allowlist value as the expected_origin.
    """
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host") or request.headers.get(
        "host", request.url.netloc
    )

    raw_hostname, _, port = host.partition(":")
    hostname = raw_hostname.lower()
    allowed = _configured_public_hosts()
    if hostname not in allowed:
        raise ValueError(
            f"webauthn origin host {hostname!r} not in configured allowlist {sorted(allowed)!r}"
        )

    # Browsers never include the scheme's default port in
    # `location.origin` (443 for https, 80 for http) — strip it here too,
    # so an explicit-but-default port (e.g. Caddy's {http.request.hostport}
    # yielding "example.com:443") still matches what clientDataJSON.origin
    # actually contains. Non-default ports (e.g. ":8443") are kept verbatim.
    default_port = "443" if proto == "https" else "80"
    origin_host = hostname if (not port or port == default_port) else f"{hostname}:{port}"

    return f"{proto}://{origin_host}"


def _client_ip(request: Request) -> str:
    """Extract client IP, respecting X-Forwarded-For from trusted reverse proxy."""
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"  # nosec B104 — fallback string returned as IP label, not a bind address


async def _resolve_admin_id(username: str) -> Optional[str]:
    """
    Look up an admin account by username and return its account_id.
    Returns None if not found or account is disabled.
    """
    from yashigani.db.postgres import tenant_transaction

    try:
        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            row = await conn.fetchrow(
                "SELECT account_id FROM admin_accounts "
                "WHERE username = $1 AND disabled = false AND account_tier = 'admin'",
                username,
            )
        return str(row["account_id"]) if row else None
    except Exception as exc:
        logger.error("Failed to resolve admin_id for username %s: %s", username, exc)
        return None


def _write_audit(
    account_id: str,
    event_label: str,
    outcome: str,
    detail: str,
) -> None:
    """Write a WebAuthn audit event (best-effort, never raises)."""
    state = backoffice_state
    if state.audit_writer is None:
        return
    try:
        from yashigani.audit.schema import (
            WebAuthnCredentialRegisteredEvent,
            WebAuthnLoginSuccessEvent,
            WebAuthnLoginFailureEvent,
            WebAuthnCredentialRevokedEvent,
        )
        from yashigani.audit.schema import AuditEvent as _AuditEvent

        # B5 fix (Iris audit): use v2.23.3 event classes with correct wire-format
        # event_type values. The v0.9.0 classes (WebAuthnCredentialUsedEvent,
        # WebAuthnCredentialDeletedEvent) carried WEBAUTHN_CREDENTIAL_USED and
        # WEBAUTHN_CREDENTIAL_DELETED — not the semantically correct labels for
        # login and revocation events.
        event: _AuditEvent
        if event_label == "WEBAUTHN_CREDENTIAL_REGISTERED":
            event = WebAuthnCredentialRegisteredEvent(
                admin_account=account_id,
                outcome=outcome,
                credential_name=detail,
            )
        elif event_label == "WEBAUTHN_LOGIN_SUCCESS":
            event = WebAuthnLoginSuccessEvent(
                admin_account=account_id,
            )
        elif event_label == "WEBAUTHN_LOGIN_FAILURE":
            event = WebAuthnLoginFailureEvent(
                admin_account=account_id,
                failure_reason=detail,
            )
        elif event_label == "WEBAUTHN_CREDENTIAL_REVOKED":
            event = WebAuthnCredentialRevokedEvent(
                admin_account=account_id,
                outcome=outcome,
                credential_uuid=detail.replace("credential_id=", ""),
            )
        else:
            return
        state.audit_writer.write(event)
    except Exception as exc:
        logger.error("Failed to write WebAuthn audit event %s: %s", event_label, exc)
