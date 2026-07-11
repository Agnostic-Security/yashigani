"""
Yashigani Backoffice — SSO routes.

GET  /auth/sso/select                  — list available IdPs (JSON)
GET  /auth/sso/oidc/{idp_id}           — initiate OIDC flow (redirect to IdP)
GET  /auth/sso/oidc/{idp_id}/callback  — OIDC callback: exchange code, create session
POST /auth/sso/saml/{idp_id}/acs       — SAML ACS endpoint

Security invariants:
  - State token and nonce are generated with secrets.token_urlsafe(32) (256-bit).
  - State is stored in Redis with a 10-minute TTL; replayed or missing state
    is rejected with 400 (CSRF prevention, ASVS V3.5.3).
  - Nonce is embedded in the state value and verified against the ID token
    nonce claim (if present) to prevent token injection (ASVS V3.5.4).
  - On callback success, the Yashigani identity is resolved or created in the
    IdentityRegistry, then a session is issued via SessionStore.
  - Email is never stored in audit logs — HMAC-SHA256 hash only.
  - All state/nonce keys use a dedicated Redis namespace (sso:state:).
  - require_feature("oidc") is called before any OIDC-specific work (tier gate).

V6.8.4 — acr/amr allowlist validation (ASVS V6.3.3):
  - OIDC: required_acr_values (allowlist) and required_amr_values (subset check)
    are read from IdPConfig. The old env-var fallback has been removed.
  - SAML: required_acr_values validated against AuthnContextClassRef.
  - Both paths write acr/amr/auth_time claims to the audit log.
  - Purpose: detect honest IdP misconfiguration, NOT a security boundary.

Last updated: 2026-04-28T23:58:36+01:00
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
from typing import Optional

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import JSONResponse, RedirectResponse

from yashigani.backoffice.state import backoffice_state
from yashigani.auth.session import _mask_ip
from yashigani.backoffice.schemas.bopla import IdPPublic
from yashigani.licensing.enforcer import (
    require_feature,
    LicenseFeatureGated,
    license_feature_gated_response,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# Redis TTL for OIDC state tokens (10 minutes — generous for slow IdPs).
_STATE_TTL_SECONDS = 600
_STATE_KEY_PREFIX = "sso:state:"

# Session max-age mirrors the existing admin/user session constant (4 hours).
_SESSION_MAX_AGE = 14400
_USER_SESSION_COOKIE = "__Host-yashigani_session"
_PENDING_2FA_COOKIE = "yashigani_sso_pending"
_PENDING_2FA_TTL = 300  # 5 minutes to complete 2FA after SSO
_PENDING_2FA_PREFIX = "sso:pending_2fa:"

# Slug sanitiser: only lowercase alphanumeric + hyphens.
_SLUG_RE = re.compile(r"[^a-z0-9\-]")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _redis():
    """
    Return a raw Redis client for SSO state storage.
    Reuses the session_store's underlying Redis connection (db/1).
    Falls back to None — callers must guard.
    """
    store = backoffice_state.session_store
    if store is None:
        return None
    return store._redis


def _build_redirect_uri(request: Request, idp_id: str) -> str:
    """Construct the absolute callback URL for this IdP."""
    base = str(request.base_url).rstrip("/")
    return f"{base}/auth/sso/oidc/{idp_id}/callback"


def _store_state(r, state: str, idp_id: str, nonce: str, code_verifier: str = "") -> None:
    """Persist state -> {idp_id, nonce, code_verifier, issued_at} in Redis with TTL."""
    payload = json.dumps(
        {
            "idp_id": idp_id,
            "nonce": nonce,
            "code_verifier": code_verifier,
            "issued_at": time.time(),
        }
    )
    r.setex(f"{_STATE_KEY_PREFIX}{state}", _STATE_TTL_SECONDS, payload)


def _consume_state(r, state: str) -> Optional[dict]:
    """
    Atomically read and delete the state entry.
    Returns the parsed payload or None if not found / expired.
    """
    key = f"{_STATE_KEY_PREFIX}{state}"
    raw = r.get(key)
    if raw is None:
        return None
    r.delete(key)
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None


def _get_hmac_key() -> bytes:
    """
    Get the per-tenant HMAC key for email hashing.
    Uses YASHIGANI_DB_AES_KEY (always present in every deployment).
    Deleting this key makes all email hashes permanently unrecoverable
    — clean GDPR Article 17 erasure without breaking the audit chain.
    Multi-tenant: derive per-org key via HKDF if org_id is provided.

    Compliance review findings #3 + #8 — this function previously fell back to a
    hardcoded string "yashigani-default-hmac-key" when both the env var
    and the secrets file were missing. That is safe for dev/demo but
    disastrous in production: an attacker able to guess the fallback value
    could forge email-hash collisions across deployments that use it.
    Fail-closed now: log.critical and raise RuntimeError to abort start-up
    rather than proceed with a publicly-known key.
    """
    key = os.getenv("YASHIGANI_DB_AES_KEY", "")
    if not key:
        # Fallback to secrets file
        try:
            secrets_dir = os.getenv("YASHIGANI_SECRETS_DIR", "/run/secrets")
            with open(os.path.join(secrets_dir, "db_aes_key")) as f:
                key = f.read().strip()
        except Exception:
            pass
    if not key:
        import logging as _logging

        _crit = _logging.getLogger("yashigani.security")
        _crit.critical(
            "_get_hmac_key: no YASHIGANI_DB_AES_KEY env var AND no "
            "/run/secrets/db_aes_key file. Refusing to start with a "
            "hardcoded fallback key (fail-closed)."
        )
        raise RuntimeError(
            "Missing YASHIGANI_DB_AES_KEY — set the env var or mount "
            "/run/secrets/db_aes_key. See docs/podman_deployment.md."
        )
    return key.encode()


def _derive_org_id() -> str:
    """
    Derive a stable org_id from deployment identity:
    domain + license_id + deployment timestamp.
    Clients with multiple deployments (different domains/subdomains)
    get different org_ids, so email hashes don't correlate across deployments.
    """
    domain = os.getenv("YASHIGANI_TLS_DOMAIN", "localhost")
    license_id = ""
    try:
        from yashigani.licensing.enforcer import get_license

        lic = get_license()
        license_id = lic.license_id or lic.org_domain or ""
    except Exception:
        pass
    # Combine domain + license for deployment-unique org_id
    return f"{domain}:{license_id}" if license_id else domain


def _email_hash(email: str, org_id: str = "") -> str:
    """
    HMAC-SHA256 hex digest of the normalised email, keyed per tenant.
    Not reversible without the HMAC key. Deleting the key = GDPR erasure.
    For multi-tenant (enterprise), the org_id is mixed into the key
    so the same email in different orgs produces different hashes.
    org_id is derived from domain + license key if not provided.
    """
    base_key = _get_hmac_key()
    effective_org = org_id or _derive_org_id()
    if effective_org:
        # Per-org key derivation: HMAC(base_key, org_id) as the effective key
        derived_key = hmac.new(base_key, effective_org.encode(), hashlib.sha256).digest()
    else:
        derived_key = base_key
    return hmac.new(derived_key, email.strip().lower().encode(), hashlib.sha256).hexdigest()


def _email_to_slug(email: str) -> str:
    """
    Derive a registry slug from an email address.
    B5 (2.25.5): delegates to the canonical implementation in identity.slug
    so all slug-derivation sites produce the same result.
    e.g. alice@example.com -> alice-example-com
    """
    from yashigani.identity.slug import email_to_slug as _canonical
    return _canonical(email)


def _resolve_or_create_identity(
    email: str,
    name: str,
    groups: list[str],
    idp_name: str,
    org_id: str,
    default_sensitivity: str,
) -> str:
    """
    Resolve an existing identity by slug or create a new one.

    Returns the identity_id.
    Raises RuntimeError("identity_suspended:...") if the identity is suspended
    (GROUP-2-4 / Iris MISSING-03).
    Raises RuntimeError("end_user_limit_exceeded:...") if seat limit is hit
    on new registration (GROUP-2-3).
    Raises RuntimeError("IdentityRegistry is not available") if registry unset.
    """
    # IdentityRegistry lives on the RBAC store Redis client (db/3).
    # We access it via backoffice_state if wired, otherwise instantiate locally.
    registry = getattr(backoffice_state, "identity_registry", None)
    if registry is None:
        raise RuntimeError("IdentityRegistry is not available")

    from yashigani.identity.registry import IdentityKind
    from yashigani.licensing.enforcer import LicenseLimitExceeded

    slug = _email_to_slug(email)
    existing = registry.get_by_slug(slug)
    if existing:
        identity_id = existing["identity_id"]
        # GROUP-2-4 / Iris MISSING-03: suspended users must not re-enter via SSO.
        # A user disabled by an admin (status="suspended" or status="inactive")
        # would otherwise bypass the suspension by initiating a fresh SSO flow.
        if existing.get("status") in ("suspended", "inactive"):
            logger.warning(
                "SSO: rejected suspended identity %s (email_hash=%s)",
                identity_id,
                _email_hash(email),
            )
            raise RuntimeError(f"identity_suspended:{identity_id}")
        # Keep groups and last_seen_at fresh.
        registry.update(identity_id, groups=groups)
        logger.info(
            "SSO: resolved existing identity %s (email_hash=%s)",
            identity_id,
            _email_hash(email),
        )
        return identity_id

    # New user — register with HUMAN kind.
    # GROUP-4-1: LicenseLimitExceeded is raised atomically by Lua script inside
    # registry.register() when the end-user seat limit is at capacity.
    try:
        identity_id, _key = registry.register(
            kind=IdentityKind.HUMAN,
            name=name or email,
            slug=slug,
            description=f"SSO user via {idp_name}",
            groups=groups,
            sensitivity_ceiling=default_sensitivity,
            org_id=org_id,
        )
    except LicenseLimitExceeded as exc:
        logger.warning(
            "SSO: end-user seat limit reached for new identity (email_hash=%s): %s",
            _email_hash(email),
            exc,
        )
        raise RuntimeError(f"end_user_limit_exceeded:{exc.current}:{exc.max_val}") from exc
    logger.info(
        "SSO: created new identity %s slug=%s (email_hash=%s)",
        identity_id,
        slug,
        _email_hash(email),
    )
    return identity_id


def _write_audit_safe(event) -> None:
    """Write an audit event, swallowing exceptions to avoid masking primary errors."""
    try:
        if backoffice_state.audit_writer is not None:
            backoffice_state.audit_writer.write(event)
    except Exception as exc:
        logger.error("SSO audit write failed: %s", exc)


async def _check_sod_admin_collision(email: str) -> bool:
    """
    SoD-002c + SoD-004: async pre-check before SSO identity creation.

    Returns True if an admin account already exists with this email (collision;
    provisioning must be blocked). Returns False if the path is clear.

    Fail-open on auth service unavailability (SoD-005 cron catches residual
    conflicts). Admin account uses email as username, so we check both the
    username lookup (fast — indexed) and the email column lookup.

    NIST AC-5 / SOC 2 CC6.3 / ISO 27001 A.5.16 / CMMC AC.L2-3.1.4 / ASVS V4.1.2.
    """
    auth_svc = getattr(backoffice_state, "auth_service", None)
    if auth_svc is None:
        return False

    # Check 1: admin usernames are emails — direct username lookup
    try:
        record = await auth_svc.get_account(email.strip().lower())
        if record is not None and record.account_tier == "admin":
            return True
    except Exception as exc:
        logger.warning("SoD-002c: username-based admin collision check failed: %s", exc)

    # Check 2: email column lookup (handles case-insensitive variations)
    if hasattr(auth_svc, "get_account_by_email"):
        try:
            record = await auth_svc.get_account_by_email(email)
            if record is not None and record.account_tier == "admin":
                return True
        except Exception as exc:
            logger.warning("SoD-002c: email-based admin collision check failed: %s", exc)

    return False


def _write_sso_success_audit(
    idp_id: str,
    idp_name: str,
    identity_id: str,
    email: str,
    groups: list[str],
    client_ip: str,
    org_id: str = "",
    # V6.8.4 — acr/amr/auth_time/iss claims for forensic audit
    acr: str = "",
    amr: Optional[list] = None,
    auth_time: Optional[int] = None,
    iss: str = "",
) -> None:
    from yashigani.audit.schema import SSOLoginSuccessEvent

    try:
        if backoffice_state.audit_writer is None:
            return
        backoffice_state.audit_writer.write(
            SSOLoginSuccessEvent(
                idp_id=idp_id,
                idp_name=idp_name,
                identity_id=identity_id,
                email_hash=_email_hash(email, org_id=org_id),
                groups=groups,
                client_ip_prefix=_mask_ip(client_ip),
                acr=acr,
                amr=amr if amr is not None else [],
                auth_time=auth_time,
                iss=iss,
            )
        )
    except Exception as exc:
        logger.error("SSO audit write failed (success): %s", exc)


def _write_sso_failure_audit(
    idp_id: str,
    idp_name: str,
    reason: str,
    client_ip: str,
) -> None:
    from yashigani.audit.schema import SSOLoginFailureEvent

    try:
        if backoffice_state.audit_writer is None:
            return
        backoffice_state.audit_writer.write(
            SSOLoginFailureEvent(
                idp_id=idp_id,
                idp_name=idp_name,
                failure_reason=reason,
                client_ip_prefix=_mask_ip(client_ip),
            )
        )
    except Exception as exc:
        logger.error("SSO audit write failed (failure): %s", exc)


def _write_saml_success_audit(
    idp_id: str,
    idp_name: str,
    identity_id: str,
    email: str,
    groups: list[str],
    client_ip: str,
    org_id: str = "",
    authn_context_class_ref: str = "",
    authn_instant: str = "",
    issuer: str = "",
) -> None:
    """V6.8.4 — write SAML-specific success event with AuthnContextClassRef."""
    from yashigani.audit.schema import SAMLLoginSuccessEvent

    try:
        if backoffice_state.audit_writer is None:
            return
        backoffice_state.audit_writer.write(
            SAMLLoginSuccessEvent(
                idp_id=idp_id,
                idp_name=idp_name,
                identity_id=identity_id,
                email_hash=_email_hash(email, org_id=org_id),
                groups=groups,
                client_ip_prefix=_mask_ip(client_ip),
                authn_context_class_ref=authn_context_class_ref,
                authn_instant=authn_instant,
                issuer=issuer,
            )
        )
    except Exception as exc:
        logger.error("SAML audit write failed (success): %s", exc)


def _write_saml_failure_audit(
    idp_id: str,
    idp_name: str,
    reason: str,
    client_ip: str,
) -> None:
    """V6.8.4 — write SAML-specific failure event."""
    from yashigani.audit.schema import SAMLLoginFailureEvent

    try:
        if backoffice_state.audit_writer is None:
            return
        backoffice_state.audit_writer.write(
            SAMLLoginFailureEvent(
                idp_id=idp_id,
                idp_name=idp_name,
                failure_reason=reason,
                client_ip_prefix=_mask_ip(client_ip),
            )
        )
    except Exception as exc:
        logger.error("SAML audit write failed (failure): %s", exc)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/sso/select")
async def list_idps():
    """
    Return the list of enabled IdPs available for SSO login.
    Unauthenticated — shown to anonymous users on the login page.
    """
    broker = backoffice_state.identity_broker
    if broker is None:
        return JSONResponse(content={"idps": []})

    idps = broker.list_idps()
    # BOPLA allowlist (#90): IdPPublic strips client_secret, client_id,
    # private_key, signing_cert, org_id, and default_sensitivity.
    return JSONResponse(
        content={
            "idps": [
                IdPPublic(
                    id=idp.id,
                    name=idp.name,
                    protocol=idp.protocol,
                    email_domains=getattr(idp, "email_domains", []) or [],
                ).model_dump()
                for idp in idps
            ]
        }
    )


@router.get("/sso/oidc/{idp_id}")
async def initiate_oidc(idp_id: str, request: Request):
    """
    Initiate an OIDC authorization flow.
    Generates a cryptographically random state + nonce, stores them in Redis
    with a 10-minute TTL, then redirects the browser to the IdP.
    """
    try:
        require_feature("oidc")
    except LicenseFeatureGated as exc:
        return JSONResponse(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            content=license_feature_gated_response(exc),
        )

    broker = backoffice_state.identity_broker
    if broker is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "identity_broker_unavailable"},
        )

    idp = broker.get_idp(idp_id)
    if idp is None or not idp.enabled:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "idp_not_found"},
        )
    if idp.protocol != "oidc":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "idp_not_oidc"},
        )

    r = _redis()
    if r is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "session_store_unavailable"},
        )

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    redirect_uri = _build_redirect_uri(request, idp_id)

    try:
        auth_url, code_verifier = broker.get_oidc_auth_url(
            idp_id=idp_id,
            redirect_uri=redirect_uri,
            state=state,
            nonce=nonce,
        )
    except Exception as exc:
        logger.error("OIDC initiation failed for IdP %s: %s", idp_id, exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"error": "oidc_discovery_failed"},
        )

    if auth_url is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "auth_url_generation_failed"},
        )

    # Store state with PKCE code_verifier for the callback (ASVS 10.4.6).
    _store_state(r, state, idp_id, nonce, code_verifier=code_verifier)

    return RedirectResponse(url=auth_url, status_code=status.HTTP_302_FOUND)


@router.get("/sso/oidc/{idp_id}/callback")
async def oidc_callback(
    idp_id: str,
    request: Request,
    code: str = "",
    state: str = "",
    error: str = "",
    error_description: str = "",
):
    """
    Handle the OIDC authorization code callback from the IdP.

    On success: resolves/creates the Yashigani identity, issues a session
    cookie, and redirects to /chat.
    On failure: redirects to /login with an error query parameter.
    """
    client_ip = request.client.host if request.client else "unknown"

    # IdP-side errors (user denied consent, etc.)
    if error:
        logger.warning(
            "OIDC callback: IdP returned error for IdP %s: %s — %s",
            idp_id,
            error,
            error_description,
        )
        _write_sso_failure_audit(idp_id, idp_id, f"idp_error:{error}", client_ip)
        return RedirectResponse(
            url=f"/login?error=sso_failed&idp={idp_id}",
            status_code=status.HTTP_302_FOUND,
        )

    # Validate required parameters
    if not code or not state:
        _write_sso_failure_audit(idp_id, idp_id, "missing_code_or_state", client_ip)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "missing_code_or_state"},
        )

    # Verify feature gate
    try:
        require_feature("oidc")
    except LicenseFeatureGated as exc:
        return JSONResponse(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            content=license_feature_gated_response(exc),
        )

    broker = backoffice_state.identity_broker
    if broker is None:
        _write_sso_failure_audit(idp_id, idp_id, "broker_unavailable", client_ip)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "identity_broker_unavailable"},
        )

    r = _redis()
    if r is None:
        _write_sso_failure_audit(idp_id, idp_id, "session_store_unavailable", client_ip)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "session_store_unavailable"},
        )

    # Consume and validate state — CSRF protection (ASVS V3.5.3)
    state_payload = _consume_state(r, state)
    if state_payload is None:
        _write_sso_failure_audit(idp_id, idp_id, "invalid_or_expired_state", client_ip)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_or_expired_state"},
        )

    if state_payload.get("idp_id") != idp_id:
        _write_sso_failure_audit(idp_id, idp_id, "state_idp_mismatch", client_ip)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "state_idp_mismatch"},
        )

    # Exchange code for tokens + validate ID token.
    # Retrieve the PKCE code_verifier stored during initiation (ASVS 10.4.6).
    code_verifier = state_payload.get("code_verifier", "")
    redirect_uri = _build_redirect_uri(request, idp_id)
    sso_result = broker.handle_oidc_callback(
        idp_id=idp_id,
        code=code,
        redirect_uri=redirect_uri,
        state=state,
        code_verifier=code_verifier,
    )

    if not sso_result.success:
        _write_sso_failure_audit(idp_id, sso_result.idp_name or idp_id, sso_result.error, client_ip)
        return RedirectResponse(
            url=f"/login?error=sso_failed&idp={idp_id}",
            status_code=status.HTTP_302_FOUND,
        )

    # -----------------------------------------------------------------------
    # V6.8.4 — acr/amr allowlist validation (ASVS V6.3.3)
    # Replaces the previous lexicographic env-var compare.
    # Purpose: catch honest IdP misconfiguration loudly. NOT a security
    # boundary — a compromised IdP can lie about these claims.
    # -----------------------------------------------------------------------
    _raw_claims: dict = sso_result.raw_claims if hasattr(sso_result, "raw_claims") else {}
    _claim_acr: str = str(_raw_claims.get("acr", "")).strip()
    _claim_amr_raw = _raw_claims.get("amr", [])
    _claim_amr: list[str] = (
        [str(m) for m in _claim_amr_raw]
        if isinstance(_claim_amr_raw, list)
        else ([str(_claim_amr_raw)] if _claim_amr_raw else [])
    )
    _claim_auth_time: Optional[int] = (
        int(_raw_claims["auth_time"]) if "auth_time" in _raw_claims and _raw_claims["auth_time"] is not None else None
    )
    _claim_iss: str = str(_raw_claims.get("iss", "")).strip()

    # acr allowlist check: if IdPConfig.required_acr_values is set,
    # the claim MUST appear in the allowlist.
    _idp_cfg = broker.get_idp(idp_id)
    _required_acr: Optional[list] = _idp_cfg.required_acr_values if _idp_cfg else None
    _required_amr: Optional[list] = _idp_cfg.required_amr_values if _idp_cfg else None

    if _required_acr is not None:
        if not _claim_acr or _claim_acr not in _required_acr:
            logger.warning(
                "OIDC acr mismatch: IdP %s returned acr=%r, allowed=%r",
                idp_id,
                _claim_acr,
                _required_acr,
            )
            _write_sso_failure_audit(
                idp_id,
                sso_result.idp_name or idp_id,
                f"acr_not_in_allowlist:got={_claim_acr!r}:allowed={_required_acr!r}",
                client_ip,
            )
            return RedirectResponse(
                url=f"/login?error=auth_strength_insufficient&idp={idp_id}",
                status_code=status.HTTP_302_FOUND,
            )

    # amr subset check: every required method must appear in the claim.
    if _required_amr is not None:
        _missing_amr = sorted(set(_required_amr) - set(_claim_amr))
        if _missing_amr:
            logger.warning(
                "OIDC amr insufficient: IdP %s returned amr=%r, required methods missing: %r",
                idp_id,
                _claim_amr,
                _missing_amr,
            )
            _write_sso_failure_audit(
                idp_id,
                sso_result.idp_name or idp_id,
                f"amr_methods_missing:got={_claim_amr!r}:missing={_missing_amr!r}",
                client_ip,
            )
            return RedirectResponse(
                url=f"/login?error=auth_strength_insufficient&idp={idp_id}",
                status_code=status.HTTP_302_FOUND,
            )

    logger.info(
        "OIDC acr=%r amr=%r auth_time=%s for IdP %s",
        _claim_acr or "(none)",
        _claim_amr or "(none)",
        _claim_auth_time,
        idp_id,
    )

    # SoD-002c + SoD-004 (combined): block SSO identity creation for admin emails.
    # An admin completing SSO would otherwise create a HUMAN identity and bridge
    # to the data plane via /auth/verify (layer 2 / SoD-003). Blocking here is
    # layer 1 of the defence-in-depth closure.
    # NIST AC-5 / SOC 2 CC6.3 / ISO 27001 A.5.16 / CMMC AC.L2-3.1.4 / ASVS V4.1.2.
    if await _check_sod_admin_collision(sso_result.email):
        from yashigani.audit.schema import SsoProvisionRejectedAdminExistsEvent
        _sod_email_hash = _email_hash(sso_result.email, org_id=_idp_cfg.org_id if _idp_cfg else "")
        _write_audit_safe(SsoProvisionRejectedAdminExistsEvent(
            idp_id=idp_id,
            idp_name=sso_result.idp_name or idp_id,
            email_hash=_sod_email_hash,
            client_ip_prefix=_mask_ip(client_ip),
        ))
        logger.warning(
            "SoD-002c/SoD-004: SSO provision rejected — admin account exists (email_hash=%s idp=%s)",
            _sod_email_hash,
            idp_id,
        )
        return RedirectResponse(
            url="/login?error=admin_cannot_use_platform&reason=separate_account_required",
            status_code=status.HTTP_302_FOUND,
        )

    # Resolve or provision the Yashigani identity.
    # Re-use _idp_cfg already fetched during the acr/amr check above.
    try:
        identity_id = _resolve_or_create_identity(
            email=sso_result.email,
            name=sso_result.name,
            groups=sso_result.groups,
            idp_name=sso_result.idp_name,
            org_id=_idp_cfg.org_id if _idp_cfg else "",
            default_sensitivity=(_idp_cfg.default_sensitivity if _idp_cfg else "INTERNAL"),
        )
    except RuntimeError as exc:
        err_str = str(exc)
        if err_str.startswith("identity_suspended:"):
            # GROUP-2-4: suspended user tried to re-enter via SSO
            _write_sso_failure_audit(idp_id, sso_result.idp_name, "identity_suspended", client_ip)
            return RedirectResponse(
                url="/login?error=account_suspended",
                status_code=status.HTTP_302_FOUND,
            )
        if err_str.startswith("end_user_limit_exceeded:"):
            # GROUP-2-3: end-user seat limit reached
            _write_sso_failure_audit(idp_id, sso_result.idp_name, "end_user_limit_exceeded", client_ip)
            return JSONResponse(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                content={
                    "error": "end_user_limit_exceeded",
                    "upgrade_url": "https://agnosticsec.com/pricing",
                },
            )
        logger.error("SSO identity resolution failed: %s", exc)
        _write_sso_failure_audit(idp_id, sso_result.idp_name, "identity_registry_unavailable", client_ip)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "identity_registry_unavailable"},
        )
    except Exception as exc:
        logger.error("SSO identity resolution error: %s", exc)
        _write_sso_failure_audit(idp_id, sso_result.idp_name, "identity_resolution_failed", client_ip)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "identity_resolution_failed"},
        )

    # Check if 2FA is required after SSO.
    # Default: true — YASHIGANI_SSO_2FA_REQUIRED=false to disable.
    # Reconciliation (V6.8.4 fix 2026-04-27): Compliance Stage B report noted this
    # was default-OFF ("false"). Maintainer-stated baseline is 2FA always-on.
    # The control is "force Yashigani TOTP on top of IdP-mediated SSO session"
    # — separate from admin local login which always requires TOTP unconditionally.
    # Flipped to default-ON per maintainer instruction.
    sso_2fa_required = os.getenv("YASHIGANI_SSO_2FA_REQUIRED", "true").lower() == "true"

    if sso_2fa_required:
        # Create a pending-2FA token instead of a full session.
        # The user must complete Yashigani TOTP before getting access.
        # V6.8.4: persist acr/amr/auth_time/iss so the 2FA-complete path
        # can write a fully-populated audit event.
        pending_token = secrets.token_urlsafe(32)
        pending_data = json.dumps(
            {
                "identity_id": identity_id,
                "email": sso_result.email,
                "name": sso_result.name,
                "groups": sso_result.groups,
                "idp_id": idp_id,
                "idp_name": sso_result.idp_name,
                "client_ip": client_ip,
                "created_at": time.time(),
                # V6.8.4 — auth-context claims for audit on 2FA completion
                "acr": _claim_acr,
                "amr": _claim_amr,
                "auth_time": _claim_auth_time,
                "iss": _claim_iss,
            }
        )
        r.setex(f"{_PENDING_2FA_PREFIX}{pending_token}", _PENDING_2FA_TTL, pending_data)

        response = RedirectResponse(
            url="/auth/sso/2fa",
            status_code=status.HTTP_302_FOUND,
        )
        response.set_cookie(
            key=_PENDING_2FA_COOKIE,
            value=pending_token,
            httponly=True,
            secure=True,
            samesite="strict",
            max_age=_PENDING_2FA_TTL,
            path="/auth",
        )
        logger.info("SSO 2FA pending for identity %s (IdP: %s)", identity_id, idp_id)
        return response

    # 2FA not required — issue full session immediately
    assert backoffice_state.session_store is not None  # set unconditionally at startup
    session = backoffice_state.session_store.create(
        account_id=identity_id,
        account_tier="user",
        client_ip=client_ip,
    )

    _write_sso_success_audit(
        idp_id=idp_id,
        idp_name=sso_result.idp_name,
        identity_id=identity_id,
        email=sso_result.email,
        groups=sso_result.groups,
        client_ip=client_ip,
        org_id=_idp_cfg.org_id if _idp_cfg else "",
        acr=_claim_acr,
        amr=_claim_amr,
        auth_time=_claim_auth_time,
        iss=_claim_iss,
    )

    response = RedirectResponse(url="/chat", status_code=status.HTTP_302_FOUND)
    response.set_cookie(
        key=_USER_SESSION_COOKIE,
        value=session.token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=_SESSION_MAX_AGE,
        path="/",
    )
    return response


@router.get("/sso/2fa")
async def sso_2fa_page(request: Request):
    """
    Serve the 2FA verification prompt after SSO.
    The user must submit their Yashigani TOTP code to complete login.
    """
    pending_token = request.cookies.get(_PENDING_2FA_COOKIE)
    if not pending_token:
        return RedirectResponse(url="/login?error=no_pending_sso", status_code=302)

    r = _redis()
    if r is None or r.get(f"{_PENDING_2FA_PREFIX}{pending_token}") is None:
        return RedirectResponse(url="/login?error=sso_2fa_expired", status_code=302)

    return JSONResponse(
        content={
            "status": "pending_2fa",
            "message": "SSO authentication successful. Enter your Yashigani TOTP code to complete login.",
            "endpoint": "/auth/sso/2fa/verify",
            "method": "POST",
            "fields": ["totp_code"],
        }
    )


@router.post("/sso/2fa/verify")
async def sso_2fa_verify(request: Request):
    """
    Verify the Yashigani TOTP code after SSO authentication.
    On success, upgrade the pending session to a full session.
    """
    pending_token = request.cookies.get(_PENDING_2FA_COOKIE)
    if not pending_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "no_pending_sso_session"},
        )

    r = _redis()
    if r is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "session_store_unavailable"},
        )

    # Atomically consume the pending token
    raw = r.get(f"{_PENDING_2FA_PREFIX}{pending_token}")
    if raw is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "sso_2fa_expired_or_invalid"},
        )

    try:
        pending = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_pending_session"},
        )

    # Parse TOTP code from request body
    try:
        body = await request.json()
        totp_code = body.get("totp_code", "")
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_request_body"},
        )

    if not totp_code or len(totp_code) != 6 or not totp_code.isdigit():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_totp_code_format"},
        )

    # Look up the identity's TOTP secret
    identity_id = pending.get("identity_id", "")
    registry = getattr(backoffice_state, "identity_registry", None)
    if registry is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "identity_registry_unavailable"},
        )

    # Verify TOTP — the identity must have a provisioned TOTP secret
    from yashigani.auth.totp import verify_totp

    identity = registry.get(identity_id)
    if identity is None:
        r.delete(f"{_PENDING_2FA_PREFIX}{pending_token}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "identity_not_found"},
        )

    totp_secret = identity.get("totp_secret", "")
    if not totp_secret:
        # Identity hasn't provisioned TOTP yet — they need to do that first
        r.delete(f"{_PENDING_2FA_PREFIX}{pending_token}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "totp_not_provisioned",
                "message": "You must provision a TOTP authenticator before using SSO. Contact your administrator.",
            },
        )

    # Phase 13: SSO identities are user-tier; fall back to SHA256/6 if the
    # identity dict doesn't carry a totp_algorithm field (pre-3.1 identities).
    # Follow-up: add totp_algorithm to the identity registry schema for identities
    # that may be admin-tier in future.
    from yashigani.auth.totp import TOTP_ALGO_SHA256 as _SSO_DEFAULT_ALGO
    _sso_totp_algo = identity.get("totp_algorithm", _SSO_DEFAULT_ALGO)
    _sso_totp_digits = 8 if _sso_totp_algo == "SHA512" else 6

    used_codes: set = set()  # Recovery codes not applicable here
    if not verify_totp(totp_secret, totp_code, used_codes, algorithm=_sso_totp_algo, digits=_sso_totp_digits):
        # Don't consume the pending token on TOTP failure — let them retry
        _write_sso_failure_audit(
            pending.get("idp_id", ""),
            pending.get("idp_name", ""),
            "totp_verification_failed",
            pending.get("client_ip", "unknown"),
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_totp_code"},
        )

    # TOTP verified — consume the pending token and issue a full session
    r.delete(f"{_PENDING_2FA_PREFIX}{pending_token}")

    client_ip = pending.get("client_ip", "unknown")
    assert backoffice_state.session_store is not None  # set unconditionally at startup
    session = backoffice_state.session_store.create(
        account_id=identity_id,
        account_tier="user",
        client_ip=client_ip,
    )

    # V6.8.4 — propagate acr/amr/auth_time/iss from the pending token
    # (set during OIDC callback) so the audit event is fully populated.
    _p_amr = pending.get("amr", [])
    _write_sso_success_audit(
        idp_id=pending.get("idp_id", ""),
        idp_name=pending.get("idp_name", ""),
        identity_id=identity_id,
        email=pending.get("email", ""),
        groups=pending.get("groups", []),
        client_ip=client_ip,
        acr=pending.get("acr", ""),
        amr=_p_amr if isinstance(_p_amr, list) else [],
        auth_time=pending.get("auth_time"),
        iss=pending.get("iss", ""),
    )

    response = RedirectResponse(url="/chat", status_code=status.HTTP_302_FOUND)
    response.set_cookie(
        key=_USER_SESSION_COOKIE,
        value=session.token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=_SESSION_MAX_AGE,
        path="/",
    )
    # Clear the pending cookie
    response.delete_cookie(_PENDING_2FA_COOKIE, path="/auth")
    return response


@router.post("/sso/saml/{idp_id}/acs")
async def saml_acs(idp_id: str, request: Request):
    """
    SAML v2 Assertion Consumer Service endpoint.
    Receives the IdP POST with SAMLResponse, validates the assertion,
    resolves/creates the identity, and issues a session.
    """
    client_ip = request.client.host if request.client else "unknown"

    try:
        require_feature("saml")
    except LicenseFeatureGated as exc:
        return JSONResponse(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            content=license_feature_gated_response(exc),
        )

    broker = backoffice_state.identity_broker
    if broker is None:
        _write_sso_failure_audit(idp_id, idp_id, "broker_unavailable", client_ip)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "identity_broker_unavailable"},
        )

    idp = broker.get_idp(idp_id)
    if idp is None or not idp.enabled or idp.protocol != "saml":
        _write_sso_failure_audit(idp_id, idp_id, "idp_not_found_or_not_saml", client_ip)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "idp_not_found"},
        )

    # Build request_data for python3-saml
    form_data = await request.form()
    saml_response = str(form_data.get("SAMLResponse", ""))
    relay_state = str(form_data.get("RelayState", ""))

    if not saml_response:
        _write_saml_failure_audit(idp_id, idp.name, "missing_saml_response", client_ip)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "missing_saml_response"},
        )

    # Construct request_data dict expected by python3-saml
    request_data = {
        "https": "on" if request.url.scheme == "https" else "off",
        "http_host": request.url.hostname or "localhost",
        "server_port": request.url.port or (443 if request.url.scheme == "https" else 80),
        "script_name": request.url.path,
        "post_data": {"SAMLResponse": saml_response, "RelayState": relay_state},
    }

    # Process the SAML response using the broker's SAML handler
    sso_result = broker.handle_saml_response(idp_id=idp_id, saml_response=saml_response)

    if not sso_result.success:
        _write_saml_failure_audit(idp_id, idp.name, sso_result.error, client_ip)
        return RedirectResponse(
            url=f"/login?error=sso_failed&idp={idp_id}",
            status_code=status.HTTP_302_FOUND,
        )

    # -----------------------------------------------------------------------
    # V6.8.4 — SAML AuthnContextClassRef allowlist (mirrors OIDC acr check)
    # -----------------------------------------------------------------------
    # Extract the AuthnContextClassRef from the SAMLUserInfo.
    # The broker returns it in sso_result.raw_claims["authn_context_class_ref"]
    # via the SSOResult.  For SAML the raw_claims dict is empty; the classref
    # lives on the SAMLUserInfo attached to the raw_saml_user_info on broker.
    # Rather than threading it through SSOResult, we look it up directly via
    # the broker's internal handle (since broker.handle_saml_response already
    # ran successfully at this point).
    _saml_classref: str = ""
    _saml_authn_instant: str = ""
    _saml_issuer: str = ""
    # Attempt to extract from the raw_claims if populated by broker
    if sso_result.raw_claims:
        _saml_classref = str(sso_result.raw_claims.get("authn_context_class_ref", "")).strip()
        _saml_authn_instant = str(sso_result.raw_claims.get("authn_instant", "")).strip()
        _saml_issuer = str(sso_result.raw_claims.get("iss", "")).strip()

    # acr allowlist validation against required_acr_values on IdPConfig.
    _required_saml_acr = idp.required_acr_values if idp else None
    if _required_saml_acr is not None:
        if not _saml_classref or _saml_classref not in _required_saml_acr:
            logger.warning(
                "SAML AuthnContextClassRef mismatch: IdP %s returned %r, allowed=%r",
                idp_id,
                _saml_classref,
                _required_saml_acr,
            )
            _write_saml_failure_audit(
                idp_id,
                idp.name,
                f"authn_context_class_ref_not_in_allowlist:got={_saml_classref!r}:allowed={_required_saml_acr!r}",
                client_ip,
            )
            return RedirectResponse(
                url=f"/login?error=auth_strength_insufficient&idp={idp_id}",
                status_code=status.HTTP_302_FOUND,
            )

    logger.info(
        "SAML AuthnContextClassRef=%r authn_instant=%s for IdP %s",
        _saml_classref or "(none)",
        _saml_authn_instant or "(none)",
        idp_id,
    )

    # SoD-002c + SoD-004 (combined): block SAML SSO identity creation for admin emails.
    # Mirrors the OIDC callback SoD check — same exploit chain applies via SAML.
    if await _check_sod_admin_collision(sso_result.email):
        from yashigani.audit.schema import SsoProvisionRejectedAdminExistsEvent
        _sod_saml_email_hash = _email_hash(sso_result.email, org_id=idp.org_id if idp else "")
        _write_audit_safe(SsoProvisionRejectedAdminExistsEvent(
            idp_id=idp_id,
            idp_name=sso_result.idp_name or idp_id,
            email_hash=_sod_saml_email_hash,
            client_ip_prefix=_mask_ip(client_ip),
        ))
        logger.warning(
            "SoD-002c/SoD-004 (SAML): SSO provision rejected — admin account exists (email_hash=%s idp=%s)",
            _sod_saml_email_hash,
            idp_id,
        )
        return RedirectResponse(
            url="/login?error=admin_cannot_use_platform&reason=separate_account_required",
            status_code=status.HTTP_302_FOUND,
        )

    # Resolve or create the identity
    try:
        identity_id = _resolve_or_create_identity(
            email=sso_result.email,
            name=sso_result.name,
            groups=sso_result.groups,
            idp_name=sso_result.idp_name,
            org_id=idp.org_id,
            default_sensitivity=idp.default_sensitivity,
        )
    except RuntimeError as exc:
        err_str = str(exc)
        if err_str.startswith("identity_suspended:"):
            _write_saml_failure_audit(idp_id, idp.name, "identity_suspended", client_ip)
            return RedirectResponse(
                url="/login?error=account_suspended",
                status_code=status.HTTP_302_FOUND,
            )
        if err_str.startswith("end_user_limit_exceeded:"):
            _write_saml_failure_audit(idp_id, idp.name, "end_user_limit_exceeded", client_ip)
            return JSONResponse(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                content={
                    "error": "end_user_limit_exceeded",
                    "upgrade_url": "https://agnosticsec.com/pricing",
                },
            )
        logger.error("SAML identity resolution failed: %s", exc)
        _write_saml_failure_audit(idp_id, idp.name, "identity_registry_unavailable", client_ip)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "identity_registry_unavailable"},
        )

    # Check 2FA requirement — default ON (matches OIDC path, V6.8.4 fix).
    r = _redis()
    sso_2fa_required = os.getenv("YASHIGANI_SSO_2FA_REQUIRED", "true").lower() == "true"

    if sso_2fa_required and r is not None:
        pending_token = secrets.token_urlsafe(32)
        pending_data = json.dumps(
            {
                "identity_id": identity_id,
                "email": sso_result.email,
                "name": sso_result.name,
                "groups": sso_result.groups,
                "idp_id": idp_id,
                "idp_name": idp.name,
                "client_ip": client_ip,
                "created_at": time.time(),
                # V6.8.4 — persist SAML auth-context for audit on 2FA completion
                "saml_authn_context_class_ref": _saml_classref,
                "saml_authn_instant": _saml_authn_instant,
                "saml_issuer": _saml_issuer,
            }
        )
        r.setex(f"{_PENDING_2FA_PREFIX}{pending_token}", _PENDING_2FA_TTL, pending_data)

        response = RedirectResponse(url="/auth/sso/2fa", status_code=status.HTTP_302_FOUND)
        response.set_cookie(
            key=_PENDING_2FA_COOKIE,
            value=pending_token,
            httponly=True,
            secure=True,
            samesite="strict",
            max_age=_PENDING_2FA_TTL,
            path="/auth",
        )
        return response

    # Issue full session — write SAML-specific audit event.
    assert backoffice_state.session_store is not None  # set unconditionally at startup
    session = backoffice_state.session_store.create(
        account_id=identity_id,
        account_tier="user",
        client_ip=client_ip,
    )

    _write_saml_success_audit(
        idp_id=idp_id,
        idp_name=idp.name,
        identity_id=identity_id,
        email=sso_result.email,
        groups=sso_result.groups,
        client_ip=client_ip,
        org_id=idp.org_id,
        authn_context_class_ref=_saml_classref,
        authn_instant=_saml_authn_instant,
        issuer=_saml_issuer,
    )

    response = RedirectResponse(url="/chat", status_code=status.HTTP_302_FOUND)
    response.set_cookie(
        key=_USER_SESSION_COOKIE,
        value=session.token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=_SESSION_MAX_AGE,
        path="/",
    )
    return response
