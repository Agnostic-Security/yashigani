"""Yashigani Auth — local auth, TOTP, session management, SPIFFE gate, step-up."""
# Last updated: 2026-05-07T01:00:00+01:00
from yashigani.auth.password import (
    hash_password, verify_password, generate_password,
    PasswordBreachedError, PasswordContextError,
    check_hibp, validate_password_not_breached,
    hibp_check_enabled, hibp_api_url,
)
from yashigani.auth.totp import (
    generate_provisioning, generate_recovery_code_set,
    verify_totp, verify_recovery_code, codes_remaining,
    TotpProvisioning, RecoveryCodeSet,
)
from yashigani.auth.session import SessionStore, Session
from yashigani.auth.local_auth import LocalAuthService, AccountRecord
from yashigani.auth.spiffe import require_spiffe_id
from yashigani.auth.stepup import has_fresh_stepup, assert_fresh_stepup, StepUpRequired, STEPUP_TTL_SECONDS
from yashigani.auth.caddy_verified import load_caddy_secret, CaddyVerifiedMiddleware
# v2.23.3 (#59)
from yashigani.auth.settings_store import AuthSettingsStore
from yashigani.auth.hibp_config import (
    mask_hibp_key, validate_hibp_key_format,
    resolve_hibp_api_key, get_hibp_key_status,
)

__all__ = [
    "hash_password", "verify_password", "generate_password",
    "PasswordBreachedError", "PasswordContextError",
    "check_hibp", "validate_password_not_breached",
    "hibp_check_enabled", "hibp_api_url",
    "generate_provisioning", "generate_recovery_code_set",
    "verify_totp", "verify_recovery_code", "codes_remaining",
    "TotpProvisioning", "RecoveryCodeSet",
    "SessionStore", "Session",
    "LocalAuthService", "AccountRecord",
    "require_spiffe_id",
    "has_fresh_stepup", "assert_fresh_stepup", "StepUpRequired", "STEPUP_TTL_SECONDS",
    "load_caddy_secret", "CaddyVerifiedMiddleware",
    # v2.23.3 (#59)
    "AuthSettingsStore",
    "mask_hibp_key", "validate_hibp_key_format",
    "resolve_hibp_api_key", "get_hibp_key_status",
]
