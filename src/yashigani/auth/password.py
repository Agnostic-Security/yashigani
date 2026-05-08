"""
Yashigani Auth — Argon2id password hashing + HIBP breach check.
OWASP ASVS V2.4: m=65536, t=3, p=4 minimum parameters.
OWASP ASVS V2.1.7: Passwords must be checked against breach databases.

Last updated: 2026-05-08T00:00:00+01:00
"""
from __future__ import annotations

import hashlib
import logging
import os
import secrets
import string
from typing import Optional

logger = logging.getLogger(__name__)

_MIN_PASSWORD_LENGTH = 36
_AUTO_PASSWORD_ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"

# OWASP ASVS 6.1.2 + 6.2.11 — context-specific word list.
# Passwords containing these words (case-insensitive) are rejected to prevent
# easily guessable passwords tied to the product, company, or common defaults.
_CONTEXT_BANNED_WORDS = frozenset([
    "yashigani", "agnostic", "security", "admin", "password", "gateway",
])


class PasswordContextError(ValueError):
    """Raised when a password contains a context-specific banned word."""

    def __init__(self, word: str):
        self.word = word
        super().__init__(
            f"Password must not contain the word '{word}'. "
            "Choose a password that does not include product, company, or common default terms."
        )


def validate_password_context(password: str) -> None:
    """
    Check password against the context-specific banned word list.
    OWASP ASVS 6.1.2 + 6.2.11: reject passwords containing product name,
    company name, domain, or common default terms.

    Raises:
        PasswordContextError: if the password contains a banned word.
    """
    pw_lower = password.lower()
    for word in _CONTEXT_BANNED_WORDS:
        if word in pw_lower:
            raise PasswordContextError(word)


def _import_argon2():
    try:
        from argon2 import PasswordHasher
        from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
        return PasswordHasher, VerifyMismatchError, VerificationError, InvalidHashError
    except ImportError as exc:
        raise ImportError(
            "argon2-cffi is required. Install with: pip install argon2-cffi"
        ) from exc


def _hasher():
    PasswordHasher, *_ = _import_argon2()
    return PasswordHasher(
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        salt_len=16,
    )


def hash_password(password: str, *, check_breach: bool = True) -> str:
    """
    Return Argon2id hash of password. Never log the input.

    Args:
        password: Plaintext password (min 36 chars).
        check_breach: If True (default), checks password against HIBP
            breach database before hashing. Raises PasswordBreachedError
            if the password has been compromised. Set to False for
            bootstrap/migration paths where the check was already done,
            or when YASHIGANI_HIBP_CHECK_ENABLED=false disables the check.

    Raises:
        ValueError: Password too short.
        PasswordBreachedError: Password found in breach database.
    """
    if len(password) < _MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"Password must be at least {_MIN_PASSWORD_LENGTH} characters"
        )
    validate_password_context(password)
    if check_breach and hibp_check_enabled():
        validate_password_not_breached(password)
    return _hasher().hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    """Return True if password matches hash. Never raise on mismatch."""
    _, VerifyMismatchError, VerificationError, InvalidHashError = _import_argon2()
    try:
        return _hasher().verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """Return True if the hash parameters are outdated and should be upgraded."""
    try:
        return _hasher().check_needs_rehash(stored_hash)
    except Exception:
        return False


def generate_password(length: int = 36) -> str:
    """
    Generate a cryptographically random password of the given length.
    Displayed once to the admin at user creation — never stored in plaintext.
    """
    if length < _MIN_PASSWORD_LENGTH:
        raise ValueError(f"Generated password must be at least {_MIN_PASSWORD_LENGTH} chars")
    return "".join(secrets.choice(_AUTO_PASSWORD_ALPHABET) for _ in range(length))


# =========================================================================
# HIBP (Have I Been Pwned) k-Anonymity breach check
# =========================================================================
# OWASP ASVS V2.1.7: "Verify that passwords submitted during account
# registration, login, and password change are checked against a set of
# breached passwords."
#
# Protocol: SHA-1 hash the password, send the first 5 characters to the
# HIBP Passwords API, receive all matching suffixes, check locally.
# The actual password NEVER leaves the system.
#
# Operator controls (env vars):
#   YASHIGANI_HIBP_CHECK_ENABLED  — "true" (default) / "false" to opt out.
#     Opting out is intended for air-gapped deployments or environments where
#     the outbound HTTPS requirement cannot be met. The check is a
#     defense-in-depth layer (ASVS V2.1.7); disabling it is a risk-accept
#     that operators must document. The default is fail-open (not fail-closed)
#     on API unreachability; disabling removes the check entirely.
#   YASHIGANI_HIBP_API_URL        — override API base URL (default:
#     "https://api.pwnedpasswords.com/range/"). Set to your own HIBP mirror
#     for air-gapped deployments. Must include the trailing slash.
#
# See: https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange
# =========================================================================

_HIBP_DEFAULT_API_URL = "https://api.pwnedpasswords.com/range/"
_HIBP_TIMEOUT = 5  # seconds

# SSRF guardrail: route HIBP calls through the centralised HttpClient.
# api.pwnedpasswords.com is public HTTPS-only — no SSRF risk in practice,
# but defence-in-depth: all outbound HTTP must pass through the policy
# gate so future changes to _HIBP_API_URL are automatically enforced.
# OWASP A10 / API7 / yashigani-retro#95.
_HIBP_HTTP_CLIENT = None   # lazy-initialised on first use


def _hibp_http_client():
    """Return a singleton HttpClient scoped to the HIBP allowlist."""
    global _HIBP_HTTP_CLIENT
    if _HIBP_HTTP_CLIENT is None:
        from yashigani.net import HttpClient
        _HIBP_HTTP_CLIENT = HttpClient(
            allowlist=["api.pwnedpasswords.com"],
            allow_http=False,   # HTTPS-only; HIBP never needs plain HTTP
            timeout_s=float(_HIBP_TIMEOUT),
        )
    return _HIBP_HTTP_CLIENT


def hibp_check_enabled() -> bool:
    """
    Return True if the HIBP breach check is enabled.

    Reads YASHIGANI_HIBP_CHECK_ENABLED at call time (not module load) so
    tests can override it via monkeypatch without import-time side effects.
    Default: True (secure default — operators must explicitly opt out).
    """
    raw = os.environ.get("YASHIGANI_HIBP_CHECK_ENABLED", "true").strip().lower()
    return raw not in ("false", "0", "no", "off")


def hibp_api_url() -> str:
    """
    Return the HIBP API base URL to use for range queries.

    Reads YASHIGANI_HIBP_API_URL at call time so tests can override it.
    Default: https://api.pwnedpasswords.com/range/
    """
    return os.environ.get("YASHIGANI_HIBP_API_URL", _HIBP_DEFAULT_API_URL)


class PasswordBreachedError(ValueError):
    """Raised when a password is found in the HIBP breach database."""

    def __init__(self, breach_count: int):
        self.breach_count = breach_count
        super().__init__(
            "This password has appeared in known data breaches; choose another."
        )


def check_hibp(password: str, *, api_key: Optional[str] = None) -> Optional[int]:
    """
    Check a password against the HIBP Passwords API using k-Anonymity.

    Routes through the centralised :class:`~yashigani.net.HttpClient` with
    an HTTPS-only allowlist scoped to ``api.pwnedpasswords.com``. This
    enforces scheme + allowlist checks via the shared SSRF-guardrail policy
    before any outbound request is issued (OWASP A10 / API7 / retro#95).

    Returns:
        None if the password is clean (not found in any breach).
        int (breach count) if the password has been compromised.

    The password is NEVER transmitted. Only the first 5 characters of its
    SHA-1 hash are sent to the API. All matching is done locally.

    Args:
        password: Plaintext password to check.
        api_key: Optional HIBP API key for rate-limit lift or mirror auth.
            If non-empty, injects ``hibp-api-key: <key>`` header. If None or
            empty, the request is sent without the header (anonymous — works
            for the free range endpoint). Resolve this value via
            ``hibp_config.resolve_hibp_api_key()`` to apply the
            admin-panel → env-var → anon priority chain.
            The key is NEVER logged at any level.

    Failure mode (fail-open): if the HIBP API is unreachable (network
    timeout, 5xx, DNS failure), this function logs a WARNING, increments
    the ``yashigani_hibp_api_unavailable_total`` metric, and returns None
    (clean — the caller proceeds). This is intentional: the HIBP check is a
    defense-in-depth layer; operator password changes must never be blocked
    by a third-party API outage.

    Does NOT check YASHIGANI_HIBP_CHECK_ENABLED — callers must check that
    separately (see hibp_check_enabled()). This function always performs the
    check when called.
    """
    # HIBP k-Anonymity protocol mandates SHA-1 as the wire format (NIST SP 800-63B §5.1.1.2).
    # usedforsecurity=False: signals to hashlib/Bandit that this is a protocol requirement,
    # not a security primitive. The actual password is stored with Argon2id. Closes B324.
    # nosem: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1 -- HIBP k-Anonymity protocol mandates SHA-1; usedforsecurity=False; not used for cryptographic integrity (NIST SP 800-63B §5.1.1.2)
    sha1_hash = hashlib.sha1(  # noqa: S324
        password.encode("utf-8"), usedforsecurity=False
    ).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    request_url = f"{hibp_api_url()}{prefix}"

    # Build request headers — api_key is never logged (security invariant).
    headers = {"User-Agent": "Yashigani-PasswordCheck/1.0"}
    if api_key:
        headers["hibp-api-key"] = api_key

    # --- SSRF policy check via HttpClient (defence-in-depth) ----------------
    # _check_policy() is synchronous (pure URL validation, no I/O). This
    # ensures scheme and allowlist are enforced even if _HIBP_API_URL is
    # ever changed to a non-HTTPS or non-allowlisted value.
    try:
        from yashigani.net import BlockedByPolicy
        _hibp_http_client()._check_policy(request_url)
    except BlockedByPolicy as exc:
        logger.error(
            "HIBP request blocked by SSRF policy — check_hibp disabled: %s", exc
        )
        return None
    except Exception as exc:
        logger.debug("HIBP policy check failed (%s) — skipping breach check", exc)
        return None

    # --- Outbound request ----------------------------------------------------
    try:
        import httpx
        response = httpx.get(
            request_url,
            timeout=_HIBP_TIMEOUT,
            headers=headers,
        )
        response.raise_for_status()
    except ImportError:
        # httpx not available — fall back to stdlib urllib (same policy already checked)
        return _check_hibp_urllib(password, api_key=api_key)
    except Exception as exc:
        logger.warning(
            "HIBP API unreachable — skipping breach check (fail-open). "
            "Network requirement: outbound HTTPS to api.pwnedpasswords.com. Error: %s",
            type(exc).__name__,
        )
        _increment_hibp_unavailable()
        return None

    for line in response.text.splitlines():
        parts = line.strip().split(":")
        if len(parts) == 2 and parts[0].upper() == suffix:
            return int(parts[1])

    return None


def _check_hibp_urllib(
    password: str,
    *,
    api_key: Optional[str] = None,
) -> Optional[int]:
    """Fallback HIBP check using stdlib urllib (no httpx dependency).

    The SSRF policy check is applied by the caller (check_hibp) before
    this function is invoked, so we do NOT re-check here — policy is
    enforced exactly once, as close to the decision point as possible.

    Args:
        password: Plaintext password to check.
        api_key: Optional HIBP API key. If non-empty, injects
            ``hibp-api-key: <key>`` header. Never logged.
    """
    import urllib.request
    import urllib.error

    # Same HIBP k-Anonymity protocol — SHA-1 mandated by external API.
    # usedforsecurity=False: not a security primitive; closes B324 (Bandit).
    # nosem: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1 -- HIBP k-Anonymity protocol mandates SHA-1; usedforsecurity=False; not used for cryptographic integrity (NIST SP 800-63B §5.1.1.2)
    sha1_hash = hashlib.sha1(  # noqa: S324
        password.encode("utf-8"), usedforsecurity=False
    ).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    headers = {"User-Agent": "Yashigani-PasswordCheck/1.0"}
    if api_key:
        # api_key deliberately not logged — security invariant
        headers["hibp-api-key"] = api_key

    req = urllib.request.Request(
        f"{hibp_api_url()}{prefix}",
        headers=headers,
    )

    try:
        with urllib.request.urlopen(req, timeout=_HIBP_TIMEOUT) as resp:  # noqa: S310
            body = resp.read().decode("utf-8")
    except (urllib.error.URLError, OSError) as exc:
        logger.warning(
            "HIBP API unreachable (urllib fallback) — skipping breach check. "
            "Error: %s", type(exc).__name__,
        )
        _increment_hibp_unavailable()
        return None

    for line in body.splitlines():
        parts = line.strip().split(":")
        if len(parts) == 2 and parts[0].upper() == suffix:
            return int(parts[1])

    return None


def _increment_hibp_unavailable() -> None:
    """Increment the HIBP API unavailability metric. Fails silently if prometheus_client not installed."""
    try:
        from yashigani.metrics.registry import hibp_check_api_unavailable_total
        hibp_check_api_unavailable_total.inc()
    except Exception:
        pass  # Metric unavailable — non-fatal


def validate_password_not_breached(password: str, *, raise_on_breach: bool = True) -> Optional[int]:
    """
    Check a password against HIBP and optionally raise PasswordBreachedError.

    Respects YASHIGANI_HIBP_CHECK_ENABLED — if the check is disabled, returns
    None immediately without contacting the API.

    Args:
        password: The plaintext password to check.
        raise_on_breach: If True (default), raises PasswordBreachedError when
            the password is found in a breach. If False, returns the breach
            count silently.

    Returns:
        None if clean or check disabled; int (breach count) if compromised
        and raise_on_breach=False.

    Raises:
        PasswordBreachedError if the password is compromised and raise_on_breach=True.
    """
    if not hibp_check_enabled():
        logger.debug("HIBP check skipped — YASHIGANI_HIBP_CHECK_ENABLED=false")
        return None

    breach_count = check_hibp(password)
    if breach_count is not None and breach_count > 0:
        logger.warning(
            "Password rejected — found in %d HIBP breach(es)", breach_count
        )
        if raise_on_breach:
            raise PasswordBreachedError(breach_count)
    return breach_count
