"""
Unit tests for the HIBP k-Anonymity breach check integration.

OWASP ASVS V2.1.7: Passwords submitted during account registration, login,
and password change must be checked against a set of breached passwords.

Coverage:
  - SHA-1 + range parsing (parse logic, prefix/suffix split)
  - Operator opt-out via YASHIGANI_HIBP_CHECK_ENABLED=false
  - Operator API URL override via YASHIGANI_HIBP_API_URL
  - Breached password rejected (check_hibp returns count, PasswordBreachedError raised)
  - Clean password accepted (check_hibp returns None)
  - API unreachable → fail-open (returns None) + warning logged + metric incremented
  - validate_password_not_breached: raise_on_breach=True vs False
  - hash_password respects HIBP opt-out
  - hibp_check_enabled() env-var parsing
  - Error message text matches brief spec
"""
from __future__ import annotations

import hashlib
import logging
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

import yashigani.auth.password as _pw_module
from yashigani.auth.password import (
    PasswordBreachedError,
    check_hibp,
    hash_password,
    hibp_api_url,
    hibp_check_enabled,
    validate_password_not_breached,
    _HIBP_DEFAULT_API_URL,
    _check_hibp_urllib,
)


# ---------------------------------------------------------------------------
# Module-level SSRF policy bypass
# ---------------------------------------------------------------------------
# PR #81 added an SSRF policy check (_hibp_http_client()._check_policy()) to
# check_hibp() before any outbound request.  Unit tests in this file pre-date
# PR #81 and patch httpx.get directly.  The autouse fixture below neutralises
# the policy check for all unit tests so they remain Redis/network-free.
# SSRF policy correctness is separately verified in
# test_v2233_hibp_route_through_httpclient.py.

@pytest.fixture(autouse=True)
def _bypass_ssrf_policy(monkeypatch):
    """Patch the HIBP HttpClient policy check to a no-op for all unit tests."""
    mock_client = MagicMock()
    mock_client._check_policy = MagicMock(return_value=None)
    monkeypatch.setattr(_pw_module, "_HIBP_HTTP_CLIENT", mock_client)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_hibp_response(password: str, count: int) -> str:
    """Build a fake HIBP range-query response containing the given password's suffix."""
    # nosem: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1 -- test helper reproducing HIBP protocol; not a security primitive
    sha1 = hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()  # noqa: S324
    suffix = sha1[5:]
    # Add a couple of unrelated entries before and after
    lines = [
        f"AAAAABBBBBCCCCCDDDDDEEEEEFFFFFF00000:{count + 999}",
        f"{suffix}:{count}",
        f"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:{count + 1}",
    ]
    return "\n".join(lines)


def _sha1_prefix_suffix(password: str):
    # nosem: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1 -- test helper reproducing HIBP protocol
    sha1 = hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()  # noqa: S324
    return sha1[:5], sha1[5:]


# ---------------------------------------------------------------------------
# hibp_check_enabled()
# ---------------------------------------------------------------------------

class TestHibpCheckEnabled:
    def test_default_is_true(self, monkeypatch):
        monkeypatch.delenv("YASHIGANI_HIBP_CHECK_ENABLED", raising=False)
        assert hibp_check_enabled() is True

    @pytest.mark.parametrize("val", ["false", "FALSE", "False", "0", "no", "NO", "off", "OFF"])
    def test_disabled_values(self, monkeypatch, val):
        monkeypatch.setenv("YASHIGANI_HIBP_CHECK_ENABLED", val)
        assert hibp_check_enabled() is False

    @pytest.mark.parametrize("val", ["true", "TRUE", "True", "1", "yes", "YES"])
    def test_enabled_values(self, monkeypatch, val):
        monkeypatch.setenv("YASHIGANI_HIBP_CHECK_ENABLED", val)
        assert hibp_check_enabled() is True


# ---------------------------------------------------------------------------
# hibp_api_url()
# ---------------------------------------------------------------------------

class TestHibpApiUrl:
    def test_default(self, monkeypatch):
        monkeypatch.delenv("YASHIGANI_HIBP_API_URL", raising=False)
        assert hibp_api_url() == _HIBP_DEFAULT_API_URL

    def test_override(self, monkeypatch):
        monkeypatch.setenv("YASHIGANI_HIBP_API_URL", "http://hibp-mirror.internal/range/")
        assert hibp_api_url() == "http://hibp-mirror.internal/range/"


# ---------------------------------------------------------------------------
# SHA-1 prefix/suffix parsing (protocol correctness)
# ---------------------------------------------------------------------------

class TestSha1Protocol:
    def test_prefix_is_5_chars(self):
        """HIBP sends first 5 chars of SHA-1 hex digest."""
        prefix, suffix = _sha1_prefix_suffix("password123correcthorsebatterystaple")
        assert len(prefix) == 5

    def test_suffix_is_35_chars(self):
        """HIBP response lines contain the remaining 35 chars of the hex digest."""
        prefix, suffix = _sha1_prefix_suffix("password123correcthorsebatterystaple")
        assert len(suffix) == 35

    def test_prefix_plus_suffix_is_40_chars(self):
        prefix, suffix = _sha1_prefix_suffix("any-password-long-enough-36-chars-here!")
        assert len(prefix + suffix) == 40

    def test_all_uppercase(self):
        prefix, suffix = _sha1_prefix_suffix("correct-horse-battery-staple-plus-extra")
        assert prefix == prefix.upper()
        assert suffix == suffix.upper()


# ---------------------------------------------------------------------------
# check_hibp — breached password
# ---------------------------------------------------------------------------

class TestCheckHibpBreached:
    def test_breached_password_returns_count(self, monkeypatch):
        """Breached password: check_hibp returns the breach count (int > 0)."""
        password = "correct-horse-battery-staple-plus-extra-x"
        count = 12345
        response_text = _make_hibp_response(password, count)

        mock_response = MagicMock()
        mock_response.text = response_text
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.get", return_value=mock_response) as mock_get:
            result = check_hibp(password)

        assert result == count
        # Verify only the prefix was sent (k-anonymity protocol)
        prefix, _ = _sha1_prefix_suffix(password)
        call_url = mock_get.call_args[0][0]
        assert call_url.endswith(prefix)
        assert len(call_url.split("/")[-1]) == 5

    def test_full_password_not_in_request_url(self, monkeypatch):
        """The full password must never appear in the HIBP API request URL."""
        password = "hunter2-but-longer-to-meet-36-chars!!"
        response_text = _make_hibp_response(password, 999)

        mock_response = MagicMock()
        mock_response.text = response_text
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.get", return_value=mock_response) as mock_get:
            check_hibp(password)

        call_url = mock_get.call_args[0][0]
        assert password not in call_url
        # Full 40-char hash must not appear in URL either
        full_hash = hashlib.sha1(password.encode(), usedforsecurity=False).hexdigest().upper()  # noqa: S324
        assert full_hash not in call_url


# ---------------------------------------------------------------------------
# check_hibp — clean password
# ---------------------------------------------------------------------------

class TestCheckHibpClean:
    def test_unique_password_returns_none(self, monkeypatch):
        """Unique password not in response: check_hibp returns None."""
        # Response contains entries but NOT our suffix
        password = "unique-password-not-in-any-breach-data!"
        # nosem: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1 -- test only
        sha1 = hashlib.sha1(password.encode(), usedforsecurity=False).hexdigest().upper()  # noqa: S324
        our_suffix = sha1[5:]

        # Build a response with entries that definitely don't match
        other_lines = "\n".join([
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:100",
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:200",
        ])
        assert our_suffix not in other_lines

        mock_response = MagicMock()
        mock_response.text = other_lines
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.get", return_value=mock_response):
            result = check_hibp(password)

        assert result is None


# ---------------------------------------------------------------------------
# check_hibp — API unreachable (fail-open)
# ---------------------------------------------------------------------------

class TestCheckHibpApiFailure:
    def test_network_error_returns_none(self, monkeypatch, caplog):
        """API unreachable: check_hibp returns None (fail-open), logs warning."""
        import httpx

        with caplog.at_level(logging.WARNING, logger="yashigani.auth.password"):
            with patch("httpx.get", side_effect=httpx.ConnectError("refused")):
                result = check_hibp("any-password-36-chars-long-enough!!")

        assert result is None
        assert any("HIBP API unreachable" in rec.message for rec in caplog.records)

    def test_timeout_returns_none(self, monkeypatch, caplog):
        """API timeout: check_hibp returns None (fail-open), logs warning."""
        import httpx

        with caplog.at_level(logging.WARNING, logger="yashigani.auth.password"):
            with patch("httpx.get", side_effect=httpx.TimeoutException("timeout")):
                result = check_hibp("any-password-36-chars-long-enough!!")

        assert result is None
        assert any("HIBP API unreachable" in rec.message for rec in caplog.records)

    def test_5xx_returns_none(self, monkeypatch, caplog):
        """HTTP 5xx from API: check_hibp returns None (fail-open), logs warning."""
        import httpx

        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Server Error", request=MagicMock(), response=MagicMock()
        )

        with caplog.at_level(logging.WARNING, logger="yashigani.auth.password"):
            with patch("httpx.get", return_value=mock_response):
                result = check_hibp("any-password-36-chars-long-enough!!")

        assert result is None
        assert any("HIBP API unreachable" in rec.message for rec in caplog.records)

    def test_api_failure_increments_metric(self, monkeypatch):
        """API failure must call _increment_hibp_unavailable (metric pathway)."""
        import httpx
        from yashigani.auth import password as pw_module

        calls = []
        original = pw_module._increment_hibp_unavailable

        def capture_increment():
            calls.append(1)
            original()

        pw_module._increment_hibp_unavailable = capture_increment
        try:
            with patch("httpx.get", side_effect=httpx.ConnectError("refused")):
                check_hibp("any-password-36-chars-long-enough!!")
        finally:
            pw_module._increment_hibp_unavailable = original

        assert len(calls) == 1

    def test_api_failure_warning_not_debug(self, monkeypatch, caplog):
        """API failure must log at WARNING level, not DEBUG (brief requirement)."""
        import httpx

        with caplog.at_level(logging.DEBUG, logger="yashigani.auth.password"):
            with patch("httpx.get", side_effect=httpx.ConnectError("refused")):
                check_hibp("any-password-36-chars-long-enough!!")

        warning_records = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warning_records) >= 1
        assert any("HIBP API unreachable" in r.message for r in warning_records)


# ---------------------------------------------------------------------------
# check_hibp — custom API URL (YASHIGANI_HIBP_API_URL)
# ---------------------------------------------------------------------------

class TestCheckHibpApiUrlOverride:
    def test_custom_url_used_in_request(self, monkeypatch):
        """YASHIGANI_HIBP_API_URL override must be used in the API request."""
        custom_base = "http://hibp-mirror.internal/range/"
        monkeypatch.setenv("YASHIGANI_HIBP_API_URL", custom_base)
        password = "correct-horse-battery-staple-plus-xyz!!"

        mock_response = MagicMock()
        mock_response.text = ""
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.get", return_value=mock_response) as mock_get:
            check_hibp(password)

        call_url = mock_get.call_args[0][0]
        assert call_url.startswith(custom_base)

    def test_default_url_used_when_not_set(self, monkeypatch):
        """Default HIBP URL is used when YASHIGANI_HIBP_API_URL is not set."""
        monkeypatch.delenv("YASHIGANI_HIBP_API_URL", raising=False)
        password = "correct-horse-battery-staple-plus-xyz!!"

        mock_response = MagicMock()
        mock_response.text = ""
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.get", return_value=mock_response) as mock_get:
            check_hibp(password)

        call_url = mock_get.call_args[0][0]
        assert call_url.startswith(_HIBP_DEFAULT_API_URL)


# ---------------------------------------------------------------------------
# validate_password_not_breached
# ---------------------------------------------------------------------------

class TestValidatePasswordNotBreached:
    def test_breached_raises_by_default(self, monkeypatch):
        """Breached password: PasswordBreachedError raised when raise_on_breach=True."""
        password = "correct-horse-battery-staple-plus-extra-x"

        with patch(
            "yashigani.auth.password.check_hibp", return_value=9999
        ):
            with pytest.raises(PasswordBreachedError):
                validate_password_not_breached(password)

    def test_breached_returns_count_when_no_raise(self, monkeypatch):
        """Breached password: count returned when raise_on_breach=False."""
        with patch("yashigani.auth.password.check_hibp", return_value=42):
            result = validate_password_not_breached(
                "any-password-36-chars-long-enough!!",
                raise_on_breach=False,
            )
        assert result == 42

    def test_clean_returns_none(self, monkeypatch):
        """Unique password: None returned."""
        with patch("yashigani.auth.password.check_hibp", return_value=None):
            result = validate_password_not_breached("any-password-36-chars-long-enough!!")
        assert result is None

    def test_disabled_skips_check(self, monkeypatch):
        """YASHIGANI_HIBP_CHECK_ENABLED=false must skip the check entirely."""
        monkeypatch.setenv("YASHIGANI_HIBP_CHECK_ENABLED", "false")
        with patch("yashigani.auth.password.check_hibp", return_value=99999) as mock_check:
            result = validate_password_not_breached("any-password-36-chars-long-enough!!")
        mock_check.assert_not_called()
        assert result is None


# ---------------------------------------------------------------------------
# PasswordBreachedError
# ---------------------------------------------------------------------------

class TestPasswordBreachedError:
    def test_is_value_error(self):
        """PasswordBreachedError must be a ValueError subclass."""
        err = PasswordBreachedError(100)
        assert isinstance(err, ValueError)

    def test_error_message_matches_spec(self):
        """Error message must match the brief specification exactly."""
        err = PasswordBreachedError(100)
        assert str(err) == "This password has appeared in known data breaches; choose another."

    def test_breach_count_stored(self):
        err = PasswordBreachedError(42)
        assert err.breach_count == 42


# ---------------------------------------------------------------------------
# hash_password — HIBP integration
# ---------------------------------------------------------------------------

class TestHashPasswordHibpIntegration:
    def test_hibp_check_called_by_default(self, monkeypatch):
        """hash_password must call validate_password_not_breached when check_breach=True."""
        password = "A" * 36

        with patch(
            "yashigani.auth.password.validate_password_not_breached"
        ) as mock_validate:
            # Ensure HIBP is enabled
            monkeypatch.setenv("YASHIGANI_HIBP_CHECK_ENABLED", "true")
            hash_password(password, check_breach=True)

        mock_validate.assert_called_once_with(password)

    def test_hibp_check_skipped_when_check_breach_false(self, monkeypatch):
        """hash_password must NOT call validate_password_not_breached when check_breach=False."""
        password = "A" * 36
        monkeypatch.setenv("YASHIGANI_HIBP_CHECK_ENABLED", "true")

        with patch(
            "yashigani.auth.password.validate_password_not_breached"
        ) as mock_validate:
            hash_password(password, check_breach=False)

        mock_validate.assert_not_called()

    def test_hibp_check_skipped_when_env_disabled(self, monkeypatch):
        """hash_password must NOT call check_hibp when YASHIGANI_HIBP_CHECK_ENABLED=false."""
        password = "A" * 36
        monkeypatch.setenv("YASHIGANI_HIBP_CHECK_ENABLED", "false")

        with patch("yashigani.auth.password.check_hibp") as mock_check:
            hash_password(password, check_breach=True)

        mock_check.assert_not_called()

    def test_breached_password_raises_from_hash_password(self, monkeypatch):
        """hash_password must propagate PasswordBreachedError for breached passwords."""
        password = "correct-horse-battery-staple-plus-xyz!!!"
        monkeypatch.setenv("YASHIGANI_HIBP_CHECK_ENABLED", "true")

        with patch("yashigani.auth.password.check_hibp", return_value=12345):
            with pytest.raises(PasswordBreachedError):
                hash_password(password, check_breach=True)

    def test_api_failure_does_not_block_hash(self, monkeypatch):
        """API failure (fail-open) must not block hash_password from completing."""
        import httpx
        password = "A" * 36
        monkeypatch.setenv("YASHIGANI_HIBP_CHECK_ENABLED", "true")

        with patch("httpx.get", side_effect=httpx.ConnectError("refused")):
            result = hash_password(password, check_breach=True)

        assert result.startswith("$argon2")


# ---------------------------------------------------------------------------
# urllib fallback path
# ---------------------------------------------------------------------------

class TestCheckHibpUrllib:
    def test_urllib_fallback_breached(self, monkeypatch):
        """urllib fallback must correctly identify a breached password."""
        import urllib.request
        from io import BytesIO
        password = "correct-horse-battery-staple-plus-extra-x"
        count = 777
        response_text = _make_hibp_response(password, count).encode()

        mock_resp = MagicMock()
        mock_resp.read.return_value = response_text
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = _check_hibp_urllib(password)

        assert result == count

    def test_urllib_fallback_clean(self, monkeypatch):
        """urllib fallback returns None for a unique password."""
        import urllib.request
        password = "unique-password-not-in-any-breach-data!!x"
        # nosem: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1 -- test only
        sha1 = hashlib.sha1(password.encode(), usedforsecurity=False).hexdigest().upper()  # noqa: S324
        our_suffix = sha1[5:]

        other_lines = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:100".encode()
        assert our_suffix.encode() not in other_lines

        mock_resp = MagicMock()
        mock_resp.read.return_value = other_lines
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = _check_hibp_urllib(password)

        assert result is None

    def test_urllib_fallback_url_error_returns_none(self, caplog):
        """urllib fallback returns None on URLError (fail-open) and logs warning."""
        import urllib.error
        password = "any-password-36-chars-long-enough!!"

        with caplog.at_level(logging.WARNING, logger="yashigani.auth.password"):
            with patch(
                "urllib.request.urlopen",
                side_effect=urllib.error.URLError("connection refused"),
            ):
                result = _check_hibp_urllib(password)

        assert result is None
        assert any("HIBP API unreachable" in r.message for r in caplog.records)
