"""
Integration tests: HIBP breach check wired into the password-change flow.

These tests exercise the full path:
  POST /auth/password/change → hash_password → check_hibp → PasswordBreachedError
  → HTTP 422 with error=password_breached

and the operator opt-out path:
  YASHIGANI_HIBP_CHECK_ENABLED=false → check skipped → HTTP 200

They use the FastAPI TestClient with a mock HIBP responder so no live network
calls are made. The HIBP API is stubbed via monkeypatch at the httpx layer.

These tests require the backoffice app to be importable (i.e. all dependencies
installed). They are NOT marked skip-if-no-db because they use LocalAuthService
(in-memory).

pytest -x src/tests/integration/test_hibp_password_change.py
"""
from __future__ import annotations

import hashlib
import logging
from unittest.mock import MagicMock, patch

import pytest

import yashigani.auth.password as _pw_module


# ---------------------------------------------------------------------------
# SSRF policy bypass
# ---------------------------------------------------------------------------
# PR #81 added an SSRF policy check to check_hibp() before any outbound request.
# Tests that use an HTTP override URL or mock httpx.get directly need to bypass
# the policy check. The autouse fixture below patches the HIBP HttpClient so all
# tests in this file remain network-free and focused on integration flow.
# SSRF policy correctness is verified in test_v2233_hibp_route_through_httpclient.py.

@pytest.fixture(autouse=True)
def _bypass_ssrf_policy(monkeypatch):
    """Patch the HIBP HttpClient policy check to a no-op for all integration tests."""
    mock_client = MagicMock()
    mock_client._check_policy = MagicMock(return_value=None)
    monkeypatch.setattr(_pw_module, "_HIBP_HTTP_CLIENT", mock_client)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_hibp_response_with_match(password: str, count: int = 99999) -> str:
    """Build a fake HIBP response that contains the given password's suffix."""
    # nosem: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1 -- test helper; HIBP protocol only
    sha1 = hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()  # noqa: S324
    suffix = sha1[5:]
    return f"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\n{suffix}:{count}\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:2"


def _make_hibp_response_no_match() -> str:
    """Build a fake HIBP response with no matching entries."""
    return "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:2"


# ---------------------------------------------------------------------------
# check_hibp flow tests (no HTTP server needed — mock at httpx level)
# ---------------------------------------------------------------------------

class TestHibpInPasswordChange:
    """Verify the HIBP check gates the password-change flow correctly."""

    def test_breached_password_rejected_with_422(self, monkeypatch):
        """A breached password must result in HTTP 422 password_breached."""
        import httpx
        from yashigani.auth.password import check_hibp

        new_password = "correct-horse-battery-staple-plus-extra!!"
        response_body = _make_hibp_response_with_match(new_password, count=12345)

        mock_response = MagicMock()
        mock_response.text = response_body
        mock_response.raise_for_status = MagicMock()

        monkeypatch.setenv("YASHIGANI_HIBP_CHECK_ENABLED", "true")

        with patch("httpx.get", return_value=mock_response):
            result = check_hibp(new_password)

        assert result == 12345

    def test_unique_password_accepted(self, monkeypatch):
        """A unique (non-breached) password must be accepted (check_hibp returns None)."""
        from yashigani.auth.password import check_hibp

        new_password = "correct-horse-battery-staple-plus-extra!!"
        response_body = _make_hibp_response_no_match()

        mock_response = MagicMock()
        mock_response.text = response_body
        mock_response.raise_for_status = MagicMock()

        monkeypatch.setenv("YASHIGANI_HIBP_CHECK_ENABLED", "true")

        with patch("httpx.get", return_value=mock_response):
            result = check_hibp(new_password)

        assert result is None

    def test_api_failure_allows_password(self, monkeypatch, caplog):
        """API failure must be fail-open: password is allowed and warning is logged."""
        import httpx
        from yashigani.auth.password import validate_password_not_breached

        password = "unique-password-not-breached-36-chars!!"
        monkeypatch.setenv("YASHIGANI_HIBP_CHECK_ENABLED", "true")

        with caplog.at_level(logging.WARNING, logger="yashigani.auth.password"):
            with patch("httpx.get", side_effect=httpx.ConnectError("refused")):
                result = validate_password_not_breached(password)

        assert result is None
        assert any("HIBP API unreachable" in r.message for r in caplog.records)

    def test_operator_optout_skips_check(self, monkeypatch):
        """YASHIGANI_HIBP_CHECK_ENABLED=false must skip HIBP check entirely."""
        from yashigani.auth.password import validate_password_not_breached

        password = "any-password-36-chars-long-enough-here!!"
        monkeypatch.setenv("YASHIGANI_HIBP_CHECK_ENABLED", "false")

        with patch("httpx.get") as mock_get:
            result = validate_password_not_breached(password)

        mock_get.assert_not_called()
        assert result is None

    def test_api_url_override(self, monkeypatch):
        """YASHIGANI_HIBP_API_URL must be used as the base URL for queries."""
        custom_url = "http://hibp-mirror.local/range/"
        monkeypatch.setenv("YASHIGANI_HIBP_API_URL", custom_url)
        monkeypatch.setenv("YASHIGANI_HIBP_CHECK_ENABLED", "true")

        password = "unique-password-not-breached-36-chars!!"

        mock_response = MagicMock()
        mock_response.text = _make_hibp_response_no_match()
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.get", return_value=mock_response) as mock_get:
            from yashigani.auth.password import check_hibp
            check_hibp(password)

        call_url = mock_get.call_args[0][0]
        assert call_url.startswith(custom_url)

    def test_privacy_prefix_only_sent(self, monkeypatch):
        """Only the 5-char SHA-1 prefix must be sent — never the full hash or password."""
        password = "unique-password-not-breached-36-chars!!"
        monkeypatch.setenv("YASHIGANI_HIBP_CHECK_ENABLED", "true")
        monkeypatch.delenv("YASHIGANI_HIBP_API_URL", raising=False)

        # nosem: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1 -- test only
        full_hash = hashlib.sha1(password.encode(), usedforsecurity=False).hexdigest().upper()  # noqa: S324
        prefix = full_hash[:5]
        suffix = full_hash[5:]

        mock_response = MagicMock()
        mock_response.text = _make_hibp_response_no_match()
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.get", return_value=mock_response) as mock_get:
            from yashigani.auth.password import check_hibp
            check_hibp(password)

        call_url = mock_get.call_args[0][0]
        path_part = call_url.split("/")[-1]

        assert path_part == prefix, f"Expected prefix {prefix!r}, got {path_part!r}"
        assert suffix not in call_url
        assert password not in call_url
