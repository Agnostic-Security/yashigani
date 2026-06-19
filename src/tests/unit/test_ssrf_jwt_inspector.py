"""
Unit tests for JWT inspector SSRF guard — LAURA-2255-010 (CWE-918).

Verifies that _fetch_jwks() calls HttpClient._check_policy() BEFORE any
network access and that dangerous URLs are rejected fail-closed, with no
outbound HTTP ever attempted.

Guards tested:
  J1 — IMDS / link-local (169.254.169.254) rejected
  J2 — loopback (127.0.0.1) rejected
  J3 — RFC-1918 private (192.168.1.1) rejected
  J4 — plain HTTP rejected (https-only)
  J5 — valid https URL with no allowlist → policy passes → network attempted
         (network call itself is mocked to avoid real DNS)
  J6 — inspect() with blocked jwks_url → returns error="jwks_ssrf_blocked",
         never reaches urllib
"""
from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from yashigani.net.http_client import BlockedByPolicy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_inspector(redis=None):
    """Return a JWTInspector without importing the full gateway stack."""
    from yashigani.gateway.jwt_inspector import JWTInspector
    return JWTInspector(redis_client=redis)


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ---------------------------------------------------------------------------
# J1–J4: policy rejects dangerous URLs before any network call
# ---------------------------------------------------------------------------

class TestFetchJwksPolicyRejection:
    """_fetch_jwks() must raise BlockedByPolicy and never call httpx.get()."""

    def _call(self, url: str):
        inspector = _make_inspector()
        # Patch HttpClient.get so any network attempt fails visibly.
        with patch("yashigani.net.http_client.httpx.AsyncClient") as mock_client_cls:
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
            with pytest.raises(BlockedByPolicy):
                _run(inspector._fetch_jwks(url))
        # If we reach here, BlockedByPolicy was raised — network was never called.
        mock_client_cls.assert_not_called()

    def test_imds_link_local_rejected(self):
        """J1: 169.254.169.254 (cloud IMDS) must raise BlockedByPolicy."""
        self._call("https://169.254.169.254/latest/meta-data/iam/info")

    def test_loopback_rejected(self):
        """J2: 127.0.0.1 must raise BlockedByPolicy."""
        self._call("https://127.0.0.1/.well-known/jwks.json")

    def test_private_ip_rejected(self):
        """J3: RFC-1918 address (192.168.1.1) must raise BlockedByPolicy."""
        self._call("https://192.168.1.1/.well-known/jwks.json")

    def test_http_scheme_rejected(self):
        """J4: plain http:// must raise BlockedByPolicy (https-only)."""
        self._call("http://example.com/.well-known/jwks.json")

    def test_loopback_localhost_hostname_not_blocked_by_check_policy(self):
        """J2b: 'localhost' as a hostname passes HttpClient._check_policy().

        HttpClient._check_policy() only blocks *literal* IP addresses; it does
        not resolve hostnames (DNS-resolution-based blocking requires the
        assert_safe_outbound_url guard, used at URL-storage time, not at fetch
        time).  'localhost' as a hostname therefore passes _check_policy and
        httpx will attempt a real connection — which fails with a network error
        in tests, not a BlockedByPolicy.

        The important invariant is that LITERAL loopback IPs (127.0.0.1) ARE
        hard-blocked, covering the primary SSRF vector where an attacker
        supplies an IP literal directly.  Hostname-based SSRF via 'localhost'
        is a secondary path addressed at URL-storage time via
        assert_safe_outbound_url (which calls socket.getaddrinfo).

        This test documents the behaviour explicitly so future reviewers
        understand the scope of each guard layer.
        """
        # Should NOT raise BlockedByPolicy — _check_policy doesn't resolve DNS.
        inspector = _make_inspector()
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock(side_effect=Exception("network error"))
        with patch(
            "yashigani.gateway.jwt_inspector.HttpClient.get",
            new=AsyncMock(return_value=mock_response),
        ):
            # Will raise Exception from raise_for_status, not BlockedByPolicy.
            with pytest.raises(Exception) as exc_info:
                _run(inspector._fetch_jwks("https://localhost/.well-known/jwks.json"))
            assert not isinstance(exc_info.value, BlockedByPolicy), (
                "localhost hostname should not be blocked by HttpClient._check_policy; "
                "that guard layer covers literal IPs only"
            )

    def test_10_net_private_rejected(self):
        """J3b: 10.0.0.1 (RFC-1918 class A) must raise BlockedByPolicy."""
        self._call("https://10.0.0.1/.well-known/jwks.json")

    def test_172_16_private_rejected(self):
        """J3c: 172.16.0.1 (RFC-1918 class B) must raise BlockedByPolicy."""
        self._call("https://172.16.0.1/.well-known/jwks.json")


# ---------------------------------------------------------------------------
# J5: valid public https URL — policy passes, network is attempted
# ---------------------------------------------------------------------------

class TestFetchJwksPolicyPass:
    """Valid https public URLs pass the guard and proceed to network."""

    def test_public_https_url_passes_policy(self):
        """J5: https://accounts.google.com/... should pass _check_policy."""
        inspector = _make_inspector()

        # Fake HTTP response with a minimal JWKS payload.
        fake_jwks = {"keys": [{"kty": "RSA", "kid": "k1", "n": "abc", "e": "AQAB", "use": "sig"}]}
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json = MagicMock(return_value=fake_jwks)

        with patch(
            "yashigani.gateway.jwt_inspector.HttpClient.get",
            new=AsyncMock(return_value=mock_response),
        ):
            # PyJWKSet.from_dict may raise on a minimal fake key — that's fine;
            # we only care that _check_policy didn't raise BlockedByPolicy.
            try:
                _run(inspector._fetch_jwks("https://accounts.google.com/.well-known/jwks.json"))
            except BlockedByPolicy as exc:
                pytest.fail(f"BlockedByPolicy raised for a valid public URL: {exc}")
            except Exception:
                pass  # PyJWKSet parsing failure or network stub — acceptable


# ---------------------------------------------------------------------------
# J6: inspect() with attacker-controlled jwks_url → jwks_ssrf_blocked
# ---------------------------------------------------------------------------

class TestInspectWithSsrfJwksUrl:
    """inspect() must return error='jwks_ssrf_blocked' when jwks_url is dangerous."""

    def _make_fake_token(self) -> str:
        """Build a structurally-valid RS256 JWT header+payload (signature fake)."""
        import base64
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "RS256", "kid": "k1"}).encode()
        ).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(
            json.dumps({"sub": "user1", "iss": "https://idp.example.com"}).encode()
        ).rstrip(b"=").decode()
        # Signature doesn't matter — we fail at JWKS fetch before verifying.
        return f"{header}.{payload}.fakesig"

    def _make_config(self, jwks_url: str):
        from yashigani.gateway.jwt_inspector import JWTConfig
        return JWTConfig(
            jwks_url=jwks_url,
            issuer="",
            audience="",
            fail_closed=True,
        )

    def _run_inspect_with_url(self, jwks_url: str):
        inspector = _make_inspector()
        token = self._make_fake_token()
        # Bypass _resolve_config — inject config directly.
        with patch.object(inspector, "_resolve_config", new=AsyncMock(
            return_value=self._make_config(jwks_url)
        )):
            return _run(inspector.inspect(token))

    def test_imds_jwks_url_returns_ssrf_blocked(self):
        """J6a: jwks_url=169.254.169.254 → error='jwks_ssrf_blocked'."""
        result = self._run_inspect_with_url("https://169.254.169.254/jwks.json")
        assert not result.valid
        assert result.error == "jwks_ssrf_blocked"

    def test_loopback_jwks_url_returns_ssrf_blocked(self):
        """J6b: jwks_url=127.0.0.1 → error='jwks_ssrf_blocked'."""
        result = self._run_inspect_with_url("https://127.0.0.1/jwks.json")
        assert not result.valid
        assert result.error == "jwks_ssrf_blocked"

    def test_private_ip_jwks_url_returns_ssrf_blocked(self):
        """J6c: jwks_url=192.168.1.1 → error='jwks_ssrf_blocked'."""
        result = self._run_inspect_with_url("https://192.168.1.1/jwks.json")
        assert not result.valid
        assert result.error == "jwks_ssrf_blocked"

    def test_http_jwks_url_returns_ssrf_blocked(self):
        """J6d: plain http:// jwks_url → error='jwks_ssrf_blocked'."""
        result = self._run_inspect_with_url("http://idp.example.com/jwks.json")
        assert not result.valid
        assert result.error == "jwks_ssrf_blocked"

    def test_ssrf_blocked_is_always_fail_closed(self):
        """J6e: even when fail_closed=False, ssrf_blocked must return valid=False."""
        inspector = _make_inspector()
        token = self._make_fake_token()
        from yashigani.gateway.jwt_inspector import JWTConfig
        config = JWTConfig(
            jwks_url="https://169.254.169.254/jwks.json",
            issuer="",
            audience="",
            fail_closed=False,  # fail-open config — SSRF block must still win
        )
        with patch.object(inspector, "_resolve_config", new=AsyncMock(return_value=config)):
            result = _run(inspector.inspect(token))
        assert not result.valid, "SSRF block must be fail-closed even when fail_closed=False"
        assert result.error == "jwks_ssrf_blocked"
