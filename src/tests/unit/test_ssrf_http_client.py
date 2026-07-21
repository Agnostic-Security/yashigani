"""Tests for yashigani.net.HttpClient SSRF guardrails."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from yashigani.net import HttpClient, BlockedByPolicy


def test_blocks_plain_http_by_default():
    c = HttpClient(allow_http=False)
    with pytest.raises(BlockedByPolicy, match="Plain HTTP disallowed"):
        c._check_policy("http://example.com/")


def test_allows_plain_http_when_opted_in():
    c = HttpClient(allow_http=True)
    # Should not raise (host is public, no allowlist configured).
    c._check_policy("http://example.com/")


def test_blocks_cloud_metadata_endpoint():
    c = HttpClient(allow_http=True)
    with pytest.raises(BlockedByPolicy, match="private / loopback / metadata"):
        c._check_policy("http://169.254.169.254/latest/meta-data")


def test_blocks_google_metadata_hostname():
    c = HttpClient(allow_http=True)
    with pytest.raises(BlockedByPolicy):
        c._check_policy("http://metadata.google.internal/")


def test_blocks_loopback():
    c = HttpClient(allow_http=True)
    with pytest.raises(BlockedByPolicy):
        c._check_policy("http://127.0.0.1/")


def test_blocks_private_rfc1918():
    c = HttpClient(allow_http=True)
    with pytest.raises(BlockedByPolicy):
        c._check_policy("http://10.0.0.5/")
    with pytest.raises(BlockedByPolicy):
        c._check_policy("http://192.168.1.1/")


def test_allowlist_enforced():
    c = HttpClient(allowlist=["api.pwnedpasswords.com"])
    # Allowed host passes.
    c._check_policy("https://api.pwnedpasswords.com/range/ABCDE")
    # Non-allowlisted host fails.
    with pytest.raises(BlockedByPolicy, match="not in YASHIGANI_OUTBOUND_ALLOWLIST"):
        c._check_policy("https://evil.example.com/")


def test_suffix_allowlist_entry():
    c = HttpClient(allowlist=[".agnosticsec.com"])
    c._check_policy("https://api.agnosticsec.com/")
    c._check_policy("https://www.agnosticsec.com/")
    with pytest.raises(BlockedByPolicy):
        c._check_policy("https://agnosticsec.com.evil.com/")


def test_blocklist_overrides_allowlist():
    c = HttpClient(allowlist=[".example.com"], blocklist=["bad.example.com"])
    c._check_policy("https://good.example.com/")
    with pytest.raises(BlockedByPolicy, match="(?i)blocklist"):
        c._check_policy("https://bad.example.com/")


def test_blocks_non_http_scheme():
    c = HttpClient()
    with pytest.raises(BlockedByPolicy, match="Scheme"):
        c._check_policy("file:///etc/passwd")
    with pytest.raises(BlockedByPolicy, match="Scheme"):
        c._check_policy("gopher://example.com/")


def test_missing_hostname():
    c = HttpClient()
    with pytest.raises(BlockedByPolicy, match="lacks a hostname"):
        c._check_policy("https:///")


# ---------------------------------------------------------------------------
# FINDING N1 (v4.1.2 onboarding e2e) — internal-CA trust for ring-fenced
# HTTPS MCP upstreams reached via the direct /mcp/* proxy path.
# ---------------------------------------------------------------------------


def _fake_internal_client(response: MagicMock) -> MagicMock:
    """Build a mock that behaves like ``internal_httpx_client()``'s return
    value: an async-context-manager whose ``.request()`` is an AsyncMock."""
    client = MagicMock()
    client.request = AsyncMock(return_value=response)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    return client


async def test_bypass_mode_https_uses_internal_ca_client():
    """A ring-fenced MCP upstream (bypass_private_for_allowlisted=True,
    https://) must go through pki.client.internal_httpx_client() — NOT a bare
    httpx.AsyncClient() with the default system trust store (FINDING N1)."""
    c = HttpClient(
        allowlist=["caddy"],
        bypass_private_for_allowlisted=True,
        allow_http=True,
    )
    fake_response = MagicMock()
    fake_client = _fake_internal_client(fake_response)

    with patch(
        "yashigani.pki.client.internal_httpx_client", return_value=fake_client
    ) as mocked_internal, patch(
        "yashigani.net.http_client.httpx.AsyncClient"
    ) as mocked_plain:
        result = await c.post(
            "https://caddy:9443/mcp/acme/demo-mcp", content=b"{}"
        )

    assert result is fake_response
    mocked_internal.assert_called_once()
    # The un-trusting default-system-CA client must NEVER be used for this
    # internal-CA-signed ring-fenced upstream.
    mocked_plain.assert_not_called()
    # No call site disables certificate verification.
    for call in mocked_internal.call_args_list:
        assert call.kwargs.get("verify") is not False
        assert "verify" not in call.kwargs  # internal_httpx_client owns verify=


async def test_standard_mode_https_keeps_system_ca():
    """A genuinely-external https:// call (bypass_private_for_allowlisted
    unset — e.g. the HIBP password check) must keep using the default system
    CA trust store and must NOT be routed through internal_httpx_client()."""
    c = HttpClient(allowlist=["api.pwnedpasswords.com"])

    class _FakeResp:
        pass

    fake_response = _FakeResp()

    class _FakeAsyncClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def request(self, method, url, **kwargs):
            assert kwargs.get("verify") is not False
            return fake_response

    with patch(
        "yashigani.net.http_client.httpx.AsyncClient", return_value=_FakeAsyncClient()
    ) as mocked_plain, patch(
        "yashigani.pki.client.internal_httpx_client"
    ) as mocked_internal:
        result = await c.get("https://api.pwnedpasswords.com/range/ABCDE")

    assert result is fake_response
    mocked_plain.assert_called_once()
    mocked_internal.assert_not_called()


async def test_bypass_mode_http_does_not_use_internal_ca():
    """Docker-bridge plain-HTTP MCP upstreams (no TLS at all) are unaffected
    by the internal-CA switch — only bypass-mode https:// routes there."""
    c = HttpClient(
        allowlist=["filesystem-mcp"],
        bypass_private_for_allowlisted=True,
        allow_http=True,
    )

    class _FakeAsyncClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def request(self, method, url, **kwargs):
            return "ok"

    with patch(
        "yashigani.net.http_client.httpx.AsyncClient", return_value=_FakeAsyncClient()
    ) as mocked_plain, patch(
        "yashigani.pki.client.internal_httpx_client"
    ) as mocked_internal:
        result = await c.post("http://filesystem-mcp:8000/mcp", content=b"{}")

    assert result == "ok"
    mocked_plain.assert_called_once()
    mocked_internal.assert_not_called()


async def test_bypass_mode_https_ssrf_gate_still_enforced():
    """The CA-trust fix must not weaken the existing SSRF allowlist gate:
    an https:// host NOT in the allowlist is still blocked before any
    client (internal or system) is ever constructed."""
    c = HttpClient(
        allowlist=["caddy"],
        bypass_private_for_allowlisted=True,
    )
    with patch(
        "yashigani.net.http_client.httpx.AsyncClient"
    ) as mocked_plain, patch(
        "yashigani.pki.client.internal_httpx_client"
    ) as mocked_internal:
        with pytest.raises(BlockedByPolicy):
            await c.post("https://evil.example.com/mcp", content=b"{}")

    mocked_plain.assert_not_called()
    mocked_internal.assert_not_called()
