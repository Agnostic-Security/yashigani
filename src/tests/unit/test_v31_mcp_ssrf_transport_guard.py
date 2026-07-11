"""
3.1 Phase 5 — MCP transport SSRF guard tests.

Verifies that ``McpHttpTransport.forward()`` is routed through the
``net.HttpClient`` SSRF guard and that:

  A. ``HttpClient`` bypass_private_for_allowlisted mode — unit tests
       A1. IMDS (169.254.169.254) blocked even when in allowlist
       A2. Link-local (169.254.x.x) blocked
       A3. Loopback (127.0.0.1) blocked
       A4. RFC-1918 (10.0.0.5) allowed when in allowlist
       A5. RFC-1918 (172.17.0.2) allowed when in allowlist
       A6. Unregistered public host blocked when allowlist is present
       A7. Empty allowlist → fail-closed (every host denied)
       A8. Allowlist is mandatory in bypass mode (no env fallback)

  B. ``_extract_allowlist_from_urls`` — hostname extraction helper
       B1. Extracts hostname from http URL
       B2. Extracts hostname from https URL with port
       B3. Handles malformed URL gracefully (skips)
       B4. Deduplicates hostnames
       B5. Private-IP literal extracted correctly

  C. ``McpHttpTransport`` end-to-end SSRF guard integration
       C1. IMDS upstream URL → forward() raises HttpTransportError
       C2. Loopback upstream URL → forward() raises HttpTransportError
       C3. Unregistered host upstream URL → forward() raises HttpTransportError
       C4. Registered Docker-service upstream → forward() reaches the server
           (mocked HTTP response to avoid real network dependency)
       C5. Redirect to non-allowlisted host → blocked (follow_redirects=False)
       C6. trusted_upstream_urls explicit list narrows the allowlist
       C7. Injected http_client (test mock) bypasses guard (backward compat)

  D. ``_is_hard_block`` — unconditional block classification
       D1. Named IMDS endpoints blocked
       D2. Loopback IPs blocked
       D3. Link-local IPs blocked
       D4. RFC-1918 IPs not blocked (bypassable)
       D5. Public IPs not blocked
       D6. Hostname (not literal IP) not blocked by hard-block

v3.1 / Phase 5 SSRF guard.
"""
from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# A. HttpClient bypass_private_for_allowlisted mode
# ---------------------------------------------------------------------------

class TestHttpClientBypassMode:
    """Unit tests for HttpClient._check_policy in MCP upstream guard mode."""

    def _client(self, allowlist: list[str] | None = None):
        from yashigani.net.http_client import HttpClient
        return HttpClient(
            allowlist=allowlist,
            allow_http=True,
            bypass_private_for_allowlisted=True,
        )

    def test_A1_imds_blocked_unconditionally(self):
        """169.254.169.254 is blocked even if mistakenly put in the allowlist."""
        from yashigani.net.http_client import BlockedByPolicy
        # Even if an operator tries to allowlist IMDS, the hard-block fires first.
        c = self._client(allowlist=["169.254.169.254"])
        with pytest.raises(BlockedByPolicy, match="IMDS / link-local / loopback"):
            c._check_policy("http://169.254.169.254/latest/meta-data")

    def test_A2_link_local_blocked_unconditionally(self):
        """Any 169.254.x.x address is hard-blocked (link-local range)."""
        from yashigani.net.http_client import BlockedByPolicy
        c = self._client(allowlist=["169.254.0.1", "169.254.100.200"])
        with pytest.raises(BlockedByPolicy, match="IMDS / link-local / loopback"):
            c._check_policy("http://169.254.0.1/")
        with pytest.raises(BlockedByPolicy, match="IMDS / link-local / loopback"):
            c._check_policy("http://169.254.100.200/")

    def test_A3_loopback_blocked_unconditionally(self):
        """Loopback (127.0.0.1, ::1) blocked unconditionally."""
        from yashigani.net.http_client import BlockedByPolicy
        c = self._client(allowlist=["127.0.0.1"])
        with pytest.raises(BlockedByPolicy, match="IMDS / link-local / loopback"):
            c._check_policy("http://127.0.0.1:8000/mcp")

    def test_A4_rfc1918_allowed_when_allowlisted_10(self):
        """10.x.x.x passes when in the allowlist (Docker bridge IP)."""
        c = self._client(allowlist=["10.0.0.5"])
        # Should NOT raise — this is a trusted MCP upstream
        c._check_policy("http://10.0.0.5:8000/mcp")

    def test_A5_rfc1918_allowed_when_allowlisted_172(self):
        """172.17.x.x passes when in the allowlist (default Docker bridge)."""
        c = self._client(allowlist=["172.17.0.2"])
        c._check_policy("http://172.17.0.2:8000/mcp")

    def test_A6_unregistered_host_blocked(self):
        """A host not in the allowlist is denied even if it's a public IP."""
        from yashigani.net.http_client import BlockedByPolicy
        c = self._client(allowlist=["filesystem-mcp"])
        with pytest.raises(BlockedByPolicy, match="not in the trusted MCP upstream allowlist"):
            c._check_policy("http://evil.example.com/mcp")

    def test_A7_empty_allowlist_fail_closed(self):
        """bypass mode with an empty allowlist denies every host (fail-closed)."""
        from yashigani.net.http_client import BlockedByPolicy
        c = self._client(allowlist=[])
        with pytest.raises(BlockedByPolicy, match="non-empty trusted upstream allowlist"):
            c._check_policy("http://filesystem-mcp:8000/mcp")

    def test_A8_hostname_in_allowlist_passes(self):
        """Docker service hostname (resolved by Docker DNS) passes when allowlisted."""
        c = self._client(allowlist=["filesystem-mcp"])
        c._check_policy("http://filesystem-mcp:8000/mcp")

    def test_A9_named_imds_host_blocked(self):
        """metadata.google.internal is in _HARD_BLOCK_HOSTS — blocked unconditionally."""
        from yashigani.net.http_client import BlockedByPolicy
        c = self._client(allowlist=["metadata.google.internal"])
        with pytest.raises(BlockedByPolicy):
            c._check_policy("http://metadata.google.internal/")


# ---------------------------------------------------------------------------
# B. _extract_allowlist_from_urls helper
# ---------------------------------------------------------------------------

class TestExtractAllowlistFromUrls:
    """Unit tests for the hostname-extraction helper."""

    def _extract(self, urls: list[str]) -> list[str]:
        from yashigani.mcp._transport_http import _extract_allowlist_from_urls
        return _extract_allowlist_from_urls(urls)

    def test_B1_http_url_extracts_hostname(self):
        assert self._extract(["http://filesystem-mcp:8000"]) == ["filesystem-mcp"]

    def test_B2_https_url_with_port(self):
        assert self._extract(["https://mcp-server.internal:8443"]) == ["mcp-server.internal"]

    def test_B3_malformed_url_skipped(self):
        # urlparse("not-a-url") returns empty hostname — should be skipped
        result = self._extract(["not-a-url", "http://demo-mcp:8000"])
        assert result == ["demo-mcp"]

    def test_B4_deduplication(self):
        result = self._extract([
            "http://filesystem-mcp:8000",
            "http://filesystem-mcp:9000",  # same host, different port
        ])
        assert result == ["filesystem-mcp"]

    def test_B5_private_ip_extracted_correctly(self):
        result = self._extract(["http://10.0.0.5:8000"])
        assert result == ["10.0.0.5"]

    def test_B6_multiple_distinct_hosts(self):
        result = self._extract([
            "http://filesystem-mcp:8000",
            "http://git-mcp:8000",
        ])
        assert result == ["filesystem-mcp", "git-mcp"]


# ---------------------------------------------------------------------------
# C. McpHttpTransport SSRF guard integration
# ---------------------------------------------------------------------------

class TestMcpHttpTransportSsrfGuard:
    """Integration tests for McpHttpTransport end-to-end SSRF guard."""

    async def _forward_to(
        self,
        upstream_url: str,
        trusted_upstream_urls: list[str] | None = None,
        http_client: Any = None,
    ) -> str:
        from yashigani.mcp._transport_http import McpHttpTransport
        kwargs: dict[str, Any] = {"upstream_url": upstream_url}
        if trusted_upstream_urls is not None:
            kwargs["trusted_upstream_urls"] = trusted_upstream_urls
        if http_client is not None:
            kwargs["http_client"] = http_client
        async with McpHttpTransport(**kwargs) as t:
            return await t.forward(
                mcp_request_json='{"jsonrpc":"2.0","method":"tools/call","id":1}',
                gateway_jwt="test-jwt",
            )

    @pytest.mark.asyncio
    async def test_C1_imds_upstream_blocked(self):
        """forward() to IMDS upstream raises HttpTransportError."""
        from yashigani.mcp._transport_http import HttpTransportError
        with pytest.raises(HttpTransportError, match="169.254.169.254"):
            await self._forward_to("http://169.254.169.254")

    @pytest.mark.asyncio
    async def test_C2_loopback_upstream_blocked(self):
        """forward() to loopback upstream raises HttpTransportError."""
        from yashigani.mcp._transport_http import HttpTransportError
        with pytest.raises(HttpTransportError):
            await self._forward_to("http://127.0.0.1:8000")

    @pytest.mark.asyncio
    async def test_C3_unregistered_host_blocked(self):
        """forward() to unregistered host raises HttpTransportError.

        When a transport is constructed for 'filesystem-mcp:8000' but someone
        tries to forward to an unregistered host — the allowlist (derived from
        upstream_url) blocks it.  In practice this can't happen because the URL
        is baked into the transport at construction time; the test demonstrates
        the guard catches it if the URL were manipulated.
        """
        from yashigani.mcp._transport_http import HttpTransportError, McpHttpTransport
        # Construct transport for 'filesystem-mcp' but provide a different
        # trusted_upstream_urls so the allowlist only contains 'filesystem-mcp',
        # then try to forward to 'evil.internal' — blocked.
        # (We achieve this by setting a mismatched trusted_upstream_urls.)
        with pytest.raises(HttpTransportError):
            async with McpHttpTransport(
                upstream_url="http://evil.internal:8000",
                trusted_upstream_urls=["http://filesystem-mcp:8000"],
            ) as t:
                await t.forward(
                    mcp_request_json='{"jsonrpc":"2.0","method":"tools/call","id":1}',
                    gateway_jwt="test-jwt",
                )

    @pytest.mark.asyncio
    async def test_C4_registered_docker_hostname_reaches_server(self):
        """Registered Docker-service hostname passes the SSRF guard."""
        # The SSRF guard allows the host; the actual network call is mocked
        # so we don't need demo-mcp to be reachable.
        import httpx
        fake_resp = MagicMock(spec=httpx.Response)
        fake_resp.text = '{"jsonrpc":"2.0","id":1,"result":{"ok":true}}'
        fake_resp.raise_for_status = MagicMock()

        from yashigani.net.http_client import HttpClient
        mock_post = AsyncMock(return_value=fake_resp)

        with patch.object(HttpClient, "post", mock_post):
            result = await self._forward_to("http://demo-mcp:8000")

        assert "ok" in result
        mock_post.assert_called_once()
        # Verify the URL that reached the client includes the hostname
        called_url = mock_post.call_args[0][0]
        assert "demo-mcp" in called_url

    @pytest.mark.asyncio
    async def test_C5_redirect_blocked_follow_redirects_false(self):
        """Redirects are blocked (follow_redirects=False in HttpClient)."""
        # HttpClient._request defaults follow_redirects=False.
        # Simulate a redirect response: httpx raises TooManyRedirects or
        # returns a 302 that raise_for_status turns into HTTPStatusError.
        import httpx
        redir_resp = MagicMock(spec=httpx.Response)
        redir_resp.status_code = 302
        redir_resp.text = ""
        redir_resp.raise_for_status = MagicMock(
            side_effect=httpx.HTTPStatusError(
                "302", request=MagicMock(), response=redir_resp
            )
        )

        from yashigani.net.http_client import HttpClient
        from yashigani.mcp._transport_http import HttpTransportError
        mock_post = AsyncMock(return_value=redir_resp)

        with patch.object(HttpClient, "post", mock_post):
            with pytest.raises(HttpTransportError, match="302"):
                await self._forward_to("http://demo-mcp:8000")

    @pytest.mark.asyncio
    async def test_C6_trusted_upstream_urls_explicit_allowlist(self):
        """trusted_upstream_urls explicitly limits the allowlist."""
        from yashigani.mcp._transport_http import HttpTransportError
        # upstream_url is 'http://filesystem-mcp:8000', but trusted set = ['git-mcp']
        # forward would go to 'filesystem-mcp' which is NOT in the trusted list
        with pytest.raises(HttpTransportError):
            async with __import__(
                "yashigani.mcp._transport_http", fromlist=["McpHttpTransport"]
            ).McpHttpTransport(
                upstream_url="http://filesystem-mcp:8000",
                trusted_upstream_urls=["http://git-mcp:8000"],
            ) as t:
                await t.forward(
                    mcp_request_json='{}',
                    gateway_jwt="test-jwt",
                )

    @pytest.mark.asyncio
    async def test_C7_injected_http_client_bypasses_guard(self):
        """Injected http_client (test mock) bypasses SSRF guard — backward compat."""
        import httpx
        from yashigani.mcp._transport_http import McpHttpTransport

        fake_resp = MagicMock(spec=httpx.Response)
        fake_resp.text = '{"jsonrpc":"2.0","id":1,"result":{}}'
        fake_resp.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.post = AsyncMock(return_value=fake_resp)
        mock_client.aclose = AsyncMock()

        # Even though upstream_url would be blocked (IMDS), injected client wins
        async with McpHttpTransport(
            upstream_url="http://169.254.169.254",
            http_client=mock_client,
        ) as t:
            result = await t.forward(
                mcp_request_json='{}',
                gateway_jwt="test-jwt",
            )

        assert "result" in result
        mock_client.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_C8_auto_guard_from_upstream_url(self):
        """Without trusted_upstream_urls, guard derives allowlist from upstream_url."""
        import httpx
        from yashigani.net.http_client import HttpClient

        fake_resp = MagicMock(spec=httpx.Response)
        fake_resp.text = '{"ok":1}'
        fake_resp.raise_for_status = MagicMock()

        mock_post = AsyncMock(return_value=fake_resp)

        with patch.object(HttpClient, "post", mock_post):
            await self._forward_to("http://demo-mcp:8000")

        # The auto-allowlist was built from 'http://demo-mcp:8000' → ['demo-mcp']
        # and the request succeeded
        mock_post.assert_called_once()


# ---------------------------------------------------------------------------
# D. _is_hard_block — unconditional block classification
# ---------------------------------------------------------------------------

class TestIsHardBlock:
    """Tests for the _is_hard_block() helper."""

    def _fn(self):
        from yashigani.net.http_client import _is_hard_block
        return _is_hard_block

    def test_D1_named_imds_hosts(self):
        fn = self._fn()
        assert fn("169.254.169.254") is True
        assert fn("metadata.google.internal") is True
        assert fn("fd00:ec2::254") is True
        assert fn("100.100.100.200") is True

    def test_D2_loopback_ips(self):
        fn = self._fn()
        assert fn("127.0.0.1") is True
        assert fn("127.0.0.100") is True
        assert fn("::1") is True

    def test_D3_link_local_ips(self):
        fn = self._fn()
        assert fn("169.254.0.1") is True
        assert fn("169.254.255.254") is True
        assert fn("fe80::1") is True

    def test_D4_rfc1918_not_hard_blocked(self):
        """RFC-1918 is NOT a hard block — it can be bypassed via allowlist."""
        fn = self._fn()
        assert fn("10.0.0.5") is False
        assert fn("172.17.0.2") is False
        assert fn("192.168.1.1") is False

    def test_D5_public_ips_not_hard_blocked(self):
        fn = self._fn()
        assert fn("1.1.1.1") is False
        assert fn("8.8.8.8") is False

    def test_D6_hostname_not_hard_blocked(self):
        """Hostnames are not hard-blocked by _is_hard_block (only literal IPs)."""
        fn = self._fn()
        assert fn("filesystem-mcp") is False
        assert fn("demo-mcp") is False
        assert fn("evil.example.com") is False
