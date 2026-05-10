"""
DNS-rebinding defence tests — OWASP API7 SSRF / issue #91.

Verifies that :func:`~yashigani.net.pinned_resolver` correctly pins the
hostname to the IP resolved at context-entry time and that a DNS change
mid-connection cannot redirect traffic to an internal address.

Test strategy
-------------
1. Fake resolver — :func:`socket.getaddrinfo` is patched globally to simulate
   a DNS-rebinding attack: the first call for the target hostname returns a
   safe allowlisted IP; the second call (which would be the real TCP connect)
   returns an internal RFC 1918 IP.  The pinned resolver must use the first
   (cached) IP for the actual connection, not the second.

2. Direct unit tests of the IP-validation helper ``_resolve_first_safe_ip``
   with a mocked resolver.

3. Verify that ``BlockedByPolicy`` is raised when ALL resolved addresses for a
   hostname are blocked (no safe IP to pin to).

4. Verify that ``SSRF_PINNED_RESOLVER_USED`` is logged at DEBUG level on a
   successful pin.

5. Verify that the pinned transport short-circuits getaddrinfo for the correct
   host and passes through for unrelated hosts.

Note: tests that exercise the full httpx transport path do so against a local
mock rather than any live network — no real DNS queries leave the process.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from yashigani.net.http_client import BlockedByPolicy
from yashigani.net.pinned_resolver import (
    _AUDIT_EVENT_NAME,
    _PinnedTransport,
    _resolve_first_safe_ip,
    pinned_resolver,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _addrinfo(ip: str, port: int = 443) -> list[tuple]:
    """Build a minimal getaddrinfo-style result for a given IP."""
    try:
        addr = ipaddress.ip_address(ip)
        family = socket.AF_INET6 if isinstance(addr, ipaddress.IPv6Address) else socket.AF_INET
    except ValueError:
        family = socket.AF_INET
    return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))]


# ---------------------------------------------------------------------------
# _resolve_first_safe_ip unit tests
# ---------------------------------------------------------------------------


class TestResolveFirstSafeIp:
    """Tests for the synchronous IP-resolution and policy-check helper."""

    def test_safe_public_ip_returned(self):
        """A public non-blocked IP is returned as-is."""
        with patch("socket.getaddrinfo", return_value=_addrinfo("93.184.216.34")):
            ip = _resolve_first_safe_ip("example.com", 443, None, None)
        assert ip == "93.184.216.34"

    def test_private_ip_blocked(self):
        """An RFC 1918 address is blocked — BlockedByPolicy raised."""
        with patch("socket.getaddrinfo", return_value=_addrinfo("10.0.0.5")):
            with pytest.raises(BlockedByPolicy, match="blocked by SSRF policy"):
                _resolve_first_safe_ip("evil.internal", 443, None, None)

    def test_loopback_blocked(self):
        """Loopback address is blocked."""
        with patch("socket.getaddrinfo", return_value=_addrinfo("127.0.0.1")):
            with pytest.raises(BlockedByPolicy, match="blocked by SSRF policy"):
                _resolve_first_safe_ip("localhost", 443, None, None)

    def test_link_local_blocked(self):
        """169.254.x.x (cloud metadata / link-local) is blocked."""
        with patch("socket.getaddrinfo", return_value=_addrinfo("169.254.169.254")):
            with pytest.raises(BlockedByPolicy, match="blocked by SSRF policy"):
                _resolve_first_safe_ip("imds.internal", 443, None, None)

    def test_dns_failure_raises_blocked_by_policy(self):
        """If getaddrinfo raises gaierror, BlockedByPolicy is raised."""
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("NXDOMAIN")):
            with pytest.raises(BlockedByPolicy, match="DNS resolution failed"):
                _resolve_first_safe_ip("nonexistent.example", 443, None, None)

    def test_empty_result_raises_blocked_by_policy(self):
        """Empty getaddrinfo result raises BlockedByPolicy."""
        with patch("socket.getaddrinfo", return_value=[]):
            with pytest.raises(BlockedByPolicy, match="no results"):
                _resolve_first_safe_ip("empty.example", 443, None, None)

    def test_allowlist_mismatch_raises(self):
        """IP not covered by allowlist raises BlockedByPolicy."""
        with patch("socket.getaddrinfo", return_value=_addrinfo("93.184.216.34")):
            with pytest.raises(BlockedByPolicy, match="blocked by SSRF policy"):
                _resolve_first_safe_ip(
                    "example.com",
                    443,
                    allowlist=["api.pwnedpasswords.com"],
                    blocklist=None,
                )

    def test_allowlist_hostname_match_accepted(self):
        """Hostname match in allowlist allows its resolved IP."""
        with patch("socket.getaddrinfo", return_value=_addrinfo("93.184.216.34")):
            ip = _resolve_first_safe_ip(
                "example.com",
                443,
                allowlist=["example.com"],
                blocklist=None,
            )
        assert ip == "93.184.216.34"

    def test_blocklist_entry_skips_ip(self):
        """An IP that matches the blocklist is skipped; if no safe IP exists, raises."""
        with patch("socket.getaddrinfo", return_value=_addrinfo("93.184.216.34")):
            with pytest.raises(BlockedByPolicy, match="blocked by SSRF policy"):
                _resolve_first_safe_ip(
                    "example.com",
                    443,
                    allowlist=None,
                    blocklist=["93.184.216.34"],
                )

    def test_first_safe_ip_chosen_among_multiple(self):
        """Given a mix of blocked and safe IPs, the first safe one is returned."""
        mixed = _addrinfo("10.0.0.1") + _addrinfo("93.184.216.34")
        with patch("socket.getaddrinfo", return_value=mixed):
            ip = _resolve_first_safe_ip("example.com", 443, None, None)
        assert ip == "93.184.216.34"


# ---------------------------------------------------------------------------
# DNS-rebinding simulation tests
# ---------------------------------------------------------------------------


class TestDnsRebindingDefence:
    """Simulate a DNS-rebinding attack: first lookup returns safe IP,
    second lookup (at connect time) returns internal IP.  The pinned resolver
    must use the first IP for the actual TCP connect."""

    def _make_rebinding_getaddrinfo(self, host: str, safe_ip: str, internal_ip: str):
        """Return a getaddrinfo replacement that rebinds after the first call."""
        call_count: list[int] = [0]

        def _fake_getaddrinfo(h, port, *args, **kwargs):
            if h == host or h == host.lower():
                call_count[0] += 1
                if call_count[0] == 1:
                    # First call (policy check / pin): safe allowlisted IP
                    return _addrinfo(safe_ip, port if isinstance(port, int) else 443)
                else:
                    # Subsequent calls (transport connect): attacker-controlled rebind
                    return _addrinfo(internal_ip, port if isinstance(port, int) else 443)
            return socket.getaddrinfo(h, port, *args, **kwargs)

        return _fake_getaddrinfo

    def test_pinned_ip_used_not_rebinding_ip(self):
        """_resolve_first_safe_ip returns the first-call IP regardless of later changes."""
        fake_resolver = self._make_rebinding_getaddrinfo(
            host="api.example.com",
            safe_ip="93.184.216.34",
            internal_ip="10.0.0.1",
        )
        with patch("socket.getaddrinfo", side_effect=fake_resolver):
            pinned = _resolve_first_safe_ip("api.example.com", 443, None, None)

        # Must be the safe IP from the first lookup, not the rebinding internal IP.
        assert pinned == "93.184.216.34"

    def test_rebinding_to_metadata_endpoint_blocked_at_pin(self):
        """If the first resolution already returns a metadata IP, the pin fails."""
        with patch("socket.getaddrinfo", return_value=_addrinfo("169.254.169.254")):
            with pytest.raises(BlockedByPolicy):
                _resolve_first_safe_ip("attacker.example", 443, None, None)

    @pytest.mark.asyncio
    async def test_pinned_transport_intercepts_getaddrinfo(self):
        """_PinnedTransport.handle_async_request patches getaddrinfo for exact host
        and restores it after the request completes."""
        import httpx

        intercepted_calls: list[str] = []
        original_getaddrinfo = socket.getaddrinfo

        async def _fake_handle(request):
            # During handle_async_request the patch is active — call getaddrinfo.
            result = socket.getaddrinfo("target.example.com", 443)
            intercepted_calls.append(str(result[0][4][0]))  # captured pinned IP
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200
            return resp

        transport = _PinnedTransport(pinned_ip="93.184.216.34")
        request = httpx.Request("GET", "https://target.example.com/test")

        with patch.object(
            httpx.AsyncHTTPTransport,
            "handle_async_request",
            side_effect=_fake_handle,
        ):
            await transport.handle_async_request(request)

        # After handle_async_request returns, getaddrinfo must be restored.
        assert socket.getaddrinfo is original_getaddrinfo

        # The intercepted call should have returned the pinned IP.
        assert intercepted_calls == ["93.184.216.34"]

    @pytest.mark.asyncio
    async def test_pinned_transport_does_not_intercept_other_hosts(self):
        """_PinnedTransport only patches getaddrinfo for the pinned request's host."""
        import httpx

        results_for_other: list[Any] = []

        async def _fake_handle(request):
            # Query a completely different host — must go to real getaddrinfo (or OS)
            try:
                r = socket.getaddrinfo("localhost", 80)
                results_for_other.extend(r)
            except Exception:
                pass
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200
            return resp

        transport = _PinnedTransport(pinned_ip="93.184.216.34")
        request = httpx.Request("GET", "https://target.example.com/test")

        with patch.object(
            httpx.AsyncHTTPTransport,
            "handle_async_request",
            side_effect=_fake_handle,
        ):
            await transport.handle_async_request(request)

        # Results for "localhost" should reflect real OS resolution (loopback),
        # not the pinned IP "93.184.216.34".
        pinned_ip_used = any(r[4][0] == "93.184.216.34" for r in results_for_other)
        assert not pinned_ip_used, "Pinned transport incorrectly intercepted getaddrinfo for an unrelated host"

    @pytest.mark.asyncio
    async def test_getaddrinfo_restored_on_transport_exception(self):
        """getaddrinfo is restored even if handle_async_request raises."""
        import httpx

        original = socket.getaddrinfo

        transport = _PinnedTransport(pinned_ip="93.184.216.34")
        request = httpx.Request("GET", "https://target.example.com/test")

        with patch.object(
            httpx.AsyncHTTPTransport,
            "handle_async_request",
            new_callable=AsyncMock,
            side_effect=RuntimeError("simulated transport failure"),
        ):
            with pytest.raises(RuntimeError, match="simulated transport failure"):
                await transport.handle_async_request(request)

        # Must be restored after exception.
        assert socket.getaddrinfo is original


# ---------------------------------------------------------------------------
# pinned_resolver context manager tests
# ---------------------------------------------------------------------------


class TestPinnedResolverContextManager:
    """Tests for the high-level pinned_resolver async context manager."""

    @pytest.mark.asyncio
    async def test_yields_httpx_client(self):
        """pinned_resolver yields an httpx.AsyncClient."""
        import httpx

        with patch("socket.getaddrinfo", return_value=_addrinfo("93.184.216.34")):
            async with pinned_resolver(
                "example.com",
                allowlist=["example.com"],
            ) as client:
                assert isinstance(client, httpx.AsyncClient)

    @pytest.mark.asyncio
    async def test_raises_blocked_when_all_ips_private(self):
        """pinned_resolver raises BlockedByPolicy if no safe address exists."""
        with patch("socket.getaddrinfo", return_value=_addrinfo("10.0.0.1")):
            with pytest.raises(BlockedByPolicy):
                async with pinned_resolver("internal.corp"):
                    pass  # Should not reach here

    @pytest.mark.asyncio
    async def test_follow_redirects_disabled(self):
        """The yielded client has follow_redirects=False (bypass prevention)."""
        with patch("socket.getaddrinfo", return_value=_addrinfo("93.184.216.34")):
            async with pinned_resolver("example.com") as client:
                assert client.follow_redirects is False

    @pytest.mark.asyncio
    async def test_audit_event_logged_on_success(self, caplog):
        """SSRF_PINNED_RESOLVER_USED is logged at DEBUG level on a successful pin."""
        with caplog.at_level(logging.DEBUG, logger="yashigani.net.pinned_resolver"):
            with patch("socket.getaddrinfo", return_value=_addrinfo("93.184.216.34")):
                async with pinned_resolver("example.com") as _:
                    pass

        logged_messages = [r.message for r in caplog.records]
        assert any(_AUDIT_EVENT_NAME in msg for msg in logged_messages), (
            f"Expected {_AUDIT_EVENT_NAME!r} in log records; got: {logged_messages}"
        )

    @pytest.mark.asyncio
    async def test_audit_event_includes_hostname_and_ip(self, caplog):
        """The debug log message includes both the hostname and the resolved IP."""
        with caplog.at_level(logging.DEBUG, logger="yashigani.net.pinned_resolver"):
            with patch("socket.getaddrinfo", return_value=_addrinfo("93.184.216.34")):
                async with pinned_resolver("example.com") as _:
                    pass

        matching = [r for r in caplog.records if _AUDIT_EVENT_NAME in r.message]
        assert matching, "No matching log records found"
        msg = matching[0].message
        assert "example.com" in msg
        assert "93.184.216.34" in msg

    @pytest.mark.asyncio
    async def test_no_audit_event_on_block(self, caplog):
        """No SSRF_PINNED_RESOLVER_USED event is emitted when resolution is blocked."""
        with caplog.at_level(logging.DEBUG, logger="yashigani.net.pinned_resolver"):
            with patch("socket.getaddrinfo", return_value=_addrinfo("10.0.0.1")):
                with pytest.raises(BlockedByPolicy):
                    async with pinned_resolver("internal.corp"):
                        pass

        logged_messages = [r.message for r in caplog.records]
        assert not any(_AUDIT_EVENT_NAME in msg for msg in logged_messages)


# ---------------------------------------------------------------------------
# Barrel export test
# ---------------------------------------------------------------------------


def test_barrel_export():
    """pinned_resolver is accessible via the yashigani.net package."""
    from yashigani.net import pinned_resolver as pr

    assert callable(pr)


def test_blocked_by_policy_exported():
    """BlockedByPolicy is still accessible via yashigani.net after the update."""
    from yashigani.net import BlockedByPolicy as BP

    assert issubclass(BP, Exception)
