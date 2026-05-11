"""
OWUI DNS-rebinding defence tests — extend-pr-112-owui-wrap (OWASP API7 / issue #91).

Verifies that _push_openwebui_model() routes all outbound calls through
pinned_resolver, so that a DNS rebinding attack cannot redirect the OWUI push
to an internal address after the initial allowlist check passes.

Attack scenario modelled
------------------------
An attacker who has compromised an admin account sets OWUI_API_URL to a
hostname that:
  1. First DNS lookup: returns an allowlisted IP (e.g. open-webui's real address)
     → passes _check_policy() AND _resolve_first_safe_ip().
  2. Subsequent DNS lookups (at TCP connect time): returns an internal RFC 1918
     address → would reach an internal service if urllib was used directly.

The pinned-resolver closes this window: the IP resolved at context entry is
cached and re-injected by _PinnedTransport for every request inside the block.

Test catalogue
--------------
TestOwuiDnsRebindingDefence
  test_owui_push_uses_pinned_resolver   — pinned_resolver is entered for OWUI call
  test_owui_rebinding_ip_not_used       — TCP connection stays on first-resolved IP
  test_owui_imds_all_ips_blocked        — IMDS endpoint rejected at pin time
  test_owui_ssrf_pinned_resolver_used_logged
                                        — SSRF_PINNED_RESOLVER_USED logged at DEBUG

TestOwuiPinnedResolverAllowlistPropagation
  test_owui_hostnames_env_reaches_pinned_resolver
                                        — YASHIGANI_OWUI_HOSTNAMES drives pinned_resolver allowlist
  test_owui_host_not_in_allowlist_blocked
                                        — host absent from OWUI allowlist is rejected by pinned_resolver

TestOwuiPushNonFatal
  test_pin_failure_is_non_fatal        — BlockedByPolicy from pinned_resolver is swallowed
  test_missing_owui_secret_is_non_fatal — missing OWUI_SECRET_KEY is swallowed
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from typing import Callable
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from yashigani.net.pinned_resolver import _AUDIT_EVENT_NAME


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _addrinfo(ip: str, port: int = 80) -> list[tuple]:
    """Build a minimal getaddrinfo-style result for a given IP."""
    try:
        addr = ipaddress.ip_address(ip)
        family = socket.AF_INET6 if isinstance(addr, ipaddress.IPv6Address) else socket.AF_INET
    except ValueError:
        family = socket.AF_INET
    return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))]


def _reset_owui_singleton():
    """Reset the lazy _OWUI_HTTP_CLIENT singleton for test isolation."""
    import yashigani.backoffice.routes.agents as _ag

    _ag._OWUI_HTTP_CLIENT = None


def _make_rebinding_resolver(
    host: str,
    *,
    safe_ip: str,
    rebind_ip: str,
) -> Callable:
    """Return a getaddrinfo shim that answers safe_ip on first call and
    rebind_ip on all subsequent calls for the given host.

    Other hosts fall through to the real OS resolver.
    """
    call_count: list[int] = [0]
    _real_getaddrinfo = socket.getaddrinfo

    def _fake(h, port, *args, **kwargs):
        if h in (host, host.lower()):
            call_count[0] += 1
            ip = safe_ip if call_count[0] == 1 else rebind_ip
            port_int = port if isinstance(port, int) else 80
            return _addrinfo(ip, port_int)
        return _real_getaddrinfo(h, port, *args, **kwargs)

    return _fake


# ---------------------------------------------------------------------------
# Core rebinding defence tests
# ---------------------------------------------------------------------------


class TestOwuiDnsRebindingDefence:
    """Verify that _push_openwebui_model uses pinned_resolver for outbound calls."""

    def setup_method(self):
        _reset_owui_singleton()

    @pytest.mark.asyncio
    async def test_owui_push_uses_pinned_resolver(self, monkeypatch):
        """
        pinned_resolver must be entered exactly once per _push_openwebui_model call.

        _push_openwebui_model imports pinned_resolver via
        `from yashigani.net import BlockedByPolicy, pinned_resolver` inside the
        function body. We patch `yashigani.net.pinned_resolver` (the attribute on
        the `yashigani.net` module) so the local import picks up our fake.
        """
        monkeypatch.setenv("OWUI_API_URL", "http://open-webui:8080")
        monkeypatch.setenv("YASHIGANI_OWUI_HOSTNAMES", "open-webui,127.0.0.1,localhost")
        monkeypatch.setenv("OWUI_SECRET_KEY", "testsecret")
        _reset_owui_singleton()

        pinned_resolver_calls: list[dict] = []

        # Build a fake httpx.AsyncClient that short-circuits the network calls.
        fake_check = MagicMock()
        fake_check.status_code = 404  # trigger the "create" path
        fake_create = MagicMock()
        fake_create.status_code = 200
        fake_client = AsyncMock()
        fake_client.get = AsyncMock(return_value=fake_check)
        fake_client.post = AsyncMock(return_value=fake_create)

        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def _fake_pinned_resolver(hostname, *, port=443, allowlist=None, **kwargs):
            pinned_resolver_calls.append({"hostname": hostname, "allowlist": allowlist})
            yield fake_client

        # agents.py now does `from yashigani.net.pinned_resolver import pinned_resolver`
        # inside the function body (direct submodule import — required so mypy resolves
        # the callable type; lazy because it's function-scoped).  Patch at the source
        # so the in-function import picks up the fake.
        with patch("yashigani.net.pinned_resolver.pinned_resolver", _fake_pinned_resolver):
            from yashigani.backoffice.routes.agents import _push_openwebui_model

            await _push_openwebui_model("test-agent", "http://open-webui:8080")

        assert len(pinned_resolver_calls) == 1, (
            f"pinned_resolver was not called exactly once; calls={pinned_resolver_calls}"
        )
        assert pinned_resolver_calls[0]["hostname"] == "open-webui", (
            f"pinned_resolver called with wrong hostname: {pinned_resolver_calls[0]}"
        )

    @pytest.mark.asyncio
    async def test_owui_rebinding_ip_not_used(self, monkeypatch):
        """
        DNS rebinding after first resolution must not redirect the connection.

        Setup: a fake resolver returns an allowlisted IP on the first getaddrinfo
        call (the pin operation in _resolve_first_safe_ip), then an RFC 1918
        address on all subsequent calls (the rebind attempt).

        The test asserts:
          1. _PinnedTransport is created with the FIRST-resolved (safe) IP.
          2. Inside _PinnedTransport.handle_async_request, getaddrinfo for the
             request host returns the PINNED IP, not the rebinding IP — because
             _PinnedTransport patches getaddrinfo before calling the underlying
             transport.

        We spy on _PinnedTransport.__init__ to capture the pinned_ip, then let
        handle_async_request run (with a mocked underlying httpx transport) so
        the getaddrinfo intercept is exercised.
        """
        monkeypatch.setenv("OWUI_API_URL", "http://open-webui:8080")
        monkeypatch.setenv("YASHIGANI_OWUI_HOSTNAMES", "open-webui")
        monkeypatch.setenv("OWUI_SECRET_KEY", "testsecret")
        _reset_owui_singleton()

        # 93.184.216.34 is example.com's IP — not private/reserved in Python 3.9.
        safe_ip = "93.184.216.34"
        rebind_ip = "10.0.0.99"  # RFC 1918 — must never be the connection target

        rebinding_resolver = _make_rebinding_resolver(
            "open-webui",
            safe_ip=safe_ip,
            rebind_ip=rebind_ip,
        )

        pinned_ips_used: list[str] = []
        getaddrinfo_inside_transport: list[str] = []

        import httpx
        from yashigani.net.pinned_resolver import _PinnedTransport

        # Spy on _PinnedTransport.__init__ to record the pinned IP.
        original_init = _PinnedTransport.__init__

        def _spy_init(self, pinned_ip: str, **kwargs):
            pinned_ips_used.append(pinned_ip)
            original_init(self, pinned_ip, **kwargs)

        # Override the underlying httpx AsyncHTTPTransport.handle_async_request
        # so no real TCP connection is attempted, but we still run _PinnedTransport's
        # patched-getaddrinfo wrapper by calling socket.getaddrinfo from "inside" it.
        async def _mock_underlying_handle(self, request: httpx.Request) -> httpx.Response:
            # At this point _PinnedTransport has already patched socket.getaddrinfo
            # to return the pinned IP. Capture what getaddrinfo returns now.
            resolved = socket.getaddrinfo(request.url.host, request.url.port or 80)
            getaddrinfo_inside_transport.append(str(resolved[0][4][0]))
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200
            resp.json = MagicMock(return_value={})
            return resp

        with patch("socket.getaddrinfo", side_effect=rebinding_resolver):
            with patch.object(_PinnedTransport, "__init__", new=_spy_init):
                with patch.object(
                    httpx.AsyncHTTPTransport,
                    "handle_async_request",
                    new=_mock_underlying_handle,
                ):
                    from yashigani.backoffice.routes.agents import _push_openwebui_model

                    await _push_openwebui_model("test-agent", "http://open-webui:8080")

        # _PinnedTransport must have been created with the FIRST-resolved (safe) IP.
        assert pinned_ips_used, "No _PinnedTransport was created — pinned_resolver not used on OWUI path."
        for pinned in pinned_ips_used:
            assert pinned == safe_ip, (
                f"_PinnedTransport created with wrong IP {pinned!r} (expected {safe_ip!r}). "
                "DNS rebinding: first-resolved IP not used for pinning."
            )

        # Inside the transport, getaddrinfo must return the pinned IP (not the rebind).
        assert getaddrinfo_inside_transport, (
            "handle_async_request was never called — no HTTP requests made by pinned session."
        )
        for target in getaddrinfo_inside_transport:
            assert target == safe_ip, (
                f"Inside _PinnedTransport, getaddrinfo returned {target!r} "
                f"instead of pinned {safe_ip!r}. "
                "DNS-rebinding defence did not intercept the transport-level lookup."
            )
        assert rebind_ip not in getaddrinfo_inside_transport, (
            f"Rebinding IP {rebind_ip!r} seen inside the transport — defence failed."
        )

    @pytest.mark.asyncio
    async def test_owui_imds_all_ips_blocked(self, monkeypatch):
        """
        If the OWUI hostname resolves only to the cloud metadata endpoint
        (169.254.169.254), _push_openwebui_model must not issue any HTTP request
        and must not raise (non-fatal).
        """
        monkeypatch.setenv("OWUI_API_URL", "http://evil-owui:8080")
        monkeypatch.setenv("YASHIGANI_OWUI_HOSTNAMES", "evil-owui")
        monkeypatch.setenv("OWUI_SECRET_KEY", "testsecret")
        _reset_owui_singleton()

        http_calls: list[str] = []

        with patch("socket.getaddrinfo", return_value=_addrinfo("169.254.169.254", 8080)):
            with patch("httpx.AsyncClient.get", side_effect=lambda *a, **k: http_calls.append("get")):
                with patch("httpx.AsyncClient.post", side_effect=lambda *a, **k: http_calls.append("post")):
                    from yashigani.backoffice.routes.agents import _push_openwebui_model

                    # Must not raise — _push_openwebui_model is fire-and-forget.
                    await _push_openwebui_model("evil-agent", "http://open-webui:8080")

        assert http_calls == [], f"httpx made outbound calls despite IMDS-only resolution: {http_calls}"

    @pytest.mark.asyncio
    async def test_owui_ssrf_pinned_resolver_used_logged(self, monkeypatch, caplog):
        """
        SSRF_PINNED_RESOLVER_USED must be logged at DEBUG level when the OWUI
        push succeeds through the pinned resolver.
        """
        monkeypatch.setenv("OWUI_API_URL", "http://open-webui:8080")
        monkeypatch.setenv("YASHIGANI_OWUI_HOSTNAMES", "open-webui")
        monkeypatch.setenv("OWUI_SECRET_KEY", "testsecret")
        _reset_owui_singleton()

        safe_ip = "93.184.216.34"

        import httpx

        async def _fake_handle(self, request: httpx.Request) -> httpx.Response:
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200
            resp.json = MagicMock(return_value={})
            return resp

        with caplog.at_level(logging.DEBUG, logger="yashigani.net.pinned_resolver"):
            with patch("socket.getaddrinfo", return_value=_addrinfo(safe_ip, 8080)):
                from yashigani.net.pinned_resolver import _PinnedTransport

                with patch.object(_PinnedTransport, "handle_async_request", new=_fake_handle):
                    from yashigani.backoffice.routes.agents import _push_openwebui_model

                    await _push_openwebui_model("logged-agent", "http://open-webui:8080")

        logged = [r.message for r in caplog.records]
        assert any(_AUDIT_EVENT_NAME in msg for msg in logged), (
            f"Expected {_AUDIT_EVENT_NAME!r} in DEBUG log; got: {logged}"
        )


# ---------------------------------------------------------------------------
# Allowlist propagation tests
# ---------------------------------------------------------------------------


class TestOwuiPinnedResolverAllowlistPropagation:
    """pinned_resolver must receive the same allowlist as _owui_http_client()."""

    def setup_method(self):
        _reset_owui_singleton()

    @pytest.mark.asyncio
    async def test_owui_hostnames_env_reaches_pinned_resolver(self, monkeypatch):
        """YASHIGANI_OWUI_HOSTNAMES entries must be passed to pinned_resolver as allowlist."""
        monkeypatch.setenv("OWUI_API_URL", "http://custom-owui:8080")
        monkeypatch.setenv("YASHIGANI_OWUI_HOSTNAMES", "custom-owui,backup-owui")
        monkeypatch.setenv("OWUI_SECRET_KEY", "testsecret")
        _reset_owui_singleton()

        captured_allowlist: list[list[str]] = []

        from contextlib import asynccontextmanager

        fake_client = AsyncMock()
        fake_client.get = AsyncMock(return_value=MagicMock(status_code=200))
        fake_client.post = AsyncMock(return_value=MagicMock(status_code=200))

        @asynccontextmanager
        async def _capture_pinned_resolver(hostname, *, port=443, allowlist=None, **kwargs):
            captured_allowlist.append(list(allowlist or []))
            yield fake_client

        # agents.py now does `from yashigani.net.pinned_resolver import pinned_resolver`
        # inside the function body — patch at the source submodule so the in-function
        # import picks up the fake.
        with patch("yashigani.net.pinned_resolver.pinned_resolver", _capture_pinned_resolver):
            from yashigani.backoffice.routes.agents import _push_openwebui_model

            await _push_openwebui_model("custom-agent", "http://custom-owui:8080")

        assert captured_allowlist, "pinned_resolver was not called"
        allowlist_used = captured_allowlist[0]
        assert "custom-owui" in allowlist_used, f"custom-owui not in pinned_resolver allowlist: {allowlist_used!r}"
        assert "backup-owui" in allowlist_used, f"backup-owui not in pinned_resolver allowlist: {allowlist_used!r}"

    @pytest.mark.asyncio
    async def test_owui_host_not_in_allowlist_blocked(self, monkeypatch):
        """
        If OWUI_API_URL points to a host NOT in YASHIGANI_OWUI_HOSTNAMES, the
        pinned_resolver must raise BlockedByPolicy (caught non-fatally).
        No outbound HTTP calls must be made.
        """
        monkeypatch.setenv("OWUI_API_URL", "http://attacker-owui.evil.example:8080")
        monkeypatch.setenv("YASHIGANI_OWUI_HOSTNAMES", "open-webui,localhost")
        monkeypatch.setenv("OWUI_SECRET_KEY", "testsecret")
        _reset_owui_singleton()

        http_calls: list[str] = []

        # The pre-flight _check_policy will block this host before pinned_resolver
        # is even reached (allowlist mismatch). Either guard catching it is correct.
        with patch("httpx.AsyncClient.get", side_effect=lambda *a, **k: http_calls.append("get")):
            with patch("httpx.AsyncClient.post", side_effect=lambda *a, **k: http_calls.append("post")):
                from yashigani.backoffice.routes.agents import _push_openwebui_model

                # Must not raise — non-fatal.
                await _push_openwebui_model("attacker-agent", "http://open-webui:8080")

        assert http_calls == [], f"httpx made outbound calls despite allowlist mismatch: {http_calls}"


# ---------------------------------------------------------------------------
# Non-fatal behaviour tests
# ---------------------------------------------------------------------------


class TestOwuiPushNonFatal:
    """_push_openwebui_model must never raise — all failures are logged."""

    def setup_method(self):
        _reset_owui_singleton()

    @pytest.mark.asyncio
    async def test_pin_failure_is_non_fatal(self, monkeypatch):
        """BlockedByPolicy from pinned_resolver must be caught, not propagated."""
        monkeypatch.setenv("OWUI_API_URL", "http://open-webui:8080")
        monkeypatch.setenv("YASHIGANI_OWUI_HOSTNAMES", "open-webui")
        monkeypatch.setenv("OWUI_SECRET_KEY", "testsecret")
        _reset_owui_singleton()

        # Force all DNS resolutions to return a metadata IP → pin will fail.
        with patch("socket.getaddrinfo", return_value=_addrinfo("169.254.169.254", 8080)):
            from yashigani.backoffice.routes.agents import _push_openwebui_model

            try:
                await _push_openwebui_model("fail-agent", "http://open-webui:8080")
            except Exception as exc:
                pytest.fail(f"_push_openwebui_model raised unexpectedly on BlockedByPolicy: {exc!r}")

    @pytest.mark.asyncio
    async def test_missing_owui_secret_is_non_fatal(self, monkeypatch):
        """Missing OWUI_SECRET_KEY must not propagate — non-fatal failure."""
        monkeypatch.setenv("OWUI_API_URL", "http://open-webui:8080")
        monkeypatch.setenv("YASHIGANI_OWUI_HOSTNAMES", "open-webui")
        monkeypatch.delenv("OWUI_SECRET_KEY", raising=False)
        _reset_owui_singleton()

        from yashigani.backoffice.routes.agents import _push_openwebui_model

        try:
            await _push_openwebui_model("no-secret-agent", "http://open-webui:8080")
        except Exception as exc:
            pytest.fail(f"_push_openwebui_model raised unexpectedly on missing OWUI_SECRET_KEY: {exc!r}")
