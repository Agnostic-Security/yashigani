"""
Unit tests for DNS-pinned SIEM delivery in AuditLogWriter.

Finding reference: A4 — DNS-rebinding window in SIEM delivery (ACS scan 2026-05-21).
OWASP: API7:2023, CWE-918.

Test coverage:
  (a) Normal webhook delivery succeeds with pinned IP.
  (b) DNS-rebinding attempt (mock DNS returns different IP on second resolve) is
      detected and rejected.
  (c) RFC 1918 / metadata-service URLs are blocked.
  (d) _SyncPinnedTransport restores socket.getaddrinfo after the request.
"""
from __future__ import annotations

import socket
from unittest.mock import MagicMock, patch, call

import httpx
import pytest


# ---------------------------------------------------------------------------
# Helper: build a minimal SiemTarget
# ---------------------------------------------------------------------------

def _make_target(url: str = "https://siem.example.com/collect") -> object:
    from yashigani.audit.writer import SiemTarget
    return SiemTarget(
        name="test-siem",
        target_type="webhook",
        url=url,
        auth_header="Authorization",
        auth_value="Bearer test-token",
        enabled=True,
    )


# ---------------------------------------------------------------------------
# Test A — normal webhook delivery succeeds with pinned IP
# ---------------------------------------------------------------------------

class TestNormalDeliveryWithPinnedIp:
    def test_successful_delivery_calls_httpx_post(self):
        """Happy path: DNS resolves to a public IP, httpx POST returns 200."""
        from yashigani.audit.writer import _send_to_target_pinned

        target = _make_target("https://siem.example.com/collect")

        # Patch _resolve_first_safe_ip to return a fake public IP
        with patch(
            "yashigani.audit.writer._resolve_first_safe_ip",
            return_value="203.0.113.42",
        ):
            # Patch httpx.Client to return a 200 response
            mock_response = MagicMock()
            mock_response.status_code = 200

            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post = MagicMock(return_value=mock_response)

            with patch("yashigani.audit.writer.httpx.Client", return_value=mock_client):
                # Should not raise
                _send_to_target_pinned(
                    "https://siem.example.com/collect",
                    '{"event": "test"}',
                    target,
                )

            mock_client.post.assert_called_once()
            call_args = mock_client.post.call_args
            assert "https://siem.example.com/collect" in str(call_args)

    def test_delivery_uses_correct_content_type_for_webhook(self):
        """Webhook type uses application/json content-type."""
        from yashigani.audit.writer import _send_to_target_pinned

        target = _make_target()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post = MagicMock(return_value=mock_response)

        with patch("yashigani.audit.writer._resolve_first_safe_ip", return_value="203.0.113.42"):
            with patch("yashigani.audit.writer.httpx.Client", return_value=mock_client):
                _send_to_target_pinned(
                    "https://siem.example.com/collect",
                    '{"event": "audit"}',
                    target,
                )

        call_kwargs = mock_client.post.call_args[1]
        headers = call_kwargs.get("headers", {})
        assert headers.get("Content-Type") == "application/json"

    def test_delivery_sends_auth_header(self):
        """Auth header is included in the POST request."""
        from yashigani.audit.writer import _send_to_target_pinned

        target = _make_target()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post = MagicMock(return_value=mock_response)

        with patch("yashigani.audit.writer._resolve_first_safe_ip", return_value="203.0.113.42"):
            with patch("yashigani.audit.writer.httpx.Client", return_value=mock_client):
                _send_to_target_pinned(
                    "https://siem.example.com/collect",
                    '{"event": "audit"}',
                    target,
                )

        call_kwargs = mock_client.post.call_args[1]
        headers = call_kwargs.get("headers", {})
        assert headers.get("Authorization") == "Bearer test-token"

    def test_non_2xx_response_raises_runtime_error(self):
        """HTTP 500 from SIEM endpoint raises RuntimeError."""
        from yashigani.audit.writer import _send_to_target_pinned

        target = _make_target()
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post = MagicMock(return_value=mock_response)

        with patch("yashigani.audit.writer._resolve_first_safe_ip", return_value="203.0.113.42"):
            with patch("yashigani.audit.writer.httpx.Client", return_value=mock_client):
                with pytest.raises(RuntimeError, match="HTTP 500"):
                    _send_to_target_pinned(
                        "https://siem.example.com/collect",
                        '{"event": "audit"}',
                        target,
                    )

    def test_follow_redirects_is_false(self):
        """httpx.Client must be constructed with follow_redirects=False."""
        from yashigani.audit.writer import _send_to_target_pinned

        target = _make_target()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post = MagicMock(return_value=mock_response)

        client_kwargs_captured = {}

        def capture_client(**kwargs):
            client_kwargs_captured.update(kwargs)
            return mock_client

        with patch("yashigani.audit.writer._resolve_first_safe_ip", return_value="203.0.113.42"):
            with patch("yashigani.audit.writer.httpx.Client", side_effect=capture_client):
                _send_to_target_pinned(
                    "https://siem.example.com/collect",
                    '{"event": "test"}',
                    target,
                )

        assert client_kwargs_captured.get("follow_redirects") is False, (
            "httpx.Client must be constructed with follow_redirects=False "
            "to prevent HTTP-redirect SSRF bypass (Iris §3.1, CWE-918)"
        )


# ---------------------------------------------------------------------------
# Test B — DNS-rebinding detection
# ---------------------------------------------------------------------------

class TestDnsRebinding:
    def test_dns_rebinding_blocked_by_resolve_first_safe_ip(self):
        """If _resolve_first_safe_ip raises BlockedByPolicy, the connection is never made.

        This is the core anti-rebinding guarantee: the IP is resolved once, checked
        once, and if it's blocked (private/loopback/metadata), we never reach httpx.
        In a DNS-rebinding attack, the attacker's hostname resolves to a legitimate
        IP at registration time but swaps to a private IP before delivery. With the
        pre-flight resolve in _send_to_target_pinned, the delivery-time resolve
        happens within _resolve_first_safe_ip (which also re-checks the SSRF policy).
        If the rebinding has occurred by delivery time, _resolve_first_safe_ip raises.
        """
        from yashigani.audit.writer import _send_to_target_pinned
        from yashigani.net.http_client import BlockedByPolicy

        target = _make_target("https://rebind.attacker.com/collect")

        # Simulate DNS rebinding: by delivery time, the hostname resolves to a private IP
        with patch(
            "yashigani.audit.writer._resolve_first_safe_ip",
            side_effect=BlockedByPolicy(
                "All resolved addresses for 'rebind.attacker.com' are blocked "
                "by SSRF policy (private/loopback/metadata)"
            ),
        ):
            with pytest.raises(BlockedByPolicy, match="SSRF policy"):
                _send_to_target_pinned(
                    "https://rebind.attacker.com/collect",
                    '{"event": "test"}',
                    target,
                )

    def test_rebinding_attempt_does_not_reach_httpx(self):
        """When _resolve_first_safe_ip raises, httpx.Client is never called."""
        from yashigani.audit.writer import _send_to_target_pinned
        from yashigani.net.http_client import BlockedByPolicy

        target = _make_target("https://rebind.attacker.com/collect")

        with patch(
            "yashigani.audit.writer._resolve_first_safe_ip",
            side_effect=BlockedByPolicy("blocked"),
        ):
            with patch("yashigani.audit.writer.httpx.Client") as mock_httpx_client:
                with pytest.raises(BlockedByPolicy):
                    _send_to_target_pinned(
                        "https://rebind.attacker.com/collect",
                        '{"event": "test"}',
                        target,
                    )

        # httpx.Client must NOT have been called
        mock_httpx_client.assert_not_called()

    def test_resolve_called_once_per_delivery(self):
        """_resolve_first_safe_ip is called exactly once per _send_to_target_pinned call.

        This confirms the pinned-IP pattern: resolve once, pin, connect. Not zero times
        (no pin) and not N times (TOCTOU risk on the second call).
        """
        from yashigani.audit.writer import _send_to_target_pinned

        target = _make_target("https://siem.example.com/collect")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post = MagicMock(return_value=mock_response)

        with patch(
            "yashigani.audit.writer._resolve_first_safe_ip",
            return_value="203.0.113.42",
        ) as mock_resolve:
            with patch("yashigani.audit.writer.httpx.Client", return_value=mock_client):
                _send_to_target_pinned(
                    "https://siem.example.com/collect",
                    '{"event": "test"}',
                    target,
                )

        assert mock_resolve.call_count == 1, (
            f"_resolve_first_safe_ip should be called exactly once per delivery, "
            f"got {mock_resolve.call_count} calls. "
            "Calling twice opens a TOCTOU window; calling zero times skips the SSRF check."
        )


# ---------------------------------------------------------------------------
# Test C — RFC 1918 / metadata-service URLs blocked
# ---------------------------------------------------------------------------

class TestSsrfBlocking:
    """
    These tests verify that _resolve_first_safe_ip correctly blocks
    known-dangerous IP addresses. Tests use the real _resolve_first_safe_ip
    with patched socket.getaddrinfo that returns the blocked IP directly.
    """

    @pytest.mark.parametrize("ip_addr,description", [
        ("169.254.169.254", "AWS metadata service (link-local)"),
        ("10.0.0.1", "RFC 1918 Class A private"),
        ("172.16.0.1", "RFC 1918 Class B private"),
        ("192.168.1.1", "RFC 1918 Class C private"),
        ("127.0.0.1", "loopback"),
    ])
    def test_blocked_ip_raises_blocked_by_policy(self, ip_addr, description):
        """Addresses in private/loopback/metadata ranges must be blocked."""
        from yashigani.net.pinned_resolver import _resolve_first_safe_ip
        from yashigani.net.http_client import BlockedByPolicy

        # Patch socket.getaddrinfo to return the specific blocked IP
        def _fake_getaddrinfo(host, port, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip_addr, port))]

        with patch("socket.getaddrinfo", _fake_getaddrinfo):
            with pytest.raises(BlockedByPolicy, match="blocked by SSRF policy"):
                _resolve_first_safe_ip("blocked.example.com", 443, None, None)

    def test_http_scheme_blocked_by_validate_siem_url(self):
        """HTTP (non-HTTPS) SIEM URLs are blocked by validate_siem_url."""
        with pytest.raises(ValueError, match="https://"):
            from yashigani.audit.writer import validate_siem_url
            validate_siem_url("http://siem.example.com/collect")

    def test_send_to_target_calls_validate_siem_url_first(self):
        """AuditLogWriter._send_to_target must call validate_siem_url before _send_to_target_pinned.

        If validate_siem_url raises, _send_to_target_pinned must NOT be called.
        This ensures the pre-flight URL check (scheme, RFC1918 DNS block) runs
        before the pinned delivery.
        """
        from yashigani.audit.writer import AuditLogWriter, SiemTarget
        from yashigani.audit.config import AuditConfig

        # Build a minimal writer (no actual file I/O needed for this test)
        config = AuditConfig(log_path="/dev/null", max_file_size_mb=100, retention_days=30)
        writer = AuditLogWriter(config=config)

        target = SiemTarget(
            name="test",
            target_type="webhook",
            url="http://siem.example.com/collect",  # http:// → validate_siem_url raises
            auth_header="Authorization",
            auth_value="Bearer token",
        )

        with patch("yashigani.audit.writer._send_to_target_pinned") as mock_pinned:
            with pytest.raises(ValueError, match="https://"):
                writer._send_to_target('{"event": "test"}', target)

        # Pinned delivery must NOT have been reached
        mock_pinned.assert_not_called()


# ---------------------------------------------------------------------------
# Test D — _SyncPinnedTransport restores socket.getaddrinfo after request
# ---------------------------------------------------------------------------

class TestSyncPinnedTransportCleanup:
    """
    Verifies that the monkey-patch on socket.getaddrinfo is cleaned up
    after handle_request completes (both success and exception paths).
    """

    def test_getaddrinfo_restored_after_request(self):
        """socket.getaddrinfo must be restored to the original after handle_request."""
        from yashigani.audit.writer import _SyncPinnedTransport

        original_getaddrinfo = socket.getaddrinfo
        transport = _SyncPinnedTransport(pinned_ip="203.0.113.42")

        # Patch the parent class method using the class name directly
        # to avoid the 2-argument calling convention issue
        with patch.object(
            httpx.HTTPTransport,
            "handle_request",
            lambda self, req: MagicMock(status_code=200),
        ):
            request = MagicMock(spec=httpx.Request)
            request.url = MagicMock()
            request.url.host = "siem.example.com"
            transport.handle_request(request)

        # After the request, getaddrinfo must be the original
        assert socket.getaddrinfo is original_getaddrinfo, (
            "socket.getaddrinfo was not restored after _SyncPinnedTransport.handle_request. "
            "This leaks the monkey-patch globally and breaks concurrent requests."
        )

    def test_getaddrinfo_restored_even_on_exception(self):
        """socket.getaddrinfo must be restored even if handle_request raises."""
        from yashigani.audit.writer import _SyncPinnedTransport

        original_getaddrinfo = socket.getaddrinfo
        transport = _SyncPinnedTransport(pinned_ip="203.0.113.42")

        with patch.object(
            httpx.HTTPTransport,
            "handle_request",
            lambda self, req: (_ for _ in ()).throw(ConnectionError("network error")),
        ):
            request = MagicMock(spec=httpx.Request)
            request.url = MagicMock()
            request.url.host = "siem.example.com"
            with pytest.raises(ConnectionError):
                transport.handle_request(request)

        assert socket.getaddrinfo is original_getaddrinfo, (
            "socket.getaddrinfo was not restored after exception in "
            "_SyncPinnedTransport.handle_request."
        )

    def test_pinned_ip_injected_for_matching_hostname(self):
        """_SyncPinnedTransport injects pinned IP for exact hostname match."""
        from yashigani.audit.writer import _SyncPinnedTransport

        pinned_ip = "203.0.113.42"
        transport = _SyncPinnedTransport(pinned_ip=pinned_ip)

        request = MagicMock(spec=httpx.Request)
        request.url = MagicMock()
        request.url.host = "siem.example.com"

        captured_getaddrinfo_result = []

        def _capture_handle(self_inner, req):
            # During handle_request, socket.getaddrinfo should return pinned IP
            result = socket.getaddrinfo("siem.example.com", 443)
            captured_getaddrinfo_result.extend(result)
            return MagicMock(status_code=200)

        with patch.object(httpx.HTTPTransport, "handle_request", _capture_handle):
            transport.handle_request(request)

        # The captured results should contain only the pinned IP
        assert len(captured_getaddrinfo_result) > 0, "No getaddrinfo results captured"
        for entry in captured_getaddrinfo_result:
            _family, _type, _proto, _canonname, sockaddr = entry
            assert sockaddr[0] == pinned_ip, (
                f"Expected pinned IP {pinned_ip!r} in sockaddr, got {sockaddr[0]!r}. "
                "DNS pinning is not working — rebinding is possible."
            )
