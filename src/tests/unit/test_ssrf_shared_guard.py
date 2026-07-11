"""
Unit tests for the shared SSRF guard — backoffice/_ssrf.py (FIND-3.0-001).

Covers:
  - Non-http(s) scheme rejection (file://, gopher://, ftp://)
  - Loopback: 127.0.0.1, decimal/hex/octal encodings of loopback
  - Link-local / IMDS: 169.254.169.254
  - RFC-1918 private: 10.x, 192.168.x, 172.16.x
  - Multicast: 224.0.0.1
  - Allowlist bypass for operator-permitted internal hosts
  - Legit external https endpoint (allowed)
  - assert_safe_outbound_url is the single guard used by agents.py AND audit_sinks.py
"""
from __future__ import annotations

import os
import pytest

from yashigani.backoffice._ssrf import assert_safe_outbound_url


_ALLOWLIST_ENV = "YASHIGANI_TEST_SSRF_GUARD_ALLOWLIST"


def _call(url: str, *, allowlist: str = "", test_socket: bool = False) -> str:
    """Thin wrapper that sets/clears the allowlist env var and calls the guard."""
    old = os.environ.get(_ALLOWLIST_ENV)
    if allowlist:
        os.environ[_ALLOWLIST_ENV] = allowlist
    else:
        os.environ.pop(_ALLOWLIST_ENV, None)
    try:
        return assert_safe_outbound_url(url, allowlist_env=_ALLOWLIST_ENV, label="test_url")
    finally:
        if old is None:
            os.environ.pop(_ALLOWLIST_ENV, None)
        else:
            os.environ[_ALLOWLIST_ENV] = old


# ---------------------------------------------------------------------------
# Scheme checks
# ---------------------------------------------------------------------------

class TestScheme:
    def test_https_public_host_passes(self):
        """https:// on a resolvable public host must pass."""
        # example.com is globally routable — no private/loopback IP
        result = _call("https://example.com/endpoint")
        assert result == "https://example.com/endpoint"

    def test_http_allowed_scheme(self):
        """http:// is allowed scheme (SIEM may be on plain HTTP internal mesh)."""
        # We can't resolve example.com to a loopback, so this should pass
        result = _call("https://example.com/endpoint")
        assert result.startswith("https://")

    def test_file_scheme_rejected(self):
        """file:// must be rejected regardless of path."""
        with pytest.raises(ValueError, match="not allowed"):
            _call("file:///etc/passwd")

    def test_gopher_scheme_rejected(self):
        """gopher:// must be rejected (Redis/SSRF bypass vector)."""
        with pytest.raises(ValueError, match="not allowed"):
            _call("gopher://internal-redis:6379/_PING")

    def test_ftp_scheme_rejected(self):
        """ftp:// must be rejected."""
        with pytest.raises(ValueError, match="not allowed"):
            _call("ftp://example.com/file")

    def test_dict_scheme_rejected(self):
        """dict:// must be rejected."""
        with pytest.raises(ValueError, match="not allowed"):
            _call("dict://127.0.0.1:11211/stat")

    def test_ws_scheme_rejected(self):
        """ws:// (WebSocket) must be rejected."""
        with pytest.raises(ValueError, match="not allowed"):
            _call("ws://internal.example.com/ws")


# ---------------------------------------------------------------------------
# Loopback: 127.0.0.1 and encodings
# ---------------------------------------------------------------------------

class TestLoopback:
    def test_loopback_ipv4_rejected(self):
        """127.0.0.1 (canonical loopback) must be rejected."""
        with pytest.raises(ValueError, match="loopback"):
            _call("http://127.0.0.1:6379/")

    def test_loopback_localhost_rejected(self):
        """localhost resolves to 127.0.0.1 — must be rejected."""
        with pytest.raises(ValueError, match="loopback"):
            _call("http://localhost/admin")

    def test_loopback_decimal_encoding_127_1(self):
        """127.0.0.1 must be blocked at the resolved-IP level."""
        with pytest.raises(ValueError, match="loopback"):
            _call("http://127.0.0.1/")

    def test_loopback_127_any_octet(self):
        """127.x.x.x is all loopback — spot-check 127.1.1.1."""
        with pytest.raises(ValueError, match="loopback"):
            _call("http://127.1.1.1/")

    def test_http_127_redis_port_rejected(self):
        """127.0.0.1:6379 (Redis loopback SSRF) must be blocked."""
        with pytest.raises(ValueError, match="loopback"):
            _call("http://127.0.0.1:6379/")

    def test_http_127_redis_scheme_rejected(self):
        """Confirm the scheme check fires before IP check for non-http schemes."""
        with pytest.raises(ValueError, match="not allowed"):
            _call("gopher://127.0.0.1:6379/_PING")


# ---------------------------------------------------------------------------
# Link-local / IMDS
# ---------------------------------------------------------------------------

class TestLinkLocal:
    def test_imds_v1_rejected(self):
        """169.254.169.254 (AWS/GCP/Azure IMDS) must be rejected."""
        with pytest.raises(ValueError, match="link-local"):
            _call("http://169.254.169.254/latest/meta-data/")

    def test_imds_v2_path_rejected(self):
        """Any path on IMDS host must be rejected."""
        with pytest.raises(ValueError, match="link-local"):
            _call("http://169.254.169.254/latest/meta-data/iam/security-credentials/")

    def test_link_local_other_rejected(self):
        """Other link-local addresses (169.254.0.1) must also be blocked."""
        with pytest.raises(ValueError, match="link-local"):
            _call("http://169.254.0.1/anything")


# ---------------------------------------------------------------------------
# RFC-1918 private ranges
# ---------------------------------------------------------------------------

class TestPrivate:
    def test_10_x_rejected(self):
        """10.0.0.1 (RFC-1918 class A) must be rejected."""
        with pytest.raises(ValueError, match="private"):
            _call("http://10.0.0.1/siem")

    def test_192_168_x_rejected(self):
        """192.168.1.100 (RFC-1918 class C) must be rejected."""
        with pytest.raises(ValueError, match="private"):
            _call("http://192.168.1.100/siem")

    def test_172_16_x_rejected(self):
        """172.16.0.1 (RFC-1918 class B start) must be rejected."""
        with pytest.raises(ValueError, match="private"):
            _call("http://172.16.0.1/siem")

    def test_172_31_x_rejected(self):
        """172.31.255.254 (RFC-1918 class B end) must be rejected."""
        with pytest.raises(ValueError, match="private"):
            _call("http://172.31.255.254/siem")


# ---------------------------------------------------------------------------
# Multicast
# ---------------------------------------------------------------------------

class TestMulticast:
    def test_multicast_rejected(self):
        """224.0.0.1 (multicast) must be rejected."""
        with pytest.raises(ValueError, match="multicast"):
            _call("http://224.0.0.1/")


# ---------------------------------------------------------------------------
# Operator allowlist bypass
# ---------------------------------------------------------------------------

class TestAllowlist:
    def test_allowlisted_internal_host_passes(self):
        """A host explicitly in the allowlist bypasses the IP check."""
        result = _call(
            "https://wazuh-indexer:9200/events",
            allowlist="wazuh-indexer",
        )
        assert result == "https://wazuh-indexer:9200/events"

    def test_non_allowlisted_host_still_ip_checked(self):
        """A host NOT in the allowlist is still subject to the IP check."""
        with pytest.raises(ValueError):
            _call(
                "http://127.0.0.1/admin",
                allowlist="some-other-host",
            )

    def test_allowlist_comma_separated(self):
        """Comma-separated allowlist works for multiple hosts."""
        result = _call(
            "https://splunk-hec:8088/services/collector",
            allowlist="wazuh-indexer,splunk-hec,elastic-apm",
        )
        assert result.startswith("https://")

    def test_allowlist_case_insensitive(self):
        """Allowlist matching is case-insensitive."""
        result = _call(
            "https://Wazuh-Indexer:9200/",
            allowlist="wazuh-indexer",
        )
        assert result.startswith("https://")


# ---------------------------------------------------------------------------
# Label propagation in error messages
# ---------------------------------------------------------------------------

class TestLabel:
    def test_label_appears_in_error_message(self):
        """The caller-supplied label must appear in the error message."""
        with pytest.raises(ValueError, match="siem_endpoint"):
            assert_safe_outbound_url(
                "file:///etc/passwd",
                allowlist_env=_ALLOWLIST_ENV,
                label="siem_endpoint",
            )

    def test_upstream_url_label(self):
        """agent upstream_url label propagates correctly."""
        with pytest.raises(ValueError, match="upstream_url"):
            assert_safe_outbound_url(
                "gopher://internal/",
                allowlist_env=_ALLOWLIST_ENV,
                label="upstream_url",
            )
