"""
Unit tests for V232-CSCAN-01b — SSRF guard on alert webhook URLs.

Covers:
  - IMDS literal (169.254.169.254)
  - RFC1918 literals (10.x, 192.168.x, 172.16.x)
  - Loopback (127.0.0.1, ::1)
  - Link-local (169.254.x.x, fe80::)
  - DNS that resolves to private (mocked via patch)
  - http:// scheme (wrong scheme)
  - https://hooks.slack.com.evil.com/ (suffix-not-equal)
  - https://attacker.com/ (wrong host not in allowlist)
  - https://user:pass@hooks.slack.com/ (userinfo in netloc)
  - Empty URL
  - Positive: https://hooks.slack.com/services/T.../B.../...

Last updated: 2026-05-03T00:00:00+01:00
"""
from __future__ import annotations

import socket
from unittest.mock import patch, MagicMock

import pytest

from yashigani.alerts._url_guard import (
    WebhookUrlForbidden,
    assert_no_imds_or_loopback_url,
    assert_webhook_url,
)

_SLACK_HOSTS = {"hooks.slack.com"}
_TEAMS_HOSTS = {"webhook.office.com", "outlook.office.com", "outlook.office365.com", "logic.azure.com"}

# A fake valid Slack webhook URL we use for positive tests.
_VALID_SLACK = "https://hooks.slack.com/services/TXXXXXXX/BXXXXXXX/xxxxxxxxxxxxxxxxxxxxxxxx"


# ---------------------------------------------------------------------------
# Helper: mock DNS to return a specific address
# ---------------------------------------------------------------------------

def _mock_getaddrinfo(addr: str):
    """Return a getaddrinfo-shaped list resolving to the given IP address."""
    return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (addr, 0))]


# ---------------------------------------------------------------------------
# Scheme checks
# ---------------------------------------------------------------------------

class TestSchemeGuard:
    def test_rejects_http_scheme(self):
        url = "http://hooks.slack.com/services/T/B/x"
        with pytest.raises(WebhookUrlForbidden) as exc_info:
            assert_webhook_url(url, allowed_hosts=_SLACK_HOSTS)
        assert "scheme_not_https" in exc_info.value.reason

    def test_rejects_ftp_scheme(self):
        url = "ftp://hooks.slack.com/services/T/B/x"
        with pytest.raises(WebhookUrlForbidden) as exc_info:
            assert_webhook_url(url, allowed_hosts=_SLACK_HOSTS)
        assert "scheme_not_https" in exc_info.value.reason

    def test_rejects_empty_scheme(self):
        url = "//hooks.slack.com/services/T/B/x"
        with pytest.raises(WebhookUrlForbidden):
            assert_webhook_url(url, allowed_hosts=_SLACK_HOSTS)

    def test_rejects_empty_url(self):
        with pytest.raises(WebhookUrlForbidden) as exc_info:
            assert_webhook_url("", allowed_hosts=_SLACK_HOSTS)
        assert "empty_url" in exc_info.value.reason


# ---------------------------------------------------------------------------
# Userinfo in netloc
# ---------------------------------------------------------------------------

class TestUserinfoGuard:
    def test_rejects_user_pass_at_host(self):
        url = "https://user:pass@hooks.slack.com/services/T/B/x"
        with patch("socket.getaddrinfo", return_value=_mock_getaddrinfo("34.0.0.1")):
            with pytest.raises(WebhookUrlForbidden) as exc_info:
                assert_webhook_url(url, allowed_hosts=_SLACK_HOSTS)
        assert "userinfo_in_netloc" in exc_info.value.reason

    def test_rejects_user_only_at_host(self):
        url = "https://user@hooks.slack.com/services/T/B/x"
        with patch("socket.getaddrinfo", return_value=_mock_getaddrinfo("34.0.0.1")):
            with pytest.raises(WebhookUrlForbidden) as exc_info:
                assert_webhook_url(url, allowed_hosts=_SLACK_HOSTS)
        assert "userinfo_in_netloc" in exc_info.value.reason


# ---------------------------------------------------------------------------
# IP literal hostnames
# ---------------------------------------------------------------------------

class TestIpLiteralGuard:
    def test_rejects_imds_ipv4_literal(self):
        url = "https://169.254.169.254/latest/meta-data/iam/security-credentials/"
        with pytest.raises(WebhookUrlForbidden) as exc_info:
            assert_webhook_url(url, allowed_hosts=_SLACK_HOSTS)
        assert "ip_literal_hostname" in exc_info.value.reason

    def test_rejects_loopback_127_literal(self):
        url = "https://127.0.0.1/hook"
        with pytest.raises(WebhookUrlForbidden) as exc_info:
            assert_webhook_url(url, allowed_hosts=_SLACK_HOSTS)
        assert "ip_literal_hostname" in exc_info.value.reason

    def test_rejects_ipv6_loopback_literal(self):
        url = "https://[::1]/hook"
        with pytest.raises(WebhookUrlForbidden) as exc_info:
            assert_webhook_url(url, allowed_hosts=_SLACK_HOSTS)
        assert "ip_literal_hostname" in exc_info.value.reason

    def test_rejects_rfc1918_10_literal(self):
        url = "https://10.0.0.1/hook"
        with pytest.raises(WebhookUrlForbidden) as exc_info:
            assert_webhook_url(url, allowed_hosts=_SLACK_HOSTS)
        assert "ip_literal_hostname" in exc_info.value.reason

    def test_rejects_rfc1918_192_168_literal(self):
        url = "https://192.168.1.100/hook"
        with pytest.raises(WebhookUrlForbidden) as exc_info:
            assert_webhook_url(url, allowed_hosts=_SLACK_HOSTS)
        assert "ip_literal_hostname" in exc_info.value.reason

    def test_rejects_rfc1918_172_16_literal(self):
        url = "https://172.16.0.1/hook"
        with pytest.raises(WebhookUrlForbidden) as exc_info:
            assert_webhook_url(url, allowed_hosts=_SLACK_HOSTS)
        assert "ip_literal_hostname" in exc_info.value.reason

    def test_rejects_link_local_169_literal(self):
        url = "https://169.254.0.1/hook"
        with pytest.raises(WebhookUrlForbidden) as exc_info:
            assert_webhook_url(url, allowed_hosts=_SLACK_HOSTS)
        assert "ip_literal_hostname" in exc_info.value.reason


# ---------------------------------------------------------------------------
# DNS resolves to private/reserved (mocked)
# ---------------------------------------------------------------------------

class TestDnsResolveGuard:
    def test_rejects_hostname_resolving_to_loopback(self):
        """A hostname that resolves to 127.0.0.1 must be blocked."""
        with patch("socket.getaddrinfo", return_value=_mock_getaddrinfo("127.0.0.1")):
            with pytest.raises(WebhookUrlForbidden) as exc_info:
                assert_webhook_url(
                    "https://hooks.slack.com/services/T/B/x",
                    allowed_hosts=_SLACK_HOSTS,
                )
        assert "resolves_to_private_or_reserved" in exc_info.value.reason

    def test_rejects_hostname_resolving_to_imds_ip(self):
        """A hostname that resolves to 169.254.169.254 must be blocked (DNS rebind)."""
        with patch("socket.getaddrinfo", return_value=_mock_getaddrinfo("169.254.169.254")):
            with pytest.raises(WebhookUrlForbidden) as exc_info:
                assert_webhook_url(
                    "https://hooks.slack.com/services/T/B/x",
                    allowed_hosts=_SLACK_HOSTS,
                )
        assert "resolves_to_private_or_reserved" in exc_info.value.reason

    def test_rejects_hostname_resolving_to_rfc1918(self):
        """A hostname that resolves to 10.0.0.1 must be blocked."""
        with patch("socket.getaddrinfo", return_value=_mock_getaddrinfo("10.0.0.1")):
            with pytest.raises(WebhookUrlForbidden) as exc_info:
                assert_webhook_url(
                    "https://hooks.slack.com/services/T/B/x",
                    allowed_hosts=_SLACK_HOSTS,
                )
        assert "resolves_to_private_or_reserved" in exc_info.value.reason

    def test_rejects_if_any_resolved_ip_is_private(self):
        """If ANY resolved IP is private, the URL must be blocked (not just first)."""
        # One public IP + one private IP — must still block
        multi_addr = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("34.0.0.1", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.1", 0)),
        ]
        with patch("socket.getaddrinfo", return_value=multi_addr):
            with pytest.raises(WebhookUrlForbidden) as exc_info:
                assert_webhook_url(
                    "https://hooks.slack.com/services/T/B/x",
                    allowed_hosts=_SLACK_HOSTS,
                )
        assert "resolves_to_private_or_reserved" in exc_info.value.reason

    def test_rejects_on_dns_failure(self):
        """If DNS fails to resolve, the URL must be blocked (fail closed)."""
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("NXDOMAIN")):
            with pytest.raises(WebhookUrlForbidden) as exc_info:
                assert_webhook_url(
                    "https://hooks.slack.com/services/T/B/x",
                    allowed_hosts=_SLACK_HOSTS,
                )
        assert "dns_resolution_failed" in exc_info.value.reason


# ---------------------------------------------------------------------------
# Host allowlist checks
# ---------------------------------------------------------------------------

class TestHostAllowlistGuard:
    def test_rejects_wrong_host(self):
        """An out-of-allowlist hostname must be rejected."""
        with patch("socket.getaddrinfo", return_value=_mock_getaddrinfo("34.0.0.1")):
            with pytest.raises(WebhookUrlForbidden) as exc_info:
                assert_webhook_url(
                    "https://attacker.com/exfil",
                    allowed_hosts=_SLACK_HOSTS,
                )
        assert "host_not_in_allowlist" in exc_info.value.reason

    def test_rejects_suffix_trick_not_subdomain(self):
        """hooks.slack.com.evil.com is NOT a subdomain of hooks.slack.com."""
        with patch("socket.getaddrinfo", return_value=_mock_getaddrinfo("34.0.0.1")):
            with pytest.raises(WebhookUrlForbidden) as exc_info:
                assert_webhook_url(
                    "https://hooks.slack.com.evil.com/hook",
                    allowed_hosts=_SLACK_HOSTS,
                )
        assert "host_not_in_allowlist" in exc_info.value.reason

    def test_rejects_allowlist_as_substring(self):
        """xhooks.slack.com must not match hooks.slack.com."""
        with patch("socket.getaddrinfo", return_value=_mock_getaddrinfo("34.0.0.1")):
            with pytest.raises(WebhookUrlForbidden) as exc_info:
                assert_webhook_url(
                    "https://xhooks.slack.com/hook",
                    allowed_hosts=_SLACK_HOSTS,
                )
        assert "host_not_in_allowlist" in exc_info.value.reason

    def test_accepts_exact_allowlist_match(self):
        """hooks.slack.com exactly must be accepted (given safe resolution)."""
        with patch("socket.getaddrinfo", return_value=_mock_getaddrinfo("34.0.0.1")):
            # Must not raise
            assert_webhook_url(_VALID_SLACK, allowed_hosts=_SLACK_HOSTS)

    def test_accepts_subdomain_of_allowlist_entry(self):
        """foo.webhook.office.com is a valid subdomain of webhook.office.com."""
        with patch("socket.getaddrinfo", return_value=_mock_getaddrinfo("52.0.0.1")):
            assert_webhook_url(
                "https://foo.webhook.office.com/hook",
                allowed_hosts=_TEAMS_HOSTS,
            )


# ---------------------------------------------------------------------------
# Positive path
# ---------------------------------------------------------------------------

class TestPositivePath:
    def test_accepts_valid_slack_webhook(self):
        """A well-formed Slack webhook URL with a public IP must be accepted."""
        with patch("socket.getaddrinfo", return_value=_mock_getaddrinfo("34.0.0.1")):
            # Must not raise
            assert_webhook_url(_VALID_SLACK, allowed_hosts=_SLACK_HOSTS)

    def test_accepts_valid_teams_webhook(self):
        """A well-formed Teams webhook URL must be accepted."""
        url = "https://webhook.office.com/webhookb2/xxx@xxx/IncomingWebhook/xxx/xxx"
        with patch("socket.getaddrinfo", return_value=_mock_getaddrinfo("52.0.0.1")):
            assert_webhook_url(url, allowed_hosts=_TEAMS_HOSTS)

    def test_exception_carries_reason_and_url(self):
        """WebhookUrlForbidden.reason and .url are populated."""
        url = "http://hooks.slack.com/services/T/B/x"
        with pytest.raises(WebhookUrlForbidden) as exc_info:
            assert_webhook_url(url, allowed_hosts=_SLACK_HOSTS)
        exc = exc_info.value
        assert exc.url == url
        assert exc.reason  # non-empty reason


# ---------------------------------------------------------------------------
# SlackSink/TeamsSink constructor guard integration
# ---------------------------------------------------------------------------

class TestSinkConstructorGuard:
    """Confirm the sinks raise WebhookUrlForbidden if given a bad URL."""

    def test_slack_sink_rejects_http_url(self):
        from yashigani.alerts.slack_sink import SlackSink
        with pytest.raises(WebhookUrlForbidden):
            SlackSink("http://169.254.169.254/imds")

    def test_teams_sink_rejects_http_url(self):
        from yashigani.alerts.teams_sink import TeamsSink
        with pytest.raises(WebhookUrlForbidden):
            TeamsSink("http://169.254.169.254/imds")

    def test_slack_sink_rejects_wrong_host(self):
        from yashigani.alerts.slack_sink import SlackSink
        with pytest.raises(WebhookUrlForbidden):
            SlackSink("https://evil.com/hook")

    def test_teams_sink_rejects_wrong_host(self):
        from yashigani.alerts.teams_sink import TeamsSink
        with pytest.raises(WebhookUrlForbidden):
            TeamsSink("https://evil.com/hook")


# ---------------------------------------------------------------------------
# assert_no_imds_or_loopback_url — codescan #1 (mustui triage 2026-07-20)
# mcp_servers.py:464 SSRF. Narrower guard than assert_webhook_url(): no host
# allowlist, http+https both allowed, RFC-1918/private-mesh hosts ACCEPTED —
# only IMDS/loopback/link-local/unspecified/multicast + the AWS IMDSv6 ULA
# address + GCP magic hostnames are blocked. Laura's PoC payload set:
# testing_runs/yashigani/codescan-triage-mustui-20260720/poc/ssrf_mcp_import_poc.py
# ---------------------------------------------------------------------------

class TestImdsLoopbackGuardScheme:
    def test_rejects_non_http_scheme(self):
        with pytest.raises(WebhookUrlForbidden) as exc_info:
            assert_no_imds_or_loopback_url("gopher://internal-redis:6379/_PING")
        assert "scheme_not_http_or_https" in exc_info.value.reason

    def test_accepts_http_scheme(self):
        # http:// (not just https://) is allowed for this guard variant —
        # MCP servers commonly run plain HTTP inside the compose network.
        with patch("socket.getaddrinfo", return_value=_mock_getaddrinfo("172.20.0.5")):
            assert_no_imds_or_loopback_url("http://demo-mcp:8000")

    def test_rejects_empty_url(self):
        with pytest.raises(WebhookUrlForbidden) as exc_info:
            assert_no_imds_or_loopback_url("")
        assert "empty_url" in exc_info.value.reason

    def test_rejects_userinfo_in_netloc(self):
        with pytest.raises(WebhookUrlForbidden) as exc_info:
            assert_no_imds_or_loopback_url("http://admin:pw@internal-mcp:8000/")
        assert "userinfo_in_netloc" in exc_info.value.reason


class TestImdsLoopbackGuardBlocksImdsAndLoopback:
    """Laura's PoC payload set — every one must now be rejected."""

    def test_rejects_aws_imds_v1(self):
        with pytest.raises(WebhookUrlForbidden) as exc_info:
            assert_no_imds_or_loopback_url(
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
            )
        assert "imds_or_loopback_ip_literal" in exc_info.value.reason

    def test_rejects_ecs_task_credentials_endpoint(self):
        with pytest.raises(WebhookUrlForbidden) as exc_info:
            assert_no_imds_or_loopback_url("http://169.254.170.2/v2/credentials/xxx")
        assert "imds_or_loopback_ip_literal" in exc_info.value.reason

    def test_rejects_aws_imds_v6_ula_literal(self):
        with pytest.raises(WebhookUrlForbidden) as exc_info:
            assert_no_imds_or_loopback_url("http://[fd00:ec2::254]/latest/meta-data/")
        assert "imds_or_loopback_ip_literal" in exc_info.value.reason

    def test_rejects_gcp_metadata_hostname(self):
        with pytest.raises(WebhookUrlForbidden) as exc_info:
            assert_no_imds_or_loopback_url("http://metadata.google.internal/computeMetadata/v1/")
        assert "cloud_metadata_hostname" in exc_info.value.reason

    def test_rejects_gcp_metadata_bare_hostname(self):
        with pytest.raises(WebhookUrlForbidden) as exc_info:
            assert_no_imds_or_loopback_url("http://metadata/computeMetadata/v1/")
        assert "cloud_metadata_hostname" in exc_info.value.reason

    def test_rejects_loopback_ipv4_with_port(self):
        with pytest.raises(WebhookUrlForbidden) as exc_info:
            assert_no_imds_or_loopback_url("http://127.0.0.1:8181/v1/policies")
        assert "imds_or_loopback_ip_literal" in exc_info.value.reason

    def test_rejects_ipv6_loopback_literal(self):
        with pytest.raises(WebhookUrlForbidden) as exc_info:
            assert_no_imds_or_loopback_url("http://[::1]:8000/")
        assert "imds_or_loopback_ip_literal" in exc_info.value.reason

    def test_rejects_link_local_ip_literal(self):
        with pytest.raises(WebhookUrlForbidden) as exc_info:
            assert_no_imds_or_loopback_url("http://169.254.0.1/anything")
        assert "imds_or_loopback_ip_literal" in exc_info.value.reason

    def test_rejects_hostname_resolving_to_loopback(self):
        with patch("socket.getaddrinfo", return_value=_mock_getaddrinfo("127.0.0.1")):
            with pytest.raises(WebhookUrlForbidden) as exc_info:
                assert_no_imds_or_loopback_url("http://sneaky-internal-host/")
        assert "resolves_to_imds_or_loopback" in exc_info.value.reason

    def test_rejects_hostname_resolving_to_imds(self):
        with patch("socket.getaddrinfo", return_value=_mock_getaddrinfo("169.254.169.254")):
            with pytest.raises(WebhookUrlForbidden) as exc_info:
                assert_no_imds_or_loopback_url("http://sneaky-internal-host/")
        assert "resolves_to_imds_or_loopback" in exc_info.value.reason

    def test_rejects_on_dns_failure(self):
        """Unresolvable hostname is rejected (fail closed) — matches
        assert_webhook_url() and backoffice/_ssrf.assert_safe_outbound_url()."""
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("NXDOMAIN")):
            with pytest.raises(WebhookUrlForbidden) as exc_info:
                assert_no_imds_or_loopback_url("http://does-not-resolve.invalid/")
        assert "dns_resolution_failed" in exc_info.value.reason


class TestImdsLoopbackGuardAllowsInternalMesh:
    """The whole point of this guard variant: legitimate internal MCP
    upstreams (RFC-1918/private-mesh, by hostname or IP literal) must NOT be
    blocked — only the IMDS/loopback special cases are."""

    def test_accepts_compose_dns_hostname_resolving_to_private_ip(self):
        # e.g. populate-demo.py's "http://demo-mcp:8000" import.
        with patch("socket.getaddrinfo", return_value=_mock_getaddrinfo("172.20.0.5")):
            assert_no_imds_or_loopback_url("http://demo-mcp:8000")

    def test_accepts_rfc1918_ip_literal_10(self):
        assert_no_imds_or_loopback_url("http://10.0.4.12:9000/mcp")

    def test_accepts_rfc1918_ip_literal_192_168(self):
        assert_no_imds_or_loopback_url("http://192.168.1.50:8000/")

    def test_accepts_rfc1918_ip_literal_172_16(self):
        assert_no_imds_or_loopback_url("http://172.16.4.4:8000/")

    def test_accepts_public_https_host(self):
        with patch("socket.getaddrinfo", return_value=_mock_getaddrinfo("34.0.0.1")):
            assert_no_imds_or_loopback_url("https://mcp.example.com/tools")

    def test_accepts_langflow_letta_openclaw_style_compose_hosts(self):
        """Structural regression: the exact three internal upstream_url values
        used by populate-demo.py must all pass."""
        with patch("socket.getaddrinfo", return_value=_mock_getaddrinfo("172.20.0.6")):
            assert_no_imds_or_loopback_url("http://langflow:7860")
            assert_no_imds_or_loopback_url("http://letta:8283")
            assert_no_imds_or_loopback_url("http://openclaw:18789")
