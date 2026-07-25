"""
Regression test — codescan #1 (mustui triage 2026-07-20), PoC-proven real
finding: py/full-ssrf, backoffice/routes/mcp_servers.py:464.

`ImportMcpServerRequest.upstream_url` was validated only for scheme+length;
`import_mcp_server()` then fired `httpx.AsyncClient().post(body.upstream_url,
...)` server-side with no host allowlist and no private/loopback/link-local/
IMDS block — a blind-SSRF / internal-recon primitive reachable by any admin
(or a forged/replayed step-up session) via POST /admin/mcp/servers/import.

Fix: assert_no_imds_or_loopback_url() (yashigani.alerts._url_guard) — a
purpose-built IMDS/loopback-only variant of the Slack/Teams webhook guard
(V232-CSCAN-01b) with NO vendor-domain allowlist and NO blanket RFC-1918
block — applied at BOTH the Pydantic field-validator (config-write time) and
immediately before the httpx call (defence-in-depth), mirroring the
slack_sink.py/teams_sink.py two-checkpoint pattern.

PoC reproduced: testing_runs/yashigani/codescan-triage-mustui-20260720/poc/ssrf_mcp_import_poc.py
"""
from __future__ import annotations

import inspect
import socket
from unittest.mock import patch

import pytest
from pydantic import ValidationError


# ---------------------------------------------------------------------------
# Field-validator (config-write time) — Laura's exact PoC payload set must
# now be rejected before ImportMcpServerRequest can even be constructed.
# ---------------------------------------------------------------------------

class TestUpstreamUrlFieldValidatorBlocksImdsAndLoopback:
    _BASE_KWARGS = dict(server_id="poc-test-mcp", topology="external_relay")

    @pytest.mark.parametrize(
        "payload",
        [
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",  # AWS IMDS
            "http://169.254.170.2/v2/credentials/xxx",  # ECS task creds
            "http://[fd00:ec2::254]/latest/meta-data/",  # AWS IMDSv6
            "http://metadata.google.internal/computeMetadata/v1/",  # GCP
            "http://127.0.0.1:8181/v1/policies",  # internal OPA (loopback)
        ],
    )
    def test_ssrf_poc_payloads_rejected(self, payload):
        from yashigani.backoffice.routes.mcp_servers import ImportMcpServerRequest

        with pytest.raises(ValidationError) as exc_info:
            ImportMcpServerRequest(upstream_url=payload, **self._BASE_KWARGS)
        assert "upstream_url rejected" in str(exc_info.value)

    def test_internal_mesh_hostname_still_allowed(self):
        """The demo-mode / operator-internal-MCP path must keep working:
        populate-demo.py imports 'http://demo-mcp:8000' — a compose-DNS
        hostname resolving to a private bridge-network IP, not IMDS/loopback."""
        from yashigani.backoffice.routes.mcp_servers import ImportMcpServerRequest

        with patch("socket.getaddrinfo", return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("172.20.0.5", 0))
        ]):
            req = ImportMcpServerRequest(
                upstream_url="http://demo-mcp:8000", **self._BASE_KWARGS
            )
        assert req.upstream_url == "http://demo-mcp:8000"

    def test_internal_mesh_ip_literal_still_allowed(self):
        """A private-mesh IP entered directly (no DNS involved) must pass —
        this guard variant does NOT blanket-block RFC-1918."""
        from yashigani.backoffice.routes.mcp_servers import ImportMcpServerRequest

        req = ImportMcpServerRequest(
            upstream_url="http://10.0.4.12:9000/mcp", **self._BASE_KWARGS
        )
        assert req.upstream_url == "http://10.0.4.12:9000/mcp"


# ---------------------------------------------------------------------------
# Structural guards — both checkpoints must exist in source (defence-in-depth
# pattern, same as slack_sink.py/teams_sink.py).
# ---------------------------------------------------------------------------

class TestBothCheckpointsWired:
    def test_field_validator_calls_guard(self):
        from yashigani.backoffice.routes import mcp_servers

        src = inspect.getsource(mcp_servers.ImportMcpServerRequest.validate_upstream_url)
        assert "assert_no_imds_or_loopback_url(v)" in src

    def test_route_revalidates_before_httpx_call(self):
        """Defence-in-depth: import_mcp_server() must call the guard again on
        body.upstream_url, and that call must appear BEFORE the httpx.AsyncClient
        POST in source order (last-line-of-defence even if the field-validator
        checkpoint is somehow bypassed)."""
        from yashigani.backoffice.routes import mcp_servers

        src = inspect.getsource(mcp_servers.import_mcp_server)
        assert "assert_no_imds_or_loopback_url(body.upstream_url)" in src
        guard_pos = src.index("assert_no_imds_or_loopback_url(body.upstream_url)")
        fetch_pos = src.index("client.post(")
        assert guard_pos < fetch_pos

    def test_guard_imported_from_shared_url_guard_module(self):
        from yashigani.backoffice.routes import mcp_servers
        from yashigani.alerts._url_guard import assert_no_imds_or_loopback_url

        assert mcp_servers.assert_no_imds_or_loopback_url is assert_no_imds_or_loopback_url
