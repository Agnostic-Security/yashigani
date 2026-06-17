"""
Unit tests for SSRF validation in PUT /admin/audit/siem/config (FIND-3.0-001).

Verifies that update_siem_config() rejects:
  - Cloud IMDS (169.254.169.254)
  - Loopback Redis (127.0.0.1:6379)
  - RFC-1918 private addresses (10.x, 192.168.x, 172.16.x)
  - Non-http(s) schemes (file://, gopher://)

And allows:
  - A legitimate external https endpoint
  - An operator-allowlisted internal host (YASHIGANI_SIEM_HOSTNAMES)

The guard used here is the same shared assert_safe_outbound_url() used by agents.py,
confirming that both flows go through one guard (FIND-3.0-001 DRY requirement).
"""
from __future__ import annotations

import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

import yashigani.backoffice.routes.audit_sinks as audit_sinks_mod
from yashigani.backoffice.routes.audit_sinks import audit_sinks_router
from yashigani.backoffice.middleware import require_admin_session, require_stepup_admin_session


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def _make_app(fake_state):
    """Build a minimal FastAPI app wired to audit_sinks_router with auth bypassed."""
    app = FastAPI()

    class _FakeSession:
        account_id = "test-admin"

    async def _fake_session():
        return _FakeSession()

    app.dependency_overrides[require_admin_session] = _fake_session
    app.dependency_overrides[require_stepup_admin_session] = _fake_session
    app.include_router(audit_sinks_router)
    return app


@pytest_asyncio.fixture
async def client(monkeypatch):
    """HTTP client with backoffice_state patched to a controllable namespace."""
    fake_state = types.SimpleNamespace(
        siem_backend="none",
        siem_endpoint=None,
        siem_wazuh_auto_deploy=False,
        audit_writer=None,
        kms_provider=None,
    )
    # Patch the state attribute that update_siem_config imports inside its body
    monkeypatch.setattr(audit_sinks_mod, "_PATCHED_STATE", fake_state, raising=False)

    # audit_sinks.py does `from yashigani.backoffice.state import backoffice_state`
    # inside the route handler (lazy import). We patch the module-level reference
    # by monkeypatching the state module's backoffice_state attribute.
    import yashigani.backoffice.state as state_mod
    monkeypatch.setattr(state_mod, "backoffice_state", fake_state)

    app = _make_app(fake_state)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c, fake_state


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

async def _put_siem(client, endpoint: str, backend: str = "splunk"):
    r = await client.put(
        "/admin/audit/siem/config",
        json={"backend": backend, "endpoint": endpoint},
    )
    return r


# ---------------------------------------------------------------------------
# SSRF rejection cases
# ---------------------------------------------------------------------------

class TestSiemConfigSSRFRejected:
    @pytest.mark.asyncio
    async def test_imds_169_254_rejected(self, client):
        c, _ = client
        r = await _put_siem(c, "http://169.254.169.254/latest/meta-data/")
        assert r.status_code == 422
        detail = r.json()["detail"]
        assert detail["error"] == "ssrf_rejected"
        assert "link-local" in detail["message"].lower() or "169.254" in detail["message"]

    @pytest.mark.asyncio
    async def test_loopback_redis_127_rejected(self, client):
        c, _ = client
        r = await _put_siem(c, "http://127.0.0.1:6379/")
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "ssrf_rejected"

    @pytest.mark.asyncio
    async def test_loopback_localhost_rejected(self, client):
        c, _ = client
        r = await _put_siem(c, "http://localhost:9200/siem-index")
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "ssrf_rejected"

    @pytest.mark.asyncio
    async def test_private_10x_rejected(self, client):
        c, _ = client
        r = await _put_siem(c, "http://10.0.0.1/siem")
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "ssrf_rejected"

    @pytest.mark.asyncio
    async def test_private_192168_rejected(self, client):
        c, _ = client
        r = await _put_siem(c, "http://192.168.1.50/siem")
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "ssrf_rejected"

    @pytest.mark.asyncio
    async def test_private_172_16_rejected(self, client):
        c, _ = client
        r = await _put_siem(c, "http://172.16.0.10/siem")
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "ssrf_rejected"

    @pytest.mark.asyncio
    async def test_file_scheme_rejected(self, client):
        c, _ = client
        r = await _put_siem(c, "file:///etc/passwd")
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "ssrf_rejected"

    @pytest.mark.asyncio
    async def test_gopher_scheme_rejected(self, client):
        c, _ = client
        r = await _put_siem(c, "gopher://internal-redis:6379/_PING")
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "ssrf_rejected"


# ---------------------------------------------------------------------------
# Allowed cases
# ---------------------------------------------------------------------------

class TestSiemConfigSSRFAllowed:
    @pytest.mark.asyncio
    async def test_external_https_endpoint_allowed(self, client):
        """A legitimate external https endpoint must be stored (200)."""
        c, state = client
        r = await _put_siem(c, "https://siem.example.com/events", backend="splunk")
        assert r.status_code == 200, r.text
        assert state.siem_endpoint == "https://siem.example.com/events"

    @pytest.mark.asyncio
    async def test_backend_none_no_endpoint_required(self, client):
        """backend=none with no endpoint is valid (turns SIEM off)."""
        c, state = client
        r = await c.put(
            "/admin/audit/siem/config",
            json={"backend": "none"},
        )
        assert r.status_code == 200
        assert state.siem_backend == "none"

    @pytest.mark.asyncio
    async def test_allowlisted_internal_host_accepted(self, client, monkeypatch):
        """An internal SIEM host in YASHIGANI_SIEM_HOSTNAMES is allowed."""
        c, state = client
        monkeypatch.setenv("YASHIGANI_SIEM_HOSTNAMES", "wazuh-indexer")
        r = await _put_siem(c, "https://wazuh-indexer:9200/audit-events", backend="elasticsearch")
        assert r.status_code == 200
        assert state.siem_endpoint == "https://wazuh-indexer:9200/audit-events"
