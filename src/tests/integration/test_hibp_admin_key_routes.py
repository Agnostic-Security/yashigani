"""
Integration tests — HIBP admin-panel API key routes (v2.23.3, PR #59).

Tests the three endpoints:
  GET    /api/v1/admin/auth/hibp/status
  PUT    /api/v1/admin/auth/hibp/key
  DELETE /api/v1/admin/auth/hibp/key

All routes exercised via FastAPI TestClient with mocked:
  - AdminSession / StepUpAdminSession (via backoffice middleware)
  - AuthSettingsStore (no live DB needed)
  - AuditWriter

Security tests:
  - TOTP step-up required for PUT/DELETE (returns 401 without step-up)
  - Key value never in any API response body
  - Audit events written on PUT/DELETE

pytest -x src/tests/integration/test_hibp_admin_key_routes.py
"""
from __future__ import annotations

import json
import logging
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

try:
    from fastapi.testclient import TestClient
    _FASTAPI_AVAILABLE = True
except ImportError:
    _FASTAPI_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not _FASTAPI_AVAILABLE,
    reason="fastapi not installed",
)


# ---------------------------------------------------------------------------
# Minimal app fixture (avoids full lifespan init)
# ---------------------------------------------------------------------------

@pytest.fixture
def hibp_client():
    """
    Return a TestClient with just the HIBP routes mounted,
    bypassing the full backoffice lifespan (no DB, no advisory lock).
    """
    from fastapi import FastAPI
    from yashigani.backoffice.routes.hibp import router
    from yashigani.backoffice.state import backoffice_state

    app = FastAPI()
    app.include_router(router, prefix="/api/v1/admin/auth/hibp")

    # --- Mock session middleware ---
    # Patch require_admin_session and require_stepup_admin_session to inject
    # a minimal Session object; StepUp variant mimics the step-up gate.
    from yashigani.auth.session import Session
    fake_session = Session(
        token="testtoken",
        account_id="admin1",
        account_tier="admin",
        created_at=0.0,
        last_active_at=0.0,
        expires_at=9999999999.0,
        ip_prefix="127.0",
        last_totp_verified_at=None,
    )

    # Patch the dependency overrides
    from yashigani.backoffice import middleware as mw
    app.dependency_overrides[mw.require_admin_session] = lambda: fake_session

    # StepUpAdminSession: by default, simulate step-up present
    _stepup_ok = {"ok": True}

    def _require_stepup():
        if not _stepup_ok["ok"]:
            from yashigani.auth.stepup import StepUpRequired
            raise StepUpRequired()
        return fake_session

    app.dependency_overrides[mw.require_stepup_admin_session] = _require_stepup

    # --- Mock store in state ---
    store = AsyncMock()
    store.get_setting = AsyncMock(return_value="")
    store.get_metadata = AsyncMock(return_value=None)
    store.set_setting = AsyncMock(return_value=None)
    backoffice_state.auth_settings_store = store

    # --- Mock audit writer ---
    audit_writer = MagicMock()
    audit_writer.write = MagicMock()
    backoffice_state.audit_writer = audit_writer

    client = TestClient(app, raise_server_exceptions=True)
    yield client, store, audit_writer, _stepup_ok, fake_session

    # Cleanup
    backoffice_state.auth_settings_store = None
    backoffice_state.audit_writer = None
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /status
# ---------------------------------------------------------------------------

class TestHibpStatusEndpoint:
    def test_status_not_configured(self, hibp_client, monkeypatch):
        client, store, aw, stepup, sess = hibp_client
        monkeypatch.delenv("YASHIGANI_HIBP_API_KEY", raising=False)
        store.get_setting = AsyncMock(return_value="")

        resp = client.get("/api/v1/admin/auth/hibp/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["configured"] is False
        assert data["source"] == "none"
        assert data["masked_value"] is None

    def test_status_admin_panel_configured(self, hibp_client, monkeypatch):
        client, store, aw, stepup, sess = hibp_client
        monkeypatch.delenv("YASHIGANI_HIBP_API_KEY", raising=False)
        store.get_setting = AsyncMock(return_value="mykey-1234567890ab")
        store.get_metadata = AsyncMock(return_value={
            "updated_at": "2026-05-07T01:00:00+00:00",
            "updated_by": "admin1",
        })

        resp = client.get("/api/v1/admin/auth/hibp/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["configured"] is True
        assert data["source"] == "admin_panel"
        assert data["masked_value"] is not None
        # Full key must not appear in response
        assert "mykey-1234567890ab" not in json.dumps(data)

    def test_status_env_var_configured(self, hibp_client, monkeypatch):
        client, store, aw, stepup, sess = hibp_client
        monkeypatch.setenv("YASHIGANI_HIBP_API_KEY", "env-key-abcd12345678")
        store.get_setting = AsyncMock(return_value="")
        store.get_metadata = AsyncMock(return_value=None)

        resp = client.get("/api/v1/admin/auth/hibp/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["configured"] is True
        assert data["source"] == "env_var"
        # Full env var key must not appear
        assert "env-key-abcd12345678" not in json.dumps(data)

    def test_status_full_key_never_in_response(self, hibp_client, monkeypatch):
        """Security invariant: full key never returned by any field."""
        client, store, aw, stepup, sess = hibp_client
        monkeypatch.delenv("YASHIGANI_HIBP_API_KEY", raising=False)
        secret = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        store.get_setting = AsyncMock(return_value=secret)
        store.get_metadata = AsyncMock(return_value={"updated_at": None, "updated_by": "admin1"})

        resp = client.get("/api/v1/admin/auth/hibp/status")
        assert resp.status_code == 200
        raw_body = resp.text
        assert secret not in raw_body, (
            f"SECURITY: full key found in API response body: {raw_body!r}"
        )


# ---------------------------------------------------------------------------
# PUT /key
# ---------------------------------------------------------------------------

class TestHibpSetKeyEndpoint:
    def test_put_key_success(self, hibp_client, monkeypatch):
        client, store, aw, stepup, sess = hibp_client
        monkeypatch.delenv("YASHIGANI_HIBP_API_KEY", raising=False)
        store.get_setting = AsyncMock(return_value="new-hibp-key-abcdef12")
        store.get_metadata = AsyncMock(return_value={
            "updated_at": "2026-05-07T01:00:00+00:00",
            "updated_by": "admin1",
        })

        resp = client.put(
            "/api/v1/admin/auth/hibp/key",
            json={"api_key": "new-hibp-key-abcdef12"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["hibp_key"]["configured"] is True

        # Store was called with the key
        store.set_setting.assert_called_once()
        call_args = store.set_setting.call_args
        assert call_args[0][0] == "hibp_api_key"
        assert call_args[0][1] == "new-hibp-key-abcdef12"

    def test_put_key_audit_event_written(self, hibp_client, monkeypatch):
        client, store, aw, stepup, sess = hibp_client
        monkeypatch.delenv("YASHIGANI_HIBP_API_KEY", raising=False)
        store.get_setting = AsyncMock(return_value="new-key-ab1234567890")
        store.get_metadata = AsyncMock(return_value={"updated_at": None, "updated_by": "admin1"})

        client.put(
            "/api/v1/admin/auth/hibp/key",
            json={"api_key": "new-key-ab1234567890"},
        )

        from yashigani.audit.schema import HibpApiKeyUpdatedEvent
        aw.write.assert_called_once()
        event = aw.write.call_args[0][0]
        assert isinstance(event, HibpApiKeyUpdatedEvent)
        assert event.admin_account == "admin1"
        # Full key must not be in the event
        assert "new-key-ab1234567890" not in event.masked_key_hint

    def test_put_key_invalid_format_422(self, hibp_client, monkeypatch):
        client, store, aw, stepup, sess = hibp_client
        resp = client.put(
            "/api/v1/admin/auth/hibp/key",
            json={"api_key": "bad key with spaces!"},
        )
        assert resp.status_code == 422
        store.set_setting.assert_not_called()

    def test_put_key_too_short_422(self, hibp_client):
        client, store, aw, stepup, sess = hibp_client
        resp = client.put(
            "/api/v1/admin/auth/hibp/key",
            json={"api_key": "abc"},
        )
        assert resp.status_code == 422

    def test_put_requires_stepup(self, hibp_client, monkeypatch):
        """PUT must return 401 step_up_required when step-up not present."""
        client, store, aw, stepup, sess = hibp_client
        stepup["ok"] = False  # disable step-up

        resp = client.put(
            "/api/v1/admin/auth/hibp/key",
            json={"api_key": "valid-key-12345678"},
        )
        assert resp.status_code == 401
        body = resp.json()
        assert body.get("detail", {}).get("error") == "step_up_required"
        store.set_setting.assert_not_called()

    def test_put_key_full_key_never_in_response(self, hibp_client, monkeypatch):
        """Security: full key never appears in PUT response body."""
        client, store, aw, stepup, sess = hibp_client
        monkeypatch.delenv("YASHIGANI_HIBP_API_KEY", raising=False)
        secret = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        store.get_setting = AsyncMock(return_value=secret)
        store.get_metadata = AsyncMock(return_value={"updated_at": None, "updated_by": "admin1"})

        resp = client.put(
            "/api/v1/admin/auth/hibp/key",
            json={"api_key": secret},
        )
        assert secret not in resp.text, (
            f"SECURITY: full key found in PUT response: {resp.text!r}"
        )


# ---------------------------------------------------------------------------
# DELETE /key
# ---------------------------------------------------------------------------

class TestHibpClearKeyEndpoint:
    def test_delete_key_success(self, hibp_client, monkeypatch):
        client, store, aw, stepup, sess = hibp_client
        monkeypatch.delenv("YASHIGANI_HIBP_API_KEY", raising=False)
        # After clear: get_setting returns ""
        store.get_setting = AsyncMock(return_value="")

        resp = client.delete("/api/v1/admin/auth/hibp/key")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["hibp_key"]["configured"] is False

        # Store was called with empty string
        store.set_setting.assert_called_once()
        call_args = store.set_setting.call_args
        assert call_args[0][0] == "hibp_api_key"
        assert call_args[0][1] == ""

    def test_delete_audit_event_written(self, hibp_client, monkeypatch):
        client, store, aw, stepup, sess = hibp_client
        monkeypatch.delenv("YASHIGANI_HIBP_API_KEY", raising=False)
        store.get_setting = AsyncMock(return_value="")

        client.delete("/api/v1/admin/auth/hibp/key")

        from yashigani.audit.schema import HibpApiKeyClearedEvent
        aw.write.assert_called_once()
        event = aw.write.call_args[0][0]
        assert isinstance(event, HibpApiKeyClearedEvent)
        assert event.admin_account == "admin1"

    def test_delete_requires_stepup(self, hibp_client, monkeypatch):
        """DELETE must return 401 step_up_required when step-up not present."""
        client, store, aw, stepup, sess = hibp_client
        stepup["ok"] = False

        resp = client.delete("/api/v1/admin/auth/hibp/key")
        assert resp.status_code == 401
        body = resp.json()
        assert body.get("detail", {}).get("error") == "step_up_required"
        store.set_setting.assert_not_called()


# ---------------------------------------------------------------------------
# Store unavailable (503)
# ---------------------------------------------------------------------------

class TestHibpStoreUnavailable:
    def test_get_status_503_when_store_none(self, monkeypatch):
        """GET /status returns 503 when auth_settings_store is None."""
        from fastapi.testclient import TestClient
        from fastapi import FastAPI
        from yashigani.backoffice.routes.hibp import router
        from yashigani.backoffice.state import backoffice_state
        from yashigani.auth.session import Session
        from yashigani.backoffice import middleware as mw

        app = FastAPI()
        app.include_router(router, prefix="/api/v1/admin/auth/hibp")

        fake_session = Session(
            token="t", account_id="a", account_tier="admin",
            created_at=0.0, last_active_at=0.0, expires_at=9999999999.0,
            ip_prefix="127.0", last_totp_verified_at=None,
        )
        app.dependency_overrides[mw.require_admin_session] = lambda: fake_session
        app.dependency_overrides[mw.require_stepup_admin_session] = lambda: fake_session

        backoffice_state.auth_settings_store = None

        client = TestClient(app, raise_server_exceptions=True)
        resp = client.get("/api/v1/admin/auth/hibp/status")
        assert resp.status_code == 503

        backoffice_state.auth_settings_store = None
        app.dependency_overrides.clear()
