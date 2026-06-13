"""
API tests for the sensitivity taxonomy CRUD endpoints (R14/R15, v2.25.5).

Mounts only the sensitivity router on a minimal FastAPI app; stubs out
the session dependencies and the TaxonomyStore so no DB or Redis is required.

Tests:
  A1  GET /taxonomy/defaults returns the 5-level default taxonomy
  A2  GET /taxonomy returns taxonomy entries (falls back to defaults when DB empty)
  A3  POST /taxonomy/{level} with valid payload returns 200 + saved data
  A4  POST /taxonomy/{level} with invalid colour_class returns 422
  A5  DELETE /taxonomy/1 returns 422 (cannot delete lowest level)
"""

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed in this environment")

from fastapi import FastAPI
from fastapi.testclient import TestClient

from yashigani.auth.session import Session
from yashigani.backoffice.middleware import (
    require_admin_session,
    require_stepup_admin_session,
)
from yashigani.backoffice.routes.sensitivity import router
from yashigani.optimization.taxonomy_store import DEFAULT_TAXONOMY, TaxonomyStore
import yashigani.backoffice.routes.sensitivity as _sens_module

import time


# ---------------------------------------------------------------------------
# Helpers — fake sessions
# ---------------------------------------------------------------------------

def _fake_session(tier: str = "admin") -> Session:
    now = time.time()
    return Session(
        token="test-token",
        account_id="test-admin",
        account_tier=tier,
        created_at=now,
        last_active_at=now,
        expires_at=now + 3600,
        ip_prefix="127.0.0",
        last_totp_verified_at=now,  # step-up satisfied
    )


def _build_app() -> FastAPI:
    """Minimal app with sensitivity router and stubbed-out session deps."""
    app = FastAPI()

    fake = _fake_session()

    async def _admin_dep():
        return fake

    async def _stepup_dep():
        return fake

    app.dependency_overrides[require_admin_session] = _admin_dep
    app.dependency_overrides[require_stepup_admin_session] = _stepup_dep
    app.include_router(router)
    return app


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestTaxonomyDefaults:
    """A1 — GET /taxonomy/defaults returns the 5-level default taxonomy."""

    def test_defaults_have_five_levels(self):
        app = _build_app()
        with TestClient(app, raise_server_exceptions=True) as client:
            resp = client.get("/taxonomy/defaults")
        assert resp.status_code == 200
        data = resp.json()
        assert "taxonomy" in data
        levels = {entry["level"] for entry in data["taxonomy"]}
        assert levels == {1, 2, 3, 4, 5}

    def test_defaults_level_5_label(self):
        app = _build_app()
        with TestClient(app, raise_server_exceptions=True) as client:
            resp = client.get("/taxonomy/defaults")
        entries = {e["level"]: e for e in resp.json()["taxonomy"]}
        assert entries[5]["label"] == "Sensitive"
        assert entries[5]["colour_class"] == "sens-level-5"

    def test_defaults_level_1_label(self):
        app = _build_app()
        with TestClient(app, raise_server_exceptions=True) as client:
            resp = client.get("/taxonomy/defaults")
        entries = {e["level"]: e for e in resp.json()["taxonomy"]}
        assert entries[1]["label"] == "Info"
        assert entries[1]["colour_class"] == "sens-level-1"


class TestTaxonomyGet:
    """A2 — GET /taxonomy falls back to defaults when DB is empty."""

    def test_get_taxonomy_returns_defaults_when_no_db(self, monkeypatch):
        # Replace the module-level _taxonomy_store with one that always returns DEFAULT_TAXONOMY
        class _StubStore(TaxonomyStore):
            async def get_taxonomy(self, tenant_id="default"):
                return dict(DEFAULT_TAXONOMY)

        monkeypatch.setattr(_sens_module, "_taxonomy_store", _StubStore())
        app = _build_app()
        with TestClient(app, raise_server_exceptions=True) as client:
            resp = client.get("/taxonomy")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["taxonomy"]) == 5


class TestTaxonomyUpsert:
    """A3/A4 — POST /taxonomy/{level}."""

    def test_upsert_valid_level(self, monkeypatch):
        """A3: Valid upsert returns 200 with saved data."""
        saved = {}

        class _StubStore(TaxonomyStore):
            async def set_level(self, tenant_id, level_number, label, colour_class):
                saved["level"] = level_number
                saved["label"] = label
                saved["colour_class"] = colour_class

        monkeypatch.setattr(_sens_module, "_taxonomy_store", _StubStore())
        app = _build_app()
        with TestClient(app, raise_server_exceptions=True) as client:
            resp = client.post(
                "/taxonomy/3",
                json={"label": "Custom Internal", "colour_class": "sens-level-3"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["level"] == 3
        assert body["label"] == "Custom Internal"
        assert body["colour_class"] == "sens-level-3"
        assert saved["level"] == 3

    def test_upsert_invalid_colour_class(self, monkeypatch):
        """A4: Invalid colour_class rejected with 422."""
        class _StubStore(TaxonomyStore):
            async def set_level(self, tenant_id, level_number, label, colour_class):
                raise ValueError(f"Invalid colour_class {colour_class!r}.")

        monkeypatch.setattr(_sens_module, "_taxonomy_store", _StubStore())
        app = _build_app()
        with TestClient(app, raise_server_exceptions=True) as client:
            resp = client.post(
                "/taxonomy/3",
                json={"label": "Bad", "colour_class": "red"},  # not a valid class
            )
        # The Pydantic validator should catch this at request validation level (422)
        # OR the route raises HTTPException 422
        assert resp.status_code == 422


class TestTaxonomyDelete:
    """A5 — DELETE /taxonomy/1 returns 422 (cannot delete lowest level)."""

    def test_delete_level_1_rejected(self, monkeypatch):
        class _StubStore(TaxonomyStore):
            async def delete_level(self, tenant_id, level_number):
                if level_number == 1:
                    raise ValueError("Cannot delete level 1 (lowest level must always exist).")

        monkeypatch.setattr(_sens_module, "_taxonomy_store", _StubStore())
        app = _build_app()
        with TestClient(app, raise_server_exceptions=True) as client:
            resp = client.delete("/taxonomy/1")
        assert resp.status_code == 422
        detail = resp.json().get("detail", {})
        assert detail.get("error") == "delete_not_allowed"
