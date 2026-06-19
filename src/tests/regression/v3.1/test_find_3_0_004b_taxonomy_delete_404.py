"""
Regression — FIND-3.0-004b: DELETE /taxonomy/{level} returns 404 for a
non-existent level (was: 200 silently, or 500 via a generic exception).

Three cases:
  - deleting a level that does NOT exist → 404
  - deleting an existing level → 200 + audit event emitted
  - delete rejected by business rules (ValueError from store) → 422

No DB required — TaxonomyStore is stubbed at the module level.
"""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed")

import time
from unittest.mock import MagicMock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from yashigani.auth.session import Session
from yashigani.backoffice.middleware import (
    require_admin_session,
    require_stepup_admin_session,
)
from yashigani.backoffice.routes.sensitivity import router
import yashigani.backoffice.routes.sensitivity as _sens_module
from yashigani.optimization.taxonomy_store import TaxonomyStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fake_session() -> Session:
    now = time.time()
    return Session(
        token="test-token",
        account_id="test-admin",
        account_tier="admin",
        created_at=now,
        last_active_at=now,
        expires_at=now + 3600,
        ip_prefix="127.0.0",
        last_totp_verified_at=now,
    )


def _build_app() -> FastAPI:
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


# A taxonomy with levels 1, 2, 3 (so level 99 does not exist)
_FAKE_TAXONOMY = {
    1: {"label": "Info", "colour_class": "sens-level-1"},
    2: {"label": "Internal", "colour_class": "sens-level-2"},
    3: {"label": "Confidential", "colour_class": "sens-level-3"},
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestDeleteNonExistentLevel:
    """FIND-3.0-004b: deleting a level that is not in the taxonomy → 404."""

    def test_delete_nonexistent_returns_404(self, monkeypatch):
        class _StubStore(TaxonomyStore):
            async def get_taxonomy(self, tenant_id="default"):
                return dict(_FAKE_TAXONOMY)

            async def delete_level(self, tenant_id, level_number):
                # Should never be reached for a non-existent level.
                raise AssertionError("delete_level must not be called for a non-existent level")

        monkeypatch.setattr(_sens_module, "_taxonomy_store", _StubStore())
        app = _build_app()
        with TestClient(app, raise_server_exceptions=True) as client:
            resp = client.delete("/taxonomy/99")

        assert resp.status_code == 404, f"expected 404, got {resp.status_code}: {resp.text}"
        detail = resp.json().get("detail", {})
        assert detail.get("error") == "taxonomy_level_not_found"
        assert detail.get("level") == 99

    def test_delete_nonexistent_returns_404_for_level_5(self, monkeypatch):
        """Level 5 does not exist in a 3-level taxonomy — must be 404."""
        class _StubStore(TaxonomyStore):
            async def get_taxonomy(self, tenant_id="default"):
                return dict(_FAKE_TAXONOMY)

            async def delete_level(self, tenant_id, level_number):
                raise AssertionError("must not be called")

        monkeypatch.setattr(_sens_module, "_taxonomy_store", _StubStore())
        app = _build_app()
        with TestClient(app, raise_server_exceptions=True) as client:
            resp = client.delete("/taxonomy/5")

        assert resp.status_code == 404


class TestDeleteExistingLevel:
    """Deleting an existing, deletable level returns 200 and fires the audit event."""

    def test_delete_existing_level_200(self, monkeypatch):
        deleted = {}
        audit_calls = []

        class _StubStore(TaxonomyStore):
            async def get_taxonomy(self, tenant_id="default"):
                return dict(_FAKE_TAXONOMY)  # level 2 is a mid-level, deletable

            async def delete_level(self, tenant_id, level_number):
                deleted["tenant_id"] = tenant_id
                deleted["level_number"] = level_number

        monkeypatch.setattr(_sens_module, "_taxonomy_store", _StubStore())

        # Stub the audit writer
        fake_writer = MagicMock()
        fake_writer.write = MagicMock(side_effect=lambda ev: audit_calls.append(ev))

        import yashigani.backoffice.routes.sensitivity as _m
        mock_state = MagicMock()
        mock_state.audit_writer = fake_writer
        monkeypatch.setattr(_m, "backoffice_state", mock_state)

        app = _build_app()
        with TestClient(app, raise_server_exceptions=True) as client:
            resp = client.delete("/taxonomy/2")

        assert resp.status_code == 200, f"expected 200, got {resp.status_code}: {resp.text}"
        body = resp.json()
        assert body["status"] == "ok"
        assert body["level"] == 2
        assert deleted["level_number"] == 2
        assert len(audit_calls) == 1
        from yashigani.audit.schema import TaxonomyLevelChangedEvent
        assert isinstance(audit_calls[0], TaxonomyLevelChangedEvent)
        assert audit_calls[0].change_type == "delete"
        assert audit_calls[0].level == 2


class TestDeleteBusinessRuleRejection:
    """ValueError from store (level 1, current-max) → 422, not 500."""

    def test_delete_level_1_returns_422(self, monkeypatch):
        class _StubStore(TaxonomyStore):
            async def get_taxonomy(self, tenant_id="default"):
                # Level 1 is present — existence check passes.
                return dict(_FAKE_TAXONOMY)

            async def delete_level(self, tenant_id, level_number):
                if level_number == 1:
                    raise ValueError("Cannot delete level 1 (lowest level must always exist).")

        monkeypatch.setattr(_sens_module, "_taxonomy_store", _StubStore())
        app = _build_app()
        with TestClient(app, raise_server_exceptions=True) as client:
            resp = client.delete("/taxonomy/1")

        assert resp.status_code == 422, f"expected 422, got {resp.status_code}: {resp.text}"
        detail = resp.json().get("detail", {})
        assert detail.get("error") == "delete_not_allowed"

    def test_delete_max_level_returns_422(self, monkeypatch):
        """Deleting current max level (3 in our 3-level taxonomy) → 422."""
        class _StubStore(TaxonomyStore):
            async def get_taxonomy(self, tenant_id="default"):
                return dict(_FAKE_TAXONOMY)

            async def delete_level(self, tenant_id, level_number):
                # level 3 is max
                if level_number == 3:
                    raise ValueError(
                        f"Cannot delete level {level_number} (current max level)."
                    )

        monkeypatch.setattr(_sens_module, "_taxonomy_store", _StubStore())
        app = _build_app()
        with TestClient(app, raise_server_exceptions=True) as client:
            resp = client.delete("/taxonomy/3")

        assert resp.status_code == 422
        detail = resp.json().get("detail", {})
        assert detail.get("error") == "delete_not_allowed"
