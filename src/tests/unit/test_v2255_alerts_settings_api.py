"""
v2.25.5 — R17/R18/R13/R23/R26 alerts+settings API unit tests.

Each endpoint tested with:
  - Auth guard (401 without session)
  - Correct response shape and status codes
  - Behaviour contract (defaults, CRUD invariants, opt-in version check)

Tests mount only the router under test with admin session bypassed via
dependency_overrides — no live stack required.

Last updated: 2026-06-13T00:00:00+01:00
"""
from __future__ import annotations

import asyncio
import os
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

try:
    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient
    _HAVE_FASTAPI = True
except ImportError:  # pragma: no cover
    _HAVE_FASTAPI = False

pytestmark = pytest.mark.skipif(
    not _HAVE_FASTAPI,
    reason="fastapi + httpx required",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _admin_override():
    """Return a simple admin session namespace for dependency overrides."""
    return SimpleNamespace(account_id="admin@test.local", account_tier="admin")


def _make_app_with_router(router, prefix: str = "") -> "FastAPI":
    from yashigani.backoffice.middleware import require_admin_session
    app = FastAPI()
    app.dependency_overrides[require_admin_session] = lambda: _admin_override()
    app.include_router(router, prefix=prefix)
    return app


def _make_app_no_auth(router, prefix: str = "") -> "FastAPI":
    """
    Build a FastAPI app WITHOUT an auth override so the real middleware runs.
    We wire a fake session_store that returns None for every lookup, which
    causes require_admin_session to raise HTTP 401 normally (no assertion error).
    """
    from yashigani.backoffice.state import backoffice_state
    fake_store = MagicMock()
    fake_store.get = MagicMock(return_value=None)  # any token → session not found → 401
    backoffice_state.session_store = fake_store

    app = FastAPI()
    app.include_router(router, prefix=prefix)
    return app


# ---------------------------------------------------------------------------
# R17 — Budget threshold alert
# ---------------------------------------------------------------------------

class TestR17BudgetThresholdAlert:
    """R17: GET/PUT /admin/alerts/budget-threshold"""

    def _app(self):
        from yashigani.backoffice.routes.alerts import router
        return _make_app_with_router(router, prefix="/admin/alerts")

    def test_get_returns_defaults(self):
        """GET budget-threshold returns enabled=True, threshold_pct=85 by default."""
        # Reset state between tests
        from yashigani.backoffice import state as st
        if hasattr(st.backoffice_state, "budget_threshold_alert_config"):
            delattr(st.backoffice_state, "budget_threshold_alert_config")

        app = self._app()

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.get("/admin/alerts/budget-threshold")

        r = asyncio.run(go())
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["enabled"] is True, "R17: default enabled must be True"
        assert body["threshold_pct"] == 85, "R17: default threshold_pct must be 85"

    def test_put_persists_and_get_reflects_change(self):
        """PUT budget-threshold updates and GET reads back the new value."""
        from yashigani.backoffice import state as st
        if hasattr(st.backoffice_state, "budget_threshold_alert_config"):
            delattr(st.backoffice_state, "budget_threshold_alert_config")

        app = self._app()

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                put_r = await c.put(
                    "/admin/alerts/budget-threshold",
                    json={"enabled": False, "threshold_pct": 70},
                )
                assert put_r.status_code == 200, put_r.text
                get_r = await c.get("/admin/alerts/budget-threshold")
                return get_r.json()

        body = asyncio.run(go())
        assert body["enabled"] is False, "R17: PUT disabled must persist"
        assert body["threshold_pct"] == 70, "R17: PUT threshold_pct must persist"

    def test_put_rejects_out_of_range_threshold(self):
        """PUT budget-threshold rejects threshold_pct=0 (below min=1)."""
        app = self._app()

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.put(
                    "/admin/alerts/budget-threshold",
                    json={"enabled": True, "threshold_pct": 0},
                )

        r = asyncio.run(go())
        assert r.status_code == 422, "R17: threshold_pct=0 must be rejected"

    def test_put_rejects_threshold_100(self):
        """PUT budget-threshold rejects threshold_pct=100 (100 = exhaustion, not threshold)."""
        app = self._app()

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.put(
                    "/admin/alerts/budget-threshold",
                    json={"enabled": True, "threshold_pct": 100},
                )

        r = asyncio.run(go())
        assert r.status_code == 422, "R17: threshold_pct=100 must be rejected (use budget_exhausted trigger)"

    def test_auth_required(self):
        """GET/PUT budget-threshold requires admin session."""
        from yashigani.backoffice.routes.alerts import router
        app = _make_app_no_auth(router, prefix="/admin/alerts")

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.get("/admin/alerts/budget-threshold")

        r = asyncio.run(go())
        assert r.status_code == 401, "R17: must require admin session"


# ---------------------------------------------------------------------------
# R18 — Custom alert rules CRUD
# ---------------------------------------------------------------------------

_VALID_ALERT_BODY = {
    "name": "High budget usage",
    "description": "Alert when any user exceeds 90% of their budget",
    "trigger_type": "budget_threshold",
    "condition": {
        "field": "budget_used_pct",
        "operator": "gte",
        "threshold": 90.0,
    },
    "channels": [],
    "enabled": True,
    "cooldown_minutes": 60,
}


class TestR18CustomAlertCRUD:
    """R18: POST/GET/PUT/DELETE /admin/alerts/custom[/{id}]"""

    def _app(self):
        from yashigani.backoffice.routes.alerts import router
        # Reset custom alerts state
        from yashigani.backoffice import state as st
        if hasattr(st.backoffice_state, "custom_alert_rules"):
            delattr(st.backoffice_state, "custom_alert_rules")
        return _make_app_with_router(router, prefix="/admin/alerts")

    def test_list_empty_initially(self):
        """GET /admin/alerts/custom returns empty list initially."""
        app = self._app()

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.get("/admin/alerts/custom")

        r = asyncio.run(go())
        assert r.status_code == 200, r.text
        assert r.json()["count"] == 0

    def test_create_returns_201_with_id(self):
        """POST creates a rule and returns 201 with server-assigned id."""
        app = self._app()

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.post("/admin/alerts/custom", json=_VALID_ALERT_BODY)

        r = asyncio.run(go())
        assert r.status_code == 201, r.text
        body = r.json()
        assert "id" in body, "R18: created rule must have id"
        assert body["name"] == "High budget usage"
        assert body["trigger_type"] == "budget_threshold"
        assert body["enabled"] is True

    def test_get_by_id_roundtrip(self):
        """POST then GET by id returns the same rule."""
        app = self._app()

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                created = await c.post("/admin/alerts/custom", json=_VALID_ALERT_BODY)
                assert created.status_code == 201
                alert_id = created.json()["id"]
                return await c.get(f"/admin/alerts/custom/{alert_id}")

        r = asyncio.run(go())
        assert r.status_code == 200, r.text
        assert r.json()["name"] == "High budget usage"

    def test_list_reflects_created_rules(self):
        """GET /admin/alerts/custom returns all created rules."""
        app = self._app()

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                await c.post("/admin/alerts/custom", json=_VALID_ALERT_BODY)
                await c.post("/admin/alerts/custom", json={
                    **_VALID_ALERT_BODY,
                    "name": "Second alert",
                })
                return await c.get("/admin/alerts/custom")

        r = asyncio.run(go())
        assert r.status_code == 200
        body = r.json()
        assert body["count"] == 2, "R18: list must reflect 2 created rules"
        names = {a["name"] for a in body["custom_alerts"]}
        assert "High budget usage" in names
        assert "Second alert" in names

    def test_update_partial(self):
        """PUT with partial update only changes provided fields."""
        app = self._app()

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                created = await c.post("/admin/alerts/custom", json=_VALID_ALERT_BODY)
                alert_id = created.json()["id"]
                updated = await c.put(
                    f"/admin/alerts/custom/{alert_id}",
                    json={"enabled": False, "cooldown_minutes": 120},
                )
                return updated

        r = asyncio.run(go())
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["enabled"] is False, "R18: PUT must disable the rule"
        assert body["cooldown_minutes"] == 120, "R18: PUT must update cooldown"
        assert body["name"] == "High budget usage", "R18: PUT must not change unspecified fields"

    def test_delete_removes_rule(self):
        """DELETE removes rule; subsequent GET returns 404."""
        app = self._app()

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                created = await c.post("/admin/alerts/custom", json=_VALID_ALERT_BODY)
                alert_id = created.json()["id"]
                deleted = await c.delete(f"/admin/alerts/custom/{alert_id}")
                assert deleted.status_code == 204, "R18: DELETE must return 204"
                return await c.get(f"/admin/alerts/custom/{alert_id}")

        r = asyncio.run(go())
        assert r.status_code == 404, "R18: GET after DELETE must return 404"

    def test_get_unknown_id_returns_404(self):
        """GET /admin/alerts/custom/{unknown-id} returns 404."""
        app = self._app()

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.get("/admin/alerts/custom/nonexistent-id")

        r = asyncio.run(go())
        assert r.status_code == 404

    def test_invalid_trigger_type_rejected(self):
        """POST with unknown trigger_type returns 422."""
        app = self._app()
        body = {**_VALID_ALERT_BODY, "trigger_type": "magic_trigger"}

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.post("/admin/alerts/custom", json=body)

        r = asyncio.run(go())
        assert r.status_code == 422, "R18: unknown trigger_type must be rejected"

    def test_invalid_operator_rejected(self):
        """POST with invalid condition operator returns 422."""
        app = self._app()
        body = {
            **_VALID_ALERT_BODY,
            "condition": {"field": "budget_used_pct", "operator": "invalid_op", "threshold": 80.0},
        }

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.post("/admin/alerts/custom", json=body)

        r = asyncio.run(go())
        assert r.status_code == 422, "R18: invalid operator must be rejected"

    def test_auth_required(self):
        """Custom alert endpoints require admin session."""
        from yashigani.backoffice.routes.alerts import router
        app = _make_app_no_auth(router, prefix="/admin/alerts")

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.get("/admin/alerts/custom")

        r = asyncio.run(go())
        assert r.status_code == 401


# ---------------------------------------------------------------------------
# R13 — RBAC group sources
# ---------------------------------------------------------------------------

class TestR13RBACGroupSources:
    """R13: GET /admin/rbac/sources/paths and /admin/rbac/sources/methods"""

    def _app(self):
        from yashigani.backoffice.routes.rbac_sources import router
        return _make_app_with_router(router, prefix="/admin/rbac")

    def test_paths_returns_list_with_required_fields(self):
        """GET /sources/paths returns a list of path objects with required fields."""
        app = self._app()

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.get("/admin/rbac/sources/paths")

        r = asyncio.run(go())
        assert r.status_code == 200, r.text
        body = r.json()
        assert "paths" in body
        assert body["count"] > 0

        # Each path entry must have required fields
        required_fields = {"path", "glob", "label", "description", "category", "risk"}
        for p in body["paths"]:
            missing = required_fields - p.keys()
            assert not missing, f"R13: path entry missing fields: {missing}"

    def test_paths_includes_well_known_mcp_paths(self):
        """GET /sources/paths includes /tools/call, /tools/list, /prompts/list."""
        app = self._app()

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.get("/admin/rbac/sources/paths")

        r = asyncio.run(go())
        body = r.json()
        globs = {p["glob"] for p in body["paths"]}
        for expected in ("/tools/call", "/tools/list", "/prompts/list", "**"):
            assert expected in globs, f"R13: expected path glob '{expected}' missing"

    def test_paths_includes_glob_field_for_dropdown(self):
        """GET /sources/paths: glob field is usable as path_glob in RBAC groups."""
        app = self._app()

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.get("/admin/rbac/sources/paths")

        r = asyncio.run(go())
        body = r.json()
        # Every entry must have a non-empty glob
        for p in body["paths"]:
            assert p["glob"], f"R13: path entry has empty glob: {p}"

    def test_methods_returns_list_with_required_fields(self):
        """GET /sources/methods returns method catalogue with required fields."""
        app = self._app()

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.get("/admin/rbac/sources/methods")

        r = asyncio.run(go())
        assert r.status_code == 200, r.text
        body = r.json()
        assert "methods" in body
        assert body["count"] > 0

        required_fields = {"method", "label", "description", "risk"}
        for m in body["methods"]:
            missing = required_fields - m.keys()
            assert not missing, f"R13: method entry missing fields: {missing}"

    def test_methods_includes_standard_verbs_and_wildcard(self):
        """GET /sources/methods includes GET, POST, PUT, DELETE, PATCH, *, HEAD, OPTIONS."""
        app = self._app()

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.get("/admin/rbac/sources/methods")

        r = asyncio.run(go())
        body = r.json()
        methods_set = {m["method"] for m in body["methods"]}
        for expected in ("*", "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
            assert expected in methods_set, f"R13: expected method '{expected}' missing"

    def test_allowed_values_field_lists_all_methods(self):
        """GET /sources/methods includes allowed_values list."""
        app = self._app()

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.get("/admin/rbac/sources/methods")

        r = asyncio.run(go())
        body = r.json()
        assert "allowed_values" in body
        # allowed_values must be non-empty and match method field in each entry
        method_keys = {m["method"] for m in body["methods"]}
        for v in body["allowed_values"]:
            assert v in method_keys, f"R13: allowed_values entry '{v}' not in methods list"

    def test_auth_required_paths(self):
        """GET sources/paths requires admin session."""
        from yashigani.backoffice.routes.rbac_sources import router
        app = _make_app_no_auth(router, prefix="/admin/rbac")

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.get("/admin/rbac/sources/paths")

        r = asyncio.run(go())
        assert r.status_code == 401

    def test_auth_required_methods(self):
        """GET sources/methods requires admin session."""
        from yashigani.backoffice.routes.rbac_sources import router
        app = _make_app_no_auth(router, prefix="/admin/rbac")

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.get("/admin/rbac/sources/methods")

        r = asyncio.run(go())
        assert r.status_code == 401


# ---------------------------------------------------------------------------
# R23 — License entitlements
# ---------------------------------------------------------------------------

class TestR23LicenseEntitlements:
    """R23: GET /admin/license/entitlements"""

    def _app(self):
        from yashigani.backoffice.routes.license import license_router
        from yashigani.backoffice.middleware import require_admin_session
        app = FastAPI()
        app.dependency_overrides[require_admin_session] = lambda: _admin_override()
        app.include_router(license_router, prefix="/admin/license")
        return app

    def test_community_tier_entitlements(self):
        """Community tier: OIDC/SAML/SCIM/PII all unavailable."""
        from yashigani.licensing.model import COMMUNITY_LICENSE
        from yashigani.licensing import enforcer as _enforcer
        _enforcer._license = COMMUNITY_LICENSE

        app = self._app()

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.get("/admin/license/entitlements")

        r = asyncio.run(go())
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["current_tier"] == "community"
        assert "entitlements" in body
        assert len(body["entitlements"]) > 0

        # On community tier, no feature should be available
        for ent in body["entitlements"]:
            assert ent["available"] is False, (
                f"R23: community tier must not grant feature '{ent['feature']}'"
            )
            assert ent["upgrade_url"] is not None, (
                "R23: upgrade_url must be present when feature not available"
            )

    def test_enterprise_tier_all_entitlements(self):
        """Enterprise tier: all features available."""
        from yashigani.licensing.model import LicenseState, LicenseTier, LicenseFeature
        from yashigani.licensing import enforcer as _enforcer
        from datetime import datetime, timezone

        enterprise_lic = LicenseState(
            tier=LicenseTier.ENTERPRISE,
            org_domain="*",
            max_agents=-1,
            max_end_users=-1,
            max_admin_seats=-1,
            max_orgs=-1,
            features=frozenset(LicenseFeature),
            issued_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
            expires_at=None,
            license_id="test-ent-001",
            valid=True,
            error=None,
        )
        _enforcer._license = enterprise_lic
        app = self._app()

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.get("/admin/license/entitlements")

        r = asyncio.run(go())
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["current_tier"] == "enterprise"

        for ent in body["entitlements"]:
            assert ent["available"] is True, (
                f"R23: enterprise must grant feature '{ent['feature']}'"
            )
            assert ent["upgrade_url"] is None, (
                "R23: upgrade_url must be None when feature available"
            )

    def test_response_shape(self):
        """Entitlements response has required fields on every entry."""
        from yashigani.licensing.model import COMMUNITY_LICENSE
        from yashigani.licensing import enforcer as _enforcer
        _enforcer._license = COMMUNITY_LICENSE

        app = self._app()

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.get("/admin/license/entitlements")

        r = asyncio.run(go())
        body = r.json()
        required_top_keys = {"current_tier", "current_tier_label", "entitlements", "upgrade_url"}
        assert required_top_keys <= body.keys()

        required_ent_keys = {
            "feature", "label", "description",
            "available", "required_tier", "required_tier_label", "upgrade_url",
        }
        for ent in body["entitlements"]:
            missing = required_ent_keys - ent.keys()
            assert not missing, f"R23: entitlement missing fields: {missing}"

    def test_auth_required(self):
        """GET entitlements requires admin session."""
        from yashigani.backoffice.routes.license import license_router
        app = _make_app_no_auth(license_router, prefix="/admin/license")

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.get("/admin/license/entitlements")

        r = asyncio.run(go())
        assert r.status_code == 401


# ---------------------------------------------------------------------------
# R26 — Version check
# ---------------------------------------------------------------------------

class TestR26VersionCheck:
    """R26: GET /admin/version"""

    def _app(self):
        from yashigani.backoffice.routes.version_check import router
        return _make_app_with_router(router, prefix="/admin/version")

    def test_returns_running_version(self):
        """GET /admin/version always returns running_version."""
        app = self._app()

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.get("/admin/version")

        r = asyncio.run(go())
        assert r.status_code == 200, r.text
        body = r.json()
        assert "running_version" in body
        assert body["running_version"]  # non-empty

    def test_check_disabled_by_default(self):
        """Version check is skipped when YASHIGANI_VERSION_CHECK_ENABLED not set."""
        env = {k: v for k, v in os.environ.items() if k != "YASHIGANI_VERSION_CHECK_ENABLED"}
        with patch.dict(os.environ, env, clear=True):
            app = self._app()

            async def go():
                async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                    return await c.get("/admin/version")

            r = asyncio.run(go())
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["check_enabled"] is False, "R26: check must be disabled by default"
        assert body["check_skipped"] is True
        assert body["latest_version"] is None
        assert body["update_available"] is None

    def test_check_disabled_explicit_false(self):
        """YASHIGANI_VERSION_CHECK_ENABLED=false skips the check."""
        with patch.dict(os.environ, {"YASHIGANI_VERSION_CHECK_ENABLED": "false"}):
            app = self._app()

            async def go():
                async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                    return await c.get("/admin/version")

            r = asyncio.run(go())
        body = r.json()
        assert body["check_enabled"] is False
        assert body["check_skipped"] is True

    def test_check_enabled_network_error_graceful(self):
        """When check is enabled but network fails, returns gracefully — never 500."""
        import httpx as _httpx

        with patch.dict(os.environ, {"YASHIGANI_VERSION_CHECK_ENABLED": "true"}):
            app = self._app()

            # Patch httpx.AsyncClient to raise a network error
            async def _raise(*a, **kw):
                raise _httpx.ConnectError("simulated network error")

            async def go():
                async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                    with patch("yashigani.backoffice.routes.version_check._fetch_latest_release",
                               side_effect=_httpx.ConnectError("unreachable")):
                        return await c.get("/admin/version")

            r = asyncio.run(go())
        assert r.status_code == 200, "R26: network error must never produce 500"
        body = r.json()
        assert body["check_enabled"] is True
        assert body["check_skipped"] is True, "R26: network failure must set check_skipped=True"
        assert body["latest_version"] is None

    def test_check_enabled_update_available(self):
        """When check succeeds and newer version exists, update_available=True."""
        mock_release = {
            "tag_name": "v99.0.0",
            "is_security": False,
            "html_url": "https://github.com/agnosticsec/yashigani/releases/tag/v99.0.0",
            "published_at": "2030-01-01T00:00:00Z",
        }

        with patch.dict(os.environ, {"YASHIGANI_VERSION_CHECK_ENABLED": "true"}):
            app = self._app()

            async def go():
                async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                    with patch("yashigani.backoffice.routes.version_check._fetch_latest_release",
                               new=AsyncMock(return_value=mock_release)):
                        return await c.get("/admin/version")

            r = asyncio.run(go())
        body = r.json()
        assert body["check_skipped"] is False
        assert body["update_available"] is True
        assert body["latest_version"] == "99.0.0"
        assert body["update_type"] == "major"

    def test_check_enabled_no_update(self):
        """When running == latest, update_available=False, update_type='none'."""
        from yashigani import __version__ as rv
        mock_release = {
            "tag_name": f"v{rv}",
            "is_security": False,
            "html_url": "https://github.com/agnosticsec/yashigani/releases/latest",
            "published_at": "2026-01-01T00:00:00Z",
        }

        with patch.dict(os.environ, {"YASHIGANI_VERSION_CHECK_ENABLED": "true"}):
            app = self._app()

            async def go():
                async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                    with patch("yashigani.backoffice.routes.version_check._fetch_latest_release",
                               new=AsyncMock(return_value=mock_release)):
                        return await c.get("/admin/version")

            r = asyncio.run(go())
        body = r.json()
        assert body["update_available"] is False
        assert body["update_type"] == "none"

    def test_security_update_classified(self):
        """A security release is classified as update_type='security'."""
        mock_release = {
            "tag_name": "v99.0.1",
            "is_security": True,
            "html_url": "https://github.com/agnosticsec/yashigani/releases/tag/v99.0.1",
            "published_at": "2030-01-02T00:00:00Z",
        }

        with patch.dict(os.environ, {"YASHIGANI_VERSION_CHECK_ENABLED": "true"}):
            app = self._app()

            async def go():
                async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                    with patch("yashigani.backoffice.routes.version_check._fetch_latest_release",
                               new=AsyncMock(return_value=mock_release)):
                        return await c.get("/admin/version")

            r = asyncio.run(go())
        body = r.json()
        assert body["update_type"] == "security"

    def test_response_shape_disabled(self):
        """Disabled response has all expected keys."""
        env = {k: v for k, v in os.environ.items() if k != "YASHIGANI_VERSION_CHECK_ENABLED"}
        with patch.dict(os.environ, env, clear=True):
            app = self._app()

            async def go():
                async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                    return await c.get("/admin/version")

            r = asyncio.run(go())
        body = r.json()
        required = {
            "running_version", "check_enabled", "check_skipped", "skip_reason",
            "latest_version", "update_available", "update_type",
            "release_url", "published_at",
        }
        missing = required - body.keys()
        assert not missing, f"R26: response missing keys: {missing}"

    def test_auth_required(self):
        """GET /admin/version requires admin session."""
        from yashigani.backoffice.routes.version_check import router
        app = _make_app_no_auth(router, prefix="/admin/version")

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.get("/admin/version")

        r = asyncio.run(go())
        assert r.status_code == 401


# ---------------------------------------------------------------------------
# OpenAPI presence (cross-cutting)
# ---------------------------------------------------------------------------

class TestOpenAPIPresence:
    """All new endpoints appear in /admin/openapi.json."""

    def test_all_new_endpoints_in_openapi(self):
        """R17/R18/R13/R23/R26 endpoints appear in the admin OpenAPI spec."""
        import os
        os.environ.setdefault("YASHIGANI_ENV", "dev")
        os.environ.setdefault("YASHIGANI_INTERNAL_BEARER", "test-bearer")
        os.environ.setdefault("YASHIGANI_OPA_OPTIONAL", "true")

        from fastapi import FastAPI
        from yashigani.backoffice.middleware import require_admin_session
        from yashigani.backoffice.routes.alerts import router as alerts_router
        from yashigani.backoffice.routes.rbac_sources import router as rbac_sources_router
        from yashigani.backoffice.routes.version_check import router as version_check_router
        from yashigani.backoffice.routes.license import license_router

        app = FastAPI()
        app.dependency_overrides[require_admin_session] = lambda: _admin_override()
        app.include_router(alerts_router, prefix="/admin/alerts")
        app.include_router(rbac_sources_router, prefix="/admin/rbac")
        app.include_router(version_check_router, prefix="/admin/version")
        app.include_router(license_router, prefix="/admin/license")

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.get("/openapi.json")

        r = asyncio.run(go())
        assert r.status_code == 200, r.text
        spec = r.json()
        paths = set(spec.get("paths", {}).keys())

        expected_paths = [
            "/admin/alerts/budget-threshold",  # R17
            "/admin/alerts/custom",             # R18
            "/admin/alerts/custom/{alert_id}",  # R18
            "/admin/rbac/sources/paths",         # R13
            "/admin/rbac/sources/methods",       # R13
            "/admin/license/entitlements",       # R23
            "/admin/version",                    # R26
        ]
        for ep in expected_paths:
            assert ep in paths, f"OpenAPI: expected endpoint '{ep}' missing from spec"
