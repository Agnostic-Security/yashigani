"""
Unit tests — N1 second-admin minimum enforcement (2.25.5).

Covers:
  1. DELETE /{username} blocked when total == min_total (2 admins)
  2. DELETE /{username} blocked when total == 1 (single admin)
  3. DELETE /{username} allowed when total == 3 (above minimum)
  4. DELETE /{username} 404 when account not found
  5. POST /{username}/disable blocked when active == min_active (2 active)
  6. POST /{username}/disable blocked when active == 1 (single active)
  7. POST /{username}/disable allowed when active == 3 (above minimum)
  8. POST /{username}/disable idempotent when already disabled
  9. PUT /{username} with disabled=True blocked at active minimum
  10. PUT /{username} with disabled=True allowed when above minimum
  11. PUT /{username} with disabled=False (enable) not blocked by active minimum
  12. GET /enforcement returns action_required=True when below_minimum
  13. GET /enforcement action_required=False when at minimum
  14. GET /enforcement below_soft_target=True advisory flag
  15. GET /enforcement all flags False when at soft_target
  16. GET /enforcement response has all required fields
  17. GET /enforcement requires admin session

Tests follow the pattern established in test_v2255_admin_ui_crud.py:
mutate backoffice_state directly, use httpx.AsyncClient + ASGITransport.

Last updated: 2026-06-13T00:00:00+01:00
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

try:
    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient
    _FASTAPI_AVAILABLE = True
except ImportError:
    _FASTAPI_AVAILABLE = False

pytestmark = pytest.mark.skipif(not _FASTAPI_AVAILABLE, reason="fastapi/httpx not installed")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_auth(total: int, active: int, account_tier: str = "admin",
               account_disabled: bool = False, missing: bool = False):
    """Create a minimal mock auth service."""
    auth = MagicMock()
    auth.total_admin_count = AsyncMock(return_value=total)
    auth.active_admin_count = AsyncMock(return_value=active)
    auth.delete_account = AsyncMock(return_value=True)
    auth.disable = AsyncMock(return_value=True)
    auth.enable = AsyncMock(return_value=True)
    auth.list_accounts = AsyncMock(return_value=[])

    if missing:
        auth.get_account = AsyncMock(return_value=None)
    else:
        rec = SimpleNamespace(
            account_id="target-id",
            username="second@example.com",
            account_tier=account_tier,
            disabled=account_disabled,
            email="second@example.com",
            force_password_change=False,
            force_totp_provision=False,
            created_at=None,
        )
        auth.get_account = AsyncMock(return_value=rec)
        auth.get_account_by_email = AsyncMock(return_value=None)

    return auth


def _make_app(auth, min_total: int = 2, min_active: int = 2, soft_target: int = 3):
    """Build a minimal FastAPI app with accounts router, mocked state, bypassed auth."""
    from yashigani.backoffice.routes import accounts as accounts_routes
    from yashigani.backoffice.middleware import require_admin_session, require_stepup_admin_session
    from yashigani.backoffice.state import backoffice_state

    backoffice_state.auth_service = auth
    backoffice_state.session_store = MagicMock()
    backoffice_state.session_store.invalidate_all_for_account = MagicMock()
    backoffice_state.audit_writer = MagicMock()
    backoffice_state.audit_writer.write = MagicMock()
    backoffice_state.identity_registry = None
    backoffice_state.admin_min_total = min_total
    backoffice_state.admin_min_active = min_active
    backoffice_state.admin_soft_target = soft_target

    sess = SimpleNamespace(account_id="admin1", account_tier="admin")
    app = FastAPI()
    app.dependency_overrides[require_admin_session] = lambda: sess
    app.dependency_overrides[require_stepup_admin_session] = lambda: sess
    app.include_router(accounts_routes.router, prefix="/admin/accounts")
    return app


def _run(coro):
    return asyncio.run(coro)


async def _get(app, path: str) -> object:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        return await c.get(path)


async def _post(app, path: str, json: dict | None = None) -> object:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        return await c.post(path, json=json or {})


async def _delete(app, path: str) -> object:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        return await c.delete(path)


async def _put(app, path: str, json: dict) -> object:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        return await c.put(path, json=json)


# ---------------------------------------------------------------------------
# N1 — DELETE guard
# ---------------------------------------------------------------------------

class TestDeleteAdminBlocked:
    def test_delete_blocked_when_at_minimum(self):
        """DELETE blocked when total == min_total (2 admins, min=2)."""
        app = _make_app(_make_auth(total=2, active=2))
        resp = _run(_delete(app, "/admin/accounts/second%40example.com"))
        assert resp.status_code == 409, f"Expected 409, got {resp.status_code}: {resp.text}"
        body = resp.json()
        assert body["detail"]["error"] == "ADMIN_MINIMUM_VIOLATION"

    def test_delete_blocked_when_only_one_admin(self):
        """DELETE blocked when total == 1 (below minimum)."""
        app = _make_app(_make_auth(total=1, active=1))
        resp = _run(_delete(app, "/admin/accounts/second%40example.com"))
        assert resp.status_code == 409, f"Expected 409, got {resp.status_code}: {resp.text}"
        body = resp.json()
        assert body["detail"]["error"] == "ADMIN_MINIMUM_VIOLATION"

    def test_delete_allowed_when_above_minimum(self):
        """DELETE allowed when total == 3 (above min_total=2)."""
        app = _make_app(_make_auth(total=3, active=3))
        resp = _run(_delete(app, "/admin/accounts/second%40example.com"))
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
        assert resp.json()["status"] == "ok"

    def test_delete_404_when_account_not_found(self):
        """DELETE returns 404 when account does not exist."""
        app = _make_app(_make_auth(total=3, active=3, missing=True))
        resp = _run(_delete(app, "/admin/accounts/nobody%40example.com"))
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# N1 — POST /{username}/disable guard
# ---------------------------------------------------------------------------

class TestDisableAdminBlocked:
    def test_disable_blocked_when_at_active_minimum(self):
        """POST /disable blocked when active == min_active (2, min=2)."""
        app = _make_app(_make_auth(total=2, active=2))
        resp = _run(_post(app, "/admin/accounts/second%40example.com/disable"))
        assert resp.status_code == 409, f"Expected 409, got {resp.status_code}: {resp.text}"
        assert resp.json()["detail"]["error"] == "ADMIN_ACTIVE_MINIMUM_VIOLATION"

    def test_disable_blocked_when_only_one_active(self):
        """POST /disable blocked when active == 1 (below minimum)."""
        app = _make_app(_make_auth(total=2, active=1))
        resp = _run(_post(app, "/admin/accounts/second%40example.com/disable"))
        assert resp.status_code == 409, f"Expected 409, got {resp.status_code}: {resp.text}"

    def test_disable_allowed_when_above_active_minimum(self):
        """POST /disable allowed when active == 3 (above min_active=2)."""
        app = _make_app(_make_auth(total=3, active=3))
        resp = _run(_post(app, "/admin/accounts/second%40example.com/disable"))
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"

    def test_disable_idempotent_when_already_disabled(self):
        """POST /disable returns ok when account is already disabled."""
        app = _make_app(_make_auth(total=3, active=3, account_disabled=True))
        resp = _run(_post(app, "/admin/accounts/second%40example.com/disable"))
        assert resp.status_code == 200
        assert resp.json()["message"] == "already_disabled"


# ---------------------------------------------------------------------------
# N1 — PUT /{username} with disabled=True guard
# ---------------------------------------------------------------------------

class TestPutAdminDisableGuard:
    def test_put_disable_blocked_at_active_minimum(self):
        """PUT with disabled=True blocked when active == min_active."""
        app = _make_app(_make_auth(total=2, active=2))
        resp = _run(_put(app, "/admin/accounts/second%40example.com", {"disabled": True}))
        assert resp.status_code == 409, f"Expected 409, got {resp.status_code}: {resp.text}"
        assert resp.json()["detail"]["error"] == "ADMIN_ACTIVE_MINIMUM_VIOLATION"

    def test_put_disable_allowed_when_above_minimum(self):
        """PUT with disabled=True allowed when active > min_active."""
        app = _make_app(_make_auth(total=3, active=3))
        resp = _run(_put(app, "/admin/accounts/second%40example.com", {"disabled": True}))
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"

    def test_put_enable_not_gated_by_active_minimum(self, monkeypatch):
        """PUT with disabled=False (re-enable) is NOT blocked by active minimum.

        Scenario: 3 total admins, 1 active (2 disabled), trying to re-enable one.
        The enable path checks only the license seat limit (not the active-minimum
        guard — enabling adds capacity). The license check is mocked because the
        dev license cap (2) would otherwise fire on any test with total >= 2.
        """
        import yashigani.licensing.enforcer as _enforcer
        monkeypatch.setattr(_enforcer, "check_admin_seat_limit", lambda n: None)

        app = _make_app(_make_auth(total=3, active=1, account_disabled=True))
        resp = _run(_put(app, "/admin/accounts/second%40example.com", {"disabled": False}))
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"


# ---------------------------------------------------------------------------
# N1 — GET /enforcement endpoint
# ---------------------------------------------------------------------------

class TestEnforcementEndpoint:
    def test_enforcement_below_minimum(self):
        """GET /enforcement returns action_required=True when total < min_total."""
        app = _make_app(_make_auth(total=1, active=1))
        resp = _run(_get(app, "/admin/accounts/enforcement"))
        assert resp.status_code == 200, f"Got {resp.status_code}: {resp.text}"
        body = resp.json()
        assert body["total"] == 1
        assert body["active"] == 1
        assert body["min_total"] == 2
        assert body["min_active"] == 2
        assert body["below_minimum"] is True
        assert body["below_active_minimum"] is True
        assert body["action_required"] is True

    def test_enforcement_at_minimum(self):
        """GET /enforcement action_required=False when total == min_total."""
        app = _make_app(_make_auth(total=2, active=2))
        resp = _run(_get(app, "/admin/accounts/enforcement"))
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 2
        assert body["active"] == 2
        assert body["below_minimum"] is False
        assert body["below_active_minimum"] is False
        assert body["action_required"] is False

    def test_enforcement_above_minimum_below_soft_target(self):
        """GET /enforcement below_soft_target=True when total < soft_target."""
        app = _make_app(_make_auth(total=2, active=2), soft_target=3)
        resp = _run(_get(app, "/admin/accounts/enforcement"))
        assert resp.status_code == 200
        body = resp.json()
        assert body["below_soft_target"] is True
        assert body["action_required"] is False  # soft target is advisory only

    def test_enforcement_all_met(self):
        """GET /enforcement all flags False when at soft_target."""
        app = _make_app(_make_auth(total=3, active=3), soft_target=3)
        resp = _run(_get(app, "/admin/accounts/enforcement"))
        assert resp.status_code == 200
        body = resp.json()
        assert body["below_minimum"] is False
        assert body["below_active_minimum"] is False
        assert body["below_soft_target"] is False
        assert body["action_required"] is False

    def test_enforcement_response_has_required_fields(self):
        """GET /enforcement response contains all required fields."""
        app = _make_app(_make_auth(total=2, active=2))
        resp = _run(_get(app, "/admin/accounts/enforcement"))
        assert resp.status_code == 200
        body = resp.json()
        required_fields = {
            "total", "active", "min_total", "min_active",
            "soft_target", "below_minimum", "below_active_minimum",
            "below_soft_target", "action_required",
        }
        missing = required_fields - set(body.keys())
        assert not missing, f"Missing fields in enforcement response: {missing}"

    def test_enforcement_requires_admin_session(self):
        """GET /enforcement without session must return 401."""
        from fastapi import FastAPI, HTTPException
        from yashigani.backoffice.routes import accounts as accounts_routes
        from yashigani.backoffice.middleware import require_admin_session
        from yashigani.backoffice.state import backoffice_state

        backoffice_state.auth_service = _make_auth(total=2, active=2)

        def _reject():
            raise HTTPException(status_code=401, detail={"error": "authentication_required"})

        app = FastAPI()
        app.dependency_overrides[require_admin_session] = _reject
        app.include_router(accounts_routes.router, prefix="/admin/accounts")

        resp = _run(_get(app, "/admin/accounts/enforcement"))
        assert resp.status_code == 401
