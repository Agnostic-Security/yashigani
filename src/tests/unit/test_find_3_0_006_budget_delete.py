"""
FIND-3.0-006 — Budget DELETE routes and store delete methods.

Tests:
  - BudgetConfigStore.delete_org_cap / delete_group_budget / delete_individual_budget
    (unit: set then delete returns True; delete non-existent returns False; list is empty after delete)
  - DELETE /admin/budget/org-caps?org_id=X&provider=Y → 204 when exists
  - DELETE /admin/budget/org-caps?org_id=X&provider=Y → 404 when absent
  - DELETE /admin/budget/groups?group_id=X&provider=Y&period=P → 204 / 404
  - DELETE /admin/budget/individuals?identity_id=X&provider=Y&period=P → 204 / 404
  - Audit event emitted on successful delete (CONFIG_CHANGED)

These are unit tests: router mounted with auth bypassed, store backed by fakeredis.
No live stack required.

Last updated: 2026-06-19T00:00:00+01:00
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

try:
    import fakeredis
    _HAVE_FAKEREDIS = True
except ImportError:  # pragma: no cover
    _HAVE_FAKEREDIS = False

try:
    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient
    _HAVE_FASTAPI = True
except ImportError:  # pragma: no cover
    _HAVE_FASTAPI = False

pytestmark = pytest.mark.skipif(
    not (_HAVE_FASTAPI and _HAVE_FAKEREDIS),
    reason="fastapi + fakeredis required",
)

_TENANT = "00000000-0000-0000-0000-000000000000"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_store():
    from yashigani.billing.budget_config_store import BudgetConfigStore
    return BudgetConfigStore(fakeredis.FakeStrictRedis())


def _make_app(store=None, audit_writer=None):
    """Mount only the budget router with auth bypassed."""
    from yashigani.backoffice.routes import budget as budget_routes
    from yashigani.backoffice.middleware import require_admin_session
    from yashigani.backoffice.state import backoffice_state

    if store is None:
        store = _make_store()

    budget_routes.configure(budget_store=store)
    backoffice_state.audit_writer = audit_writer

    app = FastAPI()
    app.dependency_overrides[require_admin_session] = lambda: SimpleNamespace(
        account_id="admin@test.local", account_tier="admin"
    )
    app.include_router(budget_routes.router)
    return app


def _teardown():
    from yashigani.backoffice.routes import budget as budget_routes
    from yashigani.backoffice.state import backoffice_state
    budget_routes.configure(budget_store=None, budget_enforcer=None)
    backoffice_state.audit_writer = None


# ===========================================================================
# Store unit tests
# ===========================================================================


class TestBudgetConfigStoreDelete:
    """Unit tests for BudgetConfigStore delete methods."""

    def test_delete_org_cap_returns_true_when_exists(self):
        store = _make_store()

        async def go():
            await store.set_org_cap(_TENANT, "default", "openai", 500_000, "monthly")
            result = await store.delete_org_cap(_TENANT, "default", "openai")
            return result

        assert asyncio.run(go()) is True

    def test_delete_org_cap_list_empty_after_delete(self):
        store = _make_store()

        async def go():
            await store.set_org_cap(_TENANT, "default", "openai", 500_000, "monthly")
            await store.delete_org_cap(_TENANT, "default", "openai")
            return await store.get_org_caps(_TENANT)

        caps = asyncio.run(go())
        assert caps == []

    def test_delete_org_cap_returns_false_when_absent(self):
        store = _make_store()

        async def go():
            return await store.delete_org_cap(_TENANT, "nonexistent", "openai")

        assert asyncio.run(go()) is False

    def test_delete_group_budget_returns_true_when_exists(self):
        store = _make_store()

        async def go():
            await store.set_group_budget(_TENANT, "engineering", "*", 1_000_000, "monthly")
            return await store.delete_group_budget(_TENANT, "engineering", "*", "monthly")

        assert asyncio.run(go()) is True

    def test_delete_group_budget_list_empty_after_delete(self):
        store = _make_store()

        async def go():
            await store.set_group_budget(_TENANT, "engineering", "*", 1_000_000, "monthly")
            await store.delete_group_budget(_TENANT, "engineering", "*", "monthly")
            return await store.get_group_budgets(_TENANT)

        assert asyncio.run(go()) == []

    def test_delete_group_budget_returns_false_when_absent(self):
        store = _make_store()

        async def go():
            return await store.delete_group_budget(_TENANT, "ghost", "*", "monthly")

        assert asyncio.run(go()) is False

    def test_delete_individual_budget_returns_true_when_exists(self):
        store = _make_store()

        async def go():
            await store.set_individual_budget(_TENANT, "alice@example.com", "*", 100_000, "monthly")
            return await store.delete_individual_budget(_TENANT, "alice@example.com", "*", "monthly")

        assert asyncio.run(go()) is True

    def test_delete_individual_budget_list_empty_after_delete(self):
        store = _make_store()

        async def go():
            await store.set_individual_budget(_TENANT, "bob@example.com", "anthropic", 50_000, "weekly")
            await store.delete_individual_budget(_TENANT, "bob@example.com", "anthropic", "weekly")
            return await store.get_individual_budgets(_TENANT)

        assert asyncio.run(go()) == []

    def test_delete_individual_budget_returns_false_when_absent(self):
        store = _make_store()

        async def go():
            return await store.delete_individual_budget(_TENANT, "ghost@example.com", "*", "monthly")

        assert asyncio.run(go()) is False

    def test_delete_only_removes_matching_key(self):
        """Deleting org_id=A:provider=X must not remove org_id=A:provider=Y."""
        store = _make_store()

        async def go():
            await store.set_org_cap(_TENANT, "default", "openai", 1_000_000, "monthly")
            await store.set_org_cap(_TENANT, "default", "anthropic", 2_000_000, "monthly")
            await store.delete_org_cap(_TENANT, "default", "openai")
            return await store.get_org_caps(_TENANT)

        caps = asyncio.run(go())
        assert len(caps) == 1
        assert caps[0]["provider"] == "anthropic"


# ===========================================================================
# Route integration tests (HTTP DELETE via ASGI)
# ===========================================================================


class TestDeleteOrgCapRoute:

    def test_delete_existing_org_cap_returns_204(self):
        store = _make_store()
        app = _make_app(store=store)

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                # Create
                await c.post("/admin/budget/org-caps", json={
                    "org_id": "default", "provider": "openai",
                    "token_cap": 500_000, "period": "monthly",
                })
                # Delete
                r = await c.delete("/admin/budget/org-caps", params={"org_id": "default", "provider": "openai"})
                return r.status_code

        try:
            assert asyncio.run(go()) == 204
        finally:
            _teardown()

    def test_delete_existing_org_cap_removes_from_list(self):
        store = _make_store()
        app = _make_app(store=store)

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                await c.post("/admin/budget/org-caps", json={
                    "org_id": "default", "provider": "openai",
                    "token_cap": 500_000, "period": "monthly",
                })
                await c.delete("/admin/budget/org-caps", params={"org_id": "default", "provider": "openai"})
                g = await c.get("/admin/budget/org-caps")
                return g.json()

        try:
            body = asyncio.run(go())
            assert body["org_caps"] == []
        finally:
            _teardown()

    def test_delete_nonexistent_org_cap_returns_404(self):
        store = _make_store()
        app = _make_app(store=store)

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                r = await c.delete("/admin/budget/org-caps", params={"org_id": "ghost", "provider": "openai"})
                return r.status_code, r.json()

        try:
            code, body = asyncio.run(go())
            assert code == 404
            assert body["detail"]["error"] == "org_cap_not_found"
        finally:
            _teardown()


class TestDeleteGroupBudgetRoute:

    def test_delete_existing_group_budget_returns_204(self):
        store = _make_store()
        app = _make_app(store=store)

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                await c.post("/admin/budget/groups", json={
                    "group_id": "engineering", "provider": "*",
                    "token_budget": 1_000_000, "period": "monthly",
                })
                r = await c.delete("/admin/budget/groups", params={
                    "group_id": "engineering", "provider": "*", "period": "monthly",
                })
                return r.status_code

        try:
            assert asyncio.run(go()) == 204
        finally:
            _teardown()

    def test_delete_nonexistent_group_budget_returns_404(self):
        store = _make_store()
        app = _make_app(store=store)

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                r = await c.delete("/admin/budget/groups", params={
                    "group_id": "ghost", "provider": "*", "period": "monthly",
                })
                return r.status_code, r.json()

        try:
            code, body = asyncio.run(go())
            assert code == 404
            assert body["detail"]["error"] == "group_budget_not_found"
        finally:
            _teardown()


class TestDeleteIndividualBudgetRoute:

    def test_delete_existing_individual_budget_returns_204(self):
        store = _make_store()
        app = _make_app(store=store)

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                await c.post("/admin/budget/individuals", json={
                    "identity_id": "alice@test.local", "provider": "*",
                    "token_budget": 100_000, "period": "monthly",
                })
                r = await c.delete("/admin/budget/individuals", params={
                    "identity_id": "alice@test.local", "provider": "*", "period": "monthly",
                })
                return r.status_code

        try:
            assert asyncio.run(go()) == 204
        finally:
            _teardown()

    def test_delete_nonexistent_individual_budget_returns_404(self):
        store = _make_store()
        app = _make_app(store=store)

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                r = await c.delete("/admin/budget/individuals", params={
                    "identity_id": "ghost@test.local", "provider": "*", "period": "monthly",
                })
                return r.status_code, r.json()

        try:
            code, body = asyncio.run(go())
            assert code == 404
            assert body["detail"]["error"] == "individual_budget_not_found"
        finally:
            _teardown()


# ===========================================================================
# Audit emission
# ===========================================================================


class TestDeleteAuditEvent:

    def test_delete_org_cap_emits_audit_event(self):
        """Successful DELETE emits a ConfigChangedEvent with change_type=delete semantics."""
        store = _make_store()
        writer = MagicMock()
        app = _make_app(store=store, audit_writer=writer)

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                await c.post("/admin/budget/org-caps", json={
                    "org_id": "default", "provider": "openai",
                    "token_cap": 500_000, "period": "monthly",
                })
                await c.delete("/admin/budget/org-caps", params={"org_id": "default", "provider": "openai"})

        try:
            asyncio.run(go())
        finally:
            _teardown()

        writer.write.assert_called_once()
        event = writer.write.call_args[0][0]
        # ConfigChangedEvent fields
        assert event.setting == "budget:org_cap"
        assert event.new_value == "deleted"
        assert "default:openai" in event.previous_value
        assert event.admin_account == "admin@test.local"

    def test_delete_no_audit_on_404(self):
        """No audit event emitted when the target doesn't exist (404 path)."""
        store = _make_store()
        writer = MagicMock()
        app = _make_app(store=store, audit_writer=writer)

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                await c.delete("/admin/budget/org-caps", params={"org_id": "ghost", "provider": "openai"})

        try:
            asyncio.run(go())
        finally:
            _teardown()

        writer.write.assert_not_called()

    def test_delete_no_audit_when_writer_none(self):
        """No crash when audit_writer is None (writer not configured)."""
        store = _make_store()
        app = _make_app(store=store, audit_writer=None)

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                await c.post("/admin/budget/org-caps", json={
                    "org_id": "default", "provider": "openai",
                    "token_cap": 500_000, "period": "monthly",
                })
                r = await c.delete("/admin/budget/org-caps", params={"org_id": "default", "provider": "openai"})
                return r.status_code

        try:
            code = asyncio.run(go())
            assert code == 204  # succeeds even without audit writer
        finally:
            _teardown()
