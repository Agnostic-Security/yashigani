"""
FIND-3.0-005 — /admin/budget/usage/{identity_id} returns 503 "Budget enforcer not available".

Root cause (confirmed): budget.configure() in the backoffice lifespan (entrypoint.py)
only passed budget_store — never budget_enforcer — so _state.budget_enforcer stayed
None and every call to /usage/{identity_id} hit the 503 guard at budget.py:225.

Fix: backoffice lifespan now connects to budget-redis and instantiates a BudgetEnforcer,
then calls configure(budget_enforcer=..., budget_store=...).

Tests:
  - With enforcer configured: GET /usage/{id} returns 200 + usage dict
  - Without enforcer (unconfigured): GET /usage/{id} still returns 503
  - Usage data written via BudgetEnforcer.record() is visible via get_usage_summary()
    (validates the data pathway the backoffice reads)

These are unit tests: router mounted with auth bypassed, BudgetEnforcer backed by
fakeredis.  No live stack required.

Last updated: 2026-06-19T00:00:00+01:00
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_enforcer(fake_r=None):
    from yashigani.billing.budget_enforcer import BudgetEnforcer
    if fake_r is None:
        fake_r = fakeredis.FakeStrictRedis()
    return BudgetEnforcer(redis_client=fake_r), fake_r


def _make_app(enforcer=None):
    """Mount budget router with auth bypassed; wire enforcer if provided."""
    from yashigani.backoffice.routes import budget as budget_routes
    from yashigani.backoffice.middleware import require_admin_session

    budget_routes.configure(budget_enforcer=enforcer, budget_store=None)

    app = FastAPI()
    app.dependency_overrides[require_admin_session] = lambda: SimpleNamespace(
        account_id="admin@test.local", account_tier="admin"
    )
    app.include_router(budget_routes.router)
    return app


def _teardown():
    from yashigani.backoffice.routes import budget as budget_routes
    budget_routes.configure(budget_enforcer=None, budget_store=None)


# ===========================================================================
# Root-cause regression: unconfigured enforcer → 503
# ===========================================================================


class TestUsageUnconfigured:
    """Unconfigured enforcer still returns 503 — guard must stay in place."""

    def test_usage_without_enforcer_returns_503(self):
        app = _make_app(enforcer=None)

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                r = await c.get("/admin/budget/usage/alice@test.local")
                return r.status_code, r.json()

        try:
            code, body = asyncio.run(go())
            assert code == 503
            assert "not available" in body.get("detail", "")
        finally:
            _teardown()


# ===========================================================================
# With enforcer wired: usage endpoint returns data
# ===========================================================================


class TestUsageWithEnforcer:

    def test_usage_with_enforcer_returns_200(self):
        """When enforcer is configured, /usage/{id} returns 200 (not 503)."""
        enforcer, _ = _make_enforcer()
        app = _make_app(enforcer=enforcer)

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                r = await c.get("/admin/budget/usage/alice@test.local")
                return r.status_code

        try:
            assert asyncio.run(go()) == 200
        finally:
            _teardown()

    def test_usage_with_enforcer_returns_correct_shape(self):
        """Response has identity_id, period, usage keys."""
        enforcer, _ = _make_enforcer()
        app = _make_app(enforcer=enforcer)

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                r = await c.get("/admin/budget/usage/alice@test.local")
                return r.json()

        try:
            body = asyncio.run(go())
            assert body["identity_id"] == "alice@test.local"
            assert body["period"] == "monthly"
            assert "usage" in body
        finally:
            _teardown()

    def test_usage_reflects_recorded_tokens(self):
        """Tokens recorded via BudgetEnforcer.record() appear in the usage summary.

        This validates the full data pathway: gateway writes → enforcer reads back
        (same fakeredis), /usage/{id} returns the recorded tokens.
        """
        enforcer, fake_r = _make_enforcer()
        app = _make_app(enforcer=enforcer)

        # Simulate the gateway recording 1000 tokens for alice on openai
        enforcer.record("alice@test.local", "openai", 1000, period="monthly")

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                r = await c.get("/admin/budget/usage/alice@test.local", params={"period": "monthly"})
                return r.json()

        try:
            body = asyncio.run(go())
            assert body["usage"].get("openai", 0) == 1000, (
                "FIND-3.0-005 REGRESSION: recorded tokens not visible via /usage/{id}"
            )
        finally:
            _teardown()

    def test_usage_empty_for_unknown_identity(self):
        """No tokens recorded → usage dict is empty (not an error)."""
        enforcer, _ = _make_enforcer()
        app = _make_app(enforcer=enforcer)

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                r = await c.get("/admin/budget/usage/nobody@test.local")
                return r.status_code, r.json()

        try:
            code, body = asyncio.run(go())
            assert code == 200
            assert body["usage"] == {}
        finally:
            _teardown()

    def test_usage_period_param_respected(self):
        """The ?period= query param is forwarded to BudgetEnforcer.get_usage_summary."""
        enforcer, _ = _make_enforcer()
        app = _make_app(enforcer=enforcer)

        # Record monthly tokens
        enforcer.record("bob@test.local", "anthropic", 500, period="monthly")

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                # Ask for daily — should be empty because we recorded monthly
                r_daily = await c.get("/admin/budget/usage/bob@test.local", params={"period": "daily"})
                # Ask for monthly — should have 500
                r_monthly = await c.get("/admin/budget/usage/bob@test.local", params={"period": "monthly"})
                return r_daily.json(), r_monthly.json()

        try:
            daily_body, monthly_body = asyncio.run(go())
            assert daily_body["usage"].get("anthropic", 0) == 0
            assert monthly_body["usage"].get("anthropic", 0) == 500
        finally:
            _teardown()
