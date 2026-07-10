"""
v2.25.5 — Admin-console CRUD + data-sourced dropdown endpoints.

Covers the supporting admin API for the 2.25.5 admin-UI pass:

  B3  — Budget caps persist + render back (BudgetConfigStore, Redis db/3).
  R4  — GET /admin/models/allocation-targets server-side filtering
        (non-admin users / orgs / non-admin groups).
  R5  — PUT /admin/accounts/{username} + PUT /admin/users/{username}
        (edit email + status, step-up gated, SoD collision-guarded,
        tier/role NOT editable).
  R19 — GET /admin/audit/facets verdict list + verdict search filter spans
        all verdict/outcome/decision fields.
  R20 — GET /admin/audit/facets source-type list + source_type search filter.

Contract test: every dropdown-source endpoint returns the expected shape.

These are source/functional unit tests — they mount only the router under
test with auth bypassed via dependency_overrides (matching the existing
test_backup_verify / test_admin_budget_requires_session patterns). They do not
require a running stack.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

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


# ===========================================================================
# B3 — BudgetConfigStore persistence + read-back
# ===========================================================================

class TestBudgetConfigStorePersists:
    """B3: budget caps must persist AND read back via the Redis db/3 store."""

    def _store(self):
        from yashigani.billing.budget_config_store import BudgetConfigStore
        return BudgetConfigStore(fakeredis.FakeStrictRedis())

    def test_org_cap_round_trips(self):
        s = self._store()

        async def go():
            await s.set_org_cap(_TENANT, "default", "openai", 1_000_000, "monthly")
            return await s.get_org_caps(_TENANT)

        caps = asyncio.run(go())
        assert len(caps) == 1
        assert caps[0]["org_id"] == "default"
        assert caps[0]["provider"] == "openai"
        assert caps[0]["token_cap"] == 1_000_000

    def test_group_budget_round_trips(self):
        s = self._store()

        async def go():
            await s.set_group_budget(_TENANT, "engineering", "*", 500_000, "monthly")
            return await s.get_group_budgets(_TENANT)

        g = asyncio.run(go())
        assert len(g) == 1 and g[0]["group_id"] == "engineering"
        assert g[0]["token_budget"] == 500_000

    def test_individual_budget_round_trips(self):
        s = self._store()

        async def go():
            await s.set_individual_budget(_TENANT, "alice@example.com", "*", 100_000, "monthly")
            return await s.get_individual_budgets(_TENANT)

        i = asyncio.run(go())
        assert len(i) == 1 and i[0]["identity_id"] == "alice@example.com"
        assert i[0]["token_budget"] == 100_000

    def test_org_cap_upsert_does_not_duplicate(self):
        s = self._store()

        async def go():
            await s.set_org_cap(_TENANT, "default", "openai", 1, "monthly")
            await s.set_org_cap(_TENANT, "default", "openai", 999, "monthly")
            return await s.get_org_caps(_TENANT)

        caps = asyncio.run(go())
        assert len(caps) == 1 and caps[0]["token_cap"] == 999

    def test_configure_wires_store_into_routes(self):
        """The B3 fix wires the store via budget.configure() — the route helper
        must pick it up so set_* actually persists (was the root cause: never
        called → _state.budget_store stayed None → 201 but no-op)."""
        from yashigani.backoffice.routes import budget as budget_routes
        s = self._store()
        budget_routes.configure(budget_store=s)
        try:
            assert budget_routes._state.budget_store is s
        finally:
            budget_routes.configure(budget_store=None)


def _budget_app():
    from yashigani.backoffice.routes import budget as budget_routes
    from yashigani.backoffice.middleware import require_admin_session
    from yashigani.billing.budget_config_store import BudgetConfigStore

    store = BudgetConfigStore(fakeredis.FakeStrictRedis())
    budget_routes.configure(budget_store=store)
    app = FastAPI()
    app.dependency_overrides[require_admin_session] = lambda: SimpleNamespace(
        account_id="admin1", account_tier="admin"
    )
    app.include_router(budget_routes.router)
    return app


class TestBudgetEndToEnd:
    """B3 functional: POST a cap then GET it back through the real routes."""

    def test_post_then_get_org_cap(self):
        app = _budget_app()

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                r = await c.post("/admin/budget/org-caps", json={
                    "org_id": "default", "provider": "openai",
                    "token_cap": 250000, "period": "monthly",
                })
                assert r.status_code == 201, r.text
                g = await c.get("/admin/budget/org-caps")
                assert g.status_code == 200
                return g.json()

        body = asyncio.run(go())
        from yashigani.backoffice.routes import budget as budget_routes
        budget_routes.configure(budget_store=None)  # teardown
        assert body["org_caps"], "B3 REGRESSION: cap did not render back"
        assert body["org_caps"][0]["token_cap"] == 250000


# ===========================================================================
# R4 — allocation-targets server-side filtering
# ===========================================================================

def _models_app(auth_service=None, rbac_store=None):
    from yashigani.backoffice.routes import models as models_routes
    from yashigani.backoffice.middleware import require_admin_session
    from yashigani.backoffice.state import backoffice_state

    backoffice_state.auth_service = auth_service
    backoffice_state.rbac_store = rbac_store
    app = FastAPI()
    app.dependency_overrides[require_admin_session] = lambda: SimpleNamespace(
        account_id="admin1", account_tier="admin"
    )
    app.include_router(models_routes.router, prefix="/admin/models")
    return app


class TestAllocationTargets:
    """R4: target dropdown source filters out admins / admin groups."""

    def test_user_targets_exclude_admins(self):
        auth = MagicMock()
        auth.list_accounts = AsyncMock(return_value=[
            SimpleNamespace(username="alice", email="alice@x.com", account_tier="user"),
            SimpleNamespace(username="bob", email="bob@x.com", account_tier="user"),
            SimpleNamespace(username="root@x.com", email="root@x.com", account_tier="admin"),
        ])
        app = _models_app(auth_service=auth)

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.get("/admin/models/allocation-targets?target_type=user")

        r = asyncio.run(go())
        assert r.status_code == 200
        ids = [t["id"] for t in r.json()["targets"]]
        assert "alice@x.com" in ids and "bob@x.com" in ids
        assert "root@x.com" not in ids, "R4: admin user leaked into target list"

    def test_group_targets_exclude_admin_groups(self):
        rbac = MagicMock()
        rbac.list_groups = MagicMock(return_value=[
            SimpleNamespace(id="g-eng", display_name="Engineering"),
            SimpleNamespace(id="g-admins", display_name="Administrators"),
            SimpleNamespace(id="g-sysadmin", display_name="sysadmin"),
        ])
        app = _models_app(rbac_store=rbac)

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.get("/admin/models/allocation-targets?target_type=group")

        r = asyncio.run(go())
        labels = [t["label"] for t in r.json()["targets"]]
        assert "Engineering" in labels
        assert "Administrators" not in labels, "R4: admin group leaked"
        assert "sysadmin" not in labels, "R4: 'admin'-substring group leaked"

    def test_org_targets_include_default(self):
        app = _models_app()

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.get("/admin/models/allocation-targets?target_type=org")

        r = asyncio.run(go())
        assert r.status_code == 200
        ids = [t["id"] for t in r.json()["targets"]]
        assert "default" in ids

    def test_invalid_target_type_rejected(self):
        app = _models_app()

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.get("/admin/models/allocation-targets?target_type=bogus")

        r = asyncio.run(go())
        assert r.status_code == 400


# ===========================================================================
# R19 / R20 — audit facets + filters
# ===========================================================================

def _audit_app():
    from yashigani.backoffice.routes import audit_search
    from yashigani.backoffice.middleware import require_admin_session
    app = FastAPI()
    app.dependency_overrides[require_admin_session] = lambda: SimpleNamespace(
        account_id="admin1", account_tier="admin"
    )
    app.include_router(audit_search.router, prefix="/admin/audit")
    return app


class TestAuditFacets:
    """R19/R20: facets source endpoint returns complete verdict + source lists."""

    def test_facets_shape_and_wildcard(self):
        app = _audit_app()

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.get("/admin/audit/facets")

        r = asyncio.run(go())
        assert r.status_code == 200
        body = r.json()
        assert "verdicts" in body and "source_types" in body
        # First entry of each is the explicit "* / All" wildcard (value == "").
        assert body["verdicts"][0]["value"] == ""
        assert body["source_types"][0]["value"] == ""
        vvals = {v["value"] for v in body["verdicts"]}
        # R19 named states must all be present.
        for needed in ("allow", "deny", "blocked", "redact", "failure", "attempt", "exception"):
            assert needed in vvals, f"R19: verdict '{needed}' missing from facets"
        svals = {s["value"] for s in body["source_types"]}
        for needed in ("USER", "AGENT", "MCP", "API"):
            assert needed in svals, f"R20: source-type '{needed}' missing from facets"

    def test_verdict_filter_spans_outcome_fields(self):
        """R19: the verdict filter must match the various fields the audit model
        uses for verdict/outcome/decision, not just `action`/`verdict`."""
        from yashigani.backoffice.routes.audit_search import _Filters
        f = _Filters(None, None, None, None, verdict="deny", user=None, free_text=None)
        assert f.matches_record({"opa_decision": "deny"}) is True
        assert f.matches_record({"action": "ALLOW"}) is False
        f2 = _Filters(None, None, None, None, verdict="exception", user=None, free_text=None)
        assert f2.matches_record({"outcome": "exception"}) is True

    def test_source_type_filter_matches_event_type(self):
        """R20: source_type matches as a substring of event_type."""
        from yashigani.backoffice.routes.audit_search import _Filters
        f = _Filters(None, None, None, None, verdict=None, user=None, free_text=None,
                     source_type="AGENT")
        assert f.matches_record({"event_type": "AGENT_CALL_ALLOWED"}) is True
        assert f.matches_record({"event_type": "ADMIN_LOGIN"}) is False
        # wildcard "*" disables the filter
        fall = _Filters(None, None, None, None, verdict=None, user=None, free_text=None,
                        source_type="*")
        assert fall.matches_record({"event_type": "ADMIN_LOGIN"}) is True


# ===========================================================================
# R5 — account/user update endpoints
# ===========================================================================

def _accounts_app(auth_service):
    from yashigani.backoffice.routes import accounts as accounts_routes
    from yashigani.backoffice.middleware import require_admin_session, require_stepup_admin_session
    from yashigani.backoffice.state import backoffice_state

    backoffice_state.auth_service = auth_service
    backoffice_state.session_store = MagicMock()
    backoffice_state.audit_writer = MagicMock()
    backoffice_state.identity_registry = None
    backoffice_state.admin_min_active = 2

    sess = SimpleNamespace(account_id="admin1", account_tier="admin")
    app = FastAPI()
    app.dependency_overrides[require_admin_session] = lambda: sess
    app.dependency_overrides[require_stepup_admin_session] = lambda: sess
    app.include_router(accounts_routes.router, prefix="/admin/accounts")
    return app


class TestUpdateAdmin:
    """R5: PUT /admin/accounts/{username} edits email + status."""

    def test_update_email(self):
        auth = MagicMock()
        rec = SimpleNamespace(account_id="a1", account_tier="admin",
                              email="old@x.com", disabled=False)
        auth.get_account = AsyncMock(return_value=rec)
        auth.get_account_by_email = AsyncMock(return_value=None)
        auth.set_email = AsyncMock(return_value=True)
        app = _accounts_app(auth)

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.put("/admin/accounts/bob@x.com", json={"email": "new@x.com"})

        r = asyncio.run(go())
        assert r.status_code == 200, r.text
        assert "email" in r.json()["changed"]
        auth.set_email.assert_awaited_once()

    def test_update_rejects_user_email_collision(self):
        """SoD-001: cannot point an admin at an email already used by a user."""
        auth = MagicMock()
        rec = SimpleNamespace(account_id="a1", account_tier="admin",
                              email="old@x.com", disabled=False)
        auth.get_account = AsyncMock(return_value=rec)
        auth.get_account_by_email = AsyncMock(return_value=SimpleNamespace(account_tier="user"))
        auth.set_email = AsyncMock()
        app = _accounts_app(auth)

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.put("/admin/accounts/bob@x.com", json={"email": "taken@x.com"})

        r = asyncio.run(go())
        assert r.status_code == 409
        auth.set_email.assert_not_awaited()

    def test_update_missing_account_404(self):
        auth = MagicMock()
        auth.get_account = AsyncMock(return_value=None)
        app = _accounts_app(auth)

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.put("/admin/accounts/ghost@x.com", json={"email": "x@x.com"})

        assert asyncio.run(go()).status_code == 404

    def test_disable_blocked_by_min_active(self):
        auth = MagicMock()
        rec = SimpleNamespace(account_id="a1", account_tier="admin",
                              email="old@x.com", disabled=False)
        auth.get_account = AsyncMock(return_value=rec)
        auth.active_admin_count = AsyncMock(return_value=2)  # == min_active
        app = _accounts_app(auth)

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.put("/admin/accounts/bob@x.com", json={"disabled": True})

        r = asyncio.run(go())
        assert r.status_code == 409
        assert r.json()["detail"]["error"] == "ADMIN_ACTIVE_MINIMUM_VIOLATION"

    def test_no_tier_field_in_request_model(self):
        """R5/SoD: tier/role must NOT be an editable field."""
        from yashigani.backoffice.routes.accounts import UpdateAdminRequest
        assert "account_tier" not in UpdateAdminRequest.model_fields
        assert "tier" not in UpdateAdminRequest.model_fields
        assert set(UpdateAdminRequest.model_fields) <= {"email", "disabled"}


# ===========================================================================
# Contract — every dropdown-source endpoint returns the expected shape
# ===========================================================================

class TestDropdownSourceContracts:
    """The UI dropdowns depend on these source endpoints returning a stable
    shape. This pins the contract so a backend change can't silently break a
    dropdown."""

    def test_allocation_targets_contract(self):
        auth = MagicMock()
        auth.list_accounts = AsyncMock(return_value=[
            SimpleNamespace(username="alice", email="alice@x.com", account_tier="user"),
        ])
        app = _models_app(auth_service=auth)

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.get("/admin/models/allocation-targets?target_type=user")

        body = asyncio.run(go()).json()
        assert "target_type" in body and "targets" in body
        assert isinstance(body["targets"], list)
        for t in body["targets"]:
            assert "id" in t and "label" in t

    def test_audit_facets_contract(self):
        app = _audit_app()

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.get("/admin/audit/facets")

        body = asyncio.run(go()).json()
        for key in ("verdicts", "source_types"):
            assert isinstance(body[key], list) and body[key]
            for entry in body[key]:
                assert "value" in entry and "label" in entry

    def test_budget_group_dropdown_source(self):
        """B3 UI: budget group-id dropdown re-uses allocation-targets?target_type=group.
        Verify the endpoint returns {id, label} entries consumable by fillSelect().
        Admin-related groups must be excluded."""
        rbac = MagicMock()
        rbac.list_groups = MagicMock(return_value=[
            SimpleNamespace(id="g-eng", display_name="Engineering"),
            SimpleNamespace(id="g-admins", display_name="Administrators"),
        ])
        app = _models_app(rbac_store=rbac)

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.get("/admin/models/allocation-targets?target_type=group")

        body = asyncio.run(go()).json()
        assert "targets" in body
        ids = [t["id"] for t in body["targets"]]
        assert "g-eng" in ids, "Engineering group must appear in budget group dropdown"
        assert "g-admins" not in ids, "Admin group must be excluded from budget group dropdown"
        # Every entry has both id and label (required by fillSelect)
        for t in body["targets"]:
            assert "id" in t and "label" in t

    def test_budget_individual_dropdown_source(self):
        """B3 UI: budget ind-id dropdown re-uses allocation-targets?target_type=user.
        Non-admin users must appear; admin accounts must be excluded."""
        auth = MagicMock()
        auth.list_accounts = AsyncMock(return_value=[
            SimpleNamespace(username="alice", email="alice@x.com", account_tier="user"),
            SimpleNamespace(username="adminroot", email="adminroot@x.com", account_tier="admin"),
        ])
        app = _models_app(auth_service=auth)

        async def go():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                return await c.get("/admin/models/allocation-targets?target_type=user")

        body = asyncio.run(go()).json()
        ids = [t["id"] for t in body["targets"]]
        assert "alice@x.com" in ids, "User alice must appear in budget individual dropdown"
        assert "adminroot@x.com" not in ids, "Admin must be excluded from individual dropdown"
