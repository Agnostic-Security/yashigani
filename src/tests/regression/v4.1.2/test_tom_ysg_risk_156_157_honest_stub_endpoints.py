"""
Regression test -- v4.1.2 YSG-RISK-156/157 (MED/LOW): stub endpoints that
previously returned a misleading 200/empty must return an honest signal.

156 — GET /user/memory (per-user Letta memory, Phase 3 / RISK-107) was a
plain 200 with `entries: []` + a "not yet configured" note. A caller
checking only the HTTP status reads that as "success, zero entries", not
"not built yet". Deferred past 4.1.2 (needs the Phase-3 NHI/SVID mesh +
per-user Letta container) -- now an honest 501.

157 — GET /admin/budget/tree (nested org->group->identity budget view) was
a plain 200 with `tree: []`. A genuinely correct nested tree needs
group->org / identity->group membership linkage that does not exist in the
budget schema (group_budgets / individual_budgets carry no org_id/group_id
FKs -- that lives in the separate RBAC group store). Deferred past 4.1.2 --
now an honest 501. GET /admin/budget/{org-caps,groups,individuals} remain
the flat (non-nested) source of truth.

Both were verified NOT to crash the existing frontend Promise.all() dashboards
that call them: ApiClient.get() (api-client.js) returns null on any !resp.ok
status rather than throwing, and both consuming JS modules already null-guard
(_coerceList / `this._tree && ...`).
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

try:
    from fastapi.testclient import TestClient
    _HAVE_FASTAPI = True
except ImportError:
    _HAVE_FASTAPI = False

pytestmark = pytest.mark.skipif(not _HAVE_FASTAPI, reason="fastapi required")

_FAKE_SESSION = SimpleNamespace(account_id="test-user", account_tier="user")
_FAKE_ADMIN_SESSION = SimpleNamespace(account_id="test-admin", account_tier="admin")


class TestUserMemoryEndpoint:
    def test_user_memory_returns_501_not_implemented(self):
        import fastapi as _fastapi

        from yashigani.backoffice import middleware as mw
        from yashigani.backoffice.routes.user_ui import router

        app = _fastapi.FastAPI()
        app.dependency_overrides[mw.require_user_session] = lambda: _FAKE_SESSION
        app.include_router(router)
        client = TestClient(app)

        resp = client.get("/user/memory")
        assert resp.status_code == 501
        assert resp.json()["detail"]["error"] == "not_implemented"


class TestBudgetTreeEndpoint:
    def test_budget_tree_returns_501_not_implemented(self):
        import fastapi as _fastapi

        from yashigani.backoffice import middleware as mw
        from yashigani.backoffice.routes.budget import router

        app = _fastapi.FastAPI()
        app.dependency_overrides[mw.require_admin_session] = lambda: _FAKE_ADMIN_SESSION
        app.include_router(router)
        client = TestClient(app)

        resp = client.get("/admin/budget/tree")
        assert resp.status_code == 501
        assert resp.json()["detail"]["error"] == "not_implemented"

    def test_flat_endpoints_still_return_200(self):
        """The 501 on /tree must not regress the flat (non-nested) endpoints
        that remain the real source of truth."""
        import fastapi as _fastapi

        from yashigani.backoffice import middleware as mw
        from yashigani.backoffice.routes.budget import router

        app = _fastapi.FastAPI()
        app.dependency_overrides[mw.require_admin_session] = lambda: _FAKE_ADMIN_SESSION
        app.include_router(router)
        client = TestClient(app)

        for path in ("/admin/budget/org-caps", "/admin/budget/groups", "/admin/budget/individuals"):
            resp = client.get(path)
            assert resp.status_code == 200, f"{path}: {resp.status_code} {resp.text}"
