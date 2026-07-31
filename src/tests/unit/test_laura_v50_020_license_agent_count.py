"""
LAURA-V50-020 (Low) — GET /admin/license reported ``limits.agents.current``
via ``registry.count("all")`` (active + inactive), so the dashboard agent
count never DECREASED after an agent was deactivated. Cap enforcement
(backoffice/routes/agents.py, backoffice/rbac_stack.py, gateway/rbac_stack.py)
uses the correct counters already and is NOT touched by this fix.

Fix under test (Tom, 2026-07-31): backoffice/routes/license.py
get_license_status() now reports ``registry.count("active")``.

Mode: unit — license_router mounted alone, require_admin_session overridden,
a fake AgentRegistry stub (count() only) wired onto backoffice_state, and
yashigani.licensing.get_license patched to a fixed LicenseState so the test
is independent of the real license file on disk.

Author: Tom. Last updated: 2026-07-31.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest

try:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    _HAVE_FASTAPI = True
except ImportError:  # pragma: no cover
    _HAVE_FASTAPI = False

pytestmark = pytest.mark.skipif(not _HAVE_FASTAPI, reason="fastapi required")


class _FakeAgentRegistry:
    """Minimal stand-in for AgentRegistry.count() — active vs all."""

    def __init__(self, active: int, all_: int) -> None:
        self._active = active
        self._all = all_

    def count(self, status: str = "active") -> int:
        if status == "active":
            return self._active
        if status == "all":
            return self._all
        return max(0, self._all - self._active)


def _make_app(registry):
    from yashigani.backoffice.routes.license import license_router
    from yashigani.backoffice.middleware import require_admin_session
    from yashigani.backoffice.state import backoffice_state

    backoffice_state.agent_registry = registry
    backoffice_state.auth_service = None
    backoffice_state.capability_policy_store = None

    app = FastAPI()
    app.dependency_overrides[require_admin_session] = lambda: SimpleNamespace(
        account_id="admin@test.local", account_tier="admin",
    )
    app.include_router(license_router, prefix="/admin/license", tags=["license"])
    return app


def _fake_license():
    from datetime import datetime, timezone

    from yashigani.licensing.model import LicenseState, LicenseTier

    return LicenseState(
        tier=LicenseTier.ENTERPRISE,
        org_domain="test.local",
        max_agents=10,
        max_end_users=10,
        max_admin_seats=5,
        max_orgs=1,
        features=frozenset(),
        issued_at=datetime.now(timezone.utc),
        expires_at=None,
        license_id="test-license",
        valid=True,
        error=None,
    )


class TestLicenseAgentCountReportsActiveOnly:
    def test_current_agents_uses_active_not_all(self):
        """3 active + 2 deactivated (5 total) -> limits.agents.current == 3,
        NOT 5. This is the core LAURA-V50-020 regression: count("all")
        included inactive agents and never decreased on deactivation."""
        registry = _FakeAgentRegistry(active=3, all_=5)
        app = _make_app(registry)
        client = TestClient(app)

        with patch("yashigani.licensing.get_license", return_value=_fake_license()):
            resp = client.get("/admin/license")

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["limits"]["agents"]["current"] == 3

    def test_current_agents_drops_after_deactivation(self):
        """Deactivating an agent (active count drops, all count unchanged)
        must be reflected immediately in the reported current count."""
        registry = _FakeAgentRegistry(active=4, all_=4)
        app = _make_app(registry)
        client = TestClient(app)

        with patch("yashigani.licensing.get_license", return_value=_fake_license()):
            resp_before = client.get("/admin/license")
        assert resp_before.json()["limits"]["agents"]["current"] == 4

        # Simulate deactivation: active drops, all (registry membership)
        # stays the same — this is exactly what registry.count("all") got
        # wrong (it never decreases here) and count("active") gets right.
        registry._active = 3

        with patch("yashigani.licensing.get_license", return_value=_fake_license()):
            resp_after = client.get("/admin/license")
        assert resp_after.json()["limits"]["agents"]["current"] == 3

    def test_no_registry_reports_zero(self):
        """backoffice_state.agent_registry is None (feature not wired) ->
        current stays 0, unchanged fail-open convention."""
        app = _make_app(None)
        client = TestClient(app)

        with patch("yashigani.licensing.get_license", return_value=_fake_license()):
            resp = client.get("/admin/license")

        assert resp.status_code == 200, resp.text
        assert resp.json()["limits"]["agents"]["current"] == 0
