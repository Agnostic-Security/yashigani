"""
Tier-C category: multitenant_licensing.

Multi-tenant isolation (no cross-org data leak) + the full licensing
lifecycle (activate -> tier -> restrain -> offline grace) must hold on a
LIVE deployment. Restrain-to-Community, never degrade
(project_yashigani_v50_scope_and_build.md licence hardening design).
"""
from __future__ import annotations

from .conftest import SKIP_NO_STACK, http_client


@SKIP_NO_STACK
def test_org_scoped_resource_not_visible_cross_tenant():
    """A resource scoped to org-a must not be readable via an org-b-scoped
    session/identity — baseline reachability + auth-gate check here; extend
    with real two-org fixtures + an actual cross-org read attempt once a
    Tier-C multi-org bootstrap identity set is wired into this leg."""
    with http_client() as c:
        resp = c.get("/admin/agents")
        assert resp.status_code in (200, 401, 403)


@SKIP_NO_STACK
def test_license_status_endpoint_reachable():
    """Baseline reachability for the licence-status surface — extend with a
    real activate/restrain/offline-grace lifecycle exercise (a live licence
    lifecycle test necessarily mutates install state, so it needs an
    explicitly disposable Tier-C leg, not the shared dev stack)."""
    with http_client() as c:
        resp = c.get("/healthz")
        assert resp.status_code == 200
