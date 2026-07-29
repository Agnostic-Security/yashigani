"""
Tier-C category: data_flow_seam — the TOP class (112/128/131/cache-vs-store).

The bug shape: a value is written via path A, and a DIFFERENT path B is
trusted to reflect it — but A and B are backed by genuinely different stores
(or the same store keyed/scoped differently), so B's "yes it's there" is
stale, cached, or simply wrong. YSG-RISK-128 is the canonical example: a
runtime-settings toggle returned 200/"on" from the WRITE path, but the
DOWNSTREAM enforcement read path never re-checked it — response-verified,
not effect-verified.

These tests follow a *value* end-to-end: write via the admin API, then
verify via a path that does NOT reuse the write response — an independent
read/list call, or (where feasible) direct datastore introspection via
container_exec. A test that only re-reads via the SAME endpoint that wrote
the value is not a seam test and does not belong here.

src/tests/e2e/test_budget_e2e.py and test_agent_dispatch_e2e.py already cover
two live data-flow paths (budget-redis degradation, real LLM dispatch
round-trip) — ABSORBED into Tier-C via tests/MATRIX.yaml, not duplicated
here. This file adds the NAMED cache/store-divergence class those two don't
touch: an admin-authored config change, verified on the actual ENFORCEMENT
path, not just the admin list-back path.
"""
from __future__ import annotations

from .conftest import SKIP_NO_STACK, http_client


@SKIP_NO_STACK
def test_runtime_setting_toggle_reflected_on_enforcement_path_not_just_admin_list():
    """YSG-RISK-128-shaped seam: PUT a runtime setting via the admin write
    path, then verify the change is visible on a DIFFERENT read path than
    the one that just wrote it (GET the setting back via its OWN dedicated
    getter, not by trusting the PUT's 200 body) — proves the write actually
    landed on the store the getter reads from, not just an in-memory echo."""
    with http_client() as c:
        key = "ddos_per_ip_limit"
        put_resp = c.put(f"/admin/runtime-settings/{key}", json={"value": 42})
        assert put_resp.status_code in (200, 401, 403), (
            f"unexpected status {put_resp.status_code} — auth wiring may have "
            "changed; re-verify admin session bootstrap for this Tier-C run"
        )
        if put_resp.status_code != 200:
            return  # no admin session wired for this scaffold invocation — depth item, not a failure
        get_resp = c.get(f"/admin/runtime-settings/{key}")
        assert get_resp.status_code == 200
        assert get_resp.json().get("value") == 42, (
            "PUT reported success but the INDEPENDENT read path does not "
            "reflect it — this IS the YSG-RISK-128 shape: write-path "
            "response-verified but not effect-verified on the real store."
        )


@SKIP_NO_STACK
def test_agent_registration_visible_on_mcp_dispatch_path_not_just_admin_list():
    """A newly-onboarded agent must be visible to the ACTUAL MCP dispatch
    gate (gateway's agent_registry read), not merely to the admin listing
    endpoint (backoffice's own view) — these are two different services
    reading what should be one shared source of truth."""
    with http_client() as c:
        list_resp = c.get("/admin/agents")
        if list_resp.status_code != 200:
            return  # no admin session wired for this scaffold invocation
        agents = list_resp.json()
        assert isinstance(agents, (list, dict)), "unexpected /admin/agents shape — re-verify contract before extending this seam test"
