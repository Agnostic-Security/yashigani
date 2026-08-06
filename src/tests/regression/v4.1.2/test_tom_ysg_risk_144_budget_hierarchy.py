"""
Regression test -- v4.1.2 YSG-RISK-144 (MED-HIGH): budget hierarchy
(individual <= group <= org) claimed but not enforced.

Root cause: BudgetEnforcer.check() only ever evaluated the identity's OWN
allocation. The per-request budget-check call site in
gateway/openai_router.py::chat_completions called ONLY `.check()`, never
`.check_group()`/`.check_org()` — an identity within its own budget but over
its GROUP or ORG cap was never denied/degraded. Compounding this,
group/org budgets set via the admin API (POST /admin/budget/groups,
POST /admin/budget/org-caps) were persisted to Postgres but NEVER synced to
Redis, so there was no cap value to even check against; and
BudgetEnforcer.record() call sites never passed group_ids/org_id, so the
group/org usage counters were never incremented either.

Fix:
  - BudgetEnforcer: get/set_group_allocation, get/set_org_allocation,
    check_hierarchy() (worst-case signal across identity/group/org tiers).
  - routes/budget.py: create_group_budget/create_org_cap now sync to Redis.
  - gateway/openai_router.py: budget check now calls check_hierarchy() with
    group_ids/org_id from the resolved identity dict; both record() call
    sites now pass group_ids/org_id too.

These tests exercise BudgetEnforcer directly against fakeredis — the
identity/group/org counter and allocation wiring, independent of the
gateway request-handling scaffolding.
"""
from __future__ import annotations

import pytest

fakeredis = pytest.importorskip("fakeredis", reason="fakeredis not installed")


@pytest.fixture()
def enforcer():
    from yashigani.billing.budget_enforcer import BudgetEnforcer

    r = fakeredis.FakeRedis(decode_responses=True)
    return BudgetEnforcer(redis_client=r)


class TestGroupOrgAllocationRoundTrip:
    def test_group_allocation_set_and_get(self, enforcer):
        assert enforcer.get_group_allocation("finance-team", "cloud") == 0
        enforcer.set_group_allocation("finance-team", "cloud", 50_000)
        assert enforcer.get_group_allocation("finance-team", "cloud") == 50_000

    def test_org_allocation_set_and_get(self, enforcer):
        assert enforcer.get_org_allocation("acme-corp", "cloud") == 0
        enforcer.set_org_allocation("acme-corp", "cloud", 1_000_000)
        assert enforcer.get_org_allocation("acme-corp", "cloud") == 1_000_000


class TestCheckHierarchyIndividualOverGroupCap:
    """The scenario named explicitly in the finding: an individual UNDER
    their own budget but OVER their group's cap must be denied (EXHAUSTED)."""

    def test_individual_within_own_budget_but_group_exhausted_is_exhausted(self, enforcer):
        from yashigani.billing.budget_enforcer import BudgetSignal

        # Individual: generous allocation, low usage — own tier is NORMAL.
        enforcer.set_group_allocation("eng-team", "cloud", 1000)
        # Group already used 1000/1000 == 100% exhausted.
        enforcer.record("someone_else", "cloud", 1000, group_ids=["eng-team"])

        state = enforcer.check_hierarchy(
            "alice", "cloud", budget_total=1_000_000,  # alice's own budget is huge
            group_ids=["eng-team"], org_id="",
        )
        assert state.signal == BudgetSignal.EXHAUSTED

    def test_individual_within_own_and_group_but_org_exhausted_is_exhausted(self, enforcer):
        from yashigani.billing.budget_enforcer import BudgetSignal

        enforcer.set_org_allocation("acme-corp", "cloud", 500)
        enforcer.record("someone_else", "cloud", 500, org_id="acme-corp")

        state = enforcer.check_hierarchy(
            "alice", "cloud", budget_total=1_000_000,
            group_ids=[], org_id="acme-corp",
        )
        assert state.signal == BudgetSignal.EXHAUSTED

    def test_all_tiers_normal_is_normal(self, enforcer):
        from yashigani.billing.budget_enforcer import BudgetSignal

        enforcer.set_group_allocation("eng-team", "cloud", 1_000_000)
        enforcer.set_org_allocation("acme-corp", "cloud", 1_000_000)

        state = enforcer.check_hierarchy(
            "alice", "cloud", budget_total=1_000_000,
            group_ids=["eng-team"], org_id="acme-corp",
        )
        assert state.signal == BudgetSignal.NORMAL

    def test_unconfigured_group_or_org_allocation_never_escalates(self, enforcer):
        """A group/org with NO configured allocation (0/unset) must be treated
        as unlimited for that tier — it must never spuriously escalate."""
        from yashigani.billing.budget_enforcer import BudgetSignal

        state = enforcer.check_hierarchy(
            "alice", "cloud", budget_total=1_000_000,
            group_ids=["unconfigured-group"], org_id="unconfigured-org",
        )
        assert state.signal == BudgetSignal.NORMAL

    def test_own_tier_used_total_pct_preserved_on_escalation(self, enforcer):
        """The returned BudgetState's used/total/pct reflect the identity's
        OWN tier even when signal is escalated by group/org — only signal
        changes."""
        enforcer.set_group_allocation("eng-team", "cloud", 100)
        enforcer.record("someone_else", "cloud", 100, group_ids=["eng-team"])

        state = enforcer.check_hierarchy(
            "alice", "cloud", budget_total=1_000_000,
            group_ids=["eng-team"], org_id="",
        )
        assert state.total == 1_000_000
        assert state.used == 0  # alice herself hasn't used anything


class TestRecordAccumulatesGroupAndOrgCounters:
    def test_record_increments_group_and_org_counters(self, enforcer):
        enforcer.record(
            "alice", "cloud", 250, group_ids=["eng-team", "on-call"], org_id="acme-corp",
        )
        group_state = enforcer.check_group("eng-team", "cloud", budget_total=1000)
        assert group_state.used == 250
        org_state = enforcer.check_org("acme-corp", "cloud", cap=1000)
        assert org_state.used == 250
        # A second group the identity belongs to is ALSO incremented.
        oncall_state = enforcer.check_group("on-call", "cloud", budget_total=1000)
        assert oncall_state.used == 250
