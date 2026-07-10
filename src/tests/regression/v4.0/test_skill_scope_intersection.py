"""
Regression tests — skill scope intersection invariant (R3 / RISK-097).

Verifies: effective_scope = declared ∩ invoker_grants ∩ system_ceiling

Properties proven:
  1. A skill in declared but NOT in invoker_grants is rejected.
  2. A skill in declared but NOT in system_ceiling is rejected.
  3. A skill in all three sets is granted.
  4. Empty declared → empty effective (no grants invented).
  5. Empty invoker_grants → system_ceiling used as the only gate (community tier).
  6. Intersection result is deterministic (order-independent).
  7. NHI invariant (RISK-097): a user with grants=[A,B] declaring [A] cannot
     receive [B] in effective_skills even if B is in system_ceiling.

Last updated: 2026-06-27T00:00:00+00:00
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from yashigani.backoffice.routes.user_agents import compute_effective_skills


# ---------------------------------------------------------------------------
# Deterministic helper — unit-testable without live Redis / identity registry
# ---------------------------------------------------------------------------

def _intersect(
    declared: list[str],
    invoker_grants: list[str],
    system_ceiling: list[str],
) -> tuple[list[str], list[str]]:
    """Mirror of compute_effective_skills without external I/O.

    Uses the same formula: effective = declared ∩ grants ∩ ceiling.
    Returns (effective_skills, rejected_skills).
    """
    d = set(declared)
    g = set(invoker_grants)
    c = set(system_ceiling)
    if g:
        effective = d & g & c
    else:
        effective = d & c
    return sorted(effective), sorted(d - effective)


# ===========================================================================
# Core intersection properties
# ===========================================================================


class TestScopeIntersection:

    def test_skill_granted_when_in_all_three(self):
        eff, rej = _intersect(["/tools/A"], ["/tools/A", "/tools/B"], ["/tools/A", "/tools/C"])
        assert "/tools/A" in eff
        assert rej == []

    def test_skill_outside_invoker_grants_rejected(self):
        """User cannot grant their agent a skill they don't hold (RISK-097 core)."""
        eff, rej = _intersect(["/tools/B"], ["/tools/A"], ["/tools/A", "/tools/B"])
        assert eff == []
        assert "/tools/B" in rej

    def test_skill_outside_system_ceiling_rejected(self):
        """A skill not exposed by any registered agent is always rejected."""
        eff, rej = _intersect(["/tools/phantom"], ["/tools/phantom"], ["/tools/A"])
        assert eff == []
        assert "/tools/phantom" in rej

    def test_empty_declared_produces_empty_effective(self):
        eff, rej = _intersect([], ["/tools/A", "/tools/B"], ["/tools/A"])
        assert eff == []
        assert rej == []

    def test_empty_invoker_grants_uses_ceiling_only(self):
        """Community tier: no identity record → ceiling is the only gate."""
        eff, rej = _intersect(
            ["/tools/A", "/tools/phantom"],
            [],  # empty grants = community tier
            ["/tools/A"],
        )
        assert eff == ["/tools/A"]
        assert rej == ["/tools/phantom"]

    def test_all_rejected_when_no_overlap(self):
        eff, rej = _intersect(["/tools/X", "/tools/Y"], ["/tools/A"], ["/tools/A"])
        assert eff == []
        assert set(rej) == {"/tools/X", "/tools/Y"}

    def test_result_is_sorted(self):
        eff, rej = _intersect(
            ["/tools/Z", "/tools/A", "/tools/M"],
            ["/tools/Z", "/tools/A", "/tools/M"],
            ["/tools/Z", "/tools/A", "/tools/M"],
        )
        assert eff == sorted(eff)
        assert rej == []

    def test_order_of_declared_does_not_matter(self):
        """Intersection result is set-based, not order-dependent."""
        eff1, _ = _intersect(["/tools/A", "/tools/B"], ["/tools/A"], ["/tools/A"])
        eff2, _ = _intersect(["/tools/B", "/tools/A"], ["/tools/A"], ["/tools/A"])
        assert eff1 == eff2

    def test_duplicates_in_declared_deduplicated(self):
        eff, rej = _intersect(
            ["/tools/A", "/tools/A", "/tools/A"],
            ["/tools/A"],
            ["/tools/A"],
        )
        assert eff == ["/tools/A"]


# ===========================================================================
# RISK-097 NHI containment invariant (§A.1)
# ===========================================================================


class TestNHIContainmentInvariant:
    """
    RISK-097: a user with allowed_paths=[A, B] who declares allowed_tools=[A]
    MUST receive effective_scope=[A], not [A, B].

    The NHI's effective_scope is declared ∩ grants ∩ ceiling — it CANNOT
    contain skills the user failed to declare, even if they hold the grant.
    """

    def test_nhi_cannot_inherit_undeclared_grants(self):
        user_grants = ["/tools/A", "/tools/B"]   # user holds both
        declared    = ["/tools/A"]                # agent only declares A
        system      = ["/tools/A", "/tools/B"]   # both exist in system

        eff, rej = _intersect(declared, user_grants, system)
        assert eff == ["/tools/A"]
        assert "/tools/B" not in eff

    def test_nhi_empty_declaration_even_with_broad_grants(self):
        """A user with all grants but empty declared → no effective skills."""
        user_grants = ["/tools/A", "/tools/B", "/tools/C"]
        declared    = []
        system      = ["/tools/A", "/tools/B", "/tools/C"]

        eff, rej = _intersect(declared, user_grants, system)
        assert eff == []

    def test_nhi_ceiling_blocks_overprivileged_declaration(self):
        """
        NHI declares a skill the user holds, but it is NOT in the system
        ceiling (ceiling = registered agents' paths).  Must be rejected.
        """
        user_grants = ["/tools/internal-secret"]
        declared    = ["/tools/internal-secret"]
        system      = ["/tools/A"]               # internal-secret not exposed

        eff, _ = _intersect(declared, user_grants, system)
        assert "/tools/internal-secret" not in eff


# ===========================================================================
# compute_effective_skills integration (mocked externals)
# ===========================================================================


class TestComputeEffectiveSkillsMocked:
    """Integration test: compute_effective_skills with mocked Redis + identity registry."""

    def test_mocked_invocation_produces_intersection(self):
        """Verify compute_effective_skills wires _get_invoker_grants + _compute_system_ceiling."""
        r = MagicMock()

        with (
            patch(
                "yashigani.backoffice.routes.user_agents._get_invoker_grants",
                return_value={"/tools/A", "/tools/B"},
            ),
            patch(
                "yashigani.backoffice.routes.user_agents._compute_system_ceiling",
                return_value={"/tools/A", "/tools/C"},
            ),
        ):
            eff, rej = compute_effective_skills(
                declared=["/tools/A", "/tools/B", "/tools/C"],
                account_id="user_a",
                r=r,
            )

        # effective = {A, B, C} ∩ {A, B} ∩ {A, C} = {A}
        assert eff == ["/tools/A"]
        assert set(rej) == {"/tools/B", "/tools/C"}

    def test_empty_registry_produces_no_effective_skills(self):
        """No active agents + no identity grants → no effective skills."""
        r = MagicMock()

        with (
            patch(
                "yashigani.backoffice.routes.user_agents._get_invoker_grants",
                return_value=set(),
            ),
            patch(
                "yashigani.backoffice.routes.user_agents._compute_system_ceiling",
                return_value=set(),
            ),
        ):
            eff, rej = compute_effective_skills(
                declared=["/tools/A"],
                account_id="user_a",
                r=r,
            )

        assert eff == []
        assert rej == ["/tools/A"]

    def test_community_tier_no_grants_ceiling_applies(self):
        """Community tier (empty grants) → system_ceiling is the only gate."""
        r = MagicMock()

        with (
            patch(
                "yashigani.backoffice.routes.user_agents._get_invoker_grants",
                return_value=set(),  # no identity record
            ),
            patch(
                "yashigani.backoffice.routes.user_agents._compute_system_ceiling",
                return_value={"/tools/A", "/tools/B"},
            ),
        ):
            eff, rej = compute_effective_skills(
                declared=["/tools/A", "/tools/Z"],
                account_id="community_user",
                r=r,
            )

        assert eff == ["/tools/A"]
        assert rej == ["/tools/Z"]
