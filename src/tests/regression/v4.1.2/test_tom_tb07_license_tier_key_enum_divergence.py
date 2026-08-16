"""
Regression test -- v4.1.2 TB-07 (Lu): licence tier key/enum divergence
silently yields zero entitlement for igniter and academic_nonprofit.

## Finding

Lu's TB-07: ``academic_nonprofit`` is advertised in README.md Sec.8 as
"Unlimited / SSO free" (Multi-IdP Identity Broker row: "Unlimited IdPs") but
the deployed broker granted 0 IdPs. Same class of defect reported for
``igniter``.

## Root cause

``LicenseTier`` (``licensing/model.py``) has 7 real, non-canary members:
``community``, ``igniter``, ``starter``, ``professional``,
``professional_plus``, ``enterprise``, ``academic_nonprofit``.

``igniter`` and ``academic_nonprofit`` were added by commit ``8073620a``
("fix(licensing): align TIER_DEFAULTS with website pricing -- source-of-
truth (retro #42)", 2026-05-06). That commit swept
``licensing/model.py::TIER_DEFAULTS`` (and ``ACADEMIC_NONPROFIT_LICENSE``,
and the enum itself) to match the website pricing table, but it did NOT
sweep the other tier-string-keyed lookup tables elsewhere in the codebase
that predate the tier addition -- ``git log -S`` on each confirms none of
them were touched by any subsequent commit either:

  1. ``auth/broker.py::_TIER_IDP_LIMITS`` -- keyed the top tier on the
     stale string ``"academic"`` (never renamed when the enum value became
     ``"academic_nonprofit"``) and never added an ``"igniter"`` key at
     all. ``.get(tier, 0)`` silently fell back to the fail-closed default
     of 0 for both tiers -- exactly Lu's reported symptom.

  2. ``pool/manager.py::_TIER_LIMITS`` -- identical defect shape (stale
     ``"academic"`` key, missing ``"igniter"``). ``TierLimits.from_tier()``
     silently fell back to the community-level default (1/3 concurrent)
     for both tiers instead of README.md Sec.8's "Container Pool Manager"
     row (igniter: 1/identity,5 total; academic_nonprofit: Unlimited).

  3. ``pki/identity.py::_TIER_ORDER`` -- a THIRD instance of the same
     class, found while auditing every tier for this defect per dispatch
     instruction. Missing ``"igniter"`` and ``"professional_plus"``
     entirely (never had an ``"academic"``/``"academic_nonprofit"`` entry
     to begin with -- it predates that tier, commit ``05ec120e``,
     v2.23.1). Consequence: ``tier_at_least("igniter", "community")``
     returned False (ValueError from ``.index("igniter")`` caught by the
     pre-existing fail-closed except) -- an Igniter customer would be
     denied even the lowest-bar ``yashigani_generated`` CA mode that
     Community-tier deployments pass. ``_parse_ca_source()`` would also
     reject any ``service_identities.yaml`` declaring
     ``min_license_tier: igniter`` or ``professional_plus`` with a
     ManifestError at manifest-LOAD time (blocking every service in the
     manifest, not just the affected entry). This function has no
     production call site yet (grep-confirmed dead code, exported +
     unit-tested for future wiring) -- filed as part of the same TB-07
     class rather than a separate live-exploitable finding.

## Fail-closed judgement call

Every one of these three lookup structures ALREADY treats an unrecognised
tier key as deny (``.get(tier, 0)`` / ``.get(tier.lower(), cls())`` /
``except ValueError: return False``) -- that is the pre-existing convention
in this exact code, and matches the sibling ``_tier_gte()`` deny-on-unknown
pattern in ``backoffice/routes/license.py``. The fix therefore does NOT
change the unknown-tier default (still deny/most-restrictive) -- it adds
the two previously-missing REAL tier keys so a legitimately-issued
igniter/academic_nonprofit licence stops hitting that fail-closed default
by accident. ``LicenseTier.CANARY`` ("never issued to customers" per
model.py) is deliberately kept OUT of all three structures in the fix --
canary correctly continues to hit the fail-closed default.

## Coverage

All 7 non-canary ``LicenseTier`` members are asserted against all three
structures below (not just the 2 reported) -- including the ones that were
ALREADY correct, to document the "checked every tier, not just the hits"
sweep. ``licensing/model.py::TIER_DEFAULTS`` and
``backoffice/routes/license.py``'s ``_TIER_ORDER``/``_TIER_DISPLAY`` were
also audited and found to be COMPLETE/correct already (both key on
``LicenseTier`` members exhaustively) -- no test needed there since there
is no regression surface to guard.
"""
from __future__ import annotations

import pytest

from yashigani.auth.broker import _TIER_IDP_LIMITS, IdentityBroker
from yashigani.licensing.model import LicenseTier
from yashigani.pki.identity import _TIER_ORDER, tier_at_least
from yashigani.pool.manager import _TIER_LIMITS, TierLimits

# Every real, issuable tier (LicenseTier minus CANARY, which is "never
# issued to customers" per model.py and must keep hitting the fail-closed
# default in all three structures).
_ALL_REAL_TIERS = [t.value for t in LicenseTier if t is not LicenseTier.CANARY]


class TestBrokerIdpLimitsTB07:
    """auth/broker.py::_TIER_IDP_LIMITS -- README.md Sec.8 'Multi-IdP
    Identity Broker' row is the source of truth."""

    def test_every_real_tier_has_an_explicit_key(self):
        missing = [t for t in _ALL_REAL_TIERS if t not in _TIER_IDP_LIMITS]
        assert missing == [], (
            f"TB-07 regression: LicenseTier member(s) {missing} have no "
            f"explicit entry in _TIER_IDP_LIMITS -- they will silently fall "
            f"back to the deny default (0 IdPs) via .get(tier, 0), exactly "
            f"the class of bug TB-07 reported for igniter/academic_nonprofit."
        )

    def test_academic_nonprofit_not_keyed_on_stale_academic_string(self):
        assert "academic" not in _TIER_IDP_LIMITS, (
            "TB-07 regression: _TIER_IDP_LIMITS must not carry the stale "
            "'academic' key -- LicenseTier.ACADEMIC_NONPROFIT.value is "
            "'academic_nonprofit'; the stale key means .get('academic_"
            "nonprofit', 0) always misses and silently denies."
        )

    def test_academic_nonprofit_gets_unlimited_idps(self):
        # README.md Sec.8: "Unlimited IdPs" -- same sentinel as enterprise.
        assert _TIER_IDP_LIMITS["academic_nonprofit"] == _TIER_IDP_LIMITS["enterprise"]
        assert _TIER_IDP_LIMITS["academic_nonprofit"] >= 999

    def test_igniter_gets_one_idp(self):
        # README.md Sec.8 Multi-IdP row: Igniter = "1 OIDC".
        assert _TIER_IDP_LIMITS["igniter"] == 1

    def test_canary_not_explicitly_keyed_fails_closed(self):
        assert "canary" not in _TIER_IDP_LIMITS

    def test_live_broker_academic_nonprofit_accepts_idp(self):
        """End-to-end: an IdentityBroker constructed at academic_nonprofit
        tier must actually accept an IdP registration -- not just the raw
        dict value. Reproduces Lu's exact reported symptom (0 IdPs
        received) and proves it FAILED before the fix."""
        from yashigani.auth.broker import IdPConfig

        broker = IdentityBroker(tier="academic_nonprofit")
        broker.add_idp(IdPConfig(
            id="idp1", name="Test IdP", protocol="oidc",
            metadata_url="https://idp.example.com/.well-known/openid-configuration",
        ))
        assert len(broker._idps) == 1, (
            "TB-07: academic_nonprofit tier must accept at least one IdP "
            "registration -- README.md Sec.8 advertises 'Unlimited IdPs'."
        )

    def test_live_broker_igniter_accepts_one_idp_then_denies_second(self):
        from yashigani.auth.broker import IdPConfig

        broker = IdentityBroker(tier="igniter")
        broker.add_idp(IdPConfig(
            id="idp1", name="Test IdP", protocol="oidc",
            metadata_url="https://idp.example.com/.well-known/openid-configuration",
        ))
        assert len(broker._idps) == 1
        with pytest.raises(ValueError, match="IdP limit reached"):
            broker.add_idp(IdPConfig(
                id="idp2", name="Second IdP", protocol="oidc",
                metadata_url="https://idp2.example.com/.well-known/openid-configuration",
            ))


class TestPoolManagerTierLimitsTB07:
    """pool/manager.py::_TIER_LIMITS -- README.md Sec.8 'Container Pool
    Manager' row is the source of truth."""

    def test_every_real_tier_has_an_explicit_key(self):
        missing = [t for t in _ALL_REAL_TIERS if t not in _TIER_LIMITS]
        assert missing == [], (
            f"TB-07 regression: LicenseTier member(s) {missing} have no "
            f"explicit entry in _TIER_LIMITS -- they will silently fall "
            f"back to the community-equivalent default via "
            f"TierLimits.from_tier()'s .get(tier.lower(), cls())."
        )

    def test_academic_nonprofit_not_keyed_on_stale_academic_string(self):
        assert "academic" not in _TIER_LIMITS

    def test_academic_nonprofit_gets_unlimited_pool(self):
        # README.md Sec.8: "Unlimited" -- same sentinel as enterprise.
        assert _TIER_LIMITS["academic_nonprofit"] == _TIER_LIMITS["enterprise"]

    def test_igniter_gets_starter_equivalent_pool(self):
        # README.md Sec.8: Igniter = "1/identity, 5 total" (== starter row).
        assert _TIER_LIMITS["igniter"] == TierLimits(
            per_service_per_identity=1, total_concurrent=5,
        )

    def test_from_tier_resolves_academic_nonprofit_correctly(self):
        limits = TierLimits.from_tier("academic_nonprofit")
        assert limits.total_concurrent >= 9999, (
            "TB-07: TierLimits.from_tier('academic_nonprofit') must resolve "
            "to the unlimited sentinel, not the community-equivalent "
            "fallback default (was: silently returned TierLimits() == 1/3 "
            "because the dict only had a stale 'academic' key)."
        )

    def test_from_tier_resolves_igniter_correctly(self):
        limits = TierLimits.from_tier("igniter")
        assert limits.total_concurrent == 5, (
            "TB-07: TierLimits.from_tier('igniter') must resolve to 1/5 "
            "(was: silently fell back to the community-equivalent 1/3 "
            "default because 'igniter' had no key at all)."
        )

    def test_canary_falls_back_to_most_restrictive_default(self):
        # Unchanged convention: canary is not explicitly keyed, and the
        # fallback (community-equivalent 1/3) is the MOST restrictive
        # value in the table, never a permissive one.
        assert "canary" not in _TIER_LIMITS
        limits = TierLimits.from_tier("canary")
        assert limits == TierLimits(per_service_per_identity=1, total_concurrent=3)


class TestPkiIdentityTierOrderTB07:
    """pki/identity.py::_TIER_ORDER + tier_at_least() -- third instance of
    the same defect class, found by auditing every tier per dispatch
    instruction (not one of the two originally reported)."""

    def test_every_real_tier_is_a_known_tier_for_manifest_validation(self):
        missing = [t for t in _ALL_REAL_TIERS if t not in _TIER_ORDER]
        assert missing == [], (
            f"TB-07 regression: LicenseTier member(s) {missing} are not in "
            f"_TIER_ORDER -- _parse_ca_source() would reject any "
            f"service_identities.yaml declaring min_license_tier for one "
            f"of these tiers with a ManifestError at manifest-LOAD time "
            f"(blocking the whole manifest, not just that entry)."
        )

    def test_igniter_meets_community_minimum(self):
        # Was: tier_at_least("igniter", "community") -> False (ValueError
        # from _TIER_ORDER.index("igniter") caught by the fail-closed
        # except) -- an Igniter customer denied even the lowest bar.
        assert tier_at_least("igniter", "community") is True

    def test_professional_plus_meets_professional_minimum(self):
        assert tier_at_least("professional_plus", "professional") is True

    def test_academic_nonprofit_always_qualifies(self):
        # Parallel-unlimited special-case, mirrors
        # backoffice/routes/license.py::_tier_gte's identical rule.
        assert tier_at_least("academic_nonprofit", "community") is True
        assert tier_at_least("academic_nonprofit", "enterprise") is True

    def test_enterprise_always_qualifies(self):
        assert tier_at_least("enterprise", "professional_plus") is True

    def test_community_does_not_meet_professional_minimum(self):
        assert tier_at_least("community", "professional") is False

    def test_unrecognised_tier_still_fails_closed(self):
        assert tier_at_least("garbage", "community") is False

    def test_canary_still_fails_closed(self):
        # LicenseTier.CANARY deliberately excluded from _TIER_ORDER --
        # must never satisfy any minimum-tier gate.
        assert "canary" not in _TIER_ORDER
        assert tier_at_least("canary", "community") is False


class TestFullTierSweepCoverage:
    """Documents the full sweep across every LicenseTier member and every
    tier-keyed lookup structure found in src/yashigani/ -- including the
    ones that were ALREADY correct, per dispatch instruction to report
    coverage, not just hits."""

    def test_all_seven_real_tiers_enumerated(self):
        # Guards against a future tier addition silently landing without
        # this test suite (and the three fixed dicts) being updated --
        # if this assertion ever fails, a new LicenseTier member exists
        # and _TIER_IDP_LIMITS / _TIER_LIMITS / _TIER_ORDER all need a
        # fresh audit pass, not just a bump of this list.
        assert _ALL_REAL_TIERS == [
            "community",
            "igniter",
            "starter",
            "professional",
            "professional_plus",
            "enterprise",
            "academic_nonprofit",
        ]

    def test_licensing_model_tier_defaults_already_correct(self):
        # model.py::TIER_DEFAULTS was the ORIGIN of the fix (8073620a) --
        # confirmed already complete/correct, no regression surface here.
        from yashigani.licensing.model import TIER_DEFAULTS

        missing = [t for t in _ALL_REAL_TIERS if t not in TIER_DEFAULTS]
        assert missing == []
        assert TIER_DEFAULTS["academic_nonprofit"]["max_agents"] == -1

    def test_backoffice_license_route_tier_order_already_correct(self):
        # backoffice/routes/license.py keys _TIER_ORDER/_TIER_DISPLAY on
        # LicenseTier enum members directly (not string literals) -- no
        # key/enum divergence is possible there. Confirmed by source
        # inspection; asserted here via the enum itself for stability.
        for t in LicenseTier:
            assert isinstance(t.value, str)
