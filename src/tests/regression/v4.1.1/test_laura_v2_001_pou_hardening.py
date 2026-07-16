"""
Regression tests — LAURA-V2-001 follow-up (2026-07-16): "replacing
require_feature()'s whole body with `return` still yields the feature", and
LAURA-V2-003 RE-VERIFY / Phase D (2026-07-17): "the shared verifier/
enforcer-getter fallback IS the single point of failure" (see
test_laura_v2_003_mesh_hardening.py for the full mesh-completeness proof).

Ref: testing_runs/yashigani/licence-v2-redteam-laura-hack-20260715T211215Z.md
     testing_runs/yashigani/licence-v2-pou-hardening-20260716/
     testing_runs/yashigani/licence-v2-redteam-mesh-verify-20260716T231542Z.md
     AgnosticSecurity/Products/Yashigani/licence-hardening-v2-design-20260713.md §5/§11

Root cause closed here (two rounds):
  Round 1 (LAURA-V2-001, 2026-07-16): every OIDC/SAML/SCIM point-of-use call
  site previously delegated to the SAME shared `enforcer.require_feature()`
  function. Patching that one function's body in that one file silently
  defeated every call site across the whole codebase. Fix: sso/oidc.py,
  sso/saml.py, backoffice/routes/sso.py, backoffice/routes/scim.py, and
  licensing/gate_middleware.py each carry their OWN local
  `_licence_hard_gate()` — a genuinely separate function definition per
  file (not a shared import). None of them call enforcer.require_feature()
  any more.

  Round 2 (LAURA-V2-003 RE-VERIFY / Phase D, 2026-07-17): Phase C's
  `_licence_hard_gate()` had each gate check its OWN 2 ring-neighbours
  first, then FALL BACK to calling verifier.get_integrity_status()/
  enforcer.get_enforcer_integrity_status() if the ring-check itself hadn't
  fired. Laura's independent re-verify proved that fallback WAS the actual
  root cause: it was the exact {verifier.py, enforcer.py} pair an attacker
  had already neutered, called by a gate whose 2-neighbour ring-check
  happened not to cover the touched files for that release's permutation —
  a live 3-file {verifier.py, enforcer.py, gate_middleware.py} edit
  silently defeated SCIM, and a 4-file {..., routes/sso.py} edit silently
  defeated SAML. Fix (Phase D): the fallback is REMOVED, not merely
  supplemented — every gate's decision now comes SOLELY from its own inline
  FULL-mesh check (every OTHER mesh member's bytes, not just 2 neighbours;
  see test_laura_v2_003_mesh_hardening.py for the completeness proof over
  all 126 proper subsets).

These tests prove, via monkeypatch (fast/deterministic — the authoritative
proof against a REAL signed build with REAL file-surgery attacks, including
reproducing Laura's exact 3-file SCIM and 4-file SAML bypasses, is in the
dispatch verification run under testing_runs/yashigani/):

  1. Patching enforcer.require_feature() (monkeypatched to a no-op) has ZERO
     effect on any of the 5 point-of-use gates — they never call it.
  2. Patching verifier.get_integrity_status()/enforcer.get_enforcer_
     integrity_status() to RAISE has ZERO effect on any of the 5
     point-of-use gates when their own mesh check is clean — proving the
     Phase C shared-getter fallback has genuinely been removed, not just
     made resilient to failure.
  3. Each point-of-use gate independently hard-refuses when its OWN
     full-mesh flag is set — a real, own-file signal, not derived from
     verifier.py/enforcer.py's getters.
  4. Each point-of-use gate correctly ALLOWS when its own mesh flag is
     False and the active licence grants the feature, and DENIES
     (feature_not_licensed class, not integrity) when the licence lacks
     the feature.
  5. enforcer.get_license() raising is still treated as an integrity
     violation and fails closed (IMPL-03) — this is a DATA read (the
     license payload), not the mesh integrity DECISION, and remains a
     legitimate fail-closed path.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

import yashigani.backoffice.routes.scim as scim_routes
import yashigani.backoffice.routes.sso as sso_routes
import yashigani.licensing.enforcer as enforcer_mod
import yashigani.licensing.verifier as verifier_mod
import yashigani.sso.oidc as oidc_mod
import yashigani.sso.saml as saml_mod
from yashigani.licensing.gate_middleware import _licence_hard_gate as mw_gate
from yashigani.licensing.gate_middleware import _mesh_checker as mw_mesh_checker
from yashigani.licensing.model import LicenseFeature, LicenseState, LicenseTier

_FULL_FEATURED_LICENSE = LicenseState(
    tier=LicenseTier.PROFESSIONAL_PLUS,
    org_domain="acme.example.com",
    max_agents=500,
    max_end_users=1000,
    max_admin_seats=50,
    max_orgs=5,
    features=frozenset({LicenseFeature.OIDC, LicenseFeature.SAML, LicenseFeature.SCIM}),
    issued_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
    expires_at=None,
    license_id="lic-test-full",
    valid=True,
    error=None,
)

# (module, gate-callable, feature, mesh-flag-module, mesh-flag-attr) for
# every point-of-use gate under test. mesh-flag-module/attr identify EACH
# gate's OWN full-mesh violation flag — the ONLY thing that now drives its
# integrity decision (Phase D).
_POU_GATES = [
    ("oidc.py provider", lambda: oidc_mod._licence_hard_gate("oidc"), "oidc", oidc_mod, "_mesh_integrity_violated"),
    ("saml.py provider", lambda: saml_mod._licence_hard_gate("saml"), "saml", saml_mod, "_mesh_integrity_violated"),
    ("routes/sso.py:oidc", lambda: sso_routes._licence_hard_gate("oidc"), "oidc", sso_routes, "_mesh_integrity_violated"),
    ("routes/sso.py:saml", lambda: sso_routes._licence_hard_gate("saml"), "saml", sso_routes, "_mesh_integrity_violated"),
    ("routes/scim.py", lambda: scim_routes._licence_hard_gate("scim"), "scim", scim_routes, "_mesh_integrity_violated"),
]


@pytest.fixture()
def _clean_and_licensed(monkeypatch):
    """Baseline: no mesh integrity violation on ANY point-of-use gate, and a
    full-featured licence loaded."""
    monkeypatch.setattr(oidc_mod, "_mesh_integrity_violated", False)
    monkeypatch.setattr(saml_mod, "_mesh_integrity_violated", False)
    monkeypatch.setattr(sso_routes, "_mesh_integrity_violated", False)
    monkeypatch.setattr(scim_routes, "_mesh_integrity_violated", False)
    original_mw_violated = mw_mesh_checker.violated
    mw_mesh_checker.violated = False
    original = enforcer_mod._license
    enforcer_mod.set_license(_FULL_FEATURED_LICENSE)
    yield
    enforcer_mod._license = original
    mw_mesh_checker.violated = original_mw_violated


class TestRequireFeatureNeuterHasZeroEffect:
    """The core LAURA-V2-001 regression: patching enforcer.require_feature()
    to a no-op must not affect ANY point-of-use gate, because none of them
    call it."""

    def test_require_feature_neutered_all_pou_gates_unaffected(
        self, monkeypatch, _clean_and_licensed
    ):
        # Simulate the exact LAURA-V2-001 attack: require_feature()'s body
        # replaced with a bare `return` (always "succeeds", no exception).
        monkeypatch.setattr(enforcer_mod, "require_feature", lambda feature: None)

        # Sanity: the attack landed — require_feature() really is neutered.
        enforcer_mod.require_feature("oidc")  # must not raise (confirms neuter)

        # Every point-of-use gate must still correctly ALLOW here (clean +
        # licensed) purely because it independently checked its OWN
        # full-mesh flag + get_license() itself — NOT because
        # require_feature() happened to also allow it. Proven by re-running
        # with a violation below.
        for name, gate, feature, mod, attr in _POU_GATES:
            gate()  # must not raise

        allowed, _reason = mw_gate("oidc")
        assert allowed is True

    def test_require_feature_neutered_does_not_mask_own_mesh_tamper(self, monkeypatch):
        """Even with require_feature() neutered AND a fully valid licence
        loaded, every point-of-use gate must STILL hard-refuse when ITS OWN
        full-mesh flag reports tamper — proving none of them derive their
        answer from require_feature()."""
        monkeypatch.setattr(enforcer_mod, "require_feature", lambda feature: None)
        original = enforcer_mod._license
        enforcer_mod.set_license(_FULL_FEATURED_LICENSE)
        monkeypatch.setattr(oidc_mod, "_mesh_integrity_violated", True)
        monkeypatch.setattr(saml_mod, "_mesh_integrity_violated", True)
        monkeypatch.setattr(sso_routes, "_mesh_integrity_violated", True)
        monkeypatch.setattr(scim_routes, "_mesh_integrity_violated", True)
        original_mw = mw_mesh_checker.violated
        mw_mesh_checker.violated = True
        try:
            for name, gate, feature, mod, attr in _POU_GATES:
                with pytest.raises(enforcer_mod.LicenseFeatureGated):
                    gate()
            allowed, reason = mw_gate("oidc")
            assert allowed is False
            assert reason == "mesh_full_integrity_violated"
        finally:
            enforcer_mod._license = original
            mw_mesh_checker.violated = original_mw


class TestSharedGetterFallbackRemoved:
    """
    LAURA-V2-003 RE-VERIFY / Phase D: the Phase C fallback (calling
    verifier.get_integrity_status()/enforcer.get_enforcer_integrity_status()
    when a gate's own check hadn't fired) has been REMOVED, not merely
    supplemented — this was the exact single point of failure Laura's
    independent re-verify exploited for a live 3-file SCIM bypass and a
    4-file SAML bypass. Prove removal structurally: patch BOTH getters to
    raise, and confirm every point-of-use gate is COMPLETELY unaffected
    when its own mesh flag is clean — the gate must never even attempt to
    call them.
    """

    def test_broken_verifier_getter_has_zero_effect(self, monkeypatch, _clean_and_licensed):
        def _boom():
            raise RuntimeError("verifier.get_integrity_status() must never be called by a POU gate")

        monkeypatch.setattr(verifier_mod, "get_integrity_status", _boom)
        for name, gate, feature, mod, attr in _POU_GATES:
            gate()  # must not raise — proves the gate never calls the broken getter
        allowed, _reason = mw_gate("scim")
        assert allowed is True

    def test_broken_enforcer_getter_has_zero_effect(self, monkeypatch, _clean_and_licensed):
        def _boom():
            raise RuntimeError("enforcer.get_enforcer_integrity_status() must never be called by a POU gate")

        monkeypatch.setattr(enforcer_mod, "get_enforcer_integrity_status", _boom)
        for name, gate, feature, mod, attr in _POU_GATES:
            gate()  # must not raise
        allowed, _reason = mw_gate("saml")
        assert allowed is True

    def test_both_broken_getters_simultaneously_have_zero_effect(self, monkeypatch, _clean_and_licensed):
        """The exact shape of Laura's attack: verifier.py+enforcer.py both
        neutered at once. Under Phase D this has zero effect on a gate
        whose own full-mesh check is clean (in reality, tampering
        verifier.py/enforcer.py's bytes WOULD trip every other gate's own
        full-mesh check — this test isolates the fallback-removal property
        specifically, independent of that separate detection path, which is
        proven in test_laura_v2_003_mesh_hardening.py)."""
        def _boom():
            raise RuntimeError("shared fallback getter must never be called")

        monkeypatch.setattr(verifier_mod, "get_integrity_status", _boom)
        monkeypatch.setattr(enforcer_mod, "get_enforcer_integrity_status", _boom)
        for name, gate, feature, mod, attr in _POU_GATES:
            gate()  # must not raise
        allowed, _reason = mw_gate("oidc")
        assert allowed is True


class TestPointOfUseGatesReadOwnMeshFlagDirectly:
    """Each gate must hard-refuse when ITS OWN full-mesh flag is True,
    regardless of licence validity — the mesh-file-local decision
    property (Phase D: no shared authority consulted)."""

    @pytest.mark.parametrize("name,gate,feature,mod,attr", _POU_GATES)
    def test_gate_refuses_on_own_mesh_violation(
        self, monkeypatch, name, gate, feature, mod, attr
    ):
        original = enforcer_mod._license
        enforcer_mod.set_license(_FULL_FEATURED_LICENSE)
        monkeypatch.setattr(mod, attr, True)
        try:
            with pytest.raises(enforcer_mod.LicenseFeatureGated):
                gate()
        finally:
            enforcer_mod._license = original

    def test_middleware_gate_refuses_on_own_mesh_violation(self, monkeypatch):
        original = enforcer_mod._license
        enforcer_mod.set_license(_FULL_FEATURED_LICENSE)
        original_mw = mw_mesh_checker.violated
        mw_mesh_checker.violated = True
        try:
            allowed, reason = mw_gate("scim")
            assert allowed is False
            assert reason == "mesh_full_integrity_violated"
        finally:
            enforcer_mod._license = original
            mw_mesh_checker.violated = original_mw


class TestPointOfUseGatesHonourFeatureGrant:
    """Clean build, valid licence: gates ALLOW when the licence grants the
    feature and DENY (feature_not_licensed class) when it doesn't — proving
    the gates aren't just "always allow when clean", they actually check
    the licence payload too."""

    @pytest.mark.parametrize("name,gate,feature,mod,attr", _POU_GATES)
    def test_gate_allows_when_clean_and_licensed(
        self, monkeypatch, name, gate, feature, mod, attr, _clean_and_licensed
    ):
        gate()  # must not raise

    @pytest.mark.parametrize("name,gate,feature,mod,attr", _POU_GATES)
    def test_gate_denies_when_clean_but_unlicensed(self, monkeypatch, name, gate, feature, mod, attr):
        monkeypatch.setattr(mod, attr, False)
        original = enforcer_mod._license
        from yashigani.licensing.model import COMMUNITY_LICENSE

        enforcer_mod.set_license(COMMUNITY_LICENSE)
        try:
            with pytest.raises(enforcer_mod.LicenseFeatureGated) as exc_info:
                gate()
            # Must be a feature-gate denial, not an integrity one — the two
            # are distinguishable failure classes (design §5: unlicensed !=
            # tampered) even though both currently raise the same exception
            # type at these call sites.
            assert exc_info.value.feature == feature
        finally:
            enforcer_mod._license = original

    def test_middleware_denies_when_clean_but_unlicensed(self, monkeypatch):
        original_mw = mw_mesh_checker.violated
        mw_mesh_checker.violated = False
        original = enforcer_mod._license
        from yashigani.licensing.model import COMMUNITY_LICENSE

        enforcer_mod.set_license(COMMUNITY_LICENSE)
        try:
            allowed, reason = mw_gate("oidc")
            assert allowed is False
            assert reason == "feature_not_licensed"
        finally:
            enforcer_mod._license = original
            mw_mesh_checker.violated = original_mw


class TestGateFailsClosedOnLicenseStateReadError:
    """IMPL-03 discipline: enforcer.get_license() is still a DATA read every
    gate performs after its OWN mesh integrity decision is clean — if THAT
    read itself raises (e.g. a botched attack that broke enforcer.py in a
    way its own full-mesh peer-check hadn't yet caught, or a genuinely
    unexpected runtime error), the gate must refuse rather than silently
    pass."""

    def test_oidc_gate_refuses_when_enforcer_get_license_raises(self, monkeypatch, _clean_and_licensed):
        def _broken_get_license():
            raise RuntimeError("simulated broken license-state read")

        monkeypatch.setattr(enforcer_mod, "get_license", _broken_get_license)
        with pytest.raises(enforcer_mod.LicenseFeatureGated):
            oidc_mod._licence_hard_gate("oidc")

    def test_middleware_gate_refuses_when_enforcer_get_license_raises(self, monkeypatch, _clean_and_licensed):
        def _broken_get_license():
            raise RuntimeError("simulated broken license-state read")

        monkeypatch.setattr(enforcer_mod, "get_license", _broken_get_license)
        allowed, reason = mw_gate("scim")
        assert allowed is False
        assert reason == "license_state_unavailable"
