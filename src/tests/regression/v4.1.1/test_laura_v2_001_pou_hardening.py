"""
Regression tests — LAURA-V2-001 follow-up (2026-07-16): "replacing
require_feature()'s whole body with `return` still yields the feature".

Ref: testing_runs/yashigani/licence-v2-redteam-laura-hack-20260715T211215Z.md
     testing_runs/yashigani/licence-v2-pou-hardening-20260716/ (bypass-matrix
     evidence against a REAL signed build — this file covers the same
     property with fast, deterministic monkeypatch-based tests)
     AgnosticSecurity/Products/Yashigani/licence-hardening-v2-design-20260713.md §5/§11

Root cause closed here: every OIDC/SAML/SCIM point-of-use call site
previously delegated to the SAME shared `enforcer.require_feature()`
function. Patching that one function's body in that one file (enforcer.py)
silently defeated every call site across the whole codebase — the exact
residual Tiago named: "alarm fires, but the call passes".

Fix: sso/oidc.py, sso/saml.py, backoffice/routes/sso.py,
backoffice/routes/scim.py, and licensing/gate_middleware.py each now carry
their OWN local `_licence_hard_gate()` — a genuinely separate function
definition per file (not a shared import) — that reads the SIGNED hash
authority directly: verifier.get_integrity_status() (the live, externally
re-derived, BUNDLE_SIG-verified flag) and
enforcer.get_enforcer_integrity_status() (enforcer's own independent
cross-check of verifier.py's bytes). None of them call
enforcer.require_feature() any more.

These tests prove, via monkeypatch (fast/deterministic — the authoritative
proof against a REAL signed build with REAL file-surgery attacks is in
testing_runs/yashigani/licence-v2-pou-hardening-20260716/, per the
"VERIFY (must, before returning)" section of the LAURA-V2-001 dispatch):

  1. Patching enforcer.require_feature() (monkeypatched to a no-op) has ZERO
     effect on any of the 5 point-of-use gates — they never call it.
  2. Each point-of-use gate independently hard-refuses when
     verifier.get_integrity_status() is True, even with a fully valid,
     feature-granting licence loaded.
  3. Each point-of-use gate independently hard-refuses when
     enforcer.get_enforcer_integrity_status() is True (covers "verifier.py
     itself was the file tampered with").
  4. Each point-of-use gate correctly ALLOWS when both flags are False and
     the active licence grants the feature, and DENIES (feature_not_licensed
     class, not integrity) when the licence lacks the feature.
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

# (module, gate-callable, feature) for every point-of-use gate under test.
_POU_GATES = [
    ("oidc.py provider", lambda: oidc_mod._licence_hard_gate("oidc"), "oidc"),
    ("saml.py provider", lambda: saml_mod._licence_hard_gate("saml"), "saml"),
    ("routes/sso.py:oidc", lambda: sso_routes._licence_hard_gate("oidc"), "oidc"),
    ("routes/sso.py:saml", lambda: sso_routes._licence_hard_gate("saml"), "saml"),
    ("routes/scim.py", lambda: scim_routes._licence_hard_gate("scim"), "scim"),
]


@pytest.fixture()
def _clean_and_licensed(monkeypatch):
    """Baseline: no integrity violation, full-featured licence loaded."""
    monkeypatch.setattr(verifier_mod, "_integrity_violated", False)
    monkeypatch.setattr(enforcer_mod, "_enforcer_integrity_violated", False)
    original = enforcer_mod._license
    enforcer_mod.set_license(_FULL_FEATURED_LICENSE)
    yield
    enforcer_mod._license = original


class TestRequireFeatureNeuterHasZeroEffect:
    """The core regression: patching enforcer.require_feature() to a no-op
    must not affect ANY point-of-use gate, because none of them call it."""

    def test_require_feature_neutered_all_pou_gates_unaffected(
        self, monkeypatch, _clean_and_licensed
    ):
        # Simulate the exact LAURA-V2-001 attack: require_feature()'s body
        # replaced with a bare `return` (always "succeeds", no exception).
        monkeypatch.setattr(enforcer_mod, "require_feature", lambda feature: None)

        # Sanity: the attack landed — require_feature() really is neutered.
        enforcer_mod.require_feature("oidc")  # must not raise (confirms neuter)

        # Every point-of-use gate must still correctly ALLOW here (clean +
        # licensed) purely because it independently checked verifier/enforcer
        # + get_license() itself — NOT because require_feature() happened to
        # also allow it. Proven by re-running with a violation below.
        for name, gate, feature in _POU_GATES:
            gate()  # must not raise

        allowed, _reason = mw_gate("oidc")
        assert allowed is True

    def test_require_feature_neutered_does_not_mask_tamper(self, monkeypatch):
        """Even with require_feature() neutered AND a fully valid licence
        loaded, every point-of-use gate must STILL hard-refuse when the
        signed integrity authority reports tamper — proving none of them
        derive their answer from require_feature()."""
        monkeypatch.setattr(enforcer_mod, "require_feature", lambda feature: None)
        original = enforcer_mod._license
        enforcer_mod.set_license(_FULL_FEATURED_LICENSE)
        monkeypatch.setattr(verifier_mod, "_integrity_violated", True)
        monkeypatch.setattr(enforcer_mod, "_enforcer_integrity_violated", False)
        try:
            for name, gate, feature in _POU_GATES:
                with pytest.raises(enforcer_mod.LicenseFeatureGated):
                    gate()
            allowed, reason = mw_gate("oidc")
            assert allowed is False
            assert reason == "build_integrity_violated"
        finally:
            enforcer_mod._license = original


class TestPointOfUseGatesReadVerifierFlagDirectly:
    """Each gate must hard-refuse on verifier.get_integrity_status() == True,
    regardless of licence validity — the 'signed hash authority' property."""

    @pytest.mark.parametrize("name,gate,feature", _POU_GATES)
    def test_gate_refuses_on_verifier_violation(
        self, monkeypatch, name, gate, feature
    ):
        original = enforcer_mod._license
        enforcer_mod.set_license(_FULL_FEATURED_LICENSE)
        monkeypatch.setattr(verifier_mod, "_integrity_violated", True)
        monkeypatch.setattr(enforcer_mod, "_enforcer_integrity_violated", False)
        try:
            with pytest.raises(enforcer_mod.LicenseFeatureGated):
                gate()
        finally:
            enforcer_mod._license = original

    def test_middleware_gate_refuses_on_verifier_violation(self, monkeypatch):
        original = enforcer_mod._license
        enforcer_mod.set_license(_FULL_FEATURED_LICENSE)
        monkeypatch.setattr(verifier_mod, "_integrity_violated", True)
        monkeypatch.setattr(enforcer_mod, "_enforcer_integrity_violated", False)
        try:
            allowed, reason = mw_gate("scim")
            assert allowed is False
            assert reason == "build_integrity_violated"
        finally:
            enforcer_mod._license = original


class TestPointOfUseGatesReadEnforcerCrossCheckDirectly:
    """Covers the 'verifier.py itself was the file tampered with' case:
    enforcer.get_enforcer_integrity_status() (enforcer's own independent
    cross-check of verifier.py's bytes) must ALSO independently trip each
    gate, even when verifier._integrity_violated itself is False (as it
    would be if verifier.py's OWN getter had been patched to lie)."""

    @pytest.mark.parametrize("name,gate,feature", _POU_GATES)
    def test_gate_refuses_on_enforcer_cross_check_violation(
        self, monkeypatch, name, gate, feature
    ):
        original = enforcer_mod._license
        enforcer_mod.set_license(_FULL_FEATURED_LICENSE)
        monkeypatch.setattr(verifier_mod, "_integrity_violated", False)
        monkeypatch.setattr(enforcer_mod, "_enforcer_integrity_violated", True)
        try:
            with pytest.raises(enforcer_mod.LicenseFeatureGated):
                gate()
        finally:
            enforcer_mod._license = original

    def test_middleware_gate_refuses_on_enforcer_cross_check_violation(self, monkeypatch):
        original = enforcer_mod._license
        enforcer_mod.set_license(_FULL_FEATURED_LICENSE)
        monkeypatch.setattr(verifier_mod, "_integrity_violated", False)
        monkeypatch.setattr(enforcer_mod, "_enforcer_integrity_violated", True)
        try:
            allowed, reason = mw_gate("saml")
            assert allowed is False
            assert reason == "build_integrity_violated"
        finally:
            enforcer_mod._license = original


class TestPointOfUseGatesHonourFeatureGrant:
    """Clean build, valid licence: gates ALLOW when the licence grants the
    feature and DENY (feature_not_licensed class) when it doesn't — proving
    the gates aren't just "always allow when clean", they actually check
    the licence payload too."""

    @pytest.mark.parametrize("name,gate,feature", _POU_GATES)
    def test_gate_allows_when_clean_and_licensed(
        self, monkeypatch, name, gate, feature, _clean_and_licensed
    ):
        gate()  # must not raise

    @pytest.mark.parametrize("name,gate,feature", _POU_GATES)
    def test_gate_denies_when_clean_but_unlicensed(self, monkeypatch, name, gate, feature):
        monkeypatch.setattr(verifier_mod, "_integrity_violated", False)
        monkeypatch.setattr(enforcer_mod, "_enforcer_integrity_violated", False)
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
        monkeypatch.setattr(verifier_mod, "_integrity_violated", False)
        monkeypatch.setattr(enforcer_mod, "_enforcer_integrity_violated", False)
        original = enforcer_mod._license
        from yashigani.licensing.model import COMMUNITY_LICENSE

        enforcer_mod.set_license(COMMUNITY_LICENSE)
        try:
            allowed, reason = mw_gate("oidc")
            assert allowed is False
            assert reason == "feature_not_licensed"
        finally:
            enforcer_mod._license = original


class TestGateFailsClosedOnImportOrAttributeError:
    """IMPL-03 discipline: if consulting the authority itself raises (e.g. a
    renamed/removed attribute — a side effect of a botched tamper attempt
    that broke get_integrity_status() itself), the gate must refuse rather
    than silently pass."""

    def test_oidc_gate_refuses_when_verifier_getter_raises(self, monkeypatch):
        def _broken_getter():
            raise RuntimeError("simulated broken authority getter")

        original = enforcer_mod._license
        enforcer_mod.set_license(_FULL_FEATURED_LICENSE)
        monkeypatch.setattr(verifier_mod, "get_integrity_status", _broken_getter)
        try:
            with pytest.raises(enforcer_mod.LicenseFeatureGated):
                oidc_mod._licence_hard_gate("oidc")
        finally:
            enforcer_mod._license = original

    def test_middleware_gate_refuses_when_enforcer_getter_raises(self, monkeypatch):
        def _broken_getter():
            raise RuntimeError("simulated broken authority getter")

        original = enforcer_mod._license
        enforcer_mod.set_license(_FULL_FEATURED_LICENSE)
        monkeypatch.setattr(enforcer_mod, "get_enforcer_integrity_status", _broken_getter)
        try:
            allowed, reason = mw_gate("scim")
            assert allowed is False
        finally:
            enforcer_mod._license = original
