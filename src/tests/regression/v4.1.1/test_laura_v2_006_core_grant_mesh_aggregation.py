"""
Regression tests — LAURA-V2-006 (CRITICAL, 2026-07-17): "core licence/tier
grant (get_license()/is_license_tampered()/require_feature()/check_*_limit())
bypasses the Phase D mesh + LAURA-V2-005 root-pin entirely — a 2-file
{verifier.py, _integrity.py} root-swap forges unlimited ENTERPRISE seats/tier,
only OIDC/SAML/SCIM's own point-of-use hard gates remain protected".

Ref: testing_runs/yashigani/licence-v2-redteam-v2005-final-20260717T120000Z.md
     testing_runs/yashigani/licence-v2-laura006-fix-20260717/ (this fix's own
     end-to-end real-signed-build verify: genuine positive path + 2-file
     forge reproduction + patch-only-enforcer.py control, all via
     verify_scratch/harness_check.py)
     Agnostic Security/Operations/Compliance/yashigani/v4.1.1/laura-pentest/
     findings/LAURA-V2-006_core_grant_bypasses_phase_d_mesh_2file.md

Root cause: `enforcer._any_integrity_violated()` — the function underlying
get_license(), is_license_tampered(), require_feature(), and every
check_*_limit() — only ever consulted the raw `_enforcer_integrity_violated`
global (T1 self/cross-hash only), never `get_enforcer_integrity_status()`
(which correctly ORs in enforcer.py's OWN Phase D full-mesh check and
LAURA-V2-005 root-pin result), and never consulted the other 5 Phase D mesh
members' (gate_middleware.py, sso/oidc.py, sso/saml.py,
backoffice/routes/sso.py, backoffice/routes/scim.py) independently-computed
get_mesh_integrity_status() at all. Consequence: editing exactly 2 files
(verifier.py's pin + _integrity.py's forged root) forged the CORE licence
grant even though 5 of the 6 untouched mesh files correctly, independently
detected and CRITICAL-logged the tamper.

Fix (this file's regressions): `_any_integrity_violated()` now ALSO reads
(a) `get_enforcer_integrity_status()` (ORs enforcer's own T1 + Phase D mesh +
root-pin flags) and (b) each of the 5 other mesh members' own
`get_mesh_integrity_status()` getter. DISTRIBUTED, not a new chokepoint: each
read is that OTHER file's own already-computed flag — enforcer.py does not
recompute anything. Patching enforcer.py alone does not touch what the other
5 files independently computed about their own full-mesh checks.

These tests prove, via monkeypatch (fast/deterministic — the authoritative
real-signed-build proof, including reproducing Laura's exact 2-file
{verifier.py, _integrity.py} forge against a genuine `licgen sign-build`
output and a genuine positive-path control, lives in
testing_runs/yashigani/licence-v2-laura006-fix-20260717/):

  1. enforcer's OWN Phase D mesh/root-pin flag (previously invisible to
     _any_integrity_violated()) now forces get_license()==COMMUNITY,
     is_license_tampered()==True, and check_agent_limit() denies — even when
     the raw T1 `_enforcer_integrity_violated` global is False.
  2. EACH of the 5 other mesh members' own `get_mesh_integrity_status()`
     independently forces the same outcome via the CORE path (not just their
     own point-of-use gate, which was already protected before this fix).
  3. Laura's exact LAURA-V2-006 evidence table, reproduced via monkeypatch:
     verifier clean (pin swap ratifies the forged root) + enforcer's raw T1
     flag clean + enforcer's Phase D mesh/root-pin flag fired (root-pin
     mismatch) + all 5 other mesh members fired — get_license()/
     is_license_tampered()/check_agent_limit() now all fail closed, where
     before this fix they silently granted.
  4. Import/consult failure on any of the 5 new mesh-member checks is itself
     treated as a violation (IMPL-03 discipline, matching the pre-existing
     agents_registry/identity_registry pattern in the same function) — an
     attacker who breaks the import while having tampered the target module
     does not bypass this check.
  5. A raised exception from `get_enforcer_integrity_status()` itself (the
     trivial in-process OR of two already-computed booleans, distinct from
     the 5 real cross-module imports in (4)) is swallowed the same way the
     sibling verifier.get_integrity_status() check immediately above it
     already is — preserving the existing "POU gates' fallback license-state
     read is resilient to a broken shared getter" invariant proven in
     test_laura_v2_001_pou_hardening.py::TestSharedGetterFallbackRemoved and
     test_laura_v2_003_mesh_hardening.py::TestSharedFallbackKilled.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

import yashigani.backoffice.routes.scim as scim_routes
import yashigani.backoffice.routes.sso as sso_routes
import yashigani.licensing.enforcer as enforcer_mod
import yashigani.licensing.gate_middleware as gate_middleware_mod
import yashigani.licensing.verifier as verifier_mod
import yashigani.sso.oidc as oidc_mod
import yashigani.sso.saml as saml_mod
from yashigani.licensing.model import LicenseFeature, LicenseState, LicenseTier

_FULL_FEATURED_LICENSE = LicenseState(
    tier=LicenseTier.ENTERPRISE,
    org_domain="acme.example.com",
    max_agents=-1,
    max_end_users=-1,
    max_admin_seats=-1,
    max_orgs=-1,
    features=frozenset({LicenseFeature.OIDC, LicenseFeature.SAML, LicenseFeature.SCIM}),
    issued_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
    expires_at=None,
    license_id="lic-test-full",
    valid=True,
    error=None,
)


@pytest.fixture()
def _clean_mesh_and_licensed(monkeypatch):
    """Baseline: every mesh/integrity flag this module knows about is False,
    a full-featured (ENTERPRISE, unlimited) licence is active. Each test
    then flips exactly ONE flag to prove that flag alone is now sufficient
    to force the CORE path closed."""
    monkeypatch.setattr(verifier_mod, "_integrity_violated", False)
    monkeypatch.setattr(verifier_mod, "_mesh_integrity_violated", False)
    monkeypatch.setattr(enforcer_mod, "_enforcer_integrity_violated", False)
    monkeypatch.setattr(enforcer_mod, "_enforcer_mesh_integrity_violated", False)
    monkeypatch.setattr(gate_middleware_mod._mesh_checker, "violated", False)
    monkeypatch.setattr(oidc_mod, "_mesh_integrity_violated", False)
    monkeypatch.setattr(saml_mod, "_mesh_integrity_violated", False)
    monkeypatch.setattr(sso_routes, "_mesh_integrity_violated", False)
    monkeypatch.setattr(scim_routes, "_mesh_integrity_violated", False)
    original = enforcer_mod._license
    enforcer_mod.set_license(_FULL_FEATURED_LICENSE)
    yield
    enforcer_mod._license = original


def _assert_forced_community_everywhere():
    assert enforcer_mod.get_license().tier == LicenseTier.COMMUNITY
    assert enforcer_mod.get_license().max_agents != -1
    assert enforcer_mod.is_license_tampered() is True
    with pytest.raises(enforcer_mod.LicenseLimitExceeded):
        enforcer_mod.check_agent_limit(999_999_999)
    with pytest.raises(enforcer_mod.LicenseFeatureGated):
        enforcer_mod.require_feature("oidc")


def _assert_clean_and_granted():
    assert enforcer_mod.get_license().tier == LicenseTier.ENTERPRISE
    assert enforcer_mod.get_license().max_agents == -1
    assert enforcer_mod.is_license_tampered() is False
    enforcer_mod.check_agent_limit(999_999_999)  # must not raise
    enforcer_mod.require_feature("oidc")  # must not raise


class TestCleanBaselineGrants:
    """False-positive guard: with every flag clean, the CORE path must
    still correctly grant the full-featured licence — this fix must not
    have turned _any_integrity_violated() into an always-True chokepoint."""

    def test_clean_mesh_grants_core_path(self, _clean_mesh_and_licensed):
        _assert_clean_and_granted()


class TestEnforcerOwnMeshFlagNowConsulted:
    """LAURA-V2-006's most direct regression: BEFORE this fix,
    `_any_integrity_violated()` only read the raw T1
    `_enforcer_integrity_violated` global — enforcer.py's OWN Phase D
    full-mesh flag (`_enforcer_mesh_integrity_violated`, set by
    `_check_enforcer_mesh_full()`/`_check_enforcer_root_pin()`) was
    computed at module load but never actually consulted by the core grant
    path. This is exactly the flag LAURA-V2-006's 2-file forge leaves set
    while the raw T1 flag stays False (verifier.py+_integrity.py forged
    together never touches enforcer.py's own bytes, so its self-hash still
    matches — only its ROOT-PIN cross-check against the now-forged
    _integrity.py fires)."""

    def test_enforcer_mesh_flag_alone_forces_community(
        self, monkeypatch, _clean_mesh_and_licensed
    ):
        # Exactly LAURA-V2-006's shape: raw T1 flag clean, Phase D mesh/pin
        # flag fired.
        monkeypatch.setattr(enforcer_mod, "_enforcer_integrity_violated", False)
        monkeypatch.setattr(enforcer_mod, "_enforcer_mesh_integrity_violated", True)
        assert enforcer_mod.get_enforcer_integrity_status() is True  # sanity: OR is correct
        _assert_forced_community_everywhere()


class TestOtherFiveMeshMembersNowConsulted:
    """The 5 mesh members previously never read by the core path at all —
    each, independently, must now be sufficient on its own to force
    COMMUNITY via get_license()/is_license_tampered()/check_agent_limit()."""

    def test_gate_middleware_mesh_flag_forces_community(
        self, monkeypatch, _clean_mesh_and_licensed
    ):
        monkeypatch.setattr(gate_middleware_mod._mesh_checker, "violated", True)
        _assert_forced_community_everywhere()

    def test_oidc_mesh_flag_forces_community(self, monkeypatch, _clean_mesh_and_licensed):
        monkeypatch.setattr(oidc_mod, "_mesh_integrity_violated", True)
        _assert_forced_community_everywhere()

    def test_saml_mesh_flag_forces_community(self, monkeypatch, _clean_mesh_and_licensed):
        monkeypatch.setattr(saml_mod, "_mesh_integrity_violated", True)
        _assert_forced_community_everywhere()

    def test_sso_routes_mesh_flag_forces_community(
        self, monkeypatch, _clean_mesh_and_licensed
    ):
        monkeypatch.setattr(sso_routes, "_mesh_integrity_violated", True)
        _assert_forced_community_everywhere()

    def test_scim_routes_mesh_flag_forces_community(
        self, monkeypatch, _clean_mesh_and_licensed
    ):
        monkeypatch.setattr(scim_routes, "_mesh_integrity_violated", True)
        _assert_forced_community_everywhere()


class TestLauraV2006ExactEvidenceTableReproduced:
    """Reproduces Laura's exact evidence table from the finding (2-file
    {verifier.py, _integrity.py} forge against a real signed build):
    verifier clean (pin swap ratifies the forged root), enforcer's raw T1
    flag clean, enforcer's Phase D mesh/root-pin flag AND all 5 other mesh
    members' flags fired. Before this fix, `_any_integrity_violated()`
    returned False despite 5 of 6 untouched mesh files correctly detecting
    tamper — the exact bug. After this fix, every core-path consumer fails
    closed."""

    def test_full_laura_evidence_table(self, monkeypatch, _clean_mesh_and_licensed):
        monkeypatch.setattr(verifier_mod, "_integrity_violated", False)
        monkeypatch.setattr(verifier_mod, "_mesh_integrity_violated", False)
        monkeypatch.setattr(enforcer_mod, "_enforcer_integrity_violated", False)
        monkeypatch.setattr(enforcer_mod, "_enforcer_mesh_integrity_violated", True)
        monkeypatch.setattr(gate_middleware_mod._mesh_checker, "violated", True)
        monkeypatch.setattr(oidc_mod, "_mesh_integrity_violated", True)
        monkeypatch.setattr(saml_mod, "_mesh_integrity_violated", True)
        monkeypatch.setattr(sso_routes, "_mesh_integrity_violated", True)
        monkeypatch.setattr(scim_routes, "_mesh_integrity_violated", True)

        # verifier's own status is unaffected — matches Laura's evidence
        # table exactly (verifier._integrity_violated=false,
        # verifier.get_integrity_status()=false — the pin-swap ratifies the
        # forged root from verifier.py's own point of view).
        assert verifier_mod.get_integrity_status() is False

        _assert_forced_community_everywhere()

        # agents/registry.py and backoffice/routes/{accounts,agents,pii,users}.py
        # all route through the SAME get_license()/require_feature() surface
        # (no per-consumer fix needed) — spot-check the other named consumers
        # from the finding's Impact section via the identical entry points.
        with pytest.raises(enforcer_mod.LicenseFeatureGated):
            enforcer_mod.require_feature("saml")
        with pytest.raises(enforcer_mod.LicenseFeatureGated):
            enforcer_mod.require_feature("scim")
        with pytest.raises(enforcer_mod.LicenseLimitExceeded):
            enforcer_mod.check_end_user_limit(999_999_999)
        with pytest.raises(enforcer_mod.LicenseLimitExceeded):
            enforcer_mod.check_admin_seat_limit(999_999_999)
        with pytest.raises(enforcer_mod.LicenseLimitExceeded):
            enforcer_mod.check_org_limit(999_999_999)


class TestFiveNewMeshImportFailureFailsClosed:
    """IMPL-03 discipline (matching the pre-existing agents_registry/
    identity_registry pattern in the same function): a raised exception
    while importing/consulting one of the 5 NEW mesh-member checks is
    itself treated as an integrity violation, not silently ignored — these
    are genuine cross-module imports (unlike the two getter calls covered
    in TestBrokenEnforcerGetterHasZeroEffectOnCorePath below), so a
    tampering-induced ImportError/AttributeError must fail closed."""

    @pytest.mark.parametrize(
        "modname",
        [
            "yashigani.licensing.gate_middleware",
            "yashigani.sso.oidc",
            "yashigani.sso.saml",
            "yashigani.backoffice.routes.sso",
            "yashigani.backoffice.routes.scim",
        ],
    )
    def test_broken_mesh_member_get_mesh_integrity_status_fails_closed(
        self, monkeypatch, modname, _clean_mesh_and_licensed
    ):
        import importlib

        mod = importlib.import_module(modname)

        def _boom():
            raise RuntimeError(f"{modname}.get_mesh_integrity_status() simulated failure")

        monkeypatch.setattr(mod, "get_mesh_integrity_status", _boom)
        _assert_forced_community_everywhere()


class TestBrokenEnforcerGetterHasZeroEffectOnCorePath:
    """The trivial in-process `get_enforcer_integrity_status()` getter (a
    pure OR of two already-computed module-level booleans, no I/O) is
    wrapped the same way as the sibling verifier.get_integrity_status()
    check immediately above it in `_any_integrity_violated()` — a raised
    exception is swallowed, not treated as a violation. This preserves the
    pre-existing "POU gates' fallback license-state read
    (enforcer.get_license()) is resilient to a broken shared getter"
    invariant already proven in test_laura_v2_001_pou_hardening.py and
    test_laura_v2_003_mesh_hardening.py — this fix must not have made those
    tests fail by introducing a new hard dependency on that getter."""

    def test_broken_enforcer_getter_swallowed_not_fatal(
        self, monkeypatch, _clean_mesh_and_licensed
    ):
        def _boom():
            raise RuntimeError("get_enforcer_integrity_status() simulated failure")

        monkeypatch.setattr(enforcer_mod, "get_enforcer_integrity_status", _boom)
        _assert_clean_and_granted()
