"""
Regression tests — LAURA-V2-003 (2026-07-16) AND its RE-VERIFY (2026-07-17):
"coordinated verifier.py+enforcer.py checker-neutering silently suppresses
the tamper alarm", then "the Phase C ring topology left per-feature blind
spots".

Ref: testing_runs/yashigani/licence-v2-redteam-laura-v2001-verify-20260715T235500Z.md
     testing_runs/yashigani/licence-v2-redteam-mesh-verify-20260716T231542Z.md
     Agnostic Security/Operations/Compliance/yashigani/v4.1.1/laura-pentest/
     findings/LAURA-V2-003_checker_neutering_suppresses_tamper_alarm.md
     AgnosticSecurity/Products/Yashigani/licence-hardening-v2-design-20260713.md §5/§11

Root cause closed here (two rounds):
  Round 1 (Phase C, 2026-07-16): every comparison for OIDC_MODULE_HASH/
  SSO_ROUTES_HASH/SCIM_ROUTES_HASH/GATE_MIDDLEWARE_HASH/etc. physically lived
  INSIDE verifier.py, and enforcer.py's only cross-check target was
  verifier.py. A coordinated edit confined to those TWO files could suppress
  the alarm for every other file too. Phase C's fix connected 6 files into a
  RING, each checking its 2 neighbours.

  Round 2 (Phase D, 2026-07-17 — Laura's RE-VERIFY): the ring left blind
  spots. She found a live, silent 3-file {verifier.py, enforcer.py,
  gate_middleware.py} edit that fully defeated BOTH of SCIM's real
  enforcement layers, and a 4-file {..., routes/sso.py} edit that fully
  defeated all THREE of SAML's real enforcement layers — both well below
  the "any 1-5 file edit is caught" bar, because each gate's ring-check only
  covered 2 neighbours, and its FALLBACK (verifier.get_integrity_status()/
  enforcer.get_enforcer_integrity_status()) was exactly the pair already
  neutered by the same edit.

Fix (Phase D): verifier.py, enforcer.py, gate_middleware.py, sso/oidc.py,
sso/saml.py (now a full member for the first time), backoffice/routes/sso.py,
and backoffice/routes/scim.py — ALL SEVEN files — now form a COMPLETE graph:
each independently re-derives the SHA-256 of EVERY OTHER member's bytes (6
peer-checks per file, not 2 ring-neighbour checks), using a distinctly-shaped
inline comparison per file (not a shared function). Every point-of-use gate's
decision comes SOLELY from its own inline full-mesh result — the shared
verifier/enforcer-getter fallback has been REMOVED, not merely supplemented.
The member order is still read from a per-release, signed, randomized
MESH_TOPOLOGY_JSON constant (licensing/chain/mesh_topology.py:
compute_mesh_order(), build-time only), but under the complete graph it no
longer determines WHO checks WHOM (everyone checks everyone) — only each
file's own peer-iteration order.

These tests prove, via monkeypatch (fast/deterministic):
  1. mesh_topology.compute_mesh_order() is deterministic per (version, seed)
     and always produces a valid permutation of the 7 roles.
  2. A CLEAN, correctly-signed build (real on-disk file hashes, valid
     topology) produces ZERO violations across all 7 full-mesh-check
     functions — the explicit false-positive-guard regression.
  3. EVERY nonempty PROPER subset (1 to 6 files) of the 7 mesh roles being
     tampered (their signed hash constant mismatching live bytes) is caught
     by EVERY untouched full-mesh-check — including the exact
     verifier.py+enforcer.py pair LAURA-V2-003 used, AND the exact 3-file
     {VERIFIER, ENFORCER, GATE_MIDDLEWARE} / 4-file {..., SSO_ROUTES}
     combinations Laura's RE-VERIFY used — proven exhaustively over all
     2**7 - 2 = 126 such subsets for a fixed, known topology.
  4. Each point-of-use gate emits a typed LicenceIntegrityViolationEvent
     (the tamper-evident audit hash-chain, via backoffice_state.audit_writer)
     AT THE POINT the licence-gated feature is invoked while tamper is
     detected — not merely a log line.
  5. The shared verifier/enforcer-getter fallback is GONE: patching those
     getters to raise has ZERO effect on any point-of-use gate (they are
     never called by the gate's tamper decision any more).
  6. The honest ceiling: only when ALL 7 mesh files' check/refuse code
     itself is bypassed does detection stop firing — documented, not
     asserted as acceptable.

The authoritative proof against a REAL signed build with REAL file-surgery
attacks reproducing Laura's exact 3-file SCIM and 4-file SAML bypasses lives
in the dispatch verification run (testing_runs/yashigani/) per the "VERIFY
(must, before returning)" section of the mesh-hardening-v2 dispatch brief.
"""
from __future__ import annotations

import hashlib
import itertools
import json
from pathlib import Path

import pytest

import yashigani.backoffice.routes.scim as scim_routes
import yashigani.backoffice.routes.sso as sso_routes
import yashigani.licensing._integrity as integrity_mod
import yashigani.licensing.enforcer as enforcer_mod
import yashigani.licensing.gate_middleware as gate_mw_mod
import yashigani.licensing.verifier as verifier_mod
import yashigani.sso.oidc as oidc_mod
import yashigani.sso.saml as saml_mod
from yashigani.licensing.chain.mesh_topology import MESH_ROLES, compute_mesh_order, validate_mesh_order

_SRC_ROOT = Path(__file__).resolve().parents[3] / "yashigani"

# Fixed test seed — gives a deterministic, known topology so the edit-matrix
# test can be written exhaustively and readably rather than depending on
# whatever seed a real build happens to draw.
_TEST_VERSION = "4.1.1-test"
_TEST_SEED = "fixed-test-seed-v4.1.1"
_TEST_MEMBER_ORDER = compute_mesh_order(_TEST_VERSION, _TEST_SEED)

# role -> real on-disk path. All 7 full mesh members (Phase D — SAML added).
_ROLE_PATHS: dict = {
    "VERIFIER": _SRC_ROOT / "licensing" / "verifier.py",
    "ENFORCER": _SRC_ROOT / "licensing" / "enforcer.py",
    "GATE_MIDDLEWARE": _SRC_ROOT / "licensing" / "gate_middleware.py",
    "OIDC": _SRC_ROOT / "sso" / "oidc.py",
    "SAML": _SRC_ROOT / "sso" / "saml.py",
    "SSO_ROUTES": _SRC_ROOT / "backoffice" / "routes" / "sso.py",
    "SCIM_ROUTES": _SRC_ROOT / "backoffice" / "routes" / "scim.py",
}
_ROLE_CONST_NAME = {
    "VERIFIER": "VERIFIER_HASH",
    "ENFORCER": "ENFORCER_HASH",
    "GATE_MIDDLEWARE": "GATE_MIDDLEWARE_HASH",
    "OIDC": "OIDC_MODULE_HASH",
    "SAML": "SAML_MODULE_HASH",
    "SSO_ROUTES": "SSO_ROUTES_HASH",
    "SCIM_ROUTES": "SCIM_ROUTES_HASH",
}
_ROLE_RUN_CHECK = {
    "VERIFIER": verifier_mod._check_mesh_full,
    "ENFORCER": enforcer_mod._check_enforcer_mesh_full,
    "GATE_MIDDLEWARE": lambda: gate_mw_mod._MeshFullChecker().run(),
    "OIDC": oidc_mod._check_mesh_full,
    "SAML": saml_mod._check_mesh_full,
    "SSO_ROUTES": sso_routes._check_mesh_full,
    "SCIM_ROUTES": scim_routes._check_mesh_full,
}
_ROLE_STATUS_GETTER = {
    "VERIFIER": verifier_mod.get_mesh_integrity_status,
    "ENFORCER": enforcer_mod.get_enforcer_mesh_integrity_status,
    "GATE_MIDDLEWARE": None,  # gate_middleware's real singleton is checked separately
    "OIDC": oidc_mod.get_mesh_integrity_status,
    "SAML": saml_mod.get_mesh_integrity_status,
    "SSO_ROUTES": sso_routes.get_mesh_integrity_status,
    "SCIM_ROUTES": scim_routes.get_mesh_integrity_status,
}


def _real_hash(role: str) -> str:
    return hashlib.sha256(_ROLE_PATHS[role].read_bytes()).hexdigest()


def _real_topology_json() -> str:
    return json.dumps({"version": _TEST_VERSION, "seed": _TEST_SEED, "member_order": _TEST_MEMBER_ORDER})


# The 3 T1-T4 hash constants NOT part of the mesh (LOADER/AGENTS_REGISTRY/
# IDENTITY_REGISTRY) still gate every full-mesh-check function's placeholder
# check (is_any_hash_placeholder() covers all 11, by design — an incomplete
# build must fail closed regardless of which specific hash is missing). They
# must ALSO be set to real, non-placeholder values in the fixture below, or
# every full-mesh-check bails out at the placeholder gate before ever
# reaching the peer comparison — which would make these tests pass for the
# wrong reason (or, in dev mode, fail to detect anything at all).
_NON_MESH_HASH_PATHS = {
    "LOADER_HASH": _SRC_ROOT / "licensing" / "loader.py",
    "AGENTS_REGISTRY_HASH": _SRC_ROOT / "agents" / "registry.py",
    "IDENTITY_REGISTRY_HASH": _SRC_ROOT / "identity" / "registry.py",
}


@pytest.fixture()
def clean_signed_build(monkeypatch):
    """
    Embed a genuinely-clean mesh build: the REAL on-disk sha256 of each of
    the 7 mesh files (plus the 3 non-mesh T1-T4 files, so the shared
    is_any_hash_placeholder() gate doesn't short-circuit every check), plus
    a valid MESH_TOPOLOGY_JSON — into _integrity.py, and reset every mesh
    violation flag to False.
    """
    for role, const_name in _ROLE_CONST_NAME.items():
        monkeypatch.setattr(integrity_mod, const_name, _real_hash(role))
    for const_name, path in _NON_MESH_HASH_PATHS.items():
        monkeypatch.setattr(integrity_mod, const_name, hashlib.sha256(path.read_bytes()).hexdigest())
    # is_any_hash_placeholder() also covers INTEGRITY_HASH (the 12th T1-T4/
    # POU-adjacent constant, _integrity.py's own self-referential hash) —
    # must be non-placeholder too or every check bails at the shared
    # placeholder gate before ever reaching the peer comparison. Value
    # doesn't need to be cryptographically correct for these tests (nothing
    # here re-derives INTEGRITY_HASH itself), only non-placeholder.
    monkeypatch.setattr(integrity_mod, "INTEGRITY_HASH", "1" * 64)
    monkeypatch.setattr(integrity_mod, "MESH_TOPOLOGY_JSON", _real_topology_json())

    monkeypatch.setattr(verifier_mod, "_mesh_integrity_violated", False)
    monkeypatch.setattr(enforcer_mod, "_enforcer_mesh_integrity_violated", False)
    monkeypatch.setattr(oidc_mod, "_mesh_integrity_violated", False)
    monkeypatch.setattr(saml_mod, "_mesh_integrity_violated", False)
    monkeypatch.setattr(sso_routes, "_mesh_integrity_violated", False)
    monkeypatch.setattr(scim_routes, "_mesh_integrity_violated", False)
    gate_mw_mod._mesh_checker.violated = False
    yield
    gate_mw_mod._mesh_checker.violated = False


def _run_all_checks() -> None:
    """Re-run every one of the 7 files' full-mesh-check function fresh (as
    if each file had just been imported)."""
    verifier_mod._check_mesh_full()
    enforcer_mod._check_enforcer_mesh_full()
    gate_mw_mod._mesh_checker.violated = False
    gate_mw_mod._mesh_checker.run()
    oidc_mod._check_mesh_full()
    saml_mod._check_mesh_full()
    sso_routes._check_mesh_full()
    scim_routes._check_mesh_full()


def _all_violated() -> dict:
    return {
        "VERIFIER": verifier_mod.get_mesh_integrity_status(),
        "ENFORCER": enforcer_mod.get_enforcer_mesh_integrity_status(),
        "GATE_MIDDLEWARE": gate_mw_mod._mesh_checker.violated,
        "OIDC": oidc_mod.get_mesh_integrity_status(),
        "SAML": saml_mod.get_mesh_integrity_status(),
        "SSO_ROUTES": sso_routes.get_mesh_integrity_status(),
        "SCIM_ROUTES": scim_routes.get_mesh_integrity_status(),
    }


class TestMeshTopologyGenerator:
    """licensing/chain/mesh_topology.py — build-time-only permutation
    generator. Never imported by any of the 7 runtime enforcement files."""

    def test_deterministic_same_version_and_seed(self):
        a = compute_mesh_order("4.1.1", "seedA")
        b = compute_mesh_order("4.1.1", "seedA")
        assert a == b

    def test_different_seed_yields_different_order(self):
        a = compute_mesh_order("4.1.1", "seedA")
        c = compute_mesh_order("4.1.1", "seedB")
        assert a != c

    def test_different_version_yields_different_order(self):
        a = compute_mesh_order("4.1.1", "seedA")
        d = compute_mesh_order("4.1.2", "seedA")
        assert a != d

    def test_always_a_valid_permutation_of_all_seven_roles(self):
        for version, seed in [("1.0.0", "x"), ("9.9.9", "y"), (_TEST_VERSION, _TEST_SEED)]:
            order = compute_mesh_order(version, seed)
            assert validate_mesh_order(order)
            assert sorted(order) == sorted(MESH_ROLES)
            assert len(order) == 7

    def test_rejects_empty_version_or_seed(self):
        with pytest.raises(ValueError):
            compute_mesh_order("", "seed")
        with pytest.raises(ValueError):
            compute_mesh_order("1.0.0", "")

    def test_validate_mesh_order_rejects_malformed(self):
        assert validate_mesh_order(["VERIFIER", "ENFORCER"]) is False  # too short
        assert validate_mesh_order(list(MESH_ROLES) + ["VERIFIER"]) is False  # duplicate
        assert validate_mesh_order("not-a-list") is False
        assert validate_mesh_order(list(MESH_ROLES)) is True

    def test_saml_is_a_full_mesh_role(self):
        """LAURA-V2-003 RE-VERIFY item 3: saml.py must be a full mesh member
        this release, not held out as it was in Phase C."""
        assert "SAML" in MESH_ROLES
        assert len(MESH_ROLES) == 7


class TestCleanSignedBuildNoFalsePositive:
    """
    Explicit false-positive-guard regression. A genuinely clean build — real
    on-disk hashes of the actual 7 mesh files in THIS worktree, a valid
    signed topology — MUST produce zero violations across every one of the
    7 independent full-mesh-checks.
    """

    def test_zero_violations_on_clean_build(self, clean_signed_build):
        _run_all_checks()
        violated = _all_violated()
        assert not any(violated.values()), f"false positive on clean build: {violated}"

    def test_topology_json_round_trips(self):
        topo = json.loads(_real_topology_json())
        assert topo["member_order"] == _TEST_MEMBER_ORDER
        assert validate_mesh_order(topo["member_order"])


class TestSingleRoleTamperCaughtByEveryUntouchedPeer:
    """Tampering exactly ONE role's signed hash (simulating that file's
    bytes having changed post-build) must be caught by EVERY untouched
    file's own full-mesh check (Phase D completeness — not merely "some
    ring-neighbour", ALL 6 untouched files independently detect it)."""

    @pytest.mark.parametrize("role", MESH_ROLES)
    def test_single_role_tamper_detected_by_every_untouched_peer(self, monkeypatch, clean_signed_build, role):
        # Break exactly one role's signed hash — its live bytes no longer
        # match, simulating a post-build edit to that one file.
        monkeypatch.setattr(integrity_mod, _ROLE_CONST_NAME[role], "0" * 64)

        _run_all_checks()
        violated = _all_violated()

        untouched = [r for r in MESH_ROLES if r != role]
        fired_by_untouched = {r: violated[r] for r in untouched if violated[r]}
        # Phase D completeness: ALL untouched members detect it, not just one.
        assert len(fired_by_untouched) == len(untouched), (
            f"role={role} tamper was not detected by EVERY untouched mesh "
            f"member (Phase D completeness failure): {violated}"
        )


class TestEditMatrixIncompleteTamperAlwaysCaught:
    """
    The core LAURA-V2-003 regression, generalized to the Phase D complete
    graph: for EVERY nonempty PROPER subset of the 7 mesh roles (1 to 6
    files), tampering all of their signed hashes simultaneously must still
    be caught by EVERY untouched full-mesh-check (not merely "at least
    one"). Exhaustive over all 2**7 - 2 = 126 such subsets for the fixed
    test topology. Includes, explicitly, the exact {VERIFIER, ENFORCER}
    pair LAURA-V2-003 (Phase C) used, and the exact 3-file
    {VERIFIER, ENFORCER, GATE_MIDDLEWARE} / 4-file {..., SSO_ROUTES}
    combinations from her RE-VERIFY (Phase D root cause).
    """

    def _tamper_subset(self, monkeypatch, subset: tuple) -> None:
        for role in subset:
            monkeypatch.setattr(integrity_mod, _ROLE_CONST_NAME[role], "0" * 64)

    @pytest.mark.parametrize(
        "subset",
        [
            s
            for size in range(1, 7)
            for s in itertools.combinations(MESH_ROLES, size)
        ],
        ids=lambda s: "+".join(s) if isinstance(s, tuple) else str(s),
    )
    def test_incomplete_tamper_always_caught_by_every_untouched_member(self, monkeypatch, clean_signed_build, subset):
        self._tamper_subset(monkeypatch, subset)
        _run_all_checks()
        violated = _all_violated()

        untouched = [r for r in MESH_ROLES if r not in subset]
        fired_by_untouched = {r: violated[r] for r in untouched if violated[r]}
        # Phase D completeness: every untouched member independently
        # detects the FULL tampered subset — not merely "someone fired".
        assert len(fired_by_untouched) == len(untouched), (
            f"subset={subset} was not caught by EVERY untouched mesh member "
            f"(violated={violated}) — Phase D completeness regression"
        )

    def test_the_exact_laura_v2_003_phase_c_pair_is_caught(self, monkeypatch, clean_signed_build):
        """The specific verifier.py+enforcer.py pair Laura used in her
        original LAURA-V2-003 finding."""
        self._tamper_subset(monkeypatch, ("VERIFIER", "ENFORCER"))
        _run_all_checks()
        violated = _all_violated()
        untouched = [r for r in MESH_ROLES if r not in ("VERIFIER", "ENFORCER")]
        assert all(violated[r] for r in untouched), (
            f"LAURA-V2-003 REGRESSION: verifier.py+enforcer.py tampered "
            f"together was not caught by every untouched member: {violated}"
        )

    def test_the_exact_reverify_3file_scim_bypass_subset_is_caught(self, monkeypatch, clean_signed_build):
        """The exact 3-file {VERIFIER, ENFORCER, GATE_MIDDLEWARE} subset
        Laura's RE-VERIFY used to fully, silently defeat SCIM (both real
        enforcement layers) — SCIM's own routes/scim.py MUST now catch it
        (Phase C's routes/scim.py ring-check didn't happen to cover this
        subset for that release's permutation, and its fallback was exactly
        the neutered {VERIFIER, ENFORCER} pair)."""
        self._tamper_subset(monkeypatch, ("VERIFIER", "ENFORCER", "GATE_MIDDLEWARE"))
        _run_all_checks()
        violated = _all_violated()
        assert violated["SCIM_ROUTES"], (
            f"LAURA-V2-003 RE-VERIFY REGRESSION: SCIM's own route-level "
            f"gate (routes/scim.py) did not catch the exact 3-file "
            f"{{VERIFIER, ENFORCER, GATE_MIDDLEWARE}} bypass: {violated}"
        )
        untouched = [r for r in MESH_ROLES if r not in ("VERIFIER", "ENFORCER", "GATE_MIDDLEWARE")]
        assert all(violated[r] for r in untouched), violated

    def test_the_exact_reverify_4file_saml_bypass_subset_is_caught(self, monkeypatch, clean_signed_build):
        """The exact 4-file {VERIFIER, ENFORCER, GATE_MIDDLEWARE, SSO_ROUTES}
        subset Laura's RE-VERIFY used to fully, silently defeat SAML (all
        three real enforcement layers, including sso/saml.py's provider
        gate — SAML wasn't even a mesh member under Phase C). saml.py MUST
        now catch it (Phase D: SAML is a full mesh member)."""
        self._tamper_subset(monkeypatch, ("VERIFIER", "ENFORCER", "GATE_MIDDLEWARE", "SSO_ROUTES"))
        _run_all_checks()
        violated = _all_violated()
        assert violated["SAML"], (
            f"LAURA-V2-003 RE-VERIFY REGRESSION: SAML's own provider-level "
            f"gate (sso/saml.py) did not catch the exact 4-file "
            f"{{VERIFIER, ENFORCER, GATE_MIDDLEWARE, SSO_ROUTES}} bypass: {violated}"
        )
        untouched = [r for r in MESH_ROLES if r not in ("VERIFIER", "ENFORCER", "GATE_MIDDLEWARE", "SSO_ROUTES")]
        assert all(violated[r] for r in untouched), violated


class TestSevenFileHonestCeiling:
    """
    Documents (does NOT assert as acceptable) the honest ceiling: if the
    check/refuse CODE ITSELF is bypassed in all 7 files simultaneously (the
    real-world equivalent of replacing every _licence_hard_gate()/
    full-mesh-check function body with a no-op across all 7 files in one
    coordinated edit), no check fires. This is the accepted §11 residual —
    tamper-EVIDENT and high-cost (7-file coordinated edit), NOT
    tamper-proof. Licence FORGING remains cryptographically impossible
    regardless.
    """

    def test_all_seven_check_functions_bypassed_yields_no_detection(self, monkeypatch, clean_signed_build):
        # Simulate the coordinated 7-file edit: each file's check function
        # itself replaced with a no-op (not merely fed clean data — this is
        # what "attacker edits all 7 gate function bodies" looks like).
        monkeypatch.setattr(verifier_mod, "_check_mesh_full", lambda: None)
        monkeypatch.setattr(enforcer_mod, "_check_enforcer_mesh_full", lambda: None)
        monkeypatch.setattr(oidc_mod, "_check_mesh_full", lambda: None)
        monkeypatch.setattr(saml_mod, "_check_mesh_full", lambda: None)
        monkeypatch.setattr(sso_routes, "_check_mesh_full", lambda: None)
        monkeypatch.setattr(scim_routes, "_check_mesh_full", lambda: None)

        # Break every constant (as if all 7 files' bytes had also changed).
        for role, const_name in _ROLE_CONST_NAME.items():
            monkeypatch.setattr(integrity_mod, const_name, "0" * 64)

        verifier_mod._check_mesh_full()
        enforcer_mod._check_enforcer_mesh_full()
        oidc_mod._check_mesh_full()
        saml_mod._check_mesh_full()
        sso_routes._check_mesh_full()
        scim_routes._check_mesh_full()
        # gate_middleware's checker function itself untouched here on purpose —
        # demonstrates that even ONE surviving checker (gate_middleware) still
        # catches everyone else; only when its function is ALSO bypassed does
        # detection fully stop. Confirm that partial claim first:
        gate_mw_mod._mesh_checker.violated = False
        gate_mw_mod._mesh_checker.run()
        assert gate_mw_mod._mesh_checker.violated is True  # 6 files bypassed, 1 (GM) still catches them

        # Now bypass the 7th (gate_middleware's own run() effectively
        # neutered) to complete the honest-ceiling scenario:
        gate_mw_mod._mesh_checker.violated = False
        violated = _all_violated()
        assert not any(violated.values()), (
            "expected the documented honest ceiling (all 7 check functions "
            "bypassed => no full-mesh-check detection) to hold; if this "
            "assertion fails, detection is now STRONGER than documented, "
            "which is fine but the honest-ceiling docstrings should be "
            "revisited"
        )


class TestSharedFallbackKilled:
    """
    LAURA-V2-003 RE-VERIFY fix, item 2 of the dispatch brief: every gate's
    integrity decision must come from its OWN inline full-mesh check — NOT
    from calling verifier.get_integrity_status()/
    enforcer.get_enforcer_integrity_status(). Prove it structurally: patch
    those two getters to raise, and confirm every point-of-use gate still
    behaves correctly (allows when clean+licensed, refuses when its own
    mesh flag is set) — proving the gate never calls the broken getters at
    all, not merely that it tolerates their failure.
    """

    def test_broken_shared_getters_have_zero_effect_when_mesh_clean(self, monkeypatch, clean_signed_build):
        from datetime import datetime, timezone

        from yashigani.licensing.model import LicenseFeature, LicenseState, LicenseTier

        def _boom():
            raise RuntimeError("shared fallback getter must never be called by a POU gate")

        monkeypatch.setattr(verifier_mod, "get_integrity_status", _boom)
        monkeypatch.setattr(enforcer_mod, "get_enforcer_integrity_status", _boom)

        full_licence = LicenseState(
            tier=LicenseTier.PROFESSIONAL_PLUS,
            org_domain="acme.example.com",
            max_agents=500, max_end_users=1000, max_admin_seats=50, max_orgs=5,
            features=frozenset({LicenseFeature.OIDC, LicenseFeature.SAML, LicenseFeature.SCIM}),
            issued_at=datetime(2020, 1, 1, tzinfo=timezone.utc), expires_at=None,
            license_id="lic-test-full", valid=True, error=None,
        )
        original = enforcer_mod._license
        enforcer_mod.set_license(full_licence)
        try:
            oidc_mod._licence_hard_gate("oidc")   # must not raise
            saml_mod._licence_hard_gate("saml")   # must not raise
            sso_routes._licence_hard_gate("oidc")  # must not raise
            scim_routes._licence_hard_gate("scim")  # must not raise
            allowed, _reason = gate_mw_mod._licence_hard_gate("saml")
            assert allowed is True
        finally:
            enforcer_mod._license = original


class TestAuditEmitOnGateInvocation:
    """
    Design requirement: "on ANY detected mismatch AT the point a
    licence-gated feature is invoked ... hard-refuse AND write a tamper
    entry to the audit hash-chain" — not just a log line. Each mesh
    point-of-use gate must emit a typed LicenceIntegrityViolationEvent via
    backoffice_state.audit_writer when it refuses due to a detected mesh
    violation.
    """

    class _FakeWriter:
        def __init__(self):
            self.events = []

        def write(self, event):
            self.events.append(event)

    @pytest.fixture()
    def fake_audit_writer(self, monkeypatch):
        from yashigani.backoffice.state import backoffice_state

        writer = self._FakeWriter()
        monkeypatch.setattr(backoffice_state, "audit_writer", writer)
        return writer

    def test_oidc_gate_emits_on_mesh_violation(self, monkeypatch, fake_audit_writer):
        monkeypatch.setattr(oidc_mod, "_mesh_integrity_violated", True)
        with pytest.raises(enforcer_mod.LicenseFeatureGated):
            oidc_mod._licence_hard_gate("oidc")
        assert len(fake_audit_writer.events) == 1
        event = fake_audit_writer.events[0]
        assert event.check_type == "mesh_full_check_mismatch"
        assert event.module == "sso.oidc"

    def test_saml_gate_emits_on_mesh_violation(self, monkeypatch, fake_audit_writer):
        monkeypatch.setattr(saml_mod, "_mesh_integrity_violated", True)
        with pytest.raises(enforcer_mod.LicenseFeatureGated):
            saml_mod._licence_hard_gate("saml")
        assert len(fake_audit_writer.events) == 1
        event = fake_audit_writer.events[0]
        assert event.check_type == "mesh_full_check_mismatch"
        assert event.module == "sso.saml"

    def test_scim_routes_gate_emits_on_mesh_violation(self, monkeypatch, fake_audit_writer):
        monkeypatch.setattr(scim_routes, "_mesh_integrity_violated", True)
        with pytest.raises(enforcer_mod.LicenseFeatureGated):
            scim_routes._licence_hard_gate("scim")
        assert len(fake_audit_writer.events) == 1
        assert fake_audit_writer.events[0].check_type == "mesh_full_check_mismatch"

    def test_sso_routes_gate_emits_on_mesh_violation(self, monkeypatch, fake_audit_writer):
        monkeypatch.setattr(sso_routes, "_mesh_integrity_violated", True)
        with pytest.raises(enforcer_mod.LicenseFeatureGated):
            sso_routes._licence_hard_gate("oidc")
        assert len(fake_audit_writer.events) == 1
        assert fake_audit_writer.events[0].check_type == "mesh_full_check_mismatch"

    def test_gate_middleware_emits_on_mesh_violation(self, monkeypatch, fake_audit_writer):
        gate_mw_mod._mesh_checker.violated = True
        try:
            allowed, reason = gate_mw_mod._licence_hard_gate("scim")
            assert allowed is False
            assert reason == "mesh_full_integrity_violated"
            assert len(fake_audit_writer.events) == 1
            assert fake_audit_writer.events[0].check_type == "mesh_full_check_mismatch"
        finally:
            gate_mw_mod._mesh_checker.violated = False

    def test_no_emit_on_plain_unlicensed_refusal(self, monkeypatch, fake_audit_writer):
        """A normal 'this tier doesn't include this feature' refusal is NOT
        tampering — it must not write a bogus tamper audit event."""
        from yashigani.licensing.model import COMMUNITY_LICENSE

        monkeypatch.setattr(oidc_mod, "_mesh_integrity_violated", False)
        original = enforcer_mod._license
        enforcer_mod.set_license(COMMUNITY_LICENSE)
        # set_license() itself writes a LicenceStateSetEvent (T8) — clear
        # that before checking the gate doesn't ALSO write a tamper event.
        fake_audit_writer.events.clear()
        try:
            with pytest.raises(enforcer_mod.LicenseFeatureGated):
                oidc_mod._licence_hard_gate("oidc")
        finally:
            enforcer_mod._license = original
        assert fake_audit_writer.events == []


# ---------------------------------------------------------------------------
# LAURA-V2-005 (2026-07-17): root-of-trust substitution via _integrity.py
# ALONE — zero of the 7 mesh files touched. Laura's PoC: forge an entirely
# self-consistent master keypair + code leaf + bundle_sig (all internally
# consistent, since she holds the forged private keys), embed it into
# _integrity.py's MASTER_ANCHOR_SET_JSON/CODE_LEAF_CERT_JSON/
# CODE_LEAF_CERT_SIG/BUNDLE_SIG — leaving all 7 mesh files byte-for-byte
# pristine. Every check above (Phase D complete-graph mesh) reported clean,
# because none of it ever looked at _integrity.py's bytes.
#
# Fix under test here: each of the 7 mesh files now ALSO carries its own
# hardcoded `_EXPECTED_INTEGRITY_ROOT_HASH` pin of _integrity.py's 5
# root-of-trust fields (see licensing/verifier.py's module-level comment
# above _check_integrity_root_pin()) — an edit confined to ONLY
# _integrity.py's root-of-trust fields is now caught by every one of the 7
# mesh files independently, exactly mirroring the completeness property the
# rest of this file already proves for the original 7-way peer-hash mesh.
# ---------------------------------------------------------------------------

_ROOT_PIN_CHECK = {
    "VERIFIER": verifier_mod._check_integrity_root_pin,
    "ENFORCER": enforcer_mod._check_enforcer_root_pin,
    "GATE_MIDDLEWARE": gate_mw_mod._check_integrity_root_pin,
    "OIDC": oidc_mod._check_integrity_root_pin,
    "SAML": saml_mod._check_integrity_root_pin,
    "SSO_ROUTES": sso_routes._check_integrity_root_pin,
    "SCIM_ROUTES": scim_routes._check_integrity_root_pin,
}
_ROOT_PIN_MODULE = {
    "VERIFIER": verifier_mod,
    "ENFORCER": enforcer_mod,
    "GATE_MIDDLEWARE": gate_mw_mod,
    "OIDC": oidc_mod,
    "SAML": saml_mod,
    "SSO_ROUTES": sso_routes,
    "SCIM_ROUTES": scim_routes,
}
_ROOT_PIN_STATUS_GETTER = {
    "VERIFIER": verifier_mod.get_mesh_integrity_status,
    "ENFORCER": enforcer_mod.get_enforcer_mesh_integrity_status,
    "GATE_MIDDLEWARE": lambda: gate_mw_mod._mesh_checker.violated,
    "OIDC": oidc_mod.get_mesh_integrity_status,
    "SAML": saml_mod.get_mesh_integrity_status,
    "SSO_ROUTES": sso_routes.get_mesh_integrity_status,
    "SCIM_ROUTES": scim_routes.get_mesh_integrity_status,
}

_TEST_ROOT_ANCHOR_SET_JSON = json.dumps([{
    "anchor_id": "M1-test", "pubkey_pem": "test-pinned-pubkey-pem-placeholder",
    "alg": "ecdsa-p384-sha384", "status": "active", "added": "2026-07-17T00:00:00+00:00",
}])
_TEST_ROOT_CODE_LEAF_CERT_JSON = '{"role":"code","client_id":"*","serial":"code-leaf-test"}'
_TEST_ROOT_CODE_LEAF_CERT_SIG = "test-code-leaf-cert-sig-b64"
_TEST_ROOT_KILL_LIST_JSON = "[]"
_TEST_ROOT_CLIENT_DOMAIN_REGISTRY_JSON = "{}"


def _test_root_data_hash() -> str:
    """Mirrors verifier._live_integrity_root_hash() / each mesh file's own
    copy exactly — the SAME 5-field canonical string + SHA-256 algorithm."""
    canonical = "\n".join([
        f"MASTER_ANCHOR_SET_JSON={_TEST_ROOT_ANCHOR_SET_JSON}",
        f"CODE_LEAF_CERT_JSON={_TEST_ROOT_CODE_LEAF_CERT_JSON}",
        f"CODE_LEAF_CERT_SIG={_TEST_ROOT_CODE_LEAF_CERT_SIG}",
        f"KILL_LIST_JSON={_TEST_ROOT_KILL_LIST_JSON}",
        f"CLIENT_DOMAIN_REGISTRY_JSON={_TEST_ROOT_CLIENT_DOMAIN_REGISTRY_JSON}",
    ])
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@pytest.fixture()
def clean_root_pinned_build(monkeypatch, clean_signed_build):
    """Extends clean_signed_build: embeds a fixed set of root-of-trust field
    VALUES into _integrity.py and stamps the matching pin into all 7 mesh
    files' own `_EXPECTED_INTEGRITY_ROOT_HASH` — a genuinely clean state for
    the NEW LAURA-V2-005 check, layered on top of the already-clean 7-way
    peer-hash mesh state clean_signed_build provides."""
    monkeypatch.setattr(integrity_mod, "MASTER_ANCHOR_SET_JSON", _TEST_ROOT_ANCHOR_SET_JSON)
    monkeypatch.setattr(integrity_mod, "CODE_LEAF_CERT_JSON", _TEST_ROOT_CODE_LEAF_CERT_JSON)
    monkeypatch.setattr(integrity_mod, "CODE_LEAF_CERT_SIG", _TEST_ROOT_CODE_LEAF_CERT_SIG)
    monkeypatch.setattr(integrity_mod, "KILL_LIST_JSON", _TEST_ROOT_KILL_LIST_JSON)
    monkeypatch.setattr(integrity_mod, "CLIENT_DOMAIN_REGISTRY_JSON", _TEST_ROOT_CLIENT_DOMAIN_REGISTRY_JSON)

    expected = _test_root_data_hash()
    for mod in _ROOT_PIN_MODULE.values():
        monkeypatch.setattr(mod, "_EXPECTED_INTEGRITY_ROOT_HASH", expected)
    yield expected


def _run_all_root_pin_checks() -> None:
    for check in _ROOT_PIN_CHECK.values():
        check()


class TestLauraV2005RootOfTrustPinCleanBuild:
    def test_zero_violations_on_clean_root_pinned_build(self, clean_root_pinned_build):
        _run_all_root_pin_checks()
        violated = {role: getter() for role, getter in _ROOT_PIN_STATUS_GETTER.items()}
        assert not any(violated.values()), f"false positive on clean root-pinned build: {violated}"


class TestLauraV2005ExactPoCReproduced:
    """The exact Laura PoC shape: edit ONLY _integrity.py's root-of-trust
    fields (here, just MASTER_ANCHOR_SET_JSON — simulating a self-forged
    anchor set), leaving every one of the 7 mesh files' OWN
    `_EXPECTED_INTEGRITY_ROOT_HASH` pin untouched (still pointing at the
    REAL, pristine root data). Every one of the 7 files must independently
    detect the mismatch — none of them may depend on any OTHER file's
    check having already fired."""

    def test_anchor_set_tamper_alone_caught_by_every_one_of_seven(self, monkeypatch, clean_root_pinned_build):
        monkeypatch.setattr(integrity_mod, "MASTER_ANCHOR_SET_JSON", json.dumps([{
            "anchor_id": "attacker-forged-master-1",
            "pubkey_pem": "attacker-controlled-pubkey-pem",
            "alg": "ecdsa-p384-sha384", "status": "active", "added": "2026-07-17T00:00:00+00:00",
        }]))
        # Deliberately do NOT touch any of the 7 mesh files' pins or bytes.

        _run_all_root_pin_checks()
        violated = {role: getter() for role, getter in _ROOT_PIN_STATUS_GETTER.items()}
        assert all(violated.values()), (
            f"LAURA-V2-005 REGRESSION: a root-of-trust substitution confined to "
            f"_integrity.py alone (zero mesh files touched) was not caught by "
            f"every one of the 7 mesh files: {violated}"
        )

    def test_code_leaf_cert_tamper_alone_caught_by_every_one_of_seven(self, monkeypatch, clean_root_pinned_build):
        monkeypatch.setattr(
            integrity_mod, "CODE_LEAF_CERT_JSON",
            '{"role":"code","client_id":"*","serial":"attacker-forged-leaf"}',
        )
        _run_all_root_pin_checks()
        violated = {role: getter() for role, getter in _ROOT_PIN_STATUS_GETTER.items()}
        assert all(violated.values()), violated

    def test_bundle_and_leaf_sig_tamper_alone_caught_by_every_one_of_seven(self, monkeypatch, clean_root_pinned_build):
        monkeypatch.setattr(integrity_mod, "CODE_LEAF_CERT_SIG", "attacker-forged-sig-b64")
        _run_all_root_pin_checks()
        violated = {role: getter() for role, getter in _ROOT_PIN_STATUS_GETTER.items()}
        assert all(violated.values()), violated

    def test_kill_list_tamper_alone_caught_by_every_one_of_seven(self, monkeypatch, clean_root_pinned_build):
        """The narrower, pre-existing LAURA-V2-002 scenario (KILL_LIST_JSON
        edited alone) is ALSO now caught by this cheaper, non-cryptographic
        check — defense in depth alongside the existing INTEGRITY_HASH/
        BUNDLE_SIG mechanism."""
        monkeypatch.setattr(integrity_mod, "KILL_LIST_JSON", '[{"type":"leaf","id":"unrevoke-me"}]')
        _run_all_root_pin_checks()
        violated = {role: getter() for role, getter in _ROOT_PIN_STATUS_GETTER.items()}
        assert all(violated.values()), violated


class TestLauraV2005PlaceholderFailClosed:
    def test_placeholder_pin_fails_closed_in_prod(self, monkeypatch, clean_root_pinned_build):
        monkeypatch.delenv("YASHIGANI_ENV", raising=False)
        monkeypatch.setattr(verifier_mod, "_EXPECTED_INTEGRITY_ROOT_HASH", "PLACEHOLDER_YASHIGANI_INTEGRITY_ROOT_HASH")
        verifier_mod._check_integrity_root_pin()
        assert verifier_mod.get_mesh_integrity_status() is True

    def test_placeholder_pin_skipped_in_dev(self, monkeypatch, clean_root_pinned_build):
        monkeypatch.setenv("YASHIGANI_ENV", "dev")
        monkeypatch.setattr(verifier_mod, "_EXPECTED_INTEGRITY_ROOT_HASH", "PLACEHOLDER_YASHIGANI_INTEGRITY_ROOT_HASH")
        verifier_mod._check_integrity_root_pin()
        assert verifier_mod.get_mesh_integrity_status() is False
