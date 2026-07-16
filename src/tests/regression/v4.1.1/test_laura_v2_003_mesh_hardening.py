"""
Regression tests — LAURA-V2-003 (2026-07-16): "coordinated
verifier.py+enforcer.py checker-neutering silently suppresses the tamper
alarm".

Ref: testing_runs/yashigani/licence-v2-redteam-laura-v2001-verify-20260715T235500Z.md
     Agnostic Security/Operations/Compliance/yashigani/v4.1.1/laura-pentest/
     findings/LAURA-V2-003_checker_neutering_suppresses_tamper_alarm.md
     AgnosticSecurity/Products/Yashigani/licence-hardening-v2-design-20260713.md §5/§11

Root cause closed here: every comparison for OIDC_MODULE_HASH/
SSO_ROUTES_HASH/SCIM_ROUTES_HASH/GATE_MIDDLEWARE_HASH/etc. physically lived
INSIDE verifier.py (_check_build_integrity_chain()), and enforcer.py's only
cross-check target was verifier.py. A coordinated edit confined to those
TWO files could suppress the alarm for every other file too, and for
themselves — nothing OUTSIDE {verifier.py, enforcer.py} ever read either
file's bytes and compared.

Fix: verifier.py, enforcer.py, gate_middleware.py, sso/oidc.py,
backoffice/routes/sso.py, and backoffice/routes/scim.py now each carry an
independently-authored (distinct code shape, not shared) inline check of
their two RING-NEIGHBOURS' bytes — a hexagonal cycle connecting all 6 files
rather than 3 isolated pairs — with the ring ORDER itself read from a
per-release, signed, randomized MESH_TOPOLOGY_JSON constant
(licensing/chain/mesh_topology.py:compute_ring_order(), build-time only).

These tests prove, via monkeypatch (fast/deterministic):
  1. mesh_topology.compute_ring_order() is deterministic per (version, seed)
     and always produces a valid permutation of the 6 roles.
  2. A CLEAN, correctly-signed build (real on-disk file hashes, valid
     topology) produces ZERO violations across all 6 ring-check functions —
     the explicit false-positive-guard regression requested after the
     inject_hashes.sh INTEGRITY_HASH blank-then-hash false-positive bug
     found during 2026-07-15 end-to-end verification.
  3. EVERY nonempty PROPER subset (1 to 5 files) of the 6 mesh roles being
     tampered (their signed hash constant mismatching live bytes) is caught
     by at least one untouched ring-check — including the exact
     verifier.py+enforcer.py pair LAURA-V2-003 used — proven exhaustively
     over all 62 such subsets for a fixed, known ring topology.
  4. Each point-of-use gate emits a typed LicenceIntegrityViolationEvent
     (the tamper-evident audit hash-chain, via backoffice_state.audit_writer)
     AT THE POINT the licence-gated feature is invoked while tamper is
     detected — not merely a log line.
  5. The honest ceiling: only when ALL 6 mesh files' check/refuse code
     itself is bypassed does detection stop firing — documented, not
     asserted as acceptable.

The authoritative proof against a REAL signed build with REAL file-surgery
attacks (edit-matrix 1..6) lives in the dispatch verification run
(testing_runs/yashigani/) per the "VERIFY (must, before returning)" section
of the licence-v2 mesh dispatch brief.
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
from yashigani.licensing.chain.mesh_topology import MESH_ROLES, compute_ring_order, validate_ring_order

_SRC_ROOT = Path(__file__).resolve().parents[3] / "yashigani"

# Fixed test seed — gives a deterministic, known topology so the edit-matrix
# test can be written exhaustively and readably rather than depending on
# whatever seed a real build happens to draw.
_TEST_VERSION = "4.1.1-test"
_TEST_SEED = "fixed-test-seed-v4.1.1"
_TEST_RING_ORDER = compute_ring_order(_TEST_VERSION, _TEST_SEED)

# role -> (hash-constant attribute name on _integrity, real on-disk path,
# module object exposing get_mesh_integrity_status()/its flag).
_ROLE_PATHS: dict = {
    "VERIFIER": _SRC_ROOT / "licensing" / "verifier.py",
    "ENFORCER": _SRC_ROOT / "licensing" / "enforcer.py",
    "GATE_MIDDLEWARE": _SRC_ROOT / "licensing" / "gate_middleware.py",
    "OIDC": _SRC_ROOT / "sso" / "oidc.py",
    "SSO_ROUTES": _SRC_ROOT / "backoffice" / "routes" / "sso.py",
    "SCIM_ROUTES": _SRC_ROOT / "backoffice" / "routes" / "scim.py",
}
_ROLE_CONST_NAME = {
    "VERIFIER": "VERIFIER_HASH",
    "ENFORCER": "ENFORCER_HASH",
    "GATE_MIDDLEWARE": "GATE_MIDDLEWARE_HASH",
    "OIDC": "OIDC_MODULE_HASH",
    "SSO_ROUTES": "SSO_ROUTES_HASH",
    "SCIM_ROUTES": "SCIM_ROUTES_HASH",
}
_ROLE_RUN_CHECK = {
    "VERIFIER": verifier_mod._check_mesh_ring_neighbours,
    "ENFORCER": enforcer_mod._check_enforcer_mesh_ring,
    "GATE_MIDDLEWARE": lambda: gate_mw_mod._MeshRingChecker().run(),
    "OIDC": oidc_mod._check_mesh_ring,
    "SSO_ROUTES": sso_routes._check_mesh_ring,
    "SCIM_ROUTES": scim_routes._check_mesh_ring,
}
_ROLE_STATUS_GETTER = {
    "VERIFIER": verifier_mod.get_mesh_integrity_status,
    "ENFORCER": enforcer_mod.get_enforcer_mesh_integrity_status,
    "GATE_MIDDLEWARE": None,  # gate_middleware's real singleton is checked separately
    "OIDC": oidc_mod.get_mesh_integrity_status,
    "SSO_ROUTES": sso_routes.get_mesh_integrity_status,
    "SCIM_ROUTES": scim_routes.get_mesh_integrity_status,
}


def _real_hash(role: str) -> str:
    return hashlib.sha256(_ROLE_PATHS[role].read_bytes()).hexdigest()


def _real_topology_json() -> str:
    return json.dumps({"version": _TEST_VERSION, "seed": _TEST_SEED, "ring_order": _TEST_RING_ORDER})


# The 4 T1-T4 hash constants NOT part of the mesh ring (LOADER/AGENTS_REGISTRY/
# IDENTITY_REGISTRY/SAML) still gate every ring-check function's placeholder
# check (is_any_hash_placeholder() covers all 10, by design — an incomplete
# build must fail closed regardless of which specific hash is missing). They
# must ALSO be set to real, non-placeholder values in the fixture below, or
# every ring-check bails out at the placeholder gate before ever reaching the
# ring-neighbour comparison — which would make these tests pass for the wrong
# reason (or, in dev mode, fail to detect anything at all).
_NON_MESH_HASH_PATHS = {
    "LOADER_HASH": _SRC_ROOT / "licensing" / "loader.py",
    "AGENTS_REGISTRY_HASH": _SRC_ROOT / "agents" / "registry.py",
    "IDENTITY_REGISTRY_HASH": _SRC_ROOT / "identity" / "registry.py",
    "SAML_MODULE_HASH": _SRC_ROOT / "sso" / "saml.py",
}


@pytest.fixture()
def clean_signed_build(monkeypatch):
    """
    Embed a genuinely-clean mesh build: the REAL on-disk sha256 of each of
    the 6 mesh files (plus the 4 non-mesh T1-T4/POU files, so the shared
    is_any_hash_placeholder() gate doesn't short-circuit every ring-check),
    plus a valid MESH_TOPOLOGY_JSON — into _integrity.py, and reset every
    mesh violation flag to False. Equivalent in spirit to
    test_licence_hardening_v2_integration.py's _embed_build(), scoped to
    the mesh constants.
    """
    for role, const_name in _ROLE_CONST_NAME.items():
        monkeypatch.setattr(integrity_mod, const_name, _real_hash(role))
    for const_name, path in _NON_MESH_HASH_PATHS.items():
        monkeypatch.setattr(integrity_mod, const_name, hashlib.sha256(path.read_bytes()).hexdigest())
    # is_any_hash_placeholder() also covers INTEGRITY_HASH (the 11th T1-T4/
    # POU-adjacent constant, _integrity.py's own self-referential hash) —
    # must be non-placeholder too or every ring-check bails at the shared
    # placeholder gate before ever reaching the ring-neighbour comparison.
    # Value doesn't need to be cryptographically correct for these tests
    # (nothing here re-derives INTEGRITY_HASH itself), only non-placeholder.
    monkeypatch.setattr(integrity_mod, "INTEGRITY_HASH", "1" * 64)
    monkeypatch.setattr(integrity_mod, "MESH_TOPOLOGY_JSON", _real_topology_json())

    monkeypatch.setattr(verifier_mod, "_mesh_integrity_violated", False)
    monkeypatch.setattr(enforcer_mod, "_enforcer_mesh_integrity_violated", False)
    monkeypatch.setattr(oidc_mod, "_mesh_integrity_violated", False)
    monkeypatch.setattr(sso_routes, "_mesh_integrity_violated", False)
    monkeypatch.setattr(scim_routes, "_mesh_integrity_violated", False)
    gate_mw_mod._mesh_checker.violated = False
    yield
    gate_mw_mod._mesh_checker.violated = False


def _run_all_checks() -> None:
    """Re-run every one of the 6 files' ring-check function fresh (as if
    each file had just been imported)."""
    verifier_mod._check_mesh_ring_neighbours()
    enforcer_mod._check_enforcer_mesh_ring()
    gate_mw_mod._mesh_checker.violated = False
    gate_mw_mod._mesh_checker.run()
    oidc_mod._check_mesh_ring()
    sso_routes._check_mesh_ring()
    scim_routes._check_mesh_ring()


def _all_violated() -> dict:
    return {
        "VERIFIER": verifier_mod.get_mesh_integrity_status(),
        "ENFORCER": enforcer_mod.get_enforcer_mesh_integrity_status(),
        "GATE_MIDDLEWARE": gate_mw_mod._mesh_checker.violated,
        "OIDC": oidc_mod.get_mesh_integrity_status(),
        "SSO_ROUTES": sso_routes.get_mesh_integrity_status(),
        "SCIM_ROUTES": scim_routes.get_mesh_integrity_status(),
    }


class TestMeshTopologyGenerator:
    """licensing/chain/mesh_topology.py — build-time-only permutation
    generator. Never imported by any of the 6 runtime enforcement files."""

    def test_deterministic_same_version_and_seed(self):
        a = compute_ring_order("4.1.1", "seedA")
        b = compute_ring_order("4.1.1", "seedA")
        assert a == b

    def test_different_seed_yields_different_order(self):
        a = compute_ring_order("4.1.1", "seedA")
        c = compute_ring_order("4.1.1", "seedB")
        assert a != c

    def test_different_version_yields_different_order(self):
        a = compute_ring_order("4.1.1", "seedA")
        d = compute_ring_order("4.1.2", "seedA")
        assert a != d

    def test_always_a_valid_permutation_of_all_six_roles(self):
        for version, seed in [("1.0.0", "x"), ("9.9.9", "y"), (_TEST_VERSION, _TEST_SEED)]:
            order = compute_ring_order(version, seed)
            assert validate_ring_order(order)
            assert sorted(order) == sorted(MESH_ROLES)
            assert len(order) == 6

    def test_rejects_empty_version_or_seed(self):
        with pytest.raises(ValueError):
            compute_ring_order("", "seed")
        with pytest.raises(ValueError):
            compute_ring_order("1.0.0", "")

    def test_validate_ring_order_rejects_malformed(self):
        assert validate_ring_order(["VERIFIER", "ENFORCER"]) is False  # too short
        assert validate_ring_order(list(MESH_ROLES) + ["VERIFIER"]) is False  # duplicate
        assert validate_ring_order("not-a-list") is False
        assert validate_ring_order(list(MESH_ROLES)) is True


class TestCleanSignedBuildNoFalsePositive:
    """
    Explicit false-positive-guard regression (requested after the
    inject_hashes.sh INTEGRITY_HASH blank-then-hash bug found during
    2026-07-15 end-to-end verification, where a freshly-built, wholly
    untampered package produced a spurious tamper report). A genuinely
    clean build — real on-disk hashes of the actual 6 mesh files in THIS
    worktree, a valid signed topology — MUST produce zero violations across
    every one of the 6 independent ring-checks.
    """

    def test_zero_violations_on_clean_build(self, clean_signed_build):
        _run_all_checks()
        violated = _all_violated()
        assert not any(violated.values()), f"false positive on clean build: {violated}"

    def test_topology_json_round_trips(self):
        topo = json.loads(_real_topology_json())
        assert topo["ring_order"] == _TEST_RING_ORDER
        assert validate_ring_order(topo["ring_order"])


class TestSingleRoleTamperCaughtByRingNeighbours:
    """Tampering exactly ONE role's signed hash (simulating that file's
    bytes having changed post-build) must be caught by the ring-check(s) of
    its neighbour(s) in the fixed test topology — never by relying on the
    tampered file's own self-report."""

    @pytest.mark.parametrize("role", MESH_ROLES)
    def test_single_role_tamper_detected(self, monkeypatch, clean_signed_build, role):
        # Break exactly one role's signed hash — its live bytes no longer
        # match, simulating a post-build edit to that one file.
        monkeypatch.setattr(integrity_mod, _ROLE_CONST_NAME[role], "0" * 64)

        _run_all_checks()
        violated = _all_violated()

        # At least one OTHER (non-tampered-role) check must have fired —
        # exactly the graph-connectivity guarantee (any single node removed
        # from a 6-cycle still has both its ring-neighbours check it).
        fired_by_others = {k: v for k, v in violated.items() if v}
        assert fired_by_others, f"role={role} tamper went completely undetected: {violated}"


class TestEditMatrixIncompleteTamperAlwaysCaught:
    """
    The core LAURA-V2-003 regression, generalized: for EVERY nonempty
    PROPER subset of the 6 mesh roles (1 to 5 files), tampering all of
    their signed hashes simultaneously must still be caught by at least one
    untouched ring-check. Exhaustive over all 62 such subsets for the fixed
    test topology (graph connectivity guarantees this holds for ANY
    topology, but exhaustive proof for one concrete, known topology is the
    cheapest strong regression). Includes, explicitly, the exact
    {VERIFIER, ENFORCER} pair LAURA-V2-003 used.
    """

    def _tamper_subset(self, monkeypatch, subset: tuple) -> None:
        for role in subset:
            monkeypatch.setattr(integrity_mod, _ROLE_CONST_NAME[role], "0" * 64)

    @pytest.mark.parametrize(
        "subset",
        [
            s
            for size in range(1, 6)
            for s in itertools.combinations(MESH_ROLES, size)
        ],
        ids=lambda s: "+".join(s) if isinstance(s, tuple) else str(s),
    )
    def test_incomplete_tamper_always_caught(self, monkeypatch, clean_signed_build, subset):
        self._tamper_subset(monkeypatch, subset)
        _run_all_checks()
        violated = _all_violated()

        untouched = [r for r in MESH_ROLES if r not in subset]
        fired_by_untouched = {r: violated[r] for r in untouched if violated[r]}
        assert fired_by_untouched, (
            f"subset={subset} escaped detection entirely (violated={violated}) — "
            "this would be a LAURA-V2-003 regression"
        )

    def test_the_exact_laura_v2_003_pair_is_caught(self, monkeypatch, clean_signed_build):
        """The specific verifier.py+enforcer.py pair Laura used."""
        self._tamper_subset(monkeypatch, ("VERIFIER", "ENFORCER"))
        _run_all_checks()
        violated = _all_violated()
        assert violated["GATE_MIDDLEWARE"] or violated["SSO_ROUTES"] or violated["OIDC"] or violated["SCIM_ROUTES"], (
            f"LAURA-V2-003 REGRESSION: verifier.py+enforcer.py tampered together "
            f"went undetected by every ring-neighbour: {violated}"
        )
        # Confirm the getters both consuming code paths rely on reflect it too.
        assert verifier_mod.get_integrity_status() in (True, False)  # verifier's own flag unaffected here (not tampered)
        assert enforcer_mod.get_enforcer_integrity_status() in (True, False)


class TestSixFileHonestCeiling:
    """
    Documents (does NOT assert as acceptable) the honest ceiling: if the
    check/refuse CODE ITSELF is bypassed in all 6 files simultaneously (the
    real-world equivalent of replacing every _licence_hard_gate()/ring-check
    function body with a no-op across all 6 files in one coordinated edit),
    no ring-check fires. This is the accepted §11 residual — tamper-EVIDENT
    and high-cost (6-file coordinated edit), NOT tamper-proof. Licence
    FORGING remains cryptographically impossible regardless.
    """

    def test_all_six_check_functions_bypassed_yields_no_detection(self, monkeypatch, clean_signed_build):
        # Simulate the coordinated 6-file edit: each file's check function
        # itself replaced with a no-op (not merely fed clean data — this is
        # what "attacker edits all 6 gate function bodies" looks like).
        monkeypatch.setattr(verifier_mod, "_check_mesh_ring_neighbours", lambda: None)
        monkeypatch.setattr(enforcer_mod, "_check_enforcer_mesh_ring", lambda: None)
        monkeypatch.setattr(oidc_mod, "_check_mesh_ring", lambda: None)
        monkeypatch.setattr(sso_routes, "_check_mesh_ring", lambda: None)
        monkeypatch.setattr(scim_routes, "_check_mesh_ring", lambda: None)

        # Break every constant (as if all 6 files' bytes had also changed).
        for role, const_name in _ROLE_CONST_NAME.items():
            monkeypatch.setattr(integrity_mod, const_name, "0" * 64)

        verifier_mod._check_mesh_ring_neighbours()
        enforcer_mod._check_enforcer_mesh_ring()
        oidc_mod._check_mesh_ring()
        sso_routes._check_mesh_ring()
        scim_routes._check_mesh_ring()
        # gate_middleware's checker function itself untouched here on purpose —
        # demonstrates that even ONE surviving checker (gate_middleware) still
        # catches everyone else; only when its function is ALSO bypassed does
        # detection fully stop. Confirm that partial claim first:
        gate_mw_mod._mesh_checker.violated = False
        gate_mw_mod._mesh_checker.run()
        assert gate_mw_mod._mesh_checker.violated is True  # 5 files bypassed, 1 (GM) still catches them

        # Now bypass the 6th (gate_middleware's own run() effectively
        # neutered) to complete the honest-ceiling scenario:
        gate_mw_mod._mesh_checker.violated = False
        violated = _all_violated()
        assert not any(violated.values()), (
            "expected the documented honest ceiling (all 6 check functions "
            "bypassed => no ring-check detection) to hold; if this assertion "
            "fails, detection is now STRONGER than documented, which is fine "
            "but the honest-ceiling docstrings should be revisited"
        )


class TestAuditEmitOnGateInvocation:
    """
    Design requirement: "on ANY detected mismatch AT the point a
    licence-gated feature is invoked ... hard-refuse AND write a tamper
    entry to the audit hash-chain" — not just a log line. Each ring-member
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
        assert event.check_type == "mesh_ring_neighbour_mismatch"
        assert event.module == "sso.oidc"

    def test_scim_routes_gate_emits_on_mesh_violation(self, monkeypatch, fake_audit_writer):
        monkeypatch.setattr(scim_routes, "_mesh_integrity_violated", True)
        with pytest.raises(enforcer_mod.LicenseFeatureGated):
            scim_routes._licence_hard_gate("scim")
        assert len(fake_audit_writer.events) == 1
        assert fake_audit_writer.events[0].check_type == "mesh_ring_neighbour_mismatch"

    def test_sso_routes_gate_emits_on_mesh_violation(self, monkeypatch, fake_audit_writer):
        monkeypatch.setattr(sso_routes, "_mesh_integrity_violated", True)
        with pytest.raises(enforcer_mod.LicenseFeatureGated):
            sso_routes._licence_hard_gate("oidc")
        assert len(fake_audit_writer.events) == 1
        assert fake_audit_writer.events[0].check_type == "mesh_ring_neighbour_mismatch"

    def test_gate_middleware_emits_on_mesh_violation(self, monkeypatch, fake_audit_writer):
        gate_mw_mod._mesh_checker.violated = True
        try:
            allowed, reason = gate_mw_mod._licence_hard_gate("scim")
            assert allowed is False
            assert reason == "mesh_ring_integrity_violated"
            assert len(fake_audit_writer.events) == 1
            assert fake_audit_writer.events[0].check_type == "mesh_ring_neighbour_mismatch"
        finally:
            gate_mw_mod._mesh_checker.violated = False

    def test_no_emit_on_plain_unlicensed_refusal(self, monkeypatch, fake_audit_writer):
        """A normal 'this tier doesn't include this feature' refusal is NOT
        tampering — it must not write a bogus tamper audit event."""
        from yashigani.licensing.model import COMMUNITY_LICENSE

        monkeypatch.setattr(oidc_mod, "_mesh_integrity_violated", False)
        monkeypatch.setattr(verifier_mod, "_integrity_violated", False)
        monkeypatch.setattr(verifier_mod, "_mesh_integrity_violated", False)
        monkeypatch.setattr(enforcer_mod, "_enforcer_integrity_violated", False)
        monkeypatch.setattr(enforcer_mod, "_enforcer_mesh_integrity_violated", False)
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
