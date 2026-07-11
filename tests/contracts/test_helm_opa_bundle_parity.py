# Last updated: 2026-06-14T00:00:00+01:00 — LAURA-30-001 (system/authz.rego subdir support)
"""
Helm OPA policy-bundle parity contract test.

Origin: LAURA-OPA-002 (combinatorial OPA bypass audit, 2026-06-04). The
canonical policy set is ``policy/*.rego`` (5 runtime files: yashigani,
v1_routing, rbac, agents, mcp). docker-compose mounts the whole ``../policy``
dir into OPA, so compose loads all 5. The Helm/K8s path is different: the
ConfigMap (``templates/configmaps.yaml``) materialises each rego via
``.Files.Get "files/policy/<name>.rego"`` and ``templates/policy.yaml``
``subPath``-mounts each one individually. Both lists were hand-maintained and
both were MISSING ``mcp.rego`` — so K8s OPA loaded only 4 of 5 packages, every
``data.yashigani.mcp.*`` query was undefined, and the MCP broker fail-closed →
MCP silently broken on K8s (a real compose-vs-K8s divergence).

Worse, the configmap comment CLAIMED this parity was "verified by sha256 in
tests/contracts/test_helm_opa_bundle_parity.py" — but that file did not exist.
This IS that file.

Contract (fails the build if violated):
  1. Every canonical ``policy/*.rego`` (excluding ``*_test.rego``) has a
     byte-identical copy at ``helm/yashigani/files/policy/<same-name>``.
  2. No EXTRA ``.rego`` exists in the Helm bundle that is not canonical.
  3. Every canonical rego is wired into ``configmaps.yaml`` via a matching
     ``.Files.Get "files/policy/<name>.rego"`` entry.
  4. Every canonical rego is subPath-mounted in ``policy.yaml``.
  5. (LAURA-30-001): Subdirectory regos (policy/system/*.rego) follow the same
     contract — canonical subdir mirrors in Helm, wired in ConfigMap + mounted.

This is the guard that should have caught LAURA-OPA-002 at the originating PR:
add a new policy file to ``policy/`` without mirroring + wiring it into Helm and
this test goes red.

No Helm binary required — pure file/text assertions (CI-portable, mirrors the
design of test_helm_env_parity.py).
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent
CANONICAL_DIR = REPO_ROOT / "policy"
HELM_BUNDLE_DIR = REPO_ROOT / "helm" / "yashigani" / "files" / "policy"
CONFIGMAPS_YAML = REPO_ROOT / "helm" / "yashigani" / "templates" / "configmaps.yaml"
POLICY_YAML = REPO_ROOT / "helm" / "yashigani" / "templates" / "policy.yaml"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_regos() -> list[Path]:
    """Top-level runtime policy rego files only — exclude *_test.rego unit tests."""
    return sorted(
        p
        for p in CANONICAL_DIR.glob("*.rego")
        if not p.name.endswith("_test.rego")
    )


def _canonical_names() -> list[str]:
    return [p.name for p in _canonical_regos()]


def _canonical_subdir_regos() -> list[Path]:
    """Enforcement rego files in policy subdirectories — exclude *_test.rego and examples/.

    Compose mounts ../policy:/policies:ro which recursively includes every
    subdirectory. Helm uses explicit subPath mounts so every enforcement subdir
    rego must be explicitly wired.

    EXCLUDED: policy/examples/ — these are user-facing sample policies loaded at
    runtime via the Policy manager (PUT /v1/policies/clients/*), NOT enforcement
    policies baked into OPA at startup. They are intentionally absent from the
    Helm bundle. Only enforcement subdirectories (e.g. system/) require Helm parity.
    """
    _excluded_subdirs = {"examples"}
    return sorted(
        p
        for p in CANONICAL_DIR.rglob("*.rego")
        if not p.name.endswith("_test.rego")
        and p.parent != CANONICAL_DIR  # exclude top-level (covered by _canonical_regos)
        and p.relative_to(CANONICAL_DIR).parts[0] not in _excluded_subdirs
    )


def _subdir_rego_relative(rego: Path) -> str:
    """Return the path relative to CANONICAL_DIR, e.g. 'system/authz.rego'."""
    return str(rego.relative_to(CANONICAL_DIR))


def test_canonical_set_is_nonempty_and_includes_mcp() -> None:
    """Guard against the discovery glob silently matching nothing, and pin the
    LAURA-OPA-002 file explicitly so a future rename can't quietly drop it."""
    names = _canonical_names()
    assert names, f"no canonical policy/*.rego found under {CANONICAL_DIR}"
    assert "mcp.rego" in names, (
        "mcp.rego missing from canonical policy/ — LAURA-OPA-002 regression"
    )


def test_canonical_set_includes_system_authz() -> None:
    """LAURA-30-001: system/authz.rego must be present in the canonical policy tree.

    This is the OPA management-API authorisation policy loaded by
    --authorization=basic. Its absence would leave OPA accepting any
    authenticated write — the same class as the original LAURA-30-001 finding.
    """
    authz = CANONICAL_DIR / "system" / "authz.rego"
    assert authz.is_file(), (
        "policy/system/authz.rego missing — LAURA-30-001 regression. "
        "OPA would have --authorization=basic but no system.authz policy, "
        "causing every management API request to fail closed (403 on all calls)."
    )


@pytest.mark.parametrize("rego", _canonical_regos(), ids=_canonical_names())
def test_helm_bundle_mirrors_canonical_byte_identical(rego: Path) -> None:
    """Every canonical policy/*.rego is present and byte-identical in the Helm
    bundle. FAILS if a policy file is added to policy/ but not mirrored, OR if
    the two copies drift (the v2.25.1 yashigani.rego comment-drift class)."""
    helm_copy = HELM_BUNDLE_DIR / rego.name
    assert helm_copy.is_file(), (
        f"{rego.name} present in policy/ but MISSING from Helm bundle "
        f"({helm_copy}). K8s OPA would not load it — compose↔K8s divergence."
    )
    canon_hash = _sha256(rego)
    helm_hash = _sha256(helm_copy)
    assert canon_hash == helm_hash, (
        f"{rego.name} DRIFTED between policy/ and Helm bundle.\n"
        f"  canonical sha256: {canon_hash}\n"
        f"  helm bundle sha256: {helm_hash}\n"
        f"Re-sync: cp policy/{rego.name} {helm_copy}"
    )


def test_helm_bundle_has_no_extra_rego() -> None:
    """No orphan .rego in the Helm bundle that isn't canonical (catches a
    deleted/renamed canonical file leaving a stale K8s copy behind).
    Top-level only; subdirs are checked by test_helm_subdir_bundle_mirrors_canonical."""
    canonical = set(_canonical_names())
    helm = {p.name for p in HELM_BUNDLE_DIR.glob("*.rego")}
    extra = helm - canonical
    assert not extra, (
        f"Helm bundle has rego files with no canonical source: {sorted(extra)}"
    )


@pytest.mark.parametrize("rego", _canonical_regos(), ids=_canonical_names())
def test_configmap_loads_every_canonical_rego(rego: Path) -> None:
    """Each canonical rego is wired into the policy-bundle ConfigMap via
    .Files.Get. A mirrored-but-unwired file would still not reach OPA."""
    content = CONFIGMAPS_YAML.read_text(encoding="utf-8")
    needle = f'.Files.Get "files/policy/{rego.name}"'
    assert needle in content, (
        f'{rego.name} not loaded by configmaps.yaml — expected `{needle}`. '
        f"This is the LAURA-OPA-002 gap (mcp.rego was absent)."
    )


@pytest.mark.parametrize("rego", _canonical_regos(), ids=_canonical_names())
def test_policy_deployment_mounts_every_canonical_rego(rego: Path) -> None:
    """Each canonical rego is subPath-mounted into the OPA container by
    policy.yaml. The ConfigMap can contain a key that is never mounted (the
    deployment uses per-file subPath mounts, not a whole-dir mount)."""
    content = POLICY_YAML.read_text(encoding="utf-8")
    needle = f"subPath: {rego.name}"
    assert needle in content, (
        f"{rego.name} not subPath-mounted in policy.yaml — expected "
        f"`{needle}`. OPA would load /policies/ without this package."
    )


# ── Subdirectory rego parity (LAURA-30-001 extension) ────────────────────────
# policy/system/authz.rego introduced the first subdirectory rego. Compose picks
# it up automatically (whole-dir mount). Helm needs explicit wiring. These tests
# catch any future subdir rego that misses the Helm bundle.

_subdir_regos = _canonical_subdir_regos()
_subdir_ids = [_subdir_rego_relative(r) for r in _subdir_regos]


@pytest.mark.parametrize("rego", _subdir_regos, ids=_subdir_ids)
def test_helm_subdir_bundle_mirrors_canonical(rego: Path) -> None:
    """Every canonical policy/<subdir>/*.rego has a byte-identical copy in the
    Helm bundle under the same relative path. Compose picks these up via the
    whole-dir mount; Helm requires an explicit copy."""
    rel = rego.relative_to(CANONICAL_DIR)
    helm_copy = HELM_BUNDLE_DIR / rel
    assert helm_copy.is_file(), (
        f"{rel} present in policy/ but MISSING from Helm bundle ({helm_copy}). "
        f"Compose loads it; K8s OPA would not — subdir drift class."
    )
    canon_hash = _sha256(rego)
    helm_hash = _sha256(helm_copy)
    assert canon_hash == helm_hash, (
        f"{rel} DRIFTED between policy/ and Helm bundle.\n"
        f"  canonical sha256: {canon_hash}\n"
        f"  helm bundle sha256: {helm_hash}\n"
        f"Re-sync: cp policy/{rel} {helm_copy}"
    )


@pytest.mark.parametrize("rego", _subdir_regos, ids=_subdir_ids)
def test_configmap_loads_every_subdir_rego(rego: Path) -> None:
    """Each subdirectory rego is referenced in configmaps.yaml via .Files.Get.

    The ConfigMap key for a subdir rego uses the relative path with '/' → '-'
    substitution (e.g. 'system/authz.rego' → key 'system-authz.rego',
    reference 'files/policy/system/authz.rego').
    """
    content = CONFIGMAPS_YAML.read_text(encoding="utf-8")
    rel = str(rego.relative_to(CANONICAL_DIR))
    needle = f'.Files.Get "files/policy/{rel}"'
    assert needle in content, (
        f'{rel} not loaded by configmaps.yaml — expected `{needle}`. '
        f"K8s OPA would not load this package."
    )


@pytest.mark.parametrize("rego", _subdir_regos, ids=_subdir_ids)
def test_policy_deployment_mounts_every_subdir_rego(rego: Path) -> None:
    """Each subdirectory rego is mounted into the OPA container at the correct
    path (preserving directory structure so OPA resolves the package name).

    The mountPath must be /policies/<subdir>/<name>.rego and the subPath must be
    the ConfigMap key (e.g. system-authz.rego for system/authz.rego).
    """
    content = POLICY_YAML.read_text(encoding="utf-8")
    rel = str(rego.relative_to(CANONICAL_DIR))
    # The mountPath in policy.yaml: /policies/<subdir>/<name>.rego
    mount_needle = f"mountPath: /policies/{rel}"
    assert mount_needle in content, (
        f"{rel} not subPath-mounted in policy.yaml (expected mountPath: /policies/{rel}). "
        f"OPA would not load this package on K8s."
    )
