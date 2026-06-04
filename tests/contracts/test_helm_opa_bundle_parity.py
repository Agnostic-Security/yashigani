# Last updated: 2026-06-04T00:00:00+01:00 — LAURA-OPA-002 (v2.25.2)
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
  4. Every canonical rego is wired into ``policy.yaml`` via a matching
     ``subPath: <name>.rego`` mount.

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
    """Runtime policy rego files only — exclude *_test.rego unit tests."""
    return sorted(
        p
        for p in CANONICAL_DIR.glob("*.rego")
        if not p.name.endswith("_test.rego")
    )


def _canonical_names() -> list[str]:
    return [p.name for p in _canonical_regos()]


def test_canonical_set_is_nonempty_and_includes_mcp() -> None:
    """Guard against the discovery glob silently matching nothing, and pin the
    LAURA-OPA-002 file explicitly so a future rename can't quietly drop it."""
    names = _canonical_names()
    assert names, f"no canonical policy/*.rego found under {CANONICAL_DIR}"
    assert "mcp.rego" in names, (
        "mcp.rego missing from canonical policy/ — LAURA-OPA-002 regression"
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
    deleted/renamed canonical file leaving a stale K8s copy behind)."""
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
