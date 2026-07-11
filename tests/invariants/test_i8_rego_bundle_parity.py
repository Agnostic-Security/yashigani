"""
I8 — Rego bundle parity (compose ↔ helm policy files byte-identical).

INVARIANT (must ALWAYS hold): the canonical OPA policy bundle ``policy/*.rego``
loaded by docker-compose is BYTE-IDENTICAL to the helm/K8s bundle at
``helm/yashigani/files/policy/*.rego``. If a policy diverges across runtimes the
gateway enforces DIFFERENT rules on K8s than on compose — exactly the drift class
that bit us twice (LAURA-OPA-002: ``mcp.rego`` missing from the helm bundle →
``data.yashigani.mcp.*`` undefined → MCP fail-closed on K8s only).

This is the **invariant-level** guard (the canonical policy set is a single
source of truth, rendered once into both runtimes). ``tests/contracts/
test_helm_opa_bundle_parity.py`` additionally checks the configmap/policy.yaml
*wiring* — this file asserts the load-bearing property: same bytes, no missing
file, no extra file, no orphan.

Fully provable here (file/text only). No LIVE-PROOF (#44) gap — runtime drift is
a static property.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CANONICAL_DIR = REPO_ROOT / "policy"
HELM_BUNDLE_DIR = REPO_ROOT / "helm" / "yashigani" / "files" / "policy"


def _runtime_regos(d: Path) -> dict[str, Path]:
    """Enforcement policy regos — top-level AND enforcement subdirectories.

    Keys are relative paths (e.g. 'yashigani.rego', 'system/authz.rego') so
    the dict captures the directory structure. Compose mounts the whole policy/
    tree; Helm must mirror the same tree in files/policy/.

    Excluded: *_test.rego unit tests; policy/examples/ (user-facing sample
    policies loaded at runtime via Policy manager, intentionally absent from
    Helm — not startup-enforcement policies).
    """
    _excluded_subdirs = {"examples"}
    return {
        str(p.relative_to(d)): p
        for p in sorted(d.rglob("*.rego"))
        if not p.name.endswith("_test.rego")
        and p.relative_to(d).parts[0] not in _excluded_subdirs
    }


def _sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def test_canonical_and_helm_dirs_exist() -> None:
    assert CANONICAL_DIR.is_dir(), f"canonical policy dir missing: {CANONICAL_DIR}"
    assert HELM_BUNDLE_DIR.is_dir(), f"helm policy bundle missing: {HELM_BUNDLE_DIR}"


def test_same_set_of_runtime_policies() -> None:
    """No policy is present in one runtime and absent in the other."""
    canonical = set(_runtime_regos(CANONICAL_DIR))
    helm = set(_runtime_regos(HELM_BUNDLE_DIR))
    missing_in_helm = canonical - helm
    extra_in_helm = helm - canonical
    assert not missing_in_helm, (
        f"policies in compose bundle but MISSING from helm (K8s would not enforce "
        f"them — LAURA-OPA-002 class): {sorted(missing_in_helm)}"
    )
    assert not extra_in_helm, (
        f"policies in helm bundle with no canonical source (orphan/drift): "
        f"{sorted(extra_in_helm)}"
    )


@pytest.mark.parametrize("name", sorted(_runtime_regos(CANONICAL_DIR)))
def test_each_policy_byte_identical(name: str) -> None:
    """Every canonical rego is byte-identical in the helm bundle."""
    canonical = CANONICAL_DIR / name
    helm = HELM_BUNDLE_DIR / name
    assert helm.exists(), f"{name} present in compose bundle, absent in helm bundle"
    assert _sha256(canonical) == _sha256(helm), (
        f"{name} DIFFERS between compose (policy/) and helm "
        f"(helm/yashigani/files/policy/) — OPA enforces different rules per runtime. "
        f"Render both from the single canonical source."
    )


def test_load_bearing_3_0_policies_present_in_both() -> None:
    """The 3.0 policies whose drift would silently weaken K8s are in both bundles.

    document.rego (doc-OPA 4-action matrix) and mcp.rego (capability-envelope
    enforcement) are the two whose absence on K8s would silently fail-open the
    feature's enforcement plane on one runtime.
    """
    for required in ("document.rego", "mcp.rego", "v1_routing.rego", "agents.rego"):
        assert (CANONICAL_DIR / required).exists(), f"canonical {required} missing"
        assert (HELM_BUNDLE_DIR / required).exists(), f"helm {required} missing"


def test_system_authz_rego_present_in_both() -> None:
    """LAURA-30-001: system/authz.rego must be present in BOTH canonical and Helm
    bundles. Its absence from Helm would leave OPA on K8s with --authorization=basic
    but no system.authz policy — every management API call would 403 (fail closed),
    breaking backoffice policy push + gateway eval on K8s silently.
    """
    authz_canon = CANONICAL_DIR / "system" / "authz.rego"
    authz_helm = HELM_BUNDLE_DIR / "system" / "authz.rego"
    assert authz_canon.is_file(), (
        f"policy/system/authz.rego missing — LAURA-30-001 regression"
    )
    assert authz_helm.is_file(), (
        f"helm/yashigani/files/policy/system/authz.rego missing — "
        f"K8s OPA would not load system.authz → all management calls 403"
    )
    assert _sha256(authz_canon) == _sha256(authz_helm), (
        "system/authz.rego DRIFTED between canonical and Helm bundle — "
        "K8s OPA would enforce different authz rules than compose"
    )
