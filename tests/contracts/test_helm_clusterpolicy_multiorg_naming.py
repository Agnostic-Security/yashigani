# Last updated: 2026-07-23T00:00:00+00:00
"""
Contract/regression test for fix/v412-k8s-clusterpolicy-multiorg-naming.

BUG (Captain, live on docker-desktop k8s): helm/yashigani/templates/
admission-policies.yaml named its 7 Kyverno ClusterPolicy resources keyed only
on `{{ .Release.Name }}`. install.sh's k8s convention pins the Helm RELEASE
NAME to the literal "yashigani" for every org — only `--namespace` varies
per org (confirmed install.sh:13672-13674:
`helm upgrade --install yashigani "$chart_dir" --namespace "$NAMESPACE"`).
Two orgs sharing a cluster (org-a ns=yashigani, org-b ns=yashigani-orgb) both
setting admissionPolicies.enabled=true therefore collided on identically
named cluster-scoped ClusterPolicy resources — the 2nd org's `helm install`
failed with "invalid ownership metadata".

FIX: every ClusterPolicy name now embeds `{{ .Release.Namespace }}` (the
per-org discriminator install.sh already varies), mirroring the per-tenant
naming PRINCIPLE cilium-clusterwide-networkpolicy.yaml already established
for the CCNP resource (different discriminator VALUE — tenantId there is an
opt-in value gated behind multiTenant.enabled; Release.Namespace here is
always present and is the actual per-org boundary for admissionPolicies,
which has no dependency on the multiTenant feature flag).

Test approach: `helm template` cannot render admission-policies.yaml at all
in this repo's Helm version (v3.14.0) — the Kyverno-CRD `lookup` pre-check
(line ~34) ALWAYS returns an empty dict under `helm template`/`helm lint`
(no live cluster connection is ever established for `lookup` in this Helm
version, contrary to that guard's own comment — a pre-existing, already-
accepted chart limitation; every other contract test in this repo works
around it by setting `admissionPolicies.enabled=false`, see
test_helm_p2_wave2_findings.py, test_helm_networkpolicy_ipv6.py). To assert
naming/scoping WITHOUT requiring a live cluster + Kyverno CRD, this test
copies the chart to a pytest tmp_path and strips ONLY that CRD-existence
guard (4 lines, the `lookup`/`fail` block) from the COPY before rendering —
the Go-template naming/scoping logic under test is otherwise byte-identical
to the shipped template. The guard itself is untouched in the real chart;
this is a test-harness workaround for a Helm-version rendering limitation,
not a functional change.

A companion LIVE proof (real `helm install --dry-run=server` against a
reachable cluster with the Kyverno ClusterPolicy CRD registered) was run
manually and is recorded in
testing_runs/yashigani/wt-fix-clusterpolicy-multiorg/evidence/
(before-org{a,b}.yaml showing the pre-fix collision, after-org{a,b}.yaml
showing the post-fix distinct + correctly-scoped names) — this pytest is
the durable, cluster-independent regression guard for CI.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent.parent
HELM_CHART = REPO_ROOT / "helm" / "yashigani"
ADMISSION_POLICIES_TEMPLATE = HELM_CHART / "templates" / "admission-policies.yaml"

# The 7 policy name suffixes admission-policies.yaml renders when
# admissionPolicies.enabled=true (helm/yashigani/templates/admission-policies.yaml).
POLICY_SUFFIXES = (
    "require-run-as-non-root",
    "require-no-privilege-escalation",
    "require-seccomp-profile",
    "require-drop-all-capabilities",
    "restrict-root-user",
    "restrict-pki-trust-plane",
    "deny-rogue-dns-bind",
)

# The exact CRD-lookup pre-install guard block this test strips from its
# COPY of the chart only (see module docstring). If admission-policies.yaml
# is edited such that this exact text no longer appears, this constant (and
# the strip below) must be updated in lockstep — a mismatch fails loudly via
# the assertion in `_stripped_chart_copy` rather than silently no-op-ing.
_CRD_GUARD_BLOCK = (
    '{{- $crd := lookup "apiextensions.k8s.io/v1" "CustomResourceDefinition" '
    '"" "clusterpolicies.kyverno.io" }}\n'
    "{{- if not $crd }}\n"
)


def _stripped_chart_copy(dest: Path) -> Path:
    """
    Copy helm/yashigani to `dest`, then remove the Kyverno-CRD-existence
    pre-install guard (lookup + fail) from the COPY's admission-policies.yaml
    only. Returns the path to the copied chart directory.
    """
    chart_copy = dest / "yashigani"
    # symlinks=False (default): dereference symlinks (e.g. files/service_identities.yaml
    # -> ../../docker/service_identities.yaml) into real files, since the copy does not
    # include the sibling docker/ directory the relative symlink target requires.
    shutil.copytree(HELM_CHART, chart_copy)
    target = chart_copy / "templates" / "admission-policies.yaml"
    content = target.read_text()
    assert _CRD_GUARD_BLOCK in content, (
        "CRD-lookup guard text not found verbatim in admission-policies.yaml — "
        "the guard was edited; update _CRD_GUARD_BLOCK in this test to match."
    )
    # Remove the two guard lines that reference `lookup`/`if not $crd`; leave
    # the matching `{{- end }}` — it now closes an empty (never-true) `if`,
    # which is harmless and keeps this a minimal, mechanical strip.
    stripped = content.replace(_CRD_GUARD_BLOCK, "{{- if false }}\n", 1)
    target.write_text(stripped)
    return chart_copy


def _helm_template(chart_dir: Path, namespace: str) -> str:
    """Run `helm template` with admissionPolicies.enabled=true; return stdout."""
    cmd = [
        "helm", "template", "yashigani", str(chart_dir),
        "--namespace", namespace,
        "--set", "global.environment=ci",
        "--set", "admissionPolicies.enabled=true",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        pytest.fail(
            f"helm template failed for namespace={namespace} (rc={result.returncode}):\n"
            f"STDOUT: {result.stdout[:2000]}\nSTDERR: {result.stderr[:2000]}"
        )
    return result.stdout


def _cluster_policies(rendered: str) -> dict[str, dict[str, Any]]:
    """Return {name: doc} for every ClusterPolicy doc in a helm render."""
    docs = [d for d in yaml.safe_load_all(rendered) if d is not None]
    return {
        d["metadata"]["name"]: d
        for d in docs
        if d.get("kind") == "ClusterPolicy"
    }


def _match_namespaces(policy: dict[str, Any]) -> set[str]:
    """All namespaces referenced across a ClusterPolicy's match.any[].resources.namespaces."""
    ns: set[str] = set()
    for rule in policy.get("spec", {}).get("rules", []):
        for entry in rule.get("match", {}).get("any", []):
            ns.update(entry.get("resources", {}).get("namespaces", []))
    return ns


@pytest.fixture(scope="module")
def two_org_render(tmp_path_factory: pytest.TempPathFactory) -> tuple[dict, dict]:
    """
    Render the (CRD-guard-stripped-copy) chart for two distinct orgs sharing
    a cluster — org-a (ns=yashigani) and org-b (ns=yashigani-orgb) — both with
    admissionPolicies.enabled=true, mirroring install.sh's fixed-release-name/
    varying-namespace multi-org convention.
    """
    dest = tmp_path_factory.mktemp("clusterpolicy-multiorg")
    chart_copy = _stripped_chart_copy(dest)
    org_a = _cluster_policies(_helm_template(chart_copy, "yashigani"))
    org_b = _cluster_policies(_helm_template(chart_copy, "yashigani-orgb"))
    return org_a, org_b


class TestClusterPolicyMultiOrgNaming:
    def test_seven_policies_render_per_org(self, two_org_render):
        org_a, org_b = two_org_render
        assert len(org_a) == 7, f"org-a: expected 7 ClusterPolicy docs, got {sorted(org_a)}"
        assert len(org_b) == 7, f"org-b: expected 7 ClusterPolicy docs, got {sorted(org_b)}"

    def test_names_distinct_across_orgs(self, two_org_render):
        """The core bug: org-a and org-b must not collide on any ClusterPolicy name."""
        org_a, org_b = two_org_render
        collisions = set(org_a) & set(org_b)
        assert not collisions, (
            f"ClusterPolicy name collision between org-a (ns=yashigani) and "
            f"org-b (ns=yashigani-orgb): {collisions}. The 2nd org's helm "
            f"install would fail with 'invalid ownership metadata' (the "
            f"original live bug)."
        )

    def test_each_org_name_embeds_its_own_namespace(self, two_org_render):
        org_a, org_b = two_org_render
        for suffix in POLICY_SUFFIXES:
            a_name = f"yashigani-yashigani-{suffix}"
            b_name = f"yashigani-yashigani-orgb-{suffix}"
            assert a_name in org_a, f"org-a missing expected name {a_name!r}. Got: {sorted(org_a)}"
            assert b_name in org_b, f"org-b missing expected name {b_name!r}. Got: {sorted(org_b)}"

    def test_each_org_policy_scopes_only_its_own_namespace(self, two_org_render):
        """
        Namespace-scoping regression guard: org-a's policies must match ONLY
        the yashigani namespace, org-b's ONLY yashigani-orgb — neither must
        govern the other org's pods (pre-existing correct behavior; this
        fix must not regress it).
        """
        org_a, org_b = two_org_render
        for name, policy in org_a.items():
            ns = _match_namespaces(policy)
            assert ns == {"yashigani"}, (
                f"org-a policy {name!r} match.namespaces={ns}, expected only "
                f"{{'yashigani'}} — must not govern org-b's namespace."
            )
        for name, policy in org_b.items():
            ns = _match_namespaces(policy)
            assert ns == {"yashigani-orgb"}, (
                f"org-b policy {name!r} match.namespaces={ns}, expected only "
                f"{{'yashigani-orgb'}} — must not govern org-a's namespace."
            )


class TestSingleOrgRenderUnchanged:
    """Default admissionPolicies.enabled=false single-org render must be untouched."""

    def test_default_disabled_render_has_no_clusterpolicy(self) -> None:
        cmd = [
            "helm", "template", "yashigani", str(HELM_CHART),
            "--namespace", "yashigani",
            "--set", "global.environment=ci",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        assert result.returncode == 0, (
            f"Default render (admissionPolicies disabled) failed:\n{result.stderr[:2000]}"
        )
        assert "kind: ClusterPolicy" not in result.stdout, (
            "ClusterPolicy rendered despite admissionPolicies.enabled defaulting to false"
        )

    def test_source_template_only_changes_name_field(self) -> None:
        """
        Sanity check on the shipped (unstripped) template source: every
        ClusterPolicy metadata.name line embeds both Release.Name and
        Release.Namespace; the match.namespaces scoping lines (unchanged by
        this fix) still reference only Release.Namespace.
        """
        content = ADMISSION_POLICIES_TEMPLATE.read_text()
        name_lines = re.findall(r"^\s*name:\s*\{\{.*\}\}.*$", content, re.MULTILINE)
        clusterpolicy_name_lines = [
            line for line in name_lines
            if any(s in line for s in POLICY_SUFFIXES)
        ]
        assert len(clusterpolicy_name_lines) == 7, (
            f"Expected 7 ClusterPolicy metadata.name lines, found "
            f"{len(clusterpolicy_name_lines)}: {clusterpolicy_name_lines}"
        )
        for line in clusterpolicy_name_lines:
            assert ".Release.Name" in line and ".Release.Namespace" in line, (
                f"ClusterPolicy name line missing per-org discriminator: {line!r}"
            )
