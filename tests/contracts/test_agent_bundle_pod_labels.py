# Last updated: 2026-05-27T00:00:00+00:00
"""
Regression-guard: yashigani.io/bundle label must be present in the pod template
spec.template.metadata.labels block of every agent-bundle Deployment.

Root cause of A4-D1 (Iris drift gate — v2.25.0 P2 wave 1):
  - Deployment.metadata.labels carried the label correctly.
  - Deployment.spec.template.metadata.labels (the pod template) did NOT.
  - K8s NetworkPolicy selectors match pod labels, not Deployment metadata labels.
  - Result: every NetworkPolicy rule selecting on yashigani.io/bundle matched
    ZERO pods at runtime (allow-gateway-ingress port 8081, allow-langflow-ingress,
    allow-letta-ingress, allow-openclaw-ingress/egress, allow-openclaw-external-egress).

Fix: yashigani.io/bundle: {{ $bundleID | quote }} added to spec.template.metadata.labels.

These tests verify the label is present at the pod-template level for all three
supported bundles (langflow, letta, openclaw) and that the label value matches
the bundle name exactly.

Test approach: subprocess helm template render — no cluster required.
YAML parsed with PyYAML to avoid brittle string matching.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent.parent
HELM_CHART = REPO_ROOT / "helm" / "yashigani"

BUNDLES = [
    ("langflow", "yashigani-langflow"),
    ("letta", "yashigani-letta"),
    ("openclaw", "yashigani-openclaw"),
]


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _helm_template_with_bundle(bundle_id: str) -> str:
    """Render helm template with one bundle enabled. Returns stdout."""
    cmd = [
        "helm",
        "template",
        "yashigani",
        str(HELM_CHART),
        "--set", "global.environment=ci",
        "--set", "mtls.enabled=true",
        "--set", "admissionPolicies.enabled=false",
        "--set", f"agentBundles.{bundle_id}.enabled=true",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        pytest.fail(
            f"helm template failed for bundle '{bundle_id}' (rc={result.returncode}):\n"
            f"STDOUT: {result.stdout[:2000]}\n"
            f"STDERR: {result.stderr[:2000]}"
        )
    return result.stdout


def _find_deployment(rendered: str, deploy_name: str) -> dict:
    """Return the first Deployment document whose metadata.name matches deploy_name."""
    for doc in yaml.safe_load_all(rendered):
        if doc is None:
            continue
        if (
            doc.get("kind") == "Deployment"
            and doc.get("metadata", {}).get("name") == deploy_name
        ):
            return doc
    return {}


def _pod_template_labels(deploy: dict) -> dict:
    """Extract spec.template.metadata.labels from a Deployment document."""
    return (
        deploy
        .get("spec", {})
        .get("template", {})
        .get("metadata", {})
        .get("labels", {})
    )


# ──────────────────────────────────────────────────────────────────────────────
# Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestAgentBundlePodTemplateLabels:
    """
    Regression guard for A4-D1: yashigani.io/bundle must be in pod template labels.

    NetworkPolicy selectors use pod labels (spec.template.metadata.labels).
    Deployment metadata labels are irrelevant to policy matching.
    """

    @pytest.mark.parametrize("bundle_id,deploy_name", BUNDLES)
    def test_yashigani_bundle_label_present_in_pod_template(
        self, bundle_id: str, deploy_name: str
    ):
        """
        Deployment.spec.template.metadata.labels must contain yashigani.io/bundle.

        Without this label the following NetworkPolicies match ZERO pods:
          allow-gateway-ingress (port 8081 ingress — A4 fix)
          allow-langflow-ingress / allow-letta-ingress / allow-openclaw-ingress
          allow-langflow-egress / allow-letta-egress / allow-openclaw-egress
          allow-openclaw-external-egress
        """
        rendered = _helm_template_with_bundle(bundle_id)
        deploy = _find_deployment(rendered, deploy_name)
        assert deploy, (
            f"Deployment '{deploy_name}' not found in rendered output. "
            f"Ensure agentBundles.{bundle_id}.enabled=true renders the Deployment."
        )

        pod_labels = _pod_template_labels(deploy)
        assert "yashigani.io/bundle" in pod_labels, (
            f"Deployment '{deploy_name}' spec.template.metadata.labels is missing "
            f"'yashigani.io/bundle'. "
            f"NetworkPolicy selectors on this label match ZERO pods at runtime. "
            f"Found pod template labels: {sorted(pod_labels.keys())}"
        )

    @pytest.mark.parametrize("bundle_id,deploy_name", BUNDLES)
    def test_yashigani_bundle_label_value_matches_bundle_name(
        self, bundle_id: str, deploy_name: str
    ):
        """
        The yashigani.io/bundle label value in pod template must equal the bundle ID.

        A mismatch (e.g. due to quoting or templating error) would cause
        NetworkPolicy selectors to match nothing despite the label being present.
        """
        rendered = _helm_template_with_bundle(bundle_id)
        deploy = _find_deployment(rendered, deploy_name)
        assert deploy, (
            f"Deployment '{deploy_name}' not found in rendered output."
        )

        pod_labels = _pod_template_labels(deploy)
        actual_value = pod_labels.get("yashigani.io/bundle")
        assert actual_value == bundle_id, (
            f"Deployment '{deploy_name}' pod template has yashigani.io/bundle={actual_value!r}, "
            f"expected {bundle_id!r}. "
            f"NetworkPolicy label selectors will not match pods with wrong label value."
        )

    @pytest.mark.parametrize("bundle_id,deploy_name", BUNDLES)
    def test_pod_template_retains_existing_standard_labels(
        self, bundle_id: str, deploy_name: str
    ):
        """
        Adding yashigani.io/bundle must not drop the three existing standard labels.

        Regression guard: ensure the fix did not accidentally remove any of the
        app.kubernetes.io/* labels that the Service selector depends on.
        """
        rendered = _helm_template_with_bundle(bundle_id)
        deploy = _find_deployment(rendered, deploy_name)
        assert deploy, (
            f"Deployment '{deploy_name}' not found in rendered output."
        )

        pod_labels = _pod_template_labels(deploy)
        for required_label in (
            "app.kubernetes.io/name",
            "app.kubernetes.io/instance",
            "app.kubernetes.io/component",
        ):
            assert required_label in pod_labels, (
                f"Deployment '{deploy_name}' pod template is missing '{required_label}' "
                f"after A4-D1 fix. Found: {sorted(pod_labels.keys())}"
            )

    @pytest.mark.parametrize("bundle_id,deploy_name", BUNDLES)
    def test_deployment_metadata_labels_also_carry_bundle_label(
        self, bundle_id: str, deploy_name: str
    ):
        """
        Deployment.metadata.labels must ALSO carry yashigani.io/bundle (pre-existing).

        This was already correct before A4-D1 — this test guards against any
        future refactor that mistakenly removes it from the Deployment metadata.
        """
        rendered = _helm_template_with_bundle(bundle_id)
        deploy = _find_deployment(rendered, deploy_name)
        assert deploy, (
            f"Deployment '{deploy_name}' not found in rendered output."
        )

        deploy_labels = deploy.get("metadata", {}).get("labels", {})
        assert "yashigani.io/bundle" in deploy_labels, (
            f"Deployment '{deploy_name}' metadata.labels is missing 'yashigani.io/bundle'. "
            f"This was correct before A4-D1 — regression introduced. "
            f"Found: {sorted(deploy_labels.keys())}"
        )
        assert deploy_labels["yashigani.io/bundle"] == bundle_id, (
            f"Deployment '{deploy_name}' metadata.labels has yashigani.io/bundle="
            f"{deploy_labels['yashigani.io/bundle']!r}, expected {bundle_id!r}."
        )
