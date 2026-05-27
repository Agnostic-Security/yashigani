"""
Contract test — B14 gateway automountServiceAccountToken conditionality.

TOM-K8S-002 / v2.25.0 P2.

Before this fix, `automountServiceAccountToken: false` was unconditional in
gateway.yaml.  When poolManager.k8sBackend.enabled=true the gateway pod's
service-account token was never mounted, so pool/backend.py could not call
load_incluster_config() and silently fell through to STUB mode.

After this fix, the value is conditional:
  - poolManager.k8sBackend.enabled=true  → automountServiceAccountToken: true
  - poolManager.k8sBackend.enabled=false → automountServiceAccountToken: false
  - default (enabled=false)              → automountServiceAccountToken: false

Test approach: helm template render (no cluster required).

Last updated: 2026-05-27T00:00:00+00:00
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent
HELM_CHART = REPO_ROOT / "helm" / "yashigani"

_INTERNAL_BEARER_SET = ["--set", "internalBearer.value=test-token-for-contracts"]


def _helm_template(extra_set: list[str] | None = None) -> str:
    """Run `helm template` and return stdout; raise on error."""
    cmd = [
        "helm",
        "template",
        "yashigani",
        str(HELM_CHART),
        *_INTERNAL_BEARER_SET,
    ]
    if extra_set:
        cmd.extend(extra_set)
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        pytest.fail(
            f"helm template failed:\n{result.stderr}\n{result.stdout}"
        )
    return result.stdout


def _extract_gateway_deployment(rendered: str) -> str:
    """
    Extract the gateway Deployment section from the rendered YAML.
    We identify it by the name: yashigani-gateway label.
    """
    # Split on yaml document separators.
    docs = re.split(r"^---$", rendered, flags=re.MULTILINE)
    for doc in docs:
        if "yashigani-gateway" in doc and "kind: Deployment" in doc:
            return doc
    return ""


class TestGatewaySATokenConditionality:
    """
    Contract assertions on gateway.yaml automountServiceAccountToken.
    TOM-K8S-002 — B14 fix.
    """

    def test_k8s_backend_enabled_sets_automount_true(self):
        """
        When poolManager.k8sBackend.enabled=true, gateway pod spec must have
        automountServiceAccountToken: true so load_incluster_config() can
        access the projected service-account token.
        """
        rendered = _helm_template(
            ["--set", "poolManager.k8sBackend.enabled=true"]
        )
        gw = _extract_gateway_deployment(rendered)
        assert gw, "Gateway Deployment not found in helm template output"

        # Find the automountServiceAccountToken line in the gateway spec.
        # We look for the exact pod spec pattern (not nested in other resources).
        match = re.search(
            r"automountServiceAccountToken:\s*(\S+)",
            gw,
        )
        assert match, (
            "B14 REGRESSION: automountServiceAccountToken not found in gateway Deployment"
        )
        value = match.group(1).strip()
        assert value == "true", (
            f"B14 REGRESSION: When poolManager.k8sBackend.enabled=true, "
            f"automountServiceAccountToken should be 'true', got '{value}'. "
            f"pool/backend.py cannot call load_incluster_config() without the SA token."
        )

    def test_k8s_backend_disabled_sets_automount_false(self):
        """
        When poolManager.k8sBackend.enabled=false (explicit), gateway pod spec
        must have automountServiceAccountToken: false — Checkov CKV_K8S_43 /
        ASVS V14.3.2.
        """
        rendered = _helm_template(
            ["--set", "poolManager.k8sBackend.enabled=false"]
        )
        gw = _extract_gateway_deployment(rendered)
        assert gw, "Gateway Deployment not found in helm template output"

        match = re.search(
            r"automountServiceAccountToken:\s*(\S+)",
            gw,
        )
        assert match, (
            "B14 REGRESSION: automountServiceAccountToken not found in gateway Deployment"
        )
        value = match.group(1).strip()
        assert value == "false", (
            f"B14 REGRESSION: When poolManager.k8sBackend.enabled=false, "
            f"automountServiceAccountToken should be 'false', got '{value}'."
        )

    def test_default_values_sets_automount_false(self):
        """
        Default render (poolManager.k8sBackend.enabled defaults to false) must
        have automountServiceAccountToken: false.  This is the safe default —
        most operators don't use the K8s pool backend.
        """
        rendered = _helm_template()
        gw = _extract_gateway_deployment(rendered)
        assert gw, "Gateway Deployment not found in helm template output"

        match = re.search(
            r"automountServiceAccountToken:\s*(\S+)",
            gw,
        )
        assert match, (
            "B14 REGRESSION: automountServiceAccountToken not found in gateway Deployment"
        )
        value = match.group(1).strip()
        assert value == "false", (
            f"B14 REGRESSION: Default render should have automountServiceAccountToken=false, "
            f"got '{value}'."
        )

    def test_gateway_deployment_only_is_affected(self):
        """
        Non-gateway Deployments (backoffice, caddy, etc.) must still have
        automountServiceAccountToken: false unconditionally — they don't talk
        to the K8s API.  Setting poolManager.k8sBackend.enabled=true should
        not flip other services' SA token config.
        """
        rendered = _helm_template(
            ["--set", "poolManager.k8sBackend.enabled=true"]
        )

        # Split into documents.
        docs = re.split(r"^---$", rendered, flags=re.MULTILINE)
        gateway_found = False
        violations = []

        for doc in docs:
            if "kind: Deployment" not in doc:
                continue
            # Extract deployment name for error messages.
            name_match = re.search(r"name:\s+(\S+)", doc)
            name = name_match.group(1) if name_match else "<unknown>"

            # Find all automountServiceAccountToken values in this doc.
            mounts = re.findall(r"automountServiceAccountToken:\s*(\S+)", doc)

            if "yashigani-gateway" in doc:
                gateway_found = True
                # Gateway should be true when k8sBackend is enabled.
                for v in mounts:
                    if v != "true":
                        violations.append(
                            f"gateway ({name}): expected 'true', got '{v}'"
                        )
            else:
                # All other Deployments must stay false.
                for v in mounts:
                    if v != "false":
                        violations.append(
                            f"non-gateway ({name}): expected 'false', got '{v}'"
                        )

        assert gateway_found, "Gateway Deployment not found in rendered output"
        assert not violations, (
            "B14 REGRESSION: automountServiceAccountToken contamination:\n"
            + "\n".join(violations)
        )
