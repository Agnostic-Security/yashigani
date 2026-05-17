"""
Captain Bucket-C — YASHIGANI_INTERNAL_BEARER Helm wiring contract tests (v2.23.4)

Asserts that the literal string "yashigani-internal" does NOT appear in
production-rendered Helm manifests, and that the internalBearer Secret and
secretKeyRef wiring are correct.

Tests:
  1. Production render contains ZERO occurrences of the literal "yashigani-internal".
  2. secrets.yaml renders a yashigani-agent-bearer Secret with the correct key.
  3. Gateway Deployment does NOT reference OPENAI_API_KEY (it's not a consumer).
  4. Open WebUI Deployment has OPENAI_API_KEY wired via secretKeyRef.
  5. Agent bundles (langflow/letta) have OPENAI_API_KEY wired via secretKeyRef.
  6. validate-security.yaml rejects a production install with empty internalBearer.value.

Last updated: 2026-05-17 (feat: Captain Bucket-C bearer-token wiring tests)
"""

import subprocess
import pathlib
import pytest
import yaml

HELM_CHART = pathlib.Path(__file__).parent.parent.parent / "helm" / "yashigani"

# A stable non-empty test value so tests 1–5 use a known token (not auto-random).
TEST_BEARER = "test-bearer-value-for-contract-validation"


def helm_template(extra_args: list[str]) -> str:
    """Run helm template and return the rendered YAML as a string."""
    cmd = [
        "helm", "template", "yashigani", str(HELM_CHART),
        *extra_args,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"helm template failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )
    return result.stdout


def helm_template_expect_fail(extra_args: list[str]) -> str:
    """Run helm template expecting failure; return stderr."""
    cmd = [
        "helm", "template", "yashigani", str(HELM_CHART),
        *extra_args,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        raise AssertionError(
            f"Expected helm template to fail but it succeeded.\nstdout: {result.stdout}"
        )
    return result.stderr


@pytest.fixture(scope="module")
def production_render():
    """Render the chart in production mode with a known bearer token value."""
    return helm_template([
        "--set", "global.environment=production",
        "--set", f"internalBearer.value={TEST_BEARER}",
        "--set", "mtls.enabled=true",
    ])


@pytest.fixture(scope="module")
def production_docs(production_render):
    """Parse the production render into individual YAML documents."""
    return list(yaml.safe_load_all(production_render))


# ─────────────────────────────────────────────────────────────────────────────
# Test 1: No literal "yashigani-internal" in production render
# ─────────────────────────────────────────────────────────────────────────────

class TestNoHardcodedBearerInProduction:
    def test_zero_occurrences_of_yashigani_internal(self, production_render):
        """
        helm template --set production=true renders ZERO occurrences of the
        literal string 'yashigani-internal' in production-rendered manifests.
        """
        count = production_render.count('"yashigani-internal"')
        # Also check unquoted form
        count += production_render.count("yashigani-internal")
        assert count == 0, (
            f"Found {count} occurrence(s) of 'yashigani-internal' in production render.\n"
            "Captain Bucket-C: all uses of the hardcoded bearer token must be replaced "
            "with secretKeyRef references. Grep the rendered output for 'yashigani-internal'."
        )


# ─────────────────────────────────────────────────────────────────────────────
# Test 2: yashigani-agent-bearer Secret is rendered with the correct key
# ─────────────────────────────────────────────────────────────────────────────

class TestInternalBearerSecretRendered:
    def test_secret_manifest_contains_bearer_key(self, production_docs):
        """
        The rendered chart contains a Secret named 'yashigani-agent-bearer'
        with the key 'yashigani_internal_bearer'.
        """
        bearer_secrets = [
            doc for doc in production_docs
            if doc is not None
            and doc.get("kind") == "Secret"
            and doc.get("metadata", {}).get("name") == "yashigani-agent-bearer"
        ]
        assert len(bearer_secrets) == 1, (
            f"Expected exactly 1 Secret named 'yashigani-agent-bearer', "
            f"found {len(bearer_secrets)}.\n"
            "Check helm/yashigani/templates/secrets.yaml for the internalBearer block."
        )
        secret = bearer_secrets[0]
        data = secret.get("data", {})
        assert "yashigani_internal_bearer" in data, (
            f"Secret 'yashigani-agent-bearer' is missing key 'yashigani_internal_bearer'.\n"
            f"Keys present: {list(data.keys())}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Test 3: Gateway Deployment does NOT have a plain OPENAI_API_KEY env entry
# ─────────────────────────────────────────────────────────────────────────────

class TestGatewayDoesNotHardcodeBearer:
    def test_gateway_deployment_no_openai_api_key_plain_value(self, production_docs):
        """
        The Gateway Deployment must NOT contain OPENAI_API_KEY as a plain env value.
        Gateway is a provider, not a consumer — it authenticates agents that present
        the bearer token; it does not forward it. This test guards against drift.
        """
        gateway_deploys = [
            doc for doc in production_docs
            if doc is not None
            and doc.get("kind") == "Deployment"
            and doc.get("metadata", {}).get("name") == "yashigani-gateway"
        ]
        assert len(gateway_deploys) == 1, (
            f"Expected 1 gateway Deployment, found {len(gateway_deploys)}"
        )
        gateway = gateway_deploys[0]
        containers = (
            gateway.get("spec", {})
            .get("template", {})
            .get("spec", {})
            .get("containers", [])
        )
        for container in containers:
            for env_entry in container.get("env", []):
                if env_entry.get("name") == "OPENAI_API_KEY":
                    value = env_entry.get("value", "")
                    assert value != "yashigani-internal", (
                        "Gateway Deployment has OPENAI_API_KEY set to the hardcoded "
                        "literal 'yashigani-internal'. Gateway is a provider, not a consumer."
                    )


# ─────────────────────────────────────────────────────────────────────────────
# Test 4: Open WebUI Deployment has OPENAI_API_KEY via secretKeyRef
# ─────────────────────────────────────────────────────────────────────────────

class TestOpenWebuiSecretKeyRef:
    def test_open_webui_openai_api_key_uses_secret_key_ref(self, production_docs):
        """
        The Open WebUI Deployment (enabled=true) has OPENAI_API_KEY wired via
        secretKeyRef pointing at 'yashigani-agent-bearer' / 'yashigani_internal_bearer'.
        """
        # Render with openWebui.enabled=true explicitly
        render = helm_template([
            "--set", "global.environment=production",
            "--set", f"internalBearer.value={TEST_BEARER}",
            "--set", "mtls.enabled=true",
            "--set", "openWebui.enabled=true",
        ])
        docs = list(yaml.safe_load_all(render))
        webui_deploys = [
            doc for doc in docs
            if doc is not None
            and doc.get("kind") == "Deployment"
            and doc.get("metadata", {}).get("name") == "open-webui"
        ]
        assert len(webui_deploys) == 1, (
            f"Expected 1 open-webui Deployment, found {len(webui_deploys)}.\n"
            "Set openWebui.enabled=true in the render."
        )
        webui = webui_deploys[0]
        containers = (
            webui.get("spec", {})
            .get("template", {})
            .get("spec", {})
            .get("containers", [])
        )
        found_secret_ref = False
        for container in containers:
            for env_entry in container.get("env", []):
                if env_entry.get("name") == "OPENAI_API_KEY":
                    # Must NOT be a plain value
                    assert "value" not in env_entry, (
                        "OPENAI_API_KEY in open-webui Deployment is a plain env value, "
                        "not a secretKeyRef. Captain Bucket-C fix not applied."
                    )
                    secret_ref = env_entry.get("valueFrom", {}).get("secretKeyRef", {})
                    assert secret_ref.get("key") == "yashigani_internal_bearer", (
                        f"OPENAI_API_KEY secretKeyRef has wrong key: {secret_ref.get('key')!r}. "
                        "Expected 'yashigani_internal_bearer'."
                    )
                    assert "yashigani-agent-bearer" in secret_ref.get("name", ""), (
                        f"OPENAI_API_KEY secretKeyRef points at wrong Secret: {secret_ref.get('name')!r}. "
                        "Expected 'yashigani-agent-bearer'."
                    )
                    found_secret_ref = True
        assert found_secret_ref, (
            "open-webui Deployment does not have an OPENAI_API_KEY env entry at all.\n"
            "Check helm/yashigani/templates/open-webui.yaml."
        )


# ─────────────────────────────────────────────────────────────────────────────
# Test 5: Agent bundles (langflow/letta) have OPENAI_API_KEY via secretKeyRef
# ─────────────────────────────────────────────────────────────────────────────

class TestAgentBundleSecretKeyRef:
    @pytest.mark.parametrize("bundle_id,deploy_name", [
        ("langflow", "yashigani-langflow"),
        ("letta", "yashigani-letta"),
    ])
    def test_agent_bundle_openai_api_key_uses_secret_key_ref(self, bundle_id, deploy_name):
        """
        Langflow and Letta Deployments have OPENAI_API_KEY wired via secretKeyRef
        pointing at 'yashigani-agent-bearer' / 'yashigani_internal_bearer'.
        """
        render = helm_template([
            "--set", "global.environment=production",
            "--set", f"internalBearer.value={TEST_BEARER}",
            "--set", "mtls.enabled=true",
            "--set", f"agentBundles.{bundle_id}.enabled=true",
        ])
        docs = list(yaml.safe_load_all(render))
        deploys = [
            doc for doc in docs
            if doc is not None
            and doc.get("kind") == "Deployment"
            and doc.get("metadata", {}).get("name") == deploy_name
        ]
        assert len(deploys) == 1, (
            f"Expected 1 Deployment named '{deploy_name}', found {len(deploys)}.\n"
            f"Set agentBundles.{bundle_id}.enabled=true in the render."
        )
        deploy = deploys[0]
        containers = (
            deploy.get("spec", {})
            .get("template", {})
            .get("spec", {})
            .get("containers", [])
        )
        found_secret_ref = False
        for container in containers:
            for env_entry in container.get("env", []):
                if env_entry.get("name") == "OPENAI_API_KEY":
                    assert "value" not in env_entry, (
                        f"OPENAI_API_KEY in {deploy_name} Deployment is a plain env value, "
                        "not a secretKeyRef. Captain Bucket-C fix not applied."
                    )
                    secret_ref = env_entry.get("valueFrom", {}).get("secretKeyRef", {})
                    assert secret_ref.get("key") == "yashigani_internal_bearer", (
                        f"OPENAI_API_KEY secretKeyRef in {deploy_name} has wrong key: "
                        f"{secret_ref.get('key')!r}. Expected 'yashigani_internal_bearer'."
                    )
                    assert "yashigani-agent-bearer" in secret_ref.get("name", ""), (
                        f"OPENAI_API_KEY secretKeyRef in {deploy_name} points at wrong Secret: "
                        f"{secret_ref.get('name')!r}. Expected 'yashigani-agent-bearer'."
                    )
                    found_secret_ref = True
        assert found_secret_ref, (
            f"{deploy_name} Deployment does not have an OPENAI_API_KEY env entry at all.\n"
            "Check helm/yashigani/templates/agent-bundles.yaml."
        )


# ─────────────────────────────────────────────────────────────────────────────
# Test 6: validate-security.yaml rejects production install with empty token
# ─────────────────────────────────────────────────────────────────────────────

class TestFailClosedOnEmptyBearer:
    def test_production_fails_with_empty_internal_bearer(self):
        """
        helm template with global.environment=production and internalBearer.value=""
        (no existingSecretName) must fail with the INTERNAL-BEARER-001 error.
        """
        stderr = helm_template_expect_fail([
            "--set", "global.environment=production",
            "--set", "internalBearer.value=",
            "--set", "mtls.enabled=true",
        ])
        assert "INTERNAL-BEARER-001" in stderr, (
            f"Expected INTERNAL-BEARER-001 error in helm stderr but not found.\n"
            f"stderr: {stderr}\n"
            "Check helm/yashigani/templates/validate-security.yaml for the "
            "INTERNAL-BEARER-001 guard."
        )
