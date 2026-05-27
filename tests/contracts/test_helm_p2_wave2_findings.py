# Last updated: 2026-05-27T00:00:00+00:00
"""
Contract tests for v2.25.0 P2 wave 2 findings:
  A6  — imagePolicy.requireImageDigests gate
  B10 — nginx-ingress namespaceSelector AND semantics (M-LIOR-001)
  B11 — wazuh.enabled=true blocked; wazuh.enabled=false default
  B12 — OWUI_SECRET_KEY injected into backoffice when openWebui.enabled
  B13 — PSA baseline labels on namespace; validate-security warn for production
  B14c— open-webui automountServiceAccountToken: false
  Iris coord #1 — backoffice.dbAesKey wired into secrets.yaml
  Iris coord #2 — gateway.env nil guard handles empty mapping
  Iris coord #3 — NOTES.txt auditLog default-off documentation present

All tests use subprocess helm template render (no cluster required).
YAML parsed with PyYAML for robust structural assertions.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml


REPO_ROOT = Path(__file__).parent.parent.parent
HELM_CHART = REPO_ROOT / "helm" / "yashigani"
TEMPLATES_DIR = HELM_CHART / "templates"

# ──────────────────────────────────────────────────────────────────────────────
# Shared helpers
# ──────────────────────────────────────────────────────────────────────────────

def _helm_template(extra_set: list[str] | None = None) -> str:
    """Run helm template with common flags; raise via pytest.fail on error."""
    cmd = [
        "helm", "template", "yashigani", str(HELM_CHART),
        "--set", "global.environment=ci",
        "--set", "mtls.enabled=true",
        "--set", "admissionPolicies.enabled=false",
        "--set", "agentBundles.langflow.enabled=true",
        "--set", "agentBundles.letta.enabled=true",
        "--set", "agentBundles.openclaw.enabled=true",
        "--set", "ollama.enabled=true",
        "--set", "openWebui.enabled=true",
        "--set", "otelCollector.enabled=true",
        "--set", "jaeger.enabled=true",
        "--set", "alertmanager.enabled=true",
        "--set", "loki.enabled=true",
        "--set", "grafana.enabled=true",
        "--set", "internalBearer.value=testtoken1234567890123456789012",
    ]
    if extra_set:
        for s in extra_set:
            cmd += ["--set", s]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        pytest.fail(
            f"helm template failed (rc={result.returncode}):\n"
            f"STDOUT: {result.stdout[:3000]}\n"
            f"STDERR: {result.stderr[:3000]}"
        )
    return result.stdout


def _helm_template_expect_fail(extra_set: list[str]) -> str:
    """Run helm template expecting failure; return stderr. Fail if it succeeds."""
    cmd = [
        "helm", "template", "yashigani", str(HELM_CHART),
        "--set", "global.environment=ci",
        "--set", "mtls.enabled=true",
        "--set", "internalBearer.value=testtoken1234567890123456789012",
    ]
    for s in extra_set:
        cmd += ["--set", s]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode == 0:
        pytest.fail("helm template unexpectedly succeeded — expected a validation error")
    return result.stderr


def _parse_docs(rendered: str) -> list[dict[str, Any]]:
    """Return all non-None YAML documents from a helm render."""
    return [d for d in yaml.safe_load_all(rendered) if d is not None]


def _by_kind_name(docs: list[dict[str, Any]], kind: str) -> dict[str, Any]:
    """Return a {name: doc} mapping for all docs matching the given kind."""
    return {
        d["metadata"]["name"]: d
        for d in docs
        if d.get("kind") == kind
    }


def _get_container_env(container: dict) -> dict[str, Any]:
    """Return {name: env_entry} for all env entries on a container."""
    return {e["name"]: e for e in container.get("env", [])}


def _get_ingress_sources(policy: dict) -> list[dict]:
    """Flatten all `from:` source entries across all ingress rules."""
    sources = []
    for rule in policy.get("spec", {}).get("ingress", []):
        sources.extend(rule.get("from", []))
    return sources


# Module-scoped fixtures
@pytest.fixture(scope="module")
def rendered_docs() -> list[dict[str, Any]]:
    return _parse_docs(_helm_template())


@pytest.fixture(scope="module")
def network_policies(rendered_docs: list[dict[str, Any]]) -> dict[str, Any]:
    return _by_kind_name(rendered_docs, "NetworkPolicy")


@pytest.fixture(scope="module")
def deployments(rendered_docs: list[dict[str, Any]]) -> dict[str, Any]:
    return _by_kind_name(rendered_docs, "Deployment")


@pytest.fixture(scope="module")
def secrets(rendered_docs: list[dict[str, Any]]) -> dict[str, Any]:
    return _by_kind_name(rendered_docs, "Secret")


@pytest.fixture(scope="module")
def namespaces(rendered_docs: list[dict[str, Any]]) -> dict[str, Any]:
    return _by_kind_name(rendered_docs, "Namespace")


# ──────────────────────────────────────────────────────────────────────────────
# A6 — imagePolicy.requireImageDigests gate
# ──────────────────────────────────────────────────────────────────────────────

class TestA6ImageDigestPolicy:
    """
    A6 (MEDIUM): imagePolicy.requireImageDigests=true must block gateway/backoffice/caddy
    tags without @sha256: digest. Default false must not block untagged images.
    Council finding: Captain MEDIUM + Nico N-003.
    """

    def test_default_false_passes_without_digest(self):
        """imagePolicy.requireImageDigests=false (default) must not fail without digest."""
        rendered = _helm_template()  # default render — no digest pins
        assert rendered, "helm template produced no output"

    def test_require_digests_blocks_gateway_without_sha(self):
        """requireImageDigests=true must fail when gateway tag has no @sha256:"""
        stderr = _helm_template_expect_fail([
            "imagePolicy.requireImageDigests=true",
        ])
        assert "A6 SECURITY VIOLATION" in stderr, f"Expected A6 error, got:\n{stderr}"
        assert "gateway" in stderr.lower(), f"Error should mention gateway:\n{stderr}"

    def test_require_digests_blocks_backoffice_without_sha(self):
        """requireImageDigests=true must fail when backoffice tag has no @sha256:"""
        stderr = _helm_template_expect_fail([
            "imagePolicy.requireImageDigests=true",
            "gateway.image.tag=2.25.0@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ])
        assert "A6 SECURITY VIOLATION" in stderr, f"Expected A6 error, got:\n{stderr}"
        assert "backoffice" in stderr.lower(), f"Error should mention backoffice:\n{stderr}"

    def test_require_digests_passes_with_all_digests(self):
        """requireImageDigests=true must pass when all owned images have @sha256:"""
        rendered = _helm_template(extra_set=[
            "imagePolicy.requireImageDigests=true",
            "gateway.image.tag=2.25.0@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "backoffice.image.tag=2.25.0@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ])
        assert rendered, "helm template produced no output"

    def test_imagePolicy_key_in_values_yaml(self):
        """values.yaml must declare imagePolicy.requireImageDigests."""
        values_yaml = HELM_CHART / "values.yaml"
        content = values_yaml.read_text()
        assert "imagePolicy:" in content, "imagePolicy section missing from values.yaml"
        assert "requireImageDigests:" in content, "requireImageDigests key missing from values.yaml"


# ──────────────────────────────────────────────────────────────────────────────
# B10 — nginx namespaceSelector AND semantics
# ──────────────────────────────────────────────────────────────────────────────

class TestB10NginxAndSemantics:
    """
    B10 (HIGH): NetworkPolicy entries for nginx-ingress must use AND semantics
    (namespaceSelector + podSelector combined) to prevent lateral movement from
    any pod in the ingress-nginx namespace.
    Source: Lior M-LIOR-001.
    """

    NGINX_NP_NAMES = [
        "allow-gateway-ingress",
        "allow-backoffice-ingress",
        "allow-open-webui-ingress",
        "allow-prometheus-ingress",
        "allow-grafana-ingress",
    ]

    def _sources_with_namespace_selector(self, policy: dict) -> list[dict]:
        """Return all ingress `from:` entries that contain a namespaceSelector."""
        return [
            src for src in _get_ingress_sources(policy)
            if "namespaceSelector" in src
        ]

    def _assert_and_semantics(self, policy: dict, policy_name: str) -> None:
        """Assert that every namespaceSelector entry also has a podSelector."""
        ns_sources = self._sources_with_namespace_selector(policy)
        assert ns_sources, (
            f"{policy_name}: no namespaceSelector entries found — check B10 fix was applied"
        )
        for src in ns_sources:
            ns_labels = src["namespaceSelector"].get("matchLabels", {})
            if ns_labels.get("kubernetes.io/metadata.name") == "ingress-nginx":
                assert "podSelector" in src, (
                    f"{policy_name}: namespaceSelector ingress-nginx entry lacks "
                    f"podSelector (AND semantics required — B10 M-LIOR-001)"
                )
                pod_labels = src["podSelector"].get("matchLabels", {})
                assert pod_labels.get("app.kubernetes.io/name") == "ingress-nginx", (
                    f"{policy_name}: podSelector does not restrict to "
                    f"app.kubernetes.io/name=ingress-nginx (got {pod_labels})"
                )

    def test_gateway_ingress_and_semantics(self, network_policies):
        np = network_policies.get("allow-gateway-ingress")
        assert np is not None, "allow-gateway-ingress NetworkPolicy not found"
        self._assert_and_semantics(np, "allow-gateway-ingress")

    def test_backoffice_ingress_and_semantics(self, network_policies):
        np = network_policies.get("allow-backoffice-ingress")
        assert np is not None, "allow-backoffice-ingress NetworkPolicy not found"
        self._assert_and_semantics(np, "allow-backoffice-ingress")

    def test_open_webui_ingress_and_semantics(self, network_policies):
        np = network_policies.get("allow-open-webui-ingress")
        assert np is not None, "allow-open-webui-ingress NetworkPolicy not found"
        self._assert_and_semantics(np, "allow-open-webui-ingress")

    def test_prometheus_ingress_and_semantics(self, network_policies):
        np = network_policies.get("allow-prometheus-ingress")
        assert np is not None, "allow-prometheus-ingress NetworkPolicy not found"
        self._assert_and_semantics(np, "allow-prometheus-ingress")

    def test_grafana_ingress_and_semantics(self, network_policies):
        np = network_policies.get("allow-grafana-ingress")
        assert np is not None, "allow-grafana-ingress NetworkPolicy not found"
        self._assert_and_semantics(np, "allow-grafana-ingress")

    def test_no_namespace_only_entries_in_any_policy(self, network_policies):
        """No NetworkPolicy may have a bare namespaceSelector matching ingress-nginx
        without a corresponding podSelector (i.e. no OR-mode ingress-nginx entries)."""
        for name, policy in network_policies.items():
            for src in _get_ingress_sources(policy):
                ns_labels = src.get("namespaceSelector", {}).get("matchLabels", {})
                if ns_labels.get("kubernetes.io/metadata.name") == "ingress-nginx":
                    assert "podSelector" in src, (
                        f"NetworkPolicy {name}: bare namespaceSelector ingress-nginx "
                        f"entry (no podSelector) — violates B10 AND-semantics fix"
                    )


# ──────────────────────────────────────────────────────────────────────────────
# B11 — Wazuh footprint declaration
# ──────────────────────────────────────────────────────────────────────────────

class TestB11WazuhFootprintDeclaration:
    """
    B11 (HIGH): Wazuh is not supported on K8s. wazuh.enabled=true must fail at
    helm install/upgrade time. wazuh.enabled=false (default) must pass.
    Source: Iris DRIFT-001 / Lu A.8.15/A.8.16.
    """

    def test_wazuh_enabled_true_fails(self):
        """wazuh.enabled=true must fail helm template with B11 error."""
        stderr = _helm_template_expect_fail(["wazuh.enabled=true"])
        assert "B11 CONFIGURATION ERROR" in stderr, (
            f"Expected B11 error when wazuh.enabled=true, got:\n{stderr}"
        )

    def test_wazuh_default_false_passes(self):
        """Default render (wazuh.enabled=false) must succeed."""
        rendered = _helm_template()
        assert rendered, "Default helm template render produced no output"

    def test_wazuh_section_in_values_yaml(self):
        """values.yaml must declare wazuh.enabled: false as explicit default."""
        values_yaml = HELM_CHART / "values.yaml"
        content = values_yaml.read_text()
        assert "wazuh:" in content, "wazuh section missing from values.yaml"
        assert "enabled: false" in content, (
            "wazuh.enabled: false default missing from values.yaml"
        )

    def test_helm_vs_compose_parity_doc_exists(self):
        """docs/helm-vs-compose-parity.md must exist and mention Wazuh."""
        parity_doc = REPO_ROOT / "docs" / "helm-vs-compose-parity.md"
        assert parity_doc.exists(), "docs/helm-vs-compose-parity.md missing"
        content = parity_doc.read_text()
        assert "Wazuh" in content, "Wazuh not mentioned in helm-vs-compose-parity.md"
        assert "A.8.15" in content or "A.8.16" in content, (
            "ISO 27001 A.8.15/A.8.16 reference missing from parity doc"
        )

    def test_no_wazuh_templates_rendered(self):
        """No rendered document should have Wazuh in its name or metadata."""
        docs = _parse_docs(_helm_template())
        for doc in docs:
            name = doc.get("metadata", {}).get("name", "")
            assert "wazuh" not in name.lower(), (
                f"Unexpected Wazuh resource rendered: {name}"
            )

    def test_notes_txt_contains_footprint_table(self):
        """NOTES.txt must contain the K8s vs Compose footprint differences table."""
        notes = TEMPLATES_DIR / "NOTES.txt"
        content = notes.read_text()
        assert "KUBERNETES vs DOCKER/PODMAN FOOTPRINT DIFFERENCES" in content, (
            "NOTES.txt missing K8s footprint differences section (B11)"
        )
        assert "Wazuh" in content, "Wazuh footprint entry missing from NOTES.txt"


# ──────────────────────────────────────────────────────────────────────────────
# B12 — OWUI_SECRET_KEY injection into backoffice
# ──────────────────────────────────────────────────────────────────────────────

class TestB12OwuiSecretKeyBackoffice:
    """
    B12 (HIGH): OWUI_SECRET_KEY must be injected into the backoffice container
    as a secretKeyRef from yashigani-open-webui-secrets when openWebui.enabled.
    Source: Tom TOM-K8S-001.
    """

    def _get_backoffice_container(self, deployments: dict) -> dict:
        bo = deployments.get("yashigani-backoffice")
        assert bo is not None, "yashigani-backoffice Deployment not found"
        containers = bo["spec"]["template"]["spec"]["containers"]
        assert containers, "No containers in backoffice pod spec"
        return containers[0]

    def test_owui_secret_key_present_when_owui_enabled(self, deployments):
        """OWUI_SECRET_KEY env var must be present in backoffice when openWebui.enabled=true."""
        container = self._get_backoffice_container(deployments)
        env = _get_container_env(container)
        assert "OWUI_SECRET_KEY" in env, (
            "OWUI_SECRET_KEY env var missing from backoffice container "
            "(openWebui.enabled=true in test render)"
        )
        owui_key = env["OWUI_SECRET_KEY"]
        assert "valueFrom" in owui_key, "OWUI_SECRET_KEY must use valueFrom (secretKeyRef)"
        assert "secretKeyRef" in owui_key["valueFrom"], (
            "OWUI_SECRET_KEY.valueFrom must use secretKeyRef"
        )
        secret_ref = owui_key["valueFrom"]["secretKeyRef"]
        assert secret_ref["name"] == "yashigani-open-webui-secrets", (
            f"OWUI_SECRET_KEY secretKeyRef.name must be 'yashigani-open-webui-secrets', "
            f"got: {secret_ref['name']}"
        )
        assert secret_ref["key"] == "secret_key", (
            f"OWUI_SECRET_KEY secretKeyRef.key must be 'secret_key', got: {secret_ref['key']}"
        )

    def test_owui_secret_key_absent_when_owui_disabled(self):
        """OWUI_SECRET_KEY must NOT be injected when openWebui.enabled=false."""
        rendered = _helm_template(extra_set=["openWebui.enabled=false"])
        docs = _parse_docs(rendered)
        deployments_by_name = _by_kind_name(docs, "Deployment")
        bo = deployments_by_name.get("yashigani-backoffice")
        assert bo is not None, "yashigani-backoffice Deployment not found"
        containers = bo["spec"]["template"]["spec"]["containers"]
        container = containers[0]
        env = _get_container_env(container)
        assert "OWUI_SECRET_KEY" not in env, (
            "OWUI_SECRET_KEY must NOT be present in backoffice when openWebui.enabled=false"
        )

    def test_open_webui_secrets_present_in_render(self, secrets):
        """yashigani-open-webui-secrets Secret must be rendered when openWebui enabled."""
        assert "yashigani-open-webui-secrets" in secrets, (
            "yashigani-open-webui-secrets Secret not rendered (openWebui.enabled=true)"
        )
        secret = secrets["yashigani-open-webui-secrets"]
        assert "secret_key" in secret.get("data", {}), (
            "yashigani-open-webui-secrets missing 'secret_key' data field"
        )


# ──────────────────────────────────────────────────────────────────────────────
# B13 — Kyverno default-off warn + PSA baseline labels
# ──────────────────────────────────────────────────────────────────────────────

class TestB13KyvernoPsaLabels:
    """
    B13 (HIGH): PSA baseline labels must be applied to the namespace.
    A validate-security.yaml warn-guard surfaces the Kyverno-off posture in production.
    Source: Laura F-002.
    """

    def test_psa_labels_on_namespace(self, namespaces):
        """Namespace must carry PSA enforce/warn/audit baseline labels."""
        # The namespace resource may have the release name or "default" depending
        # on how helm template is called without --namespace flag.
        assert namespaces, "No Namespace resource rendered — check namespace.yaml"
        # Take the first rendered namespace (should be the only one)
        ns = next(iter(namespaces.values()))
        labels = ns.get("metadata", {}).get("labels", {})
        assert labels.get("pod-security.kubernetes.io/enforce") == "baseline", (
            f"PSA enforce=baseline label missing from namespace (B13). Got: {labels}"
        )
        assert labels.get("pod-security.kubernetes.io/warn") == "baseline", (
            "PSA warn=baseline label missing from namespace"
        )
        assert labels.get("pod-security.kubernetes.io/audit") == "baseline", (
            "PSA audit=baseline label missing from namespace"
        )

    def test_psa_enforce_version_set(self, namespaces):
        """PSA enforce-version must be set (prevents drift on K8s upgrades)."""
        ns = next(iter(namespaces.values()))
        labels = ns.get("metadata", {}).get("labels", {})
        assert "pod-security.kubernetes.io/enforce-version" in labels, (
            "pod-security.kubernetes.io/enforce-version label missing"
        )

    def test_production_kyverno_off_warn_in_validate_security(self):
        """validate-security.yaml must contain the B13 Kyverno production warn."""
        vs = TEMPLATES_DIR / "validate-security.yaml"
        content = vs.read_text()
        assert "B13" in content, "B13 guard missing from validate-security.yaml"
        assert "admissionPolicies.enabled" in content, (
            "admissionPolicies reference missing from B13 guard"
        )

    def test_default_render_succeeds_with_admission_off(self):
        """admissionPolicies.enabled=false (default) must not block helm template."""
        rendered = _helm_template()
        assert rendered, "Default render failed with admissionPolicies.enabled=false"


# ──────────────────────────────────────────────────────────────────────────────
# B14-captain — open-webui automountServiceAccountToken: false
# ──────────────────────────────────────────────────────────────────────────────

class TestB14CaptainOpenWebUiSaToken:
    """
    B14-captain (HIGH): open-webui pod spec must set automountServiceAccountToken=false.
    Every other Deployment already disables this; open-webui was the missing one.
    Source: Laura F-003 / TOM-K8S-002 (Captain side).
    """

    def test_open_webui_automount_disabled(self, deployments):
        """open-webui Deployment must set automountServiceAccountToken: false."""
        ow = deployments.get("open-webui")
        assert ow is not None, "open-webui Deployment not found"
        pod_spec = ow["spec"]["template"]["spec"]
        assert pod_spec.get("automountServiceAccountToken") is False, (
            "open-webui pod spec missing automountServiceAccountToken: false (B14-captain)"
        )

    def test_all_deployments_disable_automount(self, deployments):
        """All Deployments must disable automountServiceAccountToken."""
        # Enumerate the Deployments present in a full render and assert all
        # have automountServiceAccountToken: false in the pod spec.
        # This is a regression guard — previous wave found open-webui was missing.
        for name, dep in deployments.items():
            pod_spec = dep["spec"]["template"]["spec"]
            assert pod_spec.get("automountServiceAccountToken") is False, (
                f"Deployment {name} does not set automountServiceAccountToken: false"
            )


# ──────────────────────────────────────────────────────────────────────────────
# Iris coord #1 — backoffice.dbAesKey wired into secrets.yaml
# ──────────────────────────────────────────────────────────────────────────────

class TestIrisCoord1DbAesKey:
    """
    Iris coord #1: backoffice.dbAesKey must be a first-class values.yaml key.
    When non-empty, secrets.yaml must use it in the yashigani-backoffice-secrets
    Secret instead of auto-generating via randAlphaNum.
    The install.sh kubectl pre-seeding workaround must be removed.
    """

    def test_dbAesKey_key_in_values_yaml(self):
        """values.yaml must declare backoffice.dbAesKey."""
        values_yaml = HELM_CHART / "values.yaml"
        content = values_yaml.read_text()
        assert "dbAesKey:" in content, (
            "backoffice.dbAesKey key missing from values.yaml (Iris coord #1)"
        )

    def test_operator_key_used_in_secret_when_set(self):
        """When backoffice.dbAesKey is set, secrets.yaml must use that value."""
        import base64
        test_key = "aabbccddeeff00112233445566778899"
        rendered = _helm_template(extra_set=[f"backoffice.dbAesKey={test_key}"])
        docs = _parse_docs(rendered)
        secrets = _by_kind_name(docs, "Secret")
        bo_secret = secrets.get("yashigani-backoffice-secrets")
        assert bo_secret is not None, "yashigani-backoffice-secrets Secret not rendered"
        db_aes_key_b64 = bo_secret.get("data", {}).get("db_aes_key", "")
        assert db_aes_key_b64, "db_aes_key missing from yashigani-backoffice-secrets"
        # Decode and verify the value matches
        decoded = base64.b64decode(db_aes_key_b64).decode()
        assert decoded == test_key, (
            f"backoffice.dbAesKey value not propagated correctly: "
            f"expected {test_key!r}, got {decoded!r}"
        )

    def test_install_sh_kubectl_workaround_removed(self):
        """install.sh must NOT contain the kubectl create secret --dry-run pre-seeding block."""
        install_sh = REPO_ROOT / "install.sh"
        content = install_sh.read_text()
        # The old workaround used kubectl create secret + --dry-run=client to pre-seed.
        # After Iris coord #1 fix, this should be replaced with dbAesKey in .env.helm.
        assert "Pre-seed backoffice Secret with operator-supplied AES key" not in content, (
            "install.sh still contains the old kubectl pre-seeding workaround "
            "(should be replaced by backoffice.dbAesKey in _write_helm_values)"
        )

    def test_install_sh_writes_dbAesKey_to_helm_values(self):
        """install.sh _write_helm_values must write backoffice.dbAesKey."""
        install_sh = REPO_ROOT / "install.sh"
        content = install_sh.read_text()
        assert "dbAesKey" in content, (
            "install.sh _write_helm_values does not write dbAesKey (Iris coord #1)"
        )


# ──────────────────────────────────────────────────────────────────────────────
# Iris coord #2 — gateway.env nil guard
# ──────────────────────────────────────────────────────────────────────────────

class TestIrisCoord2GatewayEnvNilGuard:
    """
    Iris coord #2: gateway.yaml must handle empty gateway.env mapping nodes without
    panicking. When _write_helm_values writes `gateway:\n  env:\n` (no sub-keys),
    direct .Values.gateway.env.field access panics — `default dict` guard required.
    """

    def test_empty_gateway_env_does_not_panic(self):
        """helm template must succeed when gateway.env is an empty mapping."""
        # Passing --set gateway.env= sets the env to an empty map (null in YAML).
        cmd = [
            "helm", "template", "yashigani", str(HELM_CHART),
            "--set", "global.environment=ci",
            "--set", "mtls.enabled=true",
            "--set", "internalBearer.value=testtoken1234567890123456789012",
            "--set", "gateway.env=",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        assert result.returncode == 0, (
            f"helm template panicked with empty gateway.env:\n{result.stderr[:2000]}"
        )

    def test_gateway_yaml_uses_gwenv_variable(self):
        """gateway.yaml must use $gwEnv variable for env field access."""
        gateway_yaml = TEMPLATES_DIR / "gateway.yaml"
        content = gateway_yaml.read_text()
        assert "$gwEnv" in content, (
            "gateway.yaml does not use $gwEnv nil-guard variable (Iris coord #2)"
        )
        assert "default dict" in content, (
            "gateway.yaml missing 'default dict' nil guard for gateway.env"
        )

    def test_backoffice_uses_nil_guard_for_deployment_stream(self):
        """backoffice.yaml must use nil guard for gateway.env.deploymentStream."""
        backoffice_yaml = TEMPLATES_DIR / "backoffice.yaml"
        content = backoffice_yaml.read_text()
        assert "default dict" in content, (
            "backoffice.yaml missing nil guard for gateway.env access (Iris coord #2)"
        )


# ──────────────────────────────────────────────────────────────────────────────
# Iris coord #3 — NOTES.txt auditLog default-off documentation
# ──────────────────────────────────────────────────────────────────────────────

class TestIrisCoord3AuditLogNotes:
    """
    Iris coord #3: NOTES.txt must document auditLog.enabled=false durability gap
    vs compose always-on audit logging. Must include rollback PVC warning.
    """

    def test_notes_txt_documents_audit_log_gap(self):
        """NOTES.txt must document the auditLog.enabled=false durability gap."""
        notes = TEMPLATES_DIR / "NOTES.txt"
        content = notes.read_text()
        assert "AUDIT LOG" in content, (
            "NOTES.txt missing AUDIT LOG section (Iris coord #3)"
        )
        assert "auditLog.enabled" in content, (
            "NOTES.txt missing auditLog.enabled reference"
        )
        assert "emptyDir" in content or "non-persistent" in content.lower() or "NOT persistent" in content, (
            "NOTES.txt must document that auditLog.enabled=false uses non-persistent storage"
        )

    def test_notes_txt_rollback_pvc_warning(self):
        """NOTES.txt must warn about orphaned PVC on auditLog rollback."""
        notes = TEMPLATES_DIR / "NOTES.txt"
        content = notes.read_text()
        assert "ROLLBACK" in content.upper(), (
            "NOTES.txt missing rollback warning for auditLog PVC (Iris coord #3)"
        )
        assert "PVC" in content or "PersistentVolumeClaim" in content, (
            "NOTES.txt must mention PVC orphan risk on auditLog rollback"
        )

    def test_notes_txt_compliance_references(self):
        """NOTES.txt must reference compliance frameworks for audit durability."""
        notes = TEMPLATES_DIR / "NOTES.txt"
        content = notes.read_text()
        assert "SOC 2" in content, "NOTES.txt missing SOC 2 compliance reference"
        assert "A.8.15" in content, "NOTES.txt missing ISO 27001 A.8.15 reference"
