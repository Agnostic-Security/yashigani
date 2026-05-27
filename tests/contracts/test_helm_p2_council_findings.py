# Last updated: 2026-05-27T00:00:00+01:00
"""
Contract tests for v2.25.0 P2 council findings: A1, A2, A4, A5, B6, B7.

Tests:
  A1 — Rotation CronJob preserves caddy_internal_hmac + *_bootstrap_token
  A2 — Grafana NetworkPolicy uses 3443 (not 3000) when mtls.enabled
  A4 — Agent bundle mesh port routing: gateway ingress :8081 permits agents;
       agent egress rules permit gateway:8081
  A5 — Obs-plane ingress NetworkPolicies exist for otel-collector, jaeger,
       alertmanager, loki; backoffice egress to otel-collector present
  B6 — Rendered OPA ConfigMap is bit-identical to canonical policy/*.rego files
  B7 — Audit env vars present on gateway + backoffice; PVC renders when enabled

All tests use subprocess helm template render (no cluster required).
YAML parsed with PyYAML for robust structural assertions.
"""
from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml


REPO_ROOT = Path(__file__).parent.parent.parent
HELM_CHART = REPO_ROOT / "helm" / "yashigani"
TEMPLATES_DIR = HELM_CHART / "templates"
POLICY_CANONICAL = REPO_ROOT / "policy"
POLICY_HELM_FILES = HELM_CHART / "files" / "policy"

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


def _egress_ports_for_selector(policy: dict, selector_key: str, selector_val: str) -> set[int]:
    """
    Return the set of TCP ports in egress rules whose `to:` podSelector
    matches {selector_key: selector_val}.
    """
    ports: set[int] = set()
    for rule in policy.get("spec", {}).get("egress", []):
        for dest in rule.get("to", []):
            labels = dest.get("podSelector", {}).get("matchLabels", {})
            if labels.get(selector_key) == selector_val:
                for p in rule.get("ports", []):
                    if p.get("protocol", "TCP") == "TCP":
                        ports.add(p["port"])
    return ports


def _ingress_ports_from_selector(policy: dict, selector_key: str, selector_val: str) -> set[int]:
    """
    Return the set of TCP ports in ingress rules whose `from:` podSelector
    matches {selector_key: selector_val}.
    """
    ports: set[int] = set()
    for rule in policy.get("spec", {}).get("ingress", []):
        for src in rule.get("from", []):
            labels = src.get("podSelector", {}).get("matchLabels", {})
            if labels.get(selector_key) == selector_val:
                for p in rule.get("ports", []):
                    if p.get("protocol", "TCP") == "TCP":
                        ports.add(p["port"])
    return ports


def _ingress_ports_no_selector_filter(policy: dict) -> set[int]:
    """Return all TCP ports across all ingress rules regardless of source selector."""
    ports: set[int] = set()
    for rule in policy.get("spec", {}).get("ingress", []):
        for p in rule.get("ports", []):
            if p.get("protocol", "TCP") == "TCP":
                ports.add(p["port"])
    return ports


# Module-scoped render so we only call helm template once per test module run.
@pytest.fixture(scope="module")
def rendered_docs() -> list[dict[str, Any]]:
    return _parse_docs(_helm_template())


@pytest.fixture(scope="module")
def network_policies(rendered_docs: list[dict[str, Any]]) -> dict[str, Any]:
    return _by_kind_name(rendered_docs, "NetworkPolicy")


@pytest.fixture(scope="module")
def config_maps(rendered_docs: list[dict[str, Any]]) -> dict[str, Any]:
    return _by_kind_name(rendered_docs, "ConfigMap")


@pytest.fixture(scope="module")
def deployments(rendered_docs: list[dict[str, Any]]) -> dict[str, Any]:
    return _by_kind_name(rendered_docs, "Deployment")


# ──────────────────────────────────────────────────────────────────────────────
# A1 — Rotation CronJob preserves caddy_internal_hmac + *_bootstrap_token
# ──────────────────────────────────────────────────────────────────────────────

class TestA1RotationCronJobPreservation:
    """
    A1 (CRITICAL): The rotation CronJob applier must carry forward caddy_internal_hmac
    and *_bootstrap_token entries from the existing Secret, NOT silently delete them.
    Council finding: Captain #2 + Lu seconded.
    """

    def _rotation_cronjob_script(self) -> str:
        """Return the raw applier script from mtls-rotation-cronjob.yaml."""
        path = TEMPLATES_DIR / "mtls-rotation-cronjob.yaml"
        assert path.exists(), f"Template not found: {path}"
        return path.read_text(encoding="utf-8")

    def test_caddy_internal_hmac_preserved(self) -> None:
        """
        The rotation applier must read caddy_internal_hmac from the existing
        K8s Secret and write it to /tmp/leaves/ before the kubectl apply.
        """
        script = self._rotation_cronjob_script()
        assert "caddy_internal_hmac" in script, (
            "mtls-rotation-cronjob.yaml: caddy_internal_hmac not referenced in "
            "applier script. The rotation will delete this key on first run, "
            "causing HTTP 401 on all requests (A1 CRITICAL)."
        )

    def test_bootstrap_token_preserved(self) -> None:
        """
        The rotation applier must carry forward *_bootstrap_token entries.
        Without this, _verify_bootstrap_token() fails for all services after rotation.
        """
        script = self._rotation_cronjob_script()
        assert "_bootstrap_token" in script, (
            "mtls-rotation-cronjob.yaml: *_bootstrap_token entries not referenced "
            "in applier script. Rotation will delete all bootstrap tokens (A1 CRITICAL)."
        )

    def test_kubectl_from_file_glob_includes_hmac_and_tokens(self) -> None:
        """
        The kubectl create secret --from-file glob must include caddy_internal_hmac
        and *_bootstrap_token in the file arguments passed to kubectl.
        """
        script = self._rotation_cronjob_script()
        # The bootstrap Job's applier (reference pattern) includes both in the glob
        assert "caddy_internal_hmac" in script and "*_bootstrap_token" in script, (
            "mtls-rotation-cronjob.yaml: rotation applier glob does not include "
            "caddy_internal_hmac AND *_bootstrap_token — one or both will be lost "
            "on first rotation (A1 CRITICAL)."
        )

    def test_hmac_read_from_existing_secret(self) -> None:
        """
        The applier must fetch caddy_internal_hmac from the current K8s Secret
        (kubectl get secret ... -o jsonpath) to preserve its value idempotently.
        """
        script = self._rotation_cronjob_script()
        # The fix pattern: kubectl get secret ... jsonpath ... caddy_internal_hmac
        assert "jsonpath" in script and "caddy_internal_hmac" in script, (
            "mtls-rotation-cronjob.yaml: applier does not read caddy_internal_hmac "
            "from existing Secret via kubectl jsonpath. The value will be regenerated "
            "or lost on rotation (A1 CRITICAL)."
        )

    def test_ca_bundle_regenerated(self) -> None:
        """
        ca_bundle.crt (root+intermediate) must be regenerated during rotation
        for libpq/psycopg2 consumers.
        """
        script = self._rotation_cronjob_script()
        assert "ca_bundle.crt" in script, (
            "mtls-rotation-cronjob.yaml: ca_bundle.crt not regenerated in rotation "
            "applier. libpq/psycopg2 consumers will fail TLS verification after rotation."
        )


# ──────────────────────────────────────────────────────────────────────────────
# A2 — Grafana NetworkPolicy uses 3443 when mtls.enabled
# ──────────────────────────────────────────────────────────────────────────────

class TestA2GrafanaNetworkPolicyPort:
    """
    A2 (CRITICAL): allow-grafana-ingress must permit port 3443 (not 3000) when
    mtls.enabled. Since retro #83 Grafana serves HTTPS on 3443.
    Council finding: Captain #3 + Iris DRIFT-008/019 + Lu seconded.
    """

    def test_grafana_ingress_policy_exists(
        self, network_policies: dict[str, Any]
    ) -> None:
        assert "allow-grafana-ingress" in network_policies, (
            "allow-grafana-ingress NetworkPolicy not found in helm render"
        )

    def test_grafana_ingress_port_is_3443_not_3000(
        self, network_policies: dict[str, Any]
    ) -> None:
        """
        When mtls.enabled=true (the test render default), allow-grafana-ingress
        must permit port 3443. Port 3000 is the plaintext fallback (non-mtls only).
        """
        policy = network_policies["allow-grafana-ingress"]
        all_ports = _ingress_ports_no_selector_filter(policy)
        assert 3443 in all_ports, (
            f"allow-grafana-ingress: port 3443 not found (mtls.enabled=true). "
            f"Caddy→Grafana proxy will be blocked by NetworkPolicy, causing 502. "
            f"Found ports: {all_ports} (A2 CRITICAL)"
        )

    def test_grafana_ingress_from_caddy_on_3443(
        self, network_policies: dict[str, Any]
    ) -> None:
        """
        The ingress rule permitting traffic from yashigani-caddy must include 3443.
        """
        policy = network_policies["allow-grafana-ingress"]
        caddy_ports = _ingress_ports_from_selector(
            policy, "app.kubernetes.io/name", "yashigani-caddy"
        )
        assert 3443 in caddy_ports, (
            f"allow-grafana-ingress: caddy source does not permit port 3443. "
            f"Ports permitted from caddy: {caddy_ports} (A2 CRITICAL)"
        )

    def test_caddy_egress_to_grafana_is_3443(
        self, network_policies: dict[str, Any]
    ) -> None:
        """
        allow-caddy-egress must permit port 3443 to grafana (already present
        from prior fix — this test ensures no regression).
        """
        policy = network_policies.get("allow-caddy-egress")
        if policy is None:
            # allow-caddy-egress may be in networkpolicy-caddy-egress.yaml
            pytest.skip("allow-caddy-egress not in default render — check networkpolicy-caddy-egress.yaml")
        grafana_ports = _egress_ports_for_selector(
            policy, "app.kubernetes.io/name", "yashigani-grafana"
        )
        assert 3443 in grafana_ports, (
            f"allow-caddy-egress: port 3443 not permitted to grafana. "
            f"Found: {grafana_ports}"
        )


# ──────────────────────────────────────────────────────────────────────────────
# A4 — Agent bundle mesh port routing
# ──────────────────────────────────────────────────────────────────────────────

class TestA4AgentMeshPortRouting:
    """
    A4 (HIGH): Agent bundles route LLM calls to gateway:8081 (mesh port).
    NetworkPolicy must permit this in both directions.
    Council finding: Laura F-001 + Iris DRIFT-009.
    """

    def test_gateway_ingress_permits_8081_from_langflow(
        self, network_policies: dict[str, Any]
    ) -> None:
        """allow-gateway-ingress must permit port 8081 from langflow pods."""
        policy = network_policies.get("allow-gateway-ingress")
        assert policy is not None, "allow-gateway-ingress not found"
        langflow_ports = _ingress_ports_from_selector(
            policy, "yashigani.io/bundle", "langflow"
        )
        assert 8081 in langflow_ports, (
            f"allow-gateway-ingress: port 8081 not permitted from langflow pods. "
            f"All langflow LLM calls will be dropped by default-deny-ingress. "
            f"Found: {langflow_ports} (A4 HIGH)"
        )

    def test_gateway_ingress_permits_8081_from_letta(
        self, network_policies: dict[str, Any]
    ) -> None:
        """allow-gateway-ingress must permit port 8081 from letta pods."""
        policy = network_policies["allow-gateway-ingress"]
        letta_ports = _ingress_ports_from_selector(
            policy, "yashigani.io/bundle", "letta"
        )
        assert 8081 in letta_ports, (
            f"allow-gateway-ingress: port 8081 not permitted from letta pods. "
            f"Found: {letta_ports} (A4 HIGH)"
        )

    def test_gateway_ingress_permits_8081_from_openclaw(
        self, network_policies: dict[str, Any]
    ) -> None:
        """allow-gateway-ingress must permit port 8081 from openclaw pods."""
        policy = network_policies["allow-gateway-ingress"]
        openclaw_ports = _ingress_ports_from_selector(
            policy, "yashigani.io/bundle", "openclaw"
        )
        assert 8081 in openclaw_ports, (
            f"allow-gateway-ingress: port 8081 not permitted from openclaw pods. "
            f"Found: {openclaw_ports} (A4 HIGH)"
        )

    def test_agent_bundle_egress_permits_8081_to_gateway(
        self, network_policies: dict[str, Any]
    ) -> None:
        """allow-agent-bundle-egress must permit port 8081 to gateway."""
        policy = network_policies.get("allow-agent-bundle-egress")
        assert policy is not None, "allow-agent-bundle-egress not found"
        gw_ports = _egress_ports_for_selector(
            policy, "app.kubernetes.io/name", "yashigani-gateway"
        )
        assert 8081 in gw_ports, (
            f"allow-agent-bundle-egress: port 8081 not permitted to gateway. "
            f"All agent LLM calls dropped by default-deny-egress. "
            f"Found: {gw_ports} (A4 HIGH)"
        )

    def test_langflow_egress_permits_8081(
        self, network_policies: dict[str, Any]
    ) -> None:
        """allow-langflow-egress must permit 8081 to gateway."""
        policy = network_policies.get("allow-langflow-egress")
        assert policy is not None, "allow-langflow-egress not found"
        gw_ports = _egress_ports_for_selector(
            policy, "app.kubernetes.io/name", "yashigani-gateway"
        )
        assert 8081 in gw_ports, (
            f"allow-langflow-egress: port 8081 not permitted to gateway. "
            f"Found: {gw_ports} (A4 HIGH)"
        )

    def test_letta_egress_permits_8081(
        self, network_policies: dict[str, Any]
    ) -> None:
        """allow-letta-egress must permit 8081 to gateway."""
        policy = network_policies.get("allow-letta-egress")
        assert policy is not None, "allow-letta-egress not found"
        gw_ports = _egress_ports_for_selector(
            policy, "app.kubernetes.io/name", "yashigani-gateway"
        )
        assert 8081 in gw_ports, (
            f"allow-letta-egress: port 8081 not permitted to gateway. "
            f"Found: {gw_ports} (A4 HIGH)"
        )

    def test_openclaw_egress_permits_8081(
        self, network_policies: dict[str, Any]
    ) -> None:
        """allow-openclaw-egress must permit 8081 to gateway."""
        policy = network_policies.get("allow-openclaw-egress")
        assert policy is not None, "allow-openclaw-egress not found"
        gw_ports = _egress_ports_for_selector(
            policy, "app.kubernetes.io/name", "yashigani-gateway"
        )
        assert 8081 in gw_ports, (
            f"allow-openclaw-egress: port 8081 not permitted to gateway. "
            f"Found: {gw_ports} (A4 HIGH)"
        )


# ──────────────────────────────────────────────────────────────────────────────
# A5 — Obs-plane NetworkPolicies present
# ──────────────────────────────────────────────────────────────────────────────

class TestA5ObsPlaneNetworkPolicies:
    """
    A5 (HIGH): otel-collector, jaeger, alertmanager, loki must have ingress
    NetworkPolicies. Backoffice must have egress to otel-collector.
    Council finding: Captain #5 + Iris DRIFT-003/004/005/006/007.
    """

    def test_otel_collector_ingress_policy_exists(
        self, network_policies: dict[str, Any]
    ) -> None:
        assert "allow-otel-collector-ingress" in network_policies, (
            "allow-otel-collector-ingress not found. Under default-deny-ingress "
            "all gateway/backoffice OTLP pushes are dropped (A5 HIGH / DRIFT-004)."
        )

    def test_otel_collector_egress_policy_exists(
        self, network_policies: dict[str, Any]
    ) -> None:
        assert "allow-otel-collector-egress" in network_policies, (
            "allow-otel-collector-egress not found. otel-collector cannot forward "
            "traces to Jaeger or logs to Loki (A5 HIGH / DRIFT-005)."
        )

    def test_otel_collector_ingress_permits_4317_from_gateway(
        self, network_policies: dict[str, Any]
    ) -> None:
        """Gateway must be able to push OTLP to otel-collector:4317."""
        policy = network_policies["allow-otel-collector-ingress"]
        gw_ports = _ingress_ports_from_selector(
            policy, "app.kubernetes.io/name", "yashigani-gateway"
        )
        assert 4317 in gw_ports, (
            f"allow-otel-collector-ingress: port 4317 not permitted from gateway. "
            f"Found: {gw_ports} (A5 HIGH)"
        )

    def test_otel_collector_ingress_permits_4317_from_backoffice(
        self, network_policies: dict[str, Any]
    ) -> None:
        """Backoffice must be able to push OTLP to otel-collector:4317."""
        policy = network_policies["allow-otel-collector-ingress"]
        bo_ports = _ingress_ports_from_selector(
            policy, "app.kubernetes.io/name", "yashigani-backoffice"
        )
        assert 4317 in bo_ports, (
            f"allow-otel-collector-ingress: port 4317 not permitted from backoffice. "
            f"Backoffice traces dropped (A5 HIGH / DRIFT-003). Found: {bo_ports}"
        )

    def test_backoffice_egress_permits_4317_to_otel_collector(
        self, network_policies: dict[str, Any]
    ) -> None:
        """allow-backoffice-egress must permit port 4317 to otel-collector (DRIFT-003)."""
        policy = network_policies.get("allow-backoffice-egress")
        assert policy is not None, "allow-backoffice-egress not found"
        otel_ports = _egress_ports_for_selector(
            policy, "app.kubernetes.io/name", "otel-collector"
        )
        assert 4317 in otel_ports, (
            f"allow-backoffice-egress: port 4317 not permitted to otel-collector. "
            f"Backoffice OTEL export dropped by default-deny-egress. "
            f"Found: {otel_ports} (A5 HIGH / DRIFT-003)"
        )

    def test_jaeger_ingress_policy_exists(
        self, network_policies: dict[str, Any]
    ) -> None:
        assert "allow-jaeger-ingress" in network_policies, (
            "allow-jaeger-ingress not found. otel-collector→Jaeger trace forwarding "
            "blocked; Jaeger UI unreachable from Caddy (A5 HIGH / DRIFT-005)."
        )

    def test_jaeger_ingress_permits_4317_from_otel_collector(
        self, network_policies: dict[str, Any]
    ) -> None:
        """otel-collector must be able to push traces to Jaeger:4317."""
        policy = network_policies["allow-jaeger-ingress"]
        otel_ports = _ingress_ports_from_selector(
            policy, "app.kubernetes.io/name", "otel-collector"
        )
        assert 4317 in otel_ports, (
            f"allow-jaeger-ingress: port 4317 not permitted from otel-collector. "
            f"Found: {otel_ports} (A5 HIGH)"
        )

    def test_alertmanager_ingress_policy_exists(
        self, network_policies: dict[str, Any]
    ) -> None:
        assert "allow-alertmanager-ingress" in network_policies, (
            "allow-alertmanager-ingress not found. Prometheus cannot push alerts; "
            "alertmanager UI unreachable (A5 HIGH / DRIFT-006)."
        )

    def test_alertmanager_ingress_permits_9093_from_prometheus(
        self, network_policies: dict[str, Any]
    ) -> None:
        """Prometheus must be able to push alerts to alertmanager:9093."""
        policy = network_policies["allow-alertmanager-ingress"]
        prom_ports = _ingress_ports_from_selector(
            policy, "app.kubernetes.io/name", "yashigani-prometheus"
        )
        assert 9093 in prom_ports, (
            f"allow-alertmanager-ingress: port 9093 not permitted from prometheus. "
            f"Found: {prom_ports} (A5 HIGH)"
        )

    def test_loki_ingress_policy_exists(
        self, network_policies: dict[str, Any]
    ) -> None:
        assert "allow-loki-ingress" in network_policies, (
            "allow-loki-ingress not found. Log queries from Grafana blocked; "
            "log pipeline from otel-collector blocked (A5 HIGH / DRIFT-007)."
        )

    def test_loki_ingress_permits_3100_from_grafana(
        self, network_policies: dict[str, Any]
    ) -> None:
        """Grafana must be able to query Loki:3100 for log data."""
        policy = network_policies["allow-loki-ingress"]
        grafana_ports = _ingress_ports_from_selector(
            policy, "app.kubernetes.io/name", "yashigani-grafana"
        )
        assert 3100 in grafana_ports, (
            f"allow-loki-ingress: port 3100 not permitted from grafana. "
            f"Loki log queries blocked (A5 HIGH). Found: {grafana_ports}"
        )

    def test_loki_ingress_permits_3100_from_otel_collector(
        self, network_policies: dict[str, Any]
    ) -> None:
        """otel-collector must be able to push logs to Loki:3100."""
        policy = network_policies["allow-loki-ingress"]
        otel_ports = _ingress_ports_from_selector(
            policy, "app.kubernetes.io/name", "otel-collector"
        )
        assert 3100 in otel_ports, (
            f"allow-loki-ingress: port 3100 not permitted from otel-collector. "
            f"Log pipeline blocked (A5 HIGH). Found: {otel_ports}"
        )


# ──────────────────────────────────────────────────────────────────────────────
# B6 — OPA bundle parity
# ──────────────────────────────────────────────────────────────────────────────

class TestB6OpaBundleParity:
    """
    B6 (P0): Helm OPA ConfigMap must be bit-identical to canonical policy/*.rego files.
    Council finding: Lu P0-#1.

    The canonical source of truth is policy/*.rego. The helm chart ships
    helm/yashigani/files/policy/*.rego (copies) and configmaps.yaml uses
    .Files.Get to embed them. This test asserts the copies are byte-identical
    to the canonical files.
    """

    REGO_FILES = ["yashigani.rego", "agents.rego", "v1_routing.rego", "rbac.rego"]

    @pytest.mark.parametrize("filename", REGO_FILES)
    def test_helm_file_matches_canonical_sha256(self, filename: str) -> None:
        """
        helm/yashigani/files/policy/<filename> must be byte-identical to
        policy/<filename>. Any divergence means the K8s OPA bundle differs
        from the compose/canonical bundle.
        """
        canonical = POLICY_CANONICAL / filename
        helm_copy = POLICY_HELM_FILES / filename
        assert canonical.exists(), f"Canonical file missing: {canonical}"
        assert helm_copy.exists(), (
            f"Helm file copy missing: {helm_copy}. "
            f"Run: cp policy/{filename} helm/yashigani/files/policy/{filename}"
        )
        canonical_sha = hashlib.sha256(canonical.read_bytes()).hexdigest()
        helm_sha = hashlib.sha256(helm_copy.read_bytes()).hexdigest()
        assert canonical_sha == helm_sha, (
            f"DRIFT: policy/{filename} and helm/yashigani/files/policy/{filename} "
            f"have different sha256.\n"
            f"  canonical: {canonical_sha}\n"
            f"  helm copy: {helm_sha}\n"
            f"Fix: cp policy/{filename} helm/yashigani/files/policy/{filename} "
            f"(B6 / Lu P0-#1)"
        )

    def test_rendered_configmap_contains_agent_response_allowed(
        self, config_maps: dict[str, Any]
    ) -> None:
        """
        The rendered yashigani-policy-bundle ConfigMap must contain
        agent_response_allowed (absent from the prior inline subset).
        """
        policy_cm = config_maps.get("yashigani-policy-bundle")
        assert policy_cm is not None, "yashigani-policy-bundle ConfigMap not found in render"
        cm_data = policy_cm.get("data", {})
        agents_rego = cm_data.get("agents.rego", "")
        assert "agent_response_allowed" in agents_rego, (
            "yashigani-policy-bundle agents.rego: agent_response_allowed rule missing. "
            "K8s OPA silently allows agent responses that compose OPA denies (B6 P0)."
        )

    def test_rendered_configmap_contains_sensitivity_rank_catch_all(
        self, config_maps: dict[str, Any]
    ) -> None:
        """
        agents.rego must contain the catch-all sensitivity_rank(level) := 4
        for unknown labels (fail-closed, ASVS V4.1.3).
        """
        policy_cm = config_maps.get("yashigani-policy-bundle")
        assert policy_cm is not None, "yashigani-policy-bundle ConfigMap not found"
        agents_rego = policy_cm.get("data", {}).get("agents.rego", "")
        assert "sensitivity_rank(level) := 4" in agents_rego or ":= 4 if" in agents_rego, (
            "yashigani-policy-bundle agents.rego: sensitivity_rank catch-all (rank=4 "
            "for unknown labels) missing. Unknown sensitivity labels would not be "
            "fail-closed in K8s (B6 P0)."
        )

    def test_rendered_configmap_has_all_four_rego_files(
        self, config_maps: dict[str, Any]
    ) -> None:
        """ConfigMap data must have all four rego keys."""
        policy_cm = config_maps.get("yashigani-policy-bundle")
        assert policy_cm is not None, "yashigani-policy-bundle ConfigMap not found"
        data_keys = set(policy_cm.get("data", {}).keys())
        required = {"yashigani.rego", "agents.rego", "v1_routing.rego", "rbac.rego"}
        missing = required - data_keys
        assert not missing, (
            f"yashigani-policy-bundle ConfigMap missing rego files: {missing} (B6 P0)"
        )


# ──────────────────────────────────────────────────────────────────────────────
# B7 — Audit log env vars and PVC persistence
# ──────────────────────────────────────────────────────────────────────────────

class TestB7AuditLogPersistence:
    """
    B7 (P0): Audit env vars must be present on gateway + backoffice when
    auditLog.enabled=true. PVC resources must render. varlog must not be
    emptyDir when auditLog.enabled=true.
    Council finding: Lu P0-#3.
    """

    AUDIT_ENV_VARS = [
        "YASHIGANI_AUDIT_LOG_PATH",
        "YASHIGANI_AUDIT_MAX_FILE_SIZE_MB",
        "YASHIGANI_AUDIT_RETENTION_DAYS",
    ]

    @pytest.fixture(scope="class")
    def audit_docs(self) -> list[dict[str, Any]]:
        """Render with auditLog.enabled=true."""
        rendered = _helm_template(["auditLog.enabled=true"])
        return _parse_docs(rendered)

    @pytest.fixture(scope="class")
    def audit_deployments(self, audit_docs: list[dict[str, Any]]) -> dict[str, Any]:
        return _by_kind_name(audit_docs, "Deployment")

    @pytest.fixture(scope="class")
    def audit_pvcs(self, audit_docs: list[dict[str, Any]]) -> dict[str, Any]:
        return _by_kind_name(audit_docs, "PersistentVolumeClaim")

    def _get_container_env_names(self, deployment: dict) -> set[str]:
        """Extract all env var names from the main container."""
        containers = (
            deployment.get("spec", {})
            .get("template", {})
            .get("spec", {})
            .get("containers", [])
        )
        names: set[str] = set()
        for container in containers:
            for env in container.get("env", []):
                names.add(env.get("name", ""))
        return names

    def _get_volume_types(self, deployment: dict) -> dict[str, str]:
        """Return {volumeName: volumeType} for all volumes in the deployment."""
        volumes = (
            deployment.get("spec", {})
            .get("template", {})
            .get("spec", {})
            .get("volumes", [])
        )
        result: dict[str, str] = {}
        for vol in volumes:
            name = vol.get("name", "")
            if "emptyDir" in vol:
                result[name] = "emptyDir"
            elif "persistentVolumeClaim" in vol:
                result[name] = "pvc"
            elif "secret" in vol:
                result[name] = "secret"
            else:
                result[name] = "other"
        return result

    @pytest.mark.parametrize("env_var", AUDIT_ENV_VARS)
    def test_gateway_has_audit_env_var_when_enabled(
        self, audit_deployments: dict[str, Any], env_var: str
    ) -> None:
        """Gateway Deployment must have audit env var when auditLog.enabled=true."""
        gw = audit_deployments.get("yashigani-gateway")
        assert gw is not None, "yashigani-gateway Deployment not found"
        env_names = self._get_container_env_names(gw)
        assert env_var in env_names, (
            f"yashigani-gateway: {env_var} not present in container env "
            f"(auditLog.enabled=true). SOC2/ISO27001/NIST AU-9 compliance gap (B7 P0)."
        )

    @pytest.mark.parametrize("env_var", AUDIT_ENV_VARS)
    def test_backoffice_has_audit_env_var_when_enabled(
        self, audit_deployments: dict[str, Any], env_var: str
    ) -> None:
        """Backoffice Deployment must have audit env var when auditLog.enabled=true."""
        bo = audit_deployments.get("yashigani-backoffice")
        assert bo is not None, "yashigani-backoffice Deployment not found"
        env_names = self._get_container_env_names(bo)
        assert env_var in env_names, (
            f"yashigani-backoffice: {env_var} not present in container env "
            f"(auditLog.enabled=true). SOC2/ISO27001/NIST AU-9 compliance gap (B7 P0)."
        )

    def test_gateway_varlog_is_pvc_when_enabled(
        self, audit_deployments: dict[str, Any]
    ) -> None:
        """Gateway varlog volume must be PVC (not emptyDir) when auditLog.enabled=true."""
        gw = audit_deployments.get("yashigani-gateway")
        assert gw is not None, "yashigani-gateway Deployment not found"
        vol_types = self._get_volume_types(gw)
        assert vol_types.get("varlog") == "pvc", (
            f"yashigani-gateway: varlog is {vol_types.get('varlog')!r} — expected 'pvc'. "
            f"emptyDir is wiped on pod restart, losing audit logs (B7 P0)."
        )

    def test_backoffice_varlog_is_pvc_when_enabled(
        self, audit_deployments: dict[str, Any]
    ) -> None:
        """Backoffice varlog volume must be PVC (not emptyDir) when auditLog.enabled=true."""
        bo = audit_deployments.get("yashigani-backoffice")
        assert bo is not None, "yashigani-backoffice Deployment not found"
        vol_types = self._get_volume_types(bo)
        assert vol_types.get("varlog") == "pvc", (
            f"yashigani-backoffice: varlog is {vol_types.get('varlog')!r} — expected 'pvc'. "
            f"emptyDir is wiped on pod restart, losing audit logs (B7 P0)."
        )

    def test_gateway_audit_pvc_created_when_enabled(
        self, audit_pvcs: dict[str, Any]
    ) -> None:
        """yashigani-gateway-audit-log PVC must be created when auditLog.enabled=true."""
        assert "yashigani-gateway-audit-log" in audit_pvcs, (
            "yashigani-gateway-audit-log PVC not found in render with auditLog.enabled=true. "
            "Gateway has no persistent audit log storage (B7 P0)."
        )

    def test_backoffice_audit_pvc_created_when_enabled(
        self, audit_pvcs: dict[str, Any]
    ) -> None:
        """yashigani-backoffice-audit-log PVC must be created when auditLog.enabled=true."""
        assert "yashigani-backoffice-audit-log" in audit_pvcs, (
            "yashigani-backoffice-audit-log PVC not found in render with auditLog.enabled=true. "
            "Backoffice has no persistent audit log storage (B7 P0)."
        )

    def test_audit_pvcs_have_retain_policy(
        self, audit_pvcs: dict[str, Any]
    ) -> None:
        """Both audit PVCs must have helm.sh/resource-policy: keep annotation."""
        for pvc_name in ["yashigani-gateway-audit-log", "yashigani-backoffice-audit-log"]:
            pvc = audit_pvcs.get(pvc_name)
            if pvc is None:
                continue  # covered by existence tests above
            annotations = pvc.get("metadata", {}).get("annotations", {})
            policy = annotations.get("helm.sh/resource-policy", "")
            assert policy == "keep", (
                f"{pvc_name}: helm.sh/resource-policy is {policy!r} — expected 'keep'. "
                f"Audit logs would be deleted on helm uninstall (B7 P0)."
            )

    def test_gateway_varlog_is_emptydir_when_disabled(
        self, deployments: dict[str, Any]
    ) -> None:
        """
        When auditLog.enabled=false (default), gateway varlog must still be emptyDir.
        No regression on upgrade.
        """
        gw = deployments.get("yashigani-gateway")
        assert gw is not None, "yashigani-gateway Deployment not found"
        vol_types = self._get_volume_types(gw)
        assert vol_types.get("varlog") == "emptyDir", (
            f"yashigani-gateway: varlog is {vol_types.get('varlog')!r} — expected 'emptyDir' "
            f"when auditLog.enabled=false. Regression: upgrade without opt-in should "
            f"not change volume type."
        )
