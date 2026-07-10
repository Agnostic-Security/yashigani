# Last updated: 2026-07-07T00:00:00+00:00
"""
v4.1 unified-sidecar §2.5 — agent INGRESS-front template contract tests.

Design refs: unified-sidecar-design-20260706.md §2.5, §2.2(b), §2.6;
Su's conflict note project_v41_design_conflict_ingress_dispatch (the §2.6
split-ringfence migration severed gateway→agent + backoffice→langflow
dispatch; §2.5 fronts restore it THROUGH caddy, never direct).

Coverage:
  I1  Rendered front snippet: mTLS require_and_verify against the internal
      intermediate, TLS 1.3, X-SPIFFE-ID strip-BEFORE-set from the verified
      peer URI SAN, Layer-B marker strip, forward_auth → /auth/verify-mcp
      (the ONE gate — no parallel verify endpoint), reverse_proxy to
      http://<system>:<shim_port>, default-deny 404.
  I2  Port discipline: pinned descriptor ports resolve exactly; the
      deterministic default matches sha256(tenant/name) in [9500,9900);
      the shared allocator errors on a collision with an MCP mesh port;
      reserved ports are rejected.
  I3  Capability keying: surface http-api/openai-api → artifact set;
      surface mcp / none / absent → {} (MCP wrap path stays disjoint).
  I4  §2.6 invariant untouched: the front adds NO bridge member — the
      committed egress overrides still pass validate_ringfence_topology,
      and a planted 3rd member on ringfence_<s>_in still raises.
  I5  Dispatch repoint parity (drift gates): install.sh registered upstream
      URLs, compose YASHIGANI_LANGFLOW_URL + YASHIGANI_AGENT_UPSTREAM_HOSTNAMES,
      and the committed artifacts all match the descriptor-pinned mesh ports.
  I6  Committed-artifact drift gates: docker/caddy/agents/<s>-ingress.caddy +
      helm/yashigani/values-<s>-ingress.yaml are byte-identical to a fresh
      render of bundles/<s>-egress.yaml.
  I7  C10 with the real caddy binary (skipped when absent); helm template
      renders RC=0 with the ingress overlays (skipped when helm absent),
      the caddy-agents ConfigMap carries the snippet, the mesh Service
      exposes exactly the enabled ports, and the agent ingress NP admits
      the caddy pod only.
"""
from __future__ import annotations

import copy
import hashlib
import pathlib
import re
import shutil
import subprocess

import pytest
import yaml

from yashigani.manifest.codegen import (
    CodegenError,
    _mcp_mesh_port,
    render_agent_ingress_artifacts,
    reset_codegen_registry,
    resolve_agent_ingress_port,
    validate_ringfence_topology,
)

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent

_CADDY = shutil.which("caddy")
_HELM = shutil.which("helm")

BUNDLED = {
    # system: (pinned mesh port, shim port)
    "langflow": (9705, 7860),
    "letta": (9775, 8283),
    "openclaw": (9671, 18789),
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _bundle_manifest(system: str) -> dict:
    with open(REPO_ROOT / "bundles" / ("%s-egress.yaml" % system)) as fh:
        return yaml.safe_load(fh)


def _sample_manifest() -> dict:
    """Generic frontable system — capability-shaped, not name-shaped."""
    return {
        "metadata": {"name": "notifybot", "tenant_id": "acme", "category": "other"},
        "spec": {
            "image": {"repository": "registry.example/notifybot", "tag": "1.0",
                      "digest": "sha256:" + "0" * 64},
            "ingress": {"surface": "http-api", "shim_port": 8100},
            "egress": {"needs": []},
        },
    }


@pytest.fixture(autouse=True)
def _fresh_registry():
    reset_codegen_registry()
    yield
    reset_codegen_registry()


# ---------------------------------------------------------------------------
# I1 — snippet content contract
# ---------------------------------------------------------------------------

class TestFrontSnippetContract:
    @pytest.mark.parametrize("system", sorted(BUNDLED))
    def test_snippet_security_contract(self, system):
        mesh_port, shim_port = BUNDLED[system]
        arts = render_agent_ingress_artifacts(_bundle_manifest(system), "docker")
        snippet = arts["docker/caddy/agents/%s-ingress.caddy" % system]

        assert ":%d {" % mesh_port in snippet
        assert "mode require_and_verify" in snippet
        assert "trust_pool file /run/secrets/ca_intermediate.crt" in snippet
        assert "protocols tls1.3" in snippet
        # Strip-BEFORE-set ordering (EX-231-08).
        strip = snippet.index("request_header -X-SPIFFE-ID")
        set_ = snippet.index(
            "request_header X-SPIFFE-ID {http.request.tls.client.san.uris.0}")
        assert strip < set_
        assert "request_header -X-Caddy-Verified-Secret" in snippet
        # The ONE verify gate (§2.5) — no parallel endpoint.
        assert ("uri /auth/verify-mcp?tenant=default&server=%s" % system) in snippet
        assert "header_up X-Caddy-Verified-Secret {$CADDY_INTERNAL_HMAC}" in snippet
        # TRACK1-F-04 / §2.5 gap fix: verify-mcp reads X-SPIFFE-ID to
        # authenticate the caller's transport identity. forward_auth does not
        # auto-copy headers — must be explicit. Without this the gate returns
        # 401 no_spiffe_id on every request (never passes).
        assert "header_up X-SPIFFE-ID {http.request.tls.client.san.uris.0}" in snippet
        assert ("handle_path /agents/default/%s/*" % system) in snippet
        assert ("reverse_proxy http://%s:%d" % (system, shim_port)) in snippet
        assert 'respond "Not Found" 404' in snippet
        # Listener presents the caddy mesh leaf (Ollama-front precedent) —
        # NEVER an agent clientAuth-only leaf.
        assert "tls /run/secrets/caddy_client.crt /run/secrets/caddy_client.key" in snippet

    def test_values_overlay_shape(self):
        arts = render_agent_ingress_artifacts(_bundle_manifest("langflow"), "docker")
        vals = yaml.safe_load(arts["helm/yashigani/values-langflow-ingress.yaml"])
        entry = vals["agentIngressFronts"]["LangflowDefault"]
        assert entry == {
            "enabled": True,
            "systemName": "langflow",
            "tenantId": "default",
            "shimPort": 7860,
            "meshPort": 9705,
        }


# ---------------------------------------------------------------------------
# I2 — port discipline
# ---------------------------------------------------------------------------

class TestPortDiscipline:
    @pytest.mark.parametrize("system", sorted(BUNDLED))
    def test_pinned_port_resolves(self, system):
        assert resolve_agent_ingress_port(_bundle_manifest(system)) == BUNDLED[system][0]

    @pytest.mark.parametrize("system", sorted(BUNDLED))
    def test_pin_equals_deterministic_default(self, system):
        """The pins are the allocator's own values — pin drift is a defect."""
        digest = hashlib.sha256(("default/%s" % system).encode()).digest()
        expected = 9500 + int.from_bytes(digest[:4], "big") % 400
        assert BUNDLED[system][0] == expected

    def test_unpinned_uses_deterministic_default(self):
        m = _sample_manifest()
        digest = hashlib.sha256(b"acme/notifybot").digest()
        assert resolve_agent_ingress_port(m) == 9500 + int.from_bytes(digest[:4], "big") % 400

    def test_reserved_port_rejected(self):
        m = _sample_manifest()
        m["spec"]["ingress"]["mesh_port"] = 18790
        with pytest.raises(CodegenError) as exc:
            resolve_agent_ingress_port(m)
        assert "INGRESS_mesh_port_invalid" in str(exc.value)

    def test_forwarder_port_rejected(self):
        m = _sample_manifest()
        m["spec"]["ingress"]["mesh_port"] = 9400
        with pytest.raises(CodegenError):
            resolve_agent_ingress_port(m)

    def test_shared_allocator_collides_with_mcp_mesh_port(self):
        """Ingress fronts and MCP mesh listeners share ONE collision domain."""
        mcp = {
            "metadata": {"name": "othermcp", "tenant_id": "acme"},
            "spec": {"mcp": {"exposes": {"mesh_port": 9705}}},
        }
        assert _mcp_mesh_port(mcp) == 9705
        with pytest.raises(CodegenError) as exc:
            resolve_agent_ingress_port(_bundle_manifest("langflow"))
        assert "collision" in str(exc.value).lower()

    def test_three_bundled_ports_distinct(self):
        ports = {p for p, _ in BUNDLED.values()}
        assert len(ports) == 3
        assert all(9500 <= p < 9900 for p in ports)


# ---------------------------------------------------------------------------
# I3 — capability keying
# ---------------------------------------------------------------------------

class TestCapabilityKeying:
    def test_mcp_surface_gets_no_front(self):
        m = _sample_manifest()
        m["spec"]["ingress"]["surface"] = "mcp"
        assert render_agent_ingress_artifacts(m, "docker") == {}

    def test_none_surface_gets_no_front(self):
        m = _sample_manifest()
        m["spec"]["ingress"]["surface"] = "none"
        assert render_agent_ingress_artifacts(m, "docker") == {}

    def test_absent_ingress_gets_no_front(self):
        m = _sample_manifest()
        del m["spec"]["ingress"]
        assert render_agent_ingress_artifacts(m, "docker") == {}

    def test_unknown_surface_errors(self):
        m = _sample_manifest()
        m["spec"]["ingress"]["surface"] = "carrier-pigeon"
        with pytest.raises(CodegenError) as exc:
            render_agent_ingress_artifacts(m, "docker")
        assert "INGRESS_surface_invalid" in str(exc.value)

    def test_invalid_runtime_errors(self):
        with pytest.raises(CodegenError) as exc:
            render_agent_ingress_artifacts(_sample_manifest(), "bare-metal")
        assert "INVALID_RUNTIME" in str(exc.value)


# ---------------------------------------------------------------------------
# I4 — §2.6 invariant untouched
# ---------------------------------------------------------------------------

class TestRingfenceInvariantUntouched:
    @pytest.mark.parametrize("system", sorted(BUNDLED))
    def test_committed_override_still_valid(self, system):
        text = (REPO_ROOT / "docker" /
                ("%s-egress-forwarder.override.yml" % system)).read_text()
        validate_ringfence_topology(text, system)  # must not raise

    def test_planted_third_member_still_raises(self):
        text = (REPO_ROOT / "docker" /
                "langflow-egress-forwarder.override.yml").read_text()
        doc = yaml.safe_load(text)
        doc["services"]["gateway"] = {"networks": ["ringfence_langflow_in"]}
        with pytest.raises(CodegenError) as exc:
            validate_ringfence_topology(yaml.safe_dump(doc), "langflow")
        assert "RINGFENCE_IN_MEMBERSHIP_VIOLATION" in str(exc.value)

    @pytest.mark.parametrize("system", sorted(BUNDLED))
    def test_front_emits_no_compose_artifact(self, system):
        """The front is caddy CONFIG — it must never emit compose topology."""
        arts = render_agent_ingress_artifacts(_bundle_manifest(system), "docker")
        assert set(arts) == {
            "docker/caddy/agents/%s-ingress.caddy" % system,
            "helm/yashigani/values-%s-ingress.yaml" % system,
        }


# ---------------------------------------------------------------------------
# I5 — dispatch repoint parity (drift gates)
# ---------------------------------------------------------------------------

class TestDispatchRepointParity:
    def test_install_sh_registered_upstreams(self):
        text = (REPO_ROOT / "install.sh").read_text()
        for system, (mesh_port, _) in BUNDLED.items():
            url = "https://caddy:%d/agents/default/%s" % (mesh_port, system)
            assert url in text, (
                "install.sh must register %s through its §2.5 front (%s)"
                % (system, url))
        # The raw direct dials must be GONE from the registration block.
        for stale in ("http://langflow:7860\"", "http://letta:8283\"",
                      "http://openclaw:18789\""):
            assert ('_url="%s' % stale.rstrip('"')) not in text

    def test_compose_langflow_url_and_allowlist(self):
        text = (REPO_ROOT / "docker" / "docker-compose.yml").read_text()
        assert "YASHIGANI_LANGFLOW_URL: https://caddy:9705/agents/default/langflow" in text
        m = re.search(r'YASHIGANI_AGENT_UPSTREAM_HOSTNAMES: "([^"]+)"', text)
        assert m, "compose must carry the SSRF hostname allowlist"
        assert "caddy" in m.group(1).split(",")

    def test_helm_allowlist_carries_mesh_service(self):
        vals = yaml.safe_load((REPO_ROOT / "helm/yashigani/values.yaml").read_text())
        assert "yashigani-caddy-mesh" in vals["backoffice"]["agentUpstreamHostnames"]


# ---------------------------------------------------------------------------
# I6 — committed-artifact drift gates
# ---------------------------------------------------------------------------

class TestCommittedArtifactDrift:
    @pytest.mark.parametrize("system", sorted(BUNDLED))
    def test_committed_matches_fresh_render(self, system):
        arts = render_agent_ingress_artifacts(_bundle_manifest(system), "docker")
        for rel, content in arts.items():
            committed = (REPO_ROOT / rel).read_text()
            assert committed == content, (
                "%s drifted from bundles/%s-egress.yaml — regenerate via the "
                "descriptor's regen command, never hand-edit" % (rel, system))


# ---------------------------------------------------------------------------
# I7 — C10 (real caddy) + helm render gates
# ---------------------------------------------------------------------------

@pytest.mark.skipif(_CADDY is None, reason="caddy binary not on PATH")
class TestC10RealCaddy:
    @pytest.mark.parametrize("system", sorted(BUNDLED))
    def test_committed_snippet_adapts(self, system, tmp_path):
        snippet = (REPO_ROOT / "docker" / "caddy" / "agents" /
                   ("%s-ingress.caddy" % system)).read_text()
        cf = tmp_path / "Caddyfile"
        cf.write_text("{\n    admin off\n}\n\n" + snippet)
        proc = subprocess.run(
            [_CADDY, "adapt", "--config", str(cf)],
            capture_output=True, timeout=30,
        )
        assert proc.returncode == 0, proc.stderr.decode()[:512]


@pytest.mark.skipif(_HELM is None, reason="helm binary not on PATH")
class TestHelmRenderGates:
    def _template(self, *extra) -> str:
        cmd = [_HELM, "template", "ysg-test", str(REPO_ROOT / "helm" / "yashigani")]
        for overlay in ("values-langflow-ingress.yaml",
                        "values-letta-ingress.yaml",
                        "values-openclaw-ingress.yaml"):
            cmd += ["-f", str(REPO_ROOT / "helm" / "yashigani" / overlay)]
        cmd += ["--set", "internalBearer.value=contract-test-bearer"]
        cmd += list(extra)
        proc = subprocess.run(cmd, capture_output=True, timeout=120)
        assert proc.returncode == 0, proc.stderr.decode()[:1024]
        return proc.stdout.decode()

    def test_configmap_snippet_and_mesh_service(self):
        out = self._template()
        docs = [d for d in yaml.safe_load_all(out) if d]
        cms = {d["metadata"]["name"]: d for d in docs if d.get("kind") == "ConfigMap"}
        agents_cm = cms["yashigani-caddy-agents"]
        for system, (mesh_port, shim_port) in BUNDLED.items():
            key = "%s-ingress.caddy" % system
            assert key in agents_cm["data"]
            snippet = agents_cm["data"][key]
            assert ":%d {" % mesh_port in snippet
            assert "mode require_and_verify" in snippet
            assert ("uri /auth/verify-mcp?tenant=default&server=%s" % system) in snippet
            # TRACK1-F-04 / §2.5 gap fix — Helm parity: X-SPIFFE-ID must be
            # forwarded in the K8s configmap snippet too.
            assert "header_up X-SPIFFE-ID {http.request.tls.client.san.uris.0}" in snippet
            # Documented K8s deltas ONLY:
            assert "forward_auth https://yashigani-backoffice:8443" in snippet
            assert ("reverse_proxy http://yashigani-%s:%d" % (system, shim_port)) in snippet

        svcs = {d["metadata"]["name"]: d for d in docs if d.get("kind") == "Service"}
        mesh = svcs["yashigani-caddy-mesh"]
        assert mesh["spec"]["type"] == "ClusterIP"
        got_ports = {p["port"] for p in mesh["spec"]["ports"]}
        assert got_ports == {p for p, _ in BUNDLED.values()}
        # NEVER on the public LB Service.
        edge = svcs["yashigani-caddy"]
        edge_ports = {p["port"] for p in edge["spec"]["ports"]}
        assert not (edge_ports & got_ports)

    def test_agent_ingress_np_admits_caddy_only(self):
        out = self._template()
        docs = [d for d in yaml.safe_load_all(out) if d]
        nps = {d["metadata"]["name"]: d for d in docs
               if d.get("kind") == "NetworkPolicy"}
        for system, (mesh_port, shim_port) in BUNDLED.items():
            np = nps["allow-agent-ingress-front-%s" % system]
            rules = np["spec"]["ingress"]
            assert len(rules) == 1
            froms = rules[0]["from"]
            assert len(froms) == 1
            assert froms[0]["podSelector"]["matchLabels"] == {
                "app.kubernetes.io/name": "yashigani-caddy"}
            assert {"protocol": "TCP", "port": shim_port} in rules[0]["ports"]
            # Dispatchers reach caddy, not the agent.
            disp = nps["allow-dispatch-egress-to-mesh-%s" % system]
            ports = disp["spec"]["egress"][0]["ports"]
            assert {"protocol": "TCP", "port": mesh_port} in ports

    def test_backoffice_langflow_url_repointed(self):
        out = self._template()
        assert ("https://yashigani-caddy-mesh:9705/agents/default/langflow"
                in out)

    def test_no_fronts_renders_empty_configmap(self):
        cmd = [_HELM, "template", "ysg-test",
               str(REPO_ROOT / "helm" / "yashigani"),
               "--set", "internalBearer.value=contract-test-bearer"]
        proc = subprocess.run(cmd, capture_output=True, timeout=120)
        assert proc.returncode == 0, proc.stderr.decode()[:1024]
        docs = [d for d in yaml.safe_load_all(proc.stdout.decode()) if d]
        assert "yashigani-caddy-mesh" not in {
            d["metadata"]["name"] for d in docs if d.get("kind") == "Service"}
