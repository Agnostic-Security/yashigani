# Last updated: 2026-07-06T00:00:00+00:00
"""
v4.1 unified-sidecar Phase 2a — egress-forwarder template contract tests.

Design refs: unified-sidecar-design-20260706.md §2.2(c/d), §2.3, §2.6, §8
item 3 (contract tests 3a-3d — BLOCKING) + synthesis must-fixes #2/#3.

Coverage:
  3a  Rendered compose override: ringfence_<s>_in service list == EXACTLY
      [system, caddy] — the generator emits no third member, and the
      invariant validator ERRORS on a planted third member (I1-02 gate).
  3b  Rendered compose override: ringfence_<s>_eg service list == EXACTLY
      [system, egress-<s>] — ingress-Caddy is NOT in this list.
  3c  K8s: the forwarder egress policy allows ONLY caddy:18790 + kube-dns,
      contains NO allow to the system pod on shim_port (deny-by-absence —
      standard K8s NP has no deny verb), and carries the INTRA-ZONE-DENY
      marker; the generator errors when shim_port is not derivable.
  3d  Shape-C (SC-EGRESS-NONE): ringfence_<s>_eg does not appear anywhere
      in the artifact set; no forwarder artifacts.

Plus: planted 3-member / cross-bridge-contamination proofs against
validate_ringfence_topology; account-pins-mandatory (L-US-3); forwarder
hardening assertions (no CADDY_INTERNAL_HMAC, header strips, local prefix
allowlist, fixed port 9400); C10 with the real caddy binary; openclaw
OVERLAP wiring (drift gate on the committed artifacts + pins-untouched
gates); helm template render gates (requires helm on PATH).
"""
from __future__ import annotations

import copy
import pathlib
import shutil
import subprocess

import pytest
import yaml

from yashigani.manifest.codegen import (
    MCP_EGRESS_FORWARDER_PORT,
    CodegenEngineShapeC,
    CodegenError,
    render_egress_forwarder_artifacts,
    reset_codegen_registry,
    validate_ringfence_topology,
)

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent

_CADDY = shutil.which("caddy")
_HELM = shutil.which("helm")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _sample_manifest() -> dict:
    """A generic system with egress needs — capability-shaped, not name-shaped."""
    return {
        "metadata": {"name": "notifybot", "tenant_id": "acme", "category": "other"},
        "spec": {
            "image": {"repository": "registry.example/notifybot", "tag": "1.0",
                      "digest": "sha256:" + "0" * 64},
            "ingress": {"surface": "http-api", "shim_port": 8100},
            "egress": {
                "needs": [
                    {"prefix": "slack", "deliver_to": "slack.com",
                     "pins": {"bot_token_env": "NB_SLACK_BOT_TOKEN"}},
                    {"prefix": "telegram", "deliver_to": "api.telegram.org",
                     "pins": {"bot_id_env": "NB_TG_BOT_ID"}},
                ],
            },
        },
    }


def _shape_c_manifest() -> dict:
    """Minimal Shape-C manifest (SC-EGRESS-NONE)."""
    return {
        "metadata": {"name": "filesystem", "tenant_id": "acme",
                     "category": "mcp_server"},
        "spec": {
            "image": {"repository": "registry.example/fs", "tag": "1.0",
                      "digest": "sha256:" + "1" * 64},
            "network": {"egress_allow": []},
            "mcp": {"posture": "mcp-b", "transport": "streamable-http",
                    "exposes": {"listen_port": None, "shim_port": 8000}},
            "secrets": [],
            "storage": {"mounts": [], "tmpfs": []},
        },
    }


def _openclaw_descriptor() -> dict:
    with open(REPO_ROOT / "bundles" / "openclaw-egress.yaml", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


@pytest.fixture(autouse=True)
def _fresh_registry():
    reset_codegen_registry()
    yield
    reset_codegen_registry()


def _render(manifest: dict, runtime: str = "docker") -> dict[str, str]:
    # Injected pass-validator: C10 with the REAL binary is exercised by the
    # dedicated tests below; membership tests must not depend on caddy.
    return render_egress_forwarder_artifacts(
        manifest, runtime, caddy_validator=lambda _cfg: 0)


def _bridge_members(compose_text: str, bridge: str) -> set[str]:
    doc = yaml.safe_load(compose_text)
    members: set[str] = set()
    for svc_name, svc in (doc.get("services") or {}).items():
        nets = (svc or {}).get("networks") or []
        names = list(nets.keys()) if isinstance(nets, dict) else list(nets)
        if bridge in names:
            members.add(svc_name)
    return members


# ---------------------------------------------------------------------------
# 3a / 3b — exact bridge membership at render
# ---------------------------------------------------------------------------

class TestRingfenceMembership:
    def test_3a_ingress_ringfence_exactly_system_plus_caddy(self) -> None:
        arts = _render(_sample_manifest())
        compose = arts["docker/notifybot-egress-forwarder.override.yml"]
        assert _bridge_members(compose, "ringfence_notifybot_in") == {
            "notifybot", "caddy"}

    def test_3a_forwarder_never_on_ingress_ringfence(self) -> None:
        arts = _render(_sample_manifest())
        compose = arts["docker/notifybot-egress-forwarder.override.yml"]
        assert "egress-notifybot" not in _bridge_members(
            compose, "ringfence_notifybot_in")

    def test_3b_egress_ringfence_exactly_system_plus_forwarder(self) -> None:
        arts = _render(_sample_manifest())
        compose = arts["docker/notifybot-egress-forwarder.override.yml"]
        assert _bridge_members(compose, "ringfence_notifybot_eg") == {
            "notifybot", "egress-notifybot"}

    def test_3b_caddy_never_on_egress_ringfence(self) -> None:
        arts = _render(_sample_manifest())
        compose = arts["docker/notifybot-egress-forwarder.override.yml"]
        assert "caddy" not in _bridge_members(compose, "ringfence_notifybot_eg")

    def test_both_bridges_internal_ipv6_off(self) -> None:
        arts = _render(_sample_manifest())
        doc = yaml.safe_load(arts["docker/notifybot-egress-forwarder.override.yml"])
        for bridge in ("ringfence_notifybot_in", "ringfence_notifybot_eg"):
            net = doc["networks"][bridge]
            assert net["internal"] is True
            assert net["enable_ipv6"] is False


# ---------------------------------------------------------------------------
# The I1-02 gate — generator ERRORS on planted topology violations
# ---------------------------------------------------------------------------

class TestRingfenceInvariantEnforcement:
    def _rendered_compose(self) -> str:
        return _render(_sample_manifest())[
            "docker/notifybot-egress-forwarder.override.yml"]

    def test_planted_third_member_on_ingress_ringfence_errors(self) -> None:
        """THE I1-02 proof: a 3rd member on ringfence_<s>_in is a hard error."""
        doc = yaml.safe_load(self._rendered_compose())
        doc["services"]["rogue-svc"] = {
            "image": "x", "networks": ["ringfence_notifybot_in"]}
        with pytest.raises(CodegenError) as exc:
            validate_ringfence_topology(yaml.safe_dump(doc), "notifybot")
        assert exc.value.code == "RINGFENCE_IN_MEMBERSHIP_VIOLATION"
        assert "rogue-svc" in str(exc.value)

    def test_planted_forwarder_on_ingress_ringfence_errors(self) -> None:
        """The exact regression §2.6 exists to prevent: forwarder on _in."""
        doc = yaml.safe_load(self._rendered_compose())
        doc["services"]["egress-notifybot"]["networks"].append(
            "ringfence_notifybot_in")
        with pytest.raises(CodegenError) as exc:
            validate_ringfence_topology(yaml.safe_dump(doc), "notifybot")
        assert exc.value.code == "RINGFENCE_IN_MEMBERSHIP_VIOLATION"

    def test_planted_third_member_on_egress_ringfence_errors(self) -> None:
        doc = yaml.safe_load(self._rendered_compose())
        doc["services"]["caddy"]["networks"].append("ringfence_notifybot_eg")
        with pytest.raises(CodegenError) as exc:
            validate_ringfence_topology(yaml.safe_dump(doc), "notifybot")
        assert exc.value.code == "RINGFENCE_EG_MEMBERSHIP_VIOLATION"

    def test_missing_caddy_on_ingress_ringfence_errors(self) -> None:
        """Wrong membership in EITHER direction errors — not just extras."""
        doc = yaml.safe_load(self._rendered_compose())
        doc["services"]["caddy"]["networks"].remove("ringfence_notifybot_in")
        with pytest.raises(CodegenError) as exc:
            validate_ringfence_topology(yaml.safe_dump(doc), "notifybot")
        assert exc.value.code == "RINGFENCE_IN_MEMBERSHIP_VIOLATION"

    def test_non_internal_bridge_errors(self) -> None:
        doc = yaml.safe_load(self._rendered_compose())
        doc["networks"]["ringfence_notifybot_eg"]["internal"] = False
        with pytest.raises(CodegenError) as exc:
            validate_ringfence_topology(yaml.safe_dump(doc), "notifybot")
        assert exc.value.code == "RINGFENCE_BRIDGE_NOT_INTERNAL"

    def test_unparseable_topology_errors(self) -> None:
        with pytest.raises(CodegenError) as exc:
            validate_ringfence_topology("services: [unclosed", "notifybot")
        assert exc.value.code == "RINGFENCE_TOPOLOGY_UNPARSEABLE"

    def test_generator_output_passes_its_own_gate(self) -> None:
        validate_ringfence_topology(self._rendered_compose(), "notifybot")


# ---------------------------------------------------------------------------
# 3c — K8s intra-zone deny (deny-by-absence + marker) & shim-port error
# ---------------------------------------------------------------------------

class TestK8sIntraZoneDeny:
    def test_3c_values_overlay_documents_deny_tuple(self) -> None:
        arts = _render(_sample_manifest())
        values = arts["helm/yashigani/values-notifybot-egress.yaml"]
        assert "INTRA-ZONE-DENY" in values
        assert "shimPort: 8100" in values
        assert "egress-notifybot -> notifybot:8100" in values

    def test_3c_shim_port_not_derivable_is_generator_error(self) -> None:
        m = _sample_manifest()
        m["spec"]["ingress"]["shim_port"] = "not-a-port"
        with pytest.raises(CodegenError) as exc:
            _render(m)
        assert exc.value.code == "EGRESS_shim_port_invalid"

    @pytest.mark.skipif(_HELM is None, reason="helm binary not on PATH")
    def test_3c_rendered_forwarder_np_deny_by_absence(self) -> None:
        """Render the chart with the committed openclaw overlay and assert the
        forwarder egress policy has NO allow to the system pod — the deny is
        the ABSENCE of the allow (standard K8s NP; design §6 Captain Q2)."""
        out = subprocess.run(  # noqa: S603
            [_HELM, "template", "ysg", str(REPO_ROOT / "helm" / "yashigani"),
             "-f", str(REPO_ROOT / "helm" / "yashigani" / "values-openclaw-egress.yaml"),
             "--set", "internalBearer.value=contract-test-bearer",
             "--show-only", "templates/egress-forwarders.yaml"],
            capture_output=True, timeout=120, text=True,
        )
        assert out.returncode == 0, out.stderr[:1000]
        nps = [d for d in yaml.safe_load_all(out.stdout)
               if d and d.get("kind") == "NetworkPolicy"]
        assert len(nps) == 1
        np_spec = nps[0]["spec"]
        assert set(np_spec["policyTypes"]) == {"Ingress", "Egress"}
        # Egress allows: caddy:18790 + kube-dns ONLY. No rule may select the
        # system pod (openclaw) — that absence IS the intra-zone deny.
        for rule in np_spec["egress"]:
            for to in rule.get("to", []):
                labels = (to.get("podSelector") or {}).get("matchLabels") or {}
                assert labels.get("app.kubernetes.io/name") != "openclaw", (
                    "I1-02 REGRESSION: forwarder egress policy allows the "
                    "system pod — the intra-zone deny is void.")
            for port in rule.get("ports", []):
                assert port.get("port") != 18789, (
                    "I1-02 REGRESSION: forwarder egress policy allows the "
                    "system shim port.")
        allowed_ports = {p.get("port") for r in np_spec["egress"]
                         for p in r.get("ports", [])}
        assert allowed_ports == {18790, 53}
        # Ingress: from the system pod only, on the forwarder port.
        ingress = np_spec["ingress"]
        assert len(ingress) == 1
        from_labels = ingress[0]["from"][0]["podSelector"]["matchLabels"]
        assert from_labels["app.kubernetes.io/name"] == "openclaw"
        assert ingress[0]["ports"][0]["port"] == MCP_EGRESS_FORWARDER_PORT

    @pytest.mark.skipif(_HELM is None, reason="helm binary not on PATH")
    def test_default_values_render_no_forwarder(self) -> None:
        out = subprocess.run(  # noqa: S603
            [_HELM, "template", "ysg", str(REPO_ROOT / "helm" / "yashigani"),
             "--set", "internalBearer.value=contract-test-bearer",
             "--show-only", "templates/egress-forwarders.yaml"],
            capture_output=True, timeout=120, text=True,
        )
        # helm exits 0 with empty output (or a could-not-find warning) when
        # the template renders nothing.
        assert "kind: Deployment" not in out.stdout


# ---------------------------------------------------------------------------
# 3d — Shape-C / SC-EGRESS-NONE: no forwarder, no egress ringfence
# ---------------------------------------------------------------------------

class TestShapeCNoEgressRingfence:
    def test_3d_shape_c_artifact_set_has_no_egress_ringfence(self) -> None:
        engine = CodegenEngineShapeC(
            _shape_c_manifest(), "docker", caddy_validator=lambda _c: 0)
        arts = engine.render(dry_run=True)
        assert "docker/filesystem-egress-forwarder.override.yml" not in arts
        assert "docker/caddy/egress/filesystem-forwarder.caddy" not in arts
        assert "helm/yashigani/values-filesystem-egress.yaml" not in arts
        for rel, content in arts.items():
            assert "ringfence_filesystem_eg" not in content, rel
            assert "egress-filesystem" not in content, rel

    def test_shape_c_with_declared_needs_gets_forwarder_set(self) -> None:
        """Capability-keyed, not shape-keyed: a Shape-C MCP that declares
        spec.egress.needs (the governed /egress/eval class — the landed
        Phase-1 grant contract writes the OPA grant from exactly this list
        at approve) gets the forwarder set. SC-EGRESS-NONE continues to
        forbid DIRECT egress (spec.network.egress_allow) only."""
        m = _shape_c_manifest()
        m["spec"]["egress"] = {"needs": [
            {"prefix": "slack", "deliver_to": "slack.com", "pins": {"x": "y"}}]}
        engine = CodegenEngineShapeC(m, "docker", caddy_validator=lambda _c: 0)
        arts = engine.render(dry_run=True)
        assert "docker/filesystem-egress-forwarder.override.yml" in arts
        validate_ringfence_topology(
            arts["docker/filesystem-egress-forwarder.override.yml"], "filesystem")
        # Direct network egress stays forbidden regardless.
        m["spec"]["network"]["egress_allow"] = [{"host": "evil.example", "ports": [443]}]
        reset_codegen_registry()
        engine2 = CodegenEngineShapeC(m, "docker", caddy_validator=lambda _c: 0)
        with pytest.raises(CodegenError) as exc:
            engine2.render(dry_run=True)
        assert exc.value.code == "SC_egress_not_empty"

    def test_3d_no_needs_renders_nothing(self) -> None:
        m = _sample_manifest()
        m["spec"]["egress"]["needs"] = []
        assert _render(m) == {}
        del m["spec"]["egress"]
        assert _render(m) == {}


# ---------------------------------------------------------------------------
# Template hardening — synthesis must-fixes #2 / #3, C2 port, C10
# ---------------------------------------------------------------------------

class TestForwarderHardening:
    def test_no_caddy_internal_hmac_anywhere(self) -> None:
        """Synthesis #2: the forwarder carries NO Layer-B HMAC material —
        no parse-time env substitution, no env assignment, no header_up.
        (Prose comments MAY mention the name to document its absence.)"""
        for rel, content in _render(_sample_manifest()).items():
            for functional_form in ("{$CADDY_INTERNAL_HMAC",
                                    "{env.CADDY_INTERNAL_HMAC",
                                    "CADDY_INTERNAL_HMAC:",
                                    "CADDY_INTERNAL_HMAC="):
                assert functional_form not in content, (rel, functional_form)

    def test_identity_header_strips_present(self) -> None:
        caddy_cfg = _render(_sample_manifest())[
            "docker/caddy/egress/notifybot-forwarder.caddy"]
        for header in ("X-SPIFFE-ID", "X-Caddy-Verified-Secret",
                       "X-Yashigani-Verified-Spiffe"):
            assert "request_header -%s" % header in caddy_cfg

    def test_local_prefix_allowlist_and_default_deny(self) -> None:
        caddy_cfg = _render(_sample_manifest())[
            "docker/caddy/egress/notifybot-forwarder.caddy"]
        assert "handle /slack/*" in caddy_cfg
        assert "handle /telegram/*" in caddy_cfg
        assert 'respond "Forbidden" 403' in caddy_cfg
        assert "admin off" in caddy_cfg
        # No undeclared prefix handles beyond the declared set + healthz.
        handles = [ln.strip() for ln in caddy_cfg.splitlines()
                   if ln.strip().startswith("handle /")]
        assert sorted(handles) == sorted(
            ["handle /healthz {", "handle /slack/* {", "handle /telegram/* {"])

    def test_forwarder_listens_on_fixed_port_9400(self) -> None:
        arts = _render(_sample_manifest())
        assert MCP_EGRESS_FORWARDER_PORT == 9400
        assert ":9400 {" in arts["docker/caddy/egress/notifybot-forwarder.caddy"]
        assert "forwarderPort: 9400" in arts[
            "helm/yashigani/values-notifybot-egress.yaml"]

    def test_forwarder_presents_leaf_to_18790(self) -> None:
        caddy_cfg = _render(_sample_manifest())[
            "docker/caddy/egress/notifybot-forwarder.caddy"]
        assert "reverse_proxy https://caddy:18790" in caddy_cfg
        assert ("tls_client_auth /run/secrets/svid/acme/notifybot/client.crt "
                "/run/secrets/svid/acme/notifybot/client.key") in caddy_cfg

    def test_forwarder_compose_l9_hardening(self) -> None:
        doc = yaml.safe_load(_render(_sample_manifest())[
            "docker/notifybot-egress-forwarder.override.yml"])
        fwd = doc["services"]["egress-notifybot"]
        assert fwd["read_only"] is True
        assert fwd["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in fwd["security_opt"]
        assert fwd["user"].startswith("65534:")
        assert fwd["sysctls"]["net.ipv6.conf.all.disable_ipv6"] == 1

    def test_intra_zone_deny_init_sidecar_emitted(self) -> None:
        doc = yaml.safe_load(_render(_sample_manifest())[
            "docker/notifybot-egress-forwarder.override.yml"])
        init = doc["services"]["ringfence-init-egress-notifybot"]
        assert init["network_mode"] == "service:egress-notifybot"
        assert init["environment"]["RINGFENCE_CADDY_PORT"] == "18790"
        assert init["cap_add"] == ["NET_ADMIN"]
        # init-after-forwarder (the reverse ordering is a dependency cycle
        # compose v5 rejects — network_mode service: implies this edge).
        assert init["depends_on"]["egress-notifybot"][
            "condition"] == "service_started"
        assert "depends_on" not in doc["services"]["egress-notifybot"]

    def test_rootless_podman_skips_init_with_gap_note(self) -> None:
        arts = _render(_sample_manifest(), runtime="podman-rootless")
        compose = arts["docker/notifybot-egress-forwarder.override.yml"]
        doc = yaml.safe_load(compose)
        assert "ringfence-init-egress-notifybot" not in doc["services"]
        assert "depends_on" not in doc["services"]["egress-notifybot"]
        assert "ROOTLESS-PODMAN-L1-GAP" in compose
        # Topology invariants hold regardless of runtime.
        validate_ringfence_topology(compose, "notifybot")

    def test_pins_mandatory_for_internet_facing_need(self) -> None:
        """Laura L-US-3 / synthesis #3: render FAILS without account pins."""
        m = _sample_manifest()
        m["spec"]["egress"]["needs"][0].pop("pins")
        with pytest.raises(CodegenError) as exc:
            _render(m)
        assert exc.value.code == "EGRESS_pin_required"

    def test_pins_not_required_for_internal_class(self) -> None:
        m = _sample_manifest()
        m["spec"]["egress"]["needs"] = [
            {"prefix": "llm", "deliver_to": "gateway-inference"}]
        arts = _render(m)
        assert "handle /llm/*" in arts[
            "docker/caddy/egress/notifybot-forwarder.caddy"]

    def test_duplicate_prefix_rejected(self) -> None:
        m = _sample_manifest()
        m["spec"]["egress"]["needs"].append(copy.deepcopy(
            m["spec"]["egress"]["needs"][0]))
        with pytest.raises(CodegenError) as exc:
            _render(m)
        assert exc.value.code == "EGRESS_prefix_duplicate"

    def test_path_metachar_prefix_rejected(self) -> None:
        """L-US-4 adjacent: prefix can never carry path metacharacters."""
        m = _sample_manifest()
        m["spec"]["egress"]["needs"][0]["prefix"] = "../deliver"
        with pytest.raises(CodegenError) as exc:
            _render(m)
        assert exc.value.code == "EGRESS_prefix_invalid"

    @pytest.mark.skipif(_CADDY is None, reason="caddy binary not on PATH")
    def test_c10_real_caddy_adapt_and_validate(self) -> None:
        """C10 with the REAL binary — no injected validator."""
        arts = render_egress_forwarder_artifacts(_sample_manifest(), "docker")
        assert "docker/caddy/egress/notifybot-forwarder.caddy" in arts

    @pytest.mark.skipif(_CADDY is None, reason="caddy binary not on PATH")
    def test_c10_broken_config_fails_closed(self) -> None:
        from yashigani.manifest.codegen import _validate_caddy_config_full
        with pytest.raises(CodegenError) as exc:
            _validate_caddy_config_full(
                "{\n  admin off\n}\n\n:9400 {\n  not_a_directive_xyz\n}\n",
                [], [])
        assert exc.value.code in ("C10_caddy_adapt_failed",
                                  "C10_caddy_validate_failed")


# ---------------------------------------------------------------------------
# openclaw — OVERLAP wiring (pins stay; grant is the transitional seed)
# ---------------------------------------------------------------------------

class TestOpenclawOverlapWiring:
    """openclaw rides the template with EVERY existing control still live."""

    def test_committed_artifacts_match_regeneration(self) -> None:
        """Drift gate: the committed openclaw forwarder artifacts must be
        byte-identical to a fresh render from bundles/openclaw-egress.yaml."""
        arts = render_egress_forwarder_artifacts(
            _openclaw_descriptor(), "docker",
            caddy_validator=lambda _c: 0)
        for rel, content in arts.items():
            committed = (REPO_ROOT / rel).read_text(encoding="utf-8")
            assert committed == content, (
                "DRIFT: %s differs from codegen output. Regenerate from "
                "bundles/openclaw-egress.yaml (header comment has the "
                "command)." % rel)

    def test_openclaw_topology_invariants(self) -> None:
        compose = (REPO_ROOT / "docker" /
                   "openclaw-egress-forwarder.override.yml").read_text()
        validate_ringfence_topology(compose, "openclaw")
        assert _bridge_members(compose, "ringfence_openclaw_in") == {
            "openclaw", "caddy"}
        assert _bridge_members(compose, "ringfence_openclaw_eg") == {
            "openclaw", "egress-openclaw"}

    def test_openclaw_forwarder_uses_transitional_leaf_files(self) -> None:
        compose = (REPO_ROOT / "docker" /
                   "openclaw-egress-forwarder.override.yml").read_text()
        doc = yaml.safe_load(compose)
        vols = doc["services"]["egress-openclaw"]["volumes"]
        assert ("./secrets/openclaw_client.crt:"
                "/run/secrets/svid/default/openclaw/client.crt:ro") in vols
        assert ("./secrets/openclaw_client.key:"
                "/run/secrets/svid/default/openclaw/client.key:ro") in vols
        # Key is 0600 uid 1000 — forwarder runs as the key owner.
        assert doc["services"]["egress-openclaw"]["user"].startswith("1000:")

    def test_openclaw_descriptor_prefixes_mirror_transitional_seed(self) -> None:
        """The descriptor's declared prefixes must equal Tom's transitional
        OPA grant seed EXACTLY — grant and forwarder surface stay in
        lock-step (pin-AND-grant overlap)."""
        from yashigani.mcp._egress_grants import (
            _OPENCLAW_TRANSITIONAL_PREFIXES,
        )
        declared = [n["prefix"] for n in
                    _openclaw_descriptor()["spec"]["egress"]["needs"]]
        assert sorted(declared) == sorted(_OPENCLAW_TRANSITIONAL_PREFIXES)

    # ── pins-untouched gates (deleting pins is a LATER, Laura-gated step) ──

    def test_static_caller_pin_untouched(self) -> None:
        canonical = (REPO_ROOT / "docker" /
                     "Caddyfile.openclaw-egress").read_text(encoding="utf-8")
        assert "(openclaw-egress-caller-gate)" in canonical
        assert "YASHIGANI_OPENCLAW_SPIFFE_ID" in canonical
        assert "spiffe://yashigani.internal/openclaw" in canonical

    def test_static_destination_and_account_pins_untouched(self) -> None:
        canonical = (REPO_ROOT / "docker" /
                     "Caddyfile.openclaw-egress").read_text(encoding="utf-8")
        for pin in ("YASHIGANI_OPENCLAW_SLACK_BOT_TOKEN",
                    "YASHIGANI_OPENCLAW_SLACK_WEBHOOK_PATH",
                    "YASHIGANI_OPENCLAW_TELEGRAM_BOT_ID"):
            assert pin in canonical, "destination/account pin %s missing" % pin
        for upstream in ("https://slack.com", "https://hooks.slack.com",
                         "https://api.telegram.org"):
            assert upstream in canonical

    def test_openclaw_env_repointed_at_forwarder_overlap_kept(self) -> None:
        """v4.1 three-agent wrap (2026-07-07, supersedes the Phase-2b
        fiction): openclaw's outbound dials the FORWARDER via openclaw's
        REAL, schema-validated config keys — the former top-level `egress`
        json block crashed the binary (Unrecognized key, proven live) and
        the OPENCLAW_*_BASE_URL / OPENCLAW_EGRESS_TLS_* env vars were never
        read by the binary (verified against the pinned image).
        OVERLAP: the client-cert TLS MOUNTS stay (compose volumes) so the
        direct :18790 path stays provable until the Laura-gated migration."""
        import json as _json

        compose = (REPO_ROOT / "docker" /
                   "docker-compose.yml").read_text(encoding="utf-8")
        # The fabricated env wiring must never come back.
        for fabricated in (
            "OPENCLAW_SLACK_API_BASE_URL",
            "OPENCLAW_SLACK_HOOKS_BASE_URL",
            "OPENCLAW_TELEGRAM_API_BASE_URL",
            "OPENCLAW_EGRESS_TLS_CERT_FILE",
            "OPENCLAW_EGRESS_TLS_KEY_FILE",
        ):
            assert f"{fabricated}:" not in compose, (
                f"{fabricated} is back in docker-compose.yml — the openclaw "
                f"binary never reads it; fictional wiring masks real gaps")
        # No direct-dial base URL may remain anywhere in the compose file.
        assert "https://caddy:18790/slack" not in compose
        assert "https://caddy:18790/telegram" not in compose
        # OVERLAP: client-cert mounts stay wired (pin-AND-grant phase).
        assert "./secrets/openclaw_client.crt:/etc/openclaw/tls/client.crt:ro" in compose
        assert "./secrets/openclaw_client.key:/etc/openclaw/tls/client.key:ro" in compose
        # Primary config (openclaw.json) repointed via REAL schema keys.
        oc_json_text = (REPO_ROOT / "docker" / "openclaw" /
                        "openclaw.json").read_text(encoding="utf-8")
        oc = _json.loads(oc_json_text)
        assert "egress" not in oc, (
            "top-level `egress` key is back in openclaw.json — the config "
            "validator REJECTS unknown keys (crash-loop, proven 2026-07-07)")
        assert (oc["models"]["providers"]["yashigani"]["baseUrl"]
                == "http://egress-openclaw:9400/llm/v1")
        assert (oc["channels"]["telegram"]["apiRoot"]
                == "http://egress-openclaw:9400/telegram")
        # channels.telegram.enabled must be explicit — openclaw persists a
        # plugin auto-enable delta into its (read-only-mounted) config file
        # otherwise, and startup fails EACCES (proven 2026-07-07).
        assert oc["channels"]["telegram"]["enabled"] is True
        assert "caddy:18790" not in oc_json_text

    def test_helm_overlay_projects_scoped_items_only(self) -> None:
        values = yaml.safe_load(
            (REPO_ROOT / "helm" / "yashigani" /
             "values-openclaw-egress.yaml").read_text(encoding="utf-8"))
        entry = values["egressForwarders"]["OpenclawDefault"]
        assert entry["existingSecret"] == {
            "name": "yashigani-pki-certs",
            "certKey": "openclaw_client.crt",
            "keyKey": "openclaw_client.key",
            "caKey": "ca_bundle.crt",
        }
        assert entry["shimPort"] == 18789
        # v4.1 three-agent wrap: the llm class joins the messaging prefixes.
        assert sorted(entry["prefixes"]) == ["llm", "slack", "slack-hooks", "telegram"]

    @pytest.mark.skipif(_CADDY is None, reason="caddy binary not on PATH")
    def test_committed_openclaw_forwarder_caddyfile_c10(self) -> None:
        from yashigani.manifest.codegen import _validate_caddy_config_full
        content = (REPO_ROOT / "docker" / "caddy" / "egress" /
                   "openclaw-forwarder.caddy").read_text(encoding="utf-8")
        base = "/run/secrets/svid/default/openclaw"
        _validate_caddy_config_full(
            content, ["%s/client.crt" % base, "%s/ca.crt" % base],
            ["%s/client.key" % base])
