"""
LAURA-I1-03 — openclaw egress-gateway topology invariants (v4.1 Phase 1c).

INVARIANTS (must ALWAYS hold — each one maps to a Laura must-fix from
laura-forwardproxy-threatmodel.md, GO-WITH-FIXES):

  FP-01  The egress gateway is a FIXED-UPSTREAM reverse_proxy, never a
         CONNECT/open forward proxy. `caddyserver/forwardproxy` / `forward_proxy`
         / an `acl` block must never appear in any Caddy config we ship.
  FP-02  The destination allowlist lives ONLY in the perimeter-owned Caddy
         config. No Slack/Telegram destination host may appear in openclaw's
         own config (openclaw.json) — a compromised openclaw must not be able
         to rewrite its destination set.
  FP-03  The egress listener requires_and_verifies mTLS and SAN-binds to the
         openclaw leaf; compose carries a dedicated 2-member ringfence bridge
         (openclaw + caddy only).
  I1-03  openclaw has NO internal:false NIC — every compose network it joins
         is internal:true (bridge membership is bidirectional at L3; "edge for
         inbound only" reopens the exfil path). No host port publish either
         (internal-only networks cannot DNAT — a `ports:` entry would be a
         silent lie).
  FP-05  The public webhook routes are exact POST paths with a fail-closed
         forward_auth verify; there is no `reverse_proxy` of openclaw's whole
         surface.

Fully provable here (file/text only). The LIVE proofs (direct egress blocked,
gateway 403 for non-openclaw leaf, unsigned webhook dropped) are Laura's
Phase-3 re-test — this suite pins the config so a regression is caught at
commit time, not at pentest time.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE = REPO_ROOT / "docker" / "docker-compose.yml"
EGRESS_SNIPPET = REPO_ROOT / "docker" / "Caddyfile.openclaw-egress"
WEBHOOK_SNIPPET = REPO_ROOT / "docker" / "Caddyfile.openclaw-webhooks"
CADDY_VARIANTS = [
    REPO_ROOT / "docker" / "Caddyfile.selfsigned",
    REPO_ROOT / "docker" / "Caddyfile.acme",
    REPO_ROOT / "docker" / "Caddyfile.ca",
]
OPENCLAW_JSON = REPO_ROOT / "docker" / "openclaw" / "openclaw.json"
HELM_CONFIGMAPS = REPO_ROOT / "helm" / "yashigani" / "templates" / "configmaps.yaml"
HELM_NETPOL = REPO_ROOT / "helm" / "yashigani" / "templates" / "networkpolicy.yaml"

EGRESS_UPSTREAMS = ("slack.com", "hooks.slack.com", "api.telegram.org")


@pytest.fixture(scope="module")
def compose() -> dict:
    return yaml.safe_load(COMPOSE.read_text())


# ── I1-03 / FP-04(4): openclaw network topology ─────────────────────────────


def test_openclaw_has_no_internal_false_nic(compose: dict) -> None:
    """Every network openclaw joins must be internal:true (no edge, ever)."""
    svc = compose["services"]["openclaw"]
    nets = svc["networks"]
    assert "edge" not in nets, "openclaw re-joined `edge` — reopens LAURA-I1-03"
    for net in nets:
        net_def = compose["networks"][net]
        assert net_def.get("internal") is True, (
            f"openclaw joins network {net!r} which is not internal:true — "
            f"an internal:false NIC is bidirectional internet reachability (I1-03)"
        )


def test_openclaw_has_no_host_port_publish(compose: dict) -> None:
    """Internal-only networks cannot DNAT a host publish; a ports: entry
    would be dead config masking the real inbound path (Caddy webhooks)."""
    svc = compose["services"]["openclaw"]
    assert "ports" not in svc, (
        "openclaw has a `ports:` publish — inbound must arrive exclusively "
        "via the Caddy /webhooks/* routes (FP-05)"
    )


def test_openclaw_ringfence_is_two_member(compose: dict) -> None:
    """FP-03: dedicated bridge {openclaw, caddy} ONLY — anything else makes
    the egress gateway a shared relay (I1-04 root cause reintroduced)."""
    members = sorted(
        name
        for name, svc in compose["services"].items()
        if "openclaw_ringfence" in (svc.get("networks") or [])
    )
    assert members == ["caddy", "openclaw"], (
        f"openclaw_ringfence members must be exactly [caddy, openclaw]; got {members}"
    )
    net_def = compose["networks"]["openclaw_ringfence"]
    assert net_def.get("internal") is True
    assert net_def.get("enable_ipv6") is False


def test_openclaw_mounts_only_its_own_leaf(compose: dict) -> None:
    """PROBE-AG1 still holds: no flat ./secrets mount; only the per-file
    binds for openclaw's own leaf + the public CA cert."""
    svc = compose["services"]["openclaw"]
    vols = [v for v in svc["volumes"] if isinstance(v, str)]
    assert not any(
        v.startswith("./secrets:") for v in vols
    ), "openclaw must never mount the flat ./secrets dir (PROBE-AG1)"
    secret_binds = sorted(v.split(":")[0] for v in vols if v.startswith("./secrets/"))
    assert secret_binds == [
        "./secrets/ca_root.crt",
        "./secrets/openclaw_client.crt",
        "./secrets/openclaw_client.key",
    ], f"unexpected secret binds on openclaw: {secret_binds}"


# ── FP-01: fixed upstreams, never an open/CONNECT proxy ─────────────────────


def test_egress_gateway_is_fixed_upstream(compose: dict) -> None:
    text = EGRESS_SNIPPET.read_text()
    for host in EGRESS_UPSTREAMS:
        assert f"reverse_proxy https://{host}" in text, (
            f"egress upstream {host} must be a reverse_proxy LITERAL in "
            f"{EGRESS_SNIPPET.name} (FP-01/FP-02)"
        )
        assert f"tls_server_name {host}" in text, (
            f"SNI must be pinned to {host} (FP-04e anti domain-fronting)"
        )
    assert "require_and_verify" in text, "egress listener must require mTLS (FP-03)"
    assert "{$YASHIGANI_OPENCLAW_SPIFFE_ID" in text, (
        "egress routes must SAN-bind to the openclaw leaf (FP-03)"
    )


def _config_lines(text: str) -> str:
    """Drop comment lines — the ban is on CONFIG tokens, not prose that
    (legitimately) cites the threat-model filename."""
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )


def test_no_forward_proxy_module_anywhere() -> None:
    """The NO-GO condition: no CONNECT/open forward proxy in any Caddy config."""
    caddy_files = list((REPO_ROOT / "docker").glob("Caddyfile*")) + [
        p for p in (REPO_ROOT / "docker" / "caddy").glob("Caddyfile*")
    ]
    assert caddy_files, "no Caddyfiles found — path drift?"
    for f in caddy_files:
        cfg = _config_lines(f.read_text())
        assert "forward_proxy" not in cfg, f"{f}: forwardproxy module configured (FP-01 NO-GO)"
        assert "forwardproxy" not in cfg, f"{f}: forwardproxy plugin referenced (FP-01 NO-GO)"
    helm_cfg = _config_lines(HELM_CONFIGMAPS.read_text())
    assert "forward_proxy" not in helm_cfg and "forwardproxy" not in helm_cfg, (
        "helm configmaps.yaml references a forward proxy (FP-01 NO-GO)"
    )
    # And the plugin is never baked into the image.
    dockerfile_cfg = _config_lines(
        (REPO_ROOT / "docker" / "caddy" / "Dockerfile.caddy").read_text()
    )
    assert "xcaddy" not in dockerfile_cfg and "forwardproxy" not in dockerfile_cfg


# ── FP-02: allowlist is perimeter-owned, never openclaw-owned ───────────────


def test_openclaw_config_carries_no_destination_hosts() -> None:
    text = OPENCLAW_JSON.read_text()
    for host in EGRESS_UPSTREAMS + ("telegram.org",):
        assert host not in text, (
            f"{host} appears in openclaw.json — the destination allowlist must "
            f"live ONLY in the Caddy config (FP-02); a compromised openclaw "
            f"could rewrite its own destinations"
        )


# ── FP-05: webhook routes exact + fail-closed ───────────────────────────────


def test_webhook_routes_are_exact_post_paths() -> None:
    text = WEBHOOK_SNIPPET.read_text()
    assert "handle /webhooks/slack {" in text
    assert "handle /webhooks/telegram {" in text
    assert "handle /webhooks/* {" in text, "missing /webhooks/* default-deny"
    assert text.count("forward_auth https://backoffice:8443") == 2, (
        "both webhook routes must forward_auth to the verifier"
    )
    assert "/auth/verify-webhook?provider=slack" in text
    assert "/auth/verify-webhook?provider=telegram" in text
    # Never publish openclaw's whole surface.
    assert not re.search(r"reverse_proxy\s+\*?\s*http://openclaw:18789\s*$", text, re.M)
    for m in re.finditer(r"handle (/\S*)\s*\{", text):
        assert m.group(1).startswith("/webhooks/"), (
            f"webhook snippet handles unexpected path {m.group(1)}"
        )


def test_all_variants_wire_the_snippets() -> None:
    for variant in CADDY_VARIANTS:
        text = variant.read_text()
        assert "import /etc/caddy/Caddyfile.openclaw-webhooks" in text, variant.name
        assert "import openclaw-webhooks" in text, variant.name
        assert "import /etc/caddy/Caddyfile.openclaw-egress" in text, variant.name


def test_caddy_mounts_and_env(compose: dict) -> None:
    svc = compose["services"]["caddy"]
    vols = [v for v in svc["volumes"] if isinstance(v, str)]
    assert "./Caddyfile.openclaw-egress:/etc/caddy/Caddyfile.openclaw-egress:ro" in vols
    assert "./Caddyfile.openclaw-webhooks:/etc/caddy/Caddyfile.openclaw-webhooks:ro" in vols
    env = svc["environment"]
    assert "YASHIGANI_OPENCLAW_SPIFFE_ID" in env
    assert "/openclaw" in env["YASHIGANI_OPENCLAW_SPIFFE_ID"]
    assert "YASHIGANI_OPENCLAW_EGRESS" in env


# ── Helm parity (static text assertions; helm template is the CI gate) ──────


def test_helm_carries_egress_and_webhook_render() -> None:
    text = HELM_CONFIGMAPS.read_text()
    assert ":18790 {" in text, "helm caddy ConfigMap missing the :18790 egress listener"
    for host in EGRESS_UPSTREAMS:
        assert f"reverse_proxy https://{host}" in text
    assert "handle /webhooks/slack {" in text
    assert "handle /webhooks/telegram {" in text
    assert "/auth/verify-webhook?provider=" in text


def test_helm_openclaw_blanket_egress_stays_dead() -> None:
    text = HELM_NETPOL.read_text()
    assert "name: allow-openclaw-external-egress" not in text, (
        "the blanket internet-egress NetworkPolicy is back — LAURA-I1-03 regression"
    )
    assert "port: 18790" in text, "openclaw → caddy:18790 egress rule missing"
