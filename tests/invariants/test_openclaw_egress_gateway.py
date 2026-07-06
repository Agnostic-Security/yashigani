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
CADDY_ENTRYPOINT = REPO_ROOT / "docker" / "caddy" / "caddy-entrypoint.sh"
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


# ── FP-06 Phase 2: compensating controls ────────────────────────────────────


def test_telegram_bot_id_pin_present_in_egress_snippet() -> None:
    """FP-06/Phase-2: Telegram bot-ID pin matcher must be in the egress snippet,
    targeting the rewritten URI path (after handle_path strips /telegram)."""
    text = EGRESS_SNIPPET.read_text()
    # The pin matcher must reference the env var with the empty-default form.
    assert "YASHIGANI_OPENCLAW_TELEGRAM_BOT_ID:}" in text, (
        "Telegram bot-ID pin env var missing from egress snippet "
        "(must use parse-time default: {$YASHIGANI_OPENCLAW_TELEGRAM_BOT_ID:})"
    )
    # Must use the rewritten path (not orig_uri) and check the bot: prefix form.
    assert "{http.request.uri.path}" in text, (
        "Telegram pin must match {http.request.uri.path} (post-handle_path rewrite)"
    )
    assert "/bot{$YASHIGANI_OPENCLAW_TELEGRAM_BOT_ID:}:" in text, (
        "Telegram pin expression must check /bot<pinid>: path prefix"
    )
    assert '@wrong_bot_id' in text, "named matcher @wrong_bot_id missing from egress snippet"
    assert 'respond @wrong_bot_id "Forbidden" 403' in text, (
        "403 respond for @wrong_bot_id missing from egress snippet"
    )


def test_telegram_bot_id_pin_inert_when_empty() -> None:
    """FP-06/Phase-2: The pin must be inert when the env var is empty.
    The CEL expression must use the short-circuit pattern:
      "{$YASHIGANI_OPENCLAW_TELEGRAM_BOT_ID:}" != "" && !...startsWith(...)
    When env is unset, the first clause ("" != "") is false, so the matcher
    never fires and no request is blocked on a default install."""
    text = EGRESS_SNIPPET.read_text()
    # The expression must start with the empty-default guard.
    assert '"{$YASHIGANI_OPENCLAW_TELEGRAM_BOT_ID:}" != ""' in text, (
        "Telegram pin expression must guard with "
        '"{$YASHIGANI_OPENCLAW_TELEGRAM_BOT_ID:}" != "" '
        "so the matcher is inert when the var is unset"
    )
    # There must be a && (AND) to short-circuit on the empty case.
    assert "&&" in text, "Telegram pin expression must use && to short-circuit inert-when-empty"


def test_egress_audit_log_in_compose_snippet() -> None:
    """FP-06/Phase-2: :18790 site block must have a `log` directive with
    JSON format and Authorization header redaction."""
    text = EGRESS_SNIPPET.read_text()
    assert "log {" in text, "log directive missing from :18790 egress snippet"
    assert "output stderr" in text, "log output must be stderr (compose convention)"
    assert "format filter" in text, "log must use filter encoder for header redaction"
    assert "wrap json" in text, "log filter must wrap json encoder"
    assert "request>headers>Authorization delete" in text, (
        "Authorization header must be deleted from egress access log "
        "(prevents bearer tokens leaking in cleartext)"
    )


def test_egress_audit_log_in_helm_render() -> None:
    """FP-06/Phase-2: Helm :18790 block must carry the same log directive
    (compose↔Helm parity, Iris rule)."""
    text = HELM_CONFIGMAPS.read_text()
    # The log must be inside the :18790 block — check both are present
    # in the same file (the :18790 block is gated on openclaw.enabled).
    assert "log {" in text, "log directive missing from Helm :18790 render"
    assert "format filter" in text, "Helm :18790 log must use filter encoder"
    assert "request>headers>Authorization delete" in text, (
        "Helm :18790 log must redact Authorization header"
    )


def test_telegram_bot_id_pin_in_helm_render() -> None:
    """FP-06/Phase-2: Helm :18790 block must carry the bot-ID pin expression
    (compose↔Helm parity)."""
    text = HELM_CONFIGMAPS.read_text()
    # Helm renders the bot ID at template time; the pattern to check for is the
    # Helm template variable and the startsWith expression.
    assert "wrong_bot_id" in text, (
        "Helm :18790 block missing @wrong_bot_id Telegram bot-ID pin matcher"
    )
    assert "startsWith" in text, (
        "Helm :18790 Telegram pin must use startsWith expression"
    )
    assert 'respond @wrong_bot_id "Forbidden" 403' in text, (
        "Helm :18790 block missing 403 response for @wrong_bot_id"
    )


def test_slack_bot_token_dual_handle_in_egress_snippet() -> None:
    """FP-06/Phase-2 CHANNEL 2: Slack Web API bot-token workspace pin must use
    the dual-handle inert-until-set pattern in the /slack/* route."""
    text = EGRESS_SNIPPET.read_text()
    # Named matcher for the pin-on branch.
    assert "@slack_pin_on" in text, (
        "Caddyfile.openclaw-egress missing @slack_pin_on matcher "
        "(FP-06 Phase 2 CHANNEL 2 Slack bot-token pin)"
    )
    # Expression guard: token non-empty → pin active.
    assert '"{$YASHIGANI_OPENCLAW_SLACK_BOT_TOKEN:}" != ""' in text, (
        "Slack bot-token expression guard missing "
        '("{$YASHIGANI_OPENCLAW_SLACK_BOT_TOKEN:}" != "") '
        "— must short-circuit inert when var is unset"
    )
    # Pin-on branch must strip caller's Authorization and inject operator's token.
    assert "header_up -Authorization" in text, (
        "Slack bot-token pin missing `header_up -Authorization` (strip caller token)"
    )
    assert 'header_up Authorization "Bearer {$YASHIGANI_OPENCLAW_SLACK_BOT_TOKEN:}"' in text, (
        "Slack bot-token pin missing bearer inject directive"
    )
    # Fallback handle (pass-through, inert) must also be present.
    assert "handle {" in text, (
        "Fallback handle block missing (required for dual-handle inert-when-empty)"
    )


def test_slack_bot_token_pin_inert_when_empty() -> None:
    """FP-06/Phase-2 CHANNEL 2: The bot-token pin MUST NOT fire when the env var
    is empty or unset. The guard expression must short-circuit on empty."""
    text = EGRESS_SNIPPET.read_text()
    # The && short-circuit guard must be present.
    assert (
        '"{$YASHIGANI_OPENCLAW_SLACK_BOT_TOKEN:}" != ""' in text
        and "handle @slack_pin_on" in text
    ), (
        "Slack bot-token pin is missing the inert-when-empty guard: "
        '"{$YASHIGANI_OPENCLAW_SLACK_BOT_TOKEN:}" != "" must gate @slack_pin_on'
    )


def test_slack_webhook_path_pin_in_egress_snippet() -> None:
    """FP-06/Phase-2 CHANNEL 1: Slack incoming-webhook path pin must be present
    in the /slack-hooks/* route with the correct startsWith expression."""
    text = EGRESS_SNIPPET.read_text()
    assert "@wrong_slack_hook" in text, (
        "Caddyfile.openclaw-egress missing @wrong_slack_hook matcher "
        "(FP-06 Phase 2 CHANNEL 1 Slack webhook-path pin)"
    )
    assert '"{$YASHIGANI_OPENCLAW_SLACK_WEBHOOK_PATH:}" != ""' in text, (
        "Slack webhook-path expression guard missing — must be inert when empty"
    )
    assert 'startsWith("{$YASHIGANI_OPENCLAW_SLACK_WEBHOOK_PATH:}")' in text, (
        "Slack webhook-path pin missing startsWith expression "
        "(must pin to the operator's /services/T.../B.../<secret> path)"
    )
    assert 'respond @wrong_slack_hook "Forbidden" 403' in text, (
        "403 response for @wrong_slack_hook missing from egress snippet"
    )


def test_slack_webhook_path_pin_inert_when_empty() -> None:
    """FP-06/Phase-2 CHANNEL 1: The webhook-path pin must not fire when the env
    var is empty. The && guard must short-circuit on empty."""
    text = EGRESS_SNIPPET.read_text()
    assert (
        '"{$YASHIGANI_OPENCLAW_SLACK_WEBHOOK_PATH:}" != ""' in text
        and "&&" in text
    ), (
        "Slack webhook-path pin missing && short-circuit guard: "
        '"{$YASHIGANI_OPENCLAW_SLACK_WEBHOOK_PATH:}" != "" && !...startsWith(...)'
    )


def test_slack_secrets_exported_in_entrypoint() -> None:
    """FP-06/Phase-2: caddy-entrypoint.sh must read both Slack secret files and
    export them as parse-time env vars before exec caddy (single-source; not in
    compose env)."""
    text = CADDY_ENTRYPOINT.read_text()
    assert "openclaw_slack_webhook_path" in text, (
        "caddy-entrypoint.sh must read /run/secrets/openclaw_slack_webhook_path "
        "(CHANNEL 1 webhook-path pin secret file)"
    )
    assert "openclaw_slack_bot_token" in text, (
        "caddy-entrypoint.sh must read /run/secrets/openclaw_slack_bot_token "
        "(CHANNEL 2 bot-token pin secret file)"
    )
    assert "YASHIGANI_OPENCLAW_SLACK_WEBHOOK_PATH" in text, (
        "caddy-entrypoint.sh must export YASHIGANI_OPENCLAW_SLACK_WEBHOOK_PATH "
        "so Caddy can substitute {$YASHIGANI_OPENCLAW_SLACK_WEBHOOK_PATH:} at parse time"
    )
    assert "YASHIGANI_OPENCLAW_SLACK_BOT_TOKEN" in text, (
        "caddy-entrypoint.sh must export YASHIGANI_OPENCLAW_SLACK_BOT_TOKEN "
        "so Caddy can substitute {$YASHIGANI_OPENCLAW_SLACK_BOT_TOKEN:} at parse time"
    )
    assert "export YASHIGANI_OPENCLAW_SLACK_WEBHOOK_PATH" in text, (
        "caddy-entrypoint.sh must `export YASHIGANI_OPENCLAW_SLACK_WEBHOOK_PATH` "
        "(not just set — Caddy must inherit from the process env)"
    )
    assert "export YASHIGANI_OPENCLAW_SLACK_BOT_TOKEN" in text, (
        "caddy-entrypoint.sh must `export YASHIGANI_OPENCLAW_SLACK_BOT_TOKEN`"
    )


def test_slack_secret_files_accessible_to_caddy_in_compose(compose: dict) -> None:
    """FP-06/Phase-2: Both Slack secret files must be accessible to the Caddy
    container via the flat ./secrets bind-mount (no per-file bind needed since
    the flat mount already covers docker/secrets/)."""
    svc = compose["services"]["caddy"]
    vols = [v for v in svc["volumes"] if isinstance(v, str)]
    # The flat bind-mount covers openclaw_slack_{webhook_path,bot_token}
    assert any(
        v.startswith("./secrets:/run/secrets") for v in vols
    ), (
        "Caddy service missing ./secrets:/run/secrets bind-mount — "
        "openclaw_slack_{webhook_path,bot_token} would not be accessible"
    )
    # The Slack env vars must NOT be declared in compose environment: — they
    # must come ONLY from the secret files via caddy-entrypoint.sh export.
    env = svc.get("environment", {})
    assert "YASHIGANI_OPENCLAW_SLACK_WEBHOOK_PATH" not in env, (
        "YASHIGANI_OPENCLAW_SLACK_WEBHOOK_PATH must NOT be in compose environment: "
        "(must come from /run/secrets/openclaw_slack_webhook_path via entrypoint)"
    )
    assert "YASHIGANI_OPENCLAW_SLACK_BOT_TOKEN" not in env, (
        "YASHIGANI_OPENCLAW_SLACK_BOT_TOKEN must NOT be in compose environment: "
        "(must come from /run/secrets/openclaw_slack_bot_token via entrypoint)"
    )


def test_install_provisions_slack_secret_files() -> None:
    """FP-06/Phase-2: install.sh must provision both Slack operator-config secret
    files (empty on default install = inert; operator supplies values to enable)."""
    install_sh = (REPO_ROOT / "install.sh").read_text()
    assert "openclaw_slack_webhook_path" in install_sh, (
        "install.sh must provision openclaw_slack_webhook_path secret file "
        "(CHANNEL 1 incoming-webhook path pin)"
    )
    assert "openclaw_slack_bot_token" in install_sh, (
        "install.sh must provision openclaw_slack_bot_token secret file "
        "(CHANNEL 2 bot-token pin)"
    )
    assert "YASHIGANI_OPENCLAW_SLACK_WEBHOOK_PATH" in install_sh, (
        "install.sh must read YASHIGANI_OPENCLAW_SLACK_WEBHOOK_PATH env var "
        "for operator-supplied webhook path"
    )
    assert "YASHIGANI_OPENCLAW_SLACK_BOT_TOKEN" in install_sh, (
        "install.sh must read YASHIGANI_OPENCLAW_SLACK_BOT_TOKEN env var "
        "for operator-supplied bot token"
    )


def test_slack_enforcement_in_helm_render() -> None:
    """FP-06/Phase-2 compose↔Helm parity: both Slack enforcement blocks must be
    present in the Helm :18790 render (configmaps.yaml)."""
    text = HELM_CONFIGMAPS.read_text()
    # CHANNEL 1: webhook-path pin
    assert "@wrong_slack_hook" in text, (
        "Helm :18790 block missing @wrong_slack_hook matcher (CHANNEL 1 parity)"
    )
    assert '"{$YASHIGANI_OPENCLAW_SLACK_WEBHOOK_PATH:}" != ""' in text, (
        "Helm :18790 block missing CHANNEL 1 inert-when-empty guard"
    )
    assert 'startsWith("{$YASHIGANI_OPENCLAW_SLACK_WEBHOOK_PATH:}")' in text, (
        "Helm :18790 block missing CHANNEL 1 startsWith expression"
    )
    assert 'respond @wrong_slack_hook "Forbidden" 403' in text, (
        "Helm :18790 block missing CHANNEL 1 403 respond"
    )
    # CHANNEL 2: bot-token dual-handle
    assert "@slack_pin_on" in text, (
        "Helm :18790 block missing @slack_pin_on matcher (CHANNEL 2 parity)"
    )
    assert '"{$YASHIGANI_OPENCLAW_SLACK_BOT_TOKEN:}" != ""' in text, (
        "Helm :18790 block missing CHANNEL 2 inert-when-empty guard"
    )
    assert 'header_up -Authorization' in text, (
        "Helm :18790 block missing `header_up -Authorization` (CHANNEL 2 strip)"
    )
    assert 'header_up Authorization "Bearer {$YASHIGANI_OPENCLAW_SLACK_BOT_TOKEN:}"' in text, (
        "Helm :18790 block missing CHANNEL 2 bearer inject"
    )


def test_slack_not_in_openclaw_config() -> None:
    """FP-02 extension: Slack bot token and webhook path must NOT appear in
    openclaw.json — a compromised openclaw must not be able to rewrite its own
    destination account."""
    text = OPENCLAW_JSON.read_text()
    assert "SLACK_BOT_TOKEN" not in text, (
        "Slack bot token reference found in openclaw.json — single-source violation "
        "(FP-02 extension: destination account must be perimeter-owned)"
    )
    assert "SLACK_WEBHOOK_PATH" not in text, (
        "Slack webhook path reference found in openclaw.json — single-source violation"
    )


def test_iptables_hashlimit_in_entrypoint() -> None:
    """FP-06/Phase-2: caddy-entrypoint.sh must contain hashlimit rules for the
    openclaw egress hosts, with a fail-soft fallback and tunable env vars."""
    text = CADDY_ENTRYPOINT.read_text()
    assert "hashlimit" in text, (
        "iptables hashlimit rule missing from caddy-entrypoint.sh "
        "(FP-06 Phase 2 egress rate-brake)"
    )
    assert "hashlimit-upto" in text, (
        "hashlimit-upto flag missing — rate is not configured"
    )
    assert "YASHIGANI_OPENCLAW_EGRESS_RATE_LIMIT" in text, (
        "tunable YASHIGANI_OPENCLAW_EGRESS_RATE_LIMIT env var missing"
    )
    assert "YASHIGANI_OPENCLAW_EGRESS_RATE_BURST" in text, (
        "tunable YASHIGANI_OPENCLAW_EGRESS_RATE_BURST env var missing"
    )
    # Fail-soft: must fall back to plain ACCEPT if hashlimit module is missing.
    assert "plain ACCEPT" in text or "fallback" in text.lower(), (
        "hashlimit block must have a fail-soft fallback to plain ACCEPT "
        "for kernels without the hashlimit module"
    )
    # The rate-brake must be gated on YASHIGANI_OPENCLAW_EGRESS=1.
    assert "_openclaw_egress_active" in text, (
        "hashlimit rules must be gated on _openclaw_egress_active "
        "(only when YASHIGANI_OPENCLAW_EGRESS=1)"
    )
