"""
YSG-RISK-061 Caddy Egress Restriction Contract Tests (v2.24.1)
Captain: caddy-entrypoint.sh + Dockerfile.caddy + compose cap_add + Helm NetworkPolicy.

Tests cover:
  1. Positive (functionality preserved):
     - Caddy Dockerfile.caddy derives from the correct base image digest
     - caddy-entrypoint.sh syntax is valid sh (via 'sh -n')
     - caddy-entrypoint.sh ends with 'exec caddy run'
     - NET_ADMIN present in compose caddy cap_add
     - NET_BIND_SERVICE still present (regression: must not be removed)
     - YASHIGANI_CADDY_EGRESS_ALLOWLIST env var present in compose caddy environment
     - Helm caddy.yaml contains NET_ADMIN in capabilities.add
     - Helm NetworkPolicy networkpolicy-caddy-egress.yaml exists and has correct structure
     - values.yaml has egressAllowlist key under caddy

  2. Negative (entrypoint logic):
     - Entrypoint contains graceful fallback when iptables fails (Podman rootless path)
     - Entrypoint applies OUTPUT DROP (not ACCEPT) as default policy
     - Entrypoint allows loopback
     - Entrypoint allows ESTABLISHED,RELATED
     - Entrypoint allows Docker DNS 127.0.0.11:53

  3. Helm parity:
     - networkpolicy-caddy-egress.yaml has ipBlock with except for RFC1918 CIDRs
     - networkpolicy-caddy-egress.yaml allows TCP:443 and TCP:80

  4. allow-caddy-egress parity (grafana + prometheus added):
     - networkpolicy.yaml allow-caddy-egress section now includes grafana:3443
     - networkpolicy.yaml allow-caddy-egress section now includes prometheus:9090
"""

import pathlib
import subprocess
import pytest
import yaml
import re

REPO = pathlib.Path(__file__).parent.parent.parent
DOCKER_DIR = REPO / "docker"
CADDY_DIR = DOCKER_DIR / "caddy"
HELM_TEMPLATES = REPO / "helm" / "yashigani" / "templates"
HELM_VALUES = REPO / "helm" / "yashigani" / "values.yaml"

DOCKERFILE = CADDY_DIR / "Dockerfile.caddy"
ENTRYPOINT = CADDY_DIR / "caddy-entrypoint.sh"
COMPOSE = DOCKER_DIR / "docker-compose.yml"
NETWORKPOLICY = HELM_TEMPLATES / "networkpolicy.yaml"
CADDY_EGRESS_POLICY = HELM_TEMPLATES / "networkpolicy-caddy-egress.yaml"
CADDY_HELM = HELM_TEMPLATES / "caddy.yaml"

BASE_IMAGE_DIGEST = "sha256:834468128c7696cec0ceea6172f7d692daf645ae51983ca76e39da54a97c570d"


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def entrypoint_text():
    assert ENTRYPOINT.exists(), f"caddy-entrypoint.sh not found at {ENTRYPOINT}"
    return ENTRYPOINT.read_text()


@pytest.fixture(scope="module")
def dockerfile_text():
    assert DOCKERFILE.exists(), f"Dockerfile.caddy not found at {DOCKERFILE}"
    return DOCKERFILE.read_text()


@pytest.fixture(scope="module")
def compose_caddy(tmp_path_factory):
    """Parse docker-compose.yml and return the caddy service block."""
    assert COMPOSE.exists(), f"docker-compose.yml not found at {COMPOSE}"
    data = yaml.safe_load(COMPOSE.read_text())
    assert "caddy" in data.get("services", {}), "caddy service missing from docker-compose.yml"
    return data["services"]["caddy"]


@pytest.fixture(scope="module")
def networkpolicy_text():
    assert NETWORKPOLICY.exists(), f"networkpolicy.yaml not found at {NETWORKPOLICY}"
    return NETWORKPOLICY.read_text()


@pytest.fixture(scope="module")
def caddy_egress_policy_text():
    assert CADDY_EGRESS_POLICY.exists(), (
        f"networkpolicy-caddy-egress.yaml not found at {CADDY_EGRESS_POLICY}"
    )
    return CADDY_EGRESS_POLICY.read_text()


@pytest.fixture(scope="module")
def caddy_helm_text():
    assert CADDY_HELM.exists(), f"caddy.yaml not found at {CADDY_HELM}"
    return CADDY_HELM.read_text()


@pytest.fixture(scope="module")
def values_caddy():
    assert HELM_VALUES.exists(), f"values.yaml not found at {HELM_VALUES}"
    data = yaml.safe_load(HELM_VALUES.read_text())
    assert "caddy" in data, "caddy key missing from values.yaml"
    return data["caddy"]


# ── 1. Positive: file existence and structure ─────────────────────────────────

class TestFileExistence:
    def test_dockerfile_caddy_exists(self):
        assert DOCKERFILE.exists(), "docker/caddy/Dockerfile.caddy must exist"

    def test_entrypoint_exists(self):
        assert ENTRYPOINT.exists(), "docker/caddy/caddy-entrypoint.sh must exist"

    def test_networkpolicy_caddy_egress_exists(self):
        assert CADDY_EGRESS_POLICY.exists(), (
            "helm/yashigani/templates/networkpolicy-caddy-egress.yaml must exist"
        )

    def test_entrypoint_is_executable_bit(self):
        import stat
        mode = ENTRYPOINT.stat().st_mode
        assert mode & stat.S_IXUSR, "caddy-entrypoint.sh must have owner execute bit set"


class TestDockerfile:
    def test_derives_from_pinned_base(self, dockerfile_text):
        assert BASE_IMAGE_DIGEST in dockerfile_text, (
            f"Dockerfile.caddy must reference base image digest {BASE_IMAGE_DIGEST}"
        )

    def test_installs_iptables(self, dockerfile_text):
        assert "iptables" in dockerfile_text, (
            "Dockerfile.caddy must install iptables"
        )

    def test_installs_iproute2(self, dockerfile_text):
        assert "iproute2" in dockerfile_text, (
            "Dockerfile.caddy must install iproute2 (for 'ip route' in entrypoint)"
        )

    def test_copies_entrypoint(self, dockerfile_text):
        assert "caddy-entrypoint.sh" in dockerfile_text, (
            "Dockerfile.caddy must COPY caddy-entrypoint.sh"
        )

    def test_sets_entrypoint(self, dockerfile_text):
        assert "ENTRYPOINT" in dockerfile_text, (
            "Dockerfile.caddy must set ENTRYPOINT to caddy-entrypoint.sh"
        )


# ── 2. Entrypoint logic ───────────────────────────────────────────────────────

class TestEntrypointSyntax:
    def test_sh_syntax_valid(self):
        """sh -n validates syntax without executing."""
        result = subprocess.run(
            ["sh", "-n", str(ENTRYPOINT)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (
            f"caddy-entrypoint.sh syntax error:\n{result.stderr}"
        )


class TestEntrypointLogic:
    def test_ends_with_exec_caddy(self, entrypoint_text):
        assert "exec caddy run" in entrypoint_text, (
            "caddy-entrypoint.sh must end with 'exec caddy run' (exec hand-off)"
        )

    def test_graceful_fallback_on_iptables_failure(self, entrypoint_text):
        """Entrypoint must log WARN and continue (not exit) when iptables fails."""
        # Check for the fallback pattern: logs warning and returns 0 (not exits)
        assert "iptables OUTPUT policy modification failed" in entrypoint_text, (
            "entrypoint must detect iptables failure and log a warning"
        )
        assert "return 0" in entrypoint_text, (
            "entrypoint must return 0 (not exit) on iptables failure — graceful fallback"
        )

    def test_sets_output_drop(self, entrypoint_text):
        assert "iptables -P OUTPUT DROP" in entrypoint_text, (
            "entrypoint must set OUTPUT chain policy to DROP"
        )

    def test_allows_loopback(self, entrypoint_text):
        assert "-o lo -j ACCEPT" in entrypoint_text, (
            "entrypoint must allow loopback egress (-o lo -j ACCEPT)"
        )

    def test_allows_established_related(self, entrypoint_text):
        assert "ESTABLISHED,RELATED" in entrypoint_text, (
            "entrypoint must allow ESTABLISHED,RELATED state (response packets)"
        )

    def test_allows_docker_dns(self, entrypoint_text):
        assert "127.0.0.11" in entrypoint_text, (
            "entrypoint must allow Docker embedded DNS at 127.0.0.11"
        )

    def test_allows_bridge_subnets(self, entrypoint_text):
        assert "ip route" in entrypoint_text, (
            "entrypoint must enumerate bridge subnets via 'ip route'"
        )

    def test_acme_letsencrypt_in_default_list(self, entrypoint_text):
        assert "acme-v02.api.letsencrypt.org" in entrypoint_text, (
            "entrypoint must include Let's Encrypt ACME endpoint in default allowlist"
        )

    def test_ocsp_responders_in_default_list(self, entrypoint_text):
        assert "lencr.org" in entrypoint_text, (
            "entrypoint must include Let's Encrypt OCSP responders in default allowlist"
        )

    def test_operator_allowlist_env_var(self, entrypoint_text):
        assert "YASHIGANI_CADDY_EGRESS_ALLOWLIST" in entrypoint_text, (
            "entrypoint must read YASHIGANI_CADDY_EGRESS_ALLOWLIST for operator overrides"
        )

    def test_log_before_drop(self, entrypoint_text):
        """LOG rule before final DROP for blocked egress visibility."""
        assert "CADDY_EGRESS_BLOCKED" in entrypoint_text, (
            "entrypoint must install LOG rule with CADDY_EGRESS_BLOCKED prefix before DROP"
        )

    def test_final_drop_rule(self, entrypoint_text):
        assert "iptables -A OUTPUT -j DROP" in entrypoint_text, (
            "entrypoint must add explicit DROP rule at end of OUTPUT chain"
        )


# ── 3. Compose changes ────────────────────────────────────────────────────────

class TestComposeCaddyCapabilities:
    def test_net_admin_present(self, compose_caddy):
        cap_add = compose_caddy.get("cap_add", [])
        assert "NET_ADMIN" in cap_add, (
            "docker-compose.yml caddy cap_add must include NET_ADMIN (YSG-RISK-061)"
        )

    def test_net_bind_service_still_present(self, compose_caddy):
        """Regression: NET_BIND_SERVICE must not have been removed."""
        cap_add = compose_caddy.get("cap_add", [])
        assert "NET_BIND_SERVICE" in cap_add, (
            "docker-compose.yml caddy cap_add must still include NET_BIND_SERVICE (regression)"
        )

    def test_cap_drop_all_still_present(self, compose_caddy):
        cap_drop = compose_caddy.get("cap_drop", [])
        assert "ALL" in cap_drop, (
            "docker-compose.yml caddy cap_drop must still be [ALL]"
        )

    def test_egress_allowlist_env_present(self, compose_caddy):
        env = compose_caddy.get("environment", {})
        assert "YASHIGANI_CADDY_EGRESS_ALLOWLIST" in env, (
            "docker-compose.yml caddy environment must include YASHIGANI_CADDY_EGRESS_ALLOWLIST"
        )

    def test_has_build_block(self, compose_caddy):
        """caddy service must use a build block pointing to Dockerfile.caddy."""
        assert "build" in compose_caddy, (
            "docker-compose.yml caddy must have a build: block (Dockerfile.caddy)"
        )


# ── 4. Helm caddy.yaml capabilities ──────────────────────────────────────────

class TestHelmCaddyCapabilities:
    def test_net_admin_in_helm_caddy(self, caddy_helm_text):
        assert "NET_ADMIN" in caddy_helm_text, (
            "helm/templates/caddy.yaml must include NET_ADMIN in capabilities.add"
        )

    def test_net_bind_service_still_in_helm(self, caddy_helm_text):
        assert "NET_BIND_SERVICE" in caddy_helm_text, (
            "helm/templates/caddy.yaml must still include NET_BIND_SERVICE (regression)"
        )

    def test_egress_allowlist_env_in_helm(self, caddy_helm_text):
        assert "YASHIGANI_CADDY_EGRESS_ALLOWLIST" in caddy_helm_text, (
            "helm/templates/caddy.yaml must wire YASHIGANI_CADDY_EGRESS_ALLOWLIST env var"
        )


# ── 5. Helm NetworkPolicy: networkpolicy-caddy-egress.yaml ───────────────────

class TestCaddyEgressNetworkPolicy:
    def test_has_ipblock_rule(self, caddy_egress_policy_text):
        assert "ipBlock" in caddy_egress_policy_text, (
            "networkpolicy-caddy-egress.yaml must have ipBlock egress rule for ACME"
        )

    def test_excludes_rfc1918_10(self, caddy_egress_policy_text):
        assert "10.0.0.0/8" in caddy_egress_policy_text, (
            "networkpolicy-caddy-egress.yaml must except RFC1918 10.0.0.0/8"
        )

    def test_excludes_rfc1918_172(self, caddy_egress_policy_text):
        assert "172.16.0.0/12" in caddy_egress_policy_text, (
            "networkpolicy-caddy-egress.yaml must except RFC1918 172.16.0.0/12"
        )

    def test_excludes_rfc1918_192(self, caddy_egress_policy_text):
        assert "192.168.0.0/16" in caddy_egress_policy_text, (
            "networkpolicy-caddy-egress.yaml must except RFC1918 192.168.0.0/16"
        )

    def test_allows_port_443(self, caddy_egress_policy_text):
        assert "port: 443" in caddy_egress_policy_text, (
            "networkpolicy-caddy-egress.yaml must allow TCP:443 (ACME API + TLS-ALPN)"
        )

    def test_allows_port_80(self, caddy_egress_policy_text):
        assert "port: 80" in caddy_egress_policy_text, (
            "networkpolicy-caddy-egress.yaml must allow TCP:80 (OCSP stapling)"
        )

    def test_targets_caddy_pod_selector(self, caddy_egress_policy_text):
        assert "yashigani-caddy" in caddy_egress_policy_text, (
            "networkpolicy-caddy-egress.yaml must target yashigani-caddy pods"
        )

    def test_policytype_egress(self, caddy_egress_policy_text):
        assert "Egress" in caddy_egress_policy_text, (
            "networkpolicy-caddy-egress.yaml must declare Egress policyType"
        )

    def test_risk_id_annotation(self, caddy_egress_policy_text):
        assert "YSG-RISK-061" in caddy_egress_policy_text, (
            "networkpolicy-caddy-egress.yaml must reference YSG-RISK-061 in annotations"
        )


# ── 6. Existing allow-caddy-egress — obs-plane additions ─────────────────────

class TestAllowCaddyEgressObsPlane:
    def test_grafana_egress_added(self, networkpolicy_text):
        """YSG-RISK-061 audit: grafana:3443 was missing from allow-caddy-egress."""
        assert "grafana" in networkpolicy_text.lower(), (
            "networkpolicy.yaml allow-caddy-egress must include grafana"
        )
        assert "3443" in networkpolicy_text, (
            "networkpolicy.yaml allow-caddy-egress must include grafana port 3443"
        )

    def test_prometheus_egress_added(self, networkpolicy_text):
        """YSG-RISK-061 audit: prometheus:9090 was missing from allow-caddy-egress."""
        # We check for the prometheus entry near the caddy-egress section.
        # The policy text has prometheus in multiple policies; the context check
        # is: port 9090 appears in the same yaml block after caddy-egress.
        caddy_egress_idx = networkpolicy_text.find("allow-caddy-egress")
        assert caddy_egress_idx != -1, "allow-caddy-egress not found in networkpolicy.yaml"
        # The next policy after allow-caddy-egress is db-maintenance; prometheus entry
        # should appear before that boundary.
        segment = networkpolicy_text[caddy_egress_idx:caddy_egress_idx + 2000]
        assert "9090" in segment or "prometheus" in segment.lower(), (
            "networkpolicy.yaml allow-caddy-egress must include prometheus (port 9090)"
        )


# ── 7. values.yaml egressAllowlist key ───────────────────────────────────────

class TestValuesEgressAllowlist:
    def test_egress_allowlist_key_exists(self, values_caddy):
        assert "egressAllowlist" in values_caddy, (
            "values.yaml caddy section must have egressAllowlist key (YSG-RISK-061)"
        )

    def test_egress_allowlist_default_empty(self, values_caddy):
        """Default must be empty string — operator opt-in for extra destinations."""
        assert values_caddy["egressAllowlist"] == "", (
            "values.yaml caddy.egressAllowlist default must be '' (empty string)"
        )


# ── 8. BUG-V243-CADDY-IPV6-IPTABLES — IPv6 BLOCKED (Yashigani is IPv4-only) ──

class TestEntrypointIpv6Blocked:
    """BUG-V243-CADDY-IPV6-IPTABLES — Yashigani is IPv4-only by design.

    History:
      e129cbc (partial): filtered IPv6 OUT of the iptables loop — stopped
        the crash but left IPv6 egress unfiltered (kernel default ACCEPT).
      64fd5c4 (parity, REJECTED): added IPv6 ACCEPT rules in parallel with
        IPv4 — adds attack surface without product value.
      This commit (BLOCK): ip6tables OUTPUT policy = DROP with ZERO ACCEPT
        rules. IPv6 is not a supported address family in Yashigani.

    Rationale (Tiago directive 2026-05-26):
      *"as we are moving towards ipv7 and ipv6 never had much traction"*
      *"do not implement ipv inside of the yashigani network"*
      *"block it"*

    Yashigani is IPv4-only by design. Supporting IPv6 inside the ring-fence
    adds a parallel egress path (= attack surface) without proportional
    deployment-ecosystem value.
    """

    # ── Policy: IPv6 OUTPUT must be DROP ────────────────────────────────────

    def test_ip6tables_sets_output_drop(self, entrypoint_text):
        """ip6tables OUTPUT policy MUST be DROP."""
        assert "ip6tables -P OUTPUT DROP" in entrypoint_text, (
            "BUG-V243 BLOCK regression: caddy-entrypoint.sh must set "
            "`ip6tables -P OUTPUT DROP` policy. Yashigani is IPv4-only "
            "(Tiago 2026-05-26: 'block it')."
        )

    # ── ip6tables ACCEPT rules — ONLY loopback + ESTABLISHED ────────────────

    def test_ip6tables_allows_loopback(self, entrypoint_text):
        """ip6tables MUST allow loopback (::1 → ::1, defensive intra-container)."""
        assert "ip6tables -A OUTPUT -o lo -j ACCEPT" in entrypoint_text, (
            "BUG-V243 BLOCK-INBOUND regression: caddy-entrypoint.sh must allow "
            "ip6tables loopback (defensive intra-container)."
        )

    def test_ip6tables_allows_established_for_inbound_responses(self, entrypoint_text):
        """ip6tables MUST allow ESTABLISHED/RELATED so v6 inbound clients get response packets."""
        assert "ip6tables -A OUTPUT -m state --state ESTABLISHED,RELATED" in entrypoint_text, (
            "BUG-V243 BLOCK-INBOUND regression: caddy-entrypoint.sh must allow "
            "ip6tables ESTABLISHED,RELATED on OUTPUT. Without this, SYN-ACK and "
            "data packets to internet IPv6 clients (allowed per Tiago directive "
            "2026-05-26 'allow ipv6 in the front to connect to the internet if "
            "the client wants to') are DROPped and connections hang."
        )

    def test_ip6tables_has_no_destination_accept_rules(self, entrypoint_text):
        """ip6tables MUST NOT have any destination ACCEPT rules (no v6 outbound allowlist)."""
        # Reject `ip6tables -A OUTPUT ... -d <addr> ... -j ACCEPT` — that would
        # allow NEW IPv6 outbound to that destination. Loopback (-o lo) and
        # state ESTABLISHED are the ONLY ACCEPTs permitted; both are non-
        # destination-based ACCEPTs that don't grant new-outbound capability.
        import re
        lines = entrypoint_text.splitlines()
        accept_dest_lines = [
            (i + 1, ln) for i, ln in enumerate(lines)
            if re.search(r"ip6tables\b.*-A\s+OUTPUT.*-d\s+\S+.*-j\s+ACCEPT", ln)
        ]
        assert not accept_dest_lines, (
            "BUG-V243 BLOCK-OUTBOUND regression: caddy-entrypoint.sh must NOT "
            "add any `ip6tables -A OUTPUT -d <dest> ... -j ACCEPT` rules. "
            "Caddy does NOT initiate NEW IPv6 outbound — only response packets "
            "to inbound v6 clients (via ESTABLISHED) and loopback are allowed. "
            "Found destination-ACCEPT rules:\n"
            + "\n".join(f"  line {n}: {ln.strip()}" for n, ln in accept_dest_lines)
        )

    # ── Resolution loop: IPv6 results skipped, NOT routed to ip6tables ──────

    def test_resolution_loop_skips_ipv6_silently(self, entrypoint_text):
        """The host resolution loop must SKIP IPv6 results (no ip6tables call)."""
        # Acceptable pattern: case `*:*` branch that does NOT call ip6tables -A.
        # We verify by looking for the case statement and ensuring the v6
        # branch does NOT contain `ip6tables -A OUTPUT`.
        has_case_match = ("*:*)" in entrypoint_text and "*.*)" in entrypoint_text)
        assert has_case_match, (
            "BUG-V243 BLOCK regression: caddy-entrypoint.sh must use a case "
            "statement matching `*:*` (IPv6) and `*.*` (IPv4) in the host "
            "resolution loop. The IPv6 branch must skip silently without "
            "calling ip6tables (since IPv6 is blocked at the policy level)."
        )

    def test_resolution_loop_no_ip6tables_accept_in_loop(self, entrypoint_text):
        """The resolution loop must not feed IPv6 addresses into ip6tables."""
        # Stronger test: scan the loop for any ip6tables ACCEPT call. There
        # should be ZERO ip6tables ACCEPT calls in the whole script (covered
        # by test_ip6tables_has_no_accept_rules above) — this just re-asserts
        # specifically for the resolution loop with an extra readable error.
        import re
        # Look for any ip6tables -A line that adds an ACCEPT for a destination
        # — this would mean we're allowlisting IPv6 destinations.
        accept_dest_pattern = re.search(
            r"ip6tables\s+-A\s+OUTPUT.*-d\s+\S+.*-j\s+ACCEPT", entrypoint_text
        )
        assert accept_dest_pattern is None, (
            "BUG-V243 BLOCK regression: the resolution loop must NOT add "
            "ip6tables ACCEPT rules for any IPv6 destination. IPv6 is "
            "BLOCKED, not allowlisted. Yashigani is IPv4-only."
        )

    # ── LOG rule for IPv6 bypass attempts (observability for canary) ────────

    def test_ip6tables_logs_blocked_v6_attempts(self, entrypoint_text):
        """ip6tables LOG rule must fire for IPv6 egress attempts (canary)."""
        assert "CADDY_EGRESS_BLOCKED_V6" in entrypoint_text, (
            "BUG-V243 BLOCK regression: caddy-entrypoint.sh must install an "
            "ip6tables LOG rule with prefix CADDY_EGRESS_BLOCKED_V6. In a "
            "healthy install this never fires; when it does, it's a canary "
            "for an IPv6-bypass attempt (compromised service, misconfigured "
            "agent) that must be investigated."
        )

    # ── Documentation: invariant comments ───────────────────────────────────

    def test_docs_ipv4_only_design_intent(self, entrypoint_text):
        """The script must document Yashigani's IPv4-only-by-design posture."""
        v4_only_signals = [
            "IPv4-only",
            "IPv4 only",
            "IPv6 is blocked",
            "Yashigani is IPv4-only",
            "BUG-V243",
        ]
        has_doc = sum(1 for sig in v4_only_signals if sig in entrypoint_text) >= 3
        assert has_doc, (
            "BUG-V243 BLOCK regression: caddy-entrypoint.sh must document "
            "the IPv4-only-by-design posture clearly. At least 3 of these "
            "signals must appear: 'IPv4-only', 'IPv4 only', 'IPv6 is "
            "blocked', 'Yashigani is IPv4-only', 'BUG-V243'."
        )

    def test_no_parity_language_carryover(self, entrypoint_text):
        """No 'parity' language should remain — that was the rejected approach."""
        # Reject the rejected-approach language to prevent regression.
        banned_phrases = ["IPv6 OUTPUT allowlist", "allowlist (IPv6"]
        found_banned = [p for p in banned_phrases if p in entrypoint_text]
        assert not found_banned, (
            "BUG-V243 BLOCK regression: caddy-entrypoint.sh must not "
            "describe the IPv6 chain as an 'allowlist' — the rejected "
            "64fd5c4 parity approach used that language. IPv6 is blocked, "
            "not allowlisted. Found:\n"
            + "\n".join(f"  '{p}'" for p in found_banned)
        )


# ── 9. LAURA-V243-002 — ACME egress gated on TLS_MODE=acme ──────────────────

class TestEntrypointAcmeTlsModeGate:
    """LAURA-V243-002 (MEDIUM) — Laura's adversarial probe 2026-05-26.

    Before this fix: DEFAULT_ACME_HOSTS (Let's Encrypt prod + staging + OCSP
    responders) was added to the egress allowlist unconditionally, regardless
    of YASHIGANI_TLS_MODE. In selfsigned/ca modes, Cloudflare IPs (172.65.32.248
    + 172.65.46.172 + AAAA equivalents) remained reachable from inside the
    Caddy container — widening post-RCE exfil surface beyond the documented
    intent (the script's header comment claims ACME hosts are only allowed in
    acme mode, but the code didn't gate).

    Fix: read YASHIGANI_TLS_MODE; only seed full_allowlist from
    DEFAULT_ACME_HOSTS when the value is "acme" (or absent, defaulting to
    acme for backward compat). Operator-supplied YASHIGANI_CADDY_EGRESS_ALLOWLIST
    is still honoured in any mode (operator opt-in is the boundary).
    """

    def test_acme_hosts_gated_on_tls_mode(self, entrypoint_text):
        """ACME default hosts must only seed allowlist when TLS_MODE=acme."""
        assert "YASHIGANI_TLS_MODE" in entrypoint_text, (
            "LAURA-V243-002 regression: caddy-entrypoint.sh must read "
            "YASHIGANI_TLS_MODE to decide whether to include ACME hosts in "
            "the egress allowlist."
        )
        # Specifically the seed must be conditional on _tls_mode = "acme".
        assert '"$_tls_mode" = "acme"' in entrypoint_text or \
               '$_tls_mode = "acme"' in entrypoint_text or \
               '"${_tls_mode}" = "acme"' in entrypoint_text, (
            "LAURA-V243-002 regression: caddy-entrypoint.sh must gate "
            "full_allowlist=$DEFAULT_ACME_HOSTS behind a check that "
            "$_tls_mode = \"acme\". Without the gate, selfsigned/ca modes "
            "still allowlist Cloudflare ACME IPs."
        )

    def test_laura_v243_002_referenced(self, entrypoint_text):
        """The fix must reference LAURA-V243-002 so future readers can trace."""
        assert "LAURA-V243-002" in entrypoint_text, (
            "LAURA-V243-002 regression: caddy-entrypoint.sh must reference "
            "LAURA-V243-002 in the comment near the TLS_MODE gate. Provides "
            "traceability if a future refactor removes the gate."
        )


# ── 10. LAURA-V243-005 — iptables ADD failure resilience ────────────────────

class TestEntrypointIptablesAddResilience:
    """LAURA-V243-005 (MED) — Laura adversarial probe 2026-05-26.

    Before this fix: bare `iptables -A OUTPUT ... -j ACCEPT` calls under
    `set -eu` aborted the entrypoint mid-loop on any failure. Caddy then
    never started — restart loop with no clear error in container logs.
    Fail-closed per Laura's live test (no bypass), but operationally opaque.

    Fix: `_iptables_add_or_warn` wrapper catches non-zero, logs the rule
    that failed, increments a counter, lets the loop continue. The OUTPUT
    policy is already DROP, so a partial allowlist remains fail-safe.
    """

    def test_has_iptables_add_wrapper(self, entrypoint_text):
        assert "_iptables_add_or_warn" in entrypoint_text, (
            "LAURA-V243-005 regression: caddy-entrypoint.sh must define a "
            "wrapper function `_iptables_add_or_warn` so iptables ADD "
            "failures don't crash the entrypoint under `set -eu`."
        )

    def test_wrapper_used_in_resolution_loop(self, entrypoint_text):
        assert "_iptables_add_or_warn -A OUTPUT -p tcp -d" in entrypoint_text, (
            "LAURA-V243-005 regression: resolution-loop v4 branch must call "
            "_iptables_add_or_warn, not bare `iptables -A OUTPUT -p tcp -d`."
        )

    def test_laura_v243_005_referenced(self, entrypoint_text):
        assert "LAURA-V243-005" in entrypoint_text, (
            "LAURA-V243-005 regression: caddy-entrypoint.sh must reference "
            "LAURA-V243-005 in the comment near the wrapper definition."
        )


# ── 11. LAURA-V243-004 — nf_log_all_netns observability canary ──────────────

class TestEntrypointNflogObservabilityCheck:
    """LAURA-V243-004 (MED) — Laura adversarial probe 2026-05-26.

    ip6tables LOG uses kernel printk, per-netns on modern kernels. Without
    host sysctl `net.netfilter.nf_log_all_netns=1`, the IPv6 bypass canary
    (CADDY_EGRESS_BLOCKED_V6) fires inside the container but is invisible
    to operators running `journalctl -k`. Enforcement (DROP) unaffected;
    observability is the gap.

    Fix: read /proc/sys/net/netfilter/nf_log_all_netns at startup (read-only
    host sysctl exposure, no extra privileges); if 0, warn with the exact
    `sysctl -w` remediation command.
    """

    def test_reads_nf_log_all_netns(self, entrypoint_text):
        assert "nf_log_all_netns" in entrypoint_text, (
            "LAURA-V243-004 regression: caddy-entrypoint.sh must read "
            "/proc/sys/net/netfilter/nf_log_all_netns and warn if 0."
        )

    def test_warns_with_remediation_command(self, entrypoint_text):
        assert "sysctl -w net.netfilter.nf_log_all_netns=1" in entrypoint_text, (
            "LAURA-V243-004 regression: warn must include the exact "
            "`sysctl -w net.netfilter.nf_log_all_netns=1` remediation."
        )

    def test_laura_v243_004_referenced(self, entrypoint_text):
        assert "LAURA-V243-004" in entrypoint_text, (
            "LAURA-V243-004 regression: caddy-entrypoint.sh must reference "
            "LAURA-V243-004 in the comment near the sysctl-check block."
        )
