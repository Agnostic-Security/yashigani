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


# ── 8. BUG-V243-CADDY-IPV6-IPTABLES regression guard ─────────────────────────

class TestEntrypointIpv6Filter:
    """BUG-V243-CADDY-IPV6-IPTABLES — verified fresh-install 2026-05-26.

    The egress allowlist loop resolves operator/ACME hosts via `getent ahosts`
    and feeds each address to `iptables`. `getent ahosts` returns BOTH A
    (IPv4) and AAAA (IPv6) records. `iptables` (the IPv4 binary) rejects IPv6
    addresses with `host/network <addr> not found` and exits non-zero. Under
    `set -e` (line 55) this crashes the entrypoint → container exits → Podman
    restart-policy=always re-runs → restart loop (393 restarts in 3 minutes
    measured on UTM VM, fresh tarball install).

    Fix: filter IPv6 results out before iterating to iptables. Either
    `getent ahostsv4` (explicit IPv4-only) or awk filter (reject any
    address containing ':').
    """

    def test_getent_ahosts_filters_ipv6(self, entrypoint_text):
        """Resolution must not feed IPv6 addresses into the iptables loop."""
        # Acceptable patterns:
        # 1. getent ahostsv4 (musl + glibc — explicit IPv4-only)
        # 2. getent ahosts ... awk '!~ /:/' (filter colons)
        # 3. getent ahosts ... awk '!/:/'   (same, regex shorthand)
        has_v4_only_getent = "getent ahostsv4" in entrypoint_text
        has_colon_filter = "!~ /:/" in entrypoint_text or "!/:/" in entrypoint_text

        assert has_v4_only_getent or has_colon_filter, (
            "BUG-V243-CADDY-IPV6-IPTABLES regression: caddy-entrypoint.sh "
            "must filter IPv6 addresses from `getent ahosts` output before "
            "passing to `iptables` (IPv4-only). Either use `getent ahostsv4` "
            "or filter via awk pattern `$1 !~ /:/`. Without the filter, AAAA "
            "records crash the entrypoint under `set -e` and Caddy restart-"
            "loops indefinitely."
        )

    def test_iptables_loop_documents_ipv4_only(self, entrypoint_text):
        """The egress loop must document the IPv4-only invariant for future maintainers."""
        # Find the resolution block and verify there's a comment about IPv4/IPv6.
        v6_comment_signals = ["IPv4 only", "AAAA", "IPv6", "BUG-V243"]
        has_doc = any(signal in entrypoint_text for signal in v6_comment_signals)
        assert has_doc, (
            "caddy-entrypoint.sh must document the IPv4-only invariant of "
            "the iptables egress allowlist near the getent loop (any of: "
            "'IPv4 only', 'AAAA', 'IPv6', 'BUG-V243'). The filter alone is "
            "fragile — comment ensures future maintainers don't 'simplify' "
            "it back to bare `getent ahosts`."
        )
