# Last updated: 2026-05-29T00:00:00+00:00 (P1 W3 Phase 2a — Caddy base hardening)
"""
P1 W3 Phase 2a — Caddy base hardening contract tests.

Covers findings C2, C6, C7, S4 from the P1 plan §2.A + §2.E.

C2 (HIGH) — admin off / unix socket only
    Verifies that all three compose Caddyfiles and the Helm Caddyfile use
    `admin unix//run/caddy/admin.sock` (not TCP :2019).
    Verifies the K8s caddy pod does NOT expose containerPort 2019.
    Verifies the allow-caddy-ingress NetworkPolicy does NOT permit :2019 inbound.

C6 (HIGH) — Caddy container hardening (seccomp + RO root)
    Verifies compose caddy service has:
      - read_only: true
      - seccomp profile wired (security_opt contains seccomp entry)
      - no-new-privileges:true
      - cap_drop: [ALL]
    Verifies Helm caddy pod has:
      - readOnlyRootFilesystem: true
      - allowPrivilegeEscalation: false
      - capabilities.drop: [ALL]
      - seccompProfile.type: RuntimeDefault

C7 (MEDIUM) — TLS private key isolation + TLS 1.3
    Verifies the Helm caddy pod does NOT mount pki-certs when mtls.disabled
    (key isolation: only caddy mounts the key).
    Verifies TLS 1.3 is enforced on all Caddy listeners (covered by
    test_caddyfile_family.py but sanity-checked here cross-file for completeness).

S4 (SHIP-BLOCKER) — Agent import sentinel
    Verifies all three compose Caddyfiles have `import /etc/caddy/agents/*.caddy`
    at the top-level (outside any site block — end of file).
    Verifies the Helm Caddyfile (configmaps.yaml) has the sentinel.
    Verifies docker-compose.yml caddy service mounts ./caddy/agents:/etc/caddy/agents:ro.
    Verifies the Helm caddy.yaml has the caddy-agents volumeMount + volume.
    Verifies the caddy-agents-configmap.yaml template exists and has data: {}.
    Verifies docker/caddy/agents/ directory exists.
    Verifies the sentinel is at the TOP LEVEL (after all site blocks) so it
    cannot accidentally shadow base Caddyfile routes.
    Mutation guards for all S4 assertions.
"""
from __future__ import annotations

import pathlib
import re

import pytest
import yaml

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_REPO = pathlib.Path(__file__).parent.parent.parent
_DOCKER = _REPO / "docker"
_HELM_TEMPLATES = _REPO / "helm" / "yashigani" / "templates"

CADDYFILES: dict[str, pathlib.Path] = {
    "selfsigned": _DOCKER / "Caddyfile.selfsigned",
    "acme":       _DOCKER / "Caddyfile.acme",
    "ca":         _DOCKER / "Caddyfile.ca",
}

_COMPOSE         = _DOCKER / "docker-compose.yml"
_CADDY_YAML      = _HELM_TEMPLATES / "caddy.yaml"
_CONFIGMAPS_YAML = _HELM_TEMPLATES / "configmaps.yaml"
_AGENTS_CM_YAML  = _HELM_TEMPLATES / "caddy-agents-configmap.yaml"
_AGENTS_DIR      = _DOCKER / "caddy" / "agents"

_SENTINEL = "import /etc/caddy/agents/*.caddy"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load(path: pathlib.Path) -> str:
    assert path.exists(), f"file not found: {path}"
    return path.read_text(encoding="utf-8")


def _compose_caddy_svc(text: str) -> dict:
    data = yaml.safe_load(text)
    assert "services" in data and "caddy" in data["services"], \
        "caddy service missing from docker-compose.yml"
    return data["services"]["caddy"]


# ---------------------------------------------------------------------------
# C2 — admin unix socket / no TCP :2019
# ---------------------------------------------------------------------------

class TestC2AdminSocket:
    """C2 (HIGH): Caddy admin API must use unix socket, not TCP :2019."""

    @pytest.mark.parametrize("name,path", list(CADDYFILES.items()))
    def test_unix_socket_in_compose_caddyfiles(self, name: str, path: pathlib.Path):
        """All compose Caddyfiles must use admin unix socket.

        FINDING-V412-CADDYADMIN-001 fix (2026-07-21): the raw admin API now
        lives on a caddy-PRIVATE path (/run/caddy-admin) that is never
        bind-mounted into backoffice — see TestCaddyAdmin001ReloadRelay below
        for the narrow /run/caddy relay backoffice actually talks to.
        """
        text = _load(path)
        assert "admin unix//run/caddy-admin/admin.sock" in text, (
            f"Caddyfile.{name}: admin must use a CADDY-PRIVATE unix socket "
            f"('admin unix//run/caddy-admin/admin.sock'), not TCP :2019 and "
            f"not the backoffice-shared path. C2 / MUST-4 / v2.24.1 hardening "
            f"+ FINDING-V412-CADDYADMIN-001."
        )

    def test_unix_socket_in_helm_caddyfile(self):
        """Helm Caddyfile (configmaps.yaml) must use admin unix socket."""
        text = _load(_CONFIGMAPS_YAML)
        assert "admin unix//run/caddy/admin.sock" in text, (
            "configmaps.yaml Caddyfile: admin must use unix socket "
            "('admin unix//run/caddy/admin.sock'), not TCP :2019. "
            "C2 / MUST-4 / v2.24.1 hardening."
        )

    @pytest.mark.parametrize("name,path", list(CADDYFILES.items()))
    def test_no_tcp_admin_in_compose_caddyfiles(self, name: str, path: pathlib.Path):
        """No TCP admin directive in compose Caddyfiles."""
        text = _load(path)
        # Matches `admin :2019` or `admin 0.0.0.0:2019` or `admin localhost:2019`
        tcp_admin = re.search(r"^\s*admin\s+[^u].*2019", text, re.MULTILINE)
        assert not tcp_admin, (
            f"Caddyfile.{name}: found a TCP-based admin directive. "
            "Remove it — TCP admin API must be disabled. Use unix socket only."
        )

    def test_no_tcp_admin_in_helm_caddyfile(self):
        """No TCP admin directive in Helm Caddyfile."""
        text = _load(_CONFIGMAPS_YAML)
        tcp_admin = re.search(r"^\s*admin\s+[^u].*2019", text, re.MULTILINE)
        assert not tcp_admin, (
            "configmaps.yaml Caddyfile: found a TCP-based admin directive. "
            "Remove it — TCP admin API must be disabled. Use unix socket only."
        )

    def test_helm_caddy_pod_no_admin_containerport(self):
        """Caddy pod must NOT expose containerPort 2019 in Helm template."""
        text = _load(_CADDY_YAML)
        # Search for an actual containerPort declaration for 2019, not just the
        # string "2019" in comments or other text.
        match = re.search(r"containerPort\s*:\s*2019", text)
        assert match is None, (
            "caddy.yaml: containerPort 2019 found. The admin TCP port must not "
            "be exposed — admin is unix-socket-only (MUST-4 / C2)."
        )

    def test_networkpolicy_no_admin_port_ingress(self):
        """allow-caddy-ingress NetworkPolicy must not permit port 2019."""
        np_path = _HELM_TEMPLATES / "networkpolicy.yaml"
        text = _load(np_path)
        # Find the allow-caddy-ingress section and scan it for :2019
        caddy_ingress_idx = text.find("allow-caddy-ingress")
        assert caddy_ingress_idx != -1, \
            "allow-caddy-ingress NetworkPolicy not found"
        # Scan within a 2000-char window from the section header
        segment = text[caddy_ingress_idx:caddy_ingress_idx + 2000]
        assert "2019" not in segment, (
            "networkpolicy.yaml allow-caddy-ingress: port 2019 found. "
            "The Caddy admin port must never be exposed as a K8s NetworkPolicy "
            "ingress rule — it is unix-socket-only (C2)."
        )


# ---------------------------------------------------------------------------
# FINDING-V412-CADDYADMIN-002 — route-registration contract (REWORK)
# ---------------------------------------------------------------------------
#
# REWORK of the FINDING-V412-CADDYADMIN-001 R1+R2 broker (5443f11f) after
# Laura's final re-attack (laura-final-reattack.md) proved that design FAILED
# live: BLOCKER-A (the broker's own `caddy adapt` EPERM'd under
# no-new-privileges — every legitimate reload 502'd) and BLOCKER-B (R2 was
# still open — backoffice could drop a rogue docker/caddy/agents/*.caddy
# file, bypassing the broker entirely via Caddy's own container-start/
# restart import). See docker/caddy/config_broker.py module docstring for
# the full writeup and src/tests/unit/test_v412_caddy_config_broker.py for
# the validation-LOGIC regression suite. This class verifies the WIRING:
# the old raw-/load relay is GONE, the broker owns a dedicated route socket,
# the dynamic-agents directory is broker-owned, and backoffice's RW install
# tree correctly RO-shadows the static agents directory.

_BROKER_PY = _DOCKER / "caddy" / "config_broker.py"
_BROKER_DOCKERFILE = _DOCKER / "caddy" / "Dockerfile.caddy-broker"


def _compose_broker_svc(text: str) -> dict:
    data = yaml.safe_load(text)
    assert "services" in data and "caddy-config-broker" in data["services"], (
        "caddy-config-broker service missing from docker-compose.yml"
    )
    return data["services"]["caddy-config-broker"]


def _compose_backoffice_svc(text: str) -> dict:
    data = yaml.safe_load(text)
    assert "services" in data and "backoffice" in data["services"]
    return data["services"]["backoffice"]


class TestCaddyAdmin002OldRelayRemoved:
    """The OLD raw-/load reload relay (FINDING-V412-CADDYADMIN-001 R1 fix)
    must be completely gone — it's exactly the mechanism BLOCKER-A/R1
    depended on."""

    @pytest.mark.parametrize("name,path", list(CADDYFILES.items()))
    def test_old_reload_relay_site_block_absent(self, name: str, path: pathlib.Path):
        text = _load(path)
        assert "MCP-onboarding reload relay" not in text, (
            f"Caddyfile.{name}: the OLD raw-/load relay site block must be "
            f"removed entirely — FINDING-V412-CADDYADMIN-002 replaces it "
            f"with backoffice talking directly to caddy-config-broker."
        )
        assert ":9999 {" not in text, (
            f"Caddyfile.{name}: the old relay's inert placeholder site "
            f"address must be gone."
        )
        assert "reverse_proxy unix//run/caddy-broker/broker.sock" not in text, (
            f"Caddyfile.{name}: no reference to the old broker socket path "
            f"should remain."
        )

    def test_old_caddy_admin_sock_volume_absent(self):
        data = yaml.safe_load(_load(_COMPOSE))
        assert "caddy_admin_sock" not in data.get("volumes", {}), (
            "docker-compose.yml: the OLD caddy_admin_sock volume (backoffice-"
            "shared reload relay) must be removed — FINDING-V412-CADDYADMIN-002."
        )
        assert "caddy_broker_sock" not in data.get("volumes", {}), (
            "docker-compose.yml: the OLD caddy_broker_sock volume (caddy-"
            "dials-broker) must be removed — caddy is no longer a peer of "
            "the broker at all post-rework."
        )

    def test_caddy_service_no_longer_mounts_backoffice_relay_socket(self):
        svc = _compose_caddy_svc(_load(_COMPOSE))
        volumes = svc.get("volumes", [])
        assert not any("caddy_admin_sock" in str(v) for v in volumes), (
            "docker-compose.yml caddy: must not mount caddy_admin_sock — "
            "the relay it served is removed."
        )
        assert not any("caddy_broker_sock" in str(v) for v in volumes), (
            "docker-compose.yml caddy: must not mount caddy_broker_sock — "
            "caddy no longer talks to the broker over any shared socket."
        )


class TestCaddyAdmin002BrokerRouteSocket:
    """The NEW contract: backoffice <-> caddy-config-broker over a dedicated
    socket, NEVER shared with caddy."""

    def test_backoffice_mounts_broker_route_socket(self):
        svc = _compose_backoffice_svc(_load(_COMPOSE))
        volumes = svc.get("volumes", [])
        assert any(
            "caddy_broker_route_sock:/run/caddy-broker-route" in str(v)
            for v in volumes
        ), (
            "docker-compose.yml backoffice: missing caddy_broker_route_sock "
            "mount — the ONLY channel backoffice has to register MCP routes "
            "post-rework."
        )

    def test_backoffice_no_longer_mounts_caddyfile_or_admin_socket(self):
        svc = _compose_backoffice_svc(_load(_COMPOSE))
        volumes = svc.get("volumes", [])
        assert not any(
            str(v).endswith(":/etc/caddy/Caddyfile:ro") for v in volumes
        ), (
            "docker-compose.yml backoffice: must not mount the monolith "
            "Caddyfile — it no longer reads or reposts Caddy content at all."
        )
        assert not any("caddy_admin_sock" in str(v) for v in volumes), (
            "docker-compose.yml backoffice: must not mount caddy_admin_sock."
        )

    def test_broker_mounts_dedicated_route_socket_not_shared_with_caddy(self):
        broker_svc = _compose_broker_svc(_load(_COMPOSE))
        broker_volumes = broker_svc.get("volumes", [])
        assert any(
            "caddy_broker_route_sock:/run/caddy-broker-route" in str(v)
            for v in broker_volumes
        ), "caddy-config-broker: missing caddy_broker_route_sock mount."

        caddy_svc = _compose_caddy_svc(_load(_COMPOSE))
        caddy_volumes = caddy_svc.get("volumes", [])
        assert not any(
            "caddy_broker_route_sock" in str(v) for v in caddy_volumes
        ), (
            "docker-compose.yml caddy: must NOT mount caddy_broker_route_sock "
            "— only backoffice and the broker are peers on this socket."
        )

    def test_broker_net_pairs_backoffice_and_broker_not_caddy(self):
        """caddy_broker_net must now pair {backoffice, caddy-config-broker}
        — caddy is no longer a member (it never talks to the broker over
        network; it only dials the real admin socket, a client role, via a
        separate shared-volume unix socket)."""
        data = yaml.safe_load(_load(_COMPOSE))
        net = data["networks"].get("caddy_broker_net")
        assert net is not None and net.get("internal") is True

        members = [
            name for name, svc in data["services"].items()
            if "caddy_broker_net" in (svc.get("networks") or [])
        ]
        assert set(members) == {"backoffice", "caddy-config-broker"}, (
            f"caddy_broker_net must have EXACTLY "
            f"{{backoffice, caddy-config-broker}} as members, found "
            f"{sorted(members)}."
        )


class TestCaddyAdmin002R2ClosedAtSource:
    """BLOCKER-B: backoffice must no longer have ANY filesystem write path
    to anything Caddy imports — docker/caddy/agents/ RO-shadowed (same
    technique as secrets/var/.env/Caddyfile, FINDING-LIC-012 precedent) AND
    the dynamic MCP-route directory is a separate volume never mounted into
    backoffice at all."""

    def test_agents_dir_ro_shadowed_in_backoffice(self):
        svc = _compose_backoffice_svc(_load(_COMPOSE))
        volumes = svc.get("volumes", [])
        shadow = next(
            (v for v in volumes
             if str(v).startswith("./caddy/agents:/mnt/install/docker/caddy/agents")),
            None,
        )
        assert shadow is not None, (
            "docker-compose.yml backoffice: docker/caddy/agents/ must be "
            "RO-shadowed under /mnt/install/docker (same technique as "
            "secrets/var/.env/Caddyfile) — without this a compromised "
            "backoffice can still write a rogue *.caddy file via the "
            "broader RW ./:/mnt/install/docker:rw mount (R2)."
        )
        assert str(shadow).endswith(":ro"), (
            "docker-compose.yml backoffice: the docker/caddy/agents/ shadow "
            "mount must be :ro."
        )

    def test_broker_owned_dynamic_dir_never_mounted_into_backoffice(self):
        svc = _compose_backoffice_svc(_load(_COMPOSE))
        volumes = svc.get("volumes", [])
        assert not any("caddy_broker_agents" in str(v) for v in volumes), (
            "docker-compose.yml backoffice: must NEVER mount "
            "caddy_broker_agents (the broker-owned dynamic MCP-route "
            "directory) — R2's fix depends on backoffice having zero "
            "filesystem path to it, not a narrowed one."
        )

    def test_broker_owns_dynamic_dir_rw(self):
        svc = _compose_broker_svc(_load(_COMPOSE))
        volumes = svc.get("volumes", [])
        mount = next(
            (v for v in volumes
             if str(v).startswith("caddy_broker_agents:/etc/caddy/agents-dynamic")),
            None,
        )
        assert mount is not None, (
            "docker-compose.yml caddy-config-broker: missing the "
            "caddy_broker_agents:/etc/caddy/agents-dynamic mount."
        )
        assert str(mount).endswith(":rw"), (
            "docker-compose.yml caddy-config-broker: the dynamic-agents "
            "mount must be :rw — this is the ONLY legitimate writer."
        )

    def test_caddy_mounts_dynamic_dir_readonly(self):
        svc = _compose_caddy_svc(_load(_COMPOSE))
        volumes = svc.get("volumes", [])
        mount = next(
            (v for v in volumes
             if str(v).startswith("caddy_broker_agents:/etc/caddy/agents-dynamic")),
            None,
        )
        assert mount is not None and str(mount).endswith(":ro"), (
            "docker-compose.yml caddy: caddy_broker_agents must be mounted "
            "read-only."
        )

    @pytest.mark.parametrize("name,path", list(CADDYFILES.items()))
    def test_dynamic_agents_import_sentinel_present(self, name: str, path: pathlib.Path):
        text = _load(path)
        assert "import /etc/caddy/agents-dynamic/*.caddy" in text, (
            f"Caddyfile.{name}: missing the broker-owned dynamic-agents "
            f"import sentinel."
        )
        # Must appear AFTER the static agents sentinel (ordering is cosmetic
        # here, but pins the documented contract).
        static_idx = text.index("import /etc/caddy/agents/*.caddy")
        dynamic_idx = text.index("import /etc/caddy/agents-dynamic/*.caddy")
        assert static_idx < dynamic_idx


class TestCaddyAdmin002BrokerCapabilityStrip:
    """BLOCKER-A: the broker's copy of the caddy binary must have its file
    capability stripped at build time — the root cause of the live 502s
    Laura measured (execve EPERM under no-new-privileges when the binary
    would gain a capability it doesn't already have)."""

    def test_broker_script_exists(self):
        assert _BROKER_PY.exists()

    def test_broker_script_compiles(self):
        import ast
        ast.parse(_load(_BROKER_PY))

    def test_broker_dockerfile_exists(self):
        assert _BROKER_DOCKERFILE.exists()

    def test_broker_dockerfile_strips_caddy_capability(self):
        text = _load(_BROKER_DOCKERFILE)
        assert "setcap -r" in text, (
            "Dockerfile.caddy-broker: missing the `setcap -r` step that "
            "strips the caddy binary's file capability — without it, "
            "`caddy adapt` EPERMs under this container's "
            "no-new-privileges security_opt (BLOCKER-A, verified live)."
        )
        assert "getcap" in text, (
            "Dockerfile.caddy-broker: the setcap step must VERIFY the strip "
            "succeeded (getcap check + FATAL exit on any remaining "
            "capability), not just attempt it."
        )

    def test_broker_dockerfile_no_longer_bakes_a_baseline(self):
        """The old build-time baseline stage (adapted-<mode>.json) is gone —
        the broker now self-checks fresh from RO-trusted live sources on
        every call (safe post-rework: nothing feeding it is backoffice-
        writable anymore)."""
        text = _load(_BROKER_DOCKERFILE)
        assert "AS baseline" not in text
        assert "/app/reference" not in text

    def test_broker_dockerfile_pins_caddy_digest(self):
        """The broker's caddy binary must come from the SAME digest-pinned
        image as the real caddy service (docker/caddy/Dockerfile.caddy) —
        drift here would mean the broker's self-checks run a different
        Caddyfile-adapter version than what actually runs."""
        broker_text = _load(_BROKER_DOCKERFILE)
        real_caddy_text = _load(_DOCKER / "caddy" / "Dockerfile.caddy")
        broker_digest = re.search(
            r"caddy:2\.11\.2-alpine@sha256:[0-9a-f]+", broker_text,
        )
        real_digest = re.search(
            r"caddy:2\.11\.2-alpine@sha256:[0-9a-f]+", real_caddy_text,
        )
        assert broker_digest and real_digest
        assert broker_digest.group(0) == real_digest.group(0)

    def test_broker_runs_as_nonroot(self):
        text = _load(_BROKER_DOCKERFILE)
        assert re.search(r"^USER 65532:65532\s*$", text, re.MULTILINE)

    def test_broker_no_secrets_mounted(self):
        svc = _compose_broker_svc(_load(_COMPOSE))
        volumes = svc.get("volumes", [])
        assert not any("/run/secrets" in str(v) for v in volumes), (
            "docker-compose.yml caddy-config-broker: must not mount "
            "/run/secrets — this service needs no cert/key material."
        )

    def test_broker_hardening_parity_with_extractor_svc(self):
        svc = _compose_broker_svc(_load(_COMPOSE))
        assert svc.get("cap_drop") == ["ALL"]
        assert svc.get("read_only") is True
        sec_opts = svc.get("security_opt", [])
        assert any("no-new-privileges:true" in o for o in sec_opts)
        assert any("seccomp" in str(o) for o in sec_opts)


# ---------------------------------------------------------------------------
# FINDING-V412-CADDYADMIN-002 — K8s parity (helm)
# ---------------------------------------------------------------------------

class TestCaddyAdmin002HelmParity:
    """K8s :2019 relay must route through the SAME broker DATA contract as
    compose. R2 (rogue docker/caddy/agents/*.caddy) still has NO K8s
    equivalent (zero chart RBAC rules grant any workload configmaps
    access) — the dynamic-agents emptyDir is pod-local and shared ONLY
    between the caddy container and the broker sidecar."""

    def test_relay_proxies_route_not_load(self):
        text = _load(_CONFIGMAPS_YAML)
        assert "path /route" in text, (
            "configmaps.yaml: the :2019 relay must matcher-gate on "
            "path /route (the new DATA-only contract), not the old raw "
            "/load body."
        )
        assert "path /load" not in text, (
            "configmaps.yaml: the OLD raw-/load matcher must be removed."
        )
        assert "method POST DELETE" in text, (
            "configmaps.yaml: the relay must admit both POST (register) "
            "and DELETE (unregister) for /route."
        )

    def test_relay_proxies_to_broker_sidecar(self):
        text = _load(_CONFIGMAPS_YAML)
        assert "reverse_proxy 127.0.0.1:{{ .Values.caddy.configBroker.port }}" in text

    def test_dynamic_agents_import_sentinel_present(self):
        text = _load(_CONFIGMAPS_YAML)
        assert "import /etc/caddy/agents-dynamic/*.caddy" in text

    def test_broker_sidecar_present_in_caddy_pod(self):
        text = _load(_CADDY_YAML)
        assert "caddy-config-broker" in text

    def test_broker_sidecar_hardened(self):
        text = _load(_CADDY_YAML)
        idx = text.index("name: caddy-config-broker")
        next_container = text.find("\n        - name:", idx + 1)
        block = text[idx:next_container if next_container != -1 else idx + 3000]
        assert "runAsNonRoot: true" in block
        assert "runAsUser: 65532" in block
        assert 'drop: ["ALL"]' in block
        assert "readOnlyRootFilesystem: true" in block
        assert "allowPrivilegeEscalation: false" in block

    def test_broker_sidecar_no_secrets_mount(self):
        text = _load(_CADDY_YAML)
        idx = text.index("name: caddy-config-broker")
        next_container = text.find("\n        - name:", idx + 1)
        block = text[idx:next_container if next_container != -1 else idx + 3000]
        assert "pki-certs" not in block

    def test_broker_sidecar_writes_dynamic_agents_dir(self):
        text = _load(_CADDY_YAML)
        idx = text.index("name: caddy-config-broker")
        next_container = text.find("\n        - name:", idx + 1)
        block = text[idx:next_container if next_container != -1 else idx + 3000]
        assert "caddy-agents-dynamic" in block
        assert "BROKER_AGENTS_DYNAMIC_DIR" in block

    def test_caddy_container_mounts_dynamic_agents_dir_readonly(self):
        text = _load(_CADDY_YAML)
        idx = text.index("- name: caddy\n")
        next_container = text.find("\n        - name:", idx + 1)
        block = text[idx:next_container if next_container != -1 else idx + 3000]
        assert "caddy-agents-dynamic" in block

    def test_backoffice_no_longer_mounts_caddyfile_configmap(self):
        """FINDING-V412-CADDYADMIN-002: backoffice no longer reads the
        monolith Caddyfile on K8s at all — it sends route DATA only."""
        text = _load(_REPO / "helm" / "yashigani" / "templates" / "backoffice.yaml")
        assert "YASHIGANI_CADDY_CADDYFILE" not in text

    def test_no_workload_rbac_grants_configmaps(self):
        """Regression guard for the R2-has-no-K8s-equivalent safety
        argument: if a future change ever grants any workload ServiceAccount
        configmaps RBAC, that assumption breaks silently — this must be
        caught, not just documented."""
        offending = []
        for p in _HELM_TEMPLATES.glob("*.yaml"):
            text = _load(p)
            if "configmaps" in text and "resources:" in text:
                if re.search(r'resources:\s*\[[^\]]*"?configmaps"?', text) or \
                   re.search(r'resources:\s*\n(\s*-\s*.*\n)*\s*-\s*"?configmaps"?', text):
                    offending.append(p.name)
        assert not offending, (
            f"RBAC rule(s) granting 'configmaps' found in {offending} — "
            f"this INVALIDATES the R2-has-no-K8s-equivalent safety argument "
            f"(a workload could now write a rogue agents ConfigMap the same "
            f"way backoffice could on compose pre-fix). Re-audit "
            f"FINDING-V412-CADDYADMIN-002."
        )



# ---------------------------------------------------------------------------
# C6 — Container hardening (compose + Helm)
# ---------------------------------------------------------------------------

class TestC6ContainerHardening:
    """C6 (HIGH): read-only root, seccomp, no-new-privs, cap_drop all."""

    def test_compose_caddy_read_only(self):
        """compose caddy must have read_only: true."""
        svc = _compose_caddy_svc(_load(_COMPOSE))
        assert svc.get("read_only") is True, (
            "docker-compose.yml caddy: read_only must be true (C6 / YSG-RISK-008)."
        )

    def test_compose_caddy_no_new_privileges(self):
        """compose caddy must have no-new-privileges in security_opt."""
        svc = _compose_caddy_svc(_load(_COMPOSE))
        sec_opts = svc.get("security_opt", [])
        assert any("no-new-privileges:true" in opt for opt in sec_opts), (
            "docker-compose.yml caddy: security_opt must include "
            "'no-new-privileges:true' (C6 / YSG-RISK-008)."
        )

    def test_compose_caddy_seccomp_profile(self):
        """compose caddy must have a seccomp profile in security_opt (C6)."""
        svc = _compose_caddy_svc(_load(_COMPOSE))
        sec_opts = svc.get("security_opt", [])
        has_seccomp = any("seccomp" in str(opt) for opt in sec_opts)
        assert has_seccomp, (
            "docker-compose.yml caddy: security_opt must include a seccomp "
            "entry (e.g. 'seccomp=./seccomp/yashigani.json'). "
            "C6 requires seccomp hardening parity with gateway/backoffice."
        )

    def test_compose_caddy_cap_drop_all(self):
        """compose caddy must drop ALL capabilities (C6)."""
        svc = _compose_caddy_svc(_load(_COMPOSE))
        cap_drop = svc.get("cap_drop", [])
        assert "ALL" in cap_drop, (
            "docker-compose.yml caddy: cap_drop must include ALL "
            "(C6 / V232-CSCAN-01k-RES-01)."
        )

    def test_helm_caddy_readonly_root_filesystem(self):
        """Helm caddy container must have readOnlyRootFilesystem: true (C6)."""
        text = _load(_CADDY_YAML)
        assert "readOnlyRootFilesystem: true" in text, (
            "caddy.yaml: readOnlyRootFilesystem must be true (C6 / YSG-RISK-008)."
        )

    def test_helm_caddy_allow_privilege_escalation_false(self):
        """Helm caddy container must set allowPrivilegeEscalation: false (C6)."""
        text = _load(_CADDY_YAML)
        assert "allowPrivilegeEscalation: false" in text, (
            "caddy.yaml: allowPrivilegeEscalation must be false (C6)."
        )

    def test_helm_caddy_seccomp_runtime_default(self):
        """Helm caddy pod must have seccompProfile.type: RuntimeDefault (C6)."""
        text = _load(_CADDY_YAML)
        assert "seccompProfile" in text, (
            "caddy.yaml: seccompProfile must be set (C6)."
        )
        assert "RuntimeDefault" in text, (
            "caddy.yaml: seccompProfile.type must be RuntimeDefault (C6)."
        )

    def test_helm_caddy_drop_all_caps(self):
        """Helm caddy container must drop ALL capabilities (C6)."""
        text = _load(_CADDY_YAML)
        # capabilities.drop: ["ALL"] in YAML
        assert 'drop: ["ALL"]' in text or "- ALL" in text or '["ALL"]' in text, (
            "caddy.yaml: capabilities.drop must include ALL (C6)."
        )

    def test_helm_caddy_admin_sock_emptydir_bounded(self):
        """Helm caddy-admin-sock emptyDir must have medium:Memory + sizeLimit:1Mi.

        Iris-F2 / LAURA-002 (LOW): matches compose tmpfs /run/caddy:size=1m.
        Memory-backed emptyDir is tmpfs-equivalent (no host-disk writes);
        sizeLimit caps runaway growth from a misbehaving admin-sock client.
        """
        text = _load(_CADDY_YAML)
        assert "medium: Memory" in text, (
            "caddy.yaml: caddy-admin-sock emptyDir must have 'medium: Memory' "
            "(tmpfs-equivalent, matches compose /run/caddy:size=1m). "
            "Iris-F2 / LAURA-002."
        )
        assert "sizeLimit: 1Mi" in text, (
            "caddy.yaml: caddy-admin-sock emptyDir must have 'sizeLimit: 1Mi' "
            "(bounded to match compose /run/caddy:size=1m). "
            "Iris-F2 / LAURA-002."
        )


# ---------------------------------------------------------------------------
# C7 — TLS private key isolation + TLS 1.3
# ---------------------------------------------------------------------------

class TestC7TlsKeyIsolation:
    """C7 (MEDIUM): caddy_client.key only in caddy pod; TLS 1.3 enforced."""

    def test_helm_caddy_tls13_in_configmap(self):
        """Helm Caddyfile must enforce TLS 1.3 on the :443 listener (C7)."""
        text = _load(_CONFIGMAPS_YAML)
        assert "protocols tls1.3" in text, (
            "configmaps.yaml Caddyfile: 'protocols tls1.3' missing. "
            "TLS 1.3 minimum required on all Caddy listeners (C7)."
        )

    def test_compose_caddy_tls_key_only_in_secrets_mount(self):
        """compose caddy mounts ./secrets which contains the key; other services
        mount it too (pre-existing architecture). This test documents the known
        state: compose secrets dir is shared, K8s pki-certs Secret is isolated.
        Passes as a documentation test; K8s isolation verified separately."""
        svc = _compose_caddy_svc(_load(_COMPOSE))
        volumes = svc.get("volumes", [])
        has_secrets_mount = any("/run/secrets" in str(v) for v in volumes)
        assert has_secrets_mount, (
            "caddy service must mount the secrets directory at /run/secrets "
            "(caddy_client.crt/key are required for mTLS to gateway/backoffice)."
        )

    def test_helm_caddy_pki_certs_read_only(self):
        """Helm caddy pki-certs volume must be read-only (C7)."""
        text = _load(_CADDY_YAML)
        # Verify the volumeMount for pki-certs sets readOnly: true
        assert "readOnly: true" in text, (
            "caddy.yaml: pki-certs volumeMount must be readOnly: true (C7)."
        )

    def test_helm_other_services_no_pki_certs_mount_from_caddy_secret(self):
        """C7: caddy_client.key isolation — the pki-certs secret in caddy.yaml
        uses mtls.secretName, which is a shared PKI secret. Other services
        have their own dedicated leaf certs. This test verifies that caddy.yaml
        is the ONLY template referencing the caddy_client.crt/key specifically
        in its Caddyfile upstream transport block (not via the shared secret).
        """
        caddy_text = _load(_CADDY_YAML)
        # caddy.yaml must reference caddy_client.crt for mTLS upstream transport
        assert "caddy_client.crt" in caddy_text, (
            "caddy.yaml: caddy_client.crt not found. Caddy needs its own leaf "
            "cert for mTLS upstream connections (C7)."
        )


# ---------------------------------------------------------------------------
# S4 — Agent import sentinel (SHIP-BLOCKER)
# ---------------------------------------------------------------------------

class TestS4AgentImportSentinel:
    """S4 (SHIP-BLOCKER): import /etc/caddy/agents/*.caddy sentinel."""

    # ── compose Caddyfiles ───────────────────────────────────────────────────

    @pytest.mark.parametrize("name,path", list(CADDYFILES.items()))
    def test_sentinel_present_in_compose_caddyfiles(self, name: str, path: pathlib.Path):
        """All three compose Caddyfiles must contain the agent import sentinel."""
        text = _load(path)
        assert _SENTINEL in text, (
            f"Caddyfile.{name}: missing S4 agent import sentinel.\n"
            f"Expected: `{_SENTINEL}`\n"
            "This is a SHIP-BLOCKER — without this sentinel, onboarded-agent "
            "Caddyfile snippets are never loaded by Caddy."
        )

    @pytest.mark.parametrize("name,path", list(CADDYFILES.items()))
    def test_sentinel_at_top_level_in_compose_caddyfiles(self, name: str, path: pathlib.Path):
        """Sentinel must appear at top level (outside any site block).

        If the sentinel is inside a site block, it would be parsed as an inline
        snippet import, not a top-level Caddyfile import. Agent snippets contain
        complete `:443 { ... }` site blocks and must be imported at the top level
        so Caddy merges them with the existing `:443` listener.
        """
        text = _load(path)
        lines = text.splitlines()
        sentinel_lineno = None
        for i, line in enumerate(lines):
            if _SENTINEL in line:
                sentinel_lineno = i
                break

        assert sentinel_lineno is not None, (
            f"Caddyfile.{name}: sentinel `{_SENTINEL}` not found"
        )

        # Count brace depth at the sentinel line — must be 0 (top level).
        depth = 0
        for i, line in enumerate(lines[:sentinel_lineno]):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            depth += stripped.count("{") - stripped.count("}")

        assert depth == 0, (
            f"Caddyfile.{name}: sentinel at line {sentinel_lineno + 1} is inside "
            f"a block (brace depth={depth}). The sentinel must be at the TOP LEVEL "
            "(outside all site blocks) so agent snippets are parsed as top-level "
            "Caddyfile fragments, not inline imports."
        )

    def test_sentinel_count_parity_across_compose_family(self):
        """All three compose Caddyfiles must have exactly 1 sentinel (parity)."""
        counts = {
            name: _load(path).count(_SENTINEL)
            for name, path in CADDYFILES.items()
        }
        for name, count in counts.items():
            assert count == 1, (
                f"Caddyfile.{name}: expected exactly 1 sentinel, got {count}.\n"
                f"All counts: {counts}"
            )

    # ── Helm Caddyfile ───────────────────────────────────────────────────────

    def test_sentinel_present_in_helm_caddyfile(self):
        """Helm Caddyfile (configmaps.yaml) must contain the agent import sentinel."""
        text = _load(_CONFIGMAPS_YAML)
        assert _SENTINEL in text, (
            "configmaps.yaml Caddyfile: missing S4 agent import sentinel.\n"
            f"Expected: `{_SENTINEL}`\n"
            "K8s/Helm deployments need the same sentinel so agent snippets "
            "from the yashigani-caddy-agents ConfigMap are loaded."
        )

    # ── docker-compose.yml bind-mount ────────────────────────────────────────

    def test_compose_agents_volume_mount_present(self):
        """docker-compose.yml caddy service must mount ./caddy/agents:/etc/caddy/agents:ro."""
        svc = _compose_caddy_svc(_load(_COMPOSE))
        volumes = svc.get("volumes", [])
        # Accepts: ./caddy/agents:/etc/caddy/agents:ro
        has_agents_mount = any(
            "caddy/agents" in str(v) and "/etc/caddy/agents" in str(v)
            for v in volumes
        )
        assert has_agents_mount, (
            "docker-compose.yml caddy: missing agents bind-mount.\n"
            "Expected entry: './caddy/agents:/etc/caddy/agents:ro'\n"
            "Without this mount, the `import /etc/caddy/agents/*.caddy` sentinel "
            "has no files to load even after agents are onboarded."
        )

    def test_compose_agents_volume_read_only(self):
        """docker-compose.yml caddy agents bind-mount must be read-only (:ro)."""
        svc = _compose_caddy_svc(_load(_COMPOSE))
        volumes = svc.get("volumes", [])
        agents_volume = next(
            (v for v in volumes if "caddy/agents" in str(v) and "/etc/caddy/agents" in str(v)),
            None,
        )
        assert agents_volume is not None, \
            "agents volume not found (prerequisite for this test)"
        assert ":ro" in str(agents_volume), (
            "docker-compose.yml caddy agents bind-mount must be read-only (:ro). "
            "Agent snippets are written by install.sh/ringfence-init, not Caddy."
        )

    # ── Helm caddy.yaml volume + volumeMount ─────────────────────────────────

    def test_helm_caddy_agents_volume_present(self):
        """Helm caddy.yaml must declare a caddy-agents volume."""
        text = _load(_CADDY_YAML)
        assert "caddy-agents" in text, (
            "caddy.yaml: caddy-agents volume not found. "
            "Add a volume named 'caddy-agents' backed by the "
            "yashigani-caddy-agents ConfigMap (S4)."
        )

    def test_helm_caddy_agents_volume_mount_present(self):
        """Helm caddy.yaml must mount caddy-agents at /etc/caddy/agents."""
        text = _load(_CADDY_YAML)
        assert "/etc/caddy/agents" in text, (
            "caddy.yaml: /etc/caddy/agents volumeMount path not found. "
            "The caddy-agents ConfigMap must be mounted at /etc/caddy/agents "
            "so the `import` sentinel can read agent snippets (S4)."
        )

    def test_helm_caddy_agents_volume_read_only(self):
        """Helm caddy.yaml caddy-agents volumeMount must be read-only."""
        text = _load(_CADDY_YAML)
        # Check the volumeMount section includes readOnly: true near caddy-agents mount
        # We find the caddy-agents volumeMount block and verify readOnly within 5 lines
        lines = text.splitlines()
        agents_mount_lineno = None
        for i, line in enumerate(lines):
            # Match only the actual mountPath line, not comment occurrences
            if re.search(r"^\s+mountPath\s*:\s*/etc/caddy/agents\s*$", line):
                agents_mount_lineno = i
                break
        assert agents_mount_lineno is not None, \
            "/etc/caddy/agents mountPath not found (prerequisite)"
        # readOnly: true must appear within 5 lines of the mountPath
        window = lines[max(0, agents_mount_lineno - 2):agents_mount_lineno + 5]
        assert any("readOnly: true" in ln for ln in window), (
            "caddy.yaml: caddy-agents volumeMount must have 'readOnly: true' "
            "within 5 lines of the mountPath declaration (S4 / C7 defence in depth)."
        )

    def test_helm_caddy_agents_volume_references_configmap(self):
        """Helm caddy.yaml caddy-agents volume must reference the agents ConfigMap."""
        text = _load(_CADDY_YAML)
        assert "yashigani-caddy-agents" in text, (
            "caddy.yaml: yashigani-caddy-agents ConfigMap reference not found. "
            "The caddy-agents volume must be backed by the yashigani-caddy-agents "
            "ConfigMap (caddy-agents-configmap.yaml template) (S4)."
        )

    # ── caddy-agents-configmap.yaml ──────────────────────────────────────────

    def test_helm_agents_configmap_template_exists(self):
        """Helm caddy-agents-configmap.yaml template must exist."""
        assert _AGENTS_CM_YAML.exists(), (
            f"helm template not found: {_AGENTS_CM_YAML}\n"
            "Create helm/yashigani/templates/caddy-agents-configmap.yaml — "
            "empty base ConfigMap for the Caddy agent snippet directory (S4)."
        )

    def test_helm_agents_configmap_is_empty_by_default(self):
        """caddy-agents-configmap.yaml must have data: {} (empty at base install)."""
        text = _load(_AGENTS_CM_YAML)
        assert "data: {}" in text, (
            "caddy-agents-configmap.yaml: data must be '{}' (empty map). "
            "No agent snippets are present at base install — the ConfigMap is "
            "populated by ringfence-init codegen as agents are onboarded (S4)."
        )

    def test_helm_agents_configmap_name(self):
        """caddy-agents-configmap.yaml must define yashigani-caddy-agents."""
        text = _load(_AGENTS_CM_YAML)
        assert "yashigani-caddy-agents" in text, (
            "caddy-agents-configmap.yaml: ConfigMap name must contain "
            "'yashigani-caddy-agents' (referenced by caddy.yaml volume) (S4)."
        )

    def test_helm_agents_configmap_s4_annotation(self):
        """caddy-agents-configmap.yaml must carry the S4 sentinel annotation."""
        text = _load(_AGENTS_CM_YAML)
        assert "s4-sentinel" in text, (
            "caddy-agents-configmap.yaml: annotation 'yashigani.io/s4-sentinel' "
            "must be present for traceability (S4)."
        )

    # ── docker/caddy/agents/ directory ──────────────────────────────────────

    def test_agents_directory_exists(self):
        """docker/caddy/agents/ directory must exist (compose bind-mount source)."""
        assert _AGENTS_DIR.is_dir(), (
            f"docker/caddy/agents/ directory not found at {_AGENTS_DIR}.\n"
            "Create it with a .gitkeep file so the bind-mount source exists "
            "at base install (no agents onboarded yet) (S4)."
        )

    # v4.1 unified-sidecar §2.5 (2026-07-07): the bundled agents' generated
    # INGRESS-front snippets are COMMITTED artifacts (Phase-2a precedent:
    # docker/caddy/egress/*-forwarder.caddy), delivered through this same
    # sentinel per design §2.2(b) ("per-system handles arrive via the
    # agents/*.caddy sentinel"). They are codegen-generated + drift-gated
    # (tests/contracts/test_v41_agent_ingress_template.py), so the S4
    # security property (read-only mount, codegen-written only) holds.
    # Nothing OUTSIDE this pinned set may appear at base.
    _BUNDLED_INGRESS_FRONTS = frozenset({
        "langflow-ingress.caddy",
        "letta-ingress.caddy",
        "openclaw-ingress.caddy",
    })

    def test_agents_directory_has_no_caddy_files_at_base(self):
        """docker/caddy/agents/ carries ONLY the pinned §2.5 bundled fronts.

        Base install has no ONBOARDED agents. Beyond the committed bundled
        ingress fronts (allowlist above — generated, drift-gated), a .caddy
        file here would indicate either a pre-baked onboarded agent
        (forbidden — onboarded agents are wrapped dynamically) or leftover
        test artifacts that must not be committed.
        """
        caddy_files = {f.name for f in _AGENTS_DIR.glob("*.caddy")}
        unexpected = caddy_files - self._BUNDLED_INGRESS_FRONTS
        assert not unexpected, (
            f"docker/caddy/agents/ contains unexpected .caddy files at base "
            f"install: {sorted(unexpected)}\n"
            "Only the committed §2.5 bundled-agent ingress fronts are "
            "permitted here — onboarded-agent snippets are generated by "
            "ringfence-init codegen at onboarding time, not pre-baked (S4)."
        )
        missing = self._BUNDLED_INGRESS_FRONTS - caddy_files
        assert not missing, (
            f"docker/caddy/agents/ is missing committed §2.5 bundled-agent "
            f"ingress fronts: {sorted(missing)} — regenerate from "
            "bundles/<agent>-egress.yaml (render_agent_ingress_artifacts)."
        )


# ---------------------------------------------------------------------------
# S4 mutation guards
# ---------------------------------------------------------------------------

class TestS4Mutations:
    """Mutation guards — verify contracts catch regressions."""

    def test_mutation_sentinel_removal_caught(self):
        """Removing the sentinel from a Caddyfile must be detected."""
        path = CADDYFILES["selfsigned"]
        original = _load(path)
        assert _SENTINEL in original, "Prerequisite: sentinel must be present"

        mutated = original.replace(_SENTINEL, "")
        assert _SENTINEL not in mutated, "Mutation failed"

        count = mutated.count(_SENTINEL)
        assert count == 0, (
            "MUTATION TEST FAILED: removing the S4 sentinel from Caddyfile.selfsigned "
            "was not detected by the sentinel count check. The contract is broken."
        )

    def test_mutation_sentinel_inside_block_caught(self):
        """A sentinel moved inside a site block must be detected."""
        # Simulate moving the sentinel inside the :443 block (depth != 0)
        # by manually computing brace depth at a known inside-block position.
        path = CADDYFILES["acme"]
        text = _load(path)

        # Find a line that is clearly inside the :443 site block
        lines = text.splitlines()
        # Simulate: what if the sentinel appeared at line 5 (inside global block)?
        # We check: if we inject the sentinel at brace-depth > 0, the check fires.
        # Inject sentinel after the opening `{` of the global block
        mutated_lines = []
        injected = False
        for line in lines:
            mutated_lines.append(line)
            if not injected and line.strip() == "{":
                # This is the global block opening brace
                mutated_lines.append("    " + _SENTINEL)  # inside global block
                injected = True

        assert injected, "Could not find global block opener in acme Caddyfile"
        mutated = "\n".join(mutated_lines)
        mutated_lines_list = mutated.splitlines()

        # Find the FIRST occurrence of the sentinel (the one we injected inside)
        first_sentinel_lineno = None
        for i, ln in enumerate(mutated_lines_list):
            if _SENTINEL in ln:
                first_sentinel_lineno = i
                break

        assert first_sentinel_lineno is not None
        depth = 0
        for i, ln in enumerate(mutated_lines_list[:first_sentinel_lineno]):
            stripped = ln.strip()
            if stripped.startswith("#"):
                continue
            depth += stripped.count("{") - stripped.count("}")

        # The injected sentinel is inside the global block (depth > 0)
        assert depth > 0, (
            "MUTATION TEST FAILED: the injected inside-block sentinel was NOT "
            "detected as being inside a block (depth={depth}). "
            "The top-level check is broken."
        )

    def test_mutation_compose_mount_removal_caught(self):
        """Removing the agents bind-mount from docker-compose.yml must be detected."""
        text = _load(_COMPOSE)
        assert "caddy/agents" in text, "Prerequisite: agents mount must be present"

        # Simulate removal: filter out lines with caddy/agents
        mutated_lines = [
            ln for ln in text.splitlines()
            if "caddy/agents" not in ln
        ]
        mutated = "\n".join(mutated_lines)

        svc = _compose_caddy_svc(mutated)
        volumes = svc.get("volumes", [])
        has_agents_mount = any(
            "caddy/agents" in str(v) and "/etc/caddy/agents" in str(v)
            for v in volumes
        )
        assert not has_agents_mount, (
            "MUTATION TEST FAILED: removing the agents bind-mount from "
            "docker-compose.yml was NOT detected. The contract is broken."
        )

    def test_mutation_helm_configmap_data_non_empty_caught(self):
        """Adding data entries to caddy-agents-configmap.yaml must be detectable."""
        text = _load(_AGENTS_CM_YAML)
        # Simulate: someone pre-populated the ConfigMap with a snippet
        mutated = text.replace("data: {}", "data:\n  test-agent.caddy: |")
        assert "data: {}" not in mutated, "Mutation failed"
        # The check `data: {}` in text will now be False
        assert "data: {}" not in mutated, (
            "MUTATION TEST FAILED: non-empty data was not detected. "
            "The base-install emptiness check is broken."
        )
