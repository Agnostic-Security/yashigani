"""
YSG-RISK-008 Compose Hardening Parity Gate (v2.23.4)

Asserts that every service in docker/docker-compose.yml has:
  1. cap_drop: [ALL]             — universal (was already true pre-v2.23.4)
  2. security_opt with no-new-privileges:true
  3. read_only: true             — OR is in the documented exemption list

Exemption list (documented asymmetry, see risk register YSG-RISK-008):
  wazuh-manager, wazuh-indexer, wazuh-dashboard
    Reason: Wazuh suite (profile-gated, opt-in) has complex internal write paths
    under /var/ossec and /usr/share/wazuh-* not covered by declared volumes.
    All three have no-new-privileges + cap_drop. read_only deferred.

  postgres
    Reason: needs writable /var/run/postgresql for the unix-domain socket + PID
    lock file, owned by uid 999 (postgres-in-container) with restrictive perms.
    podman-compose tmpfs short-form syntax does NOT accept uid=/gid= options
    (Docker does); mode=1777 on a system socket directory is unacceptable per
    security review. K8s path retains full readOnlyRootFilesystem.

  pgbouncer
    Reason: entrypoint generates /etc/pgbouncer/userlist.txt at startup; needs
    writable /var/run/pgbouncer (PID file) AND /etc/pgbouncer. Same podman
    tmpfs limitation as postgres. K8s path retains full readOnlyRootFilesystem.

  All exempt services retain no-new-privileges + cap_drop:[ALL] + user:<uid>.

If a new service is added to docker-compose.yml WITHOUT these controls, this
test fails — that is the compose equivalent of Kyverno admission enforcement.
Add to EXEMPTIONS only with an explicit ACS risk register entry and Tiago sign-off.
"""

import pathlib
import re
import pytest
import yaml


COMPOSE_FILE = pathlib.Path(__file__).parent.parent.parent / "docker" / "docker-compose.yml"

# Services exempt from read_only: true requirement.
# Each entry MUST have a documented reason in docker/docker-compose.yml (see YSG-RISK-008 comments).
READ_ONLY_EXEMPTIONS = frozenset(
    {
        "wazuh-manager",   # OpenSearch/JVM + agent internal write paths not covered by volumes
        "wazuh-indexer",   # OpenSearch /usr/share/wazuh-indexer implicit writes
        "wazuh-dashboard", # Plugin assets under /usr/share/wazuh-dashboard implicit writes
        "postgres",        # podman tmpfs no uid/gid → can't uid-restrict /var/run/postgresql
        "pgbouncer",       # podman tmpfs no uid/gid → can't uid-restrict /var/run/pgbouncer + /etc/pgbouncer/userlist.txt
    }
)


def load_compose_services():
    """Parse docker-compose.yml and return the services dict."""
    content = COMPOSE_FILE.read_text()
    # Strip YAML anchors/aliases before parse — PyYAML 6 handles these but we
    # need to expand the *common-env alias manually since it appears in env blocks.
    # Use FullLoader so anchors/aliases are resolved.
    doc = yaml.full_load(content)
    assert doc is not None, f"Failed to parse {COMPOSE_FILE}"
    services = doc.get("services", {})
    assert services, f"No services found in {COMPOSE_FILE}"
    return services


@pytest.fixture(scope="module")
def services():
    return load_compose_services()


@pytest.fixture(scope="module")
def service_names(services):
    return sorted(services.keys())


def get_security_opts(service_cfg):
    """Return list of security_opt strings for a service, normalised to lowercase."""
    opts = service_cfg.get("security_opt", [])
    return [str(o).lower() for o in opts]


def has_no_new_privileges(service_cfg):
    opts = get_security_opts(service_cfg)
    return any("no-new-privileges:true" in o for o in opts)


def has_cap_drop_all(service_cfg):
    cap_drop = service_cfg.get("cap_drop", [])
    return any(str(c).upper() == "ALL" for c in cap_drop)


def has_read_only(service_cfg):
    return service_cfg.get("read_only", False) is True


# ─────────────────────────────────────────────────────────────────────────────
# Gate 1: cap_drop: [ALL] — universal baseline
# ─────────────────────────────────────────────────────────────────────────────

class TestCapDropAll:
    def test_all_services_have_cap_drop_all(self, services, service_names):
        """Every service must have cap_drop: [ALL]. No exceptions."""
        failures = []
        for name in service_names:
            cfg = services[name]
            if not has_cap_drop_all(cfg):
                failures.append(name)
        assert not failures, (
            f"Services missing cap_drop: [ALL]: {failures}\n"
            "YSG-RISK-008: cap_drop is the baseline defence. Every service MUST have it."
        )


# ─────────────────────────────────────────────────────────────────────────────
# Gate 2: no-new-privileges:true — universal
# ─────────────────────────────────────────────────────────────────────────────

class TestNoNewPrivileges:
    def test_all_services_have_no_new_privileges(self, services, service_names):
        """Every service must have security_opt: no-new-privileges:true. No exceptions."""
        failures = []
        for name in service_names:
            cfg = services[name]
            if not has_no_new_privileges(cfg):
                failures.append(name)
        assert not failures, (
            f"Services missing no-new-privileges:true: {failures}\n"
            "YSG-RISK-008: no-new-privileges prevents privilege escalation via setuid/setgid "
            "binaries inside the container. All services must have this set.\n"
            "Fix: add `security_opt: [no-new-privileges:true]` to each failing service."
        )


# ─────────────────────────────────────────────────────────────────────────────
# Gate 3: read_only: true — universal (with documented exemptions)
# ─────────────────────────────────────────────────────────────────────────────

class TestReadOnly:
    def test_all_services_have_read_only_or_are_exempt(self, services, service_names):
        """
        Every service must have read_only: true, OR must be in READ_ONLY_EXEMPTIONS.
        Exemptions require a documented reason in docker-compose.yml and risk register YSG-RISK-008.
        """
        failures = []
        for name in service_names:
            cfg = services[name]
            if name in READ_ONLY_EXEMPTIONS:
                continue  # documented exemption
            if not has_read_only(cfg):
                failures.append(name)
        assert not failures, (
            f"Services missing read_only: true (and not in exemption list): {failures}\n"
            "YSG-RISK-008: read_only: true prevents container filesystem writes outside "
            "declared volumes and tmpfs mounts.\n"
            "Fix: add `read_only: true` to each failing service, plus `tmpfs:` entries "
            "for any paths the service needs to write to at runtime.\n"
            f"Documented exemptions: {sorted(READ_ONLY_EXEMPTIONS)}\n"
            "To add a new exemption: add to READ_ONLY_EXEMPTIONS above, add inline comment "
            "in docker-compose.yml, and update risk register YSG-RISK-008."
        )

    def test_exemptions_have_inline_comment(self, services):
        """
        Each exemption in READ_ONLY_EXEMPTIONS must have a 'read_only skipped' comment
        somewhere in docker-compose.yml within 100 lines of the service definition.
        This prevents silent exemption drift.
        """
        compose_lines = COMPOSE_FILE.read_text().splitlines()
        for exemption in READ_ONLY_EXEMPTIONS:
            if exemption not in services:
                continue  # service not in compose (removed); stale exemption caught by other test

            # Find the line number of the service definition
            service_line = None
            for i, line in enumerate(compose_lines):
                # Top-level service definitions are indented exactly 2 spaces
                if line.rstrip() == f"  {exemption}:":
                    service_line = i
                    break
            assert service_line is not None, (
                f"Could not find service definition line for '{exemption}' in docker-compose.yml"
            )

            # Search within the next 100 lines for the 'read_only skipped' comment
            window = compose_lines[service_line : service_line + 100]
            has_comment = any("read_only skipped" in line for line in window)
            assert has_comment, (
                f"Exemption '{exemption}' has no 'read_only skipped' comment within 100 lines "
                f"of its service definition in docker-compose.yml (starting line {service_line + 1}).\n"
                f"Add a comment explaining WHY read_only is skipped for this service."
            )

    def test_no_undocumented_exemptions(self, services, service_names):
        """
        All entries in READ_ONLY_EXEMPTIONS must be actual services in the compose file.
        Stale exemptions are a config drift risk.
        """
        stale = READ_ONLY_EXEMPTIONS - set(service_names)
        assert not stale, (
            f"READ_ONLY_EXEMPTIONS contains services not in docker-compose.yml: {stale}\n"
            "Remove stale exemptions from READ_ONLY_EXEMPTIONS in this test file."
        )
