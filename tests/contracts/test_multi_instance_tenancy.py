"""
Contract tests — multi-instance tenancy isolation (3.0 / YSG-RISK-061).

Covers the must-fix lifecycle/tenancy blockers from Laura's multi-instance threat
model. These are STATIC contract checks against install.sh / uninstall.sh /
docker-compose.yml — the full live two-instance isolation proof is the VM (#44)
campaign. Each test would re-fail on the original single-instance-granularity bug
(retro rule S5: every fix closes with a regression test).

Blockers covered:
  MI-1 — per-instance secrets + state isolation (per-PROJECT install dir, in-repo
         collision guard, no shared $HOME/.yashigani clobber).
  MI-2 — authenticated lifecycle target (INSTANCE_ID minted + persisted + stamped
         as a container label; uninstall validates the running label against the
         tree's state file before tearing down).
  MI-6 — per-instance SPIFFE trust domain (derived per PROJECT, written to .env +
         state file, baked into the runtime manifest, parameterised in Caddy +
         compose; legacy "yashigani.internal" preserved byte-for-byte).
  MI-4 — step-up gate on destructive lifecycle ops (uninstall / add-component),
         fail-closed unattended without a step-up proof.

Last updated: 2026-06-10.
"""
from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent.parent
INSTALL_SH = REPO_ROOT / "install.sh"
UNINSTALL_SH = REPO_ROOT / "uninstall.sh"
COMPOSE = REPO_ROOT / "docker" / "docker-compose.yml"
CADDY_FILES = [
    REPO_ROOT / "docker" / "Caddyfile.acme",
    REPO_ROOT / "docker" / "Caddyfile.ca",
    REPO_ROOT / "docker" / "Caddyfile.selfsigned",
]


def _install() -> str:
    return INSTALL_SH.read_text(encoding="utf-8")


def _uninstall() -> str:
    return UNINSTALL_SH.read_text(encoding="utf-8")


def _compose() -> str:
    return COMPOSE.read_text(encoding="utf-8")


# ===========================================================================
# MI-1 — per-instance secrets + state isolation
# ===========================================================================

class TestMI1PerInstanceIsolation:
    def test_install_dir_keyed_by_project(self):
        """A non-legacy instance must bootstrap into its own per-PROJECT tree."""
        s = _install()
        assert "_resolve_instance_install_dir" in s, "per-instance install-dir resolver missing"
        # Keys the bootstrap dir by project (the isolation boundary for secrets/state/CA).
        assert '.yashigani-${_proj}' in s, (
            "install dir is not keyed by project — second instance would clobber the first"
        )

    def test_resolver_called_before_working_directory(self):
        """The resolver must run before detect_working_directory so WORK_DIR is keyed."""
        s = _install()
        main_pos = s.find("main() {")
        assert main_pos != -1
        # Call site of the resolver inside main() (indented bare call).
        resolve_pos = s.find("\n  _resolve_instance_install_dir\n", main_pos)
        # The first detect_working_directory CALL after the resolver runs.
        dwd_pos = s.find("\n  detect_working_directory", resolve_pos)
        assert resolve_pos != -1, "resolver not called inside main()"
        assert dwd_pos != -1, "detect_working_directory not called after resolver in main()"
        assert resolve_pos < dwd_pos, (
            "_resolve_instance_install_dir must be called before detect_working_directory"
        )

    def test_explicit_install_dir_override_wins(self):
        """An explicit YSG_INSTALL_DIR must override the per-instance keying."""
        s = _install()
        assert "_YSG_INSTALL_DIR_EXPLICIT" in s, "explicit-install-dir guard missing"
        # The resolver returns early when the operator pinned the dir.
        assert '${_YSG_INSTALL_DIR_EXPLICIT:-0}" -eq 1' in s

    def test_legacy_default_path_preserved(self):
        """Legacy (project=docker) must NOT be relocated — backward-compat."""
        s = _install()
        # The resolver returns early for the legacy project.
        seg = s[s.find("_resolve_instance_install_dir() {"):]
        seg = seg[: seg.find("\n}\n")]
        assert '"$_proj" == "docker"' in seg and "return 0" in seg, (
            "legacy project=docker is not short-circuited to the default dir"
        )

    def test_in_repo_collision_guard_present(self):
        """A fresh install whose project differs from the tree's state must fail closed."""
        s = _install()
        assert "Multi-instance safety stop (MI-1)" in s, (
            "in-repo project-collision guard missing — second install could clobber in place"
        )


# ===========================================================================
# MI-2 — authenticated lifecycle target
# ===========================================================================

class TestMI2AuthenticatedTarget:
    def test_instance_id_minted_with_csprng(self):
        s = _install()
        assert "_gen_instance_id" in s
        seg = s[s.find("_gen_instance_id() {"):]
        seg = seg[: seg.find("\n}\n")]
        assert "openssl rand -hex 16" in seg, "INSTANCE_ID not minted via CSPRNG"
        assert "/dev/urandom" in seg, "no urandom fallback for INSTANCE_ID mint"

    def test_instance_id_written_to_env_and_state(self):
        s = _install()
        assert '_env_set "YASHIGANI_INSTANCE_ID"' in s, "INSTANCE_ID not written to .env"
        assert "printf 'INSTANCE_ID=%s\\n'" in s, "INSTANCE_ID not written to state file"

    def test_instance_id_preserved_across_reruns(self):
        """Upgrade/add-component re-runs must preserve the existing token."""
        s = _install()
        # generate_env_file reads any existing .env value first (idempotent).
        assert "YASHIGANI_INSTANCE_ID=" in s
        assert "_existing_iid" in s, "INSTANCE_ID mint is not preserve-then-mint (would churn on re-run)"

    def test_compose_stamps_instance_id_label(self):
        c = _compose()
        assert "com.yashigani.instance-id" in c, "gateway is not labelled with the instance id"
        assert "${YASHIGANI_INSTANCE_ID:-}" in c, "instance-id label is not sourced from .env"

    def test_uninstall_validates_target_identity(self):
        u = _uninstall()
        assert "_mi2_validate_target" in u, "uninstall lacks the MI-2 target validator"
        assert "MI-2 safety stop" in u, "uninstall does not fail closed on identity mismatch"
        # Reads the running container's instance-id label and the tree's state token.
        assert "com.yashigani.instance-id" in u
        assert "_state_instance_id" in u

    def test_uninstall_legacy_backward_compat(self):
        """Legacy installs (no token either side) must not be blocked by MI-2."""
        u = _uninstall()
        seg = u[u.find("_mi2_validate_target() {"):]
        seg = seg[: seg.find("\n}\n")]
        # Empty state token → return 0 (no binding to enforce).
        assert '[ -n "${_state_instance_id:-}" ] || return 0' in seg


# ===========================================================================
# MI-6 — per-instance SPIFFE trust domain
# ===========================================================================

class TestMI6PerInstanceTrustDomain:
    def test_trust_domain_helper_present(self):
        s = _install()
        assert "_spiffe_trust_domain" in s
        seg = s[s.find("_spiffe_trust_domain() {"):]
        seg = seg[: seg.find("\n}\n")]
        # Legacy preserved byte-for-byte.
        assert "printf 'yashigani.internal'" in seg
        # Non-legacy gets a per-instance subdomain authority.
        assert "%s.yashigani.internal" in seg

    def test_trust_domain_written_to_env(self):
        s = _install()
        assert '_env_set "YASHIGANI_SPIFFE_TRUST_DOMAIN"' in s, (
            "trust domain not written to .env (app-side validators would not see it)"
        )

    def test_trust_domain_written_to_state_file(self):
        s = _install()
        assert "printf 'SPIFFE_TRUST_DOMAIN=%s\\n'" in s

    def test_runtime_manifest_rewrite_present(self):
        s = _install()
        assert "_apply_trust_domain_to_runtime_manifest" in s, (
            "runtime manifest trust-domain rewrite missing — leaf certs keep the shared domain"
        )
        # Fail-closed: refuse to issue certs if the rewrite fails.
        assert "refusing to issue certs with wrong trust domain" in s

    def test_runtime_rewrite_is_legacy_noop(self):
        s = _install()
        seg = s[s.find("_apply_trust_domain_to_runtime_manifest() {"):]
        seg = seg[: seg.find("\n}\n")]
        assert '"$_td" == "yashigani.internal"' in seg and "return 0" in seg, (
            "legacy trust domain is not a no-op rewrite (would churn canonical manifest)"
        )

    def test_compose_common_env_carries_trust_domain(self):
        c = _compose()
        assert "YASHIGANI_SPIFFE_TRUST_DOMAIN: ${YASHIGANI_SPIFFE_TRUST_DOMAIN:-yashigani.internal}" in c, (
            "x-common-env does not propagate the trust domain to app services"
        )

    def test_compose_audit_signer_parameterised(self):
        c = _compose()
        assert "spiffe://${YASHIGANI_SPIFFE_TRUST_DOMAIN:-yashigani.internal}/audit/checkpoint-signer" in c, (
            "audit signer SPIFFE id is hardcoded to the shared trust domain"
        )

    def test_caddy_self_identity_parameterised(self):
        """Caddy's own injected SPIFFE id must not be hardcoded to the shared domain."""
        for f in CADDY_FILES:
            text = f.read_text(encoding="utf-8")
            assert 'request_header X-SPIFFE-ID "spiffe://yashigani.internal/caddy"' not in text, (
                f"{f.name} still injects a hardcoded shared-domain caddy SPIFFE id"
            )
            assert "{$YASHIGANI_CADDY_SPIFFE_ID}" in text, (
                f"{f.name} does not use the per-instance caddy SPIFFE id env var"
            )

    def test_compose_defines_caddy_spiffe_id(self):
        c = _compose()
        assert "YASHIGANI_CADDY_SPIFFE_ID: spiffe://${YASHIGANI_SPIFFE_TRUST_DOMAIN:-yashigani.internal}/caddy" in c


# ===========================================================================
# MI-4 — step-up on destructive lifecycle ops
# ===========================================================================

class TestMI4StepUpGate:
    def test_uninstall_has_stepup_gate(self):
        u = _uninstall()
        assert "_require_stepup_mi4" in u, "uninstall lacks the MI-4 step-up gate"
        assert "MI-4 safety stop" in u, "uninstall step-up gate does not fail closed"

    def test_uninstall_gate_fails_closed_unattended(self):
        """Unattended (no token / no ack) destructive run must exit non-zero."""
        u = _uninstall()
        seg = u[u.find("_require_stepup_mi4() {"):]
        seg = seg[: seg.find("\n}\n")]
        # The terminal branch (no TTY / --yes, no proof) must exit 1.
        assert "exit 1" in seg
        assert "STEPUP_TOKEN" in seg

    def test_uninstall_gate_invoked_for_destructive_runs(self):
        u = _uninstall()
        # Gated on volume removal, non-legacy project, or k8s teardown.
        assert 'REMOVE_VOLUMES" = "true"' in u
        assert "_require_stepup_mi4\nfi" in u or "    _require_stepup_mi4\n" in u

    def test_install_add_component_gated(self):
        s = _install()
        assert '_require_stepup_mi4 "add-component on running instance"' in s, (
            "add-component on a running stack is not step-up gated"
        )

    def test_install_gate_references_tom_shared_gate(self):
        """MI-4 must reference (not duplicate) Tom's auth/stepup.py shared gate."""
        s = _install()
        assert "auth/stepup.py" in s, "MI-4 gate does not reference the shared step-up gate"
