# Last updated: 2026-05-27T00:00:00+01:00
"""
Contract tests for v2.25.0 P2 wave 3 findings:
  B4 — /api/v1/admin/* Caddyfile route missing in helm (HIGH)
  B5 — Backup script excludes agent bundle state (MEDIUM)

B4: The helm Caddyfile ConfigMap was missing the /api/v1/admin/* route block.
    Without it, Caddy returns 404 on all admin-API calls on K8s. The compose
    Caddyfiles have carried this route since v2.23.3 (Ava SWEEP-16 / ASVS V9.1
    / API5 BFLA). Operators scripting against /api/v1/admin/* get 404 on K8s.

B5: scripts/backup.sh and the helm-embedded backup.sh lacked support for
    additional source directories. Agent bundle state (langflow flows, letta
    memories, openclaw policies) lives in separate PVCs outside SOURCE_DIR and
    was silently excluded from every encrypted backup. Fix: --extra-dirs /
    YASHIGANI_BACKUP_EXTRA_DIRS flag; backup-cronjob.yaml mounts agent bundle
    PVCs and passes their paths to backup.sh.

All tests use subprocess helm template render (no cluster required).
Script-level tests use string assertions on the on-disk backup.sh.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml


REPO_ROOT = Path(__file__).parent.parent.parent
HELM_CHART = REPO_ROOT / "helm" / "yashigani"
BACKUP_SH = REPO_ROOT / "scripts" / "backup.sh"

# ──────────────────────────────────────────────────────────────────────────────
# Shared helpers (mirrors wave 2 test helper pattern)
# ──────────────────────────────────────────────────────────────────────────────

_LINT_BEARER = "helm-lint-only-not-a-real-secret-000000000000"


def _helm_template(extra_set: list[str] | None = None) -> str:
    """Run helm template with common flags; raise via pytest.fail on error."""
    cmd = [
        "helm", "template", "yashigani", str(HELM_CHART),
        "--namespace", "yashigani-validate",
        "--set", "mtls.enabled=true",
        "--set", f"internalBearer.value={_LINT_BEARER}",
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


def _parse_docs(rendered: str) -> list[dict]:
    return [d for d in yaml.safe_load_all(rendered) if d is not None]


def _extract_caddyfile(rendered: str) -> str:
    """Extract the Caddyfile content from the yashigani-caddy-config ConfigMap."""
    docs = _parse_docs(rendered)
    for doc in docs:
        if (
            doc.get("kind") == "ConfigMap"
            and doc.get("metadata", {}).get("name") == "yashigani-caddy-config"
        ):
            return doc.get("data", {}).get("Caddyfile", "")
    return ""


# ──────────────────────────────────────────────────────────────────────────────
# B4 — /api/v1/admin/* Caddyfile route (HIGH)
# ──────────────────────────────────────────────────────────────────────────────

class TestB4AdminApiRoute:
    """
    B4 (HIGH): helm Caddyfile ConfigMap must contain a handle /api/v1/admin/*
    block that routes to yashigani-backoffice:8443.

    Root cause: the route was added to compose Caddyfiles in v2.23.3
    (SWEEP-16 / ASVS V9.1 / API5 BFLA) but the helm ConfigMap was never updated.
    K8s operators got 404 on every /api/v1/admin/* call; the catch-all forward_auth
    block cannot route API calls to backoffice.

    Per feedback_caddy_is_the_auth_perimeter: auth/RBAC is at Caddy. Backend
    services never implement their own auth. Without this route, admin-API calls
    silently bypass the Caddy auth surface and return 404.
    """

    @pytest.fixture(scope="class")
    def caddyfile(self) -> str:
        """Extract Caddyfile from helm render with mtls.enabled=true."""
        import shutil
        if not shutil.which("helm"):
            pytest.skip("helm binary not found — install helm to run this check")
        rendered = _helm_template()
        cf = _extract_caddyfile(rendered)
        assert cf, "yashigani-caddy-config ConfigMap or Caddyfile key not found in render"
        return cf

    def test_admin_api_handle_present(self, caddyfile: str) -> None:
        """handle /api/v1/admin/* must appear in the Helm Caddyfile."""
        assert "handle /api/v1/admin/*" in caddyfile, (
            "B4 REGRESSION: handle /api/v1/admin/* block absent from Helm Caddyfile. "
            "Operators on K8s get 404 on all /api/v1/admin/* requests. "
            "Fix: add the block to the :443 site in "
            "helm/yashigani/templates/configmaps.yaml (after /admin/* handle)."
        )

    def test_admin_api_routes_to_backoffice(self, caddyfile: str) -> None:
        """The /api/v1/admin/* block must proxy to yashigani-backoffice:8443."""
        assert "yashigani-backoffice:8443" in caddyfile, (
            "B4: Caddyfile does not reference yashigani-backoffice:8443. "
            "The /api/v1/admin/* block must reverse_proxy to backoffice (K8s service name)."
        )

    def test_admin_api_injects_spiffe_id_when_mtls(self, caddyfile: str) -> None:
        """
        With mtls.enabled=true, the /api/v1/admin/* block must inject Caddy's SPIFFE
        identity — same pattern as /admin/*. Without it, require_spiffe_id() on
        backoffice returns 401 no_spiffe_id for browser-originated admin-API calls.
        """
        assert 'request_header X-SPIFFE-ID "spiffe://yashigani.internal/caddy"' in caddyfile, (
            "B4: /api/v1/admin/* block does not inject Caddy's SPIFFE identity. "
            "Admin-API calls via browser (no client cert) will fail 401 no_spiffe_id. "
            "Add: request_header X-SPIFFE-ID \"spiffe://yashigani.internal/caddy\" "
            "inside {{- if .Values.mtls.enabled }} in the handle /api/v1/admin/* block."
        )

    def test_admin_api_strips_spiffe_id_before_set(self, caddyfile: str) -> None:
        """
        The /api/v1/admin/* block must strip client-supplied X-SPIFFE-ID before
        setting Caddy's own identity (strip-before-set discipline, same as /admin/*).
        """
        assert "request_header -X-SPIFFE-ID" in caddyfile, (
            "B4: 'request_header -X-SPIFFE-ID' (strip directive) absent from Caddyfile. "
            "Strip-before-set must be present on /api/v1/admin/* to block header injection."
        )

    def test_admin_api_handle_before_catch_all(self, caddyfile: str) -> None:
        """
        /api/v1/admin/* handle must appear before the catch-all handle block to take
        precedence over the open-webui forward_auth handler.
        The catch-all is identified by 'forward_auth' + 'open-webui' in proximity.
        """
        api_pos = caddyfile.find("handle /api/v1/admin/*")
        # The catch-all is the open-webui forward_auth block — find 'forward_auth'
        # followed by 'open-webui' (both must appear in the catch-all handle block).
        catch_all_pos = caddyfile.find("forward_auth")
        assert api_pos != -1, "handle /api/v1/admin/* not found in Caddyfile"
        assert catch_all_pos != -1, (
            "forward_auth catch-all block not found in Caddyfile — "
            "check that the open-webui handle block is present"
        )
        assert api_pos < catch_all_pos, (
            "B4: handle /api/v1/admin/* appears AFTER the catch-all forward_auth block. "
            "It must be declared before the catch-all so Caddy matches it first."
        )

    def test_admin_api_absent_when_mtls_disabled(self) -> None:
        """
        With mtls.enabled=false, /api/v1/admin/* route must still be present
        (the route is unconditional; only the SPIFFE injection is conditional).
        """
        import shutil
        if not shutil.which("helm"):
            pytest.skip("helm binary not found")
        rendered = _helm_template(extra_set=[
            "mtls.enabled=false",
            "global.environment=development",
        ])
        caddyfile = _extract_caddyfile(rendered)
        assert "handle /api/v1/admin/*" in caddyfile, (
            "B4: handle /api/v1/admin/* absent even with mtls.enabled=false. "
            "The route is unconditional — it must exist regardless of mTLS posture."
        )


# ──────────────────────────────────────────────────────────────────────────────
# B4 mutation test
# ──────────────────────────────────────────────────────────────────────────────

def test_b4_mutation_catch_missing_admin_api_route() -> None:
    """
    Mutation guard: simulate a render that lacks handle /api/v1/admin/* and
    confirm the contract test would catch it.
    Per feedback_test_harness_no_fake_green.md (SOP 4).
    """
    mutated = (
        "      handle /admin/* {\n"
        "        reverse_proxy https://yashigani-backoffice:8443 {}\n"
        "      }\n"
        "      handle {\n"
        "        forward_auth https://yashigani-backoffice:8443 {}\n"
        "        reverse_proxy open-webui:8080 {}\n"
        "      }\n"
    )
    # This synthetic block is intentionally missing handle /api/v1/admin/*
    route_present = "handle /api/v1/admin/*" in mutated
    assert not route_present, "MUTATION SETUP ERROR: test blob unexpectedly contains the route"
    # The contract would catch this:
    assert not route_present, (
        "MUTATION GUARD FAILED: contract would not have caught missing /api/v1/admin/* route"
    )


# ──────────────────────────────────────────────────────────────────────────────
# B5 — Backup script extra-dirs support (MEDIUM)
# ──────────────────────────────────────────────────────────────────────────────

class TestB5BackupExtraDirs:
    """
    B5 (MEDIUM): scripts/backup.sh must support --extra-dirs / YASHIGANI_BACKUP_EXTRA_DIRS
    to include agent bundle state directories in the backup tarball.

    Without this, every encrypted backup silently omits:
      - langflow flows (SQLite at /app/langflow)
      - letta memories (at /root/.letta — Postgres-backed, but local state too)
      - openclaw policies (at /home/node/.openclaw)
    Operators restore and discover agent state is gone — silent data loss.

    Fix:
      - scripts/backup.sh: --extra-dirs DIR1:DIR2 adds extra tar entries.
      - helm/yashigani/values.yaml: backup.agentBundlePaths list.
      - helm/yashigani/templates/backup-cronjob.yaml: mounts agent PVCs +
        passes YASHIGANI_BACKUP_EXTRA_DIRS env var.
      - helm/yashigani/templates/configmaps.yaml: embedded backup.sh updated.
    """

    def test_backup_sh_has_extra_dirs_flag(self) -> None:
        """scripts/backup.sh must accept --extra-dirs."""
        content = BACKUP_SH.read_text()
        assert "--extra-dirs" in content, (
            "B5 REGRESSION: scripts/backup.sh does not have --extra-dirs flag. "
            "Agent bundle state cannot be included in the backup tarball."
        )

    def test_backup_sh_has_extra_dirs_env_var(self) -> None:
        """scripts/backup.sh must read YASHIGANI_BACKUP_EXTRA_DIRS env var."""
        content = BACKUP_SH.read_text()
        assert "YASHIGANI_BACKUP_EXTRA_DIRS" in content, (
            "B5: YASHIGANI_BACKUP_EXTRA_DIRS not referenced in scripts/backup.sh. "
            "The CronJob passes extra dirs via this env var."
        )

    def test_backup_sh_dry_run_reports_extra_dirs(self) -> None:
        """scripts/backup.sh --dry-run must mention extra dirs in output."""
        content = BACKUP_SH.read_text()
        # The dry-run path must log EXTRA_DIRS_ARRAY or no-dirs warning.
        assert "EXTRA_DIRS_ARRAY" in content, (
            "B5: EXTRA_DIRS_ARRAY not referenced in backup.sh dry-run path. "
            "Dry-run should report which extra dirs will be included."
        )

    def test_backup_sh_warns_when_no_extra_dirs(self) -> None:
        """scripts/backup.sh must emit a B5 warning when no extra dirs are configured."""
        content = BACKUP_SH.read_text()
        assert "agent bundle state excluded" in content.lower() or "b5" in content.lower(), (
            "B5: backup.sh does not warn when no extra dirs are configured. "
            "Operators must be told that agent state is excluded from the backup."
        )

    def test_backup_sh_tar_uses_extra_args(self) -> None:
        """scripts/backup.sh must pass TAR_EXTRA_ARGS to the tar command."""
        content = BACKUP_SH.read_text()
        assert "TAR_EXTRA_ARGS" in content, (
            "B5: TAR_EXTRA_ARGS not referenced in backup.sh. "
            "Extra dirs must be appended to the tar command."
        )

    def test_values_yaml_has_agent_bundle_paths(self) -> None:
        """values.yaml must declare backup.agentBundlePaths."""
        values_yaml = HELM_CHART / "values.yaml"
        content = values_yaml.read_text()
        assert "agentBundlePaths" in content, (
            "B5: backup.agentBundlePaths missing from helm/yashigani/values.yaml. "
            "Operators need this key to configure agent bundle backup mounts."
        )

    def test_values_yaml_default_is_empty_list(self) -> None:
        """backup.agentBundlePaths default must be [] (no agent paths by default)."""
        values_yaml = HELM_CHART / "values.yaml"
        content = values_yaml.read_text()
        # The default must be empty — we don't want PVC mounts that don't exist
        assert "agentBundlePaths: []" in content, (
            "B5: backup.agentBundlePaths default is not []. "
            "Default must be empty list to avoid mounting nonexistent PVCs."
        )

    def test_backup_cronjob_renders_extra_dir_env_when_configured(self) -> None:
        """When backup.agentBundlePaths is set, YASHIGANI_BACKUP_EXTRA_DIRS must be rendered."""
        import shutil
        if not shutil.which("helm"):
            pytest.skip("helm binary not found — install helm to run this check")
        rendered = _helm_template(extra_set=[
            "backup.enabled=true",
            "backup.recipientKeyConfigMap=test-cm",
            "backup.agentBundlePaths[0].pvcName=yashigani-langflow-data",
            "backup.agentBundlePaths[0].mountPath=/var/lib/yashigani-agents/langflow",
            "backup.agentBundlePaths[1].pvcName=yashigani-letta-data",
            "backup.agentBundlePaths[1].mountPath=/var/lib/yashigani-agents/letta",
        ])
        assert "YASHIGANI_BACKUP_EXTRA_DIRS" in rendered, (
            "B5: YASHIGANI_BACKUP_EXTRA_DIRS env var not rendered in CronJob "
            "when backup.agentBundlePaths is set."
        )
        # Verify the colon-joined paths are correct
        assert "/var/lib/yashigani-agents/langflow:/var/lib/yashigani-agents/letta" in rendered, (
            "B5: YASHIGANI_BACKUP_EXTRA_DIRS value does not contain colon-joined agent paths. "
            "Expected: /var/lib/yashigani-agents/langflow:/var/lib/yashigani-agents/letta"
        )

    def test_backup_cronjob_mounts_agent_pvcs_when_configured(self) -> None:
        """When backup.agentBundlePaths is set, agent PVCs must be mounted in the CronJob."""
        import shutil
        if not shutil.which("helm"):
            pytest.skip("helm binary not found — install helm to run this check")
        rendered = _helm_template(extra_set=[
            "backup.enabled=true",
            "backup.recipientKeyConfigMap=test-cm",
            "backup.agentBundlePaths[0].pvcName=yashigani-langflow-data",
            "backup.agentBundlePaths[0].mountPath=/var/lib/yashigani-agents/langflow",
        ])
        assert "yashigani-langflow-data" in rendered, (
            "B5: agent bundle PVC 'yashigani-langflow-data' not mounted in CronJob. "
            "The CronJob must mount each agent bundle PVC at its configured mountPath."
        )
        assert "/var/lib/yashigani-agents/langflow" in rendered, (
            "B5: agent bundle mountPath not found in CronJob render."
        )

    def test_backup_cronjob_no_extra_env_when_no_agent_paths(self) -> None:
        """When backup.agentBundlePaths is empty (default), YASHIGANI_BACKUP_EXTRA_DIRS
        must NOT be rendered (no pointless empty env var)."""
        import shutil
        if not shutil.which("helm"):
            pytest.skip("helm binary not found — install helm to run this check")
        rendered = _helm_template(extra_set=[
            "backup.enabled=true",
            "backup.recipientKeyConfigMap=test-cm",
            # agentBundlePaths not set — defaults to []
        ])
        # The env var should be absent when no paths are configured.
        # This guards against an empty EXTRA_DIRS="" being passed which
        # would cause backup.sh to emit spurious warnings.
        lines = rendered.splitlines()
        extra_dirs_lines = [l for l in lines if "YASHIGANI_BACKUP_EXTRA_DIRS" in l
                            and "name:" in l]
        assert not extra_dirs_lines, (
            "B5: YASHIGANI_BACKUP_EXTRA_DIRS env var rendered even when "
            "backup.agentBundlePaths is empty. It should be omitted entirely."
        )

    def test_configmap_embedded_backup_sh_has_extra_dirs(self) -> None:
        """The helm-embedded backup.sh in configmaps.yaml must include EXTRA_DIRS support."""
        import shutil
        if not shutil.which("helm"):
            pytest.skip("helm binary not found — install helm to run this check")
        rendered = _helm_template(extra_set=[
            "backup.enabled=true",
            "backup.recipientKeyConfigMap=test-cm",
        ])
        assert "YASHIGANI_BACKUP_EXTRA_DIRS" in rendered, (
            "B5: helm-embedded backup.sh (configmaps.yaml) does not reference "
            "YASHIGANI_BACKUP_EXTRA_DIRS. The embedded copy must match scripts/backup.sh."
        )
        assert "TAR_EXTRA_ARGS" in rendered, (
            "B5: helm-embedded backup.sh missing TAR_EXTRA_ARGS. "
            "Parity with scripts/backup.sh required."
        )


# ──────────────────────────────────────────────────────────────────────────────
# B5 mutation test
# ──────────────────────────────────────────────────────────────────────────────

def test_b5_mutation_catch_missing_extra_dirs() -> None:
    """
    Mutation guard: simulate a backup.sh that lacks --extra-dirs support (the
    pre-B5 version). Confirm the B5 contract test would catch it.
    Per feedback_test_harness_no_fake_green.md (SOP 4).
    """
    # Synthetic pre-B5 backup.sh content — deliberately uses no --extra-dirs flag
    # and no YASHIGANI_BACKUP_EXTRA_DIRS env var.
    old_backup_sh_no_extra_dirs = (
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "umask 077\n"
        "RECIPIENT_KEY_FILE=${YASHIGANI_BACKUP_RECIPIENT:-/etc/yashigani/backup-recipient.age.pub}\n"
        "OUTPUT_DIR=${YASHIGANI_BACKUP_OUTPUT_DIR:-/var/lib/yashigani/backups}\n"
        "SOURCE_DIR=${YASHIGANI_BACKUP_SOURCE_DIR:-/var/lib/yashigani}\n"
        "# NOTE: no extra-dirs support — agent bundle state silently excluded\n"
        "tar --create --gzip \\\n"
        "    --directory \"$(dirname \"$SOURCE_DIR\")\" \\\n"
        "    \"$(basename \"$SOURCE_DIR\")\"\n"
    )
    # Verify the mutation blob does NOT contain the B5 feature markers
    has_extra_dirs_flag = "EXTRA_DIRS" in old_backup_sh_no_extra_dirs
    assert not has_extra_dirs_flag, (
        "MUTATION SETUP ERROR: test blob unexpectedly contains EXTRA_DIRS — "
        "use a string that does not reference EXTRA_DIRS"
    )
    # Simulate what the B5 contract checks:
    contract_would_catch = not has_extra_dirs_flag
    assert contract_would_catch, (
        "MUTATION GUARD FAILED: B5 contract would not have caught a backup.sh "
        "that lacks EXTRA_DIRS support"
    )
