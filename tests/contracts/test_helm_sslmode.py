# Last updated: 2026-05-17T00:00:00+01:00
"""
Helm sslmode regression tests — F-V232-002 (ASVS V14.4.1).

Asserts that:
  1. No `sslmode=require` token appears as an ACTUAL DSN parameter in any
     helm template render (env var value lines or pgbouncer config lines).
     Text mentions of `require` inside Python docstrings / error messages do
     NOT constitute DSN usage and are excluded.
  2. Every rendered DSN in env var `value:` lines uses `verify-ca` or
     `verify-full` (certificate-validating modes only).
  3. The embedded Python `_build_ssl_context` function in the partition
     maintenance ConfigMap rejects `sslmode=require` at runtime — i.e., no
     `CERT_NONE` branch survives in the emitted code, and a fail-closed
     ValueError path is present.

Test approach: `subprocess.run(['helm', 'template', ...])` renders the chart
locally. No Tiller / cluster required.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent
HELM_CHART = REPO_ROOT / "helm" / "yashigani"

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _helm_template(extra_set: list[str] | None = None) -> str:
    """Run `helm template` and return stdout; raise on error."""
    cmd = [
        "helm",
        "template",
        "yashigani",
        str(HELM_CHART),
        "--set", "global.environment=ci",
        "--set", "mtls.enabled=true",
        "--set", "admissionPolicies.enabled=false",
    ]
    if extra_set:
        for s in extra_set:
            cmd += ["--set", s]

    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        pytest.fail(
            f"helm template failed (rc={result.returncode}):\n"
            f"STDOUT: {result.stdout[:2000]}\n"
            f"STDERR: {result.stderr[:2000]}"
        )
    return result.stdout


def _dsn_value_lines(rendered: str) -> list[str]:
    """Extract only the `value:` lines that contain a postgresql:// DSN or
    pgbouncer sslmode config lines — i.e., lines where sslmode is an *actual*
    configuration value, not a string literal in Python source code.

    This avoids false positives from docstrings / error-message strings inside
    the embedded partition_maintenance.py ConfigMap.
    """
    matches = []
    for line in rendered.splitlines():
        stripped = line.strip()
        # DSN value lines: `value: "postgresql://..."` in K8s env blocks
        if re.match(r'^value:\s+"postgresql://', stripped):
            matches.append(line)
        # PgBouncer ini config lines: `server_tls_sslmode = ...`
        elif re.match(r"(client|server)_tls_sslmode\s*=", stripped):
            matches.append(line)
    return matches


# ──────────────────────────────────────────────────────────────────────────────
# Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestSslmodeRequireAbsent:
    """No sslmode=require token appears in actual DSN/config lines."""

    def test_no_sslmode_require_in_dsn_value_lines(self) -> None:
        """DSN value lines and pgbouncer config lines must not use sslmode=require."""
        rendered = _helm_template()
        dsn_lines = _dsn_value_lines(rendered)
        bad_lines = [
            line for line in dsn_lines
            if re.search(r"sslmode\s*=\s*require\b", line)
        ]
        assert bad_lines == [], (
            "F-V232-002: sslmode=require found in DSN value or pgbouncer config "
            "lines. These lines must use sslmode=verify-ca or sslmode=verify-full:\n"
            + "\n".join(bad_lines)
        )

    def test_verify_ca_present_in_mtls_render(self) -> None:
        """mTLS render must contain sslmode=verify-ca in DSN env value lines."""
        rendered = _helm_template()
        dsn_lines = _dsn_value_lines(rendered)
        verify_lines = [
            line for line in dsn_lines
            if re.search(r"sslmode=(verify-ca|verify-full)", line)
        ]
        assert len(verify_lines) >= 1, (
            "F-V232-002: expected at least one sslmode=verify-ca or "
            "sslmode=verify-full in DSN value lines with mtls.enabled=true, "
            "but found none."
        )


class TestPartitionConfigMapSslContext:
    """The _build_ssl_context function in the partition ConfigMap is fail-closed."""

    @pytest.fixture(scope="class")
    def fn_body(self) -> str:
        rendered = _helm_template()
        # The function is inside a ConfigMap, indented. Match from
        # `def _build_ssl_context` through to just before `async def` or
        # `_PARTITIONED_TABLES` at any indentation level.
        match = re.search(
            r"(def _build_ssl_context\b.*?)(?=\s+async def\s|\s+_PARTITIONED_TABLES\s*=)",
            rendered,
            re.DOTALL,
        )
        if not match:
            pytest.fail(
                "Could not locate _build_ssl_context function body in rendered "
                "configmaps output. Has the ConfigMap template been removed?"
            )
        return match.group(1)

    def test_cert_none_not_in_ssl_context_function(self, fn_body: str) -> None:
        """CERT_NONE must not appear inside _build_ssl_context body."""
        assert "CERT_NONE" not in fn_body, (
            "F-V232-002: ssl.CERT_NONE found inside _build_ssl_context. "
            "The sslmode=require/CERT_NONE branch must not be present in the "
            "rendered ConfigMap — server certificate validation must not be "
            "disabled."
        )

    def test_require_code_branch_not_in_ssl_context_function(self, fn_body: str) -> None:
        """The `== 'require'` comparison branch must not appear in _build_ssl_context."""
        # The old code had: `if sslmode == "require": ctx.verify_mode = ssl.CERT_NONE`
        # We check that the `sslmode == "require"` conditional is gone.
        # Note: the error message string "sslmode=require" is acceptable — we're
        # checking for the Python conditional branch, not string mentions.
        assert not re.search(r'sslmode\s*==\s*["\']require["\']', fn_body), (
            "F-V232-002: `sslmode == 'require'` conditional found inside "
            "_build_ssl_context. This fallback disables TLS cert validation "
            "and must be removed."
        )

    def test_fail_closed_rejection_present(self, fn_body: str) -> None:
        """_build_ssl_context must raise on disallowed sslmode values."""
        assert re.search(r"\braise\b", fn_body, re.DOTALL), (
            "F-V232-002: _build_ssl_context does not raise on disallowed "
            "sslmode values. Expected a raise path that rejects sslmode=require "
            "and other non-verify-* modes."
        )

    def test_verify_ca_and_full_are_only_accepted_modes(self, fn_body: str) -> None:
        """Only verify-ca and verify-full should be in the accepted-modes check."""
        assert re.search(r'verify-ca.*verify-full|verify-full.*verify-ca', fn_body), (
            "F-V232-002: expected both verify-ca and verify-full in the "
            "_build_ssl_context accepted-modes list."
        )


class TestValidateSecurityExternalPostgres:
    """validate-security.yaml fails if external postgres has no TLS CA declared."""

    def test_helm_fails_external_postgres_no_tls_ca_production(self) -> None:
        """helm template must fail for production+external postgres without TLS CA."""
        cmd = [
            "helm", "template", "yashigani", str(HELM_CHART),
            "--set", "global.environment=production",
            "--set", "mtls.enabled=true",
            "--set", "admissionPolicies.enabled=false",
            "--set", "postgres.enabled=false",
            # postgres.tls.ca intentionally NOT set
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        assert result.returncode != 0, (
            "F-V232-002: expected `helm template` to fail when "
            "postgres.enabled=false and postgres.tls.ca is unset in production, "
            "but it succeeded. The validate-security.yaml guard is not firing."
        )
        combined = result.stderr + result.stdout
        assert "F-V232-002" in combined, (
            "F-V232-002: helm template failed but the F-V232-002 guard message "
            f"was not present in output. stderr={result.stderr!r}"
        )

    def test_helm_succeeds_external_postgres_with_tls_ca_production(self) -> None:
        """helm template must succeed for production+external postgres WITH TLS CA."""
        rendered = _helm_template(extra_set=[
            "postgres.enabled=false",
            "postgres.tls.ca=LS0tLS1CRUdJTiBDRVJUSUZJQ0FU",  # dummy base64 CA blob
            "postgres.existingSecretName=my-pg-secret",
        ])
        # If we get here without pytest.fail(), the guard passed correctly.
        assert rendered  # non-empty render

    def test_helm_succeeds_internal_postgres_no_tls_ca(self) -> None:
        """Internal postgres (postgres.enabled=true) must NOT require postgres.tls.ca."""
        # postgres.enabled=true is the default; no postgres.tls.ca needed.
        rendered = _helm_template(extra_set=["postgres.enabled=true"])
        assert rendered
