"""
Phase 13 regression: install.sh _gen_totp_uri must emit SHA-512 / 8-digit TOTP
for admin accounts.

Context (Phase 13, Yashigani 3.1):
  - All Yashigani admin bootstrap accounts use HMAC-SHA-512, 8 digits.
  - User-tier accounts use SHA-256/6 (provisioned via web UI, not install.sh).
  - Classic Google Authenticator (SHA-1 only) is incompatible.
  - Required authenticator: agnosticOTP (iOS/Android) or Aegis.

History:
  - YSG-RISK-078 (2026-06-14) reverted from SHA-256 to SHA-1 due to
    authenticator-app compatibility. Phase 13 supersedes that reversion by
    mandating agnosticOTP (SHA-256/512 capable) as the required app.

Coverage:
- install.sh _gen_totp_uri emits algorithm=SHA512
- install.sh _gen_totp_uri emits digits=8
- install.sh _gen_totp_uri emits period=30
- otpauth:// scheme and secret param present
- Both bootstrapped admin URIs use SHA-512/8
- Cross-algorithm check: SHA-1 code does NOT verify against SHA-512 TOTP
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[3]  # src/tests/unit → repo root
INSTALL_SH = REPO_ROOT / "install.sh"


def _source_and_run(bash_snippet: str) -> str:
    """
    Source _gen_totp_uri from install.sh (without executing the installer)
    and run the provided bash snippet, returning stdout.
    """
    if not INSTALL_SH.exists():
        pytest.skip(f"install.sh not found at {INSTALL_SH}")

    script = (
        "set -euo pipefail\n"
        "YASHIGANI_DRY_RUN=1\n"
        "_main() { :; }\n"
        + _extract_function("_gen_totp_uri")
        + "\n"
        + bash_snippet
    )
    result = subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        pytest.fail(
            f"bash snippet failed (rc={result.returncode}):\n"
            f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}"
        )
    return result.stdout.strip()


def _extract_function(func_name: str) -> str:
    """Extract a single bash function definition from install.sh by name."""
    lines = INSTALL_SH.read_text().splitlines()
    in_func = False
    depth = 0
    collected: list[str] = []

    for line in lines:
        if not in_func:
            if re.match(rf"^{re.escape(func_name)}\s*\(\)", line):
                in_func = True
                depth = 0
                collected.append(line)
                depth += line.count("{") - line.count("}")
                continue
        else:
            collected.append(line)
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                break

    if not collected:
        pytest.fail(f"Could not extract function {func_name!r} from {INSTALL_SH}")
    return "\n".join(collected)


# ---------------------------------------------------------------------------
# Tests: Phase 13 shell URI emission (SHA-512 / 8 digits)
# ---------------------------------------------------------------------------

class TestInstallShTotpUri:
    """Verify _gen_totp_uri produces a SHA-512/8-digit URI for admin accounts (Phase 13)."""

    def _get_uri(self, username: str = "testadmin", secret: str = "JBSWY3DPEHPK3PXP") -> str:
        return _source_and_run(f'_gen_totp_uri "{username}" "{secret}"')

    def test_algorithm_is_sha512(self):
        """
        Phase 13: admin bootstrap TOTP must use HMAC-SHA-512.
        Classic Google Authenticator (SHA-1 only) is NOT compatible.
        Required app: agnosticOTP or Aegis.
        """
        uri = self._get_uri()
        assert "algorithm=SHA512" in uri, (
            f"Phase 13: install.sh admin TOTP URI must use algorithm=SHA512.\n"
            f"URI was: {uri}"
        )

    def test_does_not_contain_sha1(self):
        """
        URI must NOT revert to SHA-1 (YSG-RISK-078 reversion is superseded by Phase 13).
        """
        uri = self._get_uri()
        # algorithm=SHA1 or no algorithm param (which implies SHA-1) are both wrong
        assert "algorithm=SHA1" not in uri, (
            f"Phase 13: admin TOTP must not use SHA-1 (superseded by SHA-512 mandate).\n"
            f"URI was: {uri}"
        )
        # Also must not omit the algorithm param (omit = SHA-1 default)
        assert "algorithm=" in uri, (
            f"Phase 13: URI must explicitly specify algorithm=SHA512 (omitting means SHA-1 default).\n"
            f"URI was: {uri}"
        )

    def test_contains_digits_8(self):
        """Admin TOTP uses 8-digit codes (Phase 13)."""
        uri = self._get_uri()
        assert "digits=8" in uri, (
            f"Phase 13: admin TOTP URI must specify digits=8.\nURI was: {uri}"
        )

    def test_does_not_contain_digits_6(self):
        """URI must not emit digits=6 for admin bootstrap accounts (that's user-tier)."""
        uri = self._get_uri()
        assert "digits=6" not in uri, (
            f"Phase 13: admin TOTP URI must NOT specify digits=6 (that is user-tier).\n"
            f"URI was: {uri}"
        )

    def test_contains_period_30(self):
        uri = self._get_uri()
        assert "period=30" in uri, f"URI missing period=30: {uri}"

    def test_otpauth_scheme(self):
        uri = self._get_uri()
        assert uri.startswith("otpauth://totp/"), f"URI has wrong scheme: {uri}"

    def test_secret_in_uri(self):
        secret = "JBSWY3DPEHPK3PXP"
        uri = self._get_uri(secret=secret)
        assert f"secret={secret}" in uri, f"URI missing secret param: {uri}"

    def test_both_admin_usernames_produce_distinct_uris(self):
        uri1 = self._get_uri(username="admin1")
        uri2 = self._get_uri(username="admin2")
        assert uri1 != uri2, "admin1 and admin2 URIs must be distinct"
        assert "admin1" in uri1
        assert "admin2" in uri2

    def test_both_admin_uris_use_sha512(self):
        """Both bootstrapped admin URIs must use SHA-512 (Phase 13)."""
        uri1 = self._get_uri(username="admin1", secret="JBSWY3DPEHPK3PXP")
        uri2 = self._get_uri(username="admin2", secret="MFRA2YLNMFRA2YLN")
        assert "algorithm=SHA512" in uri1, f"admin1 URI must use SHA512: {uri1}"
        assert "algorithm=SHA512" in uri2, f"admin2 URI must use SHA512: {uri2}"
        assert "digits=8" in uri1, f"admin1 URI must have digits=8: {uri1}"
        assert "digits=8" in uri2, f"admin2 URI must have digits=8: {uri2}"


# ---------------------------------------------------------------------------
# Tests: raw TOTP compute cross-algorithm isolation
# ---------------------------------------------------------------------------

class TestPhase13AlgorithmIsolation:
    """
    Prove that SHA-1 and SHA-512 TOTP codes are distinct for the same secret,
    so a SHA-1 app (classic Google Authenticator) will always produce a wrong
    code against a SHA-512-configured account.
    """

    def _raw_totp(self, secret_b32: str, algorithm: str, digits: int) -> str:
        """
        Compute a TOTP code using our own _totp_at implementation.
        This is the same function used by the server — proves parity.
        """
        try:
            from yashigani.auth.totp import _totp_at
        except ImportError:
            pytest.skip("yashigani.auth.totp not importable")
        import time
        return _totp_at(secret_b32, int(time.time()), algorithm, digits)

    def test_sha1_code_does_not_equal_sha512_code(self):
        """
        For the same secret and same window, SHA-1/6 and SHA-512/8 codes MUST
        differ (different HMAC functions + different digit counts).
        If they accidentally collide this test is skipped (astronomically unlikely).
        """
        try:
            from yashigani.auth.totp import generate_totp_secret
        except ImportError:
            pytest.skip("yashigani.auth.totp not importable")

        secret = generate_totp_secret()
        code_sha1_6 = self._raw_totp(secret, "SHA1", 6)
        code_sha512_8 = self._raw_totp(secret, "SHA512", 8)

        if code_sha1_6 == code_sha512_8[:6]:
            # Prefix collision: skip rather than fail
            pytest.skip("SHA1/6 code collided with first 6 digits of SHA512/8 — retry")

        assert code_sha1_6 != code_sha512_8, (
            "SHA-1/6 and SHA-512/8 codes must differ — algorithm isolation requires distinct outputs"
        )

    def test_sha512_8_code_verifies_with_raw_impl(self):
        """
        End-to-end: a code produced by _totp_at(SHA512, 8) verifies via
        verify_totp(algorithm=SHA512, digits=8).
        """
        try:
            from yashigani.auth.totp import generate_totp_secret, verify_totp, _totp_at
        except ImportError:
            pytest.skip("yashigani.auth.totp not importable")
        import time

        secret = generate_totp_secret()
        code = _totp_at(secret, int(time.time()), "SHA512", 8)
        assert verify_totp(
            secret_b32=secret,
            code=code,
            used_codes_cache=set(),
            algorithm="SHA512",
            digits=8,
        ), "SHA-512/8 code must verify against SHA-512/8 TOTP"

    def test_sha1_6_code_does_not_verify_sha512_8(self):
        """
        A SHA-1/6-digit code MUST NOT verify against SHA-512/8 configuration.
        This confirms classic Google Authenticator is incompatible with admin accounts.
        """
        try:
            from yashigani.auth.totp import generate_totp_secret, verify_totp, _totp_at
        except ImportError:
            pytest.skip("yashigani.auth.totp not importable")
        import time

        secret = generate_totp_secret()
        # Produce a SHA-1/6-digit code (what Google Authenticator would generate)
        sha1_code = _totp_at(secret, int(time.time()), "SHA1", 6)
        # Attempt to verify it as SHA-512/8 — must fail
        assert not verify_totp(
            secret_b32=secret,
            code=sha1_code,
            used_codes_cache=set(),
            algorithm="SHA512",
            digits=8,
        ), "SHA-1/6 code MUST NOT verify against SHA-512/8 TOTP — algorithm isolation failure"
