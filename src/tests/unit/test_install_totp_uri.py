"""
Regression test: install.sh _gen_totp_uri must use HMAC-SHA1 (RFC 6238 default)
for universal authenticator-app compatibility.

Decision (2026-06-14, YSG-RISK-078): reverted from SHA-256 (P0-10 / maintainer
directive 2026-05-01) to SHA-1 because 19/20 test users' authenticator apps do not
support SHA-256 TOTP. HMAC-SHA1 is cryptographically secure for OTP (SHA-1 collision
attacks do not affect HMAC). SHA-1 is the RFC 6238 default and is universally supported.

Coverage:
- install.sh _gen_totp_uri does NOT emit algorithm=SHA256
- install.sh _gen_totp_uri either emits algorithm=SHA1 or omits the parameter
  (omitting = SHA1 default, per otpauth:// spec)
- install.sh _gen_totp_uri emits digits=6
- install.sh _gen_totp_uri emits period=30
- pyotp provisioning_uri with default digest also uses SHA-1 (parity check)
- A standard SHA-1 authenticator code verifies against pyotp TOTP (no digest arg)
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
# Tests: shell URI emission
# ---------------------------------------------------------------------------

class TestInstallShTotpUri:
    """Verify _gen_totp_uri produces a URI compatible with all authenticator apps."""

    def _get_uri(self, username: str = "testadmin", secret: str = "JBSWY3DPEHPK3PXP") -> str:
        return _source_and_run(f'_gen_totp_uri "{username}" "{secret}"')

    def test_does_not_contain_algorithm_sha256(self):
        """
        REGRESSION TEST (YSG-RISK-078): URI must NOT contain algorithm=SHA256.
        SHA-256 TOTP was a usability blocker — 19/20 test users' apps did not
        support it and silently produced wrong codes. Reverted 2026-06-14.
        """
        uri = self._get_uri()
        assert "algorithm=SHA256" not in uri, (
            f"YSG-RISK-078: otpauth URI must not use algorithm=SHA256 — reverted to "
            f"HMAC-SHA1 (RFC 6238 default) for universal authenticator-app compatibility.\n"
            f"URI was: {uri}"
        )

    def test_algorithm_is_sha1_or_omitted(self):
        """
        URI must either omit algorithm (= SHA1 by RFC 6238 default) or
        explicitly state algorithm=SHA1. Both are equivalent and universally supported.
        """
        uri = self._get_uri()
        # Acceptable: no algorithm param at all, or algorithm=SHA1
        if "algorithm=" in uri:
            assert "algorithm=SHA1" in uri, (
                f"If algorithm param is present, it must be SHA1: {uri}"
            )

    def test_contains_digits_6(self):
        uri = self._get_uri()
        assert "digits=6" in uri, f"URI missing digits=6: {uri}"

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

    def test_both_admin_uris_do_not_contain_sha256(self):
        """Both admin URIs must not specify SHA-256 (usability blocker — YSG-RISK-078)."""
        uri1 = self._get_uri(username="admin1", secret="JBSWY3DPEHPK3PXP")
        uri2 = self._get_uri(username="admin2", secret="MFRA2YLNMFRA2YLN")
        assert "algorithm=SHA256" not in uri1, f"admin1 URI must not use SHA256: {uri1}"
        assert "algorithm=SHA256" not in uri2, f"admin2 URI must not use SHA256: {uri2}"


# ---------------------------------------------------------------------------
# Tests: pyotp parity — shell URI must agree with pyotp's own URI
# ---------------------------------------------------------------------------

class TestShellUriMatchesPyotp:
    """
    Verify that the algorithm in the shell-emitted URI matches what
    pyotp.TOTP() (no digest kwarg = SHA-1 default) emits.
    Both must use SHA-1 so authenticator apps and pyotp agree.
    """

    def test_algorithm_matches_pyotp_uri(self):
        try:
            import pyotp
        except ImportError:
            pytest.skip("pyotp not installed")

        secret = "JBSWY3DPEHPK3PXP"
        # pyotp default (no digest kwarg) = SHA-1 per RFC 6238
        pyotp_uri = pyotp.TOTP(
            secret, issuer="Yashigani"
        ).provisioning_uri(name="testadmin", issuer_name="Yashigani")

        shell_uri = _source_and_run(f'_gen_totp_uri "testadmin" "{secret}"')

        # Neither URI should specify SHA256
        assert "algorithm=SHA256" not in pyotp_uri, (
            f"pyotp URI unexpectedly contains algorithm=SHA256: {pyotp_uri}"
        )
        assert "algorithm=SHA256" not in shell_uri, (
            f"shell URI must not contain algorithm=SHA256: {shell_uri}"
        )

    def test_sha1_code_verifies_against_default_pyotp(self):
        """
        End-to-end parity: a code generated by default pyotp (SHA-1)
        must verify against pyotp.TOTP() with no digest argument.
        Also confirms SHA-1 and SHA-256 codes differ for the same secret.
        """
        try:
            import pyotp
            import hashlib
        except ImportError:
            pytest.skip("pyotp not installed")

        secret = pyotp.random_base32()

        totp_sha1 = pyotp.TOTP(secret)           # RFC 6238 default: SHA-1
        totp_sha256 = pyotp.TOTP(secret, digest=hashlib.sha256)

        code_sha1 = totp_sha1.now()

        # SHA-1 code must verify against SHA-1 TOTP
        assert totp_sha1.verify(code_sha1), "SHA-1 code must verify with SHA-1 TOTP"

        # In virtually all cases SHA-1 and SHA-256 codes differ (prove they are
        # distinct algorithms for the same secret). Skip gracefully on collision.
        code_sha256 = totp_sha256.now()
        if code_sha1 == code_sha256:
            pytest.skip("SHA-1 and SHA-256 codes collided for this secret/window — retry")
        assert not totp_sha256.verify(code_sha1), (
            "SHA-1 code must NOT verify against SHA-256 TOTP — confirms algorithm isolation"
        )
