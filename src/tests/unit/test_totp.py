"""
Tests for yashigani.auth.totp.

Covers:
  - generate_totp_secret produces valid base32 secret
  - generate_provisioning returns TotpProvisioning with uri
  - generate_recovery_code_set count and format
  - verify_totp happy path (using pyotp)
  - verify_totp rejects wrong codes
  - verify_recovery_code happy path
  - verify_recovery_code rejects wrong codes
  - codes_remaining count
  - Recovery code format is constant (change detection for IC-11)
"""
from __future__ import annotations

import re
import time
from unittest.mock import patch

import pytest


def _import_totp():
    try:
        from yashigani.auth.totp import (
            TotpProvisioning,
            RecoveryCodeSet,
            _RECOVERY_CODE_COUNT,
            _RECOVERY_CODE_FORMAT,
            _generate_recovery_codes,
            generate_totp_secret,
            generate_provisioning,
            generate_recovery_code_set,
            verify_totp,
            verify_recovery_code,
            codes_remaining,
            TOTP_ALGO_SHA1,
            TOTP_ALGO_SHA256,
            TOTP_ALGO_SHA512,
            LEGACY_TOTP_ALGO,
            ROLE_TOTP_ALGO,
            ROLE_TOTP_DIGITS,
            _totp_at,
        )
        return (
            TotpProvisioning, RecoveryCodeSet, _RECOVERY_CODE_COUNT, _RECOVERY_CODE_FORMAT,
            _generate_recovery_codes, generate_totp_secret, generate_provisioning,
            generate_recovery_code_set, verify_totp, verify_recovery_code, codes_remaining,
        )
    except ImportError as exc:
        pytest.skip(f"totp module not importable: {exc}")


class TestRecoveryCodeConstants:
    def test_recovery_code_count_is_8(self):
        _, _, count, fmt, *_ = _import_totp()
        assert count == 8, (
            "IC-11: _RECOVERY_CODE_COUNT changed — existing recovery codes in DB are now invalid. "
            "Add a migration to regenerate codes before changing this constant."
        )

    def test_recovery_code_format_stable(self):
        _, _, _, fmt, *_ = _import_totp()
        assert fmt == "{:04X}-{:04X}-{:04X}", (
            "IC-11: _RECOVERY_CODE_FORMAT changed — existing recovery codes in DB are now invalid. "
            "Add a migration to regenerate codes before changing this constant."
        )


class TestGenerateTotpSecret:
    def test_returns_string(self):
        (_, _, _, _, _, generate_totp_secret, *_) = _import_totp()
        secret = generate_totp_secret()
        assert isinstance(secret, str)

    def test_is_valid_base32(self):
        import base64
        (_, _, _, _, _, generate_totp_secret, *_) = _import_totp()
        secret = generate_totp_secret()
        # Pad to a multiple of 8 characters as required by base64.b32decode.
        padded = secret.upper()
        remainder = len(padded) % 8
        if remainder:
            padded += "=" * (8 - remainder)
        try:
            base64.b32decode(padded)
        except Exception as exc:
            pytest.fail(f"Secret is not valid base32: {exc}")

    def test_uniqueness(self):
        (_, _, _, _, _, generate_totp_secret, *_) = _import_totp()
        secrets = {generate_totp_secret() for _ in range(10)}
        assert len(secrets) == 10


class TestGenerateProvisioning:
    def test_provisioning_has_uri(self):
        (TotpProvisioning, _, _, _, _, _, generate_provisioning, *_) = _import_totp()
        prov = generate_provisioning(account_name="alice", issuer="Yashigani")
        assert prov.provisioning_uri
        assert "otpauth://" in prov.provisioning_uri

    def test_provisioning_has_secret(self):
        (TotpProvisioning, _, _, _, _, _, generate_provisioning, *_) = _import_totp()
        prov = generate_provisioning(account_name="alice", issuer="Yashigani")
        assert prov.secret_b32
        assert isinstance(prov.secret_b32, str)


class TestGenerateRecoveryCodeSet:
    def test_correct_count(self):
        (_, RecoveryCodeSet, count, _, _generate_recovery_codes, _, _, generate_recovery_code_set, *_) = _import_totp()
        plaintext = _generate_recovery_codes()
        rcs = generate_recovery_code_set(plaintext)
        assert len(rcs.hashes) == count

    def test_code_format_matches_constant(self):
        import re
        (_, _, _, _, _generate_recovery_codes, _, _, generate_recovery_code_set, *_) = _import_totp()
        plaintext = _generate_recovery_codes()
        pattern = re.compile(r"^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$")
        for code in plaintext:
            assert pattern.match(code), f"Code {code!r} doesn't match expected format"

    def test_codes_are_unique(self):
        (_, _, _, _, _generate_recovery_codes, _, _, generate_recovery_code_set, *_) = _import_totp()
        plaintext = _generate_recovery_codes()
        assert len(set(plaintext)) == len(plaintext)


class TestVerifyTotp:
    def test_valid_code_accepted(self):
        try:
            import pyotp
        except ImportError:
            pytest.skip("pyotp not installed")

        (_, _, _, _, _, generate_totp_secret, _, _, verify_totp, *_) = _import_totp()
        secret = generate_totp_secret()
        # pyotp default (no digest kwarg) = HMAC-SHA1 per RFC 6238, matching backoffice
        totp = pyotp.TOTP(secret)
        current_code = totp.now()
        assert verify_totp(secret_b32=secret, code=current_code, used_codes_cache=set()) is True

    def test_wrong_code_rejected(self):
        (_, _, _, _, _, generate_totp_secret, _, _, verify_totp, *_) = _import_totp()
        secret = generate_totp_secret()
        assert verify_totp(secret_b32=secret, code="000000", used_codes_cache=set()) is False

    def test_empty_code_rejected(self):
        (_, _, _, _, _, generate_totp_secret, _, _, verify_totp, *_) = _import_totp()
        secret = generate_totp_secret()
        assert verify_totp(secret_b32=secret, code="", used_codes_cache=set()) is False


class TestStepupReplayIsGlobalNotPerPurpose:
    """
    FIND-B-STEPUP-REPLAY-REGRESSION-20260806.

    Supersedes/replaces the now-deleted TestStepupFirstAttemptReplayScoping
    (introduced by FIND-B-STEPUP-FIRST-ATTEMPT, 2026-08-05, commit dc43a0ec).

    RCA of the ORIGINAL finding: a fresh admin session's FIRST /auth/stepup
    call, submitted within the same 30s window as login, presented the SAME
    still-displayed TOTP code login had already consumed — and was rejected
    as a "replay", even though no attacker replay occurred.

    RCA of why the ORIGINAL FIX was wrong (this regression, caught in
    consolidated-retest Tier-A on mustui/integ/v412-retest-fixes2-20260806):
    the fix scoped the replay-cache key by an explicit `purpose` string
    (`secret:purpose:window`), giving login/stepup/change_password/etc. each
    their own replay namespace. That traded away a real security property —
    RFC 6238 / ASVS V2.8.3 / V6.8.4 require TOTP single-use to be GLOBAL: a
    code consumed for ANY verification event must be rejected for EVERY
    subsequent verification event against that secret, regardless of why it
    is being checked. Under purpose-scoping, a code observed/captured at
    LOGIN remained independently valid for use at STEPUP (or any other
    purpose) within the same window — reintroducing exactly the cross-event
    replay TOTP single-use exists to prevent. It also broke three test
    doubles' `_verify_totp_with_replay()` signatures across
    tests/security/test_pentest_auth_identity_secrets.py,
    tests/conformance/test_auth.py, and
    tests/conformance/test_conformance_auth_identity_rbac.py (none accepted
    the new `purpose` kwarg → TypeError on every production call site that
    passed it), which is what actually surfaced as 5 failing conformance/
    security tests in the consolidated retest.

    Fix: verify_totp() / _verify_totp_with_replay() are reverted to a pure
    GLOBAL secret+window cache key — no purpose dimension. The original UX
    complaint is resolved at the CLIENT layer instead (coherent methodology
    §4.17: use a FRESH OTP code for step-up, never reuse login's code) —
    proven below by test_fresh_code_after_login_succeeds_at_stepup.
    """

    def test_login_then_stepup_same_code_now_correctly_rejected(self):
        """
        The exact scenario FIND-B-STEPUP-FIRST-ATTEMPT's fix wrongly
        allowed: a code consumed by one verification event (simulating
        LOGIN) must be rejected by a second verification event sharing the
        same replay cache (simulating an immediate STEPUP) — this is the
        Postgres-backed used_totp_codes table in production, shared across
        every _verify_totp_with_replay() call for an account regardless of
        caller. Global single-use, not per-purpose.
        """
        try:
            import pyotp
        except ImportError:
            pytest.skip("pyotp not installed")

        (_, _, _, _, _, generate_totp_secret, _, _, verify_totp, *_) = _import_totp()
        secret = generate_totp_secret()
        totp = pyotp.TOTP(secret)
        code = totp.now()

        shared_cache: set = set()

        login_ok = verify_totp(secret_b32=secret, code=code, used_codes_cache=shared_cache)
        assert login_ok is True, "sanity: login's own TOTP submission must succeed"

        stepup_ok = verify_totp(secret_b32=secret, code=code, used_codes_cache=shared_cache)
        assert stepup_ok is False, (
            "FIND-B-STEPUP-REPLAY-REGRESSION-20260806: a code already "
            "consumed by one verification event MUST be rejected by any "
            "subsequent verification event sharing the replay cache, "
            "regardless of purpose (RFC 6238 / ASVS V2.8.3 / V6.8.4 global "
            "single-use). Purpose-scoping the cache key is the reverted, "
            "insecure behaviour."
        )

    def test_fresh_code_after_login_succeeds_at_stepup(self):
        """
        The CORRECT resolution of the original UX complaint: once the TOTP
        window has rolled over (a genuinely fresh code), step-up succeeds
        normally. No server-side replay-cache change is needed or wanted —
        the fix is "wait for / submit a fresh code", not "weaken global
        single-use".
        """
        try:
            import pyotp
        except ImportError:
            pytest.skip("pyotp not installed")

        (_, _, _, _, _, generate_totp_secret, _, _, verify_totp, *_) = _import_totp()
        secret = generate_totp_secret()
        totp = pyotp.TOTP(secret)

        shared_cache: set = set()
        now_ts = int(time.time())
        login_code = totp.at(now_ts)
        next_code = totp.at(now_ts + 30)
        if login_code == next_code:
            pytest.skip("code collision between windows — unlikely but skip to avoid false failure")

        login_ok = verify_totp(secret_b32=secret, code=login_code, used_codes_cache=shared_cache)
        assert login_ok is True

        with patch("yashigani.auth.totp.time") as mock_time:
            mock_time.time.return_value = float(now_ts + 30)
            stepup_ok = verify_totp(secret_b32=secret, code=next_code, used_codes_cache=shared_cache)
        assert stepup_ok is True, (
            "a genuinely fresh (next-window) code must succeed at stepup "
            "even though the PREVIOUS window's code was already consumed "
            "at login — this is the client-side mitigation for the "
            "original FIND-B-STEPUP-FIRST-ATTEMPT UX complaint"
        )

    def test_replay_of_same_code_still_blocked_two_calls(self):
        """
        Sanity companion: two back-to-back verifications with the identical
        code must still be rejected on the second call (real anti-replay,
        unaffected by this revert either way)."""
        try:
            import pyotp
        except ImportError:
            pytest.skip("pyotp not installed")

        (_, _, _, _, _, generate_totp_secret, _, _, verify_totp, *_) = _import_totp()
        secret = generate_totp_secret()
        totp = pyotp.TOTP(secret)
        code = totp.now()
        shared_cache: set = set()

        first = verify_totp(secret_b32=secret, code=code, used_codes_cache=shared_cache)
        second = verify_totp(secret_b32=secret, code=code, used_codes_cache=shared_cache)
        assert first is True
        assert second is False


class TestVerifyRecoveryCode:
    def test_valid_code_accepted(self):
        (_, _, _, _, _generate_recovery_codes, _, _, generate_recovery_code_set, _, verify_recovery_code, codes_remaining) = _import_totp()
        plaintext = _generate_recovery_codes()
        rcs = generate_recovery_code_set(plaintext)
        first_code = plaintext[0]
        matched, idx = verify_recovery_code(code=first_code, code_set=rcs)
        assert matched is True
        assert idx == 0

    def test_wrong_code_rejected(self):
        (_, _, _, _, _generate_recovery_codes, _, _, generate_recovery_code_set, _, verify_recovery_code, _) = _import_totp()
        plaintext = _generate_recovery_codes()
        rcs = generate_recovery_code_set(plaintext)
        matched, idx = verify_recovery_code(code="0000-0000-0000", code_set=rcs)
        assert matched is False
        assert idx == -1

    def test_codes_remaining_decrements(self):
        (_, _, count, _, _generate_recovery_codes, _, _, generate_recovery_code_set, _, verify_recovery_code, codes_remaining) = _import_totp()
        plaintext = _generate_recovery_codes()
        rcs = generate_recovery_code_set(plaintext)
        initial = codes_remaining(rcs)
        assert initial == count
        first_code = plaintext[0]
        matched, idx = verify_recovery_code(code=first_code, code_set=rcs)
        assert matched is True
        # Caller is responsible for marking the code used after a successful match.
        rcs.used[idx] = True
        assert codes_remaining(rcs) == initial - 1
