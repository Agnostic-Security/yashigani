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


class TestStepupFirstAttemptReplayScoping:
    """
    FIND-B-STEPUP-FIRST-ATTEMPT (2026-08-05) regression.

    Root cause: verify_totp()'s replay-cache key was `secret:window_slot`,
    shared globally regardless of WHY the code was being verified. A code
    consumed at LOGIN and the SAME still-displayed code presented moments
    later to POST /auth/stepup (a distinct ASVS V6.8.4 re-authentication
    event) collided on the identical key — so the FIRST stepup attempt in a
    fresh admin session, submitted within the same 30s window as login,
    was always rejected as a "replay" even though no attacker replay
    occurred. The fix scopes the replay key by an explicit `purpose`
    parameter so login/stepup/change_password/etc. each get an independent
    replay namespace, while still blocking a genuine replay WITHIN one
    purpose.

    This test reproduces the exact collision at the verify_totp() level
    (the pure function both pg_auth._verify_totp_with_replay and
    local_auth.LocalAuthService feed into) using a SHARED cache — mirroring
    the Postgres used_totp_codes table, which is loaded and checked in full
    on every call regardless of caller. Fails before the purpose-scoping
    fix (login consumes the window, stepup's identical code is then wrongly
    rejected); passes after.
    """

    def test_login_then_stepup_same_code_no_longer_cross_purpose_replay(self):
        try:
            import pyotp
        except ImportError:
            pytest.skip("pyotp not installed")

        (_, _, _, _, _, generate_totp_secret, _, _, verify_totp, *_) = _import_totp()
        secret = generate_totp_secret()
        totp = pyotp.TOTP(secret)
        code = totp.now()

        # One shared cache, exactly as the Postgres-backed replay cache is
        # shared across every _verify_totp_with_replay() call for an
        # account (it loads ALL non-expired used_totp_codes rows on every
        # invocation, regardless of which route is calling).
        shared_cache: set = set()

        # First verification event: LOGIN consumes this window's code.
        login_ok = verify_totp(
            secret_b32=secret, code=code, used_codes_cache=shared_cache,
            purpose="login",
        )
        assert login_ok is True, "sanity: login's own TOTP submission must succeed"

        # Second verification event: STEPUP, same session, same still-valid
        # code, same 30s window (e.g. 2-9s after login, per the live
        # reproduction). Before the fix this returned False (401
        # invalid_totp_code on the FIRST stepup attempt). After the fix,
        # stepup has its own replay namespace and accepts it.
        stepup_ok = verify_totp(
            secret_b32=secret, code=code, used_codes_cache=shared_cache,
            purpose="stepup",
        )
        assert stepup_ok is True, (
            "FIND-B-STEPUP-FIRST-ATTEMPT regression: a code already consumed "
            "for 'login' must not poison the FIRST 'stepup' verification of "
            "the same window — purpose scoping must isolate the two events."
        )

    def test_replay_within_same_purpose_still_blocked(self):
        """
        The fix must NOT weaken anti-replay: submitting the SAME code twice
        for the SAME purpose (e.g. two stepup calls back-to-back with the
        identical code) must still be rejected as a genuine replay.
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

        first = verify_totp(
            secret_b32=secret, code=code, used_codes_cache=shared_cache,
            purpose="stepup",
        )
        second = verify_totp(
            secret_b32=secret, code=code, used_codes_cache=shared_cache,
            purpose="stepup",
        )
        assert first is True
        assert second is False, (
            "Real same-purpose replay must still be rejected — purpose "
            "scoping must not weaken anti-replay within one purpose."
        )

    def test_default_purpose_preserves_prior_behaviour(self):
        """
        Callers that don't pass `purpose` (legacy call sites / existing
        tests) must see byte-identical behaviour to pre-fix: a code is
        still blocked from replay when purpose is omitted both times.
        """
        try:
            import pyotp
        except ImportError:
            pytest.skip("pyotp not installed")

        (_, _, _, _, _, generate_totp_secret, _, _, verify_totp, *_) = _import_totp()
        secret = generate_totp_secret()
        totp = pyotp.TOTP(secret)
        code = totp.now()
        cache: set = set()

        assert verify_totp(secret_b32=secret, code=code, used_codes_cache=cache) is True
        assert verify_totp(secret_b32=secret, code=code, used_codes_cache=cache) is False


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
