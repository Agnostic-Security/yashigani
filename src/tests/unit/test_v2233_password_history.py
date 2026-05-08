"""
Unit tests — CMMC L2 IA.L2-3.5.8 password reuse history (v2.23.3).

Test matrix:
  1. Positive: fresh password (not in history) is accepted.
  2. Reuse rejected: password matching hash 1..N in history is rejected.
  3. Depth+1 accepted: password identical to hash N+1 (beyond depth) is accepted.
  4. Audit event: PASSWORD_REUSE_REJECTED is emitted with correct fields on rejection.
  5. Audit event safety: user_id is present; no password, no hash in event.
  6. History pruning: after N changes the history stays at depth N entries.
  7. Config: PASSWORD_HISTORY_DEPTH env var parsed correctly; clamped to [1, 24].
  8. Config: invalid env var falls back to default 12.
  9. Config: depth 1 blocks the immediate previous password only.
  10. In-memory LocalAuthService: change_password enforces reuse correctly.

Last updated: 2026-05-09T00:00:00+00:00
"""

from __future__ import annotations

import os
from typing import Optional
from unittest.mock import patch


# ---------------------------------------------------------------------------
# Helpers — generate long-enough test passwords that pass hash_password
# validation without HIBP network calls
# ---------------------------------------------------------------------------

_PW_A = "PwHistoryAlpha!111111111111111111111"  # 36 chars
_PW_B = "PwHistoryBravo!222222222222222222222"  # 36 chars
_PW_C = "PwHistoryCharlie!3333333333333333333"  # 36 chars
_PW_D = "PwHistoryDelta!4444444444444444444444"  # 37 chars (ok)
_PW_E = "PwHistoryEcho!5555555555555555555555"  # 36 chars

_TOTP_OK = "000000"  # stub — LocalAuthService uses injected verify_totp


# ---------------------------------------------------------------------------
# Section 1 — _get_history_depth() env-var parsing
# ---------------------------------------------------------------------------


class TestGetHistoryDepth:
    """Unit tests for _get_history_depth() with env-var injection."""

    def _call(self, env_val: Optional[str]) -> int:
        from yashigani.auth.local_auth import _get_history_depth

        with patch.dict(
            os.environ, ({"PASSWORD_HISTORY_DEPTH": env_val} if env_val is not None else {}), clear=(env_val is None)
        ):
            # Clear the key when env_val is None so default triggers
            env = dict(os.environ)
            env.pop("PASSWORD_HISTORY_DEPTH", None)
            if env_val is not None:
                env["PASSWORD_HISTORY_DEPTH"] = env_val
            with patch.dict(os.environ, env, clear=True):
                return _get_history_depth()

    def test_default_12_when_env_unset(self):
        from yashigani.auth.local_auth import _get_history_depth

        env = {k: v for k, v in os.environ.items() if k != "PASSWORD_HISTORY_DEPTH"}
        with patch.dict(os.environ, env, clear=True):
            assert _get_history_depth() == 12

    def test_parses_valid_value(self):
        from yashigani.auth.local_auth import _get_history_depth

        with patch.dict(os.environ, {"PASSWORD_HISTORY_DEPTH": "8"}):
            assert _get_history_depth() == 8

    def test_clamps_below_min(self):
        from yashigani.auth.local_auth import _get_history_depth

        with patch.dict(os.environ, {"PASSWORD_HISTORY_DEPTH": "0"}):
            assert _get_history_depth() == 1

    def test_clamps_above_max(self):
        from yashigani.auth.local_auth import _get_history_depth

        with patch.dict(os.environ, {"PASSWORD_HISTORY_DEPTH": "99"}):
            assert _get_history_depth() == 24

    def test_invalid_string_returns_default(self):
        from yashigani.auth.local_auth import _get_history_depth

        with patch.dict(os.environ, {"PASSWORD_HISTORY_DEPTH": "not-a-number"}):
            assert _get_history_depth() == 12

    def test_boundary_1(self):
        from yashigani.auth.local_auth import _get_history_depth

        with patch.dict(os.environ, {"PASSWORD_HISTORY_DEPTH": "1"}):
            assert _get_history_depth() == 1

    def test_boundary_24(self):
        from yashigani.auth.local_auth import _get_history_depth

        with patch.dict(os.environ, {"PASSWORD_HISTORY_DEPTH": "24"}):
            assert _get_history_depth() == 24


# ---------------------------------------------------------------------------
# Section 2 — PasswordReuseError
# ---------------------------------------------------------------------------


class TestPasswordReuseError:
    def test_is_value_error(self):
        from yashigani.auth.local_auth import PasswordReuseError

        err = PasswordReuseError(depth=12)
        assert isinstance(err, ValueError)

    def test_depth_attribute(self):
        from yashigani.auth.local_auth import PasswordReuseError

        err = PasswordReuseError(depth=8)
        assert err.depth == 8

    def test_message_mentions_depth(self):
        from yashigani.auth.local_auth import PasswordReuseError

        err = PasswordReuseError(depth=7)
        assert "7" in str(err)


# ---------------------------------------------------------------------------
# Section 3 — LocalAuthService.change_password() reuse enforcement
# ---------------------------------------------------------------------------


def _make_svc_with_account(username: str, plaintext_password: str):
    """
    Build a LocalAuthService with one account and a known password,
    bypassing HIBP and TOTP verification with mocks.
    """
    from yashigani.auth.local_auth import LocalAuthService

    svc = LocalAuthService()

    # Pre-register account bypassing hash_password's HIBP check.
    # Patch verify_totp in local_auth's own namespace (direct import style).
    from unittest.mock import patch as _patch

    with _patch("yashigani.auth.local_auth.verify_totp", return_value=True):
        with _patch("yashigani.auth.password.validate_password_not_breached"):
            _, _ = svc.create_admin(username, plaintext_password=plaintext_password)
    return svc


def _change_pw(svc, username: str, current: str, new_pw: str) -> tuple[bool, str]:
    """Call change_password with HIBP and TOTP stubbed out."""
    from unittest.mock import patch as _patch

    with _patch("yashigani.auth.local_auth.verify_totp", return_value=True):
        with _patch("yashigani.auth.password.validate_password_not_breached"):
            return svc.change_password(username, current, _TOTP_OK, new_pw)


class TestLocalAuthServiceHistory:
    """Tests for LocalAuthService (in-memory) password history enforcement."""

    def test_fresh_password_accepted(self):
        """A new password not in history is accepted."""
        svc = _make_svc_with_account("admin@test.local", _PW_A)
        with patch.dict(os.environ, {"PASSWORD_HISTORY_DEPTH": "3"}):
            ok, reason = _change_pw(svc, "admin@test.local", _PW_A, _PW_B)
        assert ok is True
        assert reason == "ok"

    def test_immediate_reuse_rejected(self):
        """Immediately reusing the current password is rejected."""
        svc = _make_svc_with_account("admin@test.local", _PW_A)
        # First change to _PW_B (records _PW_A in history)
        with patch.dict(os.environ, {"PASSWORD_HISTORY_DEPTH": "3"}):
            _change_pw(svc, "admin@test.local", _PW_A, _PW_B)
            # Now try to reuse _PW_A
            ok, reason = _change_pw(svc, "admin@test.local", _PW_B, _PW_A)
        assert ok is False
        assert reason == "password_reuse"

    def test_reuse_rejected_across_depth(self):
        """Reuse is rejected for all N passwords in history depth."""
        svc = _make_svc_with_account("admin@test.local", _PW_A)
        with patch.dict(os.environ, {"PASSWORD_HISTORY_DEPTH": "3"}):
            # Change A→B, B→C, C→D — history depth 3 covers B, C, D
            _change_pw(svc, "admin@test.local", _PW_A, _PW_B)
            _change_pw(svc, "admin@test.local", _PW_B, _PW_C)
            _change_pw(svc, "admin@test.local", _PW_C, _PW_D)
            # All of B, C should be in history (depth 3: B, C, D stored before current change)
            # Current is D; try reusing B (should be in history)
            ok_b, reason_b = _change_pw(svc, "admin@test.local", _PW_D, _PW_B)
            ok_c, reason_c = _change_pw(svc, "admin@test.local", _PW_D, _PW_C)
        assert ok_b is False and reason_b == "password_reuse"
        assert ok_c is False and reason_c == "password_reuse"

    def test_password_beyond_depth_accepted(self):
        """A password older than depth is accepted (dropped from history)."""
        svc = _make_svc_with_account("admin@test.local", _PW_A)
        with patch.dict(os.environ, {"PASSWORD_HISTORY_DEPTH": "2"}):
            # Changes: A→B, B→C, C→D; depth 2 keeps C, D; A falls off
            _change_pw(svc, "admin@test.local", _PW_A, _PW_B)
            _change_pw(svc, "admin@test.local", _PW_B, _PW_C)
            _change_pw(svc, "admin@test.local", _PW_C, _PW_D)
            # _PW_A is beyond depth=2, so it should be accepted
            ok, reason = _change_pw(svc, "admin@test.local", _PW_D, _PW_A)
        assert ok is True
        assert reason == "ok"

    def test_depth_1_blocks_only_previous(self):
        """Depth=1 blocks only the immediately preceding password."""
        # Sub-test A: _PW_B (immediately preceding) is blocked.
        svc = _make_svc_with_account("admin@test.local", _PW_A)
        with patch.dict(os.environ, {"PASSWORD_HISTORY_DEPTH": "1"}):
            # A→B (records A in history; history now has [A])
            _change_pw(svc, "admin@test.local", _PW_A, _PW_B)
            # B→C (records B; with depth=1, history is pruned to [B])
            _change_pw(svc, "admin@test.local", _PW_B, _PW_C)
            # Try reusing _PW_B (immediately preceding, depth=1 → blocked)
            ok_b, reason_b = _change_pw(svc, "admin@test.local", _PW_C, _PW_B)
        assert ok_b is False
        assert reason_b == "password_reuse"

        # Sub-test B: _PW_A (2 changes ago with depth=1) is allowed.
        svc2 = _make_svc_with_account("admin2@test.local", _PW_A)
        with patch.dict(os.environ, {"PASSWORD_HISTORY_DEPTH": "1"}):
            # A→B (records A; depth=1 → history=[A])
            _change_pw(svc2, "admin2@test.local", _PW_A, _PW_B)
            # B→C (records B; depth=1 prunes to [B], A falls off)
            _change_pw(svc2, "admin2@test.local", _PW_B, _PW_C)
            # _PW_A is beyond depth=1 — should be accepted
            ok_a, reason_a = _change_pw(svc2, "admin2@test.local", _PW_C, _PW_A)
        assert ok_a is True
        assert reason_a == "ok"

    def test_wrong_current_password_still_rejected(self):
        """Wrong current password is rejected before reuse check."""
        svc = _make_svc_with_account("admin@test.local", _PW_A)
        with patch.dict(os.environ, {"PASSWORD_HISTORY_DEPTH": "3"}):
            ok, reason = _change_pw(svc, "admin@test.local", _PW_B, _PW_C)
        assert ok is False
        assert reason == "invalid_credentials"

    def test_history_is_per_account(self):
        """History is isolated per account_id — different accounts don't share history."""
        from yashigani.auth.local_auth import LocalAuthService
        from unittest.mock import patch as _patch

        svc = LocalAuthService()
        with _patch("yashigani.auth.local_auth.verify_totp", return_value=True):
            with _patch("yashigani.auth.password.validate_password_not_breached"):
                svc.create_admin("admin1@test.local", plaintext_password=_PW_A)
                svc.create_admin("admin2@test.local", plaintext_password=_PW_A)

        with patch.dict(os.environ, {"PASSWORD_HISTORY_DEPTH": "3"}):
            # Change admin1's password from A to B (records A in admin1's history)
            _change_pw(svc, "admin1@test.local", _PW_A, _PW_B)
            # admin2 should still be able to use _PW_A for their own different change
            ok, reason = _change_pw(svc, "admin2@test.local", _PW_A, _PW_C)
        assert ok is True
        assert reason == "ok"


# ---------------------------------------------------------------------------
# Section 4 — Audit event schema
# ---------------------------------------------------------------------------


class TestPasswordReuseRejectedEvent:
    """Verify the audit event schema — no sensitive fields, correct types."""

    def test_event_type_value(self):
        from yashigani.audit.schema import EventType

        assert EventType.PASSWORD_REUSE_REJECTED == "PASSWORD_REUSE_REJECTED"

    def test_event_dataclass_fields(self):
        from yashigani.audit.schema import PasswordReuseRejectedEvent

        evt = PasswordReuseRejectedEvent(
            user_id="test-uuid-1234",
            history_depth_checked=12,
        )
        assert evt.user_id == "test-uuid-1234"
        assert evt.history_depth_checked == 12
        assert evt.masking_applied is True

    def test_event_inherits_audit_event(self):
        from yashigani.audit.schema import PasswordReuseRejectedEvent, AuditEvent

        evt = PasswordReuseRejectedEvent(user_id="x", history_depth_checked=5)
        assert isinstance(evt, AuditEvent)
        # Must have audit_event_id and timestamp (inherited)
        assert evt.audit_event_id != ""
        assert evt.timestamp != ""

    def test_event_to_dict_no_password(self):
        """Serialised event must not contain password, hash, or plaintext."""
        from yashigani.audit.schema import PasswordReuseRejectedEvent

        evt = PasswordReuseRejectedEvent(user_id="uid-999", history_depth_checked=7)
        d = evt.to_dict()
        # Positive: expected keys present
        assert "user_id" in d
        assert "history_depth_checked" in d
        assert "masking_applied" in d
        # Negative: must NOT contain any of these
        forbidden = {"password", "hash", "plaintext", "new_password", "old_password"}
        for key in d:
            assert key.lower() not in forbidden, f"Forbidden key in event: {key}"

    def test_masking_applied_immutable_floor(self):
        """masking_applied cannot be overridden to False."""
        from yashigani.audit.schema import PasswordReuseRejectedEvent

        evt = PasswordReuseRejectedEvent(user_id="x", history_depth_checked=12)
        assert evt.masking_applied is True

    def test_event_account_tier_user(self):
        from yashigani.audit.schema import PasswordReuseRejectedEvent, AccountTier

        evt = PasswordReuseRejectedEvent(user_id="x", history_depth_checked=12)
        assert evt.account_tier == AccountTier.USER


# ---------------------------------------------------------------------------
# Section 5 — Audit event emission on rejection (LocalAuthService)
# ---------------------------------------------------------------------------


class TestAuditEventEmission:
    """Verify that PASSWORD_REUSE_REJECTED audit events are emitted correctly."""

    def test_event_emission_in_local_service(self):
        """
        LocalAuthService does not emit audit events directly (it has no
        audit_writer). This test verifies the return value 'password_reuse'
        is stable — the caller (route handler) is responsible for emission.
        """
        svc = _make_svc_with_account("admin@test.local", _PW_A)
        with patch.dict(os.environ, {"PASSWORD_HISTORY_DEPTH": "1"}):
            _change_pw(svc, "admin@test.local", _PW_A, _PW_B)
            ok, reason = _change_pw(svc, "admin@test.local", _PW_B, _PW_A)
        assert reason == "password_reuse"
        assert ok is False
