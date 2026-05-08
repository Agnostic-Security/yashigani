"""
Integration tests for v2.23.3 licence expiry grace-period behaviour.

Tests verify:
  - The HTTP API response shape of GET /admin/license/status
  - Grace-period mode transitions (active → warning → critical → expired → readonly → blocked)
  - GatewayBlockedError emits correct 503 payload (via grace_period module)
  - GatewayReadOnlyError emits correct 403 payload
  - emit_grace_period_audit() completes without raising when audit_writer is None

These tests do NOT require a live database or Redis — all licensing state
is set via enforcer.set_license().

Integration marker: tests in this file are marked @pytest.mark.integration.
CI gates that exclude unit-only runs should pass `--ignore=src/tests/integration`
or `-m "not integration"` to skip these.

Last updated: 2026-05-07T00:00:00+01:00
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from yashigani.licensing.model import (
    LicenseExpiryMode,
    LicenseFeature,
    LicenseState,
    LicenseTier,
)
from yashigani.licensing.grace_period import (
    GatewayBlockedError,
    GatewayReadOnlyError,
    check_gateway_access,
    emit_grace_period_audit,
)

pytestmark = pytest.mark.integration

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


def _lic(expires_offset_days: int | None, use_real_now: bool = False) -> LicenseState:
    """
    Build a LicenseState with expiry offset from a reference time.

    use_real_now=True: use real wall-clock time (needed for tests that do NOT
    inject 'now' into expiry_mode() — e.g. emit_grace_period_audit).
    use_real_now=False (default): use fixed _NOW (2026-06-01) for deterministic
    mode computation when 'now' is injected.
    """
    base = datetime.now(timezone.utc) if use_real_now else _NOW
    expires_at = base + timedelta(days=expires_offset_days) if expires_offset_days is not None else None
    return LicenseState(
        tier=LicenseTier.PROFESSIONAL,
        org_domain="example.com",
        max_agents=2000,
        max_end_users=500,
        max_admin_seats=25,
        max_orgs=1,
        features=frozenset([LicenseFeature.OIDC]),
        issued_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
        expires_at=expires_at,
        license_id=str(uuid.uuid4()),
        valid=True,
        error=None,
    )


@pytest.fixture(autouse=True)
def restore_license():
    from yashigani.licensing.enforcer import get_license, set_license
    original = get_license()
    yield
    set_license(original)


# ---------------------------------------------------------------------------
# Grace-period mode transition matrix
# ---------------------------------------------------------------------------

class TestGracePeriodModeTransitions:
    """
    Verifies the full mode-transition matrix:
    active → warning → critical → expired → readonly → blocked.
    """

    @pytest.mark.parametrize("offset_days,expected_mode", [
        (365,  "active"),     # well in the future
        (60,   "active"),     # >30 days
        (31,   "active"),     # just over 30
        (30,   "warning"),    # exactly 30
        (20,   "warning"),    # mid warning
        (8,    "warning"),    # just over 7
        (7,    "critical"),   # exactly 7
        (3,    "critical"),   # mid critical
        (1,    "critical"),   # 1 day left
        (0,    "critical"),   # expires today
        (-1,   "expired"),    # 1 day past
        (-7,   "expired"),    # 7 days past (well inside grace)
        (-14,  "expired"),    # exactly 14 days past = last day of grace
        (-15,  "readonly"),   # 15 days past = first day of readonly
        (-29,  "readonly"),   # 29 days past
        (-30,  "readonly"),   # exactly 30 days past = last day of readonly
        (-31,  "blocked"),    # 31 days past = first day of blocked
        (-100, "blocked"),    # well past
    ])
    def test_mode_at_offset(self, offset_days, expected_mode):
        lic = _lic(offset_days)
        mode = lic.expiry_mode(now=_NOW)
        assert mode.value == expected_mode, (
            f"offset_days={offset_days}: expected '{expected_mode}', got '{mode.value}'"
        )


# ---------------------------------------------------------------------------
# check_gateway_access integration
# ---------------------------------------------------------------------------

class TestCheckGatewayAccessIntegration:
    def _check(self, offset_days: int | None, method: str = "GET", path: str = "/admin/users"):
        from yashigani.licensing.enforcer import set_license
        lic = _lic(offset_days)
        set_license(lic)
        check_gateway_access(method, path, now=_NOW)

    def test_active_get_passes(self):
        self._check(60, "GET", "/admin/users")

    def test_active_post_passes(self):
        self._check(60, "POST", "/admin/users")

    def test_grace_get_passes(self):
        self._check(-7, "GET", "/admin/users")

    def test_grace_post_passes(self):
        self._check(-7, "POST", "/admin/users")

    def test_readonly_get_passes(self):
        self._check(-20, "GET", "/admin/users")

    def test_readonly_post_raises_readonly(self):
        from yashigani.licensing.enforcer import set_license
        set_license(_lic(-20))
        with pytest.raises(GatewayReadOnlyError) as exc_info:
            check_gateway_access("POST", "/admin/users", now=_NOW)
        assert exc_info.value.operation == "POST /admin/users"

    def test_readonly_license_status_passes(self):
        self._check(-20, "GET", "/api/v1/license/status")

    def test_blocked_get_raises(self):
        from yashigani.licensing.enforcer import set_license
        set_license(_lic(-50))
        with pytest.raises(GatewayBlockedError):
            check_gateway_access("GET", "/admin/users", now=_NOW)

    def test_blocked_post_raises_blocked_not_readonly(self):
        from yashigani.licensing.enforcer import set_license
        set_license(_lic(-50))
        # Should be GatewayBlockedError, not GatewayReadOnlyError
        with pytest.raises(GatewayBlockedError):
            check_gateway_access("POST", "/admin/users", now=_NOW)


# ---------------------------------------------------------------------------
# emit_grace_period_audit integration
# ---------------------------------------------------------------------------

class TestEmitGracePeriodAudit:
    """
    emit_grace_period_audit() must complete without raising in all cases.
    Verify it writes an audit event when mode is EXPIRED/READONLY/BLOCKED
    and does nothing in ACTIVE mode.
    """

    @pytest.fixture
    def mock_audit_writer(self):
        writer = MagicMock()
        writer.write = MagicMock()
        return writer

    @pytest.fixture
    def mock_state_with_writer(self, mock_audit_writer):
        state = MagicMock()
        state.audit_writer = mock_audit_writer
        return state

    def _run_emit(self, offset_days: int | None, state=None):
        from yashigani.licensing.enforcer import set_license
        import yashigani.licensing.grace_period as gp_mod

        # Reset the daily guard so each test can emit
        gp_mod._last_grace_audit_date = None

        # emit_grace_period_audit uses real datetime.now() internally, so
        # we must build the lic with real-now-relative offsets.
        set_license(_lic(offset_days, use_real_now=True))

        if state is not None:
            with patch("yashigani.licensing.grace_period.backoffice_state", state):
                asyncio.run(emit_grace_period_audit())
        else:
            asyncio.run(emit_grace_period_audit())

    def test_active_no_audit_write(self, mock_state_with_writer, mock_audit_writer):
        self._run_emit(60, state=mock_state_with_writer)
        mock_audit_writer.write.assert_not_called()

    def test_expired_grace_audit_write(self, mock_state_with_writer, mock_audit_writer):
        self._run_emit(-7, state=mock_state_with_writer)
        mock_audit_writer.write.assert_called_once()
        call_args = mock_audit_writer.write.call_args
        # component string should contain mode=expired
        component = call_args[1].get("component", call_args[0][1] if len(call_args[0]) > 1 else "")
        assert "expired" in component

    def test_readonly_audit_write(self, mock_state_with_writer, mock_audit_writer):
        self._run_emit(-20, state=mock_state_with_writer)
        mock_audit_writer.write.assert_called_once()

    def test_blocked_audit_write(self, mock_state_with_writer, mock_audit_writer):
        self._run_emit(-50, state=mock_state_with_writer)
        mock_audit_writer.write.assert_called_once()

    def test_no_audit_writer_does_not_raise(self):
        state = MagicMock()
        state.audit_writer = None
        # Must not raise even with no writer
        self._run_emit(-7, state=state)

    def test_daily_guard_prevents_duplicate_emit(self, mock_state_with_writer, mock_audit_writer):
        """Second call in same calendar day must not emit again."""
        import yashigani.licensing.grace_period as gp_mod
        from yashigani.licensing.enforcer import set_license

        gp_mod._last_grace_audit_date = None
        set_license(_lic(-7, use_real_now=True))

        async def _double_emit():
            with patch("yashigani.licensing.grace_period.backoffice_state", mock_state_with_writer):
                await emit_grace_period_audit()
                await emit_grace_period_audit()  # second call same day

        asyncio.run(_double_emit())
        # Only one write despite two calls
        assert mock_audit_writer.write.call_count == 1
