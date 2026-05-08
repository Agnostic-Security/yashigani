"""
Unit tests for v2.23.3 licence expiry UX.

Covers:
  - LicenseExpiryMode enum values
  - compute_expiry_mode() at every threshold boundary
  - LicenseState.expiry_mode() method
  - LicenseState.days_remaining() method
  - get_license_banner_context() banner content + severity at each mode
  - _build_banner() per mode
  - grace_period.is_write_operation() classifier
  - grace_period.check_gateway_access() raises/passes per mode
  - GatewayBlockedError / GatewayReadOnlyError message content
  - LicenseEnforcementMiddleware ASGI responses (W12 regression)
  - Readonly-safe whitelist exhaustiveness (W13 regression)
  - /admin/license/status route response shape (no live HTTP)
  - Boundary: 0 days remaining → CRITICAL (not EXPIRED)
  - Boundary: exactly 7 days → WARNING (not CRITICAL)
  - Boundary: exactly 30 days → ACTIVE (not WARNING)

Last updated: 2026-05-08T00:00:00+01:00
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from yashigani.licensing.model import (
    COMMUNITY_LICENSE,
    GRACE_PERIOD_DAYS,
    READONLY_PERIOD_DAYS,
    WARN_ORANGE_DAYS,
    WARN_YELLOW_DAYS,
    LicenseExpiryMode,
    LicenseFeature,
    LicenseState,
    LicenseTier,
    compute_expiry_mode,
)
from yashigani.licensing.grace_period import (
    GatewayBlockedError,
    GatewayReadOnlyError,
    LicenseEnforcementMiddleware,
    _READONLY_SAFE_PREFIXES,
    check_gateway_access,
    is_write_operation,
)
from yashigani.backoffice.routes.license import (
    _build_banner,
    get_license_banner_context,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


def _lic(expires_offset_days: int | None) -> LicenseState:
    """Build a LicenseState with expiry at NOW + offset days."""
    if expires_offset_days is None:
        expires_at = None
    else:
        expires_at = _NOW + timedelta(days=expires_offset_days)

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


# ---------------------------------------------------------------------------
# LicenseExpiryMode enum
# ---------------------------------------------------------------------------


class TestLicenseExpiryModeEnum:
    def test_all_modes_exist(self):
        expected = {"active", "warning", "critical", "expired", "readonly", "blocked"}
        actual = {m.value for m in LicenseExpiryMode}
        assert actual == expected

    def test_grace_period_constants(self):
        assert GRACE_PERIOD_DAYS == 14
        assert READONLY_PERIOD_DAYS == 30
        assert WARN_YELLOW_DAYS == 30
        assert WARN_ORANGE_DAYS == 7


# ---------------------------------------------------------------------------
# compute_expiry_mode boundaries
# ---------------------------------------------------------------------------


class TestComputeExpiryMode:
    """Test every boundary of compute_expiry_mode with a fixed 'now'."""

    def _mode(self, offset_days: int | None) -> LicenseExpiryMode:
        expires_at = _NOW + timedelta(days=offset_days) if offset_days is not None else None
        return compute_expiry_mode(expires_at, now=_NOW)

    # -- ACTIVE --
    def test_no_expiry_is_active(self):
        assert self._mode(None) == LicenseExpiryMode.ACTIVE

    def test_31_days_remaining_is_active(self):
        assert self._mode(31) == LicenseExpiryMode.ACTIVE

    def test_exactly_31_days_remaining_is_active(self):
        assert self._mode(WARN_YELLOW_DAYS + 1) == LicenseExpiryMode.ACTIVE

    # -- WARNING (>7 and <=30) --
    def test_30_days_remaining_is_warning(self):
        assert self._mode(WARN_YELLOW_DAYS) == LicenseExpiryMode.WARNING

    def test_15_days_remaining_is_warning(self):
        assert self._mode(15) == LicenseExpiryMode.WARNING

    def test_8_days_remaining_is_warning(self):
        assert self._mode(8) == LicenseExpiryMode.WARNING

    # -- CRITICAL (>=0 and <=7) --
    def test_7_days_remaining_is_critical(self):
        assert self._mode(WARN_ORANGE_DAYS) == LicenseExpiryMode.CRITICAL

    def test_3_days_remaining_is_critical(self):
        assert self._mode(3) == LicenseExpiryMode.CRITICAL

    def test_1_day_remaining_is_critical(self):
        assert self._mode(1) == LicenseExpiryMode.CRITICAL

    def test_0_days_remaining_is_critical(self):
        # expires_at = now + 0 days = now; delta.days = 0 >= 0 → CRITICAL
        assert self._mode(0) == LicenseExpiryMode.CRITICAL

    # -- EXPIRED / grace (0–14 days past) --
    def test_1_day_past_is_expired(self):
        assert self._mode(-1) == LicenseExpiryMode.EXPIRED

    def test_grace_period_days_past_is_expired(self):
        assert self._mode(-GRACE_PERIOD_DAYS) == LicenseExpiryMode.EXPIRED

    def test_14_days_past_is_expired(self):
        assert self._mode(-14) == LicenseExpiryMode.EXPIRED

    # -- READONLY (14–30 days past) --
    def test_15_days_past_is_readonly(self):
        assert self._mode(-15) == LicenseExpiryMode.READONLY

    def test_29_days_past_is_readonly(self):
        assert self._mode(-29) == LicenseExpiryMode.READONLY

    def test_readonly_period_days_past_is_readonly(self):
        assert self._mode(-READONLY_PERIOD_DAYS) == LicenseExpiryMode.READONLY

    # -- BLOCKED (30+ days past) --
    def test_31_days_past_is_blocked(self):
        assert self._mode(-31) == LicenseExpiryMode.BLOCKED

    def test_100_days_past_is_blocked(self):
        assert self._mode(-100) == LicenseExpiryMode.BLOCKED


# ---------------------------------------------------------------------------
# LicenseState methods
# ---------------------------------------------------------------------------


class TestLicenseStateExpiryMode:
    def test_active_license(self):
        lic = _lic(60)
        assert lic.expiry_mode(now=_NOW) == LicenseExpiryMode.ACTIVE

    def test_warning_license(self):
        lic = _lic(20)
        assert lic.expiry_mode(now=_NOW) == LicenseExpiryMode.WARNING

    def test_critical_license(self):
        lic = _lic(5)
        assert lic.expiry_mode(now=_NOW) == LicenseExpiryMode.CRITICAL

    def test_expired_grace_license(self):
        lic = _lic(-7)
        assert lic.expiry_mode(now=_NOW) == LicenseExpiryMode.EXPIRED

    def test_readonly_license(self):
        lic = _lic(-20)
        assert lic.expiry_mode(now=_NOW) == LicenseExpiryMode.READONLY

    def test_blocked_license(self):
        lic = _lic(-50)
        assert lic.expiry_mode(now=_NOW) == LicenseExpiryMode.BLOCKED

    def test_community_no_expiry_is_active(self):
        assert COMMUNITY_LICENSE.expiry_mode() == LicenseExpiryMode.ACTIVE


class TestLicenseStateDaysRemaining:
    def test_perpetual_returns_none(self):
        lic = _lic(None)
        assert lic.days_remaining(now=_NOW) is None

    def test_future_expiry_positive(self):
        lic = _lic(10)
        assert lic.days_remaining(now=_NOW) == 10

    def test_past_expiry_negative(self):
        lic = _lic(-5)
        assert lic.days_remaining(now=_NOW) == -5


# ---------------------------------------------------------------------------
# Banner building
# ---------------------------------------------------------------------------


class TestBuildBanner:
    def test_active_no_banner(self):
        b = _build_banner(LicenseExpiryMode.ACTIVE, None)
        assert b["show"] is False
        assert b["severity"] == "none"

    def test_warning_banner(self):
        b = _build_banner(LicenseExpiryMode.WARNING, 20)
        assert b["show"] is True
        assert b["severity"] == "warning"
        assert "20 days" in b["message"]
        assert "renew" in b["message"].lower()

    def test_warning_banner_singular_day(self):
        b = _build_banner(LicenseExpiryMode.WARNING, 1)
        assert "1 day" in b["message"]
        assert "1 days" not in b["message"]

    def test_critical_banner(self):
        b = _build_banner(LicenseExpiryMode.CRITICAL, 3)
        assert b["show"] is True
        assert b["severity"] == "critical"
        assert "3 days" in b["message"]
        assert "sales@agnosticsec.com" in b["message"]

    def test_expired_banner_shows_grace_remaining(self):
        # 5 days past expiry → 14 - 5 = 9 grace days left
        b = _build_banner(LicenseExpiryMode.EXPIRED, -5)
        assert b["show"] is True
        assert b["severity"] == "expired"
        assert "9 day" in b["message"]
        assert "sales@agnosticsec.com" in b["message"]

    def test_readonly_banner(self):
        b = _build_banner(LicenseExpiryMode.READONLY, -20)
        assert b["show"] is True
        assert b["severity"] == "readonly"
        assert "read-only" in b["message"]

    def test_blocked_banner(self):
        b = _build_banner(LicenseExpiryMode.BLOCKED, -50)
        assert b["show"] is True
        assert b["severity"] == "blocked"
        assert "blocked" in b["message"].lower()
        assert "agnosticsec.com/pricing" in b["message"]


# ---------------------------------------------------------------------------
# get_license_banner_context
# ---------------------------------------------------------------------------


class TestGetLicenseBannerContext:
    """
    Tests for get_license_banner_context().

    Banner context reads from the module-level enforcer state via get_license().
    Tests set the active licence via set_license() and pass a fixed 'now'
    so mode calculation is deterministic regardless of wall-clock time.
    """

    @pytest.fixture(autouse=True)
    def restore_license(self):
        from yashigani.licensing.enforcer import get_license, set_license

        original = get_license()
        yield
        set_license(original)

    def _ctx(self, lic: LicenseState) -> dict:
        from yashigani.licensing.enforcer import set_license

        set_license(lic)
        return get_license_banner_context(now=_NOW)

    def test_active_context_no_banner(self):
        ctx = self._ctx(_lic(60))
        assert ctx["license_mode"] == "active"
        assert ctx["license_banner"]["show"] is False
        assert ctx["license_days"] == 60

    def test_warning_context(self):
        ctx = self._ctx(_lic(20))
        assert ctx["license_mode"] == "warning"
        assert ctx["license_banner"]["show"] is True
        assert ctx["license_banner"]["severity"] == "warning"

    def test_critical_context(self):
        ctx = self._ctx(_lic(5))
        assert ctx["license_mode"] == "critical"
        assert ctx["license_banner"]["severity"] == "critical"

    def test_expired_context(self):
        ctx = self._ctx(_lic(-7))
        assert ctx["license_mode"] == "expired"
        assert ctx["license_banner"]["severity"] == "expired"
        assert ctx["license_days"] == -7

    def test_readonly_context(self):
        ctx = self._ctx(_lic(-20))
        assert ctx["license_mode"] == "readonly"
        assert ctx["license_banner"]["severity"] == "readonly"

    def test_blocked_context(self):
        ctx = self._ctx(_lic(-50))
        assert ctx["license_mode"] == "blocked"
        assert ctx["license_banner"]["severity"] == "blocked"

    def test_perpetual_license_no_expires_field(self):
        ctx = self._ctx(_lic(None))
        assert ctx["license_expires"] is None
        assert ctx["license_days"] is None
        assert ctx["license_mode"] == "active"

    def test_expires_iso8601_in_context(self):
        ctx = self._ctx(_lic(20))
        assert ctx["license_expires"] is not None
        # Must be parseable ISO-8601
        dt = datetime.fromisoformat(ctx["license_expires"].replace("Z", "+00:00"))
        assert dt.tzinfo is not None

    def test_import_error_returns_defaults(self):
        """If get_license() raises inside banner helper, defaults are returned."""
        # Patch enforcer.get_license at the enforcer module level
        import yashigani.licensing.enforcer as enforcer_mod

        original_fn = enforcer_mod.get_license
        enforcer_mod.get_license = lambda: (_ for _ in ()).throw(RuntimeError("not ready"))
        try:
            ctx = get_license_banner_context(now=_NOW)
        finally:
            enforcer_mod.get_license = original_fn
        assert ctx["license_mode"] == "active"
        assert ctx["license_banner"]["show"] is False


# ---------------------------------------------------------------------------
# is_write_operation
# ---------------------------------------------------------------------------


class TestIsWriteOperation:
    def test_get_is_not_write(self):
        assert is_write_operation("GET", "/admin/users") is False

    def test_post_is_write(self):
        assert is_write_operation("POST", "/admin/users") is True

    def test_put_is_write(self):
        assert is_write_operation("PUT", "/admin/agents/123") is True

    def test_patch_is_write(self):
        assert is_write_operation("PATCH", "/admin/config") is True

    def test_delete_is_write(self):
        assert is_write_operation("DELETE", "/admin/users/123") is True

    def test_healthz_never_blocked(self):
        assert is_write_operation("POST", "/healthz") is False
        assert is_write_operation("GET", "/healthz") is False

    def test_metrics_never_blocked(self):
        assert is_write_operation("GET", "/internal/metrics") is False

    def test_license_status_never_blocked(self):
        assert is_write_operation("GET", "/admin/license/status") is False
        assert is_write_operation("GET", "/api/v1/license/status") is False

    def test_chat_completions_blocked_in_readonly(self):
        assert is_write_operation("POST", "/v1/chat/completions") is True

    def test_chat_completions_get_also_blocked_in_readonly(self):
        # SSE stream starts a run even on GET variants
        assert is_write_operation("GET", "/v1/chat/completions") is True

    def test_agent_run_prefix_blocked(self):
        assert is_write_operation("POST", "/admin/agents/run") is True

    def test_method_case_insensitive(self):
        assert is_write_operation("post", "/admin/users") is True
        assert is_write_operation("get", "/admin/users") is False


# ---------------------------------------------------------------------------
# check_gateway_access
# ---------------------------------------------------------------------------


class TestCheckGatewayAccess:
    def _set_lic(self, offset_days: int | None) -> LicenseState:
        from yashigani.licensing.enforcer import set_license, get_license

        lic = _lic(offset_days)
        set_license(lic)
        return lic

    @pytest.fixture(autouse=True)
    def restore_license(self):
        from yashigani.licensing.enforcer import set_license, get_license

        original = get_license()
        yield
        set_license(original)

    def test_active_no_raise(self):
        self._set_lic(60)
        # Must not raise
        check_gateway_access("POST", "/admin/users", now=_NOW)

    def test_warning_no_raise(self):
        self._set_lic(20)
        check_gateway_access("POST", "/admin/users", now=_NOW)

    def test_critical_no_raise(self):
        self._set_lic(5)
        check_gateway_access("POST", "/admin/users", now=_NOW)

    def test_expired_grace_no_raise(self):
        self._set_lic(-7)
        check_gateway_access("POST", "/admin/users", now=_NOW)

    def test_expired_grace_read_no_raise(self):
        self._set_lic(-7)
        check_gateway_access("GET", "/admin/users", now=_NOW)

    def test_readonly_get_no_raise(self):
        self._set_lic(-20)
        check_gateway_access("GET", "/admin/license", now=_NOW)

    def test_readonly_post_raises(self):
        self._set_lic(-20)
        with pytest.raises(GatewayReadOnlyError):
            check_gateway_access("POST", "/admin/users", now=_NOW)

    def test_readonly_delete_raises(self):
        self._set_lic(-20)
        with pytest.raises(GatewayReadOnlyError):
            check_gateway_access("DELETE", "/admin/users/1", now=_NOW)

    def test_readonly_healthz_no_raise(self):
        self._set_lic(-20)
        check_gateway_access("GET", "/healthz", now=_NOW)

    def test_readonly_chat_completions_raises(self):
        self._set_lic(-20)
        with pytest.raises(GatewayReadOnlyError):
            check_gateway_access("POST", "/v1/chat/completions", now=_NOW)

    def test_blocked_any_request_raises(self):
        self._set_lic(-50)
        with pytest.raises(GatewayBlockedError):
            check_gateway_access("GET", "/admin/users", now=_NOW)

    def test_blocked_write_also_raises_blocked(self):
        self._set_lic(-50)
        with pytest.raises(GatewayBlockedError):
            check_gateway_access("POST", "/admin/users", now=_NOW)

    def test_blocked_healthz_still_raises(self):
        # Healthz is not exempt from BLOCKED — gateway is fully down
        self._set_lic(-50)
        with pytest.raises(GatewayBlockedError):
            check_gateway_access("GET", "/healthz", now=_NOW)


# ---------------------------------------------------------------------------
# GatewayBlockedError / GatewayReadOnlyError
# ---------------------------------------------------------------------------


class TestGatewayErrors:
    def test_blocked_error_message(self):
        err = GatewayBlockedError()
        assert "blocked" in str(err).lower()
        assert "agnosticsec.com" in str(err)

    def test_readonly_error_message(self):
        err = GatewayReadOnlyError(operation="POST /admin/users")
        assert "read-only" in str(err).lower()
        assert "sales@agnosticsec.com" in str(err)

    def test_readonly_error_no_operation(self):
        err = GatewayReadOnlyError()
        assert "read-only" in str(err).lower()


# ---------------------------------------------------------------------------
# /api/v1/license/status response shape (no live HTTP — unit check on function)
# ---------------------------------------------------------------------------


class TestLicenseStatusRouteShape:
    """
    Verify get_license_expiry_status() returns the correct shape
    without spinning up a full HTTP server.

    The route uses datetime.now() internally, so we build LicenseState objects
    with expiry dates relative to real wall-clock time (not the fixed _NOW
    sentinel), so mode comparisons are accurate when the test actually runs.
    """

    @pytest.fixture(autouse=True)
    def restore_license(self):
        from yashigani.licensing.enforcer import set_license, get_license

        original = get_license()
        yield
        set_license(original)

    def _real_now_lic(self, offset_days: int | None) -> LicenseState:
        """Build a LicenseState with expiry relative to real wall-clock now."""
        real_now = datetime.now(timezone.utc)
        expires_at = real_now + timedelta(days=offset_days) if offset_days is not None else None
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

    def _run(self, lic: LicenseState) -> dict:
        """Call the route handler synchronously via asyncio.run."""
        import asyncio
        from yashigani.licensing.enforcer import set_license
        from yashigani.backoffice.routes.license import get_license_expiry_status

        set_license(lic)

        async def _call():
            return await get_license_expiry_status(session=MagicMock())

        return asyncio.run(_call())

    def test_active_response(self):
        resp = self._run(self._real_now_lic(60))
        assert resp["mode"] == "active"
        assert resp["valid"] is True
        assert resp["grace_period_active"] is False
        # days_remaining should be close to 60 (±1 for timing)
        assert 58 <= resp["days_remaining"] <= 61
        assert resp["expires_at"] is not None

    def test_warning_response(self):
        resp = self._run(self._real_now_lic(20))
        assert resp["mode"] == "warning"
        assert resp["grace_period_active"] is False

    def test_expired_grace_response(self):
        resp = self._run(self._real_now_lic(-7))
        assert resp["mode"] == "expired"
        assert resp["grace_period_active"] is True
        assert resp["days_remaining"] < 0

    def test_readonly_response(self):
        resp = self._run(self._real_now_lic(-20))
        assert resp["mode"] == "readonly"
        assert resp["grace_period_active"] is False

    def test_blocked_response(self):
        resp = self._run(self._real_now_lic(-50))
        assert resp["mode"] == "blocked"
        assert resp["grace_period_active"] is False

    def test_perpetual_license_response(self):
        resp = self._run(self._real_now_lic(None))
        assert resp["mode"] == "active"
        assert resp["expires_at"] is None
        assert resp["days_remaining"] is None

    def test_required_keys_present(self):
        resp = self._run(self._real_now_lic(20))
        required = {"valid", "expires_at", "days_remaining", "grace_period_active", "mode"}
        assert required.issubset(resp.keys())


# ---------------------------------------------------------------------------
# LicenseEnforcementMiddleware — ASGI response tests (W12 regression)
# ---------------------------------------------------------------------------


class TestLicenseEnforcementMiddleware:
    """
    Regression tests for Warning 12: confirm LicenseEnforcementMiddleware
    correctly converts GatewayBlockedError → 503 and GatewayReadOnlyError → 403,
    and passes through valid requests.

    Uses a lightweight ASGI test harness (no live HTTP server required).
    """

    @staticmethod
    async def _run_middleware(check_raises, method: str = "POST", path: str = "/admin/users"):
        """
        Run LicenseEnforcementMiddleware over a synthetic ASGI scope.

        check_raises: None | GatewayBlockedError | GatewayReadOnlyError — what
                      check_gateway_access() should raise (or not) for this call.

        Returns (status_code, body_bytes).
        """
        responses = []

        async def mock_app(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        async def mock_receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def mock_send(msg):
            responses.append(msg)

        scope = {"type": "http", "method": method, "path": path}

        middleware = LicenseEnforcementMiddleware(mock_app)

        with patch(
            "yashigani.licensing.grace_period.check_gateway_access",
            side_effect=check_raises() if check_raises else None,
        ):
            await middleware(scope, mock_receive, mock_send)

        start = next(r for r in responses if r["type"] == "http.response.start")
        body_msg = next(r for r in responses if r["type"] == "http.response.body")
        return start["status"], body_msg["body"]

    def test_blocked_returns_503(self):
        import asyncio

        status, body = asyncio.run(self._run_middleware(GatewayBlockedError))
        assert status == 503
        import json

        data = json.loads(body)
        assert data["error"] == "licence_blocked"
        assert "renewal_url" in data

    def test_readonly_returns_403(self):
        import asyncio

        status, body = asyncio.run(self._run_middleware(GatewayReadOnlyError))
        assert status == 403
        import json

        data = json.loads(body)
        assert data["error"] == "licence_readonly"
        assert "renewal_url" in data

    def test_active_passes_through(self):
        import asyncio

        status, body = asyncio.run(self._run_middleware(None))
        assert status == 200
        assert body == b"ok"

    def test_non_http_scope_bypasses(self):
        """Websocket / lifespan scopes must not be affected."""
        import asyncio

        responses = []

        async def mock_app(scope, receive, send):
            await send({"type": "websocket.connect"})

        async def mock_receive():
            return {}

        async def mock_send(msg):
            responses.append(msg)

        scope = {"type": "websocket", "path": "/ws"}
        middleware = LicenseEnforcementMiddleware(mock_app)
        asyncio.run(middleware(scope, mock_receive, mock_send))
        assert responses == [{"type": "websocket.connect"}]


# ---------------------------------------------------------------------------
# Readonly-safe whitelist exhaustiveness (W13 regression)
# ---------------------------------------------------------------------------


class TestReadonlySafeWhitelist:
    """
    Warning 13 regression: verify the _READONLY_SAFE_PREFIXES whitelist covers
    the paths that must remain accessible in READONLY mode.
    """

    def test_health_endpoint_is_safe(self):
        assert is_write_operation("POST", "/healthz") is False
        assert is_write_operation("GET", "/healthz") is False

    def test_prometheus_metrics_is_safe(self):
        assert is_write_operation("GET", "/internal/metrics") is False

    def test_license_status_admin_is_safe(self):
        assert is_write_operation("GET", "/admin/license/status") is False

    def test_license_status_api_is_safe(self):
        assert is_write_operation("GET", "/api/v1/license/status") is False

    def test_all_readonly_safe_prefixes_covered(self):
        """Enumerate _READONLY_SAFE_PREFIXES and confirm each passes is_write_operation."""
        for prefix in _READONLY_SAFE_PREFIXES:
            assert is_write_operation("GET", prefix) is False, (
                f"_READONLY_SAFE_PREFIXES entry {prefix!r} is not safe under is_write_operation"
            )
            assert is_write_operation("POST", prefix) is False, (
                f"_READONLY_SAFE_PREFIXES entry {prefix!r} blocks POST but should be safe"
            )

    def test_write_operations_still_blocked(self):
        """Non-whitelisted write paths must still return True."""
        assert is_write_operation("POST", "/admin/users") is True
        assert is_write_operation("DELETE", "/admin/agents/123") is True
        assert is_write_operation("PATCH", "/admin/config") is True
