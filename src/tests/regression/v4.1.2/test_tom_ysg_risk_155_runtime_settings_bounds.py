"""
Regression test -- v4.1.2 YSG-RISK-155 (LOW): runtime-settings numeric fields
lacked bounds validation entirely.

Root cause: SettingMeta (runtime_settings/keys.py) had no min/max fields;
RuntimeSettingsService.set() (runtime_settings/service.py) only type-coerced
the incoming value (_coerce_value) with zero range checking. An admin could
set gateway.ddos.window_seconds=0 (or negative -- division/inversion in the
fixed-window counter) or gateway.ratelimit.per_user_rps=-1 (negative token
bucket refill) with no rejection.

Fix: SettingMeta gained min_value/max_value; RuntimeSettingsService.set() now
calls _validate_bounds() and raises ValueError on an out-of-range value; the
admin PUT route (routes/runtime_settings.py) catches ValueError -> 422
(previously would have been an unhandled 500).
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

try:
    from fastapi.testclient import TestClient
    _HAVE_FASTAPI = True
except ImportError:
    _HAVE_FASTAPI = False

pytestmark = pytest.mark.skipif(not _HAVE_FASTAPI, reason="fastapi required")

_FAKE_SESSION = SimpleNamespace(account_id="test-admin", account_tier="admin")


def _run(coro):
    return asyncio.run(coro)


class TestValidateBounds:
    def test_below_min_rejected(self):
        from yashigani.runtime_settings.keys import KEY_DDOS_WINDOW_SECONDS, KNOWN_SETTINGS_BY_KEY
        from yashigani.runtime_settings.service import _validate_bounds

        meta = KNOWN_SETTINGS_BY_KEY[KEY_DDOS_WINDOW_SECONDS]
        with pytest.raises(ValueError):
            _validate_bounds(KEY_DDOS_WINDOW_SECONDS, 0, meta)
        with pytest.raises(ValueError):
            _validate_bounds(KEY_DDOS_WINDOW_SECONDS, -5, meta)

    def test_above_max_rejected(self):
        from yashigani.runtime_settings.keys import KEY_DDOS_PER_IP_LIMIT, KNOWN_SETTINGS_BY_KEY
        from yashigani.runtime_settings.service import _validate_bounds

        meta = KNOWN_SETTINGS_BY_KEY[KEY_DDOS_PER_IP_LIMIT]
        with pytest.raises(ValueError):
            _validate_bounds(KEY_DDOS_PER_IP_LIMIT, 100_000_000, meta)

    def test_within_bounds_accepted(self):
        from yashigani.runtime_settings.keys import KEY_RATE_LIMIT_PER_USER_RPS, KNOWN_SETTINGS_BY_KEY
        from yashigani.runtime_settings.service import _validate_bounds

        meta = KNOWN_SETTINGS_BY_KEY[KEY_RATE_LIMIT_PER_USER_RPS]
        _validate_bounds(KEY_RATE_LIMIT_PER_USER_RPS, 50.0, meta)  # must not raise

    def test_negative_rate_limit_rejected(self):
        from yashigani.runtime_settings.keys import KEY_RATE_LIMIT_PER_USER_RPS, KNOWN_SETTINGS_BY_KEY
        from yashigani.runtime_settings.service import _validate_bounds

        meta = KNOWN_SETTINGS_BY_KEY[KEY_RATE_LIMIT_PER_USER_RPS]
        with pytest.raises(ValueError):
            _validate_bounds(KEY_RATE_LIMIT_PER_USER_RPS, -1.0, meta)

    def test_bool_setting_has_no_bounds_check(self):
        from yashigani.runtime_settings.keys import (
            KEY_MODELS_SERVICE_ACCOUNT_FULL_LIST,
            KNOWN_SETTINGS_BY_KEY,
        )
        from yashigani.runtime_settings.service import _validate_bounds

        meta = KNOWN_SETTINGS_BY_KEY[KEY_MODELS_SERVICE_ACCOUNT_FULL_LIST]
        _validate_bounds(KEY_MODELS_SERVICE_ACCOUNT_FULL_LIST, True, meta)  # must not raise


class TestServiceSetEnforcesBounds:
    def test_set_raises_value_error_on_out_of_range(self):
        from yashigani.runtime_settings.keys import KEY_DDOS_WINDOW_SECONDS
        from yashigani.runtime_settings.service import RuntimeSettingsService

        pool = MagicMock()
        svc = RuntimeSettingsService(pool=pool)
        with pytest.raises(ValueError):
            _run(svc.set(key=KEY_DDOS_WINDOW_SECONDS, value=0, changed_by="admin1"))


def _make_app():
    import fastapi as _fastapi

    from yashigani.backoffice import middleware as mw
    from yashigani.backoffice.routes.runtime_settings import router

    app = _fastapi.FastAPI()
    app.dependency_overrides[mw.require_admin_session] = lambda: _FAKE_SESSION
    app.dependency_overrides[mw.require_stepup_admin_session] = lambda: _FAKE_SESSION
    app.include_router(router, prefix="/admin/runtime-settings")
    return app


class TestPutRuntimeSettingRoute:
    def test_out_of_range_value_returns_422(self):
        from yashigani.runtime_settings.keys import KEY_DDOS_WINDOW_SECONDS

        app = _make_app()
        client = TestClient(app)

        fake_svc = SimpleNamespace(
            get_one=AsyncMock(return_value=None),
            set=AsyncMock(side_effect=ValueError(f"{KEY_DDOS_WINDOW_SECONDS}: out of range")),
        )
        with patch("yashigani.backoffice.state.backoffice_state.runtime_settings", fake_svc):
            resp = client.put(
                f"/admin/runtime-settings/{KEY_DDOS_WINDOW_SECONDS}",
                json={"value": 0},
            )
        assert resp.status_code == 422
        assert resp.json()["detail"]["error"] == "value_out_of_range"

    def test_in_range_value_succeeds(self):
        from yashigani.runtime_settings.keys import KEY_DDOS_WINDOW_SECONDS

        app = _make_app()
        client = TestClient(app)

        record = {"key": KEY_DDOS_WINDOW_SECONDS, "value": 120, "source": "api"}
        fake_svc = SimpleNamespace(
            get_one=AsyncMock(return_value=None),
            set=AsyncMock(return_value=record),
        )
        with patch("yashigani.backoffice.state.backoffice_state.runtime_settings", fake_svc), \
             patch("yashigani.backoffice.routes.runtime_settings._emit_audit", MagicMock()):
            resp = client.put(
                f"/admin/runtime-settings/{KEY_DDOS_WINDOW_SECONDS}",
                json={"value": 120},
            )
        assert resp.status_code == 200
        assert resp.json()["value"] == 120
