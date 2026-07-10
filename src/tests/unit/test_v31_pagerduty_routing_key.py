"""
Regression tests — PagerDuty routing_key field alignment (v3.1).

Root cause: dashboard.js was sending `pagerduty_integration_key` (wrong name)
while AlertConfigRequest defined `pagerduty_routing_key` (correct PagerDuty
Events API v2 field name). Pydantic silently dropped the unknown field → PagerDuty
was never configured from the UI despite "Configuration saved".

Fix: dashboard.js now sends `pagerduty_routing_key`. Model is unchanged.

Tests:
  PD-REG-01  PUT /admin/alerts/config with pagerduty_routing_key → 200
  PD-REG-02  GET /admin/alerts/config reflects pagerduty sink as set (masked)
  PD-REG-03  PUT with empty pagerduty_routing_key → pagerduty not in sinks
  PD-REG-04  PUT without pagerduty_routing_key field (omitted) → 200, pagerduty absent
  PD-REG-05  Model field inventory: pagerduty_routing_key exists, pagerduty_integration_key does NOT

Last updated: 2026-06-19T00:00:00+01:00
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
import pytest

try:
    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient
    _HAVE_FASTAPI = True
except ImportError:  # pragma: no cover
    _HAVE_FASTAPI = False

pytestmark = pytest.mark.skipif(
    not _HAVE_FASTAPI,
    reason="fastapi + httpx required",
)


# ---------------------------------------------------------------------------
# Helpers — mirror pattern from test_v2255_alerts_settings_api.py
# ---------------------------------------------------------------------------

def _admin_override():
    return SimpleNamespace(account_id="admin@test.local", account_tier="admin")


def _make_app() -> "FastAPI":
    from yashigani.backoffice.routes.alerts import router
    from yashigani.backoffice.middleware import require_admin_session
    from yashigani.backoffice import state as st

    # Reset alert_config between tests
    if hasattr(st.backoffice_state, "alert_config"):
        delattr(st.backoffice_state, "alert_config")

    # Silence audit writer
    st.backoffice_state.audit_writer = None

    app = FastAPI()
    app.dependency_overrides[require_admin_session] = lambda: _admin_override()
    app.include_router(router, prefix="/admin/alerts")
    return app


# ---------------------------------------------------------------------------
# PD-REG-01: PUT with pagerduty_routing_key set → 200
# ---------------------------------------------------------------------------

def test_put_with_pagerduty_routing_key_returns_200() -> None:
    """PD-REG-01: PUT /admin/alerts/config with pagerduty_routing_key → 200."""
    app = _make_app()

    async def go():
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            return await c.put(
                "/admin/alerts/config",
                json={
                    "slack_webhook_url": "",
                    "teams_webhook_url": "",
                    "pagerduty_routing_key": "abc123def456abc123def456abc12345",
                    "alert_on_credential_exfil": True,
                    "alert_on_anomaly_threshold": True,
                },
            )

    r = asyncio.run(go())
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "ok"
    assert body["sinks_configured"] == 1, (
        "PD-REG-01: pagerduty_routing_key must wire up exactly 1 sink"
    )


# ---------------------------------------------------------------------------
# PD-REG-02: GET /admin/alerts/config reflects pagerduty as set (masked)
# ---------------------------------------------------------------------------

def test_get_after_put_reflects_pagerduty_set() -> None:
    """PD-REG-02: GET /admin/alerts/config reflects pagerduty sink after PUT."""
    app = _make_app()

    async def go():
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            put_r = await c.put(
                "/admin/alerts/config",
                json={
                    "slack_webhook_url": "",
                    "teams_webhook_url": "",
                    "pagerduty_routing_key": "abc123def456abc123def456abc12345",
                },
            )
            assert put_r.status_code == 200, put_r.text
            return await c.get("/admin/alerts/config")

    r = asyncio.run(go())
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["configured"] is True, "PD-REG-02: configured must be True after PUT with key"

    sink_types = {s["type"] for s in body["sinks"]}
    assert "pagerduty" in sink_types, (
        "PD-REG-02: pagerduty must appear in sinks after PUT with pagerduty_routing_key"
    )

    pd_sink = next(s for s in body["sinks"] if s["type"] == "pagerduty")
    assert "masked_key" in pd_sink, "PD-REG-02: pagerduty sink must expose masked_key"
    # Masking: last 6 chars of "abc123def456abc123def456abc12345" = "c12345"
    assert pd_sink["masked_key"].endswith("c12345"), (
        "PD-REG-02: masked_key must show last 6 chars of the routing key"
    )
    assert pd_sink["masked_key"].startswith("***"), (
        "PD-REG-02: masked_key must begin with *** prefix"
    )


# ---------------------------------------------------------------------------
# PD-REG-03: PUT with empty pagerduty_routing_key → pagerduty not in sinks
# ---------------------------------------------------------------------------

def test_put_empty_routing_key_pagerduty_not_in_sinks() -> None:
    """PD-REG-03: Empty pagerduty_routing_key → pagerduty absent from sinks."""
    app = _make_app()

    async def go():
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            put_r = await c.put(
                "/admin/alerts/config",
                json={
                    "slack_webhook_url": "",
                    "teams_webhook_url": "",
                    "pagerduty_routing_key": "",
                },
            )
            assert put_r.status_code == 200, put_r.text
            assert put_r.json()["sinks_configured"] == 0
            return await c.get("/admin/alerts/config")

    r = asyncio.run(go())
    body = r.json()
    sink_types = {s["type"] for s in body["sinks"]}
    assert "pagerduty" not in sink_types, (
        "PD-REG-03: pagerduty must not appear in sinks when routing_key is empty"
    )


# ---------------------------------------------------------------------------
# PD-REG-04: PUT omitting pagerduty_routing_key → defaults to empty, pagerduty absent
# ---------------------------------------------------------------------------

def test_put_omitting_routing_key_pagerduty_absent() -> None:
    """PD-REG-04: PUT without pagerduty_routing_key → 200, pagerduty absent."""
    app = _make_app()

    async def go():
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            put_r = await c.put(
                "/admin/alerts/config",
                json={
                    "slack_webhook_url": "https://hooks.slack.com/services/T0/B0/abc",
                    "teams_webhook_url": "",
                    # pagerduty_routing_key omitted → defaults to ""
                },
            )
            assert put_r.status_code == 200, put_r.text
            body = put_r.json()
            assert body["sinks_configured"] == 1, (
                "PD-REG-04: only slack should be configured when pagerduty key omitted"
            )
            return await c.get("/admin/alerts/config")

    r = asyncio.run(go())
    body = r.json()
    sink_types = {s["type"] for s in body["sinks"]}
    assert "slack" in sink_types
    assert "pagerduty" not in sink_types, (
        "PD-REG-04: pagerduty must be absent when routing_key was not supplied"
    )


# ---------------------------------------------------------------------------
# PD-REG-05: Model field name contract — routing_key exists, integration_key does NOT
# ---------------------------------------------------------------------------

def test_model_has_routing_key_not_integration_key() -> None:
    """PD-REG-05: AlertConfigRequest has pagerduty_routing_key, NOT pagerduty_integration_key."""
    from yashigani.backoffice.routes.alerts import AlertConfigRequest

    fields = set(AlertConfigRequest.model_fields.keys())

    assert "pagerduty_routing_key" in fields, (
        "PD-REG-05: AlertConfigRequest must have pagerduty_routing_key "
        "(correct PagerDuty Events API v2 field name)"
    )
    assert "pagerduty_integration_key" not in fields, (
        "PD-REG-05: AlertConfigRequest must NOT have pagerduty_integration_key "
        "(old dashboard.js name — was the root cause of the silent-drop bug)"
    )
