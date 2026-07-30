"""
Regression test -- v4.1.2 YSG-RISK-142 (HIGH): POST /admin/audit/siem/config/test
route-registration-order collision.

Root cause: src/yashigani/backoffice/routes/audit.py registers
`POST /siem/{name}/test` (mounted with prefix /admin/audit -> full path
POST /admin/audit/siem/{name}/test) -- a path-PARAM route. audit_sinks.py
(routes/audit_sinks.py) separately registers the LITERAL path
`POST /admin/audit/siem/config/test`. Both are 3-segment paths after
/admin/audit/siem/, so "config" matches the {name} path parameter.

app.py previously registered audit_router (audit.py) BEFORE audit_sinks_router
-- FastAPI/Starlette matches routes in whole-app registration order, so
POST /admin/audit/siem/config/test silently resolved to
test_siem_target(name="config") (audit.py) instead of the intended
test_siem() handler (audit_sinks.py), making the SIEM-backend-config test
endpoint permanently unreachable.

Fix: app.py now registers audit_sinks_router BEFORE audit_router.

This test builds a minimal app with BOTH routers mounted in the SAME order
app.py uses, and asserts the literal path reaches audit_sinks.py's test_siem
(observable via a distinguishing side effect / exception), not audit.py's
test_siem_target.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

try:
    from fastapi.testclient import TestClient
    _HAVE_FASTAPI = True
except ImportError:
    _HAVE_FASTAPI = False

pytestmark = pytest.mark.skipif(not _HAVE_FASTAPI, reason="fastapi required")

_FAKE_SESSION = SimpleNamespace(account_id="test-admin", account_tier="admin")


def _make_app_with_real_registration_order():
    """Mirrors app.py's CURRENT (fixed) registration order: audit_sinks_router
    is included BEFORE audit_router."""
    import fastapi as _fastapi

    from yashigani.backoffice import middleware as mw
    from yashigani.backoffice.routes.audit import router as audit_router
    from yashigani.backoffice.routes.audit_sinks import audit_sinks_router

    app = _fastapi.FastAPI()
    app.dependency_overrides[mw.require_admin_session] = lambda: _FAKE_SESSION
    app.dependency_overrides[mw.require_stepup_admin_session] = lambda: _FAKE_SESSION
    # Order matters — this IS the fix (see app.py comment at the same call site).
    app.include_router(audit_sinks_router, tags=["audit-sinks"])
    app.include_router(audit_router, prefix="/admin/audit", tags=["audit"])
    return app


def _make_app_with_broken_registration_order():
    """Mirrors the PRE-FIX (buggy) order, to prove the test itself is
    sensitive to registration order (i.e. it would have caught the bug)."""
    import fastapi as _fastapi

    from yashigani.backoffice import middleware as mw
    from yashigani.backoffice.routes.audit import router as audit_router
    from yashigani.backoffice.routes.audit_sinks import audit_sinks_router

    app = _fastapi.FastAPI()
    app.dependency_overrides[mw.require_admin_session] = lambda: _FAKE_SESSION
    app.dependency_overrides[mw.require_stepup_admin_session] = lambda: _FAKE_SESSION
    app.include_router(audit_router, prefix="/admin/audit", tags=["audit"])
    app.include_router(audit_sinks_router, tags=["audit-sinks"])
    return app


@pytest.fixture()
def _state_for_siem_test():
    """Configure the REAL backoffice_state singleton.

    audit.py imports `backoffice_state` at MODULE level (bound at import
    time) while audit_sinks.py re-imports it LOCALLY inside each route
    function; patching/replacing the module-level name would only reach one
    of the two call sites. Mutating attributes on the existing singleton
    object reaches BOTH (they're the same object either way), and is
    restored after the test.
    """
    from yashigani.backoffice.state import backoffice_state

    orig = {
        "siem_backend": backoffice_state.siem_backend,
        "siem_endpoint": backoffice_state.siem_endpoint,
        "kms_provider": backoffice_state.kms_provider,
        "audit_writer": backoffice_state.audit_writer,
    }
    backoffice_state.siem_backend = "splunk"
    backoffice_state.siem_endpoint = "https://splunk.example.internal:8088"
    kms = SimpleNamespace(get_secret=lambda name: "fake-token")
    backoffice_state.kms_provider = kms
    writer = SimpleNamespace(_siem_targets=[])  # audit.py's _audit_writer() needs non-None + ._siem_targets
    backoffice_state.audit_writer = writer
    try:
        yield backoffice_state
    finally:
        for k, v in orig.items():
            setattr(backoffice_state, k, v)


def test_fixed_order_reaches_audit_sinks_test_siem(_state_for_siem_test):
    app = _make_app_with_real_registration_order()
    client = TestClient(app)

    with patch(
        "yashigani.audit.sinks.SiemSink.write",
        new=AsyncMock(return_value=None),
    ) as mock_write:
        resp = client.post("/admin/audit/siem/config/test")

    # audit_sinks.test_siem() calls SiemSink.write() with a synthetic test
    # event and returns {"status": "test_sent", ...} — that is proof we hit
    # the RIGHT handler, not audit.py's test_siem_target (which looks up a
    # NAMED siem target called "config" and 404s if not found).
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "test_sent"
    mock_write.assert_awaited_once()


def test_broken_order_would_have_hit_the_wrong_handler(_state_for_siem_test):
    """Proves this test is a genuine regression guard: with the PRE-FIX
    registration order restored, the same request resolves to audit.py's
    named-siem-target handler and 404s (no target called "config" exists),
    NOT audit_sinks.py's test_siem."""
    app = _make_app_with_broken_registration_order()
    client = TestClient(app)

    resp = client.post("/admin/audit/siem/config/test")

    # audit.py's test_siem_target(name="config") looks up a named SIEM target
    # called "config" in writer._siem_targets — none configured -> 404. This
    # is the OLD (buggy) behaviour this regression test guards against.
    assert resp.status_code == 404
