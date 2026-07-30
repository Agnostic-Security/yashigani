"""
Regression tests — YSG-RISK-149 (MED): POST /admin/ratelimit/reset/{key}
succeeds (bucket deleted) then crashes on an unguarded ``assert`` -> 500
instead of a 2xx.

ROOT CAUSE (backoffice/routes/ratelimit.py reset_bucket(), pre-fix):

    state.rate_limiter._redis.delete(bucket_key)   # <- succeeds
    ...
    assert state.audit_writer is not None  # "set unconditionally at startup"
    state.audit_writer.write(...)
    return {"status": "ok", ...}

The comment's premise is not guaranteed in every runtime path (degraded
startup, test harnesses, future refactors) and a bare ``assert`` is also
stripped ENTIRELY under ``python -O`` (PYTHONOPTIMIZE=1/2), which would then
crash on the next line instead (``AttributeError: 'NoneType' object has no
attribute 'write'``) — either way, a caller that successfully reset a bucket
gets an unhandled 500 instead of 200.

FIX: guard with ``if state.audit_writer is not None:``; log a warning and
skip the (non-critical) audit write when absent, but always return the 2xx
for the already-successful reset.

Cross-ref: docs/risk-register.yml YSG-RISK-149.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from fastapi import FastAPI
from fastapi.testclient import TestClient

_VALID_KEY = "yashigani:rl:ip:deadbeef"


def _make_app(rate_limiter=None, audit_writer="UNSET"):
    from yashigani.backoffice.routes import ratelimit as ratelimit_routes
    from yashigani.backoffice.middleware import require_admin_session
    from yashigani.backoffice.state import backoffice_state

    backoffice_state.rate_limiter = rate_limiter if rate_limiter is not None else MagicMock()
    if audit_writer != "UNSET":
        backoffice_state.audit_writer = audit_writer

    app = FastAPI()
    app.dependency_overrides[require_admin_session] = lambda: SimpleNamespace(
        account_id="admin@test.local", account_tier="admin"
    )
    app.include_router(ratelimit_routes.router, prefix="/admin/ratelimit")
    return app


def _teardown():
    from yashigani.backoffice.state import backoffice_state
    backoffice_state.rate_limiter = None
    backoffice_state.audit_writer = None


class TestRatelimitResetAssertGuard:
    def test_reset_with_no_audit_writer_returns_200_not_500(self):
        """YSG-RISK-149 core regression: audit_writer is None -> the reset
        (which already deleted the Redis key) must still return 200, not 500.
        """
        rl = MagicMock()
        app = _make_app(rate_limiter=rl, audit_writer=None)
        try:
            client = TestClient(app)
            resp = client.post(f"/admin/ratelimit/reset/{_VALID_KEY}")
            assert resp.status_code == 200, (
                f"YSG-RISK-149 REGRESSION: expected 200 for successful reset with "
                f"no audit_writer configured, got {resp.status_code}: {resp.text}"
            )
            assert resp.json() == {"status": "ok", "bucket_key": _VALID_KEY}
            rl._redis.delete.assert_called_once_with(_VALID_KEY)
        finally:
            _teardown()

    def test_reset_with_audit_writer_writes_event_and_returns_200(self):
        """Positive path unaffected: when audit_writer IS configured, the
        event is written and 200 is returned (no regression to the happy path).
        """
        rl = MagicMock()
        audit_writer = MagicMock()
        app = _make_app(rate_limiter=rl, audit_writer=audit_writer)
        try:
            client = TestClient(app)
            resp = client.post(f"/admin/ratelimit/reset/{_VALID_KEY}")
            assert resp.status_code == 200
            assert resp.json() == {"status": "ok", "bucket_key": _VALID_KEY}
            audit_writer.write.assert_called_once()
            written_event = audit_writer.write.call_args[0][0]
            assert written_event.setting == "rate_limit_bucket_reset"
            assert written_event.previous_value == _VALID_KEY
            assert written_event.new_value == "deleted"
        finally:
            _teardown()

    def test_invalid_prefix_key_rejected_before_delete(self):
        rl = MagicMock()
        app = _make_app(rate_limiter=rl, audit_writer=None)
        try:
            client = TestClient(app)
            resp = client.post("/admin/ratelimit/reset/not-a-valid-key")
            assert resp.status_code == 422
            rl._redis.delete.assert_not_called()
        finally:
            _teardown()

    def test_rate_limiter_not_configured_returns_503(self):
        app = FastAPI()
        from yashigani.backoffice.routes import ratelimit as ratelimit_routes
        from yashigani.backoffice.middleware import require_admin_session
        from yashigani.backoffice.state import backoffice_state

        backoffice_state.rate_limiter = None
        backoffice_state.audit_writer = None
        app.dependency_overrides[require_admin_session] = lambda: SimpleNamespace(
            account_id="admin@test.local", account_tier="admin"
        )
        app.include_router(ratelimit_routes.router, prefix="/admin/ratelimit")
        client = TestClient(app)
        try:
            resp = client.post(f"/admin/ratelimit/reset/{_VALID_KEY}")
            assert resp.status_code == 503
        finally:
            _teardown()

    def test_redis_delete_failure_returns_500_with_safe_envelope(self):
        """Unrelated failure mode (Redis unreachable) must still be a
        handled 500 with a safe envelope, not an unhandled crash.
        """
        rl = MagicMock()
        rl._redis.delete.side_effect = ConnectionError("redis unreachable")
        app = _make_app(rate_limiter=rl, audit_writer=None)
        try:
            client = TestClient(app)
            resp = client.post(f"/admin/ratelimit/reset/{_VALID_KEY}")
            assert resp.status_code == 500
        finally:
            _teardown()
