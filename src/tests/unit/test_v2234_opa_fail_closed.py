"""
v2.23.4 — OPA fail-closed regression tests.

Covers three fail-open paths closed in this release:

  Path 1 (lines ~1468-1470): OPA exception (timeout, connection refused, 5xx)
           → was fail-open (allow: True); now fail-closed (allow: False) + audit + counter.

  Path 2 (line ~1104 call-site + step 1b):  anonymous caller (identity=None)
           → was skipped at OPA guard; now rejected HTTP 401 at chat_completions
             before OPA is ever reached.

  Path 3 (lines ~1353, ~1439): opa_not_configured
           → was fail-open (allow: True); now fail-closed (allow: False) except
             YASHIGANI_OPA_OPTIONAL=true in non-production env.

ASVS V8.* + V14.5.* / feedback_zero_trust_default.md / feedback_no_v2235_close_everything_in_v2234.md

Last updated: 2026-05-18T00:00:00+00:00
"""
from __future__ import annotations

import os
import pytest
from unittest.mock import MagicMock, AsyncMock, patch


# ---------------------------------------------------------------------------
# Helpers — reset _state between tests so one test's configure() doesn't
# bleed into the next.
# ---------------------------------------------------------------------------

def _reset_router_state():
    """Reset _state fields that affect OPA routing."""
    from yashigani.gateway import openai_router as _mod
    _mod._state.opa_url = "https://policy:8181"
    _mod._state.audit_writer = None


# ---------------------------------------------------------------------------
# Path 1 — OPA exception → fail-closed
# ---------------------------------------------------------------------------

class TestOpaResponseCheckExceptionFailClosed:
    """Path 1: OPA response-check exception must deny the request (fail-closed)."""

    def _make_async_client_mock(self, post_side_effect=None, post_return=None):
        """Build an async context manager mock for internal_httpx_client."""
        mock_client = AsyncMock()
        if post_side_effect is not None:
            mock_client.post = AsyncMock(side_effect=post_side_effect)
        elif post_return is not None:
            mock_client.post = AsyncMock(return_value=post_return)

        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=mock_client)
        cm.__aexit__ = AsyncMock(return_value=False)
        return cm

    @pytest.mark.asyncio
    async def test_p1_timeout_returns_allow_false(self):
        """T1: OPA timeout → allow: False."""
        import httpx
        from yashigani.gateway import openai_router as _mod
        _reset_router_state()
        _mod._state.opa_url = "https://policy:8181"

        exc = httpx.TimeoutException("timed out")
        cm = self._make_async_client_mock(post_side_effect=exc)

        with patch("yashigani.gateway.openai_router.internal_httpx_client", return_value=cm):
            result = await _mod._opa_response_check(
                identity={"identity_id": "alice", "sensitivity_ceiling": "PUBLIC"},
                response_sensitivity="PUBLIC",
                response_verdict="clean",
                pii_detected=False,
            )

        assert result["allow"] is False
        assert result["reason"] == "opa_response_check_failed"

    @pytest.mark.asyncio
    async def test_p1_connection_refused_returns_allow_false(self):
        """T2: OPA connection refused → allow: False."""
        import httpx
        from yashigani.gateway import openai_router as _mod
        _reset_router_state()
        _mod._state.opa_url = "https://policy:8181"

        exc = httpx.ConnectError("connection refused")
        cm = self._make_async_client_mock(post_side_effect=exc)

        with patch("yashigani.gateway.openai_router.internal_httpx_client", return_value=cm):
            result = await _mod._opa_response_check(
                identity={"identity_id": "alice", "sensitivity_ceiling": "PUBLIC"},
                response_sensitivity="PUBLIC",
                response_verdict="clean",
                pii_detected=False,
            )

        assert result["allow"] is False
        assert result["reason"] == "opa_response_check_failed"

    @pytest.mark.asyncio
    async def test_p1_5xx_returns_allow_false(self):
        """T3: OPA 5xx response → allow: False."""
        import httpx
        from yashigani.gateway import openai_router as _mod
        _reset_router_state()
        _mod._state.opa_url = "https://policy:8181"

        exc = httpx.HTTPStatusError(
            "Internal Server Error",
            request=MagicMock(),
            response=MagicMock(status_code=500),
        )
        cm = self._make_async_client_mock(post_side_effect=exc)

        with patch("yashigani.gateway.openai_router.internal_httpx_client", return_value=cm):
            result = await _mod._opa_response_check(
                identity={"identity_id": "alice", "sensitivity_ceiling": "PUBLIC"},
                response_sensitivity="PUBLIC",
                response_verdict="clean",
                pii_detected=False,
            )

        assert result["allow"] is False
        assert result["reason"] == "opa_response_check_failed"

    @pytest.mark.asyncio
    async def test_p1_timeout_calls_audit_writer_once(self):
        """T4: OPA timeout → audit_writer called exactly once with exception event."""
        import httpx
        from yashigani.gateway import openai_router as _mod
        _reset_router_state()
        _mod._state.opa_url = "https://policy:8181"

        mock_audit = MagicMock()
        _mod._state.audit_writer = mock_audit

        exc = httpx.TimeoutException("timed out")
        cm = self._make_async_client_mock(post_side_effect=exc)

        with patch("yashigani.gateway.openai_router.internal_httpx_client", return_value=cm):
            await _mod._opa_response_check(
                identity={"identity_id": "alice", "sensitivity_ceiling": "PUBLIC"},
                response_sensitivity="PUBLIC",
                response_verdict="clean",
                pii_detected=False,
            )

        mock_audit.assert_called_once()
        call_args = mock_audit.call_args
        assert call_args[0][0] == "OPA_RESPONSE_CHECK_FAILED"
        payload = call_args[0][1]
        assert payload["outcome"] == "exception"
        assert payload["action"] == "denied_fail_closed"
        _mod._state.audit_writer = None

    @pytest.mark.asyncio
    async def test_p1_connection_refused_calls_audit_writer_once(self):
        """T5: OPA connection refused → audit_writer called exactly once."""
        import httpx
        from yashigani.gateway import openai_router as _mod
        _reset_router_state()
        _mod._state.opa_url = "https://policy:8181"

        mock_audit = MagicMock()
        _mod._state.audit_writer = mock_audit

        exc = httpx.ConnectError("connection refused")
        cm = self._make_async_client_mock(post_side_effect=exc)

        with patch("yashigani.gateway.openai_router.internal_httpx_client", return_value=cm):
            await _mod._opa_response_check(
                identity={"identity_id": "alice", "sensitivity_ceiling": "PUBLIC"},
                response_sensitivity="PUBLIC",
                response_verdict="clean",
                pii_detected=False,
            )

        mock_audit.assert_called_once()
        _mod._state.audit_writer = None

    @pytest.mark.asyncio
    async def test_p1_timeout_increments_prometheus_counter(self):
        """T6: OPA timeout → opa_response_check_failures_total increments."""
        import httpx
        from yashigani.gateway import openai_router as _mod
        _reset_router_state()
        _mod._state.opa_url = "https://policy:8181"

        mock_counter = MagicMock()
        mock_labels = MagicMock()
        mock_counter.labels.return_value = mock_labels

        exc = httpx.TimeoutException("timed out")
        cm = self._make_async_client_mock(post_side_effect=exc)

        with patch.object(_mod, "opa_response_check_failures_total", mock_counter):
            with patch("yashigani.gateway.openai_router.internal_httpx_client", return_value=cm):
                await _mod._opa_response_check(
                    identity={"identity_id": "alice", "sensitivity_ceiling": "PUBLIC"},
                    response_sensitivity="PUBLIC",
                    response_verdict="clean",
                    pii_detected=False,
                )

        mock_counter.labels.assert_called_once_with(outcome="exception", reason="TimeoutException")
        mock_labels.inc.assert_called_once()

    @pytest.mark.asyncio
    async def test_p1_opa_reachable_allow_true_passes(self):
        """T7: OPA reachable + allow: True → allow: True (positive regression)."""
        from yashigani.gateway import openai_router as _mod
        _reset_router_state()
        _mod._state.opa_url = "https://policy:8181"

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"result": {"allow": True, "reason": "ok"}}
        cm = self._make_async_client_mock(post_return=mock_resp)

        with patch("yashigani.gateway.openai_router.internal_httpx_client", return_value=cm):
            result = await _mod._opa_response_check(
                identity={"identity_id": "alice", "sensitivity_ceiling": "PUBLIC"},
                response_sensitivity="PUBLIC",
                response_verdict="clean",
                pii_detected=False,
            )

        assert result["allow"] is True

    @pytest.mark.asyncio
    async def test_p1_opa_reachable_allow_false_denies(self):
        """T8: OPA reachable + allow: False → allow: False (negative regression)."""
        from yashigani.gateway import openai_router as _mod
        _reset_router_state()
        _mod._state.opa_url = "https://policy:8181"

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"result": {"allow": False, "reason": "sensitivity_ceiling_exceeded"}}
        cm = self._make_async_client_mock(post_return=mock_resp)

        with patch("yashigani.gateway.openai_router.internal_httpx_client", return_value=cm):
            result = await _mod._opa_response_check(
                identity={"identity_id": "alice", "sensitivity_ceiling": "PUBLIC"},
                response_sensitivity="RESTRICTED",
                response_verdict="clean",
                pii_detected=False,
            )

        assert result["allow"] is False
        assert result["reason"] == "sensitivity_ceiling_exceeded"


# ---------------------------------------------------------------------------
# Path 3 — opa_not_configured → fail-closed
# ---------------------------------------------------------------------------

class TestOpaNotConfiguredFailClosed:
    """Path 3: OPA not configured must deny unless YASHIGANI_OPA_OPTIONAL=true in non-prod."""

    def test_p3_production_missing_opa_url_raises_at_startup(self, monkeypatch):
        """T9: configure() with no opa_url in YASHIGANI_ENV=production → RuntimeError."""
        monkeypatch.setenv("YASHIGANI_ENV", "production")
        monkeypatch.delenv("YASHIGANI_OPA_OPTIONAL", raising=False)

        from yashigani.gateway import openai_router as _mod
        with pytest.raises(RuntimeError, match="YASHIGANI_OPA_URL is required in production"):
            _mod.configure(opa_url="")

    def test_p3_dev_without_optional_flag_raises_at_startup(self, monkeypatch):
        """T10: configure() with no opa_url in dev without YASHIGANI_OPA_OPTIONAL → RuntimeError."""
        monkeypatch.setenv("YASHIGANI_ENV", "dev")
        monkeypatch.delenv("YASHIGANI_OPA_OPTIONAL", raising=False)

        from yashigani.gateway import openai_router as _mod
        with pytest.raises(RuntimeError, match="YASHIGANI_OPA_OPTIONAL"):
            _mod.configure(opa_url="")

    def test_p3_dev_with_optional_flag_starts_with_warning(self, monkeypatch):
        """T11: configure() with YASHIGANI_OPA_OPTIONAL=true in dev → allowed (starts ok)."""
        monkeypatch.setenv("YASHIGANI_ENV", "dev")
        monkeypatch.setenv("YASHIGANI_OPA_OPTIONAL", "true")
        # Patch INTERNAL_BEARER to avoid RuntimeError from _load_internal_bearer
        monkeypatch.setenv("YASHIGANI_INTERNAL_BEARER", "x" * 32)

        from yashigani.gateway import openai_router as _mod
        # Should NOT raise
        _mod.configure(opa_url="")
        # Verify opa_url is empty string (not_configured path active)
        assert _mod._state.opa_url == ""

    @pytest.mark.asyncio
    async def test_p3_response_check_no_url_dev_optional_true_allows(self, monkeypatch):
        """T12: _opa_response_check with empty opa_url + OPA_OPTIONAL=true in dev → allow: True."""
        monkeypatch.setenv("YASHIGANI_ENV", "dev")
        monkeypatch.setenv("YASHIGANI_OPA_OPTIONAL", "true")

        from yashigani.gateway import openai_router as _mod
        _mod._state.opa_url = ""

        result = await _mod._opa_response_check(
            identity={"identity_id": "alice"},
            response_sensitivity="PUBLIC",
            response_verdict="clean",
            pii_detected=False,
        )
        assert result["allow"] is True
        assert "dev_opt_in" in result["reason"]

    @pytest.mark.asyncio
    async def test_p3_response_check_no_url_without_optional_denies(self, monkeypatch):
        """T13: _opa_response_check with empty opa_url without OPA_OPTIONAL → allow: False."""
        monkeypatch.setenv("YASHIGANI_ENV", "dev")
        monkeypatch.delenv("YASHIGANI_OPA_OPTIONAL", raising=False)

        from yashigani.gateway import openai_router as _mod
        _mod._state.opa_url = ""

        result = await _mod._opa_response_check(
            identity={"identity_id": "alice"},
            response_sensitivity="PUBLIC",
            response_verdict="clean",
            pii_detected=False,
        )
        assert result["allow"] is False
        assert result["reason"] == "opa_not_configured"


# ---------------------------------------------------------------------------
# Path 2 — anonymous caller → HTTP 401 before OPA
# ---------------------------------------------------------------------------

class TestAnonymousCallerRejected:
    """Path 2: Anonymous /v1/chat/completions callers must get HTTP 401."""

    def _make_app(self):
        """Build a minimal test FastAPI app with the openai router mounted."""
        from fastapi import FastAPI
        from yashigani.gateway.openai_router import router as openai_router, configure
        app = FastAPI()
        app.include_router(openai_router)
        return app

    def test_p2_anonymous_caller_gets_401(self, monkeypatch):
        """T14: No auth header → 401 before OPA check."""
        monkeypatch.setenv("YASHIGANI_INTERNAL_BEARER", "x" * 32)
        monkeypatch.setenv("YASHIGANI_ENV", "dev")
        monkeypatch.setenv("YASHIGANI_OPA_OPTIONAL", "true")

        # Re-import with fresh env — INTERNAL_BEARER is loaded at module level
        import importlib
        import yashigani.gateway.openai_router as _mod
        importlib.reload(_mod)

        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        app = FastAPI()
        app.include_router(_mod.router)
        _mod.configure(opa_url="")

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(
            "/v1/chat/completions",
            json={"model": "test", "messages": [{"role": "user", "content": "hi"}]},
        )
        assert response.status_code == 401
        body = response.json()
        assert body["detail"]["error"] == "AUTHENTICATION_REQUIRED"

    def test_p2_internal_bearer_passes_auth_gate(self, monkeypatch):
        """T15: yashigani-internal Bearer resolves as service identity (not anonymous)."""
        _bearer = "internal-bearer-for-testing-" + "x" * 32
        monkeypatch.setenv("YASHIGANI_INTERNAL_BEARER", _bearer)

        import importlib
        import yashigani.gateway.openai_router as _mod
        importlib.reload(_mod)

        # _resolve_identity with the internal Bearer should return identity dict
        from starlette.requests import Request
        from starlette.datastructures import Headers

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/v1/chat/completions",
            "query_string": b"",
            "headers": [
                (b"authorization", f"Bearer {_bearer}".encode()),
            ],
        }
        req = Request(scope)
        identity = _mod._resolve_identity(req)
        assert identity is not None
        assert identity["identity_id"] == "internal"
        assert identity["kind"] == "service"
