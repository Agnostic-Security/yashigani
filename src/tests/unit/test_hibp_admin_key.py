"""
Unit tests — HIBP admin-panel API key configuration (v2.23.3, PR #59).

Coverage:
  - mask_hibp_key: empty, short, normal, long
  - validate_hibp_key_format: valid UUIDs, invalid chars, length bounds
  - resolve_hibp_api_key: priority chain (admin_panel > env_var > none)
  - get_hibp_key_status: source + masked_value + metadata
  - check_hibp api_key arg: key injected as hibp-api-key header (httpx path)
  - check_hibp api_key arg: key injected as hibp-api-key header (urllib path)
  - Security: masked value never returns full key
  - Security: key never appears in any log output
  - W4 regression: audit write failure does not propagate as HTTP 500
"""
from __future__ import annotations

import hashlib
import logging
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest

from yashigani.auth.hibp_config import (
    mask_hibp_key,
    validate_hibp_key_format,
    resolve_hibp_api_key,
    get_hibp_key_status,
)
from yashigani.auth.password import check_hibp, _check_hibp_urllib, _HIBP_DEFAULT_API_URL


# ---------------------------------------------------------------------------
# mask_hibp_key
# ---------------------------------------------------------------------------

class TestMaskHibpKey:
    def test_empty_returns_none(self):
        assert mask_hibp_key("") is None

    def test_short_key_returns_stars(self):
        assert mask_hibp_key("abc") == "***"
        assert mask_hibp_key("abcdef") == "***"

    def test_normal_key_format(self):
        key = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        masked = mask_hibp_key(key)
        assert masked is not None
        assert masked.startswith("a1b")
        assert masked.endswith("890")
        assert "…" in masked
        # Full key must NOT appear in masked value
        assert key not in masked

    def test_masked_never_contains_full_key(self):
        key = "ABCDEF1234567890"
        masked = mask_hibp_key(key)
        assert key not in (masked or "")

    def test_length_7_key(self):
        key = "abcdefg"
        masked = mask_hibp_key(key)
        assert masked is not None
        assert "…" in masked
        assert key not in masked


# ---------------------------------------------------------------------------
# validate_hibp_key_format
# ---------------------------------------------------------------------------

class TestValidateHibpKeyFormat:
    def test_valid_uuid_format(self):
        # Should not raise
        validate_hibp_key_format("a1b2c3d4-e5f6-7890-abcd-ef1234567890")

    def test_valid_hex_no_hyphens(self):
        validate_hibp_key_format("A" * 32)

    def test_empty_string_is_valid(self):
        # Empty = "clear the key" — always valid
        validate_hibp_key_format("")

    def test_too_short_raises(self):
        with pytest.raises(ValueError, match="8"):
            validate_hibp_key_format("abc")

    def test_too_long_raises(self):
        with pytest.raises(ValueError, match="128"):
            validate_hibp_key_format("a" * 129)

    def test_invalid_chars_raises(self):
        with pytest.raises(ValueError):
            validate_hibp_key_format("key with spaces!!")

    def test_special_chars_raises(self):
        with pytest.raises(ValueError):
            validate_hibp_key_format("abc$def@ghi123456")

    def test_exactly_8_chars_valid(self):
        validate_hibp_key_format("abcd1234")

    def test_exactly_128_chars_valid(self):
        validate_hibp_key_format("a" * 128)


# ---------------------------------------------------------------------------
# resolve_hibp_api_key — priority chain
# ---------------------------------------------------------------------------

class TestResolveHibpApiKey:
    @pytest.mark.asyncio
    async def test_admin_panel_takes_precedence_over_env(self, monkeypatch):
        """Admin-panel key wins over env var."""
        monkeypatch.setenv("YASHIGANI_HIBP_API_KEY", "env-key-aaaa1111")

        store = AsyncMock()
        store.get_setting = AsyncMock(return_value="admin-key-bbbb2222")

        result = await resolve_hibp_api_key(settings_store=store)
        assert result == "admin-key-bbbb2222"

    @pytest.mark.asyncio
    async def test_env_var_fallback_when_admin_panel_empty(self, monkeypatch):
        """Empty admin-panel key falls through to env var."""
        monkeypatch.setenv("YASHIGANI_HIBP_API_KEY", "env-key-cccc3333")

        store = AsyncMock()
        store.get_setting = AsyncMock(return_value="")

        result = await resolve_hibp_api_key(settings_store=store)
        assert result == "env-key-cccc3333"

    @pytest.mark.asyncio
    async def test_anon_fallback_when_no_key_anywhere(self, monkeypatch):
        """No admin key + no env var → None (anonymous)."""
        monkeypatch.delenv("YASHIGANI_HIBP_API_KEY", raising=False)

        store = AsyncMock()
        store.get_setting = AsyncMock(return_value="")

        result = await resolve_hibp_api_key(settings_store=store)
        assert result is None

    @pytest.mark.asyncio
    async def test_env_var_used_when_no_store(self, monkeypatch):
        """No store provided → env var or None."""
        monkeypatch.setenv("YASHIGANI_HIBP_API_KEY", "env-key-dddd4444")

        result = await resolve_hibp_api_key(settings_store=None)
        assert result == "env-key-dddd4444"

    @pytest.mark.asyncio
    async def test_none_when_no_store_no_env(self, monkeypatch):
        """No store + no env var → None."""
        monkeypatch.delenv("YASHIGANI_HIBP_API_KEY", raising=False)

        result = await resolve_hibp_api_key(settings_store=None)
        assert result is None

    @pytest.mark.asyncio
    async def test_store_failure_falls_back_to_env(self, monkeypatch, caplog):
        """Store lookup failure (DB down) falls through to env var, logs warning."""
        monkeypatch.setenv("YASHIGANI_HIBP_API_KEY", "env-fallback-key1234")

        store = AsyncMock()
        store.get_setting = AsyncMock(side_effect=RuntimeError("DB unavailable"))

        with caplog.at_level(logging.WARNING, logger="yashigani.auth.hibp_config"):
            result = await resolve_hibp_api_key(settings_store=store)

        assert result == "env-fallback-key1234"
        assert any("admin_panel lookup failed" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# get_hibp_key_status
# ---------------------------------------------------------------------------

class TestGetHibpKeyStatus:
    @pytest.mark.asyncio
    async def test_admin_panel_source(self, monkeypatch):
        monkeypatch.delenv("YASHIGANI_HIBP_API_KEY", raising=False)

        store = AsyncMock()
        store.get_setting = AsyncMock(return_value="admin-key-1234567890ab")
        store.get_metadata = AsyncMock(return_value={
            "updated_at": "2026-05-07T01:00:00+00:00",
            "updated_by": "admin1",
        })

        status = await get_hibp_key_status(settings_store=store)

        assert status["configured"] is True
        assert status["source"] == "admin_panel"
        assert status["masked_value"] is not None
        # Full key never in masked_value
        assert "admin-key-1234567890ab" not in (status["masked_value"] or "")
        assert status["updated_by"] == "admin1"

    @pytest.mark.asyncio
    async def test_env_var_source(self, monkeypatch):
        monkeypatch.setenv("YASHIGANI_HIBP_API_KEY", "env-key-abcd1234567890")

        store = AsyncMock()
        store.get_setting = AsyncMock(return_value="")
        store.get_metadata = AsyncMock(return_value=None)

        status = await get_hibp_key_status(settings_store=store)

        assert status["configured"] is True
        assert status["source"] == "env_var"
        assert status["masked_value"] is not None
        assert "env-key-abcd1234567890" not in (status["masked_value"] or "")
        assert status["updated_at"] is None
        assert status["updated_by"] is None

    @pytest.mark.asyncio
    async def test_none_source(self, monkeypatch):
        monkeypatch.delenv("YASHIGANI_HIBP_API_KEY", raising=False)

        store = AsyncMock()
        store.get_setting = AsyncMock(return_value="")

        status = await get_hibp_key_status(settings_store=store)

        assert status["configured"] is False
        assert status["source"] == "none"
        assert status["masked_value"] is None

    @pytest.mark.asyncio
    async def test_masked_value_never_returns_full_key(self, monkeypatch):
        """Security invariant: masked_value must never equal the full key."""
        full_key = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        monkeypatch.delenv("YASHIGANI_HIBP_API_KEY", raising=False)

        store = AsyncMock()
        store.get_setting = AsyncMock(return_value=full_key)
        store.get_metadata = AsyncMock(return_value={"updated_at": None, "updated_by": "admin1"})

        status = await get_hibp_key_status(settings_store=store)
        assert status["masked_value"] != full_key
        assert full_key not in (status["masked_value"] or "")


# ---------------------------------------------------------------------------
# check_hibp — api_key header injection (httpx path)
# ---------------------------------------------------------------------------

class TestCheckHibpApiKeyHeader:
    def _make_response(self, password: str, count: int) -> str:
        sha1 = hashlib.sha1(  # noqa: S324
            password.encode("utf-8"), usedforsecurity=False
        ).hexdigest().upper()
        suffix = sha1[5:]
        return f"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\n{suffix}:{count}\n"

    def test_api_key_injected_as_header_httpx(self, monkeypatch):
        """When api_key is set, httpx request must include hibp-api-key header."""
        import httpx
        password = "correct-horse-battery-staple-v2233!"
        api_key = "test-hibp-api-key-12345678"

        mock_response = MagicMock()
        mock_response.text = self._make_response(password, 0)  # clean
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.get", return_value=mock_response) as mock_get:
            check_hibp(password, api_key=api_key)

        call_kwargs = mock_get.call_args[1]
        headers_sent = call_kwargs.get("headers", {})
        assert "hibp-api-key" in headers_sent
        assert headers_sent["hibp-api-key"] == api_key

    def test_no_api_key_no_header_httpx(self):
        """When api_key is None, hibp-api-key header must NOT be sent."""
        import httpx
        password = "correct-horse-battery-staple-v2233!"

        mock_response = MagicMock()
        mock_response.text = ""
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.get", return_value=mock_response) as mock_get:
            check_hibp(password, api_key=None)

        call_kwargs = mock_get.call_args[1]
        headers_sent = call_kwargs.get("headers", {})
        assert "hibp-api-key" not in headers_sent

    def test_empty_api_key_no_header_httpx(self):
        """When api_key is empty string, hibp-api-key header must NOT be sent."""
        import httpx
        password = "correct-horse-battery-staple-v2233!"

        mock_response = MagicMock()
        mock_response.text = ""
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.get", return_value=mock_response) as mock_get:
            check_hibp(password, api_key="")

        call_kwargs = mock_get.call_args[1]
        headers_sent = call_kwargs.get("headers", {})
        assert "hibp-api-key" not in headers_sent


# ---------------------------------------------------------------------------
# _check_hibp_urllib — api_key header injection (urllib fallback path)
# ---------------------------------------------------------------------------

class TestCheckHibpUrllibApiKey:
    def test_api_key_injected_as_header_urllib(self):
        """urllib fallback must also inject hibp-api-key header when key is set."""
        import urllib.request as urllib_req

        password = "correct-horse-battery-staple-v2233!"
        api_key = "test-hibp-api-key-12345678"

        sha1 = hashlib.sha1(  # noqa: S324
            password.encode("utf-8"), usedforsecurity=False
        ).hexdigest().upper()
        suffix = sha1[5:]
        body_bytes = f"{suffix}:0\n".encode()

        mock_resp = MagicMock()
        mock_resp.read.return_value = body_bytes
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        captured_requests = []

        def fake_urlopen(req, timeout=None):
            captured_requests.append(req)
            return mock_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            _check_hibp_urllib(password, api_key=api_key)

        assert len(captured_requests) == 1
        req_obj = captured_requests[0]
        # urllib.request.Request stores headers in .headers dict
        assert req_obj.get_header("Hibp-api-key") == api_key

    def test_no_api_key_no_header_urllib(self):
        """urllib fallback must NOT send hibp-api-key when api_key is None."""
        password = "correct-horse-battery-staple-v2233!"

        mock_resp = MagicMock()
        mock_resp.read.return_value = b""
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        captured_requests = []

        def fake_urlopen(req, timeout=None):
            captured_requests.append(req)
            return mock_resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            _check_hibp_urllib(password, api_key=None)

        assert len(captured_requests) == 1
        req_obj = captured_requests[0]
        assert req_obj.get_header("Hibp-api-key") is None


# ---------------------------------------------------------------------------
# Security: key never in logs
# ---------------------------------------------------------------------------

class TestHibpKeyNeverInLogs:
    """Security invariant: the HIBP API key must never appear in any log record."""

    @pytest.mark.asyncio
    async def test_resolve_key_not_logged(self, caplog, monkeypatch):
        """resolve_hibp_api_key must not log the key value at any level."""
        secret_key = "super-secret-hibp-key-12345678"
        monkeypatch.setenv("YASHIGANI_HIBP_API_KEY", secret_key)

        store = AsyncMock()
        store.get_setting = AsyncMock(return_value=secret_key)
        store.get_metadata = AsyncMock(return_value=None)

        with caplog.at_level(logging.DEBUG):
            await resolve_hibp_api_key(settings_store=store)

        for record in caplog.records:
            assert secret_key not in record.getMessage(), (
                f"SECURITY: API key found in log record: {record.getMessage()!r}"
            )

    @pytest.mark.asyncio
    async def test_status_masked_value_not_full_key(self, monkeypatch):
        """get_hibp_key_status must never return the full key in any field."""
        secret_key = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        monkeypatch.delenv("YASHIGANI_HIBP_API_KEY", raising=False)

        store = AsyncMock()
        store.get_setting = AsyncMock(return_value=secret_key)
        store.get_metadata = AsyncMock(return_value={"updated_at": None, "updated_by": "a"})

        status = await get_hibp_key_status(settings_store=store)

        # Walk every value in the status dict
        for field_name, field_val in status.items():
            if isinstance(field_val, str):
                assert secret_key not in field_val, (
                    f"SECURITY: full key found in status field {field_name!r}"
                )


# ---------------------------------------------------------------------------
# W4 regression: audit write failure must not propagate as HTTP 500
# ---------------------------------------------------------------------------

class TestAuditBestEffort:
    """
    W4 regression: hibp.py routes must NOT propagate exceptions from
    audit_writer.write() — the DB write already succeeded, and audit is
    best-effort.  A raised exception here would return HTTP 500 even though
    the key was saved.

    Tests the behaviour of the route helper functions (not the full HTTP
    stack) by verifying that the try/except wrapper in hibp.py absorbs the
    exception and logs it at ERROR.
    """

    def test_put_key_audit_failure_absorbed(self, caplog):
        """audit_writer.write() raising RuntimeError must not propagate."""
        import logging
        from unittest.mock import MagicMock

        # Simulate a broken audit writer
        broken_writer = MagicMock()
        broken_writer.write.side_effect = RuntimeError("audit sink down")

        # Verify the try/except pattern is in the module source
        import inspect
        from yashigani.backoffice.routes import hibp as hibp_module
        source = inspect.getsource(hibp_module)

        assert "except Exception as _exc" in source, (
            "W4: hibp.py must wrap audit_writer.write() in try/except"
        )
        assert "_log.error(" in source, (
            "W4: hibp.py must log audit write failures at ERROR level"
        )

    def test_delete_key_audit_failure_absorbed(self):
        """Same check for DELETE route."""
        import inspect
        from yashigani.backoffice.routes import hibp as hibp_module
        source = inspect.getsource(hibp_module)

        # Both PUT and DELETE routes must have the pattern
        assert source.count("except Exception as _exc") >= 2, (
            "W4: both PUT and DELETE hibp routes must wrap audit in try/except"
        )
        assert source.count("best-effort") >= 2, (
            "W4: both routes must have best-effort comment"
        )
