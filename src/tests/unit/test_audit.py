"""
Unit tests for the Yashigani Audit module.
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from yashigani.audit.config import AuditConfig
from yashigani.audit.masking import CredentialMasker, IMMUTABLE_FLOOR_EVENTS
from yashigani.audit.schema import (
    AuditEvent,
    CredentialLeakDetectedEvent,
    PromptInjectionDetectedEvent,
    AdminLoginEvent,
    EmergencyUnlockExecutedEvent,
    TotpResetConsoleEvent,
    UserFullResetEvent,
    ConfigChangedEvent,
)
from yashigani.audit.scope import MaskingScopeConfig
from yashigani.audit.writer import AuditLogWriter, AuditWriteError, SiemTarget
from yashigani.audit.export import AuditLogExporter


# ---------------------------------------------------------------------------
# CredentialMasker — pattern coverage
# ---------------------------------------------------------------------------

class TestCredentialMasker:
    masker = CredentialMasker()

    def test_masks_jwt(self):
        text = "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c end"
        result = self.masker.mask_string(text)
        assert "[REDACTED:jwt]" in result
        assert "eyJhbGci" not in result

    def test_masks_bearer(self):
        text = "Authorization: Bearer abc123def456ghi789"
        result = self.masker.mask_string(text)
        assert "[REDACTED:bearer]" in result
        assert "abc123def456" not in result

    def test_masks_sk_api_key(self):
        text = "key=" + "sk-" + "abcdefghijklmnopqrstuvwxyz123456"
        result = self.masker.mask_string(text)
        assert "[REDACTED:api_key]" in result

    def test_masks_github_pat(self):
        text = "token ghp_" + "A" * 36
        result = self.masker.mask_string(text)
        assert "[REDACTED:api_key]" in result

    def test_masks_aws_key(self):
        text = "AKIA" + "IOSFODNN7EXAMPLE"
        result = self.masker.mask_string(text)
        assert "[REDACTED:api_key]" in result

    def test_masks_pem_header(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK..."
        result = self.masker.mask_string(text)
        assert "[REDACTED:private_key]" in result

    def test_masks_basic_auth(self):
        text = "Authorization: Basic dXNlcjpwYXNzd29yZA=="
        result = self.masker.mask_string(text)
        assert "[REDACTED:basic_auth]" in result

    def test_clean_string_unchanged(self):
        text = "Hello, this is a normal log message with no secrets."
        result = self.masker.mask_string(text)
        assert result == text

    def test_mask_dict_recursive(self):
        data = {
            "message": "Bearer abc123def456ghi789jkl",
            "nested": {"token": "sk-" + "x" * 25},
            "count": 42,
        }
        result = self.masker.mask_dict(data)
        assert "[REDACTED:bearer]" in result["message"]
        assert "[REDACTED:api_key]" in result["nested"]["token"]
        assert result["count"] == 42

    def test_mask_event_strings(self):
        event = AdminLoginEvent(
            account_tier="admin",
            admin_account="admin1",
            outcome="failure",
            failure_reason="Bearer abc123defghijklmnopqrstu",
        )
        masked = CredentialMasker().mask_event(event)
        assert "[REDACTED:bearer]" in masked.failure_reason
        assert masked.admin_account == "admin1"

    def test_raw_query_logged_always_false(self):
        event = PromptInjectionDetectedEvent(
            account_tier="system",
            raw_query_logged=True,  # attempt to set True
        )
        masked = CredentialMasker().mask_event(event)
        assert masked.raw_query_logged is False


# ---------------------------------------------------------------------------
# Immutable floor events cannot be bypassed
# ---------------------------------------------------------------------------

class TestImmutableFloor:
    def test_floor_events_always_masked(self):
        scope = MaskingScopeConfig(mask_all_by_default=False)
        # Even with masking disabled by default, floor events must mask
        for event_type in IMMUTABLE_FLOOR_EVENTS:
            event = AuditEvent(event_type=event_type, account_tier="system")
            assert scope.should_mask(event) is True, \
                f"Floor event {event_type} was not masked"

    def test_floor_agent_override_cannot_disable(self):
        scope = MaskingScopeConfig(
            mask_all_by_default=False,
            agent_overrides={"agent-1": False},
        )
        event = CredentialLeakDetectedEvent(account_tier="system")
        assert scope.should_mask(event, agent_id="agent-1") is True

    def test_non_floor_event_can_be_disabled(self):
        scope = MaskingScopeConfig(
            mask_all_by_default=False,
            agent_overrides={"agent-1": False},
        )
        event = AdminLoginEvent(account_tier="admin")
        assert scope.should_mask(event, agent_id="agent-1") is False

    def test_emergency_unlock_always_critical(self):
        event = EmergencyUnlockExecutedEvent(account_tier="admin")
        scope = MaskingScopeConfig(mask_all_by_default=False)
        assert scope.should_mask(event) is True
        assert event.severity == "SECURITY_CRITICAL"


# ---------------------------------------------------------------------------
# AuditLogWriter — volume sink
# ---------------------------------------------------------------------------

class TestAuditLogWriter:
    def _make_writer(self, tmp_path: Path) -> AuditLogWriter:
        config = AuditConfig(
            log_path=str(tmp_path / "audit.log"),
            max_file_size_mb=100,
            retention_days=90,
        )
        return AuditLogWriter(config=config)

    def test_write_creates_file(self, tmp_path):
        writer = self._make_writer(tmp_path)
        event = AdminLoginEvent(account_tier="admin", admin_account="admin1", outcome="success")
        writer.write(event)
        writer.close()
        log_file = tmp_path / "audit.log"
        assert log_file.exists()
        lines = log_file.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["event_type"] == "ADMIN_LOGIN"

    def test_write_thread_safe(self, tmp_path):
        writer = self._make_writer(tmp_path)
        errors = []

        def write_many():
            try:
                for _ in range(50):
                    event = AdminLoginEvent(
                        account_tier="admin",
                        admin_account="threaduser",
                        outcome="success",
                    )
                    writer.write(event)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=write_many) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        writer.close()
        assert not errors
        log_file = tmp_path / "audit.log"
        lines = log_file.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 250
        for line in lines:
            json.loads(line)  # each line must be valid JSON

    def test_log_rotation_triggers(self, tmp_path):
        config = AuditConfig(
            log_path=str(tmp_path / "audit.log"),
            max_file_size_mb=0,   # trigger rotation on every write
            retention_days=90,
        )
        writer = AuditLogWriter(config=config)
        for _ in range(3):
            writer.write(AdminLoginEvent(account_tier="admin", admin_account="a", outcome="success"))
        writer.close()
        rotated = list(tmp_path.glob("audit.log.*"))
        assert len(rotated) >= 1

    def test_siem_failure_does_not_block_volume_write(self, tmp_path):
        writer = self._make_writer(tmp_path)
        bad_target = SiemTarget(
            name="bad-siem",
            target_type="webhook",
            url="http://127.0.0.1:0/nonexistent",
            auth_header="Authorization",
            auth_value="Bearer fake",
            enabled=True,
        )
        writer.add_siem_target(bad_target)

        event = AdminLoginEvent(account_tier="admin", admin_account="admin1", outcome="success")
        writer.write(event)
        time.sleep(0.5)  # allow background SIEM thread to attempt
        writer.close()

        log_file = tmp_path / "audit.log"
        lines = log_file.read_text(encoding="utf-8").strip().splitlines()
        # At least the original event must be written even if SIEM fails
        records = [json.loads(l) for l in lines]
        event_types = {r["event_type"] for r in records}
        assert "ADMIN_LOGIN" in event_types


# ---------------------------------------------------------------------------
# AuditLogExporter — date range filtering
# ---------------------------------------------------------------------------

class TestAuditLogExporter:
    def _make_exporter(self, tmp_path: Path, records: list[dict]) -> AuditLogExporter:
        log_file = tmp_path / "audit.log"
        with open(log_file, "w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")
        config = AuditConfig(
            log_path=str(log_file),
            max_file_size_mb=100,
            retention_days=90,
        )
        return AuditLogExporter(config=config)

    def _collect(self, async_gen) -> list[bytes]:
        import asyncio
        async def _run():
            chunks = []
            async for chunk in async_gen:
                chunks.append(chunk)
            return chunks
        return asyncio.run(_run())

    def test_json_export_filters_by_date(self, tmp_path):
        records = [
            {"timestamp": "2026-01-01T00:00:00+00:00", "event_type": "A"},
            {"timestamp": "2026-03-15T12:00:00+00:00", "event_type": "B"},
            {"timestamp": "2026-06-01T00:00:00+00:00", "event_type": "C"},
        ]
        exporter = self._make_exporter(tmp_path, records)
        chunks = self._collect(exporter.export("2026-03-01", "2026-03-31", format="json"))
        result = b"".join(chunks).decode("utf-8").strip()
        parsed = [json.loads(l) for l in result.splitlines()]
        assert len(parsed) == 1
        assert parsed[0]["event_type"] == "B"

    def test_csv_export_has_header(self, tmp_path):
        records = [
            {"timestamp": "2026-03-15T00:00:00+00:00", "event_type": "X", "val": 1},
        ]
        exporter = self._make_exporter(tmp_path, records)
        chunks = self._collect(exporter.export("2026-03-01", "2026-03-31", format="csv"))
        text = b"".join(chunks).decode("utf-8")
        lines = text.strip().splitlines()
        assert "timestamp" in lines[0]
        assert "event_type" in lines[0]

    def test_invalid_format_raises(self, tmp_path):
        config = AuditConfig(log_path=str(tmp_path / "audit.log"), max_file_size_mb=100, retention_days=90)
        exporter = AuditLogExporter(config=config)
        import asyncio
        async def _run():
            async for _ in exporter.export("2026-01-01", "2026-12-31", format="xml"):
                pass
        with pytest.raises(ValueError):
            asyncio.run(_run())


# ---------------------------------------------------------------------------
# FINDING F-AUDIT — PostgresSink must NOT drop chat audit rows whose
# request_id is a non-UUID correlation id (e.g. Open WebUI "chatcmpl-...").
# owui-rbac-buildsheet §A2.
# ---------------------------------------------------------------------------

class TestFAuditCoerceUuid:
    """request_id="chatcmpl-..." must store request_id=NULL, not drop the row."""

    def test_coerce_uuid_non_uuid_is_none(self):
        import uuid as _uuid
        from yashigani.audit.sinks import _coerce_uuid

        # Non-UUID correlation ids (the bug input) coerce to None.
        assert _coerce_uuid("chatcmpl-abc123") is None
        assert _coerce_uuid("internal") is None
        assert _coerce_uuid("") is None
        assert _coerce_uuid(None) is None
        assert _coerce_uuid(12345) is None

        # A real UUID (str or UUID object) is preserved.
        u = _uuid.uuid4()
        assert _coerce_uuid(str(u)) == u
        assert _coerce_uuid(u) == u

    def test_flush_batch_chatcmpl_request_id_binds_null_not_drop(self):
        """Drain a chatcmpl event: must not raise and must bind request_id=NULL."""
        import asyncio
        import uuid as _uuid
        from unittest.mock import AsyncMock, MagicMock
        from yashigani.audit.sinks import PostgresSink

        captured: dict = {}

        # Fake asyncpg conn: capture the INSERT_AUDIT_EVENT bound params.
        conn = MagicMock()
        conn.execute = AsyncMock(return_value=None)  # set_config(...)

        async def _fetchrow(query, *args):
            # The INSERT is the fetchrow call (RETURNING seq); set_config uses execute.
            captured["args"] = args
            return {"seq": 1}

        conn.fetchrow = AsyncMock(side_effect=_fetchrow)

        # async context managers: pool.acquire() and conn.transaction()
        class _ACtx:
            def __init__(self, obj):
                self._obj = obj
            async def __aenter__(self):
                return self._obj
            async def __aexit__(self, *exc):
                return False

        pool = MagicMock()
        pool.acquire = MagicMock(return_value=_ACtx(conn))
        conn.transaction = MagicMock(return_value=_ACtx(None))

        # require_chain=False (legacy/test path) → no chain service needed.
        sink = PostgresSink(pool_getter=lambda: pool, chain_service=None)

        event = {
            "tenant_id": "internal",            # synthetic identity, non-UUID
            "event_type": "INFERENCE_PROXIED",
            "request_id": "chatcmpl-abc123",    # the bug input
            "session_id": "sess-1",
            "agent_id": "open-webui",
            "action": "ALLOW",
        }

        # Must NOT raise (previously: ValueError "badly formed hexadecimal UUID").
        asyncio.run(sink._flush_batch([event]))

        args = captured["args"]
        # INSERT_AUDIT_EVENT positional order:
        #   $1 tenant_id, $2 event_type, $3 request_id, ...
        tenant_arg, event_type_arg, request_id_arg = args[0], args[1], args[2]

        # request_id non-UUID → NULL (None), row still inserted.
        assert request_id_arg is None, (
            "chatcmpl request_id must bind as NULL, not drop the row"
        )
        # tenant_id non-UUID → all-zeros UUID (NOT NULL column preserved).
        assert tenant_arg == _uuid.UUID("00000000-0000-0000-0000-000000000000")
        assert isinstance(tenant_arg, _uuid.UUID)
        assert event_type_arg == "INFERENCE_PROXIED"

    def test_flush_batch_real_uuid_request_id_preserved(self):
        """A genuine UUID request_id is still bound as a UUID (no regression)."""
        import asyncio
        import uuid as _uuid
        from unittest.mock import AsyncMock, MagicMock
        from yashigani.audit.sinks import PostgresSink

        captured: dict = {}
        conn = MagicMock()
        conn.execute = AsyncMock(return_value=None)

        async def _fetchrow(query, *args):
            captured["args"] = args
            return {"seq": 1}

        conn.fetchrow = AsyncMock(side_effect=_fetchrow)

        class _ACtx:
            def __init__(self, obj):
                self._obj = obj
            async def __aenter__(self):
                return self._obj
            async def __aexit__(self, *exc):
                return False

        pool = MagicMock()
        pool.acquire = MagicMock(return_value=_ACtx(conn))
        conn.transaction = MagicMock(return_value=_ACtx(None))

        sink = PostgresSink(pool_getter=lambda: pool, chain_service=None)

        real_tenant = _uuid.uuid4()
        real_req = _uuid.uuid4()
        event = {
            "tenant_id": str(real_tenant),
            "event_type": "ADMIN_LOGIN",
            "request_id": str(real_req),
            "action": "ALLOW",
        }
        asyncio.run(sink._flush_batch([event]))

        args = captured["args"]
        assert args[0] == real_tenant
        assert args[2] == real_req
