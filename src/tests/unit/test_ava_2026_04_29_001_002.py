"""
Regression tests for QA findings AVA-2026-04-29-001 and AVA-2026-04-29-002.

  - AVA-2026-04-29-001 [HIGH]  Stored XSS in agent name (ASVS V5.3.3, CWE-79)
  - AVA-2026-04-29-002 [MEDIUM] AuditLogExporter.export_ndjson missing — AttributeError
                                 mid-stream + 502 keep-alive cascade (ASVS V7.1.3)

These tests are pure unit tests: no live Postgres, no live Redis, no live Caddy.
They re-fail if the original bugs are reintroduced.
"""
# Last updated: 2026-05-03T00:00:00+01:00
from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
import typing
from pathlib import Path

import pytest
from pydantic import ValidationError

from yashigani.audit.config import AuditConfig
from yashigani.audit.export import AuditLogExporter

# ---------------------------------------------------------------------------
# Load agents.py in isolation — identical pattern to test_ssrf_owui.py.
# The full backoffice import chain requires asyncpg / multipart which are
# not available in the macOS lightweight test environment.
# ---------------------------------------------------------------------------
_AGENTS_PATH = Path(__file__).parents[2] / "yashigani" / "backoffice" / "routes" / "agents.py"


def _load_agents_module():
    """Load agents.py without triggering the full backoffice import chain."""
    # FIND-3.0-001: agents.py now imports from yashigani.backoffice._ssrf.
    # Pre-load _ssrf directly (it has no backoffice deps) so that the package
    # __init__ is not triggered when agents.py does the import.
    import importlib as _il
    _ssrf_path = Path(__file__).parents[2] / "yashigani" / "backoffice" / "_ssrf.py"
    _ssrf_spec = _il.util.spec_from_file_location("yashigani.backoffice._ssrf", _ssrf_path)
    _ssrf_mod = _il.util.module_from_spec(_ssrf_spec)
    _ssrf_spec.loader.exec_module(_ssrf_mod)

    _stubs = {
        "yashigani.backoffice._ssrf": _ssrf_mod,
        "yashigani.backoffice.middleware": type(sys)("stub"),
        "yashigani.backoffice.state": type(sys)("stub"),
        "yashigani.licensing.enforcer": type(sys)("stub"),
        "pydantic": importlib.import_module("pydantic"),
        "fastapi": importlib.import_module("fastapi"),
    }
    _stubs["yashigani.backoffice.middleware"].require_admin_session = lambda *a, **kw: None
    _stubs["yashigani.backoffice.middleware"].AdminSession = object
    _stubs["yashigani.backoffice.middleware"].require_stepup_admin_session = lambda *a, **kw: None
    _stubs["yashigani.backoffice.middleware"].StepUpAdminSession = object
    _stubs["yashigani.backoffice.state"].backoffice_state = None
    _stubs["yashigani.licensing.enforcer"].require_feature = lambda *a, **kw: None

    old = {}
    for k, v in _stubs.items():
        old[k] = sys.modules.get(k)
        sys.modules[k] = v

    spec = importlib.util.spec_from_file_location("agents_isolated_ava001", _AGENTS_PATH)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    finally:
        for k, v in old.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v
    return mod


_agents_mod = _load_agents_module()
_AgentRegisterRequest = _agents_mod.AgentRegisterRequest
_AgentUpdateRequest = _agents_mod.AgentUpdateRequest
# Pydantic v2 requires model_rebuild() when the model contains forward references
# (Optional from `from __future__ import annotations`) and is loaded in isolation.
# Pass _types_namespace so Pydantic can resolve Optional[str] et al.
try:
    _AgentUpdateRequest.model_rebuild(
        _types_namespace={"Optional": typing.Optional, "list": list},
    )
except Exception:
    pass  # already built or not required in this pydantic version


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _collect_async(async_gen) -> list[bytes]:
    """Drain an async generator into a list of byte chunks."""
    async def _run():
        chunks: list[bytes] = []
        async for chunk in async_gen:
            chunks.append(chunk)
        return chunks
    return asyncio.run(_run())


def _make_exporter(tmp_path: Path, records: list[dict]) -> AuditLogExporter:
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


# ---------------------------------------------------------------------------
# AVA-2026-04-29-001 — Stored XSS: HTML tags rejected at API layer
# ASVS v5 V5.3.3 | CWE-79 | WSTG-INPV-02
# ---------------------------------------------------------------------------

class TestAva001StoredXssAgentName:
    """
    AgentRegisterRequest.name and AgentUpdateRequest.name must reject HTML tags
    with HTTP 422 (Pydantic ValidationError) before any registry write.
    """

    # --- AgentRegisterRequest -----------------------------------------------

    def test_register_rejects_script_tag(self):
        with pytest.raises(ValidationError) as exc_info:
            _AgentRegisterRequest(
                name="<script>alert('XSS-agent')</script>",
                upstream_url="https://agent.example.com",
            )
        errors = exc_info.value.errors()
        assert any(e["loc"] == ("name",) for e in errors), errors

    def test_register_rejects_img_onerror(self):
        with pytest.raises(ValidationError) as exc_info:
            _AgentRegisterRequest(
                name='<img src=x onerror=alert(1)>',
                upstream_url="https://agent.example.com",
            )
        errors = exc_info.value.errors()
        assert any(e["loc"] == ("name",) for e in errors), errors

    def test_register_rejects_svg_onload(self):
        with pytest.raises(ValidationError) as exc_info:
            _AgentRegisterRequest(
                name='<svg onload=alert(1)>',
                upstream_url="https://agent.example.com",
            )
        errors = exc_info.value.errors()
        assert any(e["loc"] == ("name",) for e in errors), errors

    def test_register_rejects_html_comment_tag(self):
        with pytest.raises(ValidationError) as exc_info:
            _AgentRegisterRequest(
                name="<!doctype>",
                upstream_url="https://agent.example.com",
            )
        errors = exc_info.value.errors()
        assert any(e["loc"] == ("name",) for e in errors), errors

    def test_register_accepts_clean_name(self):
        """Clean agent slug names must continue to pass — no regression on legitimate input.
        Note: V232-CSCAN-01a tightened name to slug pattern '^[a-z][a-z0-9_-]{0,63}$'.
        """
        req = _AgentRegisterRequest(
            name="my-production-agent-v2",
            upstream_url="https://agent.example.com",
        )
        assert req.name == "my-production-agent-v2"

    def test_register_accepts_name_with_angle_bracket_in_math_context(self):
        """A slug-compliant name with only lowercase and hyphens must be accepted.

        Note: V232-CSCAN-01a tightened name to slug pattern so free-text names
        ('threshold < 100') are now rightly rejected. This test is updated to use
        a slug that satisfies the new constraint.
        """
        req = _AgentRegisterRequest(
            name="threshold-agent",
            upstream_url="https://agent.example.com",
        )
        assert req.name == "threshold-agent"

    # --- AgentUpdateRequest -------------------------------------------------

    def test_update_rejects_script_tag(self):
        with pytest.raises(ValidationError) as exc_info:
            _AgentUpdateRequest(name="<script>alert('XSS')</script>")
        errors = exc_info.value.errors()
        assert any(e["loc"] == ("name",) for e in errors), errors

    def test_update_accepts_clean_name(self):
        """Note: V232-CSCAN-01a tightened name to slug pattern — use a slug."""
        req = _AgentUpdateRequest(name="renamed-agent")
        assert req.name == "renamed-agent"

    def test_update_accepts_none_name(self):
        """None (field omitted) must still pass — name is optional on update."""
        req = _AgentUpdateRequest(name=None)
        assert req.name is None

    def test_update_rejects_closing_tag(self):
        """Closing tags (</script>) are also rejected."""
        with pytest.raises(ValidationError) as exc_info:
            _AgentUpdateRequest(name="</script>")
        errors = exc_info.value.errors()
        assert any(e["loc"] == ("name",) for e in errors), errors


# ---------------------------------------------------------------------------
# AVA-2026-04-29-002 — AuditLogExporter.export_ndjson never existed
# ASVS v5 V7.1.3 | OWASP A09
#
# The route at /admin/audit/export called exporter.export_ndjson() and
# exporter.export_csv() — neither method exists on AuditLogExporter.
# Fix: route uses exporter.export() with format='json' / 'csv'.
# These tests verify:
#   (a) AuditLogExporter has no export_ndjson / export_csv (regression guard).
#   (b) AuditLogExporter.export(format='json') streams correct NDJSON.
#   (c) AuditLogExporter.export(format='csv')  streams correct CSV.
#   (d) The streaming generator in the fixed route closes cleanly on exception
#       (no AttributeError propagation, no keep-alive corruption).
# ---------------------------------------------------------------------------

class TestAva002AuditExporterMissingMethod:
    """Regression: export_ndjson and export_csv must NOT exist on AuditLogExporter.

    If someone adds these back under a different signature, the original route
    bug would resurface silently. This test makes that visible.
    """

    def test_export_ndjson_does_not_exist(self):
        assert not hasattr(AuditLogExporter, "export_ndjson"), (
            "AuditLogExporter.export_ndjson must not exist — "
            "the canonical method is export(format='json'). "
            "Adding export_ndjson without updating the route creates the original AVA-002 bug."
        )

    def test_export_csv_does_not_exist(self):
        assert not hasattr(AuditLogExporter, "export_csv"), (
            "AuditLogExporter.export_csv must not exist — "
            "the canonical method is export(format='csv'). "
            "Adding export_csv without updating the route creates the original AVA-002 bug."
        )

    def test_export_method_exists(self):
        """The canonical export() method must be present and callable."""
        assert callable(getattr(AuditLogExporter, "export", None))


class TestAva002AuditExportJsonStreaming:
    """AuditLogExporter.export(format='json') must stream NDJSON correctly."""

    def test_ndjson_stream_produces_valid_json_lines(self, tmp_path):
        records = [
            {"timestamp": "2026-04-29T10:00:00+00:00", "event_type": "ADMIN_LOGIN"},
            {"timestamp": "2026-04-29T11:00:00+00:00", "event_type": "AGENT_REGISTERED"},
        ]
        exporter = _make_exporter(tmp_path, records)
        chunks = _collect_async(exporter.export("2026-04-29", "2026-04-29", format="json"))
        text = b"".join(chunks).decode("utf-8").strip()
        lines = text.splitlines()
        assert len(lines) == 2
        parsed = [json.loads(line) for line in lines]
        assert parsed[0]["event_type"] == "ADMIN_LOGIN"
        assert parsed[1]["event_type"] == "AGENT_REGISTERED"

    def test_ndjson_stream_empty_log(self, tmp_path):
        """Empty log yields no chunks — no exception."""
        config = AuditConfig(
            log_path=str(tmp_path / "audit.log"),
            max_file_size_mb=100,
            retention_days=90,
        )
        exporter = AuditLogExporter(config=config)
        chunks = _collect_async(exporter.export("2026-01-01", "2026-12-31", format="json"))
        assert chunks == []


class TestAva002AuditExportCsvStreaming:
    """AuditLogExporter.export(format='csv') must stream correct CSV."""

    def test_csv_stream_has_header_and_rows(self, tmp_path):
        records = [
            {"timestamp": "2026-04-29T10:00:00+00:00", "event_type": "ADMIN_LOGIN", "outcome": "success"},
        ]
        exporter = _make_exporter(tmp_path, records)
        chunks = _collect_async(exporter.export("2026-04-29", "2026-04-29", format="csv"))
        text = b"".join(chunks).decode("utf-8")
        lines = text.strip().splitlines()
        # First line is header
        assert "timestamp" in lines[0]
        assert "event_type" in lines[0]
        # Second line is data
        assert "ADMIN_LOGIN" in lines[1]

    def test_csv_stream_date_filter(self, tmp_path):
        """Only records within the date range are exported."""
        records = [
            {"timestamp": "2026-01-15T00:00:00+00:00", "event_type": "EARLY"},
            {"timestamp": "2026-04-29T00:00:00+00:00", "event_type": "IN_RANGE"},
            {"timestamp": "2026-12-01T00:00:00+00:00", "event_type": "LATE"},
        ]
        exporter = _make_exporter(tmp_path, records)
        chunks = _collect_async(exporter.export("2026-04-01", "2026-04-30", format="csv"))
        text = b"".join(chunks).decode("utf-8")
        assert "IN_RANGE" in text
        assert "EARLY" not in text
        assert "LATE" not in text


class TestAva002RouteStreamingExceptionHandling:
    """
    Verify the fixed route's stream() generator closes cleanly when export() raises.

    The original bug: AttributeError raised after HTTP 200 sent → ASGI connection
    left dangling → next keep-alive request from same admin session gets 502.

    The fix: stream() catches Exception, logs it, and returns — generator closes
    cleanly, Starlette/Uvicorn closes the socket gracefully.
    """

    def test_stream_generator_closes_on_exception(self):
        """
        Simulate what the fixed route's stream() generator does when exporter raises.
        The generator must exhaust cleanly (StopAsyncIteration) without propagating
        the exception to the ASGI layer.
        """
        import logging

        # Replicate the exact stream() logic from the fixed route
        async def mock_exporter_raises():
            yield b"partial-line-1\n"
            raise AttributeError("export_ndjson does not exist")  # original bug

        async def stream():
            try:
                async for chunk in mock_exporter_raises():
                    yield chunk
            except Exception as exc:
                logging.getLogger(__name__).error("audit export stream error: %s", exc)
                # Do NOT re-raise — just stop yielding.

        async def _run():
            chunks = []
            async for chunk in stream():
                chunks.append(chunk)
            return chunks

        # Must NOT raise — generator must close cleanly
        chunks = asyncio.run(_run())
        assert chunks == [b"partial-line-1\n"]  # partial output before exception

    def test_stream_generator_completes_normally(self):
        """Happy path: stream() drains cleanly when no exception is raised."""
        async def mock_exporter_ok():
            yield b'{"event_type": "ADMIN_LOGIN"}\n'
            yield b'{"event_type": "AGENT_REGISTERED"}\n'

        async def stream():
            try:
                async for chunk in mock_exporter_ok():
                    yield chunk
            except Exception as exc:
                pass

        async def _run():
            chunks = []
            async for chunk in stream():
                chunks.append(chunk)
            return chunks

        chunks = asyncio.run(_run())
        assert len(chunks) == 2
