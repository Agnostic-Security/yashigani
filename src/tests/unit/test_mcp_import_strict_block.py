"""
5.0 tool-poisoning block-half — strict-mode MCP import gate (register §4 #1).

The default (DP-Y-003 §3.4) is flag-not-block. Strict mode
(YASHIGANI_MCP_IMPORT_STRICT=true) turns the day-one-poison screen into a hard
gate: a suspicious surface (or a scan that could not run) is REJECTED
fail-closed. These tests exercise the strict-mode helper and the verdict-shaped
block decision without spinning up the full async import handler.
"""
from __future__ import annotations

import os
from unittest.mock import patch

import pytest


class TestStrictModeFlag:
    def test_default_off(self):
        from yashigani.backoffice.routes.mcp_servers import _mcp_import_strict_enabled
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("YASHIGANI_MCP_IMPORT_STRICT", None)
            assert _mcp_import_strict_enabled() is False

    @pytest.mark.parametrize("val", ["true", "1", "yes", "on", "TRUE", "On"])
    def test_enabled_values(self, val):
        from yashigani.backoffice.routes.mcp_servers import _mcp_import_strict_enabled
        with patch.dict(os.environ, {"YASHIGANI_MCP_IMPORT_STRICT": val}):
            assert _mcp_import_strict_enabled() is True

    @pytest.mark.parametrize("val", ["false", "0", "no", "off", ""])
    def test_disabled_values(self, val):
        from yashigani.backoffice.routes.mcp_servers import _mcp_import_strict_enabled
        with patch.dict(os.environ, {"YASHIGANI_MCP_IMPORT_STRICT": val}):
            assert _mcp_import_strict_enabled() is False


def _strict_block_reason(verdict: dict) -> str | None:
    """Mirror of the handler's strict decision (kept in lockstep with the
    inline logic in import_mcp_server)."""
    if verdict.get("suspicious_content_flagged"):
        return "suspicious_content"
    if verdict.get("classifier_status") == "unavailable_error":
        return "poison_scan_unavailable"
    return None


class TestStrictBlockDecision:
    def test_clean_surface_not_blocked(self):
        verdict = {"suspicious_content_flagged": False, "classifier_status": "ran"}
        assert _strict_block_reason(verdict) is None

    def test_suspicious_surface_blocked(self):
        verdict = {"suspicious_content_flagged": True, "classifier_status": "ran",
                   "rejected_tools": ["evil_tool"]}
        assert _strict_block_reason(verdict) == "suspicious_content"

    def test_scan_unavailable_blocked(self):
        verdict = {"suspicious_content_flagged": False,
                   "classifier_status": "unavailable_error"}
        assert _strict_block_reason(verdict) == "poison_scan_unavailable"

    def test_not_configured_not_blocked(self):
        # not_configured is a documented safe-degrade (heuristic-only), NOT a
        # scan failure — strict mode blocks only on an active screen failure.
        verdict = {"suspicious_content_flagged": False,
                   "classifier_status": "not_configured"}
        assert _strict_block_reason(verdict) is None


class TestBlockAuditEvent:
    def test_event_captures_flagged_tools(self):
        from yashigani.audit.schema import McpImportBlockedEvent
        e = McpImportBlockedEvent(
            server_id="poisoned-srv",
            reason="suspicious_content",
            rejected_tools=["a", "b"],
            sidecar_escalations=["a"],
        )
        assert e.event_type.value == "MCP_IMPORT_BLOCKED"
        assert e.rejected_tools == ["a", "b"]
        assert e.action_taken == "blocked"
