"""
5.0 A2 — server-initiated MCP primitive gating: adversarial suite.

Register acceptance gate: "id-collision + unsolicited sampling/elicitation/roots
all rejected + audited." Drives _BridgeProcess._reader_loop with a scripted
fake stdout so no real subprocess is needed, and captures deny audit events via
the audit_hook.
"""
from __future__ import annotations

import asyncio
import json

import pytest

from yashigani.mcp import _frame_shape
from yashigani.mcp._bridge import _BridgeProcess


class _FakeStdout:
    """Async readline() that yields scripted byte lines then EOF (b"")."""

    def __init__(self, lines):
        self._lines = list(lines)

    async def readline(self):
        if self._lines:
            return self._lines.pop(0)
        return b""  # EOF → reader loop exits


class _FakeProc:
    def __init__(self, stdout):
        self.stdout = stdout
        self.returncode = None


async def _run_reader(frames, pending_ids=()):
    """Feed `frames` (list of dicts) through the reader loop; return audits +
    the futures map for the given pending ids."""
    audits = []
    bridge = _BridgeProcess(command=["true"], audit_hook=audits.append)

    loop = asyncio.get_running_loop()
    futs = {}
    for pid in pending_ids:
        f = loop.create_future()
        bridge._pending[str(pid)] = f
        futs[str(pid)] = f

    lines = [(json.dumps(fr) + "\n").encode() for fr in frames]
    bridge._proc = _FakeProc(_FakeStdout(lines))
    await bridge._reader_loop()
    return audits, futs


@pytest.mark.asyncio
class TestReversePrimitivesRejectedAndAudited:
    async def test_unsolicited_sampling_denied_and_audited(self):
        frame = {"jsonrpc": "2.0", "id": "s1", "method": "sampling/createMessage",
                 "params": {"messages": []}}
        audits, _ = await _run_reader([frame])
        assert len(audits) == 1
        assert audits[0]["event_type"] == "MCP_SERVER_PRIMITIVE_DENIED"
        assert audits[0]["reason"] == "reverse_primitive"
        assert audits[0]["method"] == "sampling/createMessage"

    async def test_unsolicited_elicitation_denied(self):
        frame = {"jsonrpc": "2.0", "id": "e1", "method": "elicitation/create"}
        audits, _ = await _run_reader([frame])
        assert audits and audits[0]["method"] == "elicitation/create"
        assert audits[0]["reason"] == "reverse_primitive"

    async def test_unsolicited_roots_denied(self):
        frame = {"jsonrpc": "2.0", "id": "r1", "method": "roots/list"}
        audits, _ = await _run_reader([frame])
        assert audits and audits[0]["method"] == "roots/list"

    async def test_every_reverse_method_is_covered(self):
        # Guard against the allowlist and the enforcement drifting apart.
        frames = [{"jsonrpc": "2.0", "id": f"x{i}", "method": m}
                  for i, m in enumerate(sorted(_frame_shape.REVERSE_PRIMITIVE_METHODS))]
        audits, _ = await _run_reader(frames)
        denied_methods = {a["method"] for a in audits}
        assert denied_methods == set(_frame_shape.REVERSE_PRIMITIVE_METHODS)


@pytest.mark.asyncio
class TestIdHijackRejectedAndAudited:
    async def test_reverse_primitive_reusing_pending_id_is_denied(self):
        # Server tries to answer pending call "call-1" with a sampling request
        frame = {"jsonrpc": "2.0", "id": "call-1", "method": "sampling/createMessage"}
        audits, futs = await _run_reader([frame], pending_ids=["call-1"])

        assert len(audits) == 1
        assert audits[0]["reason"] == "id_hijack"
        assert audits[0]["frame_id"] == "call-1"

        # The pending call was resolved with a clean deny error, NOT attacker content
        result = json.loads(futs["call-1"].result())
        assert result["error"]["code"] == -32600
        assert "default-deny" in result["error"]["message"]

    async def test_genuine_response_is_delivered_not_denied(self):
        # A legitimate result frame for a pending id must pass through untouched
        frame = {"jsonrpc": "2.0", "id": "call-2",
                 "result": {"content": [{"type": "text", "text": "ok"}]}}
        audits, futs = await _run_reader([frame], pending_ids=["call-2"])

        assert audits == [], "a genuine response must not be audited as a deny"
        delivered = json.loads(futs["call-2"].result())
        assert delivered["result"]["content"][0]["text"] == "ok"


@pytest.mark.asyncio
class TestMalformedFrames:
    async def test_malformed_frame_is_denied_and_audited(self):
        # Neither a valid response (no result/error) nor a known reverse method
        frame = {"jsonrpc": "2.0", "id": "m1", "method": "totally/unknown"}
        audits, _ = await _run_reader([frame])
        assert audits and audits[0]["reason"] == "malformed_frame"

    async def test_frame_with_both_method_and_result_is_malformed(self):
        frame = {"jsonrpc": "2.0", "id": "m2", "method": "tools/call", "result": {}}
        audits, _ = await _run_reader([frame])
        assert audits and audits[0]["reason"] == "malformed_frame"
