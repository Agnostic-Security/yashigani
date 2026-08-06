"""
Regression tests — YSG-RISK-146 (MED): MCP bridge/router crash on malformed
body -> unhandled 500 instead of 400.

ROOT CAUSE (both gateway/mcp_router_runtime.py and mcp/_bridge.py, pre-fix):

    try:
        body_str = body_bytes.decode("utf-8")
        msg = json.loads(body_str)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return 400  # only guards syntactically-invalid JSON

    method = msg.get("method", "")   # mcp_router_runtime.py
    ...
    is_notification = "id" not in msg   # _bridge.py

A JSON-RPC message MUST be a JSON *object*. A body that is syntactically
VALID JSON but NOT an object — e.g. ``42``, ``null``, ``true``, ``"x"``,
``[1,2,3]`` — parses successfully via json.loads() (so the existing
except clause never fires) and then crashes on the very next line:

  - mcp_router_runtime.py: ``msg.get("method", "")`` -> AttributeError
    (list/int/float/bool/str/None have no ``.get``).
  - _bridge.py: ``"id" not in msg`` -> TypeError for scalars/None (not
    iterable / no ``__contains__``); for a list, execution continues to
    ``msg.get("id")`` inside an except-handler branch -> AttributeError.

Both are unhandled exceptions that surface as an ASGI 500, not the 400 an
attacker-controlled malformed body should get.

FIX: after json.loads() succeeds, explicitly require ``isinstance(msg, dict)``
and return 400 (INVALID_JSON_RPC_MESSAGE / invalid_json_rpc_message) before
any attribute access on msg.

Cross-ref: docs/risk-register.yml YSG-RISK-146.
"""
from __future__ import annotations

import sys

from fastapi import FastAPI
from fastapi.testclient import TestClient

# Top-level JSON values that are syntactically valid JSON but NOT objects.
_MALFORMED_NON_OBJECT_BODIES = [
    b"42",
    b"3.14",
    b"true",
    b"false",
    b"null",
    b'"just a string"',
    b"[1, 2, 3]",
    b'[{"id": 1, "method": "tools/call"}]',
]


class TestMcpRouterRuntimeMalformedBody:
    """gateway/mcp_router_runtime.py — POST /mcp/{agent_name}."""

    def _make_app(self):
        from yashigani.gateway.mcp_router_runtime import create_mcp_call_router
        from yashigani.mcp.registry import McpBrokerRegistry, McpBrokerServerConfig

        reg = McpBrokerRegistry()
        reg.register("test-agent", object(), McpBrokerServerConfig(
            upstream_url="http://test:8000",
            is_filesystem_agent=False,
            tenant_id="test",
            agent_name="test-agent",
        ))
        app = FastAPI()
        app.include_router(create_mcp_call_router(reg))
        return TestClient(app)

    def test_valid_syntax_non_object_bodies_return_400_not_500(self):
        client = self._make_app()
        for body in _MALFORMED_NON_OBJECT_BODIES:
            resp = client.post("/mcp/test-agent", content=body)
            assert resp.status_code == 400, (
                f"YSG-RISK-146 REGRESSION: body={body!r} produced "
                f"status={resp.status_code} (expected 400). "
                f"Response: {resp.text!r}"
            )
            assert resp.json()["error"] == "INVALID_JSON_RPC_MESSAGE"

    def test_syntactically_invalid_json_still_returns_400(self):
        """Negative control — the pre-existing JSONDecodeError path must
        keep working unchanged.
        """
        client = self._make_app()
        resp = client.post("/mcp/test-agent", content=b"{not json")
        assert resp.status_code == 400
        assert resp.json()["error"] == "INVALID_JSON"

    def test_valid_object_body_unaffected(self):
        """A well-formed JSON-RPC object must NOT be rejected by the new
        dict-type gate (it should proceed past it to normal handling).
        """
        client = self._make_app()
        resp = client.post(
            "/mcp/test-agent",
            content=b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}',
        )
        # Whatever the eventual disposition (broker/registry not fully wired
        # in this minimal harness), it must NOT be rejected as malformed —
        # i.e. must not be 400 with INVALID_JSON_RPC_MESSAGE / INVALID_JSON.
        assert resp.status_code != 400 or resp.json().get("error") not in (
            "INVALID_JSON_RPC_MESSAGE", "INVALID_JSON",
        )


class TestMcpBridgeMalformedBody:
    """mcp/_bridge.py — POST /mcp (per-server bridge subprocess-facing HTTP)."""

    def _make_app(self):
        from yashigani.mcp._bridge import create_bridge_app
        return create_bridge_app(
            command=[sys.executable, "-c", "import sys\nfor line in sys.stdin:\n    pass\n"]
        )

    def test_valid_syntax_non_object_bodies_return_400_not_500(self):
        client = TestClient(self._make_app())
        for body in _MALFORMED_NON_OBJECT_BODIES:
            resp = client.post("/mcp", content=body)
            assert resp.status_code == 400, (
                f"YSG-RISK-146 REGRESSION: body={body!r} produced "
                f"status={resp.status_code} (expected 400). "
                f"Response: {resp.text!r}"
            )
            assert resp.json()["error"] == "invalid_json_rpc_message"

    def test_syntactically_invalid_json_still_returns_400(self):
        client = TestClient(self._make_app())
        resp = client.post("/mcp", content=b"{not json")
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_json"

    def test_empty_body_still_returns_400(self):
        """Pre-existing empty-body guard must keep working unchanged."""
        client = TestClient(self._make_app())
        resp = client.post("/mcp", content=b"")
        assert resp.status_code == 400
        assert resp.json()["error"] == "empty_body"
