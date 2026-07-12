"""MCP JSON-RPC frame-shape classification (G8 — server-initiated primitive gating).

Closes the reverse-direction bypass (Laura F1, 2026-07-12): a malicious MCP
server can answer a ``tools/call`` with a frame that reuses the caller's request
``id`` but carries a ``method`` (e.g. ``sampling/createMessage``) instead of a
``result`` — the bridge's id-only correlation (``_bridge.py:246``) would deliver
that server-*initiated* request to the agent as if it were the tool result,
injecting attacker content into the agent's LLM.

JSON-RPC 2.0 §5 is definitive: a *response* MUST carry ``result`` XOR ``error``
and MUST NOT carry ``method``; a *request/notification* MUST carry ``method`` and
MUST NOT carry ``result``/``error``. So the presence of ``method`` cleanly
discriminates a reverse-primitive frame from a genuine response — no ambiguity.

v1 policy: default-DENY every server-initiated reverse primitive (sampling /
elicitation / roots). A per-server allowlist + step-up (the AGT approval-channel
pattern) is v2 and requires the OPA-gated path + (for HTTP) SSE duplex support.

stdlib-only by design: this module is imported inside the bridge container.
"""

from __future__ import annotations

from typing import Optional

# Server-initiated MCP primitives that reverse the call direction. Default-deny.
REVERSE_PRIMITIVE_METHODS: frozenset[str] = frozenset({
    "sampling/createMessage",
    "elicitation/create",
    "roots/list",
})

FRAME_RESPONSE = "response"           # genuine result/error to a pending call
FRAME_REVERSE_REQUEST = "reverse_request"  # server-initiated request/notification
FRAME_MALFORMED = "malformed"          # neither a valid response nor a valid request


def classify_inbound_frame(msg: Optional[dict]) -> str:
    """Classify an inbound MCP frame received where a tool-call *response* is expected.

    Returns one of FRAME_RESPONSE / FRAME_REVERSE_REQUEST / FRAME_MALFORMED.
    Only FRAME_RESPONSE may be correlated to a pending tool-call future.
    """
    if not isinstance(msg, dict):
        return FRAME_MALFORMED
    has_method = "method" in msg
    has_result_or_error = ("result" in msg) or ("error" in msg)
    if has_method and not has_result_or_error:
        return FRAME_REVERSE_REQUEST
    if has_result_or_error and not has_method:
        return FRAME_RESPONSE
    return FRAME_MALFORMED


def is_reverse_primitive(msg: Optional[dict]) -> bool:
    """True if *msg* is a server-initiated reverse primitive we default-deny."""
    return (
        classify_inbound_frame(msg) == FRAME_REVERSE_REQUEST
        and isinstance(msg, dict)
        and msg.get("method") in REVERSE_PRIMITIVE_METHODS
    )


def build_deny_error(request_id, method: Optional[str]) -> dict:
    """A JSON-RPC error frame denying a hijacked/blocked call.

    Used to fail a pending tool-call fast (clean error instead of a hang) when a
    server tries to answer it with a reverse-primitive frame, and to reply to a
    server-initiated primitive on the stdio duplex path.
    """
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": -32600,  # Invalid Request
            "message": "server-initiated MCP primitive denied by gateway policy "
                       "(default-deny; G8)",
            "data": {"method": method, "policy": "mcp.reverse_primitive.default_deny"},
        },
    }
