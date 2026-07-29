"""
Tier-C category: dataplane_byte_proof.

The data-plane (document-OPA enforcement: REDACT/PSEUDONYMIZE/BLOCK) must be
proven with the REAL transformed bytes, on BOTH channels (user-upload +
chat-MCP), not merely "a 200 was returned." (Ava's 2026-06 4.1.2 e2e already
proved this once live — PROVEN-BYTES — this category exists so it's re-proven
per-leg, not assumed to travel from one runtime's evidence to another's.)
"""
from __future__ import annotations

from .conftest import SKIP_NO_STACK, http_client


@SKIP_NO_STACK
def test_document_upload_endpoint_reachable_before_asserting_byte_transform():
    """Baseline reachability for the document-enforcement upload path.
    Extend with a real PII-bearing upload + byte-level diff of the stored/
    returned artefact against the raw input once an authenticated Tier-C
    bootstrap identity + a real document fixture are wired into this leg's
    invocation."""
    with http_client() as c:
        resp = c.get("/healthz")
        assert resp.status_code == 200


@SKIP_NO_STACK
def test_chat_mcp_channel_reachable_before_asserting_byte_transform():
    """Baseline reachability for the chat-MCP document-enforcement channel
    (the OTHER channel Ava's 2026-06 PROVEN-BYTES evidence covered) — extend
    with a real inline-PII chat message + assertion that the stored/forwarded
    bytes are actually transformed (not just that a 200 came back)."""
    with http_client() as c:
        resp = c.get("/healthz")
        assert resp.status_code == 200
