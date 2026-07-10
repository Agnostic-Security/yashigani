"""
Tests for G-ORCH-OPA-1 / Option A: caller sensitivity ceiling populated from
identity registry before enforce_result() (mcp_router_runtime.py).

Covers:
  (a) A caller with CONFIDENTIAL ceiling gets a CONFIDENTIAL result allowed.
  (b) The same caller is denied a RESTRICTED result (ceiling < result).
  (c) No identity registry / unknown user → ceiling stays None → fail-closed deny.
  (d) Registry lookup raises → ceiling stays None → fail-closed deny.
  (e) Registry returns identity as IdentityRecord dataclass → ceiling extracted.
  (f) Registry returns identity as dict → ceiling extracted.
  (g) proxy.py passes openai_router._state.identity_registry to dispatch_mcp_call.

v3.1 / G-ORCH-OPA-1 egress ceiling fix.
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Helpers shared across tests
# ---------------------------------------------------------------------------

def _make_jsonrpc_request(method: str, params=None, req_id="1") -> str:
    msg = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        msg["params"] = params
    return json.dumps(msg)


def _make_broker_with_egress(egress_allow: bool, egress_deny_reason: str = "ok"):
    """Build a mock McpBroker where ingress always allows and egress is configurable."""
    from yashigani.mcp._types import BrokerDecision, EgressDecision, OpaDecision

    broker = MagicMock()
    opa_dec = OpaDecision(
        allow=True,
        deny_reason="ok",
        redact_args=set(),
        audit_capture=False,
        rate_limit_key=None,
    )
    ingress_decision = BrokerDecision(
        call_id="test-call-id",
        allow=True,
        deny_reason="ok",
        opa_decision=opa_dec,
        issued_jwt="test-jwt",
    )
    broker.enforce = AsyncMock(return_value=ingress_decision)
    broker.enforce_result = AsyncMock(return_value=EgressDecision(
        allow=egress_allow,
        deny_reason=egress_deny_reason if not egress_allow else "ok",
        policy_id="mcp.response_decision",
        code="MCP_RESULT_OK" if egress_allow else "MCP_RESULT_SENSITIVITY_EXCEEDED",
        user_message=(
            "Tool result approved for delivery."
            if egress_allow
            else "The tool result was blocked by the security policy."
        ),
        elapsed_ms=1,
    ))
    broker._issuer = MagicMock()
    broker._issuer.issue = MagicMock(return_value="session-jwt-value")
    return broker


def _make_registry_with_egress(
    agent_name: str = "filesystem-mcp",
    egress_allow: bool = True,
    egress_deny_reason: str = "ok",
):
    from yashigani.mcp.registry import McpBrokerRegistry, McpBrokerServerConfig

    reg = McpBrokerRegistry()
    broker = _make_broker_with_egress(egress_allow=egress_allow, egress_deny_reason=egress_deny_reason)
    cfg = McpBrokerServerConfig(
        upstream_url="http://fs-mcp:8000",
        is_filesystem_agent=True,
        tenant_id="acme",
        agent_name=agent_name,
    )
    reg.register(agent_name, broker, cfg)
    return reg, broker


def _fake_upstream_response(tool_result: str = "file content") -> str:
    return json.dumps({
        "jsonrpc": "2.0",
        "id": "t1",
        "result": {"content": [{"type": "text", "text": tool_result}]},
    })


def _patch_transport_forward(fake_response: str):
    """Context manager: patch McpHttpTransport.forward to return fake_response."""
    from yashigani.mcp._transport_http import McpHttpTransport as RealTransport

    async def fake_aenter(self):
        self.forward = AsyncMock(return_value=fake_response)
        return self

    async def fake_aexit(self, *a):
        pass

    return (
        patch.object(RealTransport, "__aenter__", fake_aenter),
        patch.object(RealTransport, "__aexit__", fake_aexit),
    )


def _make_identity_registry_mock(
    slug: str = "alice",
    sensitivity_ceiling: str = "CONFIDENTIAL",
    return_as_dict: bool = True,
):
    """Build a mock IdentityRegistry that returns an identity for `slug`."""
    registry = MagicMock()
    if return_as_dict:
        identity = {
            "identity_id": "idnt_abc123",
            "slug": slug,
            "sensitivity_ceiling": sensitivity_ceiling,
            "status": "active",
            "kind": "human",
        }
    else:
        # Return a dataclass-like object with sensitivity_ceiling attribute.
        identity = MagicMock()
        identity.sensitivity_ceiling = sensitivity_ceiling
        identity.slug = slug

    def get_by_slug(s):
        if s == slug:
            return identity
        return None

    registry.get_by_slug = MagicMock(side_effect=get_by_slug)
    return registry


def _build_app_with_registry(
    broker_registry,
    identity_registry=None,
):
    from yashigani.gateway.mcp_router_runtime import create_mcp_call_router
    app = FastAPI()
    app.include_router(
        create_mcp_call_router(
            broker_registry,
            identity_registry=identity_registry,
        )
    )
    return app


# ---------------------------------------------------------------------------
# (a) CONFIDENTIAL ceiling → CONFIDENTIAL result → allowed
# ---------------------------------------------------------------------------

class TestCeilingAllowsResult:
    """Caller with CONFIDENTIAL ceiling receives CONFIDENTIAL result."""

    def test_confidential_ceiling_allows_confidential_result(self):
        """
        When the identity registry returns sensitivity_ceiling=CONFIDENTIAL
        for the caller, and the egress OPA decision returns allow=True for a
        CONFIDENTIAL result, the response is 200 with the upstream content.
        """
        reg, broker = _make_registry_with_egress(egress_allow=True)
        id_reg = _make_identity_registry_mock(
            slug="alice", sensitivity_ceiling="CONFIDENTIAL", return_as_dict=True
        )
        app = _build_app_with_registry(reg, identity_registry=id_reg)

        fake_resp = _fake_upstream_response("confidential file content")
        p1, p2 = _patch_transport_forward(fake_resp)

        with p1, p2:
            client = TestClient(app)
            req = _make_jsonrpc_request(
                "tools/call", {"name": "read_file", "arguments": {"path": "/secret"}}, "t1"
            )
            resp = client.post(
                "/mcp/filesystem-mcp",
                content=req,
                headers={"X-Forwarded-User": "alice"},
            )

        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"

        # Verify the registry was called with the right slug.
        id_reg.get_by_slug.assert_called_once_with("alice")

        # Verify enforce_result was called with the ceiling set.
        call_args = broker.enforce_result.call_args
        ctx = call_args.kwargs.get("ctx") or call_args.args[0]
        assert ctx.caller_sensitivity_ceiling == "CONFIDENTIAL", (
            f"caller_sensitivity_ceiling was {ctx.caller_sensitivity_ceiling!r}; "
            "expected 'CONFIDENTIAL'"
        )


# ---------------------------------------------------------------------------
# (b) CONFIDENTIAL ceiling → RESTRICTED result → denied
# ---------------------------------------------------------------------------

class TestCeilingDeniesHigherResult:
    """Caller with CONFIDENTIAL ceiling cannot receive RESTRICTED result."""

    def test_confidential_ceiling_denies_restricted_result(self):
        """
        When egress OPA denies (result sensitivity exceeds caller's ceiling),
        the route returns 403 with MCP_EGRESS_DENIED — the upstream content is
        NOT returned to the caller.
        """
        reg, broker = _make_registry_with_egress(
            egress_allow=False,
            egress_deny_reason="result_sensitivity_exceeds_caller_ceiling",
        )
        id_reg = _make_identity_registry_mock(
            slug="alice", sensitivity_ceiling="CONFIDENTIAL", return_as_dict=True
        )
        app = _build_app_with_registry(reg, identity_registry=id_reg)

        fake_resp = _fake_upstream_response("restricted file content")
        p1, p2 = _patch_transport_forward(fake_resp)

        with p1, p2:
            client = TestClient(app)
            req = _make_jsonrpc_request(
                "tools/call", {"name": "read_file", "arguments": {"path": "/top-secret"}}, "t2"
            )
            resp = client.post(
                "/mcp/filesystem-mcp",
                content=req,
                headers={"X-Forwarded-User": "alice"},
            )

        assert resp.status_code == 403, f"Expected 403, got {resp.status_code}: {resp.text}"
        data = resp.json()
        assert data["error"] == "MCP_EGRESS_DENIED", f"Unexpected error: {data}"
        assert data["deny_reason"] == "result_sensitivity_exceeds_caller_ceiling"

        # The upstream content must NOT appear in the response body.
        assert "restricted file content" not in resp.text

        # Verify ceiling was set on ctx when enforce_result was called.
        call_args = broker.enforce_result.call_args
        ctx = call_args.kwargs.get("ctx") or call_args.args[0]
        assert ctx.caller_sensitivity_ceiling == "CONFIDENTIAL"


# ---------------------------------------------------------------------------
# (c) No identity registry → ceiling = None → fail-closed deny
# ---------------------------------------------------------------------------

class TestNoRegistryFailsClosed:
    """Without an identity registry, ceiling is None → egress gate denies."""

    def test_no_registry_ceiling_is_none(self):
        """
        When no identity_registry is passed to the router, ctx.caller_sensitivity_ceiling
        is None.  The mock egress gate is configured to deny (as OPA would) → 403.
        """
        reg, broker = _make_registry_with_egress(
            egress_allow=False,
            egress_deny_reason="invalid_or_missing_caller_ceiling",
        )
        app = _build_app_with_registry(reg, identity_registry=None)

        fake_resp = _fake_upstream_response("some content")
        p1, p2 = _patch_transport_forward(fake_resp)

        with p1, p2:
            client = TestClient(app)
            req = _make_jsonrpc_request(
                "tools/call", {"name": "read_file", "arguments": {"path": "/foo"}}, "t3"
            )
            resp = client.post(
                "/mcp/filesystem-mcp",
                content=req,
                headers={"X-Forwarded-User": "alice"},
            )

        assert resp.status_code == 403
        # ceiling must have been None when enforce_result was called.
        call_args = broker.enforce_result.call_args
        ctx = call_args.kwargs.get("ctx") or call_args.args[0]
        assert ctx.caller_sensitivity_ceiling is None, (
            f"Expected None ceiling when no registry, got {ctx.caller_sensitivity_ceiling!r}"
        )

    def test_unknown_user_id_ceiling_is_none(self):
        """
        user_id == 'unknown' (no X-Forwarded-User) → ceiling stays None → fail-closed.
        """
        reg, broker = _make_registry_with_egress(
            egress_allow=False,
            egress_deny_reason="invalid_or_missing_caller_ceiling",
        )
        id_reg = _make_identity_registry_mock(slug="alice", sensitivity_ceiling="RESTRICTED")
        app = _build_app_with_registry(reg, identity_registry=id_reg)

        fake_resp = _fake_upstream_response("some content")
        p1, p2 = _patch_transport_forward(fake_resp)

        with p1, p2:
            client = TestClient(app)
            req = _make_jsonrpc_request(
                "tools/call", {"name": "read_file", "arguments": {"path": "/foo"}}, "t4"
            )
            # No X-Forwarded-User header → user_id resolves to "unknown"
            resp = client.post("/mcp/filesystem-mcp", content=req)

        assert resp.status_code == 403
        # Registry should NOT have been called for "unknown"
        id_reg.get_by_slug.assert_not_called()
        call_args = broker.enforce_result.call_args
        ctx = call_args.kwargs.get("ctx") or call_args.args[0]
        assert ctx.caller_sensitivity_ceiling is None

    def test_user_not_in_registry_ceiling_is_none(self):
        """
        User slug present but not in registry → get_by_slug returns None → ceiling stays None.
        """
        reg, broker = _make_registry_with_egress(
            egress_allow=False,
            egress_deny_reason="invalid_or_missing_caller_ceiling",
        )
        # Registry that returns None for any slug.
        id_reg = MagicMock()
        id_reg.get_by_slug = MagicMock(return_value=None)

        app = _build_app_with_registry(reg, identity_registry=id_reg)

        fake_resp = _fake_upstream_response("some content")
        p1, p2 = _patch_transport_forward(fake_resp)

        with p1, p2:
            client = TestClient(app)
            req = _make_jsonrpc_request(
                "tools/call", {"name": "read_file", "arguments": {"path": "/foo"}}, "t5"
            )
            resp = client.post(
                "/mcp/filesystem-mcp",
                content=req,
                headers={"X-Forwarded-User": "bob"},
            )

        assert resp.status_code == 403
        id_reg.get_by_slug.assert_called_once_with("bob")
        call_args = broker.enforce_result.call_args
        ctx = call_args.kwargs.get("ctx") or call_args.args[0]
        assert ctx.caller_sensitivity_ceiling is None


# ---------------------------------------------------------------------------
# (d) Registry lookup raises → ceiling stays None → fail-closed deny
# ---------------------------------------------------------------------------

class TestRegistryLookupError:
    """Registry.get_by_slug raises → ceiling stays None, request is not aborted (warn + continue)."""

    def test_registry_raise_ceiling_is_none(self):
        """
        When the registry lookup raises an exception, the ceiling stays None
        (fail-closed on the egress OPA decision), but the request continues to
        the ingress enforce/forward steps — the egress gate denies (None ceiling).
        """
        reg, broker = _make_registry_with_egress(
            egress_allow=False,
            egress_deny_reason="invalid_or_missing_caller_ceiling",
        )
        id_reg = MagicMock()
        id_reg.get_by_slug = MagicMock(side_effect=RuntimeError("Redis connection error"))

        app = _build_app_with_registry(reg, identity_registry=id_reg)

        fake_resp = _fake_upstream_response("some content")
        p1, p2 = _patch_transport_forward(fake_resp)

        with p1, p2:
            client = TestClient(app)
            req = _make_jsonrpc_request(
                "tools/call", {"name": "read_file", "arguments": {"path": "/foo"}}, "t6"
            )
            resp = client.post(
                "/mcp/filesystem-mcp",
                content=req,
                headers={"X-Forwarded-User": "alice"},
            )

        # Egress denies because ceiling is None.
        assert resp.status_code == 403
        call_args = broker.enforce_result.call_args
        ctx = call_args.kwargs.get("ctx") or call_args.args[0]
        assert ctx.caller_sensitivity_ceiling is None


# ---------------------------------------------------------------------------
# (e) IdentityRecord dataclass path (sensitivity_ceiling attribute)
# ---------------------------------------------------------------------------

class TestIdentityRecordDataclass:
    """Registry returns an IdentityRecord dataclass (not a dict) — ceiling extracted."""

    def test_dataclass_identity_ceiling_extracted(self):
        """
        When the registry returns an IdentityRecord-like object (has a
        sensitivity_ceiling attribute), the ceiling is extracted correctly.
        """
        reg, broker = _make_registry_with_egress(egress_allow=True)
        id_reg = _make_identity_registry_mock(
            slug="dave", sensitivity_ceiling="INTERNAL", return_as_dict=False
        )
        app = _build_app_with_registry(reg, identity_registry=id_reg)

        fake_resp = _fake_upstream_response("internal content")
        p1, p2 = _patch_transport_forward(fake_resp)

        with p1, p2:
            client = TestClient(app)
            req = _make_jsonrpc_request(
                "tools/call", {"name": "read_file", "arguments": {"path": "/internal"}}, "t7"
            )
            resp = client.post(
                "/mcp/filesystem-mcp",
                content=req,
                headers={"X-Forwarded-User": "dave"},
            )

        assert resp.status_code == 200
        call_args = broker.enforce_result.call_args
        ctx = call_args.kwargs.get("ctx") or call_args.args[0]
        assert ctx.caller_sensitivity_ceiling == "INTERNAL"


# ---------------------------------------------------------------------------
# (f) Dict identity path
# ---------------------------------------------------------------------------

class TestDictIdentity:
    """Registry returns a plain dict — ceiling extracted via dict.get()."""

    def test_dict_identity_ceiling_extracted(self):
        """
        When the registry returns a plain dict (Redis-backed IdentityRegistry
        returns dicts from get_by_slug), the ceiling is read via dict.get().
        """
        reg, broker = _make_registry_with_egress(egress_allow=True)
        id_reg = _make_identity_registry_mock(
            slug="eve", sensitivity_ceiling="RESTRICTED", return_as_dict=True
        )
        app = _build_app_with_registry(reg, identity_registry=id_reg)

        fake_resp = _fake_upstream_response("restricted content")
        p1, p2 = _patch_transport_forward(fake_resp)

        with p1, p2:
            client = TestClient(app)
            req = _make_jsonrpc_request(
                "tools/call", {"name": "read_file", "arguments": {"path": "/restricted"}}, "t8"
            )
            resp = client.post(
                "/mcp/filesystem-mcp",
                content=req,
                headers={"X-Forwarded-User": "eve"},
            )

        assert resp.status_code == 200
        call_args = broker.enforce_result.call_args
        ctx = call_args.kwargs.get("ctx") or call_args.args[0]
        assert ctx.caller_sensitivity_ceiling == "RESTRICTED"


# ---------------------------------------------------------------------------
# (g) proxy.py passes openai_router._state.identity_registry
# ---------------------------------------------------------------------------

class TestProxyPassesIdentityRegistry:
    """
    Verify that proxy._proxy_request_body passes openai_router._state.identity_registry
    to dispatch_mcp_call as the identity_registry kwarg.
    """

    def test_proxy_passes_openai_router_state_identity_registry(self):
        """
        Static code inspection: proxy.py must import openai_router._state and pass
        _state.identity_registry to dispatch_mcp_call.

        This is a source-level guard (same pattern as Fix-1 guard in
        test_p3_mcp_security_fixes.py) that fails on regression.
        """
        import pathlib
        source = pathlib.Path(
            "src/yashigani/gateway/proxy.py"
        ).read_text()

        assert "identity_registry=_openai_router._state.identity_registry" in source, (
            "G-ORCH-OPA-1 regression: proxy.py must pass "
            "identity_registry=_openai_router._state.identity_registry "
            "to dispatch_mcp_call so the egress ceiling gate is functional."
        )

    def test_dispatch_mcp_call_signature_accepts_identity_registry(self):
        """
        dispatch_mcp_call must accept an identity_registry keyword argument.
        """
        import inspect
        from yashigani.gateway.mcp_router_runtime import dispatch_mcp_call

        sig = inspect.signature(dispatch_mcp_call)
        assert "identity_registry" in sig.parameters, (
            "G-ORCH-OPA-1: dispatch_mcp_call must accept identity_registry parameter."
        )
        param = sig.parameters["identity_registry"]
        # Must be optional (has a default of None)
        assert param.default is None, (
            f"identity_registry param default must be None (fail-closed), got {param.default!r}"
        )

    def test_handle_mcp_call_inner_signature_accepts_identity_registry(self):
        """
        _handle_mcp_call_inner must also accept identity_registry so the router
        path (create_mcp_call_router) can thread it through.
        """
        import inspect
        from yashigani.gateway.mcp_router_runtime import _handle_mcp_call_inner

        sig = inspect.signature(_handle_mcp_call_inner)
        assert "identity_registry" in sig.parameters, (
            "G-ORCH-OPA-1: _handle_mcp_call_inner must accept identity_registry parameter."
        )
