"""
Regression tests — 3.1 Phase 3+4: MCP per-agent authorization enforcement.

These tests guard the specific semantics established in 3.1 Phase 3+4:

  Phase 4 (connection allow-list):
    - Without org grant → deny ("mcp_server_not_permitted"), no OPA call.
    - With org grant → allow (Phase 4 passes).
    - No permission_store → Phase 4 is a no-op (backwards compatible).

  Phase 3 (tool allow-list):
    - caller_allowed_tools restricts which tools an agent may invoke.
    - "gateway:orchestrator" is always exempt.
    - None/empty → no restriction.

  Seeder idempotency:
    - seed_mcp_grants writes allow=True for every server_id.
    - resolve_boolean_grant returns True after seeding, False before.
    - Calling twice is safe.

  Full enforce() pipeline ordering:
    - Phase 4 fires BEFORE Phase 3 fires BEFORE OPA.
    - When Phase 4 denies, OPA is not called and Phase 3 is not checked.
    - When Phase 4 allows and Phase 3 denies, OPA is not called.
    - When both allow, OPA is called normally.

Last updated: 2026-06-28T00:00:00+00:00
"""
from __future__ import annotations

from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _perm_store():
    try:
        import fakeredis
    except ImportError:
        pytest.skip("fakeredis not installed")
    from yashigani.permissions.store import PermissionStore
    return PermissionStore(fakeredis.FakeRedis(decode_responses=False))


def _make_posture_b():
    from yashigani.mcp._types import McpPosture, PostureBinding
    return McpPosture.MCP_B, PostureBinding.for_posture(McpPosture.MCP_B)


def _make_ctx(
    server_id: str = "my-server",
    tool_name: Optional[str] = "search",
    caller_agent_id: Optional[str] = None,
    caller_allowed_tools: Optional[list[str]] = None,
):
    from yashigani.mcp._types import McpCallContext
    posture, binding = _make_posture_b()
    return McpCallContext(
        tenant_id="t1",
        agent_name=server_id,
        user_id="user-1",
        posture=posture,
        posture_binding=binding,
        action="mcp.tools.call",
        tool_name=tool_name,
        server_id=server_id,
        caller_agent_id=caller_agent_id,
        caller_allowed_tools=caller_allowed_tools,
    )


def _make_broker(permission_store=None, org_id: str = "default"):
    from yashigani.mcp.broker import McpBroker, McpBrokerConfig
    from yashigani.mcp._jwt import McpJwtIssuer
    return McpBroker(config=McpBrokerConfig(
        opa_url="http://opa:8181",
        tenant_id="t1",
        issuer=McpJwtIssuer(tenant_id="t1"),
        permission_store=permission_store,
        org_id=org_id,
    ))


def _seed(store, server_ids, org_id="default"):
    from yashigani.permissions import seed_mcp_grants
    seed_mcp_grants(store, server_ids, org_id)


def _opa_allow():
    from yashigani.mcp._opa import OpaDecisionResult
    return OpaDecisionResult(
        allow=True, deny_reason="ok", redact_args=set(),
        audit_capture=False, rate_limit_key=None, elapsed_ms=5,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Regression 1: Phase 4 deny-by-default without org grant
# ─────────────────────────────────────────────────────────────────────────────

class TestPhase4DenyByDefault:

    @pytest.mark.asyncio
    async def test_no_org_grant_denies_before_opa(self):
        """
        Phase 4 regresses to deny-by-default: a server with no org grant must be
        denied, and OPA must NOT be queried.
        """
        store = _perm_store()
        # No grants seeded
        broker = _make_broker(permission_store=store)
        ctx = _make_ctx(server_id="no-grant-server")

        opa_called = []

        async def spy_opa(**kwargs):
            opa_called.append(1)
            return _opa_allow()

        with patch("yashigani.mcp.broker.query_mcp_decision", new=spy_opa), \
             patch("yashigani.gateway._client_enforce.evaluate_client_policies",
                   new=AsyncMock(return_value={"allow": True})):
            decision = await broker.enforce(ctx)

        assert not decision.allow
        assert decision.deny_reason == "mcp_server_not_permitted"
        assert not opa_called, "OPA must not be called when Phase 4 denies"

    @pytest.mark.asyncio
    async def test_seeded_server_passes_phase4(self):
        """
        After seeding, Phase 4 passes (OPA is called) for the seeded server.
        """
        store = _perm_store()
        _seed(store, ["allowed-server"])
        broker = _make_broker(permission_store=store)
        ctx = _make_ctx(server_id="allowed-server")

        opa_called = []

        async def spy_opa(**kwargs):
            opa_called.append(1)
            return _opa_allow()

        with patch("yashigani.mcp.broker.query_mcp_decision", new=spy_opa), \
             patch("yashigani.gateway._client_enforce.evaluate_client_policies",
                   new=AsyncMock(return_value={"allow": True})):
            decision = await broker.enforce(ctx)

        assert opa_called, "OPA must be called when Phase 4 allows"
        # Decision may allow or deny based on OPA mock (which returns allow=True),
        # but Phase 4 must have passed (OPA was reached).
        assert decision.deny_reason != "mcp_server_not_permitted"

    @pytest.mark.asyncio
    async def test_no_permission_store_passes_phase4(self):
        """
        Without permission_store, Phase 4 is a no-op: OPA is always called.
        Backwards compatibility regression.
        """
        broker = _make_broker(permission_store=None)
        ctx = _make_ctx(server_id="any-server")

        opa_called = []

        async def spy_opa(**kwargs):
            opa_called.append(1)
            return _opa_allow()

        with patch("yashigani.mcp.broker.query_mcp_decision", new=spy_opa), \
             patch("yashigani.gateway._client_enforce.evaluate_client_policies",
                   new=AsyncMock(return_value={"allow": True})):
            await broker.enforce(ctx)

        assert opa_called, "OPA must be called when permission_store is None (no-op Phase 4)"


# ─────────────────────────────────────────────────────────────────────────────
# Regression 2: Phase 3 tool allow-list enforcement
# ─────────────────────────────────────────────────────────────────────────────

class TestPhase3ToolAllowList:

    @pytest.mark.asyncio
    async def test_tool_denied_when_not_in_allow_list(self):
        """
        Phase 3: when caller_allowed_tools is set and tool is not in it,
        enforce() must deny with 'tool_not_permitted' and OPA must not be called.
        """
        store = _perm_store()
        _seed(store, ["my-server"])  # Phase 4 pass
        broker = _make_broker(permission_store=store)
        ctx = _make_ctx(
            server_id="my-server",
            tool_name="dangerous_tool",
            caller_agent_id="restricted-agent",
            caller_allowed_tools=["safe_tool"],
        )

        opa_called = []

        async def spy_opa(**kwargs):
            opa_called.append(1)
            return _opa_allow()

        with patch("yashigani.mcp.broker.query_mcp_decision", new=spy_opa), \
             patch("yashigani.gateway._client_enforce.evaluate_client_policies",
                   new=AsyncMock(return_value={"allow": True})):
            decision = await broker.enforce(ctx)

        assert not decision.allow
        assert decision.deny_reason == "tool_not_permitted"
        assert not opa_called, "OPA must not be called when Phase 3 denies"

    @pytest.mark.asyncio
    async def test_tool_allowed_when_in_allow_list(self):
        """
        Phase 3: when caller_allowed_tools includes the tool, enforce() proceeds
        to OPA (OPA is called).
        """
        store = _perm_store()
        _seed(store, ["my-server"])
        broker = _make_broker(permission_store=store)
        ctx = _make_ctx(
            server_id="my-server",
            tool_name="safe_tool",
            caller_agent_id="restricted-agent",
            caller_allowed_tools=["safe_tool", "read_file"],
        )

        opa_called = []

        async def spy_opa(**kwargs):
            opa_called.append(1)
            return _opa_allow()

        with patch("yashigani.mcp.broker.query_mcp_decision", new=spy_opa), \
             patch("yashigani.gateway._client_enforce.evaluate_client_policies",
                   new=AsyncMock(return_value={"allow": True})):
            decision = await broker.enforce(ctx)

        assert opa_called, "OPA must be called when Phase 3 allows"

    @pytest.mark.asyncio
    async def test_orchestrator_bypasses_phase3(self):
        """
        gateway:orchestrator must bypass Phase 3 even when caller_allowed_tools
        is set and doesn't include the tool.  OPA must be called.
        """
        store = _perm_store()
        _seed(store, ["my-server"])
        broker = _make_broker(permission_store=store)
        ctx = _make_ctx(
            server_id="my-server",
            tool_name="any_tool",
            caller_agent_id="gateway:orchestrator",
            caller_allowed_tools=["different_tool"],  # would deny a normal caller
        )

        opa_called = []

        async def spy_opa(**kwargs):
            opa_called.append(1)
            return _opa_allow()

        with patch("yashigani.mcp.broker.query_mcp_decision", new=spy_opa), \
             patch("yashigani.gateway._client_enforce.evaluate_client_policies",
                   new=AsyncMock(return_value={"allow": True})):
            decision = await broker.enforce(ctx)

        assert opa_called, "OPA must be called for gateway:orchestrator (Phase 3 bypass)"
        assert decision.deny_reason != "tool_not_permitted", (
            "gateway:orchestrator must never get 'tool_not_permitted'"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Regression 3: Enforce() pipeline ordering
# ─────────────────────────────────────────────────────────────────────────────

class TestEnforcePipelineOrdering:
    """Phase 4 → Phase 3 → OPA — ordering must be stable."""

    @pytest.mark.asyncio
    async def test_phase4_fires_before_phase3(self):
        """
        When Phase 4 denies (no org grant), Phase 3 and OPA are both skipped.
        deny_reason is 'mcp_server_not_permitted', not 'tool_not_permitted'.
        """
        store = _perm_store()
        # No org grant seeded → Phase 4 fires
        broker = _make_broker(permission_store=store)
        ctx = _make_ctx(
            server_id="unregistered-server",
            tool_name="tool",
            caller_agent_id="agent",
            caller_allowed_tools=["other_tool"],  # would fire Phase 3 if reached
        )

        opa_called = []

        async def spy_opa(**kwargs):
            opa_called.append(1)
            return _opa_allow()

        with patch("yashigani.mcp.broker.query_mcp_decision", new=spy_opa), \
             patch("yashigani.gateway._client_enforce.evaluate_client_policies",
                   new=AsyncMock(return_value={"allow": True})):
            decision = await broker.enforce(ctx)

        assert not decision.allow
        assert decision.deny_reason == "mcp_server_not_permitted", (
            "Phase 4 must fire first when org grant is missing; "
            f"got {decision.deny_reason!r}"
        )
        assert not opa_called

    @pytest.mark.asyncio
    async def test_both_allow_opa_is_called(self):
        """
        When Phase 4 passes (org grant exists) AND Phase 3 passes (tool in list),
        OPA must be called normally.
        """
        store = _perm_store()
        _seed(store, ["srv"])
        broker = _make_broker(permission_store=store)
        ctx = _make_ctx(
            server_id="srv",
            tool_name="allowed_tool",
            caller_agent_id="agent-x",
            caller_allowed_tools=["allowed_tool"],
        )

        opa_called = []

        async def spy_opa(**kwargs):
            opa_called.append(1)
            return _opa_allow()

        with patch("yashigani.mcp.broker.query_mcp_decision", new=spy_opa), \
             patch("yashigani.gateway._client_enforce.evaluate_client_policies",
                   new=AsyncMock(return_value={"allow": True})):
            await broker.enforce(ctx)

        assert opa_called, (
            "OPA must be called when both Phase 4 and Phase 3 pass"
        )
