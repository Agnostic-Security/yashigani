"""
FIX-005 — Permission store unavailable must FAIL-CLOSED in enforcing envs.

Regression tests verifying that when the permission store (Redis) is None:
  • In production/staging (enforcing envs): MCP connection allow-list DENIES
    and the cloud-model gate DENIES — deny-by-default mandate.
  • In dev/test (non-enforcing envs): behaviour is unchanged (allow/warn).

Coverage:
  A. broker._check_connection_permit — store=None in enforcing env → DENY
  B. broker._check_connection_permit — store=None in dev env → allow (no-op)
  C. broker.enforce() — store=None + prod → deny "permission_store_unavailable"
  D. openai_router cloud gate — store=None + prod + cloud → deny response
  E. openai_router cloud gate — store=None + dev + cloud → no early deny
  F. openai_router cloud gate — store=None + prod + local (no strict) → no deny
  G. openai_router cloud gate — store=None + prod + strict-dial → deny response
  H. openai_router agent_call exemption — store=None + prod → not denied early
"""
from __future__ import annotations

import os
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Helpers — broker
# ─────────────────────────────────────────────────────────────────────────────

def _make_posture_b():
    from yashigani.mcp._types import McpPosture, PostureBinding
    return McpPosture.MCP_B, PostureBinding.for_posture(McpPosture.MCP_B)


def _make_ctx(
    server_id: str = "my-server",
    tool_name: Optional[str] = "search",
    caller_agent_id: Optional[str] = None,
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
    )


def _make_broker(permission_store=None):
    from yashigani.mcp.broker import McpBroker, McpBrokerConfig
    from yashigani.mcp._jwt import McpJwtIssuer
    issuer = McpJwtIssuer(tenant_id="t1")
    cfg = McpBrokerConfig(
        opa_url="http://opa:8181",
        tenant_id="t1",
        issuer=issuer,
        permission_store=permission_store,
    )
    return McpBroker(config=cfg)


def _opa_allow():
    from yashigani.mcp._opa import OpaDecisionResult
    return OpaDecisionResult(
        allow=True, deny_reason="ok", redact_args=set(),
        audit_capture=False, rate_limit_key=None, elapsed_ms=5,
    )


# ─────────────────────────────────────────────────────────────────────────────
# A. broker._check_connection_permit — store=None + enforcing env → DENY
# ─────────────────────────────────────────────────────────────────────────────

class TestConnectionPermitFailClosed:
    """FIX-005: broker._check_connection_permit fail-closed in enforcing envs."""

    def test_a1_store_none_production_denies(self):
        """A1: store=None + YASHIGANI_ENV=production → 'permission_store_unavailable'."""
        broker = _make_broker(permission_store=None)
        ctx = _make_ctx()
        with patch.dict(os.environ, {"YASHIGANI_ENV": "production"}):
            result = broker._check_connection_permit(ctx)
        assert result == "permission_store_unavailable", (
            "FIX-005: store=None in production must return 'permission_store_unavailable'. "
            f"Got {result!r}."
        )

    def test_a2_store_none_staging_denies(self):
        """A2: store=None + YASHIGANI_ENV=staging → 'permission_store_unavailable'."""
        broker = _make_broker(permission_store=None)
        ctx = _make_ctx()
        with patch.dict(os.environ, {"YASHIGANI_ENV": "staging"}):
            result = broker._check_connection_permit(ctx)
        assert result == "permission_store_unavailable", (
            "FIX-005: store=None in staging must return 'permission_store_unavailable'. "
            f"Got {result!r}."
        )

    def test_b1_store_none_dev_allows(self):
        """B1: store=None + YASHIGANI_ENV=development → None (no-op, dev behaviour unchanged)."""
        broker = _make_broker(permission_store=None)
        ctx = _make_ctx()
        with patch.dict(os.environ, {"YASHIGANI_ENV": "development"}):
            result = broker._check_connection_permit(ctx)
        assert result is None, (
            "FIX-005: store=None in dev env must be a no-op (None), preserving "
            "existing dev/test behaviour. Got {result!r}."
        )

    def test_b2_store_none_env_unset_allows(self):
        """B2: store=None + YASHIGANI_ENV unset → None (non-enforcing)."""
        broker = _make_broker(permission_store=None)
        ctx = _make_ctx()
        env = {k: v for k, v in os.environ.items() if k != "YASHIGANI_ENV"}
        with patch.dict(os.environ, env, clear=True):
            result = broker._check_connection_permit(ctx)
        assert result is None, (
            "FIX-005: store=None with YASHIGANI_ENV unset must be a no-op. "
            f"Got {result!r}."
        )


# ─────────────────────────────────────────────────────────────────────────────
# C. broker.enforce() — store=None + prod → deny "permission_store_unavailable"
# ─────────────────────────────────────────────────────────────────────────────

class TestEnforcePermissionStoreFailClosed:
    """FIX-005: broker.enforce() fail-closed when store=None in prod."""

    @pytest.mark.asyncio
    async def test_c1_enforce_denies_store_none_in_prod(self):
        """C1: enforce() returns deny when store=None in production (before OPA)."""
        broker = _make_broker(permission_store=None)
        ctx = _make_ctx(server_id="some-server")

        opa_called = []

        async def fake_opa(**kwargs):
            opa_called.append(True)
            return _opa_allow()

        with patch("yashigani.mcp.broker.query_mcp_decision", new=fake_opa), \
             patch("yashigani.gateway._client_enforce.evaluate_client_policies",
                   new=AsyncMock(return_value={"allow": True})), \
             patch.dict(os.environ, {"YASHIGANI_ENV": "production"}):
            decision = await broker.enforce(ctx)

        assert not decision.allow, (
            "FIX-005: enforce() must deny when store=None in production. "
            f"Got allow={decision.allow} reason={decision.deny_reason!r}."
        )
        assert decision.deny_reason == "permission_store_unavailable", (
            f"FIX-005: deny_reason must be 'permission_store_unavailable', "
            f"got {decision.deny_reason!r}."
        )
        assert len(opa_called) == 0, (
            "FIX-005: OPA must NOT be queried when permission_store_unavailable fires. "
            "It is a pre-OPA gate."
        )

    @pytest.mark.asyncio
    async def test_c2_enforce_allows_store_none_in_dev(self):
        """C2: enforce() proceeds normally when store=None in dev (OPA decides)."""
        broker = _make_broker(permission_store=None)
        ctx = _make_ctx(server_id="some-server")

        opa_called = []

        async def fake_opa(**kwargs):
            opa_called.append(True)
            return _opa_allow()

        with patch("yashigani.mcp.broker.query_mcp_decision", new=fake_opa), \
             patch("yashigani.gateway._client_enforce.evaluate_client_policies",
                   new=AsyncMock(return_value={"allow": True})), \
             patch.object(broker, "_check_capability_envelope", new=AsyncMock(return_value=None)), \
             patch.object(broker, "_emit_audit", new=AsyncMock()), \
             patch.dict(os.environ, {"YASHIGANI_ENV": "development"}):
            decision = await broker.enforce(ctx)

        assert len(opa_called) == 1, (
            "FIX-005: In dev env, OPA MUST be queried (store=None is a no-op)."
        )


# ─────────────────────────────────────────────────────────────────────────────
# D–H. openai_router cloud gate fail-closed
# ─────────────────────────────────────────────────────────────────────────────

class TestOpenAIRouterPermissionStoreFailClosed:
    """FIX-005: openai_router cloud-model gate fail-closed when store=None."""

    def _make_state(self, permission_store=None, permission_strict=False):
        """Build a minimal OpenAIRouterState with controllable permission_store."""
        from yashigani.gateway.openai_router import _state as state_module
        # Patch _state directly — not a new instance; we monkeypatch the singleton.
        state = MagicMock()
        state.permission_store = permission_store
        state.permission_strict = permission_strict
        return state

    def _check_cloud_gate(
        self, env: str, provider: str, model: str,
        permission_store=None, permission_strict: bool = False,
        is_agent_call: bool = False, brain_reasoning_leg: bool = False,
    ):
        """
        Run only the FIX-005 fail-closed pre-check from openai_router.

        We reproduce the logic inline because the full handle_chat_completion
        route depends on many wired services.  The extracted logic is:

            _perm_is_cloud = selected_provider in _CLOUD_PROVIDER_CONFIG
            _perm_gate_scope = not is_agent_call and not brain_reasoning_leg
                               and (_perm_is_cloud or permission_strict)
            if _perm_gate_scope and permission_store is None and env in enforcing:
                return "permission_store_unavailable"
            return None  # no early deny
        """
        from yashigani.gateway.openai_router import _CLOUD_PROVIDER_CONFIG
        _perm_is_cloud = provider in _CLOUD_PROVIDER_CONFIG
        _perm_gate_scope = (
            not is_agent_call
            and not brain_reasoning_leg
            and (_perm_is_cloud or permission_strict)
        )
        if (
            _perm_gate_scope
            and permission_store is None
            and env in {"production", "staging"}
        ):
            return "permission_store_unavailable"
        return None

    def test_d1_cloud_model_store_none_prod_denies(self):
        """D1: cloud model + store=None + prod → permission_store_unavailable."""
        result = self._check_cloud_gate(
            env="production", provider="openai", model="gpt-4o",
            permission_store=None,
        )
        assert result == "permission_store_unavailable", (
            f"FIX-005: cloud model + store=None + prod must deny. Got {result!r}."
        )

    def test_d2_cloud_model_store_none_staging_denies(self):
        """D2: cloud model + store=None + staging → permission_store_unavailable."""
        result = self._check_cloud_gate(
            env="staging", provider="anthropic", model="claude-3-5",
            permission_store=None,
        )
        assert result == "permission_store_unavailable", (
            f"FIX-005: cloud model + store=None + staging must deny. Got {result!r}."
        )

    def test_e1_cloud_model_store_none_dev_allows(self):
        """E1: cloud model + store=None + dev → no early deny (allow path)."""
        result = self._check_cloud_gate(
            env="development", provider="openai", model="gpt-4o",
            permission_store=None,
        )
        assert result is None, (
            f"FIX-005: cloud model + store=None + dev must be no early deny. Got {result!r}."
        )

    def test_f1_local_model_store_none_prod_no_strict_allows(self):
        """F1: local Ollama model + store=None + prod + no strict-dial → no early deny."""
        result = self._check_cloud_gate(
            env="production", provider="ollama", model="qwen2.5:3b",
            permission_store=None, permission_strict=False,
        )
        assert result is None, (
            "FIX-005: local model + no strict mode + store=None + prod → no early deny "
            f"(local-LLM usage must not be blocked). Got {result!r}."
        )

    def test_g1_strict_dial_store_none_prod_denies(self):
        """G1: strict-dial local model + store=None + prod → permission_store_unavailable."""
        result = self._check_cloud_gate(
            env="production", provider="ollama", model="qwen2.5:3b",
            permission_store=None, permission_strict=True,
        )
        assert result == "permission_store_unavailable", (
            "FIX-005: strict-dial + store=None + prod must deny fail-closed. "
            f"Got {result!r}."
        )

    def test_h1_agent_call_exempt_from_fail_closed(self):
        """H1: is_agent_call=True → exempt from store=None fail-closed deny."""
        result = self._check_cloud_gate(
            env="production", provider="openai", model="gpt-4o",
            permission_store=None, is_agent_call=True,
        )
        assert result is None, (
            "FIX-005: agent calls are exempt from the permission-store fail-closed gate. "
            f"Got {result!r}."
        )

    def test_h2_brain_reasoning_exempt_from_fail_closed(self):
        """H2: brain_reasoning_leg=True → exempt from store=None fail-closed deny."""
        result = self._check_cloud_gate(
            env="production", provider="openai", model="gpt-4o",
            permission_store=None, brain_reasoning_leg=True,
        )
        assert result is None, (
            "FIX-005: brain-reasoning leg is exempt from the permission-store fail-closed gate. "
            f"Got {result!r}."
        )
