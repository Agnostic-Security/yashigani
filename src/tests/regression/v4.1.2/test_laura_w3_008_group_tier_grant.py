"""
Regression tests for LAURA-V250-W3-008 — power_user over-block (groups empty).

REVISED ROOT CAUSE (W3-008 real integration bug — NOT merely a fixture issue):
  The identity registry stores the `groups` field only as set at REGISTRATION.
  Group memberships granted later via RBAC add_member are stored ONLY in
  rbac:user:{identity_id} in Redis and are NEVER written back to the registry
  record.  chat_completions called `identity.get("groups")` which returns only
  the reg-record snapshot → empty for a post-registration grant → Layer 2's
  group-tier loops iterate nothing → 422 for group-grantees (over-block) AND
  group-deny grants are silently bypassed (fail-open).

ORIGINAL MISDIAGNOSIS (now corrected):
  The previous determination was "fixture bug in populate_411.py."  That was
  partially true (the fixture ordering was also wrong), but the real structural
  bug is in chat_completions: the group backfill was missing entirely.

GATEWAY FIX (W3-008 — this commit):
  After identity resolution in chat_completions, for human/user principals,
  call _state.rbac_store.get_user_groups(identity_id) and union the result
  with the reg-record groups.  Fail-safe: rbac_store=None → keep reg-record
  groups (no crash); rbac store exception → warning + keep reg-record groups.

REGRESSION TESTS here (pre-backfill contracts — rbac_store=None in all mocks):
  1. Group-tier grant + identity groups pre-populated → Layer 2 passes (not 422).
     [still valid: reg-record groups work when correctly set]
  2. Group-tier grant + identity groups empty + rbac_store=None → 422.
     [valid: without backfill wired, empty groups → no grant found]
  3. No permission_store → Layer 2 gate skips, group-tier path unreachable.

See test_w3_008_rbac_backfill.py for the integration tests that verify
the real backfill fix (groups=[] in reg-record + RBAC membership → passes).

Last updated: 2026-07-15T00:00:00+00:00
"""
from __future__ import annotations

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_GROUP_ID = "grp_engineers_w3008"
_CLOUD_MODEL = "openai:gpt-4o"
_ORG_ID = "default"


def _make_state_with_group_grant(*, group_id: str = _GROUP_ID, model: str = _CLOUD_MODEL):
    """State where group {group_id} has an ALLOW grant for cloud model {model}."""
    alias_store = MagicMock()
    alias_store.get.return_value = None  # no aliases

    perm_store = MagicMock()

    def _grant(resource_type, scope_kind, scope_id, resource_id):
        # Org-level allow grant (required by 6a-perm cloud gate INV-1)
        if scope_kind == "org" and resource_id == model:
            g = MagicMock()
            g.allow = True
            g.opa_policy_ref = "policy/cloud_model_openai_gpt4o"
            return g
        # Group-level allow grant (the W3-008 target)
        if scope_kind == "group" and scope_id == group_id and resource_id == model:
            g = MagicMock()
            g.allow = True
            g.opa_policy_ref = "policy/cloud_model_openai_gpt4o"
            return g
        return None

    perm_store.get_boolean_grant.side_effect = _grant

    state = MagicMock()
    state.opa_url = "http://opa:8181"
    state.ollama_url = "http://ollama:11434"
    state.default_model = "qwen2.5:3b"
    state.optimization_engine = None
    state.sensitivity_classifier = None
    state.complexity_scorer = None
    state.budget_enforcer = None
    state.ddos_protector = None
    state.content_relay_detector = None
    state.model_alias_store = alias_store
    state.available_models = [{"id": "qwen2.5:3b"}]
    state.model_allocation_store = None
    state.audit_writer = None
    state.identity_registry = None
    state.agent_registry = None
    state.pool_manager = None
    state.pii_detector = None
    state.streaming_enabled = False
    state.streaming_inspect_interval = 200
    state.response_inspection_pipeline = None
    state.low_confidence_stepup_threshold = 0.7
    state.permission_strict = False
    state.kms_provider = None
    state._cloud_key_cache = {}
    state.permission_store = perm_store
    # W3-008 fix: explicitly None so the backfill block is skipped in these
    # pre-backfill contract tests (they test the Layer 2 code path directly
    # with groups pre-populated in the identity dict).
    state.rbac_store = None
    return state


def _make_request():
    from fastapi import Request
    req = MagicMock(spec=Request)
    req.method = "POST"
    req.headers = MagicMock()
    req.headers.__iter__ = MagicMock(return_value=iter([]))
    req.headers.items = MagicMock(return_value=[])
    req.headers.get = MagicMock(return_value=None)
    req.state = MagicMock()
    req.state.ysg_principal = None
    return req


# ---------------------------------------------------------------------------
# Test 1 (critical): group-tier grant + populated groups → Layer 2 passes
# This proves the gateway code path is CORRECT when the fixture data is right.
# ---------------------------------------------------------------------------

class TestW3008GroupTierGrantCodePathCorrect:
    """When group membership IS correctly persisted to the identity registry,
    Layer 2's group-tier lookup MUST find the grant and allow the request.
    This proves the gateway code is correct — W3-008 is a fixture bug."""

    @pytest.mark.asyncio
    async def test_group_tier_grant_with_populated_groups_not_422(self):
        """power_user identity has groups=[_GROUP_ID], permission store has
        ALLOW grant for that group on openai:gpt-4o.  Layer 2 MUST pass
        (no 422).  503 (cloud unreachable in unit test) is acceptable."""
        import contextlib
        from fastapi import HTTPException as FastHTTPException
        from fastapi.responses import JSONResponse
        from yashigani.models.effective import EffectiveModels
        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage

        # Identity with group membership CORRECTLY populated
        power_identity = {
            "identity_id": "idnt_power_w3008",
            "kind": "human",
            "groups": [_GROUP_ID],     # correctly populated
            "status": "active",
            "sensitivity_ceiling": "PUBLIC",
        }

        power_eff = EffectiveModels(
            allowed={_CLOUD_MODEL, "qwen2.5:3b"},
            has_restriction=True,
            allocated_aliases={_CLOUD_MODEL},
            gated={_CLOUD_MODEL},
        )

        body = ChatCompletionRequest(
            model=_CLOUD_MODEL,
            messages=[ChatMessage(role="user", content="ping")],
            stream=False,
        )

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._state",
                _make_state_with_group_grant(),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._resolve_identity",
                MagicMock(return_value=power_identity),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._effective_allowed_models",
                MagicMock(return_value=power_eff),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._opa_v1_check",
                AsyncMock(return_value={"allow": True, "model_allowed": True}),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router.evaluate_client_policies",
                AsyncMock(return_value={"allow": True}),
            ))
            from yashigani.gateway.openai_router import chat_completions
            try:
                result = await chat_completions(body, _make_request())
                if isinstance(result, JSONResponse):
                    body_json = json.loads(result.body)
                    code = body_json.get("error", {}).get("code", "")
                    assert result.status_code != 422, (
                        f"W3-008: power_user with correct group membership got 422 "
                        f"(code={code!r}). Gateway group-tier code path is BROKEN. "
                        "Expected: Layer 2 finds the group grant and passes. "
                        f"Body: {result.body}"
                    )
                    assert result.status_code != 403, (
                        f"W3-008: power_user with ALLOW grant got 403 (code={code!r}). "
                        f"Body: {result.body}"
                    )
                    # 200 (with local fallback) or any non-error status is fine
            except FastHTTPException as exc:
                # 503/502 = cloud unreachable in unit test; passed RBAC
                assert exc.status_code not in (422, 403), (
                    f"W3-008: power_user with correct groups: HTTPException "
                    f"{exc.status_code}: {exc.detail!r}. "
                    "Gateway group-tier code path must not deny when data is correct."
                )

    @pytest.mark.asyncio
    async def test_group_tier_loop_fires_when_groups_populated(self):
        """Verify the grant lookup is actually called for the group ID when
        groups is non-empty.  The call to get_boolean_grant for scope_kind='group'
        with the correct group ID MUST be made."""
        import contextlib
        from fastapi import HTTPException as FastHTTPException
        from fastapi.responses import JSONResponse
        from yashigani.models.effective import EffectiveModels
        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage

        power_identity = {
            "identity_id": "idnt_power_w3008b",
            "kind": "human",
            "groups": [_GROUP_ID],
            "status": "active",
            "sensitivity_ceiling": "PUBLIC",
        }
        power_eff = EffectiveModels(
            allowed={_CLOUD_MODEL, "qwen2.5:3b"},
            has_restriction=True,
            allocated_aliases={_CLOUD_MODEL},
            gated={_CLOUD_MODEL},
        )

        state = _make_state_with_group_grant()
        perm_store = state.permission_store

        body = ChatCompletionRequest(
            model=_CLOUD_MODEL,
            messages=[ChatMessage(role="user", content="test")],
            stream=False,
        )

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch("yashigani.gateway.openai_router._state", state))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._resolve_identity",
                MagicMock(return_value=power_identity),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._effective_allowed_models",
                MagicMock(return_value=power_eff),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._opa_v1_check",
                AsyncMock(return_value={"allow": True, "model_allowed": True}),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router.evaluate_client_policies",
                AsyncMock(return_value={"allow": True}),
            ))
            from yashigani.gateway.openai_router import chat_completions
            try:
                await chat_completions(body, _make_request())
            except (FastHTTPException, Exception):
                pass  # 503/etc. fine; we check the call record below

        # The group-tier lookup MUST have been attempted for _GROUP_ID
        calls = perm_store.get_boolean_grant.call_args_list
        group_calls = [
            c for c in calls
            if len(c.args) >= 3 and c.args[1] == "group" and c.args[2] == _GROUP_ID
        ]
        assert group_calls, (
            f"W3-008: get_boolean_grant was never called for scope_kind='group', "
            f"scope_id={_GROUP_ID!r}. The group-tier loop is not firing. "
            f"All calls: {[(c.args, c.kwargs) for c in calls]}"
        )


# ---------------------------------------------------------------------------
# Test 2 (documents fixture-bug state): groups=[] → 422 even with grant
# ---------------------------------------------------------------------------

class TestW3008EmptyGroupsIs422:
    """When groups=[] AND rbac_store=None (backfill disabled), Layer 2's
    group-tier loop iterates nothing → grant not found → 422.  This tests
    the no-backfill fallback: the real fix is in test_w3_008_rbac_backfill.py."""

    @pytest.mark.asyncio
    async def test_empty_groups_no_rbac_store_is_blocked(self):
        """power_user with groups=[] and rbac_store=None gets 422 even though a
        group-tier ALLOW grant exists.  Without the RBAC store wired, the
        backfill block is a no-op → groups stays empty → no grant found → 422.
        This is the 'backfill disabled' baseline; see test_w3_008_rbac_backfill.py
        for the real fix exercised with a live RBACStore."""
        import contextlib
        from fastapi.responses import JSONResponse
        from yashigani.models.effective import EffectiveModels
        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage

        # Simulate the BROKEN state: groups=[] in the identity
        broken_identity = {
            "identity_id": "idnt_power_w3008_broken",
            "kind": "human",
            "groups": [],               # BUG: fixture didn't populate this
            "status": "active",
            "sensitivity_ceiling": "PUBLIC",
        }

        power_eff = EffectiveModels(
            allowed={_CLOUD_MODEL, "qwen2.5:3b"},
            has_restriction=True,
            allocated_aliases={_CLOUD_MODEL},
            gated={_CLOUD_MODEL},
        )

        body = ChatCompletionRequest(
            model=_CLOUD_MODEL,
            messages=[ChatMessage(role="user", content="ping")],
            stream=False,
        )

        # Permission store only has a GROUP-tier grant (org grant absent here
        # so the org-level check also fails to simulate the Layer 2 path)
        perm_store = MagicMock()
        def _grant_group_only(resource_type, scope_kind, scope_id, resource_id):
            # Group-level grant exists but groups=[] so it's never reached
            if scope_kind == "group" and scope_id == _GROUP_ID and resource_id == _CLOUD_MODEL:
                g = MagicMock()
                g.allow = True
                g.opa_policy_ref = "policy/cloud_model"
                return g
            return None  # org and user tiers: no grant
        perm_store.get_boolean_grant.side_effect = _grant_group_only

        alias_store = MagicMock()
        alias_store.get.return_value = None

        state = MagicMock()
        state.opa_url = "http://opa:8181"
        state.ollama_url = "http://ollama:11434"
        state.default_model = "qwen2.5:3b"
        state.optimization_engine = None
        state.sensitivity_classifier = None
        state.complexity_scorer = None
        state.budget_enforcer = None
        state.ddos_protector = None
        state.content_relay_detector = None
        state.model_alias_store = alias_store
        state.available_models = [{"id": "qwen2.5:3b"}]
        state.model_allocation_store = None
        state.audit_writer = None
        state.identity_registry = None
        state.agent_registry = None
        state.pool_manager = None
        state.pii_detector = None
        state.streaming_enabled = False
        state.streaming_inspect_interval = 200
        state.response_inspection_pipeline = None
        state.low_confidence_stepup_threshold = 0.7
        state.permission_strict = False
        state.kms_provider = None
        state._cloud_key_cache = {}
        state.permission_store = perm_store
        # W3-008: None → backfill block is skipped; groups stays []; 422 expected.
        state.rbac_store = None

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch("yashigani.gateway.openai_router._state", state))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._resolve_identity",
                MagicMock(return_value=broken_identity),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._effective_allowed_models",
                MagicMock(return_value=power_eff),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._opa_v1_check",
                AsyncMock(return_value={"allow": True}),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router.evaluate_client_policies",
                AsyncMock(return_value={"allow": True}),
            ))
            from yashigani.gateway.openai_router import chat_completions
            result = await chat_completions(body, _make_request())

        assert isinstance(result, JSONResponse)
        # With groups=[] AND rbac_store=None (backfill disabled), the group-tier
        # loop iterates nothing → no grant found → 422.  This is the expected
        # behaviour when no RBAC store is wired (e.g. in tests or cold-start
        # before Redis is available).  The real fix is exercised with a live
        # RBACStore in test_w3_008_rbac_backfill.py.
        assert result.status_code == 422, (
            f"W3-008 no-backfill baseline: expected 422 when groups=[] and "
            f"rbac_store=None, got {result.status_code}. Body: {result.body}. "
            "If this fails, the backfill fired when it should not have "
            "(rbac_store=None should skip the backfill block entirely)."
        )
        body_json = json.loads(result.body)
        assert body_json["error"]["code"] == "model_not_found"
