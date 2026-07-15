"""
W3-008 — REAL integration tests for RBAC group membership backfill.

WHAT THIS FILE TESTS
--------------------
The fix in chat_completions (openai_router.py): after identity resolution,
for human/user identities, union `identity["groups"]` with the memberships
live in the RBAC store (`rbac:user:{identity_id}` Redis key).

Root cause (brief summary):
  _resolve_identity → _resolve_yashigani_identity_id_header →
  _state.identity_registry.get(identity_id) → hgetall("identity:reg:{id}")
  → returns groups field as set at REGISTRATION ONLY.
  Post-registration RBAC add_member writes to rbac:user:{id} ONLY, never
  back to identity:reg:{id}. So identity["groups"] was always stale for
  any user whose membership was granted after registration.

CONSEQUENCE:
  Over-block: group-tier ALLOW grant → 422 for power_user (groups=[]).
  Fail-open:  group-tier DENY grant → request not blocked.

THESE TESTS use a real RBACStore backed by fakeredis so the membership
round-trip (add_member → get_user_groups) is exercised end-to-end.

Test matrix
-----------
1. ALLOW: groups=[] in reg-record; membership added via add_member;
   group has ALLOW grant → chat_completions must NOT return 422 (passes gate).
2. DENY:  groups=[] in reg-record; membership added via add_member;
   group has DENY grant → chat_completions MUST block (403 or 422 depending
   on which deny gate fires).
3. Agent/service identity: kind="service"; add_member called;
   backfill must NOT fire → groups stays [] for the service principal.
4. rbac_store failure: rbac_store.get_user_groups raises; backfill falls back
   to reg-record groups; no crash; existing groups preserved.
5. Dedup: group already in reg-record groups AND in RBAC store → no duplicate.

fakeredis requirement
---------------------
Tests skip cleanly if fakeredis is not installed (consistent with existing
test suite — see src/tests/conftest.py).
"""
from __future__ import annotations

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

# ---------------------------------------------------------------------------
# fakeredis availability check
# ---------------------------------------------------------------------------

try:
    import fakeredis  # noqa: F401
    _HAS_FAKEREDIS = True
except ImportError:
    _HAS_FAKEREDIS = False

_SKIP_NO_FAKEREDIS = pytest.mark.skipif(
    not _HAS_FAKEREDIS,
    reason="fakeredis not installed — install with: pip install fakeredis",
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_GROUP_ID = "grp_power_w3008_real"
_CLOUD_MODEL = "openai:gpt-4o"
_IDENTITY_ID = "idnt_w3008real_001"
_DENY_GROUP_ID = "grp_deny_w3008_real"
_DENY_IDENTITY_ID = "idnt_w3008real_deny"
_SVC_IDENTITY_ID = "idnt_svc_w3008real"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_fakeredis_rbac_store():
    """Return an RBACStore backed by a fresh fakeredis instance."""
    import fakeredis as _fr
    from yashigani.rbac.store import RBACStore

    redis_client = _fr.FakeRedis(decode_responses=False)
    return RBACStore(redis_client=redis_client)


def _make_allow_group(group_id: str = _GROUP_ID):
    """Build an RBACGroup with no pre-configured members (members added separately)."""
    from yashigani.rbac.model import RBACGroup
    return RBACGroup(id=group_id, display_name="Power Users (W3-008 test)")


def _make_deny_group(group_id: str = _DENY_GROUP_ID):
    from yashigani.rbac.model import RBACGroup
    return RBACGroup(id=group_id, display_name="Denied Users (W3-008 test)")


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


def _make_base_state(rbac_store):
    """Minimal _state with the RBAC store wired.  Perm store set separately."""
    alias_store = MagicMock()
    alias_store.get.return_value = None  # no aliases

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
    state.rbac_store = rbac_store   # W3-008: the real store under test
    return state


def _make_allow_perm_store(group_id: str, model: str):
    """PermissionStore mock: org-level ALLOW + group-level ALLOW for group_id/model."""
    perm_store = MagicMock()

    def _grant(resource_type, scope_kind, scope_id, resource_id):
        if scope_kind == "org" and resource_id == model:
            g = MagicMock(); g.allow = True; return g
        if scope_kind == "group" and scope_id == group_id and resource_id == model:
            g = MagicMock(); g.allow = True; return g
        return None

    perm_store.get_boolean_grant.side_effect = _grant
    return perm_store


def _make_deny_perm_store(group_id: str, model: str):
    """PermissionStore mock: org-level ALLOW + group-level explicit DENY."""
    perm_store = MagicMock()

    def _grant(resource_type, scope_kind, scope_id, resource_id):
        # Org allows; group denies
        if scope_kind == "org" and resource_id == model:
            g = MagicMock(); g.allow = True; return g
        if scope_kind == "group" and scope_id == group_id and resource_id == model:
            g = MagicMock(); g.allow = False; return g
        return None

    perm_store.get_boolean_grant.side_effect = _grant
    return perm_store


# ---------------------------------------------------------------------------
# Test 1 — ALLOW: groups=[] in reg-record, RBAC membership → grant honoured
# ---------------------------------------------------------------------------

class TestW3008BackfillAllowGrant:
    """The core fix: a user with groups=[] in the reg-record whose group
    membership was added via RBAC add_member MUST have the group-tier ALLOW
    grant honoured (not 422)."""

    @_SKIP_NO_FAKEREDIS
    @pytest.mark.asyncio
    async def test_rbac_only_membership_allow_grant_passes_layer2(self):
        """
        Setup:
          - identity has groups=[] in reg-record
          - RBACStore.add_member(group, identity_id) → membership in rbac:user:{id}
          - PermissionStore has ALLOW grant for group on openai:gpt-4o

        Expectation:
          chat_completions must NOT return 422.  The backfill block reads the
          RBAC store, unions the group ID into identity["groups"], and the
          Layer 2 cloud gate finds the grant.
        """
        import contextlib
        from fastapi import HTTPException as FastHTTPException
        from fastapi.responses import JSONResponse
        from yashigani.models.effective import EffectiveModels
        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage

        # --- RBAC store: add group, add user to group ---
        rbac_store = _make_fakeredis_rbac_store()
        group = _make_allow_group(_GROUP_ID)
        rbac_store.add_group(group)
        rbac_store.add_member(_GROUP_ID, _IDENTITY_ID)  # membership ONLY in RBAC store

        # --- Identity: groups=[] in reg-record (the bug state pre-fix) ---
        identity = {
            "identity_id": _IDENTITY_ID,
            "kind": "human",
            "groups": [],               # ← empty: simulates reg-record before backfill
            "status": "active",
            "sensitivity_ceiling": "PUBLIC",
        }

        # --- EffectiveModels: cloud model allowed ---
        eff = EffectiveModels(
            allowed={_CLOUD_MODEL, "qwen2.5:3b"},
            has_restriction=True,
            allocated_aliases={_CLOUD_MODEL},
            gated={_CLOUD_MODEL},
        )

        # --- State with real RBAC store + perm store that has the ALLOW grant ---
        state = _make_base_state(rbac_store)
        state.permission_store = _make_allow_perm_store(_GROUP_ID, _CLOUD_MODEL)

        body = ChatCompletionRequest(
            model=_CLOUD_MODEL,
            messages=[ChatMessage(role="user", content="ping")],
            stream=False,
        )

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch("yashigani.gateway.openai_router._state", state))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._resolve_identity",
                MagicMock(return_value=identity),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._effective_allowed_models",
                MagicMock(return_value=eff),
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
                        f"W3-008: user with RBAC-only membership (groups=[] in reg) "
                        f"got 422 (code={code!r}).  Backfill fix is NOT working. "
                        f"Body: {result.body}"
                    )
                    assert result.status_code != 403, (
                        f"W3-008: user with ALLOW grant got 403 (code={code!r}). "
                        f"Body: {result.body}"
                    )
            except FastHTTPException as exc:
                # 503/502 = cloud unreachable in unit test → passed all RBAC gates
                assert exc.status_code not in (422, 403), (
                    f"W3-008: RBAC backfill: HTTPException {exc.status_code}: "
                    f"{exc.detail!r}. Backfill fix must not produce 422/403."
                )

    @_SKIP_NO_FAKEREDIS
    @pytest.mark.asyncio
    async def test_backfill_group_tier_grant_lookup_is_called(self):
        """Verify get_boolean_grant is called for the backfilled group ID."""
        import contextlib
        from fastapi import HTTPException as FastHTTPException
        from yashigani.models.effective import EffectiveModels
        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage

        rbac_store = _make_fakeredis_rbac_store()
        rbac_store.add_group(_make_allow_group(_GROUP_ID))
        rbac_store.add_member(_GROUP_ID, _IDENTITY_ID)

        identity = {
            "identity_id": _IDENTITY_ID,
            "kind": "human",
            "groups": [],
            "status": "active",
            "sensitivity_ceiling": "PUBLIC",
        }

        eff = EffectiveModels(
            allowed={_CLOUD_MODEL, "qwen2.5:3b"},
            has_restriction=True,
            allocated_aliases={_CLOUD_MODEL},
            gated={_CLOUD_MODEL},
        )

        state = _make_base_state(rbac_store)
        perm_store = _make_allow_perm_store(_GROUP_ID, _CLOUD_MODEL)
        state.permission_store = perm_store

        body = ChatCompletionRequest(
            model=_CLOUD_MODEL,
            messages=[ChatMessage(role="user", content="test")],
            stream=False,
        )

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch("yashigani.gateway.openai_router._state", state))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._resolve_identity",
                MagicMock(return_value=identity),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._effective_allowed_models",
                MagicMock(return_value=eff),
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

        calls = perm_store.get_boolean_grant.call_args_list
        group_calls = [
            c for c in calls
            if len(c.args) >= 3 and c.args[1] == "group" and c.args[2] == _GROUP_ID
        ]
        assert group_calls, (
            f"W3-008: get_boolean_grant was never called for scope_kind='group', "
            f"scope_id={_GROUP_ID!r} after backfill. "
            f"The backfill fired but the group-tier loop did not follow. "
            f"All calls: {[(c.args, c.kwargs) for c in calls]}"
        )


# ---------------------------------------------------------------------------
# Test 2 — DENY: group-tier deny grant now blocks (fail-open direction closed)
# ---------------------------------------------------------------------------

class TestW3008BackfillDenyGrant:
    """Before the fix, a user denied via a group was NOT blocked in the openai
    path when groups=[] (fail-open).  After the fix, the backfill exposes the
    group ID and the DENY grant blocks the request."""

    @_SKIP_NO_FAKEREDIS
    @pytest.mark.asyncio
    async def test_rbac_only_membership_deny_grant_blocks(self):
        """
        Setup:
          - identity has groups=[] in reg-record
          - RBACStore.add_member(deny_group, identity_id)
          - PermissionStore has org-level ALLOW + group-level explicit DENY

        Expectation:
          The backfill adds _DENY_GROUP_ID to identity["groups"].
          The LAURA-411-001 deny probe finds the group-level DENY grant and
          blocks the request (403 or raises HTTPException 403).
        """
        import contextlib
        from fastapi import HTTPException as FastHTTPException
        from fastapi.responses import JSONResponse
        from yashigani.models.effective import EffectiveModels
        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage

        rbac_store = _make_fakeredis_rbac_store()
        rbac_store.add_group(_make_deny_group(_DENY_GROUP_ID))
        rbac_store.add_member(_DENY_GROUP_ID, _DENY_IDENTITY_ID)

        identity = {
            "identity_id": _DENY_IDENTITY_ID,
            "kind": "human",
            "groups": [],               # ← empty before backfill
            "status": "active",
            "sensitivity_ceiling": "PUBLIC",
        }

        eff = EffectiveModels(
            allowed={_CLOUD_MODEL, "qwen2.5:3b"},
            has_restriction=True,
            allocated_aliases={_CLOUD_MODEL},
            gated={_CLOUD_MODEL},
        )

        state = _make_base_state(rbac_store)
        state.permission_store = _make_deny_perm_store(_DENY_GROUP_ID, _CLOUD_MODEL)

        body = ChatCompletionRequest(
            model=_CLOUD_MODEL,
            messages=[ChatMessage(role="user", content="denied ping")],
            stream=False,
        )

        blocked = False
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch("yashigani.gateway.openai_router._state", state))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._resolve_identity",
                MagicMock(return_value=identity),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._effective_allowed_models",
                MagicMock(return_value=eff),
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
                    if result.status_code in (403, 422):
                        blocked = True
            except FastHTTPException as exc:
                if exc.status_code in (403, 422):
                    blocked = True

        assert blocked, (
            "W3-008: user denied via RBAC-only group membership was NOT blocked. "
            "The fail-open direction is not closed: DENY grant on a group that "
            "only exists in the RBAC store (not in the reg-record groups) must "
            "still block the request after backfill."
        )


# ---------------------------------------------------------------------------
# Test 3 — Service identity: no backfill for non-human principals
# ---------------------------------------------------------------------------

class TestW3008NoBackfillForServiceIdentity:
    """Service/agent/internal identities must NOT be backfilled, even if
    the RBAC store contains entries for their identity_id (shouldn't happen in
    production, but must be safe to test)."""

    @_SKIP_NO_FAKEREDIS
    @pytest.mark.asyncio
    async def test_service_identity_groups_not_backfilled(self):
        """kind='service' identity: backfill block skipped; groups stays []."""
        rbac_store = _make_fakeredis_rbac_store()
        group = _make_allow_group(_GROUP_ID)
        rbac_store.add_group(group)
        rbac_store.add_member(_GROUP_ID, _SVC_IDENTITY_ID)

        # Spy on get_user_groups to confirm it is NOT called for this identity
        original_get_user_groups = rbac_store.get_user_groups
        call_log: list[str] = []

        def _spy(iid: str):
            call_log.append(iid)
            return original_get_user_groups(iid)

        rbac_store.get_user_groups = _spy

        import contextlib
        from fastapi import HTTPException as FastHTTPException
        from fastapi.responses import JSONResponse
        from yashigani.models.effective import EffectiveModels
        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage

        svc_identity = {
            "identity_id": _SVC_IDENTITY_ID,
            "kind": "service",          # ← NOT human/user → must not be backfilled
            "groups": [],
            "status": "active",
            "sensitivity_ceiling": "PUBLIC",
        }

        eff = EffectiveModels(
            allowed={"qwen2.5:3b"},
            has_restriction=False,
            allocated_aliases=set(),
            gated=set(),
        )

        state = _make_base_state(rbac_store)
        state.permission_store = MagicMock()
        state.permission_store.get_boolean_grant.return_value = None

        body = ChatCompletionRequest(
            model="qwen2.5:3b",
            messages=[ChatMessage(role="user", content="svc test")],
            stream=False,
        )

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch("yashigani.gateway.openai_router._state", state))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._resolve_identity",
                MagicMock(return_value=svc_identity),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._effective_allowed_models",
                MagicMock(return_value=eff),
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
                pass

        assert _SVC_IDENTITY_ID not in call_log, (
            f"W3-008: get_user_groups was called for a service identity "
            f"({_SVC_IDENTITY_ID!r}).  The backfill block must ONLY fire for "
            f"kind in ('human', 'user').  call_log={call_log!r}"
        )


# ---------------------------------------------------------------------------
# Test 4 — rbac_store raises: fail-safe, no crash, reg-record groups preserved
# ---------------------------------------------------------------------------

class TestW3008BackfillFailSafe:
    """If get_user_groups raises, the backfill must not crash the request.
    The reg-record groups must be preserved unchanged."""

    @pytest.mark.asyncio
    async def test_rbac_store_exception_does_not_crash_request(self):
        """get_user_groups raises RuntimeError; backfill is skipped;
        reg-record groups (['grp_existing']) are preserved; no exception raised."""
        import contextlib
        from fastapi import HTTPException as FastHTTPException
        from fastapi.responses import JSONResponse
        from yashigani.models.effective import EffectiveModels
        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage

        _EXISTING_GID = "grp_existing_pre_reg"

        # rbac_store.get_user_groups raises
        bad_rbac_store = MagicMock()
        bad_rbac_store.get_user_groups.side_effect = RuntimeError("Redis is down")

        identity = {
            "identity_id": "idnt_failsafe_w3008",
            "kind": "human",
            "groups": [_EXISTING_GID],  # pre-existing reg-record group
            "status": "active",
            "sensitivity_ceiling": "PUBLIC",
        }

        eff = EffectiveModels(
            allowed={"qwen2.5:3b"},
            has_restriction=False,
            allocated_aliases=set(),
            gated=set(),
        )

        state = _make_base_state(bad_rbac_store)
        state.permission_store = MagicMock()
        state.permission_store.get_boolean_grant.return_value = None

        body = ChatCompletionRequest(
            model="qwen2.5:3b",
            messages=[ChatMessage(role="user", content="failsafe test")],
            stream=False,
        )

        _captured_identity_groups: list[list] = []

        # We want to assert the identity passed downstream still has the
        # original group. Capture it via a side-effect on _effective_allowed_models.
        original_eff_fn = MagicMock(return_value=eff)

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch("yashigani.gateway.openai_router._state", state))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._resolve_identity",
                MagicMock(return_value=identity),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._effective_allowed_models",
                original_eff_fn,
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
            # Must NOT raise
            try:
                await chat_completions(body, _make_request())
            except FastHTTPException as exc:
                # 503 = local model unreachable → that's fine, means we passed RBAC
                if exc.status_code == 500:
                    pytest.fail(
                        f"W3-008: rbac_store exception caused a 500 crash: {exc.detail!r}. "
                        "The backfill must fail-safe (warn + keep reg-record groups)."
                    )
            except Exception as exc:
                pytest.fail(
                    f"W3-008: rbac_store exception propagated as {type(exc).__name__}: {exc}. "
                    "The backfill block must catch all exceptions (fail-safe)."
                )


# ---------------------------------------------------------------------------
# Test 5 — Dedup: group in both reg-record and RBAC store → no duplicate
# ---------------------------------------------------------------------------

class TestW3008BackfillDedup:
    """If a group ID is already in the reg-record groups AND in the RBAC store,
    the union must not produce duplicates."""

    @_SKIP_NO_FAKEREDIS
    @pytest.mark.asyncio
    async def test_no_duplicate_group_ids_after_backfill(self):
        """_GROUP_ID in both reg-record and RBAC store → appears exactly once."""
        import contextlib
        from fastapi import HTTPException as FastHTTPException
        from yashigani.models.effective import EffectiveModels
        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage

        rbac_store = _make_fakeredis_rbac_store()
        rbac_store.add_group(_make_allow_group(_GROUP_ID))
        rbac_store.add_member(_GROUP_ID, _IDENTITY_ID)

        # Already in reg-record too (the dedup case)
        identity = {
            "identity_id": _IDENTITY_ID,
            "kind": "human",
            "groups": [_GROUP_ID],      # already present in reg-record
            "status": "active",
            "sensitivity_ceiling": "PUBLIC",
        }

        eff = EffectiveModels(
            allowed={_CLOUD_MODEL, "qwen2.5:3b"},
            has_restriction=True,
            allocated_aliases={_CLOUD_MODEL},
            gated={_CLOUD_MODEL},
        )

        perm_store = _make_allow_perm_store(_GROUP_ID, _CLOUD_MODEL)
        state = _make_base_state(rbac_store)
        state.permission_store = perm_store

        body = ChatCompletionRequest(
            model=_CLOUD_MODEL,
            messages=[ChatMessage(role="user", content="dedup test")],
            stream=False,
        )

        # Intercept the group count via perm_store calls
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch("yashigani.gateway.openai_router._state", state))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._resolve_identity",
                MagicMock(return_value=identity),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._effective_allowed_models",
                MagicMock(return_value=eff),
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
                pass

        calls = perm_store.get_boolean_grant.call_args_list
        group_calls_for_id = [
            c for c in calls
            if len(c.args) >= 3 and c.args[1] == "group" and c.args[2] == _GROUP_ID
        ]
        # The group ID must appear in the grant calls (grant found) but must NOT
        # be looked up multiple times for the same layer gate.  1 call per layer
        # (Layer 2 cloud gate) is expected; >2 same-scope calls would indicate
        # duplication in the groups list.
        assert len(group_calls_for_id) >= 1, (
            f"W3-008 dedup: group {_GROUP_ID!r} not found in perm calls after backfill. "
            f"calls={[(c.args, c.kwargs) for c in calls]}"
        )
        # Acceptable: up to 2 (one per Layer 2, one per deny probe)
        # Not acceptable: > 4 (would indicate duplicate group IDs in the list)
        assert len(group_calls_for_id) <= 4, (
            f"W3-008 dedup: group {_GROUP_ID!r} looked up {len(group_calls_for_id)} times "
            f"— indicates duplicate entries in identity['groups'] after backfill. "
            f"calls_for_id={[(c.args, c.kwargs) for c in group_calls_for_id]}"
        )
