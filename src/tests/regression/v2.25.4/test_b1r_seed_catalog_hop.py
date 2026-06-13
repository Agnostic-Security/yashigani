"""
Regression — LAURA-B1R-001: orchestrate-seed model-RBAC bypass + comprehensive
single-authority enforcement across ALL model-selection entry points.

THE BYPASS (Laura, proven live, no forged header): a restricted user adds
``"orchestrate": true`` to reach a non-allocated model.  fastuser (allocated
{fast, llama3.2:3b}) → orchestrate seed on qwen2.5:3b (gated, allocated only to
group ``brains``) → previously SERVED because:

  • ``_adjudicate_seed_prompt`` called ``_opa_v1_check`` WITHOUT the effective
    allowlist → OPA saw the identity's RAW allowed_models ([] for allocation-based
    callers) → empty == no-restriction → model_allowed=True; AND
  • the orchestrate path returns from ``run_orchestration`` BEFORE the chat-egress
    alloc-bind + OPA backstop, so neither second layer fired; AND
  • ``build_tool_catalog`` exposed ``model__qwen2_5_3b`` as a callable tool to
    fastuser (the same effective-allowlist gap in catalog projection); AND
  • ``_orchestration_self_call`` exempted the principal-bearing model tool-hop
    from the chat-egress alloc-bind, so a hop to a non-allocated model was served.

THE FIX — ONE model-RBAC authority (``models.effective.model_denied_for_caller``
via the gateway ``model_denied_for_caller`` choke point) applied at EVERY entry:
  1. chat egress (alloc-bind + OPA backstop) — exemption is the SERVER-MINTED
     brain-reasoning leg ONLY (NOT ``_orchestration_self_call``);
  2. orchestration seed — explicit deny + effective allowlist into OPA;
  3. tool-catalog projection — ``model__*`` only for allocated models;
  4. model-tool hop execution — explicit deny before the self-call.

These tests exercise the pure authority + the catalog/hop projection with
fakeredis (no live stack).  The live A/B re-gate (fastuser+orchestrate=true →
403) is captured under testing_runs/.../seed-catalog-fix/.
"""
from __future__ import annotations

import fakeredis
import pytest

from yashigani.models.alias_store import ModelAlias, ModelAliasStore
from yashigani.models.allocation_store import ModelAllocationStore
from yashigani.models.effective import (
    model_denied_for_caller,
    resolve_effective_allowed_models,
)
from yashigani.gateway.tool_catalog import build_tool_catalog


# ── Fixtures: mirror Laura's live seed (fast→llama3.2, coder→qwen-coder,
#    brainy→qwen2.5:3b allocated ONLY to group 'brains' so it is GATED) ─────────

@pytest.fixture
def redis():
    return fakeredis.FakeRedis()


@pytest.fixture
def alias_store(redis):
    s = ModelAliasStore(redis_client=redis)
    s.set("fast", ModelAlias(alias="fast", provider="ollama", model="llama3.2:3b", force_local=True))
    s.set("coder", ModelAlias(alias="coder", provider="ollama", model="qwen2.5-coder:3b", force_local=True))
    s.set("brainy", ModelAlias(alias="brainy", provider="ollama", model="qwen2.5:3b", force_local=True))
    s.set("smart", ModelAlias(alias="smart", provider="anthropic", model="claude-sonnet-4-6"))
    return s


@pytest.fixture
def alloc_store(redis):
    s = ModelAllocationStore(redis_client=redis)
    s.add("fast", "user", "fastuser")
    s.add("coder", "user", "coderuser")
    s.add("brainy", "group", "brains")     # qwen2.5:3b gated to 'brains' only
    s.add("smart", "group", "cloudies")    # claude-sonnet-4-6 gated to 'cloudies'
    return s


def _fastuser():
    # Allocation-based caller: empty RAW allowed_models — restriction comes from
    # the allocation store (exactly the shape that defeated the OLD seed gate).
    return {"identity_id": "fid", "slug": "fastuser", "status": "active",
            "kind": "human", "groups": [], "allowed_models": []}


def _coderuser():
    return {"identity_id": "cid", "slug": "coderuser", "status": "active",
            "kind": "human", "groups": [], "allowed_models": []}


# ── 1. The single authority: model_denied_for_caller ─────────────────────────

class TestChokePointAuthority:
    def test_fastuser_denied_gated_brain_model(self, alloc_store, alias_store):
        denied, eff = model_denied_for_caller(
            _fastuser(), "qwen2.5:3b", alloc_store, alias_store, brain_leg=False)
        assert denied is True
        assert "llama3.2:3b" in eff.allowed
        assert "qwen2.5:3b" not in eff.allowed

    def test_fastuser_allowed_own_allocated_concrete(self, alloc_store, alias_store):
        denied, _ = model_denied_for_caller(
            _fastuser(), "llama3.2:3b", alloc_store, alias_store, brain_leg=False)
        assert denied is False

    def test_fastuser_denied_other_users_model(self, alloc_store, alias_store):
        # qwen2.5-coder:3b is allocated to coderuser only → denied to fastuser.
        denied, _ = model_denied_for_caller(
            _fastuser(), "qwen2.5-coder:3b", alloc_store, alias_store, brain_leg=False)
        assert denied is True

    def test_fastuser_denied_cloud_model(self, alloc_store, alias_store):
        denied, _ = model_denied_for_caller(
            _fastuser(), "claude-sonnet-4-6", alloc_store, alias_store, brain_leg=False)
        assert denied is True

    def test_brain_leg_exemption_allows_gated_model(self, alloc_store, alias_store):
        # The SERVER-MINTED brain-reasoning leg (internal identity) legitimately
        # runs the gated brain model — exempt so orchestration completes.
        internal = {"identity_id": "internal", "status": "active", "kind": "service",
                    "groups": [], "allowed_models": []}
        denied, _ = model_denied_for_caller(
            internal, "qwen2.5:3b", alloc_store, alias_store, brain_leg=True)
        assert denied is False
        # But WITHOUT the brain-leg marker, internal is denied the gated model.
        denied2, _ = model_denied_for_caller(
            internal, "qwen2.5:3b", alloc_store, alias_store, brain_leg=False)
        assert denied2 is True


# ── 2. Tool-catalog projection: non-allocated model__* must NOT appear ───────

class TestCatalogProjection:
    def _available(self):
        return [
            {"id": "llama3.2:3b", "owned_by": "ollama"},
            {"id": "qwen2.5:3b", "owned_by": "ollama"},
            {"id": "qwen2.5-coder:3b", "owned_by": "ollama"},
        ]

    def test_fastuser_catalog_excludes_non_allocated_models(self, alloc_store, alias_store):
        eff = resolve_effective_allowed_models(_fastuser(), alloc_store, alias_store)
        cat = build_tool_catalog(
            identity=_fastuser(), agent_registry=None,
            available_models=self._available(), default_model="llama3.2:3b",
            effective=eff,
        )
        names = set(cat.name_map.keys())
        # Allocated model present; gated/other-user models absent.
        assert "model__llama3_2_3b" in names
        assert "model__qwen2_5_3b" not in names          # gated brain model
        assert "model__qwen2_5_coder_3b" not in names    # coderuser's model

    def test_coderuser_catalog_only_own_allocated(self, alloc_store, alias_store):
        eff = resolve_effective_allowed_models(_coderuser(), alloc_store, alias_store)
        cat = build_tool_catalog(
            identity=_coderuser(), agent_registry=None,
            available_models=self._available(), default_model="llama3.2:3b",
            effective=eff,
        )
        names = set(cat.name_map.keys())
        assert "model__qwen2_5_coder_3b" in names
        assert "model__qwen2_5_3b" not in names
        assert "model__llama3_2_3b" not in names

    def test_no_effective_falls_back_to_legacy(self, alloc_store, alias_store):
        # effective=None ⇒ legacy raw-allowed_models projection (empty == all).
        ident = {"identity_id": "x", "status": "active", "groups": [], "allowed_models": []}
        cat = build_tool_catalog(
            identity=ident, agent_registry=None,
            available_models=self._available(), default_model="llama3.2:3b",
            effective=None,
        )
        # Legacy behaviour: empty raw allowed_models == all local models exposed.
        assert "model__qwen2_5_3b" in set(cat.name_map.keys())


# ── 3. Model-tool hop deny: the executor refuses a non-allocated concrete model
#       even if its tool name is forced (crafted tool_call / stale catalog) ────

class TestModelHopDeny:
    def test_hop_to_non_allocated_model_denied(self, alloc_store, alias_store, monkeypatch):
        import yashigani.gateway.orchestrator as orch

        # Stand-in _state with our fakeredis-backed stores so the gateway choke
        # point resolves the SAME effective allocation.
        class _State:
            model_allocation_store = alloc_store
            model_alias_store = alias_store
        monkeypatch.setattr("yashigani.gateway.openai_router._state", _State(), raising=False)

        from yashigani.gateway.tool_catalog import CatalogEntry, ToolCatalog
        # A crafted catalog naming the gated brain model as a model tool.
        catalog = ToolCatalog(
            tools=[],
            name_map={"model__qwen2_5_3b": CatalogEntry(kind="model", target="qwen2.5:3b")},
        )

        async def _run():
            return await orch._execute_tool_call(
                tool_name="model__qwen2_5_3b", args={"task": "hi"},
                catalog=catalog, identity=_fastuser(), depth=1, root_rid="r")

        import asyncio
        result = asyncio.run(_run())
        assert result.blocked is True
        assert result.http_status == 403
        assert result.block_source == "model_rbac"

    def test_hop_to_allocated_model_not_blocked_by_rbac(self, alloc_store, alias_store, monkeypatch):
        # An ALLOCATED model must NOT be blocked by the model-RBAC hop gate.  We
        # stop before the self-call (network) by asserting the deny path is not
        # taken: model_denied_for_caller returns False for the allocated concrete.
        denied, _ = model_denied_for_caller(
            _fastuser(), "llama3.2:3b", alloc_store, alias_store, brain_leg=False)
        assert denied is False


# ── 4. Orchestration-seed gate: fastuser+orchestrate on the gated brain model
#       is DENIED before the brain runs (the core LAURA-B1R-001 fix) ───────────

class TestSeedGateDeny:
    def _state(self, alloc_store, alias_store):
        class _Cls:
            model_allocation_store = alloc_store
            model_alias_store = alias_store
            sensitivity_classifier = None  # PUBLIC, skip
            pii_detector = None
        return _Cls()

    def _body(self, model):
        class _Msg:
            def __init__(self, c):
                self.content = c
        class _Body:
            messages = [_Msg("threat-model this please")]
        b = _Body()
        b.model = model
        return b

    def test_fastuser_seed_on_gated_brain_denied(self, alloc_store, alias_store, monkeypatch):
        import asyncio
        import yashigani.gateway.orchestrator as orch
        import yashigani.gateway.openai_router as oair

        monkeypatch.setattr(oair, "_state", self._state(alloc_store, alias_store), raising=False)
        # is_brain_reasoning_leg must be False for a real principal.
        monkeypatch.setattr(oair, "is_brain_reasoning_leg", lambda ident, m: False)

        # If the gate is correct it DENIES via the choke point BEFORE OPA; assert
        # OPA is never reached on the deny path (would be a real network call).
        async def _boom_opa(**kw):  # pragma: no cover - must not be called
            raise AssertionError("OPA must not be reached: seed RBAC denies first")
        monkeypatch.setattr(oair, "_opa_v1_check", _boom_opa)

        async def _run():
            return await orch._adjudicate_seed_prompt(
                body=self._body("qwen2.5:3b"), identity=_fastuser(),
                request_id="rid", orchestrator_model="qwen2.5:3b")
        resp = asyncio.run(_run())
        assert resp is not None
        assert resp.status_code == 403
        assert resp.headers.get("X-Yashigani-OPA-Reason") == "model_not_allocated"

    def test_brain_leg_seed_not_denied_by_rbac(self, alloc_store, alias_store, monkeypatch):
        # The genuine internal brain-reasoning leg passes the RBAC gate and reaches
        # OPA (which, with effective=None, permits the brain model).
        import asyncio
        import yashigani.gateway.orchestrator as orch
        import yashigani.gateway.openai_router as oair

        monkeypatch.setattr(oair, "_state", self._state(alloc_store, alias_store), raising=False)
        monkeypatch.setattr(oair, "is_brain_reasoning_leg", lambda ident, m: True)

        seen = {}

        async def _ok_opa(**kw):
            seen["effective"] = kw.get("effective_allowed_models", "MISSING")
            return {"allow": True, "model_allowed": True, "routing_safe": True,
                    "sensitivity_allowed": True, "reason": ""}
        monkeypatch.setattr(oair, "_opa_v1_check", _ok_opa)

        internal = {"identity_id": "internal", "status": "active", "kind": "service",
                    "groups": [], "allowed_models": []}

        async def _run():
            return await orch._adjudicate_seed_prompt(
                body=self._body("qwen2.5:3b"), identity=internal,
                request_id="rid", orchestrator_model="qwen2.5:3b")
        resp = asyncio.run(_run())
        assert resp is None  # proceeds
        # Brain leg feeds effective=None so OPA keeps legacy permit for internal.
        assert seen["effective"] is None
