"""
Unit tests for Track B1 — model-allocation persistence + effective-allowed-models
resolution + input validation.

Covers:
  • ModelAllocationStore: persist, list, delete, scope queries, restart replay.
  • resolve_effective_allowed_models: own allowed_models ∪ org/group/user
    allocations, alias→concrete expansion, deny-by-default empty-scope semantics,
    fail-closed on store blip.
  • ResourcePatternIn input validation (method allowlist + path_glob caps).

Uses fakeredis — no live Redis required.
"""
from __future__ import annotations

import fakeredis
import pytest

from yashigani.models.alias_store import ModelAlias, ModelAliasStore
from yashigani.models.allocation_store import ModelAllocationStore
from yashigani.models.effective import (
    EffectiveModels,
    resolve_effective_allowed_models,
)


# ── Fixtures ──────────────────────────────────────────────────────────────

@pytest.fixture
def redis():
    return fakeredis.FakeRedis()


@pytest.fixture
def alloc_store(redis):
    return ModelAllocationStore(redis_client=redis)


@pytest.fixture
def alias_store(redis):
    s = ModelAliasStore(redis_client=redis)
    # Two aliases mapping to distinct concrete models.
    s.set("fast", ModelAlias(alias="fast", provider="ollama", model="qwen2.5:3b", force_local=True))
    s.set("smart", ModelAlias(alias="smart", provider="anthropic", model="claude-sonnet-4-6"))
    return s


# ── Persistence ────────────────────────────────────────────────────────────

class TestAllocationPersistence:
    def test_add_and_list(self, alloc_store):
        a = alloc_store.add("fast", "group", "analysts")
        assert a.id
        rows = alloc_store.list_all()
        assert len(rows) == 1
        assert rows[0].model_alias == "fast"
        assert rows[0].target_type == "group"
        assert rows[0].target_id == "analysts"

    def test_invalid_target_type_rejected(self, alloc_store):
        with pytest.raises(ValueError):
            alloc_store.add("fast", "department", "x")

    def test_delete(self, alloc_store):
        a = alloc_store.add("fast", "user", "alice")
        assert alloc_store.delete(a.id) is True
        assert alloc_store.list_all() == []
        # second delete is a no-op
        assert alloc_store.delete(a.id) is False

    def test_survives_restart(self, redis):
        s1 = ModelAllocationStore(redis_client=redis)
        s1.add("smart", "org", "acme")
        s1.add("fast", "group", "eng")
        # New store over the SAME redis = restart replay.
        s2 = ModelAllocationStore(redis_client=redis)
        rows = {(r.model_alias, r.target_type, r.target_id) for r in s2.list_all()}
        assert ("smart", "org", "acme") in rows
        assert ("fast", "group", "eng") in rows

    def test_live_cross_process_visibility(self, redis):
        # Mirrors backoffice(write) vs gateway(read) as separate processes
        # sharing one Redis: a write via store A is visible to store B WITHOUT
        # reconstruction, because scope queries read Redis live.
        writer = ModelAllocationStore(redis_client=redis)
        reader = ModelAllocationStore(redis_client=redis)
        assert reader.aliases_for_scope("group", "eng") == set()
        writer.add("fast", "group", "eng")
        # reader's in-memory cache never saw the add, but the live read does.
        assert reader.aliases_for_scope("group", "eng") == {"fast"}
        assert reader.scope_has_allocation("group", "eng") is True

    def test_scope_queries(self, alloc_store):
        alloc_store.add("fast", "group", "eng")
        alloc_store.add("smart", "group", "eng")
        assert alloc_store.aliases_for_scope("group", "eng") == {"fast", "smart"}
        assert alloc_store.scope_has_allocation("group", "eng") is True
        assert alloc_store.scope_has_allocation("group", "sales") is False

    def test_to_opa_document(self, alloc_store):
        alloc_store.add("fast", "group", "eng")
        alloc_store.add("smart", "org", "acme")
        doc = alloc_store.to_opa_document()
        assert doc["by_scope"]["group"]["eng"] == ["fast"]
        assert doc["by_scope"]["org"]["acme"] == ["smart"]


# ── Durable mirror + reconcile (restart survival) ───────────────────────────

class _FakeDurable:
    """In-memory stand-in for AllocationDurableStore (Postgres mirror)."""
    def __init__(self):
        self.rows = {}  # alloc_id -> dict
    def upsert(self, alloc_id, model_alias, target_type, target_id):
        self.rows[alloc_id] = {"id": alloc_id, "model_alias": model_alias,
                               "target_type": target_type, "target_id": target_id}
    def delete(self, alloc_id):
        self.rows.pop(alloc_id, None)
    def list_all(self):
        return list(self.rows.values())


class TestDurableMirrorAndReconcile:
    def test_dual_write_to_durable(self, redis):
        dur = _FakeDurable()
        store = ModelAllocationStore(redis_client=redis, durable_store=dur)
        a = store.add("fast", "group", "eng")
        assert dur.rows[a.id]["model_alias"] == "fast"
        store.delete(a.id)
        assert a.id not in dur.rows

    def test_reconcile_restores_after_redis_wipe(self, redis):
        from yashigani.models.allocation_durable_store import reconcile_allocations_from_durable
        dur = _FakeDurable()
        s1 = ModelAllocationStore(redis_client=redis, durable_store=dur)
        a1 = s1.add("fast", "group", "eng")
        a2 = s1.add("smart", "org", "acme")
        # Simulate a redis wipe: fresh fakeredis, durable rows intact.
        wiped = fakeredis.FakeRedis()
        s2 = ModelAllocationStore(redis_client=wiped, durable_store=dur)
        assert s2.list_all() == []  # redis empty
        n = reconcile_allocations_from_durable(s2, dur)
        assert n == 2
        rows = {(a.model_alias, a.target_type, a.target_id) for a in s2.list_all()}
        assert ("fast", "group", "eng") in rows
        assert ("smart", "org", "acme") in rows
        # Restored allocations keep their original ids (no duplicate durable rows).
        assert {a.id for a in s2.list_all()} == {a1.id, a2.id}

    def test_reconcile_idempotent(self, redis):
        from yashigani.models.allocation_durable_store import reconcile_allocations_from_durable
        dur = _FakeDurable()
        store = ModelAllocationStore(redis_client=redis, durable_store=dur)
        store.add("fast", "group", "eng")
        # Reconcile against the SAME store — nothing to restore.
        assert reconcile_allocations_from_durable(store, dur) == 0

    def test_restore_keeps_id_and_bumps_counter(self, redis):
        store = ModelAllocationStore(redis_client=redis)
        store.restore("7", "fast", "group", "eng")
        assert {a.id for a in store.list_all()} == {"7"}
        # A subsequent add() must not reuse id 7.
        a = store.add("smart", "org", "acme")
        assert a.id == "8"


# ── Effective-allowed-models resolution ─────────────────────────────────────

class TestEffectiveResolution:
    def test_none_identity(self, alloc_store, alias_store):
        eff = resolve_effective_allowed_models(None, alloc_store, alias_store)
        assert eff.allowed == set()
        assert eff.has_restriction is False

    def test_no_allocation_no_own_is_unrestricted(self, alloc_store, alias_store):
        ident = {"identity_id": "u1", "groups": ["eng"], "org_id": "acme", "allowed_models": []}
        eff = resolve_effective_allowed_models(ident, alloc_store, alias_store)
        assert eff.has_restriction is False
        assert eff.gated == set()
        assert eff.to_opa_allowed_models() is None  # None == legacy "all"
        assert eff.is_model_denied("anything") is False

    def test_own_allowed_models_restricts(self, alloc_store, alias_store):
        ident = {"identity_id": "u1", "groups": [], "allowed_models": ["qwen2.5:3b"]}
        eff = resolve_effective_allowed_models(ident, alloc_store, alias_store)
        assert eff.has_restriction is True
        assert "qwen2.5:3b" in eff.allowed

    def test_group_allocation_expands_to_concrete(self, alloc_store, alias_store):
        alloc_store.add("fast", "group", "eng")
        ident = {"identity_id": "u1", "groups": ["eng"], "org_id": "", "allowed_models": []}
        eff = resolve_effective_allowed_models(ident, alloc_store, alias_store)
        assert eff.has_restriction is True
        # carries BOTH alias name and concrete model
        assert "fast" in eff.allowed
        assert "qwen2.5:3b" in eff.allowed
        # the non-allocated alias's concrete model is NOT present
        assert "claude-sonnet-4-6" not in eff.allowed

    def test_org_and_user_allocations_unioned(self, alloc_store, alias_store):
        alloc_store.add("fast", "org", "acme")
        alloc_store.add("smart", "user", "u1")
        ident = {"identity_id": "u1", "groups": [], "org_id": "acme", "allowed_models": []}
        eff = resolve_effective_allowed_models(ident, alloc_store, alias_store)
        assert {"fast", "qwen2.5:3b", "smart", "claude-sonnet-4-6"} <= eff.allowed

    def test_user_matched_by_email(self, alloc_store, alias_store):
        alloc_store.add("smart", "user", "alice@corp.example")
        ident = {
            "identity_id": "idnt_1", "slug": "alice", "groups": [], "org_id": "",
            "allowed_models": [], "_owui_email": "alice@corp.example",
        }
        eff = resolve_effective_allowed_models(ident, alloc_store, alias_store)
        assert "claude-sonnet-4-6" in eff.allowed

    def test_outsider_denied_globally_gated_model(self, alloc_store, alias_store):
        # 'fast' is allocated ONLY to group "eng"; caller is in "sales".
        alloc_store.add("fast", "group", "eng")
        ident = {"identity_id": "u2", "groups": ["sales"], "org_id": "", "allowed_models": []}
        eff = resolve_effective_allowed_models(ident, alloc_store, alias_store)
        # The caller's OWN scopes carry no allocation → not "restricted" to an
        # allowlist, BUT 'fast'/qwen2.5:3b are globally GATED and not allocated to
        # the caller, so they are denied.  Non-gated models stay open.
        assert eff.has_restriction is False
        assert "qwen2.5:3b" in eff.gated and "fast" in eff.gated
        assert eff.is_model_denied("fast") is True
        assert eff.is_model_denied("qwen2.5:3b") is True
        assert eff.is_model_denied("some-other-model") is False  # not gated → open

    def test_insider_allowed_outsider_denied_same_model(self, alloc_store, alias_store):
        alloc_store.add("fast", "group", "eng")
        insider = {"identity_id": "u1", "groups": ["eng"], "allowed_models": []}
        outsider = {"identity_id": "u2", "groups": ["sales"], "allowed_models": []}
        ei = resolve_effective_allowed_models(insider, alloc_store, alias_store)
        eo = resolve_effective_allowed_models(outsider, alloc_store, alias_store)
        assert ei.is_model_denied("qwen2.5:3b") is False   # insider OK
        assert eo.is_model_denied("qwen2.5:3b") is True    # outsider denied

    def test_dangling_alias_is_fail_closed(self, alloc_store, alias_store):
        # Allocate an alias that does NOT resolve to a concrete model.
        alloc_store.add("ghost", "group", "eng")
        ident = {"identity_id": "u1", "groups": ["eng"], "org_id": "", "allowed_models": []}
        eff = resolve_effective_allowed_models(ident, alloc_store, alias_store)
        assert eff.has_restriction is True
        # alias name carried, but no concrete model resolved
        assert eff.allowed == {"ghost"}
        # OPA list is non-empty (the alias) → still a true allowlist, denies others.
        assert eff.to_opa_allowed_models() == ["ghost"]

    def test_restriction_with_empty_allowed_emits_sentinel(self):
        eff = EffectiveModels(allowed=set(), has_restriction=True)
        out = eff.to_opa_allowed_models()
        assert out == ["__yashigani_no_model_allocated__"]

    def test_store_blip_fails_closed(self, alias_store):
        class _BoomStore:
            def aliases_for_scope(self, *a):
                raise RuntimeError("redis down")
            def scope_has_allocation(self, *a):
                raise RuntimeError("redis down")
            def all_allocated_aliases(self):
                raise RuntimeError("redis down")
        ident = {"identity_id": "u1", "groups": ["eng"], "org_id": "acme", "allowed_models": []}
        eff = resolve_effective_allowed_models(ident, _BoomStore(), alias_store)
        # A store blip must NOT grant unrestricted access.
        assert eff.has_restriction is True

    def test_no_alloc_store_uses_own_only(self, alias_store):
        ident = {"identity_id": "u1", "groups": ["eng"], "allowed_models": ["qwen2.5:3b"]}
        eff = resolve_effective_allowed_models(ident, None, alias_store)
        assert eff.allowed == {"qwen2.5:3b"}
        assert eff.has_restriction is True


# ── LAURA-B1-OBS-1: optimiser local-default fallback within the caller's set ──

class TestAllowedLocalDefault:
    """pick_allowed_local_default — the optimiser's local fallback must land on a
    model the caller is ENTITLED to, never the global default they are denied.

    Over-restriction was the bug: a caller allocated only a non-default LOCAL
    model (phi3.5) gets the global default (qwen2.5:3b) substituted by the
    optimiser, then DENIED by the alloc-bind re-check for a model they never
    asked for.  The fix substitutes the caller's OWN allowed local model.  The
    security bar holds: we ONLY ever return a model the caller is allocated, and
    None (→ keep the denied global default → deny downstream) for the truly-
    unallocated case.
    """

    @pytest.fixture
    def alias_store_phi(self, redis):
        s = ModelAliasStore(redis_client=redis)
        s.set("fast", ModelAlias(alias="fast", provider="ollama", model="qwen2.5:3b", force_local=True))
        s.set("smart", ModelAlias(alias="smart", provider="anthropic", model="claude-sonnet-4-6"))
        s.set("phi", ModelAlias(alias="phi", provider="ollama", model="phi3.5", force_local=True))
        return s

    def test_unrestricted_caller_keeps_global_default(self, alloc_store, alias_store_phi):
        # No restriction, global default not gated → None (legacy behaviour).
        ident = {"identity_id": "u1", "groups": [], "org_id": "", "allowed_models": []}
        eff = resolve_effective_allowed_models(ident, alloc_store, alias_store_phi)
        assert eff.pick_allowed_local_default(alias_store_phi, "qwen2.5:3b") is None

    def test_caller_entitled_to_global_default_keeps_it(self, alloc_store, alias_store_phi):
        # 'fast' (→qwen2.5:3b) allocated to the caller's group → default not denied.
        alloc_store.add("fast", "group", "eng")
        ident = {"identity_id": "u1", "groups": ["eng"], "org_id": "", "allowed_models": []}
        eff = resolve_effective_allowed_models(ident, alloc_store, alias_store_phi)
        assert eff.pick_allowed_local_default(alias_store_phi, "qwen2.5:3b") is None

    def test_phi_only_caller_served_phi_not_denied_qwen(self, alloc_store, alias_store_phi):
        # THE OBS-1 SCENARIO: user allocated ONLY phi3.5; qwen2.5:3b is gated to
        # another group → the optimiser's qwen fallback would 403 them. The fix
        # substitutes phi3.5 — a model they ARE entitled to.
        alloc_store.add("phi", "group", "research")     # caller's group
        alloc_store.add("fast", "group", "brain")       # gates qwen2.5:3b elsewhere
        ident = {"identity_id": "u1", "groups": ["research"], "org_id": "", "allowed_models": []}
        eff = resolve_effective_allowed_models(ident, alloc_store, alias_store_phi)
        # Global default qwen IS denied to this caller …
        assert eff.is_model_denied("qwen2.5:3b") is True
        # … and the fallback resolves to phi3.5, which is NOT denied.
        picked = eff.pick_allowed_local_default(alias_store_phi, "qwen2.5:3b")
        assert picked == "phi3.5"
        assert eff.is_model_denied(picked) is False

    def test_own_allowed_models_local_default(self, alloc_store, alias_store_phi):
        # Caller restricted by own allowed_models to a bare local model name.
        alloc_store.add("fast", "group", "brain")  # gates qwen2.5:3b
        ident = {"identity_id": "u1", "groups": [], "org_id": "", "allowed_models": ["phi3.5"]}
        eff = resolve_effective_allowed_models(ident, alloc_store, alias_store_phi)
        assert eff.is_model_denied("qwen2.5:3b") is True
        assert eff.pick_allowed_local_default(alias_store_phi, "qwen2.5:3b") == "phi3.5"

    def test_cloud_only_caller_no_local_substitute(self, alloc_store, alias_store_phi):
        # Caller allocated ONLY a cloud model; qwen gated elsewhere. There is NO
        # allowed LOCAL model → return None so the (denied) global default stays
        # and the request is DENIED downstream (never substitute cloud for a
        # local-route decision — that would break P1/P2/P3 data residency).
        alloc_store.add("smart", "user", "u1")     # cloud alias → claude-sonnet
        alloc_store.add("fast", "group", "brain")  # gates qwen2.5:3b
        ident = {"identity_id": "u1", "groups": [], "org_id": "", "allowed_models": []}
        eff = resolve_effective_allowed_models(ident, alloc_store, alias_store_phi)
        assert eff.is_model_denied("qwen2.5:3b") is True
        assert eff.pick_allowed_local_default(alias_store_phi, "qwen2.5:3b") is None

    def test_own_allowed_cloud_alias_name_keeps_denied_default(self, alloc_store, alias_store_phi):
        # Caller's own allowed_models names the CLOUD ALIAS `smart` (which resolves
        # to claude-sonnet-4-6). qwen gated. The alias is cloud → excluded; its
        # concrete is excluded too → no LOCAL entitlement → None (deny-by-default).
        alloc_store.add("fast", "group", "brain")  # gates qwen2.5:3b
        ident = {"identity_id": "u1", "groups": [], "org_id": "", "allowed_models": ["smart"]}
        eff = resolve_effective_allowed_models(ident, alloc_store, alias_store_phi)
        assert eff.is_model_denied("qwen2.5:3b") is True
        assert eff.pick_allowed_local_default(alias_store_phi, "qwen2.5:3b") is None


# ── Input validation (Ava finding) ──────────────────────────────────────────

class TestResourcePatternValidation:
    def _model(self):
        from yashigani.backoffice.routes.rbac import ResourcePatternIn
        return ResourcePatternIn

    def test_valid_method_and_path(self):
        m = self._model()(method="get", path_glob="/tools/**")
        assert m.method == "GET"
        assert m.path_glob == "/tools/**"

    def test_wildcard_method_ok(self):
        m = self._model()(path_glob="**")
        assert m.method == "*"

    def test_invalid_method_rejected(self):
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            self._model()(method="TRACE", path_glob="/x")

    def test_path_glob_with_space_rejected(self):
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            self._model()(method="GET", path_glob="/a b")

    def test_path_glob_metachar_rejected(self):
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            self._model()(method="GET", path_glob="/a;rm -rf")

    def test_path_glob_too_long_rejected(self):
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            self._model()(method="GET", path_glob="/" + "a" * 600)
