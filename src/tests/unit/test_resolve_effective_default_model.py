"""
Unit tests — YSG-RISK-183 ``openai_router._resolve_effective_default_model()``.

This is the gateway-side half of the admin-configurable default: the
function consulted by ``chat_completions`` when a request carries NO
explicit ``model`` (no @mention, no pinned model). Companion to
test_admin_models_default.py (the backoffice admin API) and
test_optimization_engine.py's TestCloudDefaultKeyGating (the routing-engine
P1/P5/P6 gates) — together these cover the full precedence chain.

Follows the module-state reset pattern established in test_cloud_key_routing.py.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import fakeredis

from yashigani.models.alias_store import ModelAlias, ModelAliasStore


def _reset_router_state(model_alias_store=None, kms_provider=None, default_model="llama3.1:8b"):
    from yashigani.gateway import openai_router as _m
    _m._state.model_alias_store = model_alias_store
    _m._state.kms_provider = kms_provider
    _m._state._cloud_key_cache = {}
    _m._state.default_model = default_model


def _seeded_store():
    redis = fakeredis.FakeRedis()
    store = ModelAliasStore(redis_client=redis)
    store.seed_defaults()
    return store


class TestNoAdminDefaultConfigured:
    """No admin default set -> the spec-chosen local model (_state.default_model)."""

    def test_falls_back_to_state_default_model(self):
        from yashigani.gateway import openai_router as _m
        _reset_router_state(model_alias_store=_seeded_store(), default_model="llama3.1:8b")
        assert _m._resolve_effective_default_model() == "llama3.1:8b"

    def test_no_alias_store_falls_back_to_state_default_model(self):
        from yashigani.gateway import openai_router as _m
        _reset_router_state(model_alias_store=None, default_model="qwen2.5:3b")
        assert _m._resolve_effective_default_model() == "qwen2.5:3b"


class TestAdminDefaultLocal:
    """Admin explicitly set a LOCAL alias as default -> that alias name."""

    def test_local_alias_default_is_used(self):
        from yashigani.gateway import openai_router as _m
        store = _seeded_store()
        store.set_default("fast")  # ollama, force_local=True
        _reset_router_state(model_alias_store=store, default_model="llama3.1:8b")
        assert _m._resolve_effective_default_model() == "fast"


class TestAdminDefaultCloudWithKey:
    """Admin set a CLOUD alias as default AND a key is configured -> that alias."""

    def test_cloud_alias_with_kms_key_is_used(self):
        from yashigani.gateway import openai_router as _m
        store = _seeded_store()
        store.set_default("smart")  # anthropic
        kms = MagicMock()
        kms.get_secret.return_value = "sk-configured"
        _reset_router_state(model_alias_store=store, kms_provider=kms, default_model="llama3.1:8b")
        assert _m._resolve_effective_default_model() == "smart"

    def test_cloud_alias_with_env_key_is_used(self, monkeypatch):
        from yashigani.gateway import openai_router as _m
        store = _seeded_store()
        store.set_default("smart")
        _reset_router_state(model_alias_store=store, kms_provider=None, default_model="llama3.1:8b")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-env-configured")
        assert _m._resolve_effective_default_model() == "smart"


class TestAdminDefaultCloudWithoutKey:
    """Admin set (or a previously-valid key was removed for) a CLOUD default
    with NO key configured -> fail-closed to the spec-chosen local model,
    never the unusable cloud alias (never a silent 422/503)."""

    def test_cloud_alias_without_any_key_falls_back_to_local(self, monkeypatch):
        from yashigani.gateway import openai_router as _m
        store = _seeded_store()
        store.set_default("smart")  # anthropic, no key anywhere
        _reset_router_state(model_alias_store=store, kms_provider=None, default_model="llama3.1:8b")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        assert _m._resolve_effective_default_model() == "llama3.1:8b"

    def test_key_removed_after_being_set_as_default_degrades_to_local(self, monkeypatch):
        """Defense-in-depth: even if the admin-set endpoint's write-time
        check passed (key WAS configured then), a key removed afterwards
        must not resurface a 422/503 on the next chat — read-time re-check."""
        from yashigani.gateway import openai_router as _m
        store = _seeded_store()
        store.set_default("smart")
        _reset_router_state(model_alias_store=store, kms_provider=None, default_model="llama3.1:8b")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        assert _m._resolve_effective_default_model() == "llama3.1:8b"


class TestAdminDefaultAliasMissingOrBroken:
    """Fail-closed to local on any store/lookup anomaly — never raise."""

    def test_default_pointer_to_deleted_alias_falls_back_to_local(self):
        from yashigani.gateway import openai_router as _m
        store = _seeded_store()
        store.set_default("ghost")  # never created
        _reset_router_state(model_alias_store=store, default_model="llama3.1:8b")
        assert _m._resolve_effective_default_model() == "llama3.1:8b"

    def test_get_default_raising_falls_back_to_local(self):
        from yashigani.gateway import openai_router as _m
        broken_store = MagicMock()
        broken_store.get_default.side_effect = RuntimeError("redis down")
        _reset_router_state(model_alias_store=broken_store, default_model="llama3.1:8b")
        assert _m._resolve_effective_default_model() == "llama3.1:8b"

    def test_cloud_key_check_raising_falls_back_to_local(self):
        from yashigani.gateway import openai_router as _m
        store = _seeded_store()
        store.set_default("smart")
        broken_kms = MagicMock()
        broken_kms.get_secret.side_effect = RuntimeError("kms unreachable")
        _reset_router_state(model_alias_store=store, kms_provider=broken_kms, default_model="llama3.1:8b")
        assert _m._resolve_effective_default_model() == "llama3.1:8b"


class TestChatCompletionsWiring:
    """Confirm chat_completions actually calls the new resolver, not the
    bare _state.default_model, for the no-explicit-model path (source-level
    guard against a future accidental revert)."""

    def test_chat_completions_source_uses_resolver(self):
        import inspect
        from yashigani.gateway import openai_router as _m
        src = inspect.getsource(_m.chat_completions)
        assert "_resolve_effective_default_model()" in src
