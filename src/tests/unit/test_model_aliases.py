"""
Unit tests for yashigani.models.alias_store.

Uses fakeredis for full Redis isolation — no live Redis required.
"""
from __future__ import annotations

import fakeredis
import pytest

from yashigani.models.alias_store import ModelAlias, ModelAliasStore, _DEFAULTS


# ── Fixtures ──────────────────────────────────────────────────────────────

@pytest.fixture
def redis():
    """Isolated in-process fakeredis instance."""
    return fakeredis.FakeRedis()


@pytest.fixture
def store(redis):
    """ModelAliasStore backed by a fresh fakeredis instance."""
    return ModelAliasStore(redis_client=redis)


@pytest.fixture
def seeded_store(store):
    """Store with seed_defaults() already called."""
    store.seed_defaults()
    return store


# ── seed_defaults ─────────────────────────────────────────────────────────

class TestSeedDefaults:
    def test_seeds_five_aliases(self, seeded_store):
        aliases = seeded_store.list_all()
        assert len(aliases) == 5

    def test_all_expected_names_present(self, seeded_store):
        aliases = seeded_store.list_all()
        assert set(aliases.keys()) == {"fast", "smart", "secure", "balanced", "code"}

    def test_fast_is_force_local(self, seeded_store):
        a = seeded_store.get("fast")
        assert a is not None
        assert a.force_local is True
        assert a.provider == "ollama"
        assert a.model == "qwen2.5:3b"

    def test_smart_is_cloud(self, seeded_store):
        a = seeded_store.get("smart")
        assert a is not None
        assert a.provider == "anthropic"
        assert a.model == "claude-sonnet-4-6"
        assert a.force_local is False

    def test_secure_has_sensitivity_ceiling(self, seeded_store):
        a = seeded_store.get("secure")
        assert a is not None
        assert a.sensitivity_ceiling == "CONFIDENTIAL"
        assert a.force_local is True

    def test_balanced_oe_decides(self, seeded_store):
        a = seeded_store.get("balanced")
        assert a is not None
        assert a.force_local is False
        assert a.sensitivity_ceiling is None

    def test_code_uses_coder_model(self, seeded_store):
        a = seeded_store.get("code")
        assert a is not None
        assert a.model == "qwen2.5-coder:3b"
        assert a.force_local is True

    def test_seed_defaults_is_idempotent(self, seeded_store):
        """Calling seed_defaults() a second time must not add duplicates."""
        seeded_store.seed_defaults()
        aliases = seeded_store.list_all()
        assert len(aliases) == 5

    def test_seed_defaults_skips_when_namespace_non_empty(self, store):
        """If even one alias key exists, seeding must be skipped entirely."""
        existing = ModelAlias(alias="custom", provider="ollama", model="llama3:8b")
        store.set("custom", existing)
        store.seed_defaults()
        aliases = store.list_all()
        # Only the manually added alias should be present
        assert list(aliases.keys()) == ["custom"]


# ── get / set ─────────────────────────────────────────────────────────────

class TestGetSet:
    def test_get_returns_none_for_missing(self, store):
        assert store.get("nonexistent") is None

    def test_set_then_get_roundtrips(self, store):
        config = ModelAlias(
            alias="test",
            provider="ollama",
            model="llama3:8b",
            force_local=True,
            sensitivity_ceiling="INTERNAL",
        )
        store.set("test", config)
        retrieved = store.get("test")
        assert retrieved is not None
        assert retrieved.alias == "test"
        assert retrieved.provider == "ollama"
        assert retrieved.model == "llama3:8b"
        assert retrieved.force_local is True
        assert retrieved.sensitivity_ceiling == "INTERNAL"

    def test_set_overwrites_existing(self, store):
        original = ModelAlias(alias="x", provider="ollama", model="qwen2.5:3b")
        store.set("x", original)
        updated = ModelAlias(alias="x", provider="anthropic", model="claude-sonnet-4-6")
        store.set("x", updated)
        result = store.get("x")
        assert result is not None
        assert result.provider == "anthropic"

    def test_set_without_sensitivity_ceiling(self, store):
        config = ModelAlias(alias="bare", provider="ollama", model="qwen2.5:3b")
        store.set("bare", config)
        result = store.get("bare")
        assert result is not None
        assert result.sensitivity_ceiling is None


# ── delete ────────────────────────────────────────────────────────────────

class TestDelete:
    def test_delete_existing_returns_true(self, store):
        store.set("todelete", ModelAlias(alias="todelete", provider="ollama", model="qwen2.5:3b"))
        assert store.delete("todelete") is True

    def test_delete_removes_key(self, store):
        store.set("todelete", ModelAlias(alias="todelete", provider="ollama", model="qwen2.5:3b"))
        store.delete("todelete")
        assert store.get("todelete") is None

    def test_delete_absent_returns_false(self, store):
        assert store.delete("ghost") is False


# ── list_all ──────────────────────────────────────────────────────────────

class TestListAll:
    def test_empty_store_returns_empty_dict(self, store):
        assert store.list_all() == {}

    def test_list_all_returns_all_entries(self, store):
        store.set("a", ModelAlias(alias="a", provider="ollama", model="qwen2.5:3b"))
        store.set("b", ModelAlias(alias="b", provider="anthropic", model="claude-sonnet-4-6"))
        aliases = store.list_all()
        assert set(aliases.keys()) == {"a", "b"}

    def test_list_all_excludes_deleted(self, store):
        store.set("a", ModelAlias(alias="a", provider="ollama", model="qwen2.5:3b"))
        store.set("b", ModelAlias(alias="b", provider="ollama", model="qwen2.5:3b"))
        store.delete("a")
        aliases = store.list_all()
        assert "a" not in aliases
        assert "b" in aliases


# ── Persistence (new store instance, same Redis) ──────────────────────────

class TestPersistence:
    def test_data_survives_new_store_instance(self, redis):
        """
        Verify that data written through one store instance is readable by a
        second store instance backed by the same Redis connection. This
        exercises real serialisation / deserialisation across object lifetimes.
        """
        store_a = ModelAliasStore(redis_client=redis)
        config = ModelAlias(
            alias="persistent",
            provider="anthropic",
            model="claude-sonnet-4-6",
            force_local=False,
            sensitivity_ceiling="RESTRICTED",
        )
        store_a.set("persistent", config)

        # New instance, same redis — simulates container restart with persistent Redis
        store_b = ModelAliasStore(redis_client=redis)
        result = store_b.get("persistent")

        assert result is not None
        assert result.alias == "persistent"
        assert result.provider == "anthropic"
        assert result.sensitivity_ceiling == "RESTRICTED"

    def test_seed_defaults_persists_across_instances(self, redis):
        store_a = ModelAliasStore(redis_client=redis)
        store_a.seed_defaults()

        store_b = ModelAliasStore(redis_client=redis)
        aliases = store_b.list_all()
        assert len(aliases) == 5


# ── ModelAlias dataclass ──────────────────────────────────────────────────

class TestModelAliasDataclass:
    def test_to_dict_includes_all_fields(self):
        a = ModelAlias(
            alias="x",
            provider="ollama",
            model="qwen2.5:3b",
            force_local=True,
            sensitivity_ceiling="CONFIDENTIAL",
        )
        d = a.to_dict()
        assert d["alias"] == "x"
        assert d["provider"] == "ollama"
        assert d["model"] == "qwen2.5:3b"
        assert d["force_local"] is True
        assert d["sensitivity_ceiling"] == "CONFIDENTIAL"

    def test_from_dict_roundtrip(self):
        original = ModelAlias(
            alias="round",
            provider="anthropic",
            model="claude-sonnet-4-6",
            force_local=False,
            sensitivity_ceiling=None,
        )
        restored = ModelAlias.from_dict(original.to_dict())
        assert restored == original

    def test_from_dict_defaults_force_local_false(self):
        d = {"alias": "x", "provider": "ollama", "model": "qwen2.5:3b"}
        a = ModelAlias.from_dict(d)
        assert a.force_local is False
        assert a.sensitivity_ceiling is None


# ── Default-alias pointer (YSG-RISK-183) ───────────────────────────────────

class TestDefaultAliasPointer:
    def test_get_default_none_when_unset(self, store):
        assert store.get_default() is None

    def test_set_then_get_default_roundtrips(self, seeded_store):
        seeded_store.set_default("fast")
        assert seeded_store.get_default() == "fast"

    def test_set_default_overwrites(self, seeded_store):
        seeded_store.set_default("fast")
        seeded_store.set_default("smart")
        assert seeded_store.get_default() == "smart"

    def test_clear_default_reverts_to_none(self, seeded_store):
        seeded_store.set_default("smart")
        seeded_store.clear_default()
        assert seeded_store.get_default() is None

    def test_clear_default_when_never_set_is_a_noop(self, store):
        store.clear_default()
        assert store.get_default() is None

    def test_default_pointer_does_not_appear_in_list_all(self, seeded_store):
        """The default pointer lives under a DIFFERENT key prefix
        (model:default_alias, not model:alias:*) so it must never leak into
        the alias enumeration used by list_all()/seed_defaults()."""
        seeded_store.set_default("smart")
        aliases = seeded_store.list_all()
        assert set(aliases.keys()) == {"fast", "smart", "secure", "balanced", "code"}

    def test_default_pointer_persists_across_instances(self, redis):
        store_a = ModelAliasStore(redis_client=redis)
        store_a.set_default("fast")
        store_b = ModelAliasStore(redis_client=redis)
        assert store_b.get_default() == "fast"
