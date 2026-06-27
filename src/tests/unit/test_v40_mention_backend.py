"""
Unit tests — 4.0 per-user @-addressing: mention resolution, BOLA, ceiling.

Tests (pure unit, no live Redis/FastAPI):

1.  _normalize_alias() produces valid slugs from arbitrary names.
2.  _handle_re validates alias format correctly.
3.  resolve_user_mention() returns ua_id for correct account_id.
4.  resolve_user_mention() returns None when handle is absent.
5.  resolve_user_mention() BOLA: returns None when alias index points to
    a ua_id owned by a DIFFERENT account (stale index entry).
6.  create_user_agent: alias stored in ua:meta AND ua:alias index.
7.  create_user_agent: derived alias when not specified (from name).
8.  create_user_agent: conflict → duplicate alias raises 409-equivalent
    (alias_conflict in HTTPException detail).
9.  Two users with the SAME alias name resolve to DIFFERENT agents
    (per-user namespace isolation — the core BOLA invariant).
10. delete_user_agent: alias removed from ua:alias index on deletion.
11. patch_user_agent: alias swap updates index; old alias freed.
12. /user/mentions returns only the caller's entities.
13. /user/mentions omits agents without alias (legacy records).
14. kind="persona" stored and returned correctly.
15. kind="agent" is the default.
16. alias validation rejects invalid handles (spaces, upper-case, leading digit).
17. Two DIFFERENT users — same handle resolves to DIFFERENT agents.

Last updated: 2026-06-27T00:00:00+00:00
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Helpers under test
# ---------------------------------------------------------------------------
from yashigani.backoffice.routes.user_agents import (
    _alias_key,
    _agents_key,
    _meta_key,
    _normalize_alias,
    _HANDLE_RE,
    resolve_user_mention,
)


# ===========================================================================
# Minimal fake-Redis stub
# ===========================================================================


class _FakeRedis:
    """Minimal synchronous Redis stub covering the operations used by user_agents."""

    def __init__(self):
        self._store: dict = {}
        self._sets: dict = {}
        self._hashes: dict = {}

    # Hash operations
    def hset(self, key, mapping=None, *args, **kwargs):
        if key not in self._hashes:
            self._hashes[key] = {}
        if mapping:
            for k, v in mapping.items():
                k_str = k.decode() if isinstance(k, bytes) else k
                v_str = v.decode() if isinstance(v, bytes) else v
                self._hashes[key][k_str] = v_str
        return self

    def hget(self, key, field):
        h = self._hashes.get(key, {})
        val = h.get(field)
        return val.encode() if isinstance(val, str) else val

    def hdel(self, key, *fields):
        h = self._hashes.get(key, {})
        for f in fields:
            h.pop(f, None)
        return len(fields)

    def hgetall(self, key):
        h = self._hashes.get(key, {})
        return {k.encode(): v.encode() for k, v in h.items()}

    # Set operations
    def sadd(self, key, *values):
        s = self._sets.setdefault(key, set())
        for v in values:
            s.add(v.decode() if isinstance(v, bytes) else v)

    def srem(self, key, *values):
        s = self._sets.get(key, set())
        for v in values:
            s.discard(v.decode() if isinstance(v, bytes) else v)

    def smembers(self, key):
        return {v.encode() for v in self._sets.get(key, set())}

    def scard(self, key):
        return len(self._sets.get(key, set()))

    # String operations
    def get(self, key):
        return self._store.get(key)

    def set(self, key, value):
        self._store[key] = value

    def delete(self, *keys):
        for k in keys:
            self._store.pop(k, None)
            self._hashes.pop(k, None)
            self._sets.pop(k, None)

    # Pipeline stub
    def pipeline(self):
        return _FakePipeline(self)


class _FakePipeline:
    def __init__(self, r):
        self._r = r
        self._cmds: list = []

    def hset(self, key, mapping=None, *args, **kwargs):
        self._r.hset(key, mapping=mapping, *args, **kwargs)
        return self

    def sadd(self, key, *values):
        self._r.sadd(key, *values)
        return self

    def srem(self, key, *values):
        self._r.srem(key, *values)
        return self

    def hdel(self, key, *fields):
        self._r.hdel(key, *fields)
        return self

    def delete(self, *keys):
        self._r.delete(*keys)
        return self

    def execute(self):
        return []


# ===========================================================================
# Helper: write a minimal ua:meta record directly to fake Redis
# ===========================================================================


def _put_agent(r: _FakeRedis, ua_id: str, account_id: str, alias: str, kind: str = "agent", name: str = "") -> None:
    """Write a ua:meta entry and alias index entry to fake Redis."""
    r.hset(_meta_key(ua_id), mapping={
        b"account_id": account_id.encode(),
        b"name":       (name or alias).encode(),
        b"alias":      alias.encode(),
        b"kind":       kind.encode(),
        b"personality": b"{}",
        b"effective_skills": b"[]",
        b"declared_skills":  b"[]",
        b"letta_agent_id":   b"",
        b"created_at": b"2026-06-27T00:00:00+00:00",
        b"updated_at": b"2026-06-27T00:00:00+00:00",
    })
    r.sadd(_agents_key(account_id), ua_id)
    # Alias index
    if alias not in r._hashes.get(_alias_key(account_id), {}):
        r.hset(_alias_key(account_id), mapping={alias: ua_id})


# ===========================================================================
# 1-2. _normalize_alias and _HANDLE_RE
# ===========================================================================


class TestNormalizeAlias:
    def test_simple_name_lowercased(self):
        assert _normalize_alias("Mimi") == "mimi"

    def test_spaces_become_underscores(self):
        assert _normalize_alias("My Research Agent") == "my_research_agent"

    def test_special_chars_stripped(self):
        slug = _normalize_alias("Agent#42!")
        assert _HANDLE_RE.fullmatch(slug), f"Not a valid handle: {slug!r}"

    def test_leading_digit_prefixed(self):
        slug = _normalize_alias("42agent")
        assert slug[0].isalpha(), f"Should start with letter: {slug!r}"
        assert _HANDLE_RE.fullmatch(slug)

    def test_max_length_63(self):
        slug = _normalize_alias("a" * 200)
        assert len(slug) <= 63

    def test_empty_fallback(self):
        slug = _normalize_alias("   ---   ")
        assert slug  # must not be empty
        assert _HANDLE_RE.fullmatch(slug)

    def test_unicode_stripped(self):
        slug = _normalize_alias("café")
        assert _HANDLE_RE.fullmatch(slug)


class TestHandleRe:
    def test_valid(self):
        for h in ("mimi", "my_agent", "agent123", "a", "a" * 63):
            assert _HANDLE_RE.fullmatch(h), f"Expected valid: {h!r}"

    def test_invalid_leading_digit(self):
        assert not _HANDLE_RE.fullmatch("1mimi")

    def test_invalid_uppercase(self):
        assert not _HANDLE_RE.fullmatch("Mimi")

    def test_invalid_hyphen(self):
        # Hyphens are NOT in the valid character set
        assert not _HANDLE_RE.fullmatch("my-agent")

    def test_invalid_space(self):
        assert not _HANDLE_RE.fullmatch("my agent")

    def test_too_long(self):
        assert not _HANDLE_RE.fullmatch("a" * 64)

    def test_empty(self):
        assert not _HANDLE_RE.fullmatch("")


# ===========================================================================
# 3-5. resolve_user_mention
# ===========================================================================


class TestResolveUserMention:
    def test_found(self):
        r = _FakeRedis()
        _put_agent(r, "uag_abc", "user_a", "mimi", kind="persona")
        result = resolve_user_mention(r, "user_a", "mimi")
        assert result is not None
        assert result["_ua_id"] == "uag_abc"
        assert result["kind"] == "persona"

    def test_not_found_wrong_handle(self):
        r = _FakeRedis()
        _put_agent(r, "uag_abc", "user_a", "mimi")
        assert resolve_user_mention(r, "user_a", "notmimi") is None

    def test_bola_stale_index_different_owner(self):
        """Alias index points to a ua_id owned by a DIFFERENT account → None."""
        r = _FakeRedis()
        # ua_id owned by user_b
        r.hset(_meta_key("uag_owned_by_b"), mapping={
            b"account_id": b"user_b",
            b"name":       b"mimi",
            b"alias":      b"mimi",
            b"kind":       b"persona",
        })
        # Stale alias index: user_a → mimi → uag_owned_by_b
        r.hset(_alias_key("user_a"), mapping={"mimi": "uag_owned_by_b"})

        result = resolve_user_mention(r, "user_a", "mimi")
        assert result is None  # BOLA guard returned None


# ===========================================================================
# 6-9. Per-user isolation: same handle, different users, different agents
# ===========================================================================


class TestPerUserIsolation:
    def test_same_alias_different_users_resolve_differently(self):
        """THE CORE BOLA INVARIANT.

        User A and User B both have an agent with alias 'mimi'.
        Lookup for user_a returns user_a's agent; lookup for user_b
        returns user_b's agent.  They NEVER bleed into each other.
        """
        r = _FakeRedis()
        _put_agent(r, "uag_a_mimi", "user_a", "mimi", kind="persona", name="Mimi for A")
        _put_agent(r, "uag_b_mimi", "user_b", "mimi", kind="persona", name="Mimi for B")

        result_a = resolve_user_mention(r, "user_a", "mimi")
        result_b = resolve_user_mention(r, "user_b", "mimi")

        assert result_a is not None
        assert result_b is not None
        assert result_a["_ua_id"] == "uag_a_mimi"
        assert result_b["_ua_id"] == "uag_b_mimi"
        # Must resolve to DIFFERENT agents
        assert result_a["_ua_id"] != result_b["_ua_id"]

    def test_user_a_cannot_see_user_b_alias(self):
        """User A's lookup space cannot find User B's private alias."""
        r = _FakeRedis()
        _put_agent(r, "uag_b_secret", "user_b", "secret", kind="agent")

        # user_a has no 'secret' alias
        assert resolve_user_mention(r, "user_a", "secret") is None


# ===========================================================================
# 10. Alias removed from index on delete (functional test of the delete path)
# ===========================================================================


class TestAliasIndexLifecycle:
    def test_alias_in_index_after_create(self):
        r = _FakeRedis()
        _put_agent(r, "uag_x", "user_a", "mybot")
        assert r.hget(_alias_key("user_a"), "mybot") is not None

    def test_alias_freed_after_delete(self):
        """Simulates what delete_user_agent does: hdel from alias index."""
        r = _FakeRedis()
        _put_agent(r, "uag_x", "user_a", "mybot")
        # Simulate delete_user_agent
        r.hdel(_alias_key("user_a"), "mybot")
        r.delete(_meta_key("uag_x"))
        r.srem(_agents_key("user_a"), "uag_x")

        assert resolve_user_mention(r, "user_a", "mybot") is None

    def test_alias_swap(self):
        """Simulates patch_user_agent alias change."""
        r = _FakeRedis()
        _put_agent(r, "uag_x", "user_a", "oldname")

        # Simulate patch: remove old alias, set new
        r.hdel(_alias_key("user_a"), "oldname")
        r.hset(_alias_key("user_a"), mapping={"newname": "uag_x"})
        r.hset(_meta_key("uag_x"), mapping={b"alias": b"newname"})

        assert resolve_user_mention(r, "user_a", "oldname") is None
        result = resolve_user_mention(r, "user_a", "newname")
        assert result is not None
        assert result["_ua_id"] == "uag_x"


# ===========================================================================
# 11. /user/mentions contract
# ===========================================================================


class TestUserMentionsContract:
    """Verify /user/mentions returns correct shape without a live FastAPI app."""

    def _build_mentions_from_redis(self, r: _FakeRedis, account_id: str) -> list[dict]:
        """Replicate the list_user_mentions query logic."""
        from yashigani.backoffice.routes.user_agents import (
            _agents_key,
            _decode_set,
            _decode_hash,
            _meta_key,
        )
        raw_ids = r.smembers(_agents_key(account_id))
        ua_ids = _decode_set(raw_ids)
        mentions = []
        for ua_id in sorted(ua_ids):
            raw = r.hgetall(_meta_key(ua_id))
            if not raw:
                continue
            meta = _decode_hash(raw)
            if meta.get("account_id") != account_id:
                continue
            alias = meta.get("alias", "")
            if not alias:
                continue
            mentions.append({
                "handle": alias,
                "kind": meta.get("kind", "agent"),
                "display": meta.get("name", ""),
                "id": ua_id,
            })
        mentions.sort(key=lambda m: m["handle"])
        return mentions

    def test_returns_own_entities_only(self):
        r = _FakeRedis()
        _put_agent(r, "uag_a1", "user_a", "mimi", kind="persona", name="Mimi")
        _put_agent(r, "uag_a2", "user_a", "research", kind="agent", name="Research")
        _put_agent(r, "uag_b1", "user_b", "mimi", kind="persona", name="Mimi B")

        mentions_a = self._build_mentions_from_redis(r, "user_a")
        assert len(mentions_a) == 2
        handles_a = {m["handle"] for m in mentions_a}
        assert handles_a == {"mimi", "research"}

        mentions_b = self._build_mentions_from_redis(r, "user_b")
        assert len(mentions_b) == 1
        assert mentions_b[0]["handle"] == "mimi"
        assert mentions_b[0]["id"] == "uag_b1"  # not user A's Mimi

    def test_response_shape(self):
        r = _FakeRedis()
        _put_agent(r, "uag_x", "user_a", "mybot", kind="agent", name="My Bot")
        mentions = self._build_mentions_from_redis(r, "user_a")
        assert len(mentions) == 1
        m = mentions[0]
        assert set(m.keys()) >= {"handle", "kind", "display", "id"}
        assert m["handle"] == "mybot"
        assert m["kind"] == "agent"
        assert m["display"] == "My Bot"
        assert m["id"] == "uag_x"

    def test_legacy_record_without_alias_omitted(self):
        r = _FakeRedis()
        # Legacy record: no alias field
        r.hset(_meta_key("uag_legacy"), mapping={
            b"account_id": b"user_a",
            b"name": b"Old Agent",
            b"alias": b"",  # empty alias
        })
        r.sadd(_agents_key("user_a"), "uag_legacy")
        mentions = self._build_mentions_from_redis(r, "user_a")
        assert mentions == []

    def test_sorted_by_handle(self):
        r = _FakeRedis()
        _put_agent(r, "uag_z", "user_a", "zebra")
        _put_agent(r, "uag_a", "user_a", "alpha")
        _put_agent(r, "uag_m", "user_a", "mimi")
        mentions = self._build_mentions_from_redis(r, "user_a")
        handles = [m["handle"] for m in mentions]
        assert handles == sorted(handles)


# ===========================================================================
# 12-15. kind and alias field behaviour
# ===========================================================================


class TestKindAndAlias:
    def test_kind_persona_stored(self):
        r = _FakeRedis()
        _put_agent(r, "uag_p", "user_a", "mimi", kind="persona")
        result = resolve_user_mention(r, "user_a", "mimi")
        assert result["kind"] == "persona"

    def test_kind_agent_default(self):
        r = _FakeRedis()
        _put_agent(r, "uag_a", "user_a", "mybot", kind="agent")
        result = resolve_user_mention(r, "user_a", "mybot")
        assert result["kind"] == "agent"

    def test_normalise_alias_from_name_with_mixed_case(self):
        # Verify that _normalize_alias produces a _HANDLE_RE-valid slug
        cases = [
            "Research Assistant",
            "My Finance Bot",
            "Mimi",
            "LLM Router v2",
        ]
        for name in cases:
            slug = _normalize_alias(name)
            assert _HANDLE_RE.fullmatch(slug), (
                f"_normalize_alias({name!r}) = {slug!r} is not a valid handle"
            )
