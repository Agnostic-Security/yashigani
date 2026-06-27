"""
Regression test — NHI SVID approval gate (RISK-097, 4.0 Phase 3).

Proves the fix:
  • An un-approved NHI (svid_issued=0) is NOT present in get_nhi_token_map()
    → gateway token-role-map does not load its token
    → gateway returns 403 NHI_PENDING_APPROVAL.

  • After approve_svid(), the NHI IS present in get_nhi_token_map()
    → gateway can resolve its token → gateway can serve the request.

This test uses the AgentRegistry + _FakeRedis stubs only (no live process).
It is intentionally unit-level — the live-stack integration test lives in
the invariant suite (tests/invariants/test_nhi_approve_flow.py).

Also exercises: spiffe_id persisted via registry.update() after approve.
"""
from __future__ import annotations


# ---------------------------------------------------------------------------
# Minimal Redis stub (mirrors test_nhi_tool_containment.py stubs)
# ---------------------------------------------------------------------------

class _FakeRedis:
    """Minimal Redis stub for AgentRegistry tests."""

    def __init__(self) -> None:
        self._store: dict[str, bytes] = {}
        self._sets: dict[str, set[bytes]] = {}

    def hset(self, key, field_or_mapping=None, value=None, mapping=None, **kwargs) -> None:
        """Support both hset(name, mapping=dict) and hset(name, field, value) forms."""
        if mapping is not None:
            # Explicit mapping= kwarg form
            for k, v in mapping.items():
                raw_k = k if isinstance(k, bytes) else k.encode()
                raw_v = v if isinstance(v, bytes) else str(v).encode()
                self._store[f"{key}:{raw_k.decode()}"] = raw_v
        elif isinstance(field_or_mapping, dict):
            # Positional mapping form: hset(name, {field: value, ...})
            for k, v in field_or_mapping.items():
                raw_k = k if isinstance(k, bytes) else k.encode()
                raw_v = v if isinstance(v, bytes) else str(v).encode()
                self._store[f"{key}:{raw_k.decode()}"] = raw_v
        elif field_or_mapping is not None and value is not None:
            # Field/value form: hset(name, field, value)
            raw_k = field_or_mapping if isinstance(field_or_mapping, bytes) else str(field_or_mapping).encode()
            raw_v = value if isinstance(value, bytes) else str(value).encode()
            self._store[f"{key}:{raw_k.decode()}"] = raw_v

    def hgetall(self, key: str) -> dict:
        prefix = f"{key}:"
        result = {}
        for k, v in self._store.items():
            if k.startswith(prefix):
                field = k[len(prefix):]
                result[field.encode()] = v
        return result

    def get(self, key: str):
        return self._store.get(key)

    def set(self, key: str, value) -> None:
        self._store[key] = value if isinstance(value, bytes) else str(value).encode()

    def sadd(self, key: str, *values) -> None:
        self._sets.setdefault(key, set())
        for v in values:
            self._sets[key].add(v if isinstance(v, bytes) else str(v).encode())

    def scard(self, key: str) -> int:
        return len(self._sets.get(key, set()))

    def smembers(self, key: str) -> set:
        return self._sets.get(key, set())

    def pipeline(self) -> "_FakePipeline":
        return _FakePipeline(self)


class _FakePipeline:
    def __init__(self, redis: _FakeRedis):
        self._r = redis
        self._cmds: list = []

    def hset(self, key, field_or_mapping=None, value=None, mapping=None, **kwargs):
        self._cmds.append(("hset", key, field_or_mapping, value, mapping))
        return self

    def set(self, key, value):
        self._cmds.append(("set", key, value))
        return self

    def sadd(self, key, *values):
        self._cmds.append(("sadd", key, values))
        return self

    def srem(self, key, *values):
        self._cmds.append(("srem", key, values))
        return self

    def delete(self, key):
        self._cmds.append(("delete", key))
        return self

    def execute(self):
        for cmd, *args in self._cmds:
            if cmd == "hset":
                key, field_or_mapping, value, mapping = args
                self._r.hset(key, field_or_mapping, value, mapping)
            elif cmd == "sadd":
                key, values = args
                self._r.sadd(key, *values)
            elif cmd == "set":
                key, value = args
                self._r.set(key, value)
            elif cmd in ("srem", "delete"):
                pass  # not needed for NHI approve tests
        self._cmds.clear()
        return []


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def _make_registry():  # returns AgentRegistry
    """Return an AgentRegistry backed by _FakeRedis (no live Redis)."""
    from yashigani.agents.registry import AgentRegistry
    r = _FakeRedis()
    return AgentRegistry(redis_client=r, durable_store=None)


def test_unapproved_nhi_not_in_token_map() -> None:
    """Un-approved NHI (svid_issued=0) must NOT appear in get_nhi_token_map().

    An NHI with svid_issued=0 is not present in nhi:index:active, so the
    gateway's token-role-map will not load its token → 403 NHI_PENDING_APPROVAL
    on every gateway request (fail-closed by design).
    """
    reg = _make_registry()
    _nhi_id, plaintext_token = reg.register_nhi(
        name="test-agent-unapproved",
        owner_identity_id="user__alice",
        template_id="tmpl_base",
        allowed_tools=["search"],
        allowed_paths=["/v1/chat/completions"],
        allowed_models=["gpt-4o-mini"],
        sensitivity_ceiling="INTERNAL",
        budget_cap={"max_tokens_per_run": 1000, "max_tool_calls_per_run": 5},
    )

    # Freshly registered — svid_issued=0, NOT in nhi:index:active
    token_map = reg.get_nhi_token_map()
    assert plaintext_token not in token_map, (
        "Un-approved NHI token MUST NOT be in the gateway token-role-map "
        "(svid_issued=0 → fail-closed)"
    )


def test_approved_nhi_appears_in_token_map() -> None:
    """After approve_svid(), NHI IS present in get_nhi_token_map() with p1_nhi role.

    Simulates the post-approve_svid() state from which _load_token_role_map()
    reads the NHI token and maps it to ('p1_nhi', nhi_id) at gateway startup.
    """
    reg = _make_registry()
    nhi_id, plaintext_token = reg.register_nhi(
        name="test-agent-approved",
        owner_identity_id="user__bob",
        template_id="tmpl_base",
        allowed_tools=["database.read"],
        allowed_paths=["/v1/chat/completions"],
        allowed_models=["gpt-4o-mini"],
        sensitivity_ceiling="CONFIDENTIAL",
        budget_cap={"max_tokens_per_run": 5000, "max_tool_calls_per_run": 20},
    )

    # Confirm not in map before approval
    assert plaintext_token not in reg.get_nhi_token_map()

    # Admin approves
    reg.approve_svid(nhi_id)

    # Now MUST be in map
    token_map = reg.get_nhi_token_map()
    assert plaintext_token in token_map, (
        "After approve_svid() the NHI token MUST appear in get_nhi_token_map() "
        "so the gateway can resolve the P1 role."
    )
    assert token_map[plaintext_token] == nhi_id, (
        "token_map[token] must be the nhi_id, not something else."
    )


def test_approve_svid_sets_active_index() -> None:
    """approve_svid() sets svid_issued=1 and adds NHI to both active index sets."""
    reg = _make_registry()
    nhi_id, _ = reg.register_nhi(
        name="test-index-agent",
        owner_identity_id="user__carol",
        template_id="tmpl_base",
        allowed_tools=[],
        allowed_paths=["/v1/chat/completions"],
        allowed_models=[],
        sensitivity_ceiling="PUBLIC",
        budget_cap={"max_tokens_per_run": 100, "max_tool_calls_per_run": 1},
    )

    # Before approval: svid_issued == False (bool, decoded by _decode_agent)
    nhi_before = reg.get(nhi_id)
    assert nhi_before is not None
    assert nhi_before.get("svid_issued") is False, (
        f"svid_issued should be False before approval, got {nhi_before.get('svid_issued')!r}"
    )

    reg.approve_svid(nhi_id)

    # After approval: svid_issued == True
    nhi_after = reg.get(nhi_id)
    assert nhi_after is not None
    assert nhi_after.get("svid_issued") is True, (
        f"svid_issued should be True after approval, got {nhi_after.get('svid_issued')!r}"
    )


def test_approve_svid_raises_for_unknown_id() -> None:
    """approve_svid() raises KeyError for an unknown NHI ID — caller returns 404."""
    import pytest
    reg = _make_registry()
    with pytest.raises(KeyError, match="not found"):
        reg.approve_svid("nhi_doesnotexist")


def test_approve_svid_raises_for_non_nhi_agent() -> None:
    """approve_svid() raises KeyError when called on a non-NHI agent ID."""
    import pytest
    from yashigani.agents.registry import AgentRegistry

    # We need to inject a non-NHI agent directly into the fake Redis
    # (since register() creates kind="agent" entries, but uses a Lua script stub).
    # Inject manually instead.
    r = _FakeRedis()
    reg_key = "agent:reg:agnt_fake001"
    r.hset(reg_key, mapping={
        b"kind": b"agent",
        b"name": b"fake-agent",
        b"status": b"active",
    })
    registry = AgentRegistry(redis_client=r, durable_store=None)

    with pytest.raises(KeyError, match="not an NHI"):
        registry.approve_svid("agnt_fake001")


def test_spiffe_id_persisted_via_update() -> None:
    """After approve_svid() + update(spiffe_id=...), the spiffe_id is persisted.

    Regression: spiffe_id was not in AgentRegistry.update() allowed_fields
    before 4.0 Phase 3 fix. This test verifies the update round-trips correctly.
    """
    reg = _make_registry()
    nhi_id, _ = reg.register_nhi(
        name="test-spiffe-agent",
        owner_identity_id="user__dave",
        template_id="tmpl_base",
        allowed_tools=["search"],
        allowed_paths=["/v1/chat/completions"],
        allowed_models=["gpt-4o-mini"],
        sensitivity_ceiling="INTERNAL",
        budget_cap={"max_tokens_per_run": 1000, "max_tool_calls_per_run": 5},
    )

    reg.approve_svid(nhi_id)

    expected_spiffe = f"spiffe://yashigani.local/ns/default/sa/{nhi_id}"
    reg.update(nhi_id, spiffe_id=expected_spiffe)

    nhi = reg.get(nhi_id)
    assert nhi is not None
    got = nhi.get("spiffe_id", "")
    assert got == expected_spiffe, (
        f"spiffe_id not persisted via update() — got {got!r}, want {expected_spiffe!r}. "
        "Check AgentRegistry.update() allowed_fields includes 'spiffe_id'."
    )
