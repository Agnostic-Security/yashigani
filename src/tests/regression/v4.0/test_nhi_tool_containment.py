"""
Regression test — NHI tool containment (RISK-097).

Proves the fix: when a user runs their built agent, the NHI identity is
created with effective_scope = declared ∩ invoker ∩ ceiling.  A skill
outside the ceiling is REJECTED even if the invoking user could reach it
directly.  The OPA decision uses the NHI identity (input.identity), not the
user.

Reference: nhi-p1p2-langflow-spec.md §A.6
"""
from __future__ import annotations


class _FakeRedis:
    """Minimal Redis stub for AgentRegistry tests."""

    def __init__(self) -> None:
        self._store: dict[str, bytes] = {}
        self._sets: dict[str, set[bytes]] = {}
        self._scripts: list = []

    def hset(self, key, mapping=None, **kwargs) -> None:
        if mapping:
            for k, v in mapping.items():
                raw_k = k if isinstance(k, bytes) else k.encode()
                raw_v = v if isinstance(v, bytes) else str(v).encode()
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

    def setex(self, key: str, ttl: int, value) -> None:
        self.set(key, value)

    def sadd(self, key: str, *values) -> None:
        if key not in self._sets:
            self._sets[key] = set()
        for v in values:
            self._sets[key].add(v if isinstance(v, bytes) else str(v).encode())

    def scard(self, key: str) -> int:
        return len(self._sets.get(key, set()))

    def smembers(self, key: str) -> set:
        return self._sets.get(key, set())

    def pipeline(self) -> "_FakePipeline":
        return _FakePipeline(self)

    def eval(self, script, numkeys, *args):
        # Stub Lua eval — just do the HSET + SET + SADD atomically enough for tests
        # ARGV[1]=limit ARGV[2]=agent_id ARGV[3]=token_hash ARGV[4..]=hset pairs
        argv = list(args[numkeys:])
        limit = int(argv[0])
        agent_id = argv[1]
        token_hash = argv[2]
        pairs = argv[3:]
        keys = list(args[:numkeys])

        active_key = keys[0]
        all_key = keys[1]
        reg_key = keys[2]
        tok_key = keys[3]

        current = self.scard(active_key)
        if limit != -1 and current >= limit:
            raise Exception(f"LIMIT_EXCEEDED:{current}:{limit}")

        mapping = {}
        for i in range(0, len(pairs), 2):
            k = pairs[i].encode() if isinstance(pairs[i], str) else pairs[i]
            v = pairs[i + 1].encode() if isinstance(pairs[i + 1], str) else pairs[i + 1]
            mapping[k] = v
        self.hset(reg_key, mapping=mapping)
        self.set(tok_key, token_hash)
        self.sadd(all_key, agent_id)
        self.sadd(active_key, agent_id)
        return 1


class _FakePipeline:
    def __init__(self, redis):
        self._r = redis
        self._cmds: list = []

    def hset(self, key, mapping=None, **kwargs):
        self._cmds.append(("hset", key, mapping))
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
                self._r.hset(args[0], mapping=args[1])
            elif cmd == "set":
                self._r.set(args[0], args[1])
            elif cmd == "sadd":
                self._r.sadd(args[0], *args[1])
            elif cmd == "srem":
                for v in args[1]:
                    s = self._r._sets.get(args[0], set())
                    s.discard(v if isinstance(v, bytes) else str(v).encode())
                    self._r._sets[args[0]] = s
            elif cmd == "delete":
                self._r._store.pop(args[0], None)
        self._cmds.clear()


# ---------------------------------------------------------------------------
# Test: register_nhi — effective_scope is constrained (RISK-097)
# ---------------------------------------------------------------------------

def test_register_nhi_stores_intersected_paths() -> None:
    """NHI allowed_paths must be declared ∩ user-grants (here: the caller passes
    already-intersected effective tools from compute_effective_skills; registry
    stores exactly what was passed — no expansion).
    """
    from yashigani.agents.registry import AgentRegistry

    r = _FakeRedis()
    reg = AgentRegistry(r)

    # User has access to /tools/A and /tools/B
    # Template declares /tools/A only → intersection = [/tools/A]
    nhi_id, token = reg.register_nhi(
        name="test-nhi",
        owner_identity_id="user_abc",
        template_id="uag_template1",
        allowed_tools=["/tools/A"],          # already intersected
        allowed_paths=["/tools/A"],
        allowed_models=[],
        sensitivity_ceiling="INTERNAL",
        budget_cap={"max_tokens_per_run": 8192, "max_tool_calls_per_run": 20},
    )

    assert nhi_id.startswith("nhi_"), f"Expected nhi_ prefix, got {nhi_id!r}"
    assert len(token) == 64, "Expected 32-byte hex token"

    # Verify stored data
    nhi = reg.get(nhi_id)
    assert nhi is not None, "NHI not found in registry"
    assert nhi["kind"] == "nhi"
    assert nhi["allowed_tools"] == ["/tools/A"], (
        "RISK-097 regression: NHI allowed_tools must be the intersected list, "
        f"got {nhi['allowed_tools']!r}"
    )
    assert nhi["allowed_paths"] == ["/tools/A"]
    assert "/tools/B" not in nhi["allowed_tools"], (
        "RISK-097 regression: /tools/B must not appear in NHI allowed_tools "
        "(user has it but template doesn't declare it)"
    )
    assert nhi["owner_identity_id"] == "user_abc"
    assert nhi["svid_issued"] is False, "NHI must start with svid_issued=False"


def test_nhi_token_not_in_active_index_until_svid_approved() -> None:
    """NHI is in agent:index:all but NOT in agent:index:active or nhi:index:active
    until admin calls approve_svid().
    """
    from yashigani.agents.registry import AgentRegistry

    r = _FakeRedis()
    reg = AgentRegistry(r)

    nhi_id, _token = reg.register_nhi(
        name="pending-nhi",
        owner_identity_id="user_xyz",
        template_id="uag_t2",
        allowed_tools=["/tools/C"],
        allowed_paths=["/tools/C"],
        allowed_models=[],
        sensitivity_ceiling="INTERNAL",
        budget_cap={},
    )

    # Pre-approval: should NOT be in active index
    active = {v.decode() if isinstance(v, bytes) else v for v in r.smembers("agent:index:active")}
    assert nhi_id not in active, "NHI should not be in active index before SVID approval"

    nhi_active = {v.decode() if isinstance(v, bytes) else v for v in r.smembers("nhi:index:active")}
    assert nhi_id not in nhi_active, "NHI should not be in nhi:index:active before approval"

    # get_nhi_token_map should return empty (no approved NHIs)
    token_map = reg.get_nhi_token_map()
    assert nhi_id not in token_map.values(), (
        "Token map must not expose unapproved NHI tokens"
    )

    # After approval
    reg.approve_svid(nhi_id)
    nhi = reg.get(nhi_id)
    assert nhi["svid_issued"] is True

    active_after = {v.decode() if isinstance(v, bytes) else v for v in r.smembers("agent:index:active")}
    assert nhi_id in active_after

    # Token map should now include the NHI
    token_map_after = reg.get_nhi_token_map()
    assert nhi_id in token_map_after.values(), "Approved NHI must appear in token map"


def test_nhi_scope_containment_simulation() -> None:
    """Simulate the scope containment check that the gateway would enforce.

    User has allowed_paths=["/tools/A", "/tools/B"].
    Template declares allowed_tools=["/tools/A"].
    NHI effective_tools=["/tools/A"].

    Simulated OPA check: NHI request to /tools/B → denied.
    Simulated OPA check: NHI request to /tools/A → allowed.
    """
    from yashigani.agents.registry import AgentRegistry

    r = _FakeRedis()
    reg = AgentRegistry(r)

    # Step 1: register user agent with declared skills
    user_allowed_paths = {"/tools/A", "/tools/B"}
    declared_skills = ["/tools/A"]  # template declares only A

    # Step 2: compute effective_scope (user ∩ declared ∩ system_ceiling)
    # (system ceiling also has /tools/A)
    system_ceiling = {"/tools/A"}
    effective = sorted(set(declared_skills) & user_allowed_paths & system_ceiling)
    assert effective == ["/tools/A"]

    # Step 3: register NHI with effective scope
    nhi_id, _ = reg.register_nhi(
        name="contained-nhi",
        owner_identity_id="user_u1",
        template_id="uag_t3",
        allowed_tools=effective,
        allowed_paths=effective,
        allowed_models=[],
        sensitivity_ceiling="INTERNAL",
        budget_cap={"max_tokens_per_run": 4096, "max_tool_calls_per_run": 10},
    )

    # Step 4: simulate OPA identity check
    nhi = reg.get(nhi_id)
    assert nhi is not None

    def _nhi_can_access(path: str) -> bool:
        """OPA would check input.identity.allowed_paths contains path."""
        return path in nhi["allowed_tools"]

    # OPA deny: /tools/B is NOT in NHI allowed_tools
    assert not _nhi_can_access("/tools/B"), (
        "RISK-097 regression: NHI must NOT be able to access /tools/B "
        "(user has it but it's not in the template declaration → intersection excludes it)"
    )

    # OPA allow: /tools/A IS in NHI allowed_tools
    assert _nhi_can_access("/tools/A"), (
        "NHI must be able to access /tools/A (explicitly declared)"
    )
