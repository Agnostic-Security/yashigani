"""
Regression test — Delegated context binding (R2 / R12 / R13).

Proves:
1. Mint succeeds and returns a signed JWT with the correct audience.
2. Resolve succeeds when presenting_agent_spiffe matches bound_spiffe (R12).
3. Resolve FAILS when presenting_agent_spiffe differs — leaked session-id
   is unusable by another agent even within TTL (R12).
4. Resolve FAILS when the Redis record is absent (TTL expired / consumed).
5. The delegated context audience is NOT "yashigani-orchestration-principal"
   (R13: dedicated audience, claim confusion impossible).

Reference: nhi-p1p2-langflow-spec.md §B.4 / RECONCILIATION R2/R12/R13
"""
from __future__ import annotations

import jwt as pyjwt
import pytest


class _FakeRedis:
    """Minimal Redis stub for DelegatedContextStore tests."""

    def __init__(self):
        self._store: dict[str, bytes] = {}
        self._ttls: dict[str, int] = {}

    def setex(self, key: str, ttl: int, value) -> None:
        self._store[key] = value if isinstance(value, bytes) else value.encode("utf-8")
        self._ttls[key] = ttl

    def get(self, key: str):
        return self._store.get(key)

    def delete(self, key: str) -> None:
        self._store.pop(key, None)
        self._ttls.pop(key, None)


class _FakeNonceStore:
    """Minimal nonce store stub."""

    def __init__(self):
        self._seen: set[str] = set()

    def check_and_record(self, jti: str, exp: float, tenant: str) -> bool:
        if jti in self._seen:
            return False
        self._seen.add(jti)
        return True


class _FakeIssuer:
    """Minimal McpJwtIssuer stub using a real ES384 key pair."""

    def __init__(self):
        from cryptography.hazmat.primitives.asymmetric.ec import (
            SECP384R1, generate_private_key,
        )
        from cryptography.hazmat.backends import default_backend
        self._private = generate_private_key(SECP384R1(), default_backend())
        self._public_key = self._private.public_key()
        self._key = self._private
        self.kid = "test-kid-001"

    def public_key_jwk(self) -> dict:
        return {"kid": self.kid}


def _make_store(r=None, nonce=None):
    from yashigani.gateway.delegated_context import DelegatedContextStore
    issuer = _FakeIssuer()
    r = r or _FakeRedis()
    nonce = nonce or _FakeNonceStore()
    store = DelegatedContextStore.__new__(DelegatedContextStore)
    store._issuer = issuer
    store._r = r
    store._tenant_id = "test-tenant"
    store._nonce = nonce
    store._ttl = 300
    return store, r, issuer


# ---------------------------------------------------------------------------
# Test: mint produces a signed JWT with dedicated audience (R13)
# ---------------------------------------------------------------------------

def test_mint_produces_dedicated_audience_token() -> None:
    """The minted token must have audience 'yashigani-delegated-context' (R13).

    This audience is DISTINCT from 'yashigani-orchestration-principal' (principal_token.py)
    and 'yashigani-mcp-upstream' (mcp/_jwt.py) — claim confusion is impossible.
    """
    store, r, issuer = _make_store()

    token = store.mint(
        nhi_id="nhi_abc123",
        user_identity_id="user_u1",
        effective_scope={"allowed_tools": ["/tools/A"]},
        bound_spiffe="spiffe://test.yashigani.internal/agents/default/nhi_abc123",
    )

    # Decode without verification to check claims
    payload = pyjwt.decode(
        token,
        issuer._public_key,
        algorithms=["ES384"],
        audience="yashigani-delegated-context",
    )
    assert payload["aud"] == "yashigani-delegated-context", (
        "R13 regression: delegated-context token must use 'yashigani-delegated-context' audience"
    )
    assert payload["nhi_id"] == "nhi_abc123"
    assert payload["bound_spiffe"] == "spiffe://test.yashigani.internal/agents/default/nhi_abc123"

    # Must NOT be accepted as an orchestration-principal token
    with pytest.raises(pyjwt.InvalidAudienceError):
        pyjwt.decode(
            token,
            issuer._public_key,
            algorithms=["ES384"],
            audience="yashigani-orchestration-principal",  # Wrong audience
        )


def test_resolve_succeeds_with_matching_spiffe() -> None:
    """Resolve must succeed when presenting_agent_spiffe == bound_spiffe (R12 happy path)."""
    store, r, issuer = _make_store()

    bound_spiffe = "spiffe://test.yashigani.internal/agents/default/nhi_abc123"
    token = store.mint(
        nhi_id="nhi_abc123",
        user_identity_id="user_u1",
        effective_scope={"allowed_tools": ["/tools/A"]},
        bound_spiffe=bound_spiffe,
    )

    ctx = store.resolve(token, presenting_agent_spiffe=bound_spiffe)
    assert ctx.nhi_id == "nhi_abc123"
    assert ctx.user_identity_id == "user_u1"
    assert ctx.effective_scope == {"allowed_tools": ["/tools/A"]}
    assert ctx.bound_spiffe == bound_spiffe


def test_resolve_fails_with_different_spiffe_r12() -> None:
    """R12: a leaked X-Yashigani-Session-Id is unusable by another agent.

    The delegation record is bound to the presenting agent's SPIFFE id.
    A different SPIFFE id (even with the correct token) must be rejected.
    """
    from yashigani.gateway.delegated_context import DelegatedContextError

    store, r, issuer = _make_store()

    bound_spiffe = "spiffe://test.yashigani.internal/agents/default/nhi_abc123"
    attacker_spiffe = "spiffe://test.yashigani.internal/agents/default/nhi_attacker"

    token = store.mint(
        nhi_id="nhi_abc123",
        user_identity_id="user_u1",
        effective_scope={"allowed_tools": ["/tools/A"]},
        bound_spiffe=bound_spiffe,
    )

    # Attacker presents the SAME token but with THEIR OWN SPIFFE id
    with pytest.raises(DelegatedContextError) as exc_info:
        store.resolve(token, presenting_agent_spiffe=attacker_spiffe)

    assert "r12" in str(exc_info.value).lower() or "mismatch" in str(exc_info.value).lower(), (
        "R12 regression: error message must indicate the SPIFFE mismatch binding check"
    )


def test_resolve_fails_after_redis_record_expired() -> None:
    """If the Redis record is absent (TTL expired), resolve must fail closed."""
    from yashigani.gateway.delegated_context import DelegatedContextError

    store, r, issuer = _make_store()

    bound_spiffe = "spiffe://test.yashigani.internal/agents/default/nhi_abc123"
    token = store.mint(
        nhi_id="nhi_abc123",
        user_identity_id="user_u1",
        effective_scope={},
        bound_spiffe=bound_spiffe,
    )

    # Manually expire the Redis record (simulate TTL)
    import jwt as pyjwt
    payload = pyjwt.decode(
        token,
        issuer._public_key,
        algorithms=["ES384"],
        audience="yashigani-delegated-context",
    )
    jti = payload["jti"]
    r.delete(f"delegated_ctx:{jti}")

    with pytest.raises(DelegatedContextError) as exc_info:
        store.resolve(token, presenting_agent_spiffe=bound_spiffe)

    assert "expired" in str(exc_info.value).lower() or "not found" in str(exc_info.value).lower(), (
        "resolve must fail closed when Redis record is absent (expired or consumed)"
    )


def test_resolve_fails_with_empty_token() -> None:
    """Resolve with no token raises DelegatedContextError (fail-closed)."""
    from yashigani.gateway.delegated_context import DelegatedContextError

    store, r, issuer = _make_store()

    with pytest.raises(DelegatedContextError):
        store.resolve("", presenting_agent_spiffe="spiffe://test/agents/x/y")


def test_resolve_fails_with_empty_spiffe() -> None:
    """Resolve with no presenting SPIFFE raises DelegatedContextError (fail-closed).

    Without a SPIFFE identity to bind to, the R12 check cannot run.
    """
    from yashigani.gateway.delegated_context import DelegatedContextError

    store, r, issuer = _make_store()

    token = store.mint(
        nhi_id="nhi_abc123",
        user_identity_id="user_u1",
        effective_scope={},
        bound_spiffe="spiffe://test.yashigani.internal/agents/default/nhi_abc123",
    )

    with pytest.raises(DelegatedContextError) as exc_info:
        store.resolve(token, presenting_agent_spiffe="")

    assert "spiffe" in str(exc_info.value).lower(), (
        "Error must mention SPIFFE identity requirement"
    )


def test_session_id_hash_never_returns_raw() -> None:
    """Audit helper must return SHA-384 prefix, never the raw session_id."""
    from yashigani.gateway.delegated_context import DelegatedContextStore

    raw = "super-secret-session-nonce-12345"
    h = DelegatedContextStore.session_id_hash(raw)
    assert h.startswith("sha384:"), f"Expected sha384: prefix, got {h[:20]!r}"
    assert raw not in h, "Raw session_id must never appear in the hash output"
    assert len(h) == len("sha384:") + 96   # sha384 = 96 hex chars
