"""
YSG-RISK-141 — DelegatedContextStore wiring into the NHI-forwarding path.

``gateway/delegated_context.py`` (mint/resolve, R2/R12/R13) shipped with ZERO
production callers — the anti-impersonation mitigation never ran. This test
proves the wiring added in gateway/openai_router.py + gateway/entrypoint.py:

Mint site:    _maybe_mint_delegated_context() — called from chat_completions()'s
              generic OpenAI-compatible NHI-forwarding branch, immediately after
              agent_headers["Authorization"] is set, only when the target is an
              admin-approved (svid_issued=1) per-user NHI so bound_spiffe is
              always the NHI's real registry-assigned SPIFFE.
Resolve site: _maybe_resolve_delegated_context() — called from
              _resolve_identity()'s p1_nhi branch. Reads X-Yashigani-Session-Id,
              verifies it, and populates identity["on_behalf_of"] ONLY on a
              full verification pass.

Proves:
1. An agent-forwarded call mints a token, sets X-Yashigani-Session-Id, and
   emits DelegatedCtxMintedEvent.
2. The gateway resolves + verifies an incoming session-id and populates
   on_behalf_of on the NHI identity dict fed to OPA.
3. A forged/absent X-Yashigani-Session-Id does NOT grant on_behalf_of
   (fail-closed by omission — the NHI resolves as its own identity, the call
   is not rejected outright).
4. A tampered signature is rejected — no on_behalf_of, no exception raised
   past the resolve boundary.
5. A client cannot set on_behalf_of directly — only DelegatedContextStore.resolve()
   populates it.

Reference: YSG-RISK-141 / RISK-097 / FIND-3.1-AGENT-BEARER-IMPERSONATION.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest


# ---------------------------------------------------------------------------
# Shared fakes (mirrors src/tests/regression/v4.0/test_delegated_context_binding.py)
# ---------------------------------------------------------------------------

class _FakeRedis:
    def __init__(self):
        self._store: dict[str, bytes] = {}

    def setex(self, key: str, ttl: int, value) -> None:
        self._store[key] = value if isinstance(value, bytes) else value.encode("utf-8")

    def get(self, key: str):
        return self._store.get(key)

    def delete(self, key: str) -> None:
        self._store.pop(key, None)


class _FakeNonceStore:
    def __init__(self):
        self._seen: set[str] = set()

    def check_and_record(self, jti: str, exp: float, tenant: str) -> bool:
        if jti in self._seen:
            return False
        self._seen.add(jti)
        return True


class _FakeIssuer:
    """Real ES384 key pair, no network/filesystem dependency."""

    def __init__(self):
        from cryptography.hazmat.primitives.asymmetric.ec import (
            SECP384R1, generate_private_key,
        )
        from cryptography.hazmat.backends import default_backend
        self._private = generate_private_key(SECP384R1(), default_backend())
        self._public_key = self._private.public_key()
        self._key = self._private
        self.kid = "test-kid-141"


def _make_store(ttl: int = 300):
    from yashigani.gateway.delegated_context import DelegatedContextStore
    issuer = _FakeIssuer()
    r = _FakeRedis()
    store = DelegatedContextStore.__new__(DelegatedContextStore)
    store._issuer = issuer
    store._r = r
    store._tenant_id = "test-tenant"
    store._nonce = _FakeNonceStore()
    store._ttl = ttl
    return store


def _make_request(headers: dict):
    req = MagicMock()
    lower_headers = {k.lower(): v for k, v in headers.items()}
    req.headers.get = lambda key, default="": lower_headers.get(key.lower(), default)
    return req


class _RecordingAuditWriter:
    def __init__(self):
        self.events: list = []

    def write(self, event) -> None:
        self.events.append(event)


# ---------------------------------------------------------------------------
# 1. _maybe_mint_delegated_context — mint site
# ---------------------------------------------------------------------------

class TestMaybeMintDelegatedContext:
    def test_mints_token_and_emits_audit_event(self, monkeypatch):
        import yashigani.gateway.openai_router as router_mod

        store = _make_store()
        audit = _RecordingAuditWriter()
        monkeypatch.setattr(router_mod._state, "delegated_context_store", store)
        monkeypatch.setattr(router_mod._state, "audit_writer", audit)

        token = router_mod._maybe_mint_delegated_context(
            nhi_id="nhi_abc123",
            bound_spiffe="spiffe://yashigani.internal/agents/default/nhi_abc123",
            user_identity_id="idnt_user1",
            effective_scope={"allowed_tools": ["/tools/A"]},
        )

        assert token, "mint must return a non-empty signed token"

        import jwt as pyjwt
        payload = pyjwt.decode(
            token, store._issuer._public_key, algorithms=["ES384"],
            audience="yashigani-delegated-context",
        )
        assert payload["nhi_id"] == "nhi_abc123"
        assert payload["bound_spiffe"] == (
            "spiffe://yashigani.internal/agents/default/nhi_abc123"
        )

        from yashigani.audit.schema import DelegatedCtxMintedEvent
        minted = [e for e in audit.events if isinstance(e, DelegatedCtxMintedEvent)]
        assert len(minted) == 1, "DelegatedCtxMintedEvent must be emitted exactly once"
        ev = minted[0]
        assert ev.nhi_id == "nhi_abc123"
        assert ev.user_identity_id == "idnt_user1"
        assert ev.session_id_hash.startswith("sha384:")
        assert token not in ev.session_id_hash, "raw session_id must never be logged"
        assert ev.ttl_seconds == 300

    def test_no_store_returns_none_no_audit(self, monkeypatch):
        import yashigani.gateway.openai_router as router_mod

        audit = _RecordingAuditWriter()
        monkeypatch.setattr(router_mod._state, "delegated_context_store", None)
        monkeypatch.setattr(router_mod._state, "audit_writer", audit)

        token = router_mod._maybe_mint_delegated_context(
            nhi_id="nhi_abc123", bound_spiffe="spiffe://x/y/z",
            user_identity_id="idnt_user1", effective_scope={},
        )
        assert token is None
        assert audit.events == []

    def test_missing_bound_spiffe_returns_none(self, monkeypatch):
        """A pending/unapproved NHI (no registry spiffe_id yet) must never mint."""
        import yashigani.gateway.openai_router as router_mod

        store = _make_store()
        monkeypatch.setattr(router_mod._state, "delegated_context_store", store)
        monkeypatch.setattr(router_mod._state, "audit_writer", None)

        token = router_mod._maybe_mint_delegated_context(
            nhi_id="nhi_abc123", bound_spiffe="",
            user_identity_id="idnt_user1", effective_scope={},
        )
        assert token is None

    def test_internal_identity_never_mints(self, monkeypatch):
        """The internal service identity is never a human — no delegation for it."""
        import yashigani.gateway.openai_router as router_mod

        store = _make_store()
        monkeypatch.setattr(router_mod._state, "delegated_context_store", store)
        monkeypatch.setattr(router_mod._state, "audit_writer", None)

        token = router_mod._maybe_mint_delegated_context(
            nhi_id="nhi_abc123", bound_spiffe="spiffe://x/y/z",
            user_identity_id="internal", effective_scope={},
        )
        assert token is None

    def test_mint_failure_swallowed_returns_none(self, monkeypatch):
        """A signing/Redis error at mint() time must not propagate — the
        forward proceeds without a binding, never with a broken one."""
        import yashigani.gateway.openai_router as router_mod

        store = _make_store()

        def _boom(**kwargs):
            raise RuntimeError("redis unavailable")
        monkeypatch.setattr(store, "mint", _boom)
        monkeypatch.setattr(router_mod._state, "delegated_context_store", store)
        monkeypatch.setattr(router_mod._state, "audit_writer", None)

        token = router_mod._maybe_mint_delegated_context(
            nhi_id="nhi_abc123", bound_spiffe="spiffe://x/y/z",
            user_identity_id="idnt_user1", effective_scope={},
        )
        assert token is None


# ---------------------------------------------------------------------------
# 2. _maybe_resolve_delegated_context — resolve site
# ---------------------------------------------------------------------------

class TestMaybeResolveDelegatedContext:
    def test_valid_token_populates_on_behalf_of(self, monkeypatch):
        import yashigani.gateway.openai_router as router_mod

        store = _make_store()
        monkeypatch.setattr(router_mod._state, "delegated_context_store", store)

        spiffe = "spiffe://yashigani.internal/agents/default/nhi_abc123"
        token = store.mint(
            nhi_id="nhi_abc123", user_identity_id="idnt_user1",
            effective_scope={"allowed_tools": ["/tools/A"]}, bound_spiffe=spiffe,
        )
        req = _make_request({"X-Yashigani-Session-Id": token})
        identity = {"identity_id": "nhi_abc123", "kind": "nhi", "spiffe_id": spiffe}

        router_mod._maybe_resolve_delegated_context(req, identity)

        assert identity["on_behalf_of"] == {
            "user_identity_id": "idnt_user1",
            "effective_scope": {"allowed_tools": ["/tools/A"]},
        }

    def test_absent_header_no_elevation_no_raise(self, monkeypatch):
        import yashigani.gateway.openai_router as router_mod

        store = _make_store()
        monkeypatch.setattr(router_mod._state, "delegated_context_store", store)

        req = _make_request({})
        identity = {"identity_id": "nhi_abc123", "kind": "nhi", "spiffe_id": "spiffe://x"}

        router_mod._maybe_resolve_delegated_context(req, identity)

        assert "on_behalf_of" not in identity

    def test_no_store_no_elevation_no_raise(self, monkeypatch):
        import yashigani.gateway.openai_router as router_mod

        monkeypatch.setattr(router_mod._state, "delegated_context_store", None)

        req = _make_request({"X-Yashigani-Session-Id": "anything.at.all"})
        identity = {"identity_id": "nhi_abc123", "kind": "nhi", "spiffe_id": "spiffe://x"}

        router_mod._maybe_resolve_delegated_context(req, identity)

        assert "on_behalf_of" not in identity

    def test_forged_garbage_token_no_elevation(self, monkeypatch):
        """A client cannot forge on_behalf_of by sending an arbitrary header
        value — resolve() rejects it and the identity is untouched."""
        import yashigani.gateway.openai_router as router_mod

        store = _make_store()
        monkeypatch.setattr(router_mod._state, "delegated_context_store", store)

        req = _make_request({
            "X-Yashigani-Session-Id": "forged-not-even-a-jwt",
        })
        identity = {"identity_id": "nhi_abc123", "kind": "nhi", "spiffe_id": "spiffe://x"}

        router_mod._maybe_resolve_delegated_context(req, identity)

        assert "on_behalf_of" not in identity

    def test_tampered_signature_rejected_no_elevation(self, monkeypatch):
        """A valid-shaped token signed by a DIFFERENT key (tampered/forged
        signature) must be rejected — R13/anti-forgery."""
        import yashigani.gateway.openai_router as router_mod
        import jwt as pyjwt
        from cryptography.hazmat.primitives.asymmetric.ec import (
            SECP384R1, generate_private_key,
        )
        from cryptography.hazmat.backends import default_backend

        store = _make_store()
        monkeypatch.setattr(router_mod._state, "delegated_context_store", store)

        # Mint a legitimate token first (creates the Redis record + real jti),
        # then re-sign an identical payload with an ATTACKER key.
        spiffe = "spiffe://yashigani.internal/agents/default/nhi_abc123"
        legit_token = store.mint(
            nhi_id="nhi_abc123", user_identity_id="idnt_user1",
            effective_scope={}, bound_spiffe=spiffe,
        )
        payload = pyjwt.decode(
            legit_token, store._issuer._public_key, algorithms=["ES384"],
            audience="yashigani-delegated-context",
        )
        attacker_key = generate_private_key(SECP384R1(), default_backend())
        tampered_token = pyjwt.encode(
            payload, attacker_key, algorithm="ES384",
            headers={"kid": store._issuer.kid, "alg": "ES384"},
        )

        req = _make_request({"X-Yashigani-Session-Id": tampered_token})
        identity = {"identity_id": "nhi_abc123", "kind": "nhi", "spiffe_id": spiffe}

        router_mod._maybe_resolve_delegated_context(req, identity)

        assert "on_behalf_of" not in identity, (
            "R13 regression: a tampered signature must never populate on_behalf_of"
        )

    def test_spiffe_mismatch_rejected_no_elevation(self, monkeypatch):
        """R12: a leaked X-Yashigani-Session-Id presented by a DIFFERENT NHI
        (different spiffe_id) must not grant on_behalf_of."""
        import yashigani.gateway.openai_router as router_mod

        store = _make_store()
        monkeypatch.setattr(router_mod._state, "delegated_context_store", store)

        bound_spiffe = "spiffe://yashigani.internal/agents/default/nhi_abc123"
        token = store.mint(
            nhi_id="nhi_abc123", user_identity_id="idnt_user1",
            effective_scope={}, bound_spiffe=bound_spiffe,
        )
        req = _make_request({"X-Yashigani-Session-Id": token})
        # A DIFFERENT NHI presents the same (leaked) token.
        attacker_identity = {
            "identity_id": "nhi_attacker", "kind": "nhi",
            "spiffe_id": "spiffe://yashigani.internal/agents/default/nhi_attacker",
        }

        router_mod._maybe_resolve_delegated_context(req, attacker_identity)

        assert "on_behalf_of" not in attacker_identity

    def test_nhi_id_mismatch_rejected_even_with_matching_spiffe(self, monkeypatch):
        """Defence in depth: the resolved ctx.nhi_id must equal the presenting
        caller's OWN identity_id, not just pass the spiffe binding check."""
        import yashigani.gateway.openai_router as router_mod

        store = _make_store()
        monkeypatch.setattr(router_mod._state, "delegated_context_store", store)

        spiffe = "spiffe://yashigani.internal/agents/default/nhi_abc123"
        token = store.mint(
            nhi_id="nhi_abc123", user_identity_id="idnt_user1",
            effective_scope={}, bound_spiffe=spiffe,
        )
        req = _make_request({"X-Yashigani-Session-Id": token})
        # Same spiffe_id claimed, but a different identity_id than the minted ctx.
        identity = {"identity_id": "nhi_someone_else", "kind": "nhi", "spiffe_id": spiffe}

        router_mod._maybe_resolve_delegated_context(req, identity)

        assert "on_behalf_of" not in identity


# ---------------------------------------------------------------------------
# 3. End-to-end through _resolve_identity()'s p1_nhi branch
# ---------------------------------------------------------------------------

class TestResolveIdentityP1NhiOnBehalfOf:
    def _registry_entry(self, spiffe: str):
        return {
            "kind": "nhi", "svid_issued": True, "status": "active",
            "allowed_models": [], "allowed_paths": [], "allowed_tools": ["/tools/A"],
            "sensitivity_ceiling": "PUBLIC", "budget_cap": {},
            "owner_identity_id": "idnt_user1", "template_id": "tmpl_x",
            "spiffe_id": spiffe,
        }

    def test_p1_nhi_call_with_valid_session_id_carries_on_behalf_of(self, monkeypatch):
        import yashigani.gateway.openai_router as router_mod

        store = _make_store()
        spiffe = "spiffe://yashigani.internal/agents/default/nhi_abc123"
        token = store.mint(
            nhi_id="nhi_abc123", user_identity_id="idnt_user1",
            effective_scope={"allowed_tools": ["/tools/A"]}, bound_spiffe=spiffe,
        )

        mock_registry = MagicMock()
        mock_registry.get.return_value = self._registry_entry(spiffe)

        p1_token = "cafef00d" * 8
        monkeypatch.setattr(router_mod._state, "token_role_map", {
            p1_token: ("p1_nhi", "nhi_abc123"),
        })
        monkeypatch.setattr(router_mod._state, "agent_registry", mock_registry)
        monkeypatch.setattr(router_mod._state, "delegated_context_store", store)
        monkeypatch.setattr(router_mod._state, "audit_writer", None)

        req = _make_request({
            "Authorization": f"Bearer {p1_token}",
            "X-Yashigani-Session-Id": token,
        })

        result = router_mod._resolve_identity(req)

        assert result is not None
        assert result["identity_id"] == "nhi_abc123"
        assert result["on_behalf_of"] == {
            "user_identity_id": "idnt_user1",
            "effective_scope": {"allowed_tools": ["/tools/A"]},
        }

    def test_p1_nhi_call_with_no_session_id_no_elevation(self, monkeypatch):
        import yashigani.gateway.openai_router as router_mod

        store = _make_store()
        spiffe = "spiffe://yashigani.internal/agents/default/nhi_abc123"

        mock_registry = MagicMock()
        mock_registry.get.return_value = self._registry_entry(spiffe)

        p1_token = "cafef00d" * 8
        monkeypatch.setattr(router_mod._state, "token_role_map", {
            p1_token: ("p1_nhi", "nhi_abc123"),
        })
        monkeypatch.setattr(router_mod._state, "agent_registry", mock_registry)
        monkeypatch.setattr(router_mod._state, "delegated_context_store", store)
        monkeypatch.setattr(router_mod._state, "audit_writer", None)

        req = _make_request({"Authorization": f"Bearer {p1_token}"})

        result = router_mod._resolve_identity(req)

        assert result is not None
        assert result["identity_id"] == "nhi_abc123"
        assert "on_behalf_of" not in result, (
            "Most NHI hops carry no delegated context — must resolve as the "
            "NHI's own identity with no elevation, and NOT be rejected."
        )

    def test_p1_nhi_call_with_forged_session_id_no_elevation_not_rejected(self, monkeypatch):
        """A client-supplied X-Yashigani-Session-Id that is NOT a value this
        gateway minted must never grant on_behalf_of — but the call itself
        (the NHI's own identity resolution) is not rejected outright."""
        import yashigani.gateway.openai_router as router_mod

        store = _make_store()
        spiffe = "spiffe://yashigani.internal/agents/default/nhi_abc123"

        mock_registry = MagicMock()
        mock_registry.get.return_value = self._registry_entry(spiffe)

        p1_token = "cafef00d" * 8
        monkeypatch.setattr(router_mod._state, "token_role_map", {
            p1_token: ("p1_nhi", "nhi_abc123"),
        })
        monkeypatch.setattr(router_mod._state, "agent_registry", mock_registry)
        monkeypatch.setattr(router_mod._state, "delegated_context_store", store)
        monkeypatch.setattr(router_mod._state, "audit_writer", None)

        req = _make_request({
            "Authorization": f"Bearer {p1_token}",
            "X-Yashigani-Session-Id": "client-forged-value-not-a-real-jwt",
        })

        result = router_mod._resolve_identity(req)

        assert result is not None
        assert result["identity_id"] == "nhi_abc123"
        assert "on_behalf_of" not in result
