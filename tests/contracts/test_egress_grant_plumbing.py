# Last updated: 2026-07-08T00:00:00+00:00
"""
Phase-A egress-grant plumbing contract tests.

Covers the two correctness-blocker fixes for feat/v4.1-agent-admin-policy-templates
(Nico gap-1/2/3, Lu MF-1/2/5, HIGH):

FIX 1 — grant-data passthrough bricking bug (Nico gap-1 = Lu MF-5)
  build_egress_grants_data previously stripped every field except tenant+prefixes.
  Consequence: an admin-applied bundled grant lost legacy_system → the OPA
  legacy/tenant-conjunct branch failed → store-wins overwrote the working seed
  with a dead grant → applying a template bricked the agent's egress.

  Contracts:
  1a  legacy_system is SERVER-DERIVED — a stored grant with legacy_system=True
      is NOT forwarded to a non-bundled SPIFFE (Lu MF-1 bypass prevention).
  1b  legacy_system=True IS forwarded for a SPIFFE in the bundled set (server-
      derives it regardless of what is stored).
  1c  A stored grant with legacy_system=False for a bundled SPIFFE still gets
      legacy_system=True in the built doc (server overrides store).
  1d  connect map passes through verbatim from the stored grant (Mode-B plumbing).
  1e  connect is absent from the built entry when not in the stored grant.

FIX 2 — revoke is fail-open (Lu MF-2, Nico gaps 2/3)
  (a) Seed resurfacing: delete_egress_grant + rebuild resurfaced the seed.
  (b) Push not verified on revoke: push failure left stale allow silently.

  Contracts:
  2a  After put_egress_grant + delete_egress_grant, the rebuilt doc does NOT
      contain the revoked SPIFFE (seed suppression via claimed set).
  2b  Without any put_egress_grant, the seed IS present (seed untouched for
      unclaimed systems).
  2c  claim_egress_seed is permanent: deleting the grant and rebuilding still
      suppresses the seed entry.
  2d  push_and_verify_egress_grants raises when readback shows a must-be-absent
      SPIFFE still present (fail-closed revoke verification).
  2e  push_and_verify_egress_grants passes when must-be-absent SPIFFE is gone.
  2f  push_and_verify_egress_grants skips readback when must_be_absent is empty.
"""
from __future__ import annotations

import json
from typing import Any, Optional
from unittest.mock import MagicMock, call, patch

import pytest


# ---------------------------------------------------------------------------
# In-memory Redis stub — covers the subset of commands used by the registry
# ---------------------------------------------------------------------------

class _FakeRedis:
    """Minimal in-memory Redis stub for testing store operations.

    Supports: set, get, delete, sadd, smembers, srem, sadd (as a SET type).
    Returns decoded strings (as if decode_responses=True is not set, bytes).
    """

    def __init__(self) -> None:
        self._store: dict[str, Any] = {}
        self._sets: dict[str, set] = {}

    # string ops
    def set(self, key: str, value: str) -> None:
        self._store[key] = value

    def get(self, key: str) -> Optional[bytes]:
        val = self._store.get(key)
        if val is None:
            return None
        return val.encode() if isinstance(val, str) else val

    def delete(self, *keys: str) -> int:
        n = 0
        for k in keys:
            if k in self._store:
                del self._store[k]
                n += 1
        return n

    # set ops
    def sadd(self, key: str, *members: str) -> int:
        if key not in self._sets:
            self._sets[key] = set()
        added = 0
        for m in members:
            if m not in self._sets[key]:
                self._sets[key].add(m)
                added += 1
        return added

    def smembers(self, key: str) -> set:
        # Return bytes like a non-decode_responses redis client
        return {m.encode() for m in self._sets.get(key, set())}

    def srem(self, key: str, *members: str) -> int:
        if key not in self._sets:
            return 0
        removed = 0
        for m in members:
            if m in self._sets[key]:
                self._sets[key].discard(m)
                removed += 1
        return removed


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_store(redis: Optional[_FakeRedis] = None):
    """Return a DurableMcpRegistryStore backed by the given Redis stub."""
    from yashigani.mcp._durable_registry import DurableMcpRegistryStore
    return DurableMcpRegistryStore(redis or _FakeRedis())


def _make_store_with_descriptor(
    redis: _FakeRedis,
    tenant: str,
    server: str,
    spiffe: str,
    prefixes: list[str],
    extra_grant_fields: Optional[dict] = None,
) -> None:
    """Register a descriptor and write the corresponding egress grant."""
    store = _make_store(redis)
    store.put(tenant, server, {
        "agent_name": server,
        "tenant_id": tenant,
        "upstream_url": "https://caddy:9000/mcp/%s/%s" % (tenant, server),
    })
    grant: dict = {
        "spiffe": spiffe,
        "tenant": tenant,
        "prefixes": prefixes,
    }
    if extra_grant_fields:
        grant.update(extra_grant_fields)
    store.put_egress_grant(tenant, server, grant)


# A fake bundled SPIFFE set — overridden in tests via monkeypatch.
_FAKE_BUNDLED = frozenset(["spiffe://td/openclaw", "spiffe://td/langflow"])


# ---------------------------------------------------------------------------
# FIX 1 — field passthrough (legacy_system server-derived; connect passes)
# ---------------------------------------------------------------------------

class TestLegacySystemServerDerived:
    """FIX 1 / Lu MF-1, Nico gap-1: legacy_system is NEVER read from the store."""

    def _build(self, redis: _FakeRedis) -> dict:
        """Build egress_grants_data with the fake bundled SPIFFE set patched in."""
        store = _make_store(redis)
        with patch(
            "yashigani.mcp._durable_registry.bundled_system_spiffe_set",
            return_value=_FAKE_BUNDLED,
            create=True,
        ):
            # The import inside build_egress_grants_data is a lazy local import,
            # so we patch the module-level name in _durable_registry's namespace.
            from yashigani.mcp._durable_registry import DurableMcpRegistryStore

            original = DurableMcpRegistryStore.build_egress_grants_data

            def _patched(self_inner):
                # Monkeypatch the inner import by temporarily replacing the
                # function in the module namespace that the lazy import resolves.
                import yashigani.mcp._egress_grants as _eg
                orig_fn = getattr(_eg, "bundled_system_spiffe_set", None)
                _eg.bundled_system_spiffe_set = lambda: _FAKE_BUNDLED
                try:
                    return original(self_inner)
                finally:
                    if orig_fn is not None:
                        _eg.bundled_system_spiffe_set = orig_fn
                    else:
                        del _eg.bundled_system_spiffe_set

            return _patched(store)

    def test_1a_non_bundled_spiffe_gets_no_legacy_system(self) -> None:
        """Contract 1a: a non-bundled /agents/ SPIFFE never gets legacy_system."""
        redis = _FakeRedis()
        non_bundled = "spiffe://td/agents/acme/myserver/nhi_abc123"
        _make_store_with_descriptor(
            redis, "acme", "myserver", non_bundled, ["llm"],
            extra_grant_fields={"legacy_system": True},  # attacker-supplied
        )
        out = self._build(redis)
        assert non_bundled in out
        # MUST NOT have legacy_system — attacker-supplied value stripped
        assert "legacy_system" not in out[non_bundled], (
            "FIX-1 REGRESSION: legacy_system forwarded from store for a "
            "non-bundled /agents/ SPIFFE — tenant-conjunct bypass (Lu MF-1)"
        )

    def test_1b_bundled_spiffe_gets_legacy_system_true(self) -> None:
        """Contract 1b: a bundled SPIFFE gets legacy_system=True (server-derived)."""
        redis = _FakeRedis()
        bundled = "spiffe://td/openclaw"
        _make_store_with_descriptor(
            redis, "default", "openclaw", bundled, ["llm", "slack"],
            # stored value deliberately absent — server must derive it
        )
        out = self._build(redis)
        assert bundled in out
        assert out[bundled].get("legacy_system") is True, (
            "FIX-1: bundled SPIFFE did not get legacy_system=True in built doc "
            "— OPA tenant-conjunct for system-form URI will fail (mcp.rego:812-815)"
        )

    def test_1c_bundled_spiffe_server_overrides_false_in_store(self) -> None:
        """Contract 1c: server derives legacy_system=True even if store has False."""
        redis = _FakeRedis()
        bundled = "spiffe://td/langflow"
        _make_store_with_descriptor(
            redis, "default", "langflow", bundled, ["llm"],
            extra_grant_fields={"legacy_system": False},  # store has False
        )
        out = self._build(redis)
        assert out[bundled].get("legacy_system") is True, (
            "FIX-1: server must override store's legacy_system=False for a "
            "bundled SPIFFE"
        )

    def test_1d_connect_map_passes_through(self) -> None:
        """Contract 1d: connect field is forwarded verbatim from the store."""
        redis = _FakeRedis()
        spiffe = "spiffe://td/agents/acme/oc/nhi_001"
        connect_map = {"slack": ["slack.com:443", "hooks.slack.com:443"]}
        _make_store_with_descriptor(
            redis, "acme", "oc", spiffe, ["llm"],
            extra_grant_fields={"connect": connect_map},
        )
        out = self._build(redis)
        assert spiffe in out
        assert out[spiffe].get("connect") == connect_map, (
            "FIX-1: connect map not forwarded from store to built doc "
            "— Mode-B OPA rule (egress_connect_decision) will fail"
        )

    def test_1e_connect_absent_when_not_stored(self) -> None:
        """Contract 1e: connect key absent from entry when not in stored grant."""
        redis = _FakeRedis()
        spiffe = "spiffe://td/agents/acme/srv/nhi_002"
        _make_store_with_descriptor(redis, "acme", "srv", spiffe, ["llm"])
        out = self._build(redis)
        assert "connect" not in out.get(spiffe, {}), (
            "FIX-1: connect key present in built entry with no stored connect map"
        )

    def test_1f_prefixes_still_sorted_and_present(self) -> None:
        """Regression: the passthrough fix must not break the existing prefixes field."""
        redis = _FakeRedis()
        spiffe = "spiffe://td/agents/acme/srv/nhi_003"
        _make_store_with_descriptor(redis, "acme", "srv", spiffe, ["telegram", "llm"])
        out = self._build(redis)
        assert out[spiffe]["prefixes"] == ["llm", "telegram"]


# ---------------------------------------------------------------------------
# FIX 2a — seed suppression via claimed set
# ---------------------------------------------------------------------------

class TestSeedSuppression:
    """FIX 2a: revoked seed grants must not resurface (design §4.4, Lu MF-2a)."""

    def _seed_spiffe(self, system: str = "openclaw") -> str:
        """The SPIFFE that transitional_egress_seed() would use for ``system``."""
        import os
        env_key = "YASHIGANI_%s_SPIFFE_ID" % system.upper().replace("-", "_")
        explicit = os.environ.get(env_key, "").strip()
        if explicit:
            return explicit
        from yashigani.identity.trust_domain import trust_domain
        return "spiffe://%s/%s" % (trust_domain(), system)

    def _build_doc(self, redis: Optional[_FakeRedis]) -> dict:
        from yashigani.mcp._egress_grants import build_egress_grants_doc
        store = _make_store(redis) if redis is not None else None
        return build_egress_grants_doc(store)

    def test_2b_seed_present_when_no_claims(self) -> None:
        """Contract 2b: bundled seed appears when no admin has ever touched it."""
        redis = _FakeRedis()
        doc = self._build_doc(redis)
        spiffe = self._seed_spiffe("openclaw")
        assert spiffe in doc, (
            "Expected openclaw seed entry — no claims present, seed should be live"
        )
        assert doc[spiffe].get("legacy_system") is True

    def test_2a_revoked_grant_absent_after_delete(self) -> None:
        """Contract 2a: after put + delete, seed does NOT resurface the SPIFFE."""
        redis = _FakeRedis()
        spiffe = self._seed_spiffe("openclaw")
        store = _make_store(redis)
        # Put a grant (claims the SPIFFE)
        store.put_egress_grant("default", "openclaw", {
            "spiffe": spiffe,
            "tenant": "default",
            "prefixes": ["llm", "slack"],
        })
        # Revoke (delete the grant from store)
        store.delete_egress_grant("default", "openclaw")

        # Rebuild — SPIFFE must be absent (seed suppressed by claim)
        doc = self._build_doc(redis)
        assert spiffe not in doc, (
            "FIX-2a REGRESSION: revoked grant resurfaced from transitional seed "
            "after delete_egress_grant. The seed must be suppressed once claimed."
        )

    def test_2c_claim_permanent_after_delete(self) -> None:
        """Contract 2c: claimed set is never cleared by delete_egress_grant."""
        redis = _FakeRedis()
        spiffe = self._seed_spiffe("langflow")
        store = _make_store(redis)
        store.put_egress_grant("default", "langflow", {
            "spiffe": spiffe,
            "tenant": "default",
            "prefixes": ["llm"],
        })
        store.delete_egress_grant("default", "langflow")

        # Claimed set must still contain the SPIFFE
        claimed = store.get_claimed_egress_seed_spiffes()
        assert spiffe in claimed, (
            "FIX-2a: delete_egress_grant must not clear the claimed set — "
            "the claim is permanent (design §4.4)"
        )

    def test_2b_store_none_returns_seed_only(self) -> None:
        """With no store (None), seed is returned as-is (no suppression)."""
        doc = self._build_doc(None)
        spiffe = self._seed_spiffe("openclaw")
        assert spiffe in doc, (
            "Seed should be present when registry_store=None"
        )

    def test_seed_suppression_does_not_affect_unclaimed(self) -> None:
        """Claiming letta does not affect openclaw's seed entry."""
        redis = _FakeRedis()
        letta_spiffe = self._seed_spiffe("letta")
        openclaw_spiffe = self._seed_spiffe("openclaw")
        store = _make_store(redis)
        # Claim and revoke letta only
        store.put_egress_grant("default", "letta", {
            "spiffe": letta_spiffe,
            "tenant": "default",
            "prefixes": ["llm"],
        })
        store.delete_egress_grant("default", "letta")

        doc = self._build_doc(redis)
        assert openclaw_spiffe in doc, (
            "openclaw seed must remain when only letta was claimed+revoked"
        )
        assert letta_spiffe not in doc, (
            "letta seed must be suppressed after claim+revoke"
        )


# ---------------------------------------------------------------------------
# FIX 2b — push_and_verify_egress_grants readback verification
# ---------------------------------------------------------------------------

class TestPushAndVerifyEgressGrants:
    """FIX 2b: revoke push must be verified via readback (Lu MF-2, Nico gaps 2/3)."""

    def _mock_push_and_get(self, get_result: dict, push_raises: Optional[Exception] = None):
        """Return context managers that mock push_egress_grants and the httpx GET."""
        import httpx

        # We mock push_egress_grants (already tested separately) and the httpx
        # GET call inside push_and_verify_egress_grants.
        push_mock = MagicMock(side_effect=push_raises)
        get_resp = MagicMock(spec=httpx.Response)
        get_resp.json.return_value = {"result": get_result}
        get_resp.raise_for_status = MagicMock()

        return push_mock, get_resp

    def test_2d_raises_when_must_absent_still_present_after_push(self) -> None:
        """Contract 2d: fail-closed when readback still shows revoked SPIFFE."""
        from yashigani.mcp._opa_push import push_and_verify_egress_grants

        revoked = "spiffe://td/openclaw"
        remaining_doc = {revoked: {"tenant": "default", "prefixes": ["llm"]}}

        with patch(
            "yashigani.mcp._opa_push.push_egress_grants",
        ) as mock_push, patch(
            "yashigani.pki.client.internal_httpx_sync_client",
        ) as mock_client_cm:
            # Simulate readback returning the STILL-PRESENT revoked SPIFFE
            mock_resp = MagicMock()
            mock_resp.json.return_value = {"result": remaining_doc}
            mock_resp.raise_for_status = MagicMock()
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = mock_resp
            mock_client_cm.return_value = mock_client

            with pytest.raises(RuntimeError, match="stale allow"):
                push_and_verify_egress_grants(
                    "https://policy:8181",
                    {},  # empty doc (revoked)
                    must_be_absent=frozenset([revoked]),
                )
            mock_push.assert_called_once()

    def test_2e_passes_when_must_absent_confirmed_gone(self) -> None:
        """Contract 2e: no error when readback confirms revoked SPIFFE is absent."""
        from yashigani.mcp._opa_push import push_and_verify_egress_grants

        revoked = "spiffe://td/openclaw"
        empty_doc: dict = {}  # revoked SPIFFE not present

        with patch(
            "yashigani.mcp._opa_push.push_egress_grants",
        ) as mock_push, patch(
            "yashigani.pki.client.internal_httpx_sync_client",
        ) as mock_client_cm:
            mock_resp = MagicMock()
            mock_resp.json.return_value = {"result": empty_doc}
            mock_resp.raise_for_status = MagicMock()
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = mock_resp
            mock_client_cm.return_value = mock_client

            # Must not raise
            push_and_verify_egress_grants(
                "https://policy:8181",
                {},
                must_be_absent=frozenset([revoked]),
            )
            mock_push.assert_called_once()
            mock_client.get.assert_called_once()

    def test_2f_no_readback_when_must_absent_empty(self) -> None:
        """Contract 2f: readback skipped when must_be_absent is None or empty."""
        from yashigani.mcp._opa_push import push_and_verify_egress_grants

        with patch(
            "yashigani.mcp._opa_push.push_egress_grants",
        ) as mock_push, patch(
            "yashigani.pki.client.internal_httpx_sync_client",
        ) as mock_client_cm:
            push_and_verify_egress_grants("https://policy:8181", {}, None)
            push_and_verify_egress_grants("https://policy:8181", {}, frozenset())
            assert mock_client_cm.call_count == 0, (
                "FIX-2b: readback was called even with empty must_be_absent — "
                "unnecessary OPA round-trip on every add"
            )
            assert mock_push.call_count == 2

    def test_2d_raises_when_push_itself_fails(self) -> None:
        """Push failure propagates immediately (no partial-success silent path)."""
        import httpx

        from yashigani.mcp._opa_push import push_and_verify_egress_grants

        with patch(
            "yashigani.mcp._opa_push.push_egress_grants",
            side_effect=httpx.RequestError("connection refused"),
        ):
            with pytest.raises(httpx.RequestError):
                push_and_verify_egress_grants(
                    "https://policy:8181",
                    {},
                    must_be_absent=frozenset(["spiffe://td/openclaw"]),
                )

    def test_2d_raises_when_readback_itself_fails(self) -> None:
        """Readback connection failure is also fail-closed (raises RuntimeError)."""
        from yashigani.mcp._opa_push import push_and_verify_egress_grants

        with patch("yashigani.mcp._opa_push.push_egress_grants"), patch(
            "yashigani.pki.client.internal_httpx_sync_client",
        ) as mock_cm:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.side_effect = ConnectionError("OPA down")
            mock_cm.return_value = mock_client

            with pytest.raises(RuntimeError, match="readback failed"):
                push_and_verify_egress_grants(
                    "https://policy:8181",
                    {},
                    must_be_absent=frozenset(["spiffe://td/openclaw"]),
                )


# ---------------------------------------------------------------------------
# Unit — claim_egress_seed idempotency and get_claimed_egress_seed_spiffes
# ---------------------------------------------------------------------------

class TestClaimEgressSeed:
    """Direct unit tests for the new claim methods."""

    def test_claim_is_idempotent(self) -> None:
        store = _make_store()
        store.claim_egress_seed("spiffe://td/openclaw")
        store.claim_egress_seed("spiffe://td/openclaw")
        claimed = store.get_claimed_egress_seed_spiffes()
        assert "spiffe://td/openclaw" in claimed
        assert len(claimed) == 1

    def test_empty_spiffe_is_noop(self) -> None:
        """Empty string passed to claim_egress_seed is a silent no-op."""
        store = _make_store()
        store.claim_egress_seed("")
        claimed = store.get_claimed_egress_seed_spiffes()
        assert len(claimed) == 0

    def test_multiple_systems_claimed_independently(self) -> None:
        store = _make_store()
        store.claim_egress_seed("spiffe://td/openclaw")
        store.claim_egress_seed("spiffe://td/langflow")
        claimed = store.get_claimed_egress_seed_spiffes()
        assert claimed == frozenset(["spiffe://td/openclaw", "spiffe://td/langflow"])

    def test_put_egress_grant_auto_claims(self) -> None:
        """put_egress_grant must call claim_egress_seed automatically."""
        redis = _FakeRedis()
        store = _make_store(redis)
        spiffe = "spiffe://td/openclaw"
        store.put_egress_grant("default", "openclaw", {
            "spiffe": spiffe,
            "tenant": "default",
            "prefixes": ["llm"],
        })
        claimed = store.get_claimed_egress_seed_spiffes()
        assert spiffe in claimed, (
            "put_egress_grant must claim the SPIFFE before writing the grant "
            "(design §4.4 / Lu MF-2a)"
        )

    def test_delete_egress_grant_does_not_clear_claimed(self) -> None:
        """Permanent claim: delete never removes from claimed set."""
        redis = _FakeRedis()
        store = _make_store(redis)
        spiffe = "spiffe://td/openclaw"
        store.put_egress_grant("default", "openclaw", {
            "spiffe": spiffe,
            "tenant": "default",
            "prefixes": ["llm"],
        })
        store.delete_egress_grant("default", "openclaw")
        claimed = store.get_claimed_egress_seed_spiffes()
        assert spiffe in claimed, (
            "delete_egress_grant must NOT clear the claimed set — permanent "
            "claim prevents seed resurfacing on future builds"
        )


# ---------------------------------------------------------------------------
# barrel export check
# ---------------------------------------------------------------------------

def test_barrel_exports_present() -> None:
    """New symbols are reachable via their module __all__."""
    from yashigani.mcp._egress_grants import (  # noqa: F401
        bundled_system_spiffe_set,
        build_egress_grants_doc,
        transitional_egress_seed,
    )
    from yashigani.mcp._opa_push import (  # noqa: F401
        push_and_verify_egress_grants,
        push_egress_grants,
        push_mcp_opa_data,
    )
    import yashigani.mcp._egress_grants as _eg
    import yashigani.mcp._opa_push as _push

    assert "bundled_system_spiffe_set" in _eg.__all__
    assert "push_and_verify_egress_grants" in _push.__all__
