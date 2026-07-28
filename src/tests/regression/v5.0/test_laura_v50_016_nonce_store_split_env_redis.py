# Last updated: 2026-07-28T00:00:00+00:00
"""
Regression — LAURA-V50-016 (High, P0): ``mcp/registry.py``'s nonce-store
wiring (``build_registry_from_env``, Fix-4/HA-correctness block) read a
bare, single-string ``REDIS_URL`` env var that this deployment (and every
deployment installed via ``docker/docker-compose.yml`` or ``helm/``) NEVER
sets — the gateway's actual Redis configuration is the SPLIT
``REDIS_HOST`` / ``REDIS_PORT`` / ``REDIS_USE_TLS`` trio, resolved
everywhere else in ``gateway/entrypoint.py`` via ``_gw_redis_url()`` /
``gateway/_redis_url.py::build_redis_url()``.

Because ``REDIS_URL`` was never set, ``_nonce_store`` silently fell back to
``InMemoryNonceStore`` at boot (only a WARNING log — easy to miss).  That
in-memory store was then threaded into EVERY broker built by
``_build_broker_and_config`` — including brokers lazily built by the
SEAM-1d-07 durable-registry fallback (``McpBrokerRegistry.get()`` on a
lookup miss).  ``McpBroker.__init__``'s LAURA-411-002/YSG-RISK-055
defense-in-depth guard then correctly REFUSED to construct with an
``InMemoryNonceStore`` outside dev/test (``YASHIGANI_ENV=production``),
raising ``RuntimeError``.  ``McpBrokerRegistry.get()``'s exception handler
(by design: "bad descriptor degrades to miss") downgraded that raise to a
404 — indistinguishable from a genuine "not registered" lookup miss.  Net
effect: every MCP server onboarded via the live-import ceremony (i.e.
EVERY live-onboarded server, since ``YASHIGANI_MCP_SERVERS=[]`` at boot in
the documented onboarding topology) was permanently unreachable in
production, regardless of approval/grant/tool-surface correctness.

Fix under test (Tom, 2026-07-28):
  ``mcp/registry.py``'s nonce-store selection now gates on ``REDIS_HOST``
  (the split-env "is Redis configured" signal, mirroring the old
  ``REDIS_URL``-presence check) and, when set, builds the Redis URL via
  ``gateway/_redis_url.py::build_redis_url()`` — the SAME split-env →
  ``rediss://`` construction every other Redis consumer in
  ``gateway/entrypoint.py`` uses (DB 3, shared with the MCP id store /
  durable registry store).  ``REDIS_URL`` is no longer read at all.

This suite proves: (A) split-env Redis config (no ``REDIS_URL``) selects
``RedisNonceStore``, not ``InMemoryNonceStore``; (B) the full SEAM-1d-07
lazy-load path — the EXACT reproduction Laura ran (durable-store
descriptor, ``YASHIGANI_ENV=production``, live tools/call against a
never-boot-listed, live-onboarded server) — builds the broker
successfully (no raise, no None/404 downgrade); (C) with ``REDIS_HOST``
genuinely unset (no Redis configured — dev/test), ``InMemoryNonceStore``
is still selected (unchanged, intentional dev-mode behaviour).

References: LAURA-V50-016 finding,
``src/yashigani/mcp/registry.py:291-360`` (nonce-store selection),
``src/yashigani/mcp/broker.py:298-314`` (LAURA-411-002/YSG-RISK-055 guard),
``src/yashigani/gateway/_redis_url.py`` (``build_redis_url``),
``src/yashigani/gateway/entrypoint.py:84`` (``_gw_redis_url``).
"""
from __future__ import annotations

import base64
import json
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1

from yashigani.mcp._durable_registry import DurableMcpRegistryStore
from yashigani.mcp._id_store import McpIdStore

_TENANT = "default"
_SERVER = "cloud9-demo"


class _FakeRedis:
    """Minimal in-memory Redis stand-in for the durable/id stores — same
    shape used across the mcp/_id_store + _durable_registry test suites.
    Deliberately independent of the mocked ``redis`` module used for the
    nonce-store's own ``redis.from_url()`` call under test."""

    def __init__(self):
        self.kv: dict = {}
        self.sets: dict = {}

    def set(self, k, v):
        self.kv[k] = v.encode() if isinstance(v, str) else v

    def get(self, k):
        return self.kv.get(k)

    def delete(self, *keys):
        for k in keys:
            self.kv.pop(k, None)

    def sadd(self, k, m):
        self.sets.setdefault(k, set()).add(m.encode() if isinstance(m, str) else m)

    def srem(self, k, m):
        self.sets.get(k, set()).discard(m.encode() if isinstance(m, str) else m)

    def smembers(self, k):
        return set(self.sets.get(k, set()))


def _pem_b64_p384() -> str:
    """Generate a fresh P-384 key and base64-wrap it for
    YASHIGANI_MCP_SIGNING_KEY_PEM — production McpJwtIssuer refuses an
    ephemeral key (Fix-5), so a real key must be injected."""
    key = ec.generate_private_key(SECP384R1())
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return base64.b64encode(pem).decode()


def _live_imported_descriptor(mcp_id: str) -> dict:
    """Shape mcp_onboard.py step 4b writes for a live-imported server —
    identical to the descriptor Laura's reproduction onboarded."""
    return {
        "agent_name": _SERVER,
        "upstream_url": "https://caddy:9443/mcp/%s/%s" % (_TENANT, _SERVER),
        "tenant_id": _TENANT,
        "is_filesystem_agent": False,
        "is_git_agent": False,
        "cert_fingerprint": "sha256:deadbeef",
        "spiffe_id": "spiffe://yashigani-local.yashigani.internal/agents/%s/%s/nhi_x"
        % (_TENANT, _SERVER),
        "svid_instance_id": "nhi_x",
        "image_digest": "",
        "mcp_id": mcp_id,
    }


def _mock_redis_module():
    """A drop-in ``redis`` module mock: ``redis.from_url(...)`` returns a
    bare MagicMock (RedisNonceStore does no connectivity check at
    construction time — see mcp/_nonce.py:165)."""
    return MagicMock(from_url=MagicMock(return_value=MagicMock()))


class TestSplitEnvSelectsRedisNonceStore:
    """(A) REDIS_HOST/PORT/USE_TLS set, REDIS_URL unset -> RedisNonceStore,
    NOT InMemoryNonceStore, for a plain YASHIGANI_MCP_SERVERS boot entry."""

    def test_redis_host_split_env_selects_redis_nonce_store(self, monkeypatch):
        monkeypatch.delenv("REDIS_URL", raising=False)
        monkeypatch.setenv("REDIS_HOST", "redis")
        monkeypatch.setenv("REDIS_PORT", "6380")
        monkeypatch.setenv("REDIS_USE_TLS", "true")
        monkeypatch.setenv("YASHIGANI_MCP_SERVERS", json.dumps([{
            "agent_name": "test-mcp",
            "upstream_url": "http://test-mcp:8000",
            "tenant_id": "acme",
        }]))

        from yashigani.mcp._nonce import RedisNonceStore
        import importlib
        import yashigani.mcp.registry as _reg_module
        importlib.reload(_reg_module)

        with patch.dict("sys.modules", {"redis": _mock_redis_module()}):
            from yashigani.mcp.registry import build_registry_from_env
            reg, _ = build_registry_from_env(opa_url="http://policy:8181")

        assert len(reg) == 1
        broker, _ = reg.get("test-mcp")
        assert isinstance(broker._nonce_store, RedisNonceStore), (
            "REDIS_HOST/PORT/USE_TLS (split-env, no REDIS_URL) must select "
            "RedisNonceStore — LAURA-V50-016 regression."
        )

    def test_redis_url_alone_no_longer_wires_redis(self, monkeypatch):
        """Sanity: REDIS_URL is no longer read at all — setting ONLY the
        (now-dead) bare env var, with no REDIS_HOST, must still fall back
        to InMemoryNonceStore (proves the old code path is fully retired,
        not just supplemented)."""
        monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
        monkeypatch.delenv("REDIS_HOST", raising=False)
        monkeypatch.setenv("YASHIGANI_MCP_SERVERS", json.dumps([{
            "agent_name": "test-mcp",
            "upstream_url": "http://test-mcp:8000",
            "tenant_id": "acme",
        }]))

        from yashigani.mcp._nonce import InMemoryNonceStore
        import importlib
        import yashigani.mcp.registry as _reg_module
        importlib.reload(_reg_module)

        from yashigani.mcp.registry import build_registry_from_env
        reg, _ = build_registry_from_env(opa_url="http://policy:8181")

        assert len(reg) == 1
        broker, _ = reg.get("test-mcp")
        assert isinstance(broker._nonce_store, InMemoryNonceStore)

    def test_redis_host_absent_still_uses_in_memory(self, monkeypatch):
        """(C) Genuinely unconfigured (dev/test, no Redis at all) ->
        InMemoryNonceStore, unchanged behaviour."""
        monkeypatch.delenv("REDIS_URL", raising=False)
        monkeypatch.delenv("REDIS_HOST", raising=False)
        monkeypatch.setenv("YASHIGANI_MCP_SERVERS", json.dumps([{
            "agent_name": "test-mcp",
            "upstream_url": "http://test-mcp:8000",
            "tenant_id": "acme",
        }]))

        from yashigani.mcp._nonce import InMemoryNonceStore
        import importlib
        import yashigani.mcp.registry as _reg_module
        importlib.reload(_reg_module)

        from yashigani.mcp.registry import build_registry_from_env
        reg, _ = build_registry_from_env(opa_url="http://policy:8181")

        assert len(reg) == 1
        broker, _ = reg.get("test-mcp")
        assert isinstance(broker._nonce_store, InMemoryNonceStore)


class TestLazyBrokerBuildsInProductionWithSplitEnvRedis:
    """(B) The exact LAURA-V50-016 reproduction: YASHIGANI_ENV=production +
    split-env Redis (REDIS_HOST/PORT/USE_TLS, no REDIS_URL) + a durable-
    store descriptor for a live-onboarded server (never in the boot-time
    YASHIGANI_MCP_SERVERS list) -> McpBrokerRegistry.get(name) must
    SUCCEED (a real broker, RedisNonceStore-backed), not raise-downgraded-
    to-None/404."""

    def test_lazy_broker_builds_not_inmemory_not_raise(self, monkeypatch):
        monkeypatch.setenv("YASHIGANI_ENV", "production")
        monkeypatch.setenv("YASHIGANI_MCP_SIGNING_KEY_PEM", _pem_b64_p384())
        monkeypatch.delenv("REDIS_URL", raising=False)
        monkeypatch.setenv("REDIS_HOST", "redis")
        monkeypatch.setenv("REDIS_PORT", "6380")
        monkeypatch.setenv("REDIS_USE_TLS", "true")
        # Boot-time list is empty — mirrors the documented live-onboard-only
        # topology (YASHIGANI_MCP_SERVERS=[]) that made this bug invisible
        # until a server was actually onboarded post-boot (SEAM-1d-07).
        monkeypatch.delenv("YASHIGANI_MCP_SERVERS", raising=False)

        from yashigani.mcp._nonce import InMemoryNonceStore, RedisNonceStore
        import importlib
        import yashigani.mcp.registry as _reg_module
        importlib.reload(_reg_module)

        durable_redis = _FakeRedis()
        mcp_id_store = McpIdStore(durable_redis)
        durable_store = DurableMcpRegistryStore(durable_redis)
        minted = mcp_id_store.get_or_mint(_SERVER)
        durable_store.put(_TENANT, _SERVER, _live_imported_descriptor(minted))

        with patch.dict("sys.modules", {"redis": _mock_redis_module()}):
            from yashigani.mcp.registry import build_registry_from_env
            registry, jwks_store = build_registry_from_env(
                opa_url="https://policy:8181",
                audit_writer=MagicMock(),  # FIX-D: production requires a real writer
                mcp_id_store=mcp_id_store,
                durable_store=durable_store,
            )

            assert len(registry) == 0, (
                "sanity: nothing lazily built yet — this is the exact "
                "instant the SEAM-1d-07 lazy path is first exercised"
            )
            assert jwks_store is not None

            hit = registry.get(_SERVER)

        assert hit is not None, (
            "LAURA-V50-016 REGRESSION: McpBrokerRegistry.get() degraded a "
            "REAL, approved, live-onboarded server to a lookup miss (404) "
            "— the exact bug: InMemoryNonceStore silently wired because "
            "REDIS_URL (never set by this deployment) was read instead of "
            "the split REDIS_HOST/REDIS_PORT/REDIS_USE_TLS trio, then "
            "refused by McpBroker's LAURA-411-002 production guard."
        )
        broker, server_cfg = hit
        assert server_cfg.agent_name == _SERVER
        assert server_cfg.mcp_id == minted
        assert isinstance(broker._nonce_store, RedisNonceStore), (
            "the lazily-built broker must be backed by RedisNonceStore in "
            "production — an InMemoryNonceStore here would have raised "
            "inside McpBroker.__init__ (LAURA-411-002) instead of reaching "
            "this assertion at all"
        )
        assert not isinstance(broker._nonce_store, InMemoryNonceStore)
