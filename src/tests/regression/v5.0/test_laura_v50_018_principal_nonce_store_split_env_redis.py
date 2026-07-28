# Last updated: 2026-07-28T00:00:00+00:00
"""
Regression — LAURA-V50-018 (twin of LAURA-V50-016): ``gateway/principal_
token.py``'s ``build_principal_machinery()`` (the signed orchestration-
principal claim machinery, #47/G-NEW-5/R3 — used for agent-to-agent OPA
adjudication, NOT the MCP broker's own relay-JWT path) read a bare, single-
string ``REDIS_URL`` env var — the IDENTICAL defect LAURA-V50-016 found in
``mcp/registry.py``'s nonce-store wiring. This deployment (and every
deployment installed via ``docker/docker-compose.yml`` or ``helm/``) never
sets a bare ``REDIS_URL`` for the gateway service; Redis is configured via
the split ``REDIS_HOST``/``REDIS_PORT``/``REDIS_USE_TLS`` trio.

Unlike the MCP broker path (which has McpBroker.__init__'s LAURA-411-002/
YSG-RISK-055 fail-closed guard refusing an InMemoryNonceStore outside dev/
test), ``OrchestrationPrincipalVerifier`` has NO equivalent guard — so this
twin defect was a SILENT security degrade rather than a fail-closed raise:
the orchestration-principal jti replay-dedup silently ran on a PER-PROCESS
InMemoryNonceStore in production, defeating cross-replica replay detection
for the signed agent-to-agent principal claim (multi-replica deployments:
a replayed claim admitted by replica A would not be recognised as replayed
by replica B).

Fix under test (Tom, 2026-07-28, same sweep as LAURA-V50-016): gate the
nonce-store selection on ``REDIS_HOST`` (split-env signal) and build the
URL via ``gateway/_redis_url.py::build_redis_url(3, client_cert_name=
"gateway_client")`` — DB 3, the SAME DB the MCP broker's own nonce store
uses (mcp/registry.py) — matching this module's own docstring claim that
it reuses "the SAME store the MCP broker uses for relay-JWT dedup".
``REDIS_URL`` is no longer read.

This suite proves: split-env Redis config (no REDIS_URL) selects
RedisNonceStore, not InMemoryNonceStore, for both the plain call and the
production-env path (McpJwtIssuer's own production key guard is satisfied
via an injected P-384 key so this test isolates the nonce-store defect).
"""
from __future__ import annotations

import base64
from unittest.mock import MagicMock, patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1


def _pem_b64_p384() -> str:
    """Generate a fresh P-384 key and base64-wrap it for
    YASHIGANI_MCP_SIGNING_KEY_PEM — production McpJwtIssuer (which
    OrchestrationPrincipalSigner composes over) refuses an ephemeral key."""
    key = ec.generate_private_key(SECP384R1())
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.b64encode(pem).decode("ascii")


def _mock_redis_module():
    """Drop-in ``redis`` module mock — RedisNonceStore does no connectivity
    check at construction time (mcp/_nonce.py:165)."""
    return MagicMock(from_url=MagicMock(return_value=MagicMock()))


class TestPrincipalMachinerySplitEnvSelectsRedisNonceStore:
    def test_redis_host_split_env_selects_redis_nonce_store(self, monkeypatch):
        """REDIS_HOST/PORT/USE_TLS set, REDIS_URL unset -> RedisNonceStore."""
        monkeypatch.delenv("REDIS_URL", raising=False)
        monkeypatch.setenv("REDIS_HOST", "redis")
        monkeypatch.setenv("REDIS_PORT", "6380")
        monkeypatch.setenv("REDIS_USE_TLS", "true")
        monkeypatch.delenv("YASHIGANI_ENV", raising=False)
        monkeypatch.delenv("YASHIGANI_MCP_SIGNING_KEY_PEM", raising=False)

        from yashigani.mcp._nonce import RedisNonceStore
        import importlib
        import yashigani.gateway.principal_token as _pt_module
        importlib.reload(_pt_module)

        with patch.dict("sys.modules", {"redis": _mock_redis_module()}):
            signer, verifier = _pt_module.build_principal_machinery(tenant_id="acme")

        assert isinstance(verifier._nonce, RedisNonceStore), (
            "LAURA-V50-018 regression: REDIS_HOST (split-env, no REDIS_URL) "
            "must select RedisNonceStore for the orchestration-principal "
            "replay store."
        )

    def test_production_env_split_env_redis_selects_redis_not_inmemory(
        self, monkeypatch
    ):
        """The exact LAURA-V50-018 production reproduction: YASHIGANI_ENV=
        production + split-env Redis (no REDIS_URL) -> RedisNonceStore, not
        the silently-degraded InMemoryNonceStore."""
        monkeypatch.setenv("YASHIGANI_ENV", "production")
        monkeypatch.setenv("YASHIGANI_MCP_SIGNING_KEY_PEM", _pem_b64_p384())
        monkeypatch.delenv("REDIS_URL", raising=False)
        monkeypatch.setenv("REDIS_HOST", "redis")
        monkeypatch.setenv("REDIS_PORT", "6380")
        monkeypatch.setenv("REDIS_USE_TLS", "true")

        from yashigani.mcp._nonce import InMemoryNonceStore, RedisNonceStore
        import importlib
        import yashigani.gateway.principal_token as _pt_module
        importlib.reload(_pt_module)

        with patch.dict("sys.modules", {"redis": _mock_redis_module()}):
            signer, verifier = _pt_module.build_principal_machinery(tenant_id="acme")

        assert isinstance(verifier._nonce, RedisNonceStore)
        assert not isinstance(verifier._nonce, InMemoryNonceStore), (
            "LAURA-V50-018 REGRESSION: orchestration-principal replay dedup "
            "silently degraded to a per-process InMemoryNonceStore in "
            "production — defeats cross-replica replay detection for the "
            "signed agent-to-agent principal claim."
        )

    def test_redis_url_alone_no_longer_wires_redis(self, monkeypatch):
        """Sanity: REDIS_URL is no longer read at all — setting ONLY the
        (now-dead) bare env var, with no REDIS_HOST, still falls back to
        InMemoryNonceStore (proves the old code path is fully retired)."""
        monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
        monkeypatch.delenv("REDIS_HOST", raising=False)
        monkeypatch.delenv("YASHIGANI_ENV", raising=False)
        monkeypatch.delenv("YASHIGANI_MCP_SIGNING_KEY_PEM", raising=False)

        from yashigani.mcp._nonce import InMemoryNonceStore
        import importlib
        import yashigani.gateway.principal_token as _pt_module
        importlib.reload(_pt_module)

        signer, verifier = _pt_module.build_principal_machinery(tenant_id="acme")
        assert isinstance(verifier._nonce, InMemoryNonceStore)

    def test_redis_host_absent_still_uses_in_memory(self, monkeypatch):
        """Genuinely unconfigured (dev/test, no Redis at all) ->
        InMemoryNonceStore, unchanged behaviour."""
        monkeypatch.delenv("REDIS_URL", raising=False)
        monkeypatch.delenv("REDIS_HOST", raising=False)
        monkeypatch.delenv("YASHIGANI_ENV", raising=False)
        monkeypatch.delenv("YASHIGANI_MCP_SIGNING_KEY_PEM", raising=False)

        from yashigani.mcp._nonce import InMemoryNonceStore
        import importlib
        import yashigani.gateway.principal_token as _pt_module
        importlib.reload(_pt_module)

        signer, verifier = _pt_module.build_principal_machinery(tenant_id="acme")
        assert isinstance(verifier._nonce, InMemoryNonceStore)
