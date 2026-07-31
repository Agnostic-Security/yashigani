"""
Principal-verifier prod fail-closed guard — gateway/principal_token.py::
build_principal_machinery().

Before this fix, when REDIS_HOST was unset ``build_principal_machinery()``
silently fell back to ``InMemoryNonceStore`` in EVERY environment, including
production — the exact silent-degrade class LAURA-V50-018 fixed for the
bare-REDIS_URL read in the same function. This mirrors the LAURA-411-002 /
YSG-RISK-055 guard McpBroker.__init__ already applies (mcp/broker.py
~lines 297-313): YASHIGANI_ENV is read, allow-listed to {"dev", "test", ""},
and any other value with no REDIS_HOST raises RuntimeError at startup
instead of silently degrading.

Author: Tom. Last updated: 2026-07-31.
"""
from __future__ import annotations

import base64
import importlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1


def _pem_b64_p384() -> str:
    """Fresh P-384 key, base64-wrapped for YASHIGANI_MCP_SIGNING_KEY_PEM —
    production McpJwtIssuer (which OrchestrationPrincipalSigner composes
    over) refuses an ephemeral key, so a prod-env test must supply one."""
    key = ec.generate_private_key(SECP384R1())
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.b64encode(pem).decode("ascii")


def _reload_principal_token():
    import yashigani.gateway.principal_token as _pt_module
    importlib.reload(_pt_module)
    return _pt_module


class TestProdNoRedisHostFailsClosed:
    @pytest.mark.parametrize("env_value", ["production", "staging", "qa", "preprod"])
    def test_prod_like_env_no_redis_host_raises(self, monkeypatch, env_value):
        """No REDIS_HOST + any non-dev/test/empty YASHIGANI_ENV -> RuntimeError,
        never a silent InMemoryNonceStore fallback."""
        monkeypatch.setenv("YASHIGANI_ENV", env_value)
        monkeypatch.setenv("YASHIGANI_MCP_SIGNING_KEY_PEM", _pem_b64_p384())
        monkeypatch.delenv("REDIS_URL", raising=False)
        monkeypatch.delenv("REDIS_HOST", raising=False)

        pt_module = _reload_principal_token()

        with pytest.raises(RuntimeError, match="LAURA-411-002|InMemoryNonceStore"):
            pt_module.build_principal_machinery(tenant_id="acme")

    def test_prod_env_message_cites_finding_and_remediation(self, monkeypatch):
        monkeypatch.setenv("YASHIGANI_ENV", "production")
        monkeypatch.setenv("YASHIGANI_MCP_SIGNING_KEY_PEM", _pem_b64_p384())
        monkeypatch.delenv("REDIS_URL", raising=False)
        monkeypatch.delenv("REDIS_HOST", raising=False)

        pt_module = _reload_principal_token()

        with pytest.raises(RuntimeError) as exc_info:
            pt_module.build_principal_machinery(tenant_id="acme")

        msg = str(exc_info.value)
        assert "LAURA-411-002" in msg
        assert "YSG-RISK-055" in msg
        assert "REDIS_HOST" in msg


class TestDevTestEmptyEnvNoRedisHostStillInMemory:
    @pytest.mark.parametrize("env_value", ["dev", "test", ""])
    def test_safe_env_no_redis_host_uses_in_memory(self, monkeypatch, env_value):
        """dev / test / empty (unset) YASHIGANI_ENV + no REDIS_HOST ->
        InMemoryNonceStore, unchanged behaviour — no regression."""
        if env_value:
            monkeypatch.setenv("YASHIGANI_ENV", env_value)
        else:
            monkeypatch.delenv("YASHIGANI_ENV", raising=False)
        monkeypatch.delenv("YASHIGANI_MCP_SIGNING_KEY_PEM", raising=False)
        monkeypatch.delenv("REDIS_URL", raising=False)
        monkeypatch.delenv("REDIS_HOST", raising=False)

        from yashigani.mcp._nonce import InMemoryNonceStore

        pt_module = _reload_principal_token()
        signer, verifier = pt_module.build_principal_machinery(tenant_id="acme")

        assert isinstance(verifier._nonce, InMemoryNonceStore)

    def test_prod_env_with_redis_host_set_still_works(self, monkeypatch):
        """Sanity: the guard only fires when REDIS_HOST is ABSENT. Prod env
        with REDIS_HOST configured must NOT raise (covered functionally by
        the existing LAURA-V50-018 suite; re-asserted here alongside the
        new guard so the two behaviours are proven side by side)."""
        from unittest.mock import MagicMock, patch

        monkeypatch.setenv("YASHIGANI_ENV", "production")
        monkeypatch.setenv("YASHIGANI_MCP_SIGNING_KEY_PEM", _pem_b64_p384())
        monkeypatch.delenv("REDIS_URL", raising=False)
        monkeypatch.setenv("REDIS_HOST", "redis")
        monkeypatch.setenv("REDIS_PORT", "6380")
        monkeypatch.setenv("REDIS_USE_TLS", "true")

        from yashigani.mcp._nonce import RedisNonceStore

        pt_module = _reload_principal_token()
        mock_redis = MagicMock(from_url=MagicMock(return_value=MagicMock()))
        with patch.dict("sys.modules", {"redis": mock_redis}):
            signer, verifier = pt_module.build_principal_machinery(tenant_id="acme")

        assert isinstance(verifier._nonce, RedisNonceStore)
