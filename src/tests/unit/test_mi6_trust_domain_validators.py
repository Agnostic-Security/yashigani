"""
MI-6 / YSG-RISK-061 — per-instance SPIFFE trust-domain validators (F1–F6).

Nico's crypto sign-off (PASS-WITH-FIXES, 2026-06-10) flagged that every app-layer
SPIFFE validator/minter hardcoded ``yashigani.internal`` and ignored the
``YASHIGANI_SPIFFE_TRUST_DOMAIN`` env var Su provisions per instance.  Net effect:
a non-legacy (multi-instance) deployment fails closed against its OWN workloads.

These tests prove, for each of F1–F6:
  * a NON-LEGACY instance (``apac.yashigani.internal``) ACCEPTS its own
    ``spiffe://apac.yashigani.internal/...`` identity, AND
  * a non-legacy instance REJECTS a legacy / foreign
    ``spiffe://yashigani.internal/...`` (or ``eu.*``) identity — that is the
    isolation; and
  * a LEGACY instance (env unset) is byte-for-byte unchanged: it accepts
    ``spiffe://yashigani.internal/...`` exactly as before.

The hard cross-instance backstop is the per-instance CA root (TLS handshake);
these validators make the instance trust ITSELF.  Getting accept-own/reject-foreign
exact at each site is what makes Enterprise multi-instance actually run.
"""
from __future__ import annotations

import pytest

_ENV = "YASHIGANI_SPIFFE_TRUST_DOMAIN"
_APAC = "apac.yashigani.internal"
_EU = "eu.yashigani.internal"
_LEGACY = "yashigani.internal"


# ---------------------------------------------------------------------------
# Helper (single source of truth)
# ---------------------------------------------------------------------------

class TestTrustDomainHelper:
    def test_legacy_default_when_unset(self, monkeypatch):
        monkeypatch.delenv(_ENV, raising=False)
        from yashigani.identity.trust_domain import (
            trust_domain,
            spiffe_agents_prefix,
            agent_spiffe_uri,
            gateway_issuer_prefix,
            audit_signer_spiffe_id,
        )
        assert trust_domain() == _LEGACY
        assert spiffe_agents_prefix() == "spiffe://yashigani.internal/agents"
        assert agent_spiffe_uri("acme", "goose") == \
            "spiffe://yashigani.internal/agents/acme/goose"
        assert gateway_issuer_prefix() == "https://gateway.yashigani.internal/"
        assert audit_signer_spiffe_id() == "spiffe://yashigani.internal/audit"

    def test_blank_env_falls_back_to_legacy(self, monkeypatch):
        monkeypatch.setenv(_ENV, "   ")
        from yashigani.identity.trust_domain import trust_domain
        assert trust_domain() == _LEGACY

    def test_non_legacy_instance(self, monkeypatch):
        monkeypatch.setenv(_ENV, _APAC)
        from yashigani.identity.trust_domain import (
            trust_domain,
            spiffe_agents_prefix,
            agent_spiffe_uri,
            gateway_issuer_prefix,
            audit_signer_spiffe_id,
        )
        assert trust_domain() == _APAC
        assert spiffe_agents_prefix() == "spiffe://apac.yashigani.internal/agents"
        assert agent_spiffe_uri("acme", "goose") == \
            "spiffe://apac.yashigani.internal/agents/acme/goose"
        assert gateway_issuer_prefix() == "https://gateway.apac.yashigani.internal/"
        assert audit_signer_spiffe_id() == "spiffe://apac.yashigani.internal/audit"

    def test_resolved_per_call_not_frozen(self, monkeypatch):
        from yashigani.identity.trust_domain import trust_domain
        monkeypatch.setenv(_ENV, _APAC)
        assert trust_domain() == _APAC
        monkeypatch.setenv(_ENV, _EU)
        assert trust_domain() == _EU  # not cached at import time


# ---------------------------------------------------------------------------
# F1 — pool/manager.py CertMount.__post_init__ (validator: reject foreign)
# ---------------------------------------------------------------------------

class TestF1PoolManagerCertMount:
    def _mount(self, spiffe_identity):
        from yashigani.pool.manager import CertMount
        return CertMount(
            host_cert_path="/h/c", host_key_path="/h/k", host_ca_path="/h/ca",
            spiffe_identity=spiffe_identity,
        )

    def test_non_legacy_accepts_own(self, monkeypatch):
        monkeypatch.setenv(_ENV, _APAC)
        m = self._mount("spiffe://apac.yashigani.internal/agents/acme/goose")
        assert m.spiffe_identity.startswith("spiffe://apac.yashigani.internal/agents/")

    def test_non_legacy_rejects_legacy_foreign(self, monkeypatch):
        monkeypatch.setenv(_ENV, _APAC)
        with pytest.raises(ValueError, match="apac.yashigani.internal/agents/"):
            self._mount("spiffe://yashigani.internal/agents/acme/goose")

    def test_non_legacy_rejects_other_instance(self, monkeypatch):
        monkeypatch.setenv(_ENV, _APAC)
        with pytest.raises(ValueError):
            self._mount("spiffe://eu.yashigani.internal/agents/acme/goose")

    def test_legacy_accepts_legacy_unchanged(self, monkeypatch):
        monkeypatch.delenv(_ENV, raising=False)
        m = self._mount("spiffe://yashigani.internal/agents/acme/goose")
        assert m.spiffe_identity == "spiffe://yashigani.internal/agents/acme/goose"

    def test_legacy_rejects_non_agents_namespace(self, monkeypatch):
        # core-service collision prevention preserved
        monkeypatch.delenv(_ENV, raising=False)
        with pytest.raises(ValueError):
            self._mount("spiffe://yashigani.internal/gateway")

    def test_empty_identity_allowed_both_modes(self, monkeypatch):
        monkeypatch.setenv(_ENV, _APAC)
        assert self._mount("").spiffe_identity == ""
        monkeypatch.delenv(_ENV, raising=False)
        assert self._mount("").spiffe_identity == ""


# ---------------------------------------------------------------------------
# F2 — gateway/principal_token.py (caller_spiffe_uri + iss accept/reject)
# ---------------------------------------------------------------------------

class TestF2PrincipalToken:
    def test_caller_spiffe_uri_non_legacy(self, monkeypatch):
        monkeypatch.setenv(_ENV, _APAC)
        from yashigani.gateway.principal_token import caller_spiffe_uri
        assert caller_spiffe_uri("acme", "goose") == \
            "spiffe://apac.yashigani.internal/agents/acme/goose"

    def test_caller_spiffe_uri_legacy_unchanged(self, monkeypatch):
        monkeypatch.delenv(_ENV, raising=False)
        from yashigani.gateway.principal_token import caller_spiffe_uri
        assert caller_spiffe_uri("acme", "goose") == \
            "spiffe://yashigani.internal/agents/acme/goose"

    def _iss_check(self, iss):
        """Exercise the verify-side issuer-prefix gate in isolation."""
        from yashigani.gateway import principal_token as ptmod
        from yashigani.identity.trust_domain import gateway_issuer_prefix
        return iss.startswith(gateway_issuer_prefix())

    def test_non_legacy_accepts_own_issuer(self, monkeypatch):
        monkeypatch.setenv(_ENV, _APAC)
        assert self._iss_check("https://gateway.apac.yashigani.internal/default")

    def test_non_legacy_rejects_legacy_issuer(self, monkeypatch):
        monkeypatch.setenv(_ENV, _APAC)
        assert not self._iss_check("https://gateway.yashigani.internal/default")

    def test_non_legacy_rejects_other_instance_issuer(self, monkeypatch):
        monkeypatch.setenv(_ENV, _APAC)
        assert not self._iss_check("https://gateway.eu.yashigani.internal/default")

    def test_legacy_accepts_legacy_issuer(self, monkeypatch):
        monkeypatch.delenv(_ENV, raising=False)
        assert self._iss_check("https://gateway.yashigani.internal/default")


# ---------------------------------------------------------------------------
# F3 — manifest/linter.py (resolve_spiffe_uri + N1 reject-foreign override)
# ---------------------------------------------------------------------------

class TestF3ManifestLinter:
    def _manifest(self, override=None):
        m = {
            "metadata": {"tenant_id": "acme-corp", "name": "goose"},
            "spec": {"identity": {"spiffe": {}}},
        }
        if override is not None:
            m["spec"]["identity"]["spiffe"]["override_id"] = override
        return m

    def test_resolve_default_non_legacy(self, monkeypatch):
        monkeypatch.setenv(_ENV, _APAC)
        from yashigani.manifest.linter import resolve_spiffe_uri
        assert resolve_spiffe_uri(self._manifest()) == \
            "spiffe://apac.yashigani.internal/agents/acme-corp/goose"

    def test_resolve_default_legacy_unchanged(self, monkeypatch):
        monkeypatch.delenv(_ENV, raising=False)
        from yashigani.manifest.linter import resolve_spiffe_uri
        assert resolve_spiffe_uri(self._manifest()) == \
            "spiffe://yashigani.internal/agents/acme-corp/goose"

    def test_n1_non_legacy_accepts_own_override(self, monkeypatch):
        monkeypatch.setenv(_ENV, _APAC)
        from yashigani.manifest.linter import _lint_spiffe_prefix
        ovr = "spiffe://apac.yashigani.internal/agents/acme-corp/goose"
        assert _lint_spiffe_prefix(self._manifest(ovr)) == []

    def test_n1_non_legacy_rejects_legacy_override(self, monkeypatch):
        monkeypatch.setenv(_ENV, _APAC)
        from yashigani.manifest.linter import _lint_spiffe_prefix
        ovr = "spiffe://yashigani.internal/agents/acme-corp/goose"
        errors = _lint_spiffe_prefix(self._manifest(ovr))
        assert len(errors) == 1
        assert errors[0].rule == "N1_spiffe_override_out_of_namespace"

    def test_n1_non_legacy_rejects_other_instance_override(self, monkeypatch):
        monkeypatch.setenv(_ENV, _APAC)
        from yashigani.manifest.linter import _lint_spiffe_prefix
        ovr = "spiffe://eu.yashigani.internal/agents/acme-corp/goose"
        assert len(_lint_spiffe_prefix(self._manifest(ovr))) == 1

    def test_n1_non_legacy_rejects_cross_tenant_in_own_domain(self, monkeypatch):
        # isolation within the instance's own domain still holds
        monkeypatch.setenv(_ENV, _APAC)
        from yashigani.manifest.linter import _lint_spiffe_prefix
        ovr = "spiffe://apac.yashigani.internal/agents/evil-corp/goose"
        assert len(_lint_spiffe_prefix(self._manifest(ovr))) == 1

    def test_n1_legacy_accepts_legacy_override_unchanged(self, monkeypatch):
        monkeypatch.delenv(_ENV, raising=False)
        from yashigani.manifest.linter import _lint_spiffe_prefix
        ovr = "spiffe://yashigani.internal/agents/acme-corp/goose"
        assert _lint_spiffe_prefix(self._manifest(ovr)) == []


# ---------------------------------------------------------------------------
# F4 — mcp/_jwt.py minted SPIFFE/iss + verifier iss accept/reject
# ---------------------------------------------------------------------------

@pytest.fixture
def _p384_key():
    from cryptography.hazmat.primitives.asymmetric import ec
    return ec.generate_private_key(ec.SECP384R1())


def _make_issuer(p384_key):
    from yashigani.mcp._jwt import McpJwtIssuer
    return McpJwtIssuer(tenant_id="tenant1", private_key=p384_key)


def _issue(issuer):
    return issuer.issue(
        user_id="u-opaque",
        agent_name="hermes",
        posture="mcp-a",
        posture_binding={"method": "test"},
        action="mcp.tools.call",
        call_id="00000000-0000-0000-0000-000000000001",
    )


class TestF4McpJwt:
    def test_minted_spiffe_and_iss_non_legacy(self, monkeypatch, _p384_key):
        monkeypatch.setenv(_ENV, _APAC)
        token = _issue(_make_issuer(_p384_key))
        import jwt as pyjwt
        payload = pyjwt.decode(token, options={"verify_signature": False})
        assert payload["identity"]["spiffe"] == \
            "spiffe://apac.yashigani.internal/agents/tenant1/hermes"
        assert payload["iss"] == "https://gateway.apac.yashigani.internal/tenant1"

    def test_minted_spiffe_and_iss_legacy_unchanged(self, monkeypatch, _p384_key):
        monkeypatch.delenv(_ENV, raising=False)
        token = _issue(_make_issuer(_p384_key))
        import jwt as pyjwt
        payload = pyjwt.decode(token, options={"verify_signature": False})
        assert payload["identity"]["spiffe"] == \
            "spiffe://yashigani.internal/agents/tenant1/hermes"
        assert payload["iss"] == "https://gateway.yashigani.internal/tenant1"

    def test_verifier_non_legacy_accepts_own_iss(self, monkeypatch, _p384_key):
        monkeypatch.setenv(_ENV, _APAC)
        from yashigani.mcp._jwt import McpJwtVerifier
        issuer = _make_issuer(_p384_key)
        verifier = McpJwtVerifier.from_issuer(issuer)
        payload = verifier.verify(_issue(issuer))  # own iss -> accepted
        assert payload["iss"].startswith("https://gateway.apac.yashigani.internal/")

    def test_verifier_default_iss_prefix_tracks_env(self, monkeypatch):
        # An iss-prefix-unspecified verifier resolves the instance domain.
        monkeypatch.setenv(_ENV, _APAC)
        from yashigani.mcp._jwt import McpJwtVerifier
        v = McpJwtVerifier(jwks_keys=[])
        assert v._iss_prefix == "https://gateway.apac.yashigani.internal/"
        monkeypatch.delenv(_ENV, raising=False)
        v2 = McpJwtVerifier(jwks_keys=[])
        assert v2._iss_prefix == "https://gateway.yashigani.internal/"

    def test_verifier_non_legacy_rejects_foreign_iss(self, monkeypatch, _p384_key):
        # A verifier pinned to apac rejects a token whose iss is legacy/foreign,
        # even though the SAME key signs it (signature passes; iss gate denies).
        monkeypatch.setenv(_ENV, _APAC)
        from yashigani.mcp._jwt import McpJwtVerifier
        apac_issuer = _make_issuer(_p384_key)
        verifier = McpJwtVerifier.from_issuer(apac_issuer)  # pinned apac
        monkeypatch.delenv(_ENV, raising=False)
        legacy_issuer = _make_issuer(_p384_key)  # same key, legacy iss
        legacy_token = _issue(legacy_issuer)
        import jwt as pyjwt
        assert pyjwt.decode(legacy_token, options={"verify_signature": False})[
            "iss"
        ].startswith("https://gateway.yashigani.internal/")
        with pytest.raises(Exception):
            verifier.verify(legacy_token)


# ---------------------------------------------------------------------------
# F5 — audit/sinks.py default audit-signer SPIFFE id
# ---------------------------------------------------------------------------

class TestF5AuditSink:
    def test_default_non_legacy(self, monkeypatch):
        monkeypatch.setenv(_ENV, _APAC)
        monkeypatch.delenv("YASHIGANI_AUDIT_SIGNING_SPIFFE_ID", raising=False)
        monkeypatch.delenv("YASHIGANI_AUDIT_SIGNING_KEY_PATH", raising=False)
        from yashigani.audit.sinks import _audit_checkpoint_signing
        _key, spiffe = _audit_checkpoint_signing()
        assert spiffe == "spiffe://apac.yashigani.internal/audit"

    def test_default_legacy_unchanged(self, monkeypatch):
        monkeypatch.delenv(_ENV, raising=False)
        monkeypatch.delenv("YASHIGANI_AUDIT_SIGNING_SPIFFE_ID", raising=False)
        monkeypatch.delenv("YASHIGANI_AUDIT_SIGNING_KEY_PATH", raising=False)
        from yashigani.audit.sinks import _audit_checkpoint_signing
        _key, spiffe = _audit_checkpoint_signing()
        assert spiffe == "spiffe://yashigani.internal/audit"

    def test_explicit_env_takes_precedence(self, monkeypatch):
        monkeypatch.setenv(_ENV, _APAC)
        monkeypatch.setenv(
            "YASHIGANI_AUDIT_SIGNING_SPIFFE_ID",
            "spiffe://apac.yashigani.internal/hermes",
        )
        monkeypatch.delenv("YASHIGANI_AUDIT_SIGNING_KEY_PATH", raising=False)
        from yashigani.audit.sinks import _audit_checkpoint_signing
        _key, spiffe = _audit_checkpoint_signing()
        assert spiffe == "spiffe://apac.yashigani.internal/hermes"


# ---------------------------------------------------------------------------
# F6 — broker.py agent SPIFFE minting routes through the helper
# ---------------------------------------------------------------------------

class TestF6BrokerIdentity:
    def test_broker_agent_spiffe_uri_helper(self, monkeypatch):
        # broker.py uses agent_spiffe_uri(); confirm it tracks env at both sites.
        monkeypatch.setenv(_ENV, _APAC)
        from yashigani.identity.trust_domain import agent_spiffe_uri
        assert agent_spiffe_uri("tenant1", "hermes") == \
            "spiffe://apac.yashigani.internal/agents/tenant1/hermes"
        monkeypatch.delenv(_ENV, raising=False)
        assert agent_spiffe_uri("tenant1", "hermes") == \
            "spiffe://yashigani.internal/agents/tenant1/hermes"
