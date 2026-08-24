"""
YSG-RISK-253 — Per-tenant JWT signing key isolation (test suite).

Proves that HKDF-based per-tenant key derivation correctly isolates MCP
identity JWTs across tenants so that:
  1. A token minted under tenant A's derived key is REJECTED by tenant B's
     verifier (cross-tenant forgery prevention).
  2. Same-tenant round-trips succeed.
  3. The "default" (single-tenant) install continues to work unchanged.
  4. Derivation is deterministic — same root + tenant_id → same key every time.
  5. Different tenant_ids always produce distinct keys (from the same root).
  6. Each derived key is a valid secp384r1 EC key.
  7. TenantJwtKeyStore caches keys and reuses derived instances.

Coverage matrix:
  A. derive_tenant_ec_key — input validation
     A1. Non-EC root_key raises TypeError
     A2. Wrong EC curve raises ValueError
     A3. Empty tenant_id raises ValueError
     A4. Whitespace-only tenant_id raises ValueError

  B. derive_tenant_ec_key — derivation correctness
     B1. Output is a valid EllipticCurvePrivateKey on secp384r1
     B2. Two calls with the same inputs produce the same private scalar (determinism)
     B3. Different tenant_ids produce DIFFERENT private scalars (isolation)
     B4. Different root keys for the same tenant_id produce different scalars
     B5. Derived scalar is in [1, n-1] (valid P-384 range)

  C. McpJwtIssuer — per-tenant key loaded (via env-var PEM root)
     C1. Two issuers with the same root but different tenant_ids have different public keys
     C2. Same root + same tenant_id → same public key (determinism)
     C3. McpJwtVerifier from issuer A rejects tokens issued by issuer B (cross-tenant)
     C4. McpJwtVerifier from issuer A accepts tokens issued by issuer A (same-tenant)

  D. Single-tenant / default backward compatibility
     D1. McpJwtIssuer("default") with an env-var root → valid issuer, self-test passes
     D2. Token issued and verified within the same default-tenant issuer

  E. TenantJwtKeyStore
     E1. get_key returns a valid P-384 key
     E2. Two tenants get distinct keys
     E3. Same tenant repeated call returns the same key object (cached)
     E4. Stores root key — TypeError on non-EC input
     E5. Stores root key — ValueError on wrong curve

  F. Security invariants
     F1. McpJwtVerifier created from issuer_a rejects a token signed by issuer_b
         even when both issuers used the same install-wide root PEM (cross-tenant
         forgery is cryptographically impossible)
     F2. Altering the tenant claim in a valid token does not bypass verification
         (token integrity is protected by the ES384 signature)
"""
from __future__ import annotations

import base64
import os
import time
import uuid
from typing import Optional

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    SECP384R1,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _generate_p384_key() -> EllipticCurvePrivateKey:
    """Generate a fresh ephemeral P-384 key (root key stand-in for tests)."""
    return ec.generate_private_key(SECP384R1())


def _pem_b64(key: EllipticCurvePrivateKey) -> str:
    """Encode a private key as base64-wrapped PEM for YASHIGANI_MCP_SIGNING_KEY_PEM."""
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return base64.b64encode(pem).decode()


def _make_issuer(tenant_id: str, root_key: EllipticCurvePrivateKey, monkeypatch):
    """
    Create a McpJwtIssuer for *tenant_id* using *root_key* as the install-wide root.
    Injects the root key via YASHIGANI_MCP_SIGNING_KEY_PEM.
    """
    from yashigani.mcp._jwt import McpJwtIssuer
    monkeypatch.setenv("YASHIGANI_MCP_SIGNING_KEY_PEM", _pem_b64(root_key))
    # Clear the key path so the env var takes precedence
    monkeypatch.delenv("YASHIGANI_MCP_SIGNING_KEY_PATH", raising=False)
    return McpJwtIssuer(tenant_id=tenant_id)


def _issue_token(issuer) -> str:
    """Issue a minimal MCP JWT using *issuer*."""
    return issuer.issue(
        user_id="test-user",
        agent_name="test-agent",
        posture="mcp-b",
        posture_binding={"derived_from": "tls_channel", "channel_type": "network-streamable-http"},
        action="mcp.tools.call",
        call_id=str(uuid.uuid4()),
        upstream_chain=None,
    )


# ---------------------------------------------------------------------------
# A. derive_tenant_ec_key — input validation
# ---------------------------------------------------------------------------

class TestDeriveTenantEcKeyInputValidation:
    """A1–A4: input guard-rails on derive_tenant_ec_key."""

    def test_a1_non_ec_root_raises_typeerror(self):
        """A1: non-EllipticCurvePrivateKey root raises TypeError."""
        from yashigani.auth._jwt import derive_tenant_ec_key
        with pytest.raises(TypeError, match="EllipticCurvePrivateKey"):
            derive_tenant_ec_key("not-a-key", "tenant-a")  # type: ignore[arg-type]

    def test_a2_wrong_ec_curve_raises_valueerror(self):
        """A2: P-256 root key raises ValueError (must be P-384)."""
        from yashigani.auth._jwt import derive_tenant_ec_key
        p256_key = ec.generate_private_key(ec.SECP256R1())
        with pytest.raises(ValueError, match="secp384r1"):
            derive_tenant_ec_key(p256_key, "tenant-a")

    def test_a3_empty_tenant_id_raises_valueerror(self):
        """A3: empty tenant_id raises ValueError."""
        from yashigani.auth._jwt import derive_tenant_ec_key
        root = _generate_p384_key()
        with pytest.raises(ValueError, match="tenant_id"):
            derive_tenant_ec_key(root, "")

    def test_a4_whitespace_tenant_id_raises_valueerror(self):
        """A4: whitespace-only tenant_id raises ValueError."""
        from yashigani.auth._jwt import derive_tenant_ec_key
        root = _generate_p384_key()
        with pytest.raises(ValueError, match="tenant_id"):
            derive_tenant_ec_key(root, "   ")


# ---------------------------------------------------------------------------
# B. derive_tenant_ec_key — derivation correctness
# ---------------------------------------------------------------------------

class TestDeriveTenantEcKeyDerivation:
    """B1–B5: correctness of HKDF-based per-tenant key derivation."""

    def test_b1_output_is_valid_p384_key(self):
        """B1: derived key is a valid secp384r1 EllipticCurvePrivateKey."""
        from yashigani.auth._jwt import derive_tenant_ec_key
        root = _generate_p384_key()
        derived = derive_tenant_ec_key(root, "tenant-x")
        assert isinstance(derived, EllipticCurvePrivateKey)
        assert isinstance(derived.curve, SECP384R1)
        # Key size should be 384 bits
        assert derived.key_size == 384

    def test_b2_same_inputs_same_scalar(self):
        """B2: calling twice with same root + tenant_id produces the same private scalar."""
        from yashigani.auth._jwt import derive_tenant_ec_key
        root = _generate_p384_key()
        d1 = derive_tenant_ec_key(root, "tenant-y").private_numbers().private_value
        d2 = derive_tenant_ec_key(root, "tenant-y").private_numbers().private_value
        assert d1 == d2, "Derivation must be deterministic for the same inputs"

    def test_b3_different_tenant_ids_different_scalars(self):
        """B3: different tenant_ids → different private scalars (per-tenant isolation)."""
        from yashigani.auth._jwt import derive_tenant_ec_key
        root = _generate_p384_key()
        d_a = derive_tenant_ec_key(root, "tenant-a").private_numbers().private_value
        d_b = derive_tenant_ec_key(root, "tenant-b").private_numbers().private_value
        assert d_a != d_b, (
            "Different tenant_ids must produce different keys. "
            "If equal, the KDF provides no isolation."
        )

    def test_b4_different_roots_same_tenant_different_scalars(self):
        """B4: different root keys → different derived scalars for the same tenant."""
        from yashigani.auth._jwt import derive_tenant_ec_key
        root1 = _generate_p384_key()
        root2 = _generate_p384_key()
        d1 = derive_tenant_ec_key(root1, "shared-tenant").private_numbers().private_value
        d2 = derive_tenant_ec_key(root2, "shared-tenant").private_numbers().private_value
        assert d1 != d2

    def test_b5_derived_scalar_is_in_valid_range(self):
        """B5: derived private scalar is in [1, n-1] (valid P-384 private key range)."""
        from yashigani.auth._jwt import _SECP384R1_ORDER, derive_tenant_ec_key
        root = _generate_p384_key()
        for tid in ["alpha", "beta", "gamma", "default", "tenant-00000000"]:
            d = derive_tenant_ec_key(root, tid).private_numbers().private_value
            assert 1 <= d < _SECP384R1_ORDER, (
                f"Derived scalar for {tid!r} is outside valid P-384 range: {d}"
            )


# ---------------------------------------------------------------------------
# C. McpJwtIssuer — per-tenant key isolation via env-var root
# ---------------------------------------------------------------------------

class TestMcpJwtIssuerPerTenantKeys:
    """C1–C4: McpJwtIssuer produces different keys per tenant_id from the same root."""

    def test_c1_different_tenants_different_public_keys(self, monkeypatch):
        """C1: Two issuers sharing the same root key but different tenant_ids differ."""
        root = _generate_p384_key()
        issuer_a = _make_issuer("tenant-a", root, monkeypatch)
        issuer_b = _make_issuer("tenant-b", root, monkeypatch)

        pub_a = issuer_a._public_key.public_numbers()
        pub_b = issuer_b._public_key.public_numbers()

        assert (pub_a.x, pub_a.y) != (pub_b.x, pub_b.y), (
            "Issuers for different tenants must have different public keys "
            "(per-tenant HKDF derivation violated)."
        )

    def test_c2_same_tenant_same_public_key(self, monkeypatch):
        """C2: Two issuers with the same root + same tenant_id have the same public key."""
        root = _generate_p384_key()
        issuer1 = _make_issuer("same-tenant", root, monkeypatch)
        issuer2 = _make_issuer("same-tenant", root, monkeypatch)

        pub1 = issuer1._public_key.public_numbers()
        pub2 = issuer2._public_key.public_numbers()

        assert (pub1.x, pub1.y) == (pub2.x, pub2.y), (
            "Same root + same tenant_id must produce the same derived key "
            "(determinism violated)."
        )

    def test_c3_cross_tenant_token_rejected(self, monkeypatch):
        """C3 / F1 — THE KEY SECURITY PROOF.

        A token minted by tenant-a's issuer MUST be rejected by tenant-b's
        verifier.  This proves cross-tenant forgery is cryptographically
        impossible when tenants use distinct derived keys from the same root.
        """
        import jwt as pyjwt
        from yashigani.mcp._jwt import McpJwtVerifier

        root = _generate_p384_key()
        issuer_a = _make_issuer("tenant-a", root, monkeypatch)
        issuer_b = _make_issuer("tenant-b", root, monkeypatch)

        # Mint token under tenant_a
        token_from_a = _issue_token(issuer_a)

        # Build verifier from tenant_b (has tenant_b's derived public key)
        verifier_b = McpJwtVerifier.from_issuer(issuer_b)

        # Verify: tenant_b's verifier MUST reject tenant_a's token
        with pytest.raises((pyjwt.exceptions.PyJWTError, Exception)):
            verifier_b.verify(token_from_a)

    def test_c4_same_tenant_token_accepted(self, monkeypatch):
        """C4: A token minted by tenant_a's issuer is accepted by tenant_a's verifier."""
        from yashigani.mcp._jwt import McpJwtVerifier

        root = _generate_p384_key()
        issuer_a = _make_issuer("tenant-a", root, monkeypatch)

        token = _issue_token(issuer_a)
        verifier_a = McpJwtVerifier.from_issuer(issuer_a)

        claims = verifier_a.verify(token)
        assert claims["tenant"] == "tenant-a"
        assert claims["sub"] == "test-user"


# ---------------------------------------------------------------------------
# D. Single-tenant / default backward compatibility
# ---------------------------------------------------------------------------

class TestDefaultTenantBackwardCompat:
    """D1–D2: the 'default' tenant path still works after the per-tenant change."""

    def test_d1_default_tenant_issuer_starts_clean(self, monkeypatch):
        """D1: McpJwtIssuer('default') with env-var root passes its startup self-test."""
        from yashigani.mcp._jwt import McpJwtIssuer
        root = _generate_p384_key()
        monkeypatch.setenv("YASHIGANI_MCP_SIGNING_KEY_PEM", _pem_b64(root))
        monkeypatch.delenv("YASHIGANI_MCP_SIGNING_KEY_PATH", raising=False)
        # Constructor runs _startup_self_test() — no assertion error = passes
        issuer = McpJwtIssuer(tenant_id="default")
        assert issuer.tenant_id == "default"
        assert "default" in issuer.kid

    def test_d2_default_tenant_roundtrip(self, monkeypatch):
        """D2: single-tenant default install can issue and verify tokens."""
        from yashigani.mcp._jwt import McpJwtVerifier

        root = _generate_p384_key()
        issuer = _make_issuer("default", root, monkeypatch)
        token = _issue_token(issuer)
        verifier = McpJwtVerifier.from_issuer(issuer)
        claims = verifier.verify(token)
        assert claims["tenant"] == "default"


# ---------------------------------------------------------------------------
# E. TenantJwtKeyStore
# ---------------------------------------------------------------------------

class TestTenantJwtKeyStore:
    """E1–E5: TenantJwtKeyStore caches + isolates per-tenant keys."""

    def test_e1_returns_valid_p384_key(self):
        """E1: get_key returns a valid secp384r1 key."""
        from yashigani.auth._jwt import TenantJwtKeyStore
        store = TenantJwtKeyStore(_generate_p384_key())
        key = store.get_key("my-tenant")
        assert isinstance(key, EllipticCurvePrivateKey)
        assert isinstance(key.curve, SECP384R1)

    def test_e2_different_tenants_get_distinct_keys(self):
        """E2: different tenant_ids get distinct derived keys."""
        from yashigani.auth._jwt import TenantJwtKeyStore
        store = TenantJwtKeyStore(_generate_p384_key())
        k_a = store.get_key("tenant-alpha")
        k_b = store.get_key("tenant-beta")
        d_a = k_a.private_numbers().private_value
        d_b = k_b.private_numbers().private_value
        assert d_a != d_b

    def test_e3_same_tenant_returns_same_object(self):
        """E3: repeated call for the same tenant_id returns the cached key object."""
        from yashigani.auth._jwt import TenantJwtKeyStore
        store = TenantJwtKeyStore(_generate_p384_key())
        k1 = store.get_key("cached-tenant")
        k2 = store.get_key("cached-tenant")
        assert k1 is k2, "Expected the SAME Python object (cache hit)"

    def test_e4_non_ec_root_raises_typeerror(self):
        """E4: constructing with a non-EC key raises TypeError."""
        from yashigani.auth._jwt import TenantJwtKeyStore
        with pytest.raises(TypeError):
            TenantJwtKeyStore("not-a-key")  # type: ignore[arg-type]

    def test_e5_wrong_curve_raises_valueerror(self):
        """E5: constructing with a P-256 root raises ValueError."""
        from yashigani.auth._jwt import TenantJwtKeyStore
        p256 = ec.generate_private_key(ec.SECP256R1())
        with pytest.raises(ValueError):
            TenantJwtKeyStore(p256)

    def test_e6_tenant_ids_property_tracks_cache(self):
        """E6: tenant_ids property returns all tenants with cached keys."""
        from yashigani.auth._jwt import TenantJwtKeyStore
        store = TenantJwtKeyStore(_generate_p384_key())
        assert store.tenant_ids == []
        store.get_key("alpha")
        store.get_key("beta")
        assert set(store.tenant_ids) == {"alpha", "beta"}


# ---------------------------------------------------------------------------
# F. Security invariants
# ---------------------------------------------------------------------------

class TestSecurityInvariants:
    """F1–F2: cross-tenant forgery and token integrity invariants."""

    def test_f1_cross_tenant_forgery_impossible(self, monkeypatch):
        """F1: Cross-tenant forgery is cryptographically impossible.

        This is the regression proof for YSG-RISK-253:
          - Before the fix: all tenants shared the same signing key, so a token
            from tenant A was verifiable with 'tenant B's key' (same key).
          - After the fix: HKDF derives distinct keys per tenant, so tenant A's
            token is rejected by any verifier built from tenant B's issuer.

        This test will FAIL if the per-tenant derivation is removed or bypassed.
        """
        import jwt as pyjwt
        from yashigani.mcp._jwt import McpJwtVerifier

        # Use a shared root key (as would exist on a multi-tenant install)
        shared_root = _generate_p384_key()

        # Simulate three tenants sharing the same installation (same root key)
        tenant_pairs = [
            ("org-acme", "org-globex"),
            ("org-globex", "org-initech"),
            ("org-initech", "org-acme"),
        ]
        for attacker_tenant, victim_tenant in tenant_pairs:
            attacker_issuer = _make_issuer(attacker_tenant, shared_root, monkeypatch)
            victim_issuer = _make_issuer(victim_tenant, shared_root, monkeypatch)

            forged_token = _issue_token(attacker_issuer)
            victim_verifier = McpJwtVerifier.from_issuer(victim_issuer)

            with pytest.raises((pyjwt.exceptions.PyJWTError, Exception)):
                victim_verifier.verify(forged_token)

    def test_f2_tampered_tenant_claim_rejected(self, monkeypatch):
        """F2: Altering the 'tenant' claim in a valid token is rejected.

        Proves that ES384 signature protection covers the payload — an attacker
        cannot simply flip the tenant claim to impersonate another tenant.
        """
        import jwt as pyjwt
        from yashigani.mcp._jwt import McpJwtVerifier

        root = _generate_p384_key()
        issuer = _make_issuer("legit-tenant", root, monkeypatch)
        token = _issue_token(issuer)

        # Decode without verification to tamper with the payload
        try:
            raw_claims = pyjwt.decode(
                token,
                options={"verify_signature": False},
                algorithms=["ES384"],
            )
        except Exception:
            # PyJWT version differences — decode without any options
            header, payload_b64, sig = token.split(".")
            import json
            pad = 4 - len(payload_b64) % 4
            payload_bytes = base64.urlsafe_b64decode(payload_b64 + "=" * pad)
            raw_claims = json.loads(payload_bytes)

        # Attempt to construct a token with a tampered tenant claim
        # (this should fail: we can't re-sign without the private key)
        raw_claims["tenant"] = "victim-tenant"

        # Re-encode without a real key → signature will be invalid
        # We just verify the original issuer's verifier rejects any tampered token
        verifier = McpJwtVerifier.from_issuer(issuer)
        with pytest.raises((pyjwt.exceptions.PyJWTError, Exception)):
            # Construct a fake token with a wrong signing key
            fake_key = ec.generate_private_key(SECP384R1())
            fake_token = pyjwt.encode(
                raw_claims,
                fake_key,
                algorithm="ES384",
                headers={"kid": issuer.kid, "alg": "ES384"},
            )
            verifier.verify(fake_token)
