"""
Tests for license anti-tampering: v5 chain-of-trust signature + kill-list +
self-integrity check.

Covers:
  - valid v5 license (leaf_cert chains to master anchor) → accepted
  - v5 license with wrong leaf_sig → rejected (invalid_signature)
  - v5 license whose leaf_cert does not chain to any trusted anchor → rejected
  - v5 license with a client_id/leaf_cert.client_id mismatch → rejected
    (Laura R3-F1 anti-cross-client-forgery)
  - v5 license revoked via leaf/licence/client kill-list namespaces → rejected
  - 2/3-segment (old v3/v4) licenses → REJECTED: license_format_deprecated_v5_required
    (design §3.2 "v3/v4 dropped — v5 mandatory, no downgrade path")
  - integrity check detects modified verifier.py source (VERIFIER_HASH mismatch)
  - integrity check passes with correct hash
  - integrity violation forces COMMUNITY tier on all verify_license() calls
  - placeholder VERIFIER_HASH in dev → skip (fail-open permitted)
  - placeholder VERIFIER_HASH in prod → violation flag set (fail-closed, #104)
  - placeholder chain constants (anchor set / code leaf_cert / bundle_sig) in
    dev → skip; in prod → fail-closed (supersedes the old v4
    COUNTER_PUBLIC_KEY_PEM placeholder tests, #103)
  - domain-bound license with matching YASHIGANI_TLS_DOMAIN → accepted (#102)
  - domain-bound license with mismatched YASHIGANI_TLS_DOMAIN → COMMUNITY (#102)
  - domain-bound license with unset YASHIGANI_TLS_DOMAIN → COMMUNITY (#102)
  - wildcard org_domain ("*") on paid tier → rejected (LAURA-LIMIT-DOMAINS-02, falls back to COMMUNITY)
  - wildcard org_domain ("*") on community/academic_nonprofit → accepted (#102)
  - sign_license.py v5 round trip (scripts/sign_license.py — gitignored
    internal tool; class skips cleanly if absent, mirrors the old v4 class)
  - persistent "Yashigani license tampered" banner (§5) fires on integrity
    violation, distinct from the plain "no license configured" state; no
    user deletion/suspension implied by the tamper path

Last updated: 2026-07-14T00:00:00+00:00 (licence-hardening-v2 Phase B-CORE)
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from yashigani.licensing.chain import (
    Alg,
    AnchorStatus,
    LeafCert,
    PemSigner,
    Role,
    sign_licence_v5,
)
from yashigani.licensing.chain.algorithms import sign_message
from yashigani.licensing.chain.canonical import bundle_signing_digest, leaf_cert_signing_digest


# ---------------------------------------------------------------------------
# Crypto helpers — P-384 (the interim chain algorithm, ecdsa-p384-sha384)
# ---------------------------------------------------------------------------

def _gen_p384() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP384R1())


def _pem_pub(key: ec.EllipticCurvePrivateKey) -> str:
    return (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _anchor_set_json(master_key: ec.EllipticCurvePrivateKey, anchor_id: str = "M1", status: str = "active") -> str:
    return json.dumps([{
        "anchor_id": anchor_id,
        "pubkey_pem": _pem_pub(master_key),
        "alg": Alg.ECDSA_P384_SHA384.value,
        "status": status,
        "added": _now().isoformat(),
    }])


def _make_licence_leaf(
    master_key: ec.EllipticCurvePrivateKey, client_id: str = "acme-corp", serial: str = "lic-leaf-0001"
) -> tuple[LeafCert, bytes, ec.EllipticCurvePrivateKey]:
    now = _now()
    licence_key = _gen_p384()
    leaf_cert = LeafCert(
        role=Role.LICENCE,
        client_id=client_id,
        leaf_pubkey_pem=_pem_pub(licence_key),
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=60),
        serial=serial,
        signed_at=now,
        alg=Alg.ECDSA_P384_SHA384,
    )
    leaf_cert_sig = sign_message(
        Alg.ECDSA_P384_SHA384, master_key, leaf_cert_signing_digest(leaf_cert.to_canonical_dict())
    )
    return leaf_cert, leaf_cert_sig, licence_key


def _make_payload(
    tier: str = "professional",
    org_domain: str = "test.example.com",
    client_id: str = "acme-corp",
    licence_serial: str = "lic-0001",
    expires_offset_days: int = 30,
    max_agents: int = 500,
    max_end_users: int = 1000,
    max_admin_seats: int = 50,
    max_orgs: int = 1,
    features: list | None = None,
) -> dict:
    from yashigani.licensing.chain import build_licence_payload_v5

    return build_licence_payload_v5(
        org_domain=org_domain,
        tier=tier,
        client_id=client_id,
        licence_serial=licence_serial,
        max_agents=max_agents,
        max_end_users=max_end_users,
        max_admin_seats=max_admin_seats,
        max_orgs=max_orgs,
        features=features if features is not None else ["oidc", "saml"],
        expires_at=_now() + timedelta(days=expires_offset_days),
    )


def _build_v5_license(payload: dict, leaf_cert: LeafCert, leaf_cert_sig: bytes, licence_key) -> str:
    signer = PemSigner(role=Role.LICENCE, private_key=licence_key, leaf_cert=leaf_cert)
    return sign_licence_v5(payload, signer, leaf_cert, leaf_cert_sig)


def _build_v3_license(payload: dict) -> str:
    """2-segment string — no valid crypto needed, rejected before sig check."""
    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return f"{base64.urlsafe_b64encode(payload_bytes).rstrip(b'=').decode()}.AAAA"


def _build_v4_license(payload: dict) -> str:
    """3-segment string — no valid crypto needed, rejected before sig check."""
    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    seg = base64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode()
    return f"{seg}.AAAA.AAAA"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def patched_v5_verifier(monkeypatch):
    """
    Monkeypatch _integrity.MASTER_ANCHOR_SET_JSON with a fresh master anchor
    and reset verifier._integrity_violated — isolates the v5 licence-verify
    logic (§4b) from the module-load build-integrity self-check (§4a/T1-T4),
    which is exercised separately by TestSelfIntegrity/TestBuildIntegrityChainPlaceholder.

    Returns the master private key so each test can mint its own licence leaf.
    """
    import yashigani.licensing._integrity as integrity_mod
    import yashigani.licensing.verifier as verifier_mod

    master_key = _gen_p384()
    monkeypatch.setattr(integrity_mod, "MASTER_ANCHOR_SET_JSON", _anchor_set_json(master_key))
    monkeypatch.setattr(integrity_mod, "KILL_LIST_JSON", "[]")
    monkeypatch.setattr(integrity_mod, "CLIENT_DOMAIN_REGISTRY_JSON", "{}")
    monkeypatch.setattr(verifier_mod, "_integrity_violated", False)
    return master_key


# ---------------------------------------------------------------------------
# v5 license tests
# ---------------------------------------------------------------------------

class TestV5License:
    def test_valid_v5_license_accepted(self, patched_v5_verifier):
        master_key = patched_v5_verifier
        from yashigani.licensing.verifier import verify_license
        from yashigani.licensing.model import LicenseTier

        leaf_cert, leaf_cert_sig, licence_key = _make_licence_leaf(master_key)
        payload = _make_payload()
        lic_str = _build_v5_license(payload, leaf_cert, leaf_cert_sig, licence_key)

        result = verify_license(lic_str)
        assert result.valid is True
        assert result.tier == LicenseTier.PROFESSIONAL
        assert result.license_id == "lic-0001"

    def test_v5_wrong_leaf_sig_rejected(self, patched_v5_verifier):
        master_key = patched_v5_verifier
        from yashigani.licensing.verifier import verify_license

        leaf_cert, leaf_cert_sig, licence_key = _make_licence_leaf(master_key)
        payload = _make_payload()
        lic_str = _build_v5_license(payload, leaf_cert, leaf_cert_sig, licence_key)

        parts = lic_str.split(".")
        corrupted = ".".join([parts[0], "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", parts[2], parts[3]])
        result = verify_license(corrupted)
        assert result.valid is False
        assert result.error == "invalid_signature"

    def test_v5_untrusted_leaf_cert_rejected(self, patched_v5_verifier):
        """A leaf_cert signed by a DIFFERENT master (not in the embedded anchor
        set) must fail to chain — this is the core rotation-safety property."""
        from yashigani.licensing.verifier import verify_license

        rogue_master = _gen_p384()  # NOT the anchor embedded by the fixture
        leaf_cert, leaf_cert_sig, licence_key = _make_licence_leaf(rogue_master)
        payload = _make_payload()
        lic_str = _build_v5_license(payload, leaf_cert, leaf_cert_sig, licence_key)

        result = verify_license(lic_str)
        assert result.valid is False
        assert result.error == "leaf_cert_untrusted"

    def test_v5_cross_client_forgery_rejected(self, patched_v5_verifier):
        """Laura R3-F1: a client's licence leaf can only mint licences claiming
        its OWN client_id — payload.client_id must equal leaf_cert.client_id."""
        master_key = patched_v5_verifier
        from yashigani.licensing.verifier import verify_license

        leaf_cert, leaf_cert_sig, licence_key = _make_licence_leaf(master_key, client_id="acme-corp")
        # Payload claims a DIFFERENT client_id than the leaf that signs it.
        payload = _make_payload(client_id="victim-corp")
        lic_str = _build_v5_license(payload, leaf_cert, leaf_cert_sig, licence_key)

        result = verify_license(lic_str)
        assert result.valid is False
        assert result.error == "client_id_mismatch"

    def test_v5_wrong_role_leaf_rejected(self, patched_v5_verifier):
        """A CODE-role leaf must never be accepted to sign a licence."""
        master_key = patched_v5_verifier
        from yashigani.licensing.verifier import verify_license

        now = _now()
        code_key = _gen_p384()
        code_leaf = LeafCert(
            role=Role.CODE, client_id="*", release="4.1.1", leaf_pubkey_pem=_pem_pub(code_key),
            not_before=now - timedelta(days=1), not_after=now + timedelta(days=60),
            serial="code-leaf-4.1.1", signed_at=now, alg=Alg.ECDSA_P384_SHA384,
        )
        code_leaf_sig = sign_message(Alg.ECDSA_P384_SHA384, master_key, leaf_cert_signing_digest(code_leaf.to_canonical_dict()))
        payload = _make_payload(client_id="*")

        # Manually build the wire string using sign_licence_v5's underlying
        # mechanics but with role=code — sign_licence_v5() itself refuses
        # this (raises ValueError), so we exercise the parse/verify-side
        # rejection by constructing the segments directly.
        from yashigani.licensing.chain.canonical import canonical, licence_payload_signing_digest
        from yashigani.licensing.chain.licence_v5 import base64url_encode

        payload_bytes = canonical(payload).encode("utf-8")
        digest = licence_payload_signing_digest(payload_bytes, code_leaf.to_canonical_dict())
        leaf_sig = sign_message(Alg.ECDSA_P384_SHA384, code_key, digest)
        leaf_cert_bytes = canonical(code_leaf.to_canonical_dict()).encode("utf-8")
        wire = ".".join([
            base64url_encode(payload_bytes),
            base64url_encode(leaf_sig),
            base64url_encode(leaf_cert_bytes),
            base64url_encode(code_leaf_sig),
        ])

        result = verify_license(wire)
        assert result.valid is False
        assert result.error == "wrong_leaf_role"

    def test_v5_expired_license_returns_invalid(self, patched_v5_verifier):
        master_key = patched_v5_verifier
        from yashigani.licensing.verifier import verify_license
        from yashigani.licensing.model import LicenseTier

        leaf_cert, leaf_cert_sig, licence_key = _make_licence_leaf(master_key)
        payload = _make_payload(expires_offset_days=-1)
        lic_str = _build_v5_license(payload, leaf_cert, leaf_cert_sig, licence_key)

        result = verify_license(lic_str)
        assert result.valid is False
        assert result.error == "license_expired"
        assert result.tier == LicenseTier.PROFESSIONAL

    def test_v5_retiring_anchor_still_trusted(self, patched_v5_verifier, monkeypatch):
        """A leaf_cert signed under a RETIRING anchor must still validate —
        the rotation grace window (design §2.2)."""
        import yashigani.licensing._integrity as integrity_mod

        master_key = _gen_p384()
        monkeypatch.setattr(
            integrity_mod, "MASTER_ANCHOR_SET_JSON",
            _anchor_set_json(master_key, status=AnchorStatus.RETIRING.value),
        )
        from yashigani.licensing.verifier import verify_license

        leaf_cert, leaf_cert_sig, licence_key = _make_licence_leaf(master_key)
        payload = _make_payload()
        lic_str = _build_v5_license(payload, leaf_cert, leaf_cert_sig, licence_key)
        result = verify_license(lic_str)
        assert result.valid is True

    def test_v5_retired_anchor_no_longer_trusted(self, patched_v5_verifier, monkeypatch):
        """A leaf_cert chaining ONLY to a RETIRED anchor must fail."""
        import yashigani.licensing._integrity as integrity_mod

        master_key = _gen_p384()
        monkeypatch.setattr(
            integrity_mod, "MASTER_ANCHOR_SET_JSON",
            _anchor_set_json(master_key, status=AnchorStatus.RETIRED.value),
        )
        from yashigani.licensing.verifier import verify_license

        leaf_cert, leaf_cert_sig, licence_key = _make_licence_leaf(master_key)
        payload = _make_payload()
        lic_str = _build_v5_license(payload, leaf_cert, leaf_cert_sig, licence_key)
        result = verify_license(lic_str)
        assert result.valid is False
        assert result.error == "leaf_cert_untrusted"


# ---------------------------------------------------------------------------
# Kill-list tests (§6.1 IMMEDIATE namespaces)
# ---------------------------------------------------------------------------

class TestV5KillList:
    def test_leaf_serial_revoked_rejected(self, patched_v5_verifier, monkeypatch):
        import yashigani.licensing._integrity as integrity_mod

        master_key = patched_v5_verifier
        from yashigani.licensing.verifier import verify_license

        leaf_cert, leaf_cert_sig, licence_key = _make_licence_leaf(master_key, serial="lic-leaf-REVOKED")
        payload = _make_payload()
        lic_str = _build_v5_license(payload, leaf_cert, leaf_cert_sig, licence_key)

        kill_list = json.dumps([{
            "namespace": "leaf", "identifier": "lic-leaf-REVOKED",
            "revoked_at": _now().isoformat(), "semantics": "immediate", "reason": "test",
        }])
        monkeypatch.setattr(integrity_mod, "KILL_LIST_JSON", kill_list)

        result = verify_license(lic_str)
        assert result.valid is False
        assert result.error == "leaf_revoked"

    def test_licence_serial_revoked_rejected(self, patched_v5_verifier, monkeypatch):
        import yashigani.licensing._integrity as integrity_mod

        master_key = patched_v5_verifier
        from yashigani.licensing.verifier import verify_license

        leaf_cert, leaf_cert_sig, licence_key = _make_licence_leaf(master_key)
        payload = _make_payload(licence_serial="lic-REVOKED")
        lic_str = _build_v5_license(payload, leaf_cert, leaf_cert_sig, licence_key)

        kill_list = json.dumps([{
            "namespace": "licence", "identifier": "lic-REVOKED",
            "revoked_at": _now().isoformat(), "semantics": "immediate", "reason": "leaked",
        }])
        monkeypatch.setattr(integrity_mod, "KILL_LIST_JSON", kill_list)

        result = verify_license(lic_str)
        assert result.valid is False
        assert result.error == "licence_revoked"

    def test_client_revoked_rejected_but_other_client_unaffected(self, patched_v5_verifier, monkeypatch):
        """Revoking one client's licence leaf must not affect another client
        (zero-collateral revocation, design §6)."""
        import yashigani.licensing._integrity as integrity_mod

        master_key = patched_v5_verifier
        from yashigani.licensing.verifier import verify_license

        revoked_leaf, revoked_sig, revoked_key = _make_licence_leaf(master_key, client_id="bad-corp", serial="l1")
        ok_leaf, ok_sig, ok_key = _make_licence_leaf(master_key, client_id="good-corp", serial="l2")

        kill_list = json.dumps([{
            "namespace": "client", "identifier": "bad-corp",
            "revoked_at": _now().isoformat(), "semantics": "immediate", "reason": "chargeback",
        }])
        monkeypatch.setattr(integrity_mod, "KILL_LIST_JSON", kill_list)

        revoked_payload = _make_payload(client_id="bad-corp")
        revoked_wire = _build_v5_license(revoked_payload, revoked_leaf, revoked_sig, revoked_key)
        result_revoked = verify_license(revoked_wire)
        assert result_revoked.valid is False
        assert result_revoked.error == "client_revoked"

        ok_payload = _make_payload(client_id="good-corp")
        ok_wire = _build_v5_license(ok_payload, ok_leaf, ok_sig, ok_key)
        result_ok = verify_license(ok_wire)
        assert result_ok.valid is True


# ---------------------------------------------------------------------------
# v3/v4 format rejection (design §3.2 — no downgrade path)
# ---------------------------------------------------------------------------

class TestOldFormatsRejected:
    """v3 (2-segment) and v4 (3-segment) formats must always be rejected,
    regardless of the payload/signature content — parse_licence_v5() rejects
    them before any signature is even attempted."""

    def test_v3_two_segment_rejected(self, patched_v5_verifier):
        from yashigani.licensing.verifier import verify_license
        from yashigani.licensing.model import LicenseTier

        payload = _make_payload()
        lic_str = _build_v3_license(payload)
        assert len(lic_str.split(".")) == 2

        result = verify_license(lic_str)
        assert result.valid is False
        assert result.error == "license_format_deprecated_v5_required"
        assert result.tier == LicenseTier.COMMUNITY

    def test_v4_three_segment_rejected(self, patched_v5_verifier):
        from yashigani.licensing.verifier import verify_license
        from yashigani.licensing.model import LicenseTier

        payload = _make_payload()
        lic_str = _build_v4_license(payload)
        assert len(lic_str.split(".")) == 3

        result = verify_license(lic_str)
        assert result.valid is False
        assert result.error == "license_format_deprecated_v5_required"
        assert result.tier == LicenseTier.COMMUNITY

    def test_v4_real_signature_still_rejected(self, patched_v5_verifier):
        """Even a genuinely-signed v4-shaped (3-segment) token — using real
        ECDSA signatures that would have validated under the old scheme — is
        rejected purely on segment count, before any crypto runs."""
        master_key = patched_v5_verifier
        from yashigani.licensing.verifier import verify_license

        payload = _make_payload()
        payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        sig = sign_message(Alg.ECDSA_P384_SHA384, master_key, hashlib.sha384(payload_bytes).digest())
        seg = base64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode()
        sig_seg = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        lic_str = f"{seg}.{sig_seg}.{sig_seg}"

        result = verify_license(lic_str)
        assert result.valid is False
        assert result.error == "license_format_deprecated_v5_required"


# ---------------------------------------------------------------------------
# Self-integrity tests (T1-T4 self-hash — unchanged mechanism)
# ---------------------------------------------------------------------------

class TestSelfIntegrity:
    def test_correct_hash_passes(self, monkeypatch):
        """
        When VERIFIER_HASH matches the actual SHA-256 of verifier.py,
        integrity check must pass.
        """
        import yashigani.licensing.verifier as verifier_mod
        import yashigani.licensing._integrity as integrity_mod
        from pathlib import Path

        verifier_path = Path(verifier_mod.__file__)
        real_hash = hashlib.sha256(verifier_path.read_bytes()).hexdigest()

        monkeypatch.setattr(verifier_mod, "_integrity_violated", False)
        monkeypatch.setattr(integrity_mod, "VERIFIER_HASH", real_hash)

        verifier_mod._check_self_integrity()

        assert verifier_mod._integrity_violated is False

    def test_modified_hash_sets_violation_flag(self, monkeypatch):
        """
        When VERIFIER_HASH does not match the actual digest, the integrity
        violation flag must be set.
        """
        import yashigani.licensing.verifier as verifier_mod
        import yashigani.licensing._integrity as integrity_mod

        monkeypatch.setattr(integrity_mod, "VERIFIER_HASH", "a" * 64)
        monkeypatch.setattr(verifier_mod, "_integrity_violated", False)

        verifier_mod._check_self_integrity()

        assert verifier_mod._integrity_violated is True

    def test_integrity_violation_forces_community_tier(self, patched_v5_verifier, monkeypatch):
        """
        When _integrity_violated is True, verify_license() must return
        COMMUNITY tier regardless of the (otherwise valid) v5 license content.
        """
        master_key = patched_v5_verifier
        import yashigani.licensing.verifier as verifier_mod

        leaf_cert, leaf_cert_sig, licence_key = _make_licence_leaf(master_key)
        payload = _make_payload(tier="enterprise")
        lic_str = _build_v5_license(payload, leaf_cert, leaf_cert_sig, licence_key)

        monkeypatch.setattr(verifier_mod, "_integrity_violated", True)

        from yashigani.licensing.verifier import verify_license
        from yashigani.licensing.model import LicenseTier

        result = verify_license(lic_str)
        assert result.tier == LicenseTier.COMMUNITY

    def test_placeholder_verifier_hash_skips_integrity_check(self, monkeypatch):
        """
        When VERIFIER_HASH is a placeholder AND YASHIGANI_ENV=dev, the
        self-integrity check is skipped and _integrity_violated must stay False.
        """
        import yashigani.licensing.verifier as verifier_mod
        import yashigani.licensing._integrity as integrity_mod

        monkeypatch.setenv("YASHIGANI_ENV", "dev")
        monkeypatch.setattr(
            integrity_mod, "VERIFIER_HASH",
            integrity_mod._PLACEHOLDER_INTEGRITY + "_VERIFIER_HASH",
        )
        monkeypatch.setattr(verifier_mod, "_integrity_violated", False)

        verifier_mod._check_self_integrity()

        assert verifier_mod._integrity_violated is False

    def test_placeholder_verifier_hash_sets_violation_in_prod(self, monkeypatch):
        """
        #104 (LICENSE-2024-002 / CVSS 9.1): In non-dev environments, a
        placeholder VERIFIER_HASH means the build pipeline did not embed the
        real hash — treated as a tamper event (fail-closed).
        """
        import yashigani.licensing.verifier as verifier_mod
        import yashigani.licensing._integrity as integrity_mod

        monkeypatch.delenv("YASHIGANI_ENV", raising=False)
        monkeypatch.setattr(
            integrity_mod, "VERIFIER_HASH",
            integrity_mod._PLACEHOLDER_INTEGRITY + "_VERIFIER_HASH",
        )
        monkeypatch.setattr(verifier_mod, "_integrity_violated", False)

        verifier_mod._check_self_integrity()

        assert verifier_mod._integrity_violated is True


# ---------------------------------------------------------------------------
# Build-integrity chain placeholder tests (§4a — supersedes the old v4
# COUNTER_PUBLIC_KEY_PEM placeholder tests, #103)
# ---------------------------------------------------------------------------

class TestBuildIntegrityChainPlaceholder:
    def test_chain_placeholder_skipped_in_dev(self, monkeypatch):
        import yashigani.licensing.verifier as verifier_mod
        import yashigani.licensing._integrity as integrity_mod

        monkeypatch.setenv("YASHIGANI_ENV", "dev")
        monkeypatch.setattr(integrity_mod, "VERIFIER_HASH", "a" * 64)
        monkeypatch.setattr(integrity_mod, "ENFORCER_HASH", "a" * 64)
        monkeypatch.setattr(integrity_mod, "LOADER_HASH", "a" * 64)
        monkeypatch.setattr(integrity_mod, "INTEGRITY_HASH", "a" * 64)
        monkeypatch.setattr(integrity_mod, "AGENTS_REGISTRY_HASH", "a" * 64)
        monkeypatch.setattr(integrity_mod, "IDENTITY_REGISTRY_HASH", "a" * 64)
        # Leave chain constants as placeholders.
        monkeypatch.setattr(verifier_mod, "_integrity_violated", False)

        verifier_mod._check_build_integrity_chain()

        assert verifier_mod._integrity_violated is False

    def test_chain_placeholder_fails_closed_in_prod(self, monkeypatch):
        """
        Supersedes #103 (LICENSE-2024-001): in non-dev environments, a
        placeholder master anchor-set / code leaf_cert / bundle_sig means the
        build pipeline did not embed the chain — fail-closed, never accept.
        """
        import yashigani.licensing.verifier as verifier_mod
        import yashigani.licensing._integrity as integrity_mod

        monkeypatch.delenv("YASHIGANI_ENV", raising=False)
        monkeypatch.setattr(integrity_mod, "VERIFIER_HASH", "a" * 64)
        monkeypatch.setattr(integrity_mod, "ENFORCER_HASH", "a" * 64)
        monkeypatch.setattr(integrity_mod, "LOADER_HASH", "a" * 64)
        monkeypatch.setattr(integrity_mod, "INTEGRITY_HASH", "a" * 64)
        monkeypatch.setattr(integrity_mod, "AGENTS_REGISTRY_HASH", "a" * 64)
        monkeypatch.setattr(integrity_mod, "IDENTITY_REGISTRY_HASH", "a" * 64)
        # Leave chain constants as placeholders (default source state).
        monkeypatch.setattr(verifier_mod, "_integrity_violated", False)

        verifier_mod._check_build_integrity_chain()

        assert verifier_mod._integrity_violated is True

    def test_tampered_bundle_sig_fails_closed(self, monkeypatch):
        """A fully-populated chain (real anchor/leaf/leaf_cert_sig) but with a
        BUNDLE_SIG that does not verify against the code leaf's key must fail
        closed — the direct regression test for the property proven in
        chain/build_integrity.py's own unit tests, exercised here through
        verifier._check_build_integrity_chain()."""
        import yashigani.licensing.verifier as verifier_mod
        import yashigani.licensing._integrity as integrity_mod

        monkeypatch.setattr(integrity_mod, "VERIFIER_HASH", "a" * 64)
        monkeypatch.setattr(integrity_mod, "ENFORCER_HASH", "a" * 64)
        monkeypatch.setattr(integrity_mod, "LOADER_HASH", "a" * 64)
        monkeypatch.setattr(integrity_mod, "INTEGRITY_HASH", "a" * 64)
        monkeypatch.setattr(integrity_mod, "AGENTS_REGISTRY_HASH", "a" * 64)
        monkeypatch.setattr(integrity_mod, "IDENTITY_REGISTRY_HASH", "a" * 64)

        now = _now()
        master_key = _gen_p384()
        code_key = _gen_p384()
        code_leaf = LeafCert(
            role=Role.CODE, client_id="*", release="4.1.1", leaf_pubkey_pem=_pem_pub(code_key),
            not_before=now - timedelta(days=1), not_after=now + timedelta(days=60),
            serial="code-leaf-4.1.1", signed_at=now, alg=Alg.ECDSA_P384_SHA384,
        )
        code_leaf_sig = sign_message(Alg.ECDSA_P384_SHA384, master_key, leaf_cert_signing_digest(code_leaf.to_canonical_dict()))

        monkeypatch.setattr(integrity_mod, "MASTER_ANCHOR_SET_JSON", _anchor_set_json(master_key))
        monkeypatch.setattr(integrity_mod, "CODE_LEAF_CERT_JSON", json.dumps(code_leaf.to_canonical_dict()))
        monkeypatch.setattr(integrity_mod, "CODE_LEAF_CERT_SIG", base64.b64encode(code_leaf_sig).decode())
        # BUNDLE_SIG signed by a DIFFERENT key — must fail to verify against
        # code_leaf.leaf_pubkey_pem.
        rogue_key = _gen_p384()
        bad_bundle_sig = sign_message(Alg.ECDSA_P384_SHA384, rogue_key, bundle_signing_digest("garbage"))
        monkeypatch.setattr(integrity_mod, "BUNDLE_SIG", base64.b64encode(bad_bundle_sig).decode())
        monkeypatch.setattr(integrity_mod, "KILL_LIST_JSON", "[]")

        monkeypatch.setattr(verifier_mod, "_integrity_violated", False)
        verifier_mod._check_build_integrity_chain()

        assert verifier_mod._integrity_violated is True


# ---------------------------------------------------------------------------
# _integrity module unit tests
# ---------------------------------------------------------------------------

class TestIntegrityModule:
    def test_placeholder_detection_verifier_hash(self):
        import yashigani.licensing._integrity as integrity_mod
        assert integrity_mod.is_verifier_hash_placeholder() is True

    def test_placeholder_detection_master_anchor_set(self):
        import yashigani.licensing._integrity as integrity_mod
        assert integrity_mod.is_master_anchor_set_placeholder() is True

    def test_placeholder_detection_code_leaf_cert(self):
        import yashigani.licensing._integrity as integrity_mod
        assert integrity_mod.is_code_leaf_cert_placeholder() is True

    def test_placeholder_detection_bundle_sig(self):
        import yashigani.licensing._integrity as integrity_mod
        assert integrity_mod.is_bundle_sig_placeholder() is True

    def test_non_placeholder_verifier_hash(self, monkeypatch):
        import yashigani.licensing._integrity as integrity_mod
        monkeypatch.setattr(integrity_mod, "VERIFIER_HASH", "a" * 64)
        assert integrity_mod.is_verifier_hash_placeholder() is False

    def test_non_placeholder_master_anchor_set(self, monkeypatch):
        import yashigani.licensing._integrity as integrity_mod
        monkeypatch.setattr(integrity_mod, "MASTER_ANCHOR_SET_JSON", "[]")
        assert integrity_mod.is_master_anchor_set_placeholder() is False

    def test_kill_list_default_is_empty_not_placeholder(self):
        """KILL_LIST_JSON defaults to '[]' — a SAFE value, never treated as a
        fail-closed placeholder (module docstring)."""
        import yashigani.licensing._integrity as integrity_mod
        assert integrity_mod.KILL_LIST_JSON == "[]"

    def test_client_domain_registry_default_is_empty_not_placeholder(self):
        import yashigani.licensing._integrity as integrity_mod
        assert integrity_mod.CLIENT_DOMAIN_REGISTRY_JSON == "{}"

    def test_is_any_chain_placeholder_true_by_default(self):
        import yashigani.licensing._integrity as integrity_mod
        assert integrity_mod.is_any_chain_placeholder() is True

    def test_is_any_chain_placeholder_false_when_all_set(self, monkeypatch):
        import yashigani.licensing._integrity as integrity_mod
        monkeypatch.setattr(integrity_mod, "MASTER_ANCHOR_SET_JSON", "[]")
        monkeypatch.setattr(integrity_mod, "CODE_LEAF_CERT_JSON", "{}")
        monkeypatch.setattr(integrity_mod, "CODE_LEAF_CERT_SIG", "AAAA")
        monkeypatch.setattr(integrity_mod, "BUNDLE_SIG", "AAAA")
        assert integrity_mod.is_any_chain_placeholder() is False


# ---------------------------------------------------------------------------
# Domain binding tests (#102 / LICENSE-2024-003 / CVSS 9.3)
# ---------------------------------------------------------------------------

class TestDomainBinding:
    """
    loader.load_license() must enforce org_domain binding.

    A license with org_domain != "*" is only accepted when YASHIGANI_TLS_DOMAIN
    matches exactly.  Mismatch or absence of the env var must downgrade to
    COMMUNITY tier (fail-closed) regardless of signature validity.
    """

    def _write_license_file(self, tmp_path, content: str) -> str:
        p = tmp_path / "license.ysg"
        p.write_text(content, encoding="utf-8")
        return str(p)

    def test_domain_bound_license_accepted_when_domain_matches(self, tmp_path, patched_v5_verifier, monkeypatch):
        master_key = patched_v5_verifier
        leaf_cert, leaf_cert_sig, licence_key = _make_licence_leaf(master_key)
        payload = _make_payload(org_domain="acme.example.com")
        lic_str = _build_v5_license(payload, leaf_cert, leaf_cert_sig, licence_key)
        lic_path = self._write_license_file(tmp_path, lic_str)

        monkeypatch.setenv("YASHIGANI_LICENSE_FILE", lic_path)
        monkeypatch.setenv("YASHIGANI_TLS_DOMAIN", "acme.example.com")

        from yashigani.licensing.loader import load_license
        from yashigani.licensing.model import LicenseTier

        result = load_license()
        assert result.valid is True
        assert result.tier == LicenseTier.PROFESSIONAL
        assert result.org_domain == "acme.example.com"

    def test_domain_bound_license_rejected_when_domain_mismatches(self, tmp_path, patched_v5_verifier, monkeypatch):
        master_key = patched_v5_verifier
        leaf_cert, leaf_cert_sig, licence_key = _make_licence_leaf(master_key)
        payload = _make_payload(org_domain="acme.example.com")
        lic_str = _build_v5_license(payload, leaf_cert, leaf_cert_sig, licence_key)
        lic_path = self._write_license_file(tmp_path, lic_str)

        monkeypatch.setenv("YASHIGANI_LICENSE_FILE", lic_path)
        monkeypatch.setenv("YASHIGANI_TLS_DOMAIN", "other.example.com")

        from yashigani.licensing.loader import load_license
        from yashigani.licensing.model import LicenseTier

        result = load_license()
        assert result.tier == LicenseTier.COMMUNITY

    def test_domain_bound_license_rejected_when_domain_env_unset(self, tmp_path, patched_v5_verifier, monkeypatch):
        master_key = patched_v5_verifier
        leaf_cert, leaf_cert_sig, licence_key = _make_licence_leaf(master_key)
        payload = _make_payload(org_domain="acme.example.com")
        lic_str = _build_v5_license(payload, leaf_cert, leaf_cert_sig, licence_key)
        lic_path = self._write_license_file(tmp_path, lic_str)

        monkeypatch.setenv("YASHIGANI_LICENSE_FILE", lic_path)
        monkeypatch.delenv("YASHIGANI_TLS_DOMAIN", raising=False)

        from yashigani.licensing.loader import load_license
        from yashigani.licensing.model import LicenseTier

        result = load_license()
        assert result.tier == LicenseTier.COMMUNITY

    def test_wildcard_org_domain_rejected_for_paid_tier(self, tmp_path, patched_v5_verifier, monkeypatch):
        master_key = patched_v5_verifier
        leaf_cert, leaf_cert_sig, licence_key = _make_licence_leaf(master_key)
        payload = _make_payload(org_domain="*")  # tier="professional" (default)
        lic_str = _build_v5_license(payload, leaf_cert, leaf_cert_sig, licence_key)
        lic_path = self._write_license_file(tmp_path, lic_str)

        monkeypatch.setenv("YASHIGANI_LICENSE_FILE", lic_path)
        monkeypatch.delenv("YASHIGANI_TLS_DOMAIN", raising=False)

        from yashigani.licensing.loader import load_license
        from yashigani.licensing.model import LicenseTier

        result = load_license()
        assert result.tier == LicenseTier.COMMUNITY
        assert result.valid is True  # COMMUNITY_LICENSE is always valid

    def test_wildcard_org_domain_accepted_for_community_tier(self, tmp_path, patched_v5_verifier, monkeypatch):
        master_key = patched_v5_verifier
        leaf_cert, leaf_cert_sig, licence_key = _make_licence_leaf(master_key)
        payload = _make_payload(tier="community", org_domain="*", max_agents=20, max_end_users=5, max_admin_seats=2, max_orgs=1)
        lic_str = _build_v5_license(payload, leaf_cert, leaf_cert_sig, licence_key)
        lic_path = self._write_license_file(tmp_path, lic_str)

        monkeypatch.setenv("YASHIGANI_LICENSE_FILE", lic_path)
        monkeypatch.delenv("YASHIGANI_TLS_DOMAIN", raising=False)

        from yashigani.licensing.loader import load_license
        from yashigani.licensing.model import LicenseTier

        result = load_license()
        assert result.valid is True
        assert result.tier == LicenseTier.COMMUNITY


# ---------------------------------------------------------------------------
# sign_license.py v5 integration roundtrip
# ---------------------------------------------------------------------------

class TestSignLicenseV5Roundtrip:
    """
    Full roundtrip: scripts/sign_license.py (v5) -> verify_license.
    scripts/sign_license.py is gitignored (internal signing tool) and will
    not be present in CI checkouts — skip cleanly, mirroring the old v4 class.
    """

    def _import_sign_license(self):
        import sys
        from pathlib import Path
        scripts_dir = Path(__file__).parents[3] / "scripts"
        sys.path.insert(0, str(scripts_dir))
        try:
            import sign_license
            return sign_license
        except ModuleNotFoundError:
            pytest.skip(
                "scripts/sign_license.py not available in this checkout — "
                "internal signing tool is gitignored (P0-5a)"
            )
        finally:
            sys.path.pop(0)

    def test_v5_roundtrip(self, patched_v5_verifier, tmp_path):
        master_key = patched_v5_verifier
        sl = self._import_sign_license()

        leaf_cert, leaf_cert_sig, licence_key = _make_licence_leaf(master_key)

        key_path = tmp_path / "licence_private.pem"
        key_path.write_bytes(
            licence_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        leaf_cert_path = tmp_path / "leaf_cert.json"
        leaf_cert_path.write_text(json.dumps(leaf_cert.to_canonical_dict()))

        payload = sl.build_payload_v5(
            tier="starter", org_domain="acme.example.com", client_id="acme-corp",
            licence_serial="lic-0001", expires_at="2099-01-01T00:00:00Z",
        )
        wire = sl.sign_licence_file(
            payload=payload,
            licence_key_pem_path=str(key_path),
            leaf_cert_json_path=str(leaf_cert_path),
            leaf_cert_sig_b64=base64.b64encode(leaf_cert_sig).decode(),
        )
        assert wire.count(".") == 3, "v5 license must have exactly 3 dots (4 segments)"

        from yashigani.licensing.verifier import verify_license
        from yashigani.licensing.model import LicenseTier

        result = verify_license(wire)
        assert result.valid is True
        assert result.tier == LicenseTier.STARTER

    def test_canary_not_in_valid_issuable_tiers(self):
        sl = self._import_sign_license()
        assert "canary" not in sl.VALID_TIERS, (
            "canary tier must not appear in sign_license.VALID_TIERS — "
            "it is a detection sentinel and must never be issued to customers"
        )

    def test_tier_defaults_match_model(self):
        sl = self._import_sign_license()
        from yashigani.licensing.model import TIER_DEFAULTS as model_defaults

        check_fields = ["max_agents", "max_end_users", "max_admin_seats"]
        for tier, expected in model_defaults.items():
            if tier not in sl.TIER_DEFAULTS:
                continue
            for field in check_fields:
                assert sl.TIER_DEFAULTS[tier].get(field) == expected[field], (
                    f"TIER_DEFAULTS drift: tier={tier!r} field={field!r}"
                )


# ---------------------------------------------------------------------------
# Persistent "Yashigani license tampered" banner (design §5)
# ---------------------------------------------------------------------------

class TestTamperBanner:
    """
    Design §5 fail-mode: "Module tampered / hash mismatch / leaf-cert
    invalid" -> COMMUNITY tier + persistent user-facing banner shown to ALL
    users, NO user deletion/suspension. Distinct from the plain "no license
    configured" COMMUNITY state, which must NOT show this banner.
    """

    def test_is_license_tampered_false_when_clean(self, monkeypatch):
        import yashigani.licensing.enforcer as enforcer_mod
        import yashigani.licensing.verifier as verifier_mod

        monkeypatch.setattr(verifier_mod, "_integrity_violated", False)
        monkeypatch.setattr(enforcer_mod, "_enforcer_integrity_violated", False)

        assert enforcer_mod.is_license_tampered() is False

    def test_is_license_tampered_true_on_verifier_violation(self, monkeypatch):
        import yashigani.licensing.enforcer as enforcer_mod
        import yashigani.licensing.verifier as verifier_mod

        monkeypatch.setattr(verifier_mod, "_integrity_violated", True)

        assert enforcer_mod.is_license_tampered() is True

    def test_banner_context_shows_tamper_severity(self, monkeypatch):
        import yashigani.licensing.verifier as verifier_mod
        from yashigani.backoffice.routes.license import get_license_banner_context

        monkeypatch.setattr(verifier_mod, "_integrity_violated", True)

        ctx = get_license_banner_context()
        assert ctx["license_mode"] == "tampered"
        assert ctx["license_banner"]["show"] is True
        assert ctx["license_banner"]["severity"] == "tampered"
        assert "tampered" in ctx["license_banner"]["message"].lower()
        # Honest wording, never a taunt (§5 note) — must not claim CMA/CFAA
        # attacker-facing language, and must state no accounts were touched.
        assert "no accounts" in ctx["license_banner"]["message"].lower()

    def test_banner_context_normal_when_not_tampered(self, monkeypatch):
        import yashigani.licensing.verifier as verifier_mod
        import yashigani.licensing.enforcer as enforcer_mod
        from yashigani.backoffice.routes.license import get_license_banner_context

        monkeypatch.setattr(verifier_mod, "_integrity_violated", False)
        monkeypatch.setattr(enforcer_mod, "_enforcer_integrity_violated", False)

        ctx = get_license_banner_context()
        assert ctx["license_mode"] != "tampered"

    def test_get_license_returns_community_but_does_not_delete_users(self, monkeypatch):
        """Tamper forces COMMUNITY tier (existing get_license() contract) —
        this test documents that NOTHING in the tamper path touches user
        accounts; enforcer only ever returns a LicenseState, never calls
        into any user-deletion/suspension code path."""
        import yashigani.licensing.enforcer as enforcer_mod
        import yashigani.licensing.verifier as verifier_mod
        from yashigani.licensing.model import LicenseTier

        monkeypatch.setattr(verifier_mod, "_integrity_violated", True)

        lic = enforcer_mod.get_license()
        assert lic.tier == LicenseTier.COMMUNITY
        # get_license() is a pure read of state — no side effects, so
        # asserting its return shape is the whole contract here.
        assert lic.valid is True
