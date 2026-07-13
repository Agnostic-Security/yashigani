"""
Unit tests — Yashigani licence-hardening v2 Phase A shared foundation.

Covers: yashigani.licensing.chain.{algorithms,canonical,leaf_cert,signer,anchors}

Ref: AgnosticSecurity/Products/Yashigani/licence-hardening-v2-design-20260713.md
Ref: dispatch brief "Yashigani licence-hardening v2 — PHASE A" 2026-07-13/14.

No live hardware/KMS required — PivSigner/KmsSigner tests exercise only the
pure/stub surface (raw_rs_to_der reconciliation, NotImplementedError shape).
"""
from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import serialization

from yashigani.licensing.chain.algorithms import (
    Alg,
    AlgorithmUnavailableError,
    RoleMismatchError,
    UnknownAlgorithmError,
    decode_hybrid_signature,
    der_to_raw_rs,
    encode_hybrid_signature,
    hybrid_both_must_verify,
    raw_rs_to_der,
    sign_message,
    verify_signature,
)
from yashigani.licensing.chain.anchors import AnchorSet, AnchorStatus, TrustAnchor
from yashigani.licensing.chain.canonical import (
    CTX_BUNDLE,
    CTX_LEAF_CERT,
    CTX_LICENCE_PAYLOAD,
    audit_checkpoint_signing_digest,
    canonical,
    domain_separated_digest,
    leaf_cert_signing_digest,
    licence_payload_signing_digest,
)
from yashigani.licensing.chain.leaf_cert import SHARED_CLIENT_ID, LeafCert, Role
from yashigani.licensing.chain.signer import KmsSigner, PemSigner, PivSigner


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _gen_p384_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP384R1())


def _pem(key: ec.EllipticCurvePrivateKey) -> str:
    return (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )


def _make_leaf_cert(role: Role = Role.LICENCE, client_id: str = "acme-corp", **overrides) -> LeafCert:
    now = _now()
    key = overrides.pop("_pubkey", None) or _pem(_gen_p384_key())
    fields = dict(
        role=role,
        client_id=client_id,
        leaf_pubkey_pem=key,
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=30),
        serial="leaf-0001",
        signed_at=now,
        alg=Alg.ECDSA_P384_SHA384,
    )
    fields.update(overrides)
    return LeafCert(**fields)


# ---------------------------------------------------------------------------
# canonical() determinism
# ---------------------------------------------------------------------------

class TestCanonicalDeterminism(unittest.TestCase):
    def test_key_order_independent(self):
        a = canonical({"b": 1, "a": 2, "c": 3})
        b = canonical({"c": 3, "a": 2, "b": 1})
        self.assertEqual(a, b)

    def test_no_incidental_whitespace(self):
        s = canonical({"a": 1, "b": [1, 2, 3]})
        self.assertNotIn(" ", s)
        self.assertEqual(s, '{"a":1,"b":[1,2,3]}')

    def test_pem_string_round_trips_as_json_string(self):
        pem = "-----BEGIN PUBLIC KEY-----\nABCD\n-----END PUBLIC KEY-----\n"
        s = canonical({"leaf_pubkey_pem": pem})
        self.assertIn("\\n", s)  # newline escaped, not raw
        import json
        self.assertEqual(json.loads(s)["leaf_pubkey_pem"], pem)

    def test_repeated_calls_identical(self):
        obj = {"z": 1, "a": {"y": 2, "x": 3}, "m": [3, 1, 2]}
        self.assertEqual(canonical(obj), canonical(obj))

    def test_nested_dict_key_order_independent(self):
        a = canonical({"outer": {"b": 1, "a": 2}})
        b = canonical({"outer": {"a": 2, "b": 1}})
        self.assertEqual(a, b)


class TestDomainSeparatedDigest(unittest.TestCase):
    def test_different_context_tags_produce_different_digests(self):
        d1 = domain_separated_digest(CTX_LEAF_CERT, b"same-bytes")
        d2 = domain_separated_digest(CTX_LICENCE_PAYLOAD, b"same-bytes")
        self.assertNotEqual(d1, d2)

    def test_sha384_default_length(self):
        d = domain_separated_digest(CTX_BUNDLE, b"x")
        self.assertEqual(len(d), 48)

    def test_top_tier_sha512_length(self):
        d = domain_separated_digest(CTX_BUNDLE, b"x", top_tier=True)
        self.assertEqual(len(d), 64)

    def test_cross_context_signature_reuse_is_not_transparent(self):
        # Same underlying bytes signed for two different purposes must not
        # collide — this is the entire point of domain separation.
        leaf_digest = leaf_cert_signing_digest({"x": 1})
        payload_digest = licence_payload_signing_digest(b"payload", {"x": 1})
        self.assertNotEqual(leaf_digest, payload_digest)

    def test_audit_checkpoint_digest_binds_all_widened_fields(self):
        base = audit_checkpoint_signing_digest("2026-07-14", "acme-corp", 100, b"\x00" * 48, "ecdsa-p384-sha384")
        # Changing any one widened field changes the digest (ROUND-4 fix:
        # sign date/tenant/event_count/merkle_root/alg, not merkle_root alone).
        self.assertNotEqual(base, audit_checkpoint_signing_digest("2026-07-15", "acme-corp", 100, b"\x00" * 48, "ecdsa-p384-sha384"))
        self.assertNotEqual(base, audit_checkpoint_signing_digest("2026-07-14", "other-corp", 100, b"\x00" * 48, "ecdsa-p384-sha384"))
        self.assertNotEqual(base, audit_checkpoint_signing_digest("2026-07-14", "acme-corp", 101, b"\x00" * 48, "ecdsa-p384-sha384"))
        self.assertNotEqual(base, audit_checkpoint_signing_digest("2026-07-14", "acme-corp", 100, b"\x01" * 48, "ecdsa-p384-sha384"))
        self.assertNotEqual(base, audit_checkpoint_signing_digest("2026-07-14", "acme-corp", 100, b"\x00" * 48, "ml-dsa-87"))


# ---------------------------------------------------------------------------
# Alg dispatch
# ---------------------------------------------------------------------------

class TestAlgDispatch(unittest.TestCase):
    def test_from_wire_accepts_closed_enum_members(self):
        self.assertEqual(Alg.from_wire("ecdsa-p384-sha384"), Alg.ECDSA_P384_SHA384)
        self.assertEqual(Alg.from_wire("ml-dsa-87"), Alg.ML_DSA_87)
        self.assertEqual(Alg.from_wire("hybrid(ecdsa-p384+ml-dsa-87)"), Alg.HYBRID_ECDSA_P384_ML_DSA_87)
        self.assertEqual(Alg.from_wire("slh-dsa-sha2-256s"), Alg.SLH_DSA_SHA2_256S)

    def test_from_wire_rejects_unknown_string_no_downgrade(self):
        with self.assertRaises(UnknownAlgorithmError):
            Alg.from_wire("ecdsa-p256-sha256")  # the OLD v1 algorithm — must not silently work
        with self.assertRaises(UnknownAlgorithmError):
            Alg.from_wire("rsa-2048-sha256")
        with self.assertRaises(UnknownAlgorithmError):
            Alg.from_wire("")

    def test_ecdsa_p384_sign_verify_round_trip(self):
        key = _gen_p384_key()
        digest = domain_separated_digest(CTX_LEAF_CERT, b"payload")
        sig = sign_message(Alg.ECDSA_P384_SHA384, key, digest)
        self.assertTrue(verify_signature(Alg.ECDSA_P384_SHA384, _pem(key), digest, sig))

    def test_ecdsa_p384_verify_rejects_tampered_digest(self):
        key = _gen_p384_key()
        digest = domain_separated_digest(CTX_LEAF_CERT, b"payload")
        sig = sign_message(Alg.ECDSA_P384_SHA384, key, digest)
        tampered_digest = domain_separated_digest(CTX_LEAF_CERT, b"different-payload")
        self.assertFalse(verify_signature(Alg.ECDSA_P384_SHA384, _pem(key), tampered_digest, sig))

    def test_ecdsa_p384_verify_rejects_wrong_key(self):
        key = _gen_p384_key()
        other_key = _gen_p384_key()
        digest = domain_separated_digest(CTX_LEAF_CERT, b"payload")
        sig = sign_message(Alg.ECDSA_P384_SHA384, key, digest)
        self.assertFalse(verify_signature(Alg.ECDSA_P384_SHA384, _pem(other_key), digest, sig))

    def test_ml_dsa_87_verify_fails_closed_not_downgrade(self):
        digest = domain_separated_digest(CTX_LEAF_CERT, b"payload")
        with self.assertRaises(AlgorithmUnavailableError):
            verify_signature(Alg.ML_DSA_87, "dummy-pem", digest, b"dummy-sig")

    def test_hybrid_verify_fails_closed_not_downgrade(self):
        digest = domain_separated_digest(CTX_LEAF_CERT, b"payload")
        with self.assertRaises(AlgorithmUnavailableError):
            verify_signature(Alg.HYBRID_ECDSA_P384_ML_DSA_87, "dummy-pem", digest, b"dummy-sig")

    def test_slh_dsa_verify_fails_closed(self):
        digest = domain_separated_digest(CTX_LEAF_CERT, b"payload")
        with self.assertRaises(AlgorithmUnavailableError):
            verify_signature(Alg.SLH_DSA_SHA2_256S, "dummy-pem", digest, b"dummy-sig")

    def test_verify_wrong_curve_key_raises_not_silently_false(self):
        # Key-type confusion guard, mirroring the existing verifier.py pattern.
        p256_key = ec.generate_private_key(ec.SECP256R1())
        digest = domain_separated_digest(CTX_LEAF_CERT, b"payload")
        with self.assertRaises(RuntimeError):
            verify_signature(Alg.ECDSA_P384_SHA384, _pem(p256_key), digest, b"\x00" * 100)

    def test_sign_message_unknown_alg_rejected(self):
        key = _gen_p384_key()
        with self.assertRaises(UnknownAlgorithmError):
            sign_message("not-a-real-alg", key, b"x" * 48)  # type: ignore[arg-type]


class TestRawRsDerReconciliation(unittest.TestCase):
    def test_round_trip(self):
        key = _gen_p384_key()
        digest = b"x" * 48
        der_sig = key.sign(digest, ec.ECDSA(utils.Prehashed(__import__("cryptography.hazmat.primitives.hashes", fromlist=["SHA384"]).SHA384())))
        raw = der_to_raw_rs(der_sig, curve_size_bytes=48)
        self.assertEqual(len(raw), 96)
        back_to_der = raw_rs_to_der(raw, curve_size_bytes=48)
        # DER re-encoding of the same (r, s) must verify identically even if
        # byte-for-byte encoding could theoretically differ (it won't here,
        # since decode/encode of the same ints is deterministic).
        self.assertTrue(
            verify_signature(Alg.ECDSA_P384_SHA384, _pem(key), digest, back_to_der)
        )

    def test_wrong_length_rejected(self):
        with self.assertRaises(ValueError):
            raw_rs_to_der(b"\x00" * 10, curve_size_bytes=48)

    def test_pkcs11_style_raw_signature_verifies_after_conversion(self):
        # Simulates what a YubiKey PKCS#11 C_Sign call would hand back: raw
        # r||s. PivSigner.raw_signature_to_der() must make it verify.
        key = _gen_p384_key()
        digest = b"y" * 48
        from cryptography.hazmat.primitives.hashes import SHA384
        der_sig = key.sign(digest, ec.ECDSA(utils.Prehashed(SHA384())))
        simulated_raw = der_to_raw_rs(der_sig, curve_size_bytes=48)
        converted = PivSigner.raw_signature_to_der(simulated_raw, curve_size_bytes=48)
        self.assertTrue(verify_signature(Alg.ECDSA_P384_SHA384, _pem(key), digest, converted))


# ---------------------------------------------------------------------------
# Hybrid: both-must-verify + non-strippability
# ---------------------------------------------------------------------------

class TestHybridBothMustVerify(unittest.TestCase):
    def test_and_logic_truth_table(self):
        self.assertTrue(hybrid_both_must_verify(True, True))
        self.assertFalse(hybrid_both_must_verify(True, False))
        self.assertFalse(hybrid_both_must_verify(False, True))
        self.assertFalse(hybrid_both_must_verify(False, False))

    def test_encode_decode_round_trip(self):
        classical = b"\x01" * 100
        pqc = b"\x02" * 4600  # ~ ml-dsa-87 sig size ballpark per design's re-derived cap
        blob = encode_hybrid_signature(classical, pqc)
        c2, p2 = decode_hybrid_signature(blob)
        self.assertEqual(classical, c2)
        self.assertEqual(pqc, p2)

    def test_decode_rejects_truncated_blob_missing_pqc_component(self):
        classical = b"\x01" * 50
        # Hand-craft a blob that only contains the classical component's
        # length prefix + bytes, with the PQC component chopped off — this
        # is exactly the "strip the hybrid down to classical-only" attack.
        import struct
        stripped = struct.pack(">I", len(classical)) + classical
        with self.assertRaises(ValueError):
            decode_hybrid_signature(stripped)

    def test_decode_rejects_trailing_bytes(self):
        blob = encode_hybrid_signature(b"\x01" * 10, b"\x02" * 10) + b"\xff"
        with self.assertRaises(ValueError):
            decode_hybrid_signature(blob)

    def test_decode_rejects_empty_component(self):
        with self.assertRaises(ValueError):
            decode_hybrid_signature(encode_hybrid_signature(b"", b"\x02" * 10))
        with self.assertRaises(ValueError):
            decode_hybrid_signature(encode_hybrid_signature(b"\x01" * 10, b""))

    def test_no_isolated_sub_signature_verify_path_exposed(self):
        # There must be no public function in the algorithms module that
        # verifies only the classical component of a HYBRID signature.
        import yashigani.licensing.chain.algorithms as algs
        public_names = [n for n in dir(algs) if not n.startswith("_")]
        for name in public_names:
            lowered = name.lower()
            self.assertFalse(
                "classical_only" in lowered or "downgrade" in lowered,
                f"found a suspicious public symbol suggesting a classical-only "
                f"verify path: {name}",
            )
        # And the one entry point for HYBRID always fails closed today.
        digest = domain_separated_digest(CTX_LEAF_CERT, b"x")
        with self.assertRaises(AlgorithmUnavailableError):
            verify_signature(Alg.HYBRID_ECDSA_P384_ML_DSA_87, "dummy", digest, b"dummy")


# ---------------------------------------------------------------------------
# leaf_cert round-trip + schema invariants
# ---------------------------------------------------------------------------

class TestLeafCertSchema(unittest.TestCase):
    def test_round_trip_licence_leaf(self):
        cert = _make_leaf_cert(role=Role.LICENCE, client_id="acme-corp")
        d = cert.to_canonical_dict()
        restored = LeafCert.from_canonical_dict(d)
        self.assertEqual(restored.to_canonical_dict(), d)

    def test_round_trip_code_leaf(self):
        cert = _make_leaf_cert(role=Role.CODE, client_id=SHARED_CLIENT_ID, release="4.1.1")
        d = cert.to_canonical_dict()
        restored = LeafCert.from_canonical_dict(d)
        self.assertEqual(restored.release, "4.1.1")
        self.assertEqual(restored.to_canonical_dict(), d)

    def test_round_trip_audit_leaf(self):
        cert = _make_leaf_cert(role=Role.AUDIT, client_id="acme-corp", licence_serial=None)
        d = cert.to_canonical_dict()
        restored = LeafCert.from_canonical_dict(d)
        self.assertEqual(restored.role, Role.AUDIT)

    def test_code_leaf_requires_shared_client_id(self):
        with self.assertRaises(ValueError):
            _make_leaf_cert(role=Role.CODE, client_id="acme-corp", release="4.1.1")

    def test_code_leaf_requires_release(self):
        with self.assertRaises(ValueError):
            _make_leaf_cert(role=Role.CODE, client_id=SHARED_CLIENT_ID, release=None)

    def test_licence_leaf_rejects_shared_client_id(self):
        with self.assertRaises(ValueError):
            _make_leaf_cert(role=Role.LICENCE, client_id=SHARED_CLIENT_ID)

    def test_audit_leaf_rejects_shared_client_id(self):
        # ROUND-4: client_id binding extended to audit leaves too.
        with self.assertRaises(ValueError):
            _make_leaf_cert(role=Role.AUDIT, client_id=SHARED_CLIENT_ID)

    def test_licence_leaf_rejects_release_field(self):
        with self.assertRaises(ValueError):
            _make_leaf_cert(role=Role.LICENCE, client_id="acme-corp", release="4.1.1")

    def test_not_after_must_be_after_not_before(self):
        now = _now()
        with self.assertRaises(ValueError):
            _make_leaf_cert(not_before=now, not_after=now - timedelta(days=1))

    def test_naive_datetime_rejected(self):
        with self.assertRaises(ValueError):
            _make_leaf_cert(signed_at=datetime(2026, 1, 1))  # no tzinfo

    def test_alg_lives_inside_canonical_dict(self):
        cert = _make_leaf_cert()
        d = cert.to_canonical_dict()
        self.assertIn("alg", d)
        self.assertEqual(d["alg"], "ecdsa-p384-sha384")

    def test_different_alg_changes_signing_digest(self):
        cert_a = _make_leaf_cert()
        # Can't construct a real ML-DSA leaf (PemSigner rejects it), but we
        # can prove the digest is alg-sensitive by mutating the dict directly.
        d = cert_a.to_canonical_dict()
        d_other_alg = dict(d, alg="ml-dsa-87")
        self.assertNotEqual(leaf_cert_signing_digest(d), leaf_cert_signing_digest(d_other_alg))


class TestLeafCertMasterSignVerify(unittest.TestCase):
    """End-to-end (within Phase A scope): a PemSigner master signs a leaf_cert
    digest; verify_signature() checks it. This is NOT the full Phase B chain
    (no licgen, no v5 payload) — it proves the primitives compose correctly.
    """

    def test_master_signs_leaf_cert_and_verifies(self):
        master_key = _gen_p384_key()
        cert = _make_leaf_cert()
        digest = cert.signing_digest()
        sig = sign_message(Alg.ECDSA_P384_SHA384, master_key, digest)
        self.assertTrue(verify_signature(Alg.ECDSA_P384_SHA384, _pem(master_key), digest, sig))

    def test_tampered_leaf_cert_fails_verification(self):
        master_key = _gen_p384_key()
        cert = _make_leaf_cert()
        digest = cert.signing_digest()
        sig = sign_message(Alg.ECDSA_P384_SHA384, master_key, digest)

        tampered = LeafCert.from_canonical_dict(dict(cert.to_canonical_dict(), serial="leaf-9999-forged"))
        tampered_digest = tampered.signing_digest()
        self.assertFalse(verify_signature(Alg.ECDSA_P384_SHA384, _pem(master_key), tampered_digest, sig))

    def test_leaf_sig_binds_to_exact_leaf_cert(self):
        """leaf_sig must not be transferable to a different (even validly
        master-signed) leaf_cert — proves the licence_payload_signing_digest
        binding (design: 'leaf_sig binds to the leaf cert')."""
        leaf_key = _gen_p384_key()
        cert_a = _make_leaf_cert(serial="leaf-A")
        cert_b = _make_leaf_cert(serial="leaf-B")
        payload_bytes = b'{"tier":"professional"}'

        digest_a = licence_payload_signing_digest(payload_bytes, cert_a.to_canonical_dict())
        sig = sign_message(Alg.ECDSA_P384_SHA384, leaf_key, digest_a)

        # Signature is valid against the digest computed with cert_a...
        self.assertTrue(verify_signature(Alg.ECDSA_P384_SHA384, _pem(leaf_key), digest_a, sig))
        # ...but NOT against the same payload bound to a different leaf_cert.
        digest_b = licence_payload_signing_digest(payload_bytes, cert_b.to_canonical_dict())
        self.assertFalse(verify_signature(Alg.ECDSA_P384_SHA384, _pem(leaf_key), digest_b, sig))

    def test_verify_does_not_gate_on_expired_window(self):
        """Windows are SIGNING-SIDE ONLY — never checked at verify-time. A
        leaf_cert whose not_after is already in the past must still verify
        cleanly at the crypto layer (no accidental verify-time expiry gate)."""
        master_key = _gen_p384_key()
        past_now = _now() - timedelta(days=100)
        cert = _make_leaf_cert(
            not_before=past_now - timedelta(days=30),
            not_after=past_now,  # window closed 100 days ago
        )
        digest = cert.signing_digest()
        sig = sign_message(Alg.ECDSA_P384_SHA384, master_key, digest)
        self.assertTrue(verify_signature(Alg.ECDSA_P384_SHA384, _pem(master_key), digest, sig))


# ---------------------------------------------------------------------------
# Signer backends
# ---------------------------------------------------------------------------

class TestPemSigner(unittest.TestCase):
    def test_sign_and_verify(self):
        key = _gen_p384_key()
        signer = PemSigner(role=Role.LICENCE, private_key=key)
        digest = domain_separated_digest(CTX_LICENCE_PAYLOAD, b"payload")
        sig = signer.sign(Role.LICENCE, CTX_LICENCE_PAYLOAD, digest)
        self.assertTrue(verify_signature(Alg.ECDSA_P384_SHA384, signer.public_key(), digest, sig))

    def test_role_mismatch_rejected(self):
        key = _gen_p384_key()
        signer = PemSigner(role=Role.LICENCE, private_key=key)
        digest = domain_separated_digest(CTX_LEAF_CERT, b"x")
        with self.assertRaises(RoleMismatchError):
            signer.sign(Role.CODE, CTX_LEAF_CERT, digest)

    def test_rejects_non_p384_key(self):
        p256_key = ec.generate_private_key(ec.SECP256R1())
        with self.assertRaises(ValueError):
            PemSigner(role=Role.LICENCE, private_key=p256_key)

    def test_rejects_non_ecdsa_alg(self):
        key = _gen_p384_key()
        with self.assertRaises(ValueError):
            PemSigner(role=Role.LICENCE, private_key=key, alg=Alg.ML_DSA_87)

    def test_from_pem_bytes_round_trip(self):
        key = _gen_p384_key()
        pem_bytes = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        signer = PemSigner.from_pem_bytes(role=Role.CODE, pem_bytes=pem_bytes)
        digest = domain_separated_digest(CTX_BUNDLE, b"bundle")
        sig = signer.sign(Role.CODE, CTX_BUNDLE, digest)
        self.assertTrue(verify_signature(Alg.ECDSA_P384_SHA384, signer.public_key(), digest, sig))

    def test_cert_returns_none_by_default(self):
        signer = PemSigner(role=Role.LICENCE, private_key=_gen_p384_key())
        self.assertIsNone(signer.cert())

    def test_cert_returns_bound_leaf_cert(self):
        cert = _make_leaf_cert(role=Role.LICENCE, client_id="acme-corp")
        signer = PemSigner(role=Role.LICENCE, private_key=_gen_p384_key(), leaf_cert=cert)
        self.assertIs(signer.cert(), cert)

    def test_alg_property(self):
        signer = PemSigner(role=Role.LICENCE, private_key=_gen_p384_key())
        self.assertEqual(signer.alg, Alg.ECDSA_P384_SHA384)


class TestPivSignerStub(unittest.TestCase):
    """No YubiKey hardware in this environment — verifies the PKCS#11-first
    shape and the fail-closed stub behaviour, per the design's requirement
    that YubiKey (now) and a VPC HSM/Vault (later) share this exact shape."""

    def test_constructor_shape(self):
        signer = PivSigner(
            pkcs11_module_path="/usr/lib/pkcs11/ykcs11.so",
            key_label="yashigani-master",
            slot_id=0,
            pin=b"123456",
            role=Role.CODE,
        )
        self.assertEqual(signer.role, Role.CODE)
        self.assertEqual(signer.alg, Alg.ECDSA_P384_SHA384)

    def test_sign_raises_not_implemented_without_hardware(self):
        signer = PivSigner(pkcs11_module_path="/usr/lib/pkcs11/ykcs11.so", key_label="m", role=Role.CODE)
        with self.assertRaises(NotImplementedError):
            signer.sign(Role.CODE, CTX_LEAF_CERT, b"x" * 48)

    def test_sign_still_checks_role_before_raising_hardware_error(self):
        signer = PivSigner(pkcs11_module_path="/usr/lib/pkcs11/ykcs11.so", key_label="m", role=Role.CODE)
        with self.assertRaises(RoleMismatchError):
            signer.sign(Role.LICENCE, CTX_LEAF_CERT, b"x" * 48)

    def test_public_key_raises_not_implemented_without_hardware(self):
        signer = PivSigner(pkcs11_module_path="/usr/lib/pkcs11/ykcs11.so", key_label="m", role=Role.CODE)
        with self.assertRaises(NotImplementedError):
            signer.public_key()

    def test_cert_returns_none_master_has_no_cert(self):
        signer = PivSigner(pkcs11_module_path="/usr/lib/pkcs11/ykcs11.so", key_label="m", role=Role.CODE)
        self.assertIsNone(signer.cert())

    def test_raw_signature_to_der_static_helper(self):
        key = _gen_p384_key()
        from cryptography.hazmat.primitives.hashes import SHA384
        digest = b"z" * 48
        der_sig = key.sign(digest, ec.ECDSA(utils.Prehashed(SHA384())))
        raw = der_to_raw_rs(der_sig)
        converted = PivSigner.raw_signature_to_der(raw)
        self.assertTrue(verify_signature(Alg.ECDSA_P384_SHA384, _pem(key), digest, converted))


class TestKmsSignerStub(unittest.TestCase):
    def test_constructor_validates_signature_format(self):
        with self.assertRaises(ValueError):
            KmsSigner(kms_key_id="k1", provider="azure", raw_signature_format="bogus", role=Role.LICENCE)

    def test_sign_raises_not_implemented(self):
        signer = KmsSigner(kms_key_id="k1", provider="aws", raw_signature_format="der", role=Role.LICENCE)
        with self.assertRaises(NotImplementedError):
            signer.sign(Role.LICENCE, CTX_LICENCE_PAYLOAD, b"x" * 48)

    def test_reconcile_der_provider_passthrough(self):
        key = _gen_p384_key()
        from cryptography.hazmat.primitives.hashes import SHA384
        digest = b"a" * 48
        der_sig = key.sign(digest, ec.ECDSA(utils.Prehashed(SHA384())))
        signer = KmsSigner(kms_key_id="k1", provider="aws", raw_signature_format="der", role=Role.LICENCE)
        self.assertEqual(signer.reconcile(der_sig), der_sig)

    def test_reconcile_raw_rs_provider_converts_to_der(self):
        # Azure Key Vault quirk — raw r||s must be reconciled to DER.
        key = _gen_p384_key()
        from cryptography.hazmat.primitives.hashes import SHA384
        digest = b"b" * 48
        der_sig = key.sign(digest, ec.ECDSA(utils.Prehashed(SHA384())))
        raw_sig = der_to_raw_rs(der_sig)
        signer = KmsSigner(kms_key_id="k1", provider="azure", raw_signature_format="raw_rs", role=Role.LICENCE)
        reconciled = signer.reconcile(raw_sig)
        self.assertTrue(verify_signature(Alg.ECDSA_P384_SHA384, _pem(key), digest, reconciled))

    def test_role_mismatch_checked_before_hardware_error(self):
        signer = KmsSigner(kms_key_id="k1", provider="aws", raw_signature_format="der", role=Role.LICENCE)
        with self.assertRaises(RoleMismatchError):
            signer.sign(Role.CODE, CTX_BUNDLE, b"x" * 48)


# ---------------------------------------------------------------------------
# Trust-anchor SET
# ---------------------------------------------------------------------------

class TestAnchorSet(unittest.TestCase):
    def _anchor(self, key: ec.EllipticCurvePrivateKey, anchor_id: str, status: AnchorStatus, alg: Alg = Alg.ECDSA_P384_SHA384) -> TrustAnchor:
        return TrustAnchor(anchor_id=anchor_id, pubkey_pem=_pem(key), alg=alg, status=status, added=_now())

    def test_rejects_duplicate_anchor_ids(self):
        key = _gen_p384_key()
        anchors = [self._anchor(key, "M1", AnchorStatus.ACTIVE), self._anchor(key, "M1", AnchorStatus.RETIRING)]
        with self.assertRaises(ValueError):
            AnchorSet(anchors)

    def test_active_anchors_filters_correctly(self):
        k1, k2, k3 = _gen_p384_key(), _gen_p384_key(), _gen_p384_key()
        aset = AnchorSet([
            self._anchor(k1, "M1", AnchorStatus.RETIRING),
            self._anchor(k2, "M2", AnchorStatus.ACTIVE),
            self._anchor(k3, "M0", AnchorStatus.RETIRED),
        ])
        active_ids = {a.anchor_id for a in aset.active_anchors()}
        self.assertEqual(active_ids, {"M2"})

    def test_trusted_anchors_includes_active_and_retiring_not_retired(self):
        k1, k2, k3 = _gen_p384_key(), _gen_p384_key(), _gen_p384_key()
        aset = AnchorSet([
            self._anchor(k1, "M1", AnchorStatus.RETIRING),
            self._anchor(k2, "M2", AnchorStatus.ACTIVE),
            self._anchor(k3, "M0", AnchorStatus.RETIRED),
        ])
        trusted_ids = {a.anchor_id for a in aset.trusted_anchors()}
        self.assertEqual(trusted_ids, {"M1", "M2"})

    def test_validate_leaf_cert_active_anchor_matches(self):
        master = _gen_p384_key()
        aset = AnchorSet([self._anchor(master, "M1", AnchorStatus.ACTIVE)])
        cert = _make_leaf_cert()
        sig = sign_message(Alg.ECDSA_P384_SHA384, master, cert.signing_digest())
        matched = aset.validate_leaf_cert(cert, sig)
        self.assertIsNotNone(matched)
        self.assertEqual(matched.anchor_id, "M1")

    def test_validate_leaf_cert_retiring_anchor_still_matches(self):
        """Rotation grace period: a RETIRING (not yet RETIRED) anchor must
        still validate old leaf_certs signed under it — this is what makes
        'mark M1 retiring' non-breaking (design's rotation lifecycle)."""
        m1 = _gen_p384_key()
        aset = AnchorSet([self._anchor(m1, "M1", AnchorStatus.RETIRING)])
        cert = _make_leaf_cert()
        sig = sign_message(Alg.ECDSA_P384_SHA384, m1, cert.signing_digest())
        matched = aset.validate_leaf_cert(cert, sig)
        self.assertIsNotNone(matched)
        self.assertEqual(matched.anchor_id, "M1")

    def test_validate_leaf_cert_retired_anchor_fails(self):
        """M1-license on build after M1 retired = FAIL -> re-issue (design's
        own rotation test matrix)."""
        m1 = _gen_p384_key()
        aset = AnchorSet([self._anchor(m1, "M1", AnchorStatus.RETIRED)])
        cert = _make_leaf_cert()
        sig = sign_message(Alg.ECDSA_P384_SHA384, m1, cert.signing_digest())
        matched = aset.validate_leaf_cert(cert, sig)
        self.assertIsNone(matched)

    def test_validate_leaf_cert_old_license_on_build_with_m1_and_m2(self):
        """old-license on new-build-with-{M1,M2} = PASS."""
        m1 = _gen_p384_key()
        m2 = _gen_p384_key()
        aset = AnchorSet([
            self._anchor(m1, "M1", AnchorStatus.ACTIVE),
            self._anchor(m2, "M2", AnchorStatus.ACTIVE),
        ])
        cert = _make_leaf_cert(serial="old-leaf")
        sig = sign_message(Alg.ECDSA_P384_SHA384, m1, cert.signing_digest())
        matched = aset.validate_leaf_cert(cert, sig)
        self.assertIsNotNone(matched)
        self.assertEqual(matched.anchor_id, "M1")

    def test_validate_leaf_cert_new_license_on_new_build(self):
        """new-license on new-build = PASS."""
        m1 = _gen_p384_key()
        m2 = _gen_p384_key()
        aset = AnchorSet([
            self._anchor(m1, "M1", AnchorStatus.ACTIVE),
            self._anchor(m2, "M2", AnchorStatus.ACTIVE),
        ])
        cert = _make_leaf_cert(serial="new-leaf")
        sig = sign_message(Alg.ECDSA_P384_SHA384, m2, cert.signing_digest())
        matched = aset.validate_leaf_cert(cert, sig)
        self.assertIsNotNone(matched)
        self.assertEqual(matched.anchor_id, "M2")

    def test_validate_leaf_cert_no_matching_anchor_returns_none(self):
        m1 = _gen_p384_key()
        unrelated_key = _gen_p384_key()
        aset = AnchorSet([self._anchor(m1, "M1", AnchorStatus.ACTIVE)])
        cert = _make_leaf_cert()
        sig = sign_message(Alg.ECDSA_P384_SHA384, unrelated_key, cert.signing_digest())
        self.assertIsNone(aset.validate_leaf_cert(cert, sig))

    def test_pqc_master_add_is_purely_additive(self):
        """PQC-master add=purely additive: an ML-DSA anchor whose backend
        isn't live yet must not break ECDSA validation against the other
        anchor in the same set."""
        m1 = _gen_p384_key()
        pqc_anchor = TrustAnchor(
            anchor_id="M-PQC", pubkey_pem="placeholder-mldsa-pubkey",
            alg=Alg.ML_DSA_87, status=AnchorStatus.ACTIVE, added=_now(),
        )
        aset = AnchorSet([self._anchor(m1, "M1", AnchorStatus.ACTIVE), pqc_anchor])
        cert = _make_leaf_cert()
        sig = sign_message(Alg.ECDSA_P384_SHA384, m1, cert.signing_digest())
        matched = aset.validate_leaf_cert(cert, sig)
        self.assertIsNotNone(matched)
        self.assertEqual(matched.anchor_id, "M1")

    def test_validate_does_not_gate_on_leaf_window_expiry(self):
        """Windows are signing-side only — an anchor-set validation must not
        reject an otherwise-valid signature just because the leaf_cert's own
        window has expired."""
        m1 = _gen_p384_key()
        aset = AnchorSet([self._anchor(m1, "M1", AnchorStatus.ACTIVE)])
        past = _now() - timedelta(days=200)
        cert = _make_leaf_cert(not_before=past - timedelta(days=10), not_after=past)
        sig = sign_message(Alg.ECDSA_P384_SHA384, m1, cert.signing_digest())
        matched = aset.validate_leaf_cert(cert, sig)
        self.assertIsNotNone(matched)

    def test_get_by_anchor_id(self):
        m1 = _gen_p384_key()
        anchor = self._anchor(m1, "M1", AnchorStatus.ACTIVE)
        aset = AnchorSet([anchor])
        self.assertEqual(aset.get("M1"), anchor)
        self.assertIsNone(aset.get("nonexistent"))

    def test_len_and_all_anchors(self):
        k1, k2 = _gen_p384_key(), _gen_p384_key()
        aset = AnchorSet([self._anchor(k1, "M1", AnchorStatus.ACTIVE), self._anchor(k2, "M2", AnchorStatus.RETIRED)])
        self.assertEqual(len(aset), 2)
        self.assertEqual(len(aset.all_anchors()), 2)


if __name__ == "__main__":
    unittest.main()
