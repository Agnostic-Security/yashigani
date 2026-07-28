"""
Unit tests — Yashigani licence-hardening v2 Phase B-CORE modules.

Covers: yashigani.licensing.chain.{licence_v5, kill_list, build_integrity}

Ref: AgnosticSecurity/Products/Yashigani/licence-hardening-v2-design-20260713.md
     §3.2 (Licence format v5), §4a (Build-integrity verify),
     §4b (Licence v5 verify), §6 (kill-list).

No live hardware/KMS required — everything here uses PemSigner + P-384
ephemeral keys, matching Phase A's test conventions.
"""
from __future__ import annotations

import json
import unittest
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from yashigani.licensing.chain.algorithms import Alg, sign_message
from yashigani.licensing.chain.anchors import AnchorSet, AnchorStatus, TrustAnchor
from yashigani.licensing.chain.build_integrity import (
    anchor_set_from_json,
    kill_list_from_json,
    leaf_cert_from_json,
    verify_build_integrity_chain,
)
from yashigani.licensing.chain.canonical import bundle_signing_digest, leaf_cert_signing_digest
from yashigani.licensing.chain.kill_list import KillList, KillListEntry, KillListSemantics
from yashigani.licensing.chain.leaf_cert import SHARED_CLIENT_ID, LeafCert, Role
from yashigani.licensing.chain.licence_v5 import (
    LICENCE_WIRE_SEGMENTS,
    LicenceV5FormatError,
    build_licence_payload_v5,
    parse_licence_v5,
    sign_licence_v5,
    verify_licence_v5,
)
from yashigani.licensing.chain.signer import PemSigner


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


def _make_leaf_cert(master_key, role=Role.LICENCE, client_id="acme-corp", serial="leaf-0001", **overrides):
    now = _now()
    key = overrides.pop("_pubkey", None) or _pem(_gen_p384_key())
    fields = dict(
        role=role, client_id=client_id, leaf_pubkey_pem=key,
        not_before=now - timedelta(days=1), not_after=now + timedelta(days=30),
        serial=serial, signed_at=now, alg=Alg.ECDSA_P384_SHA384,
    )
    fields.update(overrides)
    cert = LeafCert(**fields)
    sig = sign_message(Alg.ECDSA_P384_SHA384, master_key, leaf_cert_signing_digest(cert.to_canonical_dict()))
    return cert, sig


def _make_anchor_set(master_key, anchor_id="M1", status=AnchorStatus.ACTIVE) -> AnchorSet:
    return AnchorSet([TrustAnchor(
        anchor_id=anchor_id, pubkey_pem=_pem(master_key), alg=Alg.ECDSA_P384_SHA384,
        status=status, added=_now(),
    )])


# ---------------------------------------------------------------------------
# licence_v5.py — sign / parse / verify
# ---------------------------------------------------------------------------

class TestLicenceV5SignParseRoundTrip(unittest.TestCase):
    def test_wire_has_four_segments(self):
        master = _gen_p384_key()
        leaf_cert, leaf_cert_sig = _make_leaf_cert(master)
        licence_key = _gen_p384_key()
        # Rebuild leaf_cert bound to licence_key's own pubkey for a coherent signer.
        leaf_cert2, leaf_cert_sig2 = _make_leaf_cert(master, _pubkey=_pem(licence_key))
        payload = build_licence_payload_v5(
            org_domain="acme.example.com", tier="professional", client_id="acme-corp",
            licence_serial="lic-0001", max_agents=500, max_end_users=1000, max_admin_seats=50,
            max_orgs=1, expires_at=_now() + timedelta(days=365),
        )
        signer = PemSigner(role=Role.LICENCE, private_key=licence_key, leaf_cert=leaf_cert2)
        wire = sign_licence_v5(payload, signer, leaf_cert2, leaf_cert_sig2)
        self.assertEqual(wire.count("."), LICENCE_WIRE_SEGMENTS - 1)

    def test_parse_round_trips_payload_and_leaf_cert(self):
        master = _gen_p384_key()
        licence_key = _gen_p384_key()
        leaf_cert, leaf_cert_sig = _make_leaf_cert(master, _pubkey=_pem(licence_key))
        payload = build_licence_payload_v5(
            org_domain="acme.example.com", tier="starter", client_id="acme-corp",
            licence_serial="lic-0002", max_agents=100, max_end_users=250, max_admin_seats=25,
            max_orgs=1, expires_at=_now() + timedelta(days=365),
        )
        signer = PemSigner(role=Role.LICENCE, private_key=licence_key, leaf_cert=leaf_cert)
        wire = sign_licence_v5(payload, signer, leaf_cert, leaf_cert_sig)

        parsed = parse_licence_v5(wire)
        self.assertEqual(parsed.payload["org_domain"], "acme.example.com")
        self.assertEqual(parsed.payload["licence_serial"], "lic-0002")
        self.assertEqual(parsed.leaf_cert.client_id, "acme-corp")
        self.assertEqual(parsed.leaf_cert.role, Role.LICENCE)
        self.assertEqual(parsed.leaf_cert_sig, leaf_cert_sig)

    def test_sign_refuses_non_licence_role(self):
        master = _gen_p384_key()
        code_key = _gen_p384_key()
        code_leaf, code_leaf_sig = _make_leaf_cert(
            master, role=Role.CODE, client_id=SHARED_CLIENT_ID, release="4.1.1", _pubkey=_pem(code_key)
        )
        payload = build_licence_payload_v5(
            org_domain="*", tier="community", client_id=SHARED_CLIENT_ID, licence_serial="x",
            max_agents=20, max_end_users=5, max_admin_seats=2, max_orgs=1,
            expires_at=_now() + timedelta(days=1),
        )
        signer = PemSigner(role=Role.CODE, private_key=code_key, leaf_cert=code_leaf)
        with self.assertRaises(ValueError):
            sign_licence_v5(payload, signer, code_leaf, code_leaf_sig)

    def test_parse_rejects_wrong_segment_counts(self):
        for content in ("a.b", "a.b.c", "a.b.c.d.e", "nosep", ""):
            with self.assertRaises(LicenceV5FormatError):
                parse_licence_v5(content)

    def test_parse_rejects_garbage_base64(self):
        with self.assertRaises(LicenceV5FormatError):
            parse_licence_v5("!!!.###.$$$.%%%")


class TestLicenceV5Verify(unittest.TestCase):
    def _issue(self, master_key, client_id="acme-corp", org_domain="acme.example.com",
               tier="professional", expires_offset_days=365, serial="leaf-0001", licence_serial="lic-0001"):
        licence_key = _gen_p384_key()
        leaf_cert, leaf_cert_sig = _make_leaf_cert(
            master_key, client_id=client_id, serial=serial, _pubkey=_pem(licence_key)
        )
        payload = build_licence_payload_v5(
            org_domain=org_domain, tier=tier, client_id=client_id, licence_serial=licence_serial,
            max_agents=500, max_end_users=1000, max_admin_seats=50, max_orgs=1,
            expires_at=_now() + timedelta(days=expires_offset_days),
        )
        signer = PemSigner(role=Role.LICENCE, private_key=licence_key, leaf_cert=leaf_cert)
        wire = sign_licence_v5(payload, signer, leaf_cert, leaf_cert_sig)
        return wire

    def test_valid_licence_passes(self):
        master = _gen_p384_key()
        anchor_set = _make_anchor_set(master)
        wire = self._issue(master)
        result = verify_licence_v5(wire, anchor_set, KillList.empty())
        self.assertTrue(result.valid)
        self.assertIsNone(result.error)
        self.assertEqual(result.payload["tier"], "professional")

    def test_untrusted_anchor_fails(self):
        master = _gen_p384_key()
        rogue = _gen_p384_key()
        anchor_set = _make_anchor_set(master)  # trusts `master`, not `rogue`
        wire = self._issue(rogue)
        result = verify_licence_v5(wire, anchor_set, KillList.empty())
        self.assertFalse(result.valid)
        self.assertEqual(result.error, "leaf_cert_untrusted")

    def test_retired_anchor_fails(self):
        master = _gen_p384_key()
        anchor_set = _make_anchor_set(master, status=AnchorStatus.RETIRED)
        wire = self._issue(master)
        result = verify_licence_v5(wire, anchor_set, KillList.empty())
        self.assertFalse(result.valid)
        self.assertEqual(result.error, "leaf_cert_untrusted")

    def test_retiring_anchor_still_passes(self):
        master = _gen_p384_key()
        anchor_set = _make_anchor_set(master, status=AnchorStatus.RETIRING)
        wire = self._issue(master)
        result = verify_licence_v5(wire, anchor_set, KillList.empty())
        self.assertTrue(result.valid)

    def test_cross_client_forgery_fails(self):
        """Laura R3-F1: a leaf certified for client A cannot mint a licence
        payload claiming client B, even though the signature is otherwise
        cryptographically valid (leaf signs its OWN mis-claimed payload)."""
        master = _gen_p384_key()
        anchor_set = _make_anchor_set(master)
        licence_key = _gen_p384_key()
        leaf_cert, leaf_cert_sig = _make_leaf_cert(master, client_id="acme-corp", _pubkey=_pem(licence_key))
        payload = build_licence_payload_v5(
            org_domain="victim.example.com", tier="enterprise", client_id="victim-corp",
            licence_serial="lic-forged", max_agents=-1, max_end_users=-1, max_admin_seats=-1,
            max_orgs=-1, expires_at=_now() + timedelta(days=365),
        )
        signer = PemSigner(role=Role.LICENCE, private_key=licence_key, leaf_cert=leaf_cert)
        wire = sign_licence_v5(payload, signer, leaf_cert, leaf_cert_sig)

        result = verify_licence_v5(wire, anchor_set, KillList.empty())
        self.assertFalse(result.valid)
        self.assertEqual(result.error, "client_id_mismatch")

    def test_wrong_role_leaf_rejected(self):
        master = _gen_p384_key()
        anchor_set = _make_anchor_set(master)
        code_key = _gen_p384_key()
        code_leaf, code_leaf_sig = _make_leaf_cert(
            master, role=Role.CODE, client_id=SHARED_CLIENT_ID, release="4.1.1", _pubkey=_pem(code_key)
        )
        payload = build_licence_payload_v5(
            org_domain="*", tier="community", client_id=SHARED_CLIENT_ID, licence_serial="x",
            max_agents=20, max_end_users=5, max_admin_seats=2, max_orgs=1,
            expires_at=_now() + timedelta(days=1),
        )
        # Manually assemble a wire with a code-role leaf (sign_licence_v5
        # itself refuses this — exercise the parse/verify-side rejection).
        from yashigani.licensing.chain.canonical import canonical, licence_payload_signing_digest
        from yashigani.licensing.chain.licence_v5 import base64url_encode

        payload_bytes = canonical(payload).encode("utf-8")
        digest = licence_payload_signing_digest(payload_bytes, code_leaf.to_canonical_dict())
        leaf_sig = sign_message(Alg.ECDSA_P384_SHA384, code_key, digest)
        wire = ".".join([
            base64url_encode(payload_bytes),
            base64url_encode(leaf_sig),
            base64url_encode(canonical(code_leaf.to_canonical_dict()).encode("utf-8")),
            base64url_encode(code_leaf_sig),
        ])

        result = verify_licence_v5(wire, anchor_set, KillList.empty())
        self.assertFalse(result.valid)
        self.assertEqual(result.error, "wrong_leaf_role")

    def test_expired_licence_fails_on_own_term(self):
        master = _gen_p384_key()
        anchor_set = _make_anchor_set(master)
        wire = self._issue(master, expires_offset_days=-1)
        result = verify_licence_v5(wire, anchor_set, KillList.empty())
        self.assertFalse(result.valid)
        self.assertEqual(result.error, "license_expired")

    def test_leaf_window_never_checked_at_verify_time(self):
        """§2: leaf_cert not_before/not_after is SIGNING-SIDE ONLY. A licence
        signed under a leaf whose window has already elapsed (per wall
        clock) must still verify — only the licence's OWN expires_at
        matters."""
        master = _gen_p384_key()
        anchor_set = _make_anchor_set(master)
        licence_key = _gen_p384_key()
        now = _now()
        # Leaf window elapsed (not_after in the past).
        leaf_cert = LeafCert(
            role=Role.LICENCE, client_id="acme-corp", leaf_pubkey_pem=_pem(licence_key),
            not_before=now - timedelta(days=100), not_after=now - timedelta(days=1),
            serial="leaf-expired-window", signed_at=now - timedelta(days=100), alg=Alg.ECDSA_P384_SHA384,
        )
        leaf_cert_sig = sign_message(Alg.ECDSA_P384_SHA384, master, leaf_cert_signing_digest(leaf_cert.to_canonical_dict()))
        payload = build_licence_payload_v5(
            org_domain="acme.example.com", tier="professional", client_id="acme-corp",
            licence_serial="lic-0001", max_agents=500, max_end_users=1000, max_admin_seats=50,
            max_orgs=1, expires_at=now + timedelta(days=365),  # licence's OWN term is still valid
        )
        signer = PemSigner(role=Role.LICENCE, private_key=licence_key, leaf_cert=leaf_cert)
        wire = sign_licence_v5(payload, signer, leaf_cert, leaf_cert_sig)

        result = verify_licence_v5(wire, anchor_set, KillList.empty())
        self.assertTrue(result.valid, f"expected valid despite elapsed leaf window; error={result.error}")

    def test_kill_list_leaf_namespace_revokes(self):
        master = _gen_p384_key()
        anchor_set = _make_anchor_set(master)
        wire = self._issue(master, serial="leaf-to-revoke")
        kill_list = KillList([KillListEntry(namespace="leaf", identifier="leaf-to-revoke", revoked_at=_now())])
        result = verify_licence_v5(wire, anchor_set, kill_list)
        self.assertFalse(result.valid)
        self.assertEqual(result.error, "leaf_revoked")

    def test_kill_list_licence_namespace_revokes(self):
        master = _gen_p384_key()
        anchor_set = _make_anchor_set(master)
        wire = self._issue(master, licence_serial="lic-to-revoke")
        kill_list = KillList([KillListEntry(namespace="licence", identifier="lic-to-revoke", revoked_at=_now())])
        result = verify_licence_v5(wire, anchor_set, kill_list)
        self.assertFalse(result.valid)
        self.assertEqual(result.error, "licence_revoked")

    def test_kill_list_client_namespace_revokes_only_that_client(self):
        master = _gen_p384_key()
        anchor_set = _make_anchor_set(master)
        bad_wire = self._issue(master, client_id="bad-corp")
        good_wire = self._issue(master, client_id="good-corp")
        kill_list = KillList([KillListEntry(namespace="client", identifier="bad-corp", revoked_at=_now())])

        bad_result = verify_licence_v5(bad_wire, anchor_set, kill_list)
        self.assertFalse(bad_result.valid)
        self.assertEqual(bad_result.error, "client_revoked")

        good_result = verify_licence_v5(good_wire, anchor_set, kill_list)
        self.assertTrue(good_result.valid)

    def test_kill_list_master_anchor_namespace_revokes(self):
        master = _gen_p384_key()
        anchor_set = _make_anchor_set(master, anchor_id="M1")
        wire = self._issue(master)
        kill_list = KillList([KillListEntry(namespace="master-anchor", identifier="M1", revoked_at=_now())])
        result = verify_licence_v5(wire, anchor_set, kill_list)
        self.assertFalse(result.valid)
        self.assertEqual(result.error, "master_anchor_revoked")

    def test_client_domain_registry_mismatch_rejected_when_populated(self):
        master = _gen_p384_key()
        anchor_set = _make_anchor_set(master)
        wire = self._issue(master, client_id="acme-corp", org_domain="acme.example.com")
        registry = {"acme-corp": "different-domain.example.com"}
        result = verify_licence_v5(wire, anchor_set, KillList.empty(), client_domain_registry=registry)
        self.assertFalse(result.valid)
        self.assertEqual(result.error, "org_domain_registry_mismatch")

    def test_client_domain_registry_match_accepted(self):
        master = _gen_p384_key()
        anchor_set = _make_anchor_set(master)
        wire = self._issue(master, client_id="acme-corp", org_domain="acme.example.com")
        registry = {"acme-corp": "acme.example.com"}
        result = verify_licence_v5(wire, anchor_set, KillList.empty(), client_domain_registry=registry)
        self.assertTrue(result.valid)

    def test_client_domain_registry_no_entry_degrades_gracefully(self):
        """SEAM: when the registry has no entry for this client, the binding
        is skipped (WARNING), not fail-closed — the registry is not yet
        populated by any build-tooling in Phase B-CORE."""
        master = _gen_p384_key()
        anchor_set = _make_anchor_set(master)
        wire = self._issue(master, client_id="acme-corp", org_domain="acme.example.com")
        result = verify_licence_v5(wire, anchor_set, KillList.empty(), client_domain_registry={})
        self.assertTrue(result.valid)

    def test_malformed_content_never_raises(self):
        master = _gen_p384_key()
        anchor_set = _make_anchor_set(master)
        for content in ("", "a.b.c.d", "not.valid.base64!.@@@@", "a" * 10000):
            result = verify_licence_v5(content, anchor_set, KillList.empty())
            self.assertFalse(result.valid)


# ---------------------------------------------------------------------------
# kill_list.py
# ---------------------------------------------------------------------------

class TestKillList(unittest.TestCase):
    def test_empty_kill_list_revokes_nothing(self):
        kl = KillList.empty()
        self.assertFalse(kl.is_revoked_immediate("leaf", "any-serial"))
        self.assertEqual(len(kl), 0)

    def test_immediate_namespace_match(self):
        kl = KillList([KillListEntry(namespace="leaf", identifier="X", revoked_at=_now())])
        self.assertTrue(kl.is_revoked_immediate("leaf", "X"))
        self.assertFalse(kl.is_revoked_immediate("leaf", "Y"))
        self.assertFalse(kl.is_revoked_immediate("licence", "X"))  # wrong namespace

    def test_forward_only_not_matched_by_immediate_lookup(self):
        """A FORWARD_ONLY entry must never be treated as revoked via the
        IMMEDIATE lookup — the two semantics are namespace-shape-identical
        (both use client:<id>) but must never cross-contaminate (§6.1)."""
        kl = KillList([KillListEntry(
            namespace="client", identifier="acme-corp", revoked_at=_now(),
            semantics=KillListSemantics.FORWARD_ONLY,
        )])
        self.assertFalse(kl.is_revoked_immediate("client", "acme-corp"))

    def test_forward_only_lookup_respects_revoked_at(self):
        revoked_at = _now()
        kl = KillList([KillListEntry(
            namespace="client", identifier="acme-corp", revoked_at=revoked_at,
            semantics=KillListSemantics.FORWARD_ONLY,
        )])
        before = revoked_at - timedelta(days=1)
        after = revoked_at + timedelta(days=1)
        self.assertFalse(kl.is_revoked_forward_only("client", "acme-corp", before))
        self.assertTrue(kl.is_revoked_forward_only("client", "acme-corp", after))

    def test_canonical_round_trip(self):
        entries = [
            KillListEntry(namespace="leaf", identifier="L1", revoked_at=_now(), reason="leaked"),
            KillListEntry(
                namespace="client", identifier="C1", revoked_at=_now(),
                semantics=KillListSemantics.FORWARD_ONLY,
            ),
        ]
        kl = KillList(entries)
        raw = kl.to_canonical_list()
        restored = KillList.from_canonical_list(raw)
        self.assertEqual(len(restored), 2)
        self.assertTrue(restored.is_revoked_immediate("leaf", "L1"))

    def test_entry_requires_timezone_aware_revoked_at(self):
        with self.assertRaises(ValueError):
            KillListEntry(namespace="leaf", identifier="L1", revoked_at=datetime(2026, 1, 1))


# ---------------------------------------------------------------------------
# build_integrity.py (§4a)
# ---------------------------------------------------------------------------

class TestBuildIntegrityChain(unittest.TestCase):
    def _make_code_leaf(self, master_key, release="4.1.1"):
        code_key = _gen_p384_key()
        cert, sig = _make_leaf_cert(
            master_key, role=Role.CODE, client_id=SHARED_CLIENT_ID, release=release,
            serial=f"code-leaf-{release}", _pubkey=_pem(code_key),
        )
        return cert, sig, code_key

    def test_valid_chain_passes(self):
        master = _gen_p384_key()
        anchor_set = _make_anchor_set(master)
        code_leaf, code_leaf_sig, code_key = self._make_code_leaf(master)
        bundle_str = "VERIFIER_HASH=abc\nENFORCER_HASH=def"
        bundle_sig = sign_message(Alg.ECDSA_P384_SHA384, code_key, bundle_signing_digest(bundle_str))

        result = verify_build_integrity_chain(
            anchor_set, code_leaf, code_leaf_sig, bundle_str, bundle_sig, KillList.empty()
        )
        self.assertTrue(result.valid)

    def test_tampered_bundle_sig_fails(self):
        master = _gen_p384_key()
        anchor_set = _make_anchor_set(master)
        code_leaf, code_leaf_sig, code_key = self._make_code_leaf(master)
        bundle_str = "VERIFIER_HASH=abc"
        bundle_sig = sign_message(Alg.ECDSA_P384_SHA384, code_key, bundle_signing_digest(bundle_str))

        bad_sig = bytes([bundle_sig[0] ^ 0xFF]) + bundle_sig[1:]
        result = verify_build_integrity_chain(
            anchor_set, code_leaf, code_leaf_sig, bundle_str, bad_sig, KillList.empty()
        )
        self.assertFalse(result.valid)
        self.assertEqual(result.error, "invalid_bundle_sig")

    def test_untrusted_leaf_cert_fails(self):
        master = _gen_p384_key()
        rogue = _gen_p384_key()
        anchor_set = _make_anchor_set(master)  # trusts `master` only
        code_leaf, code_leaf_sig, code_key = self._make_code_leaf(rogue)  # certified by rogue
        bundle_str = "X=1"
        bundle_sig = sign_message(Alg.ECDSA_P384_SHA384, code_key, bundle_signing_digest(bundle_str))

        result = verify_build_integrity_chain(
            anchor_set, code_leaf, code_leaf_sig, bundle_str, bundle_sig, KillList.empty()
        )
        self.assertFalse(result.valid)
        self.assertEqual(result.error, "leaf_cert_untrusted")

    def test_wrong_role_leaf_rejected(self):
        master = _gen_p384_key()
        anchor_set = _make_anchor_set(master)
        licence_key = _gen_p384_key()
        licence_leaf, licence_leaf_sig = _make_leaf_cert(master, role=Role.LICENCE, _pubkey=_pem(licence_key))
        bundle_str = "X=1"
        bundle_sig = sign_message(Alg.ECDSA_P384_SHA384, licence_key, bundle_signing_digest(bundle_str))

        result = verify_build_integrity_chain(
            anchor_set, licence_leaf, licence_leaf_sig, bundle_str, bundle_sig, KillList.empty()
        )
        self.assertFalse(result.valid)
        self.assertEqual(result.error, "wrong_leaf_role")

    def test_kill_listed_code_leaf_fails(self):
        master = _gen_p384_key()
        anchor_set = _make_anchor_set(master)
        code_leaf, code_leaf_sig, code_key = self._make_code_leaf(master)
        bundle_str = "X=1"
        bundle_sig = sign_message(Alg.ECDSA_P384_SHA384, code_key, bundle_signing_digest(bundle_str))
        kill_list = KillList([KillListEntry(namespace="leaf", identifier=code_leaf.serial, revoked_at=_now())])

        result = verify_build_integrity_chain(
            anchor_set, code_leaf, code_leaf_sig, bundle_str, bundle_sig, kill_list
        )
        self.assertFalse(result.valid)
        self.assertEqual(result.error, "leaf_revoked")

    def test_kill_listed_master_anchor_fails(self):
        master = _gen_p384_key()
        anchor_set = _make_anchor_set(master, anchor_id="M1")
        code_leaf, code_leaf_sig, code_key = self._make_code_leaf(master)
        bundle_str = "X=1"
        bundle_sig = sign_message(Alg.ECDSA_P384_SHA384, code_key, bundle_signing_digest(bundle_str))
        kill_list = KillList([KillListEntry(namespace="master-anchor", identifier="M1", revoked_at=_now())])

        result = verify_build_integrity_chain(
            anchor_set, code_leaf, code_leaf_sig, bundle_str, bundle_sig, kill_list
        )
        self.assertFalse(result.valid)
        self.assertEqual(result.error, "master_anchor_revoked")

    def test_upgrade_preserves_build_trust(self):
        """The property behind the whole v2 redesign (design §0): a NEW
        release's code leaf, certified by the SAME master anchor as an
        earlier release, must ALSO validate — because trust is chain-to-
        master, not a per-release fixed key."""
        master = _gen_p384_key()
        anchor_set = _make_anchor_set(master)

        leaf_413, sig_413, key_413 = self._make_code_leaf(master, release="4.1.3")
        bundle_413 = "VERIFIER_HASH=v413"
        bundle_sig_413 = sign_message(Alg.ECDSA_P384_SHA384, key_413, bundle_signing_digest(bundle_413))
        result_413 = verify_build_integrity_chain(anchor_set, leaf_413, sig_413, bundle_413, bundle_sig_413, KillList.empty())
        self.assertTrue(result_413.valid)

        leaf_414, sig_414, key_414 = self._make_code_leaf(master, release="4.1.4")
        bundle_414 = "VERIFIER_HASH=v414"
        bundle_sig_414 = sign_message(Alg.ECDSA_P384_SHA384, key_414, bundle_signing_digest(bundle_414))
        result_414 = verify_build_integrity_chain(anchor_set, leaf_414, sig_414, bundle_414, bundle_sig_414, KillList.empty())
        self.assertTrue(result_414.valid)

        # Same anchor set validated BOTH releases — this is the fix for the
        # v4 bug where a per-release counter key broke licences on upgrade.
        self.assertEqual(len(anchor_set.all_anchors()), 1)


class TestBuildIntegrityJsonHelpers(unittest.TestCase):
    def test_anchor_set_json_round_trip(self):
        master = _gen_p384_key()
        anchor_set = _make_anchor_set(master, anchor_id="M1")
        raw = json.dumps([{
            "anchor_id": a.anchor_id, "pubkey_pem": a.pubkey_pem, "alg": a.alg.value,
            "status": a.status.value, "added": a.added.isoformat(),
        } for a in anchor_set.all_anchors()])
        restored = anchor_set_from_json(raw)
        self.assertEqual(len(restored), 1)
        self.assertEqual(restored.get("M1").pubkey_pem, _pem(master))

    def test_leaf_cert_json_round_trip(self):
        master = _gen_p384_key()
        code_leaf, _ = _make_leaf_cert(master, role=Role.CODE, client_id=SHARED_CLIENT_ID, release="4.1.1")
        raw = json.dumps(code_leaf.to_canonical_dict())
        restored = leaf_cert_from_json(raw)
        self.assertEqual(restored.role, Role.CODE)
        self.assertEqual(restored.release, "4.1.1")

    def test_kill_list_json_defaults_to_empty(self):
        kl = kill_list_from_json("")
        self.assertEqual(len(kl), 0)
        kl2 = kill_list_from_json("[]")
        self.assertEqual(len(kl2), 0)

    def test_kill_list_json_round_trip(self):
        raw = json.dumps([{
            "namespace": "leaf", "identifier": "X", "revoked_at": _now().isoformat(),
            "semantics": "immediate", "reason": None,
        }])
        kl = kill_list_from_json(raw)
        self.assertTrue(kl.is_revoked_immediate("leaf", "X"))


if __name__ == "__main__":
    unittest.main()
