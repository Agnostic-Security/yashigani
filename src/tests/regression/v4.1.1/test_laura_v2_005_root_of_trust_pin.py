"""
Regression tests — LAURA-V2-005 (CRITICAL, 2026-07-17): "full offline forge
of the licence chain-of-trust via _integrity.py alone — zero of the 7
'full-mesh' files need editing."

Ref: testing_runs/yashigani/licence-v2-redteam-mesh-final-20260717T000000Z.md
     testing_runs/yashigani/licence-v2-redteam-mesh-final-20260717T000000Z/
     scratch/poc_forge_root_of_trust.py
     Agnostic Security/Operations/Compliance/yashigani/v4.1.1/laura-pentest/
     findings/LAURA-V2-005_data_source_root_of_trust_self_forge.md

Root cause: MASTER_ANCHOR_SET_JSON, CODE_LEAF_CERT_JSON/SIG and BUNDLE_SIG
are all plain constants stored inside _integrity.py — the same
attacker-writable file that also holds the per-module *_HASH constants.
Nothing in verify_build_integrity_chain()/AnchorSet.validate_leaf_cert()/
verify_licence_v5() compared the embedded master anchor set against any
value living OUTSIDE _integrity.py. An attacker with local write access
could therefore mint their OWN master keypair, self-certify a CODE leaf
under it, recompute INTEGRITY_HASH/BUNDLE_SIG (both trivially
self-consistent, since they hold the private keys they signed with), and
self-issue an ENTERPRISE licence — touching ZERO bytes of any of the 7 mesh
files (verifier.py/enforcer.py/gate_middleware.py/sso/oidc.py/sso/saml.py/
backoffice/routes/{sso,scim}.py).

Fix (this file's regressions):
  1. verifier.py hardcodes the REAL master anchor pubkey(s)
     (_PINNED_MASTER_ANCHOR_PEMS) and _anchor_set_is_pinned() requires
     EVERY currently-trusted anchor in the embedded MASTER_ANCHOR_SET_JSON
     to re-encode to one of them (by DER bytes). Wired into
     _check_build_integrity_chain(): a forged root now fails BEFORE the
     leaf-chains-to-anchor / bundle_sig checks even run.
  2. Each of the 7 mesh files ALSO carries its own hardcoded expected hash
     of _integrity.py's root-of-trust fields (see
     test_laura_v2_003_mesh_hardening.py::TestLauraV2005* for that half —
     these tests focus specifically on the pin/ratification mechanism in
     verifier.py, since that is the piece that makes forging
     CRYPTOGRAPHICALLY impossible, not merely byte-comparison-detectable).

These tests replicate Laura's exact PoC pattern (forge master + code leaf +
bundle_sig, all internally self-consistent) against the FIXED
verifier._check_build_integrity_chain() and prove it is now REJECTED, while
a GENUINE build against the pinned master still validates.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import yashigani.licensing._integrity as integrity_mod
import yashigani.licensing.verifier as verifier_mod
from yashigani.licensing.chain.algorithms import Alg, sign_message
from yashigani.licensing.chain.canonical import bundle_signing_digest, leaf_cert_signing_digest
from yashigani.licensing.chain.leaf_cert import LeafCert, Role


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _gen_p384() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP384R1())


def _pem_pub(key) -> str:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def _anchor_set_json(master_key, anchor_id: str = "M1", status: str = "active") -> str:
    return json.dumps([{
        "anchor_id": anchor_id, "pubkey_pem": _pem_pub(master_key),
        "alg": Alg.ECDSA_P384_SHA384.value, "status": status, "added": _now().isoformat(),
    }])


def _make_code_leaf(master_key, release: str = "4.1.1-test"):
    code_key = _gen_p384()
    now = _now()
    leaf = LeafCert(
        role=Role.CODE, client_id="*", release=release, leaf_pubkey_pem=_pem_pub(code_key),
        not_before=now - timedelta(days=1), not_after=now + timedelta(days=60),
        serial=f"code-leaf-{release}", signed_at=now, alg=Alg.ECDSA_P384_SHA384,
    )
    sig = sign_message(Alg.ECDSA_P384_SHA384, master_key, leaf_cert_signing_digest(leaf.to_canonical_dict()))
    return leaf, sig, code_key


# ---------------------------------------------------------------------------
# Direct unit tests of the pin primitives
# ---------------------------------------------------------------------------

class TestPubkeyPemToDer:
    def test_pinned_demo_key_parses(self):
        """The literal PEM hardcoded in verifier.py must itself be
        well-formed and parse to non-empty DER — a build-time sanity
        invariant (a malformed pin would fail EVERY build closed, which is
        safe but should be caught here, not first discovered in prod)."""
        for pem in verifier_mod._PINNED_MASTER_ANCHOR_PEMS:
            der = verifier_mod._pubkey_pem_to_der(pem)
            assert der is not None
            assert len(der) > 0

    def test_two_pems_of_the_same_key_normalize_identically(self):
        """Robust to whitespace/line-ending variance — re-serializing a PEM
        (same key, re-wrapped) must produce IDENTICAL DER bytes."""
        key = _gen_p384()
        pem_a = _pem_pub(key)
        # Re-load and re-serialize — simulates a PEM that differs only in
        # trailing-whitespace/wrap-width, not key material.
        loaded = serialization.load_pem_public_key(pem_a.encode("utf-8"))
        pem_b = loaded.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8").replace("\n", "\r\n")  # different line endings

        der_a = verifier_mod._pubkey_pem_to_der(pem_a)
        der_b = verifier_mod._pubkey_pem_to_der(pem_b)
        assert der_a is not None and der_b is not None
        assert der_a == der_b

    def test_different_keys_normalize_differently(self):
        der_a = verifier_mod._pubkey_pem_to_der(_pem_pub(_gen_p384()))
        der_b = verifier_mod._pubkey_pem_to_der(_pem_pub(_gen_p384()))
        assert der_a != der_b

    def test_malformed_pem_returns_none_not_raise(self):
        assert verifier_mod._pubkey_pem_to_der("not a pem at all") is None
        assert verifier_mod._pubkey_pem_to_der("") is None


class TestAnchorSetIsPinned:
    def test_pinned_key_passes(self, monkeypatch):
        from yashigani.licensing.chain.anchors import AnchorSet
        from yashigani.licensing.chain import anchor_set_from_json

        pin_key = _gen_p384()
        monkeypatch.setattr(verifier_mod, "_PINNED_MASTER_ANCHOR_PEMS", (_pem_pub(pin_key),))
        anchor_set: AnchorSet = anchor_set_from_json(_anchor_set_json(pin_key))
        assert verifier_mod._anchor_set_is_pinned(anchor_set) is True

    def test_foreign_key_fails(self, monkeypatch):
        """LAURA-V2-005's exact shape: the embedded anchor set is internally
        well-formed and self-consistent — it simply does not chain to the
        pin."""
        from yashigani.licensing.chain import anchor_set_from_json

        pin_key = _gen_p384()
        attacker_key = _gen_p384()
        monkeypatch.setattr(verifier_mod, "_PINNED_MASTER_ANCHOR_PEMS", (_pem_pub(pin_key),))
        anchor_set = anchor_set_from_json(_anchor_set_json(attacker_key, anchor_id="attacker-forged-master-1"))
        assert verifier_mod._anchor_set_is_pinned(anchor_set) is False

    def test_mixed_set_one_pinned_one_foreign_fails(self, monkeypatch):
        """The narrower 'add a second anchor alongside the real one' variant
        — checking the WHOLE trusted set (not just whichever anchor
        happened to validate the code leaf) must reject this too."""
        from yashigani.licensing.chain import anchor_set_from_json

        pin_key = _gen_p384()
        attacker_key = _gen_p384()
        monkeypatch.setattr(verifier_mod, "_PINNED_MASTER_ANCHOR_PEMS", (_pem_pub(pin_key),))
        mixed = json.dumps([
            {"anchor_id": "M1", "pubkey_pem": _pem_pub(pin_key),
             "alg": Alg.ECDSA_P384_SHA384.value, "status": "active", "added": _now().isoformat()},
            {"anchor_id": "attacker-added", "pubkey_pem": _pem_pub(attacker_key),
             "alg": Alg.ECDSA_P384_SHA384.value, "status": "active", "added": _now().isoformat()},
        ])
        anchor_set = anchor_set_from_json(mixed)
        assert verifier_mod._anchor_set_is_pinned(anchor_set) is False

    def test_retired_foreign_anchor_ignored_not_a_bypass(self, monkeypatch):
        """A RETIRED (not trusted_anchors()) foreign anchor sitting in the
        set alongside a pinned active one must NOT cause a false positive —
        only ACTIVE/RETIRING anchors are evaluated, matching AnchorSet's own
        trust semantics."""
        from yashigani.licensing.chain import anchor_set_from_json

        pin_key = _gen_p384()
        retired_foreign_key = _gen_p384()
        monkeypatch.setattr(verifier_mod, "_PINNED_MASTER_ANCHOR_PEMS", (_pem_pub(pin_key),))
        mixed = json.dumps([
            {"anchor_id": "M1", "pubkey_pem": _pem_pub(pin_key),
             "alg": Alg.ECDSA_P384_SHA384.value, "status": "active", "added": _now().isoformat()},
            {"anchor_id": "old-retired", "pubkey_pem": _pem_pub(retired_foreign_key),
             "alg": Alg.ECDSA_P384_SHA384.value, "status": "retired", "added": _now().isoformat()},
        ])
        anchor_set = anchor_set_from_json(mixed)
        assert verifier_mod._anchor_set_is_pinned(anchor_set) is True

    def test_empty_pin_set_fails_closed(self, monkeypatch):
        """A misconfigured/empty pin must never vacuously 'trust
        everything' — fail closed."""
        from yashigani.licensing.chain import anchor_set_from_json

        monkeypatch.setattr(verifier_mod, "_PINNED_MASTER_ANCHOR_PEMS", ())
        anchor_set = anchor_set_from_json(_anchor_set_json(_gen_p384()))
        assert verifier_mod._anchor_set_is_pinned(anchor_set) is False


# ---------------------------------------------------------------------------
# Full Laura PoC reproduction against _check_build_integrity_chain()
# ---------------------------------------------------------------------------

class TestLauraV2005ExactPoCRejected:
    """Reproduces poc_forge_root_of_trust.py's exact attack shape: mint an
    attacker master + code leaf, recompute INTEGRITY_HASH/BUNDLE_SIG
    live/correctly (no crypto shortcuts — the forgery is otherwise
    flawless), embed into _integrity.py. Must now be REJECTED."""

    def _forge_and_embed(self, monkeypatch, pinned_key) -> None:
        """Embeds a fully self-consistent FORGED chain — everything an
        attacker holding no real private key CAN produce. `pinned_key` is
        the key the test's pin is set to (may or may not be the forging
        key, per test)."""
        monkeypatch.setattr(verifier_mod, "_PINNED_MASTER_ANCHOR_PEMS", (_pem_pub(pinned_key),))

        attacker_master = _gen_p384()
        code_leaf, code_leaf_sig, code_key = _make_code_leaf(attacker_master)

        monkeypatch.setattr(integrity_mod, "MASTER_ANCHOR_SET_JSON", _anchor_set_json(attacker_master, anchor_id="attacker-forged-master-1"))
        monkeypatch.setattr(integrity_mod, "CODE_LEAF_CERT_JSON", json.dumps(code_leaf.to_canonical_dict()))
        monkeypatch.setattr(integrity_mod, "CODE_LEAF_CERT_SIG", base64.b64encode(code_leaf_sig).decode())
        monkeypatch.setattr(integrity_mod, "KILL_LIST_JSON", "[]")
        monkeypatch.setattr(integrity_mod, "CLIENT_DOMAIN_REGISTRY_JSON", "{}")

        # Non-placeholder, arbitrary T1-T4/POU hashes — is_any_hash_placeholder()
        # must be False to reach the pin check (this test is about the pin,
        # not the hash-bundle path).
        for name in (
            "VERIFIER_HASH", "ENFORCER_HASH", "LOADER_HASH",
            "AGENTS_REGISTRY_HASH", "IDENTITY_REGISTRY_HASH",
            "OIDC_MODULE_HASH", "SAML_MODULE_HASH", "SSO_ROUTES_HASH",
            "SCIM_ROUTES_HASH", "GATE_MIDDLEWARE_HASH",
        ):
            monkeypatch.setattr(integrity_mod, name, "a" * 64)
        monkeypatch.setattr(integrity_mod, "INTEGRITY_HASH", "b" * 64)

        # BUNDLE_SIG — signed with the ATTACKER's code leaf private key,
        # exactly as Laura's PoC does (self-consistent, no shortcuts).
        bundle_str = verifier_mod._build_hash_bundle_str()
        bundle_sig = sign_message(Alg.ECDSA_P384_SHA384, code_key, bundle_signing_digest(bundle_str))
        monkeypatch.setattr(integrity_mod, "BUNDLE_SIG", base64.b64encode(bundle_sig).decode())

        monkeypatch.setattr(verifier_mod, "_integrity_violated", False)

    def test_forged_root_rejected_when_pin_is_the_real_key(self, monkeypatch):
        """The exact LAURA-V2-005 scenario: pin is set to a DIFFERENT
        (real) key than the one the attacker forged — must be rejected."""
        real_key = _gen_p384()  # stands in for the real production/demo master
        self._forge_and_embed(monkeypatch, pinned_key=real_key)

        verifier_mod._check_build_integrity_chain()

        assert verifier_mod._integrity_violated is True

    def test_genuine_build_against_the_pinned_key_still_validates(self, monkeypatch):
        """Control: the SAME code path, but the anchor set genuinely chains
        to the pinned key (no forgery) — must NOT be flagged by the pin
        check (any OTHER failure, e.g. unrelated hash mismatch, is a
        separate concern not exercised here)."""
        real_key = _gen_p384()
        monkeypatch.setattr(verifier_mod, "_PINNED_MASTER_ANCHOR_PEMS", (_pem_pub(real_key),))

        code_leaf, code_leaf_sig, code_key = _make_code_leaf(real_key)
        monkeypatch.setattr(integrity_mod, "MASTER_ANCHOR_SET_JSON", _anchor_set_json(real_key))
        monkeypatch.setattr(integrity_mod, "CODE_LEAF_CERT_JSON", json.dumps(code_leaf.to_canonical_dict()))
        monkeypatch.setattr(integrity_mod, "CODE_LEAF_CERT_SIG", base64.b64encode(code_leaf_sig).decode())
        monkeypatch.setattr(integrity_mod, "KILL_LIST_JSON", "[]")
        monkeypatch.setattr(integrity_mod, "CLIENT_DOMAIN_REGISTRY_JSON", "{}")

        # Pin ratification is evaluated independent of, and BEFORE, the
        # live-hash-bundle re-derivation — assert it directly rather than
        # relying on the full chain (which needs real on-disk file hashes
        # to also succeed; that path is covered by
        # test_laura_v2_001_002_external_authority.py).
        from yashigani.licensing.chain import anchor_set_from_json
        anchor_set = anchor_set_from_json(integrity_mod.MASTER_ANCHOR_SET_JSON)
        assert verifier_mod._anchor_set_is_pinned(anchor_set) is True

    def test_v2_004_forging_against_real_master_still_impossible(self, monkeypatch):
        """V2-004 regression: without the pinned key's PRIVATE key, an
        attacker cannot produce a valid leaf_cert_sig for ANY anchor_id
        claiming to be the pinned key — signature verification (not just
        the pin's DER-equality check) must still fail if they merely COPY
        the pinned key's PEM into their forged anchor entry without holding
        its private key (i.e. they cannot self-sign a leaf under an anchor
        whose pubkey matches the pin, because they don't hold the matching
        private key)."""
        real_key = _gen_p384()
        attacker_key_pretending_to_be_pinned = _gen_p384()  # attacker's OWN key
        monkeypatch.setattr(verifier_mod, "_PINNED_MASTER_ANCHOR_PEMS", (_pem_pub(real_key),))

        # Attacker claims the PINNED key's PEM in the anchor entry (passes
        # the pin's DER check) but SIGNS the leaf with their OWN private
        # key (the only key they hold) — the leaf_cert_sig must fail to
        # verify against the claimed (pinned) pubkey.
        code_leaf, _real_sig, code_key = _make_code_leaf(real_key)
        forged_sig = sign_message(
            Alg.ECDSA_P384_SHA384, attacker_key_pretending_to_be_pinned,
            leaf_cert_signing_digest(code_leaf.to_canonical_dict()),
        )
        anchor_set_json = _anchor_set_json(real_key)  # pubkey_pem = the REAL pinned key
        from yashigani.licensing.chain import anchor_set_from_json
        anchor_set = anchor_set_from_json(anchor_set_json)

        # Pin check passes (the CLAIMED pubkey matches the pin)...
        assert verifier_mod._anchor_set_is_pinned(anchor_set) is True
        # ...but the signature itself does not chain, because it was never
        # actually produced by the pinned key's private half.
        matched = anchor_set.validate_leaf_cert(code_leaf, forged_sig)
        assert matched is None


class TestLauraV2005PlaceholderAndDevBehaviour:
    def test_pin_check_only_runs_once_chain_constants_are_non_placeholder(self, monkeypatch):
        """Chain constants left at their default placeholder state must
        still fail closed in prod via the EXISTING is_any_chain_placeholder()
        gate — the pin check is reached only after that gate passes, so it
        must not itself crash or double-fire on placeholder input."""
        monkeypatch.delenv("YASHIGANI_ENV", raising=False)
        monkeypatch.setattr(verifier_mod, "_integrity_violated", False)
        # Leave every chain constant at its pristine placeholder default.
        verifier_mod._check_build_integrity_chain()
        assert verifier_mod._integrity_violated is True  # placeholder gate, not the pin
