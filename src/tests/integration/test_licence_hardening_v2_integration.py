"""
Integration tests — Yashigani licence-hardening v2 Phase B-CORE.

Exercises loader.load_license() -> verifier.verify_license() ->
enforcer.set_license()/get_license()/require_feature() end-to-end, plus the
backoffice tamper-banner wiring — no live DB/Redis required (pure Python,
in-process).

Ref: dispatch brief "PHASE B-CORE (verifier + v5 licence)" TESTS section:
    "integration — no-key->Community, valid-key->features unlocked,
     tamper->Community+banner+users-intact, upgrade-preserves-licence (a
     leaf-N-signed licence still verifies on an N+1 build because both
     chain to the same master anchor), downgrade/v4 rejected."

Last updated: 2026-07-14T00:00:00+00:00 (licence-hardening-v2 Phase B-CORE)
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from yashigani.licensing.chain.algorithms import Alg, sign_message
from yashigani.licensing.chain.canonical import bundle_signing_digest, leaf_cert_signing_digest
from yashigani.licensing.chain.leaf_cert import SHARED_CLIENT_ID, LeafCert, Role
from yashigani.licensing.chain.licence_v5 import build_licence_payload_v5, sign_licence_v5
from yashigani.licensing.chain.signer import PemSigner


def _now() -> datetime:
    return datetime.now(timezone.utc)


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


def _anchor_set_json(master_key, anchor_id: str = "M1", status: str = "active") -> str:
    return json.dumps([{
        "anchor_id": anchor_id, "pubkey_pem": _pem_pub(master_key),
        "alg": Alg.ECDSA_P384_SHA384.value, "status": status, "added": _now().isoformat(),
    }])


def _make_code_leaf(master_key, release: str):
    code_key = _gen_p384()
    now = _now()
    leaf = LeafCert(
        role=Role.CODE, client_id=SHARED_CLIENT_ID, release=release, leaf_pubkey_pem=_pem_pub(code_key),
        not_before=now - timedelta(days=1), not_after=now + timedelta(days=60),
        serial=f"code-leaf-{release}", signed_at=now, alg=Alg.ECDSA_P384_SHA384,
    )
    sig = sign_message(Alg.ECDSA_P384_SHA384, master_key, leaf_cert_signing_digest(leaf.to_canonical_dict()))
    return leaf, sig, code_key


def _make_licence_leaf(master_key, client_id: str = "acme-corp", serial: str = "lic-leaf-0001"):
    now = _now()
    licence_key = _gen_p384()
    leaf = LeafCert(
        role=Role.LICENCE, client_id=client_id, leaf_pubkey_pem=_pem_pub(licence_key),
        not_before=now - timedelta(days=1), not_after=now + timedelta(days=60),
        serial=serial, signed_at=now, alg=Alg.ECDSA_P384_SHA384,
    )
    sig = sign_message(Alg.ECDSA_P384_SHA384, master_key, leaf_cert_signing_digest(leaf.to_canonical_dict()))
    return leaf, sig, licence_key


def _sign_licence(payload, leaf_cert, leaf_cert_sig, licence_key) -> str:
    signer = PemSigner(role=Role.LICENCE, private_key=licence_key, leaf_cert=leaf_cert)
    return sign_licence_v5(payload, signer, leaf_cert, leaf_cert_sig)


def _embed_build(monkeypatch, master_key, release: str):
    """Simulate a completed build pipeline run: embed a real anchor set +
    code leaf/leaf_cert_sig/bundle_sig for `release` into _integrity, and
    ensure both verifier and enforcer integrity flags start clean."""
    import yashigani.licensing._integrity as integrity_mod
    import yashigani.licensing.enforcer as enforcer_mod
    import yashigani.licensing.verifier as verifier_mod

    code_leaf, code_leaf_sig, code_key = _make_code_leaf(master_key, release)
    bundle_str = verifier_mod._build_hash_bundle_str()
    bundle_sig = sign_message(Alg.ECDSA_P384_SHA384, code_key, bundle_signing_digest(bundle_str))

    monkeypatch.setattr(integrity_mod, "MASTER_ANCHOR_SET_JSON", _anchor_set_json(master_key))
    monkeypatch.setattr(integrity_mod, "CODE_LEAF_CERT_JSON", json.dumps(code_leaf.to_canonical_dict()))
    monkeypatch.setattr(integrity_mod, "CODE_LEAF_CERT_SIG", base64.b64encode(code_leaf_sig).decode())
    monkeypatch.setattr(integrity_mod, "BUNDLE_SIG", base64.b64encode(bundle_sig).decode())
    monkeypatch.setattr(integrity_mod, "KILL_LIST_JSON", "[]")
    monkeypatch.setattr(integrity_mod, "CLIENT_DOMAIN_REGISTRY_JSON", "{}")

    monkeypatch.setattr(verifier_mod, "_integrity_violated", False)
    monkeypatch.setattr(enforcer_mod, "_enforcer_integrity_violated", False)

    return code_leaf, code_leaf_sig, code_key, bundle_str, bundle_sig


@pytest.fixture(autouse=True)
def _reset_enforcer_state():
    """Every test in this module starts/ends with a clean enforcer license
    state so tests never leak into each other (module-level _license)."""
    from yashigani.licensing.enforcer import set_license
    from yashigani.licensing.model import COMMUNITY_LICENSE
    set_license(COMMUNITY_LICENSE)
    yield
    set_license(COMMUNITY_LICENSE)


class TestNoKeyFallsToCommunity:
    def test_no_license_file_present(self, tmp_path, monkeypatch):
        monkeypatch.setenv("YASHIGANI_LICENSE_FILE", str(tmp_path / "does-not-exist.ysg"))
        monkeypatch.delenv("YASHIGANI_TLS_DOMAIN", raising=False)

        from yashigani.licensing.loader import load_license
        from yashigani.licensing.model import LicenseTier

        result = load_license()
        assert result.tier == LicenseTier.COMMUNITY
        assert result.valid is True

    def test_get_license_defaults_to_community_before_set(self):
        from yashigani.licensing.enforcer import get_license
        from yashigani.licensing.model import LicenseTier

        assert get_license().tier == LicenseTier.COMMUNITY


class TestValidKeyUnlocksFeatures:
    def test_loader_to_enforcer_pipeline_unlocks_oidc(self, tmp_path, monkeypatch):
        master_key = _gen_p384()
        _embed_build(monkeypatch, master_key, "4.1.1")

        leaf_cert, leaf_cert_sig, licence_key = _make_licence_leaf(master_key)
        payload = build_licence_payload_v5(
            org_domain="acme.example.com", tier="professional", client_id="acme-corp",
            licence_serial="lic-0001", max_agents=500, max_end_users=1000, max_admin_seats=50,
            max_orgs=1, features=["oidc", "saml"], expires_at=_now() + timedelta(days=365),
        )
        wire = _sign_licence(payload, leaf_cert, leaf_cert_sig, licence_key)

        lic_path = tmp_path / "license.ysg"
        lic_path.write_text(wire, encoding="utf-8")
        monkeypatch.setenv("YASHIGANI_LICENSE_FILE", str(lic_path))
        monkeypatch.setenv("YASHIGANI_TLS_DOMAIN", "acme.example.com")

        from yashigani.licensing.enforcer import get_license, require_feature, set_license
        from yashigani.licensing.loader import load_license
        from yashigani.licensing.model import LicenseTier

        lic = load_license()
        assert lic.valid is True
        assert lic.tier == LicenseTier.PROFESSIONAL

        set_license(lic)
        assert get_license().tier == LicenseTier.PROFESSIONAL
        # Feature gate unlocked — must not raise.
        require_feature("oidc")
        require_feature("saml")

    def test_community_licence_does_not_unlock_oidc(self):
        from yashigani.licensing.enforcer import LicenseFeatureGated, require_feature

        with pytest.raises(LicenseFeatureGated):
            require_feature("oidc")


class TestTamperForcesCommunityWithBannerUsersIntact:
    def test_tamper_forces_community_tier(self, monkeypatch):
        master_key = _gen_p384()
        _embed_build(monkeypatch, master_key, "4.1.1")

        leaf_cert, leaf_cert_sig, licence_key = _make_licence_leaf(master_key)
        payload = build_licence_payload_v5(
            org_domain="acme.example.com", tier="enterprise", client_id="acme-corp",
            licence_serial="lic-0001", max_agents=-1, max_end_users=-1, max_admin_seats=-1,
            max_orgs=-1, expires_at=_now() + timedelta(days=365),
        )
        wire = _sign_licence(payload, leaf_cert, leaf_cert_sig, licence_key)

        # Simulate a tamper event AFTER a valid build was embedded.
        import yashigani.licensing.verifier as verifier_mod
        monkeypatch.setattr(verifier_mod, "_integrity_violated", True)

        from yashigani.licensing.verifier import verify_license
        from yashigani.licensing.model import LicenseTier

        result = verify_license(wire)
        assert result.tier == LicenseTier.COMMUNITY

    def test_tamper_shows_persistent_banner(self, monkeypatch):
        import yashigani.licensing.verifier as verifier_mod
        monkeypatch.setattr(verifier_mod, "_integrity_violated", True)

        from yashigani.backoffice.routes.license import get_license_banner_context

        ctx = get_license_banner_context()
        assert ctx["license_mode"] == "tampered"
        assert ctx["license_banner"]["show"] is True
        assert "tampered" in ctx["license_banner"]["message"].lower()

    def test_tamper_never_touches_user_accounts(self, monkeypatch):
        """§5: 'NO user deletion/suspension.' The entire tamper path — from
        _check_build_integrity_chain() through get_license()/
        is_license_tampered() — only ever manipulates LicenseState /
        booleans; it has no import of, or call into, any user/account
        model. This test asserts the CONTRACT (return shape), which is the
        only thing an integration test can meaningfully assert without a
        live user store — the absence of any user-mutating code path is
        additionally verified by code review (verifier.py/_integrity.py/
        enforcer.py import no user/account/identity deletion API)."""
        import yashigani.licensing.verifier as verifier_mod
        monkeypatch.setattr(verifier_mod, "_integrity_violated", True)

        from yashigani.licensing.enforcer import get_license
        from yashigani.licensing.model import LicenseState

        lic = get_license()
        assert isinstance(lic, LicenseState)
        assert lic.valid is True  # COMMUNITY_LICENSE — service continues, degraded only


class TestUpgradePreservesLicence:
    """The core v2 redesign property (design §0): a licence signed under
    leaf-N (release 4.1.1's code leaf has NOTHING to do with the licence
    leaf, but this test proves the FULL verify_license() pipeline survives
    an upgrade because both the licence leaf and every release's code leaf
    chain to the SAME master anchor set — unlike v4, where the licence's
    counter-signature was checked against a PER-RELEASE counter key and
    broke on upgrade)."""

    def test_licence_survives_a_simulated_upgrade(self, tmp_path, monkeypatch):
        master_key = _gen_p384()

        # --- Release 4.1.1: embed build, issue a licence under it. ---
        _embed_build(monkeypatch, master_key, "4.1.1")

        leaf_cert, leaf_cert_sig, licence_key = _make_licence_leaf(master_key)
        payload = build_licence_payload_v5(
            org_domain="acme.example.com", tier="professional", client_id="acme-corp",
            licence_serial="lic-0001", max_agents=500, max_end_users=1000, max_admin_seats=50,
            max_orgs=1, expires_at=_now() + timedelta(days=365),
        )
        wire = _sign_licence(payload, leaf_cert, leaf_cert_sig, licence_key)

        from yashigani.licensing.model import LicenseTier
        from yashigani.licensing.verifier import verify_license

        result_411 = verify_license(wire)
        assert result_411.valid is True
        assert result_411.tier == LicenseTier.PROFESSIONAL

        # --- Upgrade to release 4.1.2: NEW code leaf, SAME master anchor. ---
        _embed_build(monkeypatch, master_key, "4.1.2")

        # The SAME licence string (signed under the licence leaf minted at
        # 4.1.1, never re-issued) must STILL verify on the new build,
        # because it chains to the same master — never touching the code
        # leaf at all.
        result_412 = verify_license(wire)
        assert result_412.valid is True
        assert result_412.tier == LicenseTier.PROFESSIONAL
        assert result_412.max_agents == 500

    def test_build_integrity_itself_also_survives_upgrade(self, monkeypatch):
        """Companion property: the BUILD's own integrity check also passes
        for both releases independently (each release's code leaf, freshly
        minted, still chains to the one unrotated master)."""
        master_key = _gen_p384()

        _embed_build(monkeypatch, master_key, "4.1.1")
        import yashigani.licensing.verifier as verifier_mod
        monkeypatch.setattr(verifier_mod, "_integrity_violated", False)
        verifier_mod._check_build_integrity_chain()
        assert verifier_mod._integrity_violated is False

        _embed_build(monkeypatch, master_key, "4.1.2")
        monkeypatch.setattr(verifier_mod, "_integrity_violated", False)
        verifier_mod._check_build_integrity_chain()
        assert verifier_mod._integrity_violated is False


class TestDowngradeRejected:
    """Design §3.2: 'v3/v4 dropped — v5 mandatory, no downgrade path.'"""

    def test_old_v4_shaped_token_rejected(self, monkeypatch):
        master_key = _gen_p384()
        _embed_build(monkeypatch, master_key, "4.1.1")

        payload = {
            "tier": "enterprise", "org_domain": "acme.example.com",
            "max_agents": -1, "max_end_users": -1, "max_admin_seats": -1, "max_orgs": -1,
            "features": ["oidc", "saml", "scim"],
        }
        payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        seg = base64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode()
        old_v4_token = f"{seg}.AAAA.AAAA"  # 3 segments — old v4 shape

        from yashigani.licensing.verifier import verify_license

        result = verify_license(old_v4_token)
        assert result.valid is False
        assert result.error == "license_format_deprecated_v5_required"
        assert result.tier.value != "enterprise"  # never grants the claimed tier

    def test_old_v3_shaped_token_rejected(self, monkeypatch):
        master_key = _gen_p384()
        _embed_build(monkeypatch, master_key, "4.1.1")

        payload = {"tier": "enterprise", "org_domain": "*"}
        payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        seg = base64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode()
        old_v3_token = f"{seg}.AAAA"  # 2 segments — old v3 shape

        from yashigani.licensing.verifier import verify_license

        result = verify_license(old_v3_token)
        assert result.valid is False
        assert result.error == "license_format_deprecated_v5_required"

    def test_downgrade_via_loader_falls_back_to_community(self, tmp_path, monkeypatch):
        master_key = _gen_p384()
        _embed_build(monkeypatch, master_key, "4.1.1")

        payload = {"tier": "enterprise", "org_domain": "*"}
        payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        seg = base64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode()
        old_v4_token = f"{seg}.AAAA.AAAA"

        lic_path = tmp_path / "license.ysg"
        lic_path.write_text(old_v4_token, encoding="utf-8")
        monkeypatch.setenv("YASHIGANI_LICENSE_FILE", str(lic_path))

        from yashigani.licensing.loader import load_license
        from yashigani.licensing.model import LicenseTier

        result = load_license()
        assert result.tier == LicenseTier.COMMUNITY
