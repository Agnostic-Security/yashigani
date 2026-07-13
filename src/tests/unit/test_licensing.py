"""
Comprehensive tests for yashigani.licensing.

Covers:
  - LicenseState model and tier enum
  - TIER_DEFAULTS consistency
  - LicenseState.has_feature() and is_expired()
  - verify_license() placeholder behaviour
  - verify_license() with real ECDSA P-256 keypair (generated in fixture)
  - verify_license() invalid signature path
  - verify_license() expired license path
  - verify_license() v1/v2 backwards-compat field fallback
  - enforcer: set/get license, require_feature, all four limit checks
  - enforcer: -1 (unlimited) bypasses limit checks
  - enforcer: HTTP response helpers
  - enforcer: upgrade URL points to agnosticsec.com
  - _safe_int: null/None/empty/non-numeric/float/sentinel coverage (LAURA-V231-002)
  - _safe_int: negative values other than -1 clamped to default (LAURA-LICENSE-08)
  - verify_license(): null seat fields → fail-closed, no TypeError (LAURA-V231-002)
  - load_license(): corrupt/null-field license → COMMUNITY, no crash (LAURA-V231-002)
  - LAURA-V231-003: 2-segment (v3) licenses rejected with license_format_too_old

Last updated: 2026-05-06T12:40:00+01:00
"""
from __future__ import annotations

import base64
import json
import uuid
from datetime import datetime, timezone, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from yashigani.licensing.model import (
    COMMUNITY_LICENSE,
    TIER_DEFAULTS,
    LicenseState,
    LicenseTier,
)
from yashigani.licensing.enforcer import (
    LicenseFeatureGated,
    LicenseLimitExceeded,
    check_admin_seat_limit,
    check_agent_limit,
    check_end_user_limit,
    check_org_limit,
    get_license,
    license_feature_gated_response,
    license_limit_exceeded_response,
    require_feature,
    set_license,
)
from yashigani.licensing.verifier import (
    COMMUNITY_LICENSE as _VERIFIER_COMMUNITY,  # verify_license uses this too
    base64url_decode,
    verify_license,
)
from yashigani.licensing.chain import (
    Alg,
    LeafCert,
    PemSigner,
    Role,
    build_licence_payload_v5,
    sign_licence_v5,
)
from yashigani.licensing.chain.algorithms import sign_message
from yashigani.licensing.chain.canonical import leaf_cert_signing_digest


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _make_test_keypair():
    """Generate an ephemeral ECDSA P-256 keypair for testing."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ec import (
            SECP256R1, generate_private_key, ECDSA
        )
        from cryptography.hazmat.primitives.hashes import SHA256
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat, PrivateFormat, NoEncryption
        )
    except ImportError:
        pytest.skip("cryptography package not installed")

    private_key = generate_private_key(SECP256R1())
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    public_pem = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    return private_key, public_key, private_pem, public_pem


def _sign_payload_v3(payload: dict, private_pem: bytes) -> str:
    """Sign payload dict and return 2-segment v3 .ysg format string.

    Used ONLY for LAURA-V231-003 rejection tests — v3 format is no longer accepted.
    """
    from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    private_key = load_pem_private_key(private_pem, password=None)
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    payload_bytes = payload_json.encode("utf-8")
    sig = private_key.sign(payload_bytes, ECDSA(SHA256()))
    return f"{_b64url_encode(payload_bytes)}.{_b64url_encode(sig)}"


def _sign_payload(payload: dict, private_pem: bytes, counter_private_pem: bytes | None = None) -> str:
    """Sign payload dict and return 3-segment v4 .ysg format string (counter-sig mandatory).

    If counter_private_pem is None, a fresh ephemeral counter keypair is generated and
    patched into the verifier module for the duration of the test via the module-level
    _counter_key_pem_override if set, or the test must monkeypatch _integrity separately.

    In practice, all TestVerifyLicenseWithRealKey tests use the shared fixture that patches
    both the primary key and (via counter_private_pem) the counter key.
    """
    import hashlib
    from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, SECP256R1, generate_private_key
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key, Encoding, PrivateFormat, NoEncryption
    )

    private_key = load_pem_private_key(private_pem, password=None)
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    payload_bytes = payload_json.encode("utf-8")
    primary_sig = private_key.sign(payload_bytes, ECDSA(SHA256()))

    # Counter-signature over sha256(payload_bytes + sha256(primary_pub_pem_bytes))
    from cryptography.hazmat.primitives.serialization import PublicFormat
    primary_pub_pem = private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    pem_hash = hashlib.sha256(primary_pub_pem).digest()
    counter_msg = hashlib.sha256(payload_bytes + pem_hash).digest()

    if counter_private_pem is not None:
        counter_key = load_pem_private_key(counter_private_pem, password=None)
    else:
        # Generate a fresh ephemeral counter key — caller must patch _integrity to trust it
        counter_key = generate_private_key(SECP256R1())

    counter_sig = counter_key.sign(counter_msg, ECDSA(SHA256()))
    return f"{_b64url_encode(payload_bytes)}.{_b64url_encode(primary_sig)}.{_b64url_encode(counter_sig)}"


def _patch_verifier_key(public_pem: bytes, monkeypatch):
    """Monkeypatch the verifier module to use a test public key."""
    import yashigani.licensing.verifier as verifier_mod
    monkeypatch.setattr(verifier_mod, "_PUBLIC_KEY_PEM", public_pem.decode("utf-8"))
    monkeypatch.setattr(verifier_mod, "_placeholder_warned", False)


def _make_payload(
    tier="professional",
    org_domain="test.example.com",
    max_agents=500,
    max_end_users=1000,
    max_admin_seats=50,
    max_orgs=1,
    features=None,
    issued_offset_days=0,
    expires_offset_days=30,
    license_type="production",
    version=3,
    license_id=None,
) -> dict:
    now = datetime.now(timezone.utc)
    issued = now + timedelta(days=issued_offset_days)
    expires = now + timedelta(days=expires_offset_days) if expires_offset_days is not None else None

    payload = {
        "v": version,
        "tier": tier,
        "license_type": license_type,
        "org_domain": org_domain,
        "license_id": license_id or str(uuid.uuid4()),
        "max_agents": max_agents,
        "max_end_users": max_end_users,
        "max_admin_seats": max_admin_seats,
        "max_orgs": max_orgs,
        "features": features if features is not None else ["oidc", "saml", "scim"],
        "issued_at": issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if expires:
        payload["expires_at"] = expires.strftime("%Y-%m-%dT%H:%M:%SZ")
    return payload


# ─────────────────────────────────────────────────────────────────────────────
# Model tests
# ─────────────────────────────────────────────────────────────────────────────

class TestLicenseTier:
    def test_all_expected_tiers_exist(self):
        expected = {"community", "igniter", "starter", "professional", "professional_plus", "enterprise", "academic_nonprofit", "canary"}
        actual = {t.value for t in LicenseTier}
        assert actual == expected

    def test_tier_values_are_lowercase_strings(self):
        for tier in LicenseTier:
            assert tier.value == tier.value.lower()
            assert tier.value == tier.value.replace("-", "_")


class TestTierDefaults:
    def test_all_tiers_have_defaults(self):
        for tier in LicenseTier:
            assert tier.value in TIER_DEFAULTS, f"TIER_DEFAULTS missing entry for {tier.value}"

    def test_community_limits(self):
        d = TIER_DEFAULTS["community"]
        assert d["max_agents"] == 20
        assert d["max_end_users"] == 5
        assert d["max_admin_seats"] == 2
        assert d["max_orgs"] == 1

    def test_igniter_limits(self):
        # Per README §8 / pricing page (Igniter is the entry paid tier).
        d = TIER_DEFAULTS["igniter"]
        assert d["max_agents"] == 200
        assert d["max_end_users"] == 50
        assert d["max_admin_seats"] == 5
        assert d["max_orgs"] == 1

    def test_starter_limits(self):
        d = TIER_DEFAULTS["starter"]
        assert d["max_agents"] == 400
        assert d["max_end_users"] == 100
        assert d["max_admin_seats"] == 10
        assert d["max_orgs"] == 1

    def test_professional_limits(self):
        d = TIER_DEFAULTS["professional"]
        assert d["max_agents"] == 2000
        assert d["max_end_users"] == 500
        assert d["max_admin_seats"] == 25
        assert d["max_orgs"] == 1

    def test_professional_plus_limits(self):
        d = TIER_DEFAULTS["professional_plus"]
        assert d["max_agents"] == 16000
        assert d["max_end_users"] == 4000
        assert d["max_admin_seats"] == 100
        assert d["max_orgs"] == 5

    def test_enterprise_unlimited(self):
        d = TIER_DEFAULTS["enterprise"]
        assert d["max_agents"] == -1
        assert d["max_end_users"] == -1
        assert d["max_admin_seats"] == -1
        assert d["max_orgs"] == -1

    def test_academic_nonprofit_unlimited(self):
        # Per README §8: Non-profit & Education has Unlimited everything.
        d = TIER_DEFAULTS["academic_nonprofit"]
        assert d["max_agents"] == -1
        assert d["max_end_users"] == -1
        assert d["max_admin_seats"] == -1
        assert d["max_orgs"] == -1

    def test_tier_limits_are_strictly_increasing(self):
        """Igniter ≤ Starter ≤ Professional ≤ Professional Plus for all positive limits."""
        tiers = ["igniter", "starter", "professional", "professional_plus"]
        for field in ["max_agents", "max_end_users", "max_admin_seats"]:
            values = [TIER_DEFAULTS[t][field] for t in tiers]
            assert values == sorted(values), \
                f"Expected {field} to increase across {tiers}, got {values}"


class TestLicenseState:
    def test_community_license_is_valid(self):
        assert COMMUNITY_LICENSE.valid is True
        assert COMMUNITY_LICENSE.tier == LicenseTier.COMMUNITY
        assert COMMUNITY_LICENSE.expires_at is None

    def test_community_license_never_expires(self):
        assert COMMUNITY_LICENSE.is_expired() is False

    def test_has_feature_true(self):
        state = LicenseState(
            tier=LicenseTier.PROFESSIONAL,
            org_domain="example.com",
            max_agents=500,
            max_end_users=1000,
            max_admin_seats=50,
            max_orgs=1,
            features=frozenset(["oidc", "saml"]),
            issued_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            expires_at=None,
            license_id=None,
            valid=True,
            error=None,
        )
        assert state.has_feature("oidc") is True
        assert state.has_feature("saml") is True
        assert state.has_feature("scim") is False

    def test_is_expired_past(self):
        state = LicenseState(
            tier=LicenseTier.PROFESSIONAL,
            org_domain="example.com",
            max_agents=500,
            max_end_users=1000,
            max_admin_seats=50,
            max_orgs=1,
            features=frozenset(),
            issued_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
            expires_at=datetime(2025, 6, 1, tzinfo=timezone.utc),
            license_id=None,
            valid=True,
            error=None,
        )
        assert state.is_expired() is True

    def test_is_expired_future(self):
        future = datetime.now(timezone.utc) + timedelta(days=30)
        state = LicenseState(
            tier=LicenseTier.PROFESSIONAL,
            org_domain="example.com",
            max_agents=500,
            max_end_users=1000,
            max_admin_seats=50,
            max_orgs=1,
            features=frozenset(),
            issued_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            expires_at=future,
            license_id=None,
            valid=True,
            error=None,
        )
        assert state.is_expired() is False


# ─────────────────────────────────────────────────────────────────────────────
# Verifier tests
# ─────────────────────────────────────────────────────────────────────────────

class TestBase64UrlDecode:
    def test_no_padding_needed(self):
        encoded = base64.urlsafe_b64encode(b"hello").rstrip(b"=").decode()
        assert base64url_decode(encoded) == b"hello"

    def test_with_padding_needed(self):
        encoded = base64.urlsafe_b64encode(b"ab").rstrip(b"=").decode()
        assert base64url_decode(encoded) == b"ab"

    def test_url_safe_chars(self):
        # Bytes that produce +/ in standard base64, should work with urlsafe
        data = bytes([0xFB, 0xFF, 0xFE])
        encoded = base64.urlsafe_b64encode(data).rstrip(b"=").decode()
        assert base64url_decode(encoded) == data


def _gen_p384():
    return ec.generate_private_key(ec.SECP384R1())


def _pem_pub_p384(key) -> str:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def _make_v5_licence_leaf(master_key, client_id: str = "acme-corp", serial: str = "lic-leaf-0001"):
    now = datetime.now(timezone.utc)
    licence_key = _gen_p384()
    leaf_cert = LeafCert(
        role=Role.LICENCE, client_id=client_id, leaf_pubkey_pem=_pem_pub_p384(licence_key),
        not_before=now - timedelta(days=1), not_after=now + timedelta(days=60),
        serial=serial, signed_at=now, alg=Alg.ECDSA_P384_SHA384,
    )
    leaf_cert_sig = sign_message(
        Alg.ECDSA_P384_SHA384, master_key, leaf_cert_signing_digest(leaf_cert.to_canonical_dict())
    )
    return leaf_cert, leaf_cert_sig, licence_key


def _sign_v5(payload: dict, leaf_cert, leaf_cert_sig: bytes, licence_key) -> str:
    signer = PemSigner(role=Role.LICENCE, private_key=licence_key, leaf_cert=leaf_cert)
    return sign_licence_v5(payload, signer, leaf_cert, leaf_cert_sig)


class TestVerifyLicensePlaceholder:
    """When the master anchor-set is empty/unpopulated, no v5 licence can
    chain — verify_license() falls back to a COMMUNITY-tier invalid state
    (mirrors the old placeholder-key behaviour for v4)."""

    @pytest.fixture(autouse=True)
    def force_empty_anchor_set(self, monkeypatch):
        import yashigani.licensing._integrity as integrity_mod
        import yashigani.licensing.verifier as verifier_mod
        monkeypatch.setattr(integrity_mod, "MASTER_ANCHOR_SET_JSON", "[]")
        monkeypatch.setattr(verifier_mod, "_integrity_violated", False)

    def test_returns_community_on_empty_anchor_set(self):
        master_key = _gen_p384()
        leaf_cert, leaf_cert_sig, licence_key = _make_v5_licence_leaf(master_key)
        payload = build_licence_payload_v5(
            org_domain="test.example.com", tier="professional", client_id="acme-corp",
            licence_serial="lic-0001", max_agents=500, max_end_users=1000, max_admin_seats=50,
            max_orgs=1, expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )
        license_str = _sign_v5(payload, leaf_cert, leaf_cert_sig, licence_key)
        result = verify_license(license_str)
        # valid=False; tier/org info from the payload is still carried for
        # diagnostics (matches the pre-existing v4 architecture) — actual
        # enforcement of the Community fallback happens in loader.py, which
        # checks .valid and returns COMMUNITY_LICENSE (see load_license()).
        assert result.valid is False
        assert result.error == "leaf_cert_untrusted"

    def test_returns_community_on_garbage_content(self):
        # "any.content" splits into 2 segments — rejected as an old-format
        # (v3) license, not silently fail-open (no downgrade path, §3.2).
        result = verify_license("any.content")
        assert result.tier == LicenseTier.COMMUNITY
        assert result.valid is False
        assert result.error == "license_format_deprecated_v5_required"

    def test_returns_community_on_truly_unparseable_content(self):
        """Content with no dots at all (not even an old-format shape) still
        fail-opens to COMMUNITY_LICENSE (valid=True) — mirrors the pre-v5
        behaviour for genuinely unrecognisable input."""
        result = verify_license("nodotsatall")
        assert result.tier == LicenseTier.COMMUNITY
        assert result.valid is True


class TestVerifyLicenseWithRealKey:
    """Uses a generated P-384 master + licence leaf to test the full v5
    chain-of-trust verification path (§4b)."""

    @pytest.fixture(autouse=True)
    def setup_chain(self, monkeypatch):
        import yashigani.licensing._integrity as integrity_mod
        import yashigani.licensing.verifier as verifier_mod

        self.master_key = _gen_p384()
        anchor_set_json = json.dumps([{
            "anchor_id": "M1", "pubkey_pem": _pem_pub_p384(self.master_key),
            "alg": Alg.ECDSA_P384_SHA384.value, "status": "active",
            "added": datetime.now(timezone.utc).isoformat(),
        }])
        monkeypatch.setattr(integrity_mod, "MASTER_ANCHOR_SET_JSON", anchor_set_json)
        monkeypatch.setattr(integrity_mod, "KILL_LIST_JSON", "[]")
        monkeypatch.setattr(integrity_mod, "CLIENT_DOMAIN_REGISTRY_JSON", "{}")
        monkeypatch.setattr(verifier_mod, "_integrity_violated", False)

        self.leaf_cert, self.leaf_cert_sig, self.licence_key = _make_v5_licence_leaf(self.master_key)

    def _make_v5_payload(
        self,
        tier="professional", org_domain="test.example.com", client_id="acme-corp",
        licence_serial="lic-0001", max_agents=500, max_end_users=1000, max_admin_seats=50,
        max_orgs=1, features=None, expires_offset_days=30,
    ) -> dict:
        return build_licence_payload_v5(
            org_domain=org_domain, tier=tier, client_id=client_id, licence_serial=licence_serial,
            max_agents=max_agents, max_end_users=max_end_users, max_admin_seats=max_admin_seats,
            max_orgs=max_orgs, features=features if features is not None else ["oidc", "saml", "scim"],
            expires_at=datetime.now(timezone.utc) + timedelta(days=expires_offset_days),
        )

    def _sign(self, payload: dict) -> str:
        return _sign_v5(payload, self.leaf_cert, self.leaf_cert_sig, self.licence_key)

    def test_valid_v5_license(self):
        payload = self._make_v5_payload()
        license_str = self._sign(payload)
        result = verify_license(license_str)
        assert result.valid is True
        assert result.tier == LicenseTier.PROFESSIONAL
        assert result.max_agents == 500
        assert result.max_end_users == 1000
        assert result.max_admin_seats == 50
        assert result.max_orgs == 1

    def test_valid_starter_license(self):
        payload = self._make_v5_payload(
            tier="starter",
            max_agents=100, max_end_users=250, max_admin_seats=25, max_orgs=1,
            features=["oidc"],
        )
        license_str = self._sign(payload)
        result = verify_license(license_str)
        assert result.valid is True
        assert result.tier == LicenseTier.STARTER
        assert result.has_feature("oidc") is True
        assert result.has_feature("saml") is False
        assert result.max_end_users == 250
        assert result.max_admin_seats == 25

    def test_valid_professional_plus_license(self):
        payload = self._make_v5_payload(
            tier="professional_plus",
            max_agents=2000, max_end_users=10000, max_admin_seats=200, max_orgs=5,
        )
        license_str = self._sign(payload)
        result = verify_license(license_str)
        assert result.valid is True
        assert result.tier == LicenseTier.PROFESSIONAL_PLUS
        assert result.max_orgs == 5

    def test_valid_enterprise_unlimited(self):
        payload = self._make_v5_payload(
            tier="enterprise",
            max_agents=-1, max_end_users=-1, max_admin_seats=-1, max_orgs=-1,
        )
        license_str = self._sign(payload)
        result = verify_license(license_str)
        assert result.valid is True
        assert result.tier == LicenseTier.ENTERPRISE
        assert result.max_agents == -1

    def test_expired_license_returns_invalid(self):
        payload = self._make_v5_payload(expires_offset_days=-1)  # expired yesterday
        license_str = self._sign(payload)
        result = verify_license(license_str)
        assert result.valid is False
        assert result.error == "license_expired"
        # Tier and org info are still present even when expired
        assert result.tier == LicenseTier.PROFESSIONAL
        assert result.org_domain == "test.example.com"

    def test_invalid_signature_returns_invalid(self):
        payload = self._make_v5_payload()
        license_str = self._sign(payload)
        # Corrupt the leaf_sig segment (segment 2 of 4)
        parts = license_str.split(".")
        corrupted = ".".join([parts[0], "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", parts[2], parts[3]])
        result = verify_license(corrupted)
        assert result.valid is False
        assert result.error == "invalid_signature"

    def test_missing_separator_falls_back_to_community(self):
        result = verify_license("no_dot_here")
        assert result.tier == LicenseTier.COMMUNITY

    def test_features_parsed_correctly(self):
        payload = self._make_v5_payload(features=["oidc", "saml", "scim"])
        license_str = self._sign(payload)
        result = verify_license(license_str)
        assert result.has_feature("oidc") is True
        assert result.has_feature("saml") is True
        assert result.has_feature("scim") is True

    def test_community_features_empty(self):
        payload = self._make_v5_payload(tier="community", features=[], max_agents=20,
                                max_end_users=50, max_admin_seats=10, max_orgs=1)
        license_str = self._sign(payload)
        result = verify_license(license_str)
        assert result.has_feature("oidc") is False

    def test_org_domain_stored(self):
        payload = self._make_v5_payload(org_domain="mycorp.io")
        license_str = self._sign(payload)
        result = verify_license(license_str)
        assert result.org_domain == "mycorp.io"

    def test_license_id_stored(self):
        lid = str(uuid.uuid4())
        payload = self._make_v5_payload(licence_serial=lid)
        license_str = self._sign(payload)
        result = verify_license(license_str)
        assert result.license_id == lid

    def test_v1_payload_backwards_compat(self):
        """Payloads lacking max_end_users and max_admin_seats — must fall back to tier defaults
        (field-resolution logic unchanged from v4, independent of wire format version)."""
        payload = self._make_v5_payload()
        del payload["max_end_users"]
        del payload["max_admin_seats"]
        license_str = self._sign(payload)
        result = verify_license(license_str)
        assert result.valid is True
        assert result.max_end_users == TIER_DEFAULTS["professional"]["max_end_users"]
        assert result.max_admin_seats == TIER_DEFAULTS["professional"]["max_admin_seats"]

    def test_v2_max_users_field_maps_to_max_end_users(self):
        """Legacy payloads may use 'max_users' instead of 'max_end_users'."""
        payload = self._make_v5_payload()
        del payload["max_end_users"]
        payload["max_users"] = 999
        license_str = self._sign(payload)
        result = verify_license(license_str)
        assert result.max_end_users == 999

    def test_unknown_tier_falls_back_to_community(self):
        payload = self._make_v5_payload()
        payload["tier"] = "nonexistent_tier"
        license_str = self._sign(payload)
        result = verify_license(license_str)
        assert result.tier == LicenseTier.COMMUNITY


# ─────────────────────────────────────────────────────────────────────────────
# Enforcer tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def reset_enforcer_license():
    """Reset enforcer state to COMMUNITY between each test."""
    original = get_license()
    yield
    set_license(original)


def _make_license_state(
    tier=LicenseTier.PROFESSIONAL,
    features=("oidc", "saml", "scim"),
    max_agents=500,
    max_end_users=1000,
    max_admin_seats=50,
    max_orgs=1,
    valid=True,
    error=None,
) -> LicenseState:
    return LicenseState(
        tier=tier,
        org_domain="example.com",
        max_agents=max_agents,
        max_end_users=max_end_users,
        max_admin_seats=max_admin_seats,
        max_orgs=max_orgs,
        features=frozenset(features),
        issued_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        expires_at=datetime(2027, 1, 1, tzinfo=timezone.utc),
        license_id=str(uuid.uuid4()),
        valid=valid,
        error=error,
    )


class TestEnforcerSetGet:
    def test_default_is_community(self):
        # Fresh module state defaults to community
        # (enforcer resets to original via fixture)
        set_license(COMMUNITY_LICENSE)
        assert get_license().tier == LicenseTier.COMMUNITY

    def test_set_and_get(self):
        lic = _make_license_state()
        set_license(lic)
        assert get_license() is lic


class TestRequireFeature:
    def test_feature_present_does_not_raise(self):
        set_license(_make_license_state(features=["saml"]))
        require_feature("saml")  # should not raise

    def test_missing_feature_raises(self):
        set_license(_make_license_state(features=["oidc"]))
        with pytest.raises(LicenseFeatureGated) as exc_info:
            require_feature("saml")
        assert exc_info.value.feature == "saml"
        assert exc_info.value.tier == LicenseTier.PROFESSIONAL

    def test_community_has_no_features(self):
        set_license(COMMUNITY_LICENSE)
        with pytest.raises(LicenseFeatureGated):
            require_feature("oidc")


class TestAgentLimit:
    def test_under_limit_ok(self):
        set_license(_make_license_state(max_agents=10))
        check_agent_limit(9)  # no raise

    def test_at_limit_raises(self):
        set_license(_make_license_state(max_agents=10))
        with pytest.raises(LicenseLimitExceeded) as exc_info:
            check_agent_limit(10)
        assert exc_info.value.limit_name == "max_agents"
        assert exc_info.value.current == 10
        assert exc_info.value.max_val == 10

    def test_unlimited_always_ok(self):
        set_license(_make_license_state(max_agents=-1))
        check_agent_limit(1_000_000)  # no raise


class TestEndUserLimit:
    def test_under_limit_ok(self):
        set_license(_make_license_state(max_end_users=100))
        check_end_user_limit(99)

    def test_at_limit_raises(self):
        set_license(_make_license_state(max_end_users=100))
        with pytest.raises(LicenseLimitExceeded) as exc_info:
            check_end_user_limit(100)
        assert exc_info.value.limit_name == "max_end_users"

    def test_unlimited_always_ok(self):
        set_license(_make_license_state(max_end_users=-1))
        check_end_user_limit(999_999)


class TestAdminSeatLimit:
    def test_under_limit_ok(self):
        set_license(_make_license_state(max_admin_seats=5))
        check_admin_seat_limit(4)

    def test_at_limit_raises(self):
        set_license(_make_license_state(max_admin_seats=5))
        with pytest.raises(LicenseLimitExceeded) as exc_info:
            check_admin_seat_limit(5)
        assert exc_info.value.limit_name == "max_admin_seats"

    def test_unlimited_always_ok(self):
        set_license(_make_license_state(max_admin_seats=-1))
        check_admin_seat_limit(10_000)


class TestOrgLimit:
    def test_under_limit_ok(self):
        set_license(_make_license_state(max_orgs=5))
        check_org_limit(4)

    def test_at_limit_raises(self):
        set_license(_make_license_state(max_orgs=5))
        with pytest.raises(LicenseLimitExceeded) as exc_info:
            check_org_limit(5)
        assert exc_info.value.limit_name == "max_orgs"

    def test_unlimited_always_ok(self):
        set_license(_make_license_state(max_orgs=-1))
        check_org_limit(9_999)


class TestResponseHelpers:
    def test_feature_gated_response_structure(self):
        set_license(_make_license_state())
        exc = LicenseFeatureGated(feature="saml", tier=LicenseTier.COMMUNITY)
        resp = license_feature_gated_response(exc)
        assert resp["error"] == "LICENSE_FEATURE_GATED"
        assert resp["feature"] == "saml"
        assert "upgrade_url" in resp
        assert "agnosticsec.com" in resp["upgrade_url"]

    def test_limit_exceeded_response_structure(self):
        set_license(_make_license_state())
        exc = LicenseLimitExceeded("max_agents", current=500, max_val=500)
        resp = license_limit_exceeded_response(exc)
        assert resp["error"] == "LICENSE_LIMIT_EXCEEDED"
        assert resp["limit"] == "max_agents"
        assert resp["current"] == 500
        assert resp["maximum"] == 500
        assert "agnosticsec.com" in resp["upgrade_url"]

    def test_upgrade_url_points_to_agnosticsecurity(self):
        """IC-NEW-3 regression: URLs must not point to yashigani.io."""
        set_license(_make_license_state())
        exc = LicenseFeatureGated("scim", LicenseTier.COMMUNITY)
        resp = license_feature_gated_response(exc)
        assert "yashigani.io" not in resp["upgrade_url"], \
            "upgrade_url must point to agnosticsec.com, not yashigani.io"

    def test_all_limit_names_have_labels(self):
        limit_names = ["max_agents", "max_end_users", "max_admin_seats", "max_orgs"]
        set_license(_make_license_state())
        for name in limit_names:
            exc = LicenseLimitExceeded(name, current=1, max_val=1)
            resp = license_limit_exceeded_response(exc)
            assert resp["message"]  # message must not be empty
            assert resp["limit"] == name


# ─────────────────────────────────────────────────────────────────────────────
# LAURA-V231-002: _safe_int unit tests
# ─────────────────────────────────────────────────────────────────────────────

class TestSafeInt:
    """
    Unit tests for verifier._safe_int().

    Prevents regression of LAURA-V231-002: null seat fields in a license
    payload previously caused int(None) → TypeError → DoS on boot.
    """

    @pytest.fixture(autouse=True)
    def import_safe_int(self):
        from yashigani.licensing.verifier import _safe_int
        self._safe_int = _safe_int

    def _si(self, value, default=100):
        return self._safe_int(value, default)

    def test_int_passthrough(self):
        assert self._si(42) == 42

    def test_string_int(self):
        assert self._si("42") == 42

    def test_none_returns_default(self):
        assert self._si(None) == 100

    def test_empty_string_returns_default(self):
        assert self._si("") == 100

    def test_whitespace_string_returns_default(self):
        assert self._si("   ") == 100

    def test_non_numeric_string_returns_default(self):
        assert self._si("abc") == 100

    def test_null_string_returns_default(self):
        assert self._si("null") == 100

    def test_float_truncated(self):
        assert self._si(3.9) == 3

    def test_negative_non_sentinel_clamped_to_default(self):
        # LAURA-LICENSE-08: negative values other than -1 are adversarial
        # (a seat count of -2 bypasses enforcer's >= check) — clamp to default.
        assert self._si(-2) == 100
        assert self._si(-42) == 100

    def test_unlimited_sentinel_preserved(self):
        # -1 is the documented unlimited sentinel — must never be clamped
        assert self._si(-1) == -1

    def test_zero_passthrough(self):
        assert self._si(0) == 0

    def test_above_ceiling_returns_default(self):
        from yashigani.licensing.verifier import _SEAT_CEILING
        assert self._si(_SEAT_CEILING + 1) == 100

    def test_at_ceiling_passthrough(self):
        from yashigani.licensing.verifier import _SEAT_CEILING
        assert self._si(_SEAT_CEILING) == _SEAT_CEILING


# ─────────────────────────────────────────────────────────────────────────────
# LAURA-V231-002: null seat fields → fail-closed integration tests
# ─────────────────────────────────────────────────────────────────────────────

class TestNullSeatFieldsFailClosed:
    """
    Integration tests: a license payload with null / missing seat fields must
    not raise TypeError and must return a fail-closed COMMUNITY LicenseState.

    Verifies fix for LAURA-V231-002: int(None) DoS-on-boot.
    Uses v5 license format.
    """

    @pytest.fixture(autouse=True)
    def setup_chain(self, monkeypatch):
        import yashigani.licensing._integrity as integrity_mod
        import yashigani.licensing.verifier as verifier_mod

        self.master_key = _gen_p384()
        anchor_set_json = json.dumps([{
            "anchor_id": "M1", "pubkey_pem": _pem_pub_p384(self.master_key),
            "alg": Alg.ECDSA_P384_SHA384.value, "status": "active",
            "added": datetime.now(timezone.utc).isoformat(),
        }])
        monkeypatch.setattr(integrity_mod, "MASTER_ANCHOR_SET_JSON", anchor_set_json)
        monkeypatch.setattr(integrity_mod, "KILL_LIST_JSON", "[]")
        monkeypatch.setattr(integrity_mod, "CLIENT_DOMAIN_REGISTRY_JSON", "{}")
        monkeypatch.setattr(verifier_mod, "_integrity_violated", False)

        self.leaf_cert, self.leaf_cert_sig, self.licence_key = _make_v5_licence_leaf(self.master_key)

    def _sign(self, payload: dict) -> str:
        """Sign a legacy-shaped (_make_payload()) dict as v5 — injects the
        v5-only fields (client_id/licence_serial/alg/signed_at) that
        _make_payload() (a v4-era helper reused here for its seat-field
        shape) does not set, so these null-seat-field tests exercise the
        SAME field-resolution logic against a v5 wire format."""
        payload = dict(payload)
        payload.setdefault("client_id", self.leaf_cert.client_id)
        payload.setdefault("licence_serial", payload.get("license_id", "lic-0001"))
        payload.setdefault("alg", Alg.ECDSA_P384_SHA384.value)
        payload.setdefault("signed_at", datetime.now(timezone.utc).isoformat())
        if "expires_at" not in payload:
            payload["expires_at"] = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        return _sign_v5(payload, self.leaf_cert, self.leaf_cert_sig, self.licence_key)

    def test_null_max_end_users_no_typeerror(self):
        """max_end_users: null in JSON must not raise TypeError."""
        payload = _make_payload()
        payload["max_end_users"] = None
        license_str = self._sign(payload)
        # Must not raise; result must be fail-closed
        result = verify_license(license_str)
        assert isinstance(result, __import__("yashigani.licensing.model", fromlist=["LicenseState"]).LicenseState)

    def test_null_max_end_users_uses_tier_default(self):
        """max_end_users: null falls back to tier default, not crash."""
        payload = _make_payload(tier="professional")
        payload["max_end_users"] = None
        license_str = self._sign(payload)
        result = verify_license(license_str)
        # Should get tier default for professional
        assert result.max_end_users == TIER_DEFAULTS["professional"]["max_end_users"]

    def test_null_max_agents_uses_tier_default(self):
        """max_agents: null falls back to tier default."""
        payload = _make_payload(tier="professional")
        payload["max_agents"] = None
        license_str = self._sign(payload)
        result = verify_license(license_str)
        assert result.max_agents == TIER_DEFAULTS["professional"]["max_agents"]

    def test_null_max_admin_seats_uses_tier_default(self):
        """max_admin_seats: null falls back to tier default."""
        payload = _make_payload(tier="professional")
        payload["max_admin_seats"] = None
        license_str = self._sign(payload)
        result = verify_license(license_str)
        assert result.max_admin_seats == TIER_DEFAULTS["professional"]["max_admin_seats"]

    def test_all_seat_fields_null_no_crash(self):
        """All seat fields null at once: no crash, defaults applied."""
        payload = _make_payload(tier="professional")
        payload["max_end_users"] = None
        payload["max_agents"] = None
        payload["max_admin_seats"] = None
        payload["max_orgs"] = None
        license_str = self._sign(payload)
        result = verify_license(license_str)
        d = TIER_DEFAULTS["professional"]
        assert result.max_agents == d["max_agents"]
        assert result.max_end_users == d["max_end_users"]
        assert result.max_admin_seats == d["max_admin_seats"]
        assert result.max_orgs == d["max_orgs"]

    def test_valid_flag_preserved_with_null_fields(self):
        """Signature is valid; null fields must not flip valid=False."""
        payload = _make_payload(tier="professional")
        payload["max_end_users"] = None
        license_str = self._sign(payload)
        result = verify_license(license_str)
        assert result.valid is True

    def test_string_null_seat_field_uses_tier_default(self):
        """String 'null' in a seat field (malformed JSON output) is handled."""
        payload = _make_payload(tier="professional")
        payload["max_end_users"] = "null"
        license_str = self._sign(payload)
        result = verify_license(license_str)
        assert result.max_end_users == TIER_DEFAULTS["professional"]["max_end_users"]


class TestLoadLicenseCorruptPayloadFailClosed:
    """
    load_license() must return COMMUNITY_LICENSE without raising when the
    license file contains corrupt / unparseable / null-field content.

    Verifies LAURA-V231-002 defensive wrapper in loader.py.
    """

    def test_load_license_random_garbage_returns_community(self, tmp_path, monkeypatch):
        """Random bytes in license file → COMMUNITY, no crash."""
        lic_path = tmp_path / "license.ysg"
        lic_path.write_text("NOTVALIDBASE64!!!.GARBAGE", encoding="utf-8")
        monkeypatch.setenv("YASHIGANI_LICENSE_FILE", str(lic_path))

        from yashigani.licensing.loader import load_license
        result = load_license()
        assert result.tier == LicenseTier.COMMUNITY

    def test_load_license_truncated_content_returns_community(self, tmp_path, monkeypatch):
        """Truncated license (single segment, no dot) → COMMUNITY."""
        lic_path = tmp_path / "license.ysg"
        lic_path.write_text("eyJ0aWVyIjogImVudGVycHJpc2UifQ", encoding="utf-8")
        monkeypatch.setenv("YASHIGANI_LICENSE_FILE", str(lic_path))

        from yashigani.licensing.loader import load_license
        result = load_license()
        assert result.tier == LicenseTier.COMMUNITY

    def test_load_license_empty_file_returns_community(self, tmp_path, monkeypatch):
        """Empty license file → COMMUNITY."""
        lic_path = tmp_path / "license.ysg"
        lic_path.write_text("", encoding="utf-8")
        monkeypatch.setenv("YASHIGANI_LICENSE_FILE", str(lic_path))

        from yashigani.licensing.loader import load_license
        result = load_license()
        assert result.tier == LicenseTier.COMMUNITY


# ─────────────────────────────────────────────────────────────────────────────
# LAURA-V231-003: v3 license format (2-segment) rejected
# ─────────────────────────────────────────────────────────────────────────────

def _sign_payload_v3(payload: dict, private_pem: bytes) -> str:
    """Build an old-format 2-segment string (no valid v5 crypto needed — the
    v5 verifier rejects on segment count before any signature is attempted)."""
    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return f"{base64.urlsafe_b64encode(payload_bytes).rstrip(b'=').decode()}.AAAA"


def _sign_payload_v4(payload: dict, private_pem: bytes) -> str:
    """Build an old-format 3-segment string (no valid v5 crypto needed)."""
    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    seg = base64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode()
    return f"{seg}.AAAA.AAAA"


class TestV3LicenseRejected:
    """
    Design §3.2: "v3/v4 dropped — v5 mandatory, no downgrade path." Both the
    old 2-segment (v3) and 3-segment (v4) formats must be rejected with
    error="license_format_deprecated_v5_required", regardless of payload
    content or signature validity (rejected on segment count alone, before
    any crypto runs). Class name preserved for test-history continuity.
    """

    @pytest.fixture(autouse=True)
    def setup_keypair(self, monkeypatch):
        keys = _make_test_keypair()
        self.private_key, self.public_key, self.private_pem, self.public_pem = keys

    def test_two_segment_license_rejected(self):
        """A 2-segment (v3) license must be rejected (no downgrade path)."""
        payload = _make_payload()
        license_str = _sign_payload_v3(payload, self.private_pem)
        assert len(license_str.split(".")) == 2, "helper must produce 2-segment string"
        result = verify_license(license_str)
        assert result.valid is False
        assert result.error == "license_format_deprecated_v5_required"

    def test_two_segment_license_returns_community_tier(self):
        """Rejected v3 license falls back to COMMUNITY tier."""
        payload = _make_payload(tier="enterprise", max_agents=-1)
        license_str = _sign_payload_v3(payload, self.private_pem)
        result = verify_license(license_str)
        assert result.tier == LicenseTier.COMMUNITY

    def test_two_segment_enterprise_cannot_bypass_community(self):
        """Even a v3 enterprise license is rejected; caller cannot get enterprise tier."""
        payload = _make_payload(tier="enterprise", max_agents=-1, max_end_users=-1)
        license_str = _sign_payload_v3(payload, self.private_pem)
        result = verify_license(license_str)
        # Must not be enterprise
        assert result.tier != LicenseTier.ENTERPRISE
        assert result.valid is False

    def test_two_segment_via_file_returns_community(self, tmp_path, monkeypatch):
        """load_license() with a v3-format file → COMMUNITY (loader sees invalid)."""
        payload = _make_payload()
        license_str = _sign_payload_v3(payload, self.private_pem)
        lic_path = tmp_path / "license.ysg"
        lic_path.write_text(license_str, encoding="utf-8")
        monkeypatch.setenv("YASHIGANI_LICENSE_FILE", str(lic_path))

        from yashigani.licensing.loader import load_license
        result = load_license()
        assert result.tier == LicenseTier.COMMUNITY

    def test_three_segment_v4_license_rejected(self):
        """A 3-segment (old v4) license must ALSO be rejected — no downgrade path."""
        payload = _make_payload()
        license_str = _sign_payload_v4(payload, self.private_pem)
        assert len(license_str.split(".")) == 3, "helper must produce 3-segment string"
        result = verify_license(license_str)
        assert result.valid is False
        assert result.error == "license_format_deprecated_v5_required"
        assert result.tier == LicenseTier.COMMUNITY

    def test_three_segment_via_file_returns_community(self, tmp_path, monkeypatch):
        """load_license() with a v4-format file → COMMUNITY (loader sees invalid)."""
        payload = _make_payload()
        license_str = _sign_payload_v4(payload, self.private_pem)
        lic_path = tmp_path / "license.ysg"
        lic_path.write_text(license_str, encoding="utf-8")
        monkeypatch.setenv("YASHIGANI_LICENSE_FILE", str(lic_path))

        from yashigani.licensing.loader import load_license
        result = load_license()
        assert result.tier == LicenseTier.COMMUNITY
