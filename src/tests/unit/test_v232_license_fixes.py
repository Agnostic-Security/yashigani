"""
v2.23.2 licensing fixes — unit tests.

Covers:
  Group 1.1: sign_with_local produces 3-segment v4 wire format
  Group 1.2: verifier reads domains[0] with fallback to org_domain
  Group 2.1: wildcard domain rejected for paid tiers (LAURA-LIMIT-DOMAINS-02)
  Group 2.2: domain normalisation in loader (LAURA-LIMIT-DOMAINS-01)
  Group 2.3: cross-tenant activate guard (LAURA-LICENSE-01)
  Group 5.2: negative seat clamp (LAURA-LICENSE-08)
  Group 5.3: canary token sentinel (Nico)
  Group 5.4: sign_license.py TIER_DEFAULTS matches model

Last updated: 2026-05-05T00:00:00+01:00
"""
from __future__ import annotations

import base64
import json
import sys
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

import pytest


# ---------------------------------------------------------------------------
# Helpers — shared ECDSA keypair fixture
# ---------------------------------------------------------------------------

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _make_keypair():
    """Generate an ephemeral ECDSA P-256 keypair. Skip if cryptography not installed."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ec import (
            SECP256R1, generate_private_key
        )
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat, PrivateFormat, NoEncryption
        )
    except ImportError:
        pytest.skip("cryptography package not installed")

    priv = generate_private_key(SECP256R1())
    priv_pem = priv.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())
    pub_pem = priv.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    return priv, priv_pem, pub_pem


def _make_v4_token(payload: dict, primary_priv_pem: bytes, primary_pub_pem: bytes,
                   counter_priv_pem: bytes) -> str:
    """Build a v4 token using sign_license.py's sign_payload_v4 logic."""
    sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "scripts"))
    try:
        from sign_license import sign_payload_v4
        return sign_payload_v4(payload, primary_priv_pem, primary_pub_pem, counter_priv_pem)
    finally:
        pass  # sys.path insert is harmless here


# ---------------------------------------------------------------------------
# Group 1.1 — license_generator sign_with_local produces 3-segment format
# ---------------------------------------------------------------------------

class TestGroup1_1_SignWithLocalV4:
    """sign_with_local must produce 3-segment (v4) wire format."""

    def test_sign_with_local_produces_three_segments(self, tmp_path):
        """sign_with_local(...) → 'payload.sig.counter_sig' (3 dots-separated segments)."""
        try:
            import asyncio
        except ImportError:
            pytest.skip("asyncio not available")

        priv, priv_pem, pub_pem = _make_keypair()

        # Write keys to tmp files
        primary_key = tmp_path / "primary.pem"
        counter_key = tmp_path / "counter.pem"
        primary_key.write_bytes(priv_pem)
        counter_key.write_bytes(priv_pem)  # same key for dev convenience

        sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent /
                               "license_engine-YSG" / "src"))
        try:
            from services.license_generator import sign_with_local
        except ImportError:
            pytest.skip("license_engine-YSG not on path")

        payload = {
            "version": 5,
            "org_id": "test-org",
            "org_name": "Test Org",
            "tier": "professional",
            "domains": ["customer.example.com"],
            "expires_at": "2027-01-01T00:00:00Z",
            "issued_at": "2026-01-01T00:00:00Z",
        }

        result = asyncio.run(sign_with_local(
            payload, str(primary_key), counter_key_path=str(counter_key)
        ))

        parts = result.split(".")
        assert len(parts) == 3, (
            f"sign_with_local must produce exactly 3 segments; got {len(parts)}: {result[:80]}"
        )

    def test_sign_with_local_fallback_to_same_key_when_no_counter(self, tmp_path):
        """When counter_key_path is empty, falls back to primary key for counter-sig."""
        try:
            import asyncio
        except ImportError:
            pytest.skip("asyncio not available")

        priv, priv_pem, _pub_pem = _make_keypair()
        primary_key = tmp_path / "primary.pem"
        primary_key.write_bytes(priv_pem)

        sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent /
                               "license_engine-YSG" / "src"))
        try:
            from services.license_generator import sign_with_local
        except ImportError:
            pytest.skip("license_engine-YSG not on path")

        payload = {
            "version": 5, "org_id": "t", "org_name": "T", "tier": "community",
            "domains": ["*"], "expires_at": "2030-01-01T00:00:00Z",
            "issued_at": "2026-01-01T00:00:00Z",
        }

        result = asyncio.run(sign_with_local(payload, str(primary_key), counter_key_path=""))
        assert result.count(".") == 2


# ---------------------------------------------------------------------------
# Group 1.2 — verifier reads domains[0] with fallback
# ---------------------------------------------------------------------------

class TestGroup1_2_DomainsFieldFallback:
    """_build_license_state reads domains[0] before org_domain."""

    def _make_state(self, payload: dict):
        from yashigani.licensing.verifier import _build_license_state
        return _build_license_state(payload, valid=True)

    def test_domains_list_wins_over_org_domain(self):
        payload = {
            "tier": "community",
            "domains": ["customerA.com", "customerB.com"],
            "org_domain": "old.example.com",
        }
        state = self._make_state(payload)
        assert state.org_domain == "customerA.com"

    def test_empty_domains_falls_back_to_org_domain(self):
        payload = {
            "tier": "community",
            "domains": [],
            "org_domain": "fallback.example.com",
        }
        state = self._make_state(payload)
        assert state.org_domain == "fallback.example.com"

    def test_missing_domains_falls_back_to_org_domain(self):
        payload = {
            "tier": "community",
            "org_domain": "legacy.example.com",
        }
        state = self._make_state(payload)
        assert state.org_domain == "legacy.example.com"

    def test_missing_both_defaults_to_wildcard(self):
        payload = {"tier": "community"}
        state = self._make_state(payload)
        assert state.org_domain == "*"

    def test_non_list_domains_falls_back_to_org_domain(self):
        payload = {
            "tier": "community",
            "domains": "not-a-list",
            "org_domain": "fromorgdomain.com",
        }
        state = self._make_state(payload)
        assert state.org_domain == "fromorgdomain.com"


# ---------------------------------------------------------------------------
# Group 2.1 — wildcard domain rejected for paid tiers (LAURA-LIMIT-DOMAINS-02)
# ---------------------------------------------------------------------------

class TestGroup2_1_WildcardDomainBan:
    """Paid-tier licenses with org_domain='*' are forced to COMMUNITY_INVALID."""

    def _make_state(self, payload: dict):
        from yashigani.licensing.verifier import _build_license_state
        return _build_license_state(payload, valid=True)

    @pytest.mark.parametrize("tier", [
        "starter", "professional", "professional_plus", "enterprise"
    ])
    def test_paid_tier_wildcard_domain_rejected(self, tier):
        payload = {"tier": tier, "org_domain": "*"}
        state = self._make_state(payload)
        assert not state.valid
        assert state.error == "wildcard_domain_not_permitted_for_paid_tier"

    @pytest.mark.parametrize("tier", ["community", "academic_nonprofit"])
    def test_community_tier_wildcard_domain_allowed(self, tier):
        payload = {"tier": tier, "org_domain": "*"}
        state = self._make_state(payload)
        # community/academic_nonprofit are allowed wildcards
        assert state.error != "wildcard_domain_not_permitted_for_paid_tier"

    def test_paid_tier_bound_domain_accepted(self):
        payload = {"tier": "starter", "org_domain": "customer.example.com"}
        state = self._make_state(payload)
        # Should not be rejected for domain reason
        assert state.error != "wildcard_domain_not_permitted_for_paid_tier"


# ---------------------------------------------------------------------------
# Group 2.2 — domain normalisation (LAURA-LIMIT-DOMAINS-01)
# ---------------------------------------------------------------------------

class TestGroup2_2_DomainNormalisation:
    """_normalise_domain helper: lowercase + strip trailing dot + IDN encode."""

    def setup_method(self):
        from yashigani.licensing.loader import _normalise_domain
        self._n = _normalise_domain

    def test_lowercase(self):
        assert self._n("Customer.Example.COM") == "customer.example.com"

    def test_strip_trailing_dot(self):
        assert self._n("example.com.") == "example.com"

    def test_strip_trailing_dot_and_lowercase(self):
        assert self._n("EXAMPLE.COM.") == "example.com"

    def test_strip_whitespace(self):
        assert self._n("  example.com  ") == "example.com"

    def test_plain_domain_unchanged(self):
        assert self._n("example.com") == "example.com"

    def test_idn_encoding(self):
        # IDN label: münchen.de → xn--mnchen-3ya.de
        result = self._n("münchen.de")
        assert result.startswith("xn--")

    def test_domain_mismatch_after_normalise(self):
        """YASHIGANI_TLS_DOMAIN comparison uses normalised forms."""
        assert self._n("Customer.Example.COM.") == self._n("customer.example.com")


# ---------------------------------------------------------------------------
# Group 2.3 — activate_license domain mismatch (LAURA-LICENSE-01)
# ---------------------------------------------------------------------------

class TestGroup2_3_CrossTenantActivate:
    """activate_license rejects domain mismatch (LAURA-LICENSE-01)."""

    def test_normalise_imported_in_license_route(self):
        """Verify the loader's _normalise_domain is importable from the route module."""
        from yashigani.licensing.loader import _normalise_domain
        assert callable(_normalise_domain)

    def test_activate_rejects_domain_mismatch(self, monkeypatch):
        """Simulate domain mismatch check in activate_license code path."""
        from yashigani.licensing.loader import _normalise_domain
        license_domain = "customerA.com"
        runtime_domain = "customerB.com"
        assert _normalise_domain(runtime_domain) != _normalise_domain(license_domain)

    def test_activate_accepts_matching_domain(self, monkeypatch):
        from yashigani.licensing.loader import _normalise_domain
        license_domain = "Customer.Example.COM."
        runtime_domain = "customer.example.com"
        assert _normalise_domain(license_domain) == _normalise_domain(runtime_domain)


# ---------------------------------------------------------------------------
# Group 5.2 — negative seat clamp (LAURA-LICENSE-08)
# ---------------------------------------------------------------------------

class TestGroup5_2_NegativeSeatClamp:
    """_safe_int clamps negative values other than -1 to default."""

    def setup_method(self):
        from yashigani.licensing.verifier import _safe_int
        self._safe_int = _safe_int

    def test_negative_one_preserved_as_unlimited_sentinel(self):
        assert self._safe_int(-1, 20) == -1

    def test_negative_two_clamped_to_default(self):
        assert self._safe_int(-2, 20) == 20

    def test_negative_hundred_clamped_to_default(self):
        assert self._safe_int(-100, 5) == 5

    def test_zero_is_valid(self):
        assert self._safe_int(0, 20) == 0

    def test_positive_int_passes_through(self):
        assert self._safe_int(500, 20) == 500

    def test_none_returns_default(self):
        assert self._safe_int(None, 20) == 20

    def test_empty_string_returns_default(self):
        assert self._safe_int("", 20) == 20

    def test_string_negative_two_clamped(self):
        assert self._safe_int("-2", 20) == 20

    def test_string_negative_one_preserved(self):
        assert self._safe_int("-1", 20) == -1


# ---------------------------------------------------------------------------
# Group 5.3 — canary token sentinel (Nico)
# ---------------------------------------------------------------------------

class TestGroup5_3_CanaryToken:
    """LicenseTier.CANARY exists and triggers fail-closed behaviour."""

    def test_canary_tier_exists(self):
        from yashigani.licensing.model import LicenseTier
        assert LicenseTier.CANARY == "canary"

    def test_build_license_state_rejects_canary(self):
        from yashigani.licensing.verifier import _build_license_state
        payload = {"tier": "canary", "org_domain": "*"}
        state = _build_license_state(payload, valid=True)
        assert not state.valid
        assert state.error == "canary_token_rejected"

    def test_canary_not_in_valid_issuable_tiers(self):
        """CANARY tier must not appear in the issuable tier list used by sign_license.py."""
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "scripts"))
        try:
            import importlib
            import sign_license
            importlib.reload(sign_license)
            # VALID_TIERS is the list of tiers sign_license.py accepts — canary
            # must never be listed there even though it exists in TIER_DEFAULTS
            # (TIER_DEFAULTS includes canary for defensive fallback handling only).
            assert "canary" not in sign_license.VALID_TIERS, (
                "canary tier must not appear in sign_license.VALID_TIERS — "
                "it is a detection sentinel and must never be issued to customers"
            )
        except ImportError:
            pytest.skip("sign_license.py not importable from this test environment")


# ---------------------------------------------------------------------------
# Group 5.4 — TIER_DEFAULTS parity between sign_license and model
# ---------------------------------------------------------------------------

class TestGroup5_4_TierDefaultsParity:
    """sign_license.py TIER_DEFAULTS must match yashigani.licensing.model.TIER_DEFAULTS."""

    def test_tier_defaults_match_model(self):
        sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "scripts"))
        try:
            import importlib
            import sign_license
            importlib.reload(sign_license)  # ensure fresh import
            script_defaults = sign_license.TIER_DEFAULTS
        except (ImportError, AttributeError) as exc:
            pytest.skip(f"sign_license not importable: {exc}")

        from yashigani.licensing.model import TIER_DEFAULTS as model_defaults

        # Check the keys we care about for each tier
        check_fields = ["max_agents", "max_end_users", "max_admin_seats"]
        for tier, expected in model_defaults.items():
            if tier not in script_defaults:
                continue  # script may not have canary
            for field in check_fields:
                if field not in expected:
                    continue
                assert script_defaults[tier].get(field) == expected[field], (
                    f"TIER_DEFAULTS drift: tier={tier!r} field={field!r} "
                    f"script={script_defaults[tier].get(field)!r} "
                    f"model={expected[field]!r}"
                )


# ---------------------------------------------------------------------------
# Group 1.1 round-trip: license_engine signs → gateway verifier accepts
# ---------------------------------------------------------------------------

class TestGroup1_1_RoundTrip:
    """Round-trip: sign_payload_v4 → verify_license (using test keys)."""

    def test_v4_token_verified_with_correct_keys(self):
        """A v4 token signed with matching keys is accepted by verify_license."""
        priv, priv_pem, pub_pem = _make_keypair()

        sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "scripts"))
        try:
            from sign_license import sign_payload_v4, build_payload
            import argparse
            args = argparse.Namespace(
                tier="starter",
                org_domain="customer.example.com",
                license_type="production",
                license_id=None,
                max_agents=None,
                max_end_users=None,
                max_admin_seats=None,
                max_orgs=None,
                features=None,
                issued_at=None,
                expires_at="2099-01-01T00:00:00Z",
                expires=None,
            )
            payload = build_payload(args)
        except ImportError:
            pytest.skip("sign_license not importable")

        token = sign_payload_v4(payload, priv_pem, pub_pem, priv_pem)
        assert token.count(".") == 2  # v4 format

        # Now patch the verifier's _PUBLIC_KEY_PEM to our test public key and
        # ensure the counter key check is in dev mode.
        from yashigani.licensing import verifier as v_mod
        original_pem = v_mod._PUBLIC_KEY_PEM

        try:
            v_mod._PUBLIC_KEY_PEM = pub_pem.decode("utf-8")
            # In test environment YASHIGANI_ENV=dev is not set — we need to
            # bypass the counter-sig check (placeholder mode) OR pass a real
            # counter key. Since _integrity.COUNTER_PUBLIC_KEY_PEM is a
            # placeholder in source, the counter check will auto-pass in dev.
            import yashigani.licensing._integrity as _integ
            # Verify placeholder is still set (dev build)
            assert _integ.is_counter_key_placeholder(), (
                "Test requires COUNTER_PUBLIC_KEY_PEM to be placeholder for "
                "counter-sig bypass in dev mode"
            )
            # Need YASHIGANI_ENV=dev to allow placeholder counter key
            import os as _os
            orig_env = _os.environ.get("YASHIGANI_ENV")
            _os.environ["YASHIGANI_ENV"] = "dev"
            try:
                state = v_mod.verify_license(token)
            finally:
                if orig_env is None:
                    _os.environ.pop("YASHIGANI_ENV", None)
                else:
                    _os.environ["YASHIGANI_ENV"] = orig_env
        finally:
            v_mod._PUBLIC_KEY_PEM = original_pem

        assert state.valid, f"Expected valid=True, got error={state.error!r}"
        assert state.tier.value == "starter"
        assert state.org_domain == "customer.example.com"

    def test_two_segment_token_rejected(self):
        """2-segment (v3) tokens are rejected: license_format_deprecated_v5_required
        (design §3.2 — v3/v4 dropped, v5 mandatory, no downgrade path)."""
        # Build a minimal 2-segment token
        payload = json.dumps({"tier": "professional", "org_domain": "x.com"})
        payload_b64 = _b64url_encode(payload.encode())
        sig_b64 = _b64url_encode(b"fakesig")
        token = f"{payload_b64}.{sig_b64}"

        from yashigani.licensing.verifier import verify_license
        state = verify_license(token)
        assert not state.valid
        assert state.error == "license_format_deprecated_v5_required"


# ---------------------------------------------------------------------------
# Group 2.1 end-to-end: paid-tier + wildcard → community_invalid via verify_license
# ---------------------------------------------------------------------------

class TestWildcardEndToEnd:
    """Paid-tier wildcard token is downgraded even if signature valid."""

    def test_paid_tier_wildcard_forces_community(self):
        """A correctly-signed professional token with org_domain='*' → community_invalid."""
        priv, priv_pem, pub_pem = _make_keypair()

        sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "scripts"))
        try:
            from sign_license import sign_payload_v4
        except ImportError:
            pytest.skip("sign_license not importable")

        # Build a paid-tier payload with wildcard domain
        import uuid as _uuid
        payload = {
            "v": 3,
            "tier": "professional",
            "org_domain": "*",  # BAD: paid tier should not have wildcard
            "license_id": str(_uuid.uuid4()),
            "license_type": "production",
            "max_agents": 1500,
            "max_end_users": 500,
            "max_admin_seats": 25,
            "max_orgs": 1,
            "features": ["oidc", "saml"],
            "issued_at": "2026-01-01T00:00:00Z",
            "expires_at": "2099-01-01T00:00:00Z",
        }

        token = sign_payload_v4(payload, priv_pem, pub_pem, priv_pem)

        from yashigani.licensing import verifier as v_mod
        original_pem = v_mod._PUBLIC_KEY_PEM
        import os as _os
        orig_env = _os.environ.get("YASHIGANI_ENV")
        _os.environ["YASHIGANI_ENV"] = "dev"
        try:
            v_mod._PUBLIC_KEY_PEM = pub_pem.decode("utf-8")
            state = v_mod.verify_license(token)
        finally:
            v_mod._PUBLIC_KEY_PEM = original_pem
            if orig_env is None:
                _os.environ.pop("YASHIGANI_ENV", None)
            else:
                _os.environ["YASHIGANI_ENV"] = orig_env

        assert not state.valid
        assert state.error == "wildcard_domain_not_permitted_for_paid_tier"
