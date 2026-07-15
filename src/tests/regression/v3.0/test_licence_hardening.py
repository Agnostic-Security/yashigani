"""
Regression tests for licence-hardening T1–T15.

All tests use mocks — no Redis/Postgres required.
"""
from __future__ import annotations

import hashlib
import sys
import types
import unittest
from dataclasses import dataclass, field
from typing import Optional
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Test 1: enforcer integrity flag → COMMUNITY_LICENSE
# ---------------------------------------------------------------------------

class TestEnforcerIntegrityViolation(unittest.TestCase):
    def test_restrain_to_community_on_enforcer_integrity_violation(self):
        """T1/T5: _enforcer_integrity_violated=True → get_license() returns COMMUNITY_LICENSE."""
        import yashigani.licensing.enforcer as enforcer
        from yashigani.licensing.model import COMMUNITY_LICENSE, LicenseTier, LicenseState
        from datetime import datetime, timezone

        # Set up a non-community license
        non_community = LicenseState(
            tier=LicenseTier.STARTER,
            org_domain="test.com",
            max_agents=10,
            max_end_users=100,
            max_admin_seats=5,
            max_orgs=1,
            features=frozenset(),
            issued_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            expires_at=None,
            license_id="test-123",
            valid=True,
            error=None,
        )
        original_license = enforcer._license
        original_violated = enforcer._enforcer_integrity_violated
        try:
            enforcer._license = non_community
            enforcer._enforcer_integrity_violated = True
            result = enforcer.get_license()
            self.assertEqual(result.tier, LicenseTier.COMMUNITY)
        finally:
            enforcer._license = original_license
            enforcer._enforcer_integrity_violated = original_violated


# ---------------------------------------------------------------------------
# Test 2: verifier integrity flag → COMMUNITY_LICENSE
# ---------------------------------------------------------------------------

class TestVerifierIntegrityViolation(unittest.TestCase):
    def test_restrain_to_community_on_verifier_integrity_violation(self):
        """T5: verifier._integrity_violated=True → get_license() returns COMMUNITY_LICENSE."""
        import yashigani.licensing.enforcer as enforcer
        import yashigani.licensing.verifier as verifier
        from yashigani.licensing.model import COMMUNITY_LICENSE, LicenseTier, LicenseState
        from datetime import datetime, timezone

        non_community = LicenseState(
            tier=LicenseTier.STARTER,
            org_domain="test.com",
            max_agents=10,
            max_end_users=100,
            max_admin_seats=5,
            max_orgs=1,
            features=frozenset(),
            issued_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            expires_at=None,
            license_id="test-456",
            valid=True,
            error=None,
        )
        original_license = enforcer._license
        original_verifier_violated = verifier._integrity_violated
        try:
            enforcer._license = non_community
            verifier._integrity_violated = True
            result = enforcer.get_license()
            self.assertEqual(result.tier, LicenseTier.COMMUNITY)
        finally:
            enforcer._license = original_license
            verifier._integrity_violated = original_verifier_violated


# ---------------------------------------------------------------------------
# Test 3: loader integrity flag → COMMUNITY_LICENSE
# ---------------------------------------------------------------------------

class TestLoaderIntegrityViolation(unittest.TestCase):
    def test_restrain_to_community_on_loader_integrity_violation(self):
        """T2/T5: loader._loader_integrity_violated=True → get_license() returns COMMUNITY_LICENSE."""
        import yashigani.licensing.enforcer as enforcer
        import yashigani.licensing.loader as loader
        from yashigani.licensing.model import LicenseTier, LicenseState
        from datetime import datetime, timezone

        non_community = LicenseState(
            tier=LicenseTier.STARTER,
            org_domain="test.com",
            max_agents=10,
            max_end_users=100,
            max_admin_seats=5,
            max_orgs=1,
            features=frozenset(),
            issued_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            expires_at=None,
            license_id="test-789",
            valid=True,
            error=None,
        )
        original_license = enforcer._license
        original_loader_violated = loader._loader_integrity_violated
        try:
            enforcer._license = non_community
            loader._loader_integrity_violated = True
            result = enforcer.get_license()
            self.assertEqual(result.tier, LicenseTier.COMMUNITY)
        finally:
            enforcer._license = original_license
            loader._loader_integrity_violated = original_loader_violated


# ---------------------------------------------------------------------------
# Test 4: grace_period fail-safe raises GatewayBlockedError
# ---------------------------------------------------------------------------

class TestGracePeriodFailSafe(unittest.TestCase):
    def test_grace_period_fail_safe_raises_blocked(self):
        """T9 (LAURA-P6-FIX): Exception in get_license() → GatewayBlockedError raised."""
        from yashigani.licensing.grace_period import check_gateway_access, GatewayBlockedError

        with patch("yashigani.licensing.enforcer.get_license", side_effect=Exception("import failed")):
            with self.assertRaises(GatewayBlockedError):
                check_gateway_access(method="GET", path="/v1/chat/completions")


# ---------------------------------------------------------------------------
# Test 5: set_license emits audit event
# ---------------------------------------------------------------------------

class TestSetLicenseAuditEmit(unittest.TestCase):
    def test_set_license_emits_audit_event(self):
        """T8: set_license() emits LicenceStateSetEvent when audit writer available."""
        from yashigani.licensing.model import COMMUNITY_LICENSE
        from yashigani.audit.schema import LicenceStateSetEvent
        import yashigani.licensing.enforcer as enforcer

        mock_writer = MagicMock()

        # Patch the backoffice_state attribute directly in the module
        import yashigani.backoffice.state as bos
        original_state = getattr(bos, 'backoffice_state', None)
        mock_state = MagicMock()
        mock_state.audit_writer = mock_writer
        try:
            bos.backoffice_state = mock_state
            enforcer.set_license(COMMUNITY_LICENSE)
        finally:
            if original_state is not None:
                bos.backoffice_state = original_state

        mock_writer.write.assert_called_once()
        call_event = mock_writer.write.call_args[0][0]
        self.assertIsInstance(call_event, LicenceStateSetEvent)


# ---------------------------------------------------------------------------
# Test 6: LicenceIntegrityViolationEvent excludes _internal_classification
# ---------------------------------------------------------------------------

class TestLicenceIntegrityViolationEventToDict(unittest.TestCase):
    def test_licence_integrity_violation_event_excludes_internal_classification(self):
        """DG-02: to_dict() must NOT include _internal_classification."""
        from yashigani.audit.schema import LicenceIntegrityViolationEvent

        event = LicenceIntegrityViolationEvent(
            module="test",
            check_type="self_hash",
            expected_hash="abc123",
            actual_hash="def456",
        )
        event._internal_classification = "crude_patch"

        d = event.to_dict()
        self.assertNotIn("_internal_classification", d)
        self.assertEqual(d["module"], "test")
        self.assertEqual(d["check_type"], "self_hash")


# ---------------------------------------------------------------------------
# Test 7/8 (superseded): the v1 KDF-gate token (_derive_integrity_token /
# T7 / EXPECTED_TOKEN_HMAC) is REMOVED as of licence-hardening-v2 Phase
# B-CORE — the chain-based build-integrity verify (§4a,
# chain.build_integrity.verify_build_integrity_chain(), wired via
# verifier._check_build_integrity_chain()) supersedes both the old
# HASH_BUNDLE_SIG/counter-key scheme AND the KDF-gate token. See
# TestBuildIntegrityChainBadSig below for the direct replacement regression
# test, and src/tests/unit/test_license_integrity.py::
# TestBuildIntegrityChainPlaceholder for the placeholder/dev/prod coverage
# this class also used to provide.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Test 9 (superseded): bundle attestation with bad sig sets violation flag —
# now via the chain-based build-integrity check (§4a), not the old
# counter-key/HASH_BUNDLE_SIG mechanism.
# ---------------------------------------------------------------------------

class TestBuildIntegrityChainBadSig(unittest.TestCase):
    def test_build_integrity_chain_bad_bundle_sig_sets_flag(self):
        """§4a: a fully-populated chain (real anchor/leaf/leaf_cert_sig) with
        a BUNDLE_SIG that does not verify against the code leaf's own key
        must set _integrity_violated = True. Direct successor to the old T6
        HASH_BUNDLE_SIG test."""
        import base64
        import json
        from datetime import datetime, timedelta, timezone

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        import yashigani.licensing._integrity as _integrity
        import yashigani.licensing.verifier as verifier
        from yashigani.licensing.chain import Alg, LeafCert, Role
        from yashigani.licensing.chain.algorithms import sign_message
        from yashigani.licensing.chain.canonical import bundle_signing_digest, leaf_cert_signing_digest

        def _gen():
            return ec.generate_private_key(ec.SECP384R1())

        def _pem_pub(key):
            return key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode("utf-8")

        original_violated = verifier._integrity_violated

        orig = {
            name: getattr(_integrity, name)
            for name in (
                "VERIFIER_HASH", "ENFORCER_HASH", "LOADER_HASH", "INTEGRITY_HASH",
                "AGENTS_REGISTRY_HASH", "IDENTITY_REGISTRY_HASH",
                "OIDC_MODULE_HASH", "SAML_MODULE_HASH", "SSO_ROUTES_HASH",
                "SCIM_ROUTES_HASH", "GATE_MIDDLEWARE_HASH",
                "MASTER_ANCHOR_SET_JSON", "CODE_LEAF_CERT_JSON", "CODE_LEAF_CERT_SIG",
                "BUNDLE_SIG", "KILL_LIST_JSON",
            )
        }

        try:
            _integrity.VERIFIER_HASH = "a" * 64
            _integrity.ENFORCER_HASH = "b" * 64
            _integrity.LOADER_HASH = "c" * 64
            _integrity.INTEGRITY_HASH = "d" * 64
            _integrity.AGENTS_REGISTRY_HASH = "e" * 64
            _integrity.IDENTITY_REGISTRY_HASH = "f" * 64
            # POU hashes (LAURA-V2-001 follow-up, 2026-07-16) — arbitrary
            # non-placeholder values, same rationale as the T1-T4 hashes
            # above (this test exercises BUNDLE_SIG failure, not module-hash
            # matching; all that matters is is_any_hash_placeholder() is False
            # so the check reaches the signature verification).
            _integrity.OIDC_MODULE_HASH = "1" * 64
            _integrity.SAML_MODULE_HASH = "2" * 64
            _integrity.SSO_ROUTES_HASH = "3" * 64
            _integrity.SCIM_ROUTES_HASH = "4" * 64
            _integrity.GATE_MIDDLEWARE_HASH = "5" * 64

            now = datetime.now(timezone.utc)
            master_key = _gen()
            code_key = _gen()
            code_leaf = LeafCert(
                role=Role.CODE, client_id="*", release="4.1.1", leaf_pubkey_pem=_pem_pub(code_key),
                not_before=now - timedelta(days=1), not_after=now + timedelta(days=60),
                serial="code-leaf-4.1.1", signed_at=now, alg=Alg.ECDSA_P384_SHA384,
            )
            code_leaf_sig = sign_message(
                Alg.ECDSA_P384_SHA384, master_key, leaf_cert_signing_digest(code_leaf.to_canonical_dict())
            )
            _integrity.MASTER_ANCHOR_SET_JSON = json.dumps([{
                "anchor_id": "M1", "pubkey_pem": _pem_pub(master_key),
                "alg": Alg.ECDSA_P384_SHA384.value, "status": "active", "added": now.isoformat(),
            }])
            _integrity.CODE_LEAF_CERT_JSON = json.dumps(code_leaf.to_canonical_dict())
            _integrity.CODE_LEAF_CERT_SIG = base64.b64encode(code_leaf_sig).decode()
            # BUNDLE_SIG signed by a DIFFERENT key — must fail against code_leaf's key.
            rogue_key = _gen()
            bad_sig = sign_message(Alg.ECDSA_P384_SHA384, rogue_key, bundle_signing_digest("garbage"))
            _integrity.BUNDLE_SIG = base64.b64encode(bad_sig).decode()
            _integrity.KILL_LIST_JSON = "[]"

            verifier._integrity_violated = False
            verifier._check_build_integrity_chain()
            self.assertTrue(verifier._integrity_violated)
        finally:
            verifier._integrity_violated = original_violated
            for name, value in orig.items():
                setattr(_integrity, name, value)


# ---------------------------------------------------------------------------
# Test 10: admin_select_active rejects over-limit
# ---------------------------------------------------------------------------

class TestAdminSelectLuaRejectOverLimit(unittest.TestCase):
    def test_admin_select_lua_reject_over_limit(self):
        """T14: admin_select_active() with keep_ids > max_end_users → LicenseLimitExceeded."""
        from yashigani.identity.registry import IdentityRegistry
        from yashigani.licensing.enforcer import LicenseLimitExceeded

        mock_redis = MagicMock()
        # Simulate Redis returning LIMIT_EXCEEDED error
        mock_redis.scard.return_value = 0
        mock_redis.eval.side_effect = Exception("LIMIT_EXCEEDED:6:5")

        registry = IdentityRegistry.__new__(IdentityRegistry)
        registry._r = mock_redis

        with patch("yashigani.licensing.enforcer.get_license") as mock_get_lic:
            from yashigani.licensing.model import COMMUNITY_LICENSE
            lic = MagicMock()
            lic.max_end_users = 5
            mock_get_lic.return_value = lic

            with self.assertRaises(LicenseLimitExceeded):
                registry.admin_select_active(["a", "b", "c", "d", "e", "f"])


# ---------------------------------------------------------------------------
# Test 11: auto_suspend_excess suspends most-recent
# ---------------------------------------------------------------------------

class TestAutoSuspendExcess(unittest.TestCase):
    def test_auto_suspend_excess_suspends_most_recent(self):
        """T14: auto_suspend_excess(max_keep=2) with 3 active humans suspends newest one."""
        from yashigani.identity.registry import IdentityRegistry

        mock_redis = MagicMock()

        # 3 active human identities
        mock_redis.smembers.return_value = {b"idnt_aaa", b"idnt_bbb", b"idnt_ccc"}

        def hget_side_effect(key, field):
            data = {
                "identity:reg:idnt_aaa": {"created_at": "2026-01-01T00:00:00+00:00", "status": "active"},
                "identity:reg:idnt_bbb": {"created_at": "2026-06-01T00:00:00+00:00", "status": "active"},
                "identity:reg:idnt_ccc": {"created_at": "2026-06-15T00:00:00+00:00", "status": "active"},
            }
            val = data.get(key, {}).get(field, "")
            return val.encode() if isinstance(val, str) and val else None

        mock_redis.hget.side_effect = hget_side_effect
        # admin_select_active will call eval — mock to return [1, 0] (suspended 1)
        mock_redis.eval.return_value = [1, 0]

        registry = IdentityRegistry.__new__(IdentityRegistry)
        registry._r = mock_redis

        with patch("yashigani.licensing.enforcer.get_license") as mock_get_lic:
            lic = MagicMock()
            lic.max_end_users = 5
            mock_get_lic.return_value = lic

            result = registry.auto_suspend_excess(max_keep=2)

        # eval should have been called; keep_ids should contain the 2 most recent
        # (idnt_ccc 2026-06-15 and idnt_bbb 2026-06-01) and NOT idnt_aaa (2026-01-01)
        self.assertTrue(mock_redis.eval.called)
        call_args = mock_redis.eval.call_args[0]
        argv_list = list(call_args)
        # idnt_aaa is the OLDEST — sorted desc → index 2 → excluded when max_keep=2
        self.assertNotIn("idnt_aaa", argv_list)
        # idnt_ccc is the NEWEST — kept (most recent first, max_keep=2)
        self.assertIn("idnt_ccc", argv_list)


# ---------------------------------------------------------------------------
# Test 12: LicenceStateSetEvent structure
# ---------------------------------------------------------------------------

class TestLicenceStateSetEventStructure(unittest.TestCase):
    def test_licence_state_set_event_structure(self):
        """T11: LicenceStateSetEvent to_dict() has correct event_type."""
        from yashigani.audit.schema import LicenceStateSetEvent

        event = LicenceStateSetEvent(
            tier="community",
            org_domain="*",
            license_id="",
            caller_module="loader",
        )
        d = event.to_dict()
        self.assertEqual(d["event_type"], "LICENSE_STATE_SET")
        self.assertEqual(d["tier"], "community")
        self.assertEqual(d["org_domain"], "*")
        self.assertEqual(d["caller_module"], "loader")


# ---------------------------------------------------------------------------
# Test 13: agents/registry integrity flag → COMMUNITY_LICENSE (T3)
# ---------------------------------------------------------------------------

class TestAgentsRegistryIntegrityViolation(unittest.TestCase):
    def test_restrain_to_community_on_agents_registry_integrity_violation(self):
        """T3/T5: agents/registry._agents_registry_integrity_violated=True → COMMUNITY_LICENSE."""
        import yashigani.licensing.enforcer as enforcer
        import yashigani.agents.registry as agents_registry
        from yashigani.licensing.model import LicenseTier, LicenseState
        from datetime import datetime, timezone

        non_community = LicenseState(
            tier=LicenseTier.STARTER,
            org_domain="test.com",
            max_agents=10,
            max_end_users=100,
            max_admin_seats=5,
            max_orgs=1,
            features=frozenset(),
            issued_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            expires_at=None,
            license_id="test-t3",
            valid=True,
            error=None,
        )
        original_license = enforcer._license
        original_violated = agents_registry._agents_registry_integrity_violated
        try:
            enforcer._license = non_community
            agents_registry._agents_registry_integrity_violated = True
            result = enforcer.get_license()
            self.assertEqual(result.tier, LicenseTier.COMMUNITY)
        finally:
            enforcer._license = original_license
            agents_registry._agents_registry_integrity_violated = original_violated

    def test_agents_registry_hash_mismatch_sets_flag(self):
        """T3: _check_agents_registry_integrity() with wrong hash sets violated flag."""
        import yashigani.agents.registry as agents_registry
        import yashigani.licensing._integrity as _integrity

        original_violated = agents_registry._agents_registry_integrity_violated
        orig_hash = _integrity.AGENTS_REGISTRY_HASH
        try:
            agents_registry._agents_registry_integrity_violated = False
            # Set a non-placeholder hash that won't match the file digest
            _integrity.AGENTS_REGISTRY_HASH = "a" * 64
            with patch.dict("os.environ", {"YASHIGANI_ENV": "production"}):
                agents_registry._check_agents_registry_integrity()
            self.assertTrue(agents_registry._agents_registry_integrity_violated)
        finally:
            agents_registry._agents_registry_integrity_violated = original_violated
            _integrity.AGENTS_REGISTRY_HASH = orig_hash


# ---------------------------------------------------------------------------
# Test 14: identity/registry integrity flag → COMMUNITY_LICENSE (T4)
# ---------------------------------------------------------------------------

class TestIdentityRegistryIntegrityViolation(unittest.TestCase):
    def test_restrain_to_community_on_identity_registry_integrity_violation(self):
        """T4/T5: identity/registry._identity_registry_integrity_violated=True → COMMUNITY_LICENSE."""
        import yashigani.licensing.enforcer as enforcer
        import yashigani.identity.registry as identity_registry
        from yashigani.licensing.model import LicenseTier, LicenseState
        from datetime import datetime, timezone

        non_community = LicenseState(
            tier=LicenseTier.STARTER,
            org_domain="test.com",
            max_agents=10,
            max_end_users=100,
            max_admin_seats=5,
            max_orgs=1,
            features=frozenset(),
            issued_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            expires_at=None,
            license_id="test-t4",
            valid=True,
            error=None,
        )
        original_license = enforcer._license
        original_violated = identity_registry._identity_registry_integrity_violated
        try:
            enforcer._license = non_community
            identity_registry._identity_registry_integrity_violated = True
            result = enforcer.get_license()
            self.assertEqual(result.tier, LicenseTier.COMMUNITY)
        finally:
            enforcer._license = original_license
            identity_registry._identity_registry_integrity_violated = original_violated

    def test_identity_registry_hash_mismatch_sets_flag(self):
        """T4: _check_identity_registry_integrity() with wrong hash sets violated flag."""
        import yashigani.identity.registry as identity_registry
        import yashigani.licensing._integrity as _integrity

        original_violated = identity_registry._identity_registry_integrity_violated
        orig_hash = _integrity.IDENTITY_REGISTRY_HASH
        try:
            identity_registry._identity_registry_integrity_violated = False
            # Set a non-placeholder hash that won't match the file digest
            _integrity.IDENTITY_REGISTRY_HASH = "b" * 64
            with patch.dict("os.environ", {"YASHIGANI_ENV": "production"}):
                identity_registry._check_identity_registry_integrity()
            self.assertTrue(identity_registry._identity_registry_integrity_violated)
        finally:
            identity_registry._identity_registry_integrity_violated = original_violated
            _integrity.IDENTITY_REGISTRY_HASH = orig_hash


# ---------------------------------------------------------------------------
# Test 15: IMPL-01 — no runtime YASHIGANI_ENV=dev bypass in v5 chain verify
# ---------------------------------------------------------------------------

class TestNoDevBypassInChainVerification(unittest.TestCase):
    def test_untrusted_leaf_cert_rejected_even_with_dev_env(self):
        """IMPL-01 successor: chain.licence_v5.verify_licence_v5() has NO
        YASHIGANI_ENV branch at all — a licence whose leaf_cert does not
        chain to a trusted anchor must be rejected regardless of
        YASHIGANI_ENV=dev. (The v1 property this superseded was scoped to
        _verify_counter_signature(); the v2 chain design structurally
        removes the class of bug entirely — there is no dev-mode skip
        anywhere in the §4b verify sequence.)"""
        import json
        from datetime import datetime, timedelta, timezone

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        import yashigani.licensing._integrity as _integrity
        import yashigani.licensing.verifier as verifier
        from yashigani.licensing.chain import (
            Alg, LeafCert, PemSigner, Role, build_licence_payload_v5, sign_licence_v5,
        )
        from yashigani.licensing.chain.algorithms import sign_message
        from yashigani.licensing.chain.canonical import leaf_cert_signing_digest

        def _gen():
            return ec.generate_private_key(ec.SECP384R1())

        def _pem_pub(key):
            return key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode("utf-8")

        orig_anchor_set = _integrity.MASTER_ANCHOR_SET_JSON
        orig_violated = verifier._integrity_violated
        try:
            # Embedded anchor set trusts master M1 only.
            m1 = _gen()
            _integrity.MASTER_ANCHOR_SET_JSON = json.dumps([{
                "anchor_id": "M1", "pubkey_pem": _pem_pub(m1),
                "alg": Alg.ECDSA_P384_SHA384.value, "status": "active",
                "added": datetime.now(timezone.utc).isoformat(),
            }])
            verifier._integrity_violated = False

            # Licence signed under a ROGUE master (M2), not in the anchor set.
            m2_rogue = _gen()
            now = datetime.now(timezone.utc)
            licence_key = _gen()
            leaf_cert = LeafCert(
                role=Role.LICENCE, client_id="acme-corp", leaf_pubkey_pem=_pem_pub(licence_key),
                not_before=now - timedelta(days=1), not_after=now + timedelta(days=60),
                serial="lic-leaf-rogue", signed_at=now, alg=Alg.ECDSA_P384_SHA384,
            )
            leaf_cert_sig = sign_message(
                Alg.ECDSA_P384_SHA384, m2_rogue, leaf_cert_signing_digest(leaf_cert.to_canonical_dict())
            )
            payload = build_licence_payload_v5(
                org_domain="acme.example.com", tier="enterprise", client_id="acme-corp",
                licence_serial="lic-0001", max_agents=-1, max_end_users=-1, max_admin_seats=-1,
                max_orgs=-1, expires_at=now + timedelta(days=365),
            )
            signer = PemSigner(role=Role.LICENCE, private_key=licence_key, leaf_cert=leaf_cert)
            wire = sign_licence_v5(payload, signer, leaf_cert, leaf_cert_sig)

            with patch.dict("os.environ", {"YASHIGANI_ENV": "dev"}):
                result = verifier.verify_license(wire)

            # Must NOT be accepted — IMPL-01's "no env-based crypto bypass"
            # property, now structurally enforced (no dev branch exists).
            self.assertFalse(result.valid)
            self.assertEqual(result.error, "leaf_cert_untrusted")
        finally:
            _integrity.MASTER_ANCHOR_SET_JSON = orig_anchor_set
            verifier._integrity_violated = orig_violated


if __name__ == "__main__":
    unittest.main()
