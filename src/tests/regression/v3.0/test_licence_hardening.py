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
# Test 7: KDF token is deterministic
# ---------------------------------------------------------------------------

class TestKdfTokenDeterministic(unittest.TestCase):
    def test_kdf_token_community_derivation_deterministic(self):
        """T7: Same inputs → same token on repeated calls."""
        from yashigani.licensing.verifier import _derive_integrity_token

        token1 = _derive_integrity_token("bundle", "", "20,5,2")
        token2 = _derive_integrity_token("bundle", "", "20,5,2")
        self.assertEqual(token1, token2)
        self.assertEqual(len(token1), 32)


# ---------------------------------------------------------------------------
# Test 8: KDF token differs when seat_policy changes
# ---------------------------------------------------------------------------

class TestKdfTokenNoCaFingerprint(unittest.TestCase):
    def test_kdf_token_no_ca_fingerprint_input(self):
        """DG-01: Different seat_policy → different token (no CA fingerprint in inputs)."""
        from yashigani.licensing.verifier import _derive_integrity_token

        token_community = _derive_integrity_token("bundle", "", "20,5,2")
        token_different = _derive_integrity_token("bundle", "", "5,5,2")
        self.assertNotEqual(token_community, token_different)


# ---------------------------------------------------------------------------
# Test 9: bundle attestation with bad sig sets violation flag
# ---------------------------------------------------------------------------

class TestBundleAttestationBadSig(unittest.TestCase):
    def test_bundle_attestation_bad_sig_sets_flag(self):
        """T6: Bad HASH_BUNDLE_SIG with no placeholder → _integrity_violated = True."""
        import yashigani.licensing.verifier as verifier
        import yashigani.licensing._integrity as _integrity

        original_violated = verifier._integrity_violated

        # Save original values
        orig_bundle_sig = _integrity.HASH_BUNDLE_SIG
        orig_verifier_hash = _integrity.VERIFIER_HASH
        orig_enforcer_hash = _integrity.ENFORCER_HASH
        orig_loader_hash = _integrity.LOADER_HASH
        orig_integrity_hash = _integrity.INTEGRITY_HASH
        orig_agents_hash = _integrity.AGENTS_REGISTRY_HASH
        orig_identity_hash = _integrity.IDENTITY_REGISTRY_HASH
        orig_counter_key = _integrity.COUNTER_PUBLIC_KEY_PEM

        try:
            # Set non-placeholder values (fake hashes and a bad sig)
            _integrity.HASH_BUNDLE_SIG = "deadbeef" * 8  # 64-char hex, not a real sig
            _integrity.VERIFIER_HASH = "a" * 64
            _integrity.ENFORCER_HASH = "b" * 64
            _integrity.LOADER_HASH = "c" * 64
            _integrity.INTEGRITY_HASH = "d" * 64
            _integrity.AGENTS_REGISTRY_HASH = "e" * 64
            _integrity.IDENTITY_REGISTRY_HASH = "f" * 64
            # Counter key is real PEM from verifier.py
            _integrity.COUNTER_PUBLIC_KEY_PEM = verifier._PUBLIC_KEY_PEM
            verifier._integrity_violated = False

            verifier._check_hash_bundle_attestation()
            self.assertTrue(verifier._integrity_violated)
        finally:
            verifier._integrity_violated = original_violated
            _integrity.HASH_BUNDLE_SIG = orig_bundle_sig
            _integrity.VERIFIER_HASH = orig_verifier_hash
            _integrity.ENFORCER_HASH = orig_enforcer_hash
            _integrity.LOADER_HASH = orig_loader_hash
            _integrity.INTEGRITY_HASH = orig_integrity_hash
            _integrity.AGENTS_REGISTRY_HASH = orig_agents_hash
            _integrity.IDENTITY_REGISTRY_HASH = orig_identity_hash
            _integrity.COUNTER_PUBLIC_KEY_PEM = orig_counter_key


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


if __name__ == "__main__":
    unittest.main()
