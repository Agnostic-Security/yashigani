"""
W0a — ring-fence audit event type registration tests (v2.25.0 P1).

Verifies:
  1. All 10 new EventType values are registered in the EventType enum.
  2. All 10 new dataclasses are importable from yashigani.audit.
  3. Each dataclass serialises via to_dict() without error.
  4. Each dataclass has masking_applied=True (immutable floor for compliance).
  5. EventType enum is hash-chain consistent (all values are unique strings).
  6. Barrel export in yashigani.audit.__all__ covers all 10 new classes.

Lu-Gap-06 / G3 — AU-2 / AU-12 / CC7.1 compliance precondition.
"""
from __future__ import annotations

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_EXPECTED_EVENT_TYPES = [
    "MANIFEST_ONBOARD",
    "MANIFEST_OFFBOARD",
    "MANIFEST_VALIDATE_FAILED",
    "DYNAMIC_CERT_ISSUED",
    "DYNAMIC_CERT_REVOKED",
    "MCP_CALL",
    "MCP_TOOL_DESCRIPTION_FETCHED",
    "KMS_SECRET_DISTRIBUTED_TO_AGENT",
    "OPA_DECISION_ON_MCP",
    "EGRESS_ALLOW_USED",
]

_EXPECTED_EVENT_TYPE_VALUES = [
    "MANIFEST_ONBOARD",
    "MANIFEST_OFFBOARD",
    "MANIFEST_VALIDATE_FAILED",
    "DYNAMIC_CERT_ISSUED",
    "DYNAMIC_CERT_REVOKED",
    "MCP_CALL",
    "MCP_TOOL_DESCRIPTION_FETCHED",
    "KMS_SECRET_DISTRIBUTED_TO_AGENT",
    "OPA_DECISION_ON_MCP",
    "EGRESS_ALLOW_USED",
]

_EXPECTED_DATACLASS_NAMES = [
    "ManifestOnboardEvent",
    "ManifestOffboardEvent",
    "ManifestValidateFailedEvent",
    "DynamicCertIssuedEvent",
    "DynamicCertRevokedEvent",
    "McpCallEvent",
    "McpToolDescriptionFetchedEvent",
    "KmsSecretDistributedToAgentEvent",
    "OpaDecisionOnMcpEvent",
    "EgressAllowUsedEvent",
]


# ---------------------------------------------------------------------------
# 1. EventType enum contains all 10 new values
# ---------------------------------------------------------------------------

class TestEventTypeRegistration:
    """All 10 event types are registered in EventType (W0a)."""

    def test_all_new_event_types_present(self) -> None:
        from yashigani.audit.schema import EventType
        for name in _EXPECTED_EVENT_TYPES:
            assert hasattr(EventType, name), (
                "EventType.%s not found — W0a registration incomplete" % name
            )

    @pytest.mark.parametrize("name,value", zip(_EXPECTED_EVENT_TYPES, _EXPECTED_EVENT_TYPE_VALUES))
    def test_event_type_value_matches_name(self, name: str, value: str) -> None:
        """Each EventType value string equals its name (convention for audit queries)."""
        from yashigani.audit.schema import EventType
        et = getattr(EventType, name)
        assert et.value == value, (
            "EventType.%s.value == %r, expected %r" % (name, et.value, value)
        )

    def test_all_event_type_values_unique(self) -> None:
        """Merkle hash-chain consistency: all EventType values must be unique strings."""
        from yashigani.audit.schema import EventType
        values = [et.value for et in EventType]
        assert len(values) == len(set(values)), (
            "Duplicate EventType values detected — hash-chain consistency violation"
        )


# ---------------------------------------------------------------------------
# 2. Dataclasses importable from yashigani.audit barrel
# ---------------------------------------------------------------------------

class TestBarrelExport:
    """All 10 new dataclasses are in yashigani.audit.__all__ and importable."""

    def test_all_dataclasses_in_all(self) -> None:
        import yashigani.audit as audit_pkg
        for name in _EXPECTED_DATACLASS_NAMES:
            assert name in audit_pkg.__all__, (
                "%s missing from yashigani.audit.__all__" % name
            )

    @pytest.mark.parametrize("name", _EXPECTED_DATACLASS_NAMES)
    def test_dataclass_importable(self, name: str) -> None:
        import yashigani.audit as audit_pkg
        cls = getattr(audit_pkg, name, None)
        assert cls is not None, (
            "%s not importable from yashigani.audit" % name
        )


# ---------------------------------------------------------------------------
# 3. Serialisation via to_dict()
# ---------------------------------------------------------------------------

class TestEventSerialization:
    """Each event dataclass serialises cleanly via AuditEvent.to_dict()."""

    def test_manifest_onboard_to_dict(self) -> None:
        from yashigani.audit import ManifestOnboardEvent
        ev = ManifestOnboardEvent(
            tenant_id="acme",
            agent_name="goose",
            manifest_sha256="a" * 64,
            operator_identity="alice",
            artifacts_generated=["bridge", "caddy", "opa"],
            runtime="docker",
        )
        d = ev.to_dict()
        assert d["event_type"] == "MANIFEST_ONBOARD"
        assert d["tenant_id"] == "acme"
        assert d["agent_name"] == "goose"
        assert d["masking_applied"] is True

    def test_manifest_offboard_to_dict(self) -> None:
        from yashigani.audit import ManifestOffboardEvent
        ev = ManifestOffboardEvent(
            tenant_id="acme",
            agent_name="goose",
            operator_identity="alice",
            artifacts_removed=["bridge", "caddy"],
            cert_rotation_triggered=True,
        )
        d = ev.to_dict()
        assert d["event_type"] == "MANIFEST_OFFBOARD"
        assert d["cert_rotation_triggered"] is True

    def test_manifest_validate_failed_to_dict(self) -> None:
        from yashigani.audit import ManifestValidateFailedEvent
        ev = ManifestValidateFailedEvent(
            rule="M1_size_cap",
            field_name="(root)",
            detail="manifest exceeds 512 KB",
        )
        d = ev.to_dict()
        assert d["event_type"] == "MANIFEST_VALIDATE_FAILED"
        assert d["rule"] == "M1_size_cap"

    def test_dynamic_cert_issued_to_dict(self) -> None:
        from yashigani.audit import DynamicCertIssuedEvent
        ev = DynamicCertIssuedEvent(
            tenant_id="acme",
            agent_name="goose",
            spiffe_id="spiffe://yashigani.internal/agents/acme/goose",
            serial_hex="deadbeef",
            issued_at="2026-05-28T00:00:00Z",
            expires_at="2027-05-28T00:00:00Z",
            issuance_mode="onboard_time",
        )
        d = ev.to_dict()
        assert d["event_type"] == "DYNAMIC_CERT_ISSUED"
        assert d["issuance_mode"] == "onboard_time"

    def test_dynamic_cert_revoked_to_dict(self) -> None:
        from yashigani.audit import DynamicCertRevokedEvent
        ev = DynamicCertRevokedEvent(
            tenant_id="acme",
            agent_name="goose",
            spiffe_id="spiffe://yashigani.internal/agents/acme/goose",
            serial_hex="deadbeef",
            revocation_reason="offboard",
        )
        d = ev.to_dict()
        assert d["event_type"] == "DYNAMIC_CERT_REVOKED"

    def test_mcp_call_to_dict(self) -> None:
        from yashigani.audit import McpCallEvent
        ev = McpCallEvent(
            tenant_id="acme",
            agent_name="pydantic-ai",
            identity_id="spiffe://yashigani.internal/agents/acme/pydantic-ai",
            request_id="req-abc-123",
            tool_name="read_file",
            server_id="fs-server",
            opa_decision="allow",
            args_redacted=False,
            elapsed_ms=12,
        )
        d = ev.to_dict()
        assert d["event_type"] == "MCP_CALL"
        assert d["opa_decision"] == "allow"

    def test_mcp_tool_description_fetched_to_dict(self) -> None:
        from yashigani.audit import McpToolDescriptionFetchedEvent
        ev = McpToolDescriptionFetchedEvent(
            tenant_id="acme",
            agent_name="pydantic-ai",
            server_id="fs-server",
            tool_count=5,
            filtered_count=1,
            rejected_count=0,
            fetch_type="tools_list",
        )
        d = ev.to_dict()
        assert d["event_type"] == "MCP_TOOL_DESCRIPTION_FETCHED"
        assert d["tool_count"] == 5

    def test_kms_secret_distributed_to_dict(self) -> None:
        from yashigani.audit import KmsSecretDistributedToAgentEvent
        ev = KmsSecretDistributedToAgentEvent(
            tenant_id="acme",
            agent_name="goose",
            kms_key_name="/tenant/acme/goose/openai",
            kms_provider="vault",
            distribution_mode="onboard_time",
        )
        d = ev.to_dict()
        assert d["event_type"] == "KMS_SECRET_DISTRIBUTED_TO_AGENT"
        assert d["kms_provider"] == "vault"

    def test_opa_decision_on_mcp_to_dict(self) -> None:
        from yashigani.audit import OpaDecisionOnMcpEvent
        ev = OpaDecisionOnMcpEvent(
            tenant_id="acme",
            agent_name="pydantic-ai",
            tool_name="read_file",
            server_id="fs-server",
            request_id="req-abc-123",
            decision="deny",
            deny_reason="sensitivity_ceiling",
            # FIX-F(1) / Iris FIND-002: tool_sensitivity removed from schema
            # (mcp.rego does not return a tool_sensitivity label).
            chain_depth=1,
            elapsed_ms=3,
        )
        d = ev.to_dict()
        assert d["event_type"] == "OPA_DECISION_ON_MCP"
        assert d["decision"] == "deny"

    def test_egress_allow_used_to_dict(self) -> None:
        from yashigani.audit import EgressAllowUsedEvent
        ev = EgressAllowUsedEvent(
            tenant_id="acme",
            agent_name="goose",
            client_identity="spiffe://yashigani.internal/agents/acme/goose",
            egress_entry="api.openai.com",
            method="POST",
            path_truncated="/v1/chat/completions",
            upstream_status=200,
            elapsed_ms=350,
        )
        d = ev.to_dict()
        assert d["event_type"] == "EGRESS_ALLOW_USED"
        assert d["egress_entry"] == "api.openai.com"


# ---------------------------------------------------------------------------
# 4. masking_applied=True immutable floor
# ---------------------------------------------------------------------------

class TestMaskingFloor:
    """All 10 new event classes default to masking_applied=True."""

    @pytest.mark.parametrize("cls_name", _EXPECTED_DATACLASS_NAMES)
    def test_masking_applied_default_true(self, cls_name: str) -> None:
        import yashigani.audit as audit_pkg
        cls = getattr(audit_pkg, cls_name)
        ev = cls()
        assert ev.masking_applied is True, (
            "%s.masking_applied default must be True (compliance invariant)" % cls_name
        )


# ---------------------------------------------------------------------------
# 5. Prev_event_hash chain field is present
# ---------------------------------------------------------------------------

class TestChainField:
    """All new events inherit prev_event_hash from AuditEvent (Merkle chain)."""

    @pytest.mark.parametrize("cls_name", _EXPECTED_DATACLASS_NAMES)
    def test_prev_event_hash_present(self, cls_name: str) -> None:
        import yashigani.audit as audit_pkg
        cls = getattr(audit_pkg, cls_name)
        ev = cls()
        assert hasattr(ev, "prev_event_hash"), (
            "%s missing prev_event_hash — not properly inheriting from AuditEvent" % cls_name
        )
        assert isinstance(ev.prev_event_hash, str)


# ---------------------------------------------------------------------------
# 6. Compute event hash works for all new event types (chain consistency)
# ---------------------------------------------------------------------------

class TestChainHashability:
    """All 10 new event types can be hashed by compute_event_hash (chain consistency)."""

    @pytest.mark.parametrize("cls_name", _EXPECTED_DATACLASS_NAMES)
    def test_compute_event_hash(self, cls_name: str) -> None:
        from yashigani.audit import compute_event_hash
        import yashigani.audit as audit_pkg
        cls = getattr(audit_pkg, cls_name)
        ev = cls()
        event_hash = compute_event_hash(ev.to_dict())
        # SHA-384 hex = 96 chars
        assert len(event_hash) == 96, (
            "compute_event_hash for %s returned %d chars, expected 96" % (cls_name, len(event_hash))
        )
