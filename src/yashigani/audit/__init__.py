"""Yashigani Audit — hybrid volume + multi-SIEM audit logging."""

from yashigani.audit.schema import AuditEvent, EventType, AccountTier
from yashigani.audit.schema import InactiveAccountDisabledEvent
from yashigani.audit.schema import (
    AuthLoginAttemptEvent,
    AccountLockoutEvent,
    PasswordChangedEvent,
    SessionsInvalidatedEvent,
)
from yashigani.audit.masking import CredentialMasker, IMMUTABLE_FLOOR_EVENTS, AUDIT_INTEGRITY_EVENTS
from yashigani.audit.scope import MaskingScopeConfig
from yashigani.audit.writer import AuditLogWriter, AuditWriteError, SiemTarget
from yashigani.audit.export import AuditLogExporter
# v2.25.2 — DB audit sink (PostgresSink) wiring
from yashigani.audit.sinks import (
    PostgresSink,
    build_postgres_audit_sink,
    stop_postgres_audit_sink,
)
from yashigani.audit.config import AuditConfig
# v2.24.1 LU-AMEND-01 — tamper-evident audit log hash chain
from yashigani.audit.chain import (
    AuditChainService,
    compute_event_hash,
    compute_prev_hash,
    day_anchor,
)
# v2.24.1 LU-AMEND-01 wave 2 — daily checkpoint scheduler
from yashigani.audit.checkpoint_job import AuditCheckpointScheduler
# v2.25.0 P1 W0a — 10 ring-fence onboarding event dataclasses (Lu-Gap-06 / G3)
from yashigani.audit.schema import (
    ManifestOnboardEvent,
    ManifestOffboardEvent,
    ManifestValidateFailedEvent,
    DynamicCertIssuedEvent,
    DynamicCertRevokedEvent,
    McpCallEvent,
    McpToolDescriptionFetchedEvent,
    SemanticIntentEscalatedEvent,
    KmsSecretDistributedToAgentEvent,
    OpaDecisionOnMcpEvent,
    EgressAllowUsedEvent,
)

__all__ = [
    "AuditEvent",
    "EventType",
    "AccountTier",
    "InactiveAccountDisabledEvent",
    # v2.23.3 ACS gap #95 — auth_log missing events
    "AuthLoginAttemptEvent",
    "AccountLockoutEvent",
    "PasswordChangedEvent",
    "SessionsInvalidatedEvent",
    "CredentialMasker",
    "IMMUTABLE_FLOOR_EVENTS",
    "AUDIT_INTEGRITY_EVENTS",
    "MaskingScopeConfig",
    "AuditLogWriter",
    "AuditWriteError",
    "SiemTarget",
    "AuditLogExporter",
    # v2.25.2 — DB audit sink
    "PostgresSink",
    "build_postgres_audit_sink",
    "stop_postgres_audit_sink",
    "AuditConfig",
    # v2.24.1 LU-AMEND-01
    "AuditChainService",
    "compute_event_hash",
    "compute_prev_hash",
    "day_anchor",
    # v2.24.1 LU-AMEND-01 wave 2
    "AuditCheckpointScheduler",
    # v2.25.0 P1 W0a — ring-fence onboarding events (Lu-Gap-06 / G3)
    "ManifestOnboardEvent",
    "ManifestOffboardEvent",
    "ManifestValidateFailedEvent",
    "DynamicCertIssuedEvent",
    "DynamicCertRevokedEvent",
    "McpCallEvent",
    "McpToolDescriptionFetchedEvent",
    "SemanticIntentEscalatedEvent",
    "KmsSecretDistributedToAgentEvent",
    "OpaDecisionOnMcpEvent",
    "EgressAllowUsedEvent",
]
