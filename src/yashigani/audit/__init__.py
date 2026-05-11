"""Yashigani Audit — hybrid volume + multi-SIEM audit logging."""

from yashigani.audit.schema import AuditEvent, EventType, AccountTier
from yashigani.audit.schema import InactiveAccountDisabledEvent
from yashigani.audit.schema import (
    AuthLoginAttemptEvent,
    AccountLockoutEvent,
    PasswordChangedEvent,
    SessionsInvalidatedEvent,
)
from yashigani.audit.masking import CredentialMasker, IMMUTABLE_FLOOR_EVENTS
from yashigani.audit.scope import MaskingScopeConfig
from yashigani.audit.writer import AuditLogWriter, AuditWriteError, SiemTarget
from yashigani.audit.export import AuditLogExporter
from yashigani.audit.config import AuditConfig

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
    "MaskingScopeConfig",
    "AuditLogWriter",
    "AuditWriteError",
    "SiemTarget",
    "AuditLogExporter",
    "AuditConfig",
]
