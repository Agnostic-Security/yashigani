"""
Yashigani Audit — Event schema definitions.
All audit events extend AuditEvent. Fields are immutable after creation.

Last updated: 2026-05-08T00:00:00+01:00
"""
from __future__ import annotations

import uuid
import datetime
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


def _now_iso() -> str:
    return datetime.datetime.now(tz=datetime.timezone.utc).isoformat()


def _new_uuid() -> str:
    return str(uuid.uuid4())


class AccountTier(str, Enum):
    ADMIN = "admin"
    USER = "user"
    SYSTEM = "system"


class EventType(str, Enum):
    # Security
    CREDENTIAL_LEAK_DETECTED = "CREDENTIAL_LEAK_DETECTED"
    PROMPT_INJECTION_DETECTED = "PROMPT_INJECTION_DETECTED"
    SIEM_DELIVERY_FAILED = "SIEM_DELIVERY_FAILED"
    # Auth — admin
    ADMIN_LOGIN = "ADMIN_LOGIN"
    ADMIN_SESSION_INVALIDATED = "ADMIN_SESSION_INVALIDATED"
    FULL_RESET_TOTP_FAILURE = "FULL_RESET_TOTP_FAILURE"
    ADMIN_SESSION_INVALIDATED_TOTP_LOCKOUT = "ADMIN_SESSION_INVALIDATED_TOTP_LOCKOUT"
    # Auth — user
    USER_LOGIN = "USER_LOGIN"
    TOTP_RESET_CONSOLE = "TOTP_RESET_CONSOLE"
    TOTP_PROVISION_TOKEN_ISSUED = "TOTP_PROVISION_TOKEN_ISSUED"
    TOTP_PROVISION_COMPLETED = "TOTP_PROVISION_COMPLETED"
    TOTP_PROVISION_FAILED = "TOTP_PROVISION_FAILED"
    RECOVERY_CODE_USED = "RECOVERY_CODE_USED"
    RECOVERY_CODES_ACKNOWLEDGED = "RECOVERY_CODES_ACKNOWLEDGED"
    RECOVERY_CODES_REGENERATED = "RECOVERY_CODES_REGENERATED"
    EMERGENCY_UNLOCK_EXECUTED = "EMERGENCY_UNLOCK_EXECUTED"
    # Config
    CONFIG_CHANGED = "CONFIG_CHANGED"
    MASKING_CONFIG_CHANGED = "MASKING_CONFIG_CHANGED"
    KSM_ROTATION_SUCCESS = "KSM_ROTATION_SUCCESS"
    KSM_ROTATION_FAILURE = "KSM_ROTATION_FAILURE"
    KSM_ROTATION_CRITICAL = "KSM_ROTATION_CRITICAL"
    # Self-service
    SELFSERVICE_ACTION = "SELFSERVICE_ACTION"
    SELFSERVICE_POLICY_DENY = "SELFSERVICE_POLICY_DENY"
    # User management
    USER_FULL_RESET = "USER_FULL_RESET"
    # Gateway
    GATEWAY_REQUEST = "GATEWAY_REQUEST"
    RATE_LIMIT_VIOLATION = "RATE_LIMIT_VIOLATION"
    # RBAC
    RBAC_GROUP_CREATED = "RBAC_GROUP_CREATED"
    RBAC_GROUP_UPDATED = "RBAC_GROUP_UPDATED"
    RBAC_GROUP_DELETED = "RBAC_GROUP_DELETED"
    RBAC_MEMBER_ADDED = "RBAC_MEMBER_ADDED"
    RBAC_MEMBER_REMOVED = "RBAC_MEMBER_REMOVED"
    RBAC_POLICY_PUSHED = "RBAC_POLICY_PUSHED"
    # Agent registry
    AGENT_REGISTERED = "AGENT_REGISTERED"
    AGENT_UPDATED = "AGENT_UPDATED"
    AGENT_DEACTIVATED = "AGENT_DEACTIVATED"
    AGENT_TOKEN_ROTATED = "AGENT_TOKEN_ROTATED"
    # Agent auth / routing
    AGENT_AUTH_FAILED = "AGENT_AUTH_FAILED"
    AGENT_CALL_ALLOWED = "AGENT_CALL_ALLOWED"
    AGENT_CALL_DENIED_RBAC = "AGENT_CALL_DENIED_RBAC"
    AGENT_CALL_DENIED_INSPECTION = "AGENT_CALL_DENIED_INSPECTION"
    AGENT_NOT_FOUND = "AGENT_NOT_FOUND"
    # Inspection backend management
    INSPECTION_BACKEND_CHANGED = "INSPECTION_BACKEND_CHANGED"
    INSPECTION_BACKEND_UNREACHABLE = "INSPECTION_BACKEND_UNREACHABLE"
    INSPECTION_BACKEND_FALLBACK = "INSPECTION_BACKEND_FALLBACK"
    INSPECTION_BACKEND_FALLBACK_EXHAUSTED = "INSPECTION_BACKEND_FALLBACK_EXHAUSTED"
    INSPECTION_BACKEND_CONFIG_CHANGED = "INSPECTION_BACKEND_CONFIG_CHANGED"
    INSPECTION_KMS_KEY_RETRIEVED = "INSPECTION_KMS_KEY_RETRIEVED"
    # v0.7.0 — IP allowlisting
    IP_ALLOWLIST_VIOLATION = "IP_ALLOWLIST_VIOLATION"
    # v0.7.0 — Rate limit threshold changes
    RATE_LIMIT_THRESHOLD_CHANGED = "RATE_LIMIT_THRESHOLD_CHANGED"
    # v0.7.0 — OPA Policy Assistant
    OPA_ASSISTANT_SUGGESTION_GENERATED = "OPA_ASSISTANT_SUGGESTION_GENERATED"
    OPA_ASSISTANT_SUGGESTION_APPLIED = "OPA_ASSISTANT_SUGGESTION_APPLIED"
    OPA_ASSISTANT_SUGGESTION_REJECTED = "OPA_ASSISTANT_SUGGESTION_REJECTED"
    # v0.9.0 — Response-path inspection
    RESPONSE_INJECTION_DETECTED = "RESPONSE_INJECTION_DETECTED"
    # v0.9.0 — Break-glass (S-04)
    BREAK_GLASS_ACTIVATED = "BREAK_GLASS_ACTIVATED"
    BREAK_GLASS_EXPIRED = "BREAK_GLASS_EXPIRED"
    # v0.9.0 — WebAuthn/Passkeys (Phase 6)
    WEBAUTHN_CREDENTIAL_REGISTERED = "WEBAUTHN_CREDENTIAL_REGISTERED"
    WEBAUTHN_CREDENTIAL_USED = "WEBAUTHN_CREDENTIAL_USED"        # kept for v0.9.0 compat
    WEBAUTHN_CREDENTIAL_DELETED = "WEBAUTHN_CREDENTIAL_DELETED"  # kept for v0.9.0 compat
    # v2.23.3 — WebAuthn admin login events (PR #62, B5 fix — align wire names)
    WEBAUTHN_LOGIN_SUCCESS = "WEBAUTHN_LOGIN_SUCCESS"
    WEBAUTHN_LOGIN_FAILURE = "WEBAUTHN_LOGIN_FAILURE"
    WEBAUTHN_CREDENTIAL_REVOKED = "WEBAUTHN_CREDENTIAL_REVOKED"
    # v2.1 — SSO / OIDC
    SSO_LOGIN_SUCCESS = "SSO_LOGIN_SUCCESS"
    SSO_LOGIN_FAILURE = "SSO_LOGIN_FAILURE"
    # V6.8.4 — SAML-specific success/failure (mirrors OIDC events, separate
    # type so forensic queries can easily filter by protocol)
    SSO_SAML_LOGIN_SUCCESS = "SSO_SAML_LOGIN_SUCCESS"
    SSO_SAML_LOGIN_FAILURE = "SSO_SAML_LOGIN_FAILURE"
    # v2.23.3 — HIBP API key management
    HIBP_API_KEY_UPDATED = "HIBP_API_KEY_UPDATED"
    HIBP_API_KEY_CLEARED = "HIBP_API_KEY_CLEARED"
    # v2.23.3 — FedRAMP AC-2(F2) automated inactive-account disable (LU-YSG-002)
    INACTIVE_ACCOUNT_DISABLED = "INACTIVE_ACCOUNT_DISABLED"


# ---------------------------------------------------------------------------
# Base event
# ---------------------------------------------------------------------------

@dataclass
class AuditEvent:
    event_type: str
    account_tier: str                       # AccountTier value
    masking_applied: bool = True
    audit_event_id: str = field(default_factory=_new_uuid)
    timestamp: str = field(default_factory=_now_iso)
    schema_version: str = "1.0"
    # v0.9.0 — tamper-evident hash chain (F-12).
    # SHA-384 of the preceding event's canonical JSON, or SHA-384 of the
    # date string "YYYY-MM-DD" for the first event of each calendar day.
    # Empty string means the writer has not yet populated the field.
    prev_event_hash: str = ""

    def to_dict(self) -> dict:
        import dataclasses
        return dataclasses.asdict(self)


# ---------------------------------------------------------------------------
# Security events
# ---------------------------------------------------------------------------

@dataclass
class CredentialLeakDetectedEvent(AuditEvent):
    event_type: str = EventType.CREDENTIAL_LEAK_DETECTED
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True            # immutable floor — always True
    session_id: str = ""
    agent_id: str = ""
    pattern_type: str = ""                  # e.g. 'jwt', 'api_key', 'bearer'
    content_hash: str = ""                  # SHA-256 of original segment
    source_component: str = ""


@dataclass
class PromptInjectionDetectedEvent(AuditEvent):
    event_type: str = EventType.PROMPT_INJECTION_DETECTED
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    session_id: str = ""
    agent_id: str = ""
    classification: str = ""               # CREDENTIAL_EXFIL | PROMPT_INJECTION_ONLY
    severity: str = ""                     # CRITICAL | HIGH
    confidence_score: float = 0.0
    action_taken: str = ""                 # sanitized | discarded
    sanitized: bool = False
    admin_alerted: bool = True             # always True — both paths alert admin
    user_alerted: bool = True
    raw_query_logged: bool = False         # always False — invariant


@dataclass
class SiemDeliveryFailedEvent(AuditEvent):
    event_type: str = EventType.SIEM_DELIVERY_FAILED
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    siem_target_name: str = ""
    siem_target_type: str = ""
    failed_audit_event_id: str = ""
    http_status: Optional[int] = None
    error: str = ""
    retry_attempted: bool = False


# ---------------------------------------------------------------------------
# Auth events — admin
# ---------------------------------------------------------------------------

@dataclass
class AdminLoginEvent(AuditEvent):
    event_type: str = EventType.ADMIN_LOGIN
    account_tier: str = AccountTier.ADMIN
    admin_account: str = ""
    outcome: str = ""                      # success | failure
    failure_reason: Optional[str] = None


@dataclass
class AdminSessionInvalidatedEvent(AuditEvent):
    event_type: str = EventType.ADMIN_SESSION_INVALIDATED
    account_tier: str = AccountTier.ADMIN
    admin_account: str = ""
    reason: str = ""


@dataclass
class FullResetTotpFailureEvent(AuditEvent):
    event_type: str = EventType.FULL_RESET_TOTP_FAILURE
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    admin_account: str = ""
    target_user_handle: str = ""
    failure_reason: str = ""               # missing | malformed | expired | invalid | replayed


@dataclass
class AdminSessionTotpLockoutEvent(AuditEvent):
    event_type: str = EventType.ADMIN_SESSION_INVALIDATED_TOTP_LOCKOUT
    account_tier: str = AccountTier.ADMIN
    admin_account: str = ""
    endpoint: str = ""
    consecutive_failures: int = 0


# ---------------------------------------------------------------------------
# Auth events — user / TOTP
# ---------------------------------------------------------------------------

@dataclass
class UserLoginEvent(AuditEvent):
    event_type: str = EventType.USER_LOGIN
    account_tier: str = AccountTier.USER
    user_handle: str = ""
    auth_mode: str = ""                    # sso | local
    outcome: str = ""
    failure_reason: Optional[str] = None


@dataclass
class TotpResetConsoleEvent(AuditEvent):
    """Written when totp-reset CLI command is executed. Immutable floor."""
    event_type: str = EventType.TOTP_RESET_CONSOLE
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True           # immutable floor
    admin_account: str = ""               # operator who ran the command
    target_account: str = ""


@dataclass
class TotpProvisionTokenIssuedEvent(AuditEvent):
    event_type: str = EventType.TOTP_PROVISION_TOKEN_ISSUED
    account_tier: str = AccountTier.USER
    user_handle: str = ""


@dataclass
class TotpProvisionCompletedEvent(AuditEvent):
    event_type: str = EventType.TOTP_PROVISION_COMPLETED
    account_tier: str = AccountTier.USER
    user_handle: str = ""


@dataclass
class TotpProvisionFailedEvent(AuditEvent):
    event_type: str = EventType.TOTP_PROVISION_FAILED
    account_tier: str = AccountTier.USER
    user_handle: str = ""
    reason: str = ""                       # expired_token | reuse | invalid_code


@dataclass
class RecoveryCodeUsedEvent(AuditEvent):
    """Code value is never logged. Immutable floor."""
    event_type: str = EventType.RECOVERY_CODE_USED
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    admin_account: str = ""
    outcome: str = ""                      # success | failure
    codes_remaining: int = 0


@dataclass
class EmergencyUnlockExecutedEvent(AuditEvent):
    """SECURITY_CRITICAL — not maskable by any config. Immutable floor."""
    event_type: str = EventType.EMERGENCY_UNLOCK_EXECUTED
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    severity: str = "SECURITY_CRITICAL"
    admin_account: str = ""
    target_account: str = ""


# ---------------------------------------------------------------------------
# Config events
# ---------------------------------------------------------------------------

@dataclass
class ConfigChangedEvent(AuditEvent):
    event_type: str = EventType.CONFIG_CHANGED
    account_tier: str = AccountTier.ADMIN
    admin_account: str = ""
    setting: str = ""
    previous_value: str = ""
    new_value: str = ""
    below_risk_threshold: bool = False


@dataclass
class MaskingConfigChangedEvent(AuditEvent):
    """Config changes to masking scope are themselves always masked."""
    event_type: str = EventType.MASKING_CONFIG_CHANGED
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    admin_account: str = ""
    change_target: str = ""               # agent | user_session | component
    target_identifier: str = ""
    previous_value: str = ""
    new_value: str = ""


@dataclass
class KsmRotationEvent(AuditEvent):
    event_type: str = EventType.KSM_ROTATION_SUCCESS
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    outcome: str = ""                     # success | failure | critical
    rotation_type: str = ""               # scheduled | manual
    provider_name: str = ""
    new_token_handle: Optional[str] = None


# ---------------------------------------------------------------------------
# Self-service / user management
# ---------------------------------------------------------------------------

@dataclass
class SelfServiceEvent(AuditEvent):
    event_type: str = EventType.SELFSERVICE_ACTION
    account_tier: str = AccountTier.USER
    user_handle: str = ""
    action: str = ""
    outcome: str = ""
    failure_reason: Optional[str] = None


@dataclass
class UserFullResetEvent(AuditEvent):
    event_type: str = EventType.USER_FULL_RESET
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    admin_account: str = ""
    admin_totp_verified: bool = True      # always True on successful reset
    target_user_handle: str = ""


# ---------------------------------------------------------------------------
# Gateway events
# ---------------------------------------------------------------------------

@dataclass
class RateLimitViolationEvent(AuditEvent):
    """Written on every rate limit violation at the gateway."""
    event_type: str = EventType.RATE_LIMIT_VIOLATION
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    request_id: str = ""
    dimension: str = ""               # global | ip | agent | session
    client_ip_hash: str = ""          # SHA-256 prefix — never raw IP
    agent_id: str = ""
    session_id_prefix: str = ""
    retry_after_ms: int = 0
    rpi_at_time: float = 0.0
    rpi_multiplier: float = 1.0


@dataclass
class GatewayRequestEvent(AuditEvent):
    """Written for every request passing through the Yashigani gateway."""
    event_type: str = EventType.GATEWAY_REQUEST
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    request_id: str = ""
    method: str = ""
    path: str = ""
    action: str = ""                      # FORWARDED | DISCARDED | DENIED | BLOCKED
    reason: str = ""
    upstream_status: Optional[int] = None
    elapsed_ms: Optional[int] = None
    confidence_score: Optional[float] = None
    # v0.9.0 — populated when response inspection is enabled; None when disabled
    response_inspection_verdict: Optional[str] = None  # CLEAN | FLAGGED | BLOCKED | None


# ---------------------------------------------------------------------------
# RBAC events
# ---------------------------------------------------------------------------

@dataclass
class RBACGroupEvent(AuditEvent):
    """Written when an RBAC group is created, updated, or deleted."""
    event_type: str = EventType.RBAC_GROUP_CREATED
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    group_id: str = ""
    group_name: str = ""
    admin_account: str = ""
    change_detail: str = ""               # free-form summary of what changed


@dataclass
class RBACMemberEvent(AuditEvent):
    """Written when a member is added to or removed from an RBAC group."""
    event_type: str = EventType.RBAC_MEMBER_ADDED
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    group_id: str = ""
    email: str = ""
    admin_account: str = ""


@dataclass
class RBACPolicyPushEvent(AuditEvent):
    """Written after every successful or failed OPA RBAC data push."""
    event_type: str = EventType.RBAC_POLICY_PUSHED
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    groups_count: int = 0
    users_count: int = 0
    admin_account: str = ""
    outcome: str = "success"              # success | failure
    error: str = ""


# ---------------------------------------------------------------------------
# Agent registry events
# ---------------------------------------------------------------------------

@dataclass
class AgentRegisteredEvent(AuditEvent):
    event_type: str = EventType.AGENT_REGISTERED
    account_tier: str = AccountTier.ADMIN
    agent_id: str = ""
    agent_name: str = ""
    upstream_url: str = ""
    groups: list = field(default_factory=list)
    allowed_caller_groups: list = field(default_factory=list)
    allowed_paths: list = field(default_factory=list)
    admin_account: str = ""


@dataclass
class AgentUpdatedEvent(AuditEvent):
    event_type: str = EventType.AGENT_UPDATED
    account_tier: str = AccountTier.ADMIN
    agent_id: str = ""
    changed_fields: list = field(default_factory=list)
    admin_account: str = ""


@dataclass
class AgentDeactivatedEvent(AuditEvent):
    event_type: str = EventType.AGENT_DEACTIVATED
    account_tier: str = AccountTier.ADMIN
    agent_id: str = ""
    admin_account: str = ""
    reason: str = ""


@dataclass
class AgentTokenRotatedEvent(AuditEvent):
    event_type: str = EventType.AGENT_TOKEN_ROTATED
    account_tier: str = AccountTier.ADMIN
    agent_id: str = ""
    admin_account: str = ""


# ---------------------------------------------------------------------------
# Agent auth / routing events
# ---------------------------------------------------------------------------

@dataclass
class AgentAuthFailedEvent(AuditEvent):
    event_type: str = EventType.AGENT_AUTH_FAILED
    account_tier: str = AccountTier.SYSTEM
    agent_id_claimed: str = ""
    source_ip: str = ""
    path: str = ""
    failure_reason: str = ""


@dataclass
class AgentCallAllowedEvent(AuditEvent):
    event_type: str = EventType.AGENT_CALL_ALLOWED
    account_tier: str = AccountTier.SYSTEM
    caller_agent_id: str = ""
    target_agent_id: str = ""
    path: str = ""
    remainder_path: str = ""
    pipeline_action: str = ""
    classification: str = ""


@dataclass
class AgentCallDeniedRBACEvent(AuditEvent):
    event_type: str = EventType.AGENT_CALL_DENIED_RBAC
    account_tier: str = AccountTier.SYSTEM
    caller_agent_id: str = ""
    target_agent_id: str = ""
    path: str = ""
    opa_reason: str = ""


@dataclass
class AgentCallDeniedInspectionEvent(AuditEvent):
    event_type: str = EventType.AGENT_CALL_DENIED_INSPECTION
    account_tier: str = AccountTier.SYSTEM
    caller_agent_id: str = ""
    target_agent_id: str = ""
    path: str = ""
    classification: str = ""
    confidence: float = 0.0
    action: str = ""


@dataclass
class AgentNotFoundEvent(AuditEvent):
    event_type: str = EventType.AGENT_NOT_FOUND
    account_tier: str = AccountTier.SYSTEM
    caller_agent_id: str = ""
    target_agent_id_requested: str = ""
    path: str = ""


# ---------------------------------------------------------------------------
# Inspection backend management events
# ---------------------------------------------------------------------------

@dataclass
class InspectionBackendChangedEvent(AuditEvent):
    event_type: str = EventType.INSPECTION_BACKEND_CHANGED
    account_tier: str = AccountTier.ADMIN
    previous_backend: str = ""
    new_backend: str = ""
    admin_account: str = ""


@dataclass
class InspectionBackendUnreachableEvent(AuditEvent):
    event_type: str = EventType.INSPECTION_BACKEND_UNREACHABLE
    account_tier: str = AccountTier.SYSTEM
    backend_name: str = ""
    error_type: str = ""
    error_message: str = ""
    request_id: str = ""


@dataclass
class InspectionBackendFallbackEvent(AuditEvent):
    event_type: str = EventType.INSPECTION_BACKEND_FALLBACK
    account_tier: str = AccountTier.SYSTEM
    failed_backend: str = ""
    next_backend: str = ""
    fallback_position: int = 0
    request_id: str = ""


@dataclass
class InspectionBackendFallbackExhaustedEvent(AuditEvent):
    event_type: str = EventType.INSPECTION_BACKEND_FALLBACK_EXHAUSTED
    account_tier: str = AccountTier.SYSTEM
    backends_tried: list = field(default_factory=list)
    request_id: str = ""
    action_taken: str = "PROMPT_INJECTION_ONLY"


@dataclass
class InspectionBackendConfigChangedEvent(AuditEvent):
    event_type: str = EventType.INSPECTION_BACKEND_CONFIG_CHANGED
    account_tier: str = AccountTier.ADMIN
    backend_name: str = ""
    changed_fields: list = field(default_factory=list)
    admin_account: str = ""


@dataclass
class InspectionKMSKeyRetrievedEvent(AuditEvent):
    event_type: str = EventType.INSPECTION_KMS_KEY_RETRIEVED
    account_tier: str = AccountTier.SYSTEM
    backend_name: str = ""
    kms_key_name: str = ""


# ---------------------------------------------------------------------------
# v0.7.0 events
# ---------------------------------------------------------------------------

@dataclass
class IPAllowlistViolationEvent(AuditEvent):
    """Written when an agent request is rejected due to IP allowlist enforcement."""
    event_type: str = EventType.IP_ALLOWLIST_VIOLATION
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    agent_id: str = ""
    client_ip_hash: str = ""        # SHA-256 prefix — never raw IP
    allowed_cidrs: list = None  # type: ignore[assignment]  # populated in __post_init__

    def __post_init__(self):
        if self.allowed_cidrs is None:
            self.allowed_cidrs = []


@dataclass
class RateLimitThresholdChangedEvent(AuditEvent):
    """Written when rpi_scale_* thresholds are changed via the backoffice API."""
    event_type: str = EventType.RATE_LIMIT_THRESHOLD_CHANGED
    account_tier: str = AccountTier.ADMIN
    admin_account: str = ""
    previous_rpi_scale_medium: float = 0.0
    previous_rpi_scale_high: float = 0.0
    previous_rpi_scale_critical: float = 0.0
    new_rpi_scale_medium: float = 0.0
    new_rpi_scale_high: float = 0.0
    new_rpi_scale_critical: float = 0.0


@dataclass
class OPAAssistantSuggestionGeneratedEvent(AuditEvent):
    """Written when the OPA assistant generates a suggestion (before admin review)."""
    event_type: str = EventType.OPA_ASSISTANT_SUGGESTION_GENERATED
    account_tier: str = AccountTier.ADMIN
    admin_account: str = ""
    description_length: int = 0     # length of NL description (not the text itself)
    suggestion_valid: bool = False
    validation_error: Optional[str] = None


@dataclass
class OPAAssistantSuggestionAppliedEvent(AuditEvent):
    """Written when admin approves and applies an OPA assistant suggestion."""
    event_type: str = EventType.OPA_ASSISTANT_SUGGESTION_APPLIED
    account_tier: str = AccountTier.ADMIN
    admin_account: str = ""
    groups_in_suggestion: int = 0
    users_in_suggestion: int = 0


@dataclass
class OPAAssistantSuggestionRejectedEvent(AuditEvent):
    """Written when admin explicitly rejects an OPA assistant suggestion."""
    event_type: str = EventType.OPA_ASSISTANT_SUGGESTION_REJECTED
    account_tier: str = AccountTier.ADMIN
    admin_account: str = ""
    reason: str = ""


# ---------------------------------------------------------------------------
# v0.9.0 — Response-path inspection events
# ---------------------------------------------------------------------------

@dataclass
class ResponseInjectionDetectedEvent(AuditEvent):
    """
    Written when a tool response is flagged or blocked by response inspection.
    The raw response body is never stored — only a content hash.
    """
    event_type: str = EventType.RESPONSE_INJECTION_DETECTED
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    request_id: str = ""
    session_id: str = ""
    agent_id: str = ""
    verdict: str = ""                      # FLAGGED | BLOCKED
    confidence_score: float = 0.0
    action_taken: str = ""                 # 502_returned | flagged_only
    content_type: str = ""                 # Content-Type of the upstream response
    response_content_hash: str = ""        # SHA-256 of the raw response body
    fasttext_only_mode: bool = False       # True when LLM fallback was skipped


# ---------------------------------------------------------------------------
# v0.9.0 — Break-glass events (S-04)
# ---------------------------------------------------------------------------

@dataclass
class BreakGlassActivatedEvent(AuditEvent):
    """
    Written when break-glass emergency access is activated.
    Marked tamper-evident — prev_event_hash is always populated.
    Raw credentials are never stored in this event.
    """
    event_type: str = EventType.BREAK_GLASS_ACTIVATED
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    activated_by: str = ""
    ttl_hours: int = 4
    expires_at: str = ""
    approver: str = ""                     # empty string if single-admin activation
    tamper_evident: bool = True            # immutable floor — always True


@dataclass
class BreakGlassExpiredEvent(AuditEvent):
    """
    Written when break-glass access is revoked (manually or by auto-expiry).
    Marked tamper-evident — prev_event_hash is always populated.
    """
    event_type: str = EventType.BREAK_GLASS_EXPIRED
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    activated_by: str = ""
    revoked_by: str = ""                   # admin ID or "__auto_expire__"
    auto_expired: bool = False
    tamper_evident: bool = True            # immutable floor — always True


# ---------------------------------------------------------------------------
# v0.9.0 — WebAuthn/Passkey events (Phase 6)
# ---------------------------------------------------------------------------

@dataclass
class WebAuthnCredentialRegisteredEvent(AuditEvent):
    """Written when a new WebAuthn credential is successfully registered."""
    event_type: str = EventType.WEBAUTHN_CREDENTIAL_REGISTERED
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    admin_account: str = ""
    credential_uuid: str = ""              # internal UUID (not raw credential_id)
    credential_name: str = ""             # user-supplied label
    aaguid: str = ""                      # authenticator AAGUID
    outcome: str = "success"             # success | failure


@dataclass
class WebAuthnCredentialUsedEvent(AuditEvent):
    """Written on every WebAuthn authentication ceremony completion."""
    event_type: str = EventType.WEBAUTHN_CREDENTIAL_USED
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    admin_account: str = ""
    credential_uuid: str = ""
    outcome: str = "success"             # success | failure
    failure_reason: str = ""


@dataclass
class WebAuthnCredentialDeletedEvent(AuditEvent):
    """Written when a WebAuthn credential is deleted by the owning admin."""
    event_type: str = EventType.WEBAUTHN_CREDENTIAL_DELETED
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    admin_account: str = ""
    credential_uuid: str = ""


# ---------------------------------------------------------------------------
# v2.23.3 — WebAuthn admin login events (PR #62)
#
# B5 fix (Iris audit): the v0.9.0 dataclasses above carry event_type values
# WEBAUTHN_CREDENTIAL_USED and WEBAUTHN_CREDENTIAL_DELETED. The v2.23.3
# route labels are WEBAUTHN_LOGIN_SUCCESS, WEBAUTHN_LOGIN_FAILURE, and
# WEBAUTHN_CREDENTIAL_REVOKED — semantically distinct and more operationally
# meaningful for forensic queries. New dataclasses with the correct wire-format
# event_type values. Old v0.9.0 classes retained for backward compatibility
# with any existing consumers.
# ---------------------------------------------------------------------------

@dataclass
class WebAuthnLoginSuccessEvent(AuditEvent):
    """Written on successful WebAuthn authentication ceremony (admin hardware key login)."""
    event_type: str = EventType.WEBAUTHN_LOGIN_SUCCESS
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    admin_account: str = ""
    credential_uuid: str = ""


@dataclass
class WebAuthnLoginFailureEvent(AuditEvent):
    """Written on failed WebAuthn assertion (wrong key, sign_count rollback, etc.)."""
    event_type: str = EventType.WEBAUTHN_LOGIN_FAILURE
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    admin_account: str = ""
    failure_reason: str = ""


@dataclass
class WebAuthnCredentialRevokedEvent(AuditEvent):
    """Written when an admin revokes a WebAuthn credential (DELETE endpoint)."""
    event_type: str = EventType.WEBAUTHN_CREDENTIAL_REVOKED
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    admin_account: str = ""
    credential_uuid: str = ""


# ---------------------------------------------------------------------------
# v2.1 — SSO / OIDC events
# ---------------------------------------------------------------------------

@dataclass
class SSOLoginSuccessEvent(AuditEvent):
    """
    Written when a user authenticates successfully via an OIDC IdP.
    Email is stored here because it is the observable identity claim;
    masking_applied=True suppresses it in lower-assurance audit sinks.

    V6.8.4 — acr/amr/auth_time added for forensic visibility (ASVS V6.3.3).
    Supports the query: "list all admin sessions where amr did NOT include
    'mfa' in the last 30 days".
    """
    event_type: str = EventType.SSO_LOGIN_SUCCESS
    account_tier: str = AccountTier.USER
    masking_applied: bool = True
    idp_id: str = ""
    idp_name: str = ""
    identity_id: str = ""          # Yashigani identity_id (resolved or created)
    email_hash: str = ""           # HMAC-SHA256 hex of email — raw email never stored
    groups: list = field(default_factory=list)
    client_ip_prefix: str = ""     # Last octet masked
    # V6.8.4 — IdP-supplied authentication-context claims
    acr: str = ""                  # acr claim value (empty if not present)
    amr: list = field(default_factory=list)   # amr claim list (empty if not present)
    auth_time: Optional[int] = None           # auth_time epoch seconds (None if absent)
    iss: str = ""                  # iss claim from the ID token


@dataclass
class SSOLoginFailureEvent(AuditEvent):
    """
    Written when an SSO callback cannot be completed (OIDC path).
    Failure reason is stored verbatim (no user-supplied values leak here
    because the reason comes from internal validation, not the IdP response body).
    """
    event_type: str = EventType.SSO_LOGIN_FAILURE
    account_tier: str = AccountTier.USER
    masking_applied: bool = True
    idp_id: str = ""
    idp_name: str = ""
    failure_reason: str = ""
    client_ip_prefix: str = ""


@dataclass
class SAMLLoginSuccessEvent(AuditEvent):
    """
    Written when a user authenticates successfully via a SAML v2 IdP.

    V6.8.4 — mirrors SSOLoginSuccessEvent but carries SAML-specific fields:
    authn_context_class_ref (maps to OIDC acr), authn_instant (maps to auth_time).
    SAML has no direct amr equivalent; AuthnContextClassRef suffices.
    """
    event_type: str = EventType.SSO_SAML_LOGIN_SUCCESS
    account_tier: str = AccountTier.USER
    masking_applied: bool = True
    idp_id: str = ""
    idp_name: str = ""
    identity_id: str = ""
    email_hash: str = ""
    groups: list = field(default_factory=list)
    client_ip_prefix: str = ""
    # SAML-specific authentication-context claims
    authn_context_class_ref: str = ""   # AuthnContextClassRef URI (maps to acr)
    authn_instant: str = ""             # AuthnInstant ISO 8601 string
    issuer: str = ""                    # Issuer entity ID


@dataclass
class SAMLLoginFailureEvent(AuditEvent):
    """
    Written when a SAML ACS callback cannot be completed.
    """
    event_type: str = EventType.SSO_SAML_LOGIN_FAILURE
    account_tier: str = AccountTier.USER
    masking_applied: bool = True
    idp_id: str = ""
    idp_name: str = ""
    failure_reason: str = ""
    client_ip_prefix: str = ""


# ---------------------------------------------------------------------------
# v2.23.3 — HIBP API key management events
# ---------------------------------------------------------------------------

@dataclass
class HibpApiKeyUpdatedEvent(AuditEvent):
    """
    Written when an admin sets or updates the HIBP API key via admin panel.

    Security invariants:
      - The key value is NEVER stored in this event (not even masked).
      - masked_key_hint carries only first-3 + '…' + last-3 chars so there
        is confirmation in the audit trail that a key was set, without
        exposing the full value.
      - masking_applied is always True (immutable floor).
    """
    event_type: str = EventType.HIBP_API_KEY_UPDATED
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True                    # immutable floor
    admin_account: str = ""
    masked_key_hint: str = ""                        # e.g. "abc…xyz" — never full key


@dataclass
class HibpApiKeyClearedEvent(AuditEvent):
    """
    Written when an admin clears the HIBP API key (reverts to env-var or anon).

    masking_applied is always True (immutable floor).
    """
    event_type: str = EventType.HIBP_API_KEY_CLEARED
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True                    # immutable floor
    admin_account: str = ""


# ---------------------------------------------------------------------------
# v2.23.3 — FedRAMP AC-2(F2) inactive-account disable events (LU-YSG-002)
# ---------------------------------------------------------------------------

@dataclass
class InactiveAccountDisabledEvent(AuditEvent):
    """
    Written by the automated inactive-account cron task (FedRAMP AC-2(F2))
    each time an account is disabled due to inactivity.

    FedRAMP AU-3.F field coverage:
    - timestamp          — inherited from AuditEvent (default_factory=_now_iso)
    - user identity      — disabled_account_id (UID of the disabled account)
    - event type         — INACTIVE_ACCOUNT_DISABLED
    - success/failure    — outcome field (always "success" from the cron task;
                           the task either disables the account or it doesn't)
    - source IP          — source_ip = "system" (cron context; no client IP)
    - target resource    — target_resource = "admin_accounts/<account_id>"

    Lu evidence note: this event class satisfies AU-3.F requirements for the
    automated-disable audit record.  Cross-reference v2.23.3 evidence pack
    item LU-YSG-002.
    """
    event_type: str = EventType.INACTIVE_ACCOUNT_DISABLED
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    # AU-3.F: user identity (the account being acted upon)
    disabled_account_id: str = ""       # UUID of the disabled admin_accounts row
    disabled_username: str = ""         # username — masked in lower-assurance sinks
    # AU-3.F: source IP (no client IP in cron context)
    source_ip: str = "system"
    # AU-3.F: target resource
    target_resource: str = ""           # "admin_accounts/<account_id>"
    # AU-3.F: success/failure
    outcome: str = "success"
    # Additional context for forensic queries
    days_inactive: int = 0              # days since last_login_at at time of disable
    threshold_days: int = 90            # configured YASHIGANI_INACTIVE_DISABLE_DAYS
    last_login_at: str = ""             # ISO-8601 UTC of last login (or backfilled created_at)
