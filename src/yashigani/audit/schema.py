"""
Yashigani Audit — Event schema definitions.
All audit events extend AuditEvent. Fields are immutable after creation.

Last updated: 2026-05-09T00:00:00+01:00
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
    # v2.23.3 — ACS gap #95: auth_log missing events
    # AUTH_LOGIN_ATTEMPT: emitted at the start of every login handler call
    # (before auth result) to provide a complete attempt timeline for forensics
    # and CMMC AU.L2-3.3.1 / ASVS V7.2.1.
    AUTH_LOGIN_ATTEMPT = "AUTH_LOGIN_ATTEMPT"
    # ACCOUNT_LOCKOUT: emitted when an account is locked out due to failed
    # password or TOTP attempts (ASVS V2.1.5 / NIST 800-63B §5.2.2).
    ACCOUNT_LOCKOUT = "ACCOUNT_LOCKOUT"
    # PASSWORD_CHANGED: distinct from CONFIG_CHANGED — dedicated event for
    # self-service and forced password changes with audit-trail clarity.
    PASSWORD_CHANGED = "PASSWORD_CHANGED"
    # SESSIONS_INVALIDATED: emitted when all sessions for an account are
    # bulk-invalidated (password change, admin full-reset, etc.)
    SESSIONS_INVALIDATED = "SESSIONS_INVALIDATED"
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
    # Gap 4 / v2.23.4 — self-service Bearer issuance + revocation
    USER_API_KEY_ISSUED = "USER_API_KEY_ISSUED"
    USER_API_KEY_REVOKED = "USER_API_KEY_REVOKED"
    ADMIN_USER_API_KEY_ISSUED = "ADMIN_USER_API_KEY_ISSUED"
    # Gateway
    GATEWAY_REQUEST = "GATEWAY_REQUEST"
    RATE_LIMIT_VIOLATION = "RATE_LIMIT_VIOLATION"
    # Per-user rate limit breach — emitted when the user dimension is violated.
    # Distinct from RATE_LIMIT_VIOLATION (which covers global/IP/agent/session).
    # Wazuh-routable admin alert via customer-configured ruleset.
    USER_RATE_LIMIT_EXCEEDED = "USER_RATE_LIMIT_EXCEEDED"
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
    WEBAUTHN_CREDENTIAL_USED = "WEBAUTHN_CREDENTIAL_USED"  # kept for v0.9.0 compat
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
    # v2.23.3 — Admin-triggered secret rotation
    SECRET_ROTATION_REQUESTED = "SECRET_ROTATION_REQUESTED"
    SECRET_ROTATION_SUCCEEDED = "SECRET_ROTATION_SUCCEEDED"
    SECRET_ROTATION_FAILED = "SECRET_ROTATION_FAILED"
    SECRET_ROTATION_REVERTED = "SECRET_ROTATION_REVERTED"
    # v2.23.3 — HIBP API key management
    HIBP_API_KEY_UPDATED = "HIBP_API_KEY_UPDATED"
    HIBP_API_KEY_CLEARED = "HIBP_API_KEY_CLEARED"
    # v2.23.3 — FedRAMP AC-2(F2) automated inactive-account disable (LU-YSG-002)
    INACTIVE_ACCOUNT_DISABLED = "INACTIVE_ACCOUNT_DISABLED"
    # v2.23.3 — CMMC L2 IA.L2-3.5.8 password reuse history
    PASSWORD_REUSE_REJECTED = "PASSWORD_REUSE_REJECTED"
    # v2.23.3 — OWASP API7 DNS-rebinding defence (issue #91)
    SSRF_PINNED_RESOLVER_USED = "SSRF_PINNED_RESOLVER_USED"
    # v2.23.4 — Q3 arch-completion: admin-action reactivation + blocked login
    # LOGIN_BLOCKED_SUSPENDED_IDENTITY: emitted when a user-tier login attempt
    # is blocked because the HUMAN identity is suspended/inactive.
    # Admin must use POST /admin/users/{username}/reactivate to restore access.
    LOGIN_BLOCKED_SUSPENDED_IDENTITY = "LOGIN_BLOCKED_SUSPENDED_IDENTITY"
    # IDENTITY_REACTIVATED: emitted when an admin explicitly reactivates a
    # suspended identity via POST /admin/users/{username}/reactivate.
    IDENTITY_REACTIVATED = "IDENTITY_REACTIVATED"
    # v2.23.4 — OPA fail-closed (ASVS V8.* + V14.5.*)
    # OPA_RESPONSE_CHECK_FAILED: emitted when the OPA response-check path is
    # unreachable, errors, or not configured.  Request is DENIED (fail-closed).
    # Alert on sustained rate — an OPA outage causes response-delivery denials.
    OPA_RESPONSE_CHECK_FAILED = "OPA_RESPONSE_CHECK_FAILED"
    # v2.23.4 — PII detection events (ASVS V7.3.4 / Iris FINDING-004)
    # PII_DETECTED: emitted when the PII detector finds sensitive data in a
    # request or response body.  Raw PII values are NEVER logged — only
    # pii_type labels and a count.
    PII_DETECTED = "PII_DETECTED"
    # v2.23.4 — Streaming stream-termination event (Iris FINDING-004)
    # STREAM_TERMINATED: emitted when a streaming response is terminated
    # early by the StreamingInspector due to sensitive content detection.
    STREAM_TERMINATED = "STREAM_TERMINATED"
    # v2.24.1 — LU-AMEND-04: operator identity attestation on yashigani onboard
    # OPERATOR_TOKEN_ISSUED: admin issued a short-lived operator onboard token.
    # ASVS V7.2.1 + NIST IA-2 + CMMC IA.L2-3.5.1 + SOC 2 CC6.1.
    OPERATOR_TOKEN_ISSUED = "OPERATOR_TOKEN_ISSUED"
    # ONBOARD_ATTEMPTED: yashigani onboard was called; records operator identity
    # or flags as weak-identity when no token was supplied.
    # ASVS V7.2.1 + NIST AU-3 + CMMC AU.L2-3.3.1.
    ONBOARD_ATTEMPTED = "ONBOARD_ATTEMPTED"
    # v2.24.1 — LU-AMEND-03: manifest signing ceremony record.
    # MANIFEST_CEREMONY_RECORDED: operator confirmed the manifest SHA-256 and
    # the explicit acknowledgement was captured + signed.
    # NIST SR-4/SR-4(3) + CMMC SR.L2-3.11.2 + ISO 27001 A.5.21/A.5.23.
    MANIFEST_CEREMONY_RECORDED = "MANIFEST_CEREMONY_RECORDED"
    # v2.4.1 — PoolManager container-per-identity dispatch
    # POOL_BACKEND_UNAVAILABLE: emitted when the PoolManager or its container
    # backend is unreachable/erroring during a pool-managed agent dispatch.
    # Request is returned as HTTP 502 (fail-closed per SOP 1).
    POOL_BACKEND_UNAVAILABLE = "POOL_BACKEND_UNAVAILABLE"
    # v2.24.1 — drift audit finding #6: server-side next= redirect validator.
    # OPEN_REDIRECT_ATTEMPT_BLOCKED: emitted when the server-side validator
    # rejects a next= redirect target that fails the backslash / protocol-relative
    # / @ / length checks.  CWE-601 / ASVS V5.1.5 / OWASP A01:2021.
    OPEN_REDIRECT_ATTEMPT_BLOCKED = "OPEN_REDIRECT_ATTEMPT_BLOCKED"
    # v2.24.1 — admin-surfaces-all-runtime-settings rule.
    # RUNTIME_SETTING_CHANGED: emitted on every PUT /admin/runtime-settings/{key}.
    # CMMC AU.L2-3.3.1 / SOC 2 CC6.2 / ISO 27001 A.5.15.
    RUNTIME_SETTING_CHANGED = "RUNTIME_SETTING_CHANGED"
    # v2.24.1 — GAP-3 / SEC-5: agent response blocked by OPA.
    # AGENT_RESPONSE_BLOCKED_BY_OPA: emitted when the response-leg OPA check on
    # /agents/* denies delivery of the upstream agent's response to the caller.
    # Mirrors OPA_RESPONSE_CHECK_FAILED for /v1/* (which covers OPA errors);
    # this event covers a deliberate OPA policy deny (response sensitivity
    # exceeds caller ceiling, or PII detected).
    # ASVS V4.1.3 / CMMC SC.L2-3.13.10 / ISO 27001 A.8.3 / Iris SEC-5 / Ava GAP-3.
    AGENT_RESPONSE_BLOCKED_BY_OPA = "AGENT_RESPONSE_BLOCKED_BY_OPA"
    # v2.24.1 — GAP-001: GET /v1/models principal-aware OPA listing.
    # MODELS_LIST_REQUESTED: emitted on every GET /v1/models call, recording
    # the principal, OPA filter level, and count of models returned.
    # ASVS V4.1.1 / OWASP API9 / Iris GAP-001 / YSG-RISK-066.
    MODELS_LIST_REQUESTED = "MODELS_LIST_REQUESTED"
    # v2.24.1 — GAP-002: catch-all proxy response-leg OPA.
    # MCP_RESPONSE_BLOCKED_BY_OPA: emitted when the proxy response-leg OPA check
    # denies delivery of the upstream MCP response to the caller.
    # Mirrors AGENT_RESPONSE_BLOCKED_BY_OPA for the MCP proxy path.
    # ASVS V4.1.3 / CMMC SC.L2-3.13.10 / ISO 27001 A.8.3 / Iris GAP-002 / YSG-RISK-067.
    MCP_RESPONSE_BLOCKED_BY_OPA = "MCP_RESPONSE_BLOCKED_BY_OPA"
    # v2.24.1 — GAP-002: OPA error on proxy response leg (fail-closed).
    # PROXY_OPA_RESPONSE_CHECK_FAILED: emitted when the OPA call on the proxy
    # response leg errors or is unreachable; gateway returns HTTP 503.
    # Alert on sustained rate — mirrors OPA_RESPONSE_CHECK_FAILED for /v1/*.
    PROXY_OPA_RESPONSE_CHECK_FAILED = "PROXY_OPA_RESPONSE_CHECK_FAILED"
    # v2.24.1 — Iris #96: Admin/User Separation-of-Duties (SoD-001..005)
    # NIST AC-5 / SOC 2 CC6.3 / ISO 27001 A.5.16 / CMMC AC.L2-3.1.4 / OWASP ASVS V4.1.2
    # ADMIN_CREATE_REJECTED_USER_EXISTS: admin creation blocked because a user-tier
    # identity already exists with the same username/email.
    ADMIN_CREATE_REJECTED_USER_EXISTS = "ADMIN_CREATE_REJECTED_USER_EXISTS"
    # USER_CREATE_REJECTED_ADMIN_EXISTS: user creation blocked because an admin
    # account already exists with the same username/email (SoD-002a/b/c).
    USER_CREATE_REJECTED_ADMIN_EXISTS = "USER_CREATE_REJECTED_ADMIN_EXISTS"
    # SCIM_PROVISION_REJECTED_ADMIN_EXISTS: SCIM provision blocked because an admin
    # account exists with the given email (SoD-002b).
    SCIM_PROVISION_REJECTED_ADMIN_EXISTS = "SCIM_PROVISION_REJECTED_ADMIN_EXISTS"
    # SSO_PROVISION_REJECTED_ADMIN_EXISTS: SSO identity auto-provision blocked
    # because an admin account exists with the given email (SoD-002c / SoD-004).
    SSO_PROVISION_REJECTED_ADMIN_EXISTS = "SSO_PROVISION_REJECTED_ADMIN_EXISTS"
    # AUTH_VERIFY_REJECTED_ADMIN_SESSION: /auth/verify (Caddy forward_auth) blocked
    # because the session belongs to an admin — admins cannot bridge to data plane
    # (SoD-003). NIST AC-5 / OWASP ASVS V4.1.2.
    AUTH_VERIFY_REJECTED_ADMIN_SESSION = "AUTH_VERIFY_REJECTED_ADMIN_SESSION"
    # IDENTITY_STORE_CONFLICT: cross-store conflict detected by daily cron audit
    # (SoD-005). Same username/email exists in both admin_accounts and
    # identity_registry. Operator must remediate manually.
    IDENTITY_STORE_CONFLICT = "IDENTITY_STORE_CONFLICT"
    # ---------------------------------------------------------------------------
    # v2.25.0 — P1 Universal Ring-fence Onboarding (W0a — Lu-Gap-06 / G3)
    # All 10 event types registered ahead of the emitting features so the
    # Merkle chain schema is consistent before any feature dispatch lands.
    #
    # Compliance hook (Lu — do NOT assign control IDs here; map in G6 workflow):
    #   AU-2 / AU-12 / CC7.1 — these events must appear in every ring-fence
    #   audit trail.  Per-agent control mapping is deferred to Lu's G6 gate.
    # ---------------------------------------------------------------------------
    # Manifest lifecycle
    MANIFEST_ONBOARD = "MANIFEST_ONBOARD"
    MANIFEST_OFFBOARD = "MANIFEST_OFFBOARD"
    MANIFEST_VALIDATE_FAILED = "MANIFEST_VALIDATE_FAILED"
    # PKI / mTLS — dynamic cert operations (v1 = onboard-time; on-demand = v2)
    DYNAMIC_CERT_ISSUED = "DYNAMIC_CERT_ISSUED"
    DYNAMIC_CERT_REVOKED = "DYNAMIC_CERT_REVOKED"
    # MCP data-plane events
    MCP_CALL = "MCP_CALL"
    MCP_TOOL_DESCRIPTION_FETCHED = "MCP_TOOL_DESCRIPTION_FETCHED"
    # KMS secret distribution to a ring-fenced agent
    KMS_SECRET_DISTRIBUTED_TO_AGENT = "KMS_SECRET_DISTRIBUTED_TO_AGENT"
    # OPA decision on an MCP tool call (distinct from OPA_RESPONSE_CHECK_FAILED)
    OPA_DECISION_ON_MCP = "OPA_DECISION_ON_MCP"
    # Egress allowlist entry exercised (covert-channel audit — TM-URF-023 / G3)
    EGRESS_ALLOW_USED = "EGRESS_ALLOW_USED"


# ---------------------------------------------------------------------------
# Base event
# ---------------------------------------------------------------------------


@dataclass
class AuditEvent:
    event_type: str
    account_tier: str  # AccountTier value
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
class OpenRedirectAttemptBlockedEvent(AuditEvent):
    """
    Emitted when the server-side next= redirect validator rejects a redirect
    target that fails the backslash / protocol-relative / @ / length checks.

    Security invariants:
    - attempted_next is truncated to 128 chars and the raw value is SHA-256
      hashed before being stored (client_ip_hash).  No raw IP or raw next=
      value is stored in the audit record.
    - masking_applied is always True.
    - reason identifies which guard fired (backslash | double_slash |
      absolute_url | userinfo_at | too_long | empty | not_relative).

    CWE-601 / ASVS V5.1.5 / OWASP A01:2021 / drift audit finding #6.
    """

    event_type: str = EventType.OPEN_REDIRECT_ATTEMPT_BLOCKED
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True  # immutable floor — always True
    # SHA-256 hex of the source IP (first 16 chars for log brevity)
    client_ip_hash: str = ""
    # Truncated + sanitised attempted next= value (max 128 chars, no raw PII)
    attempted_next_truncated: str = ""
    # Which validation rule fired
    reason: str = ""  # backslash | double_slash | absolute_url | userinfo_at | too_long | empty | not_relative


@dataclass
class CredentialLeakDetectedEvent(AuditEvent):
    event_type: str = EventType.CREDENTIAL_LEAK_DETECTED
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True  # immutable floor — always True
    session_id: str = ""
    agent_id: str = ""
    pattern_type: str = ""  # e.g. 'jwt', 'api_key', 'bearer'
    content_hash: str = ""  # SHA-256 of original segment
    source_component: str = ""


@dataclass
class PromptInjectionDetectedEvent(AuditEvent):
    event_type: str = EventType.PROMPT_INJECTION_DETECTED
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    session_id: str = ""
    agent_id: str = ""
    classification: str = ""  # CREDENTIAL_EXFIL | PROMPT_INJECTION_ONLY
    severity: str = ""  # CRITICAL | HIGH
    confidence_score: float = 0.0
    action_taken: str = ""  # sanitized | discarded
    sanitized: bool = False
    admin_alerted: bool = True  # always True — both paths alert admin
    user_alerted: bool = True
    raw_query_logged: bool = False  # always False — invariant


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
    outcome: str = ""  # success | failure
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
    failure_reason: str = ""  # missing | malformed | expired | invalid | replayed


@dataclass
class AdminSessionTotpLockoutEvent(AuditEvent):
    event_type: str = EventType.ADMIN_SESSION_INVALIDATED_TOTP_LOCKOUT
    account_tier: str = AccountTier.ADMIN
    admin_account: str = ""
    endpoint: str = ""
    consecutive_failures: int = 0


# ---------------------------------------------------------------------------
# v2.23.3 — ACS gap #95: auth_log missing event dataclasses
# ---------------------------------------------------------------------------


@dataclass
class AuthLoginAttemptEvent(AuditEvent):
    """
    Written at the very start of every login handler call — before auth result.

    Provides a complete attempt timeline for CMMC AU.L2-3.3.1 / ASVS V7.2.1.
    The admin_account field is populated from the user-supplied username;
    masking_applied=True suppresses it in lower-assurance sinks.
    outcome is always "attempt" on this event — the follow-up AdminLoginEvent
    carries the final "success" | "failure" | "totp_provision_restricted".

    Security invariant: password is NEVER stored or referenced in this event.
    """

    event_type: str = EventType.AUTH_LOGIN_ATTEMPT
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    admin_account: str = ""  # user-supplied username (masked in lower-assurance sinks)
    client_ip_prefix: str = ""  # last octet masked for IPv4; last group masked for IPv6
    outcome: str = "attempt"  # always "attempt"


@dataclass
class AccountLockoutEvent(AuditEvent):
    """
    Written when an account is locked out after exceeding the maximum allowed
    consecutive failed authentication attempts (password or TOTP).

    ASVS V2.1.5 / NIST SP 800-63B §5.2.2 — account lockout policy.
    masking_applied=True: admin_account is suppressed in lower-assurance sinks.

    lockout_type: "password" | "totp" — distinguishes the failure mode.
    failed_attempts: the count at the moment of lockout (at least 5).
    lockout_duration_seconds: configured lockout window (default 1800 s / 30 min).
    """

    event_type: str = EventType.ACCOUNT_LOCKOUT
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    admin_account: str = ""
    lockout_type: str = ""  # "password" | "totp"
    failed_attempts: int = 0
    lockout_duration_seconds: int = 0


@dataclass
class PasswordChangedEvent(AuditEvent):
    """
    Written on every successful password change (self-service or forced).

    Distinct from ConfigChangedEvent — dedicated event for password lifecycle
    events provides cleaner forensic queries and separation from config changes.

    Security invariants (immutable floors):
    - Neither old nor new password values are ever stored here.
    - old_hash_tail / new_hash_tail carry only the last 8 chars of the
      respective Argon2id hashes — enough for audit correlation without
      exposing the full hash.
    - masking_applied is always True.

    change_type: "forced" (first-login / admin reset) | "self_service"
    """

    event_type: str = EventType.PASSWORD_CHANGED
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True  # immutable floor
    admin_account: str = ""  # account whose password changed
    change_type: str = ""  # "forced" | "self_service"
    old_hash_tail: str = ""  # last 8 chars of the previous Argon2id hash
    new_hash_tail: str = ""  # last 8 chars of the new Argon2id hash
    sessions_invalidated: bool = True  # always True on password change


@dataclass
class SessionsInvalidatedEvent(AuditEvent):
    """
    Written when all sessions for an account are bulk-invalidated.

    Covers: password change, admin full-reset, account disable.
    Provides a clear session-lifecycle record for CMMC AU.L2-3.3.1.

    reason: human-readable description of why sessions were invalidated,
    e.g. "password_change" | "admin_full_reset" | "account_disabled".
    sessions_count: number of sessions revoked (-1 if unknown, e.g. Redis flush).
    """

    event_type: str = EventType.SESSIONS_INVALIDATED
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    admin_account: str = ""  # account whose sessions were invalidated
    acting_admin: str = ""  # admin who triggered the invalidation (empty = self-service)
    reason: str = ""  # "password_change" | "admin_full_reset" | "account_disabled"
    sessions_count: int = -1  # number of sessions revoked (-1 if unknown)


# ---------------------------------------------------------------------------
# Auth events — user / TOTP
# ---------------------------------------------------------------------------


@dataclass
class UserLoginEvent(AuditEvent):
    event_type: str = EventType.USER_LOGIN
    account_tier: str = AccountTier.USER
    user_handle: str = ""
    auth_mode: str = ""  # sso | local
    outcome: str = ""
    failure_reason: Optional[str] = None


@dataclass
class TotpResetConsoleEvent(AuditEvent):
    """Written when totp-reset CLI command is executed. Immutable floor."""

    event_type: str = EventType.TOTP_RESET_CONSOLE
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True  # immutable floor
    admin_account: str = ""  # operator who ran the command
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
    reason: str = ""  # expired_token | reuse | invalid_code


@dataclass
class RecoveryCodeUsedEvent(AuditEvent):
    """Code value is never logged. Immutable floor."""

    event_type: str = EventType.RECOVERY_CODE_USED
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    admin_account: str = ""
    outcome: str = ""  # success | failure
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
    change_target: str = ""  # agent | user_session | component
    target_identifier: str = ""
    previous_value: str = ""
    new_value: str = ""


@dataclass
class KsmRotationEvent(AuditEvent):
    event_type: str = EventType.KSM_ROTATION_SUCCESS
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    outcome: str = ""  # success | failure | critical
    rotation_type: str = ""  # scheduled | manual
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
    admin_totp_verified: bool = True  # always True on successful reset
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
    dimension: str = ""  # global | ip | agent | session
    client_ip_hash: str = ""  # SHA-256 prefix — never raw IP
    agent_id: str = ""
    session_id_prefix: str = ""
    retry_after_ms: int = 0
    rpi_at_time: float = 0.0
    rpi_multiplier: float = 1.0


@dataclass
class UserRateLimitExceededEvent(AuditEvent):
    """
    Written when the per-user token bucket is exhausted.

    Distinct from RateLimitViolationEvent — this event carries the
    (hashed) user_id so it can be routed to admin alert channels via
    Wazuh or equivalent SIEM.  user_id is SHA-256 truncated to 16 hex
    chars — enough to correlate breaches without exposing PII in the
    audit chain.

    Admin alert path:
      Wazuh rule matches event_type == USER_RATE_LIMIT_EXCEEDED → fires
      configured alert (email/Slack/webhook) so operators see which
      user is hammering the gateway.
    """

    event_type: str = EventType.USER_RATE_LIMIT_EXCEEDED
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    request_id: str = ""
    user_id_hash: str = ""           # SHA-256[:16] of raw user_id
    rps_observed: float = 0.0        # approximate burst rate that triggered the limit
    limit_rps: float = 0.0           # configured per_user_rps at time of breach
    retry_after_ms: int = 0
    agent_id: str = ""
    session_id_prefix: str = ""


@dataclass
class GatewayRequestEvent(AuditEvent):
    """Written for every request passing through the Yashigani gateway."""

    event_type: str = EventType.GATEWAY_REQUEST
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    request_id: str = ""
    method: str = ""
    path: str = ""
    action: str = ""  # FORWARDED | DISCARDED | DENIED | BLOCKED
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
    change_detail: str = ""  # free-form summary of what changed


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
    outcome: str = "success"  # success | failure
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


@dataclass
class AgentResponseBlockedByOpaEvent(AuditEvent):
    """
    Emitted when the response-leg OPA check for /agents/* denies delivery
    of the upstream agent's response to the calling agent.

    v2.24.1 — GAP-3 / SEC-5: closes asymmetry between /v1/* (which had a
    response-OPA check) and /agents/* (which did not).

    Security invariants:
    - response body is never stored; response_sensitivity is the label only.
    - masking_applied is always True.
    - deny_reason identifies which guard fired (ceiling / pii / identity).

    ASVS V4.1.3 / CMMC SC.L2-3.13.10 / ISO 27001 A.8.3.
    """

    event_type: str = EventType.AGENT_RESPONSE_BLOCKED_BY_OPA
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    caller_agent_id: str = ""
    target_agent_id: str = ""
    response_sensitivity: str = ""        # PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED
    deny_reason: str = ""                 # response_sensitivity_exceeds_caller_ceiling | pii_detected_in_response | missing_agent_identity | opa_unreachable
    request_id: str = ""
    pii_detected: bool = False


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
    client_ip_hash: str = ""  # SHA-256 prefix — never raw IP
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
    description_length: int = 0  # length of NL description (not the text itself)
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
    verdict: str = ""  # FLAGGED | BLOCKED
    confidence_score: float = 0.0
    action_taken: str = ""  # 502_returned | flagged_only
    content_type: str = ""  # Content-Type of the upstream response
    response_content_hash: str = ""  # SHA-256 of the raw response body
    fasttext_only_mode: bool = False  # True when LLM fallback was skipped


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
    approver: str = ""  # empty string if single-admin activation
    tamper_evident: bool = True  # immutable floor — always True


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
    revoked_by: str = ""  # admin ID or "__auto_expire__"
    auto_expired: bool = False
    tamper_evident: bool = True  # immutable floor — always True


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
    credential_uuid: str = ""  # internal UUID (not raw credential_id)
    credential_name: str = ""  # user-supplied label
    aaguid: str = ""  # authenticator AAGUID
    outcome: str = "success"  # success | failure


@dataclass
class WebAuthnCredentialUsedEvent(AuditEvent):
    """Written on every WebAuthn authentication ceremony completion."""

    event_type: str = EventType.WEBAUTHN_CREDENTIAL_USED
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    admin_account: str = ""
    credential_uuid: str = ""
    outcome: str = "success"  # success | failure
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
    identity_id: str = ""  # Yashigani identity_id (resolved or created)
    email_hash: str = ""  # HMAC-SHA256 hex of email — raw email never stored
    groups: list = field(default_factory=list)
    client_ip_prefix: str = ""  # Last octet masked
    # V6.8.4 — IdP-supplied authentication-context claims
    acr: str = ""  # acr claim value (empty if not present)
    amr: list = field(default_factory=list)  # amr claim list (empty if not present)
    auth_time: Optional[int] = None  # auth_time epoch seconds (None if absent)
    iss: str = ""  # iss claim from the ID token


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
    authn_context_class_ref: str = ""  # AuthnContextClassRef URI (maps to acr)
    authn_instant: str = ""  # AuthnInstant ISO 8601 string
    issuer: str = ""  # Issuer entity ID


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
# v2.23.3 — Admin-triggered secret rotation events
# ---------------------------------------------------------------------------


@dataclass
class SecretRotationRequestedEvent(AuditEvent):
    """
    Written when an admin initiates a secret rotation.

    secret_name is included (e.g. "postgres_password") but the secret value
    is NEVER stored here or anywhere in the audit chain.
    masking_applied=True is an immutable floor — this event is always masked.
    """

    event_type: str = EventType.SECRET_ROTATION_REQUESTED
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True  # immutable floor
    admin_account: str = ""
    secret_name: str = ""  # e.g. "postgres_password" or "all"
    request_id: str = ""  # ties REQUEST→SUCCEEDED/FAILED events


@dataclass
class SecretRotationSucceededEvent(AuditEvent):
    """
    Written when a secret rotation completes successfully.

    If secret_name="all", child_results contains per-secret outcomes.
    No secret values are stored.
    """

    event_type: str = EventType.SECRET_ROTATION_SUCCEEDED
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True  # immutable floor
    admin_account: str = ""
    secret_name: str = ""
    request_id: str = ""
    rotated_at: str = ""


@dataclass
class SecretRotationFailedEvent(AuditEvent):
    """
    Written when a secret rotation fails (before or after service state change).

    reverted=True means the old secret was successfully restored.
    revert_failed=True means the old secret could NOT be restored — CRITICAL.
    No secret values are stored.
    """

    event_type: str = EventType.SECRET_ROTATION_FAILED
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True  # immutable floor
    admin_account: str = ""
    secret_name: str = ""
    request_id: str = ""
    failure_reason: str = ""
    reverted: bool = False
    revert_failed: bool = False
    severity: str = ""  # "CRITICAL" when revert_failed=True


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
    masking_applied: bool = True  # immutable floor
    admin_account: str = ""
    masked_key_hint: str = ""  # e.g. "abc…xyz" — never full key


@dataclass
class HibpApiKeyClearedEvent(AuditEvent):
    """
    Written when an admin clears the HIBP API key (reverts to env-var or anon).

    masking_applied is always True (immutable floor).
    """

    event_type: str = EventType.HIBP_API_KEY_CLEARED
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True  # immutable floor
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
    disabled_account_id: str = ""  # UUID of the disabled admin_accounts row
    disabled_username: str = ""  # username — masked in lower-assurance sinks
    # AU-3.F: source IP (no client IP in cron context)
    source_ip: str = "system"
    # AU-3.F: target resource
    target_resource: str = ""  # "admin_accounts/<account_id>"
    # AU-3.F: success/failure
    outcome: str = "success"
    # Additional context for forensic queries
    days_inactive: int = 0  # days since last_login_at at time of disable
    threshold_days: int = 90  # configured YASHIGANI_INACTIVE_DISABLE_DAYS
    last_login_at: str = ""  # ISO-8601 UTC of last login (or backfilled created_at)


# ---------------------------------------------------------------------------
# v2.23.3 — CMMC L2 IA.L2-3.5.8 password reuse history events
# ---------------------------------------------------------------------------


@dataclass
class PasswordReuseRejectedEvent(AuditEvent):
    """
    Written when a password-change attempt is rejected because the new
    password matches one of the last N hashes in password_history.

    Security invariants (immutable floors):
      - The new password is NEVER stored in this event.
      - The matching hash is NEVER stored in this event.
      - masking_applied is always True.
      - user_id is the account UUID — not the plaintext username — to
        allow correlation without exposing the username in lower-assurance
        sinks.

    CMMC IA.L2-3.5.8 / NIST SP 800-63B Section 5.1.1.2.
    """

    event_type: str = EventType.PASSWORD_REUSE_REJECTED
    account_tier: str = AccountTier.USER
    masking_applied: bool = True  # immutable floor
    user_id: str = ""  # UUID of the account (never plaintext username)
    # How many history slots were checked at rejection time.
    # The exact match position is intentionally not recorded (no ordering
    # information that could assist an attacker in narrowing the history).
    history_depth_checked: int = 0  # == PASSWORD_HISTORY_DEPTH at call time


# ---------------------------------------------------------------------------
# Gap 4 / v2.23.4 — User self-service Bearer issuance + admin override
# ---------------------------------------------------------------------------


@dataclass
class UserApiKeyIssuedEvent(AuditEvent):
    """Written when a user self-issues or rotates their HUMAN-identity Bearer.

    Security invariants (immutable floors):
      - The plaintext token is NEVER stored here. Only last4 is logged.
      - masking_applied is always True.
      - actor is the account_id of the user performing the action.

    ASVS V7.1.1 — all auth decisions logged with forensic context.
    Gap 4 / v2.23.4 arch-completion.
    """

    event_type: str = EventType.USER_API_KEY_ISSUED
    account_tier: str = AccountTier.USER
    masking_applied: bool = True  # immutable floor — plaintext never logged
    actor: str = ""      # account_id of the user (not username — avoids PII in lower sinks)
    identity_id: str = ""
    key_last4: str = ""  # last 4 chars of plaintext token — sufficient for forensics
    rotation: bool = False  # True if a prior token existed and was immediately invalidated


@dataclass
class UserApiKeyRevokedEvent(AuditEvent):
    """Written when a user or admin revokes a HUMAN-identity Bearer key.

    Security invariants: same as UserApiKeyIssuedEvent.
    """

    event_type: str = EventType.USER_API_KEY_REVOKED
    account_tier: str = AccountTier.USER
    masking_applied: bool = True
    actor: str = ""          # account_id of the principal performing the revocation
    identity_id: str = ""
    key_id: str = ""         # key_id being revoked (Redis field or identity_id)
    revoked_by_admin: bool = False


@dataclass
class AdminUserApiKeyIssuedEvent(AuditEvent):
    """Written when an admin issues/rotates a user's API key via the admin override route.

    Security invariants:
      - plaintext token never logged.
      - admin_account_id is the acting admin (account_id, not username).
      - target_username is included for forensic correlation.

    ASVS V7.1.1 / Lu audit-trail requirement (Gap 4 arch ticket).
    """

    event_type: str = EventType.ADMIN_USER_API_KEY_ISSUED
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    admin_account_id: str = ""   # acting admin account_id
    target_username: str = ""    # target user
    target_identity_id: str = ""
    key_last4: str = ""
    grace_seconds: int = 30      # grace window applied to prior token


@dataclass
class LoginBlockedSuspendedIdentityEvent(AuditEvent):
    """Written when a user-tier login is blocked because their HUMAN identity
    is suspended or inactive in the identity registry.

    The user must contact an admin who can call
    POST /admin/users/{username}/reactivate (requires StepUp).

    Security invariants:
      - No session is created (login is rejected before session issuance).
      - username is logged for forensic triage (not account_id — account_id
        may not be meaningful to operators; username is the primary handle).

    Q3 / v2.23.4 arch-completion.
    """

    event_type: str = EventType.LOGIN_BLOCKED_SUSPENDED_IDENTITY
    account_tier: str = AccountTier.USER
    masking_applied: bool = True
    username: str = ""          # target user whose login was blocked
    identity_id: str = ""       # identity_id that is suspended
    identity_status: str = ""   # "suspended" or "inactive"
    slug: str = ""              # slug of the blocked identity (for correlation)


@dataclass
class IdentityReactivatedEvent(AuditEvent):
    """Written when an admin explicitly reactivates a suspended HUMAN identity
    via POST /admin/users/{username}/reactivate.

    Security invariants:
      - Admin must hold a valid StepUp session (TOTP within 5 min).
      - acting_admin_account_id is account_id of the acting admin (not username).
      - target_username is the user whose identity was reactivated.
      - plaintext tokens and secrets are never logged.

    ASVS V7.1.1 / Q3 arch-completion.
    """

    event_type: str = EventType.IDENTITY_REACTIVATED
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    acting_admin_account_id: str = ""   # admin performing the reactivation
    target_username: str = ""           # user being reactivated
    target_identity_id: str = ""        # identity_id being reactivated
    reason: str = ""                    # optional reason supplied in request body


# ---------------------------------------------------------------------------
# v2.23.4 — OPA response-check fail-closed event (Iris FINDING-004)
# ---------------------------------------------------------------------------


@dataclass
class OpaResponseCheckFailedEvent(AuditEvent):
    """Written when the OPA response-check is unreachable, errors, or
    not configured and the gateway denies the response (fail-closed).

    Alert on sustained rate — OPA outage = sustained response-delivery
    denials.  ASVS V8.* + V14.5.* / v2.23.4 Iris FINDING-004.

    Security invariants:
      - No response body or user content is stored here.
      - exc_str is truncated to 256 chars to prevent log bloat.
      - masking_applied is always True.
    """

    event_type: str = EventType.OPA_RESPONSE_CHECK_FAILED
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    reason: str = ""          # "opa_not_configured" | "opa_exception"
    outcome: str = ""         # "not_configured" | "exception"
    exc_class: str = ""       # exception class name (empty for not_configured)
    exc_str: str = ""         # str(exc)[:256] (empty for not_configured)
    identity_id: str = ""
    response_sensitivity: str = ""
    action: str = "denied_fail_closed"


# ---------------------------------------------------------------------------
# v2.23.4 — PII detection event (Iris FINDING-004)
# ---------------------------------------------------------------------------


@dataclass
class PIIDetectedEvent(AuditEvent):
    """Written when the PII detector identifies sensitive data in a
    gateway request or response body.

    Security invariants (immutable floors):
      - Raw PII values are NEVER stored — only pii_type labels and counts.
      - masking_applied is always True.
      - direction is "request" or "response".
      - destination is "local" (Ollama) or "cloud" (remote LLM API).

    ASVS V7.3.4 / v2.23.4 Iris FINDING-004.
    """

    event_type: str = EventType.PII_DETECTED
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True   # immutable floor — PII labels are still sensitive
    request_id: str = ""
    direction: str = ""            # "request" | "response"
    pii_types: list = None         # type: ignore[assignment]
    action_taken: str = ""         # "logged" | "redacted" | "blocked"
    destination: str = ""          # "local" | "cloud" | "upstream"
    finding_count: int = 0

    def __post_init__(self):
        if self.pii_types is None:
            self.pii_types = []


# ---------------------------------------------------------------------------
# v2.23.4 — Stream termination event (Iris FINDING-004)
# ---------------------------------------------------------------------------


@dataclass
class StreamTerminatedEvent(AuditEvent):
    """Written when a streaming response is terminated early by the
    StreamingInspector due to sensitive content detection.

    Security invariants:
      - accumulated_chars is a character count only — no content is stored.
      - masking_applied is always True.
      - trigger format: "<layer>:<level>" e.g. "regex:CONFIDENTIAL".

    ASVS V7.3.4 / v2.23.4 Iris FINDING-004.
    """

    event_type: str = EventType.STREAM_TERMINATED
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    trigger: str = ""          # e.g. "regex:CONFIDENTIAL" | "fasttext:RESTRICTED"
    request_id: str = ""
    session_id: str = ""
    agent_id: str = ""
    accumulated_chars: int = 0


# ---------------------------------------------------------------------------
# v2.24.1 — LU-AMEND-04: operator identity attestation
# ---------------------------------------------------------------------------


@dataclass
class OperatorTokenIssuedEvent(AuditEvent):
    """
    Emitted when an admin issues a short-lived operator onboard token via
    POST /auth/operator-token.

    Security invariants:
      - The token value itself is NEVER logged; only the jti (token ID)
        and expiry are recorded. The jti enables cross-correlation with
        ONBOARD_ATTEMPTED without exposing the bearer credential.
      - admin_account is the issuing admin's username (not the target).
      - token_ttl_seconds records the TTL at issuance time.

    ASVS V7.2.1 + NIST IA-2/AU-3 + CMMC IA.L2-3.5.1/3 + SOC 2 CC6.1
    + ISO 27001 A.5.16/A.5.17 / LU-AMEND-04.
    """

    event_type: str = EventType.OPERATOR_TOKEN_ISSUED
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    admin_account: str = ""     # issuing admin username
    token_jti: str = ""         # UUID4 — correlates with ONBOARD_ATTEMPTED
    token_ttl_seconds: int = 0  # TTL at issuance (typically 900 s / 15 min)
    issued_for: str = ""        # free-text note — operator intent, e.g. agent name


@dataclass
class OnboardAttemptedEvent(AuditEvent):
    """
    Emitted when `yashigani onboard` is called.

    Identity quality:
      - identity_quality = "attested"  → operator supplied a valid token
        (jti + expiry verified by backoffice). Audit trail is complete.
      - identity_quality = "weak"      → operator did NOT supply --token.
        The onboard was allowed but flagged so auditors can identify
        un-attested onboards. CMMC CA.L2-3.12.2 / SOC 2 CC3.1 require
        that all exceptions are documented.

    Security invariants:
      - The raw token value is NEVER logged.
      - token_jti is empty string when identity_quality = "weak" (no token).
      - operator_identity is the value carried in the token's sub claim
        (typically the admin username who issued it), or "unknown" when weak.

    ASVS V7.2.1 + NIST AU-3/IA-2 + CMMC IA.L2-3.5.1 + AU.L2-3.3.1
    + SOC 2 CC6.1 + ISO 42001 A.6.1.2 / LU-AMEND-04.
    """

    event_type: str = EventType.ONBOARD_ATTEMPTED
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    identity_quality: str = ""   # "attested" | "weak"
    operator_identity: str = ""  # sub claim from token, or "unknown"
    token_jti: str = ""          # UUID4 from token, or "" when weak
    agent_name: str = ""         # agent being onboarded
    agent_url: str = ""          # upstream URL from CLI arg
    client_ip: str = ""          # caller's IP (from X-Forwarded-For or direct)

# ---------------------------------------------------------------------------
# v2.4.1 — Pool Manager events
# ---------------------------------------------------------------------------


@dataclass
class PoolBackendUnavailableEvent(AuditEvent):
    """
    Emitted when the PoolManager or its container backend fails during a
    pool-managed agent dispatch.  Request is returned as HTTP 502.

    Raised both when pool_manager is None (not initialised) and when
    get_or_create() raises an unexpected exception (socket unreachable, etc.).

    v2.4.1 — container-per-identity dispatch wiring.
    """

    event_type: str = EventType.POOL_BACKEND_UNAVAILABLE
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = False
    request_id: str = ""
    identity_id: str = ""
    agent_name: str = ""
    reason: str = ""  # "pool_manager_none" | exception class name


# ---------------------------------------------------------------------------
# v2.24.1 — LU-AMEND-03: Manifest signing ceremony record
# ---------------------------------------------------------------------------


@dataclass
class ManifestCeremonyEvent(AuditEvent):
    """
    Emitted when an operator completes a manifest signing ceremony.

    The ceremony captures:
    - The manifest SHA-256 (so the exact blob can be traced to a
      manifest_registrations row without re-reading the raw YAML).
    - The operator identity (sub claim from the operator token, or "unknown").
    - The acknowledgement text shown to the operator and their explicit "Y" response.
    - The signature_provenance JSON used for the manifest_registrations row.
    - The resulting manifest_registrations record id.

    This event is written to audit_events AND the manifest_registrations row
    has its signature_provenance populated from the same ceremony JSON.
    The dual-write ensures Lu can verify the ceremony occurred without having
    to read the manifest_registrations table from audit sinks.

    Security invariants (immutable floors):
      - masking_applied is always True (operator identities are masked in
        lower-assurance audit sinks to limit correlation risk).
      - The raw manifest YAML blob is NEVER stored in this event — only the
        SHA-256 digest. The full blob lives in manifest_registrations.
      - ack_response MUST be exactly "Y" for a ceremony to succeed; anything
        else aborts the registration. The field is stored here for forensic
        completeness (auditors can confirm what was captured).

    NIST SR-4/SR-4(3) — supply chain / component provenance traceability.
    CMMC SR.L2-3.11.2 — use of components from trusted sources.
    ISO 27001 A.5.21  — managing information security in the ICT supply chain.
    ISO 27001 A.5.23  — information security for use of cloud services.
    LU-AMEND-03 / v2.24.1.
    """

    event_type: str = EventType.MANIFEST_CEREMONY_RECORDED
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True              # immutable floor
    manifest_sha256: str = ""                 # hex SHA-256 of the YAML blob
    operator_identity: str = ""               # sub claim from token, or "unknown"
    confirmed_at: str = ""                    # ISO-8601 UTC timestamp of the ack
    ack_text_shown: str = ""                  # the exact text shown to the operator
    ack_response: str = ""                    # always "Y" for successful ceremonies
    # Provenance summary — not the full JSON (the full JSON lives in
    # manifest_registrations.signature_provenance). Only the algorithm name,
    # signer SPIFFE ID, and first/last 8 chars of the HMAC sig are stored here
    # to avoid bloating the audit log with a large signed structure.
    signature_alg: str = ""                   # e.g. "spiffe-internal-hmac"
    signer_spiffe_id: str = ""                # SPIFFE ID of the signing entity
    signature_hex_prefix: str = ""            # first 16 hex chars of the HMAC sig
    manifest_registration_id: Optional[int] = None  # FK to manifest_registrations.id


# ---------------------------------------------------------------------------
# v2.24.1 — Runtime settings audit events
# ---------------------------------------------------------------------------


@dataclass
class RuntimeSettingChangedEvent(AuditEvent):
    """
    Emitted on every PUT /admin/runtime-settings/{key}.

    Records the old and new value, the operator identity, and how the change
    was made ('ui' | 'api') for full audit traceability.

    Security invariants:
    - masking_applied is always True.
    - old_value / new_value are JSON-serialised primitives (int/float/bool/str).
      They are stored as strings to avoid accidental PII capture for future
      settings that might contain sensitive strings.  Current settings are
      all numeric, so this is defence-in-depth.

    CMMC AU.L2-3.3.1 / SOC 2 CC6.2 / ISO 27001 A.5.15.
    admin-surfaces-all-runtime-settings rule / v2.24.1.
    """

    event_type: str = EventType.RUNTIME_SETTING_CHANGED
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True          # immutable floor
    setting_key: str = ""                 # e.g. 'gateway.ddos.per_ip_limit'
    old_value: str = ""                   # JSON string of the previous value
    new_value: str = ""                   # JSON string of the new value
    changed_by: str = ""                  # admin account_id
    source: str = ""                      # 'ui' | 'api'


# ---------------------------------------------------------------------------
# v2.24.1 — GAP-001: GET /v1/models principal-aware OPA listing
# ---------------------------------------------------------------------------


@dataclass
class ModelsListRequestedEvent(AuditEvent):
    """Written on every GET /v1/models call.

    Records the caller's identity, the OPA filter level applied, and the
    count of models returned to the caller.  When OPA is not configured or
    unreachable (fail-closed), action is "denied" and model_count is 0.

    Security invariants:
      - No model names are stored — only the count (prevents log-based
        topology disclosure to a log-read attacker).
      - identity_id is the resolved identity slug, never the raw API key.
      - masking_applied is always True.

    ASVS V4.1.1 / OWASP API9 (Improper Inventory Management) /
    Iris GAP-001 / YSG-RISK-066 / v2.24.1.
    """

    event_type: str = EventType.MODELS_LIST_REQUESTED
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    identity_id: str = ""            # resolved identity slug or "anonymous"
    identity_kind: str = ""          # human | service | admin | unknown
    opa_filter: str = ""             # full | restricted | denied
    model_count: int = 0             # count of models returned (0 on deny)
    action: str = ""                 # allowed | denied | fail_closed


# ---------------------------------------------------------------------------
# v2.24.1 — GAP-002: catch-all proxy response-leg OPA
# ---------------------------------------------------------------------------


@dataclass
class McpResponseBlockedByOpaEvent(AuditEvent):
    """Written when the proxy response-leg OPA check denies delivery of the
    upstream MCP response to the caller.

    Mirrors AgentResponseBlockedByOpaEvent for the catch-all MCP proxy path.

    Security invariants:
      - No response body or user content is stored here.
      - identity_id is the resolved identity slug.
      - response_sensitivity comes from the ResponseInspectionPipeline (when
        enabled) or "PUBLIC" (pipeline off — see proxy.py).
      - masking_applied is always True.

    ASVS V4.1.3 / CMMC SC.L2-3.13.10 / ISO 27001 A.8.3 /
    Iris GAP-002 / YSG-RISK-067 / v2.24.1.
    """

    event_type: str = EventType.MCP_RESPONSE_BLOCKED_BY_OPA
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    request_id: str = ""
    identity_id: str = ""            # resolved identity slug
    identity_kind: str = ""          # human | service | admin | unknown
    request_path: str = ""           # the MCP tool path that was proxied
    response_sensitivity: str = ""   # PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED
    pii_detected: bool = False
    deny_reason: str = ""            # from OPA proxy_response_reason
    action: str = "denied"


@dataclass
class ProxyOpaResponseCheckFailedEvent(AuditEvent):
    """Written when the OPA response-leg check on the catch-all proxy errors
    or is unreachable.  Gateway returns HTTP 503 (fail-closed).

    Alert on sustained rate — an OPA outage causes proxy response-delivery
    failures.  Mirrors OPA_RESPONSE_CHECK_FAILED for the /v1/* path.

    Security invariants:
      - No response body or user content is stored.
      - exc_str is truncated to 256 chars.
      - masking_applied is always True.

    ASVS V8.* + V14.5.* / Iris GAP-002 / YSG-RISK-067 / v2.24.1.
    """

    event_type: str = EventType.PROXY_OPA_RESPONSE_CHECK_FAILED
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    request_id: str = ""
    identity_id: str = ""
    reason: str = ""           # "opa_not_configured" | "opa_exception"
    outcome: str = ""          # "not_configured" | "exception"
    exc_class: str = ""
    exc_str: str = ""          # str(exc)[:256]
    action: str = "denied_fail_closed"


# ---------------------------------------------------------------------------
# v2.24.1 — Iris #96: Admin/User Separation-of-Duties events (SoD-001..005)
# NIST AC-5 / SOC 2 CC6.3 / ISO 27001 A.5.16 / CMMC AC.L2-3.1.4 / ASVS V4.1.2
# ---------------------------------------------------------------------------


@dataclass
class AdminCreateRejectedUserExistsEvent(AuditEvent):
    """Emitted when admin creation is blocked because a user-tier identity
    already exists with the same username or email (SoD-001).

    Cross-store collision: the username/email maps to an existing user account
    in admin_accounts (account_tier=user) or the identity_registry. Creating
    an admin with the same identity would collapse the separation boundary.

    NIST AC-5 / SOC 2 CC6.3 / ISO 27001 A.5.16 / CMMC AC.L2-3.1.4 / ASVS V4.1.2.
    """

    event_type: str = EventType.ADMIN_CREATE_REJECTED_USER_EXISTS
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    acting_admin_account_id: str = ""   # admin performing the creation
    rejected_username: str = ""         # the username that collided
    collision_store: str = ""           # "user_accounts" | "identity_registry"


@dataclass
class UserCreateRejectedAdminExistsEvent(AuditEvent):
    """Emitted when user creation is blocked because an admin account
    already exists with the same username or email (SoD-002a/b/c).

    Applies to: POST /admin/users (SoD-002a), SCIM /Users (SoD-002b),
    SSO callback (SoD-002c / SoD-004 combined fix).

    NIST AC-5 / SOC 2 CC6.3 / ISO 27001 A.5.16 / CMMC AC.L2-3.1.4 / ASVS V4.1.2.
    """

    event_type: str = EventType.USER_CREATE_REJECTED_ADMIN_EXISTS
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    acting_admin_account_id: str = ""   # admin or system performing the creation
    rejected_username_or_email: str = ""  # NEVER the real email — use hash or redacted
    creation_path: str = ""             # "direct" | "scim" | "sso"


@dataclass
class ScimProvisionRejectedAdminExistsEvent(AuditEvent):
    """Emitted when SCIM provisioning is blocked because an admin account
    exists with the given email address (SoD-002b).

    The email is hashed (HMAC-SHA256) before logging — same as SSO audit events.
    The identity provider receives a SCIM error response.

    NIST AC-5 / SOC 2 CC6.3 / ISO 27001 A.5.16 / CMMC AC.L2-3.1.4 / ASVS V4.1.2.
    """

    event_type: str = EventType.SCIM_PROVISION_REJECTED_ADMIN_EXISTS
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    acting_admin_account_id: str = ""   # admin session that called SCIM
    email_hash: str = ""                # HMAC-SHA256 of the email, never raw


@dataclass
class SsoProvisionRejectedAdminExistsEvent(AuditEvent):
    """Emitted when SSO identity auto-provision is blocked because an admin
    account exists with the given email (SoD-002c + SoD-004 combined fix).

    The same admin email completing an SSO flow would otherwise silently create
    a HUMAN identity and bridge the admin to the data plane via /auth/verify.
    Both the identity creation AND the session are blocked at this point.

    The email is hashed (HMAC-SHA256) before logging — same as all SSO events.

    NIST AC-5 / SOC 2 CC6.3 / ISO 27001 A.5.16 / CMMC AC.L2-3.1.4 / ASVS V4.1.2.
    """

    event_type: str = EventType.SSO_PROVISION_REJECTED_ADMIN_EXISTS
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    idp_id: str = ""
    idp_name: str = ""
    email_hash: str = ""                # HMAC-SHA256 of the email, never raw
    client_ip_prefix: str = ""          # last-octet masked


@dataclass
class AuthVerifyRejectedAdminSessionEvent(AuditEvent):
    """Emitted when /auth/verify (Caddy forward_auth) rejects an admin session.

    Admins are permitted to authenticate to the backoffice (port 8443) but MUST
    NOT traverse the data plane (/v1/*, /agents/*, etc.) via Caddy forward_auth.
    An admin session presented to /auth/verify is always rejected with HTTP 403
    and this event is written for forensic and alerting purposes.

    Combined with SoD-002c, this closes the SoD-004 exploit chain:
      admin SSO → HUMAN identity created → admin session → /auth/verify → data plane.
    Layer 1 (SoD-002c): blocks identity creation.
    Layer 2 (SoD-003 here): blocks the /auth/verify bridge even if identity existed.

    NIST AC-5 / SOC 2 CC6.3 / OWASP ASVS V4.1.2 / v2.24.1.
    """

    event_type: str = EventType.AUTH_VERIFY_REJECTED_ADMIN_SESSION
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    account_id: str = ""                # the admin account_id from the session
    client_ip_prefix: str = ""          # last-octet masked


@dataclass
class IdentityStoreConflictEvent(AuditEvent):
    """Emitted by the daily SoD conflict audit cron (SoD-005) when the same
    username or email is found in both admin_accounts and the identity_registry.

    This indicates either:
    - A race condition in creation (cross-store collision checks failed atomically)
    - A pre-fix record that existed before SoD enforcement was added
    - Manual DB modification bypassing the API layer

    Operator must remediate: rename the user identity or delete the admin account.
    Surfaced in /admin/dashboard/sod-conflicts.

    NIST AC-5 / SOC 2 CC6.3 / ISO 27001 A.5.16 / CMMC AC.L2-3.1.4 / v2.24.1.
    """

    event_type: str = EventType.IDENTITY_STORE_CONFLICT
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    admin_account_id: str = ""          # UUID from admin_accounts
    admin_username: str = ""            # admin username (for operator display)
    identity_id: str = ""               # identity_registry identity_id
    conflict_field: str = ""            # "username" | "email"
    conflict_value_hash: str = ""       # HMAC-SHA256 of the conflicting value


# ---------------------------------------------------------------------------
# v2.25.0 — P1 Universal Ring-fence Onboarding event dataclasses (W0a)
# Lu-Gap-06 / G3 — register ahead of emitting features.
#
# Compliance hook: control-ID mapping is intentionally ABSENT from these
# dataclasses.  Lu maps controls in the G6 per-agent gate (workflow doc).
# Inserting control IDs here would couple the dataclass to Lu's mapping
# cadence; the event_type string in EventType is the stable identifier.
# ---------------------------------------------------------------------------


@dataclass
class ManifestOnboardEvent(AuditEvent):
    """
    Emitted when ``yashigani onboard <manifest.yaml>`` completes successfully.

    Records the agent name, tenant, manifest SHA-256, operator identity, and
    the five ring-fence artifacts generated.  The raw manifest YAML is never
    stored — only the SHA-256.

    Security invariants:
      - masking_applied is always True (operator identity masked in lower sinks).
      - manifest_sha256 is the hex SHA-256 of the canonical YAML blob.
      - artifacts_generated is a list of artifact-type labels, not paths.

    v2.25.0 / Lu-Gap-06 / W0a.
    """

    event_type: str = EventType.MANIFEST_ONBOARD
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    tenant_id: str = ""              # from manifest metadata.tenant_id
    agent_name: str = ""             # from manifest metadata.name
    manifest_sha256: str = ""        # hex SHA-256 of the YAML blob
    operator_identity: str = ""      # sub from operator token, or "unknown"
    token_jti: str = ""              # operator token jti, or ""
    artifacts_generated: list = None  # type: ignore[assignment]
    runtime: str = ""                # YSG_RUNTIME value at onboard time

    def __post_init__(self) -> None:
        if self.artifacts_generated is None:
            self.artifacts_generated = []


@dataclass
class ManifestOffboardEvent(AuditEvent):
    """
    Emitted when ``yashigani offboard <name>`` completes.

    Records whether each artifact was removed cleanly and whether a cert
    rotation was triggered.

    v2.25.0 / Lu-Gap-06 / W0a / S5 offboard lifecycle.
    """

    event_type: str = EventType.MANIFEST_OFFBOARD
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    tenant_id: str = ""
    agent_name: str = ""
    operator_identity: str = ""
    artifacts_removed: list = None  # type: ignore[assignment]
    cert_rotation_triggered: bool = False

    def __post_init__(self) -> None:
        if self.artifacts_removed is None:
            self.artifacts_removed = []


@dataclass
class ManifestValidateFailedEvent(AuditEvent):
    """
    Emitted when ``yashigani validate`` (or the parser inside ``onboard``)
    rejects a manifest.

    Carries the rule that fired and a sanitised excerpt of the field that
    failed (raw field values are never stored — only the field name and
    rule label).  masking_applied is always True.

    v2.25.0 / Lu-Gap-06 / W0a / M1-M9.
    """

    event_type: str = EventType.MANIFEST_VALIDATE_FAILED
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    rule: str = ""              # e.g. "M1_size_cap" | "M2_tenant_id_regex" | "M7_unsigned"
    field_name: str = ""        # the manifest field path that failed, e.g. "spec.image.digest"
    detail: str = ""            # human-readable reason (no raw field values)
    manifest_sha256: str = ""   # best-effort; empty when size cap fires before hash


@dataclass
class DynamicCertIssuedEvent(AuditEvent):
    """
    Emitted when a leaf mTLS cert is issued for a ring-fenced agent at
    onboard time (v1) or on-demand (v2, PKI Issuer API).

    Security invariants:
      - Private key material is NEVER stored.
      - serial_hex is the certificate serial number in hex (for revocation lookup).
      - spiffe_id is the full SPIFFE URI assigned to the agent.
      - expires_at is ISO-8601 UTC.

    v2.25.0 / Lu-Gap-06 / W0a / Nico NICO-002/003.
    """

    event_type: str = EventType.DYNAMIC_CERT_ISSUED
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    tenant_id: str = ""
    agent_name: str = ""
    spiffe_id: str = ""          # spiffe://yashigani.internal/agents/{tenant}/{name}
    serial_hex: str = ""         # cert serial number in hex
    issued_at: str = ""          # ISO-8601 UTC
    expires_at: str = ""         # ISO-8601 UTC
    issuance_mode: str = ""      # "onboard_time" | "on_demand"


@dataclass
class DynamicCertRevokedEvent(AuditEvent):
    """
    Emitted when a ring-fenced agent's mTLS leaf cert is revoked (on offboard
    or explicit rotation).

    v2.25.0 / Lu-Gap-06 / W0a / Nico NICO-003.
    """

    event_type: str = EventType.DYNAMIC_CERT_REVOKED
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    tenant_id: str = ""
    agent_name: str = ""
    spiffe_id: str = ""
    serial_hex: str = ""
    revocation_reason: str = ""  # "offboard" | "rotation" | "compromise"


@dataclass
class McpCallEvent(AuditEvent):
    """
    Emitted on every MCP tool call brokered by the Yashigani gateway.

    Security invariants:
      - Tool input/output are NEVER stored — only tool_name and
        args_redacted (a boolean flag) plus OPA decision.
      - identity_id is the resolved agent SPIFFE identity slug.
      - request_id correlates with GatewayRequestEvent.

    v2.25.0 / Lu-Gap-06 / W0a / P3 MCP broker.
    """

    event_type: str = EventType.MCP_CALL
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    tenant_id: str = ""
    agent_name: str = ""
    identity_id: str = ""        # resolved SPIFFE identity slug
    request_id: str = ""
    tool_name: str = ""
    server_id: str = ""          # upstream MCP server identifier
    opa_decision: str = ""       # "allow" | "deny" | "redact"
    args_redacted: bool = False
    elapsed_ms: Optional[int] = None


@dataclass
class McpToolDescriptionFetchedEvent(AuditEvent):
    """
    Emitted when the MCP broker fetches tool descriptions from an upstream
    MCP server (tools/list or prompts/list response).

    Used to audit the tool-catalogue integrity path (M4 + P3).  The tool
    description text is NEVER stored — only the tool_name and whether the
    sanitisation filter modified it.

    v2.25.0 / Lu-Gap-06 / W0a / M4 prompt-injection filter.
    """

    event_type: str = EventType.MCP_TOOL_DESCRIPTION_FETCHED
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    tenant_id: str = ""
    agent_name: str = ""
    server_id: str = ""
    tool_count: int = 0          # number of tool descriptors fetched
    filtered_count: int = 0      # number of descriptors modified by sanitiser
    rejected_count: int = 0      # number of descriptors rejected (over cap / pattern)
    fetch_type: str = ""         # "tools_list" | "prompts_list"


@dataclass
class KmsSecretDistributedToAgentEvent(AuditEvent):
    """
    Emitted when the KMS layer distributes a secret to a ring-fenced agent
    (file-based bind-mount at onboard time, or runtime refresh).

    Security invariants:
      - Secret value is NEVER stored.
      - kms_key_name is the logical key name (e.g. ``/tenant/acme/agent-goose/openai``),
        never the raw secret value.
      - masking_applied is always True.

    v2.25.0 / Lu-Gap-06 / W0a / spec.secrets KMS flow.
    """

    event_type: str = EventType.KMS_SECRET_DISTRIBUTED_TO_AGENT
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    tenant_id: str = ""
    agent_name: str = ""
    kms_key_name: str = ""       # logical KMS key path (never the value)
    kms_provider: str = ""       # "vault" | "aws" | "azure" | "gcp" | "keeper"
    distribution_mode: str = ""  # "onboard_time" | "runtime_refresh"


@dataclass
class OpaDecisionOnMcpEvent(AuditEvent):
    """
    Emitted for every OPA policy decision on an MCP tool call.

    Distinct from OPA_RESPONSE_CHECK_FAILED (which covers OPA errors/timeouts).
    This event covers deliberate policy decisions — allow, deny, or redact —
    including tool sensitivity class, budget gate, and multi-hop chain depth.

    Security invariants:
      - Tool input/output are never stored.
      - deny_reason is a label, not a raw policy string.
      - chain_depth is the JWT chain depth (multi-hop guard, Lu-Gap-02).

    v2.25.0 / Lu-Gap-06 / W0a / P3 mcp.rego.
    """

    event_type: str = EventType.OPA_DECISION_ON_MCP
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    tenant_id: str = ""
    agent_name: str = ""
    tool_name: str = ""
    server_id: str = ""
    request_id: str = ""
    decision: str = ""           # "allow" | "deny" | "redact"
    deny_reason: str = ""        # label if denied: "sensitivity_ceiling" | "budget" | "chain_depth_exceeded" | "not_in_allowlist"
    # FIX-F(1) / Iris FIND-002: tool_sensitivity removed.
    # mcp.rego's mcp_decision compound document does NOT return a tool_sensitivity
    # field — the policy does not classify individual tool sensitivity labels.
    # An always-empty string is misleading in audit records and suggests a
    # capability the policy layer doesn't implement.  Removed rather than left
    # as a permanently-empty stub.  If the policy gains tool sensitivity
    # classification in a future sprint, re-add with a matching rego key.
    # FIX-E (Lu FIX-3): persist the full SPIFFE identity chain (ordered list) so
    # an auditor sees WHICH identities were in the chain, not just how many.
    # G5 multi-hop: previously only chain_depth (int) was recorded.
    # identity_chain is the upstream_chain at the time of OPA evaluation — i.e.
    # the chain the caller presented, before this gateway hop appended its own
    # SPIFFE URI.  For first-hop (mcp-a/mcp-b) this is an empty list.
    identity_chain: list = field(default_factory=list)
    chain_depth: int = 0         # JWT identity chain depth (multi-hop) — kept for backward compat
    elapsed_ms: Optional[int] = None


@dataclass
class EgressAllowUsedEvent(AuditEvent):
    """
    Emitted every time a ring-fenced agent's traffic traverses a declared
    ``egress_allow`` entry (Agent → Caddy → OPA → external destination).

    Used as the covert-channel audit control (TM-URF-023 / G3).  For
    CONFIDENTIAL/RESTRICTED ceiling agents, ``egress_allow`` entries require
    operator justification; this event is the evidence trail for that
    justification.

    Security invariants:
      - The request URL path is truncated to 128 chars and the query string
        is dropped (no raw user-supplied values in the audit log).
      - The response body is never stored.
      - client_identity is the resolved SPIFFE identity slug.

    v2.25.0 / Lu-Gap-06 / W0a / C-adjacent / egress_allow_used audit type.
    """

    event_type: str = EventType.EGRESS_ALLOW_USED
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    tenant_id: str = ""
    agent_name: str = ""
    client_identity: str = ""    # resolved SPIFFE identity slug
    egress_entry: str = ""       # the egress_allow entry label (e.g. "openai.com")
    method: str = ""             # HTTP method
    path_truncated: str = ""     # request path, max 128 chars, query stripped
    upstream_status: Optional[int] = None
    elapsed_ms: Optional[int] = None
