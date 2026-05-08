"""
Yashigani Backoffice — Singleton application state.
Holds references to shared services injected at startup.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Any

from yashigani.auth.local_auth import LocalAuthService  # noqa: F401 — back-compat
from yashigani.auth.session import SessionStore
from yashigani.audit.writer import AuditLogWriter
from yashigani.kms.base import KSMProvider
from yashigani.kms.rotation import KSMRotationScheduler
from yashigani.inspection.pipeline import InspectionPipeline
from yashigani.chs.handle import CredentialHandleService
from yashigani.chs.resource_monitor import ResourceMonitor
from yashigani.ratelimit.limiter import RateLimiter
from yashigani.rbac.store import RBACStore
from yashigani.agents.registry import AgentRegistry
from yashigani.auth.broker import IdentityBroker


@dataclass
class BackofficeState:
    # v2.23.1 P0-2: auth_service is now PostgresLocalAuthService (async, durable).
    # Typed Any to avoid circular import through the DB pool; constructed in the
    # FastAPI lifespan after create_pool() completes.
    auth_service: Optional[Any] = None
    session_store: Optional[SessionStore] = None
    audit_writer: Optional[AuditLogWriter] = None
    kms_provider: Optional[KSMProvider] = None
    rotation_scheduler: Optional[KSMRotationScheduler] = None
    inspection_pipeline: Optional[InspectionPipeline] = None
    chs: Optional[CredentialHandleService] = None
    resource_monitor: Optional[ResourceMonitor] = None
    rate_limiter: Optional[RateLimiter] = None
    rbac_store: Optional[RBACStore] = None
    agent_registry: Optional[AgentRegistry] = None
    identity_broker: Optional[IdentityBroker] = None    # v2.1 — SSO
    identity_registry: Optional[Any] = None              # v2.1 — SSO identity resolution
    # BackendRegistry and BackendConfigStore use Optional[Any] to avoid
    # circular imports — inspection/ would create a circular dependency chain
    # through state.py if imported directly.
    backend_registry: Optional[Any] = None      # BackendRegistry instance
    backend_config_store: Optional[Any] = None  # BackendConfigStore instance
    inference_logger: Optional[Any] = None      # InferencePayloadLogger (v0.5.0)
    anomaly_detector: Optional[Any] = None      # AnomalyDetector (v0.5.0)
    response_cache: Optional[Any] = None        # ResponseCache (v0.5.0)
    license_state: Optional[Any] = None         # LicenseState (v0.6.0)
    alert_config: Optional[Any] = None          # AlertConfigRequest (v0.7.0)
    ratelimit_config_last_changed: Optional[str] = None  # ISO-8601 UTC (v0.8.0)
    webauthn_service: Optional[Any] = None               # WebAuthnService (v0.9.0) — in-memory, deprecated
    pg_webauthn_service: Optional[Any] = None            # PgWebAuthnService (v2.23.3) — DB+Redis backed
    event_bus: Optional[Any] = None                      # EventBus (v0.9.0)
    response_inspection_pipeline: Optional[Any] = None   # ResponseInspectionPipeline (v1.0)
    model_alias_store: Optional[Any] = None               # ModelAliasStore (v2.3)
    # SIEM sink runtime config (updated via /admin/audit/siem/config)
    siem_backend: str = "none"
    siem_endpoint: Optional[str] = None
    siem_wazuh_auto_deploy: bool = False
    opa_url: str = "https://policy:8181"
    ollama_url: str = "http://ollama:11434"
    # Admin minimum enforcement
    admin_min_total: int = 2
    admin_min_active: int = 2
    admin_soft_target: int = 3
    user_min_total: int = 1


# Module-level singleton — populated at application startup
backoffice_state = BackofficeState()
