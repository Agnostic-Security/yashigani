"""Backoffice route exports."""
from yashigani.backoffice.routes.auth import router as auth_router
from yashigani.backoffice.routes.accounts import router as accounts_router
from yashigani.backoffice.routes.users import router as users_router
from yashigani.backoffice.routes.kms import router as kms_router
from yashigani.backoffice.routes.audit import router as audit_router
from yashigani.backoffice.routes.inspection import router as inspection_router
from yashigani.backoffice.routes.inspection_backend import router as inspection_backend_router
from yashigani.backoffice.routes.dashboard import router as dashboard_router
from yashigani.backoffice.routes.ratelimit import router as ratelimit_router
from yashigani.backoffice.routes.rbac import router as rbac_router
from yashigani.backoffice.routes.scim import router as scim_router
from yashigani.backoffice.routes.agents import router as agents_router
from yashigani.backoffice.routes.infrastructure import router as infrastructure_router
from yashigani.backoffice.routes.jwt_config import jwt_config_router
from yashigani.backoffice.routes.cache import cache_router
from yashigani.backoffice.routes.audit_sinks import audit_sinks_router
from yashigani.backoffice.routes.kms_vault import kms_vault_router
from yashigani.backoffice.routes.license import license_router
from yashigani.backoffice.routes.opa_assistant import router as opa_assistant_router
from yashigani.backoffice.routes.alerts import router as alerts_router
from yashigani.backoffice.routes.agent_bundles import router as agent_bundles_router
# v0.9.0 — Phase 6 + Phase 7
from yashigani.backoffice.routes.webauthn import router as webauthn_router
from yashigani.backoffice.routes.events import router as events_router
from yashigani.backoffice.routes.audit_search import router as audit_search_router
# v2.1
from yashigani.backoffice.routes.models import router as models_router
from yashigani.backoffice.routes.sensitivity import router as sensitivity_router
from yashigani.backoffice.routes.sso import router as sso_router
# v2.2
from yashigani.backoffice.routes.pii import router as pii_router
# v2.3 — ASVS 11.1.3 crypto inventory
from yashigani.backoffice.routes.crypto_inventory import router as crypto_inventory_router
# ASVS 3.4.7 — CSP report endpoint
from yashigani.backoffice.routes.csp_report import router as csp_report_router
# Service management (enable/disable optional compose profiles from admin panel)
from yashigani.backoffice.routes.services import router as services_router
# v2.23.2 — Backup status + verify (#47)
from yashigani.backoffice.routes.backup import router as backup_router
# v2.23.3 — WebAuthn v1 API with public login + step-up revoke
from yashigani.backoffice.routes.webauthn_v1 import router as webauthn_v1_router

__all__ = [
    "auth_router", "accounts_router", "users_router",
    "kms_router", "audit_router", "inspection_router",
    "inspection_backend_router",
    "dashboard_router", "ratelimit_router",
    "rbac_router", "scim_router", "agents_router",
    "infrastructure_router",
    "jwt_config_router", "cache_router", "audit_sinks_router", "kms_vault_router",
    "license_router", "opa_assistant_router", "alerts_router",
    "agent_bundles_router",
    # v0.9.0
    "webauthn_router", "events_router", "audit_search_router",
    # v2.1
    "models_router",
    "sensitivity_router",
    "sso_router",
    # v2.2
    "pii_router",
    # v2.3
    "crypto_inventory_router",
    # ASVS 3.4.7
    "csp_report_router",
    # v2.23.2 — Backup status + verify (#47)
    "backup_router",
    # v2.23.3 — WebAuthn v1 API
    "webauthn_v1_router",
]
