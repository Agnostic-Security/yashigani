"""
Yashigani Backoffice — Optional service management.

Admins can enable/disable optional compose-profile services from the
admin panel without SSH access or re-running the installer.

Services: openwebui, wazuh, internal-ca, langflow, letta, openclaw.

All operations are API calls that exec podman/docker compose commands.

Security (ACS gap #95 — BFLA):
  GET  /admin/services         — AdminSession (read-only)
  POST /admin/services/{id}    — StepUpAdminSession (mutating — starts/stops
                                 system services, ASVS V6.8.4 step-up required)

Last updated: 2026-05-09T00:00:00+01:00
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import AdminSession, StepUpAdminSession
from yashigani.common.error_envelope import safe_error_envelope

router = APIRouter(prefix="/admin/services", tags=["services"])
_log = logging.getLogger("yashigani.services")

# Known optional services and their compose profiles
_OPTIONAL_SERVICES = {
    "openwebui": {
        "profile": "openwebui",
        "name": "Open WebUI",
        "description": "Browser-based AI chat interface for end users",
    },
    "wazuh": {
        "profile": "wazuh",
        "name": "Wazuh SIEM",
        "description": "Security monitoring — manager + indexer + dashboard",
    },
    "internal-ca": {
        "profile": "internal-ca",
        "name": "Internal CA",
        "description": "Smallstep CA for service-to-service TLS",
    },
    "langflow": {
        "profile": "langflow",
        "name": "Lala (Langflow)",
        "description": "Visual multi-agent workflow builder",
    },
    "letta": {"profile": "letta", "name": "Julietta (Letta)", "description": "Stateful agent with persistent memory"},
    "openclaw": {
        "profile": "openclaw",
        "name": "Scout (OpenClaw)",
        "description": "Connected agent with web search and messaging",
    },
}


def _enabled_profiles() -> set[str]:
    """Optional-service profiles deployed at install time.

    The hardened backoffice container has NO Docker socket/binary/compose file, so
    it cannot shell out to `compose ps` (that always failed -> every service showed
    "stopped"). Optional services are a deploy-time/IaC choice; install.sh records
    the enabled set in YASHIGANI_ENABLED_PROFILES (comma/space separated), which we
    read here. This is the source of truth, topology-independent, no Docker access.
    """
    raw = os.getenv("YASHIGANI_ENABLED_PROFILES", "")
    return {p.strip() for p in raw.replace(",", " ").split() if p.strip()}


def _is_service_running(profile: str) -> bool:
    """A service is 'running' iff its profile was enabled at deploy time."""
    return profile in _enabled_profiles()


@router.get("")
async def list_services(session: AdminSession):
    """List all optional services with their current status."""
    services = []
    for svc_id, svc_info in _OPTIONAL_SERVICES.items():
        running = _is_service_running(svc_info["profile"])
        services.append(
            {
                "id": svc_id,
                "name": svc_info["name"],
                "description": svc_info["description"],
                "profile": svc_info["profile"],
                "status": "running" if running else "stopped",
            }
        )
    return {"services": services}


class ServiceAction(BaseModel):
    action: str = Field(pattern="^(enable|disable)$")


@router.post("/{service_id}")
async def manage_service(service_id: str, body: ServiceAction, session: StepUpAdminSession):
    """
    Optional services are a DEPLOY-TIME / IaC choice — not toggled at runtime.

    The admin plane cannot (and must not) drive the host container engine: the
    backoffice container has no Docker socket/binary by design, and a runtime
    "enable" would be config drift plus a half-provisioned service (Wazuh/internal-CA
    need install.sh secret+cert+OPA provisioning, not a bare `compose up`). So this
    endpoint is informational: it explains how to change the set (re-run the
    installer with the profile flag). See opa/services design notes + CLAUDE.md.
    Runtime toggling, if ever required, is a future operator/reconciler feature.
    """
    if service_id not in _OPTIONAL_SERVICES:
        raise HTTPException(
            status_code=404, detail={"error": "unknown_service", "available": list(_OPTIONAL_SERVICES.keys())}
        )
    svc = _OPTIONAL_SERVICES[service_id]
    _log.info(
        "Admin %s requested %s for service %s — deploy-time managed, no runtime action",
        session.account_id, body.action, service_id,
    )
    return {
        "status": "deploy_time_managed",
        "service": service_id,
        "action": body.action,
        "message": (
            f"{svc['name']} is selected at install time, not from the console. To "
            f"{body.action} it, re-run the installer with the '--{svc['profile']}' "
            f"profile (this is part of an update/redeploy and preserves data volumes)."
        ),
        "profile": svc["profile"],
    }
