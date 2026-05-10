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
import subprocess
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


def _get_compose_cmd() -> list[str]:
    """Detect the compose command (podman compose or docker compose)."""
    for cmd in [["podman", "compose"], ["docker", "compose"]]:
        try:
            subprocess.run(cmd + ["version"], capture_output=True, timeout=5)
            return cmd
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return ["docker", "compose"]


def _get_compose_file() -> str:
    """Find the docker-compose.yml path."""
    # Check common locations
    for path in [
        Path("/app/docker/docker-compose.yml"),  # inside container
        Path(os.getenv("YASHIGANI_COMPOSE_FILE", "")),
        Path.home() / "yashigani" / "docker" / "docker-compose.yml",
    ]:
        if path.exists():
            return str(path)
    return "docker/docker-compose.yml"


def _is_service_running(profile: str) -> bool:
    """Check if a profiled service is currently running."""
    try:
        cmd = _get_compose_cmd()
        compose_file = _get_compose_file()
        result = subprocess.run(
            cmd + ["-f", compose_file, "--profile", profile, "ps", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return bool(result.stdout.strip())
    except Exception:
        return False


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
    Enable or disable an optional service.

    ACS gap #95 (BFLA): upgraded from AdminSession to StepUpAdminSession.
    Starting or stopping system services is a high-value mutating action —
    ASVS V6.8.4 requires step-up TOTP re-verification within 5 minutes.
    A step-up token can be obtained from POST /auth/stepup.
    """
    if service_id not in _OPTIONAL_SERVICES:
        raise HTTPException(
            status_code=404, detail={"error": "unknown_service", "available": list(_OPTIONAL_SERVICES.keys())}
        )

    svc = _OPTIONAL_SERVICES[service_id]
    profile = svc["profile"]
    compose_file = _get_compose_file()
    cmd = _get_compose_cmd()

    try:
        if body.action == "enable":
            _log.info("Admin %s enabling service: %s (profile=%s)", session.account_id, service_id, profile)
            result = subprocess.run(
                cmd + ["-f", compose_file, "--profile", profile, "up", "-d"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode != 0:
                raise HTTPException(
                    status_code=500,
                    detail={
                        "error": "service_start_failed",
                        "stderr": result.stderr[-500:] if result.stderr else "",
                    },
                )
            return {
                "status": "ok",
                "service": service_id,
                "action": "enabled",
                "message": f"{svc['name']} is starting. It may take a minute to become healthy.",
            }

        elif body.action == "disable":
            _log.info("Admin %s disabling service: %s (profile=%s)", session.account_id, service_id, profile)
            result = subprocess.run(
                cmd + ["-f", compose_file, "--profile", profile, "stop"],
                capture_output=True,
                text=True,
                timeout=60,
            )
            return {
                "status": "ok",
                "service": service_id,
                "action": "disabled",
                "message": f"{svc['name']} stopped. Data volumes preserved.",
            }

    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=504,
            detail={"error": "timeout", "message": "Service operation timed out. Check container logs."},
        )
    except HTTPException:
        raise
    except Exception as exc:
        payload, _ = safe_error_envelope(exc, public_message="service management failed", status=500)
        raise HTTPException(status_code=500, detail=payload)
