"""
E2E test configuration.

These tests require a running Yashigani stack (docker/podman compose up).
Skip if the stack is not running.

Run with: pytest src/tests/e2e/ -v

Last updated: 2026-04-27T21:53:12+01:00
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional
import pytest
import httpx


# ---------------------------------------------------------------------------
# TLS trust anchor — M-04 (CLAUDE.md §3: no verify=False ever)
# ---------------------------------------------------------------------------
# Pattern A for Python ssl: workloads trust ca_root.crt (refined post gate
# #58a evidence — Python 3.12/OpenSSL 3.0/Ubuntu 24.04 strict-chain validation
# rejects intermediate-only anchors). httpx + the test harness use Python ssl,
# so they get ca_root.crt. Caddy/postgres/Go consumers stay on Pattern B
# elsewhere in the codebase.
# Resolution order:
#   1. YASHIGANI_CA_CERT env var (explicit override for custom deploys / CI)
#   2. docker/secrets/ca_root.crt          (macOS local deploy)
#   3. /run/secrets/ca_root.crt            (container / linux deploy)
#
# If none of the candidates exist the probe falls through to a socket error
# (httpx raises on missing CA file), which causes _stack_running() to return
# False — the test suite skips correctly.  TLS misconfiguration is no longer
# silently hidden (M-04).
def _resolve_ca_cert() -> Optional[str]:
    """Return path to the public root CA cert, or None if not found."""
    explicit = os.getenv("YASHIGANI_CA_CERT")
    if explicit:
        return explicit
    candidates = [
        # macOS local deploy: docker/secrets relative to repo root
        # parents[0]=e2e/ parents[1]=tests/ parents[2]=src/ parents[3]=repo-root/
        Path(__file__).parents[3] / "docker" / "secrets" / "ca_root.crt",
        # Linux container or VM deploy
        Path("/run/secrets/ca_root.crt"),
    ]
    for p in candidates:
        if p.exists():
            return str(p)
    return None


# Resolved once at import — all health-check probes in this module use this value.
_CA_CERT_PATH: str | None = _resolve_ca_cert()


def _detect_runtime() -> str:
    """
    Detect whether to use 'podman' or 'docker' for container commands.
    Checks YASHIGANI_RUNTIME env var first, then probes for running containers.
    """
    env_runtime = os.getenv("YASHIGANI_RUNTIME", "").lower()
    if env_runtime in ("podman", "docker"):
        return env_runtime

    # Check if podman has running containers
    if shutil.which("podman"):
        try:
            result = subprocess.run(
                ["podman", "ps", "--format", "{{.Names}}"],
                capture_output=True, text=True, timeout=5,
            )
            if "docker-gateway-1" in result.stdout:
                return "podman"
        except Exception:
            pass

    # Check if docker has running containers
    if shutil.which("docker"):
        try:
            result = subprocess.run(
                ["docker", "ps", "--format", "{{.Names}}"],
                capture_output=True, text=True, timeout=5,
            )
            if "docker-gateway-1" in result.stdout:
                return "docker"
        except Exception:
            pass

    # Default to docker
    return "docker"


# Module-level runtime — computed once, used by all tests
RUNTIME = _detect_runtime()


def runtime_exec(container: str, *cmd: str, timeout: int = 15) -> subprocess.CompletedProcess:
    """Execute a command in a container using the detected runtime."""
    return subprocess.run(
        [RUNTIME, "exec", container, *cmd],
        capture_output=True, text=True, timeout=timeout,
    )


def runtime_run(container: str, python_code: str, timeout: int = 30) -> str:
    """Execute Python code inside a container. Returns stdout."""
    result = runtime_exec(container, "python3", "-c", python_code, timeout=timeout)
    return result.stdout.strip()


def container_running(name: str) -> bool:
    """Check if a container is running."""
    result = subprocess.run(
        [RUNTIME, "ps", "--filter", f"name={name}", "--format", "{{.Status}}"],
        capture_output=True, text=True, timeout=5,
    )
    return "Up" in result.stdout


def container_healthy(name: str) -> bool:
    """
    Check if a container is healthy.
    Falls back to checking if the container is running and responds
    to exec, since Podman 4.x sometimes gets stuck in 'unhealthy'
    even when healthcheck commands pass.
    """
    result = subprocess.run(
        [RUNTIME, "inspect", name, "--format", "{{.State.Health.Status}}"],
        capture_output=True, text=True, timeout=5,
    )
    if "healthy" in result.stdout and "unhealthy" not in result.stdout:
        return True
    # Fallback: check if container is running and responds to exec
    if container_running(name):
        try:
            probe = subprocess.run(
                [RUNTIME, "exec", name, "true"],
                capture_output=True, timeout=5,
            )
            return probe.returncode == 0
        except Exception:
            pass
    return False


def container_kill(name: str) -> None:
    """
    Kill a container and restart it.

    Podman rootless does not auto-restart containers after 'kill'
    (unlike Docker). We explicitly start the container after killing
    to simulate the self-healing behavior.
    """
    subprocess.run([RUNTIME, "kill", name], capture_output=True, timeout=10)
    import time
    time.sleep(2)
    # Podman needs explicit restart after kill — Docker auto-restarts
    # via restart: unless-stopped, but Podman 4.x doesn't.
    subprocess.run([RUNTIME, "start", name], capture_output=True, timeout=10)


def container_start(name: str) -> None:
    """Start a stopped container."""
    subprocess.run([RUNTIME, "start", name], capture_output=True, timeout=10)


def _stack_running() -> bool:
    """Check if the gateway is reachable.

    Probes, in order, the host ports the installer is known to bind to:
      * https://localhost/healthz        (Caddy on :443 — Linux / root-capable)
      * https://localhost:8443/healthz   (Caddy on :8443 — macOS default)
      * http://localhost:8080/healthz    (gateway direct, when Caddy is off)
      * YASHIGANI_HEALTH_URL              (explicit override for custom deploys)

    Fixed for QA Wave 2 Issue #33 — previously hard-coded :443 which
    missed macOS installs (installer uses :8443 to avoid root-privilege
    socket binding), causing all e2e tests to silently skip with
    "Yashigani stack not running".
    """
    candidates = []
    override = os.getenv("YASHIGANI_HEALTH_URL")
    if override:
        candidates.append(override)
    candidates.extend([
        "https://localhost/healthz",
        "https://localhost:8443/healthz",
        "http://localhost:8080/healthz",
    ])
    # M-04: use the real CA intermediate cert so TLS misconfiguration is not
    # invisible to the harness.  _CA_CERT_PATH is resolved from env or the
    # repo's docker/secrets/ directory at import time.  http:// URLs skip TLS.
    # If _CA_CERT_PATH is None (CA file not yet deployed) httpx raises on
    # https:// URLs and we fall through to the http:// fallback or container exec.
    for url in candidates:
        try:
            verify = _CA_CERT_PATH if url.startswith("https://") else False  # type: ignore[assignment]
            r = httpx.get(url, verify=verify, timeout=3)
            if r.status_code == 200:
                return True
        except Exception:
            continue

    # Last-resort: exec into the gateway container if one exists under
    # any of the common name variants.
    for name in ("docker-gateway-1", "docker_gateway_1", "yashigani-gateway-1"):
        try:
            result = runtime_exec(
                name, "python3", "-c",
                "import urllib.request; print(urllib.request.urlopen('http://localhost:8080/healthz').read().decode())",
                timeout=10,
            )
            if "ok" in (result.stdout or ""):
                return True
        except Exception:
            continue
    return False


def pytest_collection_modifyitems(config, items):
    """Skip all e2e tests if stack is not running."""
    if not _stack_running():
        skip = pytest.mark.skip(reason="Yashigani stack not running — start with docker/podman compose up")
        for item in items:
            if "e2e" in str(item.fspath):
                item.add_marker(skip)
