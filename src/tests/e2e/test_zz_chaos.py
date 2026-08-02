"""
E2E: Chaos test — self-healing verification.

Last updated: 2026-04-24T22:45:00+01:00

Kill containers while the system is running. Verify:
  1. Container runtime auto-restarts the container (restart: unless-stopped)
  2. Health checks detect the recovery
  3. The system continues to serve requests after recovery

Requires: running Yashigani stack.
"""
import os as _ytf_os

# FIND-YTF412-009: container names were hardcoded to the compose project
# "docker" (e.g. f"{_YTF_PROJ}{_YTF_SEP}gateway{_YTF_SEP}1"), but install.sh DERIVES the project from
# --domain (documented multi-instance behaviour), and podman-compose separates
# with "_" where docker compose uses "-". A whole tier therefore reported
# per-test product failures while never finding a single container to act on --
# 23 failed / 11 passed in 2m00s with the stack untouched at 26/26 up.
_YTF_PROJ = _ytf_os.getenv("YTF_COMPOSE_PROJECT", "docker")
_YTF_SEP = _ytf_os.getenv("YTF_NAME_SEP", "-")
from __future__ import annotations

import time
import pytest

from tests.e2e.conftest import (
    container_healthy,
    container_running,
    container_kill,
    runtime_run,
)


def _wait_for_healthy(name: str, timeout: int = 90) -> bool:
    """Wait until container is healthy, up to timeout seconds."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if container_healthy(name):
            return True
        time.sleep(5)
    return False


def _gateway_healthz() -> bool:
    # Post-mTLS: gateway listens on HTTPS only — use ssl context with gateway cert.
    result = runtime_run(f"{_YTF_PROJ}{_YTF_SEP}gateway{_YTF_SEP}1",
        "import ssl, urllib.request; "
        "c=ssl.create_default_context(cafile='/run/secrets/ca_root.crt'); "
        "c.load_cert_chain('/run/secrets/gateway_client.crt','/run/secrets/gateway_client.key'); "
        "r=urllib.request.urlopen('https://localhost:8080/healthz', context=c); "
        "print(r.read().decode())",
        timeout=10)
    return "ok" in result


class TestChaosOllama:
    """Kill Ollama and verify recovery."""

    def test_ollama_recovers_after_kill(self):
        assert container_running(f"{_YTF_PROJ}{_YTF_SEP}ollama{_YTF_SEP}1"), "Ollama not running before test"

        container_kill(f"{_YTF_PROJ}{_YTF_SEP}ollama{_YTF_SEP}1")
        time.sleep(5)

        # Ollama needs extra time on ARM/CPU-only systems — model reload is slow
        recovered = _wait_for_healthy(f"{_YTF_PROJ}{_YTF_SEP}ollama{_YTF_SEP}1", timeout=300)
        assert recovered, "Ollama did not recover within 300 seconds"

    def test_gateway_stays_healthy_during_ollama_restart(self):
        """Gateway should remain healthy even if Ollama is temporarily down."""
        assert _gateway_healthz(), "Gateway not healthy"


class TestChaosRedis:
    """Kill Redis and verify recovery."""

    def test_redis_recovers_after_kill(self):
        assert container_healthy(f"{_YTF_PROJ}{_YTF_SEP}redis{_YTF_SEP}1")
        container_kill(f"{_YTF_PROJ}{_YTF_SEP}redis{_YTF_SEP}1")
        time.sleep(2)
        recovered = _wait_for_healthy(f"{_YTF_PROJ}{_YTF_SEP}redis{_YTF_SEP}1", timeout=60)
        assert recovered, "Redis did not recover within 60 seconds"


class TestChaosBudgetRedis:
    """Kill budget-redis and verify recovery."""

    def test_budget_redis_recovers_after_kill(self):
        assert container_running(f"{_YTF_PROJ}{_YTF_SEP}budget-redis{_YTF_SEP}1")
        container_kill(f"{_YTF_PROJ}{_YTF_SEP}budget-redis{_YTF_SEP}1")
        time.sleep(2)
        recovered = _wait_for_healthy(f"{_YTF_PROJ}{_YTF_SEP}budget-redis{_YTF_SEP}1", timeout=60)
        assert recovered, "Budget-redis did not recover within 60 seconds"


class TestChaosPostgres:
    """Kill Postgres and verify recovery."""

    def test_postgres_recovers_after_kill(self):
        assert container_healthy(f"{_YTF_PROJ}{_YTF_SEP}postgres{_YTF_SEP}1")
        container_kill(f"{_YTF_PROJ}{_YTF_SEP}postgres{_YTF_SEP}1")
        time.sleep(2)
        recovered = _wait_for_healthy(f"{_YTF_PROJ}{_YTF_SEP}postgres{_YTF_SEP}1", timeout=60)
        assert recovered, "Postgres did not recover within 60 seconds"
