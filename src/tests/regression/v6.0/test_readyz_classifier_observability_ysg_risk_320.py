# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Classifier reachability is observable, ping-free — YSG-RISK-320.

Captain (red council) found a fleet-wide classifier outage would be INVISIBLE:
/healthz (wired into every probe) does no dependency check, and /readyz checked
only postgres+redis. The fix surfaces the classifier's circuit-breaker state in
/readyz.

Two properties are load-bearing and tested here:
  1. PING-FREE — breaker_status() must NOT call health_check() (a live GET to
     the classifier). /readyz is probed frequently; a live ping per probe would
     add load to the single-replica classifier it is observing, i.e. become part
     of the very DoS 320 is about.
  2. It reflects the breaker state that REAL traffic maintains — degraded when
     the active backend's circuit is open, healthy otherwise.
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock

from yashigani.inspection.backend_registry import BackendRegistry


def _registry() -> tuple[BackendRegistry, MagicMock]:
    backend = MagicMock()
    backend.name = "ollama"
    reg = BackendRegistry(
        active_backend=backend, fallback_chain=[], all_backends={"ollama": backend}
    )
    return reg, backend


def test_breaker_status_is_ping_free() -> None:
    """The whole point: no live health_check() on a readiness probe."""
    reg, backend = _registry()
    reg.breaker_status()
    backend.health_check.assert_not_called()


def test_healthy_when_no_circuit_open() -> None:
    reg, _ = _registry()
    status = reg.breaker_status()
    assert status["active"] == "ollama"
    assert status["active_circuit_open"] is False
    assert status["open_circuits"] == []


def test_degraded_when_active_circuit_open() -> None:
    """A tripped breaker (set by real traffic failures) shows as degraded."""
    reg, _ = _registry()
    reg._breaker_opened_at["ollama"] = time.monotonic()  # simulate real-traffic trip
    status = reg.breaker_status()
    assert status["active_circuit_open"] is True
    assert "ollama" in status["open_circuits"]


def test_cooled_down_circuit_reports_recovered() -> None:
    """After the cooldown elapses the breaker half-opens — no longer degraded,
    so readiness recovers on its own without a probe-driven ping."""
    from yashigani.inspection import backend_registry as m

    reg, _ = _registry()
    reg._breaker_opened_at["ollama"] = time.monotonic() - (m._BREAKER_COOLDOWN_SECONDS + 1)
    assert reg.breaker_status()["active_circuit_open"] is False
