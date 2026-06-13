"""
Unit tests for R25 — compute_health_rollup() criticality-weighted roll-up.

Tests the pure function without any I/O or FastAPI scaffolding so they run
instantly in the pre-push suite.

Test matrix:
  - all ok                        → "ok"
  - critical service down         → "critical"   (Caddy, Gateway)
  - non-critical service down     → "degraded"   (Redis, Postgres, OPA, …)
  - both critical and non-critical down → "critical" (most severe wins)
  - empty list                    → "ok"
  - "not_configured" status       → treated as healthy (non-breaking)
  - "community" status            → treated as healthy (non-breaking)
"""
from __future__ import annotations

import pytest
from yashigani.backoffice.routes.dashboard import compute_health_rollup


class TestRollupAllGreen:
    def test_empty_list_returns_ok(self):
        assert compute_health_rollup([]) == "ok"

    def test_all_ok(self):
        services = [
            {"name": "caddy", "status": "ok", "criticality": True},
            {"name": "gateway", "status": "ok", "criticality": True},
            {"name": "redis", "status": "ok", "criticality": False},
            {"name": "postgres", "status": "ok", "criticality": False},
        ]
        assert compute_health_rollup(services) == "ok"

    def test_not_configured_counts_as_healthy(self):
        services = [
            {"name": "caddy", "status": "ok", "criticality": True},
            {"name": "opa", "status": "not_configured", "criticality": False},
        ]
        assert compute_health_rollup(services) == "ok"

    def test_community_counts_as_healthy(self):
        services = [
            {"name": "caddy", "status": "ok", "criticality": True},
            {"name": "kms", "status": "community", "criticality": False},
        ]
        assert compute_health_rollup(services) == "ok"


class TestRollupCritical:
    def test_caddy_down_returns_critical(self):
        """Caddy is sole ingress → critical."""
        services = [
            {"name": "caddy", "status": "critical", "criticality": True},
            {"name": "gateway", "status": "ok", "criticality": True},
            {"name": "redis", "status": "ok", "criticality": False},
        ]
        assert compute_health_rollup(services) == "critical"

    def test_gateway_down_returns_critical(self):
        """Gateway is critical."""
        services = [
            {"name": "caddy", "status": "ok", "criticality": True},
            {"name": "gateway", "status": "degraded", "criticality": True},
        ]
        assert compute_health_rollup(services) == "critical"

    def test_critical_service_degraded_status_also_critical(self):
        """Any non-ok status on a critical service → critical."""
        services = [
            {"name": "gateway", "status": "degraded", "criticality": True},
        ]
        assert compute_health_rollup(services) == "critical"

    def test_critical_beats_non_critical_when_both_down(self):
        """Critical service + non-critical service both down → critical (not degraded)."""
        services = [
            {"name": "caddy", "status": "critical", "criticality": True},
            {"name": "redis", "status": "critical", "criticality": False},
        ]
        assert compute_health_rollup(services) == "critical"


class TestRollupDegraded:
    def test_non_critical_redis_down_returns_degraded(self):
        """Redis is non-critical → degraded."""
        services = [
            {"name": "caddy", "status": "ok", "criticality": True},
            {"name": "gateway", "status": "ok", "criticality": True},
            {"name": "redis", "status": "critical", "criticality": False},
        ]
        assert compute_health_rollup(services) == "degraded"

    def test_non_critical_postgres_down_returns_degraded(self):
        services = [
            {"name": "caddy", "status": "ok", "criticality": True},
            {"name": "postgres", "status": "degraded", "criticality": False},
        ]
        assert compute_health_rollup(services) == "degraded"

    def test_opa_down_returns_degraded(self):
        services = [
            {"name": "caddy", "status": "ok", "criticality": True},
            {"name": "gateway", "status": "ok", "criticality": True},
            {"name": "opa", "status": "degraded", "criticality": False},
        ]
        assert compute_health_rollup(services) == "degraded"

    def test_backoffice_down_returns_degraded(self):
        services = [
            {"name": "caddy", "status": "ok", "criticality": True},
            {"name": "backoffice", "status": "degraded", "criticality": False},
        ]
        assert compute_health_rollup(services) == "degraded"


class TestRollupEdgeCases:
    def test_unknown_service_no_criticality_key_defaults_false(self):
        """Missing criticality key → defaults to False → non-critical → degraded."""
        services = [
            {"name": "mystery", "status": "critical"},
            # no 'criticality' key
        ]
        assert compute_health_rollup(services) == "degraded"

    def test_single_critical_service_ok(self):
        services = [{"name": "caddy", "status": "ok", "criticality": True}]
        assert compute_health_rollup(services) == "ok"

    def test_single_non_critical_service_ok(self):
        services = [{"name": "redis", "status": "ok", "criticality": False}]
        assert compute_health_rollup(services) == "ok"
