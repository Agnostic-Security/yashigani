"""
E2E: Budget enforcement — exhaust budget, verify degradation.

Tests the three-tier budget system against running budget-redis.
Simulates budget exhaustion and verifies routing degrades to local.

Requires: running Yashigani stack with budget-redis healthy.

Last updated: 2026-04-24T22:45:00+01:00
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

import pytest

from tests.e2e.conftest import runtime_exec, runtime_run


def _exec_in_budget_redis(cmd: str) -> str:
    """Execute a Redis command in budget-redis.

    Post-mTLS: budget-redis listens on port 6380 with TLS.
    We use redis-cli --tls with the budget-redis client cert.
    """
    pw_result = runtime_exec(
        f"{_YTF_PROJ}{_YTF_SEP}budget-redis{_YTF_SEP}1", "cat", "/run/secrets/redis_password", timeout=5,
    )
    pw = pw_result.stdout.strip()
    result = runtime_exec(
        f"{_YTF_PROJ}{_YTF_SEP}budget-redis{_YTF_SEP}1",
        "redis-cli",
        "--tls",
        "--cert", "/run/secrets/budget-redis_client.crt",
        "--key",  "/run/secrets/budget-redis_client.key",
        "--cacert", "/run/secrets/ca_root.crt",
        "-h", "localhost",
        "-p", "6380",
        "-a", pw,
        *cmd.split(),
        timeout=10,
    )
    return result.stdout.strip()


class TestBudgetRedis:
    """Test budget-redis is running and accessible."""

    def test_budget_redis_healthy(self):
        result = _exec_in_budget_redis("PING")
        assert "PONG" in result

    def test_budget_redis_noeviction(self):
        """Verify noeviction policy is set."""
        result = _exec_in_budget_redis("CONFIG GET maxmemory-policy")
        assert "noeviction" in result


class TestBudgetEnforcement:
    """Test budget enforcement with real Redis."""

    def test_record_and_check_budget(self):
        """Record usage and verify budget state changes."""
        output = runtime_run(f"{_YTF_PROJ}{_YTF_SEP}gateway{_YTF_SEP}1", """
import redis, os, json, ssl
from urllib.parse import quote

pw = open('/run/secrets/redis_password').read().strip()
# Post-mTLS: budget-redis requires TLS on port 6380 with mutual auth.
ssl_ctx = ssl.create_default_context(cafile='/run/secrets/ca_root.crt')
ssl_ctx.load_cert_chain('/run/secrets/gateway_client.crt', '/run/secrets/gateway_client.key')
r = redis.from_url(
    f"rediss://:{quote(pw, safe='')}@budget-redis:6380/0",
    decode_responses=False,
    ssl_cert_reqs=ssl.CERT_REQUIRED,
    ssl_ca_certs='/run/secrets/ca_root.crt',
    ssl_certfile='/run/secrets/gateway_client.crt',
    ssl_keyfile='/run/secrets/gateway_client.key',
)
r.ping()

from yashigani.billing.budget_enforcer import BudgetEnforcer, BudgetSignal

enforcer = BudgetEnforcer(redis_client=r)

# Check initial state — should be NORMAL
state = enforcer.check("test-e2e-user", "anthropic", budget_total=1000)
print(f"initial:{state.signal.value}:{state.pct}")

# Record some usage
enforcer.record("test-e2e-user", "anthropic", tokens=850)

# Check again — should be WARN (85%)
state = enforcer.check("test-e2e-user", "anthropic", budget_total=1000)
print(f"after850:{state.signal.value}:{state.pct}")

# Record more — exhaust budget
enforcer.record("test-e2e-user", "anthropic", tokens=200)

# Check — should be EXHAUSTED (105%)
state = enforcer.check("test-e2e-user", "anthropic", budget_total=1000)
print(f"exhausted:{state.signal.value}:{state.pct}")

# Clean up test keys
import time
from yashigani.billing.budget_enforcer import _period_key
pk = _period_key("monthly")
r.delete(f"budget:identity:test-e2e-user:anthropic:{pk}")
print("cleanup:done")
""")
        lines = output.strip().split("\n")
        results = {l.split(":")[0]: l for l in lines if ":" in l}

        assert "initial:normal:0" in results.get("initial", "")
        assert "warn" in results.get("after850", "")
        assert "exhausted" in results.get("exhausted", "")
        assert "cleanup:done" in results.get("cleanup", "")

    def test_three_tier_recording(self):
        """Verify usage recorded at identity, group, and org levels."""
        output = runtime_run(f"{_YTF_PROJ}{_YTF_SEP}gateway{_YTF_SEP}1", """
import redis, os, ssl
from urllib.parse import quote

pw = open('/run/secrets/redis_password').read().strip()
# Post-mTLS: budget-redis requires TLS on port 6380 with mutual auth.
r = redis.from_url(
    f"rediss://:{quote(pw, safe='')}@budget-redis:6380/0",
    decode_responses=False,
    ssl_cert_reqs=ssl.CERT_REQUIRED,
    ssl_ca_certs='/run/secrets/ca_root.crt',
    ssl_certfile='/run/secrets/gateway_client.crt',
    ssl_keyfile='/run/secrets/gateway_client.key',
)

from yashigani.billing.budget_enforcer import BudgetEnforcer, _period_key

enforcer = BudgetEnforcer(redis_client=r)
pk = _period_key("monthly")

# Record with all three tiers
enforcer.record("e2e-alice", "openai", tokens=500, group_ids=["e2e-eng"], org_id="e2e-acme")

# Verify all three counters
identity_used = int(r.get(f"budget:identity:e2e-alice:openai:{pk}") or 0)
group_used = int(r.get(f"budget:group:e2e-eng:openai:{pk}") or 0)
org_used = int(r.get(f"budget:org:e2e-acme:openai:{pk}") or 0)

print(f"identity:{identity_used}")
print(f"group:{group_used}")
print(f"org:{org_used}")

# Cleanup
r.delete(f"budget:identity:e2e-alice:openai:{pk}")
r.delete(f"budget:group:e2e-eng:openai:{pk}")
r.delete(f"budget:org:e2e-acme:openai:{pk}")
print("cleanup:done")
""")
        lines = output.strip().split("\n")
        assert "identity:500" in lines
        assert "group:500" in lines
        assert "org:500" in lines
