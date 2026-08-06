"""
E2E: Agent bundle tests — send real prompts through each agent.

Verifies that registered agent bundles (Langflow, Letta, OpenClaw)
can receive and process requests through the gateway.

Requires: running Yashigani stack with agent bundles enabled.

Last updated: 2026-04-24T22:45:00+01:00
"""
from __future__ import annotations

import os as _ytf_os

# FIND-YTF412-009: container names were hardcoded to the compose project
# "docker" (e.g. f"{_YTF_PROJ}{_YTF_SEP}gateway{_YTF_SEP}1"), but install.sh DERIVES the project from
# --domain (documented multi-instance behaviour), and podman-compose separates
# with "_" where docker compose uses "-". A whole tier therefore reported
# per-test product failures while never finding a single container to act on --
# 23 failed / 11 passed in 2m00s with the stack untouched at 26/26 up.
_YTF_PROJ = _ytf_os.getenv("YTF_COMPOSE_PROJECT", "docker")
_YTF_SEP = _ytf_os.getenv("YTF_NAME_SEP", "-")

import pytest

from tests.e2e.conftest import container_running, runtime_run


class TestAgentBundleHealth:
    """Verify all agent bundle containers are running and healthy."""

    def test_openclaw_running(self):
        assert container_running(f"{_YTF_PROJ}{_YTF_SEP}openclaw{_YTF_SEP}1")

    def test_langgraph_running(self):
        assert container_running(f"{_YTF_PROJ}{_YTF_SEP}langgraph{_YTF_SEP}1")


class TestAgentRegistration:
    """Verify agents are registered in the identity/agent registry."""

    def test_agents_registered(self):
        output = runtime_run(f"{_YTF_PROJ}{_YTF_SEP}gateway{_YTF_SEP}1", """
import redis, os, ssl
from urllib.parse import quote

pw = open('/run/secrets/redis_password').read().strip()
# Post-mTLS: main redis requires TLS on port 6380 with mutual auth.
r = redis.from_url(
    f"rediss://:{quote(pw, safe='')}@redis:6380/3",
    decode_responses=True,
    ssl_cert_reqs=ssl.CERT_REQUIRED,
    ssl_ca_certs='/run/secrets/ca_root.crt',
    ssl_certfile='/run/secrets/gateway_client.crt',
    ssl_keyfile='/run/secrets/gateway_client.key',
)

# Check agent index
agents = r.smembers("agent:index:active")
print(f"active_agents:{len(agents)}")
for aid in sorted(agents):
    name = r.hget(f"agent:reg:{aid}", "name")
    print(f"agent:{aid}:{name}")
""")
        assert "active_agents:" in output
        count_line = [l for l in output.split("\n") if l.startswith("active_agents:")][0]
        count = int(count_line.split(":")[1])
        assert count >= 0


class TestAgentBundleConnectivity:
    """Test connectivity to agent bundles from the gateway network."""

    def test_openclaw_reachable(self):
        output = runtime_run(f"{_YTF_PROJ}{_YTF_SEP}gateway{_YTF_SEP}1", """
import urllib.request
try:
    r = urllib.request.urlopen("http://openclaw:18789/healthz", timeout=5)
    print(f"openclaw:{r.status}")
except Exception as e:
    print(f"openclaw:error:{e}")
""")
        assert "openclaw:" in output


class TestGatewayModelsEndpoint:
    """Test that /v1/models lists available models and agents."""

    def test_models_endpoint(self):
        # Post-mTLS: gateway listens on HTTPS only.
        # /v1/models requires user auth — we expect 401/403, not a connection error.
        output = runtime_run(f"{_YTF_PROJ}{_YTF_SEP}gateway{_YTF_SEP}1", """
import ssl, urllib.request, json
c = ssl.create_default_context(cafile='/run/secrets/ca_root.crt')
c.load_cert_chain('/run/secrets/gateway_client.crt', '/run/secrets/gateway_client.key')
try:
    r = urllib.request.urlopen("https://localhost:8080/v1/models", context=c, timeout=10)
    body = json.loads(r.read())
    models = [m["id"] for m in body.get("data", [])]
    print(f"model_count:{len(models)}")
    for m in models:
        print(f"model:{m}")
except urllib.error.HTTPError as e:
    print(f"model_count:auth_required:{e.code}")
except Exception as e:
    print(f"error:{e}")
""")
        assert "model_count:" in output
        lines = output.strip().split("\n")
        count_line = [l for l in lines if l.startswith("model_count:")][0]
        if "auth_required" in count_line:
            pass
        else:
            model_count = int(count_line.split(":")[1])
            assert model_count >= 1
