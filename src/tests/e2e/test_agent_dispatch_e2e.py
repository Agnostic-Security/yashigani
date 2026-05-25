"""
E2E: Agent dispatch round-trip — real LLM response through each agent bundle.

A1 Amendment (2026-05-24): Prior E2E sweeps verified container health and
agent registration but did NOT exercise the actual data path:
  OpenWebUI -> gateway:8081 -> [langflow|letta] -> gateway:8081 -> Ollama

This file was added to close that gap after BUG-V241-LANGFLOW-LETTA-BASE-URL
was found in production.

BUG-V241-LANGFLOW-LETTA-BASE-URL root cause:
  docker-compose.yml configured langflow and letta with:
    OPENAI_API_BASE: http://gateway:8080/v1   (mTLS-only, requires client cert)
  Port 8080: TLS + mutual auth (ssl.CERT_REQUIRED) — rejects plain HTTP
  Port 8081: plain HTTP, internal mesh only, protected by network isolation

The compose-level contract tests (static, no stack needed) are in:
  tests/contracts/test_agent_base_url_port.py (run in every CI push/PR)

This file contains LIVE dispatch tests (stack required):
  - Send real POST /v1/chat/completions through each agent, assert LLM response.
  - Tests SKIP when no stack is running.
  - When stack is running pre-fix: FAIL (502 agent_unreachable from TLS error).
  - When stack is running post-fix: PASS (200 + non-empty content).

YSG-RISK-059 covers the process gap class.

Control references:
  OWASP ASVS v5 V11.1 (Application Logic)
  A1 amendment principle (feedback_admin_bootstrap_both_admins.md section A1)
  feedback_ground_audit_in_docs_and_ops_before_flagging.md

Last updated: 2026-05-24T00:00:00+00:00
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Expected ports per service (A1 amendment spec)
# ---------------------------------------------------------------------------
_MESH_PORT = 8081   # plain-HTTP internal mesh; agents MUST use this
_MTLS_PORT = 8080   # mTLS-only; agents MUST NOT use this as OPENAI_API_BASE


# ============================================================================
# LIVE dispatch tests (require running stack)
# These are skipped if the stack is not running.  When the stack IS running:
#   - Pre-fix: FAIL (agents get 502 from gateway TLS rejection at port 8080)
#   - Post-fix: PASS (agents get 200 + real LLM response via port 8081)
# ============================================================================

def _detect_runtime() -> str:
    """Detect docker or podman."""
    import os
    import shutil
    env_runtime = os.getenv("YASHIGANI_RUNTIME", "").lower()
    if env_runtime in ("podman", "docker"):
        return env_runtime
    for rt in ("podman", "docker"):
        if shutil.which(rt):
            try:
                r = subprocess.run([rt, "ps", "--format", "{{.Names}}"],
                                   capture_output=True, text=True, timeout=5)
                if "gateway" in r.stdout:
                    return rt
            except Exception:
                pass
    return "docker"


def _container_running(name: str, runtime: str = "docker") -> bool:
    try:
        r = subprocess.run([runtime, "ps", "--filter", f"name={name}",
                           "--format", "{{.Status}}"],
                          capture_output=True, text=True, timeout=5)
        return "Up" in r.stdout
    except Exception:
        return False


def _runtime_run(container: str, python_code: str,
                 runtime: str = "docker", timeout: int = 30) -> str:
    """Execute Python code inside a container, return stdout."""
    r = subprocess.run(
        [runtime, "exec", container, "python3", "-c", python_code],
        capture_output=True, text=True, timeout=timeout,
    )
    return r.stdout.strip()


def _stack_running() -> bool:
    """Quick check: is any Yashigani gateway container running?"""
    runtime = _detect_runtime()
    for name in ("docker-gateway-1", "yashigani-gateway-1"):
        if _container_running(name, runtime):
            return True
    return False


_SKIP_NO_STACK = pytest.mark.skipif(
    not _stack_running(),
    reason="Yashigani stack not running — start with docker/podman compose up",
)


class TestAgentDispatchLive:
    """
    Live end-to-end dispatch: send a real prompt through each agent and
    assert a non-empty LLM response arrives back.

    WHAT THIS TESTS (A1 amendment):
      The full data path for langflow/letta:
        gateway:8081 receives POST /v1/chat/completions from the test harness
        -> gateway identifies model=@langflow|@letta
        -> gateway calls langflow:7860 or letta:8283
        -> agent calls back to gateway:8081/v1 (OPENAI_API_BASE)
        -> gateway calls ollama:11434
        -> response arrives back through the chain
        -> test asserts choices[0].message.content is non-empty

    WHAT PRIOR TESTS PROVED (insufficient — the A1 gap):
      - Container health (healthcheck PASS)
      - Agent registered in Redis
      - /healthz reachable from gateway via exec
      - /v1/models returns a list

    NONE of the prior checks exercised the OPENAI_API_BASE callback leg.
    A misconfigured base URL (8080 instead of 8081) passes all prior checks
    but causes every langflow/letta inference call to fail with a TLS error.
    """

    def _gateway_name(self) -> str:
        runtime = _detect_runtime()
        for name in ("docker-gateway-1", "yashigani-gateway-1"):
            if _container_running(name, runtime):
                return name
        pytest.skip("gateway container not found")

    def _dispatch_via_gateway_internal(
        self, model: str, prompt: str = "Say hello in exactly two words.",
        timeout: int = 90,
    ) -> dict:
        """
        Send a POST /v1/chat/completions to gateway:8081 from inside the
        gateway container (avoids external TLS and auth complexity).

        Returns dict with 'raw' key containing raw stdout output.
        """
        runtime = _detect_runtime()
        gw = self._gateway_name()
        code = (
            "import json, urllib.request, urllib.error\n"
            f"body = json.dumps({{'model': {json.dumps(model)},"
            f" 'messages': [{{'role': 'user', 'content': {json.dumps(prompt)}}}],"
            f" 'stream': False}}).encode()\n"
            "bearer = open('/run/secrets/yashigani_internal_bearer').read().strip()\n"
            "req = urllib.request.Request(\n"
            "    'http://localhost:8081/v1/chat/completions',\n"
            "    data=body,\n"
            "    headers={'Content-Type': 'application/json',\n"
            "             'Authorization': f'Bearer {bearer}'},\n"
            "    method='POST',\n"
            ")\n"
            "try:\n"
            f"    resp = urllib.request.urlopen(req, timeout={timeout - 10})\n"
            "    print('STATUS:200')\n"
            "    print('BODY:' + resp.read().decode())\n"
            "except urllib.error.HTTPError as e:\n"
            "    print(f'STATUS:{e.code}')\n"
            "    print('BODY:' + e.read().decode())\n"
            "except Exception as exc:\n"
            "    print(f'ERROR:{exc}')\n"
        )
        output = _runtime_run(gw, code, runtime=runtime, timeout=timeout)
        return {"raw": output}

    @_SKIP_NO_STACK
    def test_langflow_dispatch_real_llm_response(self):
        """
        Send @langflow model dispatch through gateway and assert real LLM
        response (non-empty choices[0].message.content, HTTP 200).

        FAILS pre-fix: gateway:8080 (mTLS) -> langflow gets TLS handshake
        error when calling OPENAI_API_BASE -> gateway returns 502 agent_unreachable.
        PASSES post-fix: langflow calls gateway:8081 (plain HTTP mesh) successfully.

        Regression for BUG-V241-LANGFLOW-LETTA-BASE-URL.
        """
        if not _container_running("docker-langflow-1", _detect_runtime()):
            pytest.skip("langflow container not running (not in active profiles)")

        result = self._dispatch_via_gateway_internal("@langflow")
        raw = result["raw"]

        assert "STATUS:200" in raw, (
            f"@langflow dispatch returned non-200.\n"
            f"  Raw output: {raw[:500]}\n"
            f"  If STATUS:502 + agent_unreachable: likely BUG-V241-LANGFLOW-LETTA-BASE-URL "
            f"(OPENAI_API_BASE pointing at mTLS port {_MTLS_PORT} instead of mesh port {_MESH_PORT})."
        )

        body_match = re.search(r'BODY:(.*)', raw, re.DOTALL)
        assert body_match, f"No BODY in response: {raw[:300]}"
        body_text = body_match.group(1).strip()

        try:
            body = json.loads(body_text)
        except json.JSONDecodeError:
            pytest.fail(f"Response body is not valid JSON: {body_text[:300]}")

        choices = body.get("choices", [])
        assert choices, f"No choices in response: {body}"
        content = choices[0].get("message", {}).get("content", "")
        assert content, (
            f"choices[0].message.content is empty — langflow returned no text.\n"
            f"  Response: {json.dumps(body, indent=2)[:500]}"
        )

    @_SKIP_NO_STACK
    def test_letta_dispatch_real_llm_response(self):
        """
        Send @letta model dispatch through gateway and assert real LLM response.

        Same assertion class as langflow. Letta additionally requires postgres
        and pgbouncer healthy — a skip is inserted if letta is not in profiles.

        FAILS pre-fix: letta OPENAI_API_BASE -> gateway:8080 mTLS rejection.
        PASSES post-fix: letta OPENAI_API_BASE -> gateway:8081 mesh port.

        Regression for BUG-V241-LANGFLOW-LETTA-BASE-URL.
        """
        if not _container_running("docker-letta-1", _detect_runtime()):
            pytest.skip("letta container not running (not in active profiles)")

        result = self._dispatch_via_gateway_internal("@letta")
        raw = result["raw"]

        assert "STATUS:200" in raw, (
            f"@letta dispatch returned non-200.\n"
            f"  Raw output: {raw[:500]}\n"
            f"  If STATUS:502 + agent_unreachable: likely BUG-V241-LANGFLOW-LETTA-BASE-URL."
        )

        body_match = re.search(r'BODY:(.*)', raw, re.DOTALL)
        assert body_match, f"No BODY in response: {raw[:300]}"
        body_text = body_match.group(1).strip()

        try:
            body = json.loads(body_text)
        except json.JSONDecodeError:
            pytest.fail(f"Response body is not valid JSON: {body_text[:300]}")

        choices = body.get("choices", [])
        assert choices, f"No choices in response: {body}"
        content = choices[0].get("message", {}).get("content", "")
        assert content, (
            f"choices[0].message.content is empty — letta returned no text.\n"
            f"  Response: {json.dumps(body, indent=2)[:500]}"
        )

    @_SKIP_NO_STACK
    def test_openclaw_dispatch_real_llm_response(self):
        """
        Send @openclaw model dispatch through gateway and assert real LLM response.

        OpenClaw uses protocol=openai with upstream http://openclaw:18789.
        The gateway calls OUT to OpenClaw (not the other way round), so
        the OPENAI_API_BASE bug does NOT affect openclaw.

        This test verifies openclaw dispatch works AND documents why openclaw
        is unaffected by BUG-V241-LANGFLOW-LETTA-BASE-URL (different routing
        architecture: gateway->openclaw, not openclaw->gateway).
        """
        if not _container_running("docker-openclaw-1", _detect_runtime()):
            pytest.skip("openclaw container not running (not in active profiles)")

        result = self._dispatch_via_gateway_internal("@openclaw")
        raw = result["raw"]

        assert "STATUS:200" in raw, (
            f"@openclaw dispatch returned non-200.\n"
            f"  Raw output: {raw[:500]}"
        )

        body_match = re.search(r'BODY:(.*)', raw, re.DOTALL)
        assert body_match, f"No BODY in response: {raw[:300]}"
        body_text = body_match.group(1).strip()

        try:
            body = json.loads(body_text)
        except json.JSONDecodeError:
            pytest.fail(f"Response body is not valid JSON: {body_text[:300]}")

        choices = body.get("choices", [])
        assert choices, f"No choices in response: {body}"
        content = choices[0].get("message", {}).get("content", "")
        assert content, (
            f"choices[0].message.content is empty — openclaw returned no text.\n"
            f"  Response: {json.dumps(body, indent=2)[:500]}"
        )

    @_SKIP_NO_STACK
    def test_langflow_gateway_round_trip_from_inside_langflow(self):
        """
        From INSIDE the langflow container: verify that
        http://gateway:<MESH_PORT>/v1/models returns 200 or 401 (port reachable).

        This exercises the EXACT leg that BUG-V241-LANGFLOW-LETTA-BASE-URL broke.
        When OPENAI_API_BASE=http://gateway:8080/v1, this call fails with
        a TLS handshake error (plain HTTP to HTTPS-only port).
        When OPENAI_API_BASE=http://gateway:8081/v1, this call succeeds.

        Note: this test probes the CONFIGURED OPENAI_API_BASE directly.
        It reads the value from the running container environment to
        ground the assertion against ops evidence, not just the compose file.
        """
        if not _container_running("docker-langflow-1", _detect_runtime()):
            pytest.skip("langflow container not running")

        runtime = _detect_runtime()
        code = (
            "import os, urllib.request, urllib.error\n"
            "base_url = os.environ.get('OPENAI_API_BASE', '')\n"
            "if not base_url:\n"
            "    print('ERROR:OPENAI_API_BASE not set'); raise SystemExit(1)\n"
            "print(f'CONFIGURED_BASE_URL:{base_url}')\n"
            "try:\n"
            "    req = urllib.request.Request(f'{base_url}/models')\n"
            "    resp = urllib.request.urlopen(req, timeout=5)\n"
            "    print(f'STATUS:{resp.status}')\n"
            "except urllib.error.HTTPError as e:\n"
            "    print(f'STATUS:{e.code}')\n"
            "except Exception as exc:\n"
            "    print(f'ERROR:{exc}')\n"
        )
        output = _runtime_run("docker-langflow-1", code, runtime=runtime, timeout=15)

        configured_base = ""
        base_match = re.search(r'CONFIGURED_BASE_URL:(.*)', output)
        if base_match:
            configured_base = base_match.group(1).strip()

        assert "ERROR:OPENAI_API_BASE not set" not in output, (
            f"OPENAI_API_BASE not set in langflow container: {output}"
        )

        # Port reachability: 200 (models list) or 401 (auth required) = port works.
        # Any connection error or ssl error = wrong port or network issue.
        assert re.search(r'STATUS:(200|401|403)', output), (
            f"langflow cannot reach gateway at {configured_base!r}.\n"
            f"  Output: {output[:500]}\n"
            f"  If 'ssl' or 'Connection refused' in error: OPENAI_API_BASE uses wrong port.\n"
            f"  Expected port {_MESH_PORT}, got: {configured_base}"
        )

    @_SKIP_NO_STACK
    def test_letta_gateway_round_trip_from_inside_letta(self):
        """
        From INSIDE the letta container: verify gateway:MESH_PORT is reachable.
        Same as langflow round-trip test above.
        """
        if not _container_running("docker-letta-1", _detect_runtime()):
            pytest.skip("letta container not running")

        runtime = _detect_runtime()
        code = (
            "import os, urllib.request, urllib.error\n"
            "base_url = os.environ.get('OPENAI_API_BASE', '')\n"
            "if not base_url:\n"
            "    print('ERROR:OPENAI_API_BASE not set'); raise SystemExit(1)\n"
            "print(f'CONFIGURED_BASE_URL:{base_url}')\n"
            "try:\n"
            "    req = urllib.request.Request(f'{base_url}/models')\n"
            "    resp = urllib.request.urlopen(req, timeout=5)\n"
            "    print(f'STATUS:{resp.status}')\n"
            "except urllib.error.HTTPError as e:\n"
            "    print(f'STATUS:{e.code}')\n"
            "except Exception as exc:\n"
            "    print(f'ERROR:{exc}')\n"
        )
        output = _runtime_run("docker-letta-1", code, runtime=runtime, timeout=15)

        configured_base = ""
        base_match = re.search(r'CONFIGURED_BASE_URL:(.*)', output)
        if base_match:
            configured_base = base_match.group(1).strip()

        assert re.search(r'STATUS:(200|401|403)', output), (
            f"letta cannot reach gateway at {configured_base!r}.\n"
            f"  Output: {output[:500]}\n"
            f"  If 'ssl' in error: BUG-V241-LANGFLOW-LETTA-BASE-URL."
        )

    @_SKIP_NO_STACK
    def test_dispatch_failure_is_not_silent(self):
        """
        Guards against the 'container-healthy = dispatch-working' assumption.

        Deliberately sends a request to a non-existent agent model.
        Asserts the response is 4xx or 5xx (NOT a silent 200 with empty content).

        This ensures that agent dispatch failures bubble up visibly, not silently.
        A gateway that swallows errors and returns HTTP 200 with empty content
        would defeat all the dispatch-validation tests above.
        """
        result = self._dispatch_via_gateway_internal("@nonexistent-agent-zzz999")
        raw = result["raw"]

        # Should be 4xx or 5xx — no such agent registered
        assert re.search(r'STATUS:(4\d\d|5\d\d)', raw), (
            f"Expected 4xx/5xx for unknown agent, got: {raw[:300]}\n"
            f"  If 200 with empty content, dispatch failures are silent — A1 gap."
        )
