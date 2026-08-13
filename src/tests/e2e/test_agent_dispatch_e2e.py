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

import os as _ytf_os

# FIND-YTF412-009: container names were hardcoded to the compose project
# "docker" (e.g. f"{_YTF_PROJ}{_YTF_SEP}gateway{_YTF_SEP}1"), but install.sh DERIVES the project from
# --domain (documented multi-instance behaviour), and podman-compose separates
# with "_" where docker compose uses "-". A whole tier therefore reported
# per-test product failures while never finding a single container to act on --
# 23 failed / 11 passed in 2m00s with the stack untouched at 26/26 up.
_YTF_PROJ = _ytf_os.getenv("YTF_COMPOSE_PROJECT", "docker")
_YTF_SEP = _ytf_os.getenv("YTF_NAME_SEP", "-")

import json
import os
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
    """Execute Python code inside a container, returning stdout AND stderr.

    2026-08-06: previously returned `r.stdout.strip()` only. Any exception
    raised by the injected snippet went to stderr and was silently dropped, so
    a harness fault (e.g. PermissionError on a secret file) presented as an
    empty string and every downstream assertion failed against `''` with no
    diagnostic. Four tests were mis-reported as product failures on two
    runtimes because of it. stderr is now surfaced, prefixed so it can never be
    mistaken for program output.
    """
    r = subprocess.run(
        [runtime, "exec", container, "python3", "-c", python_code],
        capture_output=True, text=True, timeout=timeout,
    )
    out = (r.stdout or "").strip()
    err = (r.stderr or "").strip()
    if err:
        out = f"{out}\nSTDERR:{err}".strip() if out else f"STDERR:{err}"
    if r.returncode != 0 and "STDERR:" not in out:
        out = f"{out}\nEXIT:{r.returncode}".strip()
    return out


# --- real-user pathway primitives (shared with the framework's login helper) ---

_USER_SESSION_CACHE: dict = {}


def _base_url() -> str:
    return (os.getenv("YASHIGANI_ADMIN_URL")
            or os.getenv("YASHIGANI_HEALTH_URL", "https://localhost:8443").replace("/healthz", ""))


def _user_client():
    """An httpx client carrying a REAL, freshly-issued user session cookie.

    Uses the framework's canonical primitives (`bootstrap_user_session` /
    `user_login_cookies`) so there is exactly one login path in the tree — the
    divergent-login consolidation in the Playwright conftest exists to stop
    modules re-inventing this.
    """
    import sys
    from pathlib import Path

    import httpx

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "playwright"))
    from conftest import (  # type: ignore
        _CA_CERT_PATH, bootstrap_user_session, user_login_cookies,
    )

    creds = _USER_SESSION_CACHE.get("creds")
    if creds is None:
        creds = bootstrap_user_session(cache_key="e2e_agent_dispatch")
        _USER_SESSION_CACHE["creds"] = creds
    cookies = user_login_cookies(
        creds["username"], creds["password"], creds["totp_secret"],
        identity_key=f"user:{creds['username']}",
    )
    return httpx.Client(
        base_url=_base_url(), cookies=cookies,
        verify=_CA_CERT_PATH if _CA_CERT_PATH else False,
        timeout=180, follow_redirects=False,
    )


def _stack_running() -> bool:
    """Quick check: is any Yashigani gateway container running?"""
    runtime = _detect_runtime()
    for name in (f"{_YTF_PROJ}{_YTF_SEP}gateway{_YTF_SEP}1", "yashigani-gateway-1"):
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
        -> gateway calls ollama via the mediated mesh path (YASHIGANI_OLLAMA_URL;
           direct ollama:11434 is ring-fence-CLOSED per YSG-RISK-193)
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
        for name in (f"{_YTF_PROJ}{_YTF_SEP}gateway{_YTF_SEP}1", "yashigani-gateway-1"):
            if _container_running(name, runtime):
                return name
        pytest.skip("gateway container not found")

    def _dispatch_via_gateway_internal(
        self, model: str, prompt: str = "Say hello in exactly two words.",
        timeout: int = 180,
    ) -> dict:
        """Dispatch one chat turn down the REAL USER PATHWAY.

        2026-08-06 — replaces a container-exec bypass. The previous version did:

            docker exec <gateway> python3 -c "
                bearer = open('/run/secrets/yashigani_internal_bearer').read()
                urlopen('http://localhost:8081/v1/chat/completions', ...)"

        Three faults, compounding:

        1. **It bypassed the user pathway.** Posting to the gateway's own mesh
           port from inside the gateway with the INTERNAL bearer skips
           authentication, the session layer, the backoffice chat proxy and the
           caller-identity resolution a real request goes through. It cannot see
           any defect that lives in those layers, which is most of them.
        2. **It could not run at all.** `/run/secrets/yashigani_internal_bearer`
           is `root:2002 0640`; the container user is `1001:1001` with no
           supplementary groups, so `open()` raised PermissionError — *outside*
           the try block, so nothing was printed.
        3. **The error was invisible.** `_runtime_run` returns stdout only and
           discards stderr, so the PermissionError surfaced as an empty string
           and every assertion failed against `''` with no clue why. Four tests
           reported as product failures on two runtimes for a harness bug.

        Now: a real user session (fresh, never-replayed TOTP) posting to
        `/user/chat/completions` — the same path the browser uses; direct
        `/v1/chat/completions` from a browser 401s by design (user_ui.py:888).
        Returns the real HTTP status and body, so a failure names itself.
        """
        client = _user_client()
        resp = client.post(
            "/user/chat/completions",
            json={"model": model, "messages": [{"role": "user", "content": prompt}],
                  "stream": False},
            timeout=timeout,
        )
        return {
            "status": resp.status_code,
            "body": resp.text,
            # Kept for assertion compatibility with the existing tests, but now
            # built from a REAL HTTP exchange rather than scraped container stdout.
            "raw": f"STATUS:{resp.status_code}\nBODY:{resp.text}",
        }

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
        if not _container_running(f"{_YTF_PROJ}{_YTF_SEP}langflow{_YTF_SEP}1", _detect_runtime()):
            pytest.skip("langflow container not running (not in active profiles)")

        # 2026-08-06: was "@langflow", which is NOT a registered handle — install.sh
        # registers the bundle as `agent__langflow` and the mention menu offers
        # `@agent_langflow` (YSG-RISK-168). The test was asserting against a name the
        # product never had, so its 404 was CORRECT behaviour being read as a defect.
        result = self._dispatch_via_gateway_internal("@agent_langflow")
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
        if not _container_running(f"{_YTF_PROJ}{_YTF_SEP}letta{_YTF_SEP}1", _detect_runtime()):
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
        if not _container_running(f"{_YTF_PROJ}{_YTF_SEP}openclaw{_YTF_SEP}1", _detect_runtime()):
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
        if not _container_running(f"{_YTF_PROJ}{_YTF_SEP}langflow{_YTF_SEP}1", _detect_runtime()):
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
        output = _runtime_run(f"{_YTF_PROJ}{_YTF_SEP}langflow{_YTF_SEP}1", code, runtime=runtime, timeout=15)

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
        if not _container_running(f"{_YTF_PROJ}{_YTF_SEP}letta{_YTF_SEP}1", _detect_runtime()):
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
        output = _runtime_run(f"{_YTF_PROJ}{_YTF_SEP}letta{_YTF_SEP}1", code, runtime=runtime, timeout=15)

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
