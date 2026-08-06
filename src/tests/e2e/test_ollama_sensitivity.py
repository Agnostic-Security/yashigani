"""
E2E: Ollama sensitivity classification — real model, real prompts.

Last updated: 2026-04-24T22:45:00+01:00

Tests the three-layer sensitivity pipeline against the running Ollama
instance with actual PII/PCI/IP content. Verifies that sensitive data
is correctly classified and would be routed locally.

Requires: running Yashigani stack with Ollama healthy.
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
import time
import pytest

from tests.e2e.conftest import runtime_exec, runtime_run, container_running, RUNTIME


def _ollama_query(prompt: str) -> str:
    """Send a prompt to ollama over the SUPPORTED mediated path.

    STALE-TEST FIX (x8x campaign 2026-08-05, YSG-RISK-193 retraction bullet;
    stitched 2026-08-06): this used to urllib straight to
    ``http://ollama:11434`` from the gateway — asserting a deliberately-CLOSED
    control. Since the ring-fence landed, ``gethostbyname('ollama')`` from the
    gateway correctly fails (Errno -3); the test was reporting the control
    working as a product failure. Now resolves the same env chain production
    uses (YASHIGANI_OLLAMA_URL -> OLLAMA_BASE_URL -> dev default) and goes
    through the product's single transport (mesh-TLS aware), so the test
    exercises the path clients actually get. The closed direct path has its
    own positive assert in test_direct_ollama_socket_is_ringfenced below.
    """
    result = runtime_run(f"{_YTF_PROJ}{_YTF_SEP}gateway{_YTF_SEP}1", f"""
import os, json
from yashigani.inspection._ollama_transport import ollama_post_json
base = os.getenv("YASHIGANI_OLLAMA_URL") or os.getenv("OLLAMA_BASE_URL") or "http://ollama:11434"
payload = {{"model": "qwen2.5:3b", "messages": [{{"role": "user", "content": {repr(prompt)}}}], "stream": False}}
try:
    print(json.dumps(ollama_post_json(base, "/api/chat", payload, timeout=120)))
except Exception as e:
    print(f"ERROR:{{e}}")
""", timeout=150)
    return result


def _classify_via_gateway(text: str) -> dict:
    """Classify text using the sensitivity classifier inside the gateway.

    STALE-TEST FIX (x8x campaign 2026-08-05, SensitivityLevel retraction
    bullet; stitched 2026-08-06): ``r.level`` has been the INT contract since
    v2.25.5 (R14/R15) — ``r.level.value`` now yields an int, so the string
    asserts below silently went stale. The probe emits the canonical enum
    NAME (robust whether r.level is a SensitivityLevel member or a plain
    int), keeping the readable string asserts contract-correct.
    """
    output = runtime_run(f"{_YTF_PROJ}{_YTF_SEP}gateway{_YTF_SEP}1", f"""
from yashigani.optimization.sensitivity_classifier import SensitivityClassifier, SensitivityLevel
c = SensitivityClassifier(enable_fasttext=False, enable_ollama=False)
r = c.classify({repr(text)})
import json
print(json.dumps({{"level": SensitivityLevel(r.level).name, "level_int": int(r.level), "triggers": r.triggers}}))
""")
    try:
        return json.loads(output)
    except (json.JSONDecodeError, ValueError):
        return {"level": "ERROR", "raw": output}


class TestOllamaSensitivity:
    """Test sensitivity classification with real regex patterns.

    STALE-TEST FIX (stitched 2026-08-06): expectations re-based on the CURRENT
    canonical ladder, measured in-process against the real classifier on this
    head (not assumed): PUBLIC=1 < INTERNAL=2 < CONFIDENTIAL=3 < RESTRICTED=4
    < SENSITIVE=5 (SENSITIVE added as top level in v2.25.5 R14/R15 — credit
    cards/API keys land there; SSN=RESTRICTED; email=CONFIDENTIAL). The old
    asserts encoded the pre-v2.25.5 4-level ladder AND the string contract —
    both stale. Measured 2026-08-06: SSN->RESTRICTED(4)['regex:US SSN'],
    card->SENSITIVE(5), api-key->SENSITIVE(5), email->CONFIDENTIAL(3),
    mixed->SENSITIVE(5) 3 triggers.
    """

    def test_public_text_classified_public(self):
        result = _classify_via_gateway("What is the capital of France?")
        assert result["level"] == "PUBLIC"
        assert result["level_int"] == 1
        assert len(result["triggers"]) == 0

    def test_ssn_detected_restricted(self):
        result = _classify_via_gateway("Employee SSN is 123-45-6789")
        assert result["level"] == "RESTRICTED"
        assert result["level_int"] == 4
        assert any("SSN" in t for t in result["triggers"])

    def test_credit_card_detected_sensitive(self):
        result = _classify_via_gateway("Payment card: 4111 1111 1111 1111")
        assert result["level"] == "SENSITIVE"
        assert result["level_int"] == 5
        assert any("card" in t.lower() for t in result["triggers"])

    def test_api_key_detected_sensitive(self):
        result = _classify_via_gateway("Use API key sk-ant-abc123def456ghi789jkl012mno345pqr")
        assert result["level"] == "SENSITIVE"
        assert result["level_int"] == 5
        assert any("API" in t for t in result["triggers"])

    def test_email_detected_confidential(self):
        result = _classify_via_gateway("Send it to alice@company.com please")
        assert result["level"] == "CONFIDENTIAL"
        assert result["level_int"] == 3

    def test_mixed_sensitivity_takes_highest(self):
        result = _classify_via_gateway(
            "alice@company.com has SSN 123-45-6789 and card 4111111111111111"
        )
        assert result["level"] == "SENSITIVE"
        assert result["level_int"] == 5
        assert len(result["triggers"]) >= 2


class TestOllamaLive:
    """Test actual Ollama inference via the gateway."""

    def test_gateway_healthz(self):
        # Post-mTLS: gateway listens on HTTPS only — use ssl context with gateway cert.
        result = runtime_run(f"{_YTF_PROJ}{_YTF_SEP}gateway{_YTF_SEP}1",
            "import ssl, urllib.request; "
            "c=ssl.create_default_context(cafile='/run/secrets/ca_root.crt'); "
            "c.load_cert_chain('/run/secrets/gateway_client.crt','/run/secrets/gateway_client.key'); "
            "print(urllib.request.urlopen('https://localhost:8080/healthz', context=c).read().decode())",
            timeout=10)
        assert "ok" in result

    def test_ollama_model_loaded(self):
        """Verify qwen2.5:3b is loaded in Ollama."""
        for _ in range(12):
            result = runtime_exec(f"{_YTF_PROJ}{_YTF_SEP}ollama{_YTF_SEP}1", "ollama", "list", timeout=10)
            if "qwen2.5" in result.stdout:
                break
            time.sleep(10)
        assert "qwen2.5" in result.stdout, f"Ollama model not loaded: {result.stderr}"

    def test_simple_prompt_gets_response(self):
        """Send a simple prompt via the supported mediated path and verify response."""
        if not container_running(f"{_YTF_PROJ}{_YTF_SEP}ollama{_YTF_SEP}1"):
            pytest.skip("Ollama not running")
        output = _ollama_query("Say hello in exactly 3 words.")
        assert "ERROR" not in output, f"Ollama query failed: {output}"
        assert "message" in output or "content" in output or "response" in output

    def test_direct_ollama_socket_is_ringfenced(self):
        """YSG-RISK-193 positive assert: direct http://ollama:11434 from the
        gateway MUST be closed (DNS failure or connection refused). This is the
        control the pre-2026-08-06 version of this file asserted BACKWARDS —
        a reachable direct socket is the failure mode, not the success mode."""
        result = runtime_run(f"{_YTF_PROJ}{_YTF_SEP}gateway{_YTF_SEP}1", """
import urllib.request
try:
    urllib.request.urlopen("http://ollama:11434/api/tags", timeout=5)
    print("RINGFENCE-OPEN")
except Exception as e:
    print(f"RINGFENCE-CLOSED:{type(e).__name__}")
""", timeout=20)
        assert "RINGFENCE-CLOSED" in result, (
            f"Direct ollama:11434 socket is REACHABLE from the gateway — "
            f"YSG-RISK-193 ring-fence regression: {result}"
        )
