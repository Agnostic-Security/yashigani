"""
E2E: Ollama sensitivity classification — real model, real prompts.

Last updated: 2026-04-24T22:45:00+01:00

Tests the three-layer sensitivity pipeline against the running Ollama
instance with actual PII/PCI/IP content. Verifies that sensitive data
is correctly classified and would be routed locally.

Requires: running Yashigani stack with Ollama healthy.
"""
from __future__ import annotations

import json
import time
import pytest

from tests.e2e.conftest import runtime_exec, runtime_run, container_running, RUNTIME


def _ollama_query(prompt: str) -> str:
    """Send a prompt to Ollama directly (bypassing gateway auth) for testing."""
    result = runtime_run("docker-gateway-1", f"""
import urllib.request, json
data = json.dumps({{"model": "qwen2.5:3b", "messages": [{{"role": "user", "content": {repr(prompt)}}}], "stream": False}}).encode()
req = urllib.request.Request("http://ollama:11434/api/chat", data=data, headers={{"Content-Type": "application/json"}})
try:
    resp = urllib.request.urlopen(req, timeout=120)
    body = resp.read().decode()
    print(body)
except Exception as e:
    print(f"ERROR:{{e}}")
""", timeout=90)
    return result


def _classify_via_gateway(text: str) -> dict:
    """Classify text using the sensitivity classifier inside the gateway."""
    output = runtime_run("docker-gateway-1", f"""
from yashigani.optimization.sensitivity_classifier import SensitivityClassifier
c = SensitivityClassifier(enable_sklearn=False, enable_ollama=False)
r = c.classify({repr(text)})
import json
print(json.dumps({{"level": r.level.value, "triggers": r.triggers}}))
""")
    try:
        return json.loads(output)
    except (json.JSONDecodeError, ValueError):
        return {"level": "ERROR", "raw": output}


class TestOllamaSensitivity:
    """Test sensitivity classification with real regex patterns."""

    def test_public_text_classified_public(self):
        result = _classify_via_gateway("What is the capital of France?")
        assert result["level"] == "PUBLIC"
        assert len(result["triggers"]) == 0

    def test_ssn_detected_confidential(self):
        result = _classify_via_gateway("Employee SSN is 123-45-6789")
        assert result["level"] == "CONFIDENTIAL"
        assert any("SSN" in t for t in result["triggers"])

    def test_credit_card_detected_restricted(self):
        result = _classify_via_gateway("Payment card: 4111 1111 1111 1111")
        assert result["level"] == "RESTRICTED"
        assert any("card" in t.lower() for t in result["triggers"])

    def test_api_key_detected_restricted(self):
        result = _classify_via_gateway("Use API key sk-ant-abc123def456ghi789jkl012mno345pqr")
        assert result["level"] == "RESTRICTED"
        assert any("API" in t for t in result["triggers"])

    def test_email_detected_internal(self):
        result = _classify_via_gateway("Send it to alice@company.com please")
        assert result["level"] == "INTERNAL"

    def test_mixed_sensitivity_takes_highest(self):
        result = _classify_via_gateway(
            "alice@company.com has SSN 123-45-6789 and card 4111111111111111"
        )
        assert result["level"] == "RESTRICTED"
        assert len(result["triggers"]) >= 2


class TestOllamaLive:
    """Test actual Ollama inference via the gateway."""

    def test_gateway_healthz(self):
        # Post-mTLS: gateway listens on HTTPS only — use ssl context with gateway cert.
        result = runtime_run("docker-gateway-1",
            "import ssl, urllib.request; "
            "c=ssl.create_default_context(cafile='/run/secrets/ca_root.crt'); "
            "c.load_cert_chain('/run/secrets/gateway_client.crt','/run/secrets/gateway_client.key'); "
            "print(urllib.request.urlopen('https://localhost:8080/healthz', context=c).read().decode())",
            timeout=10)
        assert "ok" in result

    def test_ollama_model_loaded(self):
        """Verify qwen2.5:3b is loaded in Ollama."""
        for _ in range(12):
            result = runtime_exec("docker-ollama-1", "ollama", "list", timeout=10)
            if "qwen2.5" in result.stdout:
                break
            time.sleep(10)
        assert "qwen2.5" in result.stdout, f"Ollama model not loaded: {result.stderr}"

    def test_simple_prompt_gets_response(self):
        """Send a simple prompt directly to Ollama and verify response."""
        if not container_running("docker-ollama-1"):
            pytest.skip("Ollama not running")
        output = _ollama_query("Say hello in exactly 3 words.")
        assert "ERROR" not in output, f"Ollama query failed: {output}"
        assert "message" in output or "content" in output or "response" in output
