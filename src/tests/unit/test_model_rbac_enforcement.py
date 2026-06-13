"""
Track B1 — model-RBAC ENFORCEMENT proofs.

Two layers:
  1. _opa_v1_check feeds the EFFECTIVE allowed_models into the OPA input
     (capture-the-input test).
  2. The REAL v1_routing.rego model_allowed rule denies a concrete model
     outside the effective set and allows one inside it (evaluated with the
     `opa eval` binary if present, else skipped).

These pin the "optimiser-selected model is re-checked against the allocation"
contract: whatever model reaches OPA, model_allowed denies it unless it is in
the effective set.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

_REGO = Path(__file__).resolve().parents[3] / "policy" / "v1_routing.rego"


def _opa_resp(result: dict):
    m = MagicMock()
    m.status_code = 200
    m.raise_for_status = MagicMock()
    m.json.return_value = {"result": result}
    return m


class TestEffectiveFedToOpa:
    @pytest.mark.asyncio
    async def test_effective_list_overrides_own_allowed_models(self, monkeypatch):
        from yashigani.gateway import openai_router as _mod

        monkeypatch.setattr(_mod._state, "opa_url", "https://opa:8181")
        captured: dict = {}

        async def _capture_post(url, json=None, headers=None):
            captured["input"] = json["input"]
            return _opa_resp({"allow": True, "model_allowed": True,
                              "routing_safe": True, "sensitivity_allowed": True, "reason": "ok"})

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(side_effect=_capture_post)

        identity = {"identity_id": "u1", "status": "active", "kind": "human",
                    "groups": ["eng"], "allowed_models": ["own-only"],
                    "sensitivity_ceiling": "PUBLIC"}

        with patch("yashigani.gateway.openai_router.internal_httpx_client", return_value=mock_client):
            await _mod._opa_v1_check(
                identity=identity,
                selected_model="qwen2.5:3b",
                selected_provider="ollama",
                sensitivity_level="PUBLIC",
                route_reason="P9:fallback",
                request_path="/v1/chat/completions",
                effective_allowed_models=["fast", "qwen2.5:3b"],
            )

        # The EFFECTIVE list — not the identity's own ["own-only"] — is in the input.
        assert captured["input"]["identity"]["allowed_models"] == ["fast", "qwen2.5:3b"]

    @pytest.mark.asyncio
    async def test_none_effective_falls_back_to_own(self, monkeypatch):
        from yashigani.gateway import openai_router as _mod

        monkeypatch.setattr(_mod._state, "opa_url", "https://opa:8181")
        captured: dict = {}

        async def _capture_post(url, json=None, headers=None):
            captured["input"] = json["input"]
            return _opa_resp({"allow": True, "model_allowed": True,
                              "routing_safe": True, "sensitivity_allowed": True, "reason": "ok"})

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(side_effect=_capture_post)

        identity = {"identity_id": "u1", "status": "active", "kind": "human",
                    "groups": [], "allowed_models": ["own-only"], "sensitivity_ceiling": "PUBLIC"}

        with patch("yashigani.gateway.openai_router.internal_httpx_client", return_value=mock_client):
            await _mod._opa_v1_check(
                identity=identity, selected_model="x", selected_provider="ollama",
                sensitivity_level="PUBLIC", route_reason="r", request_path="/v1/chat/completions",
                effective_allowed_models=None,
            )
        assert captured["input"]["identity"]["allowed_models"] == ["own-only"]


def _opa_eval_model_allowed(allowed_models, selected_model) -> bool:
    """Evaluate the REAL rego model_allowed rule with the opa binary."""
    inp = {
        "identity": {"status": "active", "kind": "human", "groups": [],
                     "allowed_models": allowed_models, "sensitivity_ceiling": "PUBLIC"},
        "routing_decision": {"provider": "ollama", "model": selected_model,
                             "sensitivity": "PUBLIC", "route": "local", "rule": "P9"},
        "request": {"path": "/v1/chat/completions", "method": "POST"},
        "trusted_cloud_providers": [],
    }
    out = subprocess.run(
        ["opa", "eval", "-d", str(_REGO), "-I",
         "data.yashigani.v1.model_allowed", "--format", "json"],
        input=json.dumps(inp), capture_output=True, text=True, check=True,
    )
    res = json.loads(out.stdout)
    return res["result"][0]["expressions"][0]["value"] is True


@pytest.mark.skipif(shutil.which("opa") is None, reason="opa binary not installed")
class TestRealRegoEnforcement:
    def test_concrete_model_outside_effective_denied(self):
        # Effective set = {fast, qwen2.5:3b}; optimiser tried to serve a cloud model.
        assert _opa_eval_model_allowed(["fast", "qwen2.5:3b"], "claude-sonnet-4-6") is False

    def test_concrete_model_inside_effective_allowed(self):
        assert _opa_eval_model_allowed(["fast", "qwen2.5:3b"], "qwen2.5:3b") is True

    def test_sentinel_denies_everything(self):
        # The fail-closed sentinel must deny every real model.
        assert _opa_eval_model_allowed(["__yashigani_no_model_allocated__"], "qwen2.5:3b") is False

    def test_empty_allows_all_legacy(self):
        # Empty list keeps the legacy "no restriction" behaviour.
        assert _opa_eval_model_allowed([], "anything") is True
