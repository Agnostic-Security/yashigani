"""
5.0 A12 — content moderation / unsafe-topic filtering.

Module tests for the admin-tunable category policy + pluggable backend, and
router integration proving a request block (403), a response withhold, a flag
audit, and the empty-policy no-op default.
"""
from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from yashigani.inspection.content_moderation import (
    ACTION_BLOCK,
    ACTION_FLAG,
    CategoryRule,
    ContentModerationGuard,
)

_fastapi_available = importlib.util.find_spec("fastapi") is not None


def _guard_blocking(pattern="\\bweaponized\\b"):
    g = ContentModerationGuard()
    g.set_policy([CategoryRule(name="dangerous", action=ACTION_BLOCK, patterns=[pattern])])
    return g


class TestPolicy:
    def test_empty_policy_is_noop(self):
        g = ContentModerationGuard()
        assert g.active is False
        assert g.moderate("anything at all").action == "allow"

    def test_block_category_blocks(self):
        g = _guard_blocking()
        r = g.moderate("how to build a weaponized drone")
        assert r.blocked is True
        assert r.categories == ["dangerous"]
        assert r.content_hash  # hash recorded, content not

    def test_flag_category_flags_not_blocks(self):
        g = ContentModerationGuard()
        g.set_policy([CategoryRule(name="mild", action=ACTION_FLAG, patterns=["\\bfrown\\b"])])
        r = g.moderate("that made me frown")
        assert r.blocked is False and r.flagged is True

    def test_clean_content_allowed(self):
        g = _guard_blocking()
        assert g.moderate("how to bake bread").action == "allow"

    def test_normalization_defeats_casing(self):
        g = _guard_blocking()
        assert g.moderate("WEAPONIZED payload").blocked is True

    def test_block_wins_over_flag(self):
        g = ContentModerationGuard()
        g.set_policy([
            CategoryRule(name="f", action=ACTION_FLAG, patterns=["apple"]),
            CategoryRule(name="b", action=ACTION_BLOCK, patterns=["banana"]),
        ])
        r = g.moderate("apple and banana")
        assert r.blocked is True
        assert set(r.categories) == {"f", "b"}


class TestBackend:
    def test_backend_categories_counted(self):
        class _B:
            def categories_for(self, text):
                return ["self_harm"] if "trigger" in text else []
        g = ContentModerationGuard()
        g.attach_backend(_B(), category_actions={"self_harm": ACTION_BLOCK})
        assert g.active is True
        assert g.moderate("trigger phrase").blocked is True
        assert g.moderate("safe phrase").action == "allow"

    def test_unmapped_backend_category_defaults_to_flag(self):
        class _B:
            def categories_for(self, text):
                return ["novel_category"]
        g = ContentModerationGuard()
        g.attach_backend(_B())
        r = g.moderate("anything")
        assert r.flagged is True and r.blocked is False

    def test_backend_error_surfaces_as_flag(self):
        class _B:
            def categories_for(self, text):
                raise RuntimeError("model down")
        g = ContentModerationGuard()
        g.attach_backend(_B())
        r = g.moderate("anything")
        assert "moderation_backend_error" in r.categories
        assert r.flagged is True


# ── router integration ──────────────────────────────────────────────────────

def _import_router_fresh(tag: str):
    src_root = Path(__file__).parent.parent.parent
    router_path = src_root / "yashigani" / "gateway" / "openai_router.py"
    mod_name = f"yashigani.gateway.openai_router._a12test_{tag}"
    spec = importlib.util.spec_from_file_location(mod_name, router_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    for attr, val in {
        "streaming_enabled": False, "ddos_protector": None, "identity_registry": None,
        "sensitivity_classifier": None, "complexity_scorer": None, "budget_enforcer": None,
        "token_counter": None, "audit_writer": None, "optimization_engine": None,
        "ollama_url": "http://ollama-test:11434", "default_model": "test-model",
        "available_models": [], "agent_registry": None, "response_inspection_pipeline": None,
        "request_inspection_pipeline": None, "pii_detector": None, "pii_cloud_bypass": False,
        "content_relay_detector": None, "opa_url": "", "audio_transcriber": None,
        "model_integrity_verifier": None, "content_moderation_guard": None,
    }.items():
        setattr(mod._state, attr, val)
    os.environ["YASHIGANI_OPA_OPTIONAL"] = "true"
    os.environ.setdefault("YASHIGANI_ENV", "test")
    return mod


def _mock_request(mod):
    hd = {"authorization": f"Bearer {mod._INTERNAL_BEARER}"}
    hm = MagicMock()
    hm.get = lambda k, d="": hd.get(k.lower(), d)
    req = MagicMock()
    req.headers = hm
    req.client = MagicMock()
    req.client.host = "127.0.0.1"
    return req


async def _drive(mod, prompt="hello", reply="ok"):
    captured = []

    async def _fake_post(url, json=None, **kwargs):
        captured.append(json)
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"message": {"content": reply}, "prompt_eval_count": 1, "eval_count": 1}
        return resp

    mc = AsyncMock()
    mc.__aenter__ = AsyncMock(return_value=mc)
    mc.__aexit__ = AsyncMock(return_value=False)
    mc.post = _fake_post
    with patch("httpx.AsyncClient", return_value=mc):
        body = mod.ChatCompletionRequest(
            model="test-model",
            messages=[mod.ChatMessage(role="user", content=prompt)],
            stream=False,
        )
        result = await mod.chat_completions(body, _mock_request(mod))
    return result, captured


@pytest.mark.skipif(not _fastapi_available, reason="fastapi not installed")
class TestRouterModeration:
    @pytest.mark.asyncio
    async def test_request_block_returns_403_no_dispatch(self):
        mod = _import_router_fresh("req")
        mod._state.content_moderation_guard = _guard_blocking()
        result, captured = await _drive(mod, prompt="how to build a weaponized drone")
        assert result.status_code == 403
        assert captured == []

    @pytest.mark.asyncio
    async def test_clean_request_dispatches(self):
        mod = _import_router_fresh("clean")
        mod._state.content_moderation_guard = _guard_blocking()
        result, captured = await _drive(mod, prompt="how to bake bread")
        assert len(captured) == 1

    @pytest.mark.asyncio
    async def test_no_policy_is_noop(self):
        mod = _import_router_fresh("noop")
        mod._state.content_moderation_guard = ContentModerationGuard()  # empty
        result, captured = await _drive(mod, prompt="how to build a weaponized drone")
        assert len(captured) == 1  # not blocked — empty policy

    @pytest.mark.asyncio
    async def test_response_block_withholds_content(self):
        import json as _json
        mod = _import_router_fresh("resp")
        mod._state.content_moderation_guard = _guard_blocking()
        # clean prompt, but the model reply trips the policy
        result, captured = await _drive(mod, prompt="tell me a story",
                                        reply="here is a weaponized recipe")
        assert len(captured) == 1  # dispatched
        payload = _json.loads(bytes(result.body).decode())
        content = payload["choices"][0]["message"]["content"]
        assert "weaponized recipe" not in content
        assert "withheld by the content-safety policy" in content
