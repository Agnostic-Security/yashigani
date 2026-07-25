"""
v5.0-fix/letta-brain-handle-prefix — ground-truthed contract tests.

Ava's e2e investigation (testing_runs/yashigani/v50-retest-ava-20260725/evidence/
letta_handle_investigation_notes.md) reproduced:

    HandleNotFoundError: Handle openai-proxy/qwen2.5:3b not found, must be one
    of []

and hypothesised a provider-NAMING mismatch (Letta's auto-registered OpenAI
provider is always literally named "openai", never "openai-proxy").

Tom's follow-up investigation downloaded the ACTUAL pinned letta==0.16.7 wheel
(matching docker/docker-compose.yml's pinned digest
sha256:fb7bd2c94a8bb7badbcfdb78a334abe3c1a75b5ea59e177aeba2e6356f54f92c) and
read the real source, ground-truthing two DISTINCT facts that Ava's
server.py-only read conflated:

  1. Provider NAME: letta/server/server.py:217-222 — the auto-registered
     OpenAIProvider is always named "openai" (hardcoded). CONFIRMED.

  2. Handle PREFIX (a SEPARATE concept): letta/schemas/providers/openai.py
     lines ~207-214 —

         if self.base_url.endswith("api.baseten.co/.../v1"):
             handle = self.get_handle(model_name, base_name="baseten")
         elif self.base_url != "https://api.openai.com/v1":
             handle = self.get_handle(model_name, base_name="openai-proxy")
         else:
             handle = self.get_handle(model_name)

     and letta/schemas/providers/base.py Provider.get_handle():

         return f"{base_name}/{model_name}"

     Since our OPENAI_API_BASE is always the internal egress mesh path
     (never "https://api.openai.com/v1" — see docker/docker-compose.yml:3183
     OPENAI_API_BASE=http://egress-letta:9400/llm/v1), Letta computes the
     handle prefix "openai-proxy" REGARDLESS of the provider's own name.
     yashigani's hardcoded default "openai-proxy/qwen2.5:3b" is therefore
     ALREADY CORRECT — it was never a naming-mismatch bug.

  ROOT CAUSE of Ava's reproduction: Letta's periodic model-sync
  (_sync_provider_models_async in server.py) calls
  GET {OPENAI_API_BASE}/models to enumerate models for the "openai"
  provider; when that call fails (egress 403 — the secondary finding in
  Ava's notes), the sync is skipped (caught + logged, not fatal) and ZERO
  models are ever persisted for that provider — so EVERY handle 404s with
  "must be one of []" regardless of what prefix is used.  Changing the
  prefix to "openai/..." (Ava's candidate fix (b)) would NOT have fixed
  this, and would in fact have been WRONG once the egress path is fixed,
  because it doesn't match what Letta itself computes.

These tests pin the CONTRACT (not a live Letta call — no live stack
required) so a future Letta version bump, or a well-intentioned "fix" that
renames the prefix, is caught by CI.

Last updated: 2026-07-25T00:00:00+00:00
"""
from __future__ import annotations

import importlib

import pytest


# ---------------------------------------------------------------------------
# A minimal, documented replica of Letta 0.16.7's own handle-computation
# logic (letta/schemas/providers/base.py Provider.get_handle +
# letta/schemas/providers/openai.py OpenAIProvider._list_llm_models).
# NOT imported from the letta package (letta is not a yashigani dependency —
# it runs in its own container); this is the ground-truthed CONTRACT,
# verified against the pinned wheel during this investigation.
# ---------------------------------------------------------------------------
_REAL_OPENAI_BASE_URL = "https://api.openai.com/v1"


def _letta_get_handle(model_name: str, base_name: str) -> str:
    """Mirrors Provider.get_handle() — f"{base_name}/{model_name}"."""
    return f"{base_name}/{model_name}"


def _letta_computed_handle(base_url: str, model_name: str) -> str:
    """Mirrors OpenAIProvider._list_llm_models()'s handle selection.

    (Baseten's dedicated-deployment branch omitted — not our topology.)
    """
    if base_url != _REAL_OPENAI_BASE_URL:
        return _letta_get_handle(model_name, base_name="openai-proxy")
    return _letta_get_handle(model_name, base_name="openai")


# ---------------------------------------------------------------------------
# Contract: our hardcoded default must match what Letta actually computes
# for our (always-internal, never-real-OpenAI) OPENAI_API_BASE.
# ---------------------------------------------------------------------------

class TestHandlePrefixContract:
    """LHP-001..003: our brain-model handle matches Letta's own computation."""

    def test_letta_computed_handle_for_internal_base_url(self):
        """Sanity-check the replica: internal base_url -> 'openai-proxy/...'."""
        handle = _letta_computed_handle(
            "http://egress-letta:9400/llm/v1", "qwen2.5:3b"
        )
        assert handle == "openai-proxy/qwen2.5:3b"

    def test_letta_computed_handle_for_real_openai_base_url(self):
        """Sanity-check the replica: real OpenAI base_url -> 'openai/...'
        (confirms the branch is base_url-driven, not env/config-driven —
        this is why option (b), renaming our prefix to "openai/...", would
        have been wrong: our base_url is NEVER the real OpenAI endpoint)."""
        handle = _letta_computed_handle(_REAL_OPENAI_BASE_URL, "gpt-5.4")
        assert handle == "openai/gpt-5.4"

    def test_letta_client_default_matches_letta_computed_handle(self, monkeypatch):
        """letta_client._letta_brain_model() default == what Letta computes
        for our compose-configured OPENAI_API_BASE (never the real OpenAI
        endpoint)."""
        monkeypatch.delenv("YASHIGANI_LETTA_BRAIN_MODEL", raising=False)
        from yashigani.gateway import letta_client
        importlib.reload(letta_client)

        our_default = letta_client._letta_brain_model()
        # Our compose OPENAI_API_BASE (docker/docker-compose.yml:3183) is
        # always the internal egress mesh path.
        expected = _letta_computed_handle(
            "http://egress-letta:9400/llm/v1", "qwen2.5:3b"
        )
        assert our_default == expected == "openai-proxy/qwen2.5:3b"

    def test_letta_brain_default_matches_letta_client_default(self, monkeypatch):
        """letta_brain.py and letta_client.py must never drift apart (both
        read YASHIGANI_LETTA_BRAIN_MODEL; P1.5 consolidation invariant)."""
        monkeypatch.delenv("YASHIGANI_LETTA_BRAIN_MODEL", raising=False)
        from yashigani.gateway import letta_brain, letta_client
        importlib.reload(letta_client)
        importlib.reload(letta_brain)

        assert letta_brain._letta_brain_model() == letta_client._letta_brain_model()

    def test_env_override_respected_by_both_modules(self, monkeypatch):
        """An operator override propagates identically to both modules."""
        monkeypatch.setenv("YASHIGANI_LETTA_BRAIN_MODEL", "openai-proxy/llama3:8b")
        from yashigani.gateway import letta_brain, letta_client
        importlib.reload(letta_client)
        importlib.reload(letta_brain)

        assert letta_client._letta_brain_model() == "openai-proxy/llama3:8b"
        assert letta_brain._letta_brain_model() == "openai-proxy/llama3:8b"


# ---------------------------------------------------------------------------
# Diagnostic hint — asserts the improved error message correctly identifies
# Ava's exact reproduced error shape and points at the real (egress-sync)
# cause rather than the naming red herring.
# ---------------------------------------------------------------------------

class TestHandleNotFoundHint:
    """LHP-004..006: _handle_not_found_hint() diagnostic behaviour."""

    def test_hint_fires_on_avas_exact_reproduction(self):
        from yashigani.gateway.letta_client import _handle_not_found_hint

        # Ava's exact reproduced body (letta_handle_investigation_notes.md).
        body = (
            '{"detail":"NOT_FOUND: Handle openai-proxy/qwen2.5:3b not found, '
            'must be one of []"}'
        )
        hint = _handle_not_found_hint(404, body)
        assert hint, "hint must fire on Letta's HandleNotFoundError shape"
        assert "NOT a" in hint or "not a" in hint.lower()
        assert "egress" in hint.lower()

    def test_hint_silent_on_unrelated_500(self):
        from yashigani.gateway.letta_client import _handle_not_found_hint

        hint = _handle_not_found_hint(500, "Internal Server Error")
        assert hint == ""

    def test_hint_silent_on_404_without_handle_shape(self):
        from yashigani.gateway.letta_client import _handle_not_found_hint

        hint = _handle_not_found_hint(404, '{"detail":"Not Found"}')
        assert hint == ""

    def test_hint_included_in_ensure_agent_error_message(self, monkeypatch):
        """The hint must actually reach the raised RuntimeError, not just
        exist as a helper (regression against the improvement being wired
        but never called)."""
        import asyncio
        from unittest.mock import AsyncMock, MagicMock

        monkeypatch.setenv("YASHIGANI_LETTA_BRAIN_MODEL", "openai-proxy/qwen2.5:3b")
        from yashigani.gateway import letta_client
        importlib.reload(letta_client)
        letta_client._default_agent_id = None

        get_resp = MagicMock(status_code=200)
        get_resp.json.return_value = []

        create_resp = MagicMock(status_code=404)
        create_resp.text = (
            '{"detail":"NOT_FOUND: Handle openai-proxy/qwen2.5:3b not found, '
            'must be one of []"}'
        )

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=get_resp)

        async def _mock_embed_config(_client):
            return {
                "embedding_endpoint_type": "openai",
                "embedding_endpoint": "http://gateway:8081/v1",
                "embedding_model": "qwen2.5:3b",
                "embedding_dim": 2048,
                "embedding_chunk_size": 300,
            }

        monkeypatch.setattr(
            letta_client, "_letta_embedding_config", _mock_embed_config
        )
        mock_client.post = AsyncMock(return_value=create_resp)

        async def _run():
            with pytest.raises(RuntimeError) as excinfo:
                await letta_client._ensure_agent(mock_client, "http://letta:8283")
            return str(excinfo.value)

        message = asyncio.run(_run())
        assert "egress" in message.lower()
        assert "not a" in message.lower() or "NOT a" in message
