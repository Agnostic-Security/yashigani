"""
Regression tests — YSG-RISK-158 (MED): "@"-prefix model exemption enforced at
the call-site instead of the LAURA-412-002 model-string validator ->
agent-call spoofing.

ROOT CAUSE (gateway/openai_router.py, pre-fix):

    is_agent_call = selected_model.startswith("@")
    if body.model and not is_agent_call and not brain_reasoning_leg:
        _mv_err = _validate_model_string(body.model)
        ...

ANY string starting with "@" completely skipped _validate_model_string —
the LAURA-412-002 positive-validation gate (URL-scheme rejection,
path-traversal rejection, null-sentinel rejection, ASCII-charset allowlist).
A caller could send ``body.model = "@http://evil/../..\\x00"`` and reach
downstream agent-routing code (``agent_name = selected_model[1:]``, used as
a Redis hash-field lookup key and in log lines) with ZERO of the defenses
every other model string gets — agent-call spoofing.

FIX: the "@" exemption now lives INSIDE ``_validate_model_string`` itself.
The call site validates ALL body.model values (agent calls included); the
validator recognises a leading "@" and applies the URL/path/null checks
universally plus a dedicated charset check (``_AGENT_CALL_VALID_RE``) for
the remainder after "@". Normalization + the known-model allowlist check
remain agent-call-exempt (an @-handle is not an LLM model), but validation
itself no longer is.

Cross-ref: docs/risk-register.yml YSG-RISK-158; LAURA-412-002 family.
"""
from __future__ import annotations

import contextlib
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ===========================================================================
# Unit: _validate_model_string — @-prefixed (agent-call) handling
# ===========================================================================

class TestAgentCallValidation:
    def _validate(self, s: str):
        from yashigani.gateway.openai_router import _validate_model_string
        return _validate_model_string(s)

    # ── Malicious @-prefixed payloads: MUST now be rejected ────────────────

    @pytest.mark.parametrize("model", [
        "@http://evil.example.com",
        "@https://evil.example.com/x",
        "@//evil.example.com",
        "@ftp://evil.example.com",
        "@openai://gpt-4o",          # ://-scheme anywhere
        "@../../etc/passwd",
        "@..\\..\\windows\\system32",
        "@foo|bar",
        "@foo#bar",
        "@foo!bar",
        "@foo\x00bar",               # embedded NUL
        "@foo\njunk",                # embedded newline
        "@foo\rjunk",
        "@foo​bar",             # ZWSP
        "@foo‌bar",             # ZWNJ
        "@foo﻿bar",             # BOM
        "@",                         # bare @, nothing after it
        "@ ",                        # @ + whitespace only
    ])
    def test_malicious_agent_call_payload_rejected(self, model):
        """YSG-RISK-158 REGRESSION: pre-fix, these were NEVER even passed to
        _validate_model_string (call-site exemption skipped it for anything
        starting with "@"). Post-fix, the validator itself must reject them.
        """
        result = self._validate(model)
        assert result is not None, (
            f"YSG-RISK-158 REGRESSION: malicious agent-call payload {model!r} "
            f"was NOT rejected by _validate_model_string (got None / accepted)."
        )

    # ── Legitimate agent-call handles: MUST still be accepted ──────────────

    @pytest.mark.parametrize("model", [
        "@my-agent",
        "@Agent123",
        "@agent_name.v2",
        "@filesystem-mcp",
        "@a",  # single char after @ is valid
    ])
    def test_legitimate_agent_call_still_accepted(self, model):
        result = self._validate(model)
        assert result is None, (
            f"Legitimate agent-call handle {model!r} was rejected: {result!r} "
            f"(fix must not break normal @-handle routing)"
        )

    def test_digest_form_at_with_colon_still_accepted(self):
        """Non-agent-call form: '@' mid-string (digest pin) must still work —
        this path never went through the agent-call branch (doesn't start
        with '@'), it exercises the ordinary _MODEL_VALID_RE branch.
        """
        result = self._validate("qwen2.5:3b@sha256:deadbeef")
        assert result is None

    @pytest.mark.parametrize("model", ["@null", "@none", "@undefined"])
    def test_agent_handle_literally_named_null_is_not_a_sentinel_bypass(self, model):
        """"@null" is a literal, harmless agent NAME (charset-valid) — unlike
        an ordinary model string, an unresolved agent handle never falls back
        to a silently-selected local model (it 404s as agent_not_found), so
        the null-sentinel check that exists to stop the SILENT LOCAL FALLBACK
        bypass for LLM models has no equivalent risk here. Documents the
        intentional scope boundary of this fix (URL-scheme / path-traversal /
        control-char / charset — not sentinel literals) rather than asserting
        an accidental behaviour.
        """
        result = self._validate(model)
        assert result is None


# ===========================================================================
# E2E: chat_completions call-site wiring
# ===========================================================================

def _make_state(agent_registry=None):
    alias_store = MagicMock()
    alias_store.get.return_value = None

    state = MagicMock()
    state.opa_url = "http://opa:8181"
    state.ollama_url = "http://ollama:11434"
    state.default_model = "qwen2.5:3b"
    state.optimization_engine = None
    state.sensitivity_classifier = None
    state.complexity_scorer = None
    state.budget_enforcer = None
    state.ddos_protector = None
    state.content_relay_detector = None
    state.model_alias_store = alias_store
    state.available_models = [{"id": "qwen2.5:3b"}]
    state.model_allocation_store = None
    state.audit_writer = None
    state.identity_registry = None
    state.agent_registry = agent_registry
    state.pool_manager = None
    state.pii_detector = None
    state.streaming_enabled = False
    state.streaming_inspect_interval = 200
    state.response_inspection_pipeline = None
    state.low_confidence_stepup_threshold = 0.7
    state.permission_strict = False
    state.permission_store = None
    state.kms_provider = None
    state._cloud_key_cache = {}
    return state


def _restricted_identity():
    return {
        "identity_id": "idnt_ysg158_test",
        "kind": "human",
        "groups": [],
        "status": "active",
        "sensitivity_ceiling": "PUBLIC",
    }


def _restricted_effective():
    from yashigani.models.effective import EffectiveModels
    return EffectiveModels(
        allowed={"qwen2.5:3b"},
        has_restriction=True,
        allocated_aliases=set(),
        gated=set(),
    )


def _make_request():
    from fastapi import Request
    req = MagicMock(spec=Request)
    req.method = "POST"
    req.headers = MagicMock()
    req.headers.__iter__ = MagicMock(return_value=iter([]))
    req.headers.items = MagicMock(return_value=[])
    req.headers.get = MagicMock(return_value=None)
    req.state = MagicMock()
    req.state.ysg_principal = None
    return req


class TestAgentCallE2EWiring:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("model_input", [
        "@http://evil.example.com",
        "@../../etc/passwd",
        "@foo|bar",
        "@foo\x00bar",
    ])
    async def test_malicious_agent_call_e2e_422(self, model_input):
        """End-to-end: a malicious @-prefixed body.model must be rejected by
        chat_completions with 422/invalid_model — proving the call-site no
        longer bypasses the validator for agent calls.
        """
        from fastapi.responses import JSONResponse
        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage, chat_completions

        body = ChatCompletionRequest(
            model=model_input,
            messages=[ChatMessage(role="user", content="ysg-158 test")],
            stream=False,
        )

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._state", _make_state(agent_registry=MagicMock())
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._resolve_identity",
                MagicMock(return_value=_restricted_identity()),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._effective_allowed_models",
                MagicMock(return_value=_restricted_effective()),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._opa_v1_check",
                AsyncMock(return_value={"allow": True}),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router.evaluate_client_policies",
                AsyncMock(return_value={"allow": True}),
            ))
            result = await chat_completions(body, _make_request())

        assert isinstance(result, JSONResponse), (
            f"model={model_input!r}: expected JSONResponse, got {type(result)}"
        )
        assert result.status_code == 422, (
            f"YSG-RISK-158 REGRESSION: malicious agent-call model={model_input!r} "
            f"expected 422, got {result.status_code}. Body: {result.body}"
        )
        body_json = json.loads(result.body)
        assert body_json["error"]["code"] == "model_not_found"

    @pytest.mark.asyncio
    async def test_legitimate_agent_call_not_blocked_by_model_validator(self):
        """A well-formed @-handle must NOT be rejected by the model-string
        validator. It may still fail later for unrelated reasons (agent not
        found in this minimal mock registry) — that is a DIFFERENT, expected
        code path (agent_not_found / 404), not the LAURA-412-002 invalid_model
        gate this fix touches.
        """
        from fastapi.responses import JSONResponse
        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage, chat_completions

        agent_registry = MagicMock()
        agent_registry._r.hget.return_value = None  # no per-user alias
        agent_registry.get.return_value = None      # not in global registry either

        body = ChatCompletionRequest(
            model="@filesystem-mcp",
            messages=[ChatMessage(role="user", content="ysg-158 legit test")],
            stream=False,
        )

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._state", _make_state(agent_registry=agent_registry)
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._resolve_identity",
                MagicMock(return_value=_restricted_identity()),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._effective_allowed_models",
                MagicMock(return_value=_restricted_effective()),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._opa_v1_check",
                AsyncMock(return_value={"allow": True}),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router.evaluate_client_policies",
                AsyncMock(return_value={"allow": True}),
            ))
            result = await chat_completions(body, _make_request())

        if isinstance(result, JSONResponse):
            body_json = json.loads(result.body)
            error_code = body_json.get("error", {}).get("code")
            assert error_code != "invalid_model", (
                "Legitimate @-handle was rejected by the model-string validator "
                f"(invalid_model) — fix must not block real agent calls. Body: {result.body}"
            )
