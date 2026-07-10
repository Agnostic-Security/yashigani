"""
Unit tests — FIND-4.0-REGO-001: RegoGenerator self-repair loop + template-first path.

Tests:
  1. Default model is qwen2.5:3b (only model available in this deployment).
  2. Template-first path returns via_template=True when classifier matches.
  3. Null template falls back to freeform generation.
  4. Repair messages include the OPA error and bad Rego verbatim.
  5. Few-shot examples appear in freeform generation system prompt.
  6. Low temperature (≤0.2) is set for deterministic Rego generation.
  7. Route repair loop: first attempt valid → attempts=1.
  8. Route repair loop: first OPA fail, repair succeeds → attempts=2, repair_context wired.
  9. Route repair loop: all 3 attempts fail → rego=None, attempt count in validation_error.
  10. Structural LLM failure aborts repair early — no wasted repair calls.

Last updated: 2026-07-01
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from yashigani.opa_assistant.rego_generator import RegoGenerator


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VALID_REGO = """\
package clients.test_policy

import rego.v1

deny contains "blocked" if {
    input.identity.clearance == "PUBLIC"
}

default allow := false

allow if count(deny) == 0

policy_id := "clients.test_policy.test_policy"
user_message := "Blocked by test policy."
code := 403
decision := {"allow": allow, "deny": deny, "policy_id": policy_id, "user_message": user_message, "code": code}
"""

INVALID_REGO_VAR_NAME = """\
package clients.test_policy

import rego.v1

deny[msg] {
    msg := "blocked_cloud"
    input.identity.clearance == "PUBLIC"
}

default allow := false

allow if count(deny) == 0

policy_id := "clients.test_policy.test_policy"
user_message := "Blocked."
code := 403
decision := {"allow": allow, "deny": deny, "policy_id": policy_id, "user_message": user_message, "code": code}
"""


def _make_ollama_response(content: str) -> MagicMock:
    """Build a fake httpx response from Ollama /api/chat."""
    m = MagicMock()
    m.raise_for_status = MagicMock()
    m.json = MagicMock(return_value={"message": {"content": content}})
    return m


# ---------------------------------------------------------------------------
# Unit tests: RegoGenerator model config
# ---------------------------------------------------------------------------

class TestRegoGeneratorDefaultModel:
    """Default model is qwen2.5:3b (only model in this deployment)."""

    def test_default_model_is_qwen25_3b(self):
        # llama3.1:8b is not loaded in this deployment (only qwen2.5:3b is available);
        # the default must match what's actually present.
        gen = RegoGenerator()
        assert gen._model == "qwen2.5:3b", (
            f"Expected qwen2.5:3b, got {gen._model!r}"
        )

    def test_custom_model_override(self):
        gen = RegoGenerator(model="llama3.1:8b")
        assert gen._model == "llama3.1:8b"


# ---------------------------------------------------------------------------
# Unit tests: RegoGenerator message construction
# ---------------------------------------------------------------------------

class TestRegoGeneratorRepairContext:
    """Repair path builds the correct messages."""

    def test_repair_messages_contain_error_and_rego(self):
        gen = RegoGenerator()
        error = "var cannot be used for rule name (line 8, col 28)"
        msgs = gen._build_repair_messages((error, INVALID_REGO_VAR_NAME))
        assert len(msgs) == 2
        assert msgs[0]["role"] == "system"
        # System prompt must mention the rego.v1 repair guidance
        assert "deny contains" in msgs[0]["content"]
        # User message must include the exact error text and the broken Rego
        user_content = msgs[1]["content"]
        assert error in user_content, "Error message must be in repair user content"
        assert INVALID_REGO_VAR_NAME.strip()[:30] in user_content, (
            "Broken Rego must be included in repair user content"
        )

    def test_generation_messages_contain_slug(self):
        gen = RegoGenerator()
        msgs = gen._build_generation_messages("block cloud for public users", "my_policy")
        # The slug appears in the user message (the system prompt uses <slug> as label)
        user = msgs[1]["content"]
        assert "my_policy" in user
        assert "block cloud for public users" in user

    def test_generation_messages_contain_few_shot_examples(self):
        gen = RegoGenerator()
        msgs = gen._build_generation_messages("something", "slug_a")
        system = msgs[0]["content"]
        # Both examples must be present
        assert "clearance_cloud_block" in system
        assert "finance_only" in system
        assert "deny contains" in system


# ---------------------------------------------------------------------------
# Unit tests: RegoGenerator.generate() — template path
# ---------------------------------------------------------------------------

class TestRegoGeneratorGenerate:
    """Test the async generate() method via mocked Ollama."""

    @pytest.mark.asyncio
    async def test_template_path_returns_via_template(self):
        """When classifier matches a template, via_template=True and rego is valid Rego."""
        gen = RegoGenerator()

        # Mock the classifier to return a known template match
        classifier_response = '{"template": "cloud_block", "params": {}}'

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(
                return_value=_make_ollama_response(classifier_response)
            )

            result = await gen.generate("block all requests going to cloud providers", "cloud_policy")

        assert result["valid"] is True
        assert result["rego"] is not None
        assert result.get("via_template") is True
        # Only ONE Ollama call (the classifier); no freeform generation needed
        assert mock_client.post.call_count == 1

    @pytest.mark.asyncio
    async def test_template_null_falls_back_to_freeform(self):
        """Classifier returns null template → falls back to freeform generation."""
        gen = RegoGenerator()

        responses = [
            # First call: classifier → null template
            _make_ollama_response('{"template": null, "params": {}}'),
            # Second call: freeform generation → valid Rego
            _make_ollama_response(VALID_REGO),
        ]

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(side_effect=responses)

            result = await gen.generate("something very custom", "custom_policy")

        assert result["valid"] is True
        assert result.get("via_template") is False
        # Two Ollama calls: classifier + freeform
        assert mock_client.post.call_count == 2

    @pytest.mark.asyncio
    async def test_structural_failure_returns_none(self):
        """LLM returns text without 'package' → structural fail, rego=None."""
        gen = RegoGenerator()

        call_count = [0]

        async def side_effect(url, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return _make_ollama_response('{"template": null, "params": {}}')
            return _make_ollama_response("Sorry, I can't help with that.")

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(side_effect=side_effect)

            result = await gen.generate("block everything", "test_policy")

        assert result["valid"] is False
        assert result["rego"] is None

    @pytest.mark.asyncio
    async def test_repair_context_builds_different_prompt(self):
        """When repair_context is provided, the system prompt is the repair prompt."""
        gen = RegoGenerator()
        captured_calls: list = []

        async def fake_post(url, json=None, **kwargs):
            captured_calls.append(json)
            return _make_ollama_response(VALID_REGO)

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(side_effect=fake_post)

            await gen.generate(
                "block cloud for public",
                "my_slug",
                repair_context=("var cannot be used for rule name", INVALID_REGO_VAR_NAME),
            )

        assert len(captured_calls) == 1
        messages = captured_calls[0]["messages"]
        system = messages[0]["content"]
        # Must be the repair prompt (not the generation prompt)
        assert "syntax fixer" in system.lower() or "fix" in system.lower()
        # Must NOT contain the original few-shot generation examples
        assert "clearance_cloud_block" not in system

    @pytest.mark.asyncio
    async def test_temperature_is_low(self):
        """Low temperature option must be set in Ollama request."""
        gen = RegoGenerator()
        captured: list = []

        async def fake_post(url, json=None, **kwargs):
            captured.append(json)
            return _make_ollama_response('{"template": "cloud_block", "params": {}}')

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(side_effect=fake_post)

            await gen.generate("block public cloud", "slug")

        assert captured[0]["options"]["temperature"] <= 0.2, (
            "Temperature must be low (≤ 0.2) for deterministic Rego generation"
        )


class TestRegoGeneratorStripFences:
    """Markdown fence stripping."""

    def test_strips_rego_fence(self):
        raw = "```rego\npackage clients.x\n```"
        assert RegoGenerator._strip_fences(raw) == "package clients.x"

    def test_strips_plain_fence(self):
        raw = "```\npackage clients.x\n```"
        assert RegoGenerator._strip_fences(raw) == "package clients.x"

    def test_no_fences_passthrough(self):
        raw = "package clients.x\nimport rego.v1"
        assert RegoGenerator._strip_fences(raw) == raw


# ---------------------------------------------------------------------------
# Route-level integration test: repair loop in suggest_rego
# ---------------------------------------------------------------------------

class TestSuggestRegoRepairLoop:
    """
    Test the suggest_rego route handler repair loop.

    RegoGenerator and validate_rego_module are lazily imported inside the route
    function body. We patch at the SOURCE module level so the lazy import picks
    up the mock.
    """

    # Patch targets: lazy-imported inside the route function body
    _GEN_TARGET = "yashigani.opa_assistant.rego_generator.RegoGenerator"
    _VAL_TARGET = "yashigani.opa_assistant.rego_validator.validate_rego_module"
    _STATE_TARGET = "yashigani.backoffice.routes.opa_assistant.backoffice_state"

    def _state_mock(self):
        m = MagicMock()
        m.ollama_url = "http://ollama:11434"
        m.opa_url = None
        m.audit_writer = None
        return m

    @pytest.mark.asyncio
    async def test_first_attempt_valid_attempts_eq_1(self):
        """When first attempt compiles, attempts=1 in response."""
        from yashigani.backoffice.routes.opa_assistant import (
            suggest_rego,
            SuggestRegoRequest,
        )

        body = SuggestRegoRequest(
            description="Block public cloud access",
            policy_name="test_policy",
        )
        mock_session = MagicMock()
        mock_session.account_id = "orca"

        mock_gen_instance = MagicMock()
        mock_gen_instance.generate = AsyncMock(
            return_value={"rego": VALID_REGO, "valid": True, "error": None}
        )

        with (
            patch(self._GEN_TARGET, return_value=mock_gen_instance),
            patch(self._VAL_TARGET, new=AsyncMock(return_value=(True, None))),
            patch(self._STATE_TARGET, self._state_mock()),
        ):
            response = await suggest_rego(body, mock_session)

        assert response.valid is True
        assert response.attempts == 1
        assert response.rego is not None

    @pytest.mark.asyncio
    async def test_first_invalid_second_valid_attempts_eq_2(self):
        """First compile fails, repair succeeds → attempts=2."""
        from yashigani.backoffice.routes.opa_assistant import (
            suggest_rego,
            SuggestRegoRequest,
        )

        body = SuggestRegoRequest(
            description="Block agents from using gpt-4 on cloud",
            policy_name="block_cloud_gpt4",
        )
        mock_session = MagicMock()
        mock_session.account_id = "orca"

        generate_calls: list = []

        async def fake_generate(description, policy_slug, repair_context=None):
            generate_calls.append(repair_context)
            if repair_context is None:
                # First call: structurally OK but OPA will reject
                return {"rego": INVALID_REGO_VAR_NAME, "valid": True, "error": None}
            # Second call (repair): returns valid Rego
            return {"rego": VALID_REGO, "valid": True, "error": None}

        async def fake_validate(rego_text, opa_url=None):
            if rego_text == INVALID_REGO_VAR_NAME:
                return False, "var cannot be used for rule name (line 5, col 1)"
            return True, None

        mock_gen_instance = MagicMock()
        mock_gen_instance.generate = AsyncMock(side_effect=fake_generate)

        with (
            patch(self._GEN_TARGET, return_value=mock_gen_instance),
            patch(self._VAL_TARGET, new=AsyncMock(side_effect=fake_validate)),
            patch(self._STATE_TARGET, self._state_mock()),
        ):
            response = await suggest_rego(body, mock_session)

        assert response.valid is True
        assert response.attempts == 2, f"Expected 2 attempts, got {response.attempts}"
        assert response.rego == VALID_REGO
        # First generate call: no repair_context
        assert generate_calls[0] is None
        # Second generate call: repair_context must include the error and bad Rego
        assert generate_calls[1] is not None
        error_in_ctx, rego_in_ctx = generate_calls[1]
        assert "var cannot be used for rule name" in error_in_ctx
        assert rego_in_ctx == INVALID_REGO_VAR_NAME

    @pytest.mark.asyncio
    async def test_all_attempts_fail_closed_with_attempt_count(self):
        """All 3 attempts fail → rego=None, validation_error includes attempt count."""
        from yashigani.backoffice.routes.opa_assistant import (
            suggest_rego,
            SuggestRegoRequest,
            _REGO_MAX_REPAIR_ATTEMPTS,
        )

        body = SuggestRegoRequest(
            description="Block all public requests from cloud routes",
            policy_name="block_public_cloud",
        )
        mock_session = MagicMock()
        mock_session.account_id = "orca"

        async def always_invalid(description, policy_slug, repair_context=None):
            return {"rego": INVALID_REGO_VAR_NAME, "valid": True, "error": None}

        async def always_fail(rego_text, opa_url=None):
            return False, "var cannot be used for rule name (line 5, col 1)"

        mock_gen_instance = MagicMock()
        mock_gen_instance.generate = AsyncMock(side_effect=always_invalid)

        with (
            patch(self._GEN_TARGET, return_value=mock_gen_instance),
            patch(self._VAL_TARGET, new=AsyncMock(side_effect=always_fail)),
            patch(self._STATE_TARGET, self._state_mock()),
        ):
            response = await suggest_rego(body, mock_session)

        assert response.valid is False
        assert response.rego is None
        assert response.attempts == _REGO_MAX_REPAIR_ATTEMPTS
        # Error must include attempt count so the UI can surface a useful message
        assert f"after_{_REGO_MAX_REPAIR_ATTEMPTS}_attempt" in response.validation_error, (
            f"Expected attempt count in validation_error, got: {response.validation_error!r}"
        )

    @pytest.mark.asyncio
    async def test_structural_failure_aborts_repair_early(self):
        """If generate() returns rego=None, repair loop aborts — no further generate calls."""
        from yashigani.backoffice.routes.opa_assistant import (
            suggest_rego,
            SuggestRegoRequest,
        )

        body = SuggestRegoRequest(
            description="Block everything always",
            policy_name="total_block",
        )
        mock_session = MagicMock()
        mock_session.account_id = "orca"

        generate_call_count = 0

        async def structural_fail(description, policy_slug, repair_context=None):
            nonlocal generate_call_count
            generate_call_count += 1
            return {"rego": None, "valid": False, "error": "empty_llm_response"}

        mock_gen_instance = MagicMock()
        mock_gen_instance.generate = AsyncMock(side_effect=structural_fail)

        with (
            patch(self._GEN_TARGET, return_value=mock_gen_instance),
            patch(self._VAL_TARGET, new=AsyncMock(return_value=(False, "should_not_be_called"))),
            patch(self._STATE_TARGET, self._state_mock()),
        ):
            response = await suggest_rego(body, mock_session)

        assert response.valid is False
        assert response.rego is None
        # Repair should not be attempted when there's no Rego text to repair
        assert generate_call_count == 1, (
            f"Expected 1 generate call (no repair), got {generate_call_count}"
        )
