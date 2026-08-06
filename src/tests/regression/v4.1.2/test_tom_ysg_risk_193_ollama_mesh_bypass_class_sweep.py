"""
Regression test -- v4.1.2 YSG-RISK-193 (class-wide follow-up to RISK-191):

RISK-191 fixed one mesh-bypass site (routes/budget.py's local-inventory
endpoint). Auditing every other consumer of the same broken pattern found
FOUR more landmines, all sharing one of two shapes:

  Shape A -- env-var-only, missing the OLLAMA_BASE_URL leg:
      os.getenv("YASHIGANI_OLLAMA_URL", "http://ollama:11434")
    YASHIGANI_OLLAMA_URL is never set by any deployment config (compose/
    helm/entrypoints all wire OLLAMA_BASE_URL) -- silently pinned to the
    hardcoded literal.
      * opa_assistant/sanity.py:164 (llm_review)

  Shape B -- a DEAD state-attribute check that made the env-var fallback
  unreachable:
      getattr(backoffice_state, "ollama_url", None)
      or os.getenv("YASHIGANI_OLLAMA_URL", "http://ollama:11434")
    backoffice_state.ollama_url is declared with a dataclass default of
    "http://ollama:11434" (state.py:88) but is NEVER assigned anywhere in
    the backoffice codebase -- so getattr() always returns that truthy
    literal and the env-var `or` clause never even evaluates. Worse than
    Shape A: env vars had ZERO effect regardless of what was set.
      * routes/sensitivity.py:604-605 (generate_pattern)
      * routes/policies.py:412-414 (simulate_policy, ai_explain branch)
      * routes/policies.py:1046-1048 (generate_policy)

All four also used a bare httpx.AsyncClient for the Ollama fetch/generate
call -- no mesh SSL context, so even a correctly-resolved
https://caddy:11435/ollama URL would fail CERTIFICATE_VERIFY_FAILED.

Fix (identical pattern across all four, matching the RISK-191 fix and the
pre-existing correct routes/models.py._ollama_base()):
  - Resolution: YASHIGANI_OLLAMA_URL -> OLLAMA_BASE_URL -> hardcoded
    "http://ollama:11434" dev default.
  - Transport: inspection/_ollama_transport.ollama_async_client (the
    documented single mesh-mTLS-aware transport for every OLLAMA_BASE_URL
    consumer -- F-001 lineage).

policies.py's two sites both also route through the shared
_resolve_default_model() helper for the /api/tags fetch, so that helper's
internal transport was fixed once and covers both call sites.
"""
from __future__ import annotations

import pathlib
import re
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
_SITES = {
    "budget.py": _REPO_ROOT / "yashigani" / "backoffice" / "routes" / "budget.py",
    "sensitivity.py": _REPO_ROOT / "yashigani" / "backoffice" / "routes" / "sensitivity.py",
    "policies.py": _REPO_ROOT / "yashigani" / "backoffice" / "routes" / "policies.py",
    "sanity.py": _REPO_ROOT / "yashigani" / "opa_assistant" / "sanity.py",
}

# The exact buggy Shape A/B patterns that must no longer appear anywhere.
_DEAD_GETATTR_PATTERN = re.compile(
    r'getattr\(\s*(?:backoffice_state|_state)\s*,\s*["\']ollama_url["\']\s*,\s*None\s*\)'
)
_ENV_ONLY_FALLBACK_PATTERN = re.compile(
    r'os\.getenv\(\s*["\']YASHIGANI_OLLAMA_URL["\']\s*,\s*["\']http://ollama:11434["\']\s*\)'
)


class TestNoMeshBypassPatternRemainsAnywhere:
    """Structural sweep: neither buggy shape may appear in ANY of the four
    fixed files (or budget.py, RISK-191's own fix, as a control)."""

    @pytest.mark.parametrize("name", sorted(_SITES))
    def test_file_exists(self, name):
        assert _SITES[name].is_file()

    @pytest.mark.parametrize("name", sorted(_SITES))
    def test_no_dead_state_getattr_fallback(self, name):
        src = _SITES[name].read_text()
        m = _DEAD_GETATTR_PATTERN.search(src)
        assert m is None, (
            f"{name} still contains the dead getattr(..., 'ollama_url', None) "
            f"pattern (backoffice_state.ollama_url is never assigned, so this "
            f"always short-circuits the OLLAMA_BASE_URL fallback): {m}"
        )

    @pytest.mark.parametrize("name", sorted(_SITES))
    def test_no_env_var_only_two_arg_fallback(self, name):
        src = _SITES[name].read_text()
        m = _ENV_ONLY_FALLBACK_PATTERN.search(src)
        assert m is None, (
            f"{name} still contains os.getenv('YASHIGANI_OLLAMA_URL', "
            f"'http://ollama:11434') with no OLLAMA_BASE_URL leg -- the real "
            f"deployment-wired env var is never consulted: {m}"
        )

    @pytest.mark.parametrize("name", sorted(_SITES))
    def test_ollama_base_url_is_consulted(self, name):
        src = _SITES[name].read_text()
        assert 'os.getenv("OLLAMA_BASE_URL")' in src or "os.environ.get(\"OLLAMA_BASE_URL\")" in src

    @pytest.mark.parametrize("name", sorted(_SITES))
    def test_ollama_async_client_imported_for_mesh_transport(self, name):
        src = _SITES[name].read_text()
        assert "_ollama_transport import ollama_async_client" in src

    @pytest.mark.parametrize("name", sorted(_SITES))
    def test_no_bare_asyncclient_used_for_ollama_calls(self, name):
        """None of these files should construct httpx.AsyncClient(...) directly
        anywhere near an '/api/tags', '/api/chat', or '/api/generate' Ollama
        call -- every such call must go through ollama_async_client instead.
        (httpx.HTTPError exception handling / OPA's internal_httpx_client
        calls are unaffected and out of scope for this check.)"""
        src = _SITES[name].read_text()
        for m in re.finditer(r"httpx\.AsyncClient\(", src):
            window = src[max(0, m.start() - 400): m.end() + 400]
            assert "/api/tags" not in window and "/api/chat" not in window and "/api/generate" not in window, (
                f"{name} still has a bare httpx.AsyncClient(...) near an Ollama "
                f"API call at offset {m.start()}"
            )


# ---------------------------------------------------------------------------
# Behavioural coverage: each fixed call site actually resolves OLLAMA_BASE_URL
# and routes the real network call through ollama_async_client.
# ---------------------------------------------------------------------------

def _tags_response(models: list[str]) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.raise_for_status = MagicMock()
    resp.json = MagicMock(return_value={"models": [{"name": m} for m in models]})
    return resp


def _cm(resp: MagicMock) -> MagicMock:
    client = AsyncMock()
    client.get = AsyncMock(return_value=resp)
    client.post = AsyncMock(return_value=resp)
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=client)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


class TestSensitivityGeneratePatternUsesMesh:
    async def test_generate_pattern_resolves_ollama_base_url_and_uses_mesh(self, monkeypatch):
        monkeypatch.delenv("YASHIGANI_OLLAMA_URL", raising=False)
        monkeypatch.setenv("OLLAMA_BASE_URL", "https://caddy:11435/ollama")

        tags_resp = _tags_response(["qwen2.5:3b"])
        chat_resp = MagicMock()
        chat_resp.status_code = 200
        chat_resp.raise_for_status = MagicMock()
        chat_resp.json = MagicMock(return_value={
            "message": {"content": '{"regex": "\\\\bfoo\\\\b", "level": 3, "description": "d"}'}
        })

        client = AsyncMock()
        client.get = AsyncMock(return_value=tags_resp)
        client.post = AsyncMock(return_value=chat_resp)
        cm = MagicMock()
        cm.__aenter__ = AsyncMock(return_value=client)
        cm.__aexit__ = AsyncMock(return_value=False)

        mock_ollama_async_client = MagicMock(return_value=cm)

        with patch("yashigani.inspection._ollama_transport.ollama_async_client", mock_ollama_async_client):
            from yashigani.backoffice.routes.sensitivity import generate_pattern, GeneratePatternRequest
            body = GeneratePatternRequest(description="credit card numbers")
            result = await generate_pattern(body, session=None)

        assert mock_ollama_async_client.called
        for call in mock_ollama_async_client.call_args_list:
            assert call.args[0] == "https://caddy:11435/ollama"
        assert result["status"] == "ok"
        assert result["generated_regex"]


class TestPoliciesSimulateAiExplainUsesMesh:
    async def test_ai_explain_resolves_ollama_base_url_and_uses_mesh(self, monkeypatch):
        monkeypatch.delenv("YASHIGANI_OLLAMA_URL", raising=False)
        monkeypatch.setenv("OLLAMA_BASE_URL", "https://caddy:11435/ollama")

        opa_resp = MagicMock()
        opa_resp.status_code = 200
        opa_resp.json = MagicMock(return_value={"result": {"allow": True, "deny": [], "obligations": []}})
        opa_client = AsyncMock()
        opa_client.post = AsyncMock(return_value=opa_resp)
        opa_cm = MagicMock()
        opa_cm.__aenter__ = AsyncMock(return_value=opa_client)
        opa_cm.__aexit__ = AsyncMock(return_value=False)

        tags_resp = _tags_response(["qwen2.5:3b"])
        gen_resp = MagicMock()
        gen_resp.status_code = 200
        gen_resp.raise_for_status = MagicMock()
        gen_resp.json = MagicMock(return_value={"response": "Allowed because the input matched."})
        ollama_client = AsyncMock()
        ollama_client.get = AsyncMock(return_value=tags_resp)
        ollama_client.post = AsyncMock(return_value=gen_resp)
        ollama_cm = MagicMock()
        ollama_cm.__aenter__ = AsyncMock(return_value=ollama_client)
        ollama_cm.__aexit__ = AsyncMock(return_value=False)
        mock_ollama_async_client = MagicMock(return_value=ollama_cm)

        with patch("yashigani.backoffice.routes.policies.internal_httpx_client", return_value=opa_cm), \
             patch("yashigani.inspection._ollama_transport.ollama_async_client", mock_ollama_async_client):
            from yashigani.backoffice.routes.policies import simulate_policy, SimulateRequest
            body = SimulateRequest(policy_id="examples/gdpr", input_scenario={"tool": "email.send"}, ai_explain=True)
            result = await simulate_policy(body, session=None)

        assert mock_ollama_async_client.called
        for call in mock_ollama_async_client.call_args_list:
            assert call.args[0] == "https://caddy:11435/ollama"
        assert result["ai_explanation"] == "Allowed because the input matched."


class TestPoliciesGeneratePolicyUsesMesh:
    async def test_generate_policy_resolves_ollama_base_url_and_uses_mesh(self, monkeypatch):
        monkeypatch.delenv("YASHIGANI_OLLAMA_URL", raising=False)
        monkeypatch.setenv("OLLAMA_BASE_URL", "https://caddy:11435/ollama")

        tags_resp = _tags_response(["qwen2.5:3b"])
        gen_resp = MagicMock()
        gen_resp.status_code = 200
        gen_resp.raise_for_status = MagicMock()
        gen_resp.json = MagicMock(return_value={
            "response": "package clients.generated\n\nimport rego.v1\n\ndefault allow := false\n"
        })
        ollama_client = AsyncMock()
        ollama_client.get = AsyncMock(return_value=tags_resp)
        ollama_client.post = AsyncMock(return_value=gen_resp)
        ollama_cm = MagicMock()
        ollama_cm.__aenter__ = AsyncMock(return_value=ollama_client)
        ollama_cm.__aexit__ = AsyncMock(return_value=False)
        mock_ollama_async_client = MagicMock(return_value=ollama_cm)

        async def _fake_compile_repair_once(rego, name, regenerate):
            return {"rego": rego, "repaired": False, "repair_error": None}

        async def _fake_static_sanity_check(rego, name):
            return {"ok": True, "compiled": True, "compile_error": None, "warnings": []}

        with patch("yashigani.inspection._ollama_transport.ollama_async_client", mock_ollama_async_client), \
             patch("yashigani.opa_assistant.sanity.compile_repair_once", _fake_compile_repair_once), \
             patch("yashigani.opa_assistant.sanity.static_sanity_check", _fake_static_sanity_check):
            from yashigani.backoffice.routes.policies import generate_policy, GeneratePolicyRequest
            body = GeneratePolicyRequest(prompt="Block PII access outside business hours.", name="generated")
            result = await generate_policy(body, session=None)

        assert mock_ollama_async_client.called
        for call in mock_ollama_async_client.call_args_list:
            assert call.args[0] == "https://caddy:11435/ollama"
        assert "package clients.generated" in result["rego"]


class TestSanityLlmReviewUsesMesh:
    async def test_llm_review_resolves_ollama_base_url_and_uses_mesh(self, monkeypatch):
        monkeypatch.delenv("YASHIGANI_OLLAMA_URL", raising=False)
        monkeypatch.setenv("OLLAMA_BASE_URL", "https://caddy:11435/ollama")

        resp = MagicMock()
        resp.status_code = 200
        resp.raise_for_status = MagicMock()
        resp.json = MagicMock(return_value={"response": "No issues found."})
        client = AsyncMock()
        client.post = AsyncMock(return_value=resp)
        cm = MagicMock()
        cm.__aenter__ = AsyncMock(return_value=client)
        cm.__aexit__ = AsyncMock(return_value=False)
        mock_ollama_async_client = MagicMock(return_value=cm)

        with patch("yashigani.inspection._ollama_transport.ollama_async_client", mock_ollama_async_client):
            from yashigani.opa_assistant.sanity import llm_review
            warnings = await llm_review("package clients.foo\n\ndefault allow := false\n")

        mock_ollama_async_client.assert_called_once()
        assert mock_ollama_async_client.call_args[0][0] == "https://caddy:11435/ollama"
        assert warnings == []  # "No issues found." maps to an empty warnings list

    async def test_llm_review_degrades_cleanly_on_mesh_failure(self, monkeypatch):
        """Confirms the fix didn't regress the pre-existing never-raises
        best-effort semantics."""
        import httpx

        monkeypatch.delenv("YASHIGANI_OLLAMA_URL", raising=False)
        monkeypatch.setenv("OLLAMA_BASE_URL", "https://caddy:11435/ollama")

        failing_cm = MagicMock()
        failing_cm.__aenter__ = AsyncMock(side_effect=httpx.ConnectError("connection refused"))
        failing_cm.__aexit__ = AsyncMock(return_value=False)
        mock_ollama_async_client = MagicMock(return_value=failing_cm)

        with patch("yashigani.inspection._ollama_transport.ollama_async_client", mock_ollama_async_client):
            from yashigani.opa_assistant.sanity import llm_review
            warnings = await llm_review("package clients.foo\n")

        assert warnings and warnings[0]["code"] == "llm_review_unavailable"
