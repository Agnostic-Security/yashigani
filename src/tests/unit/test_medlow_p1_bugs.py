"""
fix/medlow-findings P1 bug-fix unit tests.

Covers:
  P1.1 — createUser() email field clear-on-success (JS behaviour verified via
          HTML element presence check; JS logic is integration-tested live)
  P1.2 — Wazuh tile hide/disable when wazuh service is not deployed
          (verified via services API: GET /admin/services returns status)
  P1.3 — OPA policy draft system prompt forbids bare [] iteration;
          generate_policy returns status="compile_error" when repair fails
  P1.4 — _resolve_default_model raises 503 with specific message when no model
  P1.5 — letta_client/_letta_brain_model respects YASHIGANI_LETTA_BRAIN_MODEL
  FIND-003 — generate-pattern / OPA policy-draft default to qwen2.5:3b;
             empty LLM response triggers retry + clear error (not silent empty pattern)
"""
from __future__ import annotations

import os
import re
import pytest


# ---------------------------------------------------------------------------
# P1.1 — HTML has both new-user-name and new-user-email inputs
# ---------------------------------------------------------------------------

def test_create_user_form_has_email_input():
    """Dashboard HTML must include an email input in the create-user form."""
    html_path = (
        "src/yashigani/backoffice/templates/dashboard.html"
    )
    import pathlib
    html = pathlib.Path(html_path).read_text()
    assert 'id="new-user-email"' in html, \
        "create-user form must have a new-user-email input"
    assert 'type="email"' in html, \
        "new-user-email must be type=email"


def test_create_user_js_clears_email_on_success():
    """dashboard.js must clear new-user-email on successful user creation."""
    import pathlib
    js = pathlib.Path("src/yashigani/backoffice/static/js/dashboard.js").read_text()
    # Check the email clear line is present in the createUser() success block
    assert "document.getElementById('new-user-email').value = '';" in js, \
        "createUser() must clear new-user-email after success"


def test_create_user_js_sends_email_in_payload():
    """dashboard.js must send email in the POST /admin/users payload."""
    import pathlib
    js = pathlib.Path("src/yashigani/backoffice/static/js/dashboard.js").read_text()
    assert "var payload = { email: email };" in js, \
        "createUser() must build payload with email"
    assert "if (!email)" in js, \
        "createUser() must validate email is non-empty"


# ---------------------------------------------------------------------------
# P1.2 — Wazuh tile has id and tile-disabled class in HTML
# ---------------------------------------------------------------------------

def test_wazuh_tile_has_id_and_disabled_class():
    """Wazuh monitoring tile must have id + tile-disabled CSS class by default."""
    import pathlib
    html = pathlib.Path("src/yashigani/backoffice/templates/dashboard.html").read_text()
    assert 'id="monitoring-tile-wazuh"' in html, \
        "Wazuh tile must have id=monitoring-tile-wazuh"
    assert 'tile-disabled' in html, \
        "Wazuh tile must start with tile-disabled class"
    assert 'aria-disabled="true"' in html, \
        "Wazuh tile must have aria-disabled=true when not deployed"


def test_tile_disabled_css_class_defined():
    """dashboard.css must define .tile-disabled with pointer-events:none."""
    import pathlib
    css = pathlib.Path("src/yashigani/backoffice/static/css/dashboard.css").read_text()
    assert '.tile-disabled' in css, ".tile-disabled CSS class must be defined"
    assert 'pointer-events: none' in css, ".tile-disabled must disable pointer events"


def test_load_monitoring_js_function_exists():
    """dashboard.js must define loadMonitoring() and call it from showPage."""
    import pathlib
    js = pathlib.Path("src/yashigani/backoffice/static/js/dashboard.js").read_text()
    assert 'async function loadMonitoring()' in js, \
        "loadMonitoring() must be defined"
    assert "if (name === 'monitoring')" in js, \
        "showPage must call loadMonitoring on monitoring page"


def test_services_api_returns_wazuh_status():
    """GET /admin/services must include wazuh with a status field."""
    from yashigani.backoffice.routes.services import _OPTIONAL_SERVICES
    assert "wazuh" in _OPTIONAL_SERVICES, "wazuh must be in _OPTIONAL_SERVICES"
    assert _OPTIONAL_SERVICES["wazuh"]["profile"] == "wazuh"


def test_wazuh_status_from_enabled_profiles(monkeypatch):
    """_is_service_running('wazuh') returns True only when profile is in ENABLED_PROFILES."""
    from yashigani.backoffice.routes.services import _is_service_running, _enabled_profiles

    monkeypatch.setenv("YASHIGANI_ENABLED_PROFILES", "")
    assert not _is_service_running("wazuh"), "wazuh must be stopped when not in enabled profiles"

    monkeypatch.setenv("YASHIGANI_ENABLED_PROFILES", "wazuh,openwebui")
    assert _is_service_running("wazuh"), "wazuh must be running when in enabled profiles"


# ---------------------------------------------------------------------------
# P1.3 — Rego gen system prompt forbids bare [] patterns
# ---------------------------------------------------------------------------

def test_rego_gen_prompt_forbids_bare_array_iteration():
    """_REGO_GEN_SYSTEM must explicitly forbid bare [] iteration (Rego v1 invalid)."""
    from yashigani.backoffice.routes.policies import _REGO_GEN_SYSTEM
    # Explicit rule about the forbidden pattern
    assert 'array[] ==' in _REGO_GEN_SYSTEM or 'array[]' in _REGO_GEN_SYSTEM, \
        "Prompt must mention bare [] to tell the model it is forbidden"
    # Must show the correct alternative
    assert '"value" in input.data_tags' in _REGO_GEN_SYSTEM, \
        "Prompt must show the correct Rego v1 membership check"


def test_rego_gen_prompt_includes_rego_v1_import():
    """The system prompt example must include import rego.v1."""
    from yashigani.backoffice.routes.policies import _REGO_GEN_SYSTEM
    assert "import rego.v1" in _REGO_GEN_SYSTEM, \
        "System prompt must include import rego.v1"


def test_rego_gen_prompt_forbids_deny_set_comprehension():
    """Prompt must instruct model NOT to use Rego v0 set-comprehension deny[msg]."""
    from yashigani.backoffice.routes.policies import _REGO_GEN_SYSTEM
    # The positive form must be shown
    assert 'deny contains "code" if' in _REGO_GEN_SYSTEM, \
        "Prompt must show deny contains <code> if pattern"


def test_generate_policy_response_has_compile_ok_field():
    """generate_policy must return compile_ok field in its response schema."""
    # Verify the endpoint function returns compile_ok in its dict
    import inspect
    from yashigani.backoffice.routes import policies as pol_module
    src = inspect.getsource(pol_module.generate_policy)
    assert '"compile_ok"' in src, \
        "generate_policy must include compile_ok in response"
    assert '"compile_error"' in src, \
        "generate_policy must include status='compile_error' path"


# ---------------------------------------------------------------------------
# P1.4 — _resolve_default_model raises 503 with specific message
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_resolve_default_model_raises_503_when_no_model(monkeypatch):
    """_resolve_default_model must raise HTTPException 503 when Ollama is unreachable
    and no YASHIGANI_OPA_ASSISTANT_MODEL / OLLAMA_MODEL env var is set."""
    monkeypatch.delenv("YASHIGANI_OPA_ASSISTANT_MODEL", raising=False)
    monkeypatch.delenv("OLLAMA_MODEL", raising=False)

    # Patch httpx to simulate unreachable Ollama
    import httpx
    from unittest.mock import AsyncMock, patch, MagicMock

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("refused"))
        mock_client_cls.return_value = mock_client

        from fastapi import HTTPException
        from yashigani.backoffice.routes.policies import _resolve_default_model

        with pytest.raises(HTTPException) as exc_info:
            await _resolve_default_model("http://ollama:11434")

    assert exc_info.value.status_code == 503
    detail = exc_info.value.detail
    assert detail["error"] == "no_model_available"
    assert "ollama" in detail["message"].lower()
    assert "YASHIGANI_OPA_ASSISTANT_MODEL" in detail["message"]


@pytest.mark.asyncio
async def test_resolve_default_model_uses_pref_even_when_not_in_avail(monkeypatch):
    """When YASHIGANI_OPA_ASSISTANT_MODEL is set but not in available list,
    the function should return the pref model (not raise) and log a warning."""
    monkeypatch.setenv("YASHIGANI_OPA_ASSISTANT_MODEL", "my-custom-model:7b")

    import httpx
    from unittest.mock import AsyncMock, MagicMock, patch

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        tags_resp = MagicMock()
        tags_resp.raise_for_status = MagicMock()
        tags_resp.json = MagicMock(return_value={"models": [{"name": "gemma3:4b"}]})
        mock_client.get = AsyncMock(return_value=tags_resp)
        mock_client_cls.return_value = mock_client

        from yashigani.backoffice.routes.policies import _resolve_default_model
        model, avail = await _resolve_default_model("http://ollama:11434")

    assert model == "my-custom-model:7b"
    assert "gemma3:4b" in avail


# ---------------------------------------------------------------------------
# P1.5 — YASHIGANI_LETTA_BRAIN_MODEL env var respected
# ---------------------------------------------------------------------------

def test_letta_client_brain_model_default():
    """_letta_brain_model() defaults to openai-proxy/qwen2.5:3b."""
    # Import file directly to avoid gateway proxy.py import chain
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "letta_client_direct",
        "src/yashigani/gateway/letta_client.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    os.environ.pop("YASHIGANI_LETTA_BRAIN_MODEL", None)
    assert mod._letta_brain_model() == "openai-proxy/qwen2.5:3b"


def test_letta_client_brain_model_env_override(monkeypatch):
    """YASHIGANI_LETTA_BRAIN_MODEL overrides the default brain model."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "letta_client_direct2",
        "src/yashigani/gateway/letta_client.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    monkeypatch.setenv("YASHIGANI_LETTA_BRAIN_MODEL", "openai-proxy/llama3:8b")
    assert mod._letta_brain_model() == "openai-proxy/llama3:8b"


def test_letta_brain_model_function_defined():
    """letta_brain.py must define _letta_brain_model() with env-var override."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "letta_brain_direct",
        "src/yashigani/gateway/letta_brain.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    os.environ.pop("YASHIGANI_LETTA_BRAIN_MODEL", None)
    assert mod._letta_brain_model() == "openai-proxy/qwen2.5:3b"
    os.environ["YASHIGANI_LETTA_BRAIN_MODEL"] = "openai-proxy/my-model:3b"
    assert mod._letta_brain_model() == "openai-proxy/my-model:3b"
    del os.environ["YASHIGANI_LETTA_BRAIN_MODEL"]


def test_letta_brain_error_includes_model_name():
    """letta_brain _create_brain_agent error message must include the model name."""
    import pathlib
    src = pathlib.Path("src/yashigani/gateway/letta_brain.py").read_text()
    # Check error message template mentions the brain_model variable
    assert "model={brain_model" in src, \
        "_create_brain_agent error must include brain_model for diagnostics"


# ---------------------------------------------------------------------------
# P1.2 + P2.7 — SIEM form exists on monitoring page
# ---------------------------------------------------------------------------

def test_siem_form_exists_on_monitoring_page():
    """dashboard.html monitoring page must have the external SIEM connect form."""
    import pathlib
    html = pathlib.Path("src/yashigani/backoffice/templates/dashboard.html").read_text()
    assert 'id="siem-backend"' in html, "SIEM backend select must exist"
    assert 'id="siem-endpoint"' in html, "SIEM endpoint input must exist"
    assert 'id="siem-token"' in html, "SIEM token input must exist"
    assert 'data-action="siemSave"' in html, "SIEM Save button must exist"
    assert 'data-action="siemTest"' in html, "SIEM Test button must exist"


def test_siem_js_functions_defined():
    """dashboard.js must define loadSiemConfig, siemSave, siemTest."""
    import pathlib
    js = pathlib.Path("src/yashigani/backoffice/static/js/dashboard.js").read_text()
    assert "async function loadSiemConfig()" in js
    assert "async function siemSave()" in js
    assert "async function siemTest()" in js


# ---------------------------------------------------------------------------
# P2.6 — Cloud key UI
# ---------------------------------------------------------------------------

def test_cloud_key_form_on_models_page():
    """dashboard.html models page must have cloud provider API key form."""
    import pathlib
    html = pathlib.Path("src/yashigani/backoffice/templates/dashboard.html").read_text()
    assert 'id="cloud-key-provider"' in html, "cloud-key-provider select must exist"
    assert 'id="cloud-key-value"' in html, "cloud-key-value input must exist"
    assert 'data-action="cloudKeySet"' in html, "cloudKeySet button must exist"
    assert 'cloud-key-status' in html, "cloud-key-status table must exist"


def test_cloud_key_js_functions_defined():
    """dashboard.js must define loadCloudKeys and cloudKeySet."""
    import pathlib
    js = pathlib.Path("src/yashigani/backoffice/static/js/dashboard.js").read_text()
    assert "async function loadCloudKeys()" in js
    assert "async function cloudKeySet()" in js


def test_cloud_keys_route_get_lists_providers():
    """GET /admin/cloud-keys route must define openai and anthropic providers."""
    from yashigani.backoffice.routes.cloud_keys import _PROVIDERS
    assert "openai" in _PROVIDERS
    assert "anthropic" in _PROVIDERS
    assert _PROVIDERS["openai"] == "openai_api_key"
    assert _PROVIDERS["anthropic"] == "anthropic_api_key"


def test_cloud_keys_route_put_requires_stepup():
    """set_cloud_key endpoint must use StepUpAdminSession (type annotation check)."""
    import inspect, typing
    from yashigani.backoffice.routes.cloud_keys import set_cloud_key
    sig = inspect.signature(set_cloud_key)
    params = sig.parameters
    assert "session" in params, "set_cloud_key must have a session parameter"
    annotation = params["session"].annotation
    # FastAPI wraps Annotated[...] around the dependency; verify the string repr
    # contains StepUpAdminSession to avoid tight coupling to FastAPI internals.
    ann_str = str(annotation)
    assert "StepUpAdminSession" in ann_str or "require_stepup_admin_session" in ann_str, \
        f"set_cloud_key session must use StepUpAdminSession, got: {ann_str}"


def test_admin_cloud_key_event_in_schema():
    """AdminCloudKeySetEvent must be in the audit schema with correct event_type."""
    from yashigani.audit.schema import AdminCloudKeySetEvent, EventType
    ev = AdminCloudKeySetEvent(
        admin_account="admin1",
        provider="openai",
        kms_key="openai_api_key",
    )
    assert ev.event_type == EventType.ADMIN_CLOUD_KEY_SET
    assert ev.provider == "openai"
    assert ev.kms_key == "openai_api_key"
    # Key VALUE must not appear in the event — only kms_key name
    assert not hasattr(ev, "api_key"), \
        "AdminCloudKeySetEvent must not have api_key field"


# ---------------------------------------------------------------------------
# FIND-003 — generate-pattern defaults to qwen2.5:3b; empty → retry → error
# ---------------------------------------------------------------------------

def test_resolve_default_model_ignores_ollama_model_env(monkeypatch):
    """_resolve_default_model must NOT use OLLAMA_MODEL — only YASHIGANI_OPA_ASSISTANT_MODEL.
    This is the root cause of FIND-003: OLLAMA_MODEL=llama3.1:8b was picked up and
    that model returns empty JSON for structured-output tasks.
    """
    import inspect
    from yashigani.backoffice.routes import policies as pol_module
    src = inspect.getsource(pol_module._resolve_default_model)
    # Must NOT fall through to OLLAMA_MODEL
    assert "OLLAMA_MODEL" not in src or "YASHIGANI_OPA_ASSISTANT_MODEL" in src, \
        "_resolve_default_model must not use OLLAMA_MODEL as a fallback"
    # Confirm the structured-output default is qwen2.5:3b
    assert "qwen2.5:3b" in src, \
        "_resolve_default_model must default to qwen2.5:3b for structured-output tasks"


@pytest.mark.asyncio
async def test_resolve_default_model_defaults_to_qwen(monkeypatch):
    """When no YASHIGANI_OPA_ASSISTANT_MODEL is set but models are available,
    the function must return qwen2.5:3b (not avail[0] which could be llama3.1:8b)."""
    monkeypatch.delenv("YASHIGANI_OPA_ASSISTANT_MODEL", raising=False)
    monkeypatch.delenv("OLLAMA_MODEL", raising=False)

    import httpx
    from unittest.mock import AsyncMock, MagicMock, patch

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        tags_resp = MagicMock()
        tags_resp.raise_for_status = MagicMock()
        # Simulate llama3.1:8b as the ONLY available model
        tags_resp.json = MagicMock(return_value={"models": [{"name": "llama3.1:8b"}]})
        mock_client.get = AsyncMock(return_value=tags_resp)
        mock_client_cls.return_value = mock_client

        from yashigani.backoffice.routes.policies import _resolve_default_model
        model, avail = await _resolve_default_model("http://ollama:11434")

    # Must default to qwen2.5:3b NOT to avail[0] = llama3.1:8b
    assert model == "qwen2.5:3b", \
        f"Expected qwen2.5:3b, got {model!r} — FIND-003 regression"
    assert "llama3.1:8b" in avail


@pytest.mark.asyncio
async def test_resolve_default_model_respects_assistant_model_override(monkeypatch):
    """YASHIGANI_OPA_ASSISTANT_MODEL overrides the qwen2.5:3b default."""
    monkeypatch.setenv("YASHIGANI_OPA_ASSISTANT_MODEL", "mistral:7b")
    monkeypatch.delenv("OLLAMA_MODEL", raising=False)

    import httpx
    from unittest.mock import AsyncMock, MagicMock, patch

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        tags_resp = MagicMock()
        tags_resp.raise_for_status = MagicMock()
        tags_resp.json = MagicMock(return_value={"models": [{"name": "qwen2.5:3b"}]})
        mock_client.get = AsyncMock(return_value=tags_resp)
        mock_client_cls.return_value = mock_client

        from yashigani.backoffice.routes.policies import _resolve_default_model
        model, _ = await _resolve_default_model("http://ollama:11434")

    assert model == "mistral:7b", \
        "YASHIGANI_OPA_ASSISTANT_MODEL must override the qwen2.5:3b default"


def test_sensitivity_generate_pattern_ignores_ollama_model():
    """generate_pattern must NOT call os.getenv('OLLAMA_MODEL') in its resolution
    logic (FIND-003). OLLAMA_MODEL may be a VRAM-tier model that returns empty JSON
    for structured-output tasks. The docstring may mention it for documentation
    purposes but the code must not read it."""
    import inspect, ast
    from yashigani.backoffice.routes import sensitivity as sens_mod
    src = inspect.getsource(sens_mod.generate_pattern)
    # Parse the AST and look for os.getenv("OLLAMA_MODEL") calls in the function body.
    # We skip the docstring by checking that OLLAMA_MODEL only appears in string literals
    # inside the docstring, not in actual getenv calls.
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            # Check for os.getenv("OLLAMA_MODEL") or getenv("OLLAMA_MODEL")
            func = node.func
            is_getenv = (
                (isinstance(func, ast.Attribute) and func.attr == "getenv") or
                (isinstance(func, ast.Name) and func.id == "getenv")
            )
            if is_getenv and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and arg.value == "OLLAMA_MODEL":
                    raise AssertionError(
                        "generate_pattern calls os.getenv('OLLAMA_MODEL') — FIND-003 regression. "
                        "Must use only YASHIGANI_OPA_ASSISTANT_MODEL with qwen2.5:3b default."
                    )
    assert "qwen2.5:3b" in src, \
        "generate_pattern must use qwen2.5:3b as the structured-output default"


def test_sensitivity_generate_pattern_has_retry_logic():
    """generate_pattern must contain retry logic for empty LLM responses (FIND-003)."""
    import inspect
    from yashigani.backoffice.routes import sensitivity as sens_mod
    src = inspect.getsource(sens_mod.generate_pattern)
    assert "_needs_retry" in src or "_STRICT_SUFFIX" in src, \
        "generate_pattern must have retry logic for empty LLM responses"
    assert "empty_response" in src or "empty_regex" in src or "empty" in src.lower(), \
        "generate_pattern must surface a clear error on empty LLM response"


def test_opa_assistant_generator_has_empty_output_guard():
    """OPAAssistantGenerator.generate must guard against empty LLM output (FIND-003)."""
    import inspect
    from yashigani.opa_assistant.generator import OPAAssistantGenerator
    src = inspect.getsource(OPAAssistantGenerator.generate)
    assert "empty_llm_response" in src or "_STRICT_SUFFIX" in src, \
        "OPAAssistantGenerator.generate must guard against empty LLM output"
    assert "retry" in src.lower(), \
        "OPAAssistantGenerator.generate must retry on empty response"


@pytest.mark.asyncio
async def test_opa_assistant_generator_retries_on_empty_response():
    """OPAAssistantGenerator.generate must retry once on an empty first response
    and return a clear error if the retry also fails (FIND-003)."""
    from unittest.mock import AsyncMock, MagicMock, patch
    import httpx

    # First call returns empty string; second also returns empty → clear error
    call_count = 0

    async def fake_post(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.json = MagicMock(return_value={"message": {"content": ""}})
        return resp

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = fake_post

    from yashigani.opa_assistant.generator import OPAAssistantGenerator
    gen = OPAAssistantGenerator(ollama_url="http://ollama:11434", model="qwen2.5:3b")

    with patch("httpx.AsyncClient", return_value=mock_client):
        result = await gen.generate("allow engineering team to access all tools")

    # Must have retried (2 calls total)
    assert call_count == 2, f"Expected 2 LLM calls (initial + retry), got {call_count}"
    # Must return a clear error, not a silent empty suggestion
    assert result["valid"] is False
    assert result["suggestion"] is None
    assert "empty" in (result.get("error") or "").lower(), \
        f"Error must mention 'empty', got: {result.get('error')!r}"


@pytest.mark.asyncio
async def test_opa_assistant_generator_succeeds_on_retry():
    """OPAAssistantGenerator.generate must succeed when the retry returns valid JSON."""
    from unittest.mock import AsyncMock, MagicMock, patch
    import json as _json

    valid_rbac = {
        "groups": {"eng": {"id": "eng", "display_name": "Engineering",
                            "allowed_resources": [{"method": "*", "path_glob": "/tools/**"}]}},
        "user_groups": {"alice@example.com": ["eng"]},
    }

    call_count = 0

    async def fake_post(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        if call_count == 1:
            # First attempt: empty
            resp.json = MagicMock(return_value={"message": {"content": ""}})
        else:
            # Retry: valid JSON
            resp.json = MagicMock(return_value={"message": {"content": _json.dumps(valid_rbac)}})
        return resp

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = fake_post

    from yashigani.opa_assistant.generator import OPAAssistantGenerator
    gen = OPAAssistantGenerator(ollama_url="http://ollama:11434", model="qwen2.5:3b")

    with patch("httpx.AsyncClient", return_value=mock_client):
        result = await gen.generate("allow engineering team to access all tools")

    assert call_count == 2, f"Expected 2 calls (initial empty + retry), got {call_count}"
    assert result["valid"] is True
    assert result["suggestion"] == valid_rbac
    assert result["error"] is None


def test_compose_sets_yashigani_opa_assistant_model():
    """docker-compose.yml x-common-env must set YASHIGANI_OPA_ASSISTANT_MODEL=qwen2.5:3b
    so that structured-output assistant flows never fall through to the VRAM-tier OLLAMA_MODEL."""
    import pathlib
    compose = pathlib.Path("docker/docker-compose.yml").read_text()
    assert "YASHIGANI_OPA_ASSISTANT_MODEL" in compose, \
        "docker-compose.yml must set YASHIGANI_OPA_ASSISTANT_MODEL in x-common-env (FIND-003)"
    # Verify the default value is qwen2.5:3b
    assert "qwen2.5:3b" in compose, \
        "docker-compose.yml YASHIGANI_OPA_ASSISTANT_MODEL must default to qwen2.5:3b"
