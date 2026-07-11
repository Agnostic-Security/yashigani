"""
v2.25.5 — Policies + AI-Authoring API (R8/R9/R10/R12/R16).

Unit tests for the five new endpoint groups.  FastAPI TestClient with
dependency_overrides for auth (AdminSession / StepUpAdminSession) and
OPA/LLM calls stubbed via monkeypatch / unittest.mock.

R8  — Template duplicate (POST /admin/policies/templates/duplicate)
       + custom-policy Rego edit (PUT /admin/policies/custom/{name}/rego)
R9  — Core policy edit with confirm_danger guard (PUT /admin/policies/core/{path})
R10 — Policy lifecycle (GET /admin/policies/lifecycle,
                        GET /admin/policies/lifecycle/{name},
                        POST /admin/policies/lifecycle/{name}/promote,
                        POST /admin/policies/lifecycle/{name}/archive)
R12 — Policy simulate (POST /admin/policies/simulate)
R16 — AI-generate pattern (POST /admin/sensitivity/generate-pattern)
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

try:
    from fastapi.testclient import TestClient
    _HAVE_FASTAPI = True
except ImportError:
    _HAVE_FASTAPI = False

pytestmark = pytest.mark.skipif(not _HAVE_FASTAPI, reason="fastapi required")

# ---------------------------------------------------------------------------
# Shared fixtures: auth bypass + OPA/LLM stubs
# ---------------------------------------------------------------------------

_FAKE_SESSION = SimpleNamespace(account_id="test-admin", tier="admin")


def _make_policies_app():
    """Create a minimal FastAPI app with the policies router mounted."""
    import fastapi as _fastapi
    from yashigani.backoffice.routes.policies import router
    from yashigani.backoffice import middleware as mw

    app = _fastapi.FastAPI()
    # Bypass auth
    app.dependency_overrides[mw.require_admin_session] = lambda: _FAKE_SESSION
    app.dependency_overrides[mw.require_stepup_admin_session] = lambda: _FAKE_SESSION
    app.include_router(router, prefix="/admin/policies")
    return app


def _make_sensitivity_app():
    """Create a minimal FastAPI app with the sensitivity router mounted."""
    import fastapi as _fastapi
    from yashigani.backoffice.routes.sensitivity import router
    from yashigani.backoffice import middleware as mw

    app = _fastapi.FastAPI()
    app.dependency_overrides[mw.require_admin_session] = lambda: _FAKE_SESSION
    app.dependency_overrides[mw.require_stepup_admin_session] = lambda: _FAKE_SESSION
    app.include_router(router, prefix="/admin/sensitivity")
    return app


# ---------------------------------------------------------------------------
# R10 — Policy lifecycle (no external deps needed)
# ---------------------------------------------------------------------------

class TestPolicyLifecycle:
    """R10: lifecycle transitions without OPA dependency."""

    def setup_method(self):
        # Reset the lifecycle store between tests
        from yashigani.backoffice.routes.policies import _lifecycle_store
        with _lifecycle_store._lock:
            _lifecycle_store._data.clear()

    def test_get_lifecycle_missing_is_draft(self):
        from yashigani.backoffice.routes.policies import _lifecycle_store
        entry = _lifecycle_store.get("nonexistent_policy")
        assert entry["status"] == "draft"

    def test_promote_draft_to_staging(self):
        from yashigani.backoffice.routes.policies import _lifecycle_store
        _lifecycle_store.init_if_absent("mypol", status="draft")
        entry = _lifecycle_store.set_status("mypol", "staging", promoted_by="admin1")
        assert entry["status"] == "staging"
        assert entry["promoted_by"] == "admin1"

    def test_promote_staging_to_production(self):
        from yashigani.backoffice.routes.policies import _lifecycle_store
        _lifecycle_store.init_if_absent("mypol", status="staging")
        _lifecycle_store.set_status("mypol", "staging")
        entry = _lifecycle_store.set_status("mypol", "production", promoted_by="admin1")
        assert entry["status"] == "production"

    def test_invalid_status_raises(self):
        from yashigani.backoffice.routes.policies import _lifecycle_store
        _lifecycle_store.init_if_absent("mypol", status="draft")
        with pytest.raises(ValueError, match="invalid status"):
            _lifecycle_store.set_status("mypol", "blah")

    def test_list_all_returns_all_tracked(self):
        from yashigani.backoffice.routes.policies import _lifecycle_store
        _lifecycle_store.init_if_absent("pol1", status="draft")
        _lifecycle_store.init_if_absent("pol2", status="staging")
        all_entries = _lifecycle_store.list_all()
        names = {e["name"] for e in all_entries}
        assert {"pol1", "pol2"}.issubset(names)

    def test_lifecycle_endpoint_get(self):
        """GET /admin/policies/lifecycle/{name} returns correct shape."""
        from yashigani.backoffice.routes.policies import _lifecycle_store
        _lifecycle_store.init_if_absent("mypol", status="staging")
        app = _make_policies_app()
        with TestClient(app) as client:
            resp = client.get("/admin/policies/lifecycle/mypol")
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "mypol"
        assert data["status"] == "staging"

    def test_lifecycle_list_endpoint(self):
        """GET /admin/policies/lifecycle returns list."""
        from yashigani.backoffice.routes.policies import _lifecycle_store
        _lifecycle_store.init_if_absent("pol_a", status="draft")
        app = _make_policies_app()
        with TestClient(app) as client:
            resp = client.get("/admin/policies/lifecycle")
        assert resp.status_code == 200
        assert "lifecycle" in resp.json()

    def test_promote_endpoint_via_api(self):
        """POST /admin/policies/lifecycle/{name}/promote: draft→staging via API."""
        from yashigani.backoffice.routes.policies import _lifecycle_store
        _lifecycle_store.init_if_absent("promtest", status="draft")
        app = _make_policies_app()

        # Stub _client_policy_loaded to return True
        with patch(
            "yashigani.backoffice.routes.policies._client_policy_loaded",
            new=AsyncMock(return_value=True),
        ):
            with TestClient(app) as client:
                resp = client.post("/admin/policies/lifecycle/promtest/promote")

        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["previous"] == "draft"
        assert data["lifecycle_status"] == "staging"

    def test_promote_production_returns_409(self):
        """Cannot promote from production (already at top)."""
        from yashigani.backoffice.routes.policies import _lifecycle_store
        _lifecycle_store.init_if_absent("prodpol", status="production")
        _lifecycle_store.set_status("prodpol", "production")
        app = _make_policies_app()

        with patch(
            "yashigani.backoffice.routes.policies._client_policy_loaded",
            new=AsyncMock(return_value=True),
        ):
            with TestClient(app) as client:
                resp = client.post("/admin/policies/lifecycle/prodpol/promote")

        assert resp.status_code == 409
        assert resp.json()["detail"]["error"] == "invalid_transition"

    def test_archive_endpoint(self):
        """POST /admin/policies/lifecycle/{name}/archive marks policy archived."""
        from yashigani.backoffice.routes.policies import _lifecycle_store
        _lifecycle_store.init_if_absent("archpol", status="production")
        _lifecycle_store.set_status("archpol", "production")
        app = _make_policies_app()

        with TestClient(app) as client:
            resp = client.post("/admin/policies/lifecycle/archpol/archive")

        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["lifecycle_status"] == "archived"


# ---------------------------------------------------------------------------
# R9 — Core policy edit confirm_danger guard
# ---------------------------------------------------------------------------

class TestCorePolicyEdit:
    """R9: confirm_danger=false must block the edit; true must proceed."""

    def test_missing_confirm_danger_returns_409(self):
        app = _make_policies_app()
        with TestClient(app) as client:
            resp = client.put(
                "/admin/policies/core/yashigani",
                json={
                    "rego": "package yashigani\nimport rego.v1\n",
                    "confirm_danger": False,
                    "reason": "testing",
                },
            )
        assert resp.status_code == 409
        assert resp.json()["detail"]["error"] == "confirm_danger_required"

    def test_missing_reason_returns_400(self):
        app = _make_policies_app()
        with TestClient(app) as client:
            resp = client.put(
                "/admin/policies/core/yashigani",
                json={
                    "rego": "package yashigani\nimport rego.v1\n",
                    "confirm_danger": True,
                    "reason": "",
                },
            )
        assert resp.status_code == 400
        assert resp.json()["detail"]["error"] == "reason_required"

    def test_non_core_policy_id_rejected(self):
        app = _make_policies_app()
        with TestClient(app) as client:
            resp = client.put(
                "/admin/policies/core/clients/my_custom",
                json={
                    "rego": "package clients.my_custom\nimport rego.v1\n",
                    "confirm_danger": True,
                    "reason": "testing non-core",
                },
            )
        assert resp.status_code == 400
        assert resp.json()["detail"]["error"] == "not_a_core_policy"

    def test_confirm_danger_with_valid_rego_saves(self):
        rego = "package yashigani\nimport rego.v1\ndefault allow := true\n"
        app = _make_policies_app()

        # static_sanity_check is imported lazily inside the handler; patch the module
        with patch(
            "yashigani.opa_assistant.sanity.static_sanity_check",
            new=AsyncMock(return_value={"compiled": True, "compile_error": None, "warnings": []}),
        ):
            # Stub internal_httpx_client used for the OPA PUT
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_put_client = AsyncMock()
            mock_put_client.__aenter__ = AsyncMock(return_value=mock_put_client)
            mock_put_client.__aexit__ = AsyncMock(return_value=None)
            mock_put_client.put = AsyncMock(return_value=mock_resp)

            with patch(
                "yashigani.backoffice.routes.policies.internal_httpx_client",
                return_value=mock_put_client,
            ):
                with TestClient(app) as client:
                    resp = client.put(
                        "/admin/policies/core/yashigani",
                        json={
                            "rego": rego,
                            "confirm_danger": True,
                            "reason": "testing core edit",
                        },
                    )

        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["status"] == "ok"
        assert data["category"] == "core"


# ---------------------------------------------------------------------------
# R8 — Template duplicate
# ---------------------------------------------------------------------------

class TestTemplateDuplicate:
    """R8: duplicate a template into an editable custom policy."""

    def _mock_opa_template_get(self, raw_rego: str):
        """Returns a context manager mock for internal_httpx_client that returns raw_rego."""
        mock_get_resp = MagicMock()
        mock_get_resp.status_code = 200
        mock_get_resp.json = MagicMock(return_value={
            "result": {"id": "examples/gdpr", "raw": raw_rego}
        })

        mock_put_resp = MagicMock()
        mock_put_resp.status_code = 200

        client_mock = AsyncMock()
        client_mock.__aenter__ = AsyncMock(return_value=client_mock)
        client_mock.__aexit__ = AsyncMock(return_value=None)
        client_mock.get = AsyncMock(return_value=mock_get_resp)
        client_mock.put = AsyncMock(return_value=mock_put_resp)
        return client_mock

    def test_duplicate_creates_client_policy(self):
        rego = "package examples.gdpr\nimport rego.v1\ndefault allow := false\n"
        app = _make_policies_app()
        from yashigani.backoffice.routes.policies import _lifecycle_store
        with _lifecycle_store._lock:
            _lifecycle_store._data.clear()

        mock_client = self._mock_opa_template_get(rego)
        with patch(
            "yashigani.backoffice.routes.policies.internal_httpx_client",
            return_value=mock_client,
        ):
            with TestClient(app) as client:
                resp = client.post(
                    "/admin/policies/templates/duplicate",
                    json={
                        "template_id": "examples/gdpr",
                        "new_name": "my_gdpr_copy",
                    },
                )

        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["status"] == "ok"
        assert data["id"] == "clients/my_gdpr_copy"
        assert data["lifecycle_status"] == "draft"

    def test_duplicate_reserved_name_rejected(self):
        app = _make_policies_app()
        with TestClient(app) as client:
            resp = client.post(
                "/admin/policies/templates/duplicate",
                json={"template_id": "examples/gdpr", "new_name": "yashigani"},
            )
        assert resp.status_code == 400
        assert resp.json()["detail"]["error"] == "invalid_name"

    def test_duplicate_template_not_found(self):
        """404 from OPA → 404 from endpoint."""
        mock_get_resp = MagicMock()
        mock_get_resp.status_code = 404

        client_mock = AsyncMock()
        client_mock.__aenter__ = AsyncMock(return_value=client_mock)
        client_mock.__aexit__ = AsyncMock(return_value=None)
        client_mock.get = AsyncMock(return_value=mock_get_resp)

        app = _make_policies_app()
        with patch(
            "yashigani.backoffice.routes.policies.internal_httpx_client",
            return_value=client_mock,
        ):
            with TestClient(app) as client:
                resp = client.post(
                    "/admin/policies/templates/duplicate",
                    json={"template_id": "examples/does_not_exist", "new_name": "copy"},
                )
        assert resp.status_code == 404
        assert resp.json()["detail"]["error"] == "template_not_found"


# ---------------------------------------------------------------------------
# R8 — Edit custom policy Rego
# ---------------------------------------------------------------------------

class TestEditCustomPolicyRego:
    """R8: PUT /admin/policies/custom/{name}/rego."""

    def test_edit_reserved_name_rejected(self):
        app = _make_policies_app()
        with TestClient(app) as client:
            resp = client.put(
                "/admin/policies/custom/rbac/rego",
                json={"rego": "package clients.rbac\n", "confirm_warnings": False},
            )
        assert resp.status_code == 400
        assert resp.json()["detail"]["error"] == "invalid_name"

    def test_edit_missing_package_rejected(self):
        app = _make_policies_app()
        with TestClient(app) as client:
            resp = client.put(
                "/admin/policies/custom/mypol/rego",
                json={"rego": "import rego.v1\ndefault allow := true\n"},
            )
        assert resp.status_code == 400
        assert resp.json()["detail"]["error"] == "missing_package"

    def test_edit_saves_on_clean_rego(self):
        rego = "package clients.mypol\nimport rego.v1\ndefault allow := true\n"
        app = _make_policies_app()

        mock_put_resp = MagicMock()
        mock_put_resp.status_code = 200
        client_mock = AsyncMock()
        client_mock.__aenter__ = AsyncMock(return_value=client_mock)
        client_mock.__aexit__ = AsyncMock(return_value=None)
        client_mock.put = AsyncMock(return_value=mock_put_resp)

        with patch(
            "yashigani.opa_assistant.sanity.static_sanity_check",
            new=AsyncMock(return_value={"compiled": True, "compile_error": None, "warnings": []}),
        ):
            with patch(
                "yashigani.backoffice.routes.policies.internal_httpx_client",
                return_value=client_mock,
            ):
                with TestClient(app) as client:
                    resp = client.put(
                        "/admin/policies/custom/mypol/rego",
                        json={"rego": rego},
                    )

        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["status"] == "ok"
        assert data["id"] == "clients/mypol"

    def test_check_only_returns_warnings_without_saving(self):
        rego = "package clients.mypol\nimport rego.v1\ndefault allow := false\n"
        app = _make_policies_app()

        with patch(
            "yashigani.opa_assistant.sanity.static_sanity_check",
            new=AsyncMock(return_value={
                "compiled": True, "compile_error": None,
                "warnings": [{"code": "deny_all", "severity": "high", "message": "denies all"}],
            }),
        ):
            with TestClient(app) as client:
                resp = client.put(
                    "/admin/policies/custom/mypol/rego",
                    json={"rego": rego, "check_only": True},
                )

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "checked"
        assert data["ok"] is False  # has high warnings


# ---------------------------------------------------------------------------
# R12 — Policy simulate
# ---------------------------------------------------------------------------

class TestPolicySimulate:
    """R12: POST /admin/policies/simulate."""

    def _opa_allow_response(self, allow: bool, deny: list):
        return {"result": {"allow": allow, "deny": deny, "obligations": []}}

    def test_simulate_returns_allow(self):
        mock_post_resp = MagicMock()
        mock_post_resp.status_code = 200
        mock_post_resp.json = MagicMock(return_value=self._opa_allow_response(True, []))

        client_mock = AsyncMock()
        client_mock.__aenter__ = AsyncMock(return_value=client_mock)
        client_mock.__aexit__ = AsyncMock(return_value=None)
        client_mock.post = AsyncMock(return_value=mock_post_resp)

        app = _make_policies_app()
        with patch(
            "yashigani.backoffice.routes.policies.internal_httpx_client",
            return_value=client_mock,
        ):
            with patch(
                "yashigani.backoffice.routes.policies._resolve_default_model",
                new=AsyncMock(return_value=("gemma3:4b", ["gemma3:4b"])),
            ):
                # Also stub httpx.AsyncClient for LLM call
                with patch("httpx.AsyncClient") as mock_httpx:
                    mock_llm_resp = MagicMock()
                    mock_llm_resp.json = MagicMock(return_value={"response": "The policy allows this."})
                    mock_llm_resp.raise_for_status = MagicMock()
                    mock_httpx_inst = AsyncMock()
                    mock_httpx_inst.__aenter__ = AsyncMock(return_value=mock_httpx_inst)
                    mock_httpx_inst.__aexit__ = AsyncMock(return_value=None)
                    mock_httpx_inst.post = AsyncMock(return_value=mock_llm_resp)
                    mock_httpx.return_value = mock_httpx_inst

                    with TestClient(app) as client:
                        resp = client.post(
                            "/admin/policies/simulate",
                            json={
                                "policy_id": "clients/test_policy",
                                "input_scenario": {"identity": {"role": "human"}},
                                "ai_explain": True,
                            },
                        )

        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["verdict"] == "allow"
        assert data["allow"] is True
        assert data["policy_id"] == "clients/test_policy"

    def test_simulate_returns_deny(self):
        mock_post_resp = MagicMock()
        mock_post_resp.status_code = 200
        mock_post_resp.json = MagicMock(
            return_value=self._opa_allow_response(False, ["gdpr_violation"])
        )

        client_mock = AsyncMock()
        client_mock.__aenter__ = AsyncMock(return_value=client_mock)
        client_mock.__aexit__ = AsyncMock(return_value=None)
        client_mock.post = AsyncMock(return_value=mock_post_resp)

        app = _make_policies_app()
        with patch(
            "yashigani.backoffice.routes.policies.internal_httpx_client",
            return_value=client_mock,
        ):
            with TestClient(app) as client:
                resp = client.post(
                    "/admin/policies/simulate",
                    json={
                        "policy_id": "clients/test_policy",
                        "input_scenario": {"identity": {"role": "human"}},
                        "ai_explain": False,
                    },
                )

        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["verdict"] == "deny"
        assert "gdpr_violation" in data["deny"]
        assert data["ai_explanation"] is None

    def test_simulate_undefined_decision(self):
        mock_post_resp = MagicMock()
        mock_post_resp.status_code = 200
        mock_post_resp.json = MagicMock(return_value={"result": None})

        client_mock = AsyncMock()
        client_mock.__aenter__ = AsyncMock(return_value=client_mock)
        client_mock.__aexit__ = AsyncMock(return_value=None)
        client_mock.post = AsyncMock(return_value=mock_post_resp)

        app = _make_policies_app()
        with patch(
            "yashigani.backoffice.routes.policies.internal_httpx_client",
            return_value=client_mock,
        ):
            with TestClient(app) as client:
                resp = client.post(
                    "/admin/policies/simulate",
                    json={
                        "policy_id": "clients/test_policy",
                        "input_scenario": {},
                        "ai_explain": False,
                    },
                )

        assert resp.status_code == 200
        assert resp.json()["verdict"] == "undefined"

    def test_simulate_policy_not_found_returns_404(self):
        mock_post_resp = MagicMock()
        mock_post_resp.status_code = 404

        client_mock = AsyncMock()
        client_mock.__aenter__ = AsyncMock(return_value=client_mock)
        client_mock.__aexit__ = AsyncMock(return_value=None)
        client_mock.post = AsyncMock(return_value=mock_post_resp)

        app = _make_policies_app()
        with patch(
            "yashigani.backoffice.routes.policies.internal_httpx_client",
            return_value=client_mock,
        ):
            with TestClient(app) as client:
                resp = client.post(
                    "/admin/policies/simulate",
                    json={
                        "policy_id": "clients/missing",
                        "input_scenario": {},
                        "ai_explain": False,
                    },
                )

        assert resp.status_code == 404
        assert resp.json()["detail"]["error"] == "policy_not_found"


# ---------------------------------------------------------------------------
# R16 — AI-generate detection pattern
# ---------------------------------------------------------------------------

class TestGeneratePattern:
    """R16: POST /admin/sensitivity/generate-pattern."""

    def _llm_json_response(self, regex: str, level: int, description: str) -> str:
        import json as _j
        return _j.dumps({"regex": regex, "level": level, "description": description})

    def test_generate_returns_regex_and_level(self):
        # LAURA-2255-003: endpoint now uses chat API (/api/chat), not /api/generate.
        # Response shape: {"message": {"content": "<json>"}} (not {"response": "..."}).
        # FIND-003: model is now qwen2.5:3b by default (not avail[0]=gemma3:4b).
        mock_llm_resp = MagicMock()
        mock_llm_resp.status_code = 200
        mock_llm_resp.json = MagicMock(return_value={
            "message": {
                "content": self._llm_json_response(
                    r"\bOFFICIAL[\s-]SENSITIVE\b", 4, "UK OFFICIAL-SENSITIVE marking"
                )
            }
        })
        mock_llm_resp.raise_for_status = MagicMock()

        mock_tags_resp = MagicMock()
        # gemma3:4b is the only available model; qwen2.5:3b is the fixed default (FIND-003)
        mock_tags_resp.json = MagicMock(return_value={"models": [{"name": "gemma3:4b"}]})
        mock_tags_resp.raise_for_status = MagicMock()

        mock_httpx_inst = AsyncMock()
        mock_httpx_inst.__aenter__ = AsyncMock(return_value=mock_httpx_inst)
        mock_httpx_inst.__aexit__ = AsyncMock(return_value=None)
        mock_httpx_inst.get = AsyncMock(return_value=mock_tags_resp)
        mock_httpx_inst.post = AsyncMock(return_value=mock_llm_resp)

        app = _make_sensitivity_app()
        with patch("httpx.AsyncClient", return_value=mock_httpx_inst):
            with TestClient(app) as client:
                resp = client.post(
                    "/admin/sensitivity/generate-pattern",
                    json={"description": "UK government OFFICIAL-SENSITIVE document markings"},
                )

        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["status"] == "ok"
        assert data["generated_regex"] == r"\bOFFICIAL[\s-]SENSITIVE\b"
        assert data["suggested_level"] == 4
        # FIND-003: default is qwen2.5:3b (structured-output model), not avail[0]
        assert data["model"] == "qwen2.5:3b", \
            f"FIND-003: expected qwen2.5:3b default, got {data['model']!r}"
        # LAURA-2255-003: raw_llm_response is never returned to the client
        assert "raw_llm_response" not in data

    def test_generate_clamps_level_to_valid_range(self):
        """LLM returning level=99 should be clamped to 5.

        LAURA-2255-003: uses chat API response shape {"message": {"content": ...}}.
        """
        mock_llm_resp = MagicMock()
        mock_llm_resp.status_code = 200
        mock_llm_resp.json = MagicMock(return_value={
            "message": {
                "content": self._llm_json_response(r"\d+", 99, "numbers")
            }
        })
        mock_llm_resp.raise_for_status = MagicMock()

        mock_tags_resp = MagicMock()
        mock_tags_resp.json = MagicMock(return_value={"models": [{"name": "qwen2.5:3b"}]})

        mock_httpx_inst = AsyncMock()
        mock_httpx_inst.__aenter__ = AsyncMock(return_value=mock_httpx_inst)
        mock_httpx_inst.__aexit__ = AsyncMock(return_value=None)
        mock_httpx_inst.get = AsyncMock(return_value=mock_tags_resp)
        mock_httpx_inst.post = AsyncMock(return_value=mock_llm_resp)

        app = _make_sensitivity_app()
        with patch("httpx.AsyncClient", return_value=mock_httpx_inst):
            with TestClient(app) as client:
                resp = client.post(
                    "/admin/sensitivity/generate-pattern",
                    json={"description": "numbers"},
                )

        assert resp.status_code == 200
        assert resp.json()["suggested_level"] == 5

    def test_generate_llm_unavailable_returns_503(self):
        """LLM chat call fails → 503 llm_unavailable.

        FIND-003: model is resolved before the chat call. The tags endpoint must
        return at least one model (or YASHIGANI_OPA_ASSISTANT_MODEL must be set)
        for the code to reach the chat call; otherwise it raises no_model_available.
        This test simulates: Ollama reachable (tags returns a model), chat call fails.
        """
        import httpx

        mock_tags_resp = MagicMock()
        # Provide qwen2.5:3b as available so model resolution succeeds
        mock_tags_resp.json = MagicMock(return_value={"models": [{"name": "qwen2.5:3b"}]})
        mock_tags_resp.raise_for_status = MagicMock()

        mock_httpx_inst = AsyncMock()
        mock_httpx_inst.__aenter__ = AsyncMock(return_value=mock_httpx_inst)
        mock_httpx_inst.__aexit__ = AsyncMock(return_value=None)
        mock_httpx_inst.get = AsyncMock(return_value=mock_tags_resp)
        # Chat call fails with connection error
        mock_httpx_inst.post = AsyncMock(
            side_effect=httpx.ConnectError("connection refused")
        )

        app = _make_sensitivity_app()
        with patch("httpx.AsyncClient", return_value=mock_httpx_inst):
            with TestClient(app) as client:
                resp = client.post(
                    "/admin/sensitivity/generate-pattern",
                    json={"description": "IBAN bank account numbers"},
                )

        assert resp.status_code == 503
        assert resp.json()["detail"]["error"] == "llm_unavailable"

    def test_generate_requires_auth(self):
        """Without dependency_overrides (no auth bypass), endpoint should be auth-gated.
        In a real stack, unauthenticated request returns 401/403. In this test we verify
        the endpoint exists and the auth annotation is present on the handler."""
        from yashigani.backoffice.routes import sensitivity as sens_mod
        import inspect
        handler = sens_mod.generate_pattern
        sig = inspect.signature(handler)
        # The 'session' parameter uses AdminSession annotation (auth gate present)
        assert "session" in sig.parameters

    def test_generate_description_too_short(self):
        app = _make_sensitivity_app()
        with TestClient(app) as client:
            resp = client.post(
                "/admin/sensitivity/generate-pattern",
                json={"description": "hi"},
            )
        # Pydantic validation rejects <5 chars
        assert resp.status_code == 422

    def test_generate_parse_error_raw_not_exposed(self):
        """If LLM returns non-JSON text, raw is NOT returned to client (LAURA-2255-003).

        FIND-003 update: a plain-text non-JSON response (no '{') triggers a retry
        with a stricter prompt. If the retry also returns non-JSON, the status is
        "empty_response" (FIND-003 new status) — NOT "parse_error" (which applies
        when the JSON is present but malformed). "empty_response" is still a failure
        status and the raw LLM output is never returned to the client.

        LAURA-2255-003: raw LLM output is logged server-side only.
        """
        mock_llm_resp = MagicMock()
        mock_llm_resp.status_code = 200
        mock_llm_resp.json = MagicMock(return_value={
            "message": {
                "content": "Sorry, I cannot generate that pattern."
            }
        })
        mock_llm_resp.raise_for_status = MagicMock()

        mock_tags_resp = MagicMock()
        mock_tags_resp.json = MagicMock(return_value={"models": [{"name": "gemma3:4b"}]})
        mock_tags_resp.raise_for_status = MagicMock()

        mock_httpx_inst = AsyncMock()
        mock_httpx_inst.__aenter__ = AsyncMock(return_value=mock_httpx_inst)
        mock_httpx_inst.__aexit__ = AsyncMock(return_value=None)
        mock_httpx_inst.get = AsyncMock(return_value=mock_tags_resp)
        # Both initial call and retry return the non-JSON text (simulating a stubborn model)
        mock_httpx_inst.post = AsyncMock(return_value=mock_llm_resp)

        app = _make_sensitivity_app()
        with patch("httpx.AsyncClient", return_value=mock_httpx_inst):
            with TestClient(app) as client:
                resp = client.post(
                    "/admin/sensitivity/generate-pattern",
                    json={"description": "something specific and unusual"},
                )

        assert resp.status_code == 200
        data = resp.json()
        # FIND-003: plain-text non-JSON (no '{') → retry → still no JSON → "empty_response"
        # "parse_error" is for when JSON is present but malformed.
        assert data["status"] in ("parse_error", "empty_response"), \
            f"Expected parse_error or empty_response, got {data['status']!r}"
        # Security (LAURA-2255-003): raw LLM output MUST NOT reach the client
        assert "raw_llm_response" not in data
        # No usable regex is returned when generation fails
        assert data["generated_regex"] == ""


# ---------------------------------------------------------------------------
# OpenAPI presence: all new endpoints appear in the schema
# ---------------------------------------------------------------------------

class TestOpenAPIPresence:
    """Verify the new endpoints appear in the FastAPI OpenAPI schema."""

    def _policy_paths(self):
        app = _make_policies_app()
        with TestClient(app) as client:
            resp = client.get("/openapi.json")
        assert resp.status_code == 200
        return resp.json()["paths"]

    def _sensitivity_paths(self):
        app = _make_sensitivity_app()
        with TestClient(app) as client:
            resp = client.get("/openapi.json")
        assert resp.status_code == 200
        return resp.json()["paths"]

    def test_r8_duplicate_template_in_schema(self):
        paths = self._policy_paths()
        assert "/admin/policies/templates/duplicate" in paths
        assert "post" in paths["/admin/policies/templates/duplicate"]

    def test_r8_edit_custom_rego_in_schema(self):
        paths = self._policy_paths()
        assert "/admin/policies/custom/{name}/rego" in paths
        assert "put" in paths["/admin/policies/custom/{name}/rego"]

    def test_r9_core_edit_in_schema(self):
        paths = self._policy_paths()
        assert "/admin/policies/core/{policy_id}" in paths
        assert "put" in paths["/admin/policies/core/{policy_id}"]

    def test_r10_lifecycle_in_schema(self):
        paths = self._policy_paths()
        assert "/admin/policies/lifecycle" in paths
        assert "/admin/policies/lifecycle/{name}" in paths
        assert "/admin/policies/lifecycle/{name}/promote" in paths
        assert "/admin/policies/lifecycle/{name}/archive" in paths

    def test_r12_simulate_in_schema(self):
        paths = self._policy_paths()
        assert "/admin/policies/simulate" in paths
        assert "post" in paths["/admin/policies/simulate"]

    def test_r16_generate_pattern_in_schema(self):
        paths = self._sensitivity_paths()
        assert "/admin/sensitivity/generate-pattern" in paths
        assert "post" in paths["/admin/sensitivity/generate-pattern"]
