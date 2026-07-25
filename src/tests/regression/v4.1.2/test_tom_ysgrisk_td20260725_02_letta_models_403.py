"""
YSG-RISK/TD-2026-07-25-02 — @letta bundled-agent GET /v1/models 403.

Regression coverage for the fix. Two independent defect classes closed:

1. GAP-001 kind-set gap (policy/v1_routing.rego `models_list_allowed`):
   bundled P1 wrapped systems (Letta, Langflow, OpenClaw) resolve via
   ``_resolve_identity``'s p1_agent branch (``kind="agent"``) or p1_nhi
   branch (``kind="nhi"``) — both are mesh/PSK-authenticated service-tier
   principals running the SAME per-instance model-list sync "service"/
   "unknown" callers already do. They were omitted from the original
   GAP-001 kind-set, so a bundled agent whose identity resolved with
   kind=="agent"/"nhi" was hard-denied on /v1/models regardless of active
   status. Covered at the rego layer by policy/v1_routing_test.rego
   (test_models_agent_kind_allowed_restricted /
   test_models_nhi_kind_allowed_restricted); this file proves the SAME
   thing end-to-end through the Python handler with a mocked OPA response
   shaped exactly like the (now-fixed) rego would return.

2. dict.get(key, default) gotcha (three call sites + two registry decoders):
   ``.get(key, "active")`` only applies the default when the key is ABSENT
   — a registry-backed identity dict that carries an EXPLICIT empty string
   for "status" (e.g. a Redis hash whose status field was never written)
   silently bypasses the "active" default and reaches OPA as status="",
   which never equals "active". Fixed at:
     - openai_router._opa_models_check (identity_doc construction)
     - openai_router._resolve_nhi_identity (p1_nhi branch)
     - openai_router._resolve_identity (p1_agent branch)
     - agents.registry.AgentRegistry._decode_agent
     - identity.registry.IdentityRegistry._decode

ASVS V4.1.1 / V4.1.3 / OWASP API9 / YSG-RISK/TD-2026-07-25-02.
"""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ---------------------------------------------------------------------------
# 1. _opa_models_check — the status/kind dict.get() gotcha
# ---------------------------------------------------------------------------


def _opa_success(allow: bool, filter_: str = "restricted", reason: str = "ok"):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"result": {"allow": allow, "filter": filter_, "reason": reason}}
    return mock_resp


class TestOpaModelsCheckStatusGotcha:
    """_opa_models_check must treat an EXPLICIT empty-string status/kind the
    same as an ABSENT one — both default to "active"/"unknown", never leak
    "" to OPA (which would never satisfy status=="active")."""

    @pytest.mark.asyncio
    async def test_explicit_empty_status_defaults_to_active(self, monkeypatch):
        from yashigani.gateway import openai_router as _mod

        monkeypatch.setattr(_mod._state, "opa_url", "https://opa:8181")
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        posted_input = {}

        async def _capture_post(url, json=None, **kwargs):
            posted_input.update(json["input"])
            return _opa_success(True, "restricted", "ok")

        mock_client.post = _capture_post

        with patch("yashigani.gateway.openai_router.internal_httpx_client", return_value=mock_client):
            # identity dict with an EXPLICIT "" status (the bug shape: key
            # present, value falsy — e.g. a registry record whose status
            # field was never HSET).
            identity = {"identity_id": "letta", "status": "", "kind": "agent",
                        "sensitivity_ceiling": "RESTRICTED", "allowed_models": []}
            result = await _mod._opa_models_check(identity)

        assert posted_input["identity"]["status"] == "active"
        assert result["allow"] is True

    @pytest.mark.asyncio
    async def test_explicit_none_status_defaults_to_active(self, monkeypatch):
        from yashigani.gateway import openai_router as _mod

        monkeypatch.setattr(_mod._state, "opa_url", "https://opa:8181")
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        posted_input = {}

        async def _capture_post(url, json=None, **kwargs):
            posted_input.update(json["input"])
            return _opa_success(True, "restricted", "ok")

        mock_client.post = _capture_post

        with patch("yashigani.gateway.openai_router.internal_httpx_client", return_value=mock_client):
            identity = {"identity_id": "letta", "status": None, "kind": "service",
                        "sensitivity_ceiling": "RESTRICTED", "allowed_models": []}
            await _mod._opa_models_check(identity)

        assert posted_input["identity"]["status"] == "active"

    @pytest.mark.asyncio
    async def test_empty_kind_defaults_to_unknown(self, monkeypatch):
        from yashigani.gateway import openai_router as _mod

        monkeypatch.setattr(_mod._state, "opa_url", "https://opa:8181")
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        posted_input = {}

        async def _capture_post(url, json=None, **kwargs):
            posted_input.update(json["input"])
            return _opa_success(True, "restricted", "ok")

        mock_client.post = _capture_post

        with patch("yashigani.gateway.openai_router.internal_httpx_client", return_value=mock_client):
            identity = {"identity_id": "letta", "status": "active", "kind": "",
                        "sensitivity_ceiling": "RESTRICTED", "allowed_models": []}
            await _mod._opa_models_check(identity)

        assert posted_input["identity"]["kind"] == "unknown"

    @pytest.mark.asyncio
    async def test_real_active_status_still_forwarded_unchanged(self, monkeypatch):
        """Non-regression: a well-formed active identity is unaffected."""
        from yashigani.gateway import openai_router as _mod

        monkeypatch.setattr(_mod._state, "opa_url", "https://opa:8181")
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        posted_input = {}

        async def _capture_post(url, json=None, **kwargs):
            posted_input.update(json["input"])
            return _opa_success(True, "full", "ok")

        mock_client.post = _capture_post

        with patch("yashigani.gateway.openai_router.internal_httpx_client", return_value=mock_client):
            identity = {"identity_id": "alice", "status": "active", "kind": "human",
                        "sensitivity_ceiling": "INTERNAL", "allowed_models": []}
            await _mod._opa_models_check(identity)

        assert posted_input["identity"]["status"] == "active"
        assert posted_input["identity"]["kind"] == "human"

    @pytest.mark.asyncio
    async def test_suspended_status_still_denies(self, monkeypatch):
        """Non-regression: a GENUINELY suspended identity must still be
        forwarded as "suspended" (not silently upgraded to "active" — the
        `or` fallback only fires on FALSY values, "suspended" is truthy)."""
        from yashigani.gateway import openai_router as _mod

        monkeypatch.setattr(_mod._state, "opa_url", "https://opa:8181")
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        posted_input = {}

        async def _capture_post(url, json=None, **kwargs):
            posted_input.update(json["input"])
            return _opa_success(False, "denied", "identity_not_active_or_anonymous")

        mock_client.post = _capture_post

        with patch("yashigani.gateway.openai_router.internal_httpx_client", return_value=mock_client):
            identity = {"identity_id": "bob", "status": "suspended", "kind": "human",
                        "sensitivity_ceiling": "INTERNAL", "allowed_models": []}
            result = await _mod._opa_models_check(identity)

        assert posted_input["identity"]["status"] == "suspended"
        assert result["allow"] is False


# ---------------------------------------------------------------------------
# 2. list_models — end-to-end for the bundled-agent kinds ("agent"/"nhi")
# ---------------------------------------------------------------------------


class TestListModelsBundledAgentParity:
    """End-to-end: a caller resolving to kind="agent" (Letta/Langflow/
    OpenClaw's per-instance PSK path) or kind="nhi" gets the SAME
    restricted-filter treatment "service"/"unknown" already got — proving
    the fix closes /v1/models for bundled agents WITHOUT granting them
    "full" and without touching the human/anonymous/inactive paths."""

    def _make_request(self):
        req = MagicMock()
        req.headers = {"Authorization": "Bearer test-key"}
        req.cookies = {}
        return req

    @pytest.mark.asyncio
    async def test_agent_kind_identity_allowed_restricted(self, monkeypatch):
        from yashigani.gateway import openai_router as _mod

        agent_identity = {
            "identity_id": "agent__letta", "status": "active", "kind": "agent",
            "sensitivity_ceiling": "INTERNAL", "allowed_models": ["qwen2.5:3b"],
            "groups": [],
        }
        monkeypatch.setattr(_mod, "_resolve_identity", lambda req: agent_identity)
        monkeypatch.setattr(_mod, "_opa_models_check", AsyncMock(
            return_value={"allow": True, "filter": "restricted", "reason": "ok"}
        ))
        monkeypatch.setattr(_mod._state, "ollama_url", "http://ollama:11434")
        monkeypatch.setattr(_mod._state, "identity_registry", MagicMock())
        monkeypatch.setattr(_mod._state, "agent_registry", MagicMock())
        monkeypatch.setattr(_mod._state, "available_models", [
            {"id": "qwen2.5:3b", "provider": "ollama"},
        ])
        monkeypatch.setattr(_mod._state, "audit_writer", None)

        async def _fake_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {"models": [{"name": "qwen2.5:3b"}]}
            return resp
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = _fake_get
        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await _mod.list_models(self._make_request())

        ids = {m.id for m in result.data}
        assert "qwen2.5:3b" in ids
        # Restricted filter: no topology enumeration for an agent-kind caller.
        assert not any(i.startswith("@") for i in ids)

    @pytest.mark.asyncio
    async def test_nhi_kind_identity_allowed_restricted(self, monkeypatch):
        from yashigani.gateway import openai_router as _mod

        nhi_identity = {
            "identity_id": "nhi_abc123", "status": "active", "kind": "nhi",
            "sensitivity_ceiling": "PUBLIC", "allowed_models": ["llama3:8b"],
            "groups": [],
        }
        monkeypatch.setattr(_mod, "_resolve_identity", lambda req: nhi_identity)
        monkeypatch.setattr(_mod, "_opa_models_check", AsyncMock(
            return_value={"allow": True, "filter": "restricted", "reason": "ok"}
        ))
        monkeypatch.setattr(_mod._state, "ollama_url", "http://ollama:11434")
        monkeypatch.setattr(_mod._state, "identity_registry", MagicMock())
        monkeypatch.setattr(_mod._state, "agent_registry", MagicMock())
        monkeypatch.setattr(_mod._state, "available_models", [
            {"id": "llama3:8b", "provider": "ollama"},
        ])
        monkeypatch.setattr(_mod._state, "audit_writer", None)

        async def _fake_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {"models": [{"name": "llama3:8b"}]}
            return resp
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = _fake_get
        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await _mod.list_models(self._make_request())

        ids = {m.id for m in result.data}
        assert "llama3:8b" in ids

    @pytest.mark.asyncio
    async def test_agent_kind_denied_when_opa_denies(self, monkeypatch):
        """Least-privilege proof: the fix does NOT bypass OPA for agent-kind
        callers — an OPA deny (e.g. genuinely inactive) still 403s."""
        from yashigani.gateway import openai_router as _mod
        from fastapi import HTTPException

        agent_identity = {"identity_id": "agent__letta", "status": "suspended",
                          "kind": "agent", "sensitivity_ceiling": "INTERNAL",
                          "allowed_models": [], "groups": []}
        monkeypatch.setattr(_mod, "_resolve_identity", lambda req: agent_identity)
        monkeypatch.setattr(_mod, "_opa_models_check", AsyncMock(
            return_value={"allow": False, "filter": "denied",
                          "reason": "identity_not_active_or_anonymous"}
        ))
        monkeypatch.setattr(_mod._state, "audit_writer", None)

        with pytest.raises(HTTPException) as exc_info:
            await _mod.list_models(self._make_request())
        assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_human_anonymous_unaffected_by_fix(self, monkeypatch):
        """Least-privilege proof: anonymous callers still get 401 — the
        agent/nhi kind-set widening does not touch the identity-resolution
        401 path at all."""
        from yashigani.gateway import openai_router as _mod
        from fastapi import HTTPException

        monkeypatch.setattr(_mod, "_resolve_identity", lambda req: None)

        with pytest.raises(HTTPException) as exc_info:
            await _mod.list_models(self._make_request())
        assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# 3. _resolve_nhi_identity — status dict.get() gotcha at the source
# ---------------------------------------------------------------------------


class TestResolveNhiIdentityStatusGotcha:
    def test_empty_status_from_registry_defaults_to_active(self, monkeypatch):
        from yashigani.gateway import openai_router as _mod

        mock_registry = MagicMock()
        mock_registry.get.return_value = {
            "kind": "nhi", "svid_issued": True, "status": "",  # bug shape
            "allowed_models": [], "allowed_paths": [], "allowed_tools": [],
            "sensitivity_ceiling": "PUBLIC", "budget_cap": {},
            "owner_identity_id": "idnt_x", "template_id": "tmpl_x",
            "spiffe_id": "spiffe://yashigani.internal/nhi/x",
        }
        monkeypatch.setattr(_mod._state, "agent_registry", mock_registry)

        identity = _mod._resolve_nhi_identity("nhi_abc123")
        assert identity is not None
        assert identity["status"] == "active"

    def test_real_inactive_status_preserved(self, monkeypatch):
        from yashigani.gateway import openai_router as _mod

        mock_registry = MagicMock()
        mock_registry.get.return_value = {
            "kind": "nhi", "svid_issued": True, "status": "inactive",
            "allowed_models": [], "allowed_paths": [], "allowed_tools": [],
            "sensitivity_ceiling": "PUBLIC", "budget_cap": {},
            "owner_identity_id": "idnt_x", "template_id": "tmpl_x",
            "spiffe_id": "spiffe://yashigani.internal/nhi/x",
        }
        monkeypatch.setattr(_mod._state, "agent_registry", mock_registry)

        identity = _mod._resolve_nhi_identity("nhi_abc123")
        assert identity["status"] == "inactive"


# ---------------------------------------------------------------------------
# 4. AgentRegistry._decode_agent — status field decode-time fix
# ---------------------------------------------------------------------------


class TestDecodeAgentStatusGotcha:
    def test_missing_status_hash_field_decodes_to_active(self):
        from yashigani.agents.registry import AgentRegistry

        # Redis hash with NO "status" field at all (partial/legacy write).
        raw = {
            b"name": b"letta", b"upstream_url": b"", b"protocol": b"openai",
            b"created_at": b"2026-07-25T00:00:00Z", b"last_seen_at": b"",
            b"groups": b"[]", b"allowed_caller_groups": b"[]",
            b"allowed_paths": b"[]", b"allowed_cidrs": b"[]",
            b"kind": b"agent",
        }
        decoded = AgentRegistry._decode_agent("agnt_test", raw)
        assert decoded["status"] == "active"

    def test_real_inactive_status_preserved(self):
        from yashigani.agents.registry import AgentRegistry

        raw = {
            b"name": b"letta", b"upstream_url": b"", b"protocol": b"openai",
            b"status": b"inactive",
            b"created_at": b"2026-07-25T00:00:00Z", b"last_seen_at": b"",
            b"groups": b"[]", b"allowed_caller_groups": b"[]",
            b"allowed_paths": b"[]", b"allowed_cidrs": b"[]",
            b"kind": b"agent",
        }
        decoded = AgentRegistry._decode_agent("agnt_test", raw)
        assert decoded["status"] == "inactive"


# ---------------------------------------------------------------------------
# 5. IdentityRegistry._decode — status field decode-time fix (defense in depth)
# ---------------------------------------------------------------------------


class TestIdentityRegistryDecodeStatusGotcha:
    def test_missing_status_hash_field_decodes_to_active(self):
        from yashigani.identity.registry import IdentityRegistry

        raw = {b"identity_id": b"idnt_test", b"kind": b"service", b"name": b"x",
               b"slug": b"x"}
        decoded = IdentityRegistry._decode(raw)
        assert decoded["status"] == "active"

    def test_real_suspended_status_preserved(self):
        from yashigani.identity.registry import IdentityRegistry

        raw = {b"identity_id": b"idnt_test", b"kind": b"human", b"name": b"x",
               b"slug": b"x", b"status": b"suspended"}
        decoded = IdentityRegistry._decode(raw)
        assert decoded["status"] == "suspended"
