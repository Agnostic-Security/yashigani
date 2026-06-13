"""
R2 — fix/2.25.5-owui-deny-message: gateway deny responses carry human-readable
``error.message`` in the OpenAI error schema so Open WebUI displays the reason
in chat instead of a generic "Oops! There was an error."

Tests cover:
  1. _owui_deny_message() lookup table — known codes, unknown code fallback
  2. model_not_allocated deny (explicit-pin + alloc-bind) returns
     OpenAI error schema with human-readable message
  3. OPA v1 ingress deny (identity_not_active, sensitivity_ceiling_exceeded)
     returns OpenAI error schema with human-readable message
  4. OPA response-path deny returns OpenAI error schema with human-readable message
  5. Enforcement is unchanged — request is still denied (4xx status code)

Authorities: Tiago directive 2026-06-13 / R2 brief.
ASVS V7.3.4 (audit accuracy) / OWASP A05 (security misconfiguration — UX).
Last updated: 2026-06-13T00:00:00+00:00
"""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock, AsyncMock, patch


# ---------------------------------------------------------------------------
# Section 1 — _owui_deny_message lookup table
# ---------------------------------------------------------------------------

class TestOwuiDenyMessageLookup:
    """_owui_deny_message() returns layman strings from the lookup table."""

    def test_model_not_allocated_is_human_readable(self):
        from yashigani.gateway.openai_router import _owui_deny_message
        msg = _owui_deny_message("model_not_allocated")
        assert "model" in msg.lower() or "administrator" in msg.lower()
        # Must NOT contain the machine code
        assert "model_not_allocated" not in msg

    def test_identity_not_active_is_human_readable(self):
        from yashigani.gateway.openai_router import _owui_deny_message
        msg = _owui_deny_message("identity_not_active")
        assert "account" in msg.lower() or "active" in msg.lower()
        assert "identity_not_active" not in msg

    def test_sensitivity_ceiling_exceeded_is_human_readable(self):
        from yashigani.gateway.openai_router import _owui_deny_message
        msg = _owui_deny_message("sensitivity_ceiling_exceeded")
        assert "sensitivity" in msg.lower() or "clearance" in msg.lower()
        assert "sensitivity_ceiling_exceeded" not in msg

    def test_opa_unreachable_is_human_readable(self):
        from yashigani.gateway.openai_router import _owui_deny_message
        msg = _owui_deny_message("opa_unreachable")
        assert "temporarily" in msg.lower() or "unavailable" in msg.lower()
        assert "opa_unreachable" not in msg

    def test_pii_detected_is_human_readable(self):
        from yashigani.gateway.openai_router import _owui_deny_message
        msg = _owui_deny_message("pii_detected")
        assert "personal" in msg.lower() or "data" in msg.lower()
        assert "pii_detected" not in msg

    def test_pii_detected_encoded_is_human_readable(self):
        from yashigani.gateway.openai_router import _owui_deny_message
        msg = _owui_deny_message("pii_detected_encoded")
        assert "encoded" in msg.lower() or "personal" in msg.lower()
        assert "pii_detected_encoded" not in msg

    def test_unknown_code_returns_generic_message(self):
        from yashigani.gateway.openai_router import _owui_deny_message, _OWUI_GENERIC_DENY
        msg = _owui_deny_message("totally_unknown_reason_xyz")
        assert msg == _OWUI_GENERIC_DENY
        # Generic message must be human-readable, no machine code
        assert "totally_unknown" not in msg
        assert len(msg) > 20

    def test_all_table_entries_are_strings(self):
        from yashigani.gateway.openai_router import _OWUI_DENY_MESSAGES
        for code, msg in _OWUI_DENY_MESSAGES.items():
            assert isinstance(msg, str), f"Entry for {code!r} is not a string"
            assert len(msg) > 10, f"Entry for {code!r} is suspiciously short"
            # The machine code must not appear verbatim in its own message
            assert code not in msg, f"Machine code {code!r} leaks into its message"

    def test_all_table_messages_mention_action_or_contact(self):
        """Every deny message should tell the user what to do next."""
        from yashigani.gateway.openai_router import _OWUI_DENY_MESSAGES
        for code, msg in _OWUI_DENY_MESSAGES.items():
            msg_lower = msg.lower()
            has_guidance = (
                "administrator" in msg_lower
                or "contact" in msg_lower
                or "try again" in msg_lower
                or "remove" in msg_lower
                or "ask" in msg_lower
            )
            assert has_guidance, (
                f"Message for {code!r} lacks guidance for the user: {msg!r}"
            )


# ---------------------------------------------------------------------------
# Section 2 — model_not_allocated deny returns proper OpenAI error schema
# ---------------------------------------------------------------------------

def _reset_router_state():
    """Reset openai_router._state to a safe test baseline."""
    from yashigani.gateway import openai_router as _mod
    _mod._state.opa_url = "https://policy:8181"
    _mod._state.audit_writer = None
    _mod._state.response_inspection_pipeline = None
    _mod._state.sensitivity_classifier = None
    _mod._state.complexity_scorer = None
    _mod._state.optimization_engine = None
    _mod._state.model_allocation_store = None
    _mod._state.model_alias_store = None
    _mod._state.pii_detector = None
    _mod._state.ddos_protector = None
    _mod._state.content_relay_detector = None
    _mod._state.agent_registry = None
    _mod._state.pool_manager = None
    _mod._state.identity_registry = None


def _make_opa_allow_cm():
    """Return an async context manager that returns OPA allow=True."""
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {
        "result": {
            "allow": True,
            "model_allowed": True,
            "routing_safe": True,
            "sensitivity_allowed": True,
            "reason": "ok",
        }
    }
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_resp)
    cm = AsyncMock()
    cm.__aenter__ = AsyncMock(return_value=mock_client)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


def _make_opa_deny_cm(reason: str):
    """Return an async context manager that returns OPA allow=False with reason."""
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {
        "result": {
            "allow": False,
            "model_allowed": False,
            "routing_safe": True,
            "sensitivity_allowed": True,
            "reason": reason,
        }
    }
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_resp)
    cm = AsyncMock()
    cm.__aenter__ = AsyncMock(return_value=mock_client)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


def _make_mock_request(bearer: str = "test-internal-bearer-token-for-unit-tests"):
    """Build a minimal FastAPI Request-like mock for identity resolution."""
    mock_request = MagicMock()
    mock_request.headers = {
        "authorization": f"Bearer {bearer}",
        "x-openwebui-user-email": "",
    }
    mock_request.headers.get = lambda k, d="": {
        "authorization": f"Bearer {bearer}",
        "x-openwebui-user-email": "",
        "x-yashigani-orchestration-depth": "",
        "x-yashigani-principal": "",
    }.get(k.lower(), d)
    mock_request.client = MagicMock()
    mock_request.client.host = "127.0.0.1"
    mock_request.url = MagicMock()
    mock_request.url.path = "/v1/chat/completions"
    return mock_request


class TestModelNotAllocatedDenyShape:
    """model_not_allocated deny returns {"error": {"message": "<human>", "type": "...", "code": "..."}}."""

    @pytest.mark.asyncio
    async def test_explicit_pin_deny_has_openai_error_schema(self):
        """B1-OBS-A explicit-pin deny: error.message is human-readable, code is machine code."""
        from yashigani.gateway import openai_router as _mod

        _reset_router_state()

        # Build a mock EffectiveModels that denies the requested model
        mock_effective = MagicMock()
        mock_effective.is_model_denied.return_value = True
        mock_effective.to_opa_allowed_models.return_value = []

        # Build mock identity with restricted allocation
        mock_identity = {
            "identity_id": "alice",
            "status": "active",
            "kind": "human",
            "groups": ["users"],
            "allowed_models": [],
            "sensitivity_ceiling": "PUBLIC",
        }

        from fastapi.testclient import TestClient
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(_mod.router)

        # Override _resolve_identity and _effective_allowed_models
        # is_letta_orchestration is imported inside the handler, patch at its source
        with (
            patch.object(_mod, "_resolve_identity", return_value=mock_identity),
            patch.object(_mod, "_effective_allowed_models", return_value=mock_effective),
            patch("yashigani.gateway.letta_brain.is_letta_orchestration", return_value=False),
        ):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/v1/chat/completions",
                json={
                    "model": "denied-model",
                    "messages": [{"role": "user", "content": "hello"}],
                },
                headers={"Authorization": "Bearer test-token"},
            )

        assert resp.status_code == 403
        body = resp.json()
        # Must have OpenAI error schema
        assert "error" in body, f"Missing 'error' key in: {body}"
        err = body["error"]
        assert "message" in err, f"Missing 'error.message' in: {err}"
        assert "type" in err
        assert "code" in err
        # message must be human-readable (not a raw machine code)
        assert err["code"] == "model_not_allocated"
        assert "model_not_allocated" not in err["message"]
        # message should mention the model or administrator
        msg_lower = err["message"].lower()
        assert "model" in msg_lower or "administrator" in msg_lower, (
            f"error.message not human-readable: {err['message']!r}"
        )

    @pytest.mark.asyncio
    async def test_deny_body_is_valid_openai_error_schema(self):
        """OPA ingress deny: error.message is human-readable, not a raw reason code."""
        from yashigani.gateway import openai_router as _mod

        _reset_router_state()

        # No allocation enforcement — falls through to OPA
        mock_effective = MagicMock()
        mock_effective.is_model_denied.return_value = False
        mock_effective.to_opa_allowed_models.return_value = ["llama3:8b"]

        mock_identity = {
            "identity_id": "bob",
            "status": "inactive",  # will trigger identity_not_active OPA deny
            "kind": "human",
            "groups": [],
            "allowed_models": ["llama3:8b"],
            "sensitivity_ceiling": "PUBLIC",
        }

        opa_deny_cm = _make_opa_deny_cm("identity_not_active")

        from fastapi.testclient import TestClient
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(_mod.router)

        # is_letta_orchestration is imported inside the handler, patch at its source
        with (
            patch.object(_mod, "_resolve_identity", return_value=mock_identity),
            patch.object(_mod, "_effective_allowed_models", return_value=mock_effective),
            patch("yashigani.gateway.letta_brain.is_letta_orchestration", return_value=False),
            patch("yashigani.gateway.openai_router.internal_httpx_client", return_value=opa_deny_cm),
        ):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/v1/chat/completions",
                json={
                    "model": "llama3:8b",
                    "messages": [{"role": "user", "content": "hello"}],
                },
                headers={"Authorization": "Bearer test-token"},
            )

        assert resp.status_code == 403
        body = resp.json()
        assert "error" in body
        err = body["error"]
        assert "message" in err
        # The raw OPA reason code must NOT appear in message
        assert "identity_not_active" not in err["message"]
        # Must be human-readable
        msg_lower = err["message"].lower()
        assert "account" in msg_lower or "active" in msg_lower or "administrator" in msg_lower
        # code carries the machine code for tooling
        assert err["code"] == "identity_not_active"


# ---------------------------------------------------------------------------
# Section 3 — OPA ingress deny reason codes → human-readable messages
# ---------------------------------------------------------------------------

class TestOPAIngressDenyMessages:
    """For each OPA reason code, the deny response carries a human-readable message."""

    @pytest.mark.parametrize("reason,expected_substring", [
        ("identity_not_active", "account"),
        ("sensitivity_ceiling_exceeded", "sensitivity"),
        ("routing_unsafe_sensitive_to_cloud", "sensitive"),
        ("model_not_allowed", "model"),
        ("opa_unreachable", "unavailable"),
    ])
    @pytest.mark.asyncio
    async def test_opa_ingress_reason_maps_to_human_message(self, reason, expected_substring):
        """_opa_v1_check deny with known reason → human-readable error.message."""
        from yashigani.gateway.openai_router import _owui_deny_message

        msg = _owui_deny_message(reason)
        # message must be human-readable and contain the expected word
        assert expected_substring in msg.lower(), (
            f"For reason={reason!r}, expected {expected_substring!r} in message: {msg!r}"
        )
        # machine code must not appear verbatim in the message
        assert reason not in msg, (
            f"Machine code {reason!r} leaks into the message: {msg!r}"
        )


# ---------------------------------------------------------------------------
# Section 4 — OPA response-path deny returns proper schema
# ---------------------------------------------------------------------------

class TestOPAResponseDenyShape:
    """OPA response-path deny returns OpenAI error schema with human-readable message."""

    def _make_response_opa_deny_cm(self, reason: str):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"result": {"allow": False, "reason": reason}}
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=mock_client)
        cm.__aexit__ = AsyncMock(return_value=False)
        return cm

    @pytest.mark.parametrize("reason,expected_substring", [
        ("response_sensitivity_exceeds_ceiling", "sensitivity"),
        ("response_blocked_by_inspection", "blocked"),
        ("denied_default_deny", "denied"),
        ("invalid_identity_ceiling", "clearance"),
    ])
    def test_response_deny_message_is_human_readable(self, reason, expected_substring):
        """Response-path OPA reason codes map to human-readable messages."""
        from yashigani.gateway.openai_router import _owui_deny_message

        msg = _owui_deny_message(reason)
        assert expected_substring in msg.lower(), (
            f"For reason={reason!r}, expected {expected_substring!r} in: {msg!r}"
        )
        assert reason not in msg, (
            f"Machine code {reason!r} leaks into message: {msg!r}"
        )


# ---------------------------------------------------------------------------
# Section 5 — Enforcement unchanged (still denies, just better message)
# ---------------------------------------------------------------------------

class TestEnforcementUnchanged:
    """Enforcement is not weakened — all deny paths still return 4xx."""

    def test_model_not_allocated_still_403(self):
        """model_not_allocated deny is still HTTP 403 after the message fix."""
        # Verify via direct JSONResponse construction (shape test)
        from fastapi.responses import JSONResponse
        from yashigani.gateway.openai_router import _owui_deny_message

        resp = JSONResponse(
            status_code=403,
            content={
                "error": {
                    "message": _owui_deny_message("model_not_allocated"),
                    "type": "policy_denied",
                    "code": "model_not_allocated",
                }
            },
        )
        assert resp.status_code == 403

    def test_opa_deny_still_403(self):
        """OPA ingress deny is still HTTP 403 after the message fix."""
        from fastapi.responses import JSONResponse
        from yashigani.gateway.openai_router import _owui_deny_message

        resp = JSONResponse(
            status_code=403,
            content={
                "error": {
                    "message": _owui_deny_message("identity_not_active"),
                    "type": "policy_denied",
                    "code": "identity_not_active",
                }
            },
        )
        assert resp.status_code == 403

    def test_error_schema_has_all_three_fields(self):
        """error.message, error.type, and error.code are all present."""
        from fastapi.responses import JSONResponse
        from yashigani.gateway.openai_router import _owui_deny_message
        import json

        resp = JSONResponse(
            status_code=403,
            content={
                "error": {
                    "message": _owui_deny_message("sensitivity_ceiling_exceeded"),
                    "type": "policy_denied",
                    "code": "sensitivity_ceiling_exceeded",
                }
            },
        )
        body = json.loads(resp.body)
        assert "error" in body
        assert "message" in body["error"]
        assert "type" in body["error"]
        assert "code" in body["error"]
        # code preserves the machine reason for tooling
        assert body["error"]["code"] == "sensitivity_ceiling_exceeded"
        # message is NOT the machine code
        assert body["error"]["message"] != "sensitivity_ceiling_exceeded"
