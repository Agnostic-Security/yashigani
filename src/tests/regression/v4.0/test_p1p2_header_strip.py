"""
Regression test — P1/P2 header stripping (RISK-108 / FIND-3.1-AGENT-BEARER-IMPERSONATION).

Proves:
1. A P1 agent bearer cannot set X-Yashigani-Orchestration-Principal to impersonate a user.
2. A P1 agent bearer cannot set X-OpenWebUI-User-Email to impersonate a user.
3. An AGENT_HEADER_STRIPPED audit event is emitted when a P1 caller presents P2 headers.
4. The P2 orchestrator path (brain/self-call) is preserved — orchestration-principal
   is honoured only for the p2_orchestrator role.
5. The P2 forwarder path (OWUI) honours X-OpenWebUI-User-Email only for p2_forwarder.

Reference: nhi-p1p2-langflow-spec.md §B.1-B.4 / RECONCILIATION R2/R9
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_request(headers: dict):
    """Build a minimal FastAPI-style Request mock."""
    req = MagicMock()
    lower_headers = {k.lower(): v for k, v in headers.items()}
    req.headers.get = lambda key, default="": lower_headers.get(key.lower(), default)
    return req


class _RecordingAuditWriter:
    """Captures audit events for assertion."""

    def __init__(self):
        self.events: list = []

    def write(self, event) -> None:
        self.events.append(event)


# ---------------------------------------------------------------------------
# Tests for _resolve_caller_role + _emit_agent_header_stripped
# ---------------------------------------------------------------------------

def test_p1_agent_cannot_impersonate_via_orchestration_principal(monkeypatch) -> None:
    """A p1_agent token sets X-Yashigani-Orchestration-Principal.
    The header must be STRIPPED and AGENT_HEADER_STRIPPED event emitted.
    The resolved identity is the AGENT's own identity, not the claimed principal.
    """
    import yashigani.gateway.openai_router as router_mod

    # Set up token_role_map with a p1_agent entry
    p1_token = "deadbeef" * 8  # 64-char hex
    monkeypatch.setattr(router_mod._state, "token_role_map", {
        p1_token: ("p1_agent", "agent__letta"),
    })

    # Patch audit_writer to capture events
    audit = _RecordingAuditWriter()
    monkeypatch.setattr(router_mod._state, "audit_writer", audit)
    monkeypatch.setattr(router_mod._state, "agent_registry", None)
    monkeypatch.setattr(router_mod._state, "identity_registry", None)

    req = _make_request({
        "Authorization": f"Bearer {p1_token}",
        "X-Yashigani-Orchestration-Principal": "admin_user",  # P2 header — must be stripped
    })

    result = router_mod._resolve_identity(req)

    # Identity must be the agent's own identity (p1_agent fallback without registry)
    assert result is not None
    assert result["identity_id"] == "agent__letta", (
        f"P1 agent impersonation regression: identity should be 'agent__letta', got {result['identity_id']!r}"
    )
    assert result.get("kind") == "agent"

    # AGENT_HEADER_STRIPPED event must have been emitted
    stripped_events = [
        e for e in audit.events
        if hasattr(e, "event_type") and e.event_type == "AGENT_HEADER_STRIPPED"
    ]
    assert len(stripped_events) >= 1, (
        "RISK-108 regression: AGENT_HEADER_STRIPPED must be emitted when a P1 agent "
        "presents X-Yashigani-Orchestration-Principal"
    )
    ev = stripped_events[0]
    assert "orchestration-principal" in ev.stripped_header.lower()
    assert ev.caller_token_role == "p1_agent"
    assert ev.agent_identity_id == "agent__letta"
    assert ev.severity == "HIGH"


def test_p1_agent_cannot_impersonate_via_owui_email(monkeypatch) -> None:
    """A p1_agent token sets X-OpenWebUI-User-Email.
    The header must be stripped; identity stays as the agent's own.
    """
    import yashigani.gateway.openai_router as router_mod

    p1_token = "cafecafe" * 8
    monkeypatch.setattr(router_mod._state, "token_role_map", {
        p1_token: ("p1_agent", "agent__openclaw"),
    })

    audit = _RecordingAuditWriter()
    monkeypatch.setattr(router_mod._state, "audit_writer", audit)
    monkeypatch.setattr(router_mod._state, "agent_registry", None)
    monkeypatch.setattr(router_mod._state, "identity_registry", None)

    req = _make_request({
        "Authorization": f"Bearer {p1_token}",
        "X-OpenWebUI-User-Email": "victim@corp.example",  # P2 header — must be stripped
    })

    result = router_mod._resolve_identity(req)

    assert result is not None
    assert result["identity_id"] == "agent__openclaw", (
        f"P1 agent impersonation: expected agent__openclaw, got {result['identity_id']!r}"
    )

    stripped_events = [
        e for e in audit.events
        if hasattr(e, "event_type") and e.event_type == "AGENT_HEADER_STRIPPED"
    ]
    assert len(stripped_events) >= 1, (
        "RISK-108 regression: AGENT_HEADER_STRIPPED must be emitted for X-OpenWebUI-User-Email"
    )
    ev = stripped_events[0]
    assert "email" in ev.stripped_header.lower()
    assert ev.caller_token_role == "p1_agent"


def test_p2_orchestrator_honours_orch_principal(monkeypatch) -> None:
    """A p2_orchestrator token with X-Yashigani-Orchestration-Principal must
    resolve the named principal (brain/self-call path preserved).
    """
    import yashigani.gateway.openai_router as router_mod

    orch_token = "aabb1122" * 8
    monkeypatch.setattr(router_mod._state, "token_role_map", {
        orch_token: ("p2_orchestrator", "internal"),
    })

    # Mock identity_registry to return a known user
    mock_registry = MagicMock()
    mock_registry.get_by_slug.return_value = {
        "identity_id": "alice",
        "status": "active",
        "groups": ["users"],
        "sensitivity_ceiling": "CONFIDENTIAL",
    }
    monkeypatch.setattr(router_mod._state, "identity_registry", mock_registry)
    monkeypatch.setattr(router_mod._state, "audit_writer", None)

    req = _make_request({
        "Authorization": f"Bearer {orch_token}",
        "X-Yashigani-Orchestration-Principal": "alice",  # P2 path — must be honoured
    })

    result = router_mod._resolve_identity(req)

    assert result is not None, "p2_orchestrator must resolve the orch-principal"
    assert result["identity_id"] == "alice", (
        f"Brain/self-call path broken: expected alice, got {result['identity_id']!r}"
    )
    assert result.get("_orchestration_self_call") is True


def test_p2_forwarder_honours_owui_email(monkeypatch) -> None:
    """A p2_forwarder token with X-OpenWebUI-User-Email must resolve the
    forwarded user (OWUI trusted-forwarder path preserved).
    """
    import yashigani.gateway.openai_router as router_mod

    forwarder_token = "11223344" * 8
    monkeypatch.setattr(router_mod._state, "token_role_map", {
        forwarder_token: ("p2_forwarder", "owui"),
    })

    mock_registry = MagicMock()
    mock_registry.get_by_slug.return_value = {
        "identity_id": "bob",
        "status": "active",
        "groups": [],
        "sensitivity_ceiling": "INTERNAL",
        "allowed_models": [],
    }
    monkeypatch.setattr(router_mod._state, "identity_registry", mock_registry)
    monkeypatch.setattr(router_mod._state, "audit_writer", None)

    # Patch _resolve_owui_forwarded_user to return the mocked identity
    forwarder_identity = {
        "identity_id": "bob",
        "status": "active",
        "groups": [],
        "sensitivity_ceiling": "INTERNAL",
        "allowed_models": [],
    }
    with patch.object(router_mod, "_resolve_owui_forwarded_user", return_value=forwarder_identity):
        req = _make_request({
            "Authorization": f"Bearer {forwarder_token}",
            "X-OpenWebUI-User-Email": "bob@corp.example",
        })
        result = router_mod._resolve_identity(req)

    assert result is not None
    assert result["identity_id"] == "bob", (
        f"OWUI forwarder path broken: expected bob, got {result['identity_id']!r}"
    )


def test_no_role_map_falls_through_to_internal_bearer(monkeypatch) -> None:
    """When token_role_map is empty, falls through to the shared _INTERNAL_BEARER
    path (backward compat for 3.x deployments).
    """
    import yashigani.gateway.openai_router as router_mod

    # Empty role map → no p1/p2 resolution
    monkeypatch.setattr(router_mod._state, "token_role_map", {})
    monkeypatch.setattr(router_mod._state, "identity_registry", None)
    monkeypatch.setattr(router_mod._state, "audit_writer", None)

    # Use the actual _INTERNAL_BEARER value
    internal_bearer = router_mod._INTERNAL_BEARER

    req = _make_request({
        "Authorization": f"Bearer {internal_bearer}",
    })

    result = router_mod._resolve_identity(req)
    assert result is not None
    assert result["identity_id"] == "internal", (
        "Backward compat broken: shared _INTERNAL_BEARER must still resolve as 'internal'"
    )
