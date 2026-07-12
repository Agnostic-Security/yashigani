"""
Regression test — P1/P2 header stripping (RISK-108 / FIND-3.1-AGENT-BEARER-IMPERSONATION).

Proves:
1. A P1 agent bearer cannot set X-Yashigani-Orchestration-Principal to impersonate a user.
2. A P1 agent bearer cannot set X-Yashigani-Identity-Id to impersonate a user.
   (4.1 SEC-GAP-1: X-OpenWebUI-User-Email is a dead header — not read at all.)
3. An AGENT_HEADER_STRIPPED audit event is emitted when a P1 caller presents P2 headers.
4. The P2 orchestrator path (brain/self-call) is preserved — orchestration-principal
   is honoured only for the p2_orchestrator role.
5. The P2 forwarder path honours X-Yashigani-Identity-Id only for p2_forwarder.
   (4.1 SEC-GAP-1: X-OpenWebUI-User-Email path removed; idnt_ PK is the only forward.)

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


def test_p1_agent_cannot_impersonate_via_ysg_identity_id(monkeypatch) -> None:
    """4.1 SEC-GAP-1: a p1_agent token sets X-Yashigani-Identity-Id.
    The header must be STRIPPED and AGENT_HEADER_STRIPPED event emitted.
    Identity stays as the agent's own — impersonation impossible.

    Note: X-OpenWebUI-User-Email is a dead header in 4.1 (not read at any path),
    so the live P1 impersonation vector is X-Yashigani-Identity-Id.
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
        "X-Yashigani-Identity-Id": "idnt_victim0000000",  # P2 header — must be stripped
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
        "RISK-108 regression: AGENT_HEADER_STRIPPED must be emitted for X-Yashigani-Identity-Id"
    )
    ev = stripped_events[0]
    assert "yashigani-identity-id" in ev.stripped_header.lower()
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


def test_p2_forwarder_honours_ysg_identity_id(monkeypatch) -> None:
    """4.1 SEC-GAP-1: a p2_forwarder token with X-Yashigani-Identity-Id must
    resolve the forwarded user identity (trusted-forwarder path).
    X-OpenWebUI-User-Email path is removed; idnt_ PK is the only forward header.
    """
    import yashigani.gateway.openai_router as router_mod

    forwarder_token = "11223344" * 8
    monkeypatch.setattr(router_mod._state, "token_role_map", {
        forwarder_token: ("p2_forwarder", "owui"),
    })

    bob_identity = {
        "identity_id": "idnt_bob0000000000",
        "status": "active",
        "groups": [],
        "sensitivity_ceiling": "INTERNAL",
        "allowed_models": [],
    }
    mock_registry = MagicMock()
    mock_registry.get.return_value = bob_identity
    monkeypatch.setattr(router_mod._state, "identity_registry", mock_registry)
    monkeypatch.setattr(router_mod._state, "audit_writer", None)

    req = _make_request({
        "Authorization": f"Bearer {forwarder_token}",
        "X-Yashigani-Identity-Id": "idnt_bob0000000000",
    })
    result = router_mod._resolve_identity(req)

    assert result is not None
    assert result["identity_id"] == "idnt_bob0000000000", (
        f"P2 forwarder (4.1) path broken: expected idnt_bob0000000000, got {result['identity_id']!r}"
    )
    assert result.get("_yashigani_identity_header") is True, (
        "P2 forwarder must mark identity as resolved via X-Yashigani-Identity-Id"
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
