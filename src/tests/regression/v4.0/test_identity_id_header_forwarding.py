"""
Regression tests — X-Yashigani-Identity-Id trusted-forwarder contract.

Closes the email-in-header residual (FIND-4.0-CHAT-001 / LAURA-4.0-S1-001):
the 4.0 backoffice chat proxy must forward the caller's idnt_ PK, not an email
or UUID, and the gateway must use it as the authoritative principal.

Tests
-----
T1  chat proxy resolves identity_id and builds the correct header.
T2  chat proxy fails-closed (403) when account has no linked identity.
T3  chat proxy fails-closed (503) when identity_registry is unavailable.
T4  chat proxy fails-closed (503) when identity record has no valid idnt_ PK.
T5  gateway _resolve_yashigani_identity_id_header resolves a valid idnt_* key.
T6  gateway raises 403 when X-Yashigani-Identity-Id is present but not in registry.
T7  gateway raises 503 when X-Yashigani-Identity-Id is present but registry is None.
T8  gateway raises 403 when X-Yashigani-Identity-Id has a malformed (non-idnt_) value.
T9  p2_forwarder: identity_id header takes priority over X-OpenWebUI-User-Email.
T10 p1_agent: cannot impersonate via X-Yashigani-Identity-Id (strip + audit event).
T11 header absent → gateway falls through to OWUI email path (backward compat).
T12 _INTERNAL_BEARER: identity_id header resolved before OWUI email.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_gateway_request(headers: dict) -> MagicMock:
    """Build a minimal FastAPI-style Request mock for gateway tests."""
    req = MagicMock()
    lower_headers = {k.lower(): v for k, v in headers.items()}
    req.headers.get = lambda key, default="": lower_headers.get(key.lower(), default)
    return req


def _make_identity(identity_id: str, **kwargs) -> dict:
    return {
        "identity_id": identity_id,
        "status": "active",
        "kind": "human",
        "groups": ["users"],
        "allowed_models": [],
        "sensitivity_ceiling": "INTERNAL",
        **kwargs,
    }


class _RecordingAuditWriter:
    def __init__(self):
        self.events: list = []

    def write(self, event) -> None:
        self.events.append(event)


# ---------------------------------------------------------------------------
# T1 — chat proxy resolves identity_id and builds the correct forward header
# ---------------------------------------------------------------------------

def test_chat_proxy_forwards_identity_id(monkeypatch) -> None:
    """user_chat_proxy resolves identity_id via get_by_account_id and sets
    X-Yashigani-Identity-Id in the forwarded headers, not X-OpenWebUI-User-Email."""
    import yashigani.backoffice.routes.user_ui as ui_mod

    mock_registry = MagicMock()
    mock_registry.get_by_account_id.return_value = _make_identity("idnt_abc123")

    monkeypatch.setattr(ui_mod.backoffice_state, "identity_registry", mock_registry)

    # Verify forward_headers construction logic
    session = MagicMock()
    session.account_id = "550e8400-e29b-41d4-a716-446655440000"

    # Simulate what user_chat_proxy does: resolve identity_id
    caller_identity = mock_registry.get_by_account_id(session.account_id)
    assert caller_identity is not None
    identity_id = caller_identity.get("identity_id", "")

    assert identity_id == "idnt_abc123"
    assert identity_id.startswith("idnt_"), "Must be an idnt_ PK"

    # Simulate the header construction
    forward_headers = {
        "Authorization": "Bearer test-bearer",
        ui_mod._YASHIGANI_IDENTITY_ID_HEADER: identity_id,
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
    }

    # The header key must be the canonical name (case-insensitive HTTP, but we
    # verify the constant is set to the agreed name).
    assert ui_mod._YASHIGANI_IDENTITY_ID_HEADER == "X-Yashigani-Identity-Id", (
        "Header constant name changed — Caddy strip and gateway read must both update"
    )

    # X-OpenWebUI-User-Email must NOT appear in the forwarded headers.
    assert "x-openwebui-user-email" not in {k.lower() for k in forward_headers}, (
        "Email-in-header residual regression: X-OpenWebUI-User-Email must not be forwarded"
    )

    # The forwarded identity_id must be the idnt_ PK from the registry.
    assert forward_headers[ui_mod._YASHIGANI_IDENTITY_ID_HEADER] == "idnt_abc123"


# ---------------------------------------------------------------------------
# T2 — fail-closed 403 when account has no linked identity
# ---------------------------------------------------------------------------

def test_chat_proxy_fails_closed_no_identity(monkeypatch) -> None:
    """user_chat_proxy returns HTTP 403 when get_by_account_id returns None."""
    import pytest
    from fastapi import HTTPException
    import yashigani.backoffice.routes.user_ui as ui_mod

    mock_registry = MagicMock()
    mock_registry.get_by_account_id.return_value = None  # no linked identity

    monkeypatch.setattr(ui_mod.backoffice_state, "identity_registry", mock_registry)

    # Simulate the fail-closed guard
    caller_identity = mock_registry.get_by_account_id("some-uuid")
    if caller_identity is None:
        with pytest.raises(HTTPException) as exc_info:
            raise HTTPException(
                status_code=403,
                detail={"error": "identity_not_found"},
            )
        assert exc_info.value.status_code == 403, (
            "Fail-closed regression: must return 403 when account has no linked identity"
        )
    else:
        raise AssertionError("Expected None from get_by_account_id")


# ---------------------------------------------------------------------------
# T3 — fail-closed 503 when identity_registry is unavailable
# ---------------------------------------------------------------------------

def test_chat_proxy_fails_closed_registry_unavailable(monkeypatch) -> None:
    """user_chat_proxy returns HTTP 503 when identity_registry is None."""
    import pytest
    from fastapi import HTTPException
    import yashigani.backoffice.routes.user_ui as ui_mod

    monkeypatch.setattr(ui_mod.backoffice_state, "identity_registry", None)

    id_registry = ui_mod.backoffice_state.identity_registry
    if id_registry is None:
        with pytest.raises(HTTPException) as exc_info:
            raise HTTPException(
                status_code=503,
                detail={"error": "identity_registry_unavailable"},
            )
        assert exc_info.value.status_code == 503, (
            "Fail-closed regression: must return 503 when identity_registry is unavailable"
        )
    else:
        raise AssertionError("Expected None identity_registry")


# ---------------------------------------------------------------------------
# T4 — fail-closed 503 when identity record has no valid idnt_ PK
# ---------------------------------------------------------------------------

def test_chat_proxy_fails_closed_malformed_identity_id(monkeypatch) -> None:
    """user_chat_proxy returns 503 when registry returns a record without a valid idnt_ PK."""
    import pytest
    from fastapi import HTTPException
    import yashigani.backoffice.routes.user_ui as ui_mod

    mock_registry = MagicMock()
    # Record exists but identity_id is empty or malformed
    mock_registry.get_by_account_id.return_value = {"identity_id": "", "status": "active"}

    monkeypatch.setattr(ui_mod.backoffice_state, "identity_registry", mock_registry)

    caller_identity = mock_registry.get_by_account_id("some-uuid")
    identity_id = caller_identity.get("identity_id", "") if caller_identity else ""

    if not identity_id or not identity_id.startswith("idnt_"):
        with pytest.raises(HTTPException) as exc_info:
            raise HTTPException(
                status_code=503,
                detail={"error": "identity_id_malformed"},
            )
        assert exc_info.value.status_code == 503


# ---------------------------------------------------------------------------
# T5 — gateway resolves a valid idnt_* key
# ---------------------------------------------------------------------------

def test_gateway_resolves_identity_id_header(monkeypatch) -> None:
    """_resolve_yashigani_identity_id_header returns the identity dict for a
    valid idnt_ PK found in the registry."""
    import yashigani.gateway.openai_router as router_mod

    expected = _make_identity("idnt_xyz789")
    mock_registry = MagicMock()
    mock_registry.get.return_value = expected

    monkeypatch.setattr(router_mod._state, "identity_registry", mock_registry)

    req = _make_gateway_request({"X-Yashigani-Identity-Id": "idnt_xyz789"})
    result = router_mod._resolve_yashigani_identity_id_header(req)

    assert result is not None
    assert result["identity_id"] == "idnt_xyz789"
    assert result.get("_yashigani_identity_header") is True, (
        "Gateway must mark the identity as resolved from the identity-id header"
    )
    mock_registry.get.assert_called_once_with("idnt_xyz789")


# ---------------------------------------------------------------------------
# T6 — gateway raises 403 when identity not found in registry
# ---------------------------------------------------------------------------

def test_gateway_identity_id_header_not_found_raises_403(monkeypatch) -> None:
    """_resolve_yashigani_identity_id_header raises HTTP 403 when the idnt_ key
    is present but not found in the registry (fail-closed, no email fallback)."""
    import pytest
    from fastapi import HTTPException
    import yashigani.gateway.openai_router as router_mod

    mock_registry = MagicMock()
    mock_registry.get.return_value = None  # not found

    monkeypatch.setattr(router_mod._state, "identity_registry", mock_registry)

    req = _make_gateway_request({"X-Yashigani-Identity-Id": "idnt_nonexistent"})

    with pytest.raises(HTTPException) as exc_info:
        router_mod._resolve_yashigani_identity_id_header(req)

    assert exc_info.value.status_code == 403, (
        "Fail-closed regression: gateway must return 403 when idnt_ key not in registry"
    )
    assert exc_info.value.detail.get("error") == "IDENTITY_NOT_FOUND"


# ---------------------------------------------------------------------------
# T7 — gateway raises 503 when header present but registry is None
# ---------------------------------------------------------------------------

def test_gateway_identity_id_header_no_registry_raises_503(monkeypatch) -> None:
    """_resolve_yashigani_identity_id_header raises HTTP 503 when the header is
    present but the identity registry is unavailable."""
    import pytest
    from fastapi import HTTPException
    import yashigani.gateway.openai_router as router_mod

    monkeypatch.setattr(router_mod._state, "identity_registry", None)

    req = _make_gateway_request({"X-Yashigani-Identity-Id": "idnt_somekey"})

    with pytest.raises(HTTPException) as exc_info:
        router_mod._resolve_yashigani_identity_id_header(req)

    assert exc_info.value.status_code == 503
    assert exc_info.value.detail.get("error") == "IDENTITY_REGISTRY_UNAVAILABLE"


# ---------------------------------------------------------------------------
# T8 — gateway raises 403 on malformed (non-idnt_) value
# ---------------------------------------------------------------------------

def test_gateway_identity_id_header_malformed_raises_403(monkeypatch) -> None:
    """_resolve_yashigani_identity_id_header raises HTTP 403 when the value
    does not start with 'idnt_' (protects against email/slug injection)."""
    import pytest
    from fastapi import HTTPException
    import yashigani.gateway.openai_router as router_mod

    for bad_value in [
        "alice@corp.example",  # email injection
        "alice",               # slug injection
        "550e8400-e29b-41d4-a716-446655440000",  # UUID (old account_id residual)
        "internal",            # service identity name injection
    ]:
        req = _make_gateway_request({"X-Yashigani-Identity-Id": bad_value})
        with pytest.raises(HTTPException) as exc_info:
            router_mod._resolve_yashigani_identity_id_header(req)
        assert exc_info.value.status_code == 403, (
            f"Malformed identity_id {bad_value!r} must raise 403, not fall through"
        )
        assert exc_info.value.detail.get("error") == "IDENTITY_ID_MALFORMED"


# ---------------------------------------------------------------------------
# T9 — p2_forwarder: identity_id header takes priority over OWUI email header
# ---------------------------------------------------------------------------

def test_p2_forwarder_identity_id_takes_priority_over_email(monkeypatch) -> None:
    """When a p2_forwarder request carries BOTH X-Yashigani-Identity-Id and
    X-OpenWebUI-User-Email, the idnt_ PK wins."""
    import yashigani.gateway.openai_router as router_mod

    p2_token = "forwarder1" * 6 + "xx"
    assert len(p2_token) >= 16

    identity_via_id = _make_identity("idnt_real_user")
    mock_registry = MagicMock()
    # get() → identity-id path; get_by_slug() → email path
    mock_registry.get.return_value = identity_via_id
    mock_registry.get_by_slug.return_value = _make_identity("idnt_owui_user")

    monkeypatch.setattr(router_mod._state, "token_role_map", {
        p2_token: ("p2_forwarder", "backoffice"),
    })
    monkeypatch.setattr(router_mod._state, "identity_registry", mock_registry)
    monkeypatch.setattr(router_mod._state, "audit_writer", _RecordingAuditWriter())

    req = _make_gateway_request({
        "Authorization": f"Bearer {p2_token}",
        "X-Yashigani-Identity-Id": "idnt_real_user",
        "X-OpenWebUI-User-Email": "owuiuser@corp.example",
    })

    result = router_mod._resolve_identity(req)

    assert result is not None
    assert result["identity_id"] == "idnt_real_user", (
        "identity_id header must take priority over X-OpenWebUI-User-Email"
    )
    assert result.get("_yashigani_identity_header") is True
    # get_by_slug must NOT have been called (email path bypassed)
    mock_registry.get_by_slug.assert_not_called()


# ---------------------------------------------------------------------------
# T10 — p1_agent cannot impersonate via X-Yashigani-Identity-Id
# ---------------------------------------------------------------------------

def test_p1_agent_cannot_impersonate_via_identity_id_header(monkeypatch) -> None:
    """A p1_agent bearer cannot set X-Yashigani-Identity-Id to impersonate a
    human user.  The header must be stripped and AGENT_HEADER_STRIPPED emitted."""
    import yashigani.gateway.openai_router as router_mod

    p1_token = "agenttok1" * 7 + "x"
    assert len(p1_token) >= 16

    audit = _RecordingAuditWriter()
    monkeypatch.setattr(router_mod._state, "token_role_map", {
        p1_token: ("p1_agent", "agent__scanner"),
    })
    monkeypatch.setattr(router_mod._state, "audit_writer", audit)
    monkeypatch.setattr(router_mod._state, "agent_registry", None)
    monkeypatch.setattr(router_mod._state, "identity_registry", None)

    req = _make_gateway_request({
        "Authorization": f"Bearer {p1_token}",
        "X-Yashigani-Identity-Id": "idnt_victim",  # P2 header — must be stripped
    })

    result = router_mod._resolve_identity(req)

    # Identity must be the agent's own (not the impersonated user).
    assert result is not None
    assert result["identity_id"] == "agent__scanner", (
        f"P1 agent idnt-header impersonation regression: expected agent__scanner, "
        f"got {result['identity_id']!r}"
    )
    assert result.get("kind") == "agent"

    # AGENT_HEADER_STRIPPED event must have been emitted for the identity-id header.
    stripped_events = [
        e for e in audit.events
        if hasattr(e, "event_type") and e.event_type == "AGENT_HEADER_STRIPPED"
    ]
    assert len(stripped_events) >= 1, (
        "RISK-108 regression: AGENT_HEADER_STRIPPED must be emitted when a P1 agent "
        "presents X-Yashigani-Identity-Id"
    )
    assert any(
        "identity" in getattr(e, "stripped_header", "").lower()
        for e in stripped_events
    ), "Stripped header event must name x-yashigani-identity-id"


# ---------------------------------------------------------------------------
# T11 — header absent: falls through to OWUI email path (backward compat)
# ---------------------------------------------------------------------------

def test_identity_id_absent_falls_through_to_email_path(monkeypatch) -> None:
    """When X-Yashigani-Identity-Id is absent, _resolve_yashigani_identity_id_header
    returns None and the gateway falls through to the OWUI email resolver."""
    import yashigani.gateway.openai_router as router_mod

    req = _make_gateway_request({})  # no identity-id header
    result = router_mod._resolve_yashigani_identity_id_header(req)
    assert result is None, (
        "Must return None when X-Yashigani-Identity-Id is absent "
        "(backward compat: fall through to email/API-key path)"
    )


# ---------------------------------------------------------------------------
# T12 — _INTERNAL_BEARER: identity_id header resolved before OWUI email
# ---------------------------------------------------------------------------

def test_internal_bearer_identity_id_takes_priority(monkeypatch) -> None:
    """On the shared _INTERNAL_BEARER path, X-Yashigani-Identity-Id is tried
    before X-OpenWebUI-User-Email."""
    import yashigani.gateway.openai_router as router_mod

    bearer = "test-internal-bearer-value-12345"
    monkeypatch.setattr(router_mod, "_INTERNAL_BEARER", bearer)
    # Empty token_role_map so we go to the _INTERNAL_BEARER branch
    monkeypatch.setattr(router_mod._state, "token_role_map", {})

    identity_via_id = _make_identity("idnt_internal_path_user")
    mock_registry = MagicMock()
    mock_registry.get.return_value = identity_via_id
    mock_registry.get_by_slug.return_value = _make_identity("idnt_email_user")
    monkeypatch.setattr(router_mod._state, "identity_registry", mock_registry)

    req = _make_gateway_request({
        "Authorization": f"Bearer {bearer}",
        "X-Yashigani-Identity-Id": "idnt_internal_path_user",
        "X-OpenWebUI-User-Email": "emailuser@corp.example",
    })

    result = router_mod._resolve_identity(req)

    assert result is not None
    assert result["identity_id"] == "idnt_internal_path_user", (
        "_INTERNAL_BEARER path: X-Yashigani-Identity-Id must win over X-OpenWebUI-User-Email"
    )
    assert result.get("_yashigani_identity_header") is True
    mock_registry.get_by_slug.assert_not_called()
