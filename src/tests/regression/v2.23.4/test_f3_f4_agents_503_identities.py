"""
Regression tests for v2.23.4 F3 and F4 bugs.

F3 — /admin/agents returns HTTP 503 on K8s.
     Root cause: RBAC+AgentRegistry Redis init fails on DNS-not-ready-at-startup
     race (K8s headless Service DNS propagation lag). Single-attempt init left
     agent_registry=None for the pod lifetime → every /admin/agents → 503.
     Fix: retry-with-backoff (5 attempts, 1/2/4/8/16 s) in entrypoint.py.

F4 — alice doesn't appear in /admin/identities after login despite da6de8b.
     Root cause: GET /admin/agents lists AgentRegistry (service/machine agents),
     not IdentityRegistry HUMAN entries. da6de8b correctly writes to
     IdentityRegistry on login, but there was no /admin/identities route to
     surface those entries. Fix: add GET /admin/identities.

Last updated: 2026-05-17T00:00:00+01:00 (v2.23.4)
"""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# F3 — _get_registry() raises 503 when agent_registry is None
# ---------------------------------------------------------------------------


def test_get_registry_raises_503_when_agent_registry_none():
    """
    _get_registry() must return HTTP 503 when backoffice_state.agent_registry
    is None (Redis unavailable at startup — the F3 root-cause shape).

    Regression: before the retry fix, a DNS-not-ready-at-startup failure left
    agent_registry=None permanently, causing every list_agents call to return
    503 for the pod's entire lifetime.
    """
    from fastapi import HTTPException
    from yashigani.backoffice.routes.agents import _get_registry

    with patch("yashigani.backoffice.routes.agents.backoffice_state") as mock_state:
        mock_state.agent_registry = None
        with pytest.raises(HTTPException) as exc_info:
            _get_registry()
        assert exc_info.value.status_code == 503


def test_get_registry_returns_registry_when_initialised():
    """
    _get_registry() must return the registry object when it is properly
    initialised (normal case — Redis was reachable within the retry window).
    """
    from yashigani.backoffice.routes.agents import _get_registry

    mock_registry = MagicMock()
    with patch("yashigani.backoffice.routes.agents.backoffice_state") as mock_state:
        mock_state.agent_registry = mock_registry
        result = _get_registry()
        assert result is mock_registry


# ---------------------------------------------------------------------------
# F3 — entrypoint retry loop structure (static analysis)
# ---------------------------------------------------------------------------


def test_entrypoint_rbac_retry_loop_exists():
    """
    The RBAC+AgentRegistry init block in entrypoint.py must use a retry loop,
    not a single-attempt try/except.

    Static file check: assert the retry constants and loop structure are present
    in the source file WITHOUT importing the module (importing entrypoint triggers
    _bootstrap() at module level which tries to write to /run/secrets).

    A single-attempt pattern means any transient DNS failure at pod startup
    permanently disables /admin/agents (F3 root-cause class).
    """
    from pathlib import Path

    entrypoint_path = (
        Path(__file__).parent.parent.parent.parent
        / "yashigani" / "backoffice" / "entrypoint.py"
    )
    assert entrypoint_path.exists(), f"entrypoint.py not found: {entrypoint_path}"

    src = entrypoint_path.read_text(encoding="utf-8")
    assert "_RBAC_MAX_ATTEMPTS" in src, (
        "entrypoint.py missing _RBAC_MAX_ATTEMPTS — RBAC init retry loop absent. "
        "F3 root-cause class: single-attempt init leaves agent_registry=None on "
        "K8s DNS startup race."
    )
    assert "_rbac_backoff" in src, (
        "entrypoint.py missing _rbac_backoff — exponential backoff absent from "
        "RBAC+AgentRegistry init. F3 fix requires backoff between retry attempts."
    )


# ---------------------------------------------------------------------------
# F4 — GET /admin/identities route exists and returns IdentityResponse list
# ---------------------------------------------------------------------------


def test_list_identities_route_registered():
    """
    GET /admin/identities must be a registered route in the agents router.

    Regression: before F4 fix, GET /admin/identities returned 404 (route not
    found). The da6de8b commit writes HUMAN identities to IdentityRegistry on
    login, but no route existed to list them.
    """
    from yashigani.backoffice.routes.agents import router

    routes = [r.path for r in router.routes if hasattr(r, "path")]
    assert "/admin/identities" in routes, (
        "GET /admin/identities not registered in agents router. "
        "F4 fix: add the route to surface IdentityRegistry HUMAN entries "
        "for local-auth users who have logged in at least once (da6de8b)."
    )


def test_get_identity_registry_raises_503_when_none():
    """
    _get_identity_registry() must return 503 when identity_registry is None
    (community-tier or Redis unavailable).
    """
    from fastapi import HTTPException
    from yashigani.backoffice.routes.agents import _get_identity_registry

    with patch("yashigani.backoffice.routes.agents.backoffice_state") as mock_state:
        mock_state.identity_registry = None
        # Also must not have identity_registry as an attribute
        del mock_state.identity_registry
        with pytest.raises(HTTPException) as exc_info:
            _get_identity_registry()
        assert exc_info.value.status_code == 503


def test_identity_response_model_has_required_fields():
    """
    IdentityResponse must include identity_id, kind, name, slug, status, created_at.
    These are the minimum fields the admin panel needs to show a HUMAN identity entry.
    """
    from yashigani.backoffice.routes.agents import IdentityResponse

    fields = set(IdentityResponse.model_fields.keys())
    required = {"identity_id", "kind", "name", "slug", "status", "created_at"}
    missing = required - fields
    assert not missing, (
        f"IdentityResponse missing required fields: {missing}. "
        "These fields are needed to display HUMAN identities in the admin panel."
    )


def test_list_identities_kind_filter_rejects_invalid_kind():
    """
    GET /admin/identities?kind=garbage must return 422.
    """
    import asyncio
    from fastapi import HTTPException
    from yashigani.backoffice.routes.agents import list_identities

    mock_registry = MagicMock()
    mock_session = MagicMock()

    with patch("yashigani.backoffice.routes.agents.backoffice_state") as mock_state:
        mock_state.identity_registry = mock_registry
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(list_identities(session=mock_session, kind="garbage"))
        assert exc_info.value.status_code == 422


def test_list_identities_returns_empty_list_when_no_identities():
    """
    GET /admin/identities must return [] (not 500) when IdentityRegistry is
    initialised but empty.
    """
    import asyncio
    from yashigani.backoffice.routes.agents import list_identities

    mock_registry = MagicMock()
    mock_registry.list_all.return_value = []
    mock_session = MagicMock()

    with patch("yashigani.backoffice.routes.agents.backoffice_state") as mock_state:
        mock_state.identity_registry = mock_registry
        result = asyncio.run(list_identities(session=mock_session, kind=None))
        assert result == []
        mock_registry.list_all.assert_called_once_with(kind=None)


def test_list_identities_maps_human_entry():
    """
    GET /admin/identities must correctly map an IdentityRegistry HUMAN entry
    to an IdentityResponse object.
    """
    import asyncio
    from yashigani.backoffice.routes.agents import list_identities, IdentityResponse

    human_entry = {
        "identity_id": "ident_abc123",
        "kind": "human",
        "name": "alice@agnosticsec.com",
        "slug": "alice-agnosticsec-com",
        "description": "local-auth user; account_id=acct_xyz",
        "status": "active",
        "created_at": "2026-05-17T00:00:00Z",
        "last_seen_at": "2026-05-17T00:01:00Z",
    }

    mock_registry = MagicMock()
    mock_registry.list_all.return_value = [human_entry]
    mock_session = MagicMock()

    with patch("yashigani.backoffice.routes.agents.backoffice_state") as mock_state:
        mock_state.identity_registry = mock_registry
        result = asyncio.run(list_identities(session=mock_session, kind="human"))

    assert len(result) == 1
    resp = result[0]
    assert isinstance(resp, IdentityResponse)
    assert resp.identity_id == "ident_abc123"
    assert resp.kind == "human"
    assert resp.name == "alice@agnosticsec.com"
    assert resp.slug == "alice-agnosticsec-com"
    assert resp.status == "active"
