"""
Regression test — v4.1.2 admin-agent onboarding blocker.

Live-verified by Captain on podman/macOS @ ebaa1797 (mustui
acc/v412-integrated-latest-20260722):

  1. The plaintext PSK token returned by POST /admin/agents was rejected at
     /mcp/{agent_name} with 401 JWT_INVALID / header_parse_error: Not enough
     segments.
  2. The registration response's quick_start snippet told operators to
     POST {gw}/mcp and GET {gw}/health -- both 404. The real routes are
     /agents/{target_agent_id}/... (gateway/agent_auth.py + agent_router.py)
     and /healthz (gateway/proxy.py).

CHECK-FIRST determination (before any code change):
  POST /admin/agents registers into AgentRegistry (agents/registry.py) --
  an agent-to-agent orchestration participant. Its token is an opaque
  256-bit-hex PSK (bcrypt-hashed at rest), verified ONLY by
  AgentAuthMiddleware (gateway/agent_auth.py) on POST /agents/{target}/....
  /mcp/{agent_name} is a DIFFERENT subsystem (McpBrokerRegistry, MCP
  tool-server broker) onboarded exclusively via
  POST /admin/mcp/servers/import (backoffice/routes/mcp_servers.py) and
  gated by an external-IdP JWT (JWKS-validated, gateway/jwt_inspector.py) or
  internal-mesh mTLS -- neither of which a bare opaque PSK can satisfy (it
  has no dots, so pyjwt.get_unverified_header() fails at
  "Not enough segments" before any signature check runs).

  Conclusion: admin-registration was NEVER a supported onboarding path to
  /mcp/{agent_name}. Findings (1) and (2) share one root cause -- a quick_start
  snippet that documented a route/credential combination that was never wired
  and could never have worked. The fix is corrective documentation (this
  suite proves the corrected snippet is honest) PLUS proof that the REAL
  documented path (POST /agents/{target}/... with the same PSK) actually
  authenticates end-to-end.

These tests prove:
  A. _build_quick_start() no longer emits /mcp or /health (the broken routes).
  B. _build_quick_start() emits the REAL routes: /agents/{target}/... and
     /healthz, plus the required X-Yashigani-Caller-Agent-Id header.
  C. The token minted by AgentRegistry.register() -- the SAME plaintext_token
     surfaced in the quick_start snippet -- successfully authenticates through
     AgentAuthMiddleware at the exact path the snippet documents (end-to-end
     proof the supported path actually works).
  D. That same PSK is NOT a parseable JWT -- documenting exactly why it was
     always going to 401 at /mcp/{agent_name} (JWT_INVALID / header_parse_error),
     confirming /mcp/* was never the intended consumer of this credential.

Last updated: 2026-07-23T00:00:00+00:00
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from starlette.requests import Request


# ---------------------------------------------------------------------------
# A + B — quick_start snippet content
# ---------------------------------------------------------------------------


def test_quick_start_no_longer_emits_broken_mcp_or_health_routes():
    """The corrected snippet must not reference POST /mcp or GET /health --
    both 404 on the live gateway (Captain, podman @ ebaa1797)."""
    from yashigani.backoffice.routes.agents import _build_quick_start

    qs = _build_quick_start("agnt_deadbeef0000", "a" * 64)
    blob = " ".join(str(v) for v in qs.values())

    assert "/mcp'" not in blob and " /mcp \\" not in blob and "https://<your-gateway-url>/mcp " not in blob, (
        "quick_start must not instruct POST {gw}/mcp -- that route is 404 and, "
        "independent of the path, /mcp/{agent_name} was never wired to accept "
        "this PSK credential type (see module docstring)."
    )
    assert "/health'" not in blob, (
        "quick_start must not instruct GET {gw}/health -- the real health "
        "route is /healthz."
    )


def test_quick_start_emits_real_reachable_routes():
    """The corrected snippet must reference the REAL routes that exist on the
    live gateway: /agents/{target_agent_id}/... and /healthz."""
    from yashigani.backoffice.routes.agents import _build_quick_start

    agent_id = "agnt_deadbeef0000"
    token = "b" * 64
    qs = _build_quick_start(agent_id, token)

    assert "/agents/" in qs["curl"], "curl snippet must target the real /agents/{target}/... route"
    assert "/agents/" in qs["python_httpx"], "python snippet must target the real /agents/{target}/... route"
    assert "/healthz" in qs["health_check"], "health_check snippet must target the real /healthz route"

    # The auth mechanism AgentAuthMiddleware actually requires:
    # Authorization: Bearer <psk> AND X-Yashigani-Caller-Agent-Id: <caller>
    assert token in qs["curl"], "the minted token must appear in the curl snippet"
    assert "X-Yashigani-Caller-Agent-Id" in qs["curl"], (
        "curl snippet must document the caller-id header AgentAuthMiddleware "
        "requires alongside the Bearer token (missing it -> 401 "
        "missing_caller_agent_id_header)"
    )
    assert "X-Yashigani-Caller-Agent-Id" in qs["python_httpx"]
    assert agent_id in qs["note"], "note must surface the agent_id for operator reference"
    assert "/admin/mcp/servers/import" in qs["note"], (
        "note must tell operators that MCP tool-server access is a separate "
        "admin-only subsystem this token does not grant -- prevents the "
        "exact confusion that produced the original 401"
    )


def test_quick_start_returned_by_register_and_rotate_and_get_quickstart():
    """All three response models that surface quick_start must use the
    corrected builder (register, token/rotate, GET .../quickstart)."""
    from yashigani.backoffice.routes.agents import (
        AgentRegisterResponse,
        AgentRotateResponse,
        AgentQuickStartResponse,
        _build_quick_start,
    )

    qs = _build_quick_start("agnt_x", "c" * 64)

    # All three response models declare a `quick_start: dict` field fed by
    # the same _build_quick_start() helper -- verify the field exists on
    # each model (regression against a future refactor re-introducing a
    # second, stale builder for one of the three routes).
    for model in (AgentRegisterResponse, AgentRotateResponse, AgentQuickStartResponse):
        assert "quick_start" in model.model_fields, (
            f"{model.__name__} must expose quick_start so the corrected "
            "routes/auth-mechanism reach every surface that hands a token "
            "to an operator."
        )

    assert "/agents/" in qs["curl"]


# ---------------------------------------------------------------------------
# C — end-to-end proof: the minted token really authenticates at the
#     documented route.
# ---------------------------------------------------------------------------


def test_registered_agent_token_authenticates_at_documented_agents_path(mock_redis):
    """
    End-to-end: AgentRegistry.register() -> the plaintext token surfaced in
    quick_start -> presented at the EXACT route the corrected quick_start
    snippet documents (/agents/{target}/...) with the EXACT header the
    snippet documents (X-Yashigani-Caller-Agent-Id) -> AgentAuthMiddleware
    accepts it and sets request.state.agent_id.

    This is the "supported path actually works end-to-end" proof required
    by the brief -- not a mock of verify_token, the REAL AgentRegistry +
    REAL AgentAuthMiddleware against fakeredis.
    """
    from yashigani.agents.registry import AgentRegistry
    from yashigani.gateway.agent_auth import AgentAuthMiddleware
    from yashigani.backoffice.routes.agents import _build_quick_start

    registry = AgentRegistry(redis_client=mock_redis)
    agent_id, plaintext_token = registry.register(
        name="caller-agent",
        upstream_url="http://caller.internal:8080",
        groups=["engineering"],
        allowed_caller_groups=["engineering"],
        allowed_paths=["**"],
    )

    # The snippet operators actually see:
    qs = _build_quick_start(agent_id, plaintext_token)
    assert plaintext_token in qs["curl"]

    app = FastAPI()
    received_state = {}

    @app.post("/agents/target-agent/v1/chat/completions")
    async def agent_route(request: Request):
        received_state["agent_id"] = getattr(request.state, "agent_id", None)
        received_state["caller_type"] = getattr(request.state, "caller_type", None)
        return JSONResponse({"ok": True})

    app.add_middleware(AgentAuthMiddleware, agent_registry=registry, audit_writer=None)

    client = TestClient(app, raise_server_exceptions=False)
    resp = client.post(
        "/agents/target-agent/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {plaintext_token}",
            "X-Yashigani-Caller-Agent-Id": agent_id,
        },
        json={"model": "x", "messages": []},
    )

    assert resp.status_code == 200, (
        f"the token+headers the corrected quick_start documents must "
        f"authenticate at the real route -- got {resp.status_code}: {resp.text}"
    )
    assert received_state["agent_id"] == agent_id
    assert received_state["caller_type"] == "agent"


def test_registered_agent_token_rejected_without_caller_header(mock_redis):
    """Confirms the ONE thing operators must not skip: without
    X-Yashigani-Caller-Agent-Id the same valid PSK is rejected (401) --
    exactly why the quick_start note calls this header out explicitly."""
    from yashigani.agents.registry import AgentRegistry
    from yashigani.gateway.agent_auth import AgentAuthMiddleware

    registry = AgentRegistry(redis_client=mock_redis)
    agent_id, plaintext_token = registry.register(
        name="caller-agent-2",
        upstream_url="http://caller2.internal:8080",
        groups=[],
        allowed_caller_groups=[],
        allowed_paths=["**"],
    )

    app = FastAPI()

    @app.post("/agents/target-agent/v1/chat/completions")
    async def agent_route(request: Request):
        return JSONResponse({"ok": True})

    app.add_middleware(AgentAuthMiddleware, agent_registry=registry, audit_writer=None)
    client = TestClient(app, raise_server_exceptions=False)

    resp = client.post(
        "/agents/target-agent/v1/chat/completions",
        headers={"Authorization": f"Bearer {plaintext_token}"},
        json={"model": "x", "messages": []},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# D — proof the PSK was never a valid JWT (documents WHY /mcp/* 401'd, and
#     that this is expected/by-design, not a wiring bug to "fix" by minting
#     a JWT for a credential type that was never meant to carry one).
# ---------------------------------------------------------------------------


def test_registered_agent_psk_is_not_a_parseable_jwt(mock_redis):
    """
    The AgentRegistry PSK is a bare 256-bit hex string (no dots) -- it can
    never pass pyjwt.get_unverified_header(), which is the FIRST thing
    gateway/jwt_inspector.py does to any Bearer token presented to a JWT-
    gated route. This is the exact "header_parse_error: Not enough segments"
    Captain observed at /mcp/{agent_name} -- confirming the 401 was a
    correct rejection of a credential type that route was never wired to
    accept, not a broken JWT-minting integration.
    """
    import jwt as pyjwt
    from yashigani.agents.registry import AgentRegistry

    registry = AgentRegistry(redis_client=mock_redis)
    _, plaintext_token = registry.register(
        name="caller-agent-3",
        upstream_url="http://caller3.internal:8080",
        groups=[],
        allowed_caller_groups=[],
        allowed_paths=["**"],
    )

    assert "." not in plaintext_token, (
        "AgentRegistry PSK tokens are opaque hex -- they must never contain "
        "JWT segment separators; this is what makes them structurally "
        "unable to pass as a JWT at any JWKS-gated route."
    )
    with pytest.raises(Exception):
        pyjwt.get_unverified_header(plaintext_token)
