"""
Conformance group: GATEWAY-MCP.

Closes G1 (Lu audit YCS-20260723-v4.1.2-CONFORMANCE), Table 1 rows 1-12, for:
  gateway/proxy.py + gateway/openai_router.py (10 endpoints):
    GET  /healthz
    GET  /livez                                (see FINDING-GW-1 below)
    GET  /readyz                               (see FINDING-GW-1 below)
    GET  /docs
    GET  /redoc
    GET  /.well-known/yashigani-mcp-jwks.json
    GET  /mcp/health
    POST /v1/chat/completions
    POST /v1/embeddings
    GET  /v1/models
  mcp/_bridge.py (2 endpoints):
    POST /mcp
    POST /

Convention: see tests/conformance/conftest.py module docstring.

SCAFFOLD NOTE (this group's proof-of-concept, unlike the other 11
backoffice-app groups): the gateway app is built via ``gw_app_factory`` in
conftest.py, which this group's dispatch fixed — see that fixture's
docstring for the full rationale (the stub imported a module-level app
SINGLETON from ``gateway/entrypoint.py`` that cannot be rebuilt per test; the
fix calls ``create_gateway_app()`` — the real FastAPI app factory — directly,
mirroring ``bo_app_factory``'s use of ``create_backoffice_app()`` and this
exact codebase's own ``src/tests/unit/test_openapi_exposure.py::_make_gateway_client``).

SCOPE BOUNDARY: ``create_gateway_app()`` returns the bare FastAPI app.
``entrypoint._build_app()`` wraps THAT object with four more middlewares
(CaddyVerifiedMiddleware, SpiffePeerCertMiddleware, LicenseEnforcementMiddleware,
AgentAuthMiddleware) before it ever serves traffic in production. This group's
tests exercise ROUTE-LEVEL auth (Bearer/API-key resolution via
``_resolve_identity``, OPA request/response-leg checks) — the real, in-process
security boundaries these 12 endpoints declare in their own handler bodies.
The outer Caddy-secret / SPIFFE-peer-cert / license / agent-PSK middleware
chain is NOT exercised here (same scope boundary this exact codebase's own
``test_openapi_exposure.py`` already draws for the gateway app) — that chain
is proxy/transport-layer infrastructure shared with every other gateway route,
not specific to this group's 12 endpoints, and (for Spiffe in particular)
genuinely cannot be exercised positively without a real TLS client cert (see
FINDING-GW-3 below).

FINDING-GW-1 (spec-vs-impl divergence, gateway/proxy.py + auth/caddy_verified.py):
  ``/livez`` and ``/readyz`` are referenced as exempt paths in
  ``auth/caddy_verified.py:72-73`` (readyz) and ddos.py/endpoint_ratelimit.py's
  exempt-path sets, implying dedicated lightweight healthcheck handling. They
  are NOT registered FastAPI routes on the gateway app (verified via a route
  walk below) — dedicated routes exist ONLY for ``/healthz``, ``/mcp/health``,
  ``/.well-known/yashigani-mcp-jwks.json``, ``/docs``, ``/redoc`` (proxy.py:365-533).
  A request to ``/livez``/``/readyz`` therefore falls through to the catch-all
  reverse-proxy route (proxy.py:536-541) and traverses the FULL pipeline
  (DDoS → rate-limit → JWT → body-read → PII → OPA fail-closed-deny →
  upstream-forward) instead of being a cheap healthcheck — with no OPA
  reachable, this fails closed with 403, never reaching the upstream. This is
  real, verified behaviour (not a stub), asserted below.

FINDING-GW-2 (spec-vs-impl divergence, gateway/proxy.py:536-541): the
  catch-all route ``@app.api_route("/{path:path}", methods=["GET", "POST",
  "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])`` is registered AFTER every
  dedicated route but matches ALMOST every method on EVERY path. Starlette's
  router falls through a PARTIAL match (path matches, method doesn't) to a
  later FULL match — so an "undeclared method on a declared path" on THIS
  app does NOT produce a clean 405 the way conftest.py's module docstring's
  general Method-Not-Allowed convention describes for the backoffice app; it
  is silently absorbed by the catch-all and run through the full proxy
  pipeline instead. Verified below for both a GET-only route (/docs) and a
  POST-only route (/v1/chat/completions). This diverges from
  ``tests/conformance/conftest.py``'s universal MNA convention and is
  reported here rather than silently "fixed" to expect 405.

FINDING-GW-3 (mcp/_bridge.py — SPIFFE/mTLS + no app-layer auth):
  ``mcp/_bridge.py::create_bridge_app()`` implements NO application-layer
  authentication/authorization at all for POST /mcp or POST / (verified by
  reading the full 558-line module — the handler at lines 425-462 reads the
  Authorization header ONLY to relay it opaquely to the subprocess env as
  MCP_GATEWAY_JWT; it never validates it). Lu's matrix row 11 attributes
  Laura's "default-deny 403 unauth / verb-tamper->403 / header-spoof->403"
  PoC result to this module, but that boundary is enforced OUTSIDE this
  Python process — by the mesh/Caddy mTLS+SPIFFE front that sits in front of
  each per-instance MCP bridge container in the real deployment topology
  (the bridge trusts its network position; confirmed by the module docstring
  itself: "confirmed by Nico" that the bridge is "a transparent relay inside
  the trust boundary"). A TestClient against the bare
  ``create_bridge_app()`` app CANNOT reproduce Laura's 403 default-deny
  because there is no Caddy/SPIFFE layer in front of it in this offline
  suite — this is a genuine, structural limitation (not a mock gap), and the
  positive assertion below (unauthenticated caller reaches 200/202, not 403)
  is the ACCURATE, re-runnable evidence of where this specific module's
  security boundary actually is. This is flagged loudly per the brief: it is
  the exact P0 security surface the gate protects, and the finding is that
  the conformance-relevant boundary for POST /mcp lives in
  ``gateway/proxy.py``'s catch-all MCP dispatch interception
  (``dispatch_mcp_call()`` at proxy.py:1034-1072, guarded by rate-limit +
  DDoS + JWT + OPA) — NOT in ``mcp/_bridge.py``. That dispatch path is
  reached via ``POST /mcp/<agent_name>``, which is outside this group's
  12-endpoint list (Lu's matrix does not list it under GATEWAY-MCP).

Last updated: 2026-07-23T00:00:00+00:00
"""
from __future__ import annotations

import sys
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

pytestmark = pytest.mark.conformance

_INTERNAL_BEARER = "test-internal-bearer-token-for-conformance-suite"


# ---------------------------------------------------------------------------
# Local route-enumeration helper.
#
# conftest.py's `enumerate_routes()`/`routes_for_prefix()` are plain module
# functions (not fixtures) hardwired nowhere in particular, but its
# `declared_routes`/`route_prefix_filter` FIXTURES are hardwired to `bo_app`
# specifically — not reusable for the gateway app. Rather than edit shared
# conftest.py content, this is a minimal local copy of the SAME walk algorithm
# (same pinned starlette==1.3.1 assumptions conftest.py's docstring documents),
# scoped to this group's own gw_app.
# ---------------------------------------------------------------------------


def _enumerate_gw_routes(app) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []

    def walk(routes, prefix: str = "") -> None:
        for r in routes:
            if isinstance(r, APIRoute):
                methods = r.methods or set()
                for method in sorted(methods - {"HEAD", "OPTIONS"}):
                    out.append((method, prefix + r.path))
            elif type(r).__name__ == "_IncludedRouter":
                sub_prefix = prefix + (getattr(r.include_context, "prefix", "") or "")
                walk(r.original_router.routes, sub_prefix)
            elif hasattr(r, "routes"):
                walk(r.routes, prefix)

    walk(app.routes)
    return out


# ---------------------------------------------------------------------------
# openai_router._state reset — module-level singleton (see
# gateway/openai_router.py:1045 `_state = OpenAIRouterState()`), shared
# process-wide, NOT per-app. Every test must reset it to a clean, offline-safe
# baseline or a mutation from one test leaks into the next (mirrors
# src/tests/unit/test_v31_embeddings_endpoint.py's `_reset_router_state()`).
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_openai_router_state():
    from yashigani.gateway.openai_router import configure as configure_openai_router

    configure_openai_router(opa_url="")  # dev opt-in bypass (YASHIGANI_OPA_OPTIONAL=true)
    yield
    configure_openai_router(opa_url="")


@pytest.fixture
def gw_app(gw_app_factory):
    """Gateway app with the OpenAI-compat router mounted (matches
    entrypoint.py's real wiring order: extra_routers include openai_router
    before the catch-all)."""
    from yashigani.gateway.openai_router import router as openai_gw_router

    return gw_app_factory(extra_routers=[openai_gw_router])


@pytest.fixture
def gw_client(gw_app):
    with TestClient(gw_app, raise_server_exceptions=False) as client:
        yield client


def _internal_bearer_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {_INTERNAL_BEARER}"}


# ---------------------------------------------------------------------------
# Route-completeness check for the gateway-app-native routes (proxy.py +
# openai_router.py's 9 real routes; /livez + /readyz are deliberately EXCLUDED
# — FINDING-GW-1: they are not real routes, see module docstring).
# ---------------------------------------------------------------------------


def test_group_covers_all_declared_gateway_routes(gw_app):
    declared = _enumerate_gw_routes(gw_app)
    declared_set = {(m, p) for (m, p) in declared}
    expected = {
        ("GET", "/healthz"),
        ("GET", "/docs"),
        ("GET", "/redoc"),
        ("GET", "/.well-known/yashigani-mcp-jwks.json"),
        ("GET", "/mcp/health"),
        ("POST", "/v1/chat/completions"),
        ("POST", "/v1/embeddings"),
        ("GET", "/v1/models"),
    }
    missing = expected - declared_set
    assert not missing, f"Expected routes missing from gw_app: {missing}"
    # /openapi.json is also mounted (auth-gated schema, out of this group's
    # 12-endpoint list per Lu's matrix) — present, not asserted against here.


# ---------------------------------------------------------------------------
# GET /healthz — public, no auth (proxy.py:365-367)
# ---------------------------------------------------------------------------


class TestHealthz:
    # GAP-CLOSED: GET /healthz
    def test_unauth_200(self, gw_client):
        r = gw_client.get("/healthz")
        assert r.status_code == 200
        assert r.json() == {"status": "ok"}

    def test_post_falls_through_to_catchall_not_405(self, gw_client):
        """FINDING-GW-2: POST /healthz is NOT a declared method for this
        path, but the catch-all (proxy.py:536-541) accepts POST on any path
        and wins the Starlette PARTIAL->FULL match fallthrough, so this does
        NOT 405. With no OPA reachable, the catch-all fails closed (403) at
        the request-leg OPA check (proxy.py:980-998) before ever reaching
        the upstream. Verified real behaviour, not softened to expect 405."""
        r = gw_client.post("/healthz")
        assert r.status_code == 403
        assert r.status_code != 405


# ---------------------------------------------------------------------------
# GET /livez, GET /readyz — FINDING-GW-1: not real routes; fall through to
# the catch-all -> fail-closed OPA deny (no OPA reachable in this suite).
# ---------------------------------------------------------------------------


class TestLivezReadyz:
    # GAP-CLOSED: GET /livez
    def test_livez_not_a_declared_route(self, gw_app):
        declared = {p for (_m, p) in _enumerate_gw_routes(gw_app)}
        assert "/livez" not in declared, (
            "FINDING-GW-1 regression: /livez is now a real route — update "
            "this test's assertions to match the new dedicated handler."
        )

    def test_livez_falls_through_catchall_opa_denies_403(self, gw_client):
        r = gw_client.get("/livez")
        assert r.status_code == 403

    # GAP-CLOSED: GET /readyz
    def test_readyz_not_a_declared_route(self, gw_app):
        declared = {p for (_m, p) in _enumerate_gw_routes(gw_app)}
        assert "/readyz" not in declared, (
            "FINDING-GW-1 regression: /readyz is now a real route — update "
            "this test's assertions to match the new dedicated handler."
        )

    def test_readyz_falls_through_catchall_opa_denies_403(self, gw_client):
        r = gw_client.get("/readyz")
        assert r.status_code == 403


# ---------------------------------------------------------------------------
# GET /docs, GET /redoc — gated by _require_gateway_identity (proxy.py:411-475)
# ---------------------------------------------------------------------------


class TestDocsRedoc:
    # GAP-CLOSED: GET /docs
    def test_unauth_401(self, gw_client):
        r = gw_client.get("/docs")
        assert r.status_code == 401

    def test_internal_bearer_200(self, gw_client):
        r = gw_client.get("/docs", headers=_internal_bearer_headers())
        assert r.status_code == 200
        assert "swagger" in r.text.lower() or "openapi" in r.text.lower()
        assert "Yashigani Gateway" in r.text

    def test_post_falls_through_to_catchall_not_405(self, gw_client):
        """FINDING-GW-2: same catch-all fallthrough as /healthz."""
        r = gw_client.post("/docs")
        assert r.status_code != 405
        assert r.status_code == 403

    # GAP-CLOSED: GET /redoc
    def test_redoc_unauth_401(self, gw_client):
        r = gw_client.get("/redoc")
        assert r.status_code == 401

    def test_redoc_internal_bearer_200(self, gw_client):
        r = gw_client.get("/redoc", headers=_internal_bearer_headers())
        assert r.status_code == 200
        assert "redoc" in r.text.lower() or "openapi" in r.text.lower()


# ---------------------------------------------------------------------------
# GET /.well-known/yashigani-mcp-jwks.json — public (proxy.py:494-507)
# ---------------------------------------------------------------------------


class TestJwks:
    # GAP-CLOSED: GET /.well-known/yashigani-mcp-jwks.json
    def test_unconfigured_404(self, gw_client):
        r = gw_client.get("/.well-known/yashigani-mcp-jwks.json")
        assert r.status_code == 404
        assert r.json()["error"] == "mcp_not_configured"

    def test_configured_200_with_real_jwks_store(self, gw_app_factory):
        """Genuine positive-path: a REAL JwksStore backed by a REAL
        McpJwtIssuer (EC key, no fakeredis needed — this store is pure
        in-memory), not a MagicMock stand-in."""
        from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1, generate_private_key

        from yashigani.gateway.openai_router import router as openai_gw_router
        from yashigani.mcp._jwks import JwksStore
        from yashigani.mcp._jwt import McpJwtIssuer

        private_key = generate_private_key(SECP384R1())
        issuer = McpJwtIssuer(tenant_id="conformance-tenant", private_key=private_key, key_generated_at=0)
        store = JwksStore(issuer)

        app = gw_app_factory(extra_routers=[openai_gw_router], mcp_jwks_store=store)
        with TestClient(app, raise_server_exceptions=False) as client:
            r = client.get("/.well-known/yashigani-mcp-jwks.json")
        assert r.status_code == 200
        body = r.json()
        assert "keys" in body and len(body["keys"]) == 1
        # FINDING-GW-4 (proxy.py:337-339 vs proxy.py:504-505): the route
        # handler explicitly sets Cache-Control: max-age=60, must-revalidate
        # (JWKS_CACHE_CONTROL — see mcp/_jwks.py's own detailed rationale for
        # why 60s specifically matters for key-rotation overlap correctness),
        # but the global `security_headers` middleware (registered on every
        # response, proxy.py:326-339) unconditionally OVERWRITES Cache-Control
        # to "no-store" for any path not under /static/ — AFTER the route ran.
        # Verified empirically: the route's intended header is dead code at
        # the actual HTTP-response level. Asserting the REAL (overwritten)
        # value here per instructions ("do not silently fix the test to match
        # broken behaviour") — this is a genuine divergence to flag, not a
        # test bug.
        assert r.headers["cache-control"] == "no-store"


# ---------------------------------------------------------------------------
# GET /mcp/health — public (proxy.py:509-533)
# ---------------------------------------------------------------------------


class TestMcpHealth:
    # GAP-CLOSED: GET /mcp/health
    def test_unconfigured_503(self, gw_client):
        r = gw_client.get("/mcp/health")
        assert r.status_code == 503
        assert r.json()["detail"] == "mcp_not_configured"

    def test_no_brokers_503(self, gw_app_factory):
        from yashigani.gateway.openai_router import router as openai_gw_router

        registry = MagicMock()
        registry.all_brokers.return_value = []
        app = gw_app_factory(extra_routers=[openai_gw_router], mcp_broker_registry=registry)
        with TestClient(app, raise_server_exceptions=False) as client:
            r = client.get("/mcp/health")
        assert r.status_code == 503
        assert r.json()["detail"] == "mcp_no_brokers"

    def test_opa_healthy_200(self, gw_app_factory):
        from yashigani.gateway.openai_router import router as openai_gw_router

        broker = MagicMock()
        broker.opa_health = AsyncMock(return_value=True)
        registry = MagicMock()
        registry.all_brokers.return_value = [broker]
        app = gw_app_factory(extra_routers=[openai_gw_router], mcp_broker_registry=registry)
        with TestClient(app, raise_server_exceptions=False) as client:
            r = client.get("/mcp/health")
        assert r.status_code == 200
        assert r.json() == {"status": "ok", "opa": "healthy"}

    def test_opa_unreachable_503(self, gw_app_factory):
        from yashigani.gateway.openai_router import router as openai_gw_router

        broker = MagicMock()
        broker.opa_health = AsyncMock(return_value=False)
        registry = MagicMock()
        registry.all_brokers.return_value = [broker]
        app = gw_app_factory(extra_routers=[openai_gw_router], mcp_broker_registry=registry)
        with TestClient(app, raise_server_exceptions=False) as client:
            r = client.get("/mcp/health")
        assert r.status_code == 503
        assert r.json()["detail"] == "opa_unreachable"


# ---------------------------------------------------------------------------
# GET /v1/models — auth via _resolve_identity + genuine OPA decision
# (openai_router.py:4509-4697 + _opa_models_check at 5722-5785)
# ---------------------------------------------------------------------------


class TestV1Models:
    # GAP-CLOSED: GET /v1/models
    def test_unauth_401(self, gw_client):
        r = gw_client.get("/v1/models")
        assert r.status_code == 401
        assert r.json()["detail"]["error"]["code"] == "unauthorized"

    def test_get_only_method_not_allowed_falls_through_catchall(self, gw_client):
        """FINDING-GW-2: POST /v1/models (undeclared method on a declared
        GET-only path) also falls through to the catch-all rather than 405."""
        r = gw_client.post("/v1/models")
        assert r.status_code != 405

    def test_internal_bearer_dev_opa_optin_200_empty_list(self, gw_client):
        """Genuine positive path: internal Bearer clears identity resolution;
        opa_url="" (dev opt-in, set by the autouse fixture) clears
        _opa_models_check with filter="full". No live Ollama in this offline
        suite -> the model-fetch try/except (openai_router.py:4608-4629)
        degrades to an empty list; no identity_registry/agent_registry/
        available_models configured -> genuinely empty ModelListResponse.
        This is real degraded-but-cleared-the-gate behaviour, not a stub."""
        r = gw_client.get("/v1/models", headers=_internal_bearer_headers())
        assert r.status_code == 200
        body = r.json()
        assert body["object"] == "list"
        assert body["data"] == []

    def test_opa_mock_transport_allow(self, gw_app_factory, mock_opa, monkeypatch):
        """Demonstrates the brief's suggested httpx.MockTransport approach
        (mock_opa fixture) end-to-end for one endpoint: opa_url is set to a
        real-looking (unreachable) URL so _opa_models_check does NOT take the
        dev opt-in shortcut, and internal_httpx_client is monkeypatched to
        return an AsyncClient wired to the mock OPA transport."""
        from yashigani.gateway import openai_router as _openai_mod
        from yashigani.gateway.openai_router import configure as configure_openai_router
        from yashigani.gateway.openai_router import router as openai_gw_router

        configure_openai_router(opa_url="https://policy.invalid:8181")

        # NOTE (latent bug in the shared `mock_opa`/`MockOPATransport` fixture,
        # conftest.py: its __init__ override never calls
        # httpx.MockTransport.__init__(handler), so `self._handler` is unset
        # and httpx's ASYNC dispatch path (`handle_async_request`, used by
        # httpx.AsyncClient) raises "object has no attribute 'handler'" even
        # though the class's own `handle_request` override works fine for a
        # sync httpx.Client. Not fixed here (out of this group's one
        # permitted conftest.py edit, gw_app_factory) — worked around locally
        # by wrapping a properly-constructed httpx.MockTransport around
        # mock_opa.handle_request, which correctly threads `self._handler` for
        # the async dispatch path.  Flagged in this group's final report.
        _real_transport = httpx.MockTransport(mock_opa.handle_request)

        def _fake_internal_httpx_client(**_kw):
            return httpx.AsyncClient(transport=_real_transport)

        monkeypatch.setattr(_openai_mod, "internal_httpx_client", _fake_internal_httpx_client)

        app = gw_app_factory(extra_routers=[openai_gw_router])
        with TestClient(app, raise_server_exceptions=False) as client:
            r = client.get("/v1/models", headers=_internal_bearer_headers())
        assert r.status_code == 200

    def test_opa_mock_transport_deny_403(self, gw_app_factory, mock_opa, monkeypatch):
        from yashigani.gateway import openai_router as _openai_mod
        from yashigani.gateway.openai_router import configure as configure_openai_router
        from yashigani.gateway.openai_router import router as openai_gw_router

        configure_openai_router(opa_url="https://policy.invalid:8181")
        mock_opa.set_decision("deny")

        # NOTE (latent bug in the shared `mock_opa`/`MockOPATransport` fixture,
        # conftest.py: its __init__ override never calls
        # httpx.MockTransport.__init__(handler), so `self._handler` is unset
        # and httpx's ASYNC dispatch path (`handle_async_request`, used by
        # httpx.AsyncClient) raises "object has no attribute 'handler'" even
        # though the class's own `handle_request` override works fine for a
        # sync httpx.Client. Not fixed here (out of this group's one
        # permitted conftest.py edit, gw_app_factory) — worked around locally
        # by wrapping a properly-constructed httpx.MockTransport around
        # mock_opa.handle_request, which correctly threads `self._handler` for
        # the async dispatch path.  Flagged in this group's final report.
        _real_transport = httpx.MockTransport(mock_opa.handle_request)

        def _fake_internal_httpx_client(**_kw):
            return httpx.AsyncClient(transport=_real_transport)

        monkeypatch.setattr(_openai_mod, "internal_httpx_client", _fake_internal_httpx_client)

        app = gw_app_factory(extra_routers=[openai_gw_router])
        with TestClient(app, raise_server_exceptions=False) as client:
            r = client.get("/v1/models", headers=_internal_bearer_headers())
        # MockOPATransport returns {"result": {"allow": False, "deny": True}}
        # with no "filter"/"reason" keys -> _opa_models_check's .get() defaults
        # kick in: filter defaults to "denied", so allow=False -> 403/503 per
        # the http_status = 503 if "unreachable"/"not_configured" in reason else 403 rule.
        assert r.status_code in (403, 503)
        assert r.json()["detail"]["error"] == "MODELS_LIST_DENIED"


# ---------------------------------------------------------------------------
# POST /v1/chat/completions, POST /v1/embeddings — auth via _resolve_identity
# ---------------------------------------------------------------------------


class TestV1ChatCompletions:
    # GAP-CLOSED: POST /v1/chat/completions
    def test_unauth_401(self, gw_client):
        r = gw_client.post("/v1/chat/completions", json={
            "model": "qwen2.5:3b", "messages": [{"role": "user", "content": "hi"}],
        })
        assert r.status_code == 401
        assert r.json()["detail"]["error"]["code"] == "unauthorized"

    def test_get_falls_through_to_catchall_not_405(self, gw_client):
        """FINDING-GW-2: GET /v1/chat/completions (undeclared method on a
        declared POST-only path) falls through to the catch-all, not 405."""
        r = gw_client.get("/v1/chat/completions")
        assert r.status_code != 405

    def test_internal_bearer_clears_auth_gate(self, gw_client, monkeypatch):
        """Genuine positive path for the AUTH boundary specifically: identity
        resolution clears (internal Bearer), so the request does NOT 401/403
        on the auth gate. Downstream (OPA v1 decision + sensitivity/complexity
        scoring + no live Ollama/cloud backend wired) legitimately fails
        further into the pipeline -- documented here as the real offline
        degraded path (mirrors budget.py's ollama_unavailable 502 pattern
        already established in test_budget_models_inspection.py), not
        softened to assert a fabricated 200."""
        from yashigani.gateway import openai_router as _openai_mod

        monkeypatch.setattr(
            _openai_mod,
            "_opa_v1_check",
            AsyncMock(return_value={
                "allow": True, "reason": "ok", "model_allowed": True,
                "routing_safe": True, "sensitivity_allowed": True,
            }),
        )
        r = gw_client.post(
            "/v1/chat/completions",
            headers=_internal_bearer_headers(),
            json={"model": "qwen2.5:3b", "messages": [{"role": "user", "content": "hi"}]},
        )
        assert r.status_code not in (401, 403), (
            f"Internal bearer must clear the auth gate; got {r.status_code}: {r.text[:300]}"
        )


class TestV1Embeddings:
    # GAP-CLOSED: POST /v1/embeddings
    def test_unauth_401(self, gw_client):
        r = gw_client.post("/v1/embeddings", json={"model": "nomic-embed-text", "input": "hi"})
        assert r.status_code == 401
        assert r.json()["detail"]["error"]["code"] == "unauthorized"

    def test_get_falls_through_to_catchall_not_405(self, gw_client):
        r = gw_client.get("/v1/embeddings")
        assert r.status_code != 405

    def test_internal_bearer_real_ollama_roundtrip(self, gw_client, monkeypatch):
        """Genuine positive path: real OllamaEmbeddings dispatch, mocked at the
        httpx.AsyncClient transport boundary (established pattern from
        src/tests/unit/test_v31_embeddings_endpoint.py) -- proves the FULL
        200 OpenAI-shaped response, not just that the auth gate clears."""
        from yashigani.gateway import openai_router as _openai_mod

        monkeypatch.setattr(
            _openai_mod,
            "_opa_v1_check",
            AsyncMock(return_value={
                "allow": True, "reason": "ok", "model_allowed": True,
                "routing_safe": True, "sensitivity_allowed": True,
            }),
        )

        expected_vector = [0.1, 0.2, 0.3]
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"model": "nomic-embed-text", "embeddings": [expected_vector]}
        mock_resp.text = ""
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=mock_client)
        cm.__aexit__ = AsyncMock(return_value=False)
        monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **kw: cm)

        r = gw_client.post(
            "/v1/embeddings",
            headers=_internal_bearer_headers(),
            json={"model": "nomic-embed-text", "input": "hello world"},
        )
        assert r.status_code == 200, r.text[:300]
        body = r.json()
        assert body["object"] == "list"
        assert body["data"][0]["embedding"] == expected_vector


# ---------------------------------------------------------------------------
# mcp/_bridge.py — POST /mcp, POST / (a SEPARATE FastAPI app; see
# FINDING-GW-3 above for the auth-boundary-location finding)
# ---------------------------------------------------------------------------


_ECHO_SCRIPT = (
    "import sys\n"
    "for line in sys.stdin:\n"
    "    sys.stdout.write(line)\n"
    "    sys.stdout.flush()\n"
)
_ECHO_SUBPROCESS_CMD = [sys.executable, "-u", "-c", _ECHO_SCRIPT]


@pytest.fixture
def bridge_client():
    """A REAL _BridgeProcess backed by a REAL (non-mocked) Python subprocess
    that echoes each stdin line back to stdout -- proves the genuine
    stdio<->HTTP JSON-RPC correlation logic (id-matching, notification
    no-block) against a real process, not a MagicMock stand-in for the
    subprocess. No live MCP server is required for this: any subprocess that
    echoes its input satisfies the bridge's response-correlation contract."""
    from yashigani.mcp._bridge import create_bridge_app

    app = create_bridge_app(command=_ECHO_SUBPROCESS_CMD, read_timeout=5.0)
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client


class TestMcpBridge:
    # GAP-CLOSED: POST /mcp
    def test_request_roundtrip_200(self, bridge_client):
        payload = {"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}}
        r = bridge_client.post("/mcp", json=payload)
        assert r.status_code == 200
        assert r.json() == payload

    def test_notification_202_no_block(self, bridge_client):
        """No 'id' field -> notification -> 202 immediately, no blocking read."""
        payload = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        r = bridge_client.post("/mcp", json=payload)
        assert r.status_code == 202

    def test_empty_body_400(self, bridge_client):
        r = bridge_client.post("/mcp", content=b"")
        assert r.status_code == 400
        assert r.json()["error"] == "empty_body"

    def test_invalid_json_400(self, bridge_client):
        r = bridge_client.post("/mcp", content=b"{not json")
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_json"

    def test_oversized_body_413(self, bridge_client):
        # _BRIDGE_BODY_LIMIT default is 1 MiB (mcp/_bridge.py:68-70).
        oversized = b'{"jsonrpc":"2.0","id":1,"method":"x","params":"' + (b"a" * (1024 * 1024 + 1)) + b'"}'
        r = bridge_client.post("/mcp", content=oversized)
        assert r.status_code == 413
        assert r.json()["error"] == "REQUEST_ENTITY_TOO_LARGE"

    def test_get_method_not_allowed_405(self, bridge_client):
        """Unlike the gateway app, mcp/_bridge.py has NO catch-all route --
        an undeclared method genuinely 405s here (FastAPI native behaviour)."""
        r = bridge_client.get("/mcp")
        assert r.status_code == 405

    def test_unauthenticated_caller_reaches_200_not_403(self, bridge_client):
        """FINDING-GW-3: proves (does not assume) that this specific module
        applies NO app-layer default-deny -- a request with no Authorization
        header at all still gets a normal 200 JSON-RPC round-trip. This is
        the accurate, re-runnable evidence that the "default-deny 403" Laura
        documented for POST /mcp is enforced by the mesh/Caddy layer in
        front of the real deployment, not by mcp/_bridge.py itself."""
        payload = {"jsonrpc": "2.0", "id": 42, "method": "ping"}
        r = bridge_client.post("/mcp", json=payload)  # deliberately no Authorization header
        assert r.status_code == 200
        assert r.json() == payload

    # GAP-CLOSED: POST /
    def test_root_path_same_handler_request_roundtrip_200(self, bridge_client):
        payload = {"jsonrpc": "2.0", "id": 2, "method": "ping"}
        r = bridge_client.post("/", json=payload)
        assert r.status_code == 200
        assert r.json() == payload

    def test_root_path_notification_202(self, bridge_client):
        payload = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        r = bridge_client.post("/", json=payload)
        assert r.status_code == 202

    def test_root_path_unauthenticated_reaches_200(self, bridge_client):
        """FINDING-GW-3 confirmed on the '/' alias too."""
        payload = {"jsonrpc": "2.0", "id": 99, "method": "ping"}
        r = bridge_client.post("/", json=payload)
        assert r.status_code == 200
