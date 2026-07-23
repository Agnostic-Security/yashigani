"""
Yashigani 4.1.2 conformance suite — shared scaffold.

Closes C5 release-gate blocker G1 (Lu audit, YCS-20260723-v4.1.2-CONFORMANCE):
313/360 API endpoints had zero per-endpoint conformance assertion. This suite
boots the REAL FastAPI app objects (backoffice + gateway) with TestClient,
wires genuine auth (real Session objects in a real, fakeredis-backed
SessionStore — NOT dependency_overrides) so auth-gating assertions (401/403)
are real, and asserts declared-spec conformance per endpoint: status codes,
auth-tier gating, method-not-allowed, and response shape.

Runs fully OFFLINE — no live Postgres/Redis/OPA/Ollama required. This is
achieved by:
  1. Overriding the app's `lifespan` with a no-op (the real lifespan opens an
     asyncpg pool, runs alembic, and does several best-effort OPA re-syncs
     with sleep-based retries — all of which need a live stack and would make
     this suite slow/flaky/non-offline).
  2. Calling the *cheap* real init side-effects the lifespan would otherwise
     have performed (`load_caddy_secret()` — Layer B HMAC, reads an env var)
     directly, since `CaddyVerifiedMiddleware` fails closed (401) on every
     non-exempt path if this is skipped — this is a REAL security control,
     not a test artefact, and conformance tests must exercise it, not bypass
     it.
  3. Populating `yashigani.backoffice.state.backoffice_state` (a module-level
     singleton dataclass — see `src/yashigani/backoffice/state.py`) with real
     service instances backed by `fakeredis` wherever the service's
     constructor accepts a `redis_client` argument (most do — RBACStore,
     AgentRegistry, RateLimiter, ModelAllocationStore, BudgetConfigStore,
     etc.). Where a service is Postgres-only with no fakeredis equivalent
     (e.g. `PostgresLocalAuthService`, `AuthSettingsStore`), the owning test
     module must build a minimal in-memory async fake that implements ONLY
     the methods its router file actually calls (grep `state\\.<field>\\.` or
     `backoffice_state\\.<field>\\.` in the route file to get the exact list)
     and document this explicitly with a comment: `# MOCKED: <field> requires
     live Postgres — not available offline; fake implements <methods>`.

CONVENTION for every `tests/conformance/test_<group>.py` file:
  - One test module per router group (see the group list in the dispatch
    brief / PR description).
  - Use the fixtures below: `bo_app`, `unauth_client`, `admin_client`,
    `user_client`, `stepup_admin_client`, `caddy_headers`.
  - For EVERY endpoint in your group, assert (at minimum):
      1. The endpoint's declared auth tier is enforced: unauth -> 401 (or 403
         where the route's own docstring/OWASP note says otherwise), wrong
         tier -> 403, correct tier -> NOT 401/403 (may be 200/201/204/4xx
         business-logic, but must clear the auth gate).
      2. Method-not-allowed: an undeclared HTTP method on a declared path
         returns 405 (FastAPI native behaviour — assert it, don't assume it).
      3. Response schema shape matches the route's declared `response_model`
         (or, if a bare dict/JSONResponse, spot-check the documented shape in
         the route's docstring/spec).
      4. Any endpoint whose LIVE behaviour diverges from its OpenAPI schema /
         documented contract is a REAL FINDING — report it in your test
         docstring AND flag it in your final message. Do not silently "fix"
         the test to match broken behaviour, and do not skip the assertion.
  - NEVER write a test that always passes (e.g. `assert True`, catching every
    exception and passing anyway, or asserting only `status_code in
    (200, 401, 403, 404, 500)`). That is the exact fake-green pattern this
    gate exists to stop (Lu retro L1). Every assertion must pin an EXACT
    expected status/shape per auth tier.
  - Use `allowlist`/`denylist` language only (CLAUDE.md language rule) — never
    "whitelist"/"blacklist", including in comments/fixture names.
  - Add a `# GAP-CLOSED: <method> <path>` comment above each test so the
    final coverage report can grep-count closures per group.

Last updated: 2026-07-23T00:00:00+00:00
"""
from __future__ import annotations

import contextlib
import os

# Must be set before ANY yashigani import (mirrors src/tests/conftest.py —
# see that file's docstring for why: licensing self-integrity check + the
# gateway's fail-closed internal-bearer loader both run at module import).
os.environ.setdefault("YASHIGANI_ENV", "dev")
os.environ.setdefault(
    "YASHIGANI_INTERNAL_BEARER", "test-internal-bearer-token-for-conformance-suite"
)
os.environ.setdefault("YASHIGANI_OPA_OPTIONAL", "true")
# Layer B (EX-231-10) — CaddyVerifiedMiddleware fail-closed HMAC. A fixed
# 64-char hex test value; every authenticated TestClient request must carry
# this via the `caddy_headers` fixture below (or `X_CADDY_HEADER` constant).
os.environ.setdefault("CADDY_INTERNAL_HMAC", "b" * 64)
# No YASHIGANI_DB_DSN — deliberately unset. The real lifespan gates its entire
# asyncpg/alembic/Postgres-backed init block on `if db_dsn:`; leaving it unset
# means that block never executes even if a caller forgets to stub the
# lifespan, which is a second layer of offline-safety on top of (1) above.
os.environ.pop("YASHIGANI_DB_DSN", None)

import fakeredis
import httpx
import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

X_CADDY_HEADER = {"X-Caddy-Verified-Secret": os.environ["CADDY_INTERNAL_HMAC"]}

_ADMIN_SESSION_COOKIE = "__Host-yashigani_admin_session"
_USER_SESSION_COOKIE = "__Host-yashigani_session"


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers", "conformance: per-endpoint API conformance assertion (C5 gate)"
    )


@contextlib.asynccontextmanager
async def _noop_lifespan(app: FastAPI):
    """Replaces the real lifespan (Postgres pool + alembic + OPA re-sync
    retries) so the suite runs offline. See module docstring point 1."""
    yield


# ---------------------------------------------------------------------------
# Route enumeration — the "generated OpenAPI schema" walk.
#
# FastAPI/Starlette 1.3.1 wraps every `include_router()` call in an internal
# `fastapi.routing._IncludedRouter` container whose actual `APIRoute` objects
# live under `.original_router.routes`, NOT directly on `app.routes` (verified
# empirically 2026-07-23 against this codebase's pinned starlette==1.3.1 —
# `app.routes` alone finds 13 routes; walking `_IncludedRouter` recursively
# finds all 381). Both `app.openapi()` (schema-based) and this walk (route-
# object-based) are provided; the route walk is authoritative for
# method-not-allowed / raw dispatch assertions, `app.openapi()` is authoritative
# for response-model schema assertions.
# ---------------------------------------------------------------------------


def enumerate_routes(app: FastAPI) -> list[tuple[str, str, APIRoute]]:
    """Returns [(method, path, APIRoute), ...] for every declared endpoint,
    walking through any `_IncludedRouter` wrapper Starlette 1.3.1 introduces.

    CRITICAL: `_IncludedRouter.original_router.routes[i].path` is the path
    RELATIVE to the included router (e.g. `/models` for a route registered
    under `app.include_router(models_router, prefix="/admin/models")`) — the
    prefix is NOT baked into `.path`, it lives on
    `_IncludedRouter.include_context.prefix` and is applied by FastAPI only at
    dispatch-match time. Verified empirically 2026-07-23: a naive walk that
    used `.path` directly found 12/381 routes (only the one router mounted
    with `dependencies=[Depends(...)]` and no separate prefix layering
    happened to read correctly by coincidence) — every OTHER router's routes
    silently reported truncated paths (`/models` instead of
    `/admin/models`), which would have made every `routes_for_prefix()` call
    for those groups silently return zero routes. This function accumulates
    the prefix through the recursion so the returned path is the REAL,
    dispatchable path.
    """
    out: list[tuple[str, str, APIRoute]] = []

    def walk(routes, prefix: str = "") -> None:
        for r in routes:
            type_name = type(r).__name__
            if isinstance(r, APIRoute):
                methods = r.methods or set()
                for method in sorted(methods - {"HEAD", "OPTIONS"}):
                    out.append((method, prefix + r.path, r))
            elif type_name == "_IncludedRouter":
                sub_prefix = prefix + (getattr(r.include_context, "prefix", "") or "")
                walk(r.original_router.routes, sub_prefix)
            elif hasattr(r, "routes"):
                walk(r.routes, prefix)

    walk(app.routes)
    return out


def routes_for_prefix(app: FastAPI, *prefixes: str) -> list[tuple[str, str, APIRoute]]:
    """Filter enumerate_routes() to only paths starting with one of `prefixes`.
    Use this in each group's test module to assert you've covered every route
    your group owns (fail the test file if the count doesn't match Lu's
    matrix count for your files)."""
    all_routes = enumerate_routes(app)
    return [(m, p, r) for (m, p, r) in all_routes if any(p.startswith(pre) for pre in prefixes)]


# ---------------------------------------------------------------------------
# Backoffice app fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def bo_app_factory():
    """Returns a callable that builds a FRESH backoffice FastAPI app with the
    real lifespan replaced by a no-op and the Layer B Caddy secret loaded
    (cheap, env-var only — see module docstring point 2).

    Session-scoped factory (not the app itself) because several router
    modules (e.g. `budget.py`) hold MODULE-LEVEL state configured via their
    own `configure()` call — tests that mutate that state should build a
    fresh app + re-run `configure()` per test/module to avoid cross-test
    leakage. Group test files decide their own app-fixture scope.
    """

    def _build() -> FastAPI:
        from yashigani.auth.caddy_verified import load_caddy_secret

        load_caddy_secret()
        from yashigani.backoffice.app import create_backoffice_app

        app = create_backoffice_app()
        app.router.lifespan_context = _noop_lifespan
        return app

    return _build


@pytest.fixture
def bo_app(bo_app_factory):
    """Function-scoped fresh backoffice app. Use this unless your group needs
    session-scoped reuse for performance (route enumeration is cheap; app
    construction is cheap — no I/O happens at construction time)."""
    return bo_app_factory()


# ---------------------------------------------------------------------------
# backoffice_state wiring — fakeredis-backed real session store.
#
# This is the ONE piece of state every group needs (session-gated auth is
# universal across /admin/* and /user/* /me/*). Group-specific stores
# (rbac_store, agent_registry, auth_service, ...) are wired by each group's
# own test module/fixture — see the module docstring convention above.
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_redis_client():
    """A fresh fakeredis client per test — decode_responses=True matches
    SessionStore's own client construction (`redis.Redis.from_url(url,
    decode_responses=True)`)."""
    client = fakeredis.FakeRedis(decode_responses=True)
    yield client
    client.flushall()


@pytest.fixture
def session_store(fake_redis_client, monkeypatch):
    """Installs a REAL SessionStore (yashigani.auth.session.SessionStore)
    backed by fakeredis into backoffice_state.session_store.

    SessionStore's own __init__ always constructs its own live
    `redis.Redis.from_url(...)` client (no constructor hook for injection),
    so we bypass __init__ via __new__ and set the private attributes
    directly — the same pattern used by this store's constructor body
    (verified against src/yashigani/auth/session.py as of 2026-07-23)."""
    from yashigani.auth.session import SessionStore
    from yashigani.backoffice.state import backoffice_state

    store = SessionStore.__new__(SessionStore)
    store._redis = fake_redis_client
    store._account_index_prefix = "yashigani:account_sessions:"
    store._session_prefix = "yashigani:session:"
    monkeypatch.setattr(backoffice_state, "session_store", store, raising=False)
    return store


@pytest.fixture
def mock_audit_writer(monkeypatch):
    """Installs a MagicMock audit_writer into backoffice_state — mirrors the
    `mock_audit_writer` fixture pattern in src/tests/conftest.py. Routes call
    `backoffice_state.audit_writer.write(...)` fire-and-forget; a MagicMock
    lets us assert `.write.assert_called_with(...)` where a group wants to
    verify an audit event was emitted for a mutation."""
    from unittest.mock import MagicMock

    from yashigani.backoffice.state import backoffice_state

    writer = MagicMock()
    writer.write = MagicMock()
    monkeypatch.setattr(backoffice_state, "audit_writer", writer, raising=False)
    return writer


# ---------------------------------------------------------------------------
# Auth-tier TestClient fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def unauth_client(bo_app, session_store):
    """No cookie. Every session-gated route must 401 for this client."""
    with TestClient(bo_app, headers=X_CADDY_HEADER) as client:
        yield client


@pytest.fixture
def admin_client(bo_app, session_store):
    """Admin-tier session cookie set. `require_admin_session`-gated routes
    must clear the auth gate (not 401/403) for this client."""
    session = session_store.create(
        account_id="conformance-admin1", account_tier="admin", client_ip="127.0.0.1"
    )
    with TestClient(bo_app, headers=X_CADDY_HEADER) as client:
        client.cookies.set(_ADMIN_SESSION_COOKIE, session.token)
        client.conformance_session = session  # type: ignore[attr-defined]
        yield client


@pytest.fixture
def stepup_admin_client(bo_app, session_store):
    """Admin-tier session cookie + a fresh TOTP step-up recorded — for
    `require_stepup_admin_session`-gated routes (StepUpAdminSession)."""
    session = session_store.create(
        account_id="conformance-admin-stepup", account_tier="admin", client_ip="127.0.0.1"
    )
    session_store.record_totp_stepup(session.token)
    with TestClient(bo_app, headers=X_CADDY_HEADER) as client:
        client.cookies.set(_ADMIN_SESSION_COOKIE, session.token)
        client.conformance_session = session  # type: ignore[attr-defined]
        yield client


@pytest.fixture
def user_client(bo_app, session_store):
    """User-tier session cookie set. `require_user_session`-gated routes must
    clear the auth gate for this client; `require_admin_session`-gated routes
    must 403 (insufficient_tier) for this client."""
    session = session_store.create(
        account_id="conformance-userA", account_tier="user", client_ip="127.0.0.1"
    )
    with TestClient(bo_app, headers=X_CADDY_HEADER) as client:
        client.cookies.set(_USER_SESSION_COOKIE, session.token)
        client.conformance_session = session  # type: ignore[attr-defined]
        yield client


@pytest.fixture
def second_user_client(bo_app, session_store):
    """A SECOND, distinct user-tier session — for BOLA/IDOR cross-user
    assertions (attacker attempts to access victim's `admin_client`/
    `user_client` resources by ID)."""
    session = session_store.create(
        account_id="conformance-userB", account_tier="user", client_ip="127.0.0.1"
    )
    with TestClient(bo_app, headers=X_CADDY_HEADER) as client:
        client.cookies.set(_USER_SESSION_COOKIE, session.token)
        client.conformance_session = session  # type: ignore[attr-defined]
        yield client


# ---------------------------------------------------------------------------
# Gateway app fixture (for the GATEWAY-MCP group — /v1/*, /mcp, /healthz etc.)
# ---------------------------------------------------------------------------


@pytest.fixture
def gw_app_factory():
    """Returns a callable that builds a FRESH gateway FastAPI app.

    GATEWAY-MCP FIX (2026-07-23): the original stub imported
    ``yashigani.gateway.entrypoint.app`` — a MODULE-LEVEL SINGLETON built
    exactly once, at first import, by ``entrypoint._build_app()``. That is not
    an app *factory* the way ``create_backoffice_app()`` is: ``_build_app()``
    (a) hard-requires ``YASHIGANI_UPSTREAM_URL`` via ``os.environ[...]`` (no
    default — raises ``KeyError`` at import time if unset), (b) attempts ~15
    real ``redis.from_url(...).ping()`` connections (RBAC, rate-limit, DDoS,
    JWT inspector, model stores, workflow scheduler, egress limiter — each
    individually try/excepted to degrade to ``None`` on failure, so it doesn't
    crash offline, but it is slow and non-deterministic across environments),
    and (c) starts several background daemon threads (MetricsCollector,
    PoolHealthMonitor, a Redis pub/sub settings-subscriber thread) as an
    IMPORT-TIME side effect. Swapping ``.router.lifespan_context`` on that
    singleton afterwards does NOT rebuild it, and calling the stub's ``_build``
    again just re-returns the SAME already-built app object — there is no
    per-test (or even per-session) isolation, unlike every other fixture in
    this file.

    Verified fix: build the gateway app the same way this exact codebase's
    OWN unit-test suite already does — see
    ``src/tests/unit/test_openapi_exposure.py::_make_gateway_client`` — by
    calling ``create_gateway_app()`` (the real FastAPI app *factory* in
    ``gateway/proxy.py``) directly, mirroring how ``bo_app_factory`` above
    calls ``create_backoffice_app()``. ``create_gateway_app()`` takes plain
    keyword arguments (no Redis/DB I/O at construction time) and its
    ``_lifespan`` only does two things offline-relevant: (1) load the Layer B
    Caddy secret (cheap, env-var read — same pattern as
    ``load_caddy_secret()`` in ``bo_app_factory``), and (2) construct an
    ``httpx.AsyncClient`` (no network I/O at construction). Postgres/workflow-
    scheduler startup are gated behind env vars this suite deliberately leaves
    unset. The no-op lifespan swap below is applied anyway, for the same
    defence-in-depth reason ``bo_app_factory`` applies it, and because tests
    that never reach the catch-all's upstream-forward step never touch
    ``state["http_client"]`` regardless.

    NOTE: unlike ``bo_app_factory``, this factory does NOT add
    ``CaddyVerifiedMiddleware`` / ``SpiffePeerCertMiddleware`` /
    ``LicenseEnforcementMiddleware`` / ``AgentAuthMiddleware`` — those are
    wired by ``entrypoint._build_app()`` AROUND the object ``create_gateway_app()``
    returns, not by ``create_gateway_app()`` itself, and this exact codebase's
    own ``test_openapi_exposure.py::_make_gateway_client`` does not add them
    either. Route-level auth (Bearer/API-key resolution + OPA) IS exercised;
    the outer Caddy/Spiffe/License/Agent middleware chain is NOT — see the
    GATEWAY-MCP group's test module for the explicit scope note.
    """

    def _build(*, config=None, extra_routers=None, **create_gateway_app_kwargs) -> FastAPI:
        from yashigani.auth.caddy_verified import load_caddy_secret

        load_caddy_secret()
        from yashigani.gateway.proxy import GatewayConfig, create_gateway_app

        cfg = config or GatewayConfig(
            upstream_base_url="http://upstream.invalid:9",
            opa_url="https://policy.invalid:8181",
        )
        app = create_gateway_app(
            config=cfg,
            extra_routers=extra_routers or [],
            **create_gateway_app_kwargs,
        )
        app.router.lifespan_context = _noop_lifespan
        return app

    return _build


# ---------------------------------------------------------------------------
# httpx mock transports (OPA / upstream) — reused from src/tests/conftest.py
# pattern for groups that need them (e.g. GATEWAY-MCP for /v1/chat/completions
# OPA-gated dispatch, or any admin route that calls out to OPA synchronously).
# ---------------------------------------------------------------------------


class MockOPATransport(httpx.MockTransport):
    """
    FIX (2026-07-23, found independently by the GATEWAY-MCP fan-out group):
    the original version of this class overrode `__init__` WITHOUT calling
    `httpx.MockTransport.__init__(self, self.handle_request)` — this works
    fine under `httpx.Client` (sync dispatch resolves `self.handle_request`
    directly), but silently breaks under `httpx.AsyncClient` (async
    dispatch), because `MockTransport.__init__` is what actually wires the
    handler callable into the base transport's dispatch machinery. Several
    fan-out groups worked around this locally by wrapping
    `httpx.MockTransport(mock_opa.handle_request)` themselves instead of
    using this class directly — fixed here so `mock_opa` is a correct,
    directly-usable transport for BOTH sync and async httpx clients.
    """

    def __init__(self, allow: bool = True):
        super().__init__(self.handle_request)
        self._allow = allow

    def set_decision(self, decision: str) -> None:
        self._allow = decision != "deny"

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.path.startswith("/v1/data"):
            return httpx.Response(
                200, json={"result": {"allow": self._allow, "deny": not self._allow}}
            )
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "ok"})
        return httpx.Response(404, json={"error": "not_found"})


@pytest.fixture
def mock_opa():
    return MockOPATransport(allow=True)


# ---------------------------------------------------------------------------
# Fixture wrappers around the module-level helpers above.
#
# Cross-test-file plain imports of this conftest module (e.g.
# `from conftest import X_CADDY_HEADER`) are UNRELIABLE under pytest's
# per-directory conftest import machinery (verified empirically 2026-07-23 —
# `ModuleNotFoundError: No module named 'conftest'` even from a sibling file
# in the SAME directory). Use these fixtures instead; they are always
# injectable regardless of pytest's import-mode/rootdir configuration.
# ---------------------------------------------------------------------------


@pytest.fixture
def caddy_headers() -> dict[str, str]:
    return dict(X_CADDY_HEADER)


@pytest.fixture
def declared_routes(bo_app):
    """All (method, path, APIRoute) tuples for the whole backoffice app."""
    return enumerate_routes(bo_app)


@pytest.fixture
def route_prefix_filter(bo_app):
    """Callable: route_prefix_filter("/admin/budget", "/admin/models") ->
    [(method, path, APIRoute), ...] restricted to those prefixes."""

    def _filter(*prefixes: str):
        return routes_for_prefix(bo_app, *prefixes)

    return _filter
