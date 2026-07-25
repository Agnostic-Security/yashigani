"""
Conformance group: USER-PLANE-AGENTS.

Closes G1 (Lu audit YCS-20260723-v4.1.2-CONFORMANCE) for:
  routes/user_agents.py   (24 endpoints) — /user/agents/*, /user/memories/*,
                                            /user/skills, /user/mentions
  routes/me.py             (3 endpoints) — /me/api-key, /me/api-keys*
Total: 27 endpoints (Lu matrix rows 291-314, 191-193).

This is the highest-value IDOR/BOLA surface in the suite. Laura's live
red-team already PROVED (manual, one-off): attacker GET/DELETE of a victim's
ua_id -> 404 scoped; attacker GET of a victim's memory block_id -> 404
scoped; an SSTI probe (`{{7*7}}`) in memory content is stored/returned
verbatim, never evaluated. This file builds the repeatable, CI-runnable
regression version of those exact assertions, plus covers every other
endpoint in the group that previously had zero conformance assertion.

Backing store (verified by reading user_agents.py's `_get_redis()`,
line ~135-143): routes read/write directly against
`backoffice_state.identity_registry._r` (Redis db/3, `ua:*` keys) — NOT
`backoffice_state.user_plane_durable` (that is a best-effort Postgres
dual-write mirror every mutation wraps in `try/except` and tolerates being
`None` for; never required for these routes to function). This suite wires
the REAL `IdentityRegistry` (accepts `redis_client` directly —
src/yashigani/identity/registry.py:152) against fakeredis so every CRUD
assertion is a genuine round-trip through real route + real store code,
not a mock.

Auth tier: every /user/agents* /user/memories* /user/skills /user/mentions
route is `UserSession`-gated (`require_user_session`, RISK-100). Verified
against src/yashigani/backoffice/middleware.py: `require_user_session`
resolves the session token EXCLUSIVELY from the user-plane cookie
(`_resolve_user_token`, NEVER falls back to the admin cookie) and explicitly
rejects an admin-tier session with 403 `wrong_plane`.

IMPORTANT FIXTURE FINDING (documented per SOP — do not edit conftest.py,
add locally + report): the shared `admin_client` fixture in conftest.py sets
ONLY the admin-plane cookie (`__Host-yashigani_admin_session`). Real admin
login (auth.py:2393-2409, RISK-100 SoD) also sets ONLY the admin cookie —
admins never receive a user-plane cookie at all. So `admin_client` hitting a
`/user/*` route finds NO user cookie whatsoever and gets 401
`authentication_required` from `require_user_session`, NOT 403 `wrong_plane`
(verified below in `TestWrongPlaneAndAdminTierMismatch.
test_plain_admin_client_401_not_403_on_user_route`). To exercise the
`wrong_plane` 403 branch specifically (the real defence against an
admin-tier session token ending up in the user-cookie slot — e.g. a stale or
attacker-manipulated cookie), this file adds a LOCAL fixture,
`admin_session_via_user_cookie_client`, that presents a fresh admin-tier
session token through the user-plane cookie. Candidate for promotion to
conftest.py: `admin_session_via_user_cookie_client`, `stepup_user_client`,
`identity_registry_state`.

me.py routes use `AnySession` (accept admin OR user tier) + an explicit
`_assert_user_tier()` check inside the route body, so the PLAIN shared
`admin_client` fixture (admin cookie only) DOES correctly reach the route
and gets 403 `user_tier_required` — no local fixture needed there.

Convention: see tests/conformance/conftest.py module docstring.

Last updated: 2026-07-23T00:00:00+00:00
"""
from __future__ import annotations

from typing import ClassVar

import pytest

pytestmark = pytest.mark.conformance

_USER_SESSION_COOKIE = "__Host-yashigani_session"

_GROUP_PREFIXES = (
    "/user/agents",
    "/user/memories",
    "/user/skills",
    "/user/mentions",
    "/me/api-key",
)

# ---------------------------------------------------------------------------
# Declared-endpoint table — single source of truth for the sweep tests below
# AND the completeness assertion. (method, path, json_body_or_None).
# Dummy path-param values are deliberately non-existent IDs — auth-tier
# gating (Depends resolution) always runs BEFORE route-body BOLA/business
# logic, so a bogus ID is safe for 401/403 sweep purposes (proven pattern —
# see test_budget_models_inspection.py `test_unauth_post_401`).
# ---------------------------------------------------------------------------

_DUMMY_UA = "uag_doesnotexist0000"
_DUMMY_BLOCK = "umb_doesnotexist0000"
_DUMMY_KEY = "idnt_doesnotexist000"

_USER_AGENTS_ROUTES: list[tuple[str, str, dict | None]] = [
    ("GET", "/user/agents", None),
    ("POST", "/user/agents", {"name": "t"}),
    ("GET", f"/user/agents/{_DUMMY_UA}", None),
    ("PATCH", f"/user/agents/{_DUMMY_UA}", {"name": "t"}),
    ("DELETE", f"/user/agents/{_DUMMY_UA}", None),
    ("GET", f"/user/agents/{_DUMMY_UA}/personality", None),
    ("PUT", f"/user/agents/{_DUMMY_UA}/personality", {}),
    ("GET", f"/user/agents/{_DUMMY_UA}/skills", None),
    ("PUT", f"/user/agents/{_DUMMY_UA}/skills", {"skills": []}),
    ("GET", f"/user/agents/{_DUMMY_UA}/memories", None),
    ("POST", f"/user/agents/{_DUMMY_UA}/memories/{_DUMMY_BLOCK}", None),
    ("DELETE", f"/user/agents/{_DUMMY_UA}/memories/{_DUMMY_BLOCK}", None),
    ("GET", "/user/memories", None),
    ("POST", "/user/memories", {"label": "t"}),
    ("GET", f"/user/memories/{_DUMMY_BLOCK}", None),
    ("PATCH", f"/user/memories/{_DUMMY_BLOCK}", {}),
    ("DELETE", f"/user/memories/{_DUMMY_BLOCK}", None),
    ("GET", "/user/skills", None),
    ("GET", "/user/mentions", None),
    ("PUT", f"/user/agents/{_DUMMY_UA}/graph", {"graph": {"nodes": [], "edges": []}}),
    ("GET", f"/user/agents/{_DUMMY_UA}/graph", None),
    ("POST", f"/user/agents/{_DUMMY_UA}/run", None),
    ("POST", "/user/agents/generate", {"description": "1234567890"}),
    ("POST", "/user/agents/templates", {"draft_id": "x", "name": "y"}),
]

_ME_ROUTES: list[tuple[str, str, dict | None]] = [
    ("POST", "/me/api-key", None),
    ("GET", "/me/api-keys", None),
    ("DELETE", f"/me/api-keys/{_DUMMY_KEY}", None),
]

assert len(_USER_AGENTS_ROUTES) == 24
assert len(_ME_ROUTES) == 3


def _ids(routes: list[tuple[str, str, dict | None]]) -> list[str]:
    return [f"{m} {p}" for (m, p, _b) in routes]


# ---------------------------------------------------------------------------
# Group-specific state wiring
# ---------------------------------------------------------------------------


@pytest.fixture
def identity_registry_state(fake_redis_client, monkeypatch):
    """Wires a REAL IdentityRegistry (accepts redis_client directly —
    src/yashigani/identity/registry.py:152) against fakeredis into
    backoffice_state.identity_registry. This IS the backing store
    user_agents.py's `_get_redis()` returns (`ir._r`) — every ua:*/mem:*
    CRUD assertion below is a genuine round-trip through real route code +
    a real (fakeredis-backed) Redis client, not a mock."""
    from yashigani.backoffice.state import backoffice_state
    from yashigani.identity.registry import IdentityRegistry

    registry = IdentityRegistry(redis_client=fake_redis_client)
    monkeypatch.setattr(backoffice_state, "identity_registry", registry)
    return registry


@pytest.fixture
def admin_session_via_user_cookie_client(bo_app, session_store, caddy_headers):
    """LOCAL fixture (candidate for conftest.py promotion — see module
    docstring). Admin-tier session token presented through the USER-plane
    cookie slot — the exact confused-deputy scenario require_user_session's
    `wrong_plane` check defends against. The plain shared `admin_client`
    fixture cannot exercise this branch: real admin login (RISK-100 SoD)
    issues ONLY the admin cookie, so `admin_client` never presents a token
    via the user cookie at all (see TestWrongPlaneAndAdminTierMismatch)."""
    from fastapi.testclient import TestClient

    session = session_store.create(
        account_id="conformance-admin-wrongplane", account_tier="admin", client_ip="127.0.0.1"
    )
    with TestClient(bo_app, headers=caddy_headers) as client:
        client.cookies.set(_USER_SESSION_COOKIE, session.token)
        yield client


@pytest.fixture
def stepup_user_client(bo_app, session_store, caddy_headers):
    """LOCAL fixture (candidate for conftest.py promotion). A fresh user-tier
    session with a recorded TOTP step-up — needed for /me/api-key issuance
    (Gap 4 / v2.23.4: fresh StepUp required, see me.py:194-215). Uses a
    dedicated account_id distinct from the shared `user_client` fixture's
    "conformance-userA" to avoid session-store collisions (SessionStore.
    create() invalidates any existing session for the account)."""
    from fastapi.testclient import TestClient

    session = session_store.create(
        account_id="conformance-userA-stepup", account_tier="user", client_ip="127.0.0.1"
    )
    session_store.record_totp_stepup(session.token)
    with TestClient(bo_app, headers=caddy_headers) as client:
        client.cookies.set(_USER_SESSION_COOKIE, session.token)
        client.conformance_session = session  # type: ignore[attr-defined]
        yield client


class FakeAuthService:
    """MOCKED: backoffice_state.auth_service is PostgresLocalAuthService in
    production, which requires a live Postgres pool — not available offline.
    Implements only `get_account_by_id()`, the sole auth_service method
    me.py's routes call (grep 'auth_svc\\.' in me.py -> get_account_by_id
    only, 3 call sites)."""

    def __init__(self) -> None:
        self._records: dict[str, object] = {}

    def register(self, record) -> None:
        self._records[record.account_id] = record

    async def get_account_by_id(self, account_id: str):
        return self._records.get(account_id)


def _seed_human_identity(fake_redis_client, slug: str, identity_id: str) -> None:
    """Seed a minimal HUMAN identity directly via fakeredis.

    Bypasses IdentityRegistry.register()'s HUMAN-kind path deliberately: that
    path runs a Lua EVAL script gated by
    yashigani.licensing.enforcer.get_license().max_end_users (GROUP-4-1
    atomic seat-limit check) — Lua scripting + license machinery is not
    needed to exercise me.py's read/rotate paths, which only ever call
    IdentityRegistry.get_by_slug() / get() / rotate_key(), all plain Redis
    ops (verified against src/yashigani/identity/registry.py:369-663). Those
    three methods, exercised below, are the REAL IdentityRegistry code
    running against fakeredis — only this initial seed is hand-rolled."""
    fake_redis_client.set(f"identity:slug:{slug}", identity_id)
    fake_redis_client.hset(
        f"identity:reg:{identity_id}",
        mapping={"identity_id": identity_id, "slug": slug, "status": "active"},
    )
    fake_redis_client.sadd("identity:index:all", identity_id)
    fake_redis_client.sadd("identity:index:active", identity_id)


@pytest.fixture
def me_state(fake_redis_client, monkeypatch):
    """Wires a REAL IdentityRegistry (fakeredis-backed) + a MOCKED
    auth_service into backoffice_state for me.py's routes."""
    from yashigani.backoffice.state import backoffice_state
    from yashigani.identity.registry import IdentityRegistry

    registry = IdentityRegistry(redis_client=fake_redis_client)
    auth_svc = FakeAuthService()
    monkeypatch.setattr(backoffice_state, "identity_registry", registry)
    monkeypatch.setattr(backoffice_state, "auth_service", auth_svc)
    return registry, auth_svc


def _register_account(me_state, fake_redis_client, account_id: str, username: str) -> str:
    """Registers a FakeAuthService AccountRecord + seeds its HUMAN identity.
    Returns the identity_id."""
    from yashigani.auth.local_auth import AccountRecord
    from yashigani.identity.slug import email_to_slug

    _registry, auth_svc = me_state
    record = AccountRecord(
        account_id=account_id,
        username=username,
        password_hash="x",
        totp_secret="x",
        recovery_codes=None,
        account_tier="user",
        email=None,
        force_password_change=False,
        force_totp_provision=False,
    )
    auth_svc.register(record)
    slug = email_to_slug(f"{username}@yashigani.local")
    identity_id = f"idnt_{username.replace('-', '_')}"
    _seed_human_identity(fake_redis_client, slug, identity_id)
    return identity_id


# ---------------------------------------------------------------------------
# Route-completeness check (this IS the coverage gate for this group)
# ---------------------------------------------------------------------------


def test_group_covers_all_declared_routes(route_prefix_filter):
    """NOTE: route enumeration surfaced a genuine routing-collision finding
    while building this check — see TestRoutingCollisionFinding below.
    `GET /user/agents` is registered TWICE (user_agents.py AND user_ui.py);
    since both share the same (method, path) tuple they collapse into one
    entry in this set, so the collision does not affect the expected count."""
    declared = route_prefix_filter(*_GROUP_PREFIXES)
    declared_set = {(m, p) for (m, p, _r) in declared}
    assert len(declared_set) == 27, (
        f"Expected 27 declared routes under {_GROUP_PREFIXES}, found "
        f"{len(declared_set)}: {sorted(declared_set)}"
    )


# ---------------------------------------------------------------------------
# Auth-tier gating sweep — covers ALL 27 endpoints for (at minimum) the
# unauth-401 assertion, plus the wrong-plane/tier-mismatch 403 assertion.
# ---------------------------------------------------------------------------


class TestUnauthGatingSweep:
    @pytest.mark.parametrize(
        "method,path,body", _USER_AGENTS_ROUTES + _ME_ROUTES, ids=_ids(_USER_AGENTS_ROUTES + _ME_ROUTES)
    )
    # GAP-CLOSED: unauth 401 across all 27 declared routes
    def test_unauth_401(self, unauth_client, method, path, body):
        r = unauth_client.request(method, path, json=body)
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "authentication_required"


class TestWrongPlaneAndAdminTierMismatch:
    def test_plain_admin_client_401_not_403_on_user_route(self, admin_client):
        """Documents actual behaviour (see module docstring): admin_client
        (admin cookie only, matching real RISK-100 login behaviour) gets 401
        authentication_required, NOT 403, on a /user/* route — there is no
        user cookie present at all for require_user_session to inspect."""
        r = admin_client.get("/user/agents")
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "authentication_required"

    @pytest.mark.parametrize("method,path,body", _USER_AGENTS_ROUTES, ids=_ids(_USER_AGENTS_ROUTES))
    # GAP-CLOSED: 403 wrong_plane for an admin-tier session presented via the
    # user cookie, across all 24 user_agents.py endpoints.
    def test_wrong_plane_403_via_user_cookie(
        self, admin_session_via_user_cookie_client, method, path, body
    ):
        r = admin_session_via_user_cookie_client.request(method, path, json=body)
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "wrong_plane"

    @pytest.mark.parametrize("method,path,body", _ME_ROUTES, ids=_ids(_ME_ROUTES))
    # GAP-CLOSED: 403 user_tier_required for admin_client (AnySession-gated
    # me.py routes), across all 3 me.py endpoints.
    def test_me_admin_tier_mismatch_403(self, admin_client, method, path, body):
        r = admin_client.request(method, path, json=body)
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "user_tier_required"


class TestMethodNotAllowedSpotChecks:
    # Routing-level 405 — fires before any dependency/auth resolution, so an
    # unauthenticated client is sufficient to prove the assertion.
    def test_put_user_agents_405(self, unauth_client):
        assert unauth_client.put("/user/agents", json={}).status_code == 405

    def test_get_me_api_key_405(self, unauth_client):
        assert unauth_client.get("/me/api-key").status_code == 405

    def test_delete_user_skills_405(self, unauth_client):
        assert unauth_client.delete("/user/skills").status_code == 405

    def test_patch_user_mentions_405(self, unauth_client):
        assert unauth_client.patch("/user/mentions").status_code == 405


# ---------------------------------------------------------------------------
# REAL FINDING: routing collision between user_agents.py and user_ui.py
# ---------------------------------------------------------------------------


class TestRoutingCollisionFinding:
    """SPEC-CONFORMANCE / REAL FINDING, discovered via route enumeration
    while building this group's coverage-completeness check (not a bug in
    THIS group's file — flagged here because it surfaced on my prefix walk,
    routed to whoever owns user_ui.py):

    user_ui.py:384 registers a SECOND `GET /user/agents` route with a
    completely different response shape (system-wide agent_registry view:
    agent_id/protocol/status/groups) to user_agents.py:481's user-owned
    agent CRUD list (ua_id/alias/personality/effective_skills). Both routers
    are included in create_backoffice_app() — app.py:1620
    `app.include_router(_user_agents_router, ...)` BEFORE app.py:1627
    `app.include_router(user_ui_router, ...)`. Starlette dispatches to the
    FIRST matching route in registration order, so user_agents.py's handler
    wins and user_ui.py:384-420 (`user_list_agents`) is DEAD CODE —
    unreachable for any real request at this exact path. Pinned here as a
    regression-catcher: if router registration order ever changes, this
    test starts failing (wrong response shape) instead of silently starting
    to serve the registry view under the user-agent-CRUD URL.
    """

    def test_get_user_agents_dispatches_to_user_agents_py_not_user_ui_py(
        self, user_client, identity_registry_state
    ):
        created = user_client.post("/user/agents", json={"name": "Shape Check"}).json()
        r = user_client.get("/user/agents")
        assert r.status_code == 200
        agent_view = next(a for a in r.json()["agents"] if a["ua_id"] == created["ua_id"])
        assert "ua_id" in agent_view
        assert "alias" in agent_view
        assert "personality" in agent_view
        assert "agent_id" not in agent_view
        assert "protocol" not in agent_view


# ---------------------------------------------------------------------------
# /user/agents — CRUD lifecycle + IDOR/BOLA regression
# ---------------------------------------------------------------------------


class TestUserAgentCrudAndBola:
    # GAP-CLOSED: GET/POST /user/agents ; GET/PATCH/DELETE /user/agents/{ua_id}
    def test_create_list_get_patch_delete_lifecycle(self, user_client, identity_registry_state):
        r = user_client.post("/user/agents", json={"name": "Research Bot", "kind": "agent"})
        assert r.status_code == 201
        body = r.json()
        ua_id = body["ua_id"]
        assert body["alias"] == "research_bot"

        r2 = user_client.get("/user/agents")
        assert r2.status_code == 200
        assert any(a["ua_id"] == ua_id for a in r2.json()["agents"])

        r3 = user_client.get(f"/user/agents/{ua_id}")
        assert r3.status_code == 200
        assert r3.json()["name"] == "Research Bot"

        r4 = user_client.patch(f"/user/agents/{ua_id}", json={"name": "Renamed Bot"})
        assert r4.status_code == 200
        assert r4.json()["updated"] == ["name"]

        r5 = user_client.delete(f"/user/agents/{ua_id}")
        assert r5.status_code == 204

        r6 = user_client.get(f"/user/agents/{ua_id}")
        assert r6.status_code == 404
        assert r6.json()["detail"]["error"] == "not_found"

    def test_create_invalid_alias_422(self, user_client, identity_registry_state):
        r = user_client.post("/user/agents", json={"name": "x", "alias": "Not Valid!"})
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "invalid_alias"

    def test_create_duplicate_alias_409(self, user_client, identity_registry_state):
        user_client.post("/user/agents", json={"name": "Dup", "alias": "dup"})
        r = user_client.post("/user/agents", json={"name": "Dup2", "alias": "dup"})
        assert r.status_code == 409
        assert r.json()["detail"]["error"] == "alias_conflict"

    # GAP-CLOSED IDOR/BOLA: GET/PATCH/DELETE /user/agents/{ua_id}
    def test_idor_get_patch_delete(self, user_client, second_user_client, identity_registry_state):
        victim = user_client.post("/user/agents", json={"name": "Victim Agent"}).json()
        victim_ua_id = victim["ua_id"]

        r = second_user_client.get(f"/user/agents/{victim_ua_id}")
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "not_found"

        r2 = second_user_client.patch(f"/user/agents/{victim_ua_id}", json={"name": "pwned"})
        assert r2.status_code == 404

        r3 = second_user_client.delete(f"/user/agents/{victim_ua_id}")
        assert r3.status_code == 404

        # Resource must still exist and be untouched for the real owner —
        # proves the BOLA-rejected requests were true no-ops, not soft-fails.
        r4 = user_client.get(f"/user/agents/{victim_ua_id}")
        assert r4.status_code == 200
        assert r4.json()["name"] == "Victim Agent"

    # GAP-CLOSED IDOR/BOLA: GET/PUT /user/agents/{ua_id}/personality
    def test_idor_personality(self, user_client, second_user_client, identity_registry_state):
        ua_id = user_client.post("/user/agents", json={"name": "Persona Agent"}).json()["ua_id"]

        assert second_user_client.get(f"/user/agents/{ua_id}/personality").status_code == 404

        r = second_user_client.put(f"/user/agents/{ua_id}/personality", json={"persona": "pwned"})
        assert r.status_code == 404

        own = user_client.get(f"/user/agents/{ua_id}/personality")
        assert own.status_code == 200
        assert "pwned" not in own.json()["persona"]

    # GAP-CLOSED IDOR/BOLA: GET/PUT /user/agents/{ua_id}/skills
    def test_idor_skills(self, user_client, second_user_client, identity_registry_state):
        ua_id = user_client.post("/user/agents", json={"name": "Skill Agent"}).json()["ua_id"]

        assert second_user_client.get(f"/user/agents/{ua_id}/skills").status_code == 404
        assert second_user_client.put(
            f"/user/agents/{ua_id}/skills", json={"skills": ["pwned-skill"]}
        ).status_code == 404

        # Victim's declared skills unaffected by the attacker's attempted write.
        own = user_client.get(f"/user/agents/{ua_id}/skills")
        assert "pwned-skill" not in own.json()["declared_skills"]

    def test_skills_lifecycle_scope_intersection(self, user_client, identity_registry_state):
        """No agent_registry wired -> system_ceiling is empty -> any declared
        skill is rejected into rejected_skills, effective_skills stays empty
        (fail-closed intersection, R3/RISK-097 — see
        _compute_system_ceiling's `if registry is None: return set()`)."""
        ua_id = user_client.post("/user/agents", json={"name": "Skill Agent"}).json()["ua_id"]
        r = user_client.put(f"/user/agents/{ua_id}/skills", json={"skills": ["some-tool"]})
        assert r.status_code == 200
        assert r.json()["effective_skills"] == []
        assert r.json()["rejected_skills"] == ["some-tool"]

    # GAP-CLOSED IDOR/BOLA: GET /user/agents/{ua_id}/memories ;
    #                       POST/DELETE /user/agents/{ua_id}/memories/{block_id}
    def test_idor_memory_attach_detach(self, user_client, second_user_client, identity_registry_state):
        ua_id = user_client.post("/user/agents", json={"name": "Mem Agent"}).json()["ua_id"]
        block_id = user_client.post(
            "/user/memories", json={"label": "secret", "value": "v"}
        ).json()["block_id"]

        # Attacker cannot list victim's agent memories.
        assert second_user_client.get(f"/user/agents/{ua_id}/memories").status_code == 404

        # Attacker cannot attach the victim's block to the victim's own agent.
        assert (
            second_user_client.post(f"/user/agents/{ua_id}/memories/{block_id}").status_code == 404
        )

        # Attacker owns their OWN agent, but tries to attach the VICTIM's
        # block_id to it — proves block-ownership BOLA independently of
        # agent-ownership BOLA (both halves of _get_block_or_404 /
        # _get_agent_or_404 must hold).
        attacker_ua_id = second_user_client.post(
            "/user/agents", json={"name": "Attacker Agent"}
        ).json()["ua_id"]
        r = second_user_client.post(f"/user/agents/{attacker_ua_id}/memories/{block_id}")
        assert r.status_code == 404, (
            "attacker's own agent + victim's block_id must still 404 (block ownership BOLA)"
        )

        # Attacker cannot detach either.
        assert (
            second_user_client.delete(f"/user/agents/{ua_id}/memories/{block_id}").status_code
            == 404
        )

        # Victim's attach/detach lifecycle still works normally.
        r2 = user_client.post(f"/user/agents/{ua_id}/memories/{block_id}")
        assert r2.status_code == 201
        r3 = user_client.get(f"/user/agents/{ua_id}/memories")
        assert any(b["block_id"] == block_id for b in r3.json()["memories"])
        r4 = user_client.delete(f"/user/agents/{ua_id}/memories/{block_id}")
        assert r4.status_code == 204


# ---------------------------------------------------------------------------
# /user/memories — CRUD lifecycle + IDOR/BOLA + SSTI-non-evaluation regression
# ---------------------------------------------------------------------------


class TestUserMemoriesCrudBolaAndSsti:
    # GAP-CLOSED: GET/POST /user/memories ; GET/PATCH/DELETE /user/memories/{block_id}
    def test_create_list_get_patch_delete_lifecycle(self, user_client, identity_registry_state):
        r = user_client.post("/user/memories", json={"label": "note", "value": "hello"})
        assert r.status_code == 201
        block_id = r.json()["block_id"]

        r2 = user_client.get("/user/memories")
        assert any(b["block_id"] == block_id for b in r2.json()["memories"])

        r3 = user_client.get(f"/user/memories/{block_id}")
        assert r3.status_code == 200
        assert r3.json()["value"] == "hello"

        r4 = user_client.patch(f"/user/memories/{block_id}", json={"value": "updated"})
        assert r4.status_code == 200

        r5 = user_client.delete(f"/user/memories/{block_id}")
        assert r5.status_code == 204

        r6 = user_client.get(f"/user/memories/{block_id}")
        assert r6.status_code == 404

    # GAP-CLOSED IDOR/BOLA: GET/PATCH/DELETE /user/memories/{block_id}
    def test_idor_get_patch_delete(self, user_client, second_user_client, identity_registry_state):
        block_id = user_client.post(
            "/user/memories", json={"label": "secret", "value": "v"}
        ).json()["block_id"]

        assert second_user_client.get(f"/user/memories/{block_id}").status_code == 404
        r = second_user_client.patch(f"/user/memories/{block_id}", json={"value": "pwned"})
        assert r.status_code == 404
        assert second_user_client.delete(f"/user/memories/{block_id}").status_code == 404

        own = user_client.get(f"/user/memories/{block_id}")
        assert own.status_code == 200
        assert own.json()["value"] == "v"

    # GAP-CLOSED (regression, Laura live red-team PoC): SSTI probe non-evaluation
    def test_ssti_probe_stored_verbatim_never_evaluated(self, user_client, identity_registry_state):
        """{{7*7}} in memory content must round-trip as the LITERAL string —
        never evaluated to "49". This route does no template rendering of
        user-supplied content (plain Redis hash store/read); confirms no
        Jinja2/SSTI surface exists on the memory-value path."""
        probe = "{{7*7}}"
        r = user_client.post("/user/memories", json={"label": "ssti-probe", "value": probe})
        assert r.status_code == 201
        block_id = r.json()["block_id"]

        r2 = user_client.get(f"/user/memories/{block_id}")
        assert r2.status_code == 200
        assert r2.json()["value"] == probe, "SSTI probe must round-trip verbatim"
        assert r2.json()["value"] != "49"

        # Also round-trip through PATCH to prove the update path never evaluates either.
        r3 = user_client.patch(f"/user/memories/{block_id}", json={"value": "{{1+1}}"})
        assert r3.status_code == 200
        r4 = user_client.get(f"/user/memories/{block_id}")
        assert r4.json()["value"] == "{{1+1}}"


# ---------------------------------------------------------------------------
# /user/agents/{ua_id}/graph — persistence + IDOR/BOLA
# ---------------------------------------------------------------------------


class TestGraphPersistenceBola:
    _VALID_GRAPH: ClassVar[dict] = {
        "nodes": [
            {"id": "n1", "node_type": "input_node", "label": "in"},
            {"id": "n2", "node_type": "output_node", "label": "out"},
        ],
        "edges": [{"source_node_id": "n1", "target_node_id": "n2", "label": ""}],
    }

    # GAP-CLOSED: PUT/GET /user/agents/{ua_id}/graph
    def test_save_and_load_lifecycle(self, user_client, identity_registry_state, mock_audit_writer):
        ua_id = user_client.post("/user/agents", json={"name": "Graph Agent"}).json()["ua_id"]
        r = user_client.put(f"/user/agents/{ua_id}/graph", json={"graph": self._VALID_GRAPH})
        assert r.status_code == 200
        assert r.json()["node_count"] == 2
        assert r.json()["edge_count"] == 1
        mock_audit_writer.write.assert_called_once()

        r2 = user_client.get(f"/user/agents/{ua_id}/graph")
        assert r2.status_code == 200
        assert r2.json()["graph_hash"] == r.json()["graph_hash"]

    def test_save_invalid_graph_422(self, user_client, identity_registry_state):
        """Missing the required exactly-one-input_node/output_node
        constraints (V-001/V-002)."""
        ua_id = user_client.post("/user/agents", json={"name": "Bad Graph Agent"}).json()["ua_id"]
        r = user_client.put(f"/user/agents/{ua_id}/graph", json={"graph": {"nodes": [], "edges": []}})
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "graph_validation_failed"

    def test_load_no_graph_saved_yet(self, user_client, identity_registry_state):
        ua_id = user_client.post("/user/agents", json={"name": "Empty Graph Agent"}).json()["ua_id"]
        r = user_client.get(f"/user/agents/{ua_id}/graph")
        assert r.status_code == 200
        assert r.json()["graph"] is None

    # GAP-CLOSED IDOR/BOLA: GET/PUT /user/agents/{ua_id}/graph
    def test_idor(self, user_client, second_user_client, identity_registry_state):
        ua_id = user_client.post("/user/agents", json={"name": "Victim Graph Agent"}).json()["ua_id"]
        user_client.put(f"/user/agents/{ua_id}/graph", json={"graph": self._VALID_GRAPH})

        r = second_user_client.get(f"/user/agents/{ua_id}/graph")
        assert r.status_code == 404

        r2 = second_user_client.put(f"/user/agents/{ua_id}/graph", json={"graph": self._VALID_GRAPH})
        assert r2.status_code == 404


# ---------------------------------------------------------------------------
# /user/agents/{ua_id}/run — NHI instantiation
# ---------------------------------------------------------------------------


class TestRunUserAgent:
    # GAP-CLOSED: POST /user/agents/{ua_id}/run
    def test_run_without_registry_503(self, user_client, identity_registry_state):
        ua_id = user_client.post("/user/agents", json={"name": "Runner"}).json()["ua_id"]
        r = user_client.post(f"/user/agents/{ua_id}/run")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "registry_unavailable"

    # GAP-CLOSED IDOR/BOLA: POST /user/agents/{ua_id}/run
    def test_run_cross_user_404(self, user_client, second_user_client, identity_registry_state):
        ua_id = user_client.post("/user/agents", json={"name": "Victim Runner"}).json()["ua_id"]
        r = second_user_client.post(f"/user/agents/{ua_id}/run")
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "not_found"


# ---------------------------------------------------------------------------
# /user/agents/generate and /user/agents/templates — no-code backend
# ---------------------------------------------------------------------------


class TestGenerateAndCommitTemplate:
    # GAP-CLOSED: POST /user/agents/generate
    def test_generate_offline_gateway_unreachable_502(self, user_client, identity_registry_state):
        """Offline-environment reality: YASHIGANI_GATEWAY_MESH_URL defaults
        to http://gateway:8081/v1 (user_agents.py:1944), unreachable in this
        offline suite. YASHIGANI_INTERNAL_BEARER IS set (conftest.py), so the
        route does not take the 503 llm_gateway_not_configured branch;
        instead the real httpx POST fails to connect and the documented
        fail-closed contract is 502 llm_gateway_unreachable
        (user_agents.py:1970-1978) — same proven pattern as
        test_budget_models_inspection.py's Ollama-unreachable assertion."""
        r = user_client.post("/user/agents/generate", json={"description": "1234567890"})
        assert r.status_code == 502
        assert r.json()["detail"]["error"] == "llm_gateway_unreachable"

    # GAP-CLOSED: POST /user/agents/templates
    def test_commit_unknown_draft_404(self, user_client, identity_registry_state):
        r = user_client.post(
            "/user/agents/templates", json={"draft_id": "udrft_doesnotexist0", "name": "y"}
        )
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "draft_not_found"

    # GAP-CLOSED IDOR/BOLA: POST /user/agents/templates
    def test_commit_cross_user_draft_404(
        self, user_client, second_user_client, identity_registry_state, fake_redis_client
    ):
        """IDOR/BOLA regression: seed a draft owned by userA directly (the
        real POST /user/agents/generate path requires live Langflow/gateway
        LLM access, unavailable offline — see test above) then attempt
        commit as userB."""
        draft_id = "udrft_victimseed01"
        fake_redis_client.hset(
            f"ua:draft:{draft_id}",
            mapping={
                "account_id": "conformance-userA",
                "flow_id": "flow123",
                "flow_name": "n",
                "summary": "s",
                "spec_hash": "sha384:x",
                "spec_json": "{}",
                "created_at": "now",
            },
        )
        r = second_user_client.post(
            "/user/agents/templates", json={"draft_id": draft_id, "name": "stolen"}
        )
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "draft_not_found"

        # Draft must still be consumable by its real owner afterwards.
        r2 = user_client.post(
            "/user/agents/templates", json={"draft_id": draft_id, "name": "Mine"}
        )
        assert r2.status_code == 201


# ---------------------------------------------------------------------------
# /user/skills and /user/mentions
# ---------------------------------------------------------------------------


class TestSkillsCatalogAndMentions:
    # GAP-CLOSED: GET /user/skills
    def test_skills_degraded_empty(self, user_client, identity_registry_state):
        r = user_client.get("/user/skills")
        assert r.status_code == 200
        assert r.json() == {"available_skills": [], "count": 0}

    # GAP-CLOSED: GET /user/mentions
    def test_mentions_scoped_to_own_agents(
        self, user_client, second_user_client, identity_registry_state
    ):
        """BOLA: user_client's own agent must appear as a mention for
        user_client but NEVER for second_user_client (kind:"agent" is
        BOLA-scoped to the caller's ua:agents:{account_id} set per
        user_agents.py:1413-1416)."""
        user_client.post("/user/agents", json={"name": "My Agent"})

        own = user_client.get("/user/mentions")
        assert own.status_code == 200
        assert any(m["handle"] == "my_agent" for m in own.json()["mentions"])

        other = second_user_client.get("/user/mentions")
        assert other.status_code == 200
        assert not any(m["handle"] == "my_agent" for m in other.json()["mentions"])


# ---------------------------------------------------------------------------
# /me/api-key, /me/api-keys — self-service Bearer issuance
# ---------------------------------------------------------------------------


class TestMeApiKeyLifecycle:
    # GAP-CLOSED: POST /me/api-key requires fresh step-up
    def test_issue_requires_stepup(self, user_client, me_state):
        r = user_client.post("/me/api-key")
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    # GAP-CLOSED: POST /me/api-key ; GET /me/api-keys ; DELETE /me/api-keys/{key_id}
    def test_issue_list_revoke_full_lifecycle(self, stepup_user_client, me_state, fake_redis_client):
        identity_id = _register_account(
            me_state, fake_redis_client, "conformance-userA-stepup", "userA-stepup"
        )
        r = stepup_user_client.post("/me/api-key")
        assert r.status_code == 200
        body = r.json()
        assert body["shown_once"] is True
        assert len(body["plaintext_token"]) > 10

        r2 = stepup_user_client.get("/me/api-keys")
        assert r2.status_code == 200
        keys = r2.json()["api_keys"]
        assert len(keys) == 1
        assert "plaintext_token" not in keys[0]
        assert keys[0]["key_id"] == identity_id

        r3 = stepup_user_client.delete(f"/me/api-keys/{identity_id}")
        assert r3.status_code == 204

        r4 = stepup_user_client.delete(f"/me/api-keys/{identity_id}")
        assert r4.status_code == 404
        assert r4.json()["detail"]["error"] == "key_not_found"

    def test_revoke_cross_user_key_id_rejected(
        self, stepup_user_client, second_user_client, me_state, fake_redis_client
    ):
        """SPEC-CONFORMANCE (divergence note, not softened): unlike
        user_agents.py's strict 404-only BOLA pattern, revoke_api_key()
        resolves the CALLER'S OWN identity by slug (me.py:350-355) — it
        never looks the URL key_id up directly — then compares
        key_id != own_identity_id -> 403 key_not_owned_by_caller
        (me.py:358-365), not 404. This does not leak resource existence:
        the 'resource' here is 1:1 bound to the caller's own identity, so
        the caller already knows their own identity_id and 403 discloses
        nothing new about the victim's key. Pinned as the real, documented
        contract."""
        victim_id = _register_account(
            me_state, fake_redis_client, "conformance-userA-stepup", "userA-stepup"
        )
        # Attacker needs their OWN registered identity too, else
        # identity_not_found (404) fires before the ownership comparison.
        _register_account(me_state, fake_redis_client, "conformance-userB", "userB-attacker")

        r = second_user_client.delete(f"/me/api-keys/{victim_id}")
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "key_not_owned_by_caller"

    def test_list_no_identity_yet_empty(self, stepup_user_client, me_state):
        """Account exists (auth_service resolves it) but no identity has been
        registered yet for its slug -> registry.get_by_slug() returns None
        -> empty list, not an error (me.py:294-297)."""
        from yashigani.auth.local_auth import AccountRecord

        _registry, auth_svc = me_state
        auth_svc.register(
            AccountRecord(
                account_id="conformance-userA-stepup",
                username="userA-stepup",
                password_hash="x",
                totp_secret="x",
                recovery_codes=None,
                account_tier="user",
                email=None,
                force_password_change=False,
                force_totp_provision=False,
            )
        )
        r = stepup_user_client.get("/me/api-keys")
        assert r.status_code == 200
        assert r.json() == {"api_keys": []}
