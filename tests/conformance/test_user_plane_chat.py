"""
Conformance group: USER-PLANE-CHAT.

Closes G1 (Lu audit YCS-20260723-v4.1.2-CONFORMANCE) for:
  routes/user_conversations.py   (6 endpoints)  — /user/conversations*
  routes/user_workflows.py       (8 endpoints)  — /user/workflows*
  routes/user_ui.py             (10 endpoints)  — /chat, /agents, /builder,
                                                   /workflows, /user/agents,
                                                   /user/budget, /user/models,
                                                   /user/memory,
                                                   /user/documents,
                                                   /user/chat/completions
Total: 24 endpoints (Lu matrix rows 315-338).

PRIORITY (closes Lu's explicitly-named G3 gap, matrix row 317): Lu flagged
``GET /user/conversations/{conv_id}`` cross-user IDOR as "unconfirmed"
because the harness never seeded a conversation. This suite seeds a REAL
conversation as userA (via the real POST /user/conversations round-trip
against the fake Postgres pool below) then attempts the read as userB
(``second_user_client``) — see ``TestUserConversationsLifecycleAndIdor``.

Convention: see tests/conformance/conftest.py module docstring.

MOCKED dependencies (no fakeredis/live equivalent available offline):
  - user_conversations.py is Postgres-only (``yashigani.db.postgres.get_pool()``,
    an asyncpg ``Pool``). ``_FakeConversationsPool``/``_FakeConversationsConn``
    below implement only ``acquire()``/``transaction()``/``fetch()``/
    ``fetchrow()``/``fetchval()``/``execute()`` — the exact surface
    user_conversations.py calls (verified by reading the route file
    2026-07-23) — dispatching on distinguishing substrings of each route's
    literal SQL text, with an in-memory dict standing in for the tables.
  - user_workflows.py's ``_get_redis()`` (imported from user_agents.py)
    resolves its Redis db/3 client via
    ``backoffice_state.identity_registry._r`` — NOT a dedicated redis_client
    field on BackofficeState. ``identity_registry_state`` wires the REAL
    ``IdentityRegistry`` (accepts ``redis_client`` directly — identity/registry.py:152)
    against fakeredis so both the workflow BOLA-scoped hash/set operations
    AND user_ui.py's identity-resolution paths (user_budget/user_models/
    user_chat_proxy) share one real, fakeredis-backed store.
  - ``/user/workflows/{id}/runs*`` uses a SEPARATE live ``rediss://`` connection
    to db/6 (``yashigani.gateway.workflow_scheduler`` via ``redis.from_url`` +
    ``.ping()``, not fakeredis-injectable) — ``wf_redis_unreachable`` monkeypatches
    ``redis.from_url`` to raise ``ConnectionError`` immediately, mirroring the
    proven Ollama-unreachable pattern in test_budget_models_inspection.py, so
    the documented fail-closed 503 ``scheduler_unavailable`` contract is
    exercised deterministically rather than depending on DNS/network timing.
  - ``generate_workflow`` and ``user_chat_proxy`` make REAL httpx calls to the
    governed gateway mesh (default ``http://gateway:8081/v1``), unreachable
    offline — their documented fail-closed 502/degraded-SSE contracts are
    exercised as genuine behaviour, not stubbed.

Last updated: 2026-07-23T00:00:00+00:00
"""
from __future__ import annotations

import datetime
import json
import uuid

import pytest

from yashigani.backoffice.middleware import _USER_SESSION_COOKIE

pytestmark = pytest.mark.conformance

# ---------------------------------------------------------------------------
# Exact (method, path) set this group owns — used as the coverage gate
# instead of prefix-filtering, because several of this group's paths
# (/chat, /agents, /builder, /workflows) are bare top-level paths that a
# naive prefix filter could ambiguously collide with other groups' routes.
# ---------------------------------------------------------------------------

_MY_ROUTES: set[tuple[str, str]] = {
    ("GET", "/user/conversations"),
    ("POST", "/user/conversations"),
    ("GET", "/user/conversations/{conv_id}"),
    ("PATCH", "/user/conversations/{conv_id}"),
    ("DELETE", "/user/conversations/{conv_id}"),
    ("POST", "/user/conversations/{conv_id}/messages"),
    ("POST", "/user/workflows/generate"),
    ("POST", "/user/workflows"),
    ("GET", "/user/workflows"),
    ("GET", "/user/workflows/{wf_id}"),
    ("PATCH", "/user/workflows/{wf_id}"),
    ("DELETE", "/user/workflows/{wf_id}"),
    ("GET", "/user/workflows/{workflow_id}/runs"),
    ("GET", "/user/workflows/{workflow_id}/runs/{run_id}"),
    ("GET", "/chat"),
    ("GET", "/agents"),
    ("GET", "/builder"),
    ("GET", "/workflows"),
    ("GET", "/user/agents"),
    ("GET", "/user/budget"),
    ("GET", "/user/models"),
    ("GET", "/user/memory"),
    ("POST", "/user/documents"),
    ("POST", "/user/chat/completions"),
}


def test_group_covers_all_declared_routes(declared_routes):
    found = {(m, p) for (m, p, _r) in declared_routes if (m, p) in _MY_ROUTES}
    assert found == _MY_ROUTES, (
        f"Live route walk vs _MY_ROUTES mismatch — Lu's matrix or this file "
        f"is stale. Missing from live walk: {_MY_ROUTES - found}"
    )
    assert len(_MY_ROUTES) == 24


# ---------------------------------------------------------------------------
# Local fixtures — candidates for promotion to conftest.py noted inline.
# ---------------------------------------------------------------------------


@pytest.fixture
def admin_client_with_user_cookie(admin_client):
    """Mirrors REAL login behaviour: an admin login sets BOTH the admin AND
    user session cookies to the SAME token (see middleware.py
    require_user_session docstring + user_ui.py:308-311 comment). The shared
    `admin_client` fixture only sets the admin cookie, which under-tests the
    wrong_plane SoD control on require_user_session-gated routes (with only
    the admin cookie set, the user-plane dependency sees NO user cookie at
    all and 401s, not 403 — a materially different assertion than the real
    attack surface). CANDIDATE FOR PROMOTION to conftest.py — likely needed
    by every other user-plane conformance group for the same reason."""
    admin_client.cookies.set(_USER_SESSION_COOKIE, admin_client.conformance_session.token)
    return admin_client


class _FakeTransactionCM:
    async def __aenter__(self):
        return None

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _FakeAcquireCM:
    def __init__(self, conn: _FakeConversationsConn) -> None:
        self._conn = conn

    async def __aenter__(self) -> _FakeConversationsConn:
        return self._conn

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _FakeConversationsConn:
    """MOCKED asyncpg connection — see module docstring. Dispatches on
    distinguishing substrings of the literal SQL text used by each route in
    user_conversations.py (verified against that file 2026-07-23)."""

    def __init__(self) -> None:
        self.conversations: dict[uuid.UUID, dict] = {}
        self.messages: dict[uuid.UUID, list[dict]] = {}

    def transaction(self) -> _FakeTransactionCM:
        return _FakeTransactionCM()

    async def fetch(self, query: str, *args):
        if "ORDER BY updated_at DESC" in query:
            (account_id,) = args
            rows = [c for c in self.conversations.values() if c["account_id"] == account_id]
            rows.sort(key=lambda c: c["updated_at"], reverse=True)
            return [dict(r) for r in rows]
        if "FROM messages" in query:
            (cid,) = args
            msgs = self.messages.get(cid, [])
            return [dict(m) for m in sorted(msgs, key=lambda m: m["created_at"])]
        raise AssertionError(f"unmatched fetch query: {query!r}")

    async def fetchrow(self, query: str, *args):
        if "INSERT INTO conversations" in query:
            account_id, title = args
            cid = uuid.uuid4()
            now = datetime.datetime.now(datetime.UTC)
            self.conversations[cid] = {
                "id": cid,
                "account_id": account_id,
                "title": title,
                "created_at": now,
                "updated_at": now,
            }
            return {"id": cid}
        if "created_at, updated_at" in query and "FROM conversations" in query:
            cid, account_id = args
            conv = self.conversations.get(cid)
            if conv and conv["account_id"] == account_id:
                return dict(conv)
            return None
        if "UPDATE conversations" in query and "SET title" in query:
            title, cid, account_id = args
            conv = self.conversations.get(cid)
            if conv and conv["account_id"] == account_id:
                conv["title"] = title
                conv["updated_at"] = datetime.datetime.now(datetime.UTC)
                return {"id": cid}
            return None
        if "DELETE FROM conversations" in query:
            cid, account_id = args
            conv = self.conversations.get(cid)
            if conv and conv["account_id"] == account_id:
                del self.conversations[cid]
                self.messages.pop(cid, None)
                return {"id": cid}
            return None
        if "INSERT INTO messages" in query:
            cid, role, content, model, token_count, verdict_json = args
            mid = uuid.uuid4()
            now = datetime.datetime.now(datetime.UTC)
            self.messages.setdefault(cid, []).append(
                {
                    "id": mid,
                    "role": role,
                    "content": content,
                    "model": model,
                    "created_at": now,
                    "token_count": token_count,
                    "verdict": json.loads(verdict_json) if verdict_json else None,
                }
            )
            return {"id": mid}
        raise AssertionError(f"unmatched fetchrow query: {query!r}")

    async def fetchval(self, query: str, *args):
        # Only call site in user_conversations.py: append_messages BOLA check.
        cid, account_id = args
        conv = self.conversations.get(cid)
        if conv and conv["account_id"] == account_id:
            return conv["id"]
        return None

    async def execute(self, query: str, *args):
        if "UPDATE conversations SET updated_at" in query:
            (cid,) = args
            conv = self.conversations.get(cid)
            if conv:
                conv["updated_at"] = datetime.datetime.now(datetime.UTC)
        return "UPDATE 1"


class _FakeConversationsPool:
    def __init__(self) -> None:
        self.conn = _FakeConversationsConn()

    def acquire(self) -> _FakeAcquireCM:
        return _FakeAcquireCM(self.conn)


@pytest.fixture
def fake_pg_pool(monkeypatch):
    """MOCKED: user_conversations.py is Postgres-only — no fakeredis
    equivalent. ``get_pool()`` (src/yashigani/db/postgres.py:177-180) reads
    the module-level ``_pool`` global directly and raises RuntimeError
    (-> 503 db_unavailable, per ``_get_pool_or_503``) when it is None —
    monkeypatching that global is sufficient; no need to patch the function
    object itself."""
    pool = _FakeConversationsPool()
    monkeypatch.setattr("yashigani.db.postgres._pool", pool)
    return pool


@pytest.fixture
def identity_registry_state(fake_redis_client, monkeypatch):
    """Wires the REAL IdentityRegistry against fakeredis (constructor takes
    redis_client directly — src/yashigani/identity/registry.py:152). Needed
    by user_workflows.py's ``_get_redis()`` (imported from user_agents.py,
    which resolves its Redis db/3 client via
    ``backoffice_state.identity_registry._r`` rather than a dedicated field
    on BackofficeState) and by user_ui.py's identity-resolution paths."""
    from yashigani.backoffice.state import backoffice_state
    from yashigani.identity.registry import IdentityRegistry

    registry = IdentityRegistry(redis_client=fake_redis_client)
    monkeypatch.setattr(backoffice_state, "identity_registry", registry, raising=False)
    return registry


def _seed_identity(r, account_id: str, identity_id: str, slug: str = "usera") -> None:
    """Seed a minimal identity record + account_id link directly in Redis,
    bypassing IdentityRegistry.register()'s atomic Lua script (fakeredis
    EVAL support for that seat-limit script is unnecessary here — the routes
    under test only ever READ identity:reg/{slug,account} keys via
    .get()/.get_by_slug()/.get_by_account_id(), verified against
    identity/registry.py)."""
    r.hset(
        f"identity:reg:{identity_id}",
        mapping={"identity_id": identity_id, "kind": "human", "name": "Test User", "slug": slug},
    )
    r.set(f"identity:slug:{slug}", identity_id)
    r.set(f"identity:account:{account_id}", identity_id)


def _seed_draft(r, account_id: str, draft_id: str, spec: dict) -> None:
    """Seed a wf:draft hash directly, bypassing generate_workflow's governed
    LLM call (which requires a live gateway — see
    TestUserWorkflowsGenerate.test_generate_llm_gateway_unreachable_502 for
    the genuine offline-degrade assertion on that endpoint)."""
    r.hset(
        f"wf:draft:{draft_id}",
        mapping={
            "account_id": account_id,
            "description": "test workflow",
            "summary": "test",
            "spec": json.dumps(spec),
            "spec_hash": "sha384:test",
            "created_at": datetime.datetime.now(datetime.UTC).isoformat(),
        },
    )


@pytest.fixture
def wf_redis_unreachable(monkeypatch):
    """Offline-safe: monkeypatch redis.from_url so /user/workflows/*/runs*
    (a SEPARATE live rediss:// connection to db/6, not fakeredis) fails fast
    and deterministically rather than depending on DNS/network reachability
    of the default 'redis' hostname — mirrors the proven Ollama-unreachable
    monkeypatch pattern in test_budget_models_inspection.py."""
    import redis

    def _raise(*_a, **_kw):
        raise redis.exceptions.ConnectionError("no redis db/6 in offline conformance suite")

    monkeypatch.setattr(redis, "from_url", _raise)


# ===========================================================================
# user_conversations.py — 6 endpoints
# ===========================================================================


class TestUserConversationsAuthGating:
    # GAP-CLOSED: GET /user/conversations
    def test_list_unauth_401(self, unauth_client):
        r = unauth_client.get("/user/conversations")
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "authentication_required"

    def test_list_admin_wrong_plane_403(self, admin_client_with_user_cookie):
        r = admin_client_with_user_cookie.get("/user/conversations")
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "wrong_plane"

    # GAP-CLOSED: POST /user/conversations
    def test_create_unauth_401(self, unauth_client):
        assert unauth_client.post("/user/conversations", json={}).status_code == 401

    def test_create_admin_wrong_plane_403(self, admin_client_with_user_cookie):
        r = admin_client_with_user_cookie.post("/user/conversations", json={"title": "x"})
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "wrong_plane"

    # GAP-CLOSED: GET /user/conversations/{conv_id}
    def test_get_unauth_401(self, unauth_client):
        assert unauth_client.get(f"/user/conversations/{uuid.uuid4()}").status_code == 401

    def test_get_admin_wrong_plane_403(self, admin_client_with_user_cookie):
        r = admin_client_with_user_cookie.get(f"/user/conversations/{uuid.uuid4()}")
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "wrong_plane"

    # GAP-CLOSED: PATCH /user/conversations/{conv_id}
    def test_rename_unauth_401(self, unauth_client):
        r = unauth_client.patch(f"/user/conversations/{uuid.uuid4()}", json={"title": "x"})
        assert r.status_code == 401

    def test_rename_admin_wrong_plane_403(self, admin_client_with_user_cookie):
        r = admin_client_with_user_cookie.patch(
            f"/user/conversations/{uuid.uuid4()}", json={"title": "x"}
        )
        assert r.status_code == 403

    # GAP-CLOSED: DELETE /user/conversations/{conv_id}
    def test_delete_unauth_401(self, unauth_client):
        assert unauth_client.delete(f"/user/conversations/{uuid.uuid4()}").status_code == 401

    def test_delete_admin_wrong_plane_403(self, admin_client_with_user_cookie):
        r = admin_client_with_user_cookie.delete(f"/user/conversations/{uuid.uuid4()}")
        assert r.status_code == 403

    # GAP-CLOSED: POST /user/conversations/{conv_id}/messages
    def test_append_unauth_401(self, unauth_client):
        r = unauth_client.post(
            f"/user/conversations/{uuid.uuid4()}/messages", json={"messages": []}
        )
        assert r.status_code == 401

    def test_append_admin_wrong_plane_403(self, admin_client_with_user_cookie):
        r = admin_client_with_user_cookie.post(
            f"/user/conversations/{uuid.uuid4()}/messages",
            json={"messages": [{"role": "user", "content": "hi"}]},
        )
        assert r.status_code == 403


class TestUserConversationsWithoutPool:
    def test_list_without_pool_503(self, user_client):
        r = user_client.get("/user/conversations")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "db_unavailable"

    def test_create_without_pool_503(self, user_client):
        r = user_client.post("/user/conversations", json={"title": "x"})
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "db_unavailable"


class TestUserConversationsLifecycleAndIdor:
    def test_full_lifecycle(self, user_client, fake_pg_pool):
        r = user_client.post("/user/conversations", json={"title": "My chat"})
        assert r.status_code == 201
        conv_id = r.json()["id"]

        r = user_client.get("/user/conversations")
        assert r.status_code == 200
        assert any(c["id"] == conv_id for c in r.json()["conversations"])

        r = user_client.post(
            f"/user/conversations/{conv_id}/messages",
            json={
                "messages": [
                    {"role": "user", "content": "hi"},
                    {"role": "assistant", "content": "hello"},
                ]
            },
        )
        assert r.status_code == 201
        assert len(r.json()["ids"]) == 2

        r = user_client.get(f"/user/conversations/{conv_id}")
        assert r.status_code == 200
        body = r.json()
        assert body["title"] == "My chat"
        assert len(body["messages"]) == 2
        assert body["messages"][0]["role"] == "user"

        r = user_client.patch(f"/user/conversations/{conv_id}", json={"title": "Renamed"})
        assert r.status_code == 200
        assert r.json()["title"] == "Renamed"

        r = user_client.delete(f"/user/conversations/{conv_id}")
        assert r.status_code == 204

        r = user_client.get(f"/user/conversations/{conv_id}")
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "not_found"

    def test_get_nonexistent_404(self, user_client, fake_pg_pool):
        r = user_client.get(f"/user/conversations/{uuid.uuid4()}")
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "not_found"

    def test_get_malformed_id_422(self, user_client, fake_pg_pool):
        r = user_client.get("/user/conversations/not-a-uuid")
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "invalid_conversation_id"

    def test_append_to_nonexistent_conversation_404(self, user_client, fake_pg_pool):
        r = user_client.post(
            f"/user/conversations/{uuid.uuid4()}/messages",
            json={"messages": [{"role": "user", "content": "hi"}]},
        )
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "not_found"

    # ========================================================================
    # PRIORITY: closes Lu's explicitly-named G3 gap (YCS-20260723-v4.1.2-
    # CONFORMANCE, matrix row 317 — "harness never seeded a conversation, so
    # cross-user block on the conversation resource is unconfirmed").
    # ========================================================================

    def test_cross_user_idor_get_conversation_returns_404(
        self, user_client, second_user_client, fake_pg_pool
    ):
        """CLOSES Lu G3 gap. Seeds a REAL conversation as userA
        (user_client, account_id='conformance-userA') via the genuine POST
        /user/conversations round-trip, then attempts GET as userB
        (second_user_client, account_id='conformance-userB'). BOLA scoping
        in get_conversation() (user_conversations.py:184-189,
        `WHERE id=$1 AND account_id=$2`) must return 404 — not 200, not
        403 — so existence cannot be inferred (OWASP API3)."""
        r = user_client.post("/user/conversations", json={"title": "userA private chat"})
        assert r.status_code == 201
        conv_id = r.json()["id"]

        # Sanity: the owner CAN read their own conversation.
        r_owner = user_client.get(f"/user/conversations/{conv_id}")
        assert r_owner.status_code == 200

        # Attacker (userB) attempts cross-user read.
        r_attacker = second_user_client.get(f"/user/conversations/{conv_id}")
        assert r_attacker.status_code == 404, (
            "CRITICAL IDOR: cross-user GET /user/conversations/{conv_id} "
            f"returned {r_attacker.status_code}, expected 404. File: "
            "src/yashigani/backoffice/routes/user_conversations.py:169-230 "
            f"(conv_id={conv_id})"
        )
        assert r_attacker.json()["detail"]["error"] == "not_found"
        assert "userA private chat" not in r_attacker.text

    def test_cross_user_idor_rename_returns_404(self, user_client, second_user_client, fake_pg_pool):
        r = user_client.post("/user/conversations", json={"title": "userA chat 2"})
        conv_id = r.json()["id"]
        r2 = second_user_client.patch(f"/user/conversations/{conv_id}", json={"title": "pwned"})
        assert r2.status_code == 404, (
            f"CRITICAL IDOR: cross-user PATCH returned {r2.status_code}, expected 404."
        )
        # Confirm the title was NOT changed by the attacker.
        r3 = user_client.get(f"/user/conversations/{conv_id}")
        assert r3.json()["title"] == "userA chat 2"

    def test_cross_user_idor_delete_returns_404(self, user_client, second_user_client, fake_pg_pool):
        r = user_client.post("/user/conversations", json={"title": "userA chat 3"})
        conv_id = r.json()["id"]
        r2 = second_user_client.delete(f"/user/conversations/{conv_id}")
        assert r2.status_code == 404, (
            f"CRITICAL IDOR: cross-user DELETE returned {r2.status_code}, expected 404."
        )
        # Confirm the owner's conversation was NOT deleted by the attacker.
        r3 = user_client.get(f"/user/conversations/{conv_id}")
        assert r3.status_code == 200

    def test_cross_user_idor_append_messages_returns_404(
        self, user_client, second_user_client, fake_pg_pool
    ):
        r = user_client.post("/user/conversations", json={"title": "userA chat 4"})
        conv_id = r.json()["id"]
        r2 = second_user_client.post(
            f"/user/conversations/{conv_id}/messages",
            json={"messages": [{"role": "user", "content": "attacker injected message"}]},
        )
        assert r2.status_code == 404, (
            f"CRITICAL IDOR: cross-user POST messages returned {r2.status_code}, expected 404."
        )
        # Confirm no message was actually injected into userA's conversation.
        r3 = user_client.get(f"/user/conversations/{conv_id}")
        assert r3.json()["messages"] == []


# ===========================================================================
# user_workflows.py — 8 endpoints
# ===========================================================================


class TestUserWorkflowsAuthGating:
    # GAP-CLOSED: POST /user/workflows/generate
    def test_generate_unauth_401(self, unauth_client):
        r = unauth_client.post(
            "/user/workflows/generate", json={"description": "do something useful here"}
        )
        assert r.status_code == 401

    def test_generate_admin_wrong_plane_403(self, admin_client_with_user_cookie):
        r = admin_client_with_user_cookie.post(
            "/user/workflows/generate", json={"description": "do something useful here"}
        )
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "wrong_plane"

    # GAP-CLOSED: POST /user/workflows
    def test_commit_unauth_401(self, unauth_client):
        r = unauth_client.post(
            "/user/workflows", json={"draft_id": "x", "name": "y", "description": ""}
        )
        assert r.status_code == 401

    def test_commit_admin_wrong_plane_403(self, admin_client_with_user_cookie):
        r = admin_client_with_user_cookie.post(
            "/user/workflows", json={"draft_id": "x", "name": "y", "description": ""}
        )
        assert r.status_code == 403

    # GAP-CLOSED: GET /user/workflows
    def test_list_unauth_401(self, unauth_client):
        assert unauth_client.get("/user/workflows").status_code == 401

    def test_list_admin_wrong_plane_403(self, admin_client_with_user_cookie):
        r = admin_client_with_user_cookie.get("/user/workflows")
        assert r.status_code == 403

    # GAP-CLOSED: GET /user/workflows/{wf_id}
    def test_get_unauth_401(self, unauth_client):
        assert unauth_client.get("/user/workflows/wfl_x").status_code == 401

    def test_get_admin_wrong_plane_403(self, admin_client_with_user_cookie):
        r = admin_client_with_user_cookie.get("/user/workflows/wfl_x")
        assert r.status_code == 403

    # GAP-CLOSED: PATCH /user/workflows/{wf_id}
    def test_patch_unauth_401(self, unauth_client):
        assert unauth_client.patch("/user/workflows/wfl_x", json={}).status_code == 401

    def test_patch_admin_wrong_plane_403(self, admin_client_with_user_cookie):
        r = admin_client_with_user_cookie.patch("/user/workflows/wfl_x", json={"enabled": False})
        assert r.status_code == 403

    # GAP-CLOSED: DELETE /user/workflows/{wf_id}
    def test_delete_unauth_401(self, unauth_client):
        assert unauth_client.delete("/user/workflows/wfl_x").status_code == 401

    def test_delete_admin_wrong_plane_403(self, admin_client_with_user_cookie):
        r = admin_client_with_user_cookie.delete("/user/workflows/wfl_x")
        assert r.status_code == 403

    # GAP-CLOSED: GET /user/workflows/{workflow_id}/runs
    def test_runs_unauth_401(self, unauth_client):
        assert unauth_client.get("/user/workflows/wfl_x/runs").status_code == 401

    def test_runs_admin_wrong_plane_403(self, admin_client_with_user_cookie):
        r = admin_client_with_user_cookie.get("/user/workflows/wfl_x/runs")
        assert r.status_code == 403

    # GAP-CLOSED: GET /user/workflows/{workflow_id}/runs/{run_id}
    def test_run_detail_unauth_401(self, unauth_client):
        assert unauth_client.get("/user/workflows/wfl_x/runs/run_1").status_code == 401

    def test_run_detail_admin_wrong_plane_403(self, admin_client_with_user_cookie):
        r = admin_client_with_user_cookie.get("/user/workflows/wfl_x/runs/run_1")
        assert r.status_code == 403


class TestUserWorkflowsGenerate:
    def test_generate_llm_gateway_unreachable_502(self, user_client, identity_registry_state):
        """Offline-environment reality: generate_workflow() makes a REAL
        httpx call to the governed gateway mesh (user_agents.py
        _call_governed_gateway_llm -> YASHIGANI_GATEWAY_MESH_URL, default
        http://gateway:8081/v1) with no mock hook — unreachable in this
        offline suite. Documented fail-closed contract: 502
        llm_gateway_unreachable (user_agents.py:1970-1978), mirroring the
        proven Ollama-unreachable pattern in test_budget_models_inspection.py."""
        r = user_client.post(
            "/user/workflows/generate",
            json={"description": "Every 10 minutes fetch data and post it somewhere"},
        )
        assert r.status_code == 502
        assert r.json()["detail"]["error"] == "llm_gateway_unreachable"


class TestUserWorkflowsLifecycle:
    def test_commit_list_get_patch_delete_lifecycle(
        self, user_client, identity_registry_state, fake_redis_client
    ):
        account_id = user_client.conformance_session.account_id
        draft_id = "wfd_test1234"
        _seed_draft(
            fake_redis_client,
            account_id,
            draft_id,
            spec={
                "steps": [{"actor": "agentA", "action": "do the thing", "uses": [], "output_to": None}],
                "schedule": {"kind": "none", "seconds": None, "cron": None},
            },
        )

        r = user_client.post(
            "/user/workflows",
            json={"draft_id": draft_id, "name": "My workflow", "description": "test"},
        )
        assert r.status_code == 201
        wf_id = r.json()["workflow_id"]
        assert r.json()["spec"]["steps"][0]["actor"] == "agentA"

        # Commit consumes the draft — a second commit of the same draft_id must 404.
        r_dup = user_client.post(
            "/user/workflows", json={"draft_id": draft_id, "name": "dup", "description": ""}
        )
        assert r_dup.status_code == 404
        assert r_dup.json()["detail"]["error"] == "draft_not_found"

        r = user_client.get("/user/workflows")
        assert r.status_code == 200
        assert any(w["workflow_id"] == wf_id for w in r.json()["workflows"])
        assert "spec" not in r.json()["workflows"][0]  # list is compact

        r = user_client.get(f"/user/workflows/{wf_id}")
        assert r.status_code == 200
        assert r.json()["spec"]["steps"][0]["actor"] == "agentA"

        r = user_client.patch(f"/user/workflows/{wf_id}", json={"enabled": False})
        assert r.status_code == 200
        assert "enabled" in r.json()["updated"]
        r2 = user_client.get(f"/user/workflows/{wf_id}")
        assert r2.json()["enabled"] is False

        r = user_client.delete(f"/user/workflows/{wf_id}")
        assert r.status_code == 204
        r3 = user_client.get(f"/user/workflows/{wf_id}")
        assert r3.status_code == 404
        assert r3.json()["detail"]["error"] == "not_found"

    def test_get_nonexistent_404(self, user_client, identity_registry_state):
        r = user_client.get("/user/workflows/wfl_does_not_exist")
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "not_found"

    def test_commit_missing_draft_404(self, user_client, identity_registry_state):
        r = user_client.post(
            "/user/workflows", json={"draft_id": "wfd_missing", "name": "x", "description": ""}
        )
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "draft_not_found"

    def test_cross_user_idor_commit_stolen_draft_404(
        self, user_client, second_user_client, identity_registry_state, fake_redis_client
    ):
        """BOLA bonus: a draft created for userA cannot be committed by
        userB even if userB learns the draft_id (wf:draft account_id check,
        user_workflows.py:163-181)."""
        account_a = user_client.conformance_session.account_id
        draft_id = "wfd_stolen0001"
        _seed_draft(
            fake_redis_client, account_a, draft_id, spec={"steps": [], "schedule": {"kind": "none"}}
        )
        r = second_user_client.post(
            "/user/workflows", json={"draft_id": draft_id, "name": "stolen", "description": ""}
        )
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "draft_not_found"

    def test_cross_user_idor_workflow_get_patch_delete_404(
        self, user_client, second_user_client, identity_registry_state, fake_redis_client
    ):
        """BOLA bonus for GET/PATCH/DELETE /user/workflows/{wf_id}."""
        account_a = user_client.conformance_session.account_id
        draft_id = "wfd_test5678"
        _seed_draft(
            fake_redis_client,
            account_a,
            draft_id,
            spec={"steps": [{"actor": "a", "action": "b", "uses": [], "output_to": None}], "schedule": {"kind": "none"}},
        )
        r = user_client.post(
            "/user/workflows", json={"draft_id": draft_id, "name": "wf", "description": ""}
        )
        wf_id = r.json()["workflow_id"]

        r2 = second_user_client.get(f"/user/workflows/{wf_id}")
        assert r2.status_code == 404

        r3 = second_user_client.patch(f"/user/workflows/{wf_id}", json={"name": "pwned"})
        assert r3.status_code == 404

        r4 = second_user_client.delete(f"/user/workflows/{wf_id}")
        assert r4.status_code == 404

        # Confirm the owner's workflow survives the attempted attacker delete.
        r5 = user_client.get(f"/user/workflows/{wf_id}")
        assert r5.status_code == 200


class TestUserWorkflowsRuns:
    def test_runs_scheduler_unavailable_503(self, user_client, wf_redis_unreachable):
        r = user_client.get("/user/workflows/wfl_x/runs")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "scheduler_unavailable"

    def test_run_detail_scheduler_unavailable_503(self, user_client, wf_redis_unreachable):
        r = user_client.get("/user/workflows/wfl_x/runs/run_1")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "scheduler_unavailable"

    def test_runs_invalid_limit_422(self, user_client):
        r = user_client.get("/user/workflows/wfl_x/runs", params={"limit": 0})
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "invalid_limit"

    def test_runs_limit_too_high_422(self, user_client):
        r = user_client.get("/user/workflows/wfl_x/runs", params={"limit": 101})
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "invalid_limit"


# ===========================================================================
# user_ui.py — 10 endpoints
# ===========================================================================


class TestUserUIPages:
    """/chat, /agents, /builder, /workflows are NOT gated by
    require_user_session directly — they check ONLY cookie PRESENCE
    (user_ui.py:313-317, 346-348, 358-360, 374-376) and redirect (302)
    rather than 401 when absent.

    SPEC DIVERGENCE (real finding): Lu's audit matrix scored these PARTIAL,
    expecting a 401/403 auth-gating assertion; the actual contract is a 302
    redirect for a missing cookie and NO server-side tier check at the page
    layer at all — a session token belonging to an admin, if present under
    the user cookie name (real login behaviour per user_ui.py:308-311
    docstring), still renders 200 at the page layer; the SoD boundary is
    enforced only at the FIRST subsequent API call (403 wrong_plane), not
    at page-serve time. This suite pins the REAL behaviour rather than the
    expected-but-incorrect 401/403.
    """

    # GAP-CLOSED: GET /chat
    def test_chat_no_cookie_redirects_302(self, unauth_client):
        r = unauth_client.get("/chat", follow_redirects=False)
        assert r.status_code == 302
        assert r.headers["location"] == "/login?next=/chat"

    def test_chat_user_session_renders_200(self, user_client):
        r = user_client.get("/chat", follow_redirects=False)
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]

    def test_chat_admin_cookie_under_user_name_still_renders_200(
        self, admin_client_with_user_cookie
    ):
        """Documents the divergence: page-layer has NO tier check — an
        admin session token set under the user cookie name renders 200, not
        403. See class docstring."""
        r = admin_client_with_user_cookie.get("/chat", follow_redirects=False)
        assert r.status_code == 200

    # GAP-CLOSED: GET /agents
    def test_agents_no_cookie_redirects_302(self, unauth_client):
        r = unauth_client.get("/agents", follow_redirects=False)
        assert r.status_code == 302
        assert r.headers["location"] == "/login?next=/agents"

    def test_agents_user_session_renders_200(self, user_client):
        r = user_client.get("/agents", follow_redirects=False)
        assert r.status_code == 200

    # GAP-CLOSED: GET /builder
    def test_builder_no_cookie_redirects_302(self, unauth_client):
        r = unauth_client.get("/builder", follow_redirects=False)
        assert r.status_code == 302
        assert r.headers["location"] == "/login?next=/builder"

    def test_builder_user_session_renders_200(self, user_client):
        r = user_client.get("/builder", follow_redirects=False)
        assert r.status_code == 200

    # GAP-CLOSED: GET /workflows
    def test_workflows_page_no_cookie_redirects_302(self, unauth_client):
        r = unauth_client.get("/workflows", follow_redirects=False)
        assert r.status_code == 302
        assert r.headers["location"] == "/login?next=/workflows"

    def test_workflows_page_user_session_renders_200(self, user_client):
        r = user_client.get("/workflows", follow_redirects=False)
        assert r.status_code == 200


class TestUserAgentsListEndpoint:
    # GAP-CLOSED: GET /user/agents
    #
    # CRITICAL ROUTING COLLISION (real finding, not a test bug): TWO
    # different routers both declare ``@router.get("/user/agents")`` —
    # user_agents.py:481 (``list_user_agents`` — the caller's OWN
    # Redis-backed user-created agents) AND user_ui.py:384
    # (``user_list_agents`` — SYSTEM-WIDE registry agents, degrades to
    # ``{"agents": []}`` when ``agent_registry`` is None). app.py registers
    # ``_user_agents_router`` (app.py:1620) BEFORE ``user_ui_router``
    # (app.py:1627); Starlette matches routes in registration order, so
    # user_agents.py:481 wins EVERY request — user_ui.py:384-419's handler
    # is unreachable dead code. Verified empirically: without an identity
    # registry wired this path returns 503 registry_unavailable (from
    # user_agents.py's ``_get_redis()``), NEVER user_ui.py's documented
    # ``{"agents": []}`` degrade. This suite pins the REAL (shadowed)
    # behaviour; the shadowing itself should be raised with Maxine/the
    # USER-PLANE-AGENTS group owner as a P1 product bug (two semantically
    # different "list my agents" contracts silently collapsed to one).
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/user/agents").status_code == 401

    def test_admin_wrong_plane_403(self, admin_client_with_user_cookie):
        r = admin_client_with_user_cookie.get("/user/agents")
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "wrong_plane"

    def test_user_without_identity_registry_503_shadowed_by_user_agents_py(self, user_client):
        """Proves user_ui.py:384's ``{"agents": []}`` degrade path is
        UNREACHABLE — the live response is user_agents.py:481's
        ``_get_redis()`` 503, not user_ui.py's documented contract."""
        r = user_client.get("/user/agents")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "registry_unavailable"

    def test_user_with_identity_registry_degrades_empty(
        self, user_client, identity_registry_state
    ):
        """With identity_registry wired (so user_agents.py's _get_redis()
        succeeds), the caller has no user-created agents -> {"agents": []}
        — same SHAPE as user_ui.py's degrade, but via the OTHER
        implementation's empty-set path, not user_ui.py's None-registry
        branch."""
        r = user_client.get("/user/agents")
        assert r.status_code == 200
        assert r.json() == {"agents": []}


class TestUserBudget:
    # GAP-CLOSED: GET /user/budget
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/user/budget").status_code == 401

    def test_admin_wrong_plane_403(self, admin_client_with_user_cookie):
        r = admin_client_with_user_cookie.get("/user/budget")
        assert r.status_code == 403

    def test_user_always_unconfigured_dead_identity_resolution(
        self, user_client, identity_registry_state, fake_redis_client
    ):
        """SPEC DIVERGENCE (real finding, user_ui.py:441-449): identity
        resolution reads ``getattr(session, 'email', None)`` but
        ``yashigani.auth.session.Session`` (session.py:22-32) has NO
        ``email`` field, and nothing sets one dynamically anywhere in
        src/yashigani/{backoffice,auth}/ (grepped 2026-07-23) — so
        ``account_email`` is always '' and the slug lookup on line 445
        never executes. This endpoint is dead code past the getattr line:
        it ALWAYS returns configured=False/identity_id=None regardless of
        whether the caller has a linked identity or budget config — even
        with a fully wired identity_registry + a seeded identity link, as
        exercised here. Pinning the REAL (permanently-degraded) behaviour."""
        account_id = user_client.conformance_session.account_id
        _seed_identity(fake_redis_client, account_id, "idnt_budgettest01")
        r = user_client.get("/user/budget")
        assert r.status_code == 200
        assert r.json() == {
            "configured": False,
            "identity_id": None,
            "providers": [],
            "note": "Budget enforcement not configured for this deployment.",
        }


class TestUserModels:
    # GAP-CLOSED: GET /user/models
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/user/models").status_code == 401

    def test_admin_wrong_plane_403(self, admin_client_with_user_cookie):
        r = admin_client_with_user_cookie.get("/user/models")
        assert r.status_code == 403

    def test_user_degrades_empty_without_stores(self, user_client):
        r = user_client.get("/user/models")
        assert r.status_code == 200
        assert r.json() == {"models": [], "agents": []}


class TestUserMemory:
    # GAP-CLOSED: GET /user/memory
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/user/memory").status_code == 401

    def test_admin_wrong_plane_403(self, admin_client_with_user_cookie):
        r = admin_client_with_user_cookie.get("/user/memory")
        assert r.status_code == 403

    def test_user_phase3_stub_honest_501(self, user_client):
        """YSG-RISK-156 CLOSED: /user/memory (per-user Letta memory, Phase 3
        / RISK-107) was a plain 200 with `entries: []` + a "not yet
        configured" note — a caller checking only the HTTP status would
        read that as "success, zero entries", not "not built yet". Deferred
        past 4.1.2 (needs the Phase-3 NHI/SVID mesh + per-user Letta
        container) — now an honest 501. See
        test_tom_ysg_risk_156_157_honest_stub_endpoints.py."""
        r = user_client.get("/user/memory")
        assert r.status_code == 501
        assert r.json()["detail"]["error"] == "not_implemented"


class TestUserDocumentsUpload:
    # GAP-CLOSED: POST /user/documents
    def test_unauth_401(self, unauth_client):
        assert unauth_client.post("/user/documents", json={}).status_code == 401

    def test_admin_wrong_plane_403(self, admin_client_with_user_cookie):
        r = admin_client_with_user_cookie.post(
            "/user/documents",
            json={"filename": "a.txt", "content_type": "text/plain", "content_base64": "aGk="},
        )
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "wrong_plane"

    def test_user_enforcement_disabled_409(self, user_client):
        """Offline-safe + spec-conformance: is_document_enforcement_enabled()
        reads YASHIGANI_DOCUMENT_ENFORCEMENT_ENABLED, default/unconfigured
        offline is 'false' -> 409 document_enforcement_disabled
        (user_ui.py:655-662) — genuine documented contract, not a stub."""
        r = user_client.post(
            "/user/documents",
            json={"filename": "a.txt", "content_type": "text/plain", "content_base64": "aGk="},
        )
        assert r.status_code == 409
        assert r.json()["detail"]["error"] == "document_enforcement_disabled"

    def test_user_invalid_route_422(self, user_client):
        r = user_client.post(
            "/user/documents",
            json={
                "filename": "a.txt",
                "content_type": "text/plain",
                "content_base64": "aGk=",
                "route": "bogus-route",
            },
        )
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "invalid_route"

    def test_user_invalid_pseudonymize_mode_422(self, user_client):
        r = user_client.post(
            "/user/documents",
            json={
                "filename": "a.txt",
                "content_type": "text/plain",
                "content_base64": "aGk=",
                "pseudonymize_mode": "Z",
            },
        )
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "invalid_pseudonymize_mode"

    def test_path_traversal_filename_rejected_422(self, user_client, monkeypatch):
        """RISK-112 / CWE-22 guard — real assertion, not a stub. Enforcement
        must be enabled to reach past the 409 gate to this guard."""
        monkeypatch.setenv("YASHIGANI_DOCUMENT_ENFORCEMENT_ENABLED", "true")
        r = user_client.post(
            "/user/documents",
            json={
                "filename": "../../etc/passwd",
                "content_type": "text/plain",
                "content_base64": "aGk=",
            },
        )
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "invalid_filename"

    def test_oversized_upload_rejected_413(self, user_client, monkeypatch):
        monkeypatch.setenv("YASHIGANI_DOCUMENT_ENFORCEMENT_ENABLED", "true")
        monkeypatch.setenv("YASHIGANI_USER_UPLOAD_MAX_MB", "1")
        oversized_b64 = "A" * 1_400_000  # well past the 1 MB * 4/3 pre-check limit
        r = user_client.post(
            "/user/documents",
            json={"filename": "big.txt", "content_type": "text/plain", "content_base64": oversized_b64},
        )
        assert r.status_code == 413
        assert r.json()["detail"]["error"] == "file_too_large"

    def test_unsupported_mime_rejected_422(self, user_client, monkeypatch):
        monkeypatch.setenv("YASHIGANI_DOCUMENT_ENFORCEMENT_ENABLED", "true")
        r = user_client.post(
            "/user/documents",
            json={
                "filename": "a.exe",
                "content_type": "application/x-msdownload",
                "content_base64": "aGk=",
            },
        )
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "unsupported_content_type"


class TestUserChatProxy:
    # GAP-CLOSED: POST /user/chat/completions
    # Already covered by Ava's live e2e per the dispatch brief — still
    # assert the full auth/identity fail-closed chain here for automated
    # regression coverage independent of the live e2e run.
    def test_unauth_401(self, unauth_client):
        assert unauth_client.post("/user/chat/completions", json={}).status_code == 401

    def test_admin_wrong_plane_403(self, admin_client_with_user_cookie):
        r = admin_client_with_user_cookie.post("/user/chat/completions", json={})
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "wrong_plane"

    def test_user_no_identity_registry_503(self, user_client):
        """Fail-closed (user_ui.py:924-940): identity_registry unwired ->
        503 identity_registry_unavailable, never silently proceeds without
        a resolvable identity_id."""
        r = user_client.post(
            "/user/chat/completions", json={"model": "fast", "messages": []}
        )
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "identity_registry_unavailable"

    def test_user_unlinked_identity_403(self, user_client, identity_registry_state):
        """identity_registry wired but this account_id has never logged in
        (no identity:account:{id} link) -> fail-closed 403
        identity_not_found (user_ui.py:958-974) — NOT a silent proceed with
        the raw account UUID (the original FIND-4.0-CHAT-001 residual)."""
        r = user_client.post(
            "/user/chat/completions", json={"model": "fast", "messages": []}
        )
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "identity_not_found"

    def test_user_linked_identity_gateway_unreachable_real_503(
        self, user_client, identity_registry_state, fake_redis_client
    ):
        """Past all auth/identity guards: streams from
        YASHIGANI_GATEWAY_MESH_URL (default http://gateway:8081/v1),
        unreachable offline.

        2026-07-31 (Tom, YTF Tier-A truly-green gate): RISK-167 (chat-path
        repair, 2026-07-30, user_ui.py:1019-1046) deliberately REMOVED the
        masked-200-SSE degrade contract this test used to assert. The
        pre-fix proxy ALWAYS returned StreamingResponse(...) — which
        Starlette commits as HTTP 200 — even when the upstream never
        answered at all; every real failure (agent-dispatch 502/500,
        PII-block 403, model-unavailable 503, and this ConnectError case)
        reached the browser as status=200, silently defeating sse.js's own
        resp.ok pre-stream branch. The fix (this head) opens the upstream
        connection and inspects its REAL status/exception BEFORE deciding
        how to respond: httpx.ConnectError is now caught OUTSIDE the SSE
        generator and returned as a genuine JSONResponse(503), never
        wrapped in a fake SSE frame behind a 200. This test now asserts
        that real, non-masked contract instead of the one RISK-167 fixed."""
        account_id = user_client.conformance_session.account_id
        _seed_identity(fake_redis_client, account_id, "idnt_chattest0001")
        r = user_client.post(
            "/user/chat/completions",
            json={"model": "fast", "messages": [{"role": "user", "content": "hi"}]},
        )
        assert r.status_code == 503
        assert r.headers["content-type"].startswith("application/json")
        assert r.json()["error"]["code"] == "gateway_unreachable"


# ===========================================================================
# Spec-conformance: method-not-allowed (undeclared method on a declared path)
# ===========================================================================


class TestMethodNotAllowed:
    def test_conversations_put_405(self, unauth_client):
        r = unauth_client.put("/user/conversations", json={})
        assert r.status_code == 405

    def test_workflows_put_405(self, unauth_client):
        r = unauth_client.put("/user/workflows", json={})
        assert r.status_code == 405

    def test_user_budget_post_405(self, unauth_client):
        r = unauth_client.post("/user/budget", json={})
        assert r.status_code == 405
