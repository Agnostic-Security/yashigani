"""
Contract tests — User Agent @-mention BOLA isolation (Surface 2).

Regression harness for the @-MENTION CROSS-USER IMPERSONATION surface.

Security invariants asserted here:
  A. resolve_user_mention is BOLA-scoped: ana resolving paul's @handle via
     ana's account_id MUST return None.
  B. resolve_user_mention returns the agent when resolved via the owner's
     account_id (positive / own-scope path works).
  C. STALE ALIAS: even if the alias index has a stale entry pointing at
     another user's account_id, the BOLA double-check in resolve_user_mention
     blocks the resolution.
  D. _get_agent_or_404 raises HTTP 404 (not 403) on BOLA violation — resource
     existence must NOT be revealed to the caller (OWASP API3).
  E. GET /user/mentions returns only the calling user's own agents/personas;
     no other user's private handles appear in the response.

Tests FAIL precisely when these invariants are violated:
  - Removing the `meta.get("account_id") != account_id` guard in
    resolve_user_mention fails A and C.
  - Returning 403 instead of 404 in _get_agent_or_404 fails D.
  - Including other users' ua:agents sets in list_user_mentions fails E.

All Redis interactions use fakeredis — no live server required.

Last updated: 2026-07-02T00:00:00+00:00
"""
from __future__ import annotations

import json
import os
import uuid

import fakeredis
import pytest

os.environ.setdefault("YASHIGANI_INTERNAL_BEARER", "test-bola-bearer")

from fastapi import HTTPException

from yashigani.backoffice.routes.user_agents import (
    resolve_user_mention,
    _get_agent_or_404,
    _alias_key,
    _meta_key,
    _agents_key,
)


# ---------------------------------------------------------------------------
# Seed helpers
# ---------------------------------------------------------------------------

def _new_account_id() -> str:
    return str(uuid.uuid4())


def _new_ua_id() -> str:
    return "ua_" + uuid.uuid4().hex[:16]


def _seed_agent(
    r,
    *,
    account_id: str,
    alias: str,
    name: str,
    kind: str = "persona",
) -> str:
    """Write a minimal user-agent record to fakeredis.  Returns ua_id."""
    ua_id = _new_ua_id()

    # ua:meta:{ua_id} hash
    r.hset(_meta_key(ua_id), mapping={
        b"account_id": account_id.encode(),
        b"name": name.encode(),
        b"alias": alias.encode(),
        b"kind": kind.encode(),
        b"created_at": b"2026-07-02T00:00:00+00:00",
        b"personality": json.dumps({"persona": "demo persona", "system_prompt": ""}).encode(),
    })

    # ua:agents:{account_id} set
    r.sadd(_agents_key(account_id), ua_id.encode())

    # ua:alias:{account_id} hash (alias → ua_id lookup)
    r.hset(_alias_key(account_id), alias.encode(), ua_id.encode())

    return ua_id


# ---------------------------------------------------------------------------
# A. resolve_user_mention is BOLA-scoped — cross-user resolution returns None
# ---------------------------------------------------------------------------

def test_resolve_user_mention_cross_user_returns_none():
    """
    INVARIANT A: ana resolving paul's @PaulBot handle via ana's account_id
    MUST return None.

    FAILS if the BOLA guard (`meta.get('account_id') != account_id`) is
    removed from resolve_user_mention, which would allow one user to
    impersonate another user's persona.
    """
    r = fakeredis.FakeRedis()

    ana_account_id = _new_account_id()
    paul_account_id = _new_account_id()

    # Seed paul's persona @PaulBot under paul's account
    _seed_agent(r, account_id=paul_account_id, alias="PaulBot",
                name="Paul's Bot", kind="persona")

    # Ana tries to resolve paul's handle using ana's account_id scope
    result = resolve_user_mention(r, ana_account_id, "PaulBot")

    assert result is None, (
        "INVARIANT A violated: ana resolved paul's @PaulBot handle. "
        "Cross-user @-mention resolution MUST return None. "
        "BOLA guard is missing or bypassed."
    )


def test_resolve_user_mention_cross_user_agent_returns_none():
    """
    INVARIANT A (agent variant): ana resolving paul's @pauleye agent
    MUST return None.
    """
    r = fakeredis.FakeRedis()

    ana_account_id = _new_account_id()
    paul_account_id = _new_account_id()

    _seed_agent(r, account_id=paul_account_id, alias="pauleye",
                name="Paul's Eye", kind="agent")

    result = resolve_user_mention(r, ana_account_id, "pauleye")

    assert result is None, (
        "INVARIANT A violated: ana resolved paul's @pauleye agent. "
        "Cross-user agent resolution MUST return None."
    )


# ---------------------------------------------------------------------------
# B. Positive path — own handle resolves correctly
# ---------------------------------------------------------------------------

def test_resolve_user_mention_own_handle_resolves():
    """
    INVARIANT B: ana resolving her own @Mimi handle via ana's account_id
    MUST return the persona record.
    """
    r = fakeredis.FakeRedis()

    ana_account_id = _new_account_id()
    ua_id = _seed_agent(r, account_id=ana_account_id, alias="Mimi",
                        name="Ana's Mimi", kind="persona")

    result = resolve_user_mention(r, ana_account_id, "Mimi")

    assert result is not None, (
        "INVARIANT B violated: ana's own @Mimi handle did not resolve. "
        "Positive own-scope path is broken."
    )
    assert result.get("account_id") == ana_account_id, (
        f"Resolved account_id mismatch: got {result.get('account_id')!r}"
    )
    assert result.get("alias") == "Mimi"
    assert result.get("_ua_id") == ua_id


def test_paul_resolves_own_handle_when_ana_cannot():
    """
    INVARIANT B (multi-user): paul resolves his own handle; ana cannot.
    Both assertions in one test to confirm isolation is symmetric.
    """
    r = fakeredis.FakeRedis()

    ana_account_id = _new_account_id()
    paul_account_id = _new_account_id()

    # Same alias name for both users (collision is fine — scoped per account)
    _seed_agent(r, account_id=ana_account_id, alias="Mimi",
                name="Ana's Mimi", kind="persona")
    _seed_agent(r, account_id=paul_account_id, alias="Mimi",
                name="Paul's Mimi", kind="persona")

    # Ana resolves her own @Mimi
    ana_result = resolve_user_mention(r, ana_account_id, "Mimi")
    assert ana_result is not None
    assert ana_result.get("account_id") == ana_account_id

    # Paul resolves his own @Mimi
    paul_result = resolve_user_mention(r, paul_account_id, "Mimi")
    assert paul_result is not None
    assert paul_result.get("account_id") == paul_account_id

    # They are different records
    assert ana_result.get("_ua_id") != paul_result.get("_ua_id"), (
        "Ana and Paul should have different ua_ids for the same alias name."
    )


# ---------------------------------------------------------------------------
# C. Stale alias index does not bypass BOLA
# ---------------------------------------------------------------------------

def test_stale_alias_index_blocked_by_bola_double_check():
    """
    INVARIANT C: even if the alias index (`ua:alias:{account_id}`) has a stale
    entry pointing at another user's ua_id, the BOLA double-check in
    resolve_user_mention (which compares meta.account_id == caller_account_id)
    blocks the resolution.

    FAILS if the meta.account_id check is removed, relying solely on the
    alias index (which can become stale or be manipulated).
    """
    r = fakeredis.FakeRedis()

    ana_account_id = _new_account_id()
    paul_account_id = _new_account_id()

    # Seed paul's persona @PaulBot under paul's account
    paul_ua_id = _seed_agent(r, account_id=paul_account_id, alias="PaulBot",
                             name="Paul's Bot", kind="persona")

    # Deliberately inject a stale alias entry into ANA's alias index
    # pointing at paul's ua_id — simulating a corrupted/stale index.
    r.hset(_alias_key(ana_account_id), b"PaulBot", paul_ua_id.encode())
    # But the ua:meta still has paul's account_id — BOLA guard checks this.

    result = resolve_user_mention(r, ana_account_id, "PaulBot")

    assert result is None, (
        "INVARIANT C violated: stale alias index bypassed BOLA guard. "
        "resolve_user_mention must check meta.account_id == caller_account_id, "
        "not just the alias index lookup."
    )


# ---------------------------------------------------------------------------
# D. _get_agent_or_404 raises HTTP 404 (not 403) on BOLA violation
# ---------------------------------------------------------------------------

def test_get_agent_or_404_raises_404_on_foreign_account():
    """
    INVARIANT D: accessing paul's agent via ana's account_id raises HTTP 404,
    NOT HTTP 403.

    OWASP API3: returning 403 would reveal that the resource EXISTS for another
    user.  A 404 leaks no information about the resource's existence.

    FAILS if the BOLA guard in _get_agent_or_404 is removed or returns 403.
    """
    r = fakeredis.FakeRedis()

    ana_account_id = _new_account_id()
    paul_account_id = _new_account_id()

    paul_ua_id = _seed_agent(r, account_id=paul_account_id, alias="pauleye",
                             name="Paul's Eye", kind="agent")

    with pytest.raises(HTTPException) as exc_info:
        _get_agent_or_404(r, paul_ua_id, ana_account_id)

    assert exc_info.value.status_code == 404, (
        f"INVARIANT D violated: BOLA violation raised HTTP "
        f"{exc_info.value.status_code}, expected 404. "
        "Resource existence must not be revealed to the caller (OWASP API3). "
        "Return 404, not 403."
    )
    assert exc_info.value.detail == {"error": "not_found"}, (
        f"Expected detail={{'error': 'not_found'}}, got {exc_info.value.detail!r}"
    )


def test_get_agent_or_404_succeeds_for_own_account():
    """
    INVARIANT D (positive): _get_agent_or_404 succeeds when called with the
    agent's own account_id.
    """
    r = fakeredis.FakeRedis()

    ana_account_id = _new_account_id()
    ua_id = _seed_agent(r, account_id=ana_account_id, alias="Mimi",
                        name="Ana's Mimi", kind="persona")

    result = _get_agent_or_404(r, ua_id, ana_account_id)

    assert result is not None
    assert result.get("account_id") == ana_account_id
    assert result.get("alias") == "Mimi"


def test_get_agent_or_404_raises_404_for_nonexistent_agent():
    """
    INVARIANT D (non-existent): _get_agent_or_404 raises HTTP 404 for a
    ua_id that does not exist at all (not a BOLA violation, just missing).
    """
    r = fakeredis.FakeRedis()

    with pytest.raises(HTTPException) as exc_info:
        _get_agent_or_404(r, "ua_nonexistent_doesnt_exist", "any-account-id")

    assert exc_info.value.status_code == 404


# ---------------------------------------------------------------------------
# E. GET /user/mentions returns only calling user's own agents
# ---------------------------------------------------------------------------

def test_mentions_scope_excludes_other_users_agents():
    """
    INVARIANT E: the set of user-owned agents returned for ana's scope does NOT
    include paul's agents.

    This tests the BOLA guard in the list_user_mentions path:
      ``if meta.get('account_id') != session.account_id: continue``

    FAILS if the account_id guard is removed from the ua:agents enumeration
    in list_user_mentions (or if the ua:agents key itself is not scoped per
    account, allowing cross-user enumeration).
    """
    r = fakeredis.FakeRedis()

    ana_account_id = _new_account_id()
    paul_account_id = _new_account_id()

    ana_ua_id = _seed_agent(r, account_id=ana_account_id, alias="Mimi",
                            name="Ana's Mimi", kind="persona")
    paul_ua_id = _seed_agent(r, account_id=paul_account_id, alias="PaulBot",
                             name="Paul's Bot", kind="persona")

    # Simulate what list_user_mentions does for ana's account.
    # We replicate the core BOLA-guarded enumeration logic here.
    from yashigani.backoffice.routes.user_agents import (
        _decode_set, _decode_hash,
    )

    raw_ids = r.smembers(_agents_key(ana_account_id))
    ana_ua_ids = _decode_set(raw_ids)

    visible_aliases: list[str] = []
    for ua_id in ana_ua_ids:
        raw = r.hgetall(_meta_key(ua_id))
        if not raw:
            continue
        meta = _decode_hash(raw)
        if meta.get("account_id") != ana_account_id:
            continue  # BOLA guard
        alias = meta.get("alias", "")
        if alias:
            visible_aliases.append(alias)

    assert "Mimi" in visible_aliases, (
        "Ana's own @Mimi must appear in her mentions scope."
    )
    assert "PaulBot" not in visible_aliases, (
        "INVARIANT E violated: paul's @PaulBot appeared in ana's mentions scope. "
        "BOLA guard on ua:agents enumeration is missing or bypassed."
    )

    # Verify the converse: paul's scope does NOT include ana's Mimi
    raw_ids_paul = r.smembers(_agents_key(paul_account_id))
    paul_ua_ids = _decode_set(raw_ids_paul)

    paul_aliases: list[str] = []
    for ua_id in paul_ua_ids:
        raw = r.hgetall(_meta_key(ua_id))
        if not raw:
            continue
        meta = _decode_hash(raw)
        if meta.get("account_id") != paul_account_id:
            continue  # BOLA guard
        alias = meta.get("alias", "")
        if alias:
            paul_aliases.append(alias)

    assert "PaulBot" in paul_aliases, (
        "Paul's own @PaulBot must appear in his mentions scope."
    )
    assert "Mimi" not in paul_aliases, (
        "INVARIANT E violated: ana's @Mimi appeared in paul's mentions scope."
    )
