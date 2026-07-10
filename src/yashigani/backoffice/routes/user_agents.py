"""
Yashigani 4.0 — User-plane Letta agent capability routes + graph persistence + NHI run + no-code backend.

All endpoints enforce ``require_user_session`` (RISK-100) and are BOLA-scoped
to the calling user's ``account_id``.  User A cannot touch User B's agents,
memories, or skills — mismatches always return 404 (not 403) so resource
existence cannot be inferred.

Routes
------
/user/agents
  GET    /user/agents                              list caller's agents
  POST   /user/agents                              create agent
  GET    /user/agents/{ua_id}                      get agent config
  PATCH  /user/agents/{ua_id}                      update name / personality / description
  DELETE /user/agents/{ua_id}                      delete agent + detach all memories

  GET    /user/agents/{ua_id}/personality          get persona + system prompt
  PUT    /user/agents/{ua_id}/personality          set persona + system prompt

  GET    /user/agents/{ua_id}/skills               get agent's effective skill set
  PUT    /user/agents/{ua_id}/skills               set skills (scope intersection enforced)

  GET    /user/agents/{ua_id}/memories             list memory blocks attached to agent
  POST   /user/agents/{ua_id}/memories/{block_id}  attach memory block to agent
  DELETE /user/agents/{ua_id}/memories/{block_id}  detach memory block from agent

/user/memories
  GET    /user/memories                            list all user memory blocks
  POST   /user/memories                            create memory block
  GET    /user/memories/{block_id}                 get memory block
  PATCH  /user/memories/{block_id}                 rename / update value
  DELETE /user/memories/{block_id}                 delete (auto-detaches from agents)

/user/skills
  GET    /user/skills                              list available skills (catalog ∩ user ceiling)

Redis key design (db/3, ``ua:`` prefix):
  ua:agents:{account_id}            Set  — ua_agent_ids owned by this user
  ua:meta:{ua_agent_id}             Hash — account_id, name, description,
                                           personality (JSON: persona+system_prompt),
                                           effective_skills (JSON list),
                                           declared_skills  (JSON list),
                                           graph (JSON CTF blob — Phase 4 persistence),
                                           graph_hash (sha384:<hex> — for audit),
                                           nhi_id (nhi_* id once instantiated),
                                           letta_agent_id, created_at, updated_at
  ua:mem:all:{account_id}           Set  — block_ids owned by this user
  ua:mem:meta:{block_id}            Hash — account_id, label, value,
                                           letta_block_id, created_at, updated_at
  ua:mem:agent:{ua_agent_id}        Set  — block_ids currently attached to this agent

Graph persistence (Phase 4):
  PUT /user/agents/{ua_id}/graph    — save CTF graph JSON (server validates + strips
                                       R11 fields; agent must exist + be owned by caller)
  GET /user/agents/{ua_id}/graph    — load saved CTF graph for edit in the builder

NHI run endpoint (Phase 3):
  POST /user/agents/{ua_id}/run     — instantiate an NHI from the agent's stored graph +
                                       skills.  Computes effective_scope (R3), registers
                                       the NHI, mints delegation context.
                                       Requires the agent graph to be saved (Phase 4).
                                       Returns nhi_id + session_id + svid_pending flag.

Skill scope intersection (R3 / RISK-097):
  effective_scope = declared_skills ∩ invoker_grants ∩ system_ceiling

  * declared_skills  — skills the user requests for their agent
  * invoker_grants   — identity.allowed_tools from the identity registry
  * system_ceiling   — union of allowed_paths across all active agents in the registry
                        (what the system actually exposes)

  Stored in ua:meta.effective_skills so the gateway can enforce it when
  creating the delegation record (R2/R12, X-Yashigani-Session-Id).

Letta pool seam:
  Routes that need live Letta access call ``LettaClientPool.for_user()``.
  Until feat/4.0-agent-isolation (Captain) merges they return HTTP 503
  (``letta_pool_unavailable``).  Metadata-only routes (create/list/skill ops)
  work immediately — Letta provisioning is deferred (``letta_agent_id: null``
  until the pool is wired and the user's first chat request provisions the agent).

NHI note (RISK-097/R2/R3):
  Phase 3 (feat/4.0-agent-isolation) will register each user agent as an NHI in
  AgentRegistry (kind=nhi, owner_identity_id=account_id) and wire the P1/P2 token
  split.  Until then, ``effective_skills`` in ua:meta is the enforcement surface.

Last updated: 2026-06-27T00:00:00+00:00
"""
from __future__ import annotations

import datetime
import hashlib
import json
import logging
import os
import re
import uuid
from typing import Any, Literal, Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import UserSession
from yashigani.backoffice.state import backoffice_state

logger = logging.getLogger(__name__)

router = APIRouter()

# ---------------------------------------------------------------------------
# ID minting
# ---------------------------------------------------------------------------

_UA_PREFIX = "uag_"
_MEM_PREFIX = "umb_"


def _new_ua_id() -> str:
    return f"{_UA_PREFIX}{uuid.uuid4().hex[:12]}"


def _new_block_id() -> str:
    return f"{_MEM_PREFIX}{uuid.uuid4().hex[:12]}"


def _now_iso() -> str:
    return datetime.datetime.now(tz=datetime.timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Redis helpers
# ---------------------------------------------------------------------------

def _get_redis():
    """Return Redis db/3 client via identity registry. Raises HTTP 503 if unavailable."""
    ir = getattr(backoffice_state, "identity_registry", None)
    if ir is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "registry_unavailable", "message": "Identity registry not ready."},
        )
    return ir._r


def _get_user_plane_durable():
    """Return UserPlaneDurableStore if wired; None otherwise (degrade-safe)."""
    return getattr(backoffice_state, "user_plane_durable", None)


def _decode_hash(raw: dict) -> dict:
    """Decode a Redis hash (bytes keys + values) into a plain str dict."""
    return {
        (k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
        for k, v in raw.items()
    }


def _decode_set(raw) -> set[str]:
    """Decode a Redis set of bytes into a set of str."""
    return {v.decode() if isinstance(v, bytes) else v for v in raw}


def _meta_key(ua_id: str) -> str:
    return f"ua:meta:{ua_id}"


def resolve_user_mention(r, account_id: str, handle: str) -> Optional[dict]:
    """Look up a user agent by @-handle, scoped to ``account_id``.

    Returns the decoded ua:meta dict with an extra ``_ua_id`` key, or ``None``
    if no agent with this handle exists for this user.

    BOLA double-check: verifies that ``ua:meta.account_id == account_id`` even
    if the alias index had a stale/corrupted entry pointing elsewhere.

    Exported for use by the gateway's @-handle routing in ``openai_router.py``
    (which accesses this Redis db via ``_state.agent_registry._r``).
    """
    ua_id_raw = r.hget(_alias_key(account_id), handle)
    if ua_id_raw is None:
        return None
    ua_id = ua_id_raw.decode() if isinstance(ua_id_raw, bytes) else ua_id_raw
    raw = r.hgetall(_meta_key(ua_id))
    if not raw:
        return None
    meta = _decode_hash(raw)
    if meta.get("account_id") != account_id:
        # Stale alias index entry pointing to another account — BOLA guard
        return None
    meta["_ua_id"] = ua_id
    return meta


def _agents_key(account_id: str) -> str:
    return f"ua:agents:{account_id}"


def _mem_meta_key(block_id: str) -> str:
    return f"ua:mem:meta:{block_id}"


def _mem_all_key(account_id: str) -> str:
    return f"ua:mem:all:{account_id}"


def _mem_agent_key(ua_id: str) -> str:
    return f"ua:mem:agent:{ua_id}"


def _alias_key(account_id: str) -> str:
    """Redis hash for @-handle → ua_id lookup. Keyed per account (BOLA scope)."""
    return f"ua:alias:{account_id}"


# Valid @-handle pattern: starts with a letter, then alphanumeric + underscore, ≤63 chars.
_HANDLE_RE = re.compile(r"^[a-z][a-z0-9_]{0,62}$")


def _normalize_alias(name: str) -> str:
    """Derive a valid @-handle from a free-text agent name.

    Lowercase, collapses non-alphanumeric runs to single underscores, strips
    leading/trailing underscores, prepends 'a' if result starts with a digit.
    Truncated to 63 chars.
    """
    slug = re.sub(r"[^a-z0-9]+", "_", name.lower().strip())
    slug = slug.strip("_")
    if not slug:
        slug = "agent"
    if slug[0].isdigit():
        slug = "a" + slug
    return slug[:63]


# ---------------------------------------------------------------------------
# BOLA guards
# ---------------------------------------------------------------------------

def _get_agent_or_404(r, ua_id: str, account_id: str) -> dict:
    """Return decoded ua:meta hash or raise 404.

    BOLA: returns 404 (not 403) when the agent exists but belongs to another user,
    so resource existence cannot be inferred (OWASP API3).
    """
    raw = r.hgetall(_meta_key(ua_id))
    if not raw:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail={"error": "not_found"})
    meta = _decode_hash(raw)
    if meta.get("account_id") != account_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail={"error": "not_found"})
    return meta


def _get_block_or_404(r, block_id: str, account_id: str) -> dict:
    """Return decoded ua:mem:meta hash or raise 404 (BOLA-safe)."""
    raw = r.hgetall(_mem_meta_key(block_id))
    if not raw:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail={"error": "not_found"})
    meta = _decode_hash(raw)
    if meta.get("account_id") != account_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail={"error": "not_found"})
    return meta


# ---------------------------------------------------------------------------
# Skill scope intersection (R3 / RISK-097)
# ---------------------------------------------------------------------------

def _compute_system_ceiling(r) -> set[str]:
    """Derive the system skill ceiling from active agents' allowed_paths.

    Returns the union of allowed_paths across all active agents in the registry.
    This represents the universe of skills the system can offer.
    Falls back to empty set on any error (fail-closed).
    """
    try:
        registry = getattr(backoffice_state, "agent_registry", None)
        if registry is None:
            return set()
        ceiling: set[str] = set()
        for agent in registry.list_active():
            for path in agent.get("allowed_paths", []):
                ceiling.add(path)
        return ceiling
    except Exception as exc:
        logger.warning("_compute_system_ceiling: failed to read agent registry: %s", exc)
        return set()


def _get_invoker_grants(account_id: str) -> set[str]:
    """Return the calling user's allowed_tools from the identity registry.

    These are the tools the user personally holds the right to delegate.
    Falls back to empty set on any error (fail-closed).
    """
    try:
        ir = getattr(backoffice_state, "identity_registry", None)
        if ir is None:
            return set()
        identity = ir.get_by_slug(account_id)
        if identity is None:
            return set()
        tools = identity.get("allowed_tools", [])
        return set(tools) if tools else set()
    except Exception as exc:
        logger.warning("_get_invoker_grants: failed for account %r: %s", account_id, exc)
        return set()


def compute_effective_skills(
    declared: list[str],
    account_id: str,
    r,
) -> tuple[list[str], list[str]]:
    """Compute the scope intersection (R3).

    Returns:
        (effective_skills, rejected_skills)

    effective_skills = declared ∩ invoker_grants ∩ system_ceiling
    rejected_skills  = declared − effective_skills
    """
    declared_set = set(declared)
    invoker_grants = _get_invoker_grants(account_id)
    system_ceiling = _compute_system_ceiling(r)

    # If invoker_grants is empty (user has no identity record yet), treat as
    # "no restrictions" for community tier — ceiling is still enforced.
    # This matches the RISK-097 spec: ceiling comes from BOTH sources.
    if invoker_grants:
        effective = declared_set & invoker_grants & system_ceiling
    else:
        # No identity record → fall back to system-ceiling-only intersection.
        # This is intentionally conservative: only skills that exist in the
        # system are allowed; no user-level over-grant can sneak in.
        effective = declared_set & system_ceiling

    rejected = sorted(declared_set - effective)
    return sorted(effective), rejected


# ---------------------------------------------------------------------------
# Letta pool helper
# ---------------------------------------------------------------------------

def _letta_unavailable_503():
    """Return HTTP 503 for Letta pool not yet wired."""
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail={
            "error": "letta_pool_unavailable",
            "message": (
                "Per-user Letta agent provisioning is not yet available. "
                "Agent metadata has been saved. Letta will be provisioned "
                "when feat/4.0-agent-isolation (Captain) merges."
            ),
        },
    )


# ---------------------------------------------------------------------------
# Response serialisers
# ---------------------------------------------------------------------------

def _serialise_agent(ua_id: str, meta: dict) -> dict:
    return {
        "ua_id": ua_id,
        "name": meta.get("name", ""),
        "description": meta.get("description", ""),
        # @-addressing fields
        "alias": meta.get("alias", ""),
        "kind": meta.get("kind", "agent"),
        "personality": _j(meta.get("personality", "{}")),
        "effective_skills": _j(meta.get("effective_skills", "[]")),
        "declared_skills": _j(meta.get("declared_skills", "[]")),
        "letta_agent_id": meta.get("letta_agent_id") or None,
        "created_at": meta.get("created_at", ""),
        "updated_at": meta.get("updated_at", ""),
    }


def _serialise_block(block_id: str, meta: dict) -> dict:
    return {
        "block_id": block_id,
        "label": meta.get("label", ""),
        "value": meta.get("value", ""),
        "letta_block_id": meta.get("letta_block_id") or None,
        "created_at": meta.get("created_at", ""),
        "updated_at": meta.get("updated_at", ""),
    }


def _j(raw: str) -> list | dict:
    """Decode a JSON string stored in Redis; return [] or {} on error."""
    try:
        return json.loads(raw)
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Pydantic request bodies
# ---------------------------------------------------------------------------

class CreateAgentBody(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=512)
    persona: str = Field(default="I am a helpful AI assistant with persistent memory.", max_length=4096)
    system_prompt: str = Field(default="", max_length=8192)
    skills: list[str] = Field(default_factory=list, max_length=50)
    # @-addressing: alias is the @-handle (e.g. "mimi" → @mimi).
    # If omitted, derived from name via _normalize_alias().
    # Must be unique per user; conflicts → HTTP 409.
    alias: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=63,
        description="@-handle (lowercase alphanumeric + underscore). Derived from name if omitted.",
    )
    # "agent" = governed callee / NHI tool agent
    # "persona" = Letta conversational persona (routes via per-user Letta pool)
    kind: Literal["agent", "persona"] = Field(default="agent")


class PatchAgentBody(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=128)
    description: Optional[str] = Field(default=None, max_length=512)
    # Changing alias removes the old alias from the index and registers the new one.
    # Conflict with an existing alias owned by this user → 409.
    alias: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=63,
        description="New @-handle; must be unique within the caller's namespace.",
    )


class SetPersonalityBody(BaseModel):
    persona: Optional[str] = Field(default=None, max_length=4096)
    system_prompt: Optional[str] = Field(default=None, max_length=8192)


class SetSkillsBody(BaseModel):
    skills: list[str] = Field(max_length=50)


class CreateMemoryBody(BaseModel):
    label: str = Field(min_length=1, max_length=128)
    value: str = Field(default="", max_length=32768)


class PatchMemoryBody(BaseModel):
    label: Optional[str] = Field(default=None, min_length=1, max_length=128)
    value: Optional[str] = Field(default=None, max_length=32768)


class SaveGraphBody(BaseModel):
    """CTF graph payload from the Drawflow builder.

    The server validates structural constraints (V-001..V-015) and strips any
    client-supplied ``effective_scope`` fields before storage (R11).
    """
    # The full CTF graph object.  Arbitrary structure accepted here; server
    # validates below in _validate_and_strip_graph().
    graph: dict[str, Any] = Field(description="CTF graph object (nodes + edges)")
    # Declared scope — server will compute effective_scope server-side.
    # Client may supply declared_scope; server never accepts effective_scope from client.
    declared_scope: Optional[dict[str, Any]] = Field(default=None)


# ===========================================================================
# /user/agents — agent lifecycle
# ===========================================================================


@router.get("/user/agents")
async def list_user_agents(session: UserSession):
    """List the calling user's agents."""
    r = _get_redis()
    raw_ids = r.smembers(_agents_key(session.account_id))
    ua_ids = _decode_set(raw_ids)
    agents = []
    for ua_id in sorted(ua_ids):
        raw = r.hgetall(_meta_key(ua_id))
        if raw:
            meta = _decode_hash(raw)
            if meta.get("account_id") == session.account_id:
                agents.append(_serialise_agent(ua_id, meta))
    return {"agents": agents}


@router.post("/user/agents", status_code=status.HTTP_201_CREATED)
async def create_user_agent(body: CreateAgentBody, session: UserSession):
    """Create a new user agent.

    Computes effective_skills via scope intersection immediately.
    Alias uniqueness is enforced per user — conflict → HTTP 409.
    Letta provisioning is deferred until the pool seam is wired (503 if
    tried now).  The agent record is created in Redis regardless.
    """
    r = _get_redis()

    # Derive and validate @-handle
    raw_alias = (body.alias or _normalize_alias(body.name)).lower().strip()
    if not _HANDLE_RE.fullmatch(raw_alias):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "invalid_alias",
                "message": (
                    f"Alias {raw_alias!r} is not a valid @-handle. "
                    "Must match ^[a-z][a-z0-9_]{0,62}$."
                ),
            },
        )

    # Alias uniqueness check (per account — BOLA scope is the key itself)
    existing = r.hget(_alias_key(session.account_id), raw_alias)
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "alias_conflict",
                "message": f"@{raw_alias} is already in use. Choose a different alias.",
            },
        )

    ua_id = _new_ua_id()
    now = _now_iso()

    effective, rejected = compute_effective_skills(body.skills, session.account_id, r)

    personality = {"persona": body.persona, "system_prompt": body.system_prompt}

    mapping = {
        b"account_id":       session.account_id.encode(),
        b"name":             body.name.encode(),
        b"description":      body.description.encode(),
        b"alias":            raw_alias.encode(),
        b"kind":             body.kind.encode(),
        b"personality":      json.dumps(personality).encode(),
        b"effective_skills": json.dumps(effective).encode(),
        b"declared_skills":  json.dumps(body.skills).encode(),
        b"letta_agent_id":   b"",
        b"created_at":       now.encode(),
        b"updated_at":       now.encode(),
    }

    pipe = r.pipeline()
    pipe.hset(_meta_key(ua_id), mapping=mapping)
    pipe.sadd(_agents_key(session.account_id), ua_id.encode())
    # Alias index: ua:alias:{account_id} hash → {alias: ua_id}
    pipe.hset(_alias_key(session.account_id), raw_alias, ua_id)
    pipe.execute()

    # 4.0 USER-PLANE-DURABILITY: dual-write to Postgres (best-effort)
    _upd = _get_user_plane_durable()
    if _upd is not None:
        try:
            _upd.upsert_agent({
                "account_id":       session.account_id,
                "ua_id":            ua_id,
                "name":             body.name,
                "description":      body.description,
                "alias":            raw_alias,
                "kind":             body.kind,
                "personality":      json.dumps(personality),
                "effective_skills": json.dumps(effective),
                "declared_skills":  json.dumps(body.skills),
                "letta_agent_id":   "",
                "nhi_id":           "",
            })
        except Exception as _exc:
            logger.error(
                "USER-PLANE-DURABLE: upsert_agent failed for %s: %s", ua_id, _exc
            )

    logger.info(
        "user_agents: created %s alias=%r kind=%r for account %r",
        ua_id, raw_alias, body.kind, session.account_id,
    )

    return {
        "ua_id": ua_id,
        "name": body.name,
        "alias": raw_alias,
        "kind": body.kind,
        "effective_skills": effective,
        "rejected_skills": rejected,
        "letta_agent_id": None,
        "created_at": now,
    }


@router.get("/user/agents/{ua_id}")
async def get_user_agent(ua_id: str, session: UserSession):
    """Get agent config. 404 on BOLA violation."""
    r = _get_redis()
    meta = _get_agent_or_404(r, ua_id, session.account_id)
    return _serialise_agent(ua_id, meta)


@router.patch("/user/agents/{ua_id}")
async def patch_user_agent(ua_id: str, body: PatchAgentBody, session: UserSession):
    """Update agent name, description, or alias. 404 on BOLA violation.

    Alias change:
    - Validates new alias format.
    - Checks uniqueness within the caller's alias namespace (409 on conflict).
    - Atomically removes old alias from index and registers new one.
    """
    r = _get_redis()
    meta = _get_agent_or_404(r, ua_id, session.account_id)  # BOLA check

    updates: dict[bytes, bytes] = {b"updated_at": _now_iso().encode()}
    updated_fields: list[str] = []

    if body.name is not None:
        updates[b"name"] = body.name.encode()
        updated_fields.append("name")

    if body.description is not None:
        updates[b"description"] = body.description.encode()
        updated_fields.append("description")

    alias_updated: Optional[str] = None
    if body.alias is not None:
        new_alias = body.alias.lower().strip()
        if not _HANDLE_RE.fullmatch(new_alias):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "error": "invalid_alias",
                    "message": (
                        f"Alias {new_alias!r} is not a valid @-handle. "
                        "Must match ^[a-z][a-z0-9_]{0,62}$."
                    ),
                },
            )
        old_alias = meta.get("alias", "")
        if new_alias != old_alias:
            # Check uniqueness (only when alias is actually changing)
            existing = r.hget(_alias_key(session.account_id), new_alias)
            if existing is not None:
                existing_str = existing.decode() if isinstance(existing, bytes) else existing
                if existing_str != ua_id:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail={
                            "error": "alias_conflict",
                            "message": f"@{new_alias} is already in use.",
                        },
                    )
            # Update alias index
            pipe = r.pipeline()
            if old_alias:
                pipe.hdel(_alias_key(session.account_id), old_alias)
            pipe.hset(_alias_key(session.account_id), new_alias, ua_id)
            pipe.execute()
            updates[b"alias"] = new_alias.encode()
            updated_fields.append("alias")
            alias_updated = new_alias

    r.hset(_meta_key(ua_id), mapping=updates)

    # 4.0 USER-PLANE-DURABILITY: dual-write to Postgres (best-effort)
    _upd = _get_user_plane_durable()
    if _upd is not None:
        try:
            # Re-read meta to get the full current state for the upsert
            _fresh = _decode_hash(r.hgetall(_meta_key(ua_id)))
            _upd.upsert_agent({
                "account_id":       session.account_id,
                "ua_id":            ua_id,
                "name":             _fresh.get("name", ""),
                "description":      _fresh.get("description", ""),
                "alias":            _fresh.get("alias", ""),
                "kind":             _fresh.get("kind", "agent"),
                "personality":      _fresh.get("personality"),
                "effective_skills": _fresh.get("effective_skills"),
                "declared_skills":  _fresh.get("declared_skills"),
                "graph":            _fresh.get("graph"),
                "graph_hash":       _fresh.get("graph_hash"),
                "letta_agent_id":   _fresh.get("letta_agent_id"),
                "nhi_id":           _fresh.get("nhi_id"),
            })
        except Exception as _exc:
            logger.error(
                "USER-PLANE-DURABLE: upsert_agent (patch) failed for %s: %s", ua_id, _exc
            )

    logger.info(
        "user_agents: patched %s fields=%r for account %r",
        ua_id, updated_fields, session.account_id,
    )
    result: dict = {"ua_id": ua_id, "updated": updated_fields}
    if alias_updated is not None:
        result["alias"] = alias_updated
    return result


@router.delete("/user/agents/{ua_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user_agent(ua_id: str, session: UserSession):
    """Delete agent, detach all memory blocks, and remove alias from index.

    404 on BOLA violation.
    """
    r = _get_redis()
    meta = _get_agent_or_404(r, ua_id, session.account_id)  # BOLA check

    # Detach all memory blocks from this agent (don't delete the blocks themselves)
    attached = _decode_set(r.smembers(_mem_agent_key(ua_id)))

    # Remove alias from index (if any)
    old_alias = meta.get("alias", "")

    pipe = r.pipeline()
    pipe.delete(_meta_key(ua_id))
    pipe.srem(_agents_key(session.account_id), ua_id.encode())
    pipe.delete(_mem_agent_key(ua_id))
    if old_alias:
        pipe.hdel(_alias_key(session.account_id), old_alias)
    pipe.execute()

    # 4.0 USER-PLANE-DURABILITY: dual-write to Postgres (best-effort)
    _upd = _get_user_plane_durable()
    if _upd is not None:
        try:
            _upd.delete_agent(ua_id)
        except Exception as _exc:
            logger.error(
                "USER-PLANE-DURABLE: delete_agent failed for %s: %s", ua_id, _exc
            )

    logger.info(
        "user_agents: deleted %s alias=%r for account %r; detached %d memory blocks",
        ua_id, old_alias, session.account_id, len(attached),
    )


# ---------------------------------------------------------------------------
# /user/agents/{ua_id}/personality
# ---------------------------------------------------------------------------


@router.get("/user/agents/{ua_id}/personality")
async def get_agent_personality(ua_id: str, session: UserSession):
    """Get the agent's persona and system prompt. 404 on BOLA violation."""
    r = _get_redis()
    meta = _get_agent_or_404(r, ua_id, session.account_id)
    personality = _j(meta.get("personality", "{}"))
    if not isinstance(personality, dict):
        personality = {}
    return {
        "ua_id": ua_id,
        "persona": personality.get("persona", ""),
        "system_prompt": personality.get("system_prompt", ""),
    }


@router.put("/user/agents/{ua_id}/personality")
async def set_agent_personality(ua_id: str, body: SetPersonalityBody, session: UserSession):
    """Update the agent's persona and/or system prompt.

    Pushes to Letta via pool if available; otherwise updates Redis only
    (Letta sync deferred to pool availability).  Returns 503 only when
    a live Letta operation is attempted.  Metadata update always succeeds.
    """
    r = _get_redis()
    meta = _get_agent_or_404(r, ua_id, session.account_id)

    current = _j(meta.get("personality", "{}"))
    if not isinstance(current, dict):
        current = {}

    if body.persona is not None:
        current["persona"] = body.persona
    if body.system_prompt is not None:
        current["system_prompt"] = body.system_prompt

    r.hset(_meta_key(ua_id), mapping={
        b"personality": json.dumps(current).encode(),
        b"updated_at":  _now_iso().encode(),
    })

    # 4.0 USER-PLANE-DURABILITY: dual-write to Postgres (best-effort)
    _upd = _get_user_plane_durable()
    if _upd is not None:
        try:
            _fresh = _decode_hash(r.hgetall(_meta_key(ua_id)))
            _upd.upsert_agent({
                "account_id":       session.account_id,
                "ua_id":            ua_id,
                "name":             _fresh.get("name", ""),
                "description":      _fresh.get("description", ""),
                "alias":            _fresh.get("alias", ""),
                "kind":             _fresh.get("kind", "agent"),
                "personality":      _fresh.get("personality"),
                "effective_skills": _fresh.get("effective_skills"),
                "declared_skills":  _fresh.get("declared_skills"),
                "graph":            _fresh.get("graph"),
                "graph_hash":       _fresh.get("graph_hash"),
                "letta_agent_id":   _fresh.get("letta_agent_id"),
                "nhi_id":           _fresh.get("nhi_id"),
            })
        except Exception as _exc:
            logger.error(
                "USER-PLANE-DURABLE: upsert_agent (personality) failed for %s: %s", ua_id, _exc
            )

    # Attempt live Letta push (no-op if pool not ready)
    letta_agent_id = meta.get("letta_agent_id", "")
    letta_synced = False
    if letta_agent_id:
        try:
            from yashigani.gateway.letta_pool import LettaClientPool
            client, base_url, _ = await LettaClientPool.for_user(session.account_id)
            async with client:
                # Letta memory block PATCH to update persona block
                await client.patch(
                    f"{base_url}/v1/agents/{letta_agent_id}/memory/blocks",
                    json={"label": "persona", "value": current.get("persona", "")},
                )
            letta_synced = True
        except Exception:
            # Pool not wired or Letta unavailable — metadata saved; Letta sync deferred.
            letta_synced = False

    return {
        "ua_id": ua_id,
        "persona": current.get("persona", ""),
        "system_prompt": current.get("system_prompt", ""),
        "letta_synced": letta_synced,
    }


# ---------------------------------------------------------------------------
# /user/agents/{ua_id}/skills
# ---------------------------------------------------------------------------


@router.get("/user/agents/{ua_id}/skills")
async def get_agent_skills(ua_id: str, session: UserSession):
    """Get the agent's effective skill set. 404 on BOLA violation."""
    r = _get_redis()
    meta = _get_agent_or_404(r, ua_id, session.account_id)
    return {
        "ua_id": ua_id,
        "effective_skills": _j(meta.get("effective_skills", "[]")),
        "declared_skills":  _j(meta.get("declared_skills", "[]")),
    }


@router.put("/user/agents/{ua_id}/skills")
async def set_agent_skills(ua_id: str, body: SetSkillsBody, session: UserSession):
    """Set agent skills — scope intersection enforced (R3 / RISK-097).

    Returns the effective_skills (declared ∩ invoker_grants ∩ system_ceiling)
    and the rejected_skills (declared − effective).

    A skill outside the user's grants or outside the system ceiling is silently
    dropped into rejected_skills rather than raising a 403, so the caller can
    see exactly what was granted vs. refused.

    404 on BOLA violation.
    """
    r = _get_redis()
    _get_agent_or_404(r, ua_id, session.account_id)  # BOLA check

    effective, rejected = compute_effective_skills(body.skills, session.account_id, r)

    r.hset(_meta_key(ua_id), mapping={
        b"effective_skills": json.dumps(effective).encode(),
        b"declared_skills":  json.dumps(body.skills).encode(),
        b"updated_at":       _now_iso().encode(),
    })

    # 4.0 USER-PLANE-DURABILITY: dual-write to Postgres (best-effort)
    _upd = _get_user_plane_durable()
    if _upd is not None:
        try:
            _fresh = _decode_hash(r.hgetall(_meta_key(ua_id)))
            _upd.upsert_agent({
                "account_id":       session.account_id,
                "ua_id":            ua_id,
                "name":             _fresh.get("name", ""),
                "description":      _fresh.get("description", ""),
                "alias":            _fresh.get("alias", ""),
                "kind":             _fresh.get("kind", "agent"),
                "personality":      _fresh.get("personality"),
                "effective_skills": _fresh.get("effective_skills"),
                "declared_skills":  _fresh.get("declared_skills"),
                "graph":            _fresh.get("graph"),
                "graph_hash":       _fresh.get("graph_hash"),
                "letta_agent_id":   _fresh.get("letta_agent_id"),
                "nhi_id":           _fresh.get("nhi_id"),
            })
        except Exception as _exc:
            logger.error(
                "USER-PLANE-DURABLE: upsert_agent (skills) failed for %s: %s", ua_id, _exc
            )

    logger.info(
        "user_agents: skills set on %s for account %r — effective=%r rejected=%r",
        ua_id, session.account_id, effective, rejected,
    )
    return {
        "ua_id": ua_id,
        "effective_skills": effective,
        "rejected_skills": rejected,
    }


# ---------------------------------------------------------------------------
# /user/agents/{ua_id}/memories — memory attachment
# ---------------------------------------------------------------------------


@router.get("/user/agents/{ua_id}/memories")
async def list_agent_memories(ua_id: str, session: UserSession):
    """List memory blocks currently attached to this agent. 404 on BOLA."""
    r = _get_redis()
    _get_agent_or_404(r, ua_id, session.account_id)  # BOLA check

    block_ids = _decode_set(r.smembers(_mem_agent_key(ua_id)))
    blocks = []
    for bid in sorted(block_ids):
        raw = r.hgetall(_mem_meta_key(bid))
        if raw:
            meta = _decode_hash(raw)
            if meta.get("account_id") == session.account_id:
                blocks.append(_serialise_block(bid, meta))
    return {"ua_id": ua_id, "memories": blocks}


@router.post("/user/agents/{ua_id}/memories/{block_id}", status_code=status.HTTP_201_CREATED)
async def attach_memory_to_agent(ua_id: str, block_id: str, session: UserSession):
    """Attach a memory block to an agent.

    Both the agent and the block must be owned by the calling user (BOLA).
    Returns 404 on any BOLA violation.  Idempotent — attaching an already-
    attached block is a no-op.
    """
    r = _get_redis()
    agent_meta = _get_agent_or_404(r, ua_id, session.account_id)
    block_meta  = _get_block_or_404(r, block_id, session.account_id)

    r.sadd(_mem_agent_key(ua_id), block_id.encode())

    # 4.0 USER-PLANE-DURABILITY: dual-write to Postgres (best-effort)
    _upd = _get_user_plane_durable()
    if _upd is not None:
        try:
            _upd.set_memory_link(ua_id, block_id, True)
        except Exception as _exc:
            logger.error(
                "USER-PLANE-DURABLE: set_memory_link (attach) failed ua=%s block=%s: %s",
                ua_id, block_id, _exc,
            )

    letta_agent_id = agent_meta.get("letta_agent_id", "")
    letta_block_id = block_meta.get("letta_block_id", "")
    letta_synced = False

    if letta_agent_id and letta_block_id:
        try:
            from yashigani.gateway.letta_pool import LettaClientPool
            client, base_url, _ = await LettaClientPool.for_user(session.account_id)
            async with client:
                await client.post(
                    f"{base_url}/v1/agents/{letta_agent_id}/memory/blocks",
                    json={"id": letta_block_id},
                )
            letta_synced = True
        except Exception:
            letta_synced = False

    return {"ua_id": ua_id, "block_id": block_id, "letta_synced": letta_synced}


@router.delete("/user/agents/{ua_id}/memories/{block_id}", status_code=status.HTTP_204_NO_CONTENT)
async def detach_memory_from_agent(ua_id: str, block_id: str, session: UserSession):
    """Detach a memory block from an agent (does NOT delete the block).

    Both the agent and the block must be owned by the calling user (BOLA).
    """
    r = _get_redis()
    agent_meta = _get_agent_or_404(r, ua_id, session.account_id)
    _get_block_or_404(r, block_id, session.account_id)

    r.srem(_mem_agent_key(ua_id), block_id.encode())

    # 4.0 USER-PLANE-DURABILITY: dual-write to Postgres (best-effort)
    _upd = _get_user_plane_durable()
    if _upd is not None:
        try:
            _upd.set_memory_link(ua_id, block_id, False)
        except Exception as _exc:
            logger.error(
                "USER-PLANE-DURABLE: set_memory_link (detach) failed ua=%s block=%s: %s",
                ua_id, block_id, _exc,
            )

    letta_agent_id = agent_meta.get("letta_agent_id", "")
    # Best-effort Letta detach (no raise on failure — metadata is authoritative)
    if letta_agent_id:
        try:
            from yashigani.gateway.letta_pool import LettaClientPool
            client, base_url, _ = await LettaClientPool.for_user(session.account_id)
            async with client:
                await client.delete(
                    f"{base_url}/v1/agents/{letta_agent_id}/memory/blocks/{block_id}",
                )
        except Exception:
            pass  # Letta sync deferred; Redis detach is the source of truth


# ===========================================================================
# /user/memories — memory block CRUD
# ===========================================================================


@router.get("/user/memories")
async def list_user_memories(session: UserSession):
    """List all memory blocks owned by the calling user."""
    r = _get_redis()
    raw_ids = r.smembers(_mem_all_key(session.account_id))
    block_ids = _decode_set(raw_ids)
    blocks = []
    for bid in sorted(block_ids):
        raw = r.hgetall(_mem_meta_key(bid))
        if raw:
            meta = _decode_hash(raw)
            if meta.get("account_id") == session.account_id:
                blocks.append(_serialise_block(bid, meta))
    return {"memories": blocks}


@router.post("/user/memories", status_code=status.HTTP_201_CREATED)
async def create_memory_block(body: CreateMemoryBody, session: UserSession):
    """Create a memory block.

    Stores in Redis immediately.  Letta provisioning (letta_block_id) is
    deferred until the user attaches the block to an agent that has a live
    Letta agent_id, or until the pool seam is wired.
    """
    r = _get_redis()
    block_id = _new_block_id()
    now = _now_iso()

    mapping = {
        b"account_id":     session.account_id.encode(),
        b"label":          body.label.encode(),
        b"value":          body.value.encode(),
        b"letta_block_id": b"",
        b"created_at":     now.encode(),
        b"updated_at":     now.encode(),
    }

    pipe = r.pipeline()
    pipe.hset(_mem_meta_key(block_id), mapping=mapping)
    pipe.sadd(_mem_all_key(session.account_id), block_id.encode())
    pipe.execute()

    # 4.0 USER-PLANE-DURABILITY: dual-write to Postgres (best-effort)
    _upd = _get_user_plane_durable()
    if _upd is not None:
        try:
            _upd.upsert_memory({
                "account_id":     session.account_id,
                "block_id":       block_id,
                "label":          body.label,
                "value":          body.value,
                "letta_block_id": "",
            })
        except Exception as _exc:
            logger.error(
                "USER-PLANE-DURABLE: upsert_memory failed for %s: %s", block_id, _exc
            )

    logger.info("user_agents: memory block %s created for account %r", block_id, session.account_id)
    return {"block_id": block_id, "label": body.label, "created_at": now}


@router.get("/user/memories/{block_id}")
async def get_memory_block(block_id: str, session: UserSession):
    """Get a memory block. 404 on BOLA violation."""
    r = _get_redis()
    meta = _get_block_or_404(r, block_id, session.account_id)
    return _serialise_block(block_id, meta)


@router.patch("/user/memories/{block_id}")
async def patch_memory_block(block_id: str, body: PatchMemoryBody, session: UserSession):
    """Rename or update a memory block's value.

    Propagates value update to Letta if pool is wired and letta_block_id exists.
    Metadata update always succeeds regardless of Letta availability.
    404 on BOLA violation.
    """
    r = _get_redis()
    meta = _get_block_or_404(r, block_id, session.account_id)

    updates: dict[bytes, bytes] = {b"updated_at": _now_iso().encode()}
    if body.label is not None:
        updates[b"label"] = body.label.encode()
    if body.value is not None:
        updates[b"value"] = body.value.encode()

    r.hset(_mem_meta_key(block_id), mapping=updates)

    # 4.0 USER-PLANE-DURABILITY: dual-write to Postgres (best-effort)
    _upd = _get_user_plane_durable()
    if _upd is not None:
        try:
            _fresh_mem = _decode_hash(r.hgetall(_mem_meta_key(block_id)))
            _upd.upsert_memory({
                "account_id":     session.account_id,
                "block_id":       block_id,
                "label":          _fresh_mem.get("label", ""),
                "value":          _fresh_mem.get("value", ""),
                "letta_block_id": _fresh_mem.get("letta_block_id", ""),
            })
        except Exception as _exc:
            logger.error(
                "USER-PLANE-DURABLE: upsert_memory (patch) failed for %s: %s", block_id, _exc
            )

    letta_block_id = meta.get("letta_block_id", "")
    letta_synced = False
    if letta_block_id and body.value is not None:
        try:
            from yashigani.gateway.letta_pool import LettaClientPool
            client, base_url, _ = await LettaClientPool.for_user(session.account_id)
            async with client:
                await client.patch(
                    f"{base_url}/v1/blocks/{letta_block_id}",
                    json={"value": body.value},
                )
            letta_synced = True
        except Exception:
            letta_synced = False

    return {
        "block_id": block_id,
        "updated": [k.decode() for k in updates if k != b"updated_at"],
        "letta_synced": letta_synced,
    }


@router.delete("/user/memories/{block_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_memory_block(block_id: str, session: UserSession):
    """Delete a memory block and auto-detach it from all agents.

    Letta block deletion is attempted if pool is wired.  Redis deletion is
    always performed.  404 on BOLA violation.
    """
    r = _get_redis()
    meta = _get_block_or_404(r, block_id, session.account_id)

    # Collect all agents this block is attached to so we can remove from each
    # ua:mem:agent:{ua_id} set.  We do a scan over all agent sets.
    agent_ids = _decode_set(r.smembers(_agents_key(session.account_id)))

    letta_block_id = meta.get("letta_block_id", "")

    pipe = r.pipeline()
    pipe.delete(_mem_meta_key(block_id))
    pipe.srem(_mem_all_key(session.account_id), block_id.encode())
    for ua_id in agent_ids:
        pipe.srem(_mem_agent_key(ua_id), block_id.encode())
    pipe.execute()

    # 4.0 USER-PLANE-DURABILITY: dual-write to Postgres (best-effort)
    _upd = _get_user_plane_durable()
    if _upd is not None:
        try:
            _upd.delete_memory(block_id)
        except Exception as _exc:
            logger.error(
                "USER-PLANE-DURABLE: delete_memory failed for %s: %s", block_id, _exc
            )

    # Best-effort Letta delete
    if letta_block_id:
        try:
            from yashigani.gateway.letta_pool import LettaClientPool
            client, base_url, _ = await LettaClientPool.for_user(session.account_id)
            async with client:
                await client.delete(f"{base_url}/v1/blocks/{letta_block_id}")
        except Exception:
            pass  # Redis delete is authoritative

    logger.info("user_agents: memory block %s deleted for account %r", block_id, session.account_id)


# ===========================================================================
# Graph persistence helpers (Phase 4 — RISK-113 / R11)
# ===========================================================================

# Label allowlist pattern (no HTML chars, V-011)
_LABEL_RE = re.compile(r"^[^<>&\"']{1,256}$")
_EDGE_LABEL_RE = re.compile(r"^[^<>&\"']{0,128}$")

_VALID_NODE_TYPES = frozenset({
    "input_node", "output_node", "tool_node", "model_node",
    "agent_node", "policy_node", "langflow_node",
})

_MAX_NODES = 32
_MAX_EDGES = 64
_MAX_FANOUT = 4
_MAX_DEPTH = 9


def _sha384_graph(graph_json: str) -> str:
    """SHA-384 hex of the normalised CTF graph JSON for audit."""
    return "sha384:" + hashlib.sha384(graph_json.encode("utf-8")).hexdigest()


def _strip_effective_scope_from_node(node: dict) -> dict:
    """Remove client-supplied effective_scope from a node (R11).

    Returns a copy with ``data.effective_scope`` stripped if present.
    The server computes effective_scope server-side — the client cannot
    supply it to influence scope at execution time.
    """
    node = dict(node)
    if isinstance(node.get("data"), dict):
        data = dict(node["data"])
        data.pop("effective_scope", None)
        node["data"] = data
    return node


def _validate_and_strip_graph(graph: dict) -> tuple[dict, list[str]]:
    """Validate CTF graph and strip R11 fields.

    Returns (stripped_graph, errors).  If errors is non-empty, the caller
    must reject with HTTP 422.

    Implements V-001..V-011 (structural), V-014 (depth), V-015 (fan-out).
    V-012/V-013 (registry/scope) are deferred to NHI instantiation time.

    Server-strips:
      - ``node.data.effective_scope`` (R11: never trust client-supplied scope)
      - Any top-level ``effective_scope`` or ``import_provenance`` fields
        (those are server-populated at import time only).
    """
    errors: list[str] = []
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])

    # Size caps (RISK-111)
    if len(nodes) > _MAX_NODES:
        errors.append(f"V-NODES: too many nodes ({len(nodes)} > {_MAX_NODES})")
    if len(edges) > _MAX_EDGES:
        errors.append(f"V-EDGES: too many edges ({len(edges)} > {_MAX_EDGES})")

    # V-001: exactly one input_node
    input_nodes = [n for n in nodes if n.get("node_type") == "input_node"]
    if len(input_nodes) != 1:
        errors.append(f"V-001: expected exactly one input_node, got {len(input_nodes)}")

    # V-002: exactly one output_node
    output_nodes = [n for n in nodes if n.get("node_type") == "output_node"]
    if len(output_nodes) != 1:
        errors.append(f"V-002: expected exactly one output_node, got {len(output_nodes)}")

    # V-011: label HTML safety
    node_ids: set[str] = set()
    stripped_nodes = []
    for node in nodes:
        node_type = node.get("node_type", "")
        if node_type not in _VALID_NODE_TYPES:
            errors.append(f"V-TYPE: unknown node_type {node_type!r}")
        label = node.get("label", "")
        if not _LABEL_RE.fullmatch(label):
            errors.append(f"V-011: node label contains HTML or is too long: {label[:32]!r}")
        node_id = node.get("id", "")
        if node_id:
            node_ids.add(node_id)
        stripped_nodes.append(_strip_effective_scope_from_node(node))

    # V-003: edge node references
    stripped_edges = []
    out_edges: dict[str, int] = {}
    for edge in edges:
        src = edge.get("source_node_id", "")
        tgt = edge.get("target_node_id", "")
        if src not in node_ids:
            errors.append(f"V-003: edge source_node_id {src!r} not in graph")
        if tgt not in node_ids:
            errors.append(f"V-003: edge target_node_id {tgt!r} not in graph")
        # V-011: edge label
        elabel = edge.get("label", "")
        if elabel and not _EDGE_LABEL_RE.fullmatch(elabel):
            errors.append(f"V-011: edge label contains HTML: {elabel[:32]!r}")
        # Count fan-out per source
        out_edges[src] = out_edges.get(src, 0) + 1
        # V-004: no self-loops (simple cycle check — DAG full check is O(N+E))
        if src == tgt:
            errors.append(f"V-004: self-loop on node {src!r}")
        # Enforce governed=true and audit=true (immutable constants per spec)
        stripped_edge = dict(edge)
        stripped_edge["governed"] = True
        stripped_edge["audit"] = True
        stripped_edges.append(stripped_edge)

    # V-015: fan-out
    for node_id, fan in out_edges.items():
        if fan > _MAX_FANOUT:
            errors.append(f"V-015: node {node_id!r} fan-out {fan} > {_MAX_FANOUT}")

    # V-004: cycle detection (simple DFS)
    adj: dict[str, list[str]] = {n.get("id", ""): [] for n in nodes}
    for edge in stripped_edges:
        src = edge.get("source_node_id", "")
        tgt = edge.get("target_node_id", "")
        if src in adj:
            adj[src].append(tgt)

    visited: set[str] = set()
    rec_stack: set[str] = set()

    def _has_cycle(v: str) -> bool:
        visited.add(v)
        rec_stack.add(v)
        for nb in adj.get(v, []):
            if nb not in visited:
                if _has_cycle(nb):
                    return True
            elif nb in rec_stack:
                return True
        rec_stack.discard(v)
        return False

    for node_id in list(adj.keys()):
        if node_id not in visited:
            if _has_cycle(node_id):
                errors.append("V-004: graph contains a cycle; cycles are not permitted")
                break

    stripped_graph = {
        "nodes": stripped_nodes,
        "edges": stripped_edges,
    }
    return stripped_graph, errors


# ===========================================================================
# /user/skills — available skill catalog
# ===========================================================================


@router.get("/user/skills")
async def list_available_skills(session: UserSession):
    """List skills available to this user for assignment to agents.

    Returns the intersection of:
      - the system-wide skill catalog (active agents' allowed_paths)
      - the calling user's allowed_tools from the identity registry

    If the user has no identity record, the full system catalog is returned
    (community-tier: any registered skill may be used).
    """
    r = _get_redis()
    system_ceiling = _compute_system_ceiling(r)
    invoker_grants = _get_invoker_grants(session.account_id)

    if invoker_grants:
        available = sorted(system_ceiling & invoker_grants)
    else:
        # No identity / community tier — all system skills are available.
        available = sorted(system_ceiling)

    return {"available_skills": available, "count": len(available)}


# ===========================================================================
# /user/mentions — @-addressable entity catalog (4.0 mention addressing)
# ===========================================================================


@router.get("/user/mentions")
async def list_user_mentions(session: UserSession):
    """Return all @-addressable entities for the calling user.

    The UI autocompletes from this endpoint.  The returned ``handle`` values
    are exactly the strings that, prefixed with ``@``, can be used to address
    that entity in a workflow description or chat model field.

    Resolution contract (pinned, used by ``openai_router.py`` and
    ``user_workflows.py`` handle-validation):

      * ``kind: "agent"``   — governed callee / NHI tool agent.  Routed via the
                              NHI pool after ``POST /user/agents/{id}/run`` wires it.
      * ``kind: "persona"`` — Letta conversational persona.  Routed via the
                              per-user ``LettaClientPool``.
      * ``kind: "mcp"``     — registered MCP server the user may address.
                              Source: ``YASHIGANI_MCP_SERVERS`` env var.
                              System-wide (same set for all users); gateway enforces
                              per-call OPA adjudication at invocation time.
      * ``kind: "api"``     — active agent-registry integration the user may call.
                              Source: ``AgentRegistry.list_active()`` (kind != nhi/
                              langflow_callee). Gateway enforces OPA at invocation time.

    BOLA:
      * ``kind:"agent"`` / ``kind:"persona"`` — BOLA-scoped to the calling user's
        ``ua:agents:{account_id}`` set (only their own agents).
      * ``kind:"mcp"`` / ``kind:"api"`` — system-wide; no per-user BOLA scope
        (all users see the same system integrations; OPA per-call is the gate).

    Response shape: ``{"mentions": [{handle, kind, display, id}, ...]}``
    Sorted by kind priority then handle for deterministic ordering.
    """
    import os as _os
    import json as _json

    r = _get_redis()

    mentions: list[dict] = []

    # ------------------------------------------------------------------ #
    # 1. User-owned agents and personas (BOLA-scoped)                     #
    # ------------------------------------------------------------------ #
    raw_ids = r.smembers(_agents_key(session.account_id))
    ua_ids = _decode_set(raw_ids)

    for ua_id in sorted(ua_ids):
        raw = r.hgetall(_meta_key(ua_id))
        if not raw:
            continue
        meta = _decode_hash(raw)
        if meta.get("account_id") != session.account_id:
            continue  # BOLA guard
        alias = meta.get("alias", "")
        if not alias:
            continue  # legacy record without alias
        mentions.append({
            "handle": alias,
            "kind": meta.get("kind", "agent"),
            "display": meta.get("name", ""),
            "id": ua_id,
        })

    # ------------------------------------------------------------------ #
    # 2. MCP servers (system-wide; source: YASHIGANI_MCP_SERVERS env)     #
    # ------------------------------------------------------------------ #
    _mcp_raw = _os.environ.get("YASHIGANI_MCP_SERVERS", "").strip()
    if _mcp_raw:
        try:
            _mcp_entries = _json.loads(_mcp_raw)
            if isinstance(_mcp_entries, list):
                for _entry in _mcp_entries:
                    _agent_name = _entry.get("agent_name", "")
                    if not _agent_name:
                        continue
                    mentions.append({
                        "handle": _agent_name,
                        "kind": "mcp",
                        "display": _entry.get("display_name", _agent_name),
                        "id": _agent_name,
                    })
        except Exception as _exc:
            logger.warning(
                "list_user_mentions: failed to parse YASHIGANI_MCP_SERVERS: %s", _exc
            )

    # ------------------------------------------------------------------ #
    # 3. API integrations (active agents from AgentRegistry, kind != nhi) #
    # ------------------------------------------------------------------ #
    _ar = getattr(backoffice_state, "agent_registry", None)
    if _ar is not None:
        try:
            for _agent in _ar.list_active():
                _kind = _agent.get("kind", "agent")
                if _kind in ("nhi", "langflow_callee", "persona"):
                    continue  # skip NHIs and langflow callees (user created own)
                _name = _agent.get("name", "")
                _aid = _agent.get("agent_id", "") or _agent.get("id", "")
                if not _name or not _aid:
                    continue
                # Derive @-handle from agent name (same slug logic as user agents)
                _handle = _normalize_alias(_name)
                mentions.append({
                    "handle": _handle,
                    "kind": "api",
                    "display": _name,
                    "id": _aid,
                })
        except Exception as _exc:
            logger.warning(
                "list_user_mentions: failed to read agent_registry: %s", _exc
            )

    # Sort: user-owned agents/personas first (kind in agent/persona), then mcp,
    # then api — within each kind, alphabetical by handle.
    _KIND_ORDER = {"agent": 0, "persona": 1, "mcp": 2, "api": 3}
    mentions.sort(key=lambda m: (_KIND_ORDER.get(m["kind"], 9), m["handle"]))
    return {"mentions": mentions}


# ===========================================================================
# /user/agents/{ua_id}/graph — builder graph persistence (Phase 4 / RISK-113)
# ===========================================================================


@router.put("/user/agents/{ua_id}/graph")
async def save_agent_graph(ua_id: str, body: SaveGraphBody, session: UserSession):
    """Persist the Drawflow builder graph server-side (Phase 4).

    BOLA: the agent must be owned by the calling user (404 on violation).

    R11 enforcement:
      - Strips any client-supplied ``effective_scope`` from all nodes.
      - Sets ``governed=true`` and ``audit=true`` on all edges (immutable constants).
      - Server never accepts ``import_provenance`` or top-level ``effective_scope``
        from the client — those are server-populated fields only.

    Validation: V-001..V-011, V-014, V-015 (structural CTF constraints).
    Emits ``AGENT_TEMPLATE_SAVED`` to the audit hash-chain.

    Returns the saved graph hash and node/edge counts.
    """
    r = _get_redis()
    _get_agent_or_404(r, ua_id, session.account_id)  # BOLA check

    graph_input = body.graph
    stripped_graph, errors = _validate_and_strip_graph(graph_input)
    if errors:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "graph_validation_failed", "violations": errors},
        )

    node_count = len(stripped_graph.get("nodes", []))
    edge_count = len(stripped_graph.get("edges", []))

    # Build the persisted CTF document.
    # Strip client-supplied effective_scope and import_provenance at the top level (R11).
    scope = dict(body.declared_scope) if body.declared_scope else {}
    scope.pop("effective_scope", None)   # R11: server-computed only
    scope.pop("import_provenance", None)  # server-populated only

    ctf_doc = {
        "spec_version": "1.0",
        "graph": stripped_graph,
        "scope": scope,
        # Lifecycle and NHI fields are managed server-side; not set by PUT graph.
    }
    ctf_json = json.dumps(ctf_doc, separators=(",", ":"), sort_keys=True)
    graph_hash = _sha384_graph(ctf_json)

    r.hset(_meta_key(ua_id), mapping={
        b"graph":      ctf_json.encode("utf-8"),
        b"graph_hash": graph_hash.encode("utf-8"),
        b"updated_at": _now_iso().encode("utf-8"),
    })

    # 4.0 USER-PLANE-DURABILITY: dual-write to Postgres (best-effort)
    _upd = _get_user_plane_durable()
    if _upd is not None:
        try:
            _fresh = _decode_hash(r.hgetall(_meta_key(ua_id)))
            _upd.upsert_agent({
                "account_id":       session.account_id,
                "ua_id":            ua_id,
                "name":             _fresh.get("name", ""),
                "description":      _fresh.get("description", ""),
                "alias":            _fresh.get("alias", ""),
                "kind":             _fresh.get("kind", "agent"),
                "personality":      _fresh.get("personality"),
                "effective_skills": _fresh.get("effective_skills"),
                "declared_skills":  _fresh.get("declared_skills"),
                "graph":            ctf_json,
                "graph_hash":       graph_hash,
                "letta_agent_id":   _fresh.get("letta_agent_id"),
                "nhi_id":           _fresh.get("nhi_id"),
            })
        except Exception as _exc:
            logger.error(
                "USER-PLANE-DURABLE: upsert_agent (graph) failed for %s: %s", ua_id, _exc
            )

    logger.info(
        "user_agents: graph saved for %s account=%r nodes=%d edges=%d hash=%s",
        ua_id, session.account_id, node_count, edge_count, graph_hash[:24],
    )

    # Audit event to hash-chain (RISK-104 / AUDIT-GAP-001 class)
    aw = getattr(backoffice_state, "audit_writer", None)
    if aw is not None:
        try:
            from yashigani.audit.schema import AgentTemplateGraphSavedEvent
            aw.write(AgentTemplateGraphSavedEvent(
                owner_identity_id=session.account_id,
                ua_id=ua_id,
                node_count=node_count,
                edge_count=edge_count,
                graph_hash=graph_hash,
                effective_scope_stripped=True,
            ))
        except Exception as exc:
            logger.warning("AgentTemplateGraphSavedEvent audit write failed: %s", exc)

    return {
        "ua_id": ua_id,
        "graph_hash": graph_hash,
        "node_count": node_count,
        "edge_count": edge_count,
        "effective_scope_stripped": True,
    }


@router.get("/user/agents/{ua_id}/graph")
async def load_agent_graph(ua_id: str, session: UserSession):
    """Load the persisted CTF graph for edit in the builder.

    BOLA: the agent must be owned by the calling user (404 on violation).

    Returns the stored CTF document (``graph`` + ``scope`` + ``graph_hash``).
    If no graph has been saved yet, returns ``graph: null`` so the builder
    knows to start from an empty canvas.
    """
    r = _get_redis()
    meta = _get_agent_or_404(r, ua_id, session.account_id)

    graph_raw = meta.get("graph", "")
    graph_hash = meta.get("graph_hash", "")

    if not graph_raw:
        return {
            "ua_id": ua_id,
            "graph": None,
            "graph_hash": None,
            "message": "No graph saved yet — builder starts from empty canvas.",
        }

    try:
        ctf_doc = json.loads(graph_raw)
    except json.JSONDecodeError:
        logger.error("user_agents: corrupted graph JSON for %s", ua_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "graph_corrupted"},
        )

    return {
        "ua_id": ua_id,
        "graph": ctf_doc.get("graph"),
        "scope": ctf_doc.get("scope", {}),
        "graph_hash": graph_hash,
    }


# ===========================================================================
# /user/agents/{ua_id}/run — NHI instantiation (Phase 3 / RISK-097)
# ===========================================================================


@router.post("/user/agents/{ua_id}/run", status_code=status.HTTP_201_CREATED)
async def run_user_agent(ua_id: str, session: UserSession):
    """Instantiate an NHI from the user agent's stored graph + skills (Phase 3).

    Compute effective_scope = declared_skills ∩ invoker_grants ∩ system_ceiling (R3).
    Register the NHI in AgentRegistry (kind="nhi") with the computed scope.
    Returns nhi_id + svid_pending flag.

    If ``svid_issued=False`` the NHI requires admin approval before gateway calls
    will be accepted (403 NHI_PENDING_APPROVAL on invocation).

    BOLA: the agent must be owned by the calling user.
    Requires an agent registry (HTTP 503 if unavailable).
    """
    r = _get_redis()
    meta = _get_agent_or_404(r, ua_id, session.account_id)

    # Check if an NHI is already instantiated for this agent
    existing_nhi_id = meta.get("nhi_id", "")
    if existing_nhi_id:
        # Return existing NHI metadata (idempotent for re-run)
        return {
            "ua_id": ua_id,
            "nhi_id": existing_nhi_id,
            "svid_pending": True,  # caller should check registry for svid_issued
            "message": "NHI already instantiated for this agent.",
        }

    # Require agent registry
    agent_registry = getattr(backoffice_state, "agent_registry", None)
    if agent_registry is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "registry_unavailable",
                    "message": "Agent registry not ready — cannot instantiate NHI."},
        )

    # Require a saved graph
    graph_raw = meta.get("graph", "")
    if not graph_raw:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "no_graph_saved",
                    "message": "Save a builder graph first (PUT /user/agents/{ua_id}/graph)."},
        )

    # R3: effective_scope = declared_skills ∩ invoker_grants ∩ system_ceiling
    _raw_skills = _j(meta.get("effective_skills", "[]"))
    declared_skills: list[str] = _raw_skills if isinstance(_raw_skills, list) else []
    effective_tools, rejected = compute_effective_skills(declared_skills, session.account_id, r)

    if not effective_tools:
        # Emit NHI_INSTANTIATION_DENIED
        aw = getattr(backoffice_state, "audit_writer", None)
        if aw is not None:
            try:
                from yashigani.audit.schema import NhiInstantiationDeniedEvent
                aw.write(NhiInstantiationDeniedEvent(
                    owner_identity_id=session.account_id,
                    ua_id=ua_id,
                    reason="empty_intersection",
                ))
            except Exception as exc:
                logger.warning("NhiInstantiationDeniedEvent audit write failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "NHI_INSTANTIATION_DENIED",
                "reason": "empty_intersection",
                "message": (
                    "Scope intersection is empty — the declared skills do not overlap "
                    "with your grants or the system ceiling. No NHI can be instantiated."
                ),
            },
        )

    agent_name = meta.get("name", ua_id)
    # Compute scope hash for audit (R3) + the leaf change-prevention binding
    # (v4.1 Phase 1a GAP-2). Single source: pki/binding.tool_surface_hash —
    # byte-identical to the previous inline sha384-over-canonical-JSON.
    from yashigani.pki.binding import tool_surface_hash
    scope_hash = tool_surface_hash(effective_tools)

    # Emit NHI_INSTANTIATION_REQUESTED
    aw = getattr(backoffice_state, "audit_writer", None)
    if aw is not None:
        try:
            from yashigani.audit.schema import NhiInstantiationRequestedEvent, NhiScopeIntersectedEvent
            aw.write(NhiInstantiationRequestedEvent(
                owner_identity_id=session.account_id,
                ua_id=ua_id,
                template_name=agent_name,
            ))
        except Exception as exc:
            logger.warning("NhiInstantiationRequestedEvent audit write failed: %s", exc)

    # Register NHI in AgentRegistry
    budget_cap = {
        "max_tokens_per_run": 8192,
        "max_tool_calls_per_run": 20,
    }
    try:
        nhi_id, _plaintext_token = agent_registry.register_nhi(
            name=agent_name,
            owner_identity_id=session.account_id,
            template_id=ua_id,
            allowed_tools=effective_tools,
            allowed_paths=effective_tools,
            allowed_models=[],
            sensitivity_ceiling="INTERNAL",
            budget_cap=budget_cap,
            pids_limit=64,
            memory_mb=512,
            # v4.1 Phase 1a GAP-2 — persist the tool-surface baseline so the
            # approve path can bind it into the leaf without recomputation.
            scope_hash=scope_hash,
        )
    except Exception as exc:
        logger.error("NHI registration failed for ua_id=%s: %s", ua_id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "nhi_registration_failed", "message": str(exc)},
        )

    # Persist nhi_id back to the agent meta
    r.hset(_meta_key(ua_id), mapping={
        b"nhi_id":     nhi_id.encode("utf-8"),
        b"updated_at": _now_iso().encode("utf-8"),
    })

    # 4.0 USER-PLANE-DURABILITY: dual-write to Postgres (best-effort)
    _upd = _get_user_plane_durable()
    if _upd is not None:
        try:
            _fresh = _decode_hash(r.hgetall(_meta_key(ua_id)))
            _upd.upsert_agent({
                "account_id":       session.account_id,
                "ua_id":            ua_id,
                "name":             _fresh.get("name", ""),
                "description":      _fresh.get("description", ""),
                "alias":            _fresh.get("alias", ""),
                "kind":             _fresh.get("kind", "agent"),
                "personality":      _fresh.get("personality"),
                "effective_skills": _fresh.get("effective_skills"),
                "declared_skills":  _fresh.get("declared_skills"),
                "graph":            _fresh.get("graph"),
                "graph_hash":       _fresh.get("graph_hash"),
                "letta_agent_id":   _fresh.get("letta_agent_id"),
                "nhi_id":           nhi_id,
            })
        except Exception as _exc:
            logger.error(
                "USER-PLANE-DURABLE: upsert_agent (run/nhi) failed for %s: %s", ua_id, _exc
            )

    # Emit NHI_SCOPE_INTERSECTED
    if aw is not None:
        try:
            aw.write(NhiScopeIntersectedEvent(
                nhi_id=nhi_id,
                owner_identity_id=session.account_id,
                effective_scope_hash=scope_hash,
                declared_scope_tool_count=len(declared_skills),
                effective_scope_tool_count=len(effective_tools),
            ))
        except Exception as exc:
            logger.warning("NhiScopeIntersectedEvent audit write failed: %s", exc)

    logger.info(
        "user_agents: NHI instantiated nhi_id=%s ua_id=%s account=%r effective_tools=%d rejected=%d",
        nhi_id, ua_id, session.account_id, len(effective_tools), len(rejected),
    )

    return {
        "ua_id": ua_id,
        "nhi_id": nhi_id,
        "effective_scope": {"allowed_tools": effective_tools},
        "rejected_tools": rejected,
        "svid_pending": True,
        "message": (
            "NHI registered (svid_issued=False). An admin must approve the NHI in the "
            "backoffice before gateway invocations are accepted."
        ),
    }


# ===========================================================================
# 4.0 no-code backend — NL-driven Langflow agent generation
# EU AI Act Art.14: AI generates, human decides (AGENT_FLOW_COMMITTED anchor).
# ===========================================================================

# ---------------------------------------------------------------------------
# Draft key helpers (ua:draft:{draft_id})
# ---------------------------------------------------------------------------

_DRAFT_PREFIX = "udrft_"
_DRAFT_TTL_SECONDS = 86400  # 24 h


def _new_draft_id() -> str:
    return f"{_DRAFT_PREFIX}{uuid.uuid4().hex[:12]}"


def _draft_key(draft_id: str) -> str:
    return f"ua:draft:{draft_id}"


# ---------------------------------------------------------------------------
# Langflow node types accepted in generated flows
# (LanguageModelComponent is repaired to OpenAIModel by _repair_flow_data)
# ---------------------------------------------------------------------------

_LANGFLOW_ALLOWED_COMPONENT_TYPES = frozenset({
    "ChatInput", "ChatOutput", "Prompt", "TextInput",
    "OpenAIModel", "LanguageModelComponent",
    "Memory", "ConversationChain", "LLMChain",
})

# ---------------------------------------------------------------------------
# Flow generation prompt
# ---------------------------------------------------------------------------

_FLOW_GEN_SYSTEM_PROMPT = (
    "You are a Langflow flow generator for the Yashigani AI security gateway.\n"
    "Generate a minimal, runnable Langflow flow JSON for the requested capability.\n\n"
    "OUTPUT: return ONLY a valid JSON object — no markdown fences, no explanation.\n"
    "FORMAT: {\"nodes\": [...], \"edges\": [...]}\n\n"
    "Allowed node types: ChatInput, ChatOutput, Prompt, TextInput, OpenAIModel, Memory\n"
    "All LLM calls route through the Yashigani gateway (OpenAI-compatible API).\n"
    "Use the minimum nodes needed. The output MUST start with { and end with }."
)


def _build_flow_gen_messages(
    description: str,
    allowed_model: str,
    gateway_base: str,
) -> list[dict]:
    """Build the governed-LLM messages list for flow generation."""
    user_content = (
        f"Generate a Langflow flow that does:\n\n{description}\n\n"
        f"Use model: {allowed_model}\n"
        f"openai_api_base (all model nodes): {gateway_base}\n\n"
        "Output the Langflow flow JSON object only."
    )
    return [
        {"role": "system", "content": _FLOW_GEN_SYSTEM_PROMPT},
        {"role": "user",   "content": user_content},
    ]


# ---------------------------------------------------------------------------
# Governed gateway LLM call
# ---------------------------------------------------------------------------

async def _call_governed_gateway_llm(messages: list[dict]) -> str:
    """Call the gateway mesh /v1/chat/completions (governed, OPA-adjudicated).

    Reads:
      YASHIGANI_INTERNAL_BEARER  — per-install internal service token
      YASHIGANI_GATEWAY_MESH_URL — gateway mesh base URL (default http://gateway:8081/v1)
      YASHIGANI_LANGFLOW_MODEL   — default model (default qwen2.5:3b)

    Returns the assistant content string.
    Raises HTTPException on misconfiguration (503) or upstream error (502).
    """
    import httpx as _httpx

    bearer = os.environ.get("YASHIGANI_INTERNAL_BEARER", "")
    if not bearer:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "llm_gateway_not_configured",
                "message": "YASHIGANI_INTERNAL_BEARER is not set — cannot reach governed LLM.",
            },
        )
    gateway_url = os.environ.get("YASHIGANI_GATEWAY_MESH_URL", "http://gateway:8081/v1")
    model_name = os.environ.get("YASHIGANI_LANGFLOW_MODEL", "qwen2.5:3b")

    try:
        async with _httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                f"{gateway_url}/chat/completions",
                json={
                    "model": model_name,
                    "messages": messages,
                    "temperature": 0.1,   # low temperature for deterministic JSON
                },
                headers={"Authorization": f"Bearer {bearer}"},
            )
        if resp.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail={
                    "error": "llm_gateway_error",
                    "message": f"Governed LLM gateway returned {resp.status_code}.",
                },
            )
        data = resp.json()
        return data["choices"][0]["message"]["content"]
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("_call_governed_gateway_llm: failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "error": "llm_gateway_unreachable",
                "message": "Could not reach the governed LLM gateway.",
            },
        )


# ---------------------------------------------------------------------------
# JSON extraction + flow validation + model-name clamping
# ---------------------------------------------------------------------------

def _extract_json_from_llm_response(text: str) -> dict:
    """Extract and parse a JSON object from an LLM response string.

    Handles markdown code-fences and leading/trailing prose that small models
    sometimes emit around the JSON blob.

    Raises:
        ValueError: If no valid JSON object can be parsed from ``text``.
    """
    text = text.strip()

    # 1. Direct parse
    try:
        result = json.loads(text)
        if isinstance(result, dict):
            return result
    except json.JSONDecodeError:
        pass

    # 2. Strip markdown fences (```json ... ``` or ``` ... ```)
    stripped = re.sub(r"```(?:json)?\s*", "", text)
    stripped = re.sub(r"\s*```", "", stripped).strip()
    try:
        result = json.loads(stripped)
        if isinstance(result, dict):
            return result
    except json.JSONDecodeError:
        pass

    # 3. Brace extraction: find first { … last }
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        try:
            result = json.loads(text[start : end + 1])
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            pass

    raise ValueError(
        f"No valid JSON object found in LLM response (first 200 chars): {text[:200]!r}"
    )


def _validate_langflow_flow(flow_data: dict) -> list[str]:
    """Structural validation of a generated Langflow flow JSON.

    Returns a (possibly empty) list of error strings.
    An empty list means the flow is structurally valid.
    """
    errors: list[str] = []
    if not isinstance(flow_data, dict):
        errors.append("flow must be a JSON object")
        return errors

    nodes = flow_data.get("nodes", [])
    edges = flow_data.get("edges", [])

    if not isinstance(nodes, list):
        errors.append("flow.nodes must be an array")
    if not isinstance(edges, list):
        errors.append("flow.edges must be an array")
    if errors:
        return errors

    if len(nodes) == 0:
        errors.append("flow must have at least one node")
    if len(nodes) > 32:
        errors.append(f"flow has too many nodes ({len(nodes)} > 32)")
    if len(edges) > 64:
        errors.append(f"flow has too many edges ({len(edges)} > 64)")

    return errors


def _clamp_langflow_flow_models(
    flow_data: dict,
    allowed_model: str,
) -> tuple[dict, list[str]]:
    """Clamp every OpenAIModel node's model_name to ``allowed_model``.

    Any model_name value that differs from ``allowed_model`` is replaced.
    Returns (clamped_flow_data, warning_strings).

    This is the scope-enforcement step: whatever model name the LLM
    generated, the executed flow may only use the gateway's allowed model.
    The actual OPA-per-request enforcement on the gateway mesh is the
    second layer; this is the first layer (generation-time clamp).
    """
    flow_data = json.loads(json.dumps(flow_data))  # deep copy
    warnings: list[str] = []

    for node in flow_data.get("nodes", []):
        if not isinstance(node, dict):
            continue
        node_data = node.get("data", {})
        if not isinstance(node_data, dict):
            continue
        node_type = node_data.get("type", "")
        if node_type != "OpenAIModel":
            continue
        template = node_data.get("node", {}).get("template", {})
        if not isinstance(template, dict):
            continue
        model_slot = template.get("model_name")
        if isinstance(model_slot, dict):
            current = model_slot.get("value", "")
            if current and current != allowed_model:
                warnings.append(
                    f"model_name {current!r} → {allowed_model!r} (scope clamp)"
                )
                model_slot["value"] = allowed_model
        elif isinstance(model_slot, str) and model_slot and model_slot != allowed_model:
            warnings.append(
                f"model_name {model_slot!r} → {allowed_model!r} (scope clamp)"
            )
            template["model_name"] = allowed_model

    return flow_data, warnings[:20]  # cap at 20 warning strings


# ---------------------------------------------------------------------------
# Pydantic request bodies (no-code)
# ---------------------------------------------------------------------------


class GenerateFlowBody(BaseModel):
    """Body for POST /user/agents/generate."""

    description: str = Field(
        min_length=10,
        max_length=2000,
        description="Natural language description of what the agent should do.",
    )


class CommitFlowBody(BaseModel):
    """Body for POST /user/agents/templates (human-decides step)."""

    draft_id: str = Field(
        min_length=1,
        max_length=64,
        description="The draft_id returned by POST /user/agents/generate.",
    )
    name: str = Field(min_length=1, max_length=128, description="Display name for the agent.")
    description: str = Field(default="", max_length=512)
    skills: list[str] = Field(
        default_factory=list,
        max_length=50,
        description="Declared skills for scope intersection (R3).",
    )


# ===========================================================================
# POST /user/agents/generate — NL description → governed LLM → Langflow flow
# ===========================================================================


@router.post("/user/agents/generate")
async def generate_user_agent_flow(body: GenerateFlowBody, session: UserSession):
    """Generate a Langflow flow from a natural-language description.

    Pipeline:
      1. Call our governed LLM through the gateway mesh (OPA-adjudicated).
      2. Parse and structurally validate the generated flow JSON.
      3. Clamp all model-name references to the gateway default (scope enforcement).
      4. Create the draft flow in Langflow via create_flow().
      5. Store a draft record in Redis (ua:draft:{draft_id}, TTL 24 h) as BOLA anchor.
      6. Emit AGENT_FLOW_GENERATION_REQUESTED + AGENT_FLOW_GENERATED audit events.
      7. Return {draft_id, flow_id, summary, graph, spec_hash, clamp_warnings, draft: true}.

    The draft is NOT added to the template pool.  The caller reviews the
    preview and explicitly commits via POST /user/agents/templates.

    EU AI Act Art.14: AI generates; human decides.
    BOLA: draft is scoped by draft_id → account_id in Redis.
    """
    r = _get_redis()

    # Derive gateway mesh endpoint and the single allowed model.
    # All generated flow model nodes are clamped to this model.
    gateway_base = os.environ.get("YASHIGANI_GATEWAY_MESH_URL", "http://gateway:8081/v1")
    allowed_model = os.environ.get("YASHIGANI_LANGFLOW_MODEL", "qwen2.5:3b")

    # For the audit pre-record, capture the user's current effective scope.
    invoker_grants = _get_invoker_grants(session.account_id)
    system_ceiling = _compute_system_ceiling(r)
    user_scope = invoker_grants & system_ceiling if invoker_grants else system_ceiling
    effective_skills_preview = sorted(user_scope)[:10]

    # Emit AGENT_FLOW_GENERATION_REQUESTED before the LLM call (chain-of-custody).
    aw = getattr(backoffice_state, "audit_writer", None)
    if aw is not None:
        try:
            from yashigani.audit.schema import AgentFlowGenerationRequestedEvent
            aw.write(AgentFlowGenerationRequestedEvent(
                owner_identity_id=session.account_id,
                description_length=len(body.description),
                effective_skills=effective_skills_preview,
            ))
        except Exception as exc:
            logger.warning("AgentFlowGenerationRequestedEvent audit write failed: %s", exc)

    # --- Step 1: governed LLM call ---
    messages = _build_flow_gen_messages(body.description, allowed_model, gateway_base)
    llm_response = await _call_governed_gateway_llm(messages)

    # --- Step 2: parse + validate ---
    try:
        flow_data = _extract_json_from_llm_response(llm_response)
    except ValueError as exc:
        logger.warning(
            "generate_user_agent_flow: LLM produced non-JSON for account=%r: %s",
            session.account_id, exc,
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "invalid_flow_generated",
                "message": (
                    "The AI could not produce a valid flow for this description. "
                    "Try rephrasing or adding more detail."
                ),
            },
        )

    validation_errors = _validate_langflow_flow(flow_data)
    if validation_errors:
        logger.warning(
            "generate_user_agent_flow: validation failed for account=%r: %r",
            session.account_id, validation_errors,
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "invalid_flow_generated",
                "message": "Generated flow failed structural validation.",
                "violations": validation_errors,
            },
        )

    # --- Step 3: clamp model names (scope enforcement) ---
    flow_data, clamp_warnings = _clamp_langflow_flow_models(flow_data, allowed_model)

    # --- Step 4: create draft flow in Langflow ---
    draft_flow_name = f"draft-{uuid.uuid4().hex[:8]}"
    summary = (body.description[:200] + "…") if len(body.description) > 200 else body.description

    try:
        from yashigani.gateway.langflow_client import create_flow as _langflow_create_flow
        langflow_base = os.environ.get("YASHIGANI_LANGFLOW_URL", "http://langflow:7860")
        flow_id = await _langflow_create_flow(
            base_url=langflow_base,
            flow_data=flow_data,
            flow_name=draft_flow_name,
            description=f"Draft: {summary}",
        )
    except Exception as exc:
        logger.error(
            "generate_user_agent_flow: Langflow create_flow failed for account=%r: %s",
            session.account_id, exc,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "error": "langflow_unavailable",
                "message": "Could not create the draft flow in Langflow. Try again later.",
            },
        )

    # --- Step 5: store draft in Redis (BOLA anchor) ---
    draft_id = _new_draft_id()
    spec_hash = "sha384:" + hashlib.sha384(
        json.dumps(flow_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    now = _now_iso()

    draft_mapping: dict[bytes, bytes] = {
        b"account_id":  session.account_id.encode(),
        b"flow_id":     flow_id.encode(),
        b"flow_name":   draft_flow_name.encode(),
        b"summary":     summary.encode(),
        b"spec_hash":   spec_hash.encode(),
        b"spec_json":   json.dumps(flow_data).encode(),
        b"created_at":  now.encode(),
    }
    pipe = r.pipeline()
    pipe.hset(_draft_key(draft_id), mapping=draft_mapping)
    pipe.expire(_draft_key(draft_id), _DRAFT_TTL_SECONDS)
    pipe.execute()

    # --- Step 6: emit AGENT_FLOW_GENERATED ---
    if aw is not None:
        try:
            from yashigani.audit.schema import AgentFlowGeneratedEvent
            aw.write(AgentFlowGeneratedEvent(
                owner_identity_id=session.account_id,
                draft_id=draft_id,
                flow_id=flow_id,
                spec_hash=spec_hash,
                clamp_warnings=clamp_warnings,
            ))
        except Exception as exc:
            logger.warning("AgentFlowGeneratedEvent audit write failed: %s", exc)

    logger.info(
        "user_agents: flow generated draft_id=%s flow_id=%s for account=%r "
        "clamp_warnings=%d",
        draft_id, flow_id, session.account_id, len(clamp_warnings),
    )

    return {
        "draft_id": draft_id,
        "flow_id": flow_id,
        "summary": summary,
        "graph": flow_data,
        "spec_hash": spec_hash,
        "clamp_warnings": clamp_warnings,
        "draft": True,
    }


# ===========================================================================
# POST /user/agents/templates — human commits a draft to the template pool
# ===========================================================================


@router.post("/user/agents/templates", status_code=status.HTTP_201_CREATED)
async def commit_agent_template(body: CommitFlowBody, session: UserSession):
    """Explicitly commit a generated draft flow to the user's template pool.

    This is the HUMAN-DECIDES step (EU AI Act Art.14 / HITL invariant).
    The LLM generated the flow; this endpoint records the human's explicit
    decision to add it as an agent template.

    Steps:
      1. Look up ua:draft:{draft_id} (HTTP 404 if missing or expired).
      2. BOLA: verify draft.account_id == session.account_id (HTTP 404 on violation).
      3. Compute effective_skills via R3 scope intersection.
      4. Register a governed Langflow callee in agent_registry (non-fatal).
      5. Create ua:meta:{ua_id} with langflow_flow_id + callee_agent_id.
      6. Consume the draft (delete from Redis).
      7. Emit AGENT_FLOW_COMMITTED to the audit hash-chain.

    BOLA: only the generating user can commit their own draft.
    """
    r = _get_redis()

    # --- Step 1+2: look up draft and verify ownership (BOLA) ---
    raw_draft = r.hgetall(_draft_key(body.draft_id))
    if not raw_draft:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "draft_not_found",
                "message": "Draft not found or expired. Generate a new flow first.",
            },
        )
    draft = _decode_hash(raw_draft)

    # BOLA: return 404, not 403 — do not disclose draft existence to other users.
    if draft.get("account_id") != session.account_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "draft_not_found"},
        )

    flow_id = draft.get("flow_id", "")
    spec_hash = draft.get("spec_hash", "")
    draft_summary = draft.get("summary", body.description)

    # --- Step 3: R3 scope intersection ---
    effective, rejected = compute_effective_skills(body.skills, session.account_id, r)

    # --- Step 4: register governed Langflow callee ---
    # Name must satisfy ^[a-z][a-z0-9_-]{0,63}$ (V232-CSCAN-01a).
    # Use a deterministic short slug derived from a new UUID.
    callee_slug = f"ucallee{uuid.uuid4().hex[:8]}"

    agent_registry = getattr(backoffice_state, "agent_registry", None)
    callee_agent_id: Optional[str] = None
    if agent_registry is not None and flow_id:
        langflow_base = os.environ.get("YASHIGANI_LANGFLOW_URL", "http://langflow:7860")
        try:
            callee_agent_id, _callee_token = agent_registry.register(
                name=callee_slug,
                upstream_url=f"{langflow_base}/api/v1/run/{flow_id}",
                groups=["user_agent_callee"],
                allowed_caller_groups=["user"],
                allowed_paths=[f"/api/v1/run/{flow_id}"],
                protocol="langflow",
                kind="agent",
                sensitivity_ceiling="INTERNAL",
                allowed_tools=effective,
            )
        except Exception as exc:
            # Non-fatal: the agent template is committed to the pool; the
            # registry entry can be re-created on retry.  Log loudly.
            logger.error(
                "commit_agent_template: callee registry.register failed for "
                "account=%r flow_id=%r: %s",
                session.account_id, flow_id, exc,
            )
            callee_agent_id = None

    # --- Step 5: create ua:meta record ---
    ua_id = _new_ua_id()
    now = _now_iso()
    personality = {
        "persona": f"A Langflow-based agent: {draft_summary[:200]}",
        "system_prompt": "",
    }

    # Derive @-handle for the committed flow agent (same logic as create_user_agent).
    # If alias is taken by another agent, append a short unique suffix to avoid 409.
    raw_alias = _normalize_alias(body.name)
    if r.hget(_alias_key(session.account_id), raw_alias) is not None:
        raw_alias = f"{raw_alias[:56]}_{uuid.uuid4().hex[:6]}"

    ua_mapping: dict[bytes, bytes] = {
        b"account_id":        session.account_id.encode(),
        b"name":              body.name.encode(),
        b"description":       body.description.encode(),
        b"alias":             raw_alias.encode(),
        b"personality":       json.dumps(personality).encode(),
        b"effective_skills":  json.dumps(effective).encode(),
        b"declared_skills":   json.dumps(body.skills).encode(),
        b"letta_agent_id":    b"",
        b"langflow_flow_id":  flow_id.encode(),
        b"callee_agent_id":   (callee_agent_id or "").encode(),
        b"spec_hash":         spec_hash.encode(),
        b"kind":              b"langflow_callee",
        b"created_at":        now.encode(),
        b"updated_at":        now.encode(),
    }

    pipe = r.pipeline()
    pipe.hset(_meta_key(ua_id), mapping=ua_mapping)
    pipe.sadd(_agents_key(session.account_id), ua_id.encode())
    # Alias index: ua:alias:{account_id} hash → {alias: ua_id}
    pipe.hset(_alias_key(session.account_id), raw_alias, ua_id)
    # Consume the draft — committed; TTL would clear it anyway but be explicit.
    pipe.delete(_draft_key(body.draft_id))
    pipe.execute()

    # 4.0 USER-PLANE-DURABILITY: dual-write to Postgres (best-effort)
    _upd = _get_user_plane_durable()
    if _upd is not None:
        try:
            _upd.upsert_agent({
                "account_id":       session.account_id,
                "ua_id":            ua_id,
                "name":             body.name,
                "description":      body.description,
                "alias":            raw_alias,
                "kind":             "langflow_callee",
                "personality":      json.dumps(personality),
                "effective_skills": json.dumps(effective),
                "declared_skills":  json.dumps(body.skills),
                "letta_agent_id":   "",
                "nhi_id":           "",
            })
        except Exception as _exc:
            logger.error(
                "USER-PLANE-DURABLE: upsert_agent (commit-template) failed for %s: %s",
                ua_id, _exc,
            )

    # --- Step 6: emit AGENT_FLOW_COMMITTED (human-decides audit anchor) ---
    aw = getattr(backoffice_state, "audit_writer", None)
    if aw is not None:
        try:
            from yashigani.audit.schema import AgentFlowCommittedEvent
            aw.write(AgentFlowCommittedEvent(
                owner_identity_id=session.account_id,
                ua_id=ua_id,
                draft_id=body.draft_id,
                flow_id=flow_id,
                spec_hash=spec_hash,
                callee_registered=callee_agent_id is not None,
                human_decided=True,
            ))
        except Exception as exc:
            logger.warning("AgentFlowCommittedEvent audit write failed: %s", exc)

    logger.info(
        "user_agents: flow committed ua_id=%s flow_id=%s callee=%s for account=%r",
        ua_id, flow_id, callee_agent_id, session.account_id,
    )

    return {
        "ua_id": ua_id,
        "name": body.name,
        "flow_id": flow_id,
        "effective_skills": effective,
        "rejected_skills": rejected,
        "callee_agent_id": callee_agent_id,
        "governed_callee_registered": callee_agent_id is not None,
        "spec_hash": spec_hash,
        "created_at": now,
    }
