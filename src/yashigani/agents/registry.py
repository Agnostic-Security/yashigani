"""
Yashigani Agent Registry — Manages registered agent identities and PSK tokens.
# Last updated: 2026-05-05T00:00:00+01:00

Key schema (Redis db/3, namespace agent:*):
  agent:reg:{agent_id}      Hash: name, upstream_url, status, created_at,
                             last_seen_at, groups (JSON), allowed_caller_groups (JSON),
                             allowed_paths (JSON)
  agent:token:{agent_id}    String: bcrypt hash of PSK (cost 12)
  agent:index:all           Set: all agent_id values
  agent:index:active        Set: active agent_id values
"""
from __future__ import annotations

import bcrypt
import datetime
import json
import logging
import re
import secrets
import uuid
from typing import Optional

from yashigani.licensing.enforcer import LicenseLimitExceeded

logger = logging.getLogger(__name__)

_BCRYPT_COST = 12

# V232-CSCAN-01a: canonical agent-name pattern (must match AgentRegisterRequest.name).
# Any existing registry entry whose name does not match is flagged at startup.
_AGENT_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")


def _now_iso() -> str:
    return datetime.datetime.now(tz=datetime.timezone.utc).isoformat()


class AgentRegistry:
    """
    Thread-safe agent registry backed by Redis db/3.

    Agent IDs use the prefix agnt_ followed by 12 hex chars.
    PSK tokens are 256-bit hex strings (64 chars).
    Token hashes use bcrypt cost 12 — never store plaintext.
    """

    # LAURA-LIMIT-AGENTS-01 + AGENTS-03 (GROUP-4-1): atomic Lua script for
    # agent registration. Replaces the non-atomic count→check→hset→sadd
    # pipeline which had a TOCTOU race:
    #   Thread A: count() = 9 (limit = 10) → passes check
    #   Thread B: count() = 9 (limit = 10) → passes check
    #   Thread A: hset + sadd → active count = 10
    #   Thread B: hset + sadd → active count = 11 → LIMIT BYPASSED
    #
    # The Lua script executes atomically under Redis's single-threaded model.
    # KEYS[1] = agent:index:active
    # KEYS[2] = agent:index:all
    # KEYS[3] = agent:reg:{agent_id}
    # KEYS[4] = agent:token:{agent_id}
    # ARGV[1] = limit (int, -1 = unlimited)
    # ARGV[2] = agent_id
    # ARGV[3] = token_hash
    # ARGV[4..N] = flat key-value pairs for HSET
    _REGISTER_LUA = """
local limit = tonumber(ARGV[1])
local current = tonumber(redis.call("SCARD", KEYS[1]))
if limit ~= -1 and current >= limit then
    return redis.error_reply("LIMIT_EXCEEDED:" .. current .. ":" .. limit)
end
local agent_id = ARGV[2]
local token_hash = ARGV[3]
-- Build HSET mapping from ARGV[4..] (pairs: field, value, field, value, ...)
local hset_args = {}
for i = 4, #ARGV do
    table.insert(hset_args, ARGV[i])
end
redis.call("HSET", KEYS[3], unpack(hset_args))
redis.call("SET", KEYS[4], token_hash)
redis.call("SADD", KEYS[2], agent_id)
redis.call("SADD", KEYS[1], agent_id)
return 1
"""

    def __init__(self, redis_client) -> None:
        self._r = redis_client
        total = self._r.scard("agent:index:all") or 0
        logger.info("AgentRegistry initialised: %d agent(s) in index", total)
        # V232-CSCAN-01a migration check: warn on names that pre-date the slug constraint.
        # These entries are not deleted (non-breaking), but the gateway will skip their
        # secret-file lookup due to the path-resolution guard in openai_router.py.
        self._warn_non_compliant_names()

    # ── Startup integrity check (V232-CSCAN-01a) ─────────────────────────────

    def _warn_non_compliant_names(self) -> None:
        """Log a structured warning for any existing agent whose name does not satisfy
        the slug pattern '^[a-z][a-z0-9_-]{0,63}$' introduced in v2.23.2.

        Non-compliant entries are NOT deleted — that would break existing deployments.
        They are flagged here and surfaced as ``legacy_name_violation=True`` in list_all()
        so the admin UI can display them as a flagged row.
        """
        try:
            for agent in self.list_all():
                name = agent.get("name", "")
                if not _AGENT_NAME_RE.fullmatch(name):
                    logger.warning(
                        "V232-CSCAN-01a: agent %r (id=%s) has a name %r that does not satisfy "
                        "the slug pattern -- secret-file lookup will be skipped for this agent; "
                        "re-register with a compliant name or remove this entry",
                        name, agent.get("agent_id", "?"), name,
                    )
        except Exception as exc:
            logger.warning("V232-CSCAN-01a name-compliance check failed (non-fatal): %s", exc)

    # ── Registration ─────────────────────────────────────────────────────────

    def register(
        self,
        name: str,
        upstream_url: str,
        groups: list,
        allowed_caller_groups: list,
        allowed_paths: list,
        allowed_cidrs: list | None = None,
        protocol: str = "openai",
    ) -> tuple[str, str]:
        """
        Register a new agent atomically via Lua script.

        The Lua script performs an atomic SCARD → limit check → HSET + SET + SADD
        sequence. This eliminates the TOCTOU race in the previous count → check →
        pipeline pattern (LAURA-LIMIT-AGENTS-01 / AGENTS-03, GROUP-4-1).

        Returns (agent_id, plaintext_token). The plaintext token is never
        stored again — the caller is responsible for delivering it securely.

        Raises LicenseLimitExceeded when the active agent count is at the limit.
        """
        from yashigani.licensing.enforcer import get_license

        lic = get_license()
        limit = lic.max_agents  # -1 = unlimited

        agent_id = f"agnt_{uuid.uuid4().hex[:12]}"
        plaintext_token = secrets.token_bytes(32).hex()

        token_hash = bcrypt.hashpw(
            plaintext_token.encode("utf-8"), bcrypt.gensalt(rounds=_BCRYPT_COST)
        ).decode("utf-8")

        now = _now_iso()

        # Flat HSET argv list: field, value, field, value, ...
        hset_pairs: list[str] = [
            "name",                    name,
            "upstream_url",            upstream_url,
            "protocol",                protocol,
            "status",                  "active",
            "created_at",              now,
            "last_seen_at",            "",
            "groups",                  json.dumps(groups),
            "allowed_caller_groups",   json.dumps(allowed_caller_groups),
            "allowed_paths",           json.dumps(allowed_paths),
            "allowed_cidrs",           json.dumps(allowed_cidrs or []),
        ]

        keys = [
            "agent:index:active",          # KEYS[1]
            "agent:index:all",             # KEYS[2]
            f"agent:reg:{agent_id}",       # KEYS[3]
            f"agent:token:{agent_id}",     # KEYS[4]
        ]
        argv = [
            str(limit),                    # ARGV[1]
            agent_id,                      # ARGV[2]
            token_hash,                    # ARGV[3]
        ] + hset_pairs                     # ARGV[4..]

        try:
            self._r.eval(self._REGISTER_LUA, len(keys), *keys, *argv)
        except Exception as exc:
            err_str = str(exc)
            if "LIMIT_EXCEEDED" in err_str:
                # Parse "LIMIT_EXCEEDED:current:max" from Redis error reply
                try:
                    parts = err_str.split(":")
                    current = int(parts[1])
                    max_val = int(parts[2])
                except (IndexError, ValueError):
                    current = self.count("active")
                    max_val = limit
                raise LicenseLimitExceeded(
                    limit_name="max_agents",
                    current=current,
                    max_val=max_val,
                ) from exc
            raise

        logger.info("AgentRegistry: registered %s (%s)", agent_id, name)
        return agent_id, plaintext_token

    # ── Reads ─────────────────────────────────────────────────────────────────

    def get(self, agent_id: str) -> Optional[dict]:
        """Return agent dict or None if not found."""
        reg_key = f"agent:reg:{agent_id}"
        raw = self._r.hgetall(reg_key)
        if not raw:
            return None
        return self._decode_agent(agent_id, raw)

    def list_all(self) -> list[dict]:
        """Return all agents (active and inactive)."""
        agent_ids = [
            aid.decode("utf-8") if isinstance(aid, bytes) else aid
            for aid in self._r.smembers("agent:index:all")
        ]
        result = []
        for aid in sorted(agent_ids):
            agent = self.get(aid)
            if agent is not None:
                result.append(agent)
        return result

    def list_active(self) -> list[dict]:
        """Return active agents only."""
        agent_ids = [
            aid.decode("utf-8") if isinstance(aid, bytes) else aid
            for aid in self._r.smembers("agent:index:active")
        ]
        result = []
        for aid in sorted(agent_ids):
            agent = self.get(aid)
            if agent is not None:
                result.append(agent)
        return result

    # ── Mutations ─────────────────────────────────────────────────────────────

    def update(self, agent_id: str, **fields) -> None:
        """
        Update mutable fields: name, upstream_url, groups,
        allowed_caller_groups, allowed_paths.
        """
        allowed_fields = {
            "name", "upstream_url", "groups",
            "allowed_caller_groups", "allowed_paths", "allowed_cidrs",
        }
        reg_key = f"agent:reg:{agent_id}"
        mapping = {}
        for k, v in fields.items():
            if k not in allowed_fields:
                logger.warning("AgentRegistry.update: ignoring unknown field %r", k)
                continue
            if isinstance(v, (list, dict)):
                mapping[k.encode("utf-8")] = json.dumps(v).encode("utf-8")
            else:
                mapping[k.encode("utf-8")] = str(v).encode("utf-8")
        if mapping:
            self._r.hset(reg_key, mapping=mapping)
            logger.info("AgentRegistry: updated %s fields=%s", agent_id, list(fields.keys()))

    def deactivate(self, agent_id: str) -> None:
        """Set status=inactive and remove from active index."""
        reg_key = f"agent:reg:{agent_id}"
        self._r.hset(reg_key, b"status", b"inactive")
        self._r.srem("agent:index:active", agent_id.encode("utf-8"))
        logger.info("AgentRegistry: deactivated %s", agent_id)

    # ── Token operations ──────────────────────────────────────────────────────

    def verify_token(self, agent_id: str, plaintext_token: str) -> bool:
        """
        Verify a plaintext PSK against the stored bcrypt hash.
        Calls _update_last_seen on success.
        Always returns False on any error (fail-closed).
        """
        try:
            token_key = f"agent:token:{agent_id}"
            stored = self._r.get(token_key)
            if not stored:
                return False
            stored_hash = stored if isinstance(stored, bytes) else stored.encode("utf-8")
            candidate = plaintext_token.encode("utf-8")
            ok = bcrypt.checkpw(candidate, stored_hash)
            if ok:
                self._update_last_seen(agent_id)
            return ok
        except Exception as exc:
            logger.error("AgentRegistry.verify_token error for %s: %s", agent_id, exc)
            return False

    def rotate_token(self, agent_id: str) -> str:
        """
        Generate a new 256-bit token, hash and store it, return the plaintext.
        """
        plaintext_token = secrets.token_bytes(32).hex()
        token_hash = bcrypt.hashpw(
            plaintext_token.encode("utf-8"), bcrypt.gensalt(rounds=_BCRYPT_COST)
        ).decode("utf-8")
        token_key = f"agent:token:{agent_id}"
        self._r.set(token_key, token_hash.encode("utf-8"))
        logger.info("AgentRegistry: token rotated for %s", agent_id)
        return plaintext_token

    # ── Counts ────────────────────────────────────────────────────────────────

    def count(self, status: str = "active") -> int:
        """Return count of agents by status ('active' or 'inactive' or 'all')."""
        if status == "active":
            return self._r.scard("agent:index:active") or 0
        if status == "all":
            return self._r.scard("agent:index:all") or 0
        # inactive = all - active
        total = self._r.scard("agent:index:all") or 0
        active = self._r.scard("agent:index:active") or 0
        return max(0, total - active)

    # ── Internal ─────────────────────────────────────────────────────────────

    def _update_last_seen(self, agent_id: str) -> None:
        reg_key = f"agent:reg:{agent_id}"
        self._r.hset(reg_key, b"last_seen_at", _now_iso().encode("utf-8"))

    @staticmethod
    def _decode_agent(agent_id: str, raw: dict) -> dict:
        """Decode Redis hash (bytes keys/values) into a Python dict."""

        def _b(key: bytes) -> str:
            val = raw.get(key, b"")
            return val.decode("utf-8") if isinstance(val, bytes) else val

        def _j(key: bytes) -> list:
            try:
                return json.loads(_b(key))
            except Exception:
                return []

        upstream_url = _b(b"upstream_url")
        # v2.4.1 — pool_image: derived from upstream_url when it uses pool:// scheme.
        # Stored as pool://<image>; surfaced as a separate convenience field so
        # callers can distinguish pool-managed from externally-deployed agents.
        pool_image = upstream_url[len("pool://"):] if upstream_url.startswith("pool://") else None

        return {
            "agent_id": agent_id,
            "name": _b(b"name"),
            "upstream_url": upstream_url,
            "protocol": _b(b"protocol") or "openai",
            "status": _b(b"status"),
            "created_at": _b(b"created_at"),
            "last_seen_at": _b(b"last_seen_at"),
            "groups": _j(b"groups"),
            "allowed_caller_groups": _j(b"allowed_caller_groups"),
            "allowed_paths": _j(b"allowed_paths"),
            "allowed_cidrs": _j(b"allowed_cidrs"),
            # v0.9.0 — token rotation fields (F-09)
            "token_last_rotated": _b(b"token_last_rotated"),
            "token_rotation_schedule": _b(b"token_rotation_schedule"),
            # v2.4.1 — pool_image (None for externally-deployed agents)
            "pool_image": pool_image,
        }
