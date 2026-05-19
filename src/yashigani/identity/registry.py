"""
Yashigani Unified Identity Registry.

Every entity (human or service) is an identity with a `kind` field.
Backed by Redis (hot path) with Postgres as durable store.
Same governance, budget, RBAC, and audit trail for all identity kinds.

Redis namespace (db/3):
  identity:reg:{identity_id}      Hash: all identity fields
  identity:key:{identity_id}      String: bcrypt hash of current API key
  identity:key:grace:{identity_id} String: bcrypt hash of previous key (grace period)
  identity:index:all              Set: all identity_id values
  identity:index:active           Set: active identity_id values
  identity:index:kind:human       Set: human identity_ids
  identity:index:kind:service     Set: service identity_ids
  identity:index:org:{org_id}     Set: identity_ids owned by org_id (SEC-240-7)
  identity:slug:{slug}            String: identity_id (slug -> id lookup)
"""
# Last updated: 2026-05-03T00:00:00+01:00
from __future__ import annotations

import datetime
import enum
import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import Optional

from yashigani.identity.api_key import (
    generate_api_key,
    hash_api_key,
    verify_api_key,
    expiry_from_now,
    MAX_LIFETIME_DAYS,
)

logger = logging.getLogger(__name__)


class IdentityKind(str, enum.Enum):
    HUMAN = "human"
    SERVICE = "service"


def _now_iso() -> str:
    return datetime.datetime.now(tz=datetime.timezone.utc).isoformat()


def _new_identity_id() -> str:
    return f"idnt_{uuid.uuid4().hex[:12]}"


@dataclass
class IdentityRecord:
    """In-memory representation of an identity."""
    identity_id: str
    kind: IdentityKind
    name: str
    slug: str
    description: str = ""
    expertise: list[str] = field(default_factory=list)
    system_prompt: str = ""
    model_preference: str = ""
    sensitivity_ceiling: str = "PUBLIC"
    upstream_url: str = ""
    container_image: str = ""
    container_config: dict = field(default_factory=dict)
    capabilities: list[str] = field(default_factory=list)
    allowed_tools: list[str] = field(default_factory=list)
    allowed_models: list[str] = field(default_factory=list)
    icon_url: str = ""
    groups: list[str] = field(default_factory=list)
    allowed_callers: list[str] = field(default_factory=list)
    allowed_paths: list[str] = field(default_factory=list)
    allowed_cidrs: list[str] = field(default_factory=list)
    org_id: str = ""
    status: str = "active"
    created_at: str = ""
    updated_at: str = ""
    last_seen_at: str = ""
    token_rotation_schedule: str = ""
    # V10.3.5 — sender-constrained token binding.
    # When non-empty, the bearer token is SPIFFE-URI-bound: the caller must
    # present a client cert whose URI SAN (passed by Caddy as X-SPIFFE-ID)
    # exactly matches this value.  Empty = no binding (community/legacy agents).
    bound_spiffe_uri: str = ""


class IdentityRegistry:
    """
    Unified identity registry backed by Redis db/3.

    Thread-safe. All mutations are atomic Redis operations.
    """

    # LAURA-LIMIT-AGENTS-01 / GROUP-4-1: atomic Lua script for HUMAN identity
    # registration. Checks `identity:index:kind:human` SCARD against the
    # end-user limit before registering to eliminate the TOCTOU race in the
    # previous slug-check → pipeline sequence.
    #
    # This script ONLY enforces the HUMAN limit; SERVICE identities use the
    # regular pipeline path (no per-kind seat limit for service accounts).
    #
    # KEYS[1] = identity:index:kind:human  (limit source — SCARD)
    # KEYS[2] = identity:index:all
    # KEYS[3] = identity:index:active
    # KEYS[4] = identity:index:kind:human  (sadd target — same key as [1])
    # KEYS[5] = identity:slug:{slug}
    # KEYS[6] = identity:reg:{identity_id}
    # KEYS[7] = identity:key:{identity_id}
    # KEYS[8] = identity:index:org:{org_id} (may be "" — caller passes "" to skip)
    # ARGV[1] = limit (-1 = unlimited)
    # ARGV[2] = identity_id
    # ARGV[3] = key_hash
    # ARGV[4] = org_id (empty string = no org index)
    # ARGV[5..N] = flat key-value pairs for HSET on identity:reg
    _REGISTER_HUMAN_LUA = """
local limit = tonumber(ARGV[1])
local current = tonumber(redis.call("SCARD", KEYS[1]))
if limit ~= -1 and current >= limit then
    return redis.error_reply("LIMIT_EXCEEDED:" .. current .. ":" .. limit)
end
local identity_id = ARGV[2]
local key_hash = ARGV[3]
local org_id = ARGV[4]
local slug_key = KEYS[5]
local reg_key = KEYS[6]
local key_key = KEYS[7]
-- Build HSET mapping from ARGV[5..] (pairs: field, value, ...)
local hset_args = {}
for i = 5, #ARGV do
    table.insert(hset_args, ARGV[i])
end
redis.call("HSET", reg_key, unpack(hset_args))
redis.call("SET", key_key, key_hash)
redis.call("SET", slug_key, identity_id)
redis.call("SADD", KEYS[2], identity_id)
redis.call("SADD", KEYS[3], identity_id)
redis.call("SADD", KEYS[4], identity_id)
if org_id ~= "" then
    redis.call("SADD", KEYS[8], identity_id)
end
return 1
"""

    def __init__(self, redis_client) -> None:
        self._r = redis_client
        count = self._r.scard("identity:index:all") or 0
        logger.info("IdentityRegistry initialised: %d identity(ies)", count)

    # ── Registration ─────────────────────────────────────────────────────

    def register(
        self,
        kind: IdentityKind,
        name: str,
        slug: str,
        description: str = "",
        expertise: list[str] | None = None,
        system_prompt: str = "",
        model_preference: str = "",
        sensitivity_ceiling: str = "PUBLIC",
        upstream_url: str = "",
        container_image: str = "",
        container_config: dict | None = None,
        capabilities: list[str] | None = None,
        allowed_tools: list[str] | None = None,
        allowed_models: list[str] | None = None,
        icon_url: str = "",
        groups: list[str] | None = None,
        allowed_callers: list[str] | None = None,
        allowed_paths: list[str] | None = None,
        allowed_cidrs: list[str] | None = None,
        org_id: str = "",
        spiffe_uri: str = "",
    ) -> tuple[str, str]:
        """
        Register a new identity.

        For HUMAN kind: uses an atomic Lua script that checks the end-user seat
        limit against identity:index:kind:human before registering (GROUP-4-1 /
        LAURA-LIMIT-AGENTS-01). Raises LicenseLimitExceeded on breach.

        For SERVICE kind: uses the regular Redis pipeline (no per-kind limit).

        Returns (identity_id, plaintext_api_key).
        The plaintext key is shown once — caller must deliver it securely.
        """
        from yashigani.licensing.enforcer import LicenseLimitExceeded, get_license

        # Check slug uniqueness (non-atomic pre-check; slug key SET is part of
        # Lua script for HUMAN, so a duplicate slug after this check is safe
        # for SERVICE kind — SET is idempotent/last-writer-wins, which is
        # acceptable since slug collisions raise ValueError before reaching Lua).
        if self._r.exists(f"identity:slug:{slug}"):
            raise ValueError(f"Slug '{slug}' is already taken")

        identity_id = _new_identity_id()
        plaintext_key = generate_api_key()
        key_hash = hash_api_key(plaintext_key)
        now = _now_iso()
        expires = expiry_from_now(MAX_LIFETIME_DAYS).isoformat()

        reg_key = f"identity:reg:{identity_id}"
        # Flat mapping as list of (field, value) for Lua HSET argv
        mapping_pairs: list[str] = [
            "identity_id",         identity_id,
            "kind",                kind.value,
            "name",                name,
            "slug",                slug,
            "description",         description,
            "expertise",           json.dumps(expertise or []),
            "system_prompt",       system_prompt,
            "model_preference",    model_preference,
            "sensitivity_ceiling", sensitivity_ceiling,
            "upstream_url",        upstream_url,
            "container_image",     container_image,
            "container_config",    json.dumps(container_config or {}),
            "capabilities",        json.dumps(capabilities or []),
            "allowed_tools",       json.dumps(allowed_tools or []),
            "allowed_models",      json.dumps(allowed_models or []),
            "icon_url",            icon_url,
            "groups",              json.dumps(groups or []),
            "allowed_callers",     json.dumps(allowed_callers or []),
            "allowed_paths",       json.dumps(allowed_paths or []),
            "allowed_cidrs",       json.dumps(allowed_cidrs or []),
            "org_id",              org_id,
            "bound_spiffe_uri",    spiffe_uri,
            "status",              "active",
            "created_at",          now,
            "updated_at",          now,
            "last_seen_at",        "",
            "token_rotation_schedule", "",
            "api_key_created_at",  now,
            "api_key_expires_at",  expires,
            "api_key_rotated_at",  now,
        ]

        if kind == IdentityKind.HUMAN:
            # Atomic Lua path: enforces end-user limit against
            # identity:index:kind:human in a single atomic script (GROUP-4-1).
            lic = get_license()
            limit = lic.max_end_users  # -1 = unlimited

            kind_key = f"identity:index:kind:{kind.value}"
            org_index_key = f"identity:index:org:{org_id}" if org_id else ""

            keys = [
                kind_key,                          # KEYS[1] — SCARD source
                "identity:index:all",              # KEYS[2]
                "identity:index:active",           # KEYS[3]
                kind_key,                          # KEYS[4] — SADD target (same)
                f"identity:slug:{slug}",           # KEYS[5]
                reg_key,                           # KEYS[6]
                f"identity:key:{identity_id}",     # KEYS[7]
                org_index_key,                     # KEYS[8] (may be "")
            ]
            argv = [
                str(limit),                        # ARGV[1]
                identity_id,                       # ARGV[2]
                key_hash,                          # ARGV[3]
                org_id,                            # ARGV[4]
            ] + mapping_pairs                      # ARGV[5..]

            try:
                self._r.eval(self._REGISTER_HUMAN_LUA, len(keys), *keys, *argv)
            except Exception as exc:
                err_str = str(exc)
                if "LIMIT_EXCEEDED" in err_str:
                    try:
                        parts = err_str.split(":")
                        current = int(parts[1])
                        max_val = int(parts[2])
                    except (IndexError, ValueError):
                        current = self._r.scard("identity:index:kind:human") or 0
                        max_val = limit
                    raise LicenseLimitExceeded(
                        limit_name="max_end_users",
                        current=current,
                        max_val=max_val,
                    ) from exc
                raise
        else:
            # SERVICE kind — non-atomic pipeline (no per-kind limit)
            mapping_dict = {
                mapping_pairs[i]: mapping_pairs[i + 1]
                for i in range(0, len(mapping_pairs), 2)
            }
            pipe = self._r.pipeline()
            pipe.hset(reg_key, mapping=mapping_dict)
            pipe.set(f"identity:key:{identity_id}", key_hash)
            pipe.set(f"identity:slug:{slug}", identity_id)
            pipe.sadd("identity:index:all", identity_id)
            pipe.sadd("identity:index:active", identity_id)
            pipe.sadd(f"identity:index:kind:{kind.value}", identity_id)
            # SEC-240-7: org_id index for O(1) suspend_owned_by() lookup.
            if org_id:
                pipe.sadd(f"identity:index:org:{org_id}", identity_id)
            pipe.execute()

        logger.info(
            "IdentityRegistry: registered %s (%s, kind=%s, slug=%s)",
            identity_id, name, kind.value, slug,
        )
        return identity_id, plaintext_key

    # ── Reads ────────────────────────────────────────────────────────────

    def get(self, identity_id: str) -> Optional[dict]:
        """Return identity dict or None."""
        raw = self._r.hgetall(f"identity:reg:{identity_id}")
        if not raw:
            return None
        return self._decode(raw)

    def get_by_slug(self, slug: str) -> Optional[dict]:
        """Look up identity by slug (@mention name)."""
        identity_id = self._r.get(f"identity:slug:{slug}")
        if not identity_id:
            return None
        if isinstance(identity_id, bytes):
            identity_id = identity_id.decode("utf-8")
        return self.get(identity_id)

    def get_by_api_key(self, plaintext_key: str) -> Optional[dict]:
        """Look up identity by API key. Checks current key + grace key."""
        for identity_id in self._iter_active_ids():
            if self.verify_key(identity_id, plaintext_key):
                return self.get(identity_id)
        return None

    def list_all(self, kind: IdentityKind | None = None) -> list[dict]:
        """List all identities, optionally filtered by kind."""
        if kind:
            ids = self._r.smembers(f"identity:index:kind:{kind.value}")
        else:
            ids = self._r.smembers("identity:index:all")
        result = []
        for aid in sorted(self._decode_set(ids)):
            identity = self.get(aid)
            if identity:
                result.append(identity)
        return result

    def list_active(self, kind: IdentityKind | None = None) -> list[dict]:
        """List active identities."""
        active_ids = self._decode_set(self._r.smembers("identity:index:active"))
        if kind:
            kind_ids = self._decode_set(
                self._r.smembers(f"identity:index:kind:{kind.value}")
            )
            active_ids = active_ids & kind_ids
        result = []
        for aid in sorted(active_ids):
            identity = self.get(aid)
            if identity and identity["status"] == "active":
                result.append(identity)
        return result

    def count(self, status: str = "active", kind: IdentityKind | None = None) -> int:
        """Count identities by status and optionally kind."""
        if status == "active":
            if kind:
                active = self._decode_set(self._r.smembers("identity:index:active"))
                kind_set = self._decode_set(
                    self._r.smembers(f"identity:index:kind:{kind.value}")
                )
                return len(active & kind_set)
            return self._r.scard("identity:index:active") or 0
        if status == "all":
            if kind:
                return self._r.scard(f"identity:index:kind:{kind.value}") or 0
            return self._r.scard("identity:index:all") or 0
        # inactive
        total_count: int = self._r.scard("identity:index:all") or 0  # type: ignore[assignment]
        active_count: int = self._r.scard("identity:index:active") or 0  # type: ignore[assignment]
        return max(0, total_count - active_count)

    # ── Mutations ────────────────────────────────────────────────────────

    def update(self, identity_id: str, **fields) -> None:
        """Update mutable identity fields."""
        allowed = {
            "name", "description", "expertise", "system_prompt",
            "model_preference", "sensitivity_ceiling", "upstream_url",
            "container_image", "container_config", "capabilities",
            "allowed_tools", "allowed_models", "icon_url", "groups",
            "allowed_callers", "allowed_paths", "allowed_cidrs",
            "org_id", "token_rotation_schedule", "bound_spiffe_uri",
        }
        reg_key = f"identity:reg:{identity_id}"
        mapping = {}
        for k, v in fields.items():
            if k not in allowed:
                continue
            if isinstance(v, (list, dict)):
                mapping[k] = json.dumps(v)
            else:
                mapping[k] = str(v)
        if mapping:
            mapping["updated_at"] = _now_iso()
            self._r.hset(reg_key, mapping=mapping)
            logger.info("IdentityRegistry: updated %s fields=%s", identity_id, list(fields.keys()))

    def suspend(self, identity_id: str) -> None:
        """Suspend an identity (temporary disable)."""
        self._r.hset(f"identity:reg:{identity_id}", "status", "suspended")
        self._r.srem("identity:index:active", identity_id)
        logger.info("IdentityRegistry: suspended %s", identity_id)

    def reactivate(self, identity_id: str) -> None:
        """Re-enable a suspended identity."""
        self._r.hset(f"identity:reg:{identity_id}", mapping={
            "status": "active",
            "updated_at": _now_iso(),
        })
        self._r.sadd("identity:index:active", identity_id)
        logger.info("IdentityRegistry: reactivated %s", identity_id)

    def deactivate(self, identity_id: str) -> None:
        """Permanently deactivate an identity."""
        reg = self.get(identity_id)
        if not reg:
            return
        pipe = self._r.pipeline()
        pipe.hset(f"identity:reg:{identity_id}", mapping={
            "status": "deactivated",
            "updated_at": _now_iso(),
        })
        pipe.srem("identity:index:active", identity_id)
        pipe.delete(f"identity:key:{identity_id}")
        pipe.delete(f"identity:key:grace:{identity_id}")
        pipe.delete(f"identity:slug:{reg['slug']}")
        # Clean up org index (SEC-240-7).
        org_id = reg.get("org_id", "")
        if org_id:
            pipe.srem(f"identity:index:org:{org_id}", identity_id)
        pipe.execute()
        logger.info("IdentityRegistry: deactivated %s", identity_id)

    def suspend_owned_by(self, org_id: str) -> int:
        """Suspend all active identities registered under *org_id*.

        SEC-240-7 — O(1) lookup via the ``identity:index:org:{org_id}`` Redis
        set populated at register time.  Previously callers iterated
        ``list_all()`` and filtered in Python — O(N) over the full registry.

        Returns the number of identities suspended.
        """
        if not org_id:
            return 0
        owned_ids = self._decode_set(
            self._r.smembers(f"identity:index:org:{org_id}")
        )
        suspended = 0
        for identity_id in owned_ids:
            reg = self.get(identity_id)
            if reg and reg.get("status") == "active":
                self.suspend(identity_id)
                suspended += 1
        logger.info(
            "IdentityRegistry: suspend_owned_by(%s) suspended %d identit(ies)",
            org_id, suspended,
        )
        return suspended

    # ── Key operations ───────────────────────────────────────────────────

    def verify_key(self, identity_id: str, plaintext_key: str) -> bool:
        """Verify API key against current hash + grace hash. Fail-closed."""
        try:
            # Try current key
            current_hash = self._r.get(f"identity:key:{identity_id}")
            if current_hash:
                h = current_hash.decode("utf-8") if isinstance(current_hash, bytes) else current_hash
                if verify_api_key(plaintext_key, h):
                    self._update_last_seen(identity_id)
                    return True

            # Try grace key (previous key during rotation grace period)
            grace_hash = self._r.get(f"identity:key:grace:{identity_id}")
            if grace_hash:
                h = grace_hash.decode("utf-8") if isinstance(grace_hash, bytes) else grace_hash
                if verify_api_key(plaintext_key, h):
                    self._update_last_seen(identity_id)
                    return True

            return False
        except Exception as exc:
            logger.error("IdentityRegistry.verify_key error for %s: %s", identity_id, exc)
            return False

    def rotate_key(self, identity_id: str, grace_seconds: int = 7 * 86400) -> str:
        """
        Rotate API key. Returns new plaintext key.
        Previous key remains valid for grace_seconds (default 7 days).
        """
        plaintext_key = generate_api_key()
        new_hash = hash_api_key(plaintext_key)
        now = _now_iso()
        expires = expiry_from_now(MAX_LIFETIME_DAYS).isoformat()

        pipe = self._r.pipeline()

        # Move current key to grace — skip when grace_seconds=0 (immediate rotation;
        # EX 0 is rejected by Redis: "invalid expire time in 'set' command").
        current = self._r.get(f"identity:key:{identity_id}")
        if current and grace_seconds > 0:
            pipe.set(f"identity:key:grace:{identity_id}", current, ex=grace_seconds)

        # Set new key
        pipe.set(f"identity:key:{identity_id}", new_hash)
        pipe.hset(f"identity:reg:{identity_id}", mapping={
            "api_key_rotated_at": now,
            "api_key_expires_at": expires,
            "updated_at": now,
        })
        pipe.execute()

        logger.info("IdentityRegistry: key rotated for %s (grace=%ds)", identity_id, grace_seconds)
        return plaintext_key

    # ── Internal ─────────────────────────────────────────────────────────

    def _update_last_seen(self, identity_id: str) -> None:
        self._r.hset(f"identity:reg:{identity_id}", "last_seen_at", _now_iso())

    def _iter_active_ids(self):
        """Iterate active identity IDs."""
        return self._decode_set(self._r.smembers("identity:index:active"))

    @staticmethod
    def _decode_set(s) -> set[str]:
        return {v.decode("utf-8") if isinstance(v, bytes) else v for v in (s or set())}

    @staticmethod
    def _decode(raw: dict) -> dict:
        """Decode Redis hash into a Python dict."""
        def _s(key: str) -> str:
            val = raw.get(key, raw.get(key.encode("utf-8"), b""))
            return val.decode("utf-8") if isinstance(val, bytes) else (val or "")

        def _j(key: str) -> list | dict:
            try:
                return json.loads(_s(key))
            except (json.JSONDecodeError, TypeError):
                return []

        return {
            "identity_id": _s("identity_id"),
            "kind": _s("kind"),
            "name": _s("name"),
            "slug": _s("slug"),
            "description": _s("description"),
            "expertise": _j("expertise"),
            "system_prompt": _s("system_prompt"),
            "model_preference": _s("model_preference"),
            "sensitivity_ceiling": _s("sensitivity_ceiling"),
            "upstream_url": _s("upstream_url"),
            "container_image": _s("container_image"),
            "container_config": _j("container_config"),
            "capabilities": _j("capabilities"),
            "allowed_tools": _j("allowed_tools"),
            "allowed_models": _j("allowed_models"),
            "icon_url": _s("icon_url"),
            "groups": _j("groups"),
            "allowed_callers": _j("allowed_callers"),
            "allowed_paths": _j("allowed_paths"),
            "allowed_cidrs": _j("allowed_cidrs"),
            "org_id": _s("org_id"),
            "bound_spiffe_uri": _s("bound_spiffe_uri"),
            "status": _s("status"),
            "created_at": _s("created_at"),
            "updated_at": _s("updated_at"),
            "last_seen_at": _s("last_seen_at"),
            "token_rotation_schedule": _s("token_rotation_schedule"),
            "api_key_created_at": _s("api_key_created_at"),
            "api_key_expires_at": _s("api_key_expires_at"),
            "api_key_rotated_at": _s("api_key_rotated_at"),
        }
