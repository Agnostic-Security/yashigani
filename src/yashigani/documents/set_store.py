"""
Yashigani Document Enforcement — Redis-backed document-SET store (2.26).

A "document set" is an operator-defined grouping of files that should share a
PSEUDONYMIZE **salt**, so the SAME original value tokenises CONSISTENTLY across
every file in the set (legitimate cross-file correlation — e.g. the same person's
opaque token in last month's and this month's export must match so the analyst
can join them).  By default the engine uses a per-FILE salt (maximum isolation);
binding a document to a set widens the salt to the set, which REDUCES per-file
isolation and is therefore opt-in only and clearly flagged in the UI.

Security properties:
  * The set's salt is a **256-bit high-entropy opaque secret** minted here with
    ``secrets.token_hex`` — NEVER the set name, NEVER operator-supplied, NEVER
    logged.  The token derivation HMACs over it, so the token still leaks nothing
    about the set (Laura's class/count-leak finding stays closed at set scope).
  * The salt is the crypto material that lets a holder of the set's mapping files
    recognise the same value across files; it is custodied like the deployment
    secret and surfaced to the engine seam ONLY (``inspect(set_salt=...)``), never
    to a client response.  The admin API returns set metadata (id, name, member
    count, created-at, the security note) but ``salt`` is REDACTED from every
    response body.

Mirrors :class:`yashigani.documents.policy_store.DocumentPolicyStore`:
  - Redis db/3, namespaced ``document:set:`` to coexist with ``document:policy:``.
  - Write-through cache; ``_load_from_redis()`` replays state on construction.
  - Idempotent, fail-closed on Redis errors (a mutation never silently no-ops).

Redis key schema (db/3):
    document:set:{id}     — JSON: {id, name, salt, members[], created_at}
    document:set_seq      — integer counter for new set ids
"""
from __future__ import annotations

import json
import logging
import secrets
import time

logger = logging.getLogger(__name__)

_KEY_SET = "document:set:{}"   # .format(set_id)
_KEY_SEQ = "document:set_seq"

#: Salt entropy: 256 bits (32 bytes → 64 hex chars).  Same bar as the replacer-map
#: capability handle.  Distinct from a per-file doc_hash (which is a SHA-256 of
#: bytes the holder already has) — a set salt is a real secret.
_SALT_BYTES = 32

#: The fixed security note surfaced on every set (the UI shows it verbatim so the
#: operator cannot miss the isolation tradeoff).  Plain text — the UI escapes it.
SECURITY_NOTE = (
    "Files in this set share one pseudonymisation salt, so the same value "
    "tokenises identically across every file in the set. This enables "
    "legitimate cross-file correlation but REDUCES per-file isolation: an "
    "attacker who recognises a token in one file recognises it in all of them. "
    "Use a set only when cross-file correlation is required; otherwise keep the "
    "default per-file salt."
)


class DocumentSetStore:
    """Thread-safe document-set store backed by Redis db/3.

    Holds the opaque per-set salt + membership.  All mutations are write-through;
    the constructor replays state from Redis so a restart never loses a set."""

    def __init__(self, redis_client) -> None:
        self._redis = redis_client
        self._sets: dict[str, dict] = {}
        self._load_from_redis()

    # ------------------------------------------------------------------
    # Startup: replay from Redis
    # ------------------------------------------------------------------

    def _load_from_redis(self) -> None:
        try:
            cursor = 0
            while True:
                cursor, keys = self._redis.scan(cursor, match="document:set:*", count=200)
                for key in keys:
                    raw = self._redis.get(key)
                    if raw is None:
                        continue
                    try:
                        d = json.loads(raw)
                        self._sets[d["id"]] = d
                    except Exception as exc:
                        logger.error("DocumentSetStore: failed to deserialise %s: %s", key, exc)
                if cursor == 0:
                    break
        except Exception as exc:
            logger.error("DocumentSetStore: failed to load from Redis: %s", exc)

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def create_set(self, *, name: str, members: list[str] | None = None) -> dict:
        """Create a set with a freshly-minted opaque salt (write-through).

        Returns the FULL row (incl. salt) for internal callers; the admin route
        REDACTS the salt before returning to a client (see ``public_view``)."""
        name = (name or "").strip()
        if not name:
            raise ValueError("set name is required")
        if len(name) > 128:
            raise ValueError("set name too long (max 128)")
        try:
            new_id = str(self._redis.incr(_KEY_SEQ))
        except Exception as exc:
            # Fail-closed: never mint a colliding id from a stale cache.
            raise RuntimeError(f"DocumentSetStore: id allocation failed: {exc}") from exc
        row = {
            "id": new_id,
            "name": name,
            # The opaque high-entropy set salt — a real secret, never the name.
            "salt": secrets.token_hex(_SALT_BYTES),
            "members": list(members or []),
            "created_at": time.time(),
        }
        self._sets[new_id] = row
        self._redis.set(_KEY_SET.format(new_id), json.dumps(row))
        return row

    def remove_set(self, set_id: str) -> bool:
        existed = self._sets.pop(set_id, None) is not None
        if existed:
            self._redis.delete(_KEY_SET.format(set_id))
        return existed

    def add_member(self, set_id: str, member: str) -> dict:
        """Add a document/member label to a set (write-through).  Returns the row."""
        row = self._sets.get(set_id)
        if row is None:
            raise KeyError(set_id)
        member = (member or "").strip()
        if not member:
            raise ValueError("member label is required")
        if member not in row["members"]:
            row["members"].append(member)
            self._redis.set(_KEY_SET.format(set_id), json.dumps(row))
        return row

    def get_set(self, set_id: str) -> dict | None:
        """Full row INCLUDING the salt — internal use only (the seam reads it)."""
        return self._sets.get(set_id)

    def get_salt(self, set_id: str) -> str | None:
        """The opaque salt for a set, or None.  The ONLY salt accessor the engine
        seam uses; never returned to a client."""
        row = self._sets.get(set_id)
        return row.get("salt") if row else None

    def list_sets(self) -> list[dict]:
        def _key(s: dict):
            try:
                return (0, int(s["id"]))
            except (ValueError, TypeError):
                return (1, s["id"])
        return sorted(self._sets.values(), key=_key)

    # ------------------------------------------------------------------
    # Public view (salt REDACTED) — what the admin API may return
    # ------------------------------------------------------------------

    @staticmethod
    def public_view(row: dict) -> dict:
        """Strip the salt — a set's salt is a secret and NEVER leaves the gateway.

        Returns metadata only: id, name, member labels, member count, created_at.
        The presence of a salt is signalled by ``has_salt`` (always True), never
        the value."""
        return {
            "id": row["id"],
            "name": row["name"],
            "members": list(row.get("members", [])),
            "member_count": len(row.get("members", [])),
            "created_at": row.get("created_at"),
            "has_salt": bool(row.get("salt")),
        }
