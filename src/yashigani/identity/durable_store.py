"""
Postgres durable mirror of the IdentityRegistry (B1 follow-on, 2.25.5).

Why this exists
---------------
IdentityRegistry keeps identities in Redis db/3 only.  Redis runs with AOF
enabled (Su, B1 aa04626) which covers container-recreate; a full volume-
deletion or data-migration still loses identities silently.

Fix shape (mirrors AgentDurableStore / AllocationDurableStore)
--------------------------------------------------------------
  * Durable source of truth: Postgres ``identities`` table (migration-0005,
    extended by migration-0020).
  * Fast request-time lookup: Redis db/3 — UNCHANGED.  The hot auth path reads
    Redis only.
  * Dual-write: IdentityRegistry.register / update / suspend / reactivate /
    deactivate also write through this store.
  * Startup reconcile: on boot, identities present in Postgres but absent from
    Redis are re-hydrated into Redis (reconcile_identities_from_durable).
  * Back-fill: if Postgres is EMPTY but Redis has identities (first boot after
    this fix), the reconciler back-fills Postgres from Redis so those identities
    become durable for future reboots.

Transport: short-lived sync psycopg2 connections (same pattern as
AllocationDurableStore) — identity mutations are rare admin operations, not
a hot path.

RLS: ``identities`` is FORCE RLS on ``app.tenant_id`` — every connection sets
the platform tenant before touching the table.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

_PLATFORM_TENANT_ID = "00000000-0000-0000-0000-000000000000"

# Column type map for the ``identities`` table (migration-0005 + migration-0020).
# Drives serialization in upsert() — psycopg2 adapts Python lists to text[] natively;
# jsonb columns must receive a JSON string (json.dumps / psycopg2 Json adapter).
#
# text[] columns — pass a Python list directly:
_TEXT_ARRAY_FIELDS = frozenset({
    "expertise", "capabilities", "allowed_tools", "allowed_models",
    "groups", "allowed_callers", "allowed_paths", "allowed_cidrs",
})
# jsonb columns — pass json.dumps(value):
_JSONB_FIELDS = frozenset({"container_config"})


def _direct_dsn() -> str:
    """Prefer the direct (non-pgbouncer) DSN for predictable RLS SET LOCAL."""
    return os.environ.get("YASHIGANI_DB_DSN_DIRECT") or os.environ.get("YASHIGANI_DB_DSN", "")


class IdentityDurableStore:
    """Sync psycopg2-backed durable mirror of the IdentityRegistry.

    Thread-safe: each method opens a fresh short-lived connection so there is
    no shared connection state between callers.  Identity mutations are rare
    enough that connection overhead is negligible.
    """

    def __init__(self, dsn: Optional[str] = None) -> None:
        self._dsn = dsn

    def _dsn_or_raise(self) -> str:
        dsn = self._dsn or _direct_dsn()
        if not dsn or "${POSTGRES_PASSWORD}" in dsn:
            raise RuntimeError(
                "IdentityDurableStore: no usable Postgres DSN "
                "(YASHIGANI_DB_DSN_DIRECT / YASHIGANI_DB_DSN unset or templated)"
            )
        return dsn

    def _connect(self):
        from yashigani.db.postgres import connect_with_retry_sync

        conn = connect_with_retry_sync(self._dsn_or_raise(), max_attempts=3, backoff_s=2.0)
        conn.autocommit = False
        with conn.cursor() as cur:
            cur.execute("SELECT set_config('app.tenant_id', %s, false)", (_PLATFORM_TENANT_ID,))
        return conn

    # ── Writes (dual-write target) ──────────────────────────────────────────

    def upsert(self, identity: dict) -> None:
        """Insert-or-update the durable row for one identity.

        ``identity`` is the decoded dict returned by IdentityRegistry._decode()
        (or the mapping_pairs dict assembled in register()).

        Fail-loud: durability is the whole point — any failure re-raises after
        logging so the caller (IdentityRegistry.register/update) decides whether
        to surface it.
        """
        identity_id = identity.get("identity_id", "")
        if not identity_id:
            raise ValueError("IdentityDurableStore.upsert: missing identity_id")

        def _pg_array(v) -> list:
            """Return a Python list for text[] columns.

            psycopg2 adapts a Python list to a Postgres array literal natively.
            Passing json.dumps(v) produced a JSON string (e.g. '["users"]') which
            Postgres rejects as 'malformed array literal' (2255-005).

            Handles three cases that appear in practice:
            - Already a list   → pass through (normal dual-write path).
            - A JSON string    → parse back to list (back-fill from Redis stores
                                 lists as JSON strings in Redis hashes).
            - None / empty str → empty list (maps to '{}' in Postgres).
            """
            if isinstance(v, list):
                return v
            if isinstance(v, str):
                if not v or v == "[]":
                    return []
                try:
                    parsed = json.loads(v)
                    return parsed if isinstance(parsed, list) else []
                except (json.JSONDecodeError, ValueError):
                    return []
            return []

        def _pg_jsonb(v) -> str:
            """Return a JSON string for jsonb columns."""
            if isinstance(v, str):
                # Already a JSON string (e.g. from Redis hash back-fill).
                try:
                    json.loads(v)  # validate
                    return v
                except (json.JSONDecodeError, ValueError):
                    pass
            return json.dumps(v if v is not None else {})

        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO identities (
                        tenant_id, identity_id, kind, name, slug, description,
                        expertise, system_prompt, model_preference,
                        sensitivity_ceiling, upstream_url, container_image,
                        container_config, capabilities, allowed_tools,
                        allowed_models, icon_url, groups, allowed_callers,
                        allowed_paths, allowed_cidrs, org_id, bound_spiffe_uri,
                        api_key_hash, status, created_at, updated_at, last_seen_at,
                        token_rotation_schedule, api_key_created_at,
                        api_key_expires_at, api_key_rotated_at
                    )
                    VALUES (
                        %s::uuid, %s, %s, %s, %s, %s,
                        %s, %s, %s,
                        %s, %s, %s,
                        %s::jsonb, %s, %s,
                        %s, %s, %s, %s,
                        %s, %s, %s, %s,
                        %s, %s,
                        %s::timestamptz, %s::timestamptz, %s::timestamptz,
                        %s,
                        %s::timestamptz, %s::timestamptz, %s::timestamptz
                    )
                    ON CONFLICT (tenant_id, identity_id) DO UPDATE SET
                        kind               = EXCLUDED.kind,
                        name               = EXCLUDED.name,
                        slug               = EXCLUDED.slug,
                        description        = EXCLUDED.description,
                        expertise          = EXCLUDED.expertise,
                        system_prompt      = EXCLUDED.system_prompt,
                        model_preference   = EXCLUDED.model_preference,
                        sensitivity_ceiling = EXCLUDED.sensitivity_ceiling,
                        upstream_url       = EXCLUDED.upstream_url,
                        container_image    = EXCLUDED.container_image,
                        container_config   = EXCLUDED.container_config,
                        capabilities       = EXCLUDED.capabilities,
                        allowed_tools      = EXCLUDED.allowed_tools,
                        allowed_models     = EXCLUDED.allowed_models,
                        icon_url           = EXCLUDED.icon_url,
                        groups             = EXCLUDED.groups,
                        allowed_callers    = EXCLUDED.allowed_callers,
                        allowed_paths      = EXCLUDED.allowed_paths,
                        allowed_cidrs      = EXCLUDED.allowed_cidrs,
                        org_id             = EXCLUDED.org_id,
                        bound_spiffe_uri   = EXCLUDED.bound_spiffe_uri,
                        api_key_hash       = EXCLUDED.api_key_hash,
                        status             = EXCLUDED.status,
                        updated_at         = EXCLUDED.updated_at,
                        last_seen_at       = EXCLUDED.last_seen_at,
                        token_rotation_schedule = EXCLUDED.token_rotation_schedule,
                        api_key_created_at = EXCLUDED.api_key_created_at,
                        api_key_expires_at = EXCLUDED.api_key_expires_at,
                        api_key_rotated_at = EXCLUDED.api_key_rotated_at
                    """,
                    (
                        _PLATFORM_TENANT_ID,
                        identity_id,
                        identity.get("kind", "service"),
                        identity.get("name", ""),
                        identity.get("slug", ""),
                        identity.get("description", ""),
                        # text[] columns — pass Python list; psycopg2 adapts to Postgres array
                        _pg_array(identity.get("expertise", [])),
                        identity.get("system_prompt", ""),
                        identity.get("model_preference", ""),
                        identity.get("sensitivity_ceiling", "PUBLIC"),
                        identity.get("upstream_url", ""),
                        identity.get("container_image", ""),
                        # jsonb column — pass JSON string
                        _pg_jsonb(identity.get("container_config", {})),
                        # text[] columns (cont.)
                        _pg_array(identity.get("capabilities", [])),
                        _pg_array(identity.get("allowed_tools", [])),
                        _pg_array(identity.get("allowed_models", [])),
                        identity.get("icon_url", ""),
                        _pg_array(identity.get("groups", [])),
                        _pg_array(identity.get("allowed_callers", [])),
                        _pg_array(identity.get("allowed_paths", [])),
                        _pg_array(identity.get("allowed_cidrs", [])),
                        identity.get("org_id", "") or _PLATFORM_TENANT_ID,
                        identity.get("bound_spiffe_uri", ""),
                        identity.get("api_key_hash", ""),
                        identity.get("status", "active"),
                        identity.get("created_at") or None,
                        identity.get("updated_at") or None,
                        identity.get("last_seen_at") or None,
                        identity.get("token_rotation_schedule", ""),
                        identity.get("api_key_created_at") or None,
                        identity.get("api_key_expires_at") or None,
                        identity.get("api_key_rotated_at") or None,
                    ),
                )
            conn.commit()
            logger.info(
                "IdentityDurableStore: upserted identity %s (%s) into Postgres",
                identity_id, identity.get("kind", "?"),
            )
        except Exception:
            conn.rollback()
            logger.exception("IdentityDurableStore: upsert FAILED for %s", identity_id)
            raise
        finally:
            conn.close()

    def update_status(self, identity_id: str, status: str) -> None:
        """Update only the status + updated_at columns (for suspend/reactivate/deactivate)."""
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE identities SET status = %s, updated_at = now()
                    WHERE tenant_id = %s::uuid AND identity_id = %s
                    """,
                    (status, _PLATFORM_TENANT_ID, identity_id),
                )
            conn.commit()
            logger.info(
                "IdentityDurableStore: updated status of %s → %s", identity_id, status
            )
        except Exception:
            conn.rollback()
            logger.exception(
                "IdentityDurableStore: update_status FAILED for %s", identity_id
            )
            raise
        finally:
            conn.close()

    def delete(self, identity_id: str) -> None:
        """Hard-delete a durable identity row (called on deactivate)."""
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM identities "
                    "WHERE tenant_id = %s::uuid AND identity_id = %s",
                    (_PLATFORM_TENANT_ID, identity_id),
                )
            conn.commit()
            logger.info("IdentityDurableStore: deleted identity %s from Postgres", identity_id)
        except Exception:
            conn.rollback()
            logger.exception("IdentityDurableStore: delete FAILED for %s", identity_id)
            raise
        finally:
            conn.close()

    # ── Reconcile reads (Postgres → Redis) ─────────────────────────────────

    def list_all(self) -> list[dict]:
        """Return every durable identity row (for the startup reconciler)."""
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT identity_id, kind, name, slug, description,
                           expertise, system_prompt, model_preference,
                           sensitivity_ceiling, upstream_url, container_image,
                           container_config, capabilities, allowed_tools,
                           allowed_models, icon_url, groups, allowed_callers,
                           allowed_paths, allowed_cidrs, org_id,
                           bound_spiffe_uri, api_key_hash, status,
                           created_at, updated_at, last_seen_at,
                           token_rotation_schedule, api_key_created_at,
                           api_key_expires_at, api_key_rotated_at
                    FROM identities
                    WHERE tenant_id = %s::uuid
                    """,
                    (_PLATFORM_TENANT_ID,),
                )
                cols = [d[0] for d in cur.description]
                rows = cur.fetchall()
            result = []
            for row in rows:
                d = dict(zip(cols, row))
                # Normalise timestamps to ISO strings (may be datetime objects)
                for ts_col in ("created_at", "updated_at", "last_seen_at",
                               "api_key_created_at", "api_key_expires_at",
                               "api_key_rotated_at"):
                    v = d.get(ts_col)
                    if v is not None and not isinstance(v, str):
                        d[ts_col] = v.isoformat()
                    elif v is None:
                        d[ts_col] = ""
                result.append(d)
            return result
        finally:
            conn.close()

    def list_all_minimal(self) -> list[tuple[str, str]]:
        """Return (identity_id, slug) for every durable row — used for back-fill check."""
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT identity_id, slug FROM identities WHERE tenant_id = %s::uuid",
                    (_PLATFORM_TENANT_ID,),
                )
                return list(cur.fetchall())
        finally:
            conn.close()


# ── Startup reconciler ──────────────────────────────────────────────────────

def reconcile_identities_from_durable(
    registry,
    durable: IdentityDurableStore,
) -> int:
    """Re-push Postgres identities into Redis db/3 if missing on boot.

    Behaviour:
      * Idempotent — safe to call every boot.
      * Restores ONLY identities present in Postgres but absent from Redis db/3.
        An existing Redis entry is authoritative (live state); never overwritten.
      * API keys are restored as hashes — plaintext keys are never stored in
        Postgres (they were shown once at registration and discarded).  The
        reconciler restores the bcrypt hash so verify_key() keeps working; the
        plaintext key is not re-issued (operator must rotate if lost).
      * Back-fill: if Postgres is empty but Redis has identities (first boot
        after this fix), back-fill Postgres from Redis so they become durable.
      * Fail-loud for logging; swallows exceptions so a Postgres blip does NOT
        block gateway/backoffice startup (identities already in Redis still work;
        the next boot will retry).

    Returns:
        Number of identities restored from Postgres into Redis (0 if in-sync).
    """
    if registry is None or durable is None:
        logger.warning(
            "IDENTITY-RECONCILE: skipped — registry or durable_store not wired "
            "(identities will NOT auto-restore after a redis volume-deletion)"
        )
        return 0

    # -- Read durable Postgres rows -----------------------------------------
    try:
        durable_rows = durable.list_all()
    except Exception as exc:
        logger.error(
            "IDENTITY-RECONCILE: could not read identities from Postgres (%s) — "
            "identities will NOT auto-restore this boot; investigate the DB.", exc,
        )
        return 0

    if not durable_rows:
        # First boot after this fix: Postgres is empty but Redis may already have
        # identities.  Back-fill Postgres from Redis ONCE so they survive the next
        # volume-deletion.
        backfilled = _backfill_durable_from_redis(registry, durable)
        if backfilled:
            logger.warning(
                "IDENTITY-RECONCILE: durable store was empty — back-filled %d existing "
                "Redis identity(ies) into Postgres so they survive a volume-deletion",
                backfilled,
            )
        else:
            logger.info(
                "IDENTITY-RECONCILE: durable store empty and no Redis identities to back-fill"
            )
        return 0

    # -- Determine which identity_ids are already live in Redis ---------------
    existing_ids: set[str] = set(registry._decode_set(
        registry._r.smembers("identity:index:all")
    ))

    restored = 0
    for row in durable_rows:
        identity_id = row.get("identity_id", "")
        if not identity_id or identity_id in existing_ids:
            continue
        # Re-hydrate into Redis using the raw mapping (mirrors register() but
        # restores the ORIGINAL identity_id + api_key_hash without re-generating).
        try:
            _restore_identity_to_redis(registry, row)
            restored += 1
            logger.info(
                "IDENTITY-RECONCILE: restored %s (%s, kind=%s) from Postgres → Redis",
                identity_id, row.get("slug", ""), row.get("kind", ""),
            )
        except Exception as exc:
            logger.warning(
                "IDENTITY-RECONCILE: failed to restore %s (%s): %s",
                identity_id, row.get("slug", ""), exc,
            )

    if restored:
        logger.info(
            "IDENTITY-RECONCILE: restored %d identity(ies) from Postgres into Redis db/3",
            restored,
        )
    else:
        logger.info("IDENTITY-RECONCILE: Redis and Postgres in sync (%d identities)", len(durable_rows))

    return restored


def _restore_identity_to_redis(registry, row: dict) -> None:
    """Re-insert a durable Postgres identity row into Redis db/3.

    Uses the same Redis key schema as IdentityRegistry.register() but does NOT
    re-generate identity_id or API key — restores the ORIGINAL values so
    existing callers' tokens keep working.  The api_key_hash is the bcrypt hash
    of the original key (plaintext never stored).
    """
    import json as _json

    identity_id = row["identity_id"]
    slug = row.get("slug", "")
    kind = row.get("kind", "service")
    api_key_hash = row.get("api_key_hash", "")
    org_id = row.get("org_id", "")
    status = row.get("status", "active")

    # Build the flat Redis hash mapping
    def _j(v) -> str:
        if isinstance(v, (list, dict)):
            return _json.dumps(v)
        return str(v) if v is not None else "[]"

    mapping = {
        "identity_id":             identity_id,
        "kind":                    kind,
        "name":                    row.get("name", ""),
        "slug":                    slug,
        "description":             row.get("description", ""),
        "expertise":               _j(row.get("expertise", [])),
        "system_prompt":           row.get("system_prompt", ""),
        "model_preference":        row.get("model_preference", ""),
        "sensitivity_ceiling":     row.get("sensitivity_ceiling", "PUBLIC"),
        "upstream_url":            row.get("upstream_url", ""),
        "container_image":         row.get("container_image", ""),
        "container_config":        _j(row.get("container_config", {})),
        "capabilities":            _j(row.get("capabilities", [])),
        "allowed_tools":           _j(row.get("allowed_tools", [])),
        "allowed_models":          _j(row.get("allowed_models", [])),
        "icon_url":                row.get("icon_url", ""),
        "groups":                  _j(row.get("groups", [])),
        "allowed_callers":         _j(row.get("allowed_callers", [])),
        "allowed_paths":           _j(row.get("allowed_paths", [])),
        "allowed_cidrs":           _j(row.get("allowed_cidrs", [])),
        "org_id":                  org_id,
        "bound_spiffe_uri":        row.get("bound_spiffe_uri", ""),
        "status":                  status,
        "created_at":              row.get("created_at", ""),
        "updated_at":              row.get("updated_at", ""),
        "last_seen_at":            row.get("last_seen_at", ""),
        "token_rotation_schedule": row.get("token_rotation_schedule", ""),
        "api_key_created_at":      row.get("api_key_created_at", ""),
        "api_key_expires_at":      row.get("api_key_expires_at", ""),
        "api_key_rotated_at":      row.get("api_key_rotated_at", ""),
    }

    reg_key = f"identity:reg:{identity_id}"
    pipe = registry._r.pipeline()
    pipe.hset(reg_key, mapping=mapping)
    if api_key_hash:
        pipe.set(f"identity:key:{identity_id}", api_key_hash)
    if slug:
        pipe.set(f"identity:slug:{slug}", identity_id)
    pipe.sadd("identity:index:all", identity_id)
    if status == "active":
        pipe.sadd("identity:index:active", identity_id)
    pipe.sadd(f"identity:index:kind:{kind}", identity_id)
    if org_id and org_id != "00000000-0000-0000-0000-000000000000":
        pipe.sadd(f"identity:index:org:{org_id}", identity_id)
    pipe.execute()


def _backfill_durable_from_redis(registry, durable: IdentityDurableStore) -> int:
    """Back-fill Postgres from Redis when Postgres is empty (first boot after this fix).

    Reads every identity from Redis and upserts it into Postgres.  Skips any
    identity that is already in Postgres (list_all_minimal check).  Best-effort:
    a failure on one identity is logged and skipped rather than aborting the
    entire back-fill.
    """
    try:
        all_ids = registry._decode_set(registry._r.smembers("identity:index:all"))
    except Exception as exc:
        logger.warning("IDENTITY-RECONCILE: back-fill — could not read Redis index: %s", exc)
        return 0

    if not all_ids:
        return 0

    try:
        existing_pg = {row[0] for row in durable.list_all_minimal()}
    except Exception as exc:
        logger.warning("IDENTITY-RECONCILE: back-fill — could not check Postgres: %s", exc)
        return 0

    count = 0
    for identity_id in all_ids:
        if identity_id in existing_pg:
            continue
        try:
            raw = registry._r.hgetall(f"identity:reg:{identity_id}")
            if not raw:
                continue
            decoded = registry._decode(raw)
            # Fetch the api_key_hash directly (not included in _decode output)
            key_hash = registry._r.get(f"identity:key:{identity_id}")
            if key_hash:
                decoded["api_key_hash"] = (
                    key_hash.decode("utf-8") if isinstance(key_hash, bytes) else key_hash
                )
            durable.upsert(decoded)
            count += 1
        except Exception as exc:
            logger.warning(
                "IDENTITY-RECONCILE: back-fill failed for %s: %s", identity_id, exc
            )

    return count
