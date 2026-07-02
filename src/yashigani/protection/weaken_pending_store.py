"""
Yashigani — Data-Protection Weaken Pending Store (LAURA-V400-R2-001).

Redis db/3-backed store for pending dual-admin maker-checker weaken requests.

THREE data-protection controls can be weakened (each requires dual-admin approval):
  pii_config       — PII scanning mode set to pass or log (not enforcing)
  pii_cloud_bypass — PII cloud bypass enabled (PII reaches cloud LLMs)
  doc_enforcement  — Document enforcement disabled

Design:
  * Key namespace ``dp_weaken:`` (disjoint from ``mcp_envelope_pending:``,
    ``document:``, ``rbac:``).
  * Write-through cache: in-memory cache for reads; Redis is the durable
    mirror so a restart does not lose pending requests.
  * Redis TTL = 24 hours. Expired entries are silently dropped on read.
  * In-memory cache refreshed from Redis on every read (cross-process
    coherency — the backoffice may run multiple processes behind Caddy).
  * Tenant-scoped: every entry carries tenant_id so multi-tenant deploys
    list only their own pending weaken requests.

SECURITY:
  * requester_id is stored from the authenticated admin session — never
    from client-supplied body.
  * Distinct-admin check (maker != checker) is enforced in the approve
    route, not here — this store is purely data.
  * Fail-closed: if the store is unavailable, weaken requests cannot be
    submitted (the route's _dp_store() helper raises 503).

Redis key schema (db/3):
    dp_weaken:{request_id}   — JSON pending-weaken-request row (TTL 24h)

Controls:
    pii_config       — from_state: {mode, enabled_types}
                       to_state:   {mode, enabled_types}
    pii_cloud_bypass — from_state: {enabled: bool}
                       to_state:   {enabled: bool}
    doc_enforcement  — from_state: {enabled: bool}
                       to_state:   {enabled: bool}

Last updated: 2026-07-02T00:00:00+00:00
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Any, Optional

logger = logging.getLogger("yashigani.protection.weaken_pending_store")

_KEY_PREFIX = "dp_weaken:"
_SCAN_MATCH = "dp_weaken:*"
_TTL_SECONDS = 24 * 60 * 60   # 24 hours

VALID_CONTROLS = frozenset({"pii_config", "pii_cloud_bypass", "doc_enforcement"})


def _now() -> float:
    return time.time()


class DpWeakenPendingStore:
    """Redis-backed store of pending data-protection weaken requests.

    Constructed in the backoffice entrypoint with the shared Redis db/3
    client (same instance as RBAC / document stores, disjoint key namespace).
    The dp_weaken admin routes write entries on maker-submit and drop them
    on checker-approve or checker-reject.
    """

    def __init__(self, redis_client: Any) -> None:
        self._redis = redis_client
        self._pending: dict[str, dict] = {}
        self._load_from_redis()

    # ------------------------------------------------------------------
    # Startup replay
    # ------------------------------------------------------------------

    def _load_from_redis(self) -> None:
        try:
            cursor = 0
            while True:
                cursor, keys = self._redis.scan(cursor, match=_SCAN_MATCH, count=200)
                for key in keys:
                    raw = self._redis.get(key)
                    if raw is None:
                        continue
                    try:
                        row = json.loads(raw)
                        # Drop expired entries at load time.
                        if row.get("expires_at", 0) > _now():
                            self._pending[row["request_id"]] = row
                    except Exception as exc:
                        logger.error(
                            "DpWeakenPendingStore: bad row %s: %s", key, exc
                        )
                if cursor == 0:
                    break
        except Exception as exc:
            logger.error(
                "DpWeakenPendingStore: load from Redis failed: %s", exc
            )

    # ------------------------------------------------------------------
    # Cross-process coherency — Redis refresh
    # ------------------------------------------------------------------

    def _refresh_from_redis(self) -> None:
        """Reload the in-memory cache with a fresh Redis scan.

        Called at the start of every read method so that entries written by
        a sibling process are visible here without requiring a restart.
        On Redis failure the existing cache is kept (fail-safe — operator
        sees stale list rather than an empty one that looks like no pending)."""
        fresh: dict[str, dict] = {}
        try:
            cursor = 0
            while True:
                cursor, keys = self._redis.scan(cursor, match=_SCAN_MATCH, count=200)
                for key in keys:
                    raw = self._redis.get(key)
                    if raw is None:
                        continue
                    try:
                        row = json.loads(raw)
                        if row.get("expires_at", 0) > _now():
                            fresh[row["request_id"]] = row
                    except Exception as exc:
                        logger.error(
                            "DpWeakenPendingStore: bad row on refresh %s: %s",
                            key, exc,
                        )
                if cursor == 0:
                    break
            self._pending = fresh
        except Exception as exc:
            logger.error(
                "DpWeakenPendingStore: refresh from Redis failed — using stale cache: %s",
                exc,
            )

    # ------------------------------------------------------------------
    # Write (maker-submit path)
    # ------------------------------------------------------------------

    def create_request(
        self,
        *,
        tenant_id: str,
        requester_id: str,
        control: str,
        from_state: dict,
        to_state: dict,
    ) -> dict:
        """Persist a pending weaken request.

        Returns the stored row. Idempotent on (requester_id, control):
        if the same requester already has a pending request for the same
        control, it is OVERWRITTEN (a re-submit updates the desired state).
        This prevents stale duplicate entries from building up.

        Raises ValueError if control is not one of the valid control names."""
        if control not in VALID_CONTROLS:
            raise ValueError(
                f"control must be one of {sorted(VALID_CONTROLS)}, got {control!r}"
            )
        # Overwrite any existing pending request from the same requester for
        # the same control (idempotent re-submit).
        existing_id = self._find_existing(tenant_id, requester_id, control)
        request_id = existing_id or str(uuid.uuid4())
        now = _now()
        row: dict = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "requester_id": requester_id,
            "control": control,
            "from_state": from_state,
            "to_state": to_state,
            "requested_at": now,
            "expires_at": now + _TTL_SECONDS,
            "status": "pending",
        }
        self._pending[request_id] = row
        try:
            self._redis.setex(
                f"{_KEY_PREFIX}{request_id}",
                _TTL_SECONDS,
                json.dumps(row),
            )
        except Exception as exc:
            logger.error(
                "DpWeakenPendingStore: persist failed for %s: %s", request_id, exc
            )
        logger.warning(
            "DpWeakenPendingStore: pending weaken request created "
            "id=%s tenant=%s requester=%s control=%s",
            request_id, tenant_id, requester_id, control,
        )
        return row

    def _find_existing(
        self, tenant_id: str, requester_id: str, control: str
    ) -> Optional[str]:
        """Return request_id of an existing pending request for (tenant, requester,
        control), or None.  Uses the in-memory cache (no Redis refresh needed here
        since this is called within the same request context as create_request)."""
        for row in self._pending.values():
            if (
                row.get("tenant_id") == tenant_id
                and row.get("requester_id") == requester_id
                and row.get("control") == control
                and row.get("expires_at", 0) > _now()
            ):
                return row["request_id"]
        return None

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def list_for_tenant(self, tenant_id: str) -> list[dict]:
        """All pending weaken requests for a tenant, newest first.

        Always reloads from Redis for cross-process coherency.
        Returns summary rows (no internal-only fields)."""
        self._refresh_from_redis()
        rows = [
            self._summary(r)
            for r in self._pending.values()
            if r.get("tenant_id") == tenant_id
        ]
        rows.sort(key=lambda r: r.get("requested_at", 0.0), reverse=True)
        return rows

    def get(self, request_id: str, tenant_id: str) -> Optional[dict]:
        """Return the full pending row IFF it belongs to the tenant.

        Cross-tenant lookups fail closed (None). Reloads from Redis first."""
        self._refresh_from_redis()
        row = self._pending.get(request_id)
        if row is None or row.get("tenant_id") != tenant_id:
            return None
        if row.get("expires_at", 0) <= _now():
            return None  # expired
        return row

    def count_for_tenant(self, tenant_id: str) -> int:
        """Count non-expired pending requests for a tenant (for dashboard badge)."""
        self._refresh_from_redis()
        return sum(
            1
            for r in self._pending.values()
            if r.get("tenant_id") == tenant_id
            and r.get("expires_at", 0) > _now()
        )

    # ------------------------------------------------------------------
    # Resolve (approve / reject drops the pending entry)
    # ------------------------------------------------------------------

    def resolve(self, request_id: str, tenant_id: str) -> bool:
        """Drop a pending entry after an operator decision (approve or reject).

        Tenant-scoped: a cross-tenant resolve is a no-op (False)."""
        row = self._pending.get(request_id)
        if row is None or row.get("tenant_id") != tenant_id:
            return False
        self._pending.pop(request_id, None)
        try:
            self._redis.delete(f"{_KEY_PREFIX}{request_id}")
        except Exception as exc:
            logger.error(
                "DpWeakenPendingStore: delete failed for %s: %s", request_id, exc
            )
        return True

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _summary(row: dict) -> dict:
        """Queue-list metadata row."""
        return {
            "request_id": row["request_id"],
            "tenant_id": row.get("tenant_id", ""),
            "requester_id": row.get("requester_id", ""),
            "control": row.get("control", ""),
            "from_state": row.get("from_state", {}),
            "to_state": row.get("to_state", {}),
            "requested_at": row.get("requested_at", 0.0),
            "expires_at": row.get("expires_at", 0.0),
            "status": row.get("status", "pending"),
        }
