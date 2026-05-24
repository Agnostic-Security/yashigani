"""
Yashigani Manifest Registry Service — LU-AMEND-02 / v2.24.1.

Append-only ledger of every agent manifest registration.

Compliance:
  NIST AU-2/AU-3/AU-12/AC-6(9) + CMMC AU.L2-3.3.1/2 +
  SOC 2 CC6.2/6.3/CC8.1 + ISO 42001 A.6.1.2/A.6.2.6.

TOAST size note (LU-AMEND-02 brief §4.1):
  manifest_yaml_blob is stored as PostgreSQL TEXT which is automatically
  TOASTed above ~2 kB. Practical payload limits:
    - Soft warning:  512 kB (service layer logs at WARNING)
    - Hard limit:   1 MB  (service raises ValueError — refuse to store)
  These limits prevent accidental ingestion of runaway YAML blobs while
  staying well within PostgreSQL's theoretical 1 GB per-cell TOAST limit.
  Operators storing manifests above 512 kB should audit whether the YAML
  contains embedded data that belongs in a separate secrets store.

Last updated: 2026-05-24T00:00:00+00:00
"""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Any

_log = logging.getLogger("yashigani.manifest_registry")

# Hard limit: refuse to store manifests larger than this.
_MANIFEST_HARD_LIMIT_BYTES = 1 * 1024 * 1024  # 1 MB
# Soft limit: log a warning above this threshold.
_MANIFEST_SOFT_LIMIT_BYTES = 512 * 1024        # 512 kB


# ---------------------------------------------------------------------------
# Record type
# ---------------------------------------------------------------------------

@dataclass
class ManifestRegistrationRecord:
    """A single row from manifest_registrations, returned by history/show queries."""
    id: int
    tenant_id: str
    agent_id: str
    manifest_sha256: str
    manifest_yaml_blob: str
    registered_by_operator_identity: str
    registered_at: datetime
    previous_manifest_sha256: Optional[str]
    signature_provenance: Optional[dict]


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class ManifestRegistryService:
    """
    Append-only ledger for agent manifest registrations.

    All write operations INSERT only — UPDATE and DELETE are revoked from
    yashigani_app at the DB level (migration 0012).

    The pool is injected at construction time; the service does NOT call
    get_pool() internally so it can be used in tests with a mock pool.

    Usage::

        svc = ManifestRegistryService(pool=get_pool())

        record_id = await svc.register(
            tenant_id="00000000-0000-0000-0000-000000000000",
            agent_id="my-agent",
            manifest_yaml="name: my-agent\nupstream: http://...",
            operator_identity="admin1",
            signature_provenance=None,
        )

        history = await svc.history(tenant_id="...", limit=50, offset=0)
        record  = await svc.show(record_id=1)
        ok, msg = await svc.verify(record_id=1)
    """

    def __init__(self, pool: Any) -> None:
        if pool is None:
            raise RuntimeError(
                "ManifestRegistryService requires a non-None asyncpg pool. "
                "Ensure create_pool() has been called before constructing this service."
            )
        self._pool = pool

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_sha256(blob: str) -> str:
        """Compute hex SHA-256 of the manifest YAML blob (UTF-8 encoded)."""
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    @staticmethod
    def _check_blob_size(blob: str) -> None:
        """Enforce size limits on manifest_yaml_blob."""
        size = len(blob.encode("utf-8"))
        if size > _MANIFEST_HARD_LIMIT_BYTES:
            raise ValueError(
                f"manifest_yaml_blob exceeds hard limit "
                f"({size} bytes > {_MANIFEST_HARD_LIMIT_BYTES} bytes). "
                "Store large embedded data in a dedicated secrets store."
            )
        if size > _MANIFEST_SOFT_LIMIT_BYTES:
            _log.warning(
                "manifest_yaml_blob is large (%d bytes > soft limit %d bytes). "
                "Consider whether the YAML contains embedded data that should "
                "live in a separate secrets store.",
                size,
                _MANIFEST_SOFT_LIMIT_BYTES,
            )

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    async def register(
        self,
        tenant_id: str,
        agent_id: str,
        manifest_yaml: str,
        operator_identity: str,
        signature_provenance: Optional[dict] = None,
    ) -> int:
        """
        Append a manifest registration record.

        Computes manifest_sha256 from blob, looks up the most recent
        previous_manifest_sha256 for this agent_id, then INSERTs.

        Parameters
        ----------
        tenant_id:
            Tenant identifier string (typically a UUID matching tenants.id).
        agent_id:
            Agent registry identifier.
        manifest_yaml:
            Full YAML text of the manifest being registered.
        operator_identity:
            sub claim from the operator token, or "unknown" for weak-identity.
        signature_provenance:
            Ceremony JSON dict (alg, signer, sig, ack fields), or None.

        Returns
        -------
        int
            The new record's id (BIGSERIAL).
        """
        if not tenant_id:
            raise ValueError("tenant_id is required")
        if not agent_id:
            raise ValueError("agent_id is required")
        if not manifest_yaml:
            raise ValueError("manifest_yaml is required")
        if not operator_identity:
            raise ValueError("operator_identity is required")

        self._check_blob_size(manifest_yaml)
        sha = self._compute_sha256(manifest_yaml)

        provenance_json: Optional[str] = None
        if signature_provenance is not None:
            provenance_json = json.dumps(signature_provenance, sort_keys=True)

        async with self._pool.acquire() as conn:
            # Look up the most recent manifest for this agent_id (across all tenants).
            # Per Lu spec: previous_manifest_sha256 tracks the chain for the agent,
            # not per-tenant — so an agent that moves tenants still carries its history.
            prev_row = await conn.fetchrow(
                """
                SELECT manifest_sha256
                FROM   manifest_registrations
                WHERE  agent_id = $1
                ORDER  BY registered_at DESC, id DESC
                LIMIT  1
                """,
                agent_id,
            )
            prev_sha: Optional[str] = prev_row["manifest_sha256"] if prev_row else None

            row = await conn.fetchrow(
                """
                INSERT INTO manifest_registrations (
                    tenant_id,
                    agent_id,
                    manifest_sha256,
                    manifest_yaml_blob,
                    registered_by_operator_identity,
                    previous_manifest_sha256,
                    signature_provenance
                ) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
                RETURNING id
                """,
                tenant_id,
                agent_id,
                sha,
                manifest_yaml,
                operator_identity,
                prev_sha,
                provenance_json,
            )

        record_id: int = row["id"]
        _log.info(
            "ManifestRegistry: registered agent=%s tenant=%s sha256=%.12s... id=%d prev=%.12s",
            agent_id,
            tenant_id,
            sha,
            record_id,
            prev_sha[:12] if prev_sha else "null",
        )
        return record_id

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    async def history(
        self,
        tenant_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> list[ManifestRegistrationRecord]:
        """
        List registrations for a tenant, newest first.

        Parameters
        ----------
        tenant_id:
            Filter to this tenant.
        limit:
            Maximum rows to return (1–200, default 50).
        offset:
            Pagination offset.

        Returns
        -------
        list[ManifestRegistrationRecord]
        """
        limit = max(1, min(limit, 200))
        offset = max(0, offset)

        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT id, tenant_id, agent_id, manifest_sha256,
                       manifest_yaml_blob, registered_by_operator_identity,
                       registered_at, previous_manifest_sha256,
                       signature_provenance
                FROM   manifest_registrations
                WHERE  tenant_id = $1
                ORDER  BY registered_at DESC, id DESC
                LIMIT  $2 OFFSET $3
                """,
                tenant_id,
                limit,
                offset,
            )
        return [_row_to_record(r) for r in rows]

    async def show(self, record_id: int) -> Optional[ManifestRegistrationRecord]:
        """
        Return a single registration record by id.

        Returns None if not found.
        """
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT id, tenant_id, agent_id, manifest_sha256,
                       manifest_yaml_blob, registered_by_operator_identity,
                       registered_at, previous_manifest_sha256,
                       signature_provenance
                FROM   manifest_registrations
                WHERE  id = $1
                """,
                record_id,
            )
        if row is None:
            return None
        return _row_to_record(row)

    async def verify(self, record_id: int) -> tuple[bool, str]:
        """
        Re-verify SHA-256 of stored blob against stored manifest_sha256.

        Returns
        -------
        (ok: bool, message: str)
            ok=True if recomputed SHA matches stored SHA.
            ok=False if there is a mismatch (tamper evidence).
        """
        record = await self.show(record_id)
        if record is None:
            return False, f"record_id={record_id} not found"

        recomputed = self._compute_sha256(record.manifest_yaml_blob)
        if recomputed == record.manifest_sha256:
            return True, f"OK: sha256={recomputed}"
        return (
            False,
            f"MISMATCH: stored={record.manifest_sha256} recomputed={recomputed}",
        )

    async def latest_for_agent(
        self, agent_id: str
    ) -> Optional[ManifestRegistrationRecord]:
        """
        Return the most recent registration for an agent (any tenant).
        Used by the ceremony flow to populate previous_manifest_sha256.
        """
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT id, tenant_id, agent_id, manifest_sha256,
                       manifest_yaml_blob, registered_by_operator_identity,
                       registered_at, previous_manifest_sha256,
                       signature_provenance
                FROM   manifest_registrations
                WHERE  agent_id = $1
                ORDER  BY registered_at DESC, id DESC
                LIMIT  1
                """,
                agent_id,
            )
        if row is None:
            return None
        return _row_to_record(row)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _row_to_record(row: Any) -> ManifestRegistrationRecord:
    """Convert an asyncpg Record to a ManifestRegistrationRecord."""
    prov = row["signature_provenance"]
    # asyncpg returns JSONB columns as dicts directly; TEXT-cast JSONB returns str.
    if isinstance(prov, str):
        try:
            prov = json.loads(prov)
        except (ValueError, TypeError):
            prov = None
    return ManifestRegistrationRecord(
        id=row["id"],
        tenant_id=row["tenant_id"],
        agent_id=row["agent_id"],
        manifest_sha256=row["manifest_sha256"],
        manifest_yaml_blob=row["manifest_yaml_blob"],
        registered_by_operator_identity=row["registered_by_operator_identity"],
        registered_at=row["registered_at"],
        previous_manifest_sha256=row["previous_manifest_sha256"],
        signature_provenance=prov,
    )
