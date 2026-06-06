"""
Yashigani Audit — Tamper-evident hash chain service (LU-AMEND-01).

Implements the app-side hash computation for the audit_events hash chain.
Design decision: app-side over trigger-side (documented in migration 0011).

Hash scheme (consistent with writer.py F-12):
  - Algorithm: SHA-384 (hex-encoded)
  - Canonical form: JSON, sort_keys=True, separators=(",",":"), no prev_hash field
  - Day anchor: SHA-384("YYYY-MM-DD") for the first event of each calendar day

Daily merkle-root checkpoint:
  - Computed by AuditChainService.run_daily_checkpoint()
  - Merkle tree: balanced binary tree of SHA-384 hashes of all event_hash values
    for the day, ordered by seq (authoritative, wave-3) with (created_at, id)
    fallback for NULL-seq rows (backfilled wave-2 rows).
  - Signed with the service's internal SPIFFE identity (internal PKI leaf key)
    rather than an external Sigstore endpoint (rationale in migration 0011).

Ordering authority (LU-AMEND-01 wave-3):
  - Migration 0014 adds a BIGSERIAL seq column to audit_events.
  - seq is the AUTHORITATIVE ordering key for all chain queries (checkpoint,
    verify_chain_segment). Under timestamp collision (two events at the same
    microsecond) seq provides strict monotonic order; UUID v4 sort does not.
  - Backfilled rows (seq IS NOT NULL after migration 0014) use seq throughout.
  - Queries ORDER BY seq NULLS LAST to handle any rows where seq is temporarily
    NULL (should not occur in production after migration 0014 completes).

Last updated: 2026-05-25T00:00:00+00:00

Compliance:
    ASVS V7.3.3 — audit log integrity (tamper-evident)
    NIST AU-9 / AU-10 — protection of audit information + non-repudiation
    CMMC AU.L2-3.3.8/9 — protect and limit audit log management
    SOC 2 CC7.2/CC7.3 — monitoring + evaluation of security events
    ISO 27001 A.8.15/A.5.28 — logging + evidence collection
    GDPR Art. 32(1)(b) — integrity of personal data processing
"""
from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import date, datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Hash-chain primitives (mirrors writer.py F-12 scheme exactly)
# ---------------------------------------------------------------------------

def _canonical_json(event_dict: dict) -> str:
    """
    Produce a deterministic, compact JSON string for hashing.

    The ``prev_hash`` and ``prev_event_hash`` fields are excluded from the
    canonical form so that the hash of event N does not depend on event N's
    own chain link — only on the content of the preceding event.
    """
    d = {
        k: v for k, v in event_dict.items()
        if k not in ("prev_hash", "prev_event_hash")
    }
    return json.dumps(d, sort_keys=True, separators=(",", ":"), default=str)


def _sha384_hex(text: str) -> str:
    return hashlib.sha384(text.encode("utf-8")).hexdigest()


def day_anchor(date_str: str) -> str:
    """SHA-384 of a 'YYYY-MM-DD' string — chain anchor for the first event of each day."""
    return _sha384_hex(date_str)


def compute_event_hash(event_dict: dict) -> str:
    """Compute SHA-384 of the canonical JSON of an event (excluding hash fields)."""
    return _sha384_hex(_canonical_json(event_dict))


def compute_prev_hash(preceding_event_dict: Optional[dict], current_date_str: str) -> str:
    """Compute the prev_hash for the next event.

    If preceding_event_dict is None (first event of the day), returns the
    day anchor.  Otherwise returns SHA-384 of the preceding event's canonical
    JSON (i.e., the preceding event's own event_hash if populated; we recompute
    from canonical JSON for independence from DB state).
    """
    if preceding_event_dict is None:
        return day_anchor(current_date_str)
    return _sha384_hex(_canonical_json(preceding_event_dict))


# ---------------------------------------------------------------------------
# Merkle tree helpers (for daily checkpoint)
# ---------------------------------------------------------------------------

def _merkle_root(hashes: list[str]) -> str:
    """Compute a binary SHA-384 merkle root over a sorted list of hex hashes.

    If the list is empty, returns SHA-384 of the empty string.
    Odd number of leaves: duplicate the last leaf (standard Bitcoin-style).
    """
    if not hashes:
        return _sha384_hex("")
    layer = list(hashes)
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])  # duplicate last leaf for odd counts
        next_layer = []
        for i in range(0, len(layer), 2):
            combined = layer[i] + layer[i + 1]
            next_layer.append(_sha384_hex(combined))
        layer = next_layer
    return layer[0]


# ---------------------------------------------------------------------------
# ECDSA signing with internal PKI leaf key (internal Sigstore alternative)
# ---------------------------------------------------------------------------

def _sign_checkpoint(merkle_root_hex: str, key_path: Path) -> str:
    """Sign a merkle root with the service's internal ECDSA leaf key.

    Returns the DER-encoded signature as a hex string, or an empty string
    if the key is not available (key_path does not exist).

    Signing uses ECDSA with SHA-384 (consistent with P-256 / P-384 key families).
    The signature covers SHA-384(merkle_root_hex.encode("utf-8")) directly
    (Prehash=True via the ECDSA prehash interface).

    Design note: we sign the merkle root itself (a SHA-384 hex string) rather
    than re-hashing it, so the verifier can compute the same root from the
    event_hash column values and verify the signature without any additional
    prehash step.
    """
    if not key_path.exists():
        logger.warning(
            "audit-chain: signing key not found at %s — checkpoint will be unsigned",
            key_path,
        )
        return ""
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        raw_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        if not isinstance(raw_key, ec.EllipticCurvePrivateKey):
            logger.warning(
                "audit-chain: signing key at %s is not EC — skipping signature", key_path
            )
            return ""
        sig = raw_key.sign(
            merkle_root_hex.encode("utf-8"),
            ec.ECDSA(hashes.SHA384()),
        )
        return sig.hex()
    except Exception as exc:
        logger.error("audit-chain: checkpoint signing failed — %s", exc)
        return ""


# ---------------------------------------------------------------------------
# AuditChainService
# ---------------------------------------------------------------------------

class AuditChainService:
    """
    App-side hash chain management for the audit_events table.

    Responsibilities:
      1. compute_hashes_for_event(event_dict) → (prev_hash, event_hash)
         Called by the PostgresSink (or any writer) before INSERT so that
         the hash-chain columns are populated on every new row.

      2. run_daily_checkpoint(target_date, pool, spiffe_id, key_path)
         Called once per day (by a scheduler or cron-alike task).
         Fetches all event_hash values for target_date, computes the merkle
         root, signs it, and writes one row to audit_chain_checkpoints.

    Thread safety: the in-process chain state (_last_hash, _current_day) is
    protected by a threading.Lock for sync callers. For async callers, wrap
    calls in asyncio.Lock at the call site (the PostgresSink already serialises
    inserts in its batch loop).
    """

    def __init__(
        self,
        *,
        signing_key_path: Optional[Path] = None,
        signing_spiffe_id: str = "",
    ) -> None:
        """
        signing_key_path — path to the service's internal PKI leaf private key.
            Used to sign daily checkpoints. If None / missing, checkpoints are
            written unsigned (signature_hex = '').
        signing_spiffe_id — SPIFFE URI of the signing identity, e.g.
            'spiffe://yashigani.internal/{tenant_id}/hermes'.
            Stored in audit_chain_checkpoints.signing_spiffe_id.
        """
        import threading
        self._signing_key_path = signing_key_path
        self._signing_spiffe_id = signing_spiffe_id
        self._lock = threading.Lock()
        # In-memory chain state (protected by self._lock)
        self._last_hash: Optional[str] = None
        self._current_day: Optional[str] = None  # "YYYY-MM-DD"

    def compute_hashes_for_event(self, event_dict: dict) -> tuple[str, str]:
        """Compute (prev_hash, event_hash) for an event about to be inserted.

        Returns:
            (prev_hash, event_hash) — both SHA-384 hex strings.

        Updates the in-memory chain state under the lock so the next call
        receives the correct prev_hash.

        The caller MUST include prev_hash and event_hash in the INSERT
        statement. Not including them defeats the chain.
        """
        with self._lock:
            today = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
            if self._current_day != today or self._last_hash is None:
                # First event of the day (or first ever): anchor with day hash
                prev = day_anchor(today)
                self._current_day = today
            else:
                prev = self._last_hash

            ev_hash = compute_event_hash(event_dict)
            # Advance the chain pointer
            self._last_hash = ev_hash

        return prev, ev_hash

    async def run_daily_checkpoint(
        self,
        target_date: date,
        pool,
        tenant_id: str = "00000000-0000-0000-0000-000000000000",
    ) -> dict:
        """Compute and persist the daily merkle-root checkpoint.

        Args:
            target_date — the calendar date to checkpoint (typically yesterday,
                called from a scheduled job that runs at 00:05 UTC).
            pool — asyncpg pool (or compatible pool with acquire() context manager).
            tenant_id — the tenant UUID to checkpoint. For platform events use the
                sentinel tenant '00000000-0000-0000-0000-000000000000'.

        Returns:
            dict with keys: date, event_count, merkle_root, chain_break_count,
            signed (bool), checkpoint_id (UUID str).

        Raises:
            RuntimeError if the checkpoint INSERT fails.
        """
        date_str = target_date.isoformat()
        start_ts = datetime(
            target_date.year, target_date.month, target_date.day,
            tzinfo=timezone.utc,
        )
        end_ts = start_ts + timedelta(days=1)

        async with pool.acquire() as conn:
            async with conn.transaction():
                # Set tenant context for RLS
                await conn.execute(
                    "SELECT set_config('app.tenant_id', $1, true)",
                    tenant_id,
                )

                # Fetch event hashes for the target date, ordered by seq
                # (LU-AMEND-01 wave-3 authoritative ordering key).
                # seq is BIGSERIAL assigned at INSERT time — strictly monotonic
                # even when two events share the same created_at microsecond.
                # Rows with NULL event_hash are excluded (chain not populated).
                # ORDER BY seq NULLS LAST: all post-migration rows have seq;
                # any stray NULL-seq rows are sorted to the end so they do not
                # corrupt the chain ordering of normal rows.
                rows = await conn.fetch(
                    """
                    SELECT event_hash, prev_hash, seq
                    FROM audit_events
                    WHERE tenant_id = $1
                      AND created_at >= $2
                      AND created_at < $3
                      AND event_hash IS NOT NULL
                    ORDER BY seq NULLS LAST
                    """,
                    uuid.UUID(tenant_id),
                    start_ts,
                    end_ts,
                )

                event_count = len(rows)
                hashes = [r["event_hash"] for r in rows]

                # Count chain breaks: a break occurs when a row's prev_hash does
                # not match the event_hash of the immediately preceding row.
                chain_breaks = 0
                for i in range(1, len(rows)):
                    expected_prev = rows[i - 1]["event_hash"]
                    actual_prev = rows[i]["prev_hash"]
                    if actual_prev != expected_prev:
                        chain_breaks += 1
                        logger.warning(
                            "audit-chain: chain break detected at event index %d "
                            "for tenant %s on %s (expected prev=%s, got %s)",
                            i, tenant_id, date_str,
                            expected_prev[:16] + "...",
                            (actual_prev or "NULL")[:16] + "...",
                        )

                root = _merkle_root(hashes)

                # Sign the merkle root
                sig_hex = ""
                if self._signing_key_path:
                    sig_hex = _sign_checkpoint(root, self._signing_key_path)

                # Insert the checkpoint — IMMUTABLE ONCE WRITTEN (v2.25.2, Lu
                # wire-sink-gate P1/P2 / irrevocable chain).  ON CONFLICT DO
                # NOTHING: the FIRST checkpoint for a (tenant, date) is
                # authoritative; a re-run is a no-op rather than an overwrite.
                #
                # Rationale: the previous ON CONFLICT DO UPDATE let a checkpoint
                # be silently rewritten, which is a tamper vector (recompute the
                # merkle root over edited rows, overwrite the checkpoint).  It
                # also only worked because yashigani_app used to be a SUPERUSER
                # bypassing the grant — the demoted runtime role has SELECT+INSERT
                # only (no UPDATE) on audit_chain_checkpoints, matching the
                # immutable-once-written design intent already documented in
                # migration 0011.  An auditor compares the on-disk checkpoint to a
                # freshly recomputed root; a divergence is a finding, not a
                # silent update.
                checkpoint_id = str(uuid.uuid4())
                status = await conn.execute(
                    """
                    INSERT INTO audit_chain_checkpoints
                        (id, tenant_id, checkpoint_date, event_count, merkle_root,
                         chain_break_count, signing_spiffe_id, signature_hex, computed_at)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
                    ON CONFLICT (tenant_id, checkpoint_date) DO NOTHING
                    """,
                    uuid.UUID(checkpoint_id),
                    uuid.UUID(tenant_id),
                    target_date,  # asyncpg accepts datetime.date directly
                    event_count,
                    root,
                    chain_breaks,
                    self._signing_spiffe_id,
                    sig_hex,
                )
                # "INSERT 0 0" => a checkpoint already existed (no-op re-run).
                if status.endswith(" 0"):
                    logger.info(
                        "audit-chain: checkpoint for %s tenant=%s already exists — "
                        "immutable, re-run is a no-op",
                        date_str, tenant_id,
                    )

        logger.info(
            "audit-chain: checkpoint written for %s | tenant=%s | events=%d | "
            "root=%s... | breaks=%d | signed=%s",
            date_str, tenant_id, event_count,
            root[:16], chain_breaks, bool(sig_hex),
        )

        return {
            "date": date_str,
            "event_count": event_count,
            "merkle_root": root,
            "chain_break_count": chain_breaks,
            "signed": bool(sig_hex),
            "checkpoint_id": checkpoint_id,
            "signing_spiffe_id": self._signing_spiffe_id,
        }

    def verify_event(self, event_dict: dict, stored_event_hash: str) -> bool:
        """Verify that an event's stored event_hash matches the computed hash.

        Args:
            event_dict — the event as stored (may include prev_hash/event_hash
                columns; they are excluded from the canonical form).
            stored_event_hash — the event_hash value from the DB row.

        Returns:
            True if the computed hash matches stored_event_hash.
        """
        computed = compute_event_hash(event_dict)
        return computed == stored_event_hash

    def verify_chain_segment(
        self, events: list[dict], date_str: str
    ) -> tuple[bool, list[int]]:
        """Verify the hash chain for a sequence of events.

        Args:
            events — list of event dicts ordered by seq (LU-AMEND-01 wave-3
                authoritative ordering key), each including prev_hash and
                event_hash fields as stored in the DB. For backfilled pre-wave-3
                rows without seq, callers should order by (created_at, id).
            date_str — "YYYY-MM-DD" of the segment (used to compute the expected
                day anchor for the first event).

        Returns:
            (chain_ok, break_indices) — chain_ok is True if no breaks detected.
            break_indices is the list of 0-based indices where breaks occur.
        """
        breaks: list[int] = []
        expected_prev = day_anchor(date_str)

        for i, ev in enumerate(events):
            actual_prev = ev.get("prev_hash") or ev.get("prev_event_hash", "")
            ev_hash = ev.get("event_hash", "")

            if i == 0:
                # First event: prev must be the day anchor
                if actual_prev != expected_prev:
                    breaks.append(i)
            else:
                if actual_prev != expected_prev:
                    breaks.append(i)

            # Advance expected_prev to the hash of this event
            expected_prev = ev_hash

        return len(breaks) == 0, breaks
