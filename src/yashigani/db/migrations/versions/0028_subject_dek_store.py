"""Crypto-shred (5.0) — durable mirror of per-subject wrapped DEKs.

Revision ID: 0028
Revises: 0027
Create Date: 2026-07-12

Rationale (crypto-shred erasure, GDPR Art 17 —
    Products/Yashigani/crypto-shred-erasure-design-5.0-20260712.md):
    CryptoShredKeyStore keeps per-subject Data Encryption Keys (DEKs) in Redis as
    the hot path. This table is the durable Postgres mirror (same pattern as
    migration-0020's IdentityRegistry mirror), so a Redis volume loss cannot
    orphan the ciphertext already fanned out to the file/SIEM sinks.

    It stores ONLY the KEK-wrapped DEK (itself ciphertext) — never a plaintext
    DEK, never a KEK (the KEK lives in the KMS secret-store). Destroying a DEK =
    UPDATE wrapped_dek=NULL, status='shredded' here + Redis DEL: a real hard
    delete of the key material (no KMS soft-delete window), which renders the
    subject's audit ciphertext permanently inert while the SHA-384 chain (which
    covers the ciphertext) stays verifiable.

    A shredded row is retained as a tombstone (wrapped_dek NULL, shredded_at set)
    so the erasure itself is auditable and the backup-replay purge can re-destroy
    a DEK that a restored snapshot resurrected.

    IF NOT EXISTS guards throughout; pure additive; safe to re-run.

Downgrade:
    Drops the table. (No data preserved — wrapped DEKs are reconstructable from
    Redis; a downgrade in a live deployment would forfeit the durable mirror.)
"""
from __future__ import annotations

from alembic import op


# revision identifiers, used by Alembic.
revision = "0028"
down_revision = "0027"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS subject_dek_store (
            tenant_id   text        NOT NULL,
            subject_id  text        NOT NULL,
            wrapped_dek text,                                  -- NULL after shred
            status      text        NOT NULL DEFAULT 'active', -- active | shredded
            created_at  timestamptz NOT NULL DEFAULT now(),
            shredded_at timestamptz,
            PRIMARY KEY (tenant_id, subject_id)
        );
        """
    )
    # Index to enumerate shredded tombstones (backup-replay purge / erasure audit).
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_subject_dek_store_status "
        "ON subject_dek_store (tenant_id, status);"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_subject_dek_store_status;")
    op.execute("DROP TABLE IF EXISTS subject_dek_store;")
