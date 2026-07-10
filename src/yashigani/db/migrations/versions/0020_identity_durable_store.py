"""B1 follow-on — Postgres durable mirror for IdentityRegistry (migration-0005 identities table).

Revision ID: 0020
Revises: 0019
Create Date: 2026-06-13

Rationale (B1 follow-on, 2.25.5 build sheet):
    IdentityRegistry keeps identities in Redis db/3 only.  The ``identities``
    table created in migration-0005 was never written by the live registration
    path — its docstring says "Postgres as durable store" but the code only
    reads/writes Redis.  Su's AOF fix (B1, aa04626) covers the container-
    recreate case; a full volume-deletion or a migration still loses identities
    silently.

    This migration adds the columns required to make the ``identities`` table a
    durable dual-write target for IdentityRegistry:

      * ``bound_spiffe_uri`` — SPIFFE URI binding (V10.3.5, not in 0005).
      * ``api_key_hash``     — already present in 0005 (no-op ADD IF NOT EXISTS).

    The migration uses IF NOT EXISTS guards throughout so it is safe to run
    against a DB that already has some of these columns (e.g. a dev instance
    that was hand-patched). Pure additive; no destructive ALTER.

Downgrade:
    Removes the ``bound_spiffe_uri`` column added here.  Does NOT touch columns
    already present from 0005 (api_key_hash etc.) — those remain.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add bound_spiffe_uri — not in the original 0005 schema, required by the
    # IdentityRecord dataclass (V10.3.5 sender-constrained token binding).
    # ADD COLUMN IF NOT EXISTS is idempotent on Postgres ≥ 9.6.
    op.execute(
        """
        ALTER TABLE identities
            ADD COLUMN IF NOT EXISTS bound_spiffe_uri TEXT NOT NULL DEFAULT ''
        """
    )
    # Ensure api_key_hash is present (was in 0005 but ADD IF NOT EXISTS is safe
    # on DBs missing it for any reason).
    op.execute(
        """
        ALTER TABLE identities
            ADD COLUMN IF NOT EXISTS api_key_hash TEXT NOT NULL DEFAULT ''
        """
    )
    # UNIQUE (tenant_id, identity_id) is the natural upsert key.  0005 already
    # defines UNIQUE (identity_id) globally; add a per-tenant one for the
    # ON CONFLICT clause in the dual-write upsert if it does not exist.
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conname = 'identities_tenant_id_identity_id_key'
            ) THEN
                ALTER TABLE identities
                    ADD CONSTRAINT identities_tenant_id_identity_id_key
                    UNIQUE (tenant_id, identity_id);
            END IF;
        END
        $$
        """
    )


def downgrade() -> None:
    op.execute(
        """
        ALTER TABLE identities
            DROP COLUMN IF EXISTS bound_spiffe_uri
        """
    )
    op.execute(
        """
        ALTER TABLE identities
            DROP CONSTRAINT IF EXISTS identities_tenant_id_identity_id_key
        """
    )
