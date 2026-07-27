"""YSG-RISK-155 — durable columns for NHI registrations on agent_registry.

Revision ID: 0030
Revises: 0029
Create Date: 2026-07-27

Rationale (YSG-RISK-155):
    ``AgentRegistry.register_nhi()`` dual-writes to the durable ``agent_registry``
    Postgres mirror (migration 0017) exactly like ``register()`` does for
    ordinary agents, but two things silently defeated it:

      1. ``agent_registry.token_hash`` was ``NOT NULL`` (migration 0001).
         An NHI's bearer token is a one-time plaintext secret handed to the
         NHI container and is NEVER re-persisted (see register_nhi's
         docstring) — so its durable dual-write always passes
         ``token_hash=None``. ``AgentDurableStore.upsert()`` treated
         ``token_hash is None`` as "metadata-only UPDATE, preserve the
         existing hash" and ran a bare ``UPDATE ... WHERE agent_id=%s``. For
         a BRAND-NEW nhi_id there is no existing row, so the UPDATE matched
         zero rows and the NHI was silently never persisted at all.

      2. The table had no columns for the NHI-specific fields the Redis hash
         carries (kind, template_id, owner_identity_id, allowed_models,
         budget_cap, svid_issued, pids_limit, memory_mb, spiffe_id,
         scope_hash, sensitivity_ceiling, allowed_tools). Even a corrected
         upsert would have nowhere to put them, and
         ``AgentRegistry.restore_from_durable()``'s existing
         ``if kind == "nhi":`` branch (which already expects these fields)
         was dead code because ``AgentDurableStore.list_all()`` could not
         SELECT columns that did not exist.

    This migration:
      * Drops the ``NOT NULL`` constraint on ``token_hash`` — legitimately
        NULL for ``kind='nhi'`` rows — and replaces it with a CHECK that still
        requires a token_hash for every non-NHI (``kind='agent'``) row, so a
        bug that leaves a *normal* agent's hash NULL is still caught at the
        DB layer.
      * Adds the NHI + additive-4.0-Phase-5 columns so
        ``AgentDurableStore.upsert()``/``list_all()`` can round-trip them and
        ``restore_from_durable()``'s NHI branch stops being dead code.

    All ADD COLUMN statements use IF NOT EXISTS / safe defaults so this is
    idempotent on a hand-patched dev DB, matching the pattern established by
    migration 0020 (identities table).

Downgrade:
    Drops the columns added here and restores token_hash NOT NULL. The
    downgrade is destructive for any NHI row whose token_hash is NULL by
    design — matches the existing precedent (0017/0018 downgrades are also
    lossy for data introduced after the column existed).
"""
from __future__ import annotations

from alembic import op


# revision identifiers, used by Alembic.
revision = "0030"
down_revision = "0029"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # --- token_hash: NULL only permitted for kind='nhi' -----------------------
    op.execute(
        "ALTER TABLE agent_registry ALTER COLUMN token_hash DROP NOT NULL"
    )

    # --- Additive columns (4.0 Phase 5 / §A.3 generic + NHI-specific) --------
    op.execute(
        "ALTER TABLE agent_registry "
        "ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'agent'"
    )
    op.execute(
        "ALTER TABLE agent_registry "
        "ADD COLUMN IF NOT EXISTS sensitivity_ceiling TEXT NOT NULL DEFAULT ''"
    )
    op.execute(
        "ALTER TABLE agent_registry "
        "ADD COLUMN IF NOT EXISTS allowed_tools JSON NOT NULL DEFAULT '[]'"
    )
    op.execute(
        "ALTER TABLE agent_registry "
        "ADD COLUMN IF NOT EXISTS template_id TEXT NOT NULL DEFAULT ''"
    )
    op.execute(
        "ALTER TABLE agent_registry "
        "ADD COLUMN IF NOT EXISTS owner_identity_id TEXT NOT NULL DEFAULT ''"
    )
    op.execute(
        "ALTER TABLE agent_registry "
        "ADD COLUMN IF NOT EXISTS allowed_models JSON NOT NULL DEFAULT '[]'"
    )
    op.execute(
        "ALTER TABLE agent_registry "
        "ADD COLUMN IF NOT EXISTS budget_cap JSON NOT NULL DEFAULT '{}'"
    )
    op.execute(
        "ALTER TABLE agent_registry "
        "ADD COLUMN IF NOT EXISTS svid_issued BOOLEAN NOT NULL DEFAULT false"
    )
    op.execute(
        "ALTER TABLE agent_registry "
        "ADD COLUMN IF NOT EXISTS pids_limit INTEGER NOT NULL DEFAULT 64"
    )
    op.execute(
        "ALTER TABLE agent_registry "
        "ADD COLUMN IF NOT EXISTS memory_mb INTEGER NOT NULL DEFAULT 512"
    )
    op.execute(
        "ALTER TABLE agent_registry "
        "ADD COLUMN IF NOT EXISTS spiffe_id TEXT NOT NULL DEFAULT ''"
    )
    op.execute(
        "ALTER TABLE agent_registry "
        "ADD COLUMN IF NOT EXISTS scope_hash TEXT NOT NULL DEFAULT ''"
    )

    # --- Guard: only 'nhi' rows may have a NULL token_hash --------------------
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conname = 'agent_registry_token_hash_required_for_agent_kind'
            ) THEN
                ALTER TABLE agent_registry
                    ADD CONSTRAINT agent_registry_token_hash_required_for_agent_kind
                    CHECK (kind = 'nhi' OR token_hash IS NOT NULL);
            END IF;
        END
        $$
        """
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE agent_registry "
        "DROP CONSTRAINT IF EXISTS agent_registry_token_hash_required_for_agent_kind"
    )
    op.execute("ALTER TABLE agent_registry DROP COLUMN IF EXISTS scope_hash")
    op.execute("ALTER TABLE agent_registry DROP COLUMN IF EXISTS spiffe_id")
    op.execute("ALTER TABLE agent_registry DROP COLUMN IF EXISTS memory_mb")
    op.execute("ALTER TABLE agent_registry DROP COLUMN IF EXISTS pids_limit")
    op.execute("ALTER TABLE agent_registry DROP COLUMN IF EXISTS svid_issued")
    op.execute("ALTER TABLE agent_registry DROP COLUMN IF EXISTS budget_cap")
    op.execute("ALTER TABLE agent_registry DROP COLUMN IF EXISTS allowed_models")
    op.execute("ALTER TABLE agent_registry DROP COLUMN IF EXISTS owner_identity_id")
    op.execute("ALTER TABLE agent_registry DROP COLUMN IF EXISTS template_id")
    op.execute("ALTER TABLE agent_registry DROP COLUMN IF EXISTS allowed_tools")
    op.execute("ALTER TABLE agent_registry DROP COLUMN IF EXISTS sensitivity_ceiling")
    op.execute("ALTER TABLE agent_registry DROP COLUMN IF EXISTS kind")
    # NOTE: destructive for any row whose token_hash is NULL (NHIs). Setting
    # NOT NULL back requires those rows to have a value first; this downgrade
    # intentionally does not attempt to backfill one (matches 0017/0018
    # precedent of lossy downgrades for data introduced after the column
    # existed). Operators downgrading past this migration with live NHI rows
    # must delete or backfill them first, or the ALTER will fail loudly.
    op.execute("ALTER TABLE agent_registry ALTER COLUMN token_hash SET NOT NULL")
