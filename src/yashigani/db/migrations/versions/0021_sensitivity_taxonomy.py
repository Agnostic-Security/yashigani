"""R14/R15 — per-tenant sensitivity taxonomy config table.

Revision ID: 0021
Revises: 0020
Create Date: 2026-06-13

Rationale (R14/R15, v2.25.5):
    Introduce a per-tenant sensitivity taxonomy store so admin can rename
    sensitivity level labels, remap colour classes, and add/remove levels
    within the 2–10 range.  The canonical numeric level (1–N) is the
    enforcement value; labels + colour classes are display-only metadata.

    This table seeds the default 5-level taxonomy (Info/Public/Internal/
    Confidential/Sensitive) as the tenant='default' baseline.

Schema:
    sensitivity_taxonomy(
        tenant_id   TEXT NOT NULL DEFAULT 'default',
        level_number INTEGER NOT NULL CHECK (level_number >= 1),
        label       TEXT NOT NULL,
        colour_class TEXT NOT NULL DEFAULT 'sens-level-1',
        created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (tenant_id, level_number)
    )

Downgrade: drops the sensitivity_taxonomy table.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS sensitivity_taxonomy (
            tenant_id    TEXT        NOT NULL DEFAULT 'default',
            level_number INTEGER     NOT NULL CHECK (level_number >= 1),
            label        TEXT        NOT NULL,
            colour_class TEXT        NOT NULL DEFAULT 'sens-level-1',
            created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY (tenant_id, level_number)
        )
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS sensitivity_taxonomy")
