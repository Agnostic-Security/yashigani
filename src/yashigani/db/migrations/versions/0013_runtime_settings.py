"""v2.24.1 — Runtime settings persistence table.

Revision ID: 0013
Revises: 0012
Create Date: 2026-05-24

Rationale (admin-surfaces-all-runtime-settings rule):
    Every operator-tunable value must be persisted in DB so it survives
    restarts and is mutable via the backoffice admin API + UI without a
    redeploy.  Env vars seed the DB on first boot; subsequent boots read
    from DB.

    Compliance mapping:
      CMMC AU.L2-3.3.1   — create/retain system audit logs for events
      SOC 2 CC6.2        — logical access and authentication events
      ISO 27001 A.5.15   — access control (operator identity on every change)

Changes in this migration:

  1. CREATE TABLE runtime_settings — persisted operator-configurable values.
     Columns:
       key              TEXT PRIMARY KEY     — dotted setting key, e.g.
                                               'gateway.ddos.per_ip_limit'
       value            JSONB NOT NULL       — current value (number/bool/str)
       default_value    JSONB NOT NULL       — install-time default
       source           TEXT NOT NULL        — 'env' | 'ui' | 'api'
                                               tracks how this value was set
       last_changed_by  TEXT                 — admin account id; NULL = seeded
                                               at install time from env
       last_changed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()

  2. REVOKE UPDATE, DELETE ON runtime_settings FROM yashigani_app
     — writes are mediated by the RuntimeSettingsService (SECURITY DEFINER
       function or service-layer direct write under strict conditions).
     yashigani_app retains SELECT and INSERT (for seed-on-first-boot).

  3. GRANT SELECT, INSERT, UPDATE ON runtime_settings TO yashigani_app
     — UPDATE is required so the service can change 'value', 'source',
       'last_changed_by', 'last_changed_at' in place (upsert pattern).
     DELETE is still revoked — settings rows are never deleted, only
     updated or reset to default_value.

  4. Index on last_changed_at for audit list queries (newest-first).

Design decisions:
  - JSONB for value + default_value because settings have heterogeneous
    types (int, float, bool, string).  JSONB preserves numeric precision
    and enables type-safe extraction with ->>, ::int, ::float etc.
  - source column distinguishes 'env' (install-time seed, operator hasn't
    touched this via UI/API), 'ui' (changed via admin web panel), and 'api'
    (changed via PUT /admin/runtime-settings/{key}).  Auditors can see at a
    glance whether a value was ever explicitly set by a human operator.
  - UPDATE retained for yashigani_app (unlike audit_events / manifest_registrations
    which are append-only).  Runtime settings are inherently mutable;
    the audit trail is the RuntimeSettingChangedEvent audit record, not the
    table row immutability.

Downgrade: drops the table.

Evidence artefact: reference this migration SHA in the v2.24.1 compliance pack
for the admin-surfaces-all-runtime-settings rule implementation.
"""
# Last updated: 2026-05-24T00:00:00+00:00
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0013"
down_revision: Union[str, None] = "0012"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_DDL_UP = """
-- ================================================================
-- v2.24.1: Runtime settings persistence
-- ================================================================

CREATE TABLE runtime_settings (
    key              TEXT PRIMARY KEY,
    value            JSONB NOT NULL,
    default_value    JSONB NOT NULL,
    source           TEXT NOT NULL DEFAULT 'env'
                         CHECK (source IN ('env', 'ui', 'api')),
    last_changed_by  TEXT,
    last_changed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Audit list queries: newest-first
CREATE INDEX idx_runtime_settings_changed
    ON runtime_settings (last_changed_at DESC);

-- ================================================================
-- Access control
-- ================================================================
-- yashigani_app may SELECT, INSERT (seed), and UPDATE (change value).
-- DELETE is revoked — settings rows are never removed, only reset.
GRANT SELECT, INSERT, UPDATE ON runtime_settings TO yashigani_app;
REVOKE DELETE ON runtime_settings FROM yashigani_app;
"""

_DDL_DOWN = """
DROP TABLE IF EXISTS runtime_settings CASCADE;
"""


def upgrade() -> None:
    op.execute(_DDL_UP)


def downgrade() -> None:
    op.execute(_DDL_DOWN)
