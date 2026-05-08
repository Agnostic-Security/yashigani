"""v2.23.3 — Persistent encrypted auth settings (admin-panel HIBP API key).

Revision ID: 0008
Revises: 0007
Create Date: 2026-05-07

Rationale:
    Operators who use the commercial-tier rate-limit lift on the HIBP
    Passwords API, or who run a self-hosted HIBP mirror requiring auth,
    need a way to set/rotate the HIBP API key from the admin panel without
    touching .env files or restarting containers. This migration creates the
    durable backing store for that and any future small auth-config values.

Table:
    auth_settings — key/value store for operator-configurable auth settings.
    Each row's value is encrypted at rest using pgp_sym_encrypt so the
    app AES key (injected per transaction via app.aes_key) is required to
    decrypt. Single row per setting key; upsert-on-conflict is used for writes.

Initial setting keys:
    hibp_api_key — HIBP API key for rate-limit lift or mirror auth.
                   Empty string means "not configured" (fall back to env var
                   or anonymous request). Empty string is still encrypted.
"""
# Last updated: 2026-05-08T00:00:00+01:00
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0008"
down_revision: Union[str, None] = "0007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_DDL_UP = """
-- ==========================================================================
-- AUTH SETTINGS — encrypted key/value store for operator auth configuration
-- ==========================================================================

CREATE TABLE auth_settings (
    key             TEXT PRIMARY KEY,
    value_encrypted BYTEA NOT NULL,         -- pgp_sym_encrypt(value, app.aes_key)
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by      TEXT NOT NULL DEFAULT ''  -- admin username who last changed it
);

-- No RLS: auth_settings is a global (not per-tenant) operator configuration
-- table. Only the backoffice application user reads/writes it.
GRANT SELECT, INSERT, UPDATE, DELETE ON auth_settings TO yashigani_app;

-- NOTE: we do NOT pre-populate the hibp_api_key row here because Alembic
-- runs migrations outside a tenant transaction (no SET app.aes_key), so
-- pgp_sym_encrypt would fail with "unrecognized configuration parameter".
-- The AuthSettingsStore.get_setting() / set_setting() methods handle the
-- missing-row case gracefully: a missing row is treated as empty string.
-- The application creates the row on first write (upsert-on-conflict).
"""

_DDL_DOWN = """
DROP TABLE IF EXISTS auth_settings CASCADE;
"""


def upgrade() -> None:
    op.execute(_DDL_UP)


def downgrade() -> None:
    op.execute(_DDL_DOWN)
