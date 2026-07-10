"""v2.25.2 — Lu wire-sink-gate P1: demote runtime role + irrevocable audit chain.

Revision ID: 0015
Revises: 0014
Create Date: 2026-06-04

Rationale (Lu finding YCS-20260604, P1 + P2; Tiago decision 2026-06-04 — combined
B+C "irrevocable audit" remediation):

    PART B — least-privilege runtime DB user (PREVENTION)
    -----------------------------------------------------
    Pre-2.25.2, the postgres container bootstrap superuser was POSTGRES_USER=
    yashigani_app, so yashigani_app was BOTH a cluster SUPERUSER and the owner
    of every table.  Consequences:
      - REVOKE UPDATE, DELETE ON audit_events FROM yashigani_app (migration
        0011) was INEFFECTIVE — a superuser bypasses table ACLs.
      - ENABLE ROW LEVEL SECURITY was bypassed — a table owner is exempt from
        RLS unless FORCE ROW LEVEL SECURITY is set.
      - The runtime DSN identity could UPDATE / DELETE audit rows and overwrite
        checkpoints, defeating the append-only / tamper-evident guarantee.

    Fix (no new privileged owner role — Tiago directive):
      - The bootstrap superuser is renamed to yashigani_admin (compose
        POSTGRES_USER=yashigani_admin; the EXISTING install-admin credential
        runs DDL / migrations).
      - yashigani_app is demoted to a NOSUPERUSER NOCREATEDB NOCREATEROLE
        runtime login role.  This migration handles the UPGRADE path where an
        existing install still has yashigani_app as superuser/owner: it
        ALTERs the role to NOSUPERUSER and REASSIGNs OWNED objects to the admin.
      - Ownership of all tables moves to yashigani_admin so the per-table
        REVOKE / RLS already authored in 0006-0013 finally takes effect.
      - FORCE ROW LEVEL SECURITY on the audit tables so even a future owner
        cannot bypass tenant isolation.

    PART C — irrevocable signed chain (PROACTIVE IMMUTABILITY)
    ---------------------------------------------------------
      - A CHECK constraint rejects any audit_events row whose prev_hash or
        event_hash is NULL.  An unchained event is REJECTED at INSERT time
        (immutable-by-construction) rather than landing with NULL chain links
        that a checkpoint could only flag after the fact.
        The constraint is NOT VALID for pre-existing (wave-1/2) rows so the
        migration does not fail on historical NULL-hash rows; it is enforced
        for all NEW inserts.

Compliance mapping (unchanged from 0011):
    ASVS V7.3.3 — audit log integrity (tamper-evident)
    NIST 800-53 AU-9 / AU-10 — protection of audit information + non-repudiation
    CMMC AU.L2-3.3.8/9 — protect + limit audit log management
    SOC 2 CC7.2 / CC7.3 — system monitoring + evaluation
    ISO 27001 A.8.15 / A.5.28 — logging + evidence collection
    GDPR Art. 32(1)(b) — integrity of personal data processing

Idempotency: every statement is guarded (IF EXISTS / DO-block / NOT VALID /
CREATE ... IF NOT EXISTS-equivalent), so re-running on a partially-applied or
already-correct cluster is a no-op.  Runs as the admin superuser (the only
identity that can ALTER ROLE / REASSIGN OWNED).

Last updated: 2026-06-04T00:00:00+00:00
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0015"
down_revision: Union[str, None] = "0014"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_DDL_UP = """
-- ================================================================
-- PART B.1 — demote yashigani_app to a least-privilege runtime role
-- ================================================================
-- On a fresh install, migration 0001 now creates yashigani_app already
-- NOSUPERUSER, so this ALTER is a no-op.  On the UPGRADE path (existing
-- installs where yashigani_app was the POSTGRES_USER bootstrap superuser),
-- this is the statement that actually removes its superuser bit.
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'yashigani_app') THEN
        ALTER ROLE yashigani_app NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    END IF;
END $$;

-- ================================================================
-- PART B.2 — reassign object ownership away from yashigani_app
-- ================================================================
-- A table OWNER bypasses table ACLs *and* (non-FORCE) RLS.  On the upgrade
-- path every table is owned by yashigani_app (it was the bootstrap user).
-- Reassign all objects it owns to the admin superuser so the per-table
-- REVOKE / RLS authored in earlier migrations becomes enforceable.
-- REASSIGN OWNED is the supported, complete way to move every owned object
-- (tables, partitions, sequences, functions) in one statement.
-- Guarded: only runs when both roles exist and they differ.
DO $$
DECLARE
    _admin text := current_user;  -- the migration runs as the admin superuser
BEGIN
    IF EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'yashigani_app')
       AND _admin <> 'yashigani_app' THEN
        EXECUTE format('REASSIGN OWNED BY yashigani_app TO %I', _admin);
    END IF;
END $$;

-- ================================================================
-- PART B.3 — FORCE ROW LEVEL SECURITY on the audit tables
-- ================================================================
-- ENABLE RLS (set in 0001) is bypassed by the table owner.  FORCE RLS makes
-- the policy apply to the owner too, so tenant isolation cannot be bypassed
-- by anyone connecting as the table owner.
ALTER TABLE audit_events            FORCE ROW LEVEL SECURITY;
ALTER TABLE inference_events        FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_chain_checkpoints FORCE ROW LEVEL SECURITY;

-- ================================================================
-- PART B.4 — re-assert the audit grant matrix (now enforceable)
-- ================================================================
-- audit_events / inference_events / audit_chain_checkpoints: SELECT + INSERT
-- only.  UPDATE / DELETE are revoked at the privilege level — no runtime code
-- path can mutate or delete an audit record.  Emergency fixes require the
-- admin superuser session (separately authorised + logged).
GRANT  SELECT, INSERT ON audit_events            TO yashigani_app;
GRANT  SELECT, INSERT ON inference_events         TO yashigani_app;
GRANT  SELECT, INSERT ON audit_chain_checkpoints  TO yashigani_app;
REVOKE UPDATE, DELETE ON audit_events            FROM yashigani_app;
REVOKE UPDATE, DELETE ON inference_events         FROM yashigani_app;
REVOKE UPDATE, DELETE ON audit_chain_checkpoints  FROM yashigani_app;

-- Sequence USAGE so BIGSERIAL nextval() works for the demoted role.
GRANT USAGE, SELECT ON SEQUENCE audit_events_seq_seq TO yashigani_app;

-- ================================================================
-- PART C — irrevocable chain: reject unchained audit_events inserts
-- ================================================================
-- prev_hash / event_hash are nullable columns (migration 0011) so historical
-- rows are not blocked.  We add a CHECK constraint that rejects NULL hashes on
-- NEW rows.  NOT VALID skips validation of existing rows (which may legitimately
-- have NULL hashes from wave-1/2) but ENFORCES the constraint for every INSERT
-- and UPDATE going forward.  An unchained event is therefore rejected at the DB
-- — immutable-by-construction, not flagged after the fact.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT FROM pg_catalog.pg_constraint
        WHERE conname = 'audit_events_chain_not_null'
    ) THEN
        ALTER TABLE audit_events
            ADD CONSTRAINT audit_events_chain_not_null
            CHECK (prev_hash IS NOT NULL AND event_hash IS NOT NULL) NOT VALID;
    END IF;
END $$;
"""

# Downgrade restores UPDATE/DELETE and drops the CHECK constraint, but does NOT
# re-grant superuser to yashigani_app (that was always a misconfiguration) and
# does NOT remove FORCE RLS or reverse ownership (those are strict improvements
# whose reversal would re-open the very tamper window this migration closes).
_DDL_DOWN = """
ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS audit_events_chain_not_null;
GRANT UPDATE, DELETE ON audit_events            TO yashigani_app;
GRANT UPDATE, DELETE ON inference_events         TO yashigani_app;
GRANT UPDATE, DELETE ON audit_chain_checkpoints  TO yashigani_app;
"""


def upgrade() -> None:
    op.execute(_DDL_UP)


def downgrade() -> None:
    op.execute(_DDL_DOWN)
