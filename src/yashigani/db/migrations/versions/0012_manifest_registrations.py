"""v2.24.1 — LU-AMEND-02: multi-tenant manifest registration ledger.

Revision ID: 0012
Revises: 0011
Create Date: 2026-05-24

Rationale (LU-AMEND-02 specification):
    Lu GRC review (YCS-20260523-v2.24.1-COUNCIL-LU §3.LU-AMEND-02) requires a
    durable, append-only ledger of every agent manifest registration so that
    auditors can trace the exact YAML blob, SHA-256, operator identity, and
    signing provenance for any onboard event.

    Compliance mapping:
      NIST 800-53 AU-2   — event logging: what events must be logged
      NIST 800-53 AU-3   — content of audit records: actor, time, object, outcome
      NIST 800-53 AU-12  — audit record generation: generate records per AU-2/AU-3
      NIST 800-53 AC-6(9)— log use of privileged functions (agent register = priv)
      CMMC AU.L2-3.3.1   — create/retain system audit logs for events
      CMMC AU.L2-3.3.2   — ensure actions of individual users can be traced
      SOC 2 CC6.2 / 6.3  — logical access and authentication events
      SOC 2 CC8.1        — change management: changes authorised and documented
      ISO 42001 A.6.1.2  — AI system inventory and version control
      ISO 42001 A.6.2.6  — AI system monitoring and audit logging

Changes in this migration:

  1. CREATE TABLE manifest_registrations — append-only ledger.
     Columns:
       id               BIGSERIAL PRIMARY KEY
       tenant_id        TEXT NOT NULL   — arbitrary string; not FK to tenants so
                                          CLI callers can register before the
                                          tenant UUID is assigned. A UUID value
                                          matching tenants.id is the normal case.
       agent_id         TEXT NOT NULL   — agent registry ID (string, not UUID,
                                          to allow pre-registration of agents
                                          that are not yet in the registry)
       manifest_sha256  TEXT NOT NULL   — hex SHA-256 of manifest_yaml_blob
       manifest_yaml_blob TEXT NOT NULL — full YAML manifest as stored at
                                          registration time.
                                          TOAST behaviour note: PostgreSQL
                                          automatically TOASTs values > ~2kB.
                                          Practical limit for this column is the
                                          TOAST max (1 GB per row), but manifests
                                          should stay well under 1 MB. The service
                                          layer enforces a 1 MB soft limit and
                                          emits a warning above 512 kB.
       registered_by_operator_identity TEXT NOT NULL
                                       — sub claim from the operator token, or
                                         "unknown" for weak-identity onboards.
       registered_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
       previous_manifest_sha256 TEXT   — NULL on first registration for this
                                          agent_id; SHA-256 of the immediately
                                          preceding manifest for that agent.
       signature_provenance JSONB      — ceremony JSON: algorithm, signer SPIFFE
                                          ID, HMAC signature hex, ack metadata.
                                          NULL when the registration is created
                                          by the service layer without a ceremony
                                          (programmatic registrations).

  2. Indexes:
       idx_manifest_reg_tenant — (tenant_id, registered_at DESC) for history queries
       idx_manifest_reg_agent  — (agent_id, registered_at DESC) for per-agent history

  3. REVOKE UPDATE, DELETE ON manifest_registrations FROM yashigani_app
     — append-only enforcement matching audit_events (migration 0011).
     yashigani_app retains SELECT and INSERT.

  4. GRANT SELECT, INSERT ON manifest_registrations TO yashigani_app
     — explicit grants so the role can access the new table.

Design decisions:
  - tenant_id is TEXT not UUID foreign key because:
    a) Early onboarding may happen before the tenant UUID is provisioned.
    b) CLI scripts cannot always look up the UUID from the backoffice.
    c) String comparison is sufficient for audit queries.
    Auditors should correlate against tenants.id when UUID values are used.

  - manifest_yaml_blob is TEXT (not BYTEA) because:
    a) YAML is a text format; UTF-8 TEXT enables full-text search in psql.
    b) pg_dump/restore handles TEXT columns more portably.
    c) TOAST storage is automatic above 2kB — no special handling needed.

  - signature_provenance is JSONB (not a set of columns) because:
    a) The ceremony JSON schema may evolve (v2 adds Sigstore/RSA-PSS-SHA-384).
    b) JSONB preserves the original signed document faithfully.
    c) GIN indexes on JSONB allow future provenance queries if needed.

Downgrade: drops the table (CASCADE removes indexes).

Evidence artefact: reference this migration SHA in the v2.24.1 compliance pack
for LU-AMEND-02 closure.
"""
# Last updated: 2026-05-24T00:00:00+00:00
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0012"
down_revision: Union[str, None] = "0011"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_DDL_UP = """
-- ================================================================
-- LU-AMEND-02: Multi-tenant manifest registration ledger
-- ================================================================

CREATE TABLE manifest_registrations (
    id                              BIGSERIAL PRIMARY KEY,
    tenant_id                       TEXT NOT NULL,
    agent_id                        TEXT NOT NULL,
    manifest_sha256                 TEXT NOT NULL,
    manifest_yaml_blob              TEXT NOT NULL,
    registered_by_operator_identity TEXT NOT NULL,
    registered_at                   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    previous_manifest_sha256        TEXT,
    signature_provenance            JSONB
);

-- ================================================================
-- Indexes
-- ================================================================

-- Tenant history queries: newest first within a tenant
CREATE INDEX idx_manifest_reg_tenant
    ON manifest_registrations (tenant_id, registered_at DESC);

-- Per-agent history queries: newest first for an agent
CREATE INDEX idx_manifest_reg_agent
    ON manifest_registrations (agent_id, registered_at DESC);

-- ================================================================
-- Append-only enforcement: REVOKE destructive privileges
-- ================================================================
-- yashigani_app must be able to INSERT and SELECT (for history + lookups).
-- UPDATE and DELETE are revoked — no code path is authorised to mutate
-- or purge manifest registration records.
-- Emergency corrections require a superuser session (separately authorised,
-- must be logged by the DBA).

GRANT SELECT, INSERT ON manifest_registrations TO yashigani_app;
REVOKE UPDATE, DELETE ON manifest_registrations FROM yashigani_app;

-- Sequence: grant USAGE so BIGSERIAL nextval works under yashigani_app.
GRANT USAGE ON SEQUENCE manifest_registrations_id_seq TO yashigani_app;
"""

_DDL_DOWN = """
-- Reverse: drop the ledger table (CASCADE removes indexes)
DROP TABLE IF EXISTS manifest_registrations CASCADE;
"""


def upgrade() -> None:
    op.execute(_DDL_UP)


def downgrade() -> None:
    op.execute(_DDL_DOWN)
