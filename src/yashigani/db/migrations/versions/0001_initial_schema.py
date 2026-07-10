"""Initial schema — tenants, RBAC, agents, audit, inference, JWT, cache, anomaly, endpoint RL.

Revision ID: 0001
Revises:
Create Date: 2026-03-27
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_DDL_UP = """
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
-- pg_partman and pg_cron are optional — require specialized Postgres images.
-- When not available, audit table partitions must be created manually.
DO $$ BEGIN CREATE EXTENSION IF NOT EXISTS "pg_partman"; EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'pg_partman not available — manual partition management required'; END $$;
DO $$ BEGIN CREATE EXTENSION IF NOT EXISTS "pg_cron"; EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'pg_cron not available — scheduled jobs disabled'; END $$;

-- tenants (not per-tenant; platform-scoped)
CREATE TABLE tenants (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_active       BOOLEAN NOT NULL DEFAULT true
);

-- Insert platform sentinel tenant
INSERT INTO tenants (id, name, is_active)
VALUES ('00000000-0000-0000-0000-000000000000', 'platform', true);

-- tenant_context
CREATE TABLE tenant_context (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    config_key      TEXT NOT NULL,
    config_value    TEXT NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, config_key)
);
ALTER TABLE tenant_context ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant_context
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- rbac_groups
CREATE TABLE rbac_groups (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    description     TEXT,
    rate_limit_rps  INTEGER,
    rate_limit_burst INTEGER,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);
ALTER TABLE rbac_groups ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON rbac_groups
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- rbac_members (email is AES-encrypted PII)
CREATE TABLE rbac_members (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    group_id        UUID NOT NULL REFERENCES rbac_groups(id) ON DELETE CASCADE,
    email_encrypted BYTEA NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, group_id, email_encrypted)
);
ALTER TABLE rbac_members ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON rbac_members
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- agent_registry
CREATE TABLE agent_registry (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_name      TEXT NOT NULL,
    upstream_url    TEXT NOT NULL,
    token_hash      TEXT NOT NULL,
    rate_limit_rps  INTEGER NOT NULL DEFAULT 10,
    rate_limit_burst INTEGER NOT NULL DEFAULT 5,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, agent_name)
);
ALTER TABLE agent_registry ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent_registry
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- audit_events (partitioned by month, append-only)
CREATE TABLE audit_events (
    id              UUID DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    event_type      TEXT NOT NULL,
    request_id      UUID,
    session_id      TEXT,
    agent_id        TEXT,
    action          TEXT NOT NULL,
    reason          TEXT,
    upstream_status INTEGER,
    elapsed_ms      INTEGER,
    confidence_score DOUBLE PRECISION,
    client_ip_hash  TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);

CREATE TABLE audit_events_2026_03
    PARTITION OF audit_events
    FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');

CREATE TABLE audit_events_2026_04
    PARTITION OF audit_events
    FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');

ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit_events
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

CREATE INDEX idx_audit_events_tenant_created ON audit_events (tenant_id, created_at DESC);
CREATE INDEX idx_audit_events_request_id ON audit_events (request_id);

-- inference_events (partitioned by month, payload content AES-encrypted)
CREATE TABLE inference_events (
    id                      UUID DEFAULT uuid_generate_v4(),
    tenant_id               UUID NOT NULL REFERENCES tenants(id),
    session_id              TEXT NOT NULL,
    agent_id                TEXT NOT NULL,
    payload_hash            TEXT NOT NULL,
    payload_length          INTEGER NOT NULL,
    response_length         INTEGER,
    payload_content         BYTEA,
    response_content        BYTEA,
    classification_label    TEXT NOT NULL,
    classification_confidence DOUBLE PRECISION NOT NULL,
    backend_used            TEXT NOT NULL,
    latency_ms              INTEGER NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);

CREATE TABLE inference_events_2026_03
    PARTITION OF inference_events
    FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');

CREATE TABLE inference_events_2026_04
    PARTITION OF inference_events
    FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');

ALTER TABLE inference_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON inference_events
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

CREATE INDEX idx_inference_events_tenant_session ON inference_events (tenant_id, session_id, created_at DESC);
CREATE INDEX idx_inference_events_payload_hash ON inference_events (payload_hash);

-- anomaly_thresholds
CREATE TABLE anomaly_thresholds (
    id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id               UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    window_seconds          INTEGER NOT NULL DEFAULT 60,
    call_count_n            INTEGER NOT NULL DEFAULT 10,
    payload_threshold_bytes INTEGER NOT NULL DEFAULT 256,
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id)
);
ALTER TABLE anomaly_thresholds ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON anomaly_thresholds
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- jwt_config
CREATE TABLE jwt_config (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    jwks_url    TEXT NOT NULL,
    issuer      TEXT NOT NULL,
    audience    TEXT NOT NULL,
    fail_closed BOOLEAN NOT NULL DEFAULT true,
    scope       TEXT NOT NULL DEFAULT 'tenant',   -- 'tenant' | 'platform'
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, scope)
);
ALTER TABLE jwt_config ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON jwt_config
    USING (tenant_id = current_setting('app.tenant_id')::uuid
           OR tenant_id = '00000000-0000-0000-0000-000000000000'::uuid);

-- cache_config
CREATE TABLE cache_config (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    enabled     BOOLEAN NOT NULL DEFAULT false,
    ttl_seconds INTEGER NOT NULL DEFAULT 300,
    max_size_mb INTEGER NOT NULL DEFAULT 64,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id)
);
ALTER TABLE cache_config ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON cache_config
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- endpoint_ratelimit_overrides
CREATE TABLE endpoint_ratelimit_overrides (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    endpoint_hash   TEXT NOT NULL,
    endpoint_label  TEXT NOT NULL,
    rps             INTEGER NOT NULL,
    burst           INTEGER NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, endpoint_hash)
);
ALTER TABLE endpoint_ratelimit_overrides ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON endpoint_ratelimit_overrides
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- siem_config (admin-set SIEM integration)
CREATE TABLE siem_config (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    backend     TEXT NOT NULL DEFAULT 'none',  -- 'none' | 'splunk' | 'elasticsearch' | 'wazuh'
    endpoint    TEXT,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO siem_config (backend) VALUES ('none');

-- Application role (least privilege).
-- v2.25.2 (Lu wire-sink-gate P1): yashigani_app is the RUNTIME role and MUST be
-- NOSUPERUSER.  DDL / migrations run as the separate bootstrap admin superuser
-- (compose POSTGRES_USER=yashigani_admin).  Created explicitly NOSUPERUSER here
-- so a fresh install never has a superuser runtime identity; migration 0015
-- additionally demotes any pre-2.25.2 install where yashigani_app was the
-- bootstrap superuser.  NOBYPASSRLS so FORCE RLS on the audit tables applies.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'yashigani_app') THEN
        CREATE ROLE yashigani_app
            LOGIN
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOREPLICATION
            NOBYPASSRLS
            PASSWORD 'PLACEHOLDER_REPLACED_BY_BOOTSTRAP';
    ELSE
        -- Idempotent / upgrade-in-place: ensure the role is least-privilege even
        -- if it pre-exists (e.g. created as the old bootstrap superuser).
        ALTER ROLE yashigani_app NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    END IF;
END $$;
GRANT CONNECT ON DATABASE yashigani TO yashigani_app;
GRANT USAGE ON SCHEMA public TO yashigani_app;
GRANT SELECT, INSERT ON audit_events TO yashigani_app;
GRANT SELECT, INSERT ON inference_events TO yashigani_app;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO yashigani_app;
REVOKE DELETE ON audit_events FROM yashigani_app;
REVOKE DELETE ON inference_events FROM yashigani_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE ON TABLES TO yashigani_app;

-- pg_partman: register partitioned tables for auto-maintenance (optional)
DO $$ BEGIN
    PERFORM partman.create_parent(
        p_parent_table := 'public.audit_events',
        p_control := 'created_at',
        p_type := 'range',
        p_interval := 'monthly',
        p_premake := 3
    );
    PERFORM partman.create_parent(
        p_parent_table := 'public.inference_events',
        p_control := 'created_at',
        p_type := 'range',
        p_interval := 'monthly',
        p_premake := 3
    );
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'pg_partman not available — skipping partition auto-management';
END $$;

-- pg_cron: nightly partition maintenance (optional)
DO $cron$ BEGIN
    PERFORM cron.schedule('partman-maintenance', '0 2 * * *', 'SELECT partman.run_maintenance()');
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'pg_cron not available — skipping scheduled maintenance';
END $cron$;
"""

_DDL_DOWN = """
DROP TABLE IF EXISTS siem_config CASCADE;
DROP TABLE IF EXISTS endpoint_ratelimit_overrides CASCADE;
DROP TABLE IF EXISTS cache_config CASCADE;
DROP TABLE IF EXISTS jwt_config CASCADE;
DROP TABLE IF EXISTS anomaly_thresholds CASCADE;
DROP TABLE IF EXISTS inference_events CASCADE;
DROP TABLE IF EXISTS audit_events CASCADE;
DROP TABLE IF EXISTS agent_registry CASCADE;
DROP TABLE IF EXISTS rbac_members CASCADE;
DROP TABLE IF EXISTS rbac_groups CASCADE;
DROP TABLE IF EXISTS tenant_context CASCADE;
DROP TABLE IF EXISTS tenants CASCADE;
"""


def upgrade() -> None:
    op.execute(_DDL_UP)


def downgrade() -> None:
    op.execute(_DDL_DOWN)
