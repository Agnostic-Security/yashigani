#!/bin/bash
# Create databases for agent bundles that need Postgres persistence.
# This script runs as part of Postgres docker-entrypoint-initdb.d on first start only.
#
# v4.1 fix (F-B): yashigani_app role must exist before CREATE DATABASE ... OWNER yashigani_app.
# Alembic migration 0001_initial_schema.py is the canonical source-of-truth for this role, but
# initdb.d scripts run BEFORE gateway/backoffice start (and before any Alembic migration).
# Without this pre-creation, CREATE DATABASE letta OWNER yashigani_app fails with PG error
# 42704 (undefined_object: role "yashigani_app" does not exist).
#
# The role is created here with LOGIN, NOSUPERUSER and no password.  Migration 0001 will
# execute a conditional CREATE ROLE ... IF NOT EXISTS (idempotent) and install.sh resets
# the password via ALTER ROLE after migrations complete.  The GRANT ALL ON SCHEMA public
# below is also idempotent; migration 0001 issues the same grants on the yashigani DB and
# letta needs the same access for its own Alembic run (startup.sh: alembic upgrade head).
set -e

# ---------------------------------------------------------------------------
# Step 0 — create yashigani_app runtime role idempotently
# ---------------------------------------------------------------------------
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-'EOSQL'
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'yashigani_app') THEN
        CREATE ROLE yashigani_app
          LOGIN
          NOSUPERUSER
          NOCREATEDB
          NOCREATEROLE
          NOREPLICATION;
      END IF;
    END
    $$;
EOSQL

# ---------------------------------------------------------------------------
# Step 1 — create letta database owned by yashigani_app (idempotent)
# ---------------------------------------------------------------------------
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    SELECT 'CREATE DATABASE letta OWNER yashigani_app'
    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'letta')\gexec
EOSQL

# ---------------------------------------------------------------------------
# Step 2 — enable pgvector extension in letta database
# ---------------------------------------------------------------------------
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "letta" <<-EOSQL
    CREATE EXTENSION IF NOT EXISTS vector;
EOSQL

# ---------------------------------------------------------------------------
# Step 3 — grant schema access so letta's Alembic run (startup.sh) succeeds
# Without GRANT ALL ON SCHEMA public, Alembic fails with 42501 (permission denied
# for schema public) when attempting CREATE TABLE on a fresh letta database.
# Idempotent: re-granting already-held privileges is a no-op in PG.
# ---------------------------------------------------------------------------
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "letta" <<-EOSQL
    GRANT ALL ON SCHEMA public TO yashigani_app;
EOSQL
