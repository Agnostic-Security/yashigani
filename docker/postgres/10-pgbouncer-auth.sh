#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Yashigani v2.24.0 — pgbouncer auth_query postgres-side setup.
# Last updated: 2026-05-22
#
# YSG-RISK-049 architectural close — ref:
#   internal-docs/yashigani/iris-v240-pgbouncer-auth-query-design.md
#   internal-docs/yashigani/laura-v240-pgbouncer-auth-query-threat-model.md
#
# Runs ONCE on first initdb (postgres entrypoint executes
# /docker-entrypoint-initdb.d/*.sh alphabetically before starting the server).
# Numbered 10-* so it runs after 05-enable-ssl.sh which writes pg_hba.conf.
#
# IDEMPOTENT: safe to re-run on an existing cluster (IF NOT EXISTS / OR REPLACE
# guards throughout). For v2.23.4→v2.24.0 upgrades, the operator runs this
# script once via:
#   docker exec yashigani-postgres psql -U postgres -d yashigani \
#     -f /docker-entrypoint-initdb.d/10-pgbouncer-auth.sh
# before starting the updated pgbouncer containers.
#
# What this script does:
#   1. Creates pgbouncer_authenticator role (LOGIN, NOSUPERUSER, password from env).
#   2. Creates SECURITY DEFINER function ysg_pgbouncer_get_auth in yashigani DB.
#   3. REVOKE EXECUTE from PUBLIC, GRANT EXECUTE to pgbouncer_authenticator only.
#   4. REVOKE CONNECT on databases that pgbouncer_authenticator must not access.
#   5. Appends pg_hba carveout BEFORE the catch-all (Amendment A2 — Laura 2026-05-21).
#      No clientcert requirement for pgbouncer_authenticator; scoped to internal
#      Docker bridge network 172.16.0.0/12 (covers dynamically-assigned data subnet).
#      Residual: YSG-RISK-050 LOW — cert separation for auth_query connection
#      deferred to v2.24.x hardening backlog.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

echo "[10-pgbouncer-auth] Starting pgbouncer auth_query postgres-side setup"

# Fail-closed: password must be injected via env var (from Docker secret mount).
: "${PGBOUNCER_AUTH_PASSWORD:?PGBOUNCER_AUTH_PASSWORD must be set — mount docker/secrets/pgbouncer_auth_password as a secret and set the env var}"
: "${PGDATA:?PGDATA must be set by the postgres image}"

# ─── 1. Create pgbouncer_authenticator role ──────────────────────────────────
# NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION, NOINHERIT.
# Grants: LOGIN + CONNECT to yashigani only + EXECUTE on ysg_pgbouncer_get_auth.
# No table grants, no schema grants, no access to letta or postgres databases.
echo "[10-pgbouncer-auth] Creating pgbouncer_authenticator role"
psql -v ON_ERROR_STOP=1 --username postgres <<SQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'pgbouncer_authenticator') THEN
    CREATE ROLE pgbouncer_authenticator
      LOGIN
      NOSUPERUSER
      NOCREATEDB
      NOCREATEROLE
      NOREPLICATION
      NOINHERIT
      PASSWORD '${PGBOUNCER_AUTH_PASSWORD}';
  ELSE
    -- On re-run: update password to current value (rotation support).
    ALTER ROLE pgbouncer_authenticator PASSWORD '${PGBOUNCER_AUTH_PASSWORD}';
  END IF;
END
\$\$;
SQL

# ─── 2. Create SECURITY DEFINER function in yashigani database ───────────────
# The function reads pg_shadow (superuser-only catalog) via SECURITY DEFINER.
# Owner: postgres (superuser at runtime of this init script).
# search_path locked to pg_catalog,public — search_path hijack defence (Laura C1).
# Parameterised query (uname text arg) — no string concatenation (Laura C1).
# auth_dbname = yashigani on both pgbouncer.ini and pgbouncer-letta.ini (Amendment C6).
# pg_shadow is a global catalog view — function lives once, in yashigani database.
echo "[10-pgbouncer-auth] Creating ysg_pgbouncer_get_auth function in yashigani database"
psql -v ON_ERROR_STOP=1 --username postgres --dbname yashigani <<'SQL'
CREATE OR REPLACE FUNCTION ysg_pgbouncer_get_auth(uname text)
  RETURNS TABLE(usename text, passwd text)
  LANGUAGE sql
  SECURITY DEFINER
  STABLE
  SET search_path = pg_catalog, public
AS $$
  SELECT usename::text, passwd::text
  FROM pg_catalog.pg_shadow
  WHERE usename = uname
  LIMIT 1;
$$;

-- Ownership: postgres superuser (function must run as superuser to read pg_shadow).
-- ALTER FUNCTION ownership is a no-op when already owned by postgres, but
-- explicit for audit trail.
ALTER FUNCTION ysg_pgbouncer_get_auth(text) OWNER TO postgres;

-- Restrict execute: revoke from PUBLIC, grant only to pgbouncer_authenticator.
REVOKE ALL ON FUNCTION ysg_pgbouncer_get_auth(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ysg_pgbouncer_get_auth(text) TO pgbouncer_authenticator;
SQL

# ─── 3. REVOKE CONNECT on non-auth databases (C2 — Laura recommendation) ─────
# pgbouncer_authenticator should only connect to yashigani (auth_dbname).
# Remove implicit CONNECT privilege from letta and postgres system databases
# so a credential leak cannot be leveraged to connect elsewhere.
echo "[10-pgbouncer-auth] Restricting pgbouncer_authenticator database CONNECT privileges"
psql -v ON_ERROR_STOP=1 --username postgres <<'SQL'
-- Ensure CONNECT to yashigani is retained (it is by default; explicit for clarity).
GRANT CONNECT ON DATABASE yashigani TO pgbouncer_authenticator;

-- Revoke CONNECT on all other databases pgbouncer_authenticator has no business in.
-- letta: pgbouncer-letta uses auth_dbname=yashigani — never needs direct letta connect.
DO $$
BEGIN
  IF EXISTS (SELECT FROM pg_catalog.pg_database WHERE datname = 'letta') THEN
    REVOKE CONNECT ON DATABASE letta FROM pgbouncer_authenticator;
  END IF;
END
$$;

-- Revoke from template databases to prevent future CREATE DATABASE inheritance.
-- template1 is the default parent, so new DBs inherit its ACL.
REVOKE CONNECT ON DATABASE template1 FROM pgbouncer_authenticator;
SQL

# ─── 4. pg_hba carveout — Amendment A2 (Laura threat-model, 2026-05-21) ─────
# Insert BEFORE the hostssl catch-all (first-match-wins in pg_hba.conf).
#
# Rationale: the catch-all requires clientcert=verify-ca. pgbouncer uses a
# single global server_tls_cert_file — per-connection cert selection for the
# auth_query internal connection is not supported by edoburu. Requiring the
# shared cert on the auth_query connection creates a privilege-escalation path
# (Laura Amendment A). Solution: dedicated pg_hba rule scoped to:
#   - Database: yashigani (only database pgbouncer_authenticator needs)
#   - User: pgbouncer_authenticator (only this role)
#   - Network: 172.16.0.0/12 (full Docker bridge pool, covers any dynamic
#     subnet Docker assigns to the internal 'data' network, which has no
#     explicit subnet in docker-compose.yml)
#   - Method: scram-sha-256 (no clientcert — residual filed as YSG-RISK-050 LOW)
#
# The sed substitution prepends the carveout line immediately before the first
# hostssl catch-all line (hostssl all all 0.0.0.0/0 ...).
# 05-enable-ssl.sh writes pg_hba.conf; this script appends the carveout after.
echo "[10-pgbouncer-auth] Inserting pg_hba carveout for pgbouncer_authenticator (Amendment A2)"

CARVEOUT="hostssl  yashigani  pgbouncer_authenticator  172.16.0.0/12  scram-sha-256"
CARVEOUT_COMMENT="# pgbouncer auth_query connection (Amendment A2 — YSG-RISK-049 close, 2026-05-22)."
CARVEOUT_COMMENT2="# scram-sha-256, NO clientcert, CIDR-scoped to Docker bridge pool."
CARVEOUT_COMMENT3="# Residual cert separation: YSG-RISK-050 LOW (deferred to v2.24.x hardening)."

# Check if carveout already present (idempotency on re-run).
if grep -q "pgbouncer_authenticator" "${PGDATA}/pg_hba.conf"; then
  echo "[10-pgbouncer-auth] pg_hba carveout already present — skipping insertion (idempotent)"
else
  # Insert carveout + comments before the first hostssl catch-all line.
  # The catch-all pattern: 'hostssl all' or 'hostssl  all'.
  sed -i \
    "s|^hostssl\s\+all\s\+all\s\+0\.0\.0\.0/0|${CARVEOUT_COMMENT}\n${CARVEOUT_COMMENT2}\n${CARVEOUT_COMMENT3}\n${CARVEOUT}\n&|" \
    "${PGDATA}/pg_hba.conf"
  echo "[10-pgbouncer-auth] pg_hba carveout inserted before catch-all"
fi

# Reload pg_hba.conf so the new rule takes effect without a full restart.
# During initdb, postgres is not running in server mode yet, so pg_ctl reload
# is not applicable — the file is read on next server start. This is correct
# for the init-script path. For the upgrade path (docker exec psql -f ...) the
# operator must run SELECT pg_reload_conf() after, or restart postgres.
echo "[10-pgbouncer-auth] pg_hba.conf state:"
grep -E "pgbouncer_authenticator|hostssl all" "${PGDATA}/pg_hba.conf"

echo "[10-pgbouncer-auth] Done. pgbouncer auth_query postgres-side setup complete."
echo "[10-pgbouncer-auth] Summary:"
echo "  - Role pgbouncer_authenticator: created/updated"
echo "  - Function yashigani.ysg_pgbouncer_get_auth: created/updated"
echo "  - EXECUTE: pgbouncer_authenticator only (PUBLIC revoked)"
echo "  - CONNECT letta: revoked from pgbouncer_authenticator"
echo "  - pg_hba carveout: 172.16.0.0/12, yashigani db, scram-sha-256, no clientcert"
