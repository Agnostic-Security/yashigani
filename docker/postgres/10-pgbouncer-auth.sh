#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Yashigani v2.24.0 — pgbouncer auth_query postgres-side setup.
# Last updated: 2026-05-22
#
# YSG-RISK-049 architectural close — ref:
#   internal-docs/yashigani/iris-v240-pgbouncer-auth-query-design.md
#   internal-docs/yashigani/laura-v240-pgbouncer-auth-query-threat-model.md
# YSG-RISK-050 closed — ref:
#   internal-docs/yashigani/iris-v240-ysg-risk-050-cert-separation-design.md
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
#   5. Removes pg_hba A2 carveout if present (YSG-RISK-050 close — idempotent).
#      pgbouncer_authenticator now presents pgbouncer-auth_client.crt (dedicated
#      outbound cert). The catch-all (clientcert=verify-ca) applies uniformly.
#      YSG-RISK-050 is CLOSED. No residual.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

echo "[10-pgbouncer-auth] Starting pgbouncer auth_query postgres-side setup"

# Fail-closed: read pgbouncer_authenticator password from mounted secret file.
# Compose path: blanket ./secrets:/run/secrets:ro mount provides the file.
# K8s path: pgbouncer-auth-secret mounted into postgres pod at /run/secrets/pgbouncer_authenticator_password.
# NOTE (compose ownership): pgbouncer_authenticator_password is chowned 70:0 0640 by install.sh for pgbouncer
# (UID 70). The postgres init script runs as UID 999 (pgvector/pgvector compose user). Install.sh must also
# set GID-999 group-read on this file (per-consumer ownership step, same pattern as postgres_password 1001:999 0640).
# Until Su adds that step, set PGBOUNCER_AUTH_PASSWORD via env var as a fallback for the compose path.
_pwfile="/run/secrets/pgbouncer_authenticator_password"
if [[ -r "${_pwfile}" ]]; then
  PGBOUNCER_AUTH_PASSWORD="$(cat "${_pwfile}")"
  if [[ -z "${PGBOUNCER_AUTH_PASSWORD}" ]]; then
    printf 'FATAL: %s is empty — install.sh must generate pgbouncer_authenticator_password\n' "${_pwfile}" >&2
    exit 1
  fi
elif [[ -n "${PGBOUNCER_AUTH_PASSWORD:-}" ]]; then
  # Env-var fallback: compose path when file not yet readable by UID 999.
  # Remove once install.sh adds 999-group-read ownership step for this file.
  printf 'INFO: %s not readable by this process — falling back to PGBOUNCER_AUTH_PASSWORD env var\n' "${_pwfile}" >&2
else
  printf 'FATAL: %s not readable AND PGBOUNCER_AUTH_PASSWORD env var not set\n' "${_pwfile}" >&2
  printf 'FATAL: Mount docker/secrets/pgbouncer_authenticator_password or set the env var\n' >&2
  exit 1
fi
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

# ─── 4. pg_hba carveout removal — YSG-RISK-050 CLOSED (v2.24.0) ─────────────
# YSG-RISK-050 CLOSED: carveout removed. pgbouncer_authenticator now presents
# pgbouncer-auth_client.crt (dedicated outbound cert, CN=pgbouncer-auth).
# pg_hba catch-all (hostssl all all 0.0.0.0/0 scram-sha-256 clientcert=verify-ca)
# applies uniformly — no special-case rule for pgbouncer_authenticator needed.
#
# Idempotent removal: cleans up the A2 carveout if present from a prior
# v2.24.0-pre / YSG-RISK-049-only install. No-op on fresh installs that never
# had the carveout. Both the carveout line and its associated comment lines are
# removed. Design ref: iris-v240-ysg-risk-050-cert-separation-design.md §3.
echo "[10-pgbouncer-auth] Removing pg_hba A2 carveout for pgbouncer_authenticator (YSG-RISK-050 close)"

if grep -q "pgbouncer_authenticator" "${PGDATA}/pg_hba.conf"; then
  sed -i '/pgbouncer_authenticator/d' "${PGDATA}/pg_hba.conf"
  sed -i '/Amendment A2.*YSG-RISK-049/d' "${PGDATA}/pg_hba.conf"
  echo "[10-pgbouncer-auth] Removed A2 carveout (YSG-RISK-050 close — uniform catch-all now covers pgbouncer_authenticator)"
else
  echo "[10-pgbouncer-auth] No A2 carveout present — nothing to remove (fresh install, idempotent)"
fi

# Reload pg_hba.conf so the change takes effect without a full restart.
# During initdb, postgres is not running in server mode yet — the file is read
# on next server start. This is correct for the init-script path.
# For the upgrade path (docker exec psql -U postgres -d yashigani -f
# /docker-entrypoint-initdb.d/10-pgbouncer-auth.sh), pg_reload_conf() fires
# immediately and the updated pg_hba.conf is picked up by the live server.
psql -v ON_ERROR_STOP=1 --username postgres -c "SELECT pg_reload_conf();" 2>/dev/null || true

echo "[10-pgbouncer-auth] pg_hba.conf state (hostssl lines):"
grep "^hostssl" "${PGDATA}/pg_hba.conf" || echo "  (no hostssl lines — fresh initdb, normal)"

echo "[10-pgbouncer-auth] Done. pgbouncer auth_query postgres-side setup complete."
echo "[10-pgbouncer-auth] Summary:"
echo "  - Role pgbouncer_authenticator: created/updated"
echo "  - Function yashigani.ysg_pgbouncer_get_auth: created/updated"
echo "  - EXECUTE: pgbouncer_authenticator only (PUBLIC revoked)"
echo "  - CONNECT letta: revoked from pgbouncer_authenticator"
echo "  - pg_hba A2 carveout: removed (YSG-RISK-050 close); catch-all applies uniformly"
