#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Yashigani v2.24.0 — pgbouncer auth_query postgres-side setup (Helm / K8s).
# Last updated: 2026-05-22
#
# YSG-RISK-049 architectural close — ref:
#   internal-docs/yashigani/iris-v240-pgbouncer-auth-query-design.md
#   internal-docs/yashigani/laura-v240-pgbouncer-auth-query-threat-model.md
# YSG-RISK-050 closed — ref:
#   internal-docs/yashigani/iris-v240-ysg-risk-050-cert-separation-design.md
#
# Mounted into postgres pod via yashigani-postgres-init ConfigMap key
# "10-pgbouncer-auth.sh". Runs ONCE on first initdb, after 05-enable-ssl.sh.
#
# pg_hba CIDR NOTE (REMOVED v2.24.0): The A2 carveout and its CIDR
# (formerly 10.0.0.0/8 for K8s / 172.16.0.0/12 for Compose) are removed
# as part of YSG-RISK-050 close. pgbouncer_authenticator now presents
# pgbouncer-auth_client.crt; the catch-all applies uniformly.
# values.yaml pgbouncer.authNetworkCidr field removed — no longer needed.
#
# See docker/postgres/10-pgbouncer-auth.sh for full canonical documentation.
# This file MUST remain functionally identical to the docker version.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

echo "[10-pgbouncer-auth] Starting pgbouncer auth_query postgres-side setup (K8s)"

# Fail-closed: read pgbouncer_authenticator password from mounted secret file.
# K8s path: pgbouncer-auth-secret mounted into postgres pod at
#   /run/secrets/pgbouncer_authenticator_password (subPath, defaultMode 0440).
#   fsGroup: 70 in pod securityContext ensures postgres (UID 70) can read it.
_pwfile="/run/secrets/pgbouncer_authenticator_password"
if [[ ! -r "${_pwfile}" ]]; then
  printf 'FATAL: %s not readable — yashigani-pgbouncer-auth-secret must be mounted\n' "${_pwfile}" >&2
  exit 1
fi
PGBOUNCER_AUTH_PASSWORD="$(cat "${_pwfile}")"
if [[ -z "${PGBOUNCER_AUTH_PASSWORD}" ]]; then
  printf 'FATAL: %s is empty — secrets.yaml must generate pgbouncer_authenticator_password\n' "${_pwfile}" >&2
  exit 1
fi
: "${PGDATA:?PGDATA must be set by the postgres image}"

# ─── 1. Create pgbouncer_authenticator role ──────────────────────────────────
# VEB-SQL hardening: psql -v auth_pw + :'auth_pw' quote-literal substitution.
# - <<'SQL' (quoted heredoc) — shell never interpolates; only psql sees $...
# - -v auth_pw="$PGBOUNCER_AUTH_PASSWORD" — passes value via psql variable mechanism
# - :'auth_pw' in CREATE/ALTER statements — psql quote-literal substitution; correctly
#   escapes any ' in the value (doubles it: ' → '') before sending to the server
# - \gset + \if meta-commands for idempotency — avoids DO $$ block where psql
#   variable substitution does NOT apply (psql tokeniser treats $$ as opaque)
# Defense-in-depth: install.sh:5184 charset 'A-Za-z0-9!*,._~-' excludes ' today,
# but this fix makes the SQL safe regardless of future charset changes.
echo "[10-pgbouncer-auth] Creating pgbouncer_authenticator role"
psql -v ON_ERROR_STOP=1 -v auth_pw="$PGBOUNCER_AUTH_PASSWORD" \
     --username "${POSTGRES_USER:-yashigani_app}" --dbname postgres <<'SQL'
\pset tuples_only on
\pset format unaligned
SELECT NOT EXISTS (
  SELECT FROM pg_catalog.pg_roles WHERE rolname = 'pgbouncer_authenticator'
) AS needs_create \gset
\if :needs_create
  CREATE ROLE pgbouncer_authenticator
    LOGIN
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOREPLICATION
    NOINHERIT
    PASSWORD :'auth_pw';
\else
  -- On re-run: update password to current value (rotation support).
  ALTER ROLE pgbouncer_authenticator PASSWORD :'auth_pw';
\endif
SQL

# ─── 2. Create SECURITY DEFINER function in yashigani database ───────────────
echo "[10-pgbouncer-auth] Creating ysg_pgbouncer_get_auth function in yashigani database"
psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER:-yashigani_app}" \
     -v owner="${POSTGRES_USER:-yashigani_app}" \
     --dbname yashigani <<'SQL'
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

-- Ownership: postgres superuser / POSTGRES_USER (function must run as superuser to read pg_shadow).
-- ALTER FUNCTION ownership is a no-op when already owned by the postgres superuser (POSTGRES_USER),
-- but explicit for audit trail.
ALTER FUNCTION ysg_pgbouncer_get_auth(text) OWNER TO :"owner";

REVOKE ALL ON FUNCTION ysg_pgbouncer_get_auth(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ysg_pgbouncer_get_auth(text) TO pgbouncer_authenticator;
SQL

# ─── 3. REVOKE CONNECT on non-auth databases ─────────────────────────────────
echo "[10-pgbouncer-auth] Restricting pgbouncer_authenticator database CONNECT privileges"
psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER:-yashigani_app}" --dbname postgres <<'SQL'
GRANT CONNECT ON DATABASE yashigani TO pgbouncer_authenticator;

DO $$
BEGIN
  IF EXISTS (SELECT FROM pg_catalog.pg_database WHERE datname = 'letta') THEN
    REVOKE CONNECT ON DATABASE letta FROM pgbouncer_authenticator;
  END IF;
END
$$;

REVOKE CONNECT ON DATABASE template1 FROM pgbouncer_authenticator;
SQL

# ─── 4. pg_hba carveout removal — YSG-RISK-050 CLOSED (v2.24.0) ─────────────
# YSG-RISK-050 CLOSED: carveout removed. pgbouncer_authenticator now presents
# pgbouncer-auth_client.crt (dedicated outbound cert, CN=pgbouncer-auth).
# pg_hba catch-all (hostssl all all 0.0.0.0/0 scram-sha-256 clientcert=verify-ca)
# applies uniformly — no special-case rule for pgbouncer_authenticator needed.
# pgbouncer.authNetworkCidr values.yaml field removed (no longer used).
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
# For the upgrade path, pg_reload_conf() fires immediately and the updated
# pg_hba.conf is picked up by the live server.
psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER:-yashigani_app}" --dbname postgres -c "SELECT pg_reload_conf();" 2>/dev/null || true

echo "[10-pgbouncer-auth] pg_hba.conf state (hostssl lines):"
grep "^hostssl" "${PGDATA}/pg_hba.conf" || echo "  (no hostssl lines — fresh initdb, normal)"

echo "[10-pgbouncer-auth] Done. pgbouncer auth_query postgres-side setup complete (K8s)."
echo "[10-pgbouncer-auth] Summary:"
echo "  - Role pgbouncer_authenticator: created/updated"
echo "  - Function yashigani.ysg_pgbouncer_get_auth: created/updated"
echo "  - EXECUTE: pgbouncer_authenticator only (PUBLIC revoked)"
echo "  - CONNECT letta: revoked from pgbouncer_authenticator"
echo "  - pg_hba A2 carveout: removed (YSG-RISK-050 close); catch-all applies uniformly"
