#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Yashigani v2.24.0 — pgbouncer auth_query postgres-side setup (Helm / K8s).
# Last updated: 2026-05-22
#
# YSG-RISK-049 architectural close — ref:
#   internal-docs/yashigani/iris-v240-pgbouncer-auth-query-design.md
#   internal-docs/yashigani/laura-v240-pgbouncer-auth-query-threat-model.md
#
# Mounted into postgres pod via yashigani-postgres-init ConfigMap key
# "10-pgbouncer-auth.sh". Runs ONCE on first initdb, after 05-enable-ssl.sh.
#
# K8s CIDR NOTE: The pg_hba carveout uses 10.0.0.0/8 (standard K8s pod pool).
# If your cluster uses a different pod CIDR, override via values.yaml
# pgbouncer.authNetworkCidr — Captain scope to wire substitution here.
# (Docker Compose path uses 172.16.0.0/12 — the docker bridge pool default.)
#
# See docker/postgres/10-pgbouncer-auth.sh for full canonical documentation.
# This file MUST remain byte-identical to the docker version EXCEPT for the
# pg_hba CIDR (K8s pod network vs Docker bridge network). Drift register entry:
# drift-class "pgbouncer auth_query init script" — docker vs helm CIDR only.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

echo "[10-pgbouncer-auth] Starting pgbouncer auth_query postgres-side setup (K8s)"

# Fail-closed: password must be injected via env var (from K8s Secret mount).
: "${PGBOUNCER_AUTH_PASSWORD:?PGBOUNCER_AUTH_PASSWORD must be set — mount yashigani-pgbouncer-auth-secret and set the env var}"
: "${PGDATA:?PGDATA must be set by the postgres image}"

# ─── 1. Create pgbouncer_authenticator role ──────────────────────────────────
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

ALTER FUNCTION ysg_pgbouncer_get_auth(text) OWNER TO postgres;

REVOKE ALL ON FUNCTION ysg_pgbouncer_get_auth(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ysg_pgbouncer_get_auth(text) TO pgbouncer_authenticator;
SQL

# ─── 3. REVOKE CONNECT on non-auth databases ─────────────────────────────────
echo "[10-pgbouncer-auth] Restricting pgbouncer_authenticator database CONNECT privileges"
psql -v ON_ERROR_STOP=1 --username postgres <<'SQL'
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

# ─── 4. pg_hba carveout — Amendment A2 (K8s pod CIDR = 10.0.0.0/8) ──────────
# K8s: pod CIDR 10.0.0.0/8 covers standard K8s cluster pod networks.
# Override via values.yaml pgbouncer.authNetworkCidr if cluster uses different range.
echo "[10-pgbouncer-auth] Inserting pg_hba carveout for pgbouncer_authenticator (Amendment A2)"

CARVEOUT="hostssl  yashigani  pgbouncer_authenticator  10.0.0.0/8  scram-sha-256"
CARVEOUT_COMMENT="# pgbouncer auth_query connection (Amendment A2 — YSG-RISK-049 close, 2026-05-22)."
CARVEOUT_COMMENT2="# scram-sha-256, NO clientcert, CIDR-scoped to K8s pod network (10.0.0.0/8)."
CARVEOUT_COMMENT3="# Residual cert separation: YSG-RISK-050 LOW (deferred to v2.24.x hardening)."

if grep -q "pgbouncer_authenticator" "${PGDATA}/pg_hba.conf"; then
  echo "[10-pgbouncer-auth] pg_hba carveout already present — skipping insertion (idempotent)"
else
  sed -i \
    "s|^hostssl\s\+all\s\+all\s\+0\.0\.0\.0/0|${CARVEOUT_COMMENT}\n${CARVEOUT_COMMENT2}\n${CARVEOUT_COMMENT3}\n${CARVEOUT}\n&|" \
    "${PGDATA}/pg_hba.conf"
  echo "[10-pgbouncer-auth] pg_hba carveout inserted before catch-all"
fi

echo "[10-pgbouncer-auth] pg_hba.conf state:"
grep -E "pgbouncer_authenticator|hostssl all" "${PGDATA}/pg_hba.conf"

echo "[10-pgbouncer-auth] Done. pgbouncer auth_query postgres-side setup complete (K8s)."
echo "[10-pgbouncer-auth] Summary:"
echo "  - Role pgbouncer_authenticator: created/updated"
echo "  - Function yashigani.ysg_pgbouncer_get_auth: created/updated"
echo "  - EXECUTE: pgbouncer_authenticator only (PUBLIC revoked)"
echo "  - CONNECT letta: revoked from pgbouncer_authenticator"
echo "  - pg_hba carveout: 10.0.0.0/8, yashigani db, scram-sha-256, no clientcert"
