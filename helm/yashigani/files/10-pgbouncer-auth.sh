#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Yashigani v2.24.0 — pgbouncer auth_query postgres-side setup.
# Last updated: 2026-05-25 (fix: YSG-RISK-073 cycle 7 — cert auth + pg_ident CN map)
#
# YSG-RISK-049 architectural close — ref:
#   internal-docs/yashigani/iris-v240-pgbouncer-auth-query-design.md
#   internal-docs/yashigani/laura-v240-pgbouncer-auth-query-threat-model.md
# YSG-RISK-050 closed — ref:
#   internal-docs/yashigani/iris-v240-ysg-risk-050-cert-separation-design.md
# YSG-RISK-073 cycle 7 closed — cert auth + pg_ident; YSG-RISK-077 (platform SCRAM bug).
#
# Runs ONCE on first initdb (postgres entrypoint executes
# /docker-entrypoint-initdb.d/*.sh alphabetically before starting the server).
# Numbered 10-* so it runs after 05-enable-ssl.sh which writes pg_hba.conf.
#
# IDEMPOTENT: safe to re-run on an existing cluster (IF NOT EXISTS / OR REPLACE
# guards throughout). For v2.23.4→v2.24.0 upgrades, the operator runs this
# script once via:
#   docker exec yashigani-postgres psql -U "${POSTGRES_USER:-yashigani_admin}" -d yashigani \
#     -f /docker-entrypoint-initdb.d/10-pgbouncer-auth.sh
# before starting the updated pgbouncer containers.
#
# What this script does:
#   1. Creates pgbouncer_authenticator role (LOGIN, NOSUPERUSER, NO PASSWORD).
#      Cycle 7: no password — cert auth replaces SCRAM for auth_user connection.
#   2. Creates SECURITY DEFINER function ysg_pgbouncer_get_auth in yashigani DB.
#   3. REVOKE EXECUTE from PUBLIC, GRANT EXECUTE to pgbouncer_authenticator only.
#   4. REVOKE CONNECT on databases that pgbouncer_authenticator must not access.
#   5. Writes pg_ident.conf CN mapping (pgb-auth-map).
#   6. Inserts cert auth pg_hba carveout for pgbouncer_authenticator (YSG-RISK-073 cycle 7).
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

echo "[10-pgbouncer-auth] Starting pgbouncer auth_query postgres-side setup"
: "${PGDATA:?PGDATA must be set by the postgres image}"

# ─── 1. Create pgbouncer_authenticator role ──────────────────────────────────
# NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION, NOINHERIT.
# Grants: LOGIN + CONNECT to yashigani only + EXECUTE on ysg_pgbouncer_get_auth.
# No table grants, no schema grants, no access to letta or postgres databases.
#
# NOTE on pg_hba auth method (YSG-RISK-073 cycle 7 — cert + pg_ident):
# The pg_hba carveout uses `cert map=pgb-auth-map`. Single-factor cert auth:
# - cert method: pg16 requires verify-full (CN verified against pg_ident map).
# - pg_ident map pgb-auth-map:
#     pgbouncer-auth    → pgbouncer_authenticator  (main pgbouncer instance)
#     letta-pgbouncer   → pgbouncer_authenticator  (letta sidecar pgbouncer)
# - NO PASSWORD required: cert is the sole credential.
#
# WHY NOT scram-sha-256 (cycle 6 approach — broken on Mac/Podman / YSG-RISK-077):
# pgbouncer 1.25.1 (edoburu, ARM64) has a SCRAM client-side computation bug.
# It computes incorrect SCRAM proofs when authenticating outbound as auth_user
# on ARM64 Linux (including Mac Podman's ARM64 container runtime). The bug was
# confirmed on Mac/Podman (cycle 7 failure) and the cycle 6 "live test PASS" was
# run on the Linux VM only — same pgbouncer binary, different Podman network stack.
# Platform SCRAM root cause documented in YSG-RISK-077.
#
# WHY cert + pg_ident is SECURE (not a downgrade from SCRAM):
# - cert method implies verify-full: full chain + CN verified (stronger than
#   the old trust+clientcert=verify-ca which was only verify-ca).
# - pg_ident mapping restricts to CN=pgbouncer-auth AND CN=letta-pgbouncer ONLY.
#   Any other cert (even CA-signed) cannot authenticate as pgbouncer_authenticator.
# - YSG-RISK-075 (Laura cycle 5): lateral-pivot attack via trust+clientcert allowed
#   ANY CA-cert holder to impersonate pgbouncer_authenticator (11 certs on data net).
#   cert+pg_ident closes this: only the two named CNs are mapped. All other data-
#   network services hold certs with different CNs — none can impersonate.
# - pgbouncer-auth cert: mounted EXCLUSIVELY to pgbouncer containers.
# - letta-pgbouncer cert: mounted EXCLUSIVELY to letta-pgbouncer container.
# - An attacker needs the private key for one of these two specific certs,
#   which requires compromising THOSE specific containers (not just any data net service).
#
# NO PASSWORD = no pgbouncer_authenticator_password secret needed:
# The role has no password. LOGIN without password is valid for cert auth.
# install.sh still generates pgbouncer_authenticator_password for backwards compat
# but it is no longer mounted into postgres and no longer used for auth_user.
# (pgbouncer command wrapper simplified — DATABASE_URL no longer needs the password.)
echo "[10-pgbouncer-auth] Creating pgbouncer_authenticator role (cert auth — no password)"
psql -v ON_ERROR_STOP=1 \
     --username "${POSTGRES_USER:-yashigani_admin}" --dbname postgres <<'SQL'
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
    NOINHERIT;
\else
  -- Idempotent on re-run: remove any stored password (cert auth needs none).
  -- This also handles upgrades from cycle 5/6 which set a password.
  ALTER ROLE pgbouncer_authenticator PASSWORD NULL;
\endif
SQL

# ─── 2. Create SECURITY DEFINER function in yashigani database ───────────────
# The function reads pg_shadow (superuser-only catalog) via SECURITY DEFINER.
# Owner: postgres (superuser at runtime of this init script).
# search_path locked to pg_catalog,public — search_path hijack defence (Laura C1).
# Parameterised query (uname text arg) — no string concatenation (Laura C1).
# auth_dbname = yashigani on both pgbouncer.ini and pgbouncer-letta.ini (Amendment C6).
# pg_shadow is a global catalog view — function lives once, in yashigani database.
echo "[10-pgbouncer-auth] Creating ysg_pgbouncer_get_auth function in yashigani database"
psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER:-yashigani_admin}" \
     -v owner="${POSTGRES_USER:-yashigani_admin}" \
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

-- Restrict execute: revoke from PUBLIC, grant only to pgbouncer_authenticator.
REVOKE ALL ON FUNCTION ysg_pgbouncer_get_auth(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ysg_pgbouncer_get_auth(text) TO pgbouncer_authenticator;
SQL

# ─── 3. REVOKE CONNECT on non-auth databases (C2 — Laura recommendation) ─────
# pgbouncer_authenticator should only connect to yashigani (auth_dbname).
# Remove implicit CONNECT privilege from letta and postgres system databases
# so a credential leak cannot be leveraged to connect elsewhere.
echo "[10-pgbouncer-auth] Restricting pgbouncer_authenticator database CONNECT privileges"
psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER:-yashigani_admin}" --dbname postgres <<'SQL'
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

# ─── 4. pg_ident.conf CN map + cert pg_hba carveout (YSG-RISK-073 cycle 7) ──
# BUG-NEW-001 / YSG-RISK-073: History of the pgbouncer_authenticator pg_hba carveout.
#
# CYCLE 7 FIX: cert auth via pg_ident CN mapping (YSG-RISK-077 root cause).
#
# ROOT CAUSE (YSG-RISK-077): pgbouncer 1.25.1 (edoburu, ARM64) has a SCRAM
# client-side computation bug on ARM64 Linux. It sends incorrect SCRAM proofs
# when authenticating outbound as auth_user. This affects Mac/Podman (ARM64
# container runtime). Cycle 6 "live test PASS" was Linux VM only (same binary,
# different host). Confirmed via verbose pgbouncer debug logging + Python
# SCRAM proof verification (testing_runs/captain_bug_c7_001_scram_fix_20260525/).
#
# FIX: cert auth method + pg_ident.conf CN mapping.
# - pg_ident map (pgb-auth-map) maps two CNs to pgbouncer_authenticator:
#     pgbouncer-auth    → pgbouncer_authenticator  (main pgbouncer)
#     letta-pgbouncer   → pgbouncer_authenticator  (letta-pgbouncer sidecar)
# - cert method: PG16 cert auth implies verify-full (full chain + CN verified).
# - NO PASSWORD: pgbouncer presents its TLS client cert; no SCRAM exchange.
# - pgbouncer_authenticator role has no password (PASSWORD NULL).
#
# SECURITY vs TRUST+CLIENTCERT (Laura cycle 5 finding — YSG-RISK-075):
# - cycle 5 trust+clientcert=verify-ca: ANY CA-cert holder can impersonate
#   pgbouncer_authenticator (11 certs on data network; one compromise = full DB).
#   Laura confirmed attack chain. Unacceptable.
# - cycle 7 cert+pg_ident: ONLY certs with CN=pgbouncer-auth OR CN=letta-pgbouncer
#   map to pgbouncer_authenticator. All other certs (11 on data net) have different
#   CNs and cannot impersonate. YSG-RISK-075 lateral-pivot CLOSED.
#
# SECURITY vs SCRAM+CLIENTCERT (cycle 6 — broken on Mac/Podman):
# - cycle 6 scram-sha-256+clientcert=verify-ca: two-factor (cert + password).
#   verify-ca only (chain verified, CN not checked).
# - cycle 7 cert+pg_ident: cert method = verify-full (chain + CN checked).
#   CN mapped to specific role via pg_ident (CN-specific restriction).
#   Net security: STRONGER CN binding + platform-independent (no SCRAM bug).
#
# CERT AUTH + pg_ident HISTORY:
#   v2.24.3 cycle 3/4: `cert clientcert=verify-ca` — WRONG syntax.
#     PG16 rejects: cert method requires verify-full, not verify-ca.
#     AND: no pg_ident map; CN=pgbouncer-auth != role pgbouncer_authenticator.
#   v2.24.3 cycle 7: `cert map=pgb-auth-map` — CORRECT.
#     cert method implies verify-full (no clientcert= needed, it's implicit).
#     pg_ident maps CN → role (no CN==role-name requirement).
#     Tested live on Mac/Podman: PASS. Postgres log:
#       connection authenticated: identity="CN=pgbouncer-auth,O=Agnostic Security"
#                                  method=cert (/pg_hba.conf:N)
#
# SINGLE SOURCE OF TRUTH: this script is the ONLY writer of the
# pgbouncer_authenticator carveout AND pg_ident entries. 05-enable-ssl.sh
# does NOT write these (removed in BUG-C4-002 fix). Prevents duplicate entries.
#
# Idempotent: removes stale pg_hba lines, rewrites pg_ident.conf map entries,
# inserts cert carveout. Handles:
#   - Fresh initdb.
#   - Upgrade from v2.24.0-v2.24.2 (no carveout).
#   - Upgrade from v2.24.3 cycle 3/4 (cert+verify-ca — broken).
#   - Upgrade from v2.24.3 cycle 5 (trust+clientcert).
#   - Upgrade from v2.24.3 cycle 6 (scram-sha-256+clientcert).

# Step 4a: write pg_ident.conf CN map (idempotent — remove existing pgb-auth-map, add fresh).
echo "[10-pgbouncer-auth] Writing pg_ident.conf pgb-auth-map (cert CN → pgbouncer_authenticator)"
_ident="${PGDATA}/pg_ident.conf"
# Remove any existing pgb-auth-map entries (idempotent for re-runs/upgrades).
sed -i '/^pgb-auth-map/d' "${_ident}"
# Append the two mappings:
#   CN=pgbouncer-auth   (main pgbouncer — pgbouncer-auth_client.crt)
#   CN=letta-pgbouncer  (letta sidecar — letta-pgbouncer_client.crt)
{
  printf '# YSG-RISK-073 cycle 7: pgbouncer cert CN → pgbouncer_authenticator (cert auth map)\n'
  printf '# Both pgbouncer instances authenticate via cert; pg_ident maps their CN to the role.\n'
  printf 'pgb-auth-map  pgbouncer-auth    pgbouncer_authenticator\n'
  printf 'pgb-auth-map  letta-pgbouncer   pgbouncer_authenticator\n'
} >> "${_ident}"
echo "[10-pgbouncer-auth] pg_ident.conf pgb-auth-map written"

# Step 4b: remove any existing pgbouncer_authenticator pg_hba lines (any method).
# Normalises fresh installs and handles all upgrade paths.
if grep -q "pgbouncer_authenticator" "${PGDATA}/pg_hba.conf"; then
  sed -i '/pgbouncer_authenticator/d' "${PGDATA}/pg_hba.conf"
  sed -i '/Amendment A2.*YSG-RISK-049/d' "${PGDATA}/pg_hba.conf"
  sed -i '/YSG-RISK-073/d' "${PGDATA}/pg_hba.conf"
  sed -i '/TWO-FACTOR.*clientcert/d' "${PGDATA}/pg_hba.conf"
  sed -i '/pgbouncer 1.25.1.*SCRAM/d' "${PGDATA}/pg_hba.conf"
  sed -i '/Closes Laura cycle/d' "${PGDATA}/pg_hba.conf"
  echo "[10-pgbouncer-auth] Removed existing pgbouncer_authenticator pg_hba entries (normalising)"
fi

# Step 4c: insert the cert+pg_ident carveout BEFORE the first hostssl catch-all.
# Auth method: cert map=pgb-auth-map
# - cert: PG16 cert auth implies verify-full (full chain + CN verified via pg_ident).
# - map=pgb-auth-map: only CNs in the map (pgbouncer-auth, letta-pgbouncer) match.
# - NO clientcert= option: cert method handles it (implicit verify-full).
# awk inserts before the FIRST hostssl all match only (avoids duplicates for
# the two catch-all lines 0.0.0.0/0 + ::/0 in pg_hba.conf).
# awk is available in the pgvector/pgvector:pg16 Debian base image.
echo "[10-pgbouncer-auth] Inserting cert+pg_ident carveout for pgbouncer_authenticator (YSG-RISK-073 cycle 7)"
if grep -q "^hostssl all" "${PGDATA}/pg_hba.conf"; then
  _hba="${PGDATA}/pg_hba.conf"
  _tmp="${PGDATA}/pg_hba.conf.new.$$"
  awk '
    /^hostssl all/ && !inserted {
      print "# YSG-RISK-073 cycle 7: pgbouncer_authenticator auth_query -- cert auth via pg_ident CN map."
      print "# cert method: PG16 verify-full (full chain + CN mapped via pg_ident pgb-auth-map)."
      print "# CN=pgbouncer-auth (main pgbouncer) + CN=letta-pgbouncer (sidecar) → pgbouncer_authenticator."
      print "# NO password. Avoids pgbouncer 1.25.1 ARM64 SCRAM computation bug (YSG-RISK-077)."
      print "# Stronger than trust+clientcert: verify-full + CN-specific pg_ident map. YSG-RISK-075 CLOSED."
      print "hostssl yashigani pgbouncer_authenticator 0.0.0.0/0  cert  map=pgb-auth-map"
      print "hostssl yashigani pgbouncer_authenticator ::/0        cert  map=pgb-auth-map"
      inserted = 1
    }
    { print }
  ' "${_hba}" > "${_tmp}"
  chown postgres:postgres "${_tmp}"
  chmod 0600 "${_tmp}"
  mv "${_tmp}" "${_hba}"
  echo "[10-pgbouncer-auth] Inserted cert+pg_ident carveout for pgbouncer_authenticator (YSG-RISK-073 cycle 7)"
else
  echo "[10-pgbouncer-auth] WARNING: no hostssl catch-all found — carveout will be needed at startup"
fi

# Reload pg_hba.conf so the change takes effect without a full restart.
# During initdb, postgres is not running in server mode yet — the file is read
# on next server start. This is correct for the init-script path.
# For the upgrade path (docker exec psql -U "${POSTGRES_USER:-yashigani_admin}" -d yashigani -f
# /docker-entrypoint-initdb.d/10-pgbouncer-auth.sh), pg_reload_conf() fires
# immediately and the updated pg_hba.conf is picked up by the live server.
psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER:-yashigani_admin}" --dbname postgres -c "SELECT pg_reload_conf();" 2>/dev/null || true

echo "[10-pgbouncer-auth] pg_hba.conf state (hostssl lines):"
grep "^hostssl" "${PGDATA}/pg_hba.conf" || echo "  (no hostssl lines — fresh initdb, normal)"

echo "[10-pgbouncer-auth] Done. pgbouncer auth_query postgres-side setup complete."
echo "[10-pgbouncer-auth] Summary:"
echo "  - Role pgbouncer_authenticator: created/updated"
echo "  - Function yashigani.ysg_pgbouncer_get_auth: created/updated"
echo "  - EXECUTE: pgbouncer_authenticator only (PUBLIC revoked)"
echo "  - CONNECT letta: revoked from pgbouncer_authenticator"
echo "  - pg_ident.conf pgb-auth-map: CN=pgbouncer-auth + CN=letta-pgbouncer → pgbouncer_authenticator"
echo "  - pg_hba cert+pg_ident carveout: inserted for pgbouncer_authenticator (YSG-RISK-073 cycle 7)"
echo "  - pg_hba catch-all (scram-sha-256 clientcert=verify-ca): applies to all other roles"
echo "  - YSG-RISK-073: CLOSED (cycle 7). YSG-RISK-075: CLOSED. YSG-RISK-077: documented (ARM64 SCRAM bug)."
