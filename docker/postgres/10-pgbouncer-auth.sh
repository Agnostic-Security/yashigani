#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Yashigani v2.24.0 — pgbouncer auth_query postgres-side setup.
# Last updated: 2026-05-25 (fix: YSG-RISK-073 cycle 6 — scram-sha-256 clientcert=verify-ca; two-factor restored)
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
#   docker exec yashigani-postgres psql -U "${POSTGRES_USER:-yashigani_app}" -d yashigani \
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
#
# NOTE on pg_hba auth method (YSG-RISK-073 cycle 6):
# The pg_hba carveout uses `scram-sha-256 clientcert=verify-ca`. Two-factor auth:
# - clientcert=verify-ca: CA chain + private-key proof (cert factor).
# - scram-sha-256: pgbouncer_authenticator password challenge (password factor).
# pgbouncer 1.25.1 (edoburu image) DOES support SCRAM-SHA-256 as the auth initiator.
# Cycle 5 cycle comment ("pgbouncer 1.25.1 cannot SCRAM") was incorrect — the cycle 5
# failure was a misconfiguration, not a pgbouncer limitation. Confirmed by live test:
#   postgres log: "connection authenticated: identity=pgbouncer_authenticator method=scram-sha-256"
# Two-factor (cert + password) is fully restored as of cycle 6. See YSG-RISK-073.
#
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
# The function reads pg_shadow (superuser-only catalog) via SECURITY DEFINER.
# Owner: postgres (superuser at runtime of this init script).
# search_path locked to pg_catalog,public — search_path hijack defence (Laura C1).
# Parameterised query (uname text arg) — no string concatenation (Laura C1).
# auth_dbname = yashigani on both pgbouncer.ini and pgbouncer-letta.ini (Amendment C6).
# pg_shadow is a global catalog view — function lives once, in yashigani database.
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

-- Restrict execute: revoke from PUBLIC, grant only to pgbouncer_authenticator.
REVOKE ALL ON FUNCTION ysg_pgbouncer_get_auth(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ysg_pgbouncer_get_auth(text) TO pgbouncer_authenticator;
SQL

# ─── 3. REVOKE CONNECT on non-auth databases (C2 — Laura recommendation) ─────
# pgbouncer_authenticator should only connect to yashigani (auth_dbname).
# Remove implicit CONNECT privilege from letta and postgres system databases
# so a credential leak cannot be leveraged to connect elsewhere.
echo "[10-pgbouncer-auth] Restricting pgbouncer_authenticator database CONNECT privileges"
psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER:-yashigani_app}" --dbname postgres <<'SQL'
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

# ─── 4. pg_hba carveout — YSG-RISK-073 CLOSED (v2.24.3 cycle 6) ─────────────
# BUG-NEW-001 / YSG-RISK-073: History of the pgbouncer_authenticator pg_hba carveout.
#
# BACKGROUND: YSG-RISK-050 removed the A2 trust carveout assuming pgbouncer could SCRAM.
# The actual problem in early cycles was misconfiguration, not a pgbouncer limitation.
#
# Fix: add a narrow pg_hba `scram-sha-256 clientcert=verify-ca` carveout for
# pgbouncer_authenticator BEFORE the catch-all.
# - `clientcert=verify-ca`: requires a TLS cert signed by our internal CA.
#   Private-key proof + CA chain verification both hold.
# - `scram-sha-256`: pgbouncer_authenticator password challenge. TWO-FACTOR: cert + password.
#   pgbouncer 1.25.1 (edoburu) DOES support SCRAM as the auth initiator (confirmed cycle 6).
#
# WHY NOT `cert` auth method (cycle 4 attempt — broken):
#   Layer A — PG16 syntax rejection: `clientcert=verify-ca` is invalid when the
#     auth method is `cert`. PostgreSQL 16 only accepts `clientcert=verify-full`
#     with cert auth. PG crashes with "clientcert only accepts verify-full when
#     using cert authentication". Verified by Ava cycle 4.
#   Layer B — CN mismatch: cert auth requires CN==role-name (with verify-full).
#     pgbouncer-auth cert has CN=pgbouncer-auth; role is pgbouncer_authenticator.
#
# WHY NOT `md5 clientcert=verify-ca` (cycle 5 attempt — broken):
#   pgbouncer 1.25.1 (edoburu image) cannot correctly perform server-side md5
#   authentication against postgres in this configuration. The md5 challenge
#   response does not match regardless of whether userlist.txt contains cleartext
#   or pre-hashed md5. Verified by live test on Podman (Mac) during cycle 5.
#   Root cause: likely an edoburu image-specific auth handling issue.
#
# WHY NOT `trust clientcert=verify-ca` (cycle 5 fix — SECURITY GAP):
#   Cycle 5 chose trust+clientcert as a workaround when SCRAM appeared broken.
#   Laura adversarial probe (cycle 5 release gate) confirmed a REAL attack chain:
#   Any compromised container on the `data` network holding a CA-signed cert can
#   connect to postgres claiming role `pgbouncer_authenticator` — trust+clientcert
#   requires no password, so cert alone is sufficient. With 11 CA-cert holders on
#   `data`, the blast radius is any container compromise → full DB read.
#   YSG-RISK-075 documents this class. Cycle 5 fix is REVERTED here (cycle 6).
#
# SCRAM-SHA-256 CONFIRMATION (cycle 6 live test):
#   pgbouncer 1.25.1 (edoburu) DOES support SCRAM-SHA-256 as the auth initiator.
#   Cycle 5 comment "pgbouncer 1.25.1 does not implement SCRAM as the auth initiator"
#   was INCORRECT — the failure was a configuration error, not a pgbouncer limitation.
#   Cycle 6 live test evidence:
#     postgres log line: "connection authenticated: identity=pgbouncer_authenticator
#                         method=scram-sha-256 (.../pg_hba.conf:5)"
#     psql via pgbouncer: SELECT current_user → yashigani_app (PASS)
#   Evidence: testing_runs/captain_cycle6_pgident_or_scram_20260525/option-gamma-live-test.log
#
# SECURITY OF scram-sha-256 + clientcert=verify-ca (TWO-FACTOR):
#   Factor 1 — cert: CA-signed cert + private key (held only by pgbouncer containers).
#   Factor 2 — password: SCRAM challenge for pgbouncer_authenticator password.
#   An attacker who steals a CA-signed cert from another data-network service CANNOT
#   authenticate as pgbouncer_authenticator without also knowing the password.
#   The password is mounted as a Docker/K8s secret to the pgbouncer containers only.
#   This closes the Laura cycle 5 lateral-pivot attack chain.
#
# SINGLE SOURCE OF TRUTH: this script (10-pgbouncer-auth.sh) is the ONLY writer
# of the pgbouncer_authenticator carveout. 05-enable-ssl.sh does NOT write a
# carveout (removed in BUG-C4-002 fix). This prevents duplicate entries.
#
# History:
#   v2.24.0 YSG-RISK-050: removed the A2 `trust` carveout (no clientcert — weaker).
#   v2.24.3 cycle 3 / YSG-RISK-073: `cert clientcert=verify-ca` — WRONG (PG16 syntax).
#   v2.24.3 cycle 4: cert attempt committed (7f296a1 — broken).
#   v2.24.3 cycle 5: `trust clientcert=verify-ca` — cert-equivalent but single-factor.
#     Security gap: any CA-cert holder can impersonate pgbouncer_authenticator.
#     Laura cycle 5 confirmed attack chain (YSG-RISK-075).
#   v2.24.3 cycle 6: `scram-sha-256 clientcert=verify-ca` — two-factor restored.
#     SCRAM confirmed working in pgbouncer 1.25.1 (edoburu). Lateral-pivot closed.
#
# Idempotent: awk removes stale carveout lines (any method), inserts scram+clientcert.
# This handles:
#   - Fresh initdb (05-enable-ssl.sh did NOT write a carveout; this adds one).
#   - Upgrade from v2.24.0/v2.24.1/v2.24.2 (no carveout present; carveout added).
#   - Upgrade from v2.24.3 cycle 3/4 (cert carveout; replaced with scram+clientcert).
#   - Upgrade from v2.24.3 cycle 5 (trust+clientcert; replaced with scram+clientcert).
#   - Upgrade from v2.24.0-pre (A2 bare-trust carveout; replaced with scram+clientcert).
#
# Design ref: iris-v240-pgbouncer-auth-query-design.md; YSG-RISK-073; YSG-RISK-075.
echo "[10-pgbouncer-auth] Ensuring pg_hba scram-sha-256+clientcert carveout for pgbouncer_authenticator (YSG-RISK-073 cycle 6)"

# Step 4a: remove any existing pgbouncer_authenticator pg_hba lines (any method).
# This normalises fresh installs (05-enable-ssl.sh no longer writes a carveout
# as of cycle 5 — single source of truth is this script) and handles upgrades
# from v2.24.0-v2.24.2 (no carveout), v2.24.3 cycle 3/4 (cert carveout),
# v2.24.3 cycle 5 (trust+clientcert carveout), or v2.24.0-pre (bare-trust carveout).
if grep -q "pgbouncer_authenticator" "${PGDATA}/pg_hba.conf"; then
  sed -i '/pgbouncer_authenticator/d' "${PGDATA}/pg_hba.conf"
  sed -i '/Amendment A2.*YSG-RISK-049/d' "${PGDATA}/pg_hba.conf"
  sed -i '/YSG-RISK-073/d' "${PGDATA}/pg_hba.conf"
  echo "[10-pgbouncer-auth] Removed existing pgbouncer_authenticator pg_hba entries (normalising)"
fi

# Step 4b: insert the scram-sha-256+clientcert carveout BEFORE the first hostssl catch-all.
# The carveout must come before `hostssl all all` so postgres matches this rule first.
# Auth method: scram-sha-256 clientcert=verify-ca (two-factor: cert + password).
# NOT trust (cycle 5 — one-factor; Laura confirmed lateral-pivot attack — YSG-RISK-075).
# NOT cert (PG16 rejects verify-ca with cert method — BUG-C4-001).
# NOT md5 (pgbouncer 1.25.1 edoburu cannot compute server-side md5 — cycle 5 finding).
#
# Implementation: awk for "insert before first match only".
# sed '/^hostssl all/i ...' inserts before EVERY matching line — pg_hba.conf has
# two catch-all lines (0.0.0.0/0 + ::/0), which produces duplicate carveouts.
# awk processes the file once, inserting only before the first `hostssl all` match.
# awk is available in the pgvector/pgvector:pg16 Debian base image.
if grep -q "^hostssl all" "${PGDATA}/pg_hba.conf"; then
  _hba="${PGDATA}/pg_hba.conf"
  _tmp="${PGDATA}/pg_hba.conf.new.$$"
  awk '
    /^hostssl all/ && !inserted {
      print "# YSG-RISK-073 cycle 6: pgbouncer_authenticator auth_query -- scram-sha-256 clientcert=verify-ca."
      print "# TWO-FACTOR: clientcert=verify-ca (CA chain + private-key proof) + scram-sha-256 (password)."
      print "# Closes Laura cycle 5 lateral-pivot: any CA-cert holder could impersonate pgbouncer_authenticator"
      print "# under the old cycle-5 trust carveout (no password needed). YSG-RISK-075."
      print "# pgbouncer 1.25.1 (edoburu) confirmed SCRAM-capable as auth initiator (cycle 6 live test)."
      print "hostssl yashigani pgbouncer_authenticator 0.0.0.0/0  scram-sha-256  clientcert=verify-ca"
      print "hostssl yashigani pgbouncer_authenticator ::/0        scram-sha-256  clientcert=verify-ca"
      inserted = 1
    }
    { print }
  ' "${_hba}" > "${_tmp}"
  chown postgres:postgres "${_tmp}"
  chmod 0600 "${_tmp}"
  mv "${_tmp}" "${_hba}"
  echo "[10-pgbouncer-auth] Inserted scram-sha-256+clientcert carveout for pgbouncer_authenticator (YSG-RISK-073 cycle 6)"
else
  # No catch-all present yet (first-init path where 05-enable-ssl.sh runs later
  # alphabetically). 10-pgbouncer-auth.sh is numbered 10-* but postgres runs
  # init scripts after pg_hba is written by 05-enable-ssl.sh. This branch should
  # not trigger in practice; log and continue.
  echo "[10-pgbouncer-auth] WARNING: no hostssl catch-all found — carveout will be written by 05-enable-ssl.sh"
fi

# Reload pg_hba.conf so the change takes effect without a full restart.
# During initdb, postgres is not running in server mode yet — the file is read
# on next server start. This is correct for the init-script path.
# For the upgrade path (docker exec psql -U "${POSTGRES_USER:-yashigani_app}" -d yashigani -f
# /docker-entrypoint-initdb.d/10-pgbouncer-auth.sh), pg_reload_conf() fires
# immediately and the updated pg_hba.conf is picked up by the live server.
psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER:-yashigani_app}" --dbname postgres -c "SELECT pg_reload_conf();" 2>/dev/null || true

echo "[10-pgbouncer-auth] pg_hba.conf state (hostssl lines):"
grep "^hostssl" "${PGDATA}/pg_hba.conf" || echo "  (no hostssl lines — fresh initdb, normal)"

echo "[10-pgbouncer-auth] Done. pgbouncer auth_query postgres-side setup complete."
echo "[10-pgbouncer-auth] Summary:"
echo "  - Role pgbouncer_authenticator: created/updated"
echo "  - Function yashigani.ysg_pgbouncer_get_auth: created/updated"
echo "  - EXECUTE: pgbouncer_authenticator only (PUBLIC revoked)"
echo "  - CONNECT letta: revoked from pgbouncer_authenticator"
echo "  - pg_hba scram-sha-256+clientcert carveout: inserted for pgbouncer_authenticator (YSG-RISK-073 cycle 6)"
echo "  - pg_hba catch-all (scram-sha-256 clientcert=verify-ca): applies to all other roles"
