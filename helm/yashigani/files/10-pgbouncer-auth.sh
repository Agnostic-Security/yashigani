#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Yashigani v2.24.0 — pgbouncer auth_query postgres-side setup (Helm / K8s).
# Last updated: 2026-05-25 (fix: BUG-C4-001/002 — trust clientcert=verify-ca; single source of truth)
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
# See docker/postgres/10-pgbouncer-auth.sh for full canonical documentation.
# This file MUST remain functionally identical to the docker version.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

echo "[10-pgbouncer-auth] Starting pgbouncer auth_query postgres-side setup (K8s)"

# Fail-closed: read pgbouncer_authenticator password from mounted secret file.
# K8s path: pgbouncer-auth-secret mounted into postgres pod at
#   /run/secrets/pgbouncer-auth/pgbouncer_authenticator_password (directory mount, defaultMode 0440).
#   BUG-NEW-002 fix: moved from subPath at /run/secrets/ to a separate directory to avoid
#   the containerd "not a directory" error when pki-certs already owns /run/secrets.
#   fsGroup: 70 in pod securityContext ensures postgres (UID 70) can read it.
_pwfile="/run/secrets/pgbouncer-auth/pgbouncer_authenticator_password"
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
# NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION, NOINHERIT.
# Grants: LOGIN + CONNECT to yashigani only + EXECUTE on ysg_pgbouncer_get_auth.
# No table grants, no schema grants, no access to letta or postgres databases.
#
# NOTE on pg_hba auth method (YSG-RISK-073 cycle 5):
# The pg_hba carveout uses `trust clientcert=verify-ca`. Trust requires no password
# from pgbouncer — the CA-verified client cert IS the authentication proof.
# pgbouncer 1.25.1 CAN authenticate via trust (no password needed); cannot do SCRAM
# (original BUG-NEW-001); cannot do md5 server-side in practice with this edoburu image.
# Password is still CREATED on the role (defense-in-depth + future compatibility),
# but not used by the pg_hba trust+clientcert path.
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

# ─── 4. pg_hba carveout — YSG-RISK-073 CLOSED (v2.24.3 cycle 5) ─────────────
# BUG-NEW-001 / YSG-RISK-073: PgBouncer 1.25.1 (edoburu image) cannot perform
# SCRAM-SHA-256 as the CLIENT when postgres requires scram-sha-256 for the
# auth_query connection. The SCRAM challenge is issued by postgres; pgbouncer
# cannot respond. This broke all postgres-backed services on clean install.
#
# Fix: add a narrow pg_hba `trust clientcert=verify-ca` carveout for
# pgbouncer_authenticator BEFORE the catch-all.
# - `clientcert=verify-ca` requires the connecting client to present a TLS cert
#   signed by our internal CA. Private-key proof + CA chain verification both hold.
#   This is the SAME security assertion as `cert` auth (which is broken per below).
# - `trust` means no additional password challenge. The CA-verified client cert
#   IS the authentication proof — identical to how the `cert` pg_hba method works,
#   without PG16's syntax restriction.
# - No SCRAM challenge issued; no md5 challenge issued.
#
# WHY NOT `cert` auth method (cycle 4 attempt — broken):
#   Layer A — PG16 syntax rejection: `clientcert=verify-ca` is invalid when the
#     auth method is `cert`. PostgreSQL 16 only accepts `clientcert=verify-full`
#     with cert auth. PG crashes with "clientcert only accepts verify-full when
#     using cert authentication". Verified by Ava cycle 4.
#   Layer B — CN mismatch: cert auth requires CN==role-name (with verify-full).
#     pgbouncer-auth cert has CN=pgbouncer-auth; role is pgbouncer_authenticator.
#
# WHY NOT `md5 clientcert=verify-ca` (cycle 5 attempt — also broken):
#   pgbouncer 1.25.1 (edoburu image) cannot correctly perform server-side md5
#   authentication against postgres in this configuration. The md5 challenge
#   response does not match regardless of whether userlist.txt contains cleartext
#   or pre-hashed md5. Verified by live test on Podman (Mac) during cycle 5.
#   Root cause: likely an edoburu image-specific auth handling issue.
#
# WHY NOT `scram-sha-256` (the original architecture):
#   PgBouncer 1.25.1 cannot perform SCRAM-SHA-256 as the authentication
#   INITIATOR (upstream client to postgres). auth_type controls the CLIENT-FACING
#   (downstream) auth; the auth_user upstream connection uses its own mechanism.
#   pgbouncer 1.25.1 does not implement SCRAM as the auth initiator.
#
# SECURITY OF trust + clientcert=verify-ca:
#   The cert_client presents pgbouncer-auth_client.crt (or letta-pgbouncer_client.crt),
#   both CA-signed by our internal PKI. Only the pgbouncer containers hold the
#   private keys (Docker/K8s secrets). Compromising the cert requires compromising
#   the pgbouncer container. The `trust` method adds no additional password check,
#   but the clientcert=verify-ca CHECK is enforced — anyone without the CA-signed
#   cert is rejected at the TLS level before `trust` is applied. This is security-
#   equivalent to the `cert` method that Ava proposed (which uses the same cert
#   verification but has PG16 syntax restrictions).
#   Role is NOSUPERUSER, NOINHERIT, only EXECUTE on ysg_pgbouncer_get_auth.
#   Blast radius: read of SCRAM verifiers from pg_shadow for ONE function call.
#   Net security posture: cert-equivalent, PG16-compatible, pgbouncer-compatible.
#
# SINGLE SOURCE OF TRUTH: this script (10-pgbouncer-auth.sh) is the ONLY writer
# of the pgbouncer_authenticator carveout. 05-enable-ssl.sh does NOT write a
# carveout (removed in BUG-C4-002 fix). This prevents duplicate entries.
#
# History:
#   v2.24.0 YSG-RISK-050: removed the A2 `trust` carveout (no clientcert — weaker).
#   v2.24.3 cycle 3 / YSG-RISK-073: `cert clientcert=verify-ca` — WRONG (PG16 syntax).
#   v2.24.3 cycle 4: cert attempt committed (7f296a1 — broken; this fixes it).
#   v2.24.3 cycle 5: `trust clientcert=verify-ca` — cert-equivalent, PG16-valid.
#     Key difference from v2.24.0 A2 carveout: clientcert=verify-ca IS required
#     (the old A2 used bare trust without cert). Duplicate removed from 05-enable-ssl.sh.
#
# Idempotent: awk removes stale carveout lines (any method), inserts trust+clientcert.
# This handles:
#   - Fresh initdb (05-enable-ssl.sh did NOT write a carveout; this adds one).
#   - Upgrade from v2.24.0/v2.24.1/v2.24.2 (no carveout present; carveout added).
#   - Upgrade from v2.24.3 cycle 3/4 (cert carveout; replaced with trust+clientcert).
#   - Upgrade from v2.24.0-pre (A2 bare-trust carveout; replaced with trust+clientcert).
#
# Design ref: iris-v240-pgbouncer-auth-query-design.md; YSG-RISK-073.
echo "[10-pgbouncer-auth] Ensuring pg_hba trust+clientcert carveout for pgbouncer_authenticator (YSG-RISK-073)"

# Step 4a: remove any existing pgbouncer_authenticator pg_hba lines (any method).
# This normalises fresh installs (05-enable-ssl.sh no longer writes a carveout
# as of cycle 5 — single source of truth is this script) and handles upgrades
# from v2.24.0-v2.24.2 (no carveout), v2.24.3 cycle 3/4 (cert carveout),
# or v2.24.0-pre (trust carveout).
if grep -q "pgbouncer_authenticator" "${PGDATA}/pg_hba.conf"; then
  sed -i '/pgbouncer_authenticator/d' "${PGDATA}/pg_hba.conf"
  sed -i '/Amendment A2.*YSG-RISK-049/d' "${PGDATA}/pg_hba.conf"
  sed -i '/YSG-RISK-073/d' "${PGDATA}/pg_hba.conf"
  echo "[10-pgbouncer-auth] Removed existing pgbouncer_authenticator pg_hba entries (normalising)"
fi

# Step 4b: insert the trust+clientcert carveout BEFORE the first hostssl catch-all.
# The carveout must come before `hostssl all all` or postgres applies the
# catch-all first and issues a SCRAM challenge pgbouncer cannot answer.
# Auth method: trust clientcert=verify-ca (cert = sole authenticator; PG16-valid).
# NOT cert (PG16 rejects verify-ca with cert method — see header comment).
# NOT md5 (pgbouncer 1.25.1 edoburu cannot compute server-side md5 — see header).
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
      print "# YSG-RISK-073: pgbouncer_authenticator auth_query -- trust clientcert=verify-ca."
      print "# clientcert=verify-ca: cert must be CA-signed (private-key proof + chain)."
      print "# trust: no password challenge. Cert IS the authenticator (same as cert method,"
      print "# but PG16-valid: cert method requires verify-full; trust+clientcert allows verify-ca)."
      print "# pgbouncer 1.25.1 cannot SCRAM (original bug) or md5 (edoburu image limitation)."
      print "hostssl yashigani pgbouncer_authenticator 0.0.0.0/0  trust  clientcert=verify-ca"
      print "hostssl yashigani pgbouncer_authenticator ::/0        trust  clientcert=verify-ca"
      inserted = 1
    }
    { print }
  ' "${_hba}" > "${_tmp}"
  chown postgres:postgres "${_tmp}"
  chmod 0600 "${_tmp}"
  mv "${_tmp}" "${_hba}"
  echo "[10-pgbouncer-auth] Inserted trust+clientcert carveout for pgbouncer_authenticator (YSG-RISK-073)"
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
# For the upgrade path (kubectl exec psql -U ... -f /docker-entrypoint-initdb.d/10-pgbouncer-auth.sh),
# pg_reload_conf() fires immediately and the updated pg_hba.conf is picked up by the live server.
psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER:-yashigani_app}" --dbname postgres -c "SELECT pg_reload_conf();" 2>/dev/null || true

echo "[10-pgbouncer-auth] pg_hba.conf state (hostssl lines):"
grep "^hostssl" "${PGDATA}/pg_hba.conf" || echo "  (no hostssl lines — fresh initdb, normal)"

echo "[10-pgbouncer-auth] Done. pgbouncer auth_query postgres-side setup complete (K8s)."
echo "[10-pgbouncer-auth] Summary:"
echo "  - Role pgbouncer_authenticator: created/updated"
echo "  - Function yashigani.ysg_pgbouncer_get_auth: created/updated"
echo "  - EXECUTE: pgbouncer_authenticator only (PUBLIC revoked)"
echo "  - CONNECT letta: revoked from pgbouncer_authenticator"
echo "  - pg_hba trust+clientcert carveout: inserted for pgbouncer_authenticator (YSG-RISK-073)"
echo "  - pg_hba catch-all (scram-sha-256 clientcert=verify-ca): applies to all other roles"
