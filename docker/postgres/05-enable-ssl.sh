#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Yashigani v4.1.2 — enable TLS + client-cert verification on Postgres.
# Last updated: 2026-07-20 (fix(postgres): FINDING-V412-RESTART-012 — resync
#   server.crt/server.key on EVERY invocation, not just first-init. Previously
#   the server leaf was installed once at initdb and frozen for the container's
#   lifetime; a plain leaf rotation (time-based renewal / URI-SAN-drift, or BYO
#   CA re-sync) updated docker/secrets/postgres_client.crt but postgres kept
#   presenting its ORIGINAL leaf forever, drifting from what every other mounted
#   trust store considered current. Closed with the same checksum-compare +
#   atomic-write + pg_ctl-reload pattern already used for the trust bundle.
#
# This init script is invoked in two contexts:
#
#   1. FIRST INIT (initdb): the stock postgres entrypoint executes all scripts
#      under /docker-entrypoint-initdb.d/ in alphabetical order before starting
#      the server for real.  Full setup runs: server cert + trust bundle sync,
#      postgresql.conf append, pg_hba.conf overwrite.
#
#   2. SYNC RE-RUN (BYO CA swap / rotation / leaf renewal): called manually via
#      `docker exec postgres bash /docker-entrypoint-initdb.d/05-enable-ssl.sh`
#      after the host-side secrets change.  The server-leaf sync and
#      trust-bundle sync blocks run UNCONDITIONALLY on every invocation
#      (first-init AND re-run) — only postgresql.conf and pg_hba.conf are
#      skipped on re-run (they are already correctly configured from
#      first-init).
#
# After first-init:
#   * ssl = on in postgresql.conf
#   * Server presents its own leaf cert (./secrets/postgres_client.crt) to
#     connecting clients
#   * Clients must present a cert signed by our internal CA
#     (clientcert=verify-ca)
#   * Password auth (scram-sha-256) still required on top of the cert for all
#     roles (defence in depth — three factors: TLS + cert + password).
#     EXCEPTION: pgbouncer_authenticator uses `cert map=pgb-auth-map` (YSG-RISK-073
#     cycle 7). cert method: PG16 implies verify-full (CN verified via pg_ident map
#     pgb-auth-map). NO password. The carveout is written by 10-pgbouncer-auth.sh
#     (single source of truth — not written here to prevent duplicate entries).
#     Rationale: pgbouncer 1.25.1 ARM64 has a SCRAM computation bug (YSG-RISK-077).
#     cert+pg_ident avoids SCRAM entirely and is stronger than trust+clientcert
#     (verify-full + CN-specific mapping vs verify-ca only).
#
# PKI design: root → intermediate → leaf (two-tier).
# ssl_ca_file (root.crt) must contain BOTH ca_root.crt and ca_intermediate.crt
# concatenated.  See the comment on the trust-bundle write below for the full
# rationale.
#
# "root.crt" is postgres's hardcoded ssl_ca_file name; the content is the bundle.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

echo "[05-enable-ssl] Running trust-bundle sync check"

# Fail-closed: both CA certs must be present.
: "${PGDATA:?PGDATA must be set by the postgres image}"
for f in /run/secrets/ca_root.crt /run/secrets/ca_intermediate.crt; do
  if [[ ! -f "${f}" ]]; then
    echo "[05-enable-ssl] FATAL: ${f} not found — PKI bootstrap must run before postgres init" >&2
    exit 1
  fi
done

# ─────────────────────────────────────────────────────────────────────────────
# TRUST-BUNDLE SYNC — runs on EVERY invocation (first-init AND re-run)
#
# BYO CA swap / rotation scenario: the host installs new ca_root.crt +
# ca_intermediate.crt into docker/secrets/.  The secrets are bind-mounted
# into the container as /run/secrets/.  This block detects the change via
# SHA-256 checksum and re-writes PGDATA/root.crt so postgres trusts the new CA.
# A pg_ctl reload is issued if postgres is already running (deferred-activation
# case); if this is first-init, postgres is not yet running and picks up the
# new root.crt at startup.
# ─────────────────────────────────────────────────────────────────────────────

_assemble_trust_bundle() {
  # Concatenate root + intermediate into the bundle postgres expects.
  # ca_intermediate.crt is always present (guarded above), but be defensive.
  cat /run/secrets/ca_root.crt /run/secrets/ca_intermediate.crt
}

# Compute SHA-256 of the assembled source bundle.
_src_sha=$(_assemble_trust_bundle | sha256sum | cut -d' ' -f1)

# Compute SHA-256 of the current PGDATA/root.crt (empty string if absent).
_dst_sha=$(sha256sum "${PGDATA}/root.crt" 2>/dev/null | cut -d' ' -f1 || echo "")

if [[ "$_src_sha" != "$_dst_sha" ]]; then
  echo "[05-enable-ssl] Trust bundle changed (src=${_src_sha:0:12} dst=${_dst_sha:0:12}) — updating PGDATA/root.crt"

  # Write atomically: temp file → chmod/chown → mv.
  # Using a temp path inside PGDATA so mv is on the same filesystem (atomic rename).
  _trust_tmp="${PGDATA}/root.crt.new.$$"
  _assemble_trust_bundle > "${_trust_tmp}"
  chown postgres:postgres "${_trust_tmp}"
  chmod 0640 "${_trust_tmp}"
  mv "${_trust_tmp}" "${PGDATA}/root.crt"

  echo "[05-enable-ssl] PGDATA/root.crt updated"

  # Trigger reload if postgres is already running (deferred-activation / rotation).
  # pg_ctl status exits 0 when postmaster is running.
  if pg_ctl -D "${PGDATA}" status >/dev/null 2>&1; then
    pg_ctl -D "${PGDATA}" reload
    echo "[05-enable-ssl] pg_ctl reload sent — postgres re-read new root.crt"
  else
    echo "[05-enable-ssl] Postgres not yet running — new root.crt will be used at startup"
  fi
else
  echo "[05-enable-ssl] Trust bundle unchanged (sha=${_src_sha:0:12}) — no action"
fi

# ─────────────────────────────────────────────────────────────────────────────
# SERVER-LEAF SYNC — runs on EVERY invocation (first-init AND re-run)
#
# FINDING-V412-RESTART-012: the trust bundle (root.crt) above is resynced on
# every invocation, but historically server.crt/server.key were installed
# ONLY at first-init and frozen for the container's lifetime — including
# across a plain `--pki-action=rotate-leaves` (re-issues postgres_client.crt
# under the SAME intermediate). On a stack that lives long enough to hit a
# leaf rotation (time-based renewal or URI-SAN-drift), postgres kept
# presenting its ORIGINAL leaf forever; nothing re-copied the rotated leaf
# into PGDATA. Server identity drifted from what install.sh/docker-secrets/
# considered "current" — the exact class of drift Laura (r6) and Tom (r3)
# reproduced against backoffice. Close it the same way the trust bundle is
# already closed: checksum-compare, atomic write, pg_ctl reload if running.
# ─────────────────────────────────────────────────────────────────────────────

_leaf_src_sha=$(cat /run/secrets/postgres_client.crt /run/secrets/postgres_client.key 2>/dev/null | sha256sum | cut -d' ' -f1)
_leaf_dst_sha=$( { cat "${PGDATA}/server.crt" "${PGDATA}/server.key"; } 2>/dev/null | sha256sum | cut -d' ' -f1 || echo "")

if [[ -n "$_leaf_src_sha" && "$_leaf_src_sha" != "$_leaf_dst_sha" ]]; then
  echo "[05-enable-ssl] Server leaf changed (src=${_leaf_src_sha:0:12} dst=${_leaf_dst_sha:0:12}) — updating server.crt/server.key"

  _leaf_crt_tmp="${PGDATA}/server.crt.new.$$"
  _leaf_key_tmp="${PGDATA}/server.key.new.$$"
  install -m 0644 -o postgres -g postgres /run/secrets/postgres_client.crt "${_leaf_crt_tmp}"
  install -m 0600 -o postgres -g postgres /run/secrets/postgres_client.key "${_leaf_key_tmp}"
  mv "${_leaf_crt_tmp}" "${PGDATA}/server.crt"
  mv "${_leaf_key_tmp}" "${PGDATA}/server.key"

  echo "[05-enable-ssl] server.crt/server.key updated"

  if pg_ctl -D "${PGDATA}" status >/dev/null 2>&1; then
    pg_ctl -D "${PGDATA}" reload
    echo "[05-enable-ssl] pg_ctl reload sent — postgres re-read new server leaf"
  else
    echo "[05-enable-ssl] Postgres not yet running — new server leaf will be used at startup"
  fi
else
  echo "[05-enable-ssl] Server leaf unchanged (sha=${_leaf_src_sha:0:12}) — no action"
fi

# ─────────────────────────────────────────────────────────────────────────────
# FIRST-INIT ONLY — postgresql.conf + pg_hba.conf
#
# Guard: postgresql.conf already contains "ssl = on" → this is a re-run
# (deferred activation / rotation).  Server cert + trust bundle are already
# resynced above (runs unconditionally); skip only the postgresql.conf /
# pg_hba.conf block to avoid duplicating settings or clobbering any operator
# customisations to pg_hba.conf.
# ─────────────────────────────────────────────────────────────────────────────

if grep -q '^ssl = on' "${PGDATA}/postgresql.conf" 2>/dev/null; then
  echo "[05-enable-ssl] postgresql.conf already has ssl=on — skipping first-init block (re-run path)"
  exit 0
fi

echo "[05-enable-ssl] First-init path — configuring postgresql.conf + pg_hba.conf"

# Server cert + trust bundle are already installed above (unconditional sync
# blocks run before this guard). Ensure ownership is correct in case the sync
# blocks ran before PGDATA ownership was otherwise settled.
chown postgres:postgres "${PGDATA}/root.crt" "${PGDATA}/server.crt" "${PGDATA}/server.key"
chmod 0640 "${PGDATA}/root.crt"
chmod 0644 "${PGDATA}/server.crt"
chmod 0600 "${PGDATA}/server.key"

# Append TLS settings to postgresql.conf (keep existing settings; our lines
# win by virtue of being later in the file).
cat >> "${PGDATA}/postgresql.conf" <<'PGCONF'

# ── Yashigani internal mTLS ─────────────────────────────────────────────────
ssl = on
ssl_cert_file = 'server.crt'
ssl_key_file  = 'server.key'
ssl_ca_file   = 'root.crt'
# Require TLS 1.2 minimum (aligns with edge + internal client policy).
ssl_min_protocol_version = 'TLSv1.2'
# Log every failed SSL handshake — noisy but essential for spotting rogue
# clients during mTLS rollout.
log_connections = on
PGCONF

# Rewrite pg_hba.conf so plaintext connections from the network are rejected.
# local + 127.0.0.1 remain for the postgres entrypoint bootstrap flows.
#
# YSG-RISK-048 CLOSED 2026-05-20: the former letta-specific plain-TCP carveout
# (host letta yashigani_app ... scram-sha-256) was removed when the stunnel sidecar
# was implemented and remains removed under the pgbouncer design. Letta now connects
# via letta-pgbouncer sidecar (edoburu/pgbouncer:v1.25.1-p0, UID 70) which presents
# letta-pgbouncer_client.crt to postgres over full mTLS. clientcert=verify-ca
# catch-all applies to all services including letta's sidecar.
cat > "${PGDATA}/pg_hba.conf" <<'HBA'
# TYPE  DATABASE  USER           ADDRESS        METHOD
# Local socket — used by the postgres docker-entrypoint itself for init.
local   all       all                           trust
# Loopback — postgres image runs its own bootstrap on 127.0.0.1.
host    all       all            127.0.0.1/32   trust
host    all       all            ::1/128        trust
# All other network connections must use TLS with a client cert signed by our
# internal CA, AND present a valid scram-sha-256 password. Three factors.
# Letta reaches postgres via the letta-pgbouncer sidecar which presents
# letta-pgbouncer_client.crt — no carveout required (YSG-RISK-048 closed).
hostssl all       all            0.0.0.0/0      scram-sha-256  clientcert=verify-ca
hostssl all       all            ::/0           scram-sha-256  clientcert=verify-ca
# Defence in depth — explicitly reject any plaintext attempt.
hostnossl all     all            0.0.0.0/0      reject
hostnossl all     all            ::/0           reject
HBA

chown postgres:postgres "${PGDATA}/pg_hba.conf"
chmod 0600 "${PGDATA}/pg_hba.conf"

echo "[05-enable-ssl] Done. Postgres will require TLS + client cert for network connections."
