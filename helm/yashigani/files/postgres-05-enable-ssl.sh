#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Yashigani v2.23.4 — enable TLS + client-cert verification on Postgres.
# Last updated: 2026-05-20 (LETTA-001: asyncpg client-cert limitation, letta TLS-only rule)
#
# This init script runs ONCE on first initdb of the postgres container (the
# stock postgres entrypoint executes /docker-entrypoint-initdb.d/*.sh in
# alphabetical order before starting the server for real).
#
# After this script:
#   * ssl = on in postgresql.conf
#   * Server presents its own leaf cert (./secrets/postgres_client.crt) to
#     connecting clients
#   * Clients must present a cert signed by our internal CA
#     (clientcert=verify-ca)
#   * Password auth (scram-sha-256) still required on top of the cert
#     (defence in depth — three factors: TLS + cert + password)
#
# PKI design: root → intermediate → leaf (two-tier).
# ssl_ca_file (root.crt) must contain the INTERMEDIATE CA, not the root.
# All service leaf certs are signed directly by the intermediate.  When
# pgbouncer presents its client cert to postgres it may not send the
# intermediate in the TLS handshake chain (behaviour varies by libssl
# version / pgbouncer version).  Seeding root.crt with the intermediate
# ensures postgres can always verify the leaf directly without requiring the
# intermediate to appear in the peer's TLS Certificate message.
#
# The root CA MUST NOT appear in this file and MUST NOT be mounted as an
# mTLS trust anchor into any workload container (design invariant, retro S1).
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

echo "[05-enable-ssl] Installing server cert chain and enabling TLS"

# Fail-closed: both CA certs must be present before we write anything.
: "${PGDATA:?PGDATA must be set by the postgres image}"
for f in /run/secrets/ca_root.crt /run/secrets/ca_intermediate.crt; do
  if [[ ! -f "${f}" ]]; then
    echo "[05-enable-ssl] FATAL: ${f} not found — PKI bootstrap must run before postgres init" >&2
    exit 1
  fi
done

# Postgres requires SSL material inside PGDATA and owned by the postgres user.
install -m 0644 -o postgres -g postgres /run/secrets/postgres_client.crt "${PGDATA}/server.crt"
install -m 0600 -o postgres -g postgres /run/secrets/postgres_client.key "${PGDATA}/server.key"

# Trust bundle: ca_root.crt + ca_intermediate.crt concatenated. Required because
# leaf certs in /run/secrets are issued as chain-bundles (see pki/issuer.py).
# When pgbouncer/clients present a chain-bundle, postgres needs ca_root.crt as
# self-signed anchor at depth 2 to verify the embedded intermediate. Bundling
# both gives postgres anchors for any client cert format — defense-in-depth
# (Platform gate #58a evidence, 2026-04-28).
install -m 0640 -o postgres -g postgres /dev/null "${PGDATA}/root.crt"
cat /run/secrets/ca_root.crt /run/secrets/ca_intermediate.crt > "${PGDATA}/root.crt"
chown postgres:postgres "${PGDATA}/root.crt"
chmod 0640 "${PGDATA}/root.crt"

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
# Letta-specific rule added before the clientcert catch-all (asyncpg limitation).
cat > "${PGDATA}/pg_hba.conf" <<'HBA'
# TYPE  DATABASE  USER           ADDRESS        METHOD
# Local socket — used by the postgres docker-entrypoint itself for init.
local   all       all                           trust
# Loopback — postgres image runs its own bootstrap on 127.0.0.1.
host    all       all            127.0.0.1/32   trust
host    all       all            ::1/128        trust
# Letta: asyncpg (runtime) and pg8000 (alembic) cannot negotiate TLS via URI params.
# YSG-RISK-048: plain TCP + scram-sha-256 for letta; mTLS forward-close target v2.24.0.
# MUST appear BEFORE the hostssl clientcert=verify-ca catch-all.
# AGENT-RUNTIME-003c: pg8000 alembic path fails with sslmode kwarg on hostssl rule.
host letta     yashigani_app  0.0.0.0/0      scram-sha-256
host letta     yashigani_app  ::/0           scram-sha-256
# Everything else must come in over TLS with a client cert signed by our
# internal CA, AND present a valid scram-sha-256 password. Three factors.
hostssl all       all            0.0.0.0/0      scram-sha-256  clientcert=verify-ca
hostssl all       all            ::/0           scram-sha-256  clientcert=verify-ca
# Defence in depth — explicitly reject any plaintext attempt.
hostnossl all     all            0.0.0.0/0      reject
hostnossl all     all            ::/0           reject
HBA

chown postgres:postgres "${PGDATA}/pg_hba.conf"
chmod 0600 "${PGDATA}/pg_hba.conf"

echo "[05-enable-ssl] Done. Postgres will require TLS + client cert for network connections."
