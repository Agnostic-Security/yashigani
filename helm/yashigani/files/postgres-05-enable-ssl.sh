#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Yashigani v4.1.2 — enable TLS + client-cert verification on Postgres.
# Last updated: 2026-07-20 (fix(postgres): FINDING-LAURA-V412-PKI-PIN — chain-
#   of-continuity verification before trusting/installing ANY new root,
#   intermediate, or server leaf. Closes the rogue-CA-injection gap Laura
#   proved live (LAURA-V412-RESTART-012-TM, Q1/Q2): the checksum-diff sync
#   below previously installed and trusted whatever bytes sat in
#   docker/secrets/, with no distinction between a legitimate rotation and a
#   rogue chain written by a compromised mesh service (docker/secrets/ is
#   bind-mounted RW into backoffice — see FINDING-LIC-012, fixed separately
#   in docker-compose.yml/values.yaml). Now:
#     - intermediate (root unchanged): must openssl-verify against the
#       PINNED root before install. Reject loud otherwise.
#     - root rotation (root changed): no prior root to chain to (self-signed)
#       — require an explicit operator-attested pin
#       (/run/secrets-pki-attest/ca_root.attested_sha256), written ONLY by
#       install.sh's `--pki-action=rotate-root` ceremony (host-shell +
#       typed-YES confirmation — a compromised container cannot produce this
#       file). Reject loud otherwise.
#
#   FINDING-V412-RESTART-012 (2026-07-21): the attestation file previously
#   lived at /run/secrets/ca_root.attested_sha256 — inside the SAME shared
#   docker/secrets/ directory that backoffice (and every other mesh service)
#   also mounts. Laura proved the RO mount was not enforced for backoffice on
#   podman-compose, so a compromised backoffice could forge this file via the
#   same write primitive that overwrites ca_root.crt (laura-012-rogue-
#   reattack.md, Attack 3). Fixed at TWO independent layers: (a) the RO-mount
#   bug itself is closed (docker-compose.yml backoffice volumes — /run/secrets
#   is now a pure :ro mount, no nested :rw children), AND (b) the attestation
#   file has been relocated to a dedicated, postgres-ONLY host directory
#   (docker/secrets-pki-attest/) that no other compose service mounts at all
#   — see YASHIGANI_PG_ATTEST_DIR below. Even a future regression of (a) on
#   ANY service cannot forge this file, because nothing but postgres can see
#   the directory it lives in.
#     - server leaf: must openssl-verify against the (now-verified) trust
#       bundle, and its public key must match its own private key, before
#       install. Reject loud otherwise.
#   No blind checksum-diff-and-trust anywhere below. See
#   testing_runs/yashigani/v412-fix-012-harden-20260720/ for the design note
#   and Laura's re-attack.
#
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
#     EXCEPTION: pgbouncer_authenticator uses `cert map=pgb-auth-map` (YSG-RISK-227
#     cycle 7). cert method: PG16 implies verify-full (CN verified via pg_ident map
#     pgb-auth-map). NO password. The carveout is written by 10-pgbouncer-auth.sh
#     (single source of truth — not written here to prevent duplicate entries).
#     Rationale: pgbouncer 1.25.1 ARM64 has a SCRAM computation bug (YSG-RISK-231).
#     cert+pg_ident avoids SCRAM entirely and is stronger than trust+clientcert
#     (verify-full + CN-specific mapping vs verify-ca only).
#
# PKI design: root → intermediate → leaf (two-tier).
# ssl_ca_file (root.crt) must contain BOTH ca_root.crt and ca_intermediate.crt
# concatenated.  See the comment on the trust-bundle write below for the full
# rationale.
#
# "root.crt" is postgres's hardcoded ssl_ca_file name; the content is the bundle.
#
# Last updated: 2026-07-24 (fix(k8s): FINDING-V412-K8S-PG-SSL — remove every
#   `chown postgres:postgres` / `install -o/-g postgres` in this K8s copy.
#   templates/postgres.yaml now pins runAsUser/runAsGroup/fsGroup to 999,
#   matching this image's real postgres UID/GID exactly (see that file's
#   comment) — every file this script creates is already owned uid999:gid999
#   at creation time (the process never runs as any other UID, ever; there
#   is no root moment to drop from). An explicit chown was therefore always
#   redundant here, AND is exactly the failure mode that broke this path
#   before (a chown to a MISMATCHED "postgres" UID resolved from
#   /etc/passwd needs CAP_CHOWN, which capabilities.drop:[ALL] removes).
#   Dropped outright as defense-in-depth against any future image/UID drift
#   regressing this class of bug again — chmod alone is sufficient since
#   ownership is already correct by construction.
#
#   NOTE — deliberate divergence from docker/postgres/05-enable-ssl.sh: the
#   compose copy of this script is UNCHANGED and keeps its chown calls.
#   Compose pins `user: "999:999"` on the container (docker-compose.yml,
#   "gate V232-SMOKE-018") which ALSO exactly matches this image's real
#   postgres UID/GID, so chown there is already a same-UID no-op requiring
#   no capability — it isn't broken, so it isn't touched (per-runtime
#   optimisation: docker/podman/k8s are independent streams, see
#   feedback_optimize_per_runtime_not_flimsy_shared.md). This is the ONLY
#   functional delta between the two copies; keep it that way if you edit
#   either file — do not silently reintroduce chown here or silently drop it
#   there without updating this note.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

echo "[05-enable-ssl] Running trust-bundle sync check"

# Fail-closed: both CA certs must be present.
: "${PGDATA:?PGDATA must be set by the postgres image}"

# YASHIGANI_PG_SECRETS_DIR: override point for offline testing only (defaults
# to the real container mount path). Lets tests/invariants exercise the
# chain-of-continuity logic below (rogue-chain rejection, legit-rotation
# acceptance) against a scratch directory without a running container or
# root — see tests/invariants/test_i10_pki_chain_of_continuity.sh.
_SECRETS_DIR="${YASHIGANI_PG_SECRETS_DIR:-/run/secrets}"

for f in "${_SECRETS_DIR}/ca_root.crt" "${_SECRETS_DIR}/ca_intermediate.crt"; do
  if [[ ! -f "${f}" ]]; then
    echo "[05-enable-ssl] FATAL: ${f} not found — PKI bootstrap must run before postgres init" >&2
    exit 1
  fi
done

# Fail-closed: openssl is required for chain-of-continuity verification below.
# Do NOT silently skip verification if the binary is missing — that would
# degrade back to blind-trust, exactly the gap this fix closes.
if ! command -v openssl >/dev/null 2>&1; then
  echo "[05-enable-ssl] FATAL: openssl not found in postgres image — cannot verify chain-of-continuity. Refusing to sync trust material." >&2
  exit 1
fi

_sha256_of() {
  # Usage: _sha256_of <file>. Prints hex digest, or empty string if absent.
  sha256sum "$1" 2>/dev/null | cut -d' ' -f1 || true
}

_openssl_verify_chain() {
  # Usage: _openssl_verify_chain <trusted CAfile> <cert to verify>
  # Returns 0 if <cert> chains to <trusted CAfile>, non-zero otherwise.
  openssl verify -CAfile "$1" "$2" >/dev/null 2>&1
}

_pubkey_sha256() {
  # Usage: _pubkey_sha256 cert|key <path>. Prints sha256 of the DER public key
  # so a cert and its private key can be compared for a matching pair.
  case "$1" in
    cert) openssl x509 -noout -pubkey -in "$2" 2>/dev/null | openssl sha256 2>/dev/null | awk '{print $NF}' ;;
    key)  openssl pkey  -pubout        -in "$2" 2>/dev/null | openssl sha256 2>/dev/null | awk '{print $NF}' ;;
  esac
}

# ─────────────────────────────────────────────────────────────────────────────
# TRUST-BUNDLE SYNC — runs on EVERY invocation (first-init AND re-run)
#
# BYO CA swap / rotation scenario: the host installs new ca_root.crt +
# ca_intermediate.crt into docker/secrets/.  The secrets are bind-mounted
# into the container as /run/secrets/.  This block detects the change via
# SHA-256 checksum and re-writes PGDATA/root.crt so postgres trusts the new CA
# — but ONLY after chain-of-continuity verification (FINDING-LAURA-V412-PKI-PIN,
# below).  A pg_ctl reload is issued if postgres is already running (deferred-
# activation case); if this is first-init, postgres is not yet running and
# picks up the new root.crt at startup.
# ─────────────────────────────────────────────────────────────────────────────

_assemble_trust_bundle() {
  # Concatenate root + intermediate into the bundle postgres expects.
  # ca_intermediate.crt is always present (guarded above), but be defensive.
  cat "${_SECRETS_DIR}/ca_root.crt" "${_SECRETS_DIR}/ca_intermediate.crt"
}

# ─────────────────────────────────────────────────────────────────────────────
# FINDING-LAURA-V412-PKI-PIN — chain-of-continuity verification.
#
# Root CAs are self-signed — there is nothing to `openssl verify` a NEW root
# against (that is a mathematical property of a root CA, not a gap we can
# close with more crypto checks alone). The trust anchor for "is this root
# change operator-sanctioned" is therefore PROCEDURAL: install.sh's
# `--pki-action=rotate-root` ceremony requires host shell access AND an
# interactive typed-YES confirmation (install.sh:handle_pki_subcommand,
# rotate-root case) before it writes a NEW root at all. Immediately after a
# successful rotate-root, install.sh stamps the sha256 of the new root into
# ${_ATTEST_DIR}/ca_root.attested_sha256 — a host-written file in a
# DEDICATED, postgres-ONLY mount (FINDING-V412-RESTART-012: no longer inside
# the shared docker/secrets/ tree — see YASHIGANI_PG_ATTEST_DIR below). A
# compromised mesh service (Laura's threat model — TA-3/TA-4, no host shell,
# capabilities dropped, no docker socket) can overwrite ca_root.crt itself
# (it's in the flat, widely-mounted secrets dir) but can NEVER reach — let
# alone produce — a matching attestation file: no container but postgres has
# this directory mounted at all, at any permission. A rogue root swap is
# provably rejectable here even if some OTHER service's /run/secrets RO
# enforcement regresses in the future.
#
# Intermediate rotation under an UNCHANGED root is the common, safe case this
# whole finding class exists to fix (leaf/intermediate renewal without a full
# root ceremony) — that path is verified cryptographically: openssl verify
# the incoming intermediate against the (pinned, unchanged) root.
# ─────────────────────────────────────────────────────────────────────────────

# YASHIGANI_PG_ATTEST_DIR: override point for offline testing only (same
# rationale as YASHIGANI_PG_SECRETS_DIR above). Defaults to the dedicated,
# postgres-ONLY mount (docker-compose.yml / postgres.yaml) — NOT under
# /run/secrets, and not shared with any other compose service or K8s volume.
_ATTEST_DIR="${YASHIGANI_PG_ATTEST_DIR:-/run/secrets-pki-attest}"

_PINNED_ROOT_FILE="${PGDATA}/.ysg_pinned_root_sha256"
_ATTESTED_ROOT_FILE="${_ATTEST_DIR}/ca_root.attested_sha256"

_new_root_sha="$(_sha256_of "${_SECRETS_DIR}/ca_root.crt")"
_pinned_root_sha=""
[[ -f "$_PINNED_ROOT_FILE" ]] && _pinned_root_sha="$(cat "$_PINNED_ROOT_FILE" 2>/dev/null || true)"

_write_pinned_root() {
  # Usage: _write_pinned_root <sha256>. Atomic write, 0600.
  # No chown: this process runs as uid999:gid999 (postgres) for its entire
  # lifetime (templates/postgres.yaml runAsUser/runAsGroup: 999) — the file
  # this function just created is already owned uid999:gid999 by
  # construction. See the FINDING-V412-K8S-PG-SSL note at the top of this file.
  local _tmp="${_PINNED_ROOT_FILE}.new.$$"
  printf '%s\n' "$1" > "${_tmp}"
  chmod 0600 "${_tmp}"
  mv "${_tmp}" "${_PINNED_ROOT_FILE}"
}

if [[ -z "$_pinned_root_sha" ]]; then
  # No prior pin on record — first sync since this fix shipped, or genuine
  # first-init. Trust-on-first-use is unavoidable for an initial trust anchor
  # (there is nothing yet to compare against); this is NOT weaker than the
  # pre-fix behaviour (which blind-trusted on EVERY sync, not just this one).
  # Every subsequent invocation is verified against the pin written here.
  echo "[05-enable-ssl] No pinned root on record — pinning current root (sha=${_new_root_sha:0:12}) as trust anchor"
  _pinned_root_sha="$_new_root_sha"
  _write_pinned_root "$_pinned_root_sha"
fi

if [[ "$_new_root_sha" != "$_pinned_root_sha" ]]; then
  echo "[05-enable-ssl] Root CA CHANGED (pinned=${_pinned_root_sha:0:12} incoming=${_new_root_sha:0:12}) — root rotation detected, checking operator attestation"

  if [[ ! -f "$_ATTESTED_ROOT_FILE" ]]; then
    echo "[05-enable-ssl] REJECTED: root changed but no operator attestation found at ${_ATTESTED_ROOT_FILE}." >&2
    echo "[05-enable-ssl]   This is either (a) an unauthorised/rogue root write, or (b) a legitimate root" >&2
    echo "[05-enable-ssl]   rotation whose attestation did not propagate. To perform a legitimate root" >&2
    echo "[05-enable-ssl]   rotation, run: ./install.sh --pki-action=rotate-root" >&2
    echo "[05-enable-ssl]   Refusing to install untrusted root — postgres continues trusting the PINNED root only." >&2
    exit 1
  fi

  _attested_sha="$(tr -d '[:space:]' < "$_ATTESTED_ROOT_FILE" 2>/dev/null || true)"
  if [[ -z "$_attested_sha" || "$_attested_sha" != "$_new_root_sha" ]]; then
    echo "[05-enable-ssl] REJECTED: operator attestation (${_attested_sha:0:12}) does not match incoming root (${_new_root_sha:0:12})." >&2
    echo "[05-enable-ssl]   Refusing to install untrusted root — postgres continues trusting the PINNED root only." >&2
    exit 1
  fi

  echo "[05-enable-ssl] Operator attestation verified (sha=${_new_root_sha:0:12}) — accepting root rotation"
  _pinned_root_sha="$_new_root_sha"
  _write_pinned_root "$_pinned_root_sha"
else
  echo "[05-enable-ssl] Root CA unchanged (sha=${_pinned_root_sha:0:12}) — pin holds"
fi

# Intermediate must chain to the (pinned, possibly just-rotated) root —
# blocks a rogue/mismatched intermediate regardless of whether root changed.
if ! _openssl_verify_chain "${_SECRETS_DIR}/ca_root.crt" "${_SECRETS_DIR}/ca_intermediate.crt"; then
  echo "[05-enable-ssl] REJECTED: ca_intermediate.crt does not chain to the trusted root (openssl verify failed)." >&2
  echo "[05-enable-ssl]   Refusing to update the trust bundle — postgres continues trusting the CURRENT bundle." >&2
  exit 1
fi
echo "[05-enable-ssl] Chain-of-continuity verified: ca_intermediate.crt chains to the trusted root"

# Compute SHA-256 of the assembled source bundle (now verified above).
_src_sha=$(_assemble_trust_bundle | sha256sum | cut -d' ' -f1)

# Compute SHA-256 of the current PGDATA/root.crt (empty string if absent).
_dst_sha=$(sha256sum "${PGDATA}/root.crt" 2>/dev/null | cut -d' ' -f1 || echo "")

if [[ "$_src_sha" != "$_dst_sha" ]]; then
  echo "[05-enable-ssl] Trust bundle changed (src=${_src_sha:0:12} dst=${_dst_sha:0:12}) — updating PGDATA/root.crt"

  # Write atomically: temp file → chmod/chown → mv.
  # Using a temp path inside PGDATA so mv is on the same filesystem (atomic rename).
  # No chown — already owned uid999:gid999 by construction (see top-of-file note).
  _trust_tmp="${PGDATA}/root.crt.new.$$"
  _assemble_trust_bundle > "${_trust_tmp}"
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
#
# FINDING-LAURA-V412-PKI-PIN: before installing, the new leaf must (a) chain
# to the trust bundle just verified above, and (b) its public key must match
# its own private key (defends against a corrupted/mismatched pair, or a
# rogue key paired with a leaf/cert from an unrelated chain).
# ─────────────────────────────────────────────────────────────────────────────

_leaf_src_sha=$(cat "${_SECRETS_DIR}/postgres_client.crt" "${_SECRETS_DIR}/postgres_client.key" 2>/dev/null | sha256sum | cut -d' ' -f1)
_leaf_dst_sha=$( { cat "${PGDATA}/server.crt" "${PGDATA}/server.key"; } 2>/dev/null | sha256sum | cut -d' ' -f1 || echo "")

if [[ -n "$_leaf_src_sha" && "$_leaf_src_sha" != "$_leaf_dst_sha" ]]; then
  echo "[05-enable-ssl] Server leaf changed (src=${_leaf_src_sha:0:12} dst=${_leaf_dst_sha:0:12}) — verifying before install"

  if ! _openssl_verify_chain "${PGDATA}/root.crt" "${_SECRETS_DIR}/postgres_client.crt"; then
    echo "[05-enable-ssl] REJECTED: postgres_client.crt does not chain to the trusted bundle (openssl verify failed)." >&2
    echo "[05-enable-ssl]   Refusing to install — postgres continues presenting its CURRENT server leaf." >&2
    exit 1
  fi

  _leaf_pub_cert="$(_pubkey_sha256 cert "${_SECRETS_DIR}/postgres_client.crt")"
  _leaf_pub_key="$(_pubkey_sha256 key "${_SECRETS_DIR}/postgres_client.key")"
  if [[ -z "$_leaf_pub_cert" || -z "$_leaf_pub_key" || "$_leaf_pub_cert" != "$_leaf_pub_key" ]]; then
    echo "[05-enable-ssl] REJECTED: postgres_client.crt / postgres_client.key public-key mismatch — refusing to install a non-matching pair." >&2
    exit 1
  fi

  echo "[05-enable-ssl] Server leaf verified (chains to trust bundle, key pair matches) — updating server.crt/server.key"

  # No -o/-g on install — the destination is created by this process
  # (uid999:gid999) and is already owned correctly by construction (see
  # top-of-file note). -o/-g postgres would resolve via /etc/passwd, which is
  # only safe as long as that resolves to the SAME uid/gid the process is
  # already running as; dropped outright so this can never regress silently.
  _leaf_crt_tmp="${PGDATA}/server.crt.new.$$"
  _leaf_key_tmp="${PGDATA}/server.key.new.$$"
  install -m 0644 "${_SECRETS_DIR}/postgres_client.crt" "${_leaf_crt_tmp}"
  install -m 0600 "${_SECRETS_DIR}/postgres_client.key" "${_leaf_key_tmp}"
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
# blocks run before this guard), already owned uid999:gid999 by construction
# (see top-of-file note) — no chown needed. Ensure mode bits are correct in
# case the sync blocks ran before this guard on first-init.
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

# No chown — already owned uid999:gid999 by construction (see top-of-file note).
chmod 0600 "${PGDATA}/pg_hba.conf"

echo "[05-enable-ssl] Done. Postgres will require TLS + client cert for network connections."
