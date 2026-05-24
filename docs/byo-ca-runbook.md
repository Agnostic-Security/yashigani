# BYO Internal CA Runbook

**Product:** Yashigani  
**Version:** v2.24.1+  
**Audience:** Operators with an existing enterprise PKI  
**Design authority:** `internal-docs/yashigani/iris-v240-byo-internal-ca-design.md`

---

## Overview

Yashigani generates its own internal CA at install time and uses it to issue
mTLS leaf certificates for all services. If your organisation has an existing
internal CA (corporate PKI), you can configure Yashigani to use your CA to
sign the internal service-to-service leaf certs.

This replaces the Yashigani-generated intermediate CA with your own. The edge
TLS certificate (the cert your browsers see for `https://your-domain`) is
separate and is not affected by this runbook.

**What Yashigani needs from you:**

| File | Description |
|---|---|
| `intermediate.pem` | Your intermediate CA certificate (PEM format) |
| `intermediate.key` | Private key for the intermediate certificate (PEM format) |
| `root.pem` | Your root CA certificate (PEM format, the trust anchor) |

Yashigani uses your intermediate to sign internal leaf certs. Your root cert
becomes the trust anchor that all services use to verify each other.

Your root private key is **never** required.

---

## Two activation paths

### Path A: Provide at install time

Pass the flags when running the installer:

```bash
./install.sh \
  --with-internal-ca \
  --internal-ca-cert /absolute/path/to/intermediate.pem \
  --internal-ca-key  /absolute/path/to/intermediate.key \
  --internal-ca-root /absolute/path/to/root.pem
```

All flags must be absolute paths. Tilde (`~`) is not accepted.

### Path B: Install first, provide CA later (deferred)

**Step 1:** Run the installer with `--with-internal-ca` alone. Yashigani
installs with its own generated PKI and writes a `.byo_ca_pending` sentinel
to signal that BYO CA activation is deferred.

```bash
./install.sh --with-internal-ca
```

**Step 2:** When you are ready to switch to your CA, run the installer again
with the cert flags against the existing install:

```bash
./install.sh \
  --internal-ca-cert /absolute/path/to/intermediate.pem \
  --internal-ca-key  /absolute/path/to/intermediate.key \
  --internal-ca-root /absolute/path/to/root.pem
```

The installer detects the existing install (via `ca_root.crt` or
`.byo_ca_pending` sentinel) and routes to the BYO CA activation path. The
full install does not re-run.

---

## CA requirements

Your intermediate CA certificate must satisfy all of the following:

| Check | Requirement |
|---|---|
| Format | PEM (`-----BEGIN CERTIFICATE-----`) |
| Valid X.509 | Parses without error (`openssl x509 -in cert.pem -noout`) |
| Key matches cert | Modulus of cert equals modulus of private key |
| Chain valid | `openssl verify -CAfile root.pem intermediate.pem` exits 0 |
| Not expired | `notBefore <= now <= notAfter` |
| Key strength | RSA >= 2048 bits or EC >= P-256 |
| CA:true | `openssl x509 -noout -text -in intermediate.pem` shows `CA:TRUE` |
| Root self-signs | `openssl verify -CAfile root.pem root.pem` exits 0 |
| Absolute path | All paths passed to installer must start with `/` |
| File size | Each file must be <= 65536 bytes |

The installer validates all of these before writing any files to disk.
Validation failure exits non-zero with a specific error message.

---

## What happens during activation

1. **Backup**: existing `ca_root.crt`, `ca_intermediate.crt`, and
   `ca_intermediate.key` are copied to `docker/backups/byo_ca_<timestamp>/`.

2. **Stage**: your intermediate cert, key, and root cert are copied into
   `docker/secrets/` as `byo_ca_intermediate.crt`, `byo_ca_intermediate.key`,
   and `byo_ca_root.crt`.

3. **Manifest update**: `docker/service_identities.yaml` is updated to set
   `ca_source.mode: byo_intermediate` and the paths to your CA files.

4. **PKI bootstrap**: the issuer (`issuer.py`) reads your intermediate CA and
   issues new leaf certificates for all services (gateway, backoffice,
   pgbouncer, postgres, redis, etc.) signed by your intermediate.

5. **Key ownership**: leaf private keys are chowned to the correct container
   UIDs (`_pki_chown_client_keys`).

6. **Postgres trust-bundle sync**: the postgres container's `PGDATA/root.crt`
   is updated to contain your root + intermediate certificate bundle. This
   happens via `docker exec` into the running postgres container (or at next
   start if postgres is not running). A `pg_ctl reload` is issued so postgres
   picks up the new trust bundle without a full restart.

7. **Sentinel cleared**: the `.byo_ca_pending` file (if present) is removed.

8. **Mode written**: `YASHIGANI_BYO_CA_MODE=byo_intermediate` is written to
   `docker/.env` so future re-runs know the install is in BYO mode.

**If the stack is running**, the installer restarts core services
(`gateway backoffice pgbouncer redis budget-redis policy`) to pick up the
new leaf certs. Postgres is reloaded in-place (no restart).

---

## Postgres PGDATA trust bundle

The postgres trust bundle (`PGDATA/root.crt`) is written once at database
initialisation and is not updated by postgres automatically. When you activate
a BYO CA on an existing install, Yashigani runs the idempotent
`05-enable-ssl.sh` script inside the running postgres container to update
`PGDATA/root.crt` atomically and issue a `pg_ctl reload`.

If the installer cannot reach the postgres container (not running, exec fails),
it prints a warning. In that case, restart postgres manually after activation:

```bash
docker compose -f docker/docker-compose.yml restart postgres
```

Postgres will pick up the updated `ca_root.crt` and `ca_intermediate.crt`
from `docker/secrets/` via the bind mount on next startup.

---

## Verifying the swap

After activation, verify the cert chain:

```bash
# Verify gateway leaf cert against your root
docker exec yashigani-gateway-1 \
  openssl verify -CAfile /run/secrets/byo_ca_root.crt \
                 /run/secrets/gateway_client.crt

# Verify pgbouncer leaf cert
docker exec yashigani-pgbouncer-1 \
  openssl verify -CAfile /run/secrets/byo_ca_root.crt \
                 /run/secrets/pgbouncer_client.crt

# Verify postgres trust bundle was updated
docker exec yashigani-postgres-1 bash -c \
  'sha256sum "${PGDATA}/root.crt"'
# Compare with: sha256sum docker/secrets/byo_ca_root.crt docker/secrets/byo_ca_intermediate.crt
# (concatenated) -- should match
```

For automated verification, use the test script in this release:

```bash
bash tests/byo-ca/scenario-2/test-scenario-2.sh --phase4
```

The test script covers cert-chain verification, PGDATA trust-bundle SHA
comparison, and compose service health checks.

---

## CA renewal (intermediate expires)

When your intermediate CA certificate approaches expiry, generate a new
intermediate signed by your root and run the re-run path:

```bash
./install.sh \
  --internal-ca-cert /absolute/path/to/new_intermediate.pem \
  --internal-ca-key  /absolute/path/to/new_intermediate.key \
  --internal-ca-root /absolute/path/to/root.pem
```

The installer detects the existing BYO CA install (`YASHIGANI_BYO_CA_MODE=byo_intermediate`
in `.env`) and re-runs the activation path with the new intermediate. All leaf
certs are re-issued. The postgres trust-bundle sync runs as part of this flow.

The root cert does not need to change unless your root itself is rotating.

---

## Reverting to Yashigani-generated PKI

To revert to a Yashigani-generated PKI:

```bash
./install.sh --pki-action=bootstrap --reset-ca
```

This clears `docker/secrets/byo_ca_*`, regenerates the internal CA, and
re-issues all leaf certs. The postgres PGDATA trust-bundle sync runs
automatically. The `YASHIGANI_BYO_CA_MODE` flag is removed from `.env`.

The old BYO CA files remain in `docker/backups/` for audit purposes.

---

## Troubleshooting

### Validation error: "cert is not a CA cert"

Your intermediate PEM does not have the `CA:TRUE` basic constraint. This is
enforced to prevent a leaf certificate from being used as a signing CA.
Request a new intermediate from your PKI team with `CA:TRUE`.

### Validation error: "chain invalid"

`openssl verify -CAfile root.pem intermediate.pem` returned non-zero. The
intermediate is not signed by the provided root. Verify you are providing the
correct root for this intermediate.

### Validation error: "key does not match cert"

The private key and certificate are not a pair. This commonly happens when
the key file was regenerated after the certificate was issued. Use the key
that corresponds to the `intermediate.pem` certificate.

### Postgres still rejecting clients after swap

If clients report `SSL error: certificate verify failed` after the swap:

1. Check whether the postgres trust bundle was updated:
   ```bash
   docker exec yashigani-postgres-1 bash -c \
     'openssl x509 -in "${PGDATA}/root.crt" -noout -subject'
   ```
2. If it still shows the old Yashigani root, restart postgres:
   ```bash
   docker compose -f docker/docker-compose.yml restart postgres
   ```
   Postgres will pick up `docker/secrets/ca_root.crt` (your new root) via
   the bind mount and re-run `05-enable-ssl.sh` at startup.

### Services still using old certs after swap

If you see TLS handshake errors between services, confirm the services were
restarted after activation. The installer restarts core services automatically
if the stack was running. If you ran activation with the stack stopped, start
the stack:

```bash
docker compose -f docker/docker-compose.yml up -d
```
