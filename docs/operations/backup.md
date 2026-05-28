<!-- last-updated: 2026-05-09T00:00:00+01:00 (v2.23.3) -->

# Yashigani Backup and Restore

This document covers backup creation, encryption, and restore for all supported
runtimes (Docker, Podman, Kubernetes).

---

## Overview

Yashigani produces two types of backup:

| Type | Produced by | Format | Runtime |
|------|-------------|--------|---------|
| Upgrade snapshot | `install.sh` `_backup_existing_data()` | Directory under `backups/<timestamp>/` | Docker, Podman, K8s |
| Operator backup | `scripts/backup.sh` | `backups/<timestamp>.tar.gz.age` (encrypted) | Any host with `age` installed |

The operator backup (v2.23.3+) satisfies **MP.L2-3.8.9** (CMMC L2 — backup
media protection) and closes the CWE-312 (cleartext storage) finding.

---

## Encryption

Backups created by `scripts/backup.sh` are encrypted with
[age](https://age-encryption.org/) using X25519 asymmetric encryption
(AES-256-GCM, AEAD). The recipient public key is used to encrypt; only the
holder of the matching identity (private key) can decrypt.

### Why age?

- Modern, audited, minimal attack surface (no key management ceremony required)
- Asymmetric: the backup job only needs the public key — no private key at rest on the server
- Binary output (not ASCII-armored) — saves disk space

---

## Operator key setup

Perform this once before enabling backups. Keep the identity key offline or in a
hardware security module. **Loss of the identity key means encrypted backups
cannot be decrypted.**

```bash
# 1. Generate key pair — run on a secure, air-gapped host or HSM
age-keygen -o /etc/yashigani/backup-identity.age
# Output:
#   Public key: age1abc123...   ← copy this value
#   Wrote to:   /etc/yashigani/backup-identity.age

# 2. Lock down the private key
chmod 0400 /etc/yashigani/backup-identity.age

# 3. Extract recipient public key to the file backup.sh reads
age-keygen -y /etc/yashigani/backup-identity.age \
  > /etc/yashigani/backup-recipient.age.pub
chmod 0444 /etc/yashigani/backup-recipient.age.pub

# 4. Verify the recipient file looks correct
cat /etc/yashigani/backup-recipient.age.pub
# Expected output:  age1abc123...  (a single line starting with age1)
```

Store the identity file (`/etc/yashigani/backup-identity.age`) in:
- A password manager (1Password, Bitwarden)
- An offline encrypted vault
- A hardware key (YubiKey PIV slot or similar)

**Do NOT commit the identity file to git or store it in a cloud provider
alongside the backups it protects.**

---

## Running a backup

```bash
# Minimal invocation (uses defaults from /etc/yashigani/)
bash scripts/backup.sh

# Explicit paths
bash scripts/backup.sh \
  --recipient-key /etc/yashigani/backup-recipient.age.pub \
  --output-dir /var/lib/yashigani/backups \
  --source-dir /var/lib/yashigani

# Dry-run (validates configuration without writing anything)
bash scripts/backup.sh --dry-run
```

Output file: `/var/lib/yashigani/backups/<timestamp>.tar.gz.age`

The output file is created with mode `0400` (owner read-only). The output
directory is created with mode `0700` if it does not already exist.

---

## Restoring from an encrypted backup

```bash
# One-step decrypt + restore
bash restore.sh \
  --encrypted /etc/yashigani/backup-identity.age \
  /var/lib/yashigani/backups/20260509_020000.tar.gz.age

# Or set identity via environment
YASHIGANI_BACKUP_IDENTITY_FILE=/etc/yashigani/backup-identity.age \
  bash restore.sh /var/lib/yashigani/backups/20260509_020000.tar.gz.age

# Kubernetes restore
bash restore.sh --k8s -n yashigani \
  --encrypted /etc/yashigani/backup-identity.age \
  /var/lib/yashigani/backups/20260509_020000.tar.gz.age
```

Legacy unencrypted backups (`.tar.gz` or directory path) are still accepted
with a deprecation warning. Plan to migrate to encrypted backups before the
next compliance assessment.

---

## Kubernetes CronJob

Enable the scheduled backup in your Helm values:

```yaml
backup:
  enabled: true
  schedule: "0 2 * * *"   # 02:00 UTC daily
  recipientKeyConfigMap: "yashigani-backup-recipient"   # REQUIRED
  identitySecret: "yashigani-backup-identity"           # for restore only
  outputDir: "/var/lib/yashigani/backups"
  pvcName: "my-backup-pvc"    # OR set pvc.create: true
```

Provision the ConfigMap and Secret before enabling:

```bash
# ConfigMap — holds the public key (encryption only; safe to store in-cluster)
kubectl create configmap yashigani-backup-recipient \
  --from-literal=recipient.age.pub="age1abc123..." \
  -n yashigani

# Secret — holds the private key (restore only; consider storing offline instead)
kubectl create secret generic yashigani-backup-identity \
  --from-file=identity.age=/etc/yashigani/backup-identity.age \
  -n yashigani
```

The backup CronJob mounts ONLY the ConfigMap (public key). The identity Secret
is not mounted by the backup job — it is referenced in values for restore
documentation purposes only. Keep a copy of the identity key outside the cluster.

---

## Key rotation runbook

Rotate backup keys when:
- A key may be compromised
- An operator with key access leaves the organisation
- The key is more than 12 months old (recommended)

```bash
# 1. Generate new key pair
age-keygen -o /tmp/backup-identity-new.age
chmod 0400 /tmp/backup-identity-new.age

# 2. Extract new recipient key
age-keygen -y /tmp/backup-identity-new.age > /tmp/backup-recipient-new.age.pub

# 3. Re-encrypt any existing archives you need to keep decryptable under the new key
#    (decrypt with old identity, re-encrypt with new recipient)
for f in /var/lib/yashigani/backups/*.tar.gz.age; do
  age --decrypt --identity /etc/yashigani/backup-identity.age "$f" \
    | age --encrypt --recipient "$(cat /tmp/backup-recipient-new.age.pub)" \
        --output "${f%.age}.rotated.age"
done

# 4. Install new keys
mv /tmp/backup-identity-new.age /etc/yashigani/backup-identity.age
chmod 0400 /etc/yashigani/backup-identity.age
mv /tmp/backup-recipient-new.age.pub /etc/yashigani/backup-recipient.age.pub

# 5. K8s: update ConfigMap and Secret
kubectl create configmap yashigani-backup-recipient \
  --from-file=recipient.age.pub=/etc/yashigani/backup-recipient.age.pub \
  -n yashigani --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic yashigani-backup-identity \
  --from-file=identity.age=/etc/yashigani/backup-identity.age \
  -n yashigani --dry-run=client -o yaml | kubectl apply -f -

# 6. Verify next backup uses the new key
bash scripts/backup.sh --dry-run
```

---

## Retention

Backups are not automatically pruned by the CronJob. Implement retention via:

```bash
# Remove backups older than 30 days
find /var/lib/yashigani/backups -name "*.tar.gz.age" -mtime +30 -delete
```

Add this to a cron job or a Kubernetes post-backup hook appropriate to your
retention policy and regulatory requirements.

---

## Pre-flight check (G19)

`scripts/preflight.sh` includes Gate G19 which checks:

1. `age` binary is present in PATH
2. The recipient public key file exists and starts with `age1`

Run before deployment:

```bash
bash scripts/preflight.sh
# Look for:
#   PASS  Backup encryption (G19)   age present (v1.2.1)
#   PASS  Backup recipient key (G19) /etc/yashigani/backup-recipient.age.pub — age1abc...
```

---

## Security properties

> This section covers the install-time backup produced by `install.sh` `_backup_existing_data()`
> (v2.25.0+, closes YSG-RISK-050/051). The operator backup produced by `scripts/backup.sh` uses
> age asymmetric encryption (see sections above).

The install-time backup uses a dual-wrap AES-256-GCM envelope (CNSA-2.0 symmetric suite,
Nico-verified). The bundle is encrypted with a random DEK wrapped under two independent KEKs —
EITHER wrap can recover the DEK.

### Wrap#1 — admin-password path (everyday restore)

- The admin password **is not stored** in the backup. At backup time, the raw 32-byte argon2
  verifier (V) is extracted from the stored PHC in the database; V is used as IKM for
  HKDF-SHA384 → KEK1. No argon2 call is made at backup time; no plaintext password is needed.
- At restore time, `argon2id_raw(typed_plaintext, argon2_salt_from_meta, params_from_meta)` is
  computed. If the password is unchanged this equals V → same KEK1 → successful unwrap.
- argon2 parameters (salt, time_cost, memory_cost, parallelism, version) are stored in
  `backup-meta.json` in cleartext. This is sound: the salt is non-secret (already in the DB PHC).

### Wrap#2 — recovery path (license/local-key)

- **Licensed tier:** IKM2 = raw bytes of the `.ysg` license file. The DEK can be recovered via
  the portal — download your `.ysg` file and pass it to `restore.sh --recovery-license <file>`.
  The portal retains prior `.ysg` files keyed by `license_id` (contact support if needed).
- **Community tier:** IKM2 = `YASHIGANI_DB_AES_KEY` from `docker/.env`. This key is LOCAL —
  **there is NO portal recovery**. If you lose both the backup and your `.env`, the backup is
  unrecoverable. **Safeguard and offsite your `.env` before taking backups.**

### FIPS_MODE=1

Under `FIPS_MODE=1`, wrap#1 (admin-password path) is **ABSENT** — there is NO password-recovery
path. Only wrap#2 (license/local-key) is written. This is inherent: argon2id is not FIPS-approved,
and PBKDF2 cannot reproduce an argon2 verifier (different function, different output). Restore under
FIPS requires `--recovery-license` or `--recovery-key`.

### DB-holder property (inherent, documented)

Because KEK1 = HKDF(V) and V is the stored verifier, **an attacker holding the live database
obtains V directly and can derive KEK1 without knowing the plaintext password.** This is inherent
to non-interactive backup with password recovery — there is no sound alternative (Nico-confirmed).

This is acceptable for the intended threat model: backups exist for disaster recovery (database
gone → password is the credential). An attacker with both the live database and the backup file
already owns the running system.

**wrap#1 separates the backup from an attacker who holds the backup file but not the live DB.**
**An attacker holding BOTH the live DB (which contains the stored verifier V) and the backup file
can derive KEK1 without knowing the plaintext password. wrap#2 (license/local-key) is the
protection against an attacker holding both assets; it requires a separate credential not stored
in the DB.**

### Integrity and tamper protection

- `backup-meta.json` is covered by HMAC-SHA384 (MAC_KEY derived via HKDF-SHA384 from the DEK).
  The HMAC is verified before any decryption attempt; tampered metadata causes fail-closed.
- `bundle.enc` is AES-256-GCM; the GCM tag authenticates both ciphertext and `backup-meta.json`
  (passed as AAD). Tampering with either causes fail-closed (InvalidTag).
- AAD includes version string + timestamp + wrap-id byte — prevents cross-backup and cross-wrap
  substitution attacks.

### Key hierarchy summary

```
DEK = os.urandom(32)
MAC_KEY = HKDF-SHA384(DEK, info="yashigani-backup-meta-mac-v1", len=48)
-- Wrap#1 (FIPS_MODE=0 only) --
  V = base64decode(PHC_hash_segment)  # NO argon2 call at backup
  KEK1 = HKDF-SHA384(V, kek1_hkdf_salt, info="yashigani-kek1-v1", len=32)
  WDEK1 = AES-256-GCM(KEK1, IV1, aad="yashigani-backup-v1"+ts+\x01, pt=DEK)
-- Wrap#2 (always) --
  IKM2 = .ysg bytes (licensed) | YASHIGANI_DB_AES_KEY (community)
  KEK2 = HKDF-SHA384(IKM2, kek2_hkdf_salt, info="yashigani-kek2-v1", len=32)
  WDEK2 = AES-256-GCM(KEK2, IV2, aad="yashigani-backup-v1"+ts+\x02, pt=DEK)
-- Bundle --
  CT = AES-256-GCM(DEK, IV_B, aad=meta_bytes_with_hmac_hex="", pt=gzip_tar)
  hmac_hex = HMAC-SHA384(MAC_KEY, aad_bytes)
```

All salts are per-backup random (stored in `backup-meta.json`). No fixed derived-key files.

---

## Compliance notes

| Control | Standard | Status |
|---------|----------|--------|
| MP.L2-3.8.9 | CMMC L2 | CLOSED — backups encrypted with AES-256-GCM via age |
| CWE-312 | CWE | CLOSED — no cleartext sensitive data at rest in backup archives |
| YSG-RISK-050 | Internal | CLOSED — install-time backup: AES-256-GCM dual-wrap (v2.25.0+) |
| YSG-RISK-051 | Internal | CLOSED — install-time backup: HMAC-SHA384 manifest integrity (v2.25.0+) |
| YSG-RISK-052 | Internal | DOCUMENTED — community tier: local-key-only, no portal recovery; see above |

Evidence artefact: `scripts/backup.sh` + `install.sh` `_backup_existing_data()` + this document.

---

*Last updated: 2026-05-28T00:00:00+01:00 — v2.25.0 (Security properties section added — YSG-RISK-050/051/052; Nico ruling 2026-05-28)*
