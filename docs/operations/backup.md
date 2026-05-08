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

## Compliance notes

| Control | Standard | Status |
|---------|----------|--------|
| MP.L2-3.8.9 | CMMC L2 | CLOSED — backups encrypted with AES-256-GCM via age |
| CWE-312 | CWE | CLOSED — no cleartext sensitive data at rest in backup archives |

Evidence artefact: `scripts/backup.sh` + this document.

---

*Last updated: 2026-05-09T00:00:00+01:00 — v2.23.3*
