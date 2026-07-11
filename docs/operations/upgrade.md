<!-- last-updated: 2026-05-10T11:30:00+01:00 (v2.23.3) -->

# Yashigani Upgrade Guide

This document covers upgrading Yashigani across versions, with specific notes
for the v2.22.2 → v2.23.3 N-1 upgrade path validated during release testing.

---

## Upgrade paths

| From | To | Supported | Notes |
|------|----|-----------|-------|
| v2.22.2 | v2.23.3 | Yes | Admin accounts **not** migrated — see §Admin account migration below |
| v2.23.2 | v2.23.3 | Yes | Standard `update.sh` path |
| v2.23.2.x | v2.23.3 | Yes | Standard `update.sh` path |

---

## Quick start (Docker/Podman)

```bash
# 1. Pull the new release
git fetch && git checkout v2.23.3

# 2. Run the updater
bash update.sh

# 3. Verify services
docker compose -f docker/docker-compose.yml ps    # or podman compose
curl -sk https://<your-domain>/healthz
```

---

## REQUIRED for K8s operators on arm64 nodes

> **DEFECT-N1-003 — BLOCKER for arm64 K8s operations**

The Yashigani bootstrap job image is published as an `amd64` manifest by
default in the Helm chart. On **arm64 Kubernetes nodes** (Apple Silicon
development clusters, Ampere-based cloud nodes) the bootstrap job fails
with `ImagePullBackOff` because the `amd64` image cannot run on `arm64`.

**You must set the following Helm values when upgrading or installing on
any arm64 K8s cluster:**

```bash
helm upgrade yashigani ./helm/yashigani \
  --namespace yashigani \
  --set global.imageRegistry=localhost:5000 \
  --set global.imageOwner=local \
  [... other flags ...]
```

Alternatively, in your `values.yaml`:

```yaml
global:
  imageRegistry: localhost:5000
  imageOwner: local
```

**Why:** The `localhost:5000` registry must be pre-populated with arm64
builds of all Yashigani images before running Helm. Build and push:

```bash
# On the arm64 node or a connected arm64 machine:
docker buildx build --platform linux/arm64 \
  -t localhost:5000/local/yashigani-gateway:v2.23.3 \
  -f docker/Dockerfile.gateway . --push

docker buildx build --platform linux/arm64 \
  -t localhost:5000/local/yashigani-backoffice:v2.23.3 \
  -f docker/Dockerfile.backoffice . --push

# (Repeat for all images in helm/yashigani/values.yaml)
```

**Without these flags, the bootstrap job will ImagePullBackOff and the
upgrade will not complete.** This is the most common failure mode on
arm64 K8s clusters.

---

## Admin account migration — REQUIRED reading for all upgrades from v2.22.2

> **DEFECT-N1-002 — EXPECTED behaviour, not a bug**

**Yashigani v2.22.2 stored admin accounts in memory.** Admin sessions were
not persisted across restarts — each restart required re-running the bootstrap.

**Yashigani v2.23.3 stores admin accounts in Postgres** (`admin_accounts` table).
The v2.22.2 in-memory admin credentials are **not migrated** to Postgres during
the upgrade. The upgrade process regenerates fresh admin credentials via the
bootstrap job.

### What this means for operators

After upgrading from v2.22.2 to v2.23.3:

1. **Previous admin usernames and passwords no longer work.** The accounts do
   not exist in the new Postgres-backed store.
2. **Bootstrap creates new admin credentials.** The upgrade process runs the
   bootstrap job, which generates new admin1 and admin2 credentials.
3. **You must capture the new credentials before communicating them to admins.**

### How to retrieve the new admin credentials (K8s)

```bash
# Find the bootstrap secret (created by the bootstrap job):
kubectl get secret -n yashigani | grep -i admin

# Example output:
#   yashigani-admin-bootstrap   kubernetes.io/opaque   6      2m

# Retrieve the credentials:
kubectl get secret yashigani-admin-bootstrap -n yashigani \
  -o jsonpath='{.data.admin1_username}' | base64 -d
kubectl get secret yashigani-admin-bootstrap -n yashigani \
  -o jsonpath='{.data.admin1_password}' | base64 -d
kubectl get secret yashigani-admin-bootstrap -n yashigani \
  -o jsonpath='{.data.admin1_totp_secret}' | base64 -d

# Repeat for admin2_*
```

### How to retrieve the new admin credentials (Docker/Podman)

```bash
# Secrets are written to docker/secrets/ during bootstrap:
cat docker/secrets/admin1_username
cat docker/secrets/admin1_password
cat docker/secrets/admin1_totp_secret

cat docker/secrets/admin2_username
cat docker/secrets/admin2_password
cat docker/secrets/admin2_totp_secret
```

> **Before completing the upgrade**, ensure you have communicated the new
> credentials to all admin users. Operators who have not received the new
> credentials will be locked out immediately after the upgrade completes.

---

## TOTP authenticator compatibility

> **DEFECT-N1-001 — LOW, accepted per security baseline**

Yashigani uses **SHA-256** as the TOTP digest algorithm, per the
`feedback_sha256_minimum_pqr.md` security baseline (NIST SP 800-63B alignment).

**Standard RFC 6238 TOTP authenticators that only support SHA-1 will not work**
with Yashigani v2.23.3. This includes older builds of Google Authenticator on
some platforms.

Use a SHA-256-capable authenticator app:

| App | Platform | SHA-256 support |
|-----|----------|-----------------|
| Aegis Authenticator | Android | Yes |
| Bitwarden Authenticator | iOS, Android | Yes |
| 2FAS Authenticator | iOS, Android | Yes |
| Google Authenticator (2022+) | iOS, Android | Yes (check version) |
| Raivo OTP | iOS | Yes |
| Tofu | iOS | Yes |

**How to verify:** When scanning the TOTP QR code, confirm your authenticator
app shows `Algorithm: SHA-256`. If your app does not display this or defaults
to SHA-1, choose a different app from the list above.

**Note:** The TOTP secret files under `docker/secrets/admin1_totp_secret` and
`admin2_totp_secret` are compatible with any SHA-256-capable TOTP app. You can
re-scan the secret from the admin panel (Settings → Two-Factor Authentication).

---

## Kubernetes upgrade procedure (v2.22.2 → v2.23.3)

```bash
# 1. Take a backup (if upgrade snapshot is insufficient)
bash scripts/backup.sh \
  --source-dir docker \
  --output-dir backups \
  --recipient-key /etc/yashigani/backup-recipient.age.pub

# 2. For arm64 nodes: ensure local registry is populated (see §REQUIRED above)

# 3. Run Helm upgrade
helm upgrade yashigani ./helm/yashigani \
  --namespace yashigani \
  --atomic \
  --timeout 10m \
  [--set global.imageRegistry=localhost:5000 --set global.imageOwner=local]  # arm64 only

# 4. Wait for bootstrap job to complete
kubectl wait job/yashigani-bootstrap \
  --namespace yashigani \
  --for=condition=complete \
  --timeout=300s

# 5. Retrieve new admin credentials (see §Admin account migration above)
kubectl get secret -n yashigani | grep -i admin

# 6. Communicate new credentials to admin users

# 7. Verify
curl -sk https://<your-domain>/healthz
```

---

## Docker / Podman upgrade procedure

```bash
# 1. Pull the release
git fetch && git checkout v2.23.3

# 2. Run the updater (handles compose service restart automatically)
bash update.sh

# 3. Retrieve new admin credentials
cat docker/secrets/admin1_username
cat docker/secrets/admin1_password
cat docker/secrets/admin1_totp_secret

# 4. Verify
curl -sk https://localhost/healthz
```

---

## Rollback

If the upgrade fails, restore from the pre-upgrade backup:

```bash
# Restore from operator backup (encrypted):
bash restore.sh --encrypted /etc/yashigani/backup-identity.age \
  backups/<timestamp>.tar.gz.age

# Restore from upgrade snapshot (directory):
bash restore.sh backups/<timestamp>/
```

See `docs/operations/backup.md` for full restore procedures including K8s.

---

## Migration timeline for in-memory admin accounts (v2.22.2 operators)

| Step | When | Who | Action |
|------|------|-----|--------|
| Pre-upgrade | Before upgrade window | Operator | Note all current admin usernames for communication |
| During upgrade | Bootstrap job | Automated | New credentials generated in `admin_accounts` table |
| Post-upgrade | Immediately after | Operator | Retrieve new credentials from bootstrap secret |
| Post-upgrade | Within 1 hour | Operator | Communicate new credentials to all admin users |
| Post-upgrade | Within 24 hours | Admin users | Log in with new credentials + configure TOTP app |

---

*Yashigani Upgrade Guide — 2026-05-10T11:30:00+01:00*
