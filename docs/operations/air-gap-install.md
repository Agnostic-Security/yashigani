<!-- last-updated: 2026-05-09T00:00:00+01:00 (feat: air-gap mode + customer-built offline bundle #58, v2.23.3) -->

# Air-Gap Installation

Yashigani v2.23.3 supports fully offline ("air-gapped") installation on hosts
with no outbound internet access.

## Design: customer-builds-the-bundle

Agnostic Security ships a **manifest** (kilobytes), not a blob. The operator
builds the bundle on a connected host using their own registry credentials,
pulls from upstream registries directly, and verifies digests before transfer.
This means:

- No Agnostic Security CDN, no hosting cost, no signing keys we hold
- Customer supply-chain attestation (SBOM, cosign, Notary v2) is applied by the
  customer, not delegated to us
- Operator can exclude profiles they do not deploy (e.g. skip Wazuh)
- Reproducible: rebuild the bundle from the same manifest at any time

The pinned `airgap/manifest.yml` (committed to the repo) is the single source
of truth. Every image in `docker/docker-compose.yml` and `helm/yashigani/values.yaml`
is listed in this manifest at matching `name:tag@sha256:digest`.

---

## Prerequisites

### Connected host (bundle builder)

| Requirement | Notes |
|---|---|
| `podman` or `docker` | Image pull + save |
| `python3` | Manifest YAML parsing |
| `zstd` | Bundle compression (`apt install zstd` / `brew install zstd`) |
| Registry access | Direct access to `docker.io`, `ghcr.io`, `quay.io` |
| Disk space | ~8 GB for `core` profile; ~20 GB for `full` |

### Isolated host (installation target)

| Requirement | Notes |
|---|---|
| `podman` or `docker` | Image load |
| `python3` | Manifest parse during install |
| `zstd` | Bundle unpack |
| Disk space | Same as above (plus runtime data) |
| No network required | All outbound fetches are blocked by `--air-gap` |

---

## Step 1 — Build the bundle (connected host)

Clone the Yashigani repository and checkout v2.23.3:

```bash
git clone https://github.com/agnosticsec-com/yashigani.git
cd yashigani
git checkout v2.23.3
```

Run the bundle builder. Choose a profile:

```bash
# Minimal: gateway, backoffice, postgres, pgbouncer, OPA, Redis, Caddy, Ollama
./scripts/prepare-airgap-bundle.sh --profile core

# Core + observability (Grafana, Loki, Prometheus, Jaeger, OTel)
./scripts/prepare-airgap-bundle.sh --profile core --profile observability

# Full bundle: core + observability + Open WebUI
./scripts/prepare-airgap-bundle.sh --profile full

# Core + Wazuh SIEM
./scripts/prepare-airgap-bundle.sh --profile core --profile wazuh

# Dry-run to see what would be included without pulling
./scripts/prepare-airgap-bundle.sh --profile core --dry-run
```

Additional flags:

```
--runtime podman|docker   Force a specific container runtime (auto-detected)
--output  DIR             Directory to write the bundle into (default: .)
--no-build                Skip building gateway/backoffice from source
--version VER             Override the version string in the bundle filename
```

The builder will:

1. Pull each image from its upstream registry
2. Verify the pulled image digest against `airgap/manifest.yml` (fail-closed)
3. Save each image to an individual `.tar` file
4. Pack all tars into a `zstd`-compressed bundle
5. Write a sidecar `.manifest` file with the bundle SHA256 and image list

Output:

```
yashigani-airgap-v2.23.3-core.tar.zst     (the bundle — transfer this)
yashigani-airgap-v2.23.3-core.manifest    (sidecar — transfer this)
```

---

## Step 2 — Transfer to the isolated host

Transfer the following files via removable media, secure file transfer, or
whichever out-of-band method your security policy permits:

```
yashigani-airgap-v2.23.3-core.tar.zst
yashigani-airgap-v2.23.3-core.manifest
install.sh
airgap/manifest.yml
```

**Verify the bundle before installation** (optional but recommended):

```bash
# The expected SHA256 is in the sidecar .manifest file
grep "Bundle SHA256" yashigani-airgap-v2.23.3-core.manifest
sha256sum yashigani-airgap-v2.23.3-core.tar.zst
```

---

## Step 3 — Install on the isolated host

```bash
./install.sh \
  --air-gap \
  --bundle yashigani-airgap-v2.23.3-core.tar.zst \
  --domain yashigani.internal.example.com \
  --tls-mode selfsigned \
  --deploy production \
  --runtime podman
```

The `--air-gap` flag:

- Requires `--bundle <path>` (exits non-zero if omitted)
- Verifies the bundle's SHA256 against the sidecar `.manifest` (if present)
- Unpacks the bundle and loads each image via `podman load` / `docker load`
- Verifies each loaded image digest against `airgap/manifest.yml` (fail-closed:
  digest mismatch aborts before any service starts)
- Skips ALL outbound fetches: registry pulls, HIBP, ACME, npm, PyPI, GitHub releases
- Forces `--tls-mode selfsigned` (ACME requires outbound connectivity)
- Skips HIBP password breach check (see below)

### Pre-flight gate (G20)

The air-gap pre-flight gate (`G20`) in `scripts/preflight.sh` verifies:

| Gate | Check |
|---|---|
| G20a | Bundle file exists |
| G20b | `airgap/manifest.yml` present beside `install.sh` |
| G20c | Manifest parses and contains a version field |
| G20d | `zstd` is installed |
| G20e | Sidecar `.manifest` present (warn-only if absent) |

### Non-interactive air-gap install

```bash
./install.sh \
  --air-gap \
  --bundle yashigani-airgap-v2.23.3-core.tar.zst \
  --non-interactive \
  --deploy production \
  --domain yashigani.internal \
  --admin-email admin@example.com \
  --runtime podman
```

---

## HIBP (Have I Been Pwned) in air-gap mode

`--air-gap` implies `--no-hibp`. The installer generates passwords locally but
cannot reach `api.pwnedpasswords.com` to verify them against the breach database.

**Operator action:** Use a strong password policy at your organisation's level.
If a breach is suspected (e.g. the isolated network was compromised), rotate all
passwords via the admin API once network access is available:

```bash
./install.sh --pki-action rotate-leaves
# Then via the admin API or backoffice UI:
POST /api/v1/admin/rotate-secret  {"secret": "all"}
```

---

## Open WebUI in air-gap mode

Open WebUI is included in the `full` profile bundle. If you use `--profile core`,
Open WebUI is not bundled and `--with-openwebui` will fail (no image).

Options:
- Include it in the bundle: `--profile full` or `--profile core --profile openwebui`
- Ship a separate Open WebUI bundle under your own supply-chain process and load
  it manually before running `install.sh --air-gap`

---

## Supply-chain provenance

The `.manifest` sidecar file records:

- Bundle SHA256
- List of images with their `name:tag@sha256:digest` references
- Which profiles are included
- Build timestamp and runtime used

**Retain the sidecar as supply-chain provenance evidence.** Cross-reference it
against `airgap/manifest.yml` to produce your SBOM entry for this deployment.
If your organisation uses `cosign` or Notary v2, sign the bundle SHA256 entry in
your internal attestation store before transfer.

---

## Updating an air-gapped installation

Air-gap installs do not have automatic update paths. To update:

1. On the connected host: rebuild the bundle from the new release manifest
   ```bash
   git fetch && git checkout v2.23.4  # or whichever version
   ./scripts/prepare-airgap-bundle.sh --profile core
   ```
2. Transfer the new bundle to the isolated host
3. Run the installer in upgrade mode:
   ```bash
   ./install.sh --air-gap --bundle yashigani-airgap-v2.23.4-core.tar.zst --upgrade
   ```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `--air-gap requires --bundle` | `--air-gap` passed without `--bundle` | Add `--bundle <path>` |
| `Bundle not found` | Path typo or file not transferred | Verify path; re-transfer |
| `BUNDLE INTEGRITY FAILURE` | Bundle corrupted or tampered | Re-transfer; compare SHA256 |
| `DIGEST MISMATCH` | Image altered after pull; wrong manifest | Rebuild bundle from clean pull |
| `Failed to unpack bundle` | `zstd` not installed | `apt install zstd` |
| `airgap/manifest.yml not found` | Manifest not transferred | Copy `airgap/manifest.yml` alongside `install.sh` |
| `G20d: zstd not found` | Missing dependency | `apt install zstd` / `brew install zstd` |
