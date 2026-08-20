<!-- last-updated: 2026-05-29T00:00:00+00:00 (P1/W5/N6 — FIPS 140-3 deployment guide + operator checklist) -->

# FIPS 140-3 Deployment Guide

This document is the operator reference for running Yashigani in FIPS mode.
It covers the validated module boundary, gateway startup requirements, algorithm
constraints, KMS configuration, and the pre-flight checklist required before any
FIPS-mode deployment is declared compliant.

---

## 1. Validated crypto module — CMVP #4985

All FIPS assertions in this deployment are anchored to a single certificate:

| Field | Value |
|---|---|
| Certificate | CMVP #4985 |
| Module name | OpenSSL FIPS Provider |
| Standard | FIPS 140-3, Level 1 (lifecycle assurance Level 3) |
| Status | ACTIVE |
| Validation date | 2025-03-11 (Acumen Security; updated 2025-11-21 Lightship Security Inc.) |
| Expiry (sunset) | 2030-03-10 |
| Source | https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4985 |
| Fetch timestamp | 2026-05-29T00:00:00Z |
| Cache TTL | 30 days — re-fetch required before 2026-06-28 |

**What this covers.** Every Python `cryptography` library operation (RSA, ECDSA, SHA,
HMAC) routes through OpenSSL as a backend via cffi bindings. When the process is
started with the environment variables in §2, those operations execute inside CMVP #4985.
This is the module backing PKI issuance (`_pki_run_issuer`), manifest signing
(RSA-PSS-3072/SHA-384), and MCP identity JWT signing (ES384).

**What this does not cover.** Container base images, Vault community edition, cosign,
and any Go binary in the stack do NOT inherit this certificate. Each is addressed in §7.

---

## 2. Gateway startup — FIPS Provider activation

The OpenSSL FIPS Provider must be active in the gateway process environment at startup.
This is the operator's responsibility; Yashigani does not load the provider at runtime.

### Required environment variables

```
OPENSSL_MODULES=/path/to/openssl/fips.so
OPENSSL_CONF=/etc/ssl/openssl_fips.cnf
```

`OPENSSL_MODULES` points to the directory containing (or the full path to) the FIPS
Provider shared object for your platform. `OPENSSL_CONF` points to an OpenSSL
configuration file that activates the provider and sets `fips = yes`.

### Docker/Podman (compose deployments)

Set `FIPS_MODE=1` via the installer flag or environment variable:

```bash
# Flag
bash install.sh --fips-mode 1 --cmvp-cert "#4985"

# Environment variable equivalent
YSG_FIPS_MODE=1 YSG_CMVP_CERT="#4985" bash install.sh
```

`install.sh` writes `FIPS_MODE=1` and `YSG_CMVP_CERT=#4985` to `docker/.env`.
`docker/docker-compose.yml` (`x-common-env`, line 108) propagates `FIPS_MODE` to
the gateway, backoffice, and Caddy containers. The `YASHIGANI_CMVP_CERT` value is
surfaced by `/admin/crypto/inventory` as runtime attestation evidence for auditors.

**Container image requirement.** `FIPS_MODE=1` activates the FIPS code paths only if
the container base image includes the CMVP #4985-validated FIPS Provider. Standard
Python slim images do not include it. Use a FIPS-configured base image — for example
a RHEL/UBI image with `openssl-fips`, or an AWS BoringCrypto image — and rebuild the
gateway image against it. Without the correct base image, setting `FIPS_MODE=1` routes
code through the FIPS paths but the underlying OpenSSL is not the validated module.

### Kubernetes/Helm

```yaml
fips:
  mode: true
  cmvpCert: "#4985"
```

Or via `--set` flags:

```bash
helm upgrade --install yashigani ./helm/yashigani \
  --set fips.mode=true \
  --set fips.cmvpCert="#4985"
```

`helm/yashigani/values.yaml` (`fips` block, line 1577) controls injection of
`FIPS_MODE=1` into gateway and backoffice containers. The `cmvpCert` value is
passed through and surfaced at the crypto inventory endpoint.

### Verification (pre-flight)

Before opening any traffic, confirm the provider loaded:

```bash
openssl list -providers | grep -i fips
# Expected: name: fips  (with "active" status)
```

If the provider is absent, `lib/yashigani-fips.sh::_fips_assert_provider_loaded`
will emit `ERROR: FIPS_MODE=1 but OpenSSL FIPS provider not loaded` on the first
FIPS-path hash operation and return exit code 1. Treat this as a hard deployment
blocker.

---

## 3. Algorithm inventory in FIPS mode

The table below lists every algorithm Yashigani uses in production paths, its FIPS
approval basis, and its status under FIPS_MODE=1.

| Algorithm | Use | Approval basis | FIPS status |
|---|---|---|---|
| ES384 (ECDSA P-384/SHA-384) | MCP identity JWT signing | FIPS 186-5 Table 1 (P-384 approved); FIPS 180-4 (SHA-384) | APPROVED — via Python `cryptography` + CMVP #4985 |
| RSA-PSS-3072/SHA-384 | Manifest signing | FIPS 186-5 §5 (RSA-PSS); FIPS 180-4 (SHA-384) | APPROVED — via Python `cryptography` + CMVP #4985 |
| SHA-384 / HMAC-SHA-384 | Backup manifest integrity | FIPS 180-4 / FIPS 198-1 | APPROVED — `openssl dgst -sha384` via CMVP #4985 |
| SHA-256 | Install-time integrity checks | FIPS 180-4 | APPROVED — `openssl dgst -sha256` via CMVP #4985 |
| PBKDF2-HMAC-SHA384 | KDF for backup key wrap#2 | SP 800-132 | APPROVED — via Python `cryptography` + CMVP #4985 |
| ECDH P-256 | TLS key exchange (mTLS, leaf certs) | FIPS 186-5; SP 800-56A rev 3 | APPROVED — via CMVP #4985 |
| SHA-512/SHA-256 TOTP (role-tiered) | MFA (HMAC-SHA512 admin / HMAC-SHA256 user, per RFC 6238) | FIPS 180-4 / FIPS 198-1 | APPROVED — both SHA-256 and SHA-512 variants; see note below |
| argon2id | Admin password hash | Not FIPS-approved | BLOCKED in FIPS mode — wrap#1 absent by design |
| cosign/Sigstore | Manifest signature verification | Go `crypto` (BoringCrypto #3678 expired) | BLOCKED in FIPS mode — see §4 |

**TOTP note.** Yashigani uses role-tiered TOTP since v3.1: admin accounts use
HMAC-SHA-512 with 8-digit codes (`algorithm=SHA512&digits=8`); user accounts use
HMAC-SHA-256 with 6-digit codes (`algorithm=SHA256&digits=6`). Both SHA-256 and
SHA-512 are FIPS 180-4 / FIPS 198-1 approved and route through CMVP #4985 when
FIPS Provider is active. Do not use authenticator apps that default to SHA-1
without reading the `algorithm=` parameter from the provisioning URI. agnosticOTP,
Authy, and Raivo all support both SHA-256 and SHA-512.

**argon2id note.** argon2id is a memory-hard function, not a FIPS-approved KDF.
Under `FIPS_MODE=1`, the admin password wrap#1 (argon2id path) is absent by design
(Nico ruling 2026-05-28). Only PBKDF2-HMAC-SHA384 wrap#2 is written. This is
documented in `install.sh` lines 2729-2790.

---

## 4. BLOCKED in FIPS mode — cosign/Sigstore

cosign uses Go's `crypto` package, which does not route through the OpenSSL FIPS
Provider. The BoringCrypto CMVP certificate #3678 expired and has no active replacement.
**cosign is not FIPS-assertable. It is unconditionally blocked in FIPS mode.**

When `YASHIGANI_FIPS=1`:

- `signatures.py::verify_manifest_signature` raises `ManifestSignatureError` if
  `spec.signature.algorithm = cosign-bundled-key` is present in any manifest (FIX-2,
  NICO-005 gate, `signatures.py` lines 367-377).
- This check fires before the `YSG_REQUIRE_SIGNED_MANIFEST` enforcement level — it
  cannot be bypassed with `=warn` or `=skip`.
- Manifest verification routes exclusively to the RSA-PSS-3072/SHA-384 path
  (`rsa-pss-3072-sha384`) in FIPS mode.
- Production manifests MUST be signed with the RSA-PSS-3072 key and include
  `spec.signature.algorithm: rsa-pss-3072-sha384`.

**Signing a manifest in FIPS mode:**

```bash
# Generate the signing key (once, at install time — requires FIPS Provider active)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -out manifest-signing.key

openssl rsa -in manifest-signing.key -pubout -out manifest-signing-fips.pub

# Sign
openssl dgst -sha384 -sigopt rsa_padding_mode:pss \
  -sigopt rsa_pss_saltlen:48 \
  -sign manifest-signing.key -out sig.bin manifest.yaml

# Encode as hex for the manifest field
xxd -p -c 256 sig.bin | tr -d '\n'
```

Verify via CLI:

```bash
yashigani validate manifest.yaml --fips-pubkey manifest-signing-fips.pub
```

---

## 5. MCP identity JWT — ES384 FIPS posture

The gateway-signed JWT that carries MCP caller identity uses ES384 (ECDSA P-384 /
SHA-384). This is FIPS-assertable via the OpenSSL FIPS Provider when the gateway
starts with the environment in §2.

The full signing key spec, claim set, TTL, nonce dedup, JWKS format, and chain
construction rules are in the canonical design authority document:

```
Agnostic Security/Products/Yashigani/mcp-identity-jwt-spec-20260529.md
```

FIPS-specific facts from that spec:

- Key type: EC P-384, generated at install time via `openssl ecparam -genkey -name
  secp384r1` with FIPS Provider active.
- Signing operation: Python `cryptography.hazmat.primitives.asymmetric.ec` ECDSA,
  which routes through CMVP #4985 when `OPENSSL_MODULES` + `OPENSSL_CONF` are set.
- Algorithm assertion at startup: the broker self-test checks that the JWT header
  carries `{"alg": "ES384"}`.
- **ES384 requires NO fallback algorithm in FIPS mode.** It is approved directly.
  The cosign/Go limitation (§4) does not apply to ES384 in Python.

---

## 6. Manifest signing — RSA-PSS-3072/SHA-384

RSA-PSS-3072/SHA-384 is the FIPS-mode manifest signing algorithm. The implementation
is in `src/yashigani/manifest/signatures.py::_verify_rsa_pss`.

Critical implementation constraints that MUST hold in any FIPS deployment:

**RSA key size: exactly 3072 bits.** The `_assert_rsa_3072` guard (`signatures.py`
lines 214-234) enforces this at verification time. Smaller keys fail with
`ManifestSignatureError`. This is a Yashigani policy floor (128-bit security target),
not a CMVP minimum — CMVP #4985 approves RSA >= 2048.

**PSS salt length: `DIGEST_LENGTH` (48 bytes for SHA-384).** This is mandated by
FIPS 186-5 §5.4, which caps salt length at hLen. The `_verify_rsa_pss` implementation
uses `padding.PSS.DIGEST_LENGTH` (`signatures.py` lines 310-315). Using
`padding.PSS.MAX_LENGTH` (333 bytes for RSA-3072/SHA-384) would exceed the FIPS cap
and is explicitly prohibited.

**FIPS Provider must be loaded before calling `_verify_rsa_pss`.** If `YASHIGANI_FIPS=1`
is set but the provider is absent, the function logs a warning
(`_NICO_REVIEW_REQUIRED`) and proceeds — the call succeeds cryptographically but is
not FIPS-assertable. Do not reach this state in production; use the pre-flight
checklist in §9.

---

## 7. PKI leaf cert issuance — `_pki_run_issuer`

Internal leaf certificates (gateway, backoffice, Caddy, agent identities) are issued
by `src/yashigani/pki/issuer.py`, invoked as `_pki_run_issuer` by `install.sh`.

The PKI issuer uses `cryptography.hazmat.primitives.asymmetric.ec` (P-256 for current
leaf keys, `_CURVE = ec.SECP256R1()` at `issuer.py` line 75). P-256 is FIPS 186-5
approved. When `FIPS_MODE=1` and the FIPS Provider is active in the process that runs
`install.sh`, key generation and certificate signing route through CMVP #4985.

**Operator note.** `install.sh` runs the PKI issuer in a container via
`_pki_run_issuer_docker` / `_pki_run_issuer_podman_linux` / `_pki_run_issuer_podman_macos`
(depending on runtime). For FIPS assertability of the PKI bootstrap, that container
must also use a FIPS-configured base image with OpenSSL FIPS Provider loaded. If it
does not, leaf certs are generated with standard OpenSSL and the PKI issuance is not
within the CMVP #4985 boundary — note this in your System Security Plan if using a
non-FIPS base image.

---

## 8. KMS configuration for FIPS deployments

Yashigani supports five KMS backends for secrets and signing keys. FIPS requirements
vary by backend.

### Vault

Vault community edition uses Go `crypto`, which is not FIPS-validated (same issue as
cosign, §4). **FIPS-mode deployments with Vault must use Vault Enterprise FIPS build.**
The Vault Enterprise FIPS build uses BoringCrypto; validate that BoringCrypto
certificate separately before asserting SC.L2-3.13.11 for Vault-backed key operations.

```bash
# Install-time — Vault FIPS Enterprise
install.sh --fips-mode 1 --cmvp-cert "#4985" --kms-provider vault \
  --kms-vault-addr https://vault.internal:8200 \
  --kms-vault-token <narrow-token>
```

Each tenant MUST have a narrow token scoped to its own key paths only. Shared
root tokens are not acceptable for multi-tenant deployments.

### AWS KMS — FIPS endpoints

AWS KMS provides FIPS 140-2 validated endpoints in US regions. Use the FIPS endpoint:

```
https://kms.<region>.amazonaws.com
```

Replace with:

```
https://kms-fips.<region>.amazonaws.com
```

Set `AWS_KMS_FIPS_ENDPOINT=1` in the gateway environment, or configure the KMS client
endpoint URL explicitly. Per-tenant IAM: each tenant's gateway process MUST use an IAM
role with `kms:Sign`, `kms:Verify`, `kms:GetPublicKey` scoped to only that tenant's
key ARN. ABAC via `PrincipalTag/yashigani-tenant` is the recommended pattern.

### Azure Key Vault

Azure Key Vault is FIPS 140-2 Level 2 validated (HSMs are Level 3). No separate FIPS
endpoint is required — the standard endpoint uses FIPS-validated hardware. Per-tenant
configuration: each tenant's managed identity or service principal MUST have
`Key Sign`, `Key Verify`, and `Key Get` permissions scoped to that tenant's key vault
only. Do not share a vault across tenants.

### GCP Cloud KMS

GCP Cloud KMS uses FIPS 140-2 Level 3 validated HSMs. No separate FIPS endpoint is
required. Workload Identity Federation is the recommended auth pattern. Per-tenant
scoping: each tenant's Workload Identity should be bound to a specific key ring and
key name.

### Keeper

For Keeper-backed deployments, the Keeper EC key bytes are loaded into the gateway
process and signing is performed in-process via OpenSSL FIPS Provider. The Keeper
storage vault itself is not within the CMVP #4985 boundary; Keeper handles its own
encryption. The signing operation — once the key is loaded — is within CMVP #4985
provided the gateway is started per §2.

### Per-tenant narrow token requirement (all providers)

For all five KMS backends, each tenant in a multi-tenant deployment MUST have distinct
credentials (token, role, service principal, workload identity) scoped to only its
own keys. Shared cross-tenant credentials fail the need-to-know principle for key
material and are incompatible with SC.L2-3.13.11 key management requirements.

---

## 9. CMMC SC.L2-3.13.11 — SSP language

The following text is copy-pasteable into a System Security Plan for CMMC Level 2
practice SC.L2-3.13.11 (Employ FIPS-validated cryptography when used to protect the
confidentiality of CUI).

---

**SC.L2-3.13.11 Implementation Statement**

The [SYSTEM NAME] system employs FIPS 140-3 validated cryptography for all operations
involving the protection of Controlled Unclassified Information (CUI). All
cryptographic operations (digital signature generation and verification, key
generation, hash computation, and HMAC computation) are performed by the Python
`cryptography` library (version ≥42) configured to use the OpenSSL FIPS Provider as
its backend.

**Validated module:** OpenSSL FIPS Provider, CMVP Certificate #4985, FIPS 140-3
Level 1 (lifecycle assurance Level 3), issued 2025-03-11, valid through 2030-03-10.

**Activation:** The gateway process is started with `OPENSSL_MODULES` and
`OPENSSL_CONF` environment variables that direct OpenSSL to load and activate the
FIPS Provider. The operator verifies provider activation at startup via
`openssl list -providers` (expected output: `name: fips`, status: active). The
deployment flag `FIPS_MODE=1` enables FIPS code paths in the Yashigani software layer.

**Algorithms in use:**
- Digital signatures: ECDSA P-384/SHA-384 (ES384) for MCP identity JWTs; RSA-PSS-3072/
  SHA-384 for agent manifest signing. Both approved under FIPS 186-5.
- Hashing: SHA-256 and SHA-384, approved under FIPS 180-4.
- HMAC: HMAC-SHA-384 for backup integrity, approved under FIPS 198-1.
- KDF: PBKDF2-HMAC-SHA384 for key wrapping, approved under SP 800-132.
- TLS: ECDH P-256 key exchange (FIPS 186-5; SP 800-56A rev 3); TLS 1.2 minimum.

**Non-approved algorithms blocked:** argon2id is explicitly disabled in FIPS mode
(admin password wrap#1 is absent; PBKDF2 wrap#2 only). cosign (Go-based,
BoringCrypto certificate #3678 expired) is unconditionally blocked in FIPS mode;
manifest verification routes exclusively to the RSA-PSS-3072 path.

**KMS:** For deployments using an external KMS, AWS KMS FIPS endpoints
(`kms-fips.<region>.amazonaws.com`) or Vault Enterprise FIPS build are used, with
per-tenant narrow credentials scoped to each tenant's keys.

**Evidence artifacts:** Runtime FIPS attestation is surfaced at `/admin/crypto/inventory`
(requires admin session). The endpoint returns the `cmvp_cert` value set at install
time, the active FIPS mode flag, and the algorithm inventory. This endpoint is
available to auditors via the Yashigani admin portal.

---

## 10. Operator pre-flight checklist

Complete all items before declaring a FIPS-mode deployment compliant. Record results
and the name of the operator completing each check.

### A. Install-time configuration

```
[ ] install.sh invoked with --fips-mode 1 --cmvp-cert "#4985"
    OR YSG_FIPS_MODE=1 and YSG_CMVP_CERT="#4985" set in environment before install.

[ ] docker/.env (compose) or Helm values (k8s) inspected after install:
      FIPS_MODE=1 present
      YSG_CMVP_CERT=#4985 present

[ ] Container base image confirmed to include OpenSSL FIPS Provider (CMVP #4985).
    Check: docker run <image> openssl list -providers | grep -i fips
    Expected: name: fips
```

### B. Provider activation

```
[ ] Provider loaded in gateway container:
      docker exec yashigani-gateway openssl list -providers | grep -i fips
      Expected: name: fips

[ ] Provider loaded in backoffice container:
      docker exec yashigani-backoffice openssl list -providers | grep -i fips
      Expected: name: fips

[ ] Auto-detect guard active: lib/yashigani-fips.sh::_fips_assert_provider_loaded
    tested — exits 0 when provider present, exits 1 + error when absent.
```

### C. Algorithm gates

```
[ ] Manifest with cosign-bundled-key algorithm rejected in FIPS mode:
      YASHIGANI_FIPS=1 yashigani validate test-cosign-manifest.yaml
      Expected: ManifestSignatureError citing NICO-005/FIX-2

[ ] Manifest with rsa-pss-3072-sha384 algorithm accepted:
      YASHIGANI_FIPS=1 yashigani validate signed-manifest.yaml \
        --fips-pubkey manifest-signing-fips.pub
      Expected: exit 0

[ ] RSA key size guard active:
      Attempt verification with a 2048-bit RSA key.
      Expected: ManifestSignatureError "FIPS RSA key must be exactly 3072 bits"

[ ] PSS salt length confirmed as DIGEST_LENGTH (48 bytes for SHA-384).
    Review: signatures.py lines 310-315 — padding.PSS.DIGEST_LENGTH, not MAX_LENGTH.
    (Code review or unit test suite confirmation: test_v250_w1_manifest_signatures.py)
```

### D. MCP identity JWT

```
[ ] Gateway broker self-test at startup confirms JWT alg header = ES384.
    Log line: "MCP identity JWT self-test: alg=ES384 OK"

[ ] MCP signing key generated with FIPS Provider active:
      openssl ecparam -genkey -name secp384r1 (FIPS_MODE=1 active at generation time)
    OR: KMS-backed key (Vault Enterprise FIPS / AWS KMS FIPS / Azure KV / GCP KMS).

[ ] JWKS endpoint accessible (no auth required):
      curl -s https://gateway.yashigani.internal/.well-known/yashigani-mcp-jwks.json
      Expected: {"keys":[{"kty":"EC","crv":"P-384","alg":"ES384",...}]}

[ ] JWT nonce store: Redis configured for production.
      Non-Redis (in-process) nonce store is dev mode only — not crash-safe.
```

### E. PKI issuance

```
[ ] PKI bootstrap container used a FIPS-configured base image.
    Note in SSP if base image was standard Python slim (issuance outside CMVP boundary).

[ ] Leaf certs generated with EC P-256 keys (SECP256R1).
    Check: openssl x509 -in secrets/leaf-gateway.crt -text | grep "Public Key Algorithm"
    Expected: id-ecPublicKey; NIST P-256

[ ] Leaf cert expiry > 0 days (not expired):
      yashigani pki status
      Expected: all services show days_remaining > 0
```

### F. KMS (if applicable)

```
[ ] KMS provider identified: [ ] Vault Enterprise FIPS  [ ] AWS KMS  [ ] Azure KV
                              [ ] GCP KMS               [ ] Keeper

[ ] If Vault: confirmed Enterprise FIPS build (not community edition).
    vault version | grep "+fips1.13" or equivalent enterprise FIPS suffix.

[ ] If AWS KMS: FIPS endpoint in use (kms-fips.<region>.amazonaws.com).

[ ] Per-tenant narrow tokens/credentials verified:
      Each tenant's credentials are scoped to only that tenant's key paths/ARNs/vaults.
      Cross-tenant credential sharing confirmed absent.
```

### G. Runtime attestation

```
[ ] /admin/crypto/inventory returns expected values (admin session required):
    - fips_mode: true
    - cmvp_cert: "#4985"
    - algorithm entries present for all active paths

[ ] CMVP #4985 certificate still ACTIVE and not expired:
    Live fetch: https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4985
    Check status field = "Active"; expiry = 2030-03-10.
    Record fetch timestamp in SSP evidence trail.
    Cache expires: 2026-06-28 — re-fetch before that date.
```

### H. Non-FIPS algorithm audit

```
[ ] argon2id confirmed absent from FIPS-mode password wrap:
      grep -r "argon2" <deploy-logs> — should show wrap1.present=false in install log.

[ ] No cosign binary reachable inside gateway container in FIPS mode:
      docker exec yashigani-gateway which cosign
      Expected: exit 1 (not found) or binary present but gate blocks it via YASHIGANI_FIPS=1
```

---

## 11. Troubleshooting

**`ERROR: FIPS_MODE=1 but OpenSSL FIPS provider not loaded`**
The `_fips_assert_provider_loaded` check failed. The container base image does not
include the CMVP #4985 FIPS Provider. Rebuild the gateway image with a FIPS-configured
base image and retry.

**`ManifestSignatureError: FIPS mode requires algorithm rsa-pss-3072-sha384`**
A manifest with `algorithm: cosign-bundled-key` was submitted in FIPS mode. This is
the NICO-005/FIX-2 gate. Re-sign the manifest with the RSA-PSS-3072 key and update
`spec.signature.algorithm` to `rsa-pss-3072-sha384`.

**`ManifestSignatureError: FIPS RSA key must be exactly 3072 bits`**
The public key supplied via `--fips-pubkey` or `fips_public_key_pem` is not 3072 bits.
Generate a 3072-bit RSA key (`openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072`).

**`attestation field cmvp_cert: null` at /admin/crypto/inventory**
The `--cmvp-cert` flag or `YSG_CMVP_CERT` environment variable was not set at install
time. Re-run install with `--cmvp-cert "#4985"` or set `YSG_CMVP_CERT=#4985` in
`docker/.env` and restart containers.

**Vault signing key errors**
If using Vault community edition in FIPS mode, key operations fail because Go `crypto`
is not FIPS-validated. Upgrade to Vault Enterprise FIPS build.

---

*Document owner: Nico (crypto / FIPS / attestation). CMVP #4985 re-fetch due 2026-06-28.*
*Cross-references: `mcp-identity-jwt-spec-20260529.md` (ES384 spec); `signatures.py` (RSA-PSS implementation); `lib/yashigani-fips.sh` (shell FIPS helpers); `install.sh` (FIPS_MODE flag, CMVP_CERT, wrap#1 absence); `docker/docker-compose.yml` line 108 (FIPS_MODE propagation); `helm/yashigani/values.yaml` line 1577 (fips block).*
