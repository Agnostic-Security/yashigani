# Yashigani Release Signing

Yashigani release tags are **SSH-signed** using a hardware-backed (Yubikey) `ed25519` key held by the maintainer (`maxine@agnosticsec.com`).

## Why SSH not GPG

- The maintainer's signing key is hardware-backed (Yubikey). Software GPG export is not possible.
- Git natively supports SSH tag signing since 2.34 (`gpg.format=ssh`).
- `git tag -v` verifies SSH-signed tags using an `allowed_signers` file (per `man 5 allowed_signers`).
- No additional infrastructure (GPG agent, software keyring) needed.

The GPG path was confirmed non-viable: the GPG import step completed but `private-keys-v1.d/` was empty because GnuPG detected a smartcard stub. Hardware-backed keys cannot sign in CI without the physical device. GPG CI path removed 2026-05-25.

## Verifying a release tag

```bash
git config gpg.ssh.allowedSignersFile docs/release-signing-key.pub
git tag -v v2.24.2
# Expected: "Good \"git\" signature for maxine@agnosticsec.com with ED25519 key SHA256:y5RP8TQfAFKBECUDgqP300d8CrdY4njSRS8HzxIQdJE"
```

The public key file at `docs/release-signing-key.pub` is in OpenSSH `allowed_signers(5)` format.

Tags signed from v2.23.3 onward are SSH-signed. v2.23.2 and earlier are unsigned.

## Key rotation

Maintainer rotates the SSH key by:

1. Generating new ed25519 keypair on Yubikey
2. Committing the new public key as a SECOND entry in `docs/release-signing-key.pub`
3. Keeping the old key entry — historical tags must remain verifiable
4. Releasing the next tag with the new key

The `allowed_signers` format supports multiple keys per principal; both old and new keys coexist in the file during and after rotation.

## What is NOT supported

- **GPG signing** — historically referenced in CHANGELOG v2.23.2 as aspirational; never implemented. The maintainer's hardware-backed key is incompatible with software GPG export. Correction landed in commit `be94e26`; this document is the formal declaration (2026-05-25).
- **CI-side signing** — release tags are created locally by the maintainer with hardware-key consent; CI does not have access to the Yubikey. See `.github/workflows/tag-sign.yml` for the verification recipe CI tooling can use.

## Compliance references

| Standard | Control | How satisfied |
|---|---|---|
| NIST SP 800-53 SI-7 | Software integrity | SSH-signed tags with hardware-backed key; public key committed in-repo for verification |
| SOC 2 CC8.1 | Change management | Release tag signing provides tamper-evident record of release commits |
| SLSA Level 3 | Build provenance — release artifact signing | Maintainer-signed tags; key is hardware-backed (Yubikey); rotation process documented |

