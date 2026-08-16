# Yashigani Release Signing

Yashigani release tags are **SSH-signed** using a hardware-backed (Yubikey) `ed25519` key held by the maintainer (`maxine@agnosticsec.com`).

## Why SSH not GPG

- The maintainer's signing key is hardware-backed (Yubikey). Software GPG export is not possible.
- Git natively supports SSH tag signing since 2.34 (`gpg.format=ssh`).
- `git tag -v` verifies SSH-signed tags using an `allowed_signers` file (per `man 5 allowed_signers`).
- No additional infrastructure (GPG agent, software keyring) needed.

The GPG path was confirmed non-viable during run 25682146979: the GPG import step completed but `private-keys-v1.d/` was empty because GnuPG detected a smartcard stub. Hardware-backed keys cannot sign in CI without the physical device. GPG CI path removed 2026-05-25 per Tiago directive.

## Verifying a release tag

```bash
git config gpg.ssh.allowedSignersFile docs/release-signing-key.pub
git tag -v v2.24.2
# Expected: "Good \"git\" signature for maxine@agnosticsec.com with ED25519 key SHA256:y5RP8TQfAFKBECUDgqP300d8CrdY4njSRS8HzxIQdJE"
```

The public key file at `docs/release-signing-key.pub` is in OpenSSH `allowed_signers(5)` format.

A tag is verified **only** when `git tag -v` exits 0 *and* prints `Good "git" signature for
<principal>`. Output of the form `Good "git" signature with ED25519 key ...` followed by
`No principal matched.` means the signing key is not listed in the allowed-signers file: the
signature is cryptographically valid but **cannot be attributed**, and git exits non-zero.

## Actual signing coverage

Verified by running `git tag -v` against `docs/release-signing-key.pub` on every tag in the
repository (2026-08-16). This table supersedes the earlier statement that "tags signed from
v2.23.3 onward are SSH-signed", which was wrong in both directions.

| Tags | Status |
|---|---|
| v0.9.4 – v2.23.2 | Unsigned — signing began at v2.23.3 |
| v2.23.3 – v2.25.3 | SSH-signed by `maxine@agnosticsec.com`, key `SHA256:y5RP8TQfAFKBECUDgqP300d8CrdY4njSRS8HzxIQdJE` — **verifies, exit 0** |
| v2.25.3.1, v3.0.0, v3.1.0, v3.1.1, v3.1.2 | SSH-signed by a second maintainer key `SHA256:nrTH8N+nyrCYkeVVlQh39YBOc+M1NCSaI+4JUWs+jpY` (tagger `Max <max@agnosticsec.com>`) — **`No principal matched`, exit 1** |
| v2.25.4, v2.25.5, v4.1.0 | Unsigned |

Two open defects follow from this table:

1. **The rotation procedure below was not completed.** A second signing key entered use at
   v2.25.3.1 but was never added to `docs/release-signing-key.pub` as a second entry (step 2
   of the rotation procedure). Consequence: every v3.x tag fails verification for every
   customer. The tags are fine — the allowed-signers file is incomplete. Adding the second
   public key restores verification retroactively with no re-tagging. **The second key must be
   confirmed as an authorised release key by the maintainer before it is committed**; knowing
   its fingerprint is not authority to trust it.
2. **Signing is not enforced at tag time.** v2.25.4, v2.25.5 and v4.1.0 were tagged unsigned
   inside the signed era. Nothing in the release process rejects an unsigned tag.

## Key rotation

Maintainer rotates the SSH key by:

1. Generating new ed25519 keypair on Yubikey
2. Committing the new public key as a SECOND entry in `docs/release-signing-key.pub`
3. Keeping the old key entry — historical tags must remain verifiable
4. Releasing the next tag with the new key

The `allowed_signers` format supports multiple keys per principal; both old and new keys coexist in the file during and after rotation.

## What is NOT supported

- **GPG signing** — historically referenced in CHANGELOG v2.23.2 as aspirational; never implemented. The maintainer's hardware-backed key is incompatible with software GPG export. Correction landed in commit `be94e26`; this document is the formal declaration (2026-05-25).
- **CI-side signing** — release tags are created locally by the maintainer with hardware-key consent; CI does not have access to the Yubikey. A verification recipe for CI tooling exists at
`.github/workflows-disabled-2026-05-27/tag-sign.yml`; note that this workflow directory has
been disabled since 2026-05-27, so nothing currently verifies tag signatures automatically.

## Compliance references

| Standard | Control | How satisfied |
|---|---|---|
| NIST SP 800-53 SI-7 | Software integrity | **Partially.** SSH-signed tags with a hardware-backed key and an in-repo allowed-signers file, but coverage has gaps (see table above) and signing is not enforced at tag time. |
| SOC 2 CC8.1 | Change management | **Partially.** Tag signing gives a tamper-evident record for the tags that are both signed and attributable; three tags in the signed era are unsigned and five are unattributable. |
| SLSA Level 3 | Build provenance — release artifact signing | **Not met today.** The cosign keyless signing and SBOM-attestation steps exist in `.github/workflows-disabled-2026-05-27/release.yml` but that workflow directory has been disabled since 2026-05-27, so released images carry no signature or provenance attestation. Tag signing alone does not satisfy this level. |

These are statements of current state, not compliance verdicts. No control in this document
is asserted to pass.

Risk register entry: YSG-RISK-223.
