<!-- Last-Updated: 2026-07-18 -->

# Supply-chain / artifact-integrity approach — podman-compose-ysg

**Gate requirement (Laura, threat-model-podman-compose-fork-20260718.md,
Finding 1 + Verdict condition 2):** vendoring a Python source tree is
conditional on artifact-integrity verification. There is no existing
digest/signature pattern for a vendored **Python** artifact in this repo
today — only container **images** have one (`airgap/manifest.yml`,
SHA-256 `RepoDigest` comparison, hard-abort on mismatch, `install.sh:
6153-6398`).

This document designs the equivalent pattern for this fork. **The
`install.sh` verify call itself is deliberately NOT wired in this build**
(per the brief — install.sh integration is a separate, later step pending
Iris's universal-installer design). What follows is the manifest format +
verification approach, ready for that later wiring step to call.

## Design — mirrors the existing airgap/manifest.yml pattern

1. **[`MANIFEST.sha256`](./MANIFEST.sha256)** — a flat, `sha256sum`-format
   manifest of every source file in this directory (`podman_compose.py`,
   `LICENSE`, `CHANGES.agnostic.md`, `NOTICE.md`, `README.md`,
   `vendor-integrity.md`, `tests/*.py`), generated at build/release time by
   [`generate-manifest.sh`](./generate-manifest.sh) and committed alongside
   the fork as a discrete, dated artifact. Same shape as
   `sha256sum <file>` output — auditable with the standard tool, no custom
   format to learn.

2. **[`verify-manifest.sh`](./verify-manifest.sh)** — standalone,
   fail-closed verification script. Recomputes SHA-256 for every entry in
   `MANIFEST.sha256` and hard-aborts (`exit 1`) on ANY mismatch or missing
   file — same fail-closed contract as `install.sh`'s existing
   `load_airgap_bundle()` image-digest check (`log_error` + `exit 1`, no
   downgrade-to-warning path). Runnable standalone today:

   ```sh
   bash vendor/podman-compose-ysg/verify-manifest.sh
   ```

   **Future wiring point (documented, not implemented here):** `install.sh`
   would call this script once, early, before ever invoking
   `podman_compose.py`, exactly the way it already calls the airgap
   image-digest check before starting any service. That wiring is explicit
   scope for the later install.sh-integration dispatch, not this build.

3. **Signature — reuse licence-hardening key infra, do not invent new
   crypto (Laura's explicit instruction).** Yashigani already has ECDSA
   P-256/SHA-256 signing infrastructure for licence bundles
   (`scripts/sign_license.py`, keys under `keys/<env>/`,
   `sign_bundle.py`/`compute_kdf_token.py` per the `feat/licence-hardening`
   branch, COORDINATION 2026-06-15). That branch has **not yet merged**
   into `release/4.1.2`/this fork's branch base, so this build cannot
   literally invoke it. **Documented hook, not implemented in this build:**
   once `feat/licence-hardening`'s signing infra lands, `MANIFEST.sha256`
   should be signed the same way a licence bundle is (ECDSA P-256 detached
   signature over the manifest file, verified with the public key already
   shipped for licence verification) — this reuses one trust root instead
   of introducing a second one. Until then, `verify-manifest.sh` provides
   SHA-256 integrity (tamper-evidence against accidental corruption or a
   non-key-holding attacker modifying the vendored file tree) but not yet
   non-repudiable authenticity (a key-holding attacker could regenerate
   both the file and its digest). This gap is intentional and documented,
   not hidden — closing it is a follow-up once the licence-hardening
   signing infra is available to this branch.

## CVE-watch / update-cadence owner

**Owner: Lu (GRC), process-level — not a one-time gate item (Laura's
Verdict condition 3).** Cadence: reviewed every Yashigani release cycle
(minimum quarterly), checking `containers/podman-compose` upstream issues +
CVE feeds for anything affecting the 1.5.x line. Freezing at `1.5.0+ysg.1`
means this fork does **not** automatically inherit upstream fixes released
after 1.5.0 (1.6.0 introduced its own unfixed dependency-graph-hang
regression — not a reason to track it). Recorded in
`CHANGES.agnostic.md`.

## What this build delivers vs. what's deferred

| Delivered now | Deferred (later, separate dispatch) |
|---|---|
| `MANIFEST.sha256` (SHA-256 per file) | ECDSA signature over the manifest (needs licence-hardening infra merged) |
| `verify-manifest.sh` (standalone, fail-closed) | `install.sh` calling `verify-manifest.sh` before invoking the fork |
| CVE-watch owner assignment (Lu, documented here + CHANGES.agnostic.md) | Iris's universal-installer design determining the final vendored-tool path/wiring |
