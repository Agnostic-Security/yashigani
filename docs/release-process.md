# Yashigani Release Process

**Last updated:** 2026-05-06T00:00:00+01:00

This document covers the end-to-end process for cutting a Yashigani release from a clean branch tip to a signed, published GitHub release with full evidence archive. It is the authoritative source for M7 gate-check procedures.

---

## 1. Prerequisites

| Tool | Why needed | Install |
|------|-----------|---------|
| `git` | Commit, tag, push | OS package |
| `gh` CLI | Download CI artifacts, create release | `brew install gh` (macOS) / see [cli.github.com](https://cli.github.com) |
| `gh auth login` | PAT with `repo` + `read:packages` scopes | `gh auth login --scopes repo,read:packages` |

Note: workflow edits (anything under `.github/workflows/`) require a PAT with `workflow` scope in addition to `repo`. Split workflow commits from code commits when needed.

---

## 2. CI Workflow Summary

Three workflows provide the M7 gate evidence:

### 2.1 CI (`ci.yml`)

Triggers on push/PR to: `main`, `release/**`, `v2.23.*`, `2.23.x`.

| Job | What it does | Artifacts uploaded |
|-----|--------------|--------------------|
| `test` (matrix: py3.12, py3.13) | `pytest src/tests/` with `--junitxml` | `unit-tests-py3.12-<sha>`, `unit-tests-py3.13-<sha>` |
| `mypy` (py3.12) | `mypy src/yashigani/` with `--xml-report` | `mypy-<sha>` |

Artifact retention: **90 days**.

### 2.2 Security Scan (`security.yml`)

Triggers on push/PR to same branches; scheduled runs add extended rule-packs.

| Job | Trigger | Artifacts uploaded |
|-----|---------|--------------------|
| `opengrep-push` | push/PR | `opengrep-<sha>` |
| `opengrep-full` | schedule (03:00 UTC) | SARIF only (Code Scanning) |
| `bandit-sast` | push/PR/schedule | `bandit-report` |
| `pip-audit` | push/PR/schedule | `pip-audit-report` |

Artifact retention: **90 days**.

---

## 3. Artifact Contents

### Unit-test artifact (`unit-tests-py<ver>-<sha>/`)

```
test-results-<ver>.xml    # JUnit XML, parseable by CI dashboards
verdict-<ver>.txt         # Grep-able verdict lines:
                          #   Unit tests: PASS|FAIL
                          #   Total: <n>
                          #   Passed: <n>
                          #   Failed: <n>
                          #   Skipped: <n>
                          #   Commit: <sha>
                          #   Workflow: CI
                          #   Run: <run-id>
```

### Mypy artifact (`mypy-<sha>/`)

```
mypy-xml/index.xml        # XML report from --xml-report
mypy-xml/any-exprs.txt    # Any-expression report
mypy-output.txt           # Full stdout/stderr from mypy run
mypy-summary.txt          # Grep-able verdict lines:
                          #   Type check: PASS|FAIL
                          #   Errors: <n>
                          #   Files checked: <n>
                          #   Commit: <sha>
                          #   Workflow: CI
                          #   Run: <run-id>
```

### Opengrep artifact (`opengrep-<sha>/`)

```
opengrep-results.json     # Full JSON output from opengrep scan
opengrep-summary.txt      # Grep-able verdict lines:
                          #   Opengrep: PASS|FAIL
                          #   Critical: <n>
                          #   High: <n>
                          #   Medium: <n>
                          #   Low: <n>
                          #   Info: <n>
                          #   Total findings: <n>
                          #   Scan errors: <n>
                          #   Commit: <sha>
                          #   Workflow: Security Scan
                          #   Run: <run-id>
```

**PASS/FAIL semantics:** `Opengrep: PASS` requires zero CRITICAL or HIGH findings AND zero scan errors. MEDIUM/LOW findings produce `PASS` with non-zero counts (non-blocking). A scan infrastructure error always produces `FAIL`.

---

## 4. Evidence Archive

CI evidence lives OUTSIDE the yashigani repo (in the DevOps evidence repository).

**Archive root:** an DevOps evidence directory, organised by version + commit SHA.

**Archive script:** `scripts/archive_ci_artifacts.sh`

```sh
# Usage (run from inside the yashigani repo directory):
scripts/archive_ci_artifacts.sh <commit-sha> <version>

# Example for v2.23.1 at ec46ab4:
scripts/archive_ci_artifacts.sh ec46ab4 2.23.1
```

The script:
1. Uses `gh run list --commit <sha>` to find all workflow runs for the commit.
2. Warns if any runs are not yet completed.
3. Downloads all artifacts from completed runs via `gh run download`.
4. Copies the three gate artifacts to the canonical evidence path.
5. Writes `archive-manifest.txt` listing all captured files.
6. Runs the gate verdict check inline and exits non-zero on any FAIL.

---

## 5. Pre-flight Gate Check (M7)

Run this one-liner before cutting any release tag. Every line must exit 0.

```sh
# Artifact dir names embed the full SHA. Use glob to match regardless of
# whether SHA is short or full. Resolve with git rev-parse first.
SHA=$(git rev-parse ec46ab4)
VER=2.23.1
BASE="${YASHIGANI_EVIDENCE_ROOT:?set to the DevOps evidence directory}/v${VER}/ci-evidence/${SHA}"

grep -q "Unit tests: PASS" "${BASE}"/unit-tests-py3.12-*/verdict-3.12.txt \
  && grep -q "Unit tests: PASS" "${BASE}"/unit-tests-py3.13-*/verdict-3.13.txt \
  && grep -q "Type check: PASS" "${BASE}"/mypy-*/mypy-summary.txt \
  && grep -q "Opengrep: PASS"   "${BASE}"/opengrep-*/opengrep-summary.txt \
  && echo "ALL CI GATES PASS — safe to tag" \
  || echo "FAIL — one or more gates not green"
```

Release-gate boxes tick ONLY when this grep passes on real downloaded artifacts. A CI URL alone is not sufficient evidence.

---

## 6. Full Release Checklist (M7)

Execute in order. Gate N does not start until Gate N-1 is GREEN.

| # | Gate | Owner | Evidence path | Verdict grep |
|---|------|-------|---------------|--------------|
| 1 | Unit tests (py3.12) | CI | `ci-evidence/<sha>/unit-tests-py3.12-<sha>/verdict-3.12.txt` | `Unit tests: PASS` |
| 2 | Unit tests (py3.13) | CI | `ci-evidence/<sha>/unit-tests-py3.13-<sha>/verdict-3.13.txt` | `Unit tests: PASS` |
| 3 | Type check (mypy) | CI | `ci-evidence/<sha>/mypy-<sha>/mypy-summary.txt` | `Type check: PASS` |
| 4 | Opengrep scan | CI | `ci-evidence/<sha>/opengrep-<sha>/opengrep-summary.txt` | `Opengrep: PASS` |
| 5 | Bandit SAST | CI | `bandit-report-<sha>.json` in evidence dir | No HIGH/CRITICAL net-new |
| 6 | pip-audit | CI | `pip-audit-report-<sha>.json` | Exit 0 |
| 6a | Specialist PR review | Release Coordinator | GitHub PR approval trail for each merged PR in release range | See §6a |
| 7 | Docker restore | Release Engineer | `macos-podman-<sha>-closure-*.log` | `RESTORE TEST GREEN` + both admin 200 lines |
| 8 | Podman restore | Release Engineer | same format | same |
| 9 | K8s Helm restore | Release Engineer | `k8s-helm-<sha>-closure-*.log` | `RESTORE TEST GREEN` + both admin 200 lines |
| 10 | OWASP ASVS v5 L3 | Compliance Reviewer | `YCS-<date>-v<ver>-OWASP-3X.md` | No FAIL above Medium |
| 11 | Adversarial security sweep | Security Tester | `pentest/` findings | No P0/P1 open |
| 12 | Risk register updated | Compliance Reviewer | exception-register.md | All accepted risks logged |
| 13 | Maintainer HITL GO | Release Coordinator | Verbal/chat confirmation | "GO release" |
| 14 | Tag + push | Release Engineer | `git tag v<ver>` | Tag visible on GitHub |

---

## 6a. Specialist PR Review Gate

**Rationale:** F-T10-001 (2026-05-06) — Captain authored Python `gateway/` code that shipped two correctness bugs (`math.isfinite` NaN clamp, `float(os.getenv(...))` DoS on bad env value). Tom caught both on review. Root cause: wrong specialist dispatched for the language domain. Rule codified in `~/.claude/projects/-Users-max-Documents-Claude/memory/feedback_right_specialist_per_language.md`.

**Domain-to-specialist mapping (MUST have approval before merge):**

| Files changed | Required reviewer | Identity |
|---|---|---|
| `src/yashigani/gateway/**/*.py` | Tom | `tom@agnosticsec.com` |
| Any other `**/*.py` (services, tests, migrations) | Tom | `tom@agnosticsec.com` |
| `install.sh`, `uninstall.sh`, `restore.sh`, `update.sh`, `scripts/*.sh`, `*.sh` entrypoints | Su | `su@agnosticsec.com` |
| `Dockerfile*`, `docker-compose*.yml`, `helm/**`, `**/*.yaml` K8s manifests | Captain | `captain@agnosticsec.com` |

**Hard rule:** A PR touching files in one of the above domains MUST carry an approved review from the listed specialist before it is counted as merged for the purposes of this gate. An approval from any other reviewer does not substitute.

**How to verify at release time:**

For each PR merged into the release branch since the previous release tag, run:

```sh
# List PRs merged in release range:
gh pr list --state merged --base 2.23.x --limit 100 --json number,title,mergedAt,reviews

# For each PR touching gateway/ Python:
gh pr view <number> --json reviews | jq '.reviews[] | select(.state=="APPROVED") | .author.login'
# Must include "tom" or "tomYSG" (check team slug for the repo).

# For each PR touching install.sh / scripts/:
# Must include "su" or "suYSG".

# For each PR touching Dockerfiles / helm/:
# Must include "captain" or "captainYSG".
```

**Evidence format:** paste the `gh pr view` output per PR (or the `gh pr list` JSON) into the release evidence directory as `ci-evidence/<sha>/specialist-review-gate.txt`. Gate 6a is GREEN only when every in-scope PR has the required approval recorded in that file.

**Cross-domain PRs:** decompose at review time — a PR touching Python and Helm needs both Tom and Captain approvals. A PR touching Python and shell needs both Tom and Su approvals.

**Rule reference:** `~/.claude/projects/-Users-max-Documents-Claude/memory/feedback_right_specialist_per_language.md`

---

## 7. Tagging

### 7.1 Signing method

All release tags from v2.23.1 onward are **GPG-signed** (annotated tag objects with a PGP signature). The signing key identity is `releases@agnosticsec.com`.

Signing is handled automatically by CI (`.github/workflows/tag-sign.yml`):

1. Push the annotated tag to `origin`.
2. The `tag-sign.yml` workflow imports the `GPG_PRIVATE_KEY` secret, deletes the unsigned tag, re-creates it as a signed tag at the same commit, verifies the signature, and force-pushes it back.
3. Downstream: `build-push.yml` and `release.yml` trigger on the tag and build/sign/publish images (cosign keyless) + SBOM.

Tag consumers should always fetch with `--force` to pick up the re-signed object:

```sh
git fetch --tags --force origin
git tag -v v2.23.2    # expects: "Good signature from releases@agnosticsec.com"
```

### 7.2 Pushing a tag (Release Engineer — Gate 14)

```sh
# On branch 2.23.x, tip at the release SHA:
git tag -a "v2.23.2" -m "Yashigani v2.23.2

<paste release headline bullets here>"
git push origin "v2.23.2"
# CI tag-sign.yml signs it automatically; wait for the workflow to complete
# then verify:
git fetch --tags --force origin
git tag -v v2.23.2
```

The `build-push.yml` and `release.yml` workflows trigger automatically on `v*.*.*` tags and handle image build, cosign signing, SBOM generation, and GitHub release creation.

### 7.3 Local signing (offline / emergency)

If CI is unavailable, use the local signing script (requires GPG key on dev machine):

```sh
bash scripts/sign_release_tag.sh v2.23.2 <commit-sha>
```

See `scripts/sign_release_tag.sh` for prerequisites and key setup instructions.

### 7.4 Retroactive signing of existing unsigned tags

If a tag was pushed without a signature, dispatch the `tag-sign.yml` workflow manually:

```
GitHub -> Actions -> "Tag -- GPG Sign & Verify" -> Run workflow
  tag: v2.23.1
  commit_sha: 733c3624ed04bc51e1982fca690b33232861884a
```

The workflow re-creates the tag as signed at the same commit and force-pushes it. This is a corrective action and must be noted in the release retro (finding V232-NEG02).

---

## 8. Post-release

1. Fast-forward `main` to the release tag: `git push origin 2.23.x:main`.
2. Update `README.md` and `docs/` for the new version.
3. Archive the release evidence directory to long-term storage.
4. Write the release retro (ISO 9001 §9.3/10.2/10.3) in the DevOps evidence repository.
5. Open the next version milestone on GitHub.

---

## 11. Release History

| Version | Date | Tag SHA (short) | Branch tip SHA | Notes |
|---------|------|-----------------|----------------|-------|
| v2.23.2 | 2026-05-03 | `7dcd498` | `7dcd498` | Security hardening, supply-chain, ASVS L3 92%. GPG-signed (see §9 ceremony). |
| v2.23.1 | 2026-05-02 | `3b49d0e` | `3b49d0e` | Core-plane mTLS, two-tier PKI, release hardening. GPG signing available via §7.4 retroactive dispatch. |

> **GPG signing status:** Tag signing infrastructure (key ceremony + CI workflow `tag-sign.yml`) landed in the v2.23.2 release cycle. Both v2.23.2 and v2.23.1 can be verified via `git tag -v <tag>` after completing the key ceremony in §9.

---

## 9. GPG Release Signing Key Setup (one-time, per team)

This section documents the one-time key-generation ceremony. It must be performed by a designated release manager with access to add GitHub repository secrets.

### 9.1 Generate the key

```sh
gpg --full-generate-key
# Choose: (1) RSA and RSA  -- or (4) RSA (sign only) for a dedicated signing key
# Key size: 4096
# Expiry: 2y  (renew before expiry; update docs/release-signing-key.asc on renewal)
# Real name: Agnostic Security Releases
# Email: releases@agnosticsec.com
# Comment: (leave blank)
```

### 9.2 Export private key (for GitHub Secrets)

```sh
gpg --armor --export-secret-keys releases@agnosticsec.com
# Copy the full armored block including -----BEGIN PGP PRIVATE KEY BLOCK-----
# Store as GitHub Secret: GPG_PRIVATE_KEY
# Store the passphrase as: GPG_PASSPHRASE
```

### 9.3 Export public key (for in-repo trust anchor)

```sh
gpg --armor --export releases@agnosticsec.com > docs/release-signing-key.asc
git add docs/release-signing-key.asc
git commit -m "chore(pki): add GPG release signing public key (releases@agnosticsec.com)"
```

### 9.4 Configure GitHub Secrets

In the yashigani repository settings -> Secrets and variables -> Actions:

| Secret name | Content |
|-------------|---------|
| `GPG_PRIVATE_KEY` | Armored private key block from §9.2 |
| `GPG_PASSPHRASE` | Passphrase chosen during key generation |

### 9.5 Verify CI signing works

Push a test tag on a non-main branch (e.g. `v0.0.0-test`) and confirm the `tag-sign.yml` workflow completes with "Signature: GOOD". Delete the test tag afterward.

### 9.6 Status — v2.23.2 release (GPG signing)

The v2.23.2 tag (`7dcd498`) has been pushed. The GPG key ceremony (§9.1–§9.4) must be completed to activate tag-signing CI. Until the ceremony is complete, the tag is unsigned.

**Maintainer action required:** complete §9.1 through §9.4 to generate the `releases@agnosticsec.com` key and add `GPG_PRIVATE_KEY` / `GPG_PASSPHRASE` to GitHub Secrets. Then dispatch `tag-sign.yml` twice:

1. Retroactive v2.23.1 sign:
   - `tag: v2.23.1`, `commit_sha: 3b49d0e` (or the full SHA from `git rev-parse v2.23.1`)
2. v2.23.2 sign:
   - `tag: v2.23.2`, `commit_sha: 7dcd498b906a5dab8ba7e1456db6c7001f2a98a6`

After both dispatches succeed, verify with `git fetch --tags --force origin && git tag -v v2.23.2`.

---

## 10. Tag signature verification (for end users and auditors)

All Yashigani releases from v2.23.1 onward are signed with the Agnostic Security GPG release key. To verify:

```sh
# 1. Import the Agnostic Security release signing public key (once):
gpg --import docs/release-signing-key.asc

# 2. Fetch tags (force-refresh in case a tag was re-signed):
git fetch --tags --force origin

# 3. Verify the tag signature:
git tag -v v2.23.2
# Expected output includes:
# "Good signature from 'Agnostic Security Releases <releases@agnosticsec.com>'"
```

Container image signatures (gateway and backoffice) are verified separately via cosign. See `scripts/sign_image.sh` for commands.
