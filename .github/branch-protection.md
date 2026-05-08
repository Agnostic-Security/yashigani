# Branch Protection — `main`

<!-- Last updated: 2026-05-08T00:00:00+01:00 -->

Configure via: Settings > Branches > Add rule > Branch name pattern: `main`

---

## Required Status Checks

All 7 CI jobs must pass before merge is permitted. Enable "Require status checks to pass before merging" and add:

| Check Name | Workflow | Notes |
|---|---|---|
| `Lint (ruff + mypy)` | `ci.yml` / `lint` | Blocks `test` job; must pass first |
| `Unit Tests (>=80% coverage)` | `ci.yml` / `test` | Coverage gate enforced by pytest |
| `Docker Build Validation` | `ci.yml` / `docker-build-check` | Hadolint at error threshold |
| `SAST (Opengrep)` | `ci.yml` / `sast` | PR ruleset only (see table below) |
| `Trivy Container Scan` | `security.yml` / `trivy-scan` | Runs on PR trigger |
| `Bandit SAST` | `security.yml` / `bandit-sast` | Runs on PR trigger |
| `pip-audit Dependency Check` | `security.yml` / `pip-audit` | Runs on PR trigger |

Enable "Require branches to be up to date before merging."

**Note — Install Smoke (`install-smoke.yml`):** The `smoke-gate (Linux + mutation only)` job from `install-smoke.yml` is intentionally NOT in the required status checks above. macOS smoke cells are INFORMATIONAL (GH hosted runners lack VZ/Colima/Podman machine support; see `docs/release-process.md §2.3`). The Linux smoke cells and mutation test are enforced inside `smoke-gate` itself, which runs against the release branch (`v2.23.3`, `2.23.x`) during M7 pre-flight — not as a PR merge gate on `main`. Do NOT add `smoke-gate (Linux + mutation only)` as a required status check on `main`.

---

## Additional Protection Settings

| Setting | Value |
|---|---|
| Require signed commits | Enabled |
| Restrict who can push to matching branches | @yashigani/platform team only |
| Require linear history | Enabled — no merge commits |
| Allow force pushes | Disabled |
| Allow deletions | Disabled |
| Require pull request reviews before merging | Minimum 1 approval from code owner |
| Dismiss stale reviews on new push | Enabled |

---

## Opengrep Ruleset by Trigger

| Ruleset | PR Trigger | Scheduled (03:00 UTC daily) |
|---|---|---|
| `p/python` | Yes | Yes |
| `p/owasp-top-ten` | Yes | Yes |
| `p/secrets` | No | Yes |
| `p/supply-chain` | No | Yes |

PR scans use the reduced ruleset (`ci.yml` / `sast` job) to keep feedback fast.
Full ruleset runs nightly via `security.yml` / `opengrep-full` and reports to GitHub Security tab via SARIF upload.
