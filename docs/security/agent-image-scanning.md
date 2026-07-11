# Agent Image Component Scanning (N1)

## What this scans

The `agent-image-component-scan.yml` workflow scans the **built-in Python code shipped inside each agent image** — the application logic that is present before any user interaction. This is release-time hygiene: catching upstream code quality issues in third-party agent images before they reach a customer deployment.

Specifically, it extracts and scans:

| Agent | Scanned path | Notes |
|-------|-------------|-------|
| langflow | `/app/.venv/lib/python3.12/site-packages/langflow/` | Full installed package (base components + UI components). Python version resolved dynamically at scan time. |
| letta | `/app/letta/` | Application source tree. |
| openclaw | `/app/skills/*/scripts/*.py` | Python scripts only (7 files). See note below. |

Tools:
- **bandit** (pinned 1.8.3): Python SAST for security anti-patterns
- **opengrep** (pinned v1.20.0): SAST with `p/python` + `p/owasp-top-ten` rulesets

Gate: HIGH/CRITICAL findings fail CI. MEDIUM findings surface as warnings only.

## What this does NOT scan

**User-uploaded flows and custom components created at runtime.**

Yashigani uses per-user-container isolation for agent sessions. When a user uploads a custom flow or creates a component via the langflow UI, that code runs inside an isolated container provisioned for that user — it is not co-mingled with other users' code or with the built-in component surface. Scanning user-uploaded code at runtime would require an admission webhook pattern (see evolution path below).

**openclaw TypeScript/JavaScript code.** openclaw is a TypeScript/JavaScript application. bandit and opengrep cover Python only. The `/app/skills/*/scripts/` surface (7 Python files as of 2026.5.6) is the entire Python exposure. If openclaw gains Python components, update the scanned path.

**OS-level and package-level CVEs.** These are covered separately by `trivy-agent-images.yml` (C-CAP-004).

## Allowlist

`.github/agent-image-scan-allowlist.json` holds per-image, per-tool accepted findings.

Schema per entry:

```json
{
  "TEST_ID_OR_RULE_ID": {
    "severity": "HIGH",
    "reason": "explanation of why this is accepted or a false positive",
    "reviewer": "captain",
    "expiry_date": "YYYY-MM-DD",
    "upstream_issue": "URL or 'pending'"
  }
}
```

Rules:
- Entries expire by `expiry_date`. Expired entries **fail CI** — they must be renewed or the upstream issue must be fixed.
- Maximum expiry window: 90 days. Renewing requires a fresh reviewer sign-off in the commit body.
- Allowlist entries are per-image and per-tool. Suppressing a rule in `letta/bandit` does not suppress it in `letta/opengrep`.

## Current allowlist state (2026-05-24)

| Image | Tool | Rule | Reason summary | Expiry |
|-------|------|------|---------------|--------|
| letta | bandit | B324 | 3x MD5 usages without `usedforsecurity=False` in letta 0.16.7. All non-cryptographic (UUID derivation, IPC checksum). Upstream code quality issue. | 2026-08-24 |

langflow: 0 allowlisted findings (no HIGH/CRITICAL from bandit or opengrep).
openclaw: 0 allowlisted findings (0 findings from bandit; only 7 Python scripts in image).

## Evolution path

When shared-tenant agent containers ever ship (v2.25+ design), this scan becomes the
**basis** for an admission webhook that evaluates user-uploaded component code before
allowing it to run. The allowlist mechanism, gate thresholds, and SARIF upload pattern
are all designed to be reused in that admission context.

The v2.25+ design is intentionally deferred — it requires the full Iris design for
user-upload admission policy, which is out of scope for N1.
