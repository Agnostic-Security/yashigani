# OWASP API Security (technical baseline) — Yashigani 4.1.2 — NOT ASSESSED

**Assessment status:** NOT ASSESSED FOR RELEASE 4.1.2. **No compliance rate is published for this framework.**

**Framework version:** Yashigani-internal API security baseline (aligned to OWASP API Top 10)

**Controls in scope:** 38

**Prior assessment:** v2.23.2 (assessed 2026-05-08) — **verdicts withdrawn 2026-08-16**, finding `YCS-20260816-v4.1.2-TB-01`.

> **No control in this document is asserted to pass, fail, or be out of scope.**
> Yashigani 4.1.2 has not been assessed against this framework. Any statement to
> the contrary that predates this file is withdrawn and must not be relied on.

## Why the previous verdicts were withdrawn

The verdicts previously published here were produced by an automated keyword
scan and were not control assessments. The evidence string for each PASS was a substring
match in an arbitrary repository file. Representative example, previously published in
`soc2-type2.md`:

```
WITHDRAWN VERDICT — reproduced to show the defect, not asserted:
| CC6.6 | Encryption in transit | PASS | Found 'https' in scripts/generate_training_data.py |
```

The literal `https` appearing inside a training-data generation script is not evidence that
transport encryption is enforced. Across the 20 shipped framework reports, approximately 700
of 1,062 PASS verdicts were of this class; in this report's framework family the share ran as
high as 99% (NIST SP 800-53) and 98% (ISO/IEC 27001). Each such verdict is individually false
and all are withdrawn.

Two further defects applied to the withdrawn set:

- **Dangling evidence.** `docs/incident_response_plan.md`, cited as the evidence for SOC 2
  CC7.4 (Incident response), does not exist in this repository.
- **Stale by five releases.** The assessment was performed against v2.23.2 (2026-05-08) and
  shipped unchanged through v2.23.3, v2.23.4, v2.24.x, v2.25.x, v3.x and v4.1.x without
  re-verification.

## Control scope (enumeration only — no verdicts)

The control set below records which controls a future assessment would need to
cover. It carries no verdicts and no evidence.

| Control ID | Control name | 4.1.2 status |
|---|---|---|
| API1 | Broken Object Level Auth | NOT ASSESSED |
| API2 | Broken Authentication | NOT ASSESSED |
| API3 | Broken Object Property Level Auth | NOT ASSESSED |
| API4 | Unrestricted Resource Consumption | NOT ASSESSED |
| API5 | Broken Function Level Auth | NOT ASSESSED |
| API6 | Unrestricted Access to Sensitive Flows | NOT ASSESSED |
| API7 | Server Side Request Forgery | NOT ASSESSED |
| API8 | Security Misconfiguration | NOT ASSESSED |
| API9 | Improper Inventory Management | NOT ASSESSED |
| API10 | Unsafe Consumption of APIs | NOT ASSESSED |
| API-AUTH-1 | Password hashing uses adaptive algorithm (Argon2id) | NOT ASSESSED |
| API-AUTH-2 | Token expiry enforced (session max_age) | NOT ASSESSED |
| API-AUTH-3 | Multi-factor authentication (TOTP mandatory) | NOT ASSESSED |
| API-AUTH-4 | Brute-force protection (exponential backoff) | NOT ASSESSED |
| API-AUTH-5 | Credential rotation support (agent PSK auto-rotation) | NOT ASSESSED |
| API-AUTHZ-1 | RBAC via OPA (deny by default) | NOT ASSESSED |
| API-AUTHZ-2 | Per-agent path restrictions (allowed_paths) | NOT ASSESSED |
| API-AUTHZ-3 | Per-agent CIDR restrictions (allowed_cidrs) | NOT ASSESSED |
| API-AUTHZ-4 | Sensitivity ceiling per identity | NOT ASSESSED |
| API-DATA-1 | Request body size limit (Caddy) | NOT ASSESSED |
| API-DATA-2 | Parameterised queries (asyncpg $1/$2, no f-strings in SQL) | NOT ASSESSED |
| API-DATA-3 | Response content inspection before delivery | NOT ASSESSED |
| API-DATA-4 | No mass assignment (Pydantic strict field definitions) | NOT ASSESSED |
| API-ERR-1 | Generic error messages (no credential enumeration) | NOT ASSESSED |
| API-ERR-2 | No stack traces in API responses | NOT ASSESSED |
| API-ERR-3 | Fail-closed on security component failure | NOT ASSESSED |
| API-LOG-1 | All auth events audited (login, logout, failure) | NOT ASSESSED |
| API-LOG-2 | All policy decisions audited (OPA allow/deny) | NOT ASSESSED |
| API-LOG-3 | SIEM integration (Wazuh/Splunk/Elasticsearch) | NOT ASSESSED |
| API-LOG-4 | Tamper-evident audit chain (SHA-384 Merkle) | NOT ASSESSED |
| API-TLS-1 | TLS 1.2+ enforced (no plaintext API access) | NOT ASSESSED |
| API-TLS-2 | Security headers (X-Content-Type-Options, X-Frame-Options) | NOT ASSESSED |
| API-TLS-3 | CORS not enabled (API is same-origin only) | NOT ASSESSED |
| API-BIZ-1 | Budget enforcement prevents resource exhaustion | NOT ASSESSED |
| API-BIZ-2 | Graceful degradation (budget exhausted -> local, never reject) | NOT ASSESSED |
| API-BIZ-3 | Self-service password reset requires TOTP (not email-only) | NOT ASSESSED |
| API-BIZ-4 | Request timeout enforcement prevents slow-loris attacks | NOT ASSESSED |
| API-BIZ-5 | Endpoint-specific rate limiting (per-path granularity) | NOT ASSESSED |

## What is required before any verdict is published here

A verdict may be re-published in this file only when all of the following hold
for the release being assessed:

1. The control text is taken from the canonical published framework source, at the correct
   framework version, using canonical control identifiers.
2. Each verdict cites a `file:line` in this repository, at the assessed commit, that a reader
   can open and check without access to any internal or non-shipped document.
3. The cited code was read, not pattern-matched, and the reviewer recorded the attacker
   scenario the control was tested against.
4. Absence of an expected artefact is recorded as NEEDS REVIEW, never as PASS.
5. Any headline rate is recomputed from the verdicts in that same file at that same commit.

Until then this report asserts nothing.

## Prior working papers

The withdrawn v2.23.2 assessment and its working papers are retained in Agnostic
Security's internal compliance archive, outside this repository, for audit-trail
purposes. They are superseded and are not offered as evidence for any release.

> **Disclaimer.** This report is produced by Agnostic Security Ltd against its own
> product and is not a substitute for independent assessment. For an audit opinion, engage a
> qualified third-party auditor. *We don't replace your auditor — we make their job easier.*
