# CMMC 2.0 Level 2 — Yashigani 4.1.2 — NOT ASSESSED

**Assessment status:** NOT ASSESSED FOR RELEASE 4.1.2. **No compliance rate is published for this framework.**

**Framework version:** CMMC Model 2.0 Level 2 (DoD, 2024 final rule)

**Controls in scope:** 33

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
| AC.L2-3.1.1 | Limit system access to authorised users | NOT ASSESSED |
| AC.L2-3.1.2 | Limit access to authorised transactions and functions | NOT ASSESSED |
| AC.L2-3.1.7 | Prevent non-privileged users from executing privileged functions | NOT ASSESSED |
| AC.L2-3.1.8 | Limit unsuccessful logon attempts | NOT ASSESSED |
| AC.L2-3.1.9 | Provide privacy and security notices at logon | NOT ASSESSED |
| AC.L2-3.1.10 | Session lock and pattern-hiding after inactivity | NOT ASSESSED |
| AC.L2-3.1.11 | Terminate user sessions after defined conditions | NOT ASSESSED |
| AC.L2-3.1.13 | Employ cryptographic mechanisms for remote access confidentiality | NOT ASSESSED |
| AU.L2-3.3.1 | Create and retain audit logs | NOT ASSESSED |
| AU.L2-3.3.7 | Synchronise system clocks to authoritative source | NOT ASSESSED |
| CM.L2-3.4.1 | Establish baseline configurations and inventories | NOT ASSESSED |
| CM.L2-3.4.3 | Track, review, approve, disapprove, log changes | NOT ASSESSED |
| IA.L2-3.5.1 | Identify system users, processes acting on behalf of users, and devices | NOT ASSESSED |
| IA.L2-3.5.2 | Authenticate identities before granting system access | NOT ASSESSED |
| IA.L2-3.5.3 | Multifactor authentication for privileged and remote network access | NOT ASSESSED |
| IA.L2-3.5.4 | Replay-resistant authentication | NOT ASSESSED |
| IA.L2-3.5.7 | Enforce minimum password complexity and change | NOT ASSESSED |
| IA.L2-3.5.8 | Prohibit password reuse for a specified number of generations | NOT ASSESSED |
| IA.L2-3.5.10 | Store and transmit only cryptographically protected passwords | NOT ASSESSED |
| IR.L2-3.6.1 | Establish operational incident-handling capability | NOT ASSESSED |
| MP.L2-3.8.9 | Protect confidentiality of backup CUI at storage locations | NOT ASSESSED |
| RA.L2-3.11.1 | Periodically assess risk to organisational operations from CUI processing | NOT ASSESSED |
| RA.L2-3.11.2 | Scan for vulnerabilities in systems and applications periodically | NOT ASSESSED |
| CA.L2-3.12.2 | Develop and implement plans of action for correcting deficiencies | NOT ASSESSED |
| CA.L2-3.12.4 | Develop, document, periodically update system security plans | NOT ASSESSED |
| SC.L2-3.13.8 | Implement cryptographic mechanisms to prevent unauthorised disclosure of CUI during transmission | NOT ASSESSED |
| SC.L2-3.13.9 | Terminate network connections at end of session or after inactivity | NOT ASSESSED |
| SC.L2-3.13.10 | Establish and manage cryptographic keys for cryptography employed | NOT ASSESSED |
| SC.L2-3.13.11 | Employ FIPS-validated cryptography when used to protect CUI confidentiality | NOT ASSESSED |
| SC.L2-3.13.15 | Protect authenticity of communications sessions | NOT ASSESSED |
| SC.L2-3.13.16 | Protect confidentiality of CUI at rest | NOT ASSESSED |
| SI.L2-3.14.1 | Identify, report, correct system flaws in a timely manner | NOT ASSESSED |
| SI.L2-3.14.6 | Monitor system and communications to detect attacks and indicators of potential attacks | NOT ASSESSED |

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
