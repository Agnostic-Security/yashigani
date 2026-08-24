# SOC 2 Type II — Yashigani 4.1.2 — NOT ASSESSED

**Assessment status:** NOT ASSESSED FOR RELEASE 4.1.2. **No compliance rate is published for this framework.**

**Framework version:** AICPA TSP 100 (2017) Trust Services Criteria

**Controls in scope:** 25

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
| CC2.1 | COSO Principle 13 — Obtains or generates relevant, quality information | NOT ASSESSED |
| CC3.2 | COSO Principle 7 — Identifies and analyses risks | NOT ASSESSED |
| CC3.4 | COSO Principle 9 — Identifies and assesses significant change | NOT ASSESSED |
| CC4.1 | COSO Principle 16 — Selects, develops, and performs ongoing and/or separate evaluations | NOT ASSESSED |
| CC5.2 | COSO Principle 11 — Selects and develops general controls over technology | NOT ASSESSED |
| CC6.1 | Logical access security software, infrastructure, and architectures | NOT ASSESSED |
| CC6.3 | Role-based access control and least privilege | NOT ASSESSED |
| CC6.6 | Encryption in transit | NOT ASSESSED |
| CC6.7 | Encryption at rest | NOT ASSESSED |
| CC6.8 | Prevention of unauthorized code deployment | NOT ASSESSED |
| CC7.1 | Detection of new vulnerabilities | NOT ASSESSED |
| CC7.2 | Monitoring system components for anomalies | NOT ASSESSED |
| CC7.4 | Incident response | NOT ASSESSED |
| CC7.5 | Recovery from identified security incidents | NOT ASSESSED |
| CC8.1 | Changes to infrastructure and software | NOT ASSESSED |
| CC8.2 | Testing of changes | NOT ASSESSED |
| CC9.1 | Identification and management of vendor and business partner risks | NOT ASSESSED |
| A1.2 | Environmental protections, software, data backup, and recovery infrastructure | NOT ASSESSED |
| C1.1 | Identification and maintenance of confidential information | NOT ASSESSED |
| C1.2 | Disposal of confidential information | NOT ASSESSED |
| PI1.2 | System inputs are complete, accurate, and valid | NOT ASSESSED |
| PI1.5 | Data stored is complete, accurate, and not improperly modified | NOT ASSESSED |
| P3.2 | Personal information retention | NOT ASSESSED |
| P4.1 | Disposal of personal information | NOT ASSESSED |
| P4.2 | Anonymisation and de-identification | NOT ASSESSED |

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
