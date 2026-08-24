# HIPAA Security Rule — Yashigani 4.1.2 — NOT ASSESSED

**Assessment status:** NOT ASSESSED FOR RELEASE 4.1.2. **No compliance rate is published for this framework.**

**Framework version:** 45 CFR Part 164 Subpart C (Security Standards for the Protection of EPHI)

**Controls in scope:** 51

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
| 164.308(a)(1)(i) | Security Management Process | NOT ASSESSED |
| 164.308(a)(1)(ii)(A) | Risk Analysis (Required) | NOT ASSESSED |
| 164.308(a)(1)(ii)(B) | Risk Management (Required) | NOT ASSESSED |
| 164.308(a)(1)(ii)(C) | Sanction Policy (Required) | NOT ASSESSED |
| 164.308(a)(1)(ii)(D) | Information System Activity Review (Required) | NOT ASSESSED |
| 164.308(a)(2) | Assigned Security Responsibility (Required) | NOT ASSESSED |
| 164.308(a)(3)(i) | Workforce Security | NOT ASSESSED |
| 164.308(a)(3)(ii)(A) | Authorization and/or Supervision (Addressable) | NOT ASSESSED |
| 164.308(a)(3)(ii)(B) | Workforce Clearance Procedure (Addressable) | NOT ASSESSED |
| 164.308(a)(3)(ii)(C) | Termination Procedures (Addressable) | NOT ASSESSED |
| 164.308(a)(4)(i) | Information Access Management | NOT ASSESSED |
| 164.308(a)(4)(ii)(A) | Isolating Health Care Clearinghouse Functions (Required) | NOT ASSESSED |
| 164.308(a)(4)(ii)(B) | Access Authorization (Addressable) | NOT ASSESSED |
| 164.308(a)(4)(ii)(C) | Access Establishment and Modification (Addressable) | NOT ASSESSED |
| 164.308(a)(5)(i) | Security Awareness and Training | NOT ASSESSED |
| 164.308(a)(5)(ii)(A) | Security Reminders (Addressable) | NOT ASSESSED |
| 164.308(a)(5)(ii)(B) | Protection from Malicious Software (Addressable) | NOT ASSESSED |
| 164.308(a)(5)(ii)(C) | Log-in Monitoring (Addressable) | NOT ASSESSED |
| 164.308(a)(5)(ii)(D) | Password Management (Addressable) | NOT ASSESSED |
| 164.308(a)(6)(i) | Security Incident Procedures | NOT ASSESSED |
| 164.308(a)(6)(ii) | Response and Reporting (Required) | NOT ASSESSED |
| 164.308(a)(7)(i) | Contingency Plan | NOT ASSESSED |
| 164.308(a)(7)(ii)(A) | Data Backup Plan (Required) | NOT ASSESSED |
| 164.308(a)(7)(ii)(B) | Disaster Recovery Plan (Required) | NOT ASSESSED |
| 164.308(a)(7)(ii)(C) | Emergency Mode Operation Plan (Required) | NOT ASSESSED |
| 164.308(a)(7)(ii)(D) | Testing and Revision Procedures (Addressable) | NOT ASSESSED |
| 164.308(a)(7)(ii)(E) | Applications and Data Criticality Analysis (Addressable) | NOT ASSESSED |
| 164.308(a)(8) | Evaluation (Required) | NOT ASSESSED |
| 164.308(b)(1) | Business Associate Contracts and Other Arrangements (Required) | NOT ASSESSED |
| 164.310(d)(2)(iv) | Data Backup and Storage (Addressable) | NOT ASSESSED |
| 164.312(a)(1) | Access Control | NOT ASSESSED |
| 164.312(a)(2)(i) | Unique User Identification (Required) | NOT ASSESSED |
| 164.312(a)(2)(ii) | Emergency Access Procedure (Required) | NOT ASSESSED |
| 164.312(a)(2)(iii) | Automatic Logoff (Addressable) | NOT ASSESSED |
| 164.312(a)(2)(iv) | Encryption and Decryption (Addressable) | NOT ASSESSED |
| 164.312(b) | Audit Controls (Required) | NOT ASSESSED |
| 164.312(c)(1) | Integrity | NOT ASSESSED |
| 164.312(c)(2) | Mechanism to Authenticate Electronic PHI (Addressable) | NOT ASSESSED |
| 164.312(d) | Person or Entity Authentication (Required) | NOT ASSESSED |
| 164.312(e)(1) | Transmission Security | NOT ASSESSED |
| 164.312(e)(2)(i) | Integrity Controls (Addressable) | NOT ASSESSED |
| 164.312(e)(2)(ii) | Encryption (Addressable) | NOT ASSESSED |
| 164.314(a)(1) | Business Associate Contracts or Other Arrangements (Required) | NOT ASSESSED |
| 164.314(a)(2)(i) | Business Associate Contracts (Required) | NOT ASSESSED |
| 164.314(a)(2)(ii) | Other Arrangements (Required) | NOT ASSESSED |
| 164.314(b)(1) | Requirements for Group Health Plans | NOT ASSESSED |
| 164.316(a) | Policies and Procedures (Required) | NOT ASSESSED |
| 164.316(b)(1) | Documentation (Required) | NOT ASSESSED |
| 164.316(b)(2)(i) | Time Limit (Required) | NOT ASSESSED |
| 164.316(b)(2)(ii) | Availability (Required) | NOT ASSESSED |
| 164.316(b)(2)(iii) | Updates (Required) | NOT ASSESSED |

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
