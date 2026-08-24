# FedRAMP Moderate — Yashigani 4.1.2 — NOT ASSESSED

**Assessment status:** NOT ASSESSED FOR RELEASE 4.1.2. **No compliance rate is published for this framework.**

**Framework version:** FedRAMP Rev 5 baseline (Moderate impact)

**Controls in scope:** 42

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
| AC-1.F | Access Control Policy — FedRAMP: Policy reviewed annually, procedures reviewed annually | NOT ASSESSED |
| AC-2.F | Account Management — FedRAMP: Automated account management required | NOT ASSESSED |
| AC-2(F2) | Account Management — FedRAMP: Disable inactive accounts within 90 days | NOT ASSESSED |
| AC-2(F3) | Account Management — FedRAMP: Audit account changes | NOT ASSESSED |
| AC-2(12).F | Account Management — FedRAMP: Monitor for atypical usage | NOT ASSESSED |
| AC-2(13).F | Account Management — FedRAMP: Disable accounts posing significant risk | NOT ASSESSED |
| AC-6(F1) | Least Privilege — FedRAMP: Explicitly authorise privileged functions | NOT ASSESSED |
| AC-7.F | Unsuccessful Logon Attempts — FedRAMP: Lock after 3 consecutive failures | NOT ASSESSED |
| AC-8.F | System Use Notification — FedRAMP: Government system banner required | NOT ASSESSED |
| AC-10.F | Concurrent Session Control — FedRAMP: 3 sessions maximum | NOT ASSESSED |
| AC-11.F | Device Lock — FedRAMP: 15-minute inactivity lock | NOT ASSESSED |
| AC-17.F | Remote Access — FedRAMP: All remote access via managed access control point | NOT ASSESSED |
| AC-17(9).F | Remote Access — FedRAMP: Disconnect remote access within 15 minutes | NOT ASSESSED |
| AU-2.F | Event Logging — FedRAMP: Specific audit events required | NOT ASSESSED |
| AU-3.F | Audit Record Content — FedRAMP: Full audit record details | NOT ASSESSED |
| AU-6.F | Audit Review — FedRAMP: Weekly review plus real-time alerts | NOT ASSESSED |
| AU-9.F | Audit Protection — FedRAMP: Centralised log collection | NOT ASSESSED |
| AU-11.F | Audit Record Retention — FedRAMP: Minimum 1 year online, 3 years total | NOT ASSESSED |
| CA-7.F | Continuous Monitoring — FedRAMP ConMon requirements | NOT ASSESSED |
| CA-7(F2) | Continuous Monitoring — FedRAMP: Monthly vulnerability scanning | NOT ASSESSED |
| CM-2.F | Baseline Configuration — FedRAMP: CIS or DISA STIG baselines | NOT ASSESSED |
| CM-6.F | Configuration Settings — FedRAMP: USGCB/CIS compliance | NOT ASSESSED |
| CM-8.F | System Component Inventory — FedRAMP: Accurate, granular inventory | NOT ASSESSED |
| IA-2.F | Authentication — FedRAMP: MFA required for all users | NOT ASSESSED |
| IA-2(6).F | Authentication — FedRAMP: Separate device for MFA | NOT ASSESSED |
| IA-5.F | Authenticator Management — FedRAMP: Minimum 12-character passwords | NOT ASSESSED |
| IA-5(F2) | Authenticator Management — FedRAMP: Password change every 60 days | NOT ASSESSED |
| IA-8.F | Non-Organisational User Auth — FedRAMP: PIV or SAML/OIDC federation | NOT ASSESSED |
| RA-5.F | Vulnerability Scanning — FedRAMP: Monthly scans with 30-day remediation | NOT ASSESSED |
| RA-5(F3) | Vulnerability Scanning — FedRAMP: Include web application scanning | NOT ASSESSED |
| SC-7.F | Boundary Protection — FedRAMP: Managed interfaces with TIC compliance | NOT ASSESSED |
| SC-8.F | Transmission Protection — FedRAMP: FIPS 140-2/3 validated cryptography | NOT ASSESSED |
| SC-12.F | Cryptographic Key Management — FedRAMP: FIPS 140-2/3 key management | NOT ASSESSED |
| SC-13.F | Cryptographic Protection — FedRAMP: FIPS-validated algorithms | NOT ASSESSED |
| SC-28.F | Protection at Rest — FedRAMP: FIPS 140-2/3 validated encryption at rest | NOT ASSESSED |
| SI-2.F | Flaw Remediation — FedRAMP: 30/15-day remediation timelines | NOT ASSESSED |
| SI-4.F | System Monitoring — FedRAMP: IDS/IPS at boundary and key internal points | NOT ASSESSED |
| CONMON-6 | FedRAMP Digital Identity Requirements | NOT ASSESSED |
| DOC-IRP | FedRAMP Incident Response Plan | NOT ASSESSED |
| DOC-CTP | FedRAMP Contingency Plan | NOT ASSESSED |
| DOC-BOUNDARY | FedRAMP System Boundary and Data Flow Diagrams | NOT ASSESSED |
| DOC-INVENTORY | FedRAMP System Inventory | NOT ASSESSED |

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
