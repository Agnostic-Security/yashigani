# NIST CSF 2.0 — Yashigani 4.1.2 — NOT ASSESSED

**Assessment status:** NOT ASSESSED FOR RELEASE 4.1.2. **No compliance rate is published for this framework.**

**Framework version:** NIST Cybersecurity Framework v2.0 (2024)

**Controls in scope:** 61

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
| ID.AM-01 | Inventories of hardware managed by the organization are maintained | NOT ASSESSED |
| ID.AM-02 | Inventories of software, services, and systems are maintained | NOT ASSESSED |
| ID.AM-03 | Authorized network communication and data flow representations are maintained | NOT ASSESSED |
| ID.AM-07 | Inventories of data and metadata for designated data types are maintained | NOT ASSESSED |
| ID.AM-08 | Systems, hardware, software, services, and data managed throughout their life cycles | NOT ASSESSED |
| ID.RA-01 | Vulnerabilities in assets identified, validated, and recorded | NOT ASSESSED |
| ID.RA-05 | Threats, vulnerabilities, likelihoods, and impacts used to understand inherent risk | NOT ASSESSED |
| ID.RA-07 | Changes and exceptions managed, assessed for risk impact, recorded, and tracked | NOT ASSESSED |
| ID.RA-08 | Processes for receiving, analysing, and responding to vulnerability disclosures established | NOT ASSESSED |
| ID.RA-09 | Authenticity and integrity of hardware and software assessed prior to acquisition and use | NOT ASSESSED |
| PR.AA-01 | Identities and credentials for authorized users, services, and hardware managed | NOT ASSESSED |
| PR.AA-03 | Users, services, and hardware are authenticated | NOT ASSESSED |
| PR.AA-04 | Identity assertions protected, conveyed, and verified | NOT ASSESSED |
| PR.AA-05 | Access permissions, entitlements, and authorizations defined, managed, enforced, and reviewed | NOT ASSESSED |
| PR.AC-01 | Identities and credentials issued, managed, verified, revoked, and audited (CSF 1.1 ref) | NOT ASSESSED |
| PR.AC-03 | Remote access managed (CSF 1.1 ref) | NOT ASSESSED |
| PR.AC-04 | Access permissions incorporating least privilege and separation of duties (CSF 1.1 ref) | NOT ASSESSED |
| PR.AC-05 | Network integrity protected (network segregation, segmentation) (CSF 1.1 ref) | NOT ASSESSED |
| PR.AC-06 | Identities proofed and bound to credentials and asserted in interactions (CSF 1.1 ref) | NOT ASSESSED |
| PR.AC-07 | Users, devices, and assets authenticated commensurate with risk (CSF 1.1 ref) | NOT ASSESSED |
| PR.DS-01 | Confidentiality, integrity, and availability of data-at-rest protected | NOT ASSESSED |
| PR.DS-02 | Confidentiality, integrity, and availability of data-in-transit protected | NOT ASSESSED |
| PR.DS-04 | Adequate capacity to ensure availability maintained | NOT ASSESSED |
| PR.DS-05 | Protections against data leaks implemented | NOT ASSESSED |
| PR.DS-06 | Integrity checking mechanisms used to verify software, firmware, and information integrity | NOT ASSESSED |
| PR.DS-07 | Development and testing environments separate from production | NOT ASSESSED |
| PR.DS-10 | Confidentiality, integrity, and availability of data-in-use protected | NOT ASSESSED |
| PR.DS-11 | Backups of data created, protected, maintained, and tested | NOT ASSESSED |
| PR.IP-01 | Baseline configuration of IT systems created and maintained | NOT ASSESSED |
| PR.IP-02 | System Development Life Cycle implemented to manage systems | NOT ASSESSED |
| PR.IP-03 | Configuration change control processes in place | NOT ASSESSED |
| PR.IP-04 | Backups of information conducted, maintained, and tested | NOT ASSESSED |
| PR.IP-12 | Vulnerability management plan developed and implemented | NOT ASSESSED |
| PR.IR-01 | Networks and environments protected from unauthorized logical access and usage | NOT ASSESSED |
| PR.IR-03 | Mechanisms implemented to achieve resilience in normal and adverse situations | NOT ASSESSED |
| PR.IR-04 | Adequate resource capacity to ensure availability maintained | NOT ASSESSED |
| PR.PS-01 | Configuration management practices established and applied | NOT ASSESSED |
| PR.PS-02 | Software maintained, replaced, and removed commensurate with risk | NOT ASSESSED |
| PR.PS-04 | Log records generated and made available for continuous monitoring | NOT ASSESSED |
| PR.PS-05 | Installation and execution of unauthorized software prevented | NOT ASSESSED |
| PR.PS-06 | Secure software development practices integrated and monitored throughout SDLC | NOT ASSESSED |
| PR.PT-01 | Audit/log records determined, documented, implemented, and reviewed per policy (CSF 1.1 ref) | NOT ASSESSED |
| PR.PT-03 | Principle of least functionality incorporated by configuring systems to provide only essential capabilities (CSF 1.1 ref) | NOT ASSESSED |
| PR.PT-04 | Communications and control networks protected (CSF 1.1 ref) | NOT ASSESSED |
| PR.PT-05 | Mechanisms for resilience requirements implemented (CSF 1.1 ref) | NOT ASSESSED |
| DE.AE-01 | Baseline of network operations and expected data flows established and managed | NOT ASSESSED |
| DE.AE-03 | Information correlated from multiple sources | NOT ASSESSED |
| DE.AE-05 | Incident alert thresholds established | NOT ASSESSED |
| DE.AE-06 | Information on adverse events provided to authorized staff and tools | NOT ASSESSED |
| DE.CM-01 | Networks and network services monitored for adverse events | NOT ASSESSED |
| DE.CM-03 | Personnel activity and technology usage monitored for adverse events | NOT ASSESSED |
| DE.CM-04 | Malicious code detected | NOT ASSESSED |
| DE.CM-05 | Unauthorized mobile code detected | NOT ASSESSED |
| DE.CM-07 | Monitoring for unauthorized personnel, connections, devices, and software performed | NOT ASSESSED |
| DE.CM-08 | Vulnerability scans performed | NOT ASSESSED |
| DE.CM-09 | Computing hardware, software, runtime environments, and data monitored for adverse events | NOT ASSESSED |
| DE.DP-04 | Event detection information communicated | NOT ASSESSED |
| RS.AN-05 | Processes established to receive, analyse, and respond to vulnerability disclosures | NOT ASSESSED |
| RS.AN-07 | Incident data and metadata collected with integrity and provenance preserved | NOT ASSESSED |
| RC.RP-03 | Integrity of backups and restoration assets verified before use | NOT ASSESSED |
| RC.RP-05 | Integrity of restored assets verified; systems and services restored; normal operations resumed | NOT ASSESSED |

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
