# NIST SP 800-53 Rev 5 — Moderate baseline — Yashigani 4.1.2 — NOT ASSESSED

**Assessment status:** NOT ASSESSED FOR RELEASE 4.1.2. **No compliance rate is published for this framework.**

**Framework version:** NIST SP 800-53 Rev 5 (Moderate baseline)

**Controls in scope:** 157

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
| AC-2 | Account Management | NOT ASSESSED |
| AC-2(1) | Account Management — Automated System Account Management | NOT ASSESSED |
| AC-2(2) | Account Management — Automated Temporary and Emergency Accounts | NOT ASSESSED |
| AC-2(3) | Account Management — Disable Accounts | NOT ASSESSED |
| AC-2(4) | Account Management — Automated Audit Actions | NOT ASSESSED |
| AC-2(5) | Account Management — Inactivity Logout | NOT ASSESSED |
| AC-3 | Access Enforcement | NOT ASSESSED |
| AC-4 | Information Flow Enforcement | NOT ASSESSED |
| AC-5 | Separation of Duties | NOT ASSESSED |
| AC-6 | Least Privilege | NOT ASSESSED |
| AC-6(1) | Least Privilege — Authorize Access to Security Functions | NOT ASSESSED |
| AC-6(2) | Least Privilege — Non-Privileged Access for Non-Security Functions | NOT ASSESSED |
| AC-6(5) | Least Privilege — Privileged Accounts | NOT ASSESSED |
| AC-6(9) | Least Privilege — Log Use of Privileged Functions | NOT ASSESSED |
| AC-6(10) | Least Privilege — Prohibit Non-Privileged Users from Executing Privileged Functions | NOT ASSESSED |
| AC-7 | Unsuccessful Logon Attempts | NOT ASSESSED |
| AC-8 | System Use Notification | NOT ASSESSED |
| AC-10 | Concurrent Session Control | NOT ASSESSED |
| AC-11 | Device Lock | NOT ASSESSED |
| AC-12 | Session Termination | NOT ASSESSED |
| AC-14 | Permitted Actions Without Identification or Authentication | NOT ASSESSED |
| AC-17 | Remote Access | NOT ASSESSED |
| AC-17(1) | Remote Access — Monitoring and Control | NOT ASSESSED |
| AU-2 | Event Logging | NOT ASSESSED |
| AU-3 | Content of Audit Records | NOT ASSESSED |
| AU-3(1) | Content of Audit Records — Additional Audit Information | NOT ASSESSED |
| AU-4 | Audit Log Storage Capacity | NOT ASSESSED |
| AU-5 | Response to Audit Logging Process Failures | NOT ASSESSED |
| AU-6 | Audit Record Review, Analysis, and Reporting | NOT ASSESSED |
| AU-6(1) | Audit Review — Automated Process Integration | NOT ASSESSED |
| AU-7 | Audit Record Reduction and Report Generation | NOT ASSESSED |
| AU-8 | Time Stamps | NOT ASSESSED |
| AU-9 | Protection of Audit Information | NOT ASSESSED |
| AU-9(4) | Protection of Audit Information — Access by Subset of Privileged Users | NOT ASSESSED |
| AU-11 | Audit Record Retention | NOT ASSESSED |
| AU-12 | Audit Record Generation | NOT ASSESSED |
| AU-12(1) | Audit Record Generation — System-Wide Audit Trail | NOT ASSESSED |
| AU-12(3) | Audit Record Generation — Changes by Authorised Individuals | NOT ASSESSED |
| CA-7 | Continuous Monitoring | NOT ASSESSED |
| CA-7(4) | Continuous Monitoring — Risk Monitoring | NOT ASSESSED |
| CA-9 | Internal System Connections | NOT ASSESSED |
| CM-2 | Baseline Configuration | NOT ASSESSED |
| CM-3 | Configuration Change Control | NOT ASSESSED |
| CM-3(2) | Configuration Change Control — Testing, Validation, and Documentation | NOT ASSESSED |
| CM-6 | Configuration Settings | NOT ASSESSED |
| CM-7 | Least Functionality | NOT ASSESSED |
| CP-9 | System Backup | NOT ASSESSED |
| CP-10 | System Recovery and Reconstitution | NOT ASSESSED |
| CP-10(2) | System Recovery — Transaction Recovery | NOT ASSESSED |
| IA-2 | Identification and Authentication (Organisational Users) | NOT ASSESSED |
| IA-2(1) | Identification and Authentication — Multi-Factor Authentication | NOT ASSESSED |
| IA-2(2) | Identification and Authentication — MFA for Non-Privileged Accounts | NOT ASSESSED |
| IA-2(8) | Identification and Authentication — Access to Accounts — Replay Resistant | NOT ASSESSED |
| IA-3 | Device Identification and Authentication | NOT ASSESSED |
| IA-4 | Identifier Management | NOT ASSESSED |
| IA-5 | Authenticator Management | NOT ASSESSED |
| IA-5(1) | Authenticator Management — Password-Based Authentication | NOT ASSESSED |
| IA-5(2) | Authenticator Management — PKI-Based Authentication | NOT ASSESSED |
| IA-6 | Authentication Feedback | NOT ASSESSED |
| IA-8 | Identification and Authentication (Non-Organisational Users) | NOT ASSESSED |
| IR-4 | Incident Handling | NOT ASSESSED |
| IR-4(1) | Incident Handling — Automated Incident Handling Processes | NOT ASSESSED |
| IR-5 | Incident Monitoring | NOT ASSESSED |
| PS-4 | Personnel Termination | NOT ASSESSED |
| PT-3 | PII Processing Purposes | NOT ASSESSED |
| PT-4 | Consent | NOT ASSESSED |
| PT-7 | Specific Categories of PII | NOT ASSESSED |
| RA-5 | Vulnerability Monitoring and Scanning | NOT ASSESSED |
| RA-5(2) | Vulnerability Scanning — Update Vulnerabilities to Be Scanned | NOT ASSESSED |
| SA-4(9) | Acquisition Process — Functions, Ports, Protocols, and Services | NOT ASSESSED |
| SA-10 | Developer Configuration Management | NOT ASSESSED |
| SA-11 | Developer Testing and Evaluation | NOT ASSESSED |
| SA-11(1) | Developer Testing — Static Code Analysis | NOT ASSESSED |
| SA-11(2) | Developer Testing — Threat Modelling and Vulnerability Analyses | NOT ASSESSED |
| SA-11(8) | Developer Testing — Dynamic Code Analysis | NOT ASSESSED |
| SC-2 | Separation of System and User Functionality | NOT ASSESSED |
| SC-4 | Information in Shared System Resources | NOT ASSESSED |
| SC-5 | Denial-of-Service Protection | NOT ASSESSED |
| SC-7 | Boundary Protection | NOT ASSESSED |
| SC-7(3) | Boundary Protection — Access Points | NOT ASSESSED |
| SC-7(4) | Boundary Protection — External Telecommunications Services | NOT ASSESSED |
| SC-7(5) | Boundary Protection — Deny by Default / Allow by Exception | NOT ASSESSED |
| SC-7(8) | Boundary Protection — Route Traffic to Authenticated Proxy | NOT ASSESSED |
| SC-8 | Transmission Confidentiality and Integrity | NOT ASSESSED |
| SC-8(1) | Transmission Protection — Cryptographic Protection | NOT ASSESSED |
| SC-10 | Network Disconnect | NOT ASSESSED |
| SC-12 | Cryptographic Key Establishment and Management | NOT ASSESSED |
| SC-12(1) | Cryptographic Key Management — Availability | NOT ASSESSED |
| SC-13 | Cryptographic Protection | NOT ASSESSED |
| SC-17 | Public Key Infrastructure Certificates | NOT ASSESSED |
| SC-18 | Mobile Code | NOT ASSESSED |
| SC-23 | Session Authenticity | NOT ASSESSED |
| SC-28 | Protection of Information at Rest | NOT ASSESSED |
| SC-28(1) | Protection at Rest — Cryptographic Protection | NOT ASSESSED |
| SC-39 | Process Isolation | NOT ASSESSED |
| SC-3 | Security Function Isolation | NOT ASSESSED |
| SC-6 | Resource Availability | NOT ASSESSED |
| SC-7(21) | Boundary Protection — Isolation of System Components | NOT ASSESSED |
| SC-8(2) | Transmission Protection — Pre- and Post-Transmission Handling | NOT ASSESSED |
| SC-12(2) | Cryptographic Key Management — Symmetric Keys | NOT ASSESSED |
| SC-12(3) | Cryptographic Key Management — Asymmetric Keys | NOT ASSESSED |
| SC-23(3) | Session Authenticity — Unique Session Identifiers | NOT ASSESSED |
| SC-23(5) | Session Authenticity — Allowed Certificate Authorities | NOT ASSESSED |
| SC-24 | Fail in Known State | NOT ASSESSED |
| SC-26 | Decoys | NOT ASSESSED |
| SC-44 | Detonation Chambers | NOT ASSESSED |
| SI-2 | Flaw Remediation | NOT ASSESSED |
| SI-2(2) | Flaw Remediation — Automated Flaw Remediation Status | NOT ASSESSED |
| SI-3 | Malicious Code Protection | NOT ASSESSED |
| SI-4 | System Monitoring | NOT ASSESSED |
| SI-4(2) | System Monitoring — Automated Tools and Mechanisms | NOT ASSESSED |
| SI-4(4) | System Monitoring — Inbound and Outbound Communications Traffic | NOT ASSESSED |
| SI-4(5) | System Monitoring — System-Generated Alerts | NOT ASSESSED |
| SI-7 | Software, Firmware, and Information Integrity | NOT ASSESSED |
| SI-7(1) | Integrity Verification — Integrity Checks | NOT ASSESSED |
| SI-7(7) | Integrity Verification — Integration of Detection and Response | NOT ASSESSED |
| SI-10 | Information Input Validation | NOT ASSESSED |
| SI-11 | Error Handling | NOT ASSESSED |
| SR-4 | Provenance | NOT ASSESSED |
| SR-9 | Tamper Resistance and Detection | NOT ASSESSED |
| SR-11 | Component Authenticity | NOT ASSESSED |
| AC-3(4) | Access Enforcement — Discretionary Access Control | NOT ASSESSED |
| AC-4(4) | Information Flow — Content Check | NOT ASSESSED |
| AC-16 | Security and Privacy Attributes | NOT ASSESSED |
| AU-6(3) | Audit Review — Correlate Audit Record Repositories | NOT ASSESSED |
| AU-6(5) | Audit Review — Integrated Analysis of Audit Records | NOT ASSESSED |
| CM-5(1) | Access Restrictions for Change — Automated Access Enforcement | NOT ASSESSED |
| CM-7(2) | Least Functionality — Prevent Program Execution | NOT ASSESSED |
| CM-8(1) | System Component Inventory — Updates During Installation and Removal | NOT ASSESSED |
| CM-8(3) | System Component Inventory — Automated Unauthorised Component Detection | NOT ASSESSED |
| IA-2(6) | Identification and Authentication — Access to Accounts — Separate Device | NOT ASSESSED |
| IA-2(12) | Identification and Authentication — Acceptance of PIV Credentials | NOT ASSESSED |
| IA-4(4) | Identifier Management — Identify User Status | NOT ASSESSED |
| IA-5(6) | Authenticator Management — Protection of Authenticators | NOT ASSESSED |
| IA-5(7) | Authenticator Management — No Embedded Unencrypted Static Authenticators | NOT ASSESSED |
| IA-11 | Re-Authentication | NOT ASSESSED |
| SC-7(9) | Boundary Protection — Restrict Threatening Outgoing Traffic | NOT ASSESSED |
| SC-7(10) | Boundary Protection — Prevent Exfiltration | NOT ASSESSED |
| SC-7(18) | Boundary Protection — Fail Secure | NOT ASSESSED |
| SC-23(1) | Session Authenticity — Invalidate Session Identifiers at Logout | NOT ASSESSED |
| SC-25 | Thin Nodes | NOT ASSESSED |
| SC-36 | Distributed Processing and Storage | NOT ASSESSED |
| SI-4(7) | System Monitoring — Automated Response to Suspicious Events | NOT ASSESSED |
| SI-6 | Security and Privacy Function Verification | NOT ASSESSED |
| SI-7(2) | Integrity Verification — Automated Notifications of Integrity Violations | NOT ASSESSED |
| SI-7(5) | Integrity Verification — Automated Response to Integrity Violations | NOT ASSESSED |
| SI-8 | Spam Protection | NOT ASSESSED |
| SI-10(1) | Information Input Validation — Manual Override | NOT ASSESSED |
| SA-10(1) | Developer Configuration Management — Software and Firmware Integrity Verification | NOT ASSESSED |
| SA-15(1) | Development Process — Security and Privacy in Development Environment | NOT ASSESSED |
| IR-4(4) | Incident Handling — Information Correlation | NOT ASSESSED |
| IR-7(1) | Incident Response Assistance — Automation Support | NOT ASSESSED |
| SR-4(1) | Provenance — Identity | NOT ASSESSED |
| SR-4(2) | Provenance — Track and Trace | NOT ASSESSED |
| AC-2(7) | Account Management — Privileged User Accounts | NOT ASSESSED |
| SC-7(11) | Boundary Protection — Restrict Incoming Communications Traffic | NOT ASSESSED |
| SI-4(12) | System Monitoring — Automated Organisation-Generated Alerts | NOT ASSESSED |

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
