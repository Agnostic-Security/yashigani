# PCI DSS v4.0 — Yashigani 4.1.2 — NOT ASSESSED

**Assessment status:** NOT ASSESSED FOR RELEASE 4.1.2. **No compliance rate is published for this framework.**

**Framework version:** PCI DSS v4.0 (PCI Security Standards Council, 2022)

**Controls in scope:** 148

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
| 1.1.1 | Network security controls defined and understood | NOT ASSESSED |
| 1.2.1 | Inbound and outbound traffic restricted to CDE | NOT ASSESSED |
| 1.2.2 | Inbound traffic from untrusted networks restricted | NOT ASSESSED |
| 1.2.3 | Outbound traffic from CDE restricted | NOT ASSESSED |
| 1.2.4 | Accurate network diagrams maintained | NOT ASSESSED |
| 1.2.5 | All services, protocols, and ports identified | NOT ASSESSED |
| 1.2.6 | Security features defined for insecure services | NOT ASSESSED |
| 1.2.8 | Configuration files for network security controls secured | NOT ASSESSED |
| 1.3.1 | Inbound traffic to CDE restricted to necessary | NOT ASSESSED |
| 1.3.2 | Outbound traffic from CDE restricted to necessary | NOT ASSESSED |
| 1.4.1 | NSCs between trusted and untrusted networks | NOT ASSESSED |
| 1.4.2 | Inbound traffic from untrusted to trusted restricted | NOT ASSESSED |
| 2.1.1 | Secure configuration standards defined | NOT ASSESSED |
| 2.2.1 | Configuration standards developed for all system components | NOT ASSESSED |
| 2.2.2 | Vendor default accounts managed | NOT ASSESSED |
| 2.2.3 | Primary function requires different security levels separated | NOT ASSESSED |
| 2.2.4 | Only necessary services, protocols, daemons enabled | NOT ASSESSED |
| 2.2.5 | Insecure services, daemons, protocols not in use | NOT ASSESSED |
| 2.2.6 | System security parameters configured to prevent misuse | NOT ASSESSED |
| 2.2.7 | All non-console admin access encrypted | NOT ASSESSED |
| 2.2.8 | System configurations documented and maintained | NOT ASSESSED |
| 2.2.9 | Vendor default credentials changed before production | NOT ASSESSED |
| 2.2.10 | Security configuration standards applied consistently | NOT ASSESSED |
| 2.2.11 | Configuration drift detection in place | NOT ASSESSED |
| 3.1.1 | Data retention and disposal policies defined | NOT ASSESSED |
| 3.2.1 | Account data storage minimised | NOT ASSESSED |
| 3.3.1 | Sensitive authentication data not retained after authorisation | NOT ASSESSED |
| 3.3.2 | Sensitive authentication data not stored in logs | NOT ASSESSED |
| 3.3.3 | Sensitive authentication data not stored in databases | NOT ASSESSED |
| 3.4.1 | PAN masked when displayed | NOT ASSESSED |
| 3.4.2 | PAN secured with strong cryptography when stored | NOT ASSESSED |
| 3.5.1 | PAN rendered unreadable wherever stored | NOT ASSESSED |
| 3.6.1 | Cryptographic key management procedures defined | NOT ASSESSED |
| 3.6.2 | Secret and private keys secured | NOT ASSESSED |
| 3.7.1 | Cryptographic keys rotated at defined intervals | NOT ASSESSED |
| 3.7.3 | Cryptographic keys stored securely | NOT ASSESSED |
| 3.7.6 | Cleartext cryptographic key components not stored | NOT ASSESSED |
| 3.7.7 | Key management processes documented and implemented | NOT ASSESSED |
| 4.1.1 | Strong cryptography for data in transit defined | NOT ASSESSED |
| 4.2.1 | Strong cryptography used for PAN transmission | NOT ASSESSED |
| 4.2.1.1 | Trusted certificates used | NOT ASSESSED |
| 4.2.1.2 | TLS 1.2 or higher enforced | NOT ASSESSED |
| 4.2.1.3 | Strong cipher suites used | NOT ASSESSED |
| 4.2.2 | PAN secured when sent via end-user messaging | NOT ASSESSED |
| 4.2.4 | Internal network transmissions of PAN encrypted | NOT ASSESSED |
| 4.2.5 | Certificate management processes implemented | NOT ASSESSED |
| 5.1.1 | Anti-malware policies and procedures defined | NOT ASSESSED |
| 6.1.1 | Secure development policies defined | NOT ASSESSED |
| 6.2.1 | Custom software developed securely | NOT ASSESSED |
| 6.2.3 | Custom software reviewed for vulnerabilities | NOT ASSESSED |
| 6.2.3.1 | Manual code review performed for custom software | NOT ASSESSED |
| 6.2.3.2 | Automated code analysis for custom software | NOT ASSESSED |
| 6.2.4 | Common software attacks prevented | NOT ASSESSED |
| 6.2.4.1 | Injection attacks prevented | NOT ASSESSED |
| 6.2.4.2 | XSS attacks prevented | NOT ASSESSED |
| 6.2.4.3 | CSRF attacks prevented | NOT ASSESSED |
| 6.2.4.4 | SSRF attacks prevented | NOT ASSESSED |
| 6.2.4.5 | Path traversal prevented | NOT ASSESSED |
| 6.3.1 | Security vulnerabilities identified and addressed | NOT ASSESSED |
| 6.3.2 | Third-party software inventoried | NOT ASSESSED |
| 6.3.3 | Critical patches installed within one month | NOT ASSESSED |
| 6.4.1 | Public-facing web applications protected against attacks | NOT ASSESSED |
| 6.4.3 | Payment page scripts managed and integrity verified | NOT ASSESSED |
| 6.5.1 | Changes to system components follow change management | NOT ASSESSED |
| 6.5.2 | Changes tested and approved before production | NOT ASSESSED |
| 6.5.3 | Pre-production and production environments separated | NOT ASSESSED |
| 6.5.6 | Test data and accounts removed before production | NOT ASSESSED |
| 7.1.1 | Access control policies defined | NOT ASSESSED |
| 7.2.1 | Access control model defined | NOT ASSESSED |
| 7.2.2 | Access assigned based on job function and need | NOT ASSESSED |
| 7.2.5 | Application and system accounts managed | NOT ASSESSED |
| 7.2.6 | Access to query repositories of cardholder data restricted | NOT ASSESSED |
| 7.3.1 | Access control system in place | NOT ASSESSED |
| 7.3.2 | Access control system configured to enforce least privilege | NOT ASSESSED |
| 7.3.3 | Access control system set to deny all by default | NOT ASSESSED |
| 7.3.4 | Access to sensitive areas restricted to authorised users | NOT ASSESSED |
| 7.3.5 | Access to audit logs restricted | NOT ASSESSED |
| 7.3.6 | Access to security tools and configurations restricted | NOT ASSESSED |
| 8.1.1 | Identification and authentication policies defined | NOT ASSESSED |
| 8.2.1 | All users assigned unique IDs | NOT ASSESSED |
| 8.2.2 | Group, shared, or generic accounts not used | NOT ASSESSED |
| 8.2.3 | Service accounts used only for intended purpose | NOT ASSESSED |
| 8.2.4 | Addition and deletion of user IDs managed | NOT ASSESSED |
| 8.2.5 | Access revoked for terminated users immediately | NOT ASSESSED |
| 8.2.6 | Inactive accounts removed or disabled within 90 days | NOT ASSESSED |
| 8.2.8 | Session idle timeout of 15 minutes or less | NOT ASSESSED |
| 8.3.1 | Authentication factors for all users and administrators | NOT ASSESSED |
| 8.3.2 | Strong cryptography for authentication | NOT ASSESSED |
| 8.3.3 | User identity verified for authentication factor changes | NOT ASSESSED |
| 8.3.4 | Invalid authentication attempts limited | NOT ASSESSED |
| 8.3.5 | Account lockout duration at least 30 minutes | NOT ASSESSED |
| 8.3.6 | Passwords meet minimum complexity | NOT ASSESSED |
| 8.3.7 | New passwords different from previous four | NOT ASSESSED |
| 8.3.9 | Passwords changed at least every 90 days if sole factor | NOT ASSESSED |
| 8.3.10 | MFA for all access into CDE | NOT ASSESSED |
| 8.3.10.1 | MFA for all non-console administrative access | NOT ASSESSED |
| 8.3.11 | Physical token or smart card for MFA | NOT ASSESSED |
| 8.4.1 | MFA implemented for all CDE access | NOT ASSESSED |
| 8.4.2 | MFA for all remote network access | NOT ASSESSED |
| 8.4.3 | MFA for all remote access from outside network | NOT ASSESSED |
| 10.1.1 | Logging and monitoring policies defined | NOT ASSESSED |
| 10.2.1 | Audit logs enabled for all system components | NOT ASSESSED |
| 10.2.1.1 | All individual user accesses to cardholder data logged | NOT ASSESSED |
| 10.2.1.2 | All actions by individuals with administrative access logged | NOT ASSESSED |
| 10.2.1.3 | Access to audit trails logged | NOT ASSESSED |
| 10.2.1.4 | Invalid logical access attempts logged | NOT ASSESSED |
| 10.2.1.5 | Changes to identification and authentication logged | NOT ASSESSED |
| 10.2.1.6 | Initialisation of audit logs logged | NOT ASSESSED |
| 10.2.1.7 | Creation and deletion of system-level objects logged | NOT ASSESSED |
| 10.2.2 | Audit log entries contain required details | NOT ASSESSED |
| 10.3.1 | Audit trail records for all access captured | NOT ASSESSED |
| 10.3.2 | Audit trail protected from modification | NOT ASSESSED |
| 10.3.3 | Audit trail files backed up | NOT ASSESSED |
| 10.3.4 | File integrity monitoring on audit trails | NOT ASSESSED |
| 10.4.1.1 | Automated mechanisms for log review | NOT ASSESSED |
| 10.5.1 | Audit log history retained for at least 12 months | NOT ASSESSED |
| 10.5.2 | At least 3 months of logs immediately available | NOT ASSESSED |
| 10.6.1 | System clocks synchronised using NTP | NOT ASSESSED |
| 10.7.1 | Failures of critical security controls detected and addressed | NOT ASSESSED |
| 11.1.1 | Security testing policies defined | NOT ASSESSED |
| 11.3.1 | Internal vulnerability scans quarterly | NOT ASSESSED |
| 11.3.1.3 | Internal scans after significant changes | NOT ASSESSED |
| 11.5.1 | Intrusion detection / prevention techniques in place | NOT ASSESSED |
| 11.5.1.1 | IDS/IPS alerts monitored | NOT ASSESSED |
| 11.5.2 | Change detection mechanism deployed | NOT ASSESSED |
| 11.6.1 | Payment page change monitoring | NOT ASSESSED |
| 11.5.3 | Alert personnel of unauthorised critical file changes | NOT ASSESSED |
| 11.5.5 | File comparisons performed for changes | NOT ASSESSED |
| 6.2.1.1 | Secure coding guidelines followed | NOT ASSESSED |
| 6.2.1.2 | Code review includes security checklist | NOT ASSESSED |
| 6.3.3.1 | Automated dependency vulnerability scanning in CI | NOT ASSESSED |
| 6.4.1.1 | Security headers configured on web applications | NOT ASSESSED |
| 6.4.1.2 | HTTP response headers prevent information leakage | NOT ASSESSED |
| 8.3.1.1 | Strong authentication for all API access | NOT ASSESSED |
| 8.3.2.1 | Password hashing uses adaptive one-way function | NOT ASSESSED |
| 8.3.6.1 | Passwords checked against breach databases | NOT ASSESSED |
| 8.2.8.1 | Session tokens invalidated on logout | NOT ASSESSED |
| 10.2.1.8 | All API access logged | NOT ASSESSED |
| 10.2.2.1 | Logs include source IP address | NOT ASSESSED |
| 10.2.2.2 | Logs include user identity | NOT ASSESSED |
| 10.4.1.2 | Real-time alerting for critical security events | NOT ASSESSED |
| 11.3.1.4 | Container image vulnerability scanning | NOT ASSESSED |
| 11.5.1.2 | Web application firewall or equivalent protection | NOT ASSESSED |
| 3.4.3 | Tokenisation used where possible | NOT ASSESSED |
| 3.5.3 | Key-encrypting keys at least as strong as data-encrypting keys | NOT ASSESSED |
| 4.2.1.4 | Certificate pinning or strict transport security | NOT ASSESSED |
| 4.2.1.5 | Perfect forward secrecy enabled | NOT ASSESSED |
| 6.2.4.6 | Business logic attacks prevented | NOT ASSESSED |

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
