# OWASP ASVS v5 (Application Security Verification Standard) — Yashigani 4.1.2 — NOT ASSESSED

**Assessment status:** NOT ASSESSED FOR RELEASE 4.1.2. **No compliance rate is published for this framework.**

**Framework version:** OWASP ASVS v5 — Level 3

**Controls in scope:** 182

**Prior assessment:** v2.23.2 (assessed 2026-05-08) — **verdicts withdrawn 2026-08-16**, finding `YCS-20260816-v4.1.2-TB-01`.

> **No control in this document is asserted to pass, fail, or be out of scope.**
> Yashigani 4.1.2 has not been assessed against this framework. Any statement to
> the contrary that predates this file is withdrawn and must not be relied on.

## Why the previous verdicts were withdrawn

The verdicts previously published here are withdrawn for four independent
reasons, any one of which invalidates the former 100.0% headline:

1. **The chapter taxonomy is ASVS v4-era, labelled as v5.** The report used
   `V2 Authentication`, `V6 Stored Cryptography`, `V7 Error Handling & Logging` and
   `V8 Data Protection`. Canonical ASVS v5.0 is `V2 Validation and Business Logic`,
   `V6 Authentication`, `V7 Session Management`, `V8 Authorization`; logging is `V16`,
   cryptography is `V11`, data protection is `V14`.
2. **38% of the control IDs are not ASVS v5 controls** — 70 of the 182 IDs carried here do not
   appear in the canonical ASVS v5 control set.
3. **At least one verdict was false on its own terms.** `V16.1.1 All security events logged |
   PASS` does not hold: `AGENT_REGISTERED` is defined in `src/yashigani/audit/schema.py` but has
   no emitter on any production path, and no `ADMIN_CREATED` / `ADMIN_ACCOUNT_CREATED` event
   type exists at all — admin bootstrap creation emits no audit event.
4. **Ten verdicts were evidenced by internal agent-memory notes** under `~/.claude/`
   (`feedback_zero_trust_default.md` and similar). Those files are not shipped, not in the
   product, and unresolvable by any customer or third-party auditor.

The assessment was also performed against v2.23.2 (2026-05-08) and never re-run for 4.1.2.

## Control scope (enumeration only — no verdicts)

The control set below records which controls a future assessment would need to
cover. It carries no verdicts and no evidence.

| Control ID | Control name | 4.1.2 status |
|---|---|---|
| V1.2.1 | Output encoding context-aware | NOT ASSESSED |
| V1.2.2 | Output encoding by sink | NOT ASSESSED |
| V1.2.3 | Encoding library | NOT ASSESSED |
| V1.2.4 | Encoding when concatenating | NOT ASSESSED |
| V1.3.1 | Input validation framework | NOT ASSESSED |
| V1.3.2 | Validate by type | NOT ASSESSED |
| V1.3.3 | Validation server-side | NOT ASSESSED |
| V1.3.4 | Validate range/length/format | NOT ASSESSED |
| V1.4.1 | Sanitize HTML/SQL/LDAP/XML/XPATH | NOT ASSESSED |
| V1.4.2 | Sanitize file paths | NOT ASSESSED |
| V1.4.3 | Sanitize URL components | NOT ASSESSED |
| V1.4.4 | Sanitize OS commands | NOT ASSESSED |
| V1.5.1 | Deserialize untrusted | NOT ASSESSED |
| V1.5.2 | XML external entities | NOT ASSESSED |
| V1.5.3 | SSI / template injection | NOT ASSESSED |
| V1.6.1 | Header smuggling guard | NOT ASSESSED |
| V1.6.2 | CRLF injection | NOT ASSESSED |
| V1.7.1 | Sanitize log content | NOT ASSESSED |
| V1.7.2 | No raw user input in logs | NOT ASSESSED |
| V2.1.1 | Min length 12 | NOT ASSESSED |
| V2.1.2 | Allow all chars / no truncation | NOT ASSESSED |
| V2.1.3 | No periodic rotation | NOT ASSESSED |
| V2.1.5 | Allow paste | NOT ASSESSED |
| V2.1.7 | Breach-DB check | NOT ASSESSED |
| V2.1.8 | Show entropy meter | NOT ASSESSED |
| V2.1.9 | No password hints | NOT ASSESSED |
| V2.1.10 | No knowledge-based auth | NOT ASSESSED |
| V2.1.11 | Password history (no reuse) | NOT ASSESSED |
| V2.1.12 | Context banned words | NOT ASSESSED |
| V2.2.1 | Anti-automation throttle | NOT ASSESSED |
| V2.2.2 | Generic error message | NOT ASSESSED |
| V2.2.3 | Authenticated rate limit not bypassable by reset | NOT ASSESSED |
| V2.2.4 | Account lockout | NOT ASSESSED |
| V2.2.5 | Brute-force resistance | NOT ASSESSED |
| V2.3.1 | Authentication factor — TOTP | NOT ASSESSED |
| V2.3.2 | Authentication factor — WebAuthn/FIDO2 | NOT ASSESSED |
| V2.4.1 | Verifier impersonation resistance | NOT ASSESSED |
| V2.5.1 | Anti-counterfeiting (TOTP secret per account) | NOT ASSESSED |
| V2.5.2 | Replay-resistant OTP | NOT ASSESSED |
| V2.6.1 | OOB authenticator (recovery codes) | NOT ASSESSED |
| V2.7.1 | Cryptographic auth disabled by default | NOT ASSESSED |
| V2.8.1 | Single-use OTP | NOT ASSESSED |
| V2.8.2 | OOB delivery secured | NOT ASSESSED |
| V2.8.3 | OTP replay defeated across windows | NOT ASSESSED |
| V2.9.1 | Cryptographic device bind to user | NOT ASSESSED |
| V2.10.1 | Service authentication (mTLS) | NOT ASSESSED |
| V3.1.1 | Session token entropy ≥128-bit | NOT ASSESSED |
| V3.2.1 | Generate at logon | NOT ASSESSED |
| V3.2.2 | Idle timeout | NOT ASSESSED |
| V3.2.3 | Absolute timeout | NOT ASSESSED |
| V3.2.4 | Re-auth on privilege escalation | NOT ASSESSED |
| V3.3.1 | Logout invalidates server-side | NOT ASSESSED |
| V3.3.2 | Logout invalidates all sessions on credential change | NOT ASSESSED |
| V3.3.3 | No concurrent sessions per user | NOT ASSESSED |
| V3.4.1 | HttpOnly cookie | NOT ASSESSED |
| V3.4.2 | Secure flag | NOT ASSESSED |
| V3.4.3 | SameSite=Strict | NOT ASSESSED |
| V3.4.4 | `__Host-` prefix | NOT ASSESSED |
| V3.5.1 | Token storage server-side only | NOT ASSESSED |
| V3.5.2 | Bind session to user-agent/IP | NOT ASSESSED |
| V3.5.3 | No session ID in URL | NOT ASSESSED |
| V3.5.4 | SSO state/nonce single-use | NOT ASSESSED |
| V3.6.1 | Re-auth before sensitive op | NOT ASSESSED |
| V3.7.1 | Anti-CSRF — SameSite=Strict | NOT ASSESSED |
| V4.1.1 | Default deny | NOT ASSESSED |
| V4.1.2 | Authn enforced before authz | NOT ASSESSED |
| V4.1.3 | Centralized authz logic | NOT ASSESSED |
| V4.1.4 | Server-side authz | NOT ASSESSED |
| V4.1.5 | Step-up auth on sensitive ops | NOT ASSESSED |
| V4.2.1 | Function-level authz (BFLA) | NOT ASSESSED |
| V4.2.2 | Object-level authz (BOLA) | NOT ASSESSED |
| V4.2.3 | Negative test for IDOR | NOT ASSESSED |
| V4.3.1 | Admin segregation | NOT ASSESSED |
| V4.3.2 | Multi-tenancy data isolation | NOT ASSESSED |
| V4.3.3 | Service-to-service authz | NOT ASSESSED |
| V4.4.1 | ABAC/RBAC implemented | NOT ASSESSED |
| V5.1.1 | File upload allowlist by type | NOT ASSESSED |
| V5.1.2 | File size limit | NOT ASSESSED |
| V5.1.3 | Anti-virus scan | NOT ASSESSED |
| V5.2.1 | File path traversal prevention | NOT ASSESSED |
| V5.2.2 | Symlink resolution | NOT ASSESSED |
| V5.3.1 | File metadata stripped | NOT ASSESSED |
| V5.4.1 | Temporary files secure | NOT ASSESSED |
| V5.5.1 | No file inclusion via user input | NOT ASSESSED |
| V6.1.1 | Approved algorithms | NOT ASSESSED |
| V6.1.2 | Random number generation | NOT ASSESSED |
| V6.1.3 | Key length minimums | NOT ASSESSED |
| V6.2.1 | Stored secret protection | NOT ASSESSED |
| V6.2.2 | No hardcoded secrets | NOT ASSESSED |
| V6.3.1 | Key management — rotation | NOT ASSESSED |
| V6.3.2 | Keys not exposed in logs | NOT ASSESSED |
| V6.4.1 | Crypto inventory | NOT ASSESSED |
| V6.5.1 | No deprecated crypto | NOT ASSESSED |
| V7.1.1 | Generic 500 page | NOT ASSESSED |
| V7.1.2 | No PII in logs | NOT ASSESSED |
| V7.2.1 | Audit security events | NOT ASSESSED |
| V7.2.2 | Tamper-evident audit log | NOT ASSESSED |
| V7.2.3 | Audit log integrity protection | NOT ASSESSED |
| V7.3.1 | Time synchronization | NOT ASSESSED |
| V7.3.2 | Log forwarding to SIEM | NOT ASSESSED |
| V7.3.3 | SIEM forwarding failure logged | NOT ASSESSED |
| V7.4.1 | No security errors leaked | NOT ASSESSED |
| V8.1.1 | Sensitive data classified | NOT ASSESSED |
| V8.1.2 | Data minimization in logs | NOT ASSESSED |
| V8.2.1 | Sensitive data encrypted at rest | NOT ASSESSED |
| V8.2.2 | Sensitive data encrypted in transit | NOT ASSESSED |
| V8.3.1 | Cache control | NOT ASSESSED |
| V8.3.2 | No sensitive data in URLs | NOT ASSESSED |
| V8.3.3 | Permission propagation TTL | NOT ASSESSED |
| V8.4.1 | Backup encryption | NOT ASSESSED |
| V8.5.1 | Data retention | NOT ASSESSED |
| V9.1.1 | TLS for all communications | NOT ASSESSED |
| V9.1.2 | Server certificate validation | NOT ASSESSED |
| V9.1.3 | Approved cipher suites | NOT ASSESSED |
| V9.1.4 | TLS termination at trust boundary | NOT ASSESSED |
| V9.2.1 | Mutual TLS for sensitive APIs | NOT ASSESSED |
| V9.2.2 | Certificate revocation | NOT ASSESSED |
| V9.2.3 | Header smuggling defence | NOT ASSESSED |
| V9.3.1 | No sensitive data in cleartext channels | NOT ASSESSED |
| V9.4.1 | Strong cipher key sizes | NOT ASSESSED |
| V9.5.1 | HSTS on edge | NOT ASSESSED |
| V10.1.1 | SAST in CI | NOT ASSESSED |
| V10.1.2 | SCA in CI | NOT ASSESSED |
| V10.1.3 | Container scan in CI | NOT ASSESSED |
| V10.1.4 | Secrets scan in CI | NOT ASSESSED |
| V10.2.1 | Software supply chain integrity | NOT ASSESSED |
| V10.2.2 | SBOM generated | NOT ASSESSED |
| V10.3.1 | Code signing | NOT ASSESSED |
| V10.3.2 | Header smuggling defence | NOT ASSESSED |
| V11.1.1 | Business logic flows enforced | NOT ASSESSED |
| V11.1.2 | Default-deny ACL | NOT ASSESSED |
| V11.1.3 | Anti-automation business limits | NOT ASSESSED |
| V11.1.4 | Business logic time-of-check / time-of-use | NOT ASSESSED |
| V11.2.1 | Sequential workflow enforcement | NOT ASSESSED |
| V11.2.2 | Anti-replay (TOTP, JWT, session) | NOT ASSESSED |
| V11.2.3 | Tool-use confirmation for high-risk actions | NOT ASSESSED |
| V11.2.4 | Constant-time comparison for security | NOT ASSESSED |
| V12.1.1 | OpenAPI/contract publication | NOT ASSESSED |
| V12.1.2 | Schema validation on every API | NOT ASSESSED |
| V12.2.1 | Authentication required on every API | NOT ASSESSED |
| V12.3.1 | Rate-limit per API endpoint | NOT ASSESSED |
| V12.4.1 | CORS allowlist | NOT ASSESSED |
| V12.5.1 | Versioned APIs | NOT ASSESSED |
| V12.6.1 | Strong content-type | NOT ASSESSED |
| V12.7.1 | SSRF defence on outbound | NOT ASSESSED |
| V13.1.1 | No default credentials in prod | NOT ASSESSED |
| V13.1.2 | Fail-closed on missing secrets | NOT ASSESSED |
| V13.1.3 | Secrets not in env-leak | NOT ASSESSED |
| V13.2.1 | Container image hardening | NOT ASSESSED |
| V13.2.2 | Container security context | NOT ASSESSED |
| V13.2.3 | Read-only root FS | NOT ASSESSED |
| V13.3.1 | No debug endpoints in prod | NOT ASSESSED |
| V13.3.2 | No verbose error pages | NOT ASSESSED |
| V13.4.1 | Dependency pinning | NOT ASSESSED |
| V13.4.2 | Service-identity manifest single-source | NOT ASSESSED |
| V13.5.1 | Rate-limiter fail mode is admin-configurable | NOT ASSESSED |
| V14.1.1 | Build pipeline integrity | NOT ASSESSED |
| V14.1.2 | No secrets in build env | NOT ASSESSED |
| V14.1.3 | Reproducible builds | NOT ASSESSED |
| V14.2.1 | SBOM published per release | NOT ASSESSED |
| V14.2.2 | Vulnerability monitoring | NOT ASSESSED |
| V14.3.1 | Container runtime parity tested | NOT ASSESSED |
| V14.3.2 | IaC scanning | NOT ASSESSED |
| V14.4.1 | Cryptographic service identity | NOT ASSESSED |
| V14.4.2 | Identity propagation across hops | NOT ASSESSED |
| V15.1.1 | Secure-by-default architecture | NOT ASSESSED |
| V15.1.2 | Defence in depth | NOT ASSESSED |
| V15.2.1 | Code review before merge | NOT ASSESSED |
| V15.2.2 | Threat-model per release | NOT ASSESSED |
| V15.3.1 | Async/await consistency | NOT ASSESSED |
| V15.4.1 | No `eval`/`exec`/`compile` on untrusted input | NOT ASSESSED |
| V16.1.1 | All security events logged | NOT ASSESSED |
| V16.1.2 | Log integrity (tamper-evident) | NOT ASSESSED |
| V16.1.3 | Centralized log forwarding | NOT ASSESSED |
| V16.2.1 | Time synchronization | NOT ASSESSED |
| V16.2.2 | Log retention policy | NOT ASSESSED |
| V16.3.1 | Generic error responses | NOT ASSESSED |
| V16.3.2 | No stack traces to client | NOT ASSESSED |
| V16.4.1 | Logging service authentication | NOT ASSESSED |
| V17.1.1 | WebRTC | NOT ASSESSED |
| V17.2.1 | IoT/Device protocols | NOT ASSESSED |
| V17.3.1 | Mobile app crypto | NOT ASSESSED |

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
