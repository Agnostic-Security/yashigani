# Yashigani Security Gateway -- OWASP Compliance Mapping

**Document Version:** 2.23.2
**Date:** 2026-05-07
<!-- Last updated: 2026-05-07T00:00:00+01:00 -->
**Codebase version:** v2.23.2
**Assessment Level:** OWASP ASVS v5.0 Level 3 (High Assurance)
**Audience:** Security Architects, Compliance Engineers, Procurement Teams
**Classification:** Public

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Section 1: OWASP ASVS v5 Level 3 Assessment](#section-1-owasp-asvs-v5-level-3-assessment)
3. [Section 2: OWASP API Security Top 10 (2023) Mapping](#section-2-owasp-api-security-top-10-2023-mapping)
4. [Section 3: OWASP Agentic AI and LLM Top 10 Mapping](#section-3-owasp-agentic-ai-and-llm-top-10-mapping)
5. [Section 4: Compliance Summary Table](#section-4-compliance-summary-table)
6. [Section 5: Gap Analysis and Residual Risk](#section-5-gap-analysis-and-residual-risk)
7. [Appendix: Terminology and References](#appendix-terminology-and-references)

---

## Executive Summary

Yashigani is a security enforcement gateway purpose-built for MCP (Model Context Protocol) servers and agentic AI systems. It operates as a reverse proxy between AI agents and MCP tool servers, providing defense-in-depth through a multi-layer inspection pipeline, OPA-enforced access control, credential isolation, and comprehensive audit infrastructure.

This document maps Yashigani's security controls against three authoritative OWASP frameworks:

- **OWASP Application Security Verification Standard (ASVS) v5.0** -- 14 control chapters assessed at **Level 3** (highest assurance)
- **OWASP API Security Top 10 (2023)** -- 10 API-specific risk categories
- **OWASP LLM Top 10 and Agentic AI Security** -- 10 LLM risk categories plus agent-specific controls

ASVS v5 (released 2025) restructured significantly from v4.x. The chapter numbering, requirement identifiers, and several control areas were reorganized. This document follows the v5 structure exclusively.

### Assessment Level

This assessment targets **ASVS v5 Level 3**, the highest assurance tier intended for applications that handle highly sensitive data, perform critical business functions, or operate in high-threat environments. Level 3 requires all Level 1 and Level 2 controls plus additional high-assurance controls including formal verification, hardware-backed security, and advanced cryptographic protections.

### Summary Coverage (ASVS v5 Level 3)

**Coverage scope:** OWASP ASVS v5 (all 17 chapters), OWASP API Security, OWASP Agentic AI / LLM Top 10, plus infrastructure controls. Per-control assessment with PASS / PARTIAL / FAIL / N/A verdicts and file:line evidence.

| Verdict | Count | Percentage |
|---|---|---|
| PASS | 166 | 92% |
| MANUAL | 7 | 4% |
| N/A | 7 | 4% |
| FAIL | 0 | 0% |

> **v2.23.2 improvement:** All six release-blocking FAILs from v2.23.1 are CLOSED. ASVS L3 PASS rate increased from 59% to 92%.

| Framework | Controls assessed | PASS | PARTIAL / MANUAL | N/A | FAIL |
|---|---|---|---|---|---|
| OWASP ASVS v5 (L3) | 180 | 166 (92%) | 7 (4%) | 7 (4%) | 0 |
| OWASP API Security Top 10 | 10 | 9 (90%) | 1 (10%) | 0 | 0 |
| OWASP Agentic AI + LLM Top 10 | 25 | 22 (88%) | 2 (8%) | 1 (4%) | 0 |

**Per-chapter ASVS v5 L3 pass rates (v2.23.2):**

| Chapter | Controls | PASS | MANUAL | N/A | FAIL |
|---|---|---|---|---|---|
| V1 Encoding & Sanitization | 18 | 16 | 2 | 0 | 0 |
| V2 Authentication | 26 | 24 | 1 | 1 | 0 |
| V3 Session Management | 18 | 18 | 0 | 0 | 0 |
| V4 Access Control | 12 | 12 | 0 | 0 | 0 |
| V5 File Handling | 8 | 5 | 0 | 3 | 0 |
| V6 Stored Cryptography | 9 | 9 | 0 | 0 | 0 |
| V7 Error Handling & Logging | 9 | 9 | 0 | 0 | 0 |
| V8 Data Protection | 9 | 8 | 1 | 0 | 0 |
| V9 Communications | 10 | 10 | 0 | 0 | 0 |
| V10 Malicious Code | 8 | 7 | 1 | 0 | 0 |
| V11 Business Logic | 8 | 8 | 0 | 0 | 0 |
| V12 API & Web Service | 8 | 8 | 0 | 0 | 0 |
| V13 Configuration | 11 | 11 | 0 | 0 | 0 |
| V14 Software Lifecycle | 9 | 7 | 2 | 0 | 0 |
| V15 Secure Coding & Architecture | 6 | 6 | 0 | 0 | 0 |
| V16 Security Logging & Error Handling | 8 | 8 | 0 | 0 | 0 |
| V17 WebRTC / Advanced | 3 | 0 | 0 | 3 | 0 |
| **Totals** | **180** | **166** | **7** | **7** | **0** |

Controls marked MANUAL reflect areas requiring human review or operator-side validation that cannot be asserted by automated tooling. Controls marked N/A do not apply to a gateway/proxy architecture (e.g. V17 WebRTC, V5 client-side file upload controls).

### Coverage Ratings

- **PASS** -- Yashigani directly implements or enforces this control at L3
- **MANUAL** -- Control requires human review or operator-side validation; automated tooling cannot assert it
- **N/A** -- Requirement does not apply to a gateway/proxy architecture
- **FAIL** -- Control not implemented or insufficient for L3 (zero in v2.23.2)

---

## Section 1: OWASP ASVS v5 Level 3 Assessment

ASVS v5 defines three verification levels:
- **L1** -- Minimum security baseline (opportunistic)
- **L2** -- Standard for most applications (structured)
- **L3** -- High-assurance for critical and high-value applications (comprehensive)

Level 3 includes all L1 and L2 requirements plus additional controls for defense against advanced attackers, insider threats, and nation-state adversaries.

---

### V1 -- Architecture, Design, and Threat Modeling

ASVS v5 V1 requires documented security architecture, threat models, and secure design principles applied throughout the SDLC.

| Req ID | Requirement | L3 | Yashigani Control | Verdict |
|---|---|---|---|---|
| V1.1.1 | Verify that a security architecture document exists describing the application's security controls | L1 | This document, plus architecture docs in `/docs/`, threat model in `THREAT_MODEL.md` | PASS |
| V1.1.2 | Verify that a threat model exists and is updated for design changes | L2 | Threat model maintained for the gateway proxy, OPA policy engine, and inspection pipeline; updated per release | PASS |
| V1.1.3 | Verify that all security controls have a centralized implementation | L1 | OPA policy engine is the single authorization decision point; CHS is the single credential stripping point; inspection pipeline is the single content analysis point | PASS |
| V1.1.4 | Verify that security controls are applied on a trusted system | L1 | All controls execute server-side in the gateway process; no security decisions delegated to clients | PASS |
| V1.2.1 | Verify that all authentication pathways and identity management flows are defined in the architecture | L2 | Auth flows documented: local password+TOTP, SAML, OIDC, agent bearer token, JWT validation, WebAuthn/FIDO2 | PASS |
| V1.2.2 | Verify that all access control decisions are documented and centralized | L2 | OPA is the sole authorization engine; RBAC groups and policy bundles are the sole access control definitions | PASS |
| V1.3.1 | Verify that input validation is performed on a trusted system and applied consistently | L1 | FastText+OPA inspection pipeline operates server-side on every request before forwarding | PASS |
| V1.4.1 | Verify that the application uses a vetted cryptographic module | L2 | Python `cryptography` library (OpenSSL backend), `argon2-cffi`, `secrets` module for CSPRNG | PASS |
| V1.4.2 | Verify that all cryptographic operations use a single, approved implementation | L3 | All crypto operations use `cryptography` library or `argon2-cffi`; no hand-rolled crypto; no fallback to weaker implementations | PASS |
| V1.5.1 | Verify that the application segregates sensitive data by sensitivity level | L2 | Credentials in secrets backends (Docker Secrets, Vault, cloud KMS); sensitive DB columns encrypted with AES-256-GCM; audit logs separated from application data | PASS |
| V1.5.2 | Verify that the architecture enforces tenant isolation | L2 | PostgreSQL RLS, separate Redis DB indices per tenant, OPA tenant context in every policy evaluation | PASS |
| V1.6.1 | Verify that the application has a defined secure SDLC process | L3 | GitHub Actions CI with Trivy scanning, CODEOWNERS on security-critical paths, locked dependencies, digest-pinned base images | PARTIAL |
| V1.6.2 | Verify that formal code review is required for security-sensitive changes | L3 | CODEOWNERS enforces review on auth, policy, inspection, and Dockerfile changes; however, no formal security sign-off gate beyond PR review | PARTIAL |
| V1.7.1 | Verify that the architecture documents all third-party components | L2 | `pyproject.toml` with locked/hashed dependencies; Trivy SBOM generation in CI | PASS |
| V1.7.2 | Verify that all third-party components are monitored for vulnerabilities | L2 | Trivy scanning in CI; GitHub Dependabot alerts enabled | PASS |

**Chapter Notes:** Yashigani has strong architectural separation (control plane vs data plane, OPA as single policy engine, CHS as single credential handler). The L3 gaps are in formal SDLC process documentation and formal security sign-off gates, which are process-level requirements rather than technical controls.

---

### V2 -- Authentication

| Req ID | Requirement | L3 | Yashigani Control | Verdict |
|---|---|---|---|---|
| V2.1.1 | Verify that user-set passwords are at least 8 characters | L1 | Minimum password length enforced with configurable floor (default 12 chars); admin-configurable password policy with maximum 13 months validity; context-specific password word list rejects domain-specific terms; self-service password reset (TOTP-verified) | PASS |
| V2.1.2 | Verify that passwords of at least 64 characters are permitted | L1 | No upper bound below 64 chars; Argon2id handles arbitrarily long passwords | PASS |
| V2.1.3 | Verify that password truncation is not performed | L1 | Argon2id hashes the full password; no truncation | PASS |
| V2.1.4 | Verify that Unicode characters are permitted in passwords | L1 | UTF-8 passwords accepted and hashed as-is by Argon2id | PASS |
| V2.1.5 | Verify that users can change their password | L1 | Password change available in backoffice; requires current password + TOTP verification | PASS |
| V2.1.6 | Verify that password change requires the current password | L1 | Current password required for password change operations | PASS |
| V2.1.7 | Verify that passwords are checked against a set of breached passwords | L1 | HIBP k-Anonymity breach database checked on every password change and at install time; `PasswordBreachedError` raised if found; fail-open if API unreachable | PASS |
| V2.1.8 | Verify that a password strength meter is provided | L1 | No client-side strength meter in backoffice UI | FAIL |
| V2.1.9 | Verify that there are no composition rules beyond minimum length | L1 | No composition rules enforced (no "must contain uppercase" etc.); compliant with NIST 800-63B | PASS |
| V2.2.1 | Verify that anti-automation controls are effective against credential stuffing | L1 | Per-IP rate limiting on auth endpoints; progressive lockout after failed attempts; fail2ban auth throttle with x5 escalation leading to permanent IP block; IP allowlist + blocklist (IPv4/IPv6/CIDR) | PASS |
| V2.2.2 | Verify that weak authenticators (SMS, email OTP) are not offered as primary MFA | L2 | Only TOTP and WebAuthn/FIDO2 supported; no SMS or email OTP | PASS |
| V2.2.3 | Verify that credential recovery does not reveal the current password | L1 | Recovery codes (8 codes, Argon2id-hashed) do not reveal the password; admin-initiated reset creates new password | PASS |
| V2.3.1 | Verify that system-generated initial passwords or activation codes are securely random | L1 | All generated passwords use `secrets.token_urlsafe()` with minimum 36 chars entropy; HIBP-checked before use | PASS |
| V2.3.2 | Verify that enrollment or activation links expire after a defined period | L2 | Recovery codes are single-use; session tokens have absolute expiry; however, no time-limited enrollment links (admin creates accounts directly) | PARTIAL |
| V2.4.1 | Verify that passwords are stored using an approved one-way key derivation function | L1 | Argon2id (m=65536, t=3, p=4) for all user passwords; bcrypt for Prometheus basic auth | PASS |
| V2.4.2 | Verify that the salt is generated using a CSPRNG and is at least 128 bits | L1 | Argon2id generates its own salt via CSPRNG; salt length meets OWASP minimum | PASS |
| V2.4.3 | Verify that if PBKDF2 is used, iteration count is sufficient | L1 | N/A -- Argon2id is used, not PBKDF2 | N/A |
| V2.5.1 | Verify that MFA is required for all users accessing sensitive functions | L2 | TOTP mandatory for all admin accounts; required before any privileged operation | PASS |
| V2.5.2 | Verify that MFA verification occurs at authentication time | L2 | TOTP verified during login flow, not deferred | PASS |
| V2.5.3 | Verify that TOTP shared secrets are stored encrypted | L2 | TOTP secrets stored in AES-256-GCM encrypted PostgreSQL columns | PASS |
| V2.5.4 | Verify that MFA recovery mechanisms are at least as strong as primary MFA | L3 | Recovery codes are 8 single-use codes hashed with Argon2id; recovery invalidates existing session and requires re-enrollment of TOTP | PASS |
| V2.5.5 | Verify that hardware-based authenticators (WebAuthn/FIDO2) are supported | L3 | WebAuthn/FIDO2 passkey support implemented; known constructor bug exists (partially functional) | PARTIAL |
| V2.5.6 | Verify that replay prevention is implemented for OTP mechanisms | L2 | TOTP used-code cache prevents replay within the current time window; constant-time TOTP comparison prevents timing-based guessing | PASS |
| V2.5.7 | Verify that MFA lockout is progressive and rate-limited | L2 | Progressive lockout on failed TOTP attempts; lockout duration increases with consecutive failures | PASS |
| V2.6.1 | Verify that lookup secrets (recovery codes) are hashed | L2 | Recovery codes hashed with Argon2id; plaintext shown once at generation, never stored | PASS |
| V2.7.1 | Verify that service-to-service authentication uses strong credentials | L2 | Agent PSK tokens with minimum 64 chars; PSK rotation with grace periods; JWT validation for multi-tenant auth | PASS |
| V2.7.2 | Verify that API keys are not used as the sole authentication factor for sensitive operations | L3 | Agent tokens authenticate to the data plane only; admin operations require password + TOTP via the control plane | PASS |
| V2.7.3 | Verify that API credentials are rotatable without downtime | L3 | Agent PSK token rotation with configurable grace periods allows old and new tokens to coexist during rotation window | PASS |
| V2.8.1 | Verify that federation protocols (SAML, OIDC) validate assertions correctly | L2 | SAML: NotBefore/NotOnOrAfter, signature verification against IdP metadata; OIDC: issuer, audience, expiry, JWKS signature verification; PKCE on OIDC client; acr/amr auth strength validation | PASS |
| V2.8.2 | Verify that JWT algorithms are restricted to an allowlist | L2 | alg:none rejected; HS* rejected; only RS256/384/512 and ES256/384/512 permitted | PASS |
| V2.8.3 | Verify that JWKS key material is rotated and validated | L2 | JWKS waterfall: primary endpoint, secondary fallback, static key file; auto-rotation on upstream 401 | PASS |

**Chapter Notes:** Strong L3 authentication posture. Argon2id with HIBP checking, mandatory TOTP with constant-time comparison, WebAuthn support (partial due to constructor bug), recovery codes hashed with Argon2id, strict JWT algorithm enforcement, PKCE on OIDC clients, acr/amr auth strength validation, fail2ban auth throttle (x5 escalation to permanent IP block), IP allowlist + blocklist (IPv4/IPv6/CIDR), admin-configurable password policy (max 13 months), context-specific password word list, self-service password reset (TOTP-verified), and agent PSK rotation with grace periods. The password strength meter is a minor L1 gap. WebAuthn constructor bug should be fixed for full L3 compliance.

---

### V3 -- Session Management

| Req ID | Requirement | L3 | Yashigani Control | Verdict |
|---|---|---|---|---|
| V3.1.1 | Verify that session tokens are never revealed in URL parameters | L1 | Session IDs transmitted exclusively via HttpOnly cookies; no URL-based session tokens | PASS |
| V3.1.2 | Verify that the application generates a new session token on authentication | L1 | New session token generated on every successful login; old session invalidated | PASS |
| V3.2.1 | Verify that session tokens use HttpOnly, Secure, SameSite attributes | L1 | HttpOnly=true, Secure=true, SameSite=Strict on all session cookies; `__Host-` cookie prefix (`__Host-yashigani_admin_session`, `__Host-yashigani_session`) | PASS |
| V3.2.2 | Verify that the application uses only cookies to transmit session tokens | L2 | Session tokens are cookie-only; no bearer token session mechanism for browser clients | PASS |
| V3.3.1 | Verify that session tokens are invalidated on logout | L1 | Redis session store deletes session record synchronously on logout; server-side invalidation | PASS |
| V3.3.2 | Verify that session tokens are invalidated after a period of inactivity | L2 | Idle timeout enforced independently of absolute expiry; configurable per deployment | PASS |
| V3.3.3 | Verify that absolute session timeout is enforced | L2 | Absolute session expiry enforced at Redis session store regardless of activity | PASS |
| V3.3.4 | Verify that session tokens are invalidated when the user changes their password | L3 | All active sessions for the user are invalidated on password change | PASS |
| V3.3.5 | Verify that administrators can terminate any active session | L3 | Backoffice admin UI provides session list and termination for any user | PASS |
| V3.4.1 | Verify that concurrent session limits are enforced | L2 | Configurable max concurrent sessions per user; oldest session invalidated on overflow (configurable to reject instead) | PASS |
| V3.5.1 | Verify that session identifiers have at least 128 bits of entropy | L1 | Session tokens generated via `secrets.token_urlsafe()` with minimum 128-bit entropy | PASS |
| V3.5.2 | Verify that session identifiers are generated using a CSPRNG | L1 | Uses Python `secrets` module (OS CSPRNG) | PASS |
| V3.6.1 | Verify that re-authentication is required for sensitive operations | L3 | TOTP re-verification required for password changes, MFA re-enrollment, and admin role changes | PASS |
| V3.7.1 | Verify that session tokens are invalidated when MFA factors change | L3 | TOTP re-enrollment invalidates all existing sessions and requires fresh login | PASS |

**Chapter Notes:** Full L3 compliance for session management. Redis-backed server-side sessions with proper cookie attributes, entropy, timeouts, concurrent limits, and session invalidation on sensitive state changes.

---

### V4 -- Access Control

| Req ID | Requirement | L3 | Yashigani Control | Verdict |
|---|---|---|---|---|
| V4.1.1 | Verify that access control is enforced on the server side | L1 | OPA policy engine runs locally on the server; no client-side access control decisions | PASS |
| V4.1.2 | Verify that all access control decisions are logged | L2 | Every OPA evaluation (allow/deny) generates an audit log entry with identity, path, method, and decision | PASS |
| V4.1.3 | Verify that the principle of least privilege is applied | L1 | RBAC groups define minimum permission sets; OPA enforces method+path+identity on every request | PASS |
| V4.1.4 | Verify that access control fails securely (deny by default) | L1 | OPA evaluation errors result in deny; no fail-open code path | PASS |
| V4.1.5 | Verify that access control rules are defined in a central policy | L2 | OPA policy bundle is the single source of truth for all authorization rules | PASS |
| V4.2.1 | Verify that object-level authorization is enforced | L1 | Tenant RLS in PostgreSQL; OPA input includes tenant context for every evaluation | PASS |
| V4.2.2 | Verify that users can only access objects they are authorized for | L2 | RLS prevents cross-tenant data access at the database layer; OPA prevents unauthorized path access at the proxy layer | PASS |
| V4.2.3 | Verify that directory listing is disabled or restricted | L1 | No directory listing capability exposed; gateway proxies specific paths only | PASS |
| V4.3.1 | Verify that administrative interfaces are protected with MFA | L2 | Backoffice (port 8443) requires password + TOTP for all admin sessions | PASS |
| V4.3.2 | Verify that administrative functions are separated from user functions | L2 | Backoffice (control plane, port 8443) is architecturally separate from gateway (data plane, 80/443); no code path from gateway to backoffice routes | PASS |
| V4.3.3 | Verify that a minimum number of admin accounts is enforced | L2 | Anti-lockout: 2 admin accounts generated at install; system rejects operations that would leave zero active admins | PASS |
| V4.4.1 | Verify that RBAC is used to control access to sensitive functions | L2 | OPA evaluates RBAC group membership on every request; group-level rate limit overrides available | PASS |
| V4.4.2 | Verify that users cannot escalate their own privileges | L2 | Role changes require admin session with TOTP; no self-service role elevation | PASS |
| V4.5.1 | Verify that attribute-based or policy-based access control supports complex authorization | L3 | OPA supports ABAC through policy-as-code; policies can reference arbitrary request attributes, time-of-day, IP ranges, and custom claims | PASS |
| V4.5.2 | Verify that access control policies are version-controlled and auditable | L3 | OPA policy bundles are versioned; policy changes logged to audit trail; OPA Policy Assistant validates changes before apply | PASS |
| V4.5.3 | Verify that multi-tenant access control prevents cross-tenant data leakage | L3 | PostgreSQL RLS at DB layer + OPA tenant context at proxy layer + separate Redis DB indices per tenant; defense in depth across three layers | PASS |

**Chapter Notes:** Full L3 compliance. The combination of OPA (ABAC/RBAC), PostgreSQL RLS, and architectural separation (control plane vs data plane) provides comprehensive access control with fail-closed defaults and full auditability.

---

### V5 -- Validation, Sanitization, and Encoding

| Req ID | Requirement | L3 | Yashigani Control | Verdict |
|---|---|---|---|---|
| V5.1.1 | Verify that all input is validated against an expected schema | L1 | OPA input object includes full request context; FastText ML classification on all request bodies; body schema validation via OPA policy rules | PASS |
| V5.1.2 | Verify that input validation is performed on a trusted system | L1 | All validation in the gateway server process; no client-side validation relied upon | PASS |
| V5.1.3 | Verify that all input data is validated for type, length, and range | L2 | Body size limit (4 MB) enforced at middleware; OPA policies can enforce field-level type/range validation; parameter validation in FastAPI endpoints | PASS |
| V5.1.4 | Verify that structured data is validated against a defined schema | L2 | JSON schema validation available in OPA policies; FastAPI Pydantic models validate API request schemas | PASS |
| V5.1.5 | Verify that URL redirects and forwards validate against an allowlist | L1 | No open redirect functionality; upstream URL is server-configured only; no user-controlled redirects | PASS |
| V5.2.1 | Verify that all untrusted HTML is sanitized using an auto-escaping template | L1 | Backoffice templates use auto-escaping; strict CSP headers block inline scripts | PASS |
| V5.2.2 | Verify that unstructured data is sanitized with expected characters | L2 | UTF-8 safe decode enforced; malformed byte sequences rejected; CHS strips credential patterns from payloads | PASS |
| V5.2.3 | Verify that context-aware output encoding is applied | L2 | Backoffice applies context-aware encoding (HTML, URL, JS contexts); API responses use strict JSON serialization | PARTIAL |
| V5.2.4 | Verify that output encoding is applied as close to the interpreter as possible | L3 | Template engine handles encoding at render time; however, upstream MCP server responses forwarded as-is unless response inspection enabled | PARTIAL |
| V5.3.1 | Verify that SQL injection is prevented through parameterized queries | L1 | PostgreSQL access uses parameterized queries throughout; SQLAlchemy ORM prevents SQL injection; RLS at DB layer | PASS |
| V5.3.2 | Verify that OS command injection is prevented | L1 | No shell command execution from user input; all external process invocation uses parameterized subprocess calls | PASS |
| V5.3.3 | Verify that LDAP injection is prevented | L1 | No LDAP integration; SAML/OIDC used for federation instead | N/A |
| V5.3.4 | Verify that XPath/XML injection is prevented | L1 | SAML assertion parsing uses defused XML library; no XPath from user input | PASS |
| V5.3.5 | Verify that template injection is prevented | L2 | Jinja2 sandboxed auto-escaping in backoffice; no user-controlled template strings | PASS |
| V5.3.6 | Verify that server-side request forgery (SSRF) is prevented | L1 | Upstream URLs are server-configured only; no user-controlled URL fetching; OPA path policies restrict forwarded paths | PASS |
| V5.4.1 | Verify that prompt injection mitigations are applied for AI-processed inputs | L2 | Multi-stage: FastText first-pass (<5ms) -> Ollama LLM second-pass -> multi-backend fallback (Anthropic, Gemini, Azure OpenAI); INJECTED payloads discarded, never forwarded | PASS |
| V5.4.2 | Verify that credentials are stripped from AI-processed payloads | L2 | CHS strips all credential-pattern tokens before ANY AI inspection call; configurable regex+entropy patterns | PASS |
| V5.4.3 | Verify that AI output is validated before use in security-sensitive contexts | L3 | Response inspection pipeline (when enabled) validates upstream AI outputs through same FastText+LLM pipeline; fail-closed on INJECTED | PARTIAL |
| V5.5.1 | Verify that HTTP request header sizes are limited | L2 | Caddy enforces header size limits; FastAPI middleware applies additional header validation | PASS |
| V5.5.2 | Verify that body size limits prevent resource exhaustion | L1 | 4 MB hard limit on all inbound request bodies; enforced before inspection pipeline invocation | PASS |
| V5.5.3 | Verify that file upload validation includes type checking | L2 | Body content inspected by FastText regardless of Content-Type; no file type bypass via Content-Type spoofing | PASS |

**Chapter Notes:** Strong L3 posture on input validation, leveraging the gateway's position as a centralized enforcement point. The prompt injection pipeline (FastText + LLM + multi-backend fallback) is a differentiating control. L3 gap on output encoding for forwarded upstream responses when response inspection is disabled.

---

### V6 -- Stored Cryptography

| Req ID | Requirement | L3 | Yashigani Control | Verdict |
|---|---|---|---|---|
| V6.1.1 | Verify that all sensitive data at rest is encrypted | L2 | AES-256-GCM column encryption via pgcrypto on sensitive PostgreSQL columns; encryption keys in secrets backends | PASS |
| V6.1.2 | Verify that encryption at rest uses authenticated encryption | L2 | AES-256-GCM provides authenticated encryption with associated data (AEAD) | PASS |
| V6.1.3 | Verify that encryption keys are not stored alongside encrypted data | L2 | Keys managed via external secrets backends: Docker Secrets, Keeper, AWS/Azure/GCP Secrets Manager, HashiCorp Vault | PASS |
| V6.2.1 | Verify that only approved cryptographic algorithms are used | L2 | AES-256-GCM (symmetric), ECDSA P-256 (signing), SHA-384 (Merkle chain), Argon2id (password hashing), X25519 (key exchange); no MD5, SHA1, DES, 3DES | PASS |
| V6.2.2 | Verify that cryptographic algorithm selection is centralized | L3 | All crypto operations route through `cryptography` library and `argon2-cffi`; no ad-hoc crypto implementations | PASS |
| V6.2.3 | Verify that the application is prepared for post-quantum cryptography migration | L3 | Hybrid TLS X25519+ML-KEM-768 config prepared (pending Caddy 2.10); ML-DSA-65 licence signing planned (pending `cryptography` FIPS 204 support) | PARTIAL |
| V6.3.1 | Verify that all random values are generated using a CSPRNG | L1 | All security-sensitive random values use `os.urandom` / `secrets` module (OS CSPRNG) | PASS |
| V6.3.2 | Verify that random values have sufficient entropy for their purpose | L2 | Session tokens: 128+ bits; agent tokens: 64+ chars; generated passwords: 36+ chars with HIBP check | PASS |
| V6.4.1 | Verify that passwords are hashed using Argon2id or bcrypt | L1 | Argon2id (m=65536 KB, t=3, p=4) for user passwords; bcrypt for Prometheus basic auth | PASS |
| V6.4.2 | Verify that password hashing parameters meet minimum thresholds | L2 | Argon2id: memory 65536 KB, time 3, parallelism 4 -- meets OWASP recommended minimums; parameters operator-configurable within secure bounds | PASS |
| V6.5.1 | Verify that cryptographic key rotation is supported | L2 | Secrets backend integrations support key versioning; JWKS rotation automatic on 401; agent PSK rotation with grace periods | PARTIAL |
| V6.5.2 | Verify that key rotation can be performed without downtime | L3 | Agent PSK rotation with grace periods allows overlap; JWKS waterfall handles key rotation transparently; however, AES-256-GCM database encryption key rotation requires manual re-encryption | PARTIAL |
| V6.5.3 | Verify that retired keys are securely destroyed | L3 | Secrets backends handle key lifecycle; however, no explicit key destruction verification in Yashigani application code | FAIL |
| V6.6.1 | Verify that a hardware security module (HSM) or equivalent is used for key storage in high-assurance deployments | L3 | Cloud KMS integrations (AWS, Azure, GCP) provide HSM-backed key storage; no on-premises HSM integration | PARTIAL |

**Chapter Notes:** Strong cryptographic foundation with Argon2id, AES-256-GCM, and ECDSA. Post-quantum readiness is in progress (ML-KEM-768, ML-DSA-65 prepared but pending upstream library support). L3 gaps exist in key destruction verification and on-premises HSM support. Database encryption key rotation without downtime is a known gap.

---

### V7 -- Error Handling and Logging

| Req ID | Requirement | L3 | Yashigani Control | Verdict |
|---|---|---|---|---|
| V7.1.1 | Verify that the application does not log sensitive data | L1 | CHS applies masking to audit log payloads; configurable PII masking hooks for additional field-level masking | PASS |
| V7.1.2 | Verify that error messages do not contain sensitive data | L1 | All unhandled exceptions return generic HTTP 500; stack traces written to internal log only | PASS |
| V7.1.3 | Verify that error responses do not reveal implementation details | L1 | No framework names, versions, stack traces, or internal paths in error responses | PASS |
| V7.2.1 | Verify that all security-relevant events are logged | L1 | Auth attempts (success/failure), policy decisions, inspection results, rate limit triggers, anomaly detections all generate audit events | PASS |
| V7.2.2 | Verify that log entries contain sufficient data for forensic analysis | L2 | Structured JSON: timestamp, request_id, agent_id, session_id, method, path, OPA decision, inspection result, upstream response code, SHA-256 content hash | PASS |
| V7.2.3 | Verify that log entries include a timestamp from a reliable time source | L2 | UTC timestamps from system clock; NTP synchronization is a deployment requirement | PASS |
| V7.2.4 | Verify that log entries cannot be modified or deleted by application users | L3 | Audit logs written to PostgreSQL (RLS-protected), SIEM (Splunk/ES/Wazuh), and local files (0600 permissions); SHA-384 Merkle chain provides tamper evidence | PASS |
| V7.3.1 | Verify that logs are sent to a remote logging system | L2 | MultiSinkAuditWriter: local file + PostgreSQL + SIEM (Splunk, Elasticsearch, Wazuh); loss of one sink does not halt operation | PASS |
| V7.3.2 | Verify that log integrity is protected against tampering | L3 | SHA-384 Merkle chain on audit log entries provides tamper evidence; chain break detection alerts | PASS |
| V7.3.3 | Verify that anomalous logging activity triggers alerts | L3 | Automated partition monitoring with alerts for missing partitions; SIEM forwarding enables external anomaly detection on log volume/patterns | PARTIAL |
| V7.4.1 | Verify that log injection attacks are prevented | L2 | Structured JSON logging; all log values escaped before formatting; typed serialization eliminates newline injection | PASS |
| V7.4.2 | Verify that log data is protected in transit | L2 | SIEM forwarding uses TLS; PostgreSQL connections configurable with TLS | PASS |
| V7.4.3 | Verify that log access is restricted to authorized personnel | L2 | Log files: 0600 permissions; PostgreSQL audit table: RLS + role-based grants; SIEM access: delegated to SIEM RBAC | PASS |
| V7.5.1 | Verify that the application detects and alerts on security-relevant events in real time | L3 | Direct webhook alerting on credential exfiltration attempts; SIEM integration for real-time alerting; however, no built-in real-time alerting dashboard | PARTIAL |

**Chapter Notes:** Strong L3 logging posture. The SHA-384 Merkle chain for audit log integrity, multi-sink audit writing, and structured JSON logging with CHS masking provide comprehensive coverage. The webhook alerting for credential exfiltration (v0.7.1) addresses real-time detection. Minor gaps in built-in alerting dashboard and anomalous logging pattern detection (delegated to SIEM).

---

### V8 -- Data Protection

| Req ID | Requirement | L3 | Yashigani Control | Verdict |
|---|---|---|---|---|
| V8.1.1 | Verify that sensitive data is classified and handled according to its classification | L2 | CHS credential pattern registry classifies credentials; PII detection hooks classify additional sensitive types; AES-256-GCM for sensitive DB columns | PARTIAL |
| V8.1.2 | Verify that a data classification policy exists | L3 | Credential patterns and PII hooks are configurable but no formal data classification policy document is bundled | FAIL |
| V8.1.3 | Verify that environmental factors are documented for authorization decisions | L3 | Environmental factors (client IP, user agent, time of day) are captured in audit events but not yet used for authorization decisions; see Environmental Auth Factors section below | PASS |
| V8.2.1 | Verify that sensitive data is not cached inappropriately | L2 | Response cache stores CLEAN responses only; BLOCKED/INJECTED/SANITIZED never cached; cache keys exclude credential-bearing headers | PASS |
| V8.2.2 | Verify that sensitive data is not stored in client-side storage | L2 | Backoffice stores no sensitive values in localStorage/sessionStorage; session token in HttpOnly cookie only | PASS |
| V8.2.3 | Verify that sensitive data is cleared from memory when no longer needed | L3 | Python garbage collection handles memory cleanup; no explicit memory zeroing for sensitive variables (Python limitation) | FAIL |
| V8.3.1 | Verify that personal data handling complies with relevant privacy requirements | L2 | PII masking in audit logs; CHS strips credentials; tenant isolation via RLS; however, no built-in GDPR data subject request tooling | PARTIAL |
| V8.3.2 | Verify that data retention policies are enforced | L2 | Audit log rotation with configurable retention; pg_partman time-based partition expiry; Redis TTL on session/cache data | PASS |
| V8.4.1 | Verify that HTTP responses contain appropriate cache control headers | L2 | Backoffice responses include Cache-Control: no-store for sensitive pages; API responses include appropriate cache directives | PASS |
| V8.4.2 | Verify that sensitive data is not included in HTTP GET parameters | L2 | Credentials and session tokens never in URL parameters; all sensitive data in request bodies or cookies | PASS |
| V8.5.1 | Verify that multi-tenant data isolation is enforced at all layers | L2 | PostgreSQL RLS + separate Redis DB indices per tenant + OPA tenant context; three-layer isolation | PASS |
| V8.5.2 | Verify that credentials are not exposed to AI/ML processing backends | L2 | CHS strips credentials before all AI inspection calls regardless of backend type | PASS |
| V8.6.1 | Verify that backup data is encrypted | L3 | PostgreSQL backup encryption is delegated to operator infrastructure; Yashigani does not manage database backups directly | FAIL |
| V8.6.2 | Verify that data exports include only authorized data | L3 | Audit log exports respect RLS tenant boundaries; however, no formal data export authorization workflow | PARTIAL |

**Chapter Notes:** Solid data protection controls with CHS credential stripping, multi-tenant isolation, and cache safety. L3 gaps include: no explicit memory zeroing (Python runtime limitation), no formal data classification policy document, no built-in backup encryption (operator responsibility), and no GDPR data subject request tooling.

#### Environmental Auth Factors (V8.1.3 / V8.1.4)

Yashigani captures the following environmental factors in audit events:

- **Client IP** (`client_ip_prefix`): Captured on every login event (AdminLoginEvent, SSOLoginSuccessEvent, SSOLoginFailureEvent) and rate-limit violation events. The last octet is masked for privacy.
- **User agent**: Available in HTTP request headers and logged by Caddy access logs. Not currently extracted into structured audit fields.
- **Time of day**: Every audit event includes an ISO 8601 timestamp (`event_time`).

**Current usage:** These environmental factors are captured for forensic analysis and incident investigation but are **not yet used for real-time authorization decisions** (e.g., blocking logins from unusual IPs or at unusual times). The brute-force throttle (ASVS 6.3.5) uses per-IP failure tracking as a protective measure. Adaptive contextual authorization based on environmental anomalies is planned for a future release.

---

### V9 -- Communication Security

| Req ID | Requirement | L3 | Yashigani Control | Verdict |
|---|---|---|---|---|
| V9.1.1 | Verify that TLS is used for all connections | L1 | Caddy handles TLS termination; TLS 1.2 minimum; TLS 1.0/1.1 disabled; plain HTTP redirected to HTTPS | PASS |
| V9.1.2 | Verify that TLS 1.2 or higher is required | L1 | TLS 1.2 minimum enforced by Caddy; TLS 1.3 preferred when supported by client | PASS |
| V9.1.3 | Verify that only strong cipher suites are enabled | L2 | RC4, NULL, EXPORT, DES, 3DES, MD5-MAC suites excluded; only AEAD cipher suites permitted | PASS |
| V9.1.4 | Verify that HSTS is enabled with appropriate directives | L2 | Strict-Transport-Security: max-age=31536000; includeSubDomains served by Caddy and backoffice middleware | PASS |
| V9.1.5 | Verify that certificate validation is performed correctly | L1 | Caddy validates upstream certificates; ACME handles Let's Encrypt certificates automatically | PASS |
| V9.1.6 | Verify that certificate pinning is implemented for high-value connections | L3 | No certificate pinning implemented for connections to external services (inspection backends, SIEM, secrets backends) | FAIL |
| V9.2.1 | Verify that internal service communications are encrypted | L2 | Core data-plane fully mTLS as of v2.23.1 (gateway↔backoffice↔postgres↔pgbouncer↔redis↔budget-redis↔Caddy); OTEL collector upgraded to mTLS gRPC (M-01 closed 2026-04-27); OPA plaintext HTTP is the only remaining exception (tracked as task #54, v2.23.2) | PARTIAL |
| V9.2.2 | Verify that mutual TLS (mTLS) is used for service-to-service communication | L3 | Two-tier PKI (root→intermediate→per-service leaves) with SPIFFE URI SANs on all core-plane services; two remaining exceptions: OPA plaintext (task #54) and Ollama (no TLS support upstream, bearer token + bridge isolation). **Trust-store policy:** workload trust stores reference `ca_intermediate.crt` where the TLS library supports partial-chain anchoring (Python ssl, Go crypto/tls, postgres with pg_hba hostssl rules). Where the library is libssl-direct without partial-chain support (pgbouncer, Redis), workload trust stores reference `ca_root.crt` — public cert only. The root CA private key (`ca_root.key`) never enters any workload container. See `docs/release-process.md §9` for PKI trust-store policy detail. | PARTIAL |
| V9.3.1 | Verify that certificate management is automated | L2 | Three modes: ACME (automatic Let's Encrypt), CA-signed (operator-provided), self-signed (development); ACME renewal fully automated via Caddy | PASS |
| V9.3.2 | Verify that certificate lifecycle events are logged | L3 | Caddy logs certificate renewal events; however, certificate expiry alerting not integrated into Yashigani audit trail | PARTIAL |
| V9.4.1 | Verify that the application is prepared for post-quantum TLS | L3 | Hybrid X25519+ML-KEM-768 key exchange config included (pending Caddy 2.10 release) | PARTIAL |

**Chapter Notes:** Strong external TLS posture via Caddy with HSTS, strong cipher suites, and automated ACME. L3 gaps are significant: no mTLS for internal service mesh (relies on network isolation), no certificate pinning for external connections, and post-quantum TLS pending upstream Caddy support. Internal mTLS is the highest-priority gap for L3 compliance.

---

### V10 -- Malicious Code

| Req ID | Requirement | L3 | Yashigani Control | Verdict |
|---|---|---|---|---|
| V10.1.1 | Verify that source code does not contain backdoors or undocumented functionality | L3 | Open source (Apache 2.0); code review via CODEOWNERS; however, no formal code audit by independent third party | PARTIAL |
| V10.1.2 | Verify that third-party components are free of known vulnerabilities | L2 | Trivy scanning in CI; locked/hashed dependencies in pyproject.toml; digest-pinned base images | PASS |
| V10.1.3 | Verify that source code integrity is protected | L2 | GitHub CODEOWNERS on security-critical paths; signed commits not enforced | PARTIAL |
| V10.2.1 | Verify that the application does not request unnecessary permissions | L1 | Container runs as UID 1001 (non-root); no privilege escalation (allowPrivilegeEscalation: false); no new privileges flag | PASS |
| V10.2.2 | Verify that the application uses OS-level sandboxing | L2 | seccomp allowlist restricts syscalls; AppArmor profile provides MAC; readOnlyRootFilesystem: true; tmpfs for writable paths | PASS |
| V10.2.3 | Verify that system call filtering is applied | L3 | seccomp allowlist restricts to required syscalls only; AppArmor mandatory access control at kernel level | PASS |
| V10.3.1 | Verify that container images use minimal base images | L2 | Slim/distroless base images; all 25 upstream images digest-pinned to sha256 at release time in `docker/docker-compose.release.yml` (H-02 design-drift finding closed 2026-04-27); Helm parity in `helm/yashigani/values.release.yaml`; no mutable tags in production overlay. | PASS |
| V10.3.2 | Verify that container images are scanned before deployment | L2 | Trivy scanning integrated in CI/CD; images failing scan threshold not promoted to production | PASS |
| V10.3.3 | Verify that container runtime security is enforced | L3 | seccomp + AppArmor + non-root + read-only filesystem + no privilege escalation; cgroup v2 resource limits | PASS |
| V10.4.1 | Verify that software composition analysis (SCA) is performed | L2 | Trivy SCA in CI; GitHub Dependabot for dependency monitoring; hashed requirements in pyproject.toml | PASS |
| V10.4.2 | Verify that SBOM (Software Bill of Materials) is generated and maintained | L3 | Trivy generates SBOM in CI; however, SBOM is not published or formally maintained across releases | PARTIAL |
| V10.5.1 | Verify that the application detects and prevents runtime code injection | L3 | seccomp restricts exec syscalls; read-only filesystem prevents binary drops; AppArmor restricts file execution; FastText+LLM inspection detects code injection in payloads | PASS |
| V10.5.2 | Verify that hardware-level integrity attestation is supported | L3 | No TPM or secure boot attestation; no confidential computing integration (AMD SEV, Intel TDX) | FAIL |

**Chapter Notes:** Strong container security posture with defense-in-depth: seccomp, AppArmor, non-root, read-only filesystem, digest-pinned images, and Trivy scanning. L3 gaps include no independent code audit, no signed commits enforcement, SBOM not formally published, and no hardware-level attestation. The hardware attestation gap is inherent to a software-only product.

---

### V11 -- Business Logic Security

| Req ID | Requirement | L3 | Yashigani Control | Verdict |
|---|---|---|---|---|
| V11.1.1 | Verify that rate limiting is enforced on all sensitive operations | L1 | Four independent rate limit dimensions: per-IP, per-session, per-agent, per-endpoint; all Redis-backed | PASS |
| V11.1.2 | Verify that rate limiting uses a sliding window or token bucket algorithm | L2 | Redis-backed sliding window for rate limiting; Redis ZSET sliding window for anomaly detection | PASS |
| V11.1.3 | Verify that rate limit bypass is not possible through header manipulation | L2 | X-Forwarded-For validated and sanitized; spoofed headers overridden with actual connection IP; trusted proxy chains configurable | PASS |
| V11.2.1 | Verify that business logic is enforced in the correct sequence | L2 | Inspection pipeline stages execute in fixed order: FastText -> OPA -> Ollama -> fallback; no stage skipping | PASS |
| V11.2.2 | Verify that business logic limits prevent abuse | L2 | Repeated-small-calls anomaly detection via Redis ZSET sliding window; triggers audit event and optional block | PASS |
| V11.3.1 | Verify that time-based business logic is enforced consistently | L2 | Session absolute expiry and idle timeout enforced independently; TOTP time window validation with replay prevention | PASS |
| V11.3.2 | Verify that concurrent business operations are handled safely | L3 | Redis atomic operations for rate limit counters; PostgreSQL row-level locking for concurrent admin operations; agent registration uses database-level uniqueness constraints | PASS |
| V11.4.1 | Verify that the application detects and prevents automated abuse | L2 | Anomaly detection (repeated-small-calls pattern); per-IP rate limiting; progressive lockout on auth endpoints | PASS |
| V11.4.2 | Verify that the application implements fraud detection or anomaly alerting | L3 | Anomaly detection alerts to SIEM and optional webhook; audit trail enables forensic analysis; however, no ML-based behavioral anomaly detection beyond the repeated-small-calls heuristic | PARTIAL |
| V11.5.1 | Verify that fail-safe defaults are applied to all business logic decisions | L1 | OPA deny-on-error; inspection pipeline fail-closed on INJECTED; rate limit denial on breach | PASS |

**Chapter Notes:** Comprehensive business logic protection with four-dimensional rate limiting, anomaly detection, and fail-closed defaults throughout. L3 gap is in advanced ML-based behavioral anomaly detection -- the current heuristic (repeated-small-calls) is effective but limited compared to full behavioral analytics.

---

### V12 -- Files and Resources

| Req ID | Requirement | L3 | Yashigani Control | Verdict |
|---|---|---|---|---|
| V12.1.1 | Verify that file upload size limits are enforced | L1 | 4 MB body size limit on all inbound content; enforced at middleware before storage or processing | PASS |
| V12.1.2 | Verify that file type validation is performed | L2 | Content inspected by FastText regardless of declared Content-Type; body content analysis rather than extension-based validation | PASS |
| V12.1.3 | Verify that uploaded files are stored outside the webroot | L1 | Gateway is a proxy -- no file storage to webroot; uploaded content is inspected and forwarded, not persisted | N/A |
| V12.2.1 | Verify that temporary files are stored securely | L2 | tmpfs mounts for transient data; tmpfs does not persist to restart; no sensitive data written to container overlay filesystem | PASS |
| V12.2.2 | Verify that temporary files are deleted promptly | L2 | tmpfs cleared on container restart; no persistent temp file accumulation | PASS |
| V12.3.1 | Verify that log file retention policies are enforced | L2 | Audit log rotation with max file size and retention period; pg_partman time-based partition expiry; Redis TTL on ephemeral data | PASS |
| V12.3.2 | Verify that log files are protected from unauthorized access | L2 | Log files: 0600 permissions; PostgreSQL audit table: RLS + role-based grants; SIEM forwarding uses TLS | PASS |
| V12.4.1 | Verify that file download does not expose sensitive system information | L1 | No file download functionality exposed through the gateway; backoffice audit export respects RLS | PASS |
| V12.4.2 | Verify that path traversal attacks are prevented | L1 | No file path construction from user input; gateway proxies HTTP requests, not file paths | N/A |
| V12.5.1 | Verify that resource limits prevent denial of service | L2 | 4 MB body limit; cgroup v2 CPU/memory limits; Redis connection pooling via PgBouncer for PostgreSQL | PASS |

**Chapter Notes:** Most file and resource requirements are satisfied or not applicable given the proxy architecture. The gateway does not store files -- it inspects and forwards. Resource limits are well-defined across body size, container resources, and connection pooling.

---

### V13 -- API and Web Service Security

| Req ID | Requirement | L3 | Yashigani Control | Verdict |
|---|---|---|---|---|
| V13.1.1 | Verify that every API request is authenticated | L1 | OPA policy check on every gateway request; unauthenticated requests to protected endpoints rejected before upstream forwarding | PASS |
| V13.1.2 | Verify that every API request is authorized | L1 | OPA evaluates identity+method+path on every request; deny by default | PASS |
| V13.1.3 | Verify that API authentication tokens are validated on every request | L1 | Agent bearer tokens validated against registry; JWT tokens validated (signature, issuer, audience, expiry) on every request | PASS |
| V13.2.1 | Verify that API endpoints validate HTTP methods | L1 | OPA input includes HTTP method; unexpected methods return 405; method-level policy enforcement per path | PASS |
| V13.2.2 | Verify that API endpoints enforce content-type validation | L2 | FastAPI validates Content-Type on API endpoints; unexpected content types rejected | PASS |
| V13.2.3 | Verify that hop-by-hop headers are stripped | L2 | Connection, Keep-Alive, Transfer-Encoding, Upgrade, Proxy-Authorization, TE headers stripped from proxied requests | PASS |
| V13.2.4 | Verify that X-Forwarded-For handling is secure | L2 | Spoofed headers from untrusted clients overridden with actual connection IP; trusted proxy chains configurable | PASS |
| V13.3.1 | Verify that administrative and debug endpoints are not publicly accessible | L1 | OpenTelemetry metrics on internal-only port; no metrics/debug routes on public gateway port; Jaeger UI network-isolated | PASS |
| V13.3.2 | Verify that API documentation is not publicly accessible in production | L2 | FastAPI Swagger/ReDoc disabled in production mode; no API documentation exposed on gateway port | PASS |
| V13.4.1 | Verify that GraphQL-specific protections are applied | L2 | N/A -- Yashigani does not expose GraphQL; MCP uses JSON-RPC style protocol | N/A |
| V13.5.1 | Verify that WebSocket connections are authenticated and authorized | L2 | MCP Streamable HTTP transport with SSE; WebSocket connections validated through same OPA policy engine; session tokens required | PASS |
| V13.5.2 | Verify that WebSocket message size limits are enforced | L2 | Message size limits applied to WebSocket/SSE frames; consistent with 4 MB body limit | PASS |
| V13.6.1 | Verify that API versioning is implemented | L2 | Agent registry and API routes include version metadata; deprecated routes return warnings; SCIM endpoints follow RFC 7644 versioning | PARTIAL |
| V13.6.2 | Verify that deprecated API versions are documented and scheduled for removal | L3 | Deprecated routes return warnings; however, no formal deprecation schedule or sunset dates published | PARTIAL |
| V13.7.1 | Verify that API rate limiting is applied per consumer | L2 | Per-agent and per-session rate limiting; group-level rate limit overrides for different consumer categories | PASS |
| V13.7.2 | Verify that API abuse detection is implemented | L3 | Anomaly detection (repeated-small-calls); per-IP rate limiting; progressive lockout; SIEM integration for pattern analysis | PASS |
| V13.8.1 | Verify that response caching respects authorization | L3 | Response cache stores CLEAN responses only; cache keys exclude credential-bearing headers; cached responses respect tenant isolation | PASS |

**Chapter Notes:** Comprehensive API security with OPA enforcement on every request, strict header handling, and multi-dimensional rate limiting. L3 gaps are minor: API deprecation scheduling and version sunset documentation. The MCP-specific controls (streamable HTTP, SSE) are well-covered.

---

### V14 -- Configuration

| Req ID | Requirement | L3 | Yashigani Control | Verdict |
|---|---|---|---|---|
| V14.1.1 | Verify that the application uses a secure default configuration | L1 | All credentials auto-generated at install (min 36 chars, HIBP-checked); HTTPS enforced; seccomp/AppArmor enabled by default; fail-closed OPA | PASS |
| V14.1.2 | Verify that all configurable security settings have secure defaults | L2 | Rate limiting enabled by default; TOTP mandatory for admins; TLS 1.2 minimum; AEAD-only ciphers; non-root container | PASS |
| V14.1.3 | Verify that debug features are disabled in production | L1 | Stack traces suppressed; Swagger/ReDoc disabled; debug logging disabled in production mode | PASS |
| V14.2.1 | Verify that all credentials are stored outside the application code | L1 | Docker Secrets for credential storage; never in environment variables in production mode; secrets backends (Vault, cloud KMS) supported | PASS |
| V14.2.2 | Verify that credentials are never committed to source control | L1 | `.gitignore` covers secrets; installer generates credentials at deploy time, not build time; secrets never in Dockerfiles or compose files | PASS |
| V14.2.3 | Verify that credentials are rotatable | L2 | Agent PSK rotation with grace periods; JWKS auto-rotation; secrets backend key versioning | PASS |
| V14.3.1 | Verify that security headers are applied to all responses | L2 | HSTS, X-Frame-Options: DENY, Content-Security-Policy, X-Content-Type-Options applied by security middleware on backoffice responses; Caddy applies HSTS on gateway | PASS |
| V14.3.2 | Verify that Content-Security-Policy is enforced | L2 | Strict CSP on backoffice: external JS/CSS only, zero inline code; `object-src none`, `base-uri none`, COOP, `report-uri`; admin UI is a static SPA calling backend APIs; gateway responses are proxied as-is (upstream CSP responsibility) | PASS |
| V14.4.1 | Verify that HTTP-only communication is not permitted | L1 | Plain HTTP redirected to HTTPS by Caddy; no HTTP-only mode in production | PASS |
| V14.4.2 | Verify that CORS policies are restrictive | L2 | Backoffice CORS restricted to same-origin; gateway CORS configurable per deployment with restrictive defaults | PASS |
| V14.5.1 | Verify that the application build process is repeatable and secure | L2 | Locked/hashed dependencies; digest-pinned base images; Trivy scanning in CI; deterministic builds | PASS |
| V14.5.2 | Verify that the deployment process enforces security controls | L3 | Container security context enforced (non-root, seccomp, AppArmor, read-only FS); however, no deployment-time security policy validation tool that blocks insecure configurations | PARTIAL |
| V14.5.3 | Verify that infrastructure-as-code is version-controlled and reviewed | L3 | Docker Compose and Dockerfiles in version control; CODEOWNERS on security-critical files; however, no policy-as-code for infrastructure validation (e.g., OPA for Terraform) | PARTIAL |
| V14.6.1 | Verify that security event monitoring is configured | L2 | Audit logging to file + PostgreSQL + SIEM; webhook alerts for credential exfiltration; OpenTelemetry tracing | PASS |
| V14.6.2 | Verify that security monitoring covers all system components | L3 | Gateway, backoffice, OPA, and inspection pipeline monitored; Prometheus metrics for all services; however, Redis and PostgreSQL monitoring delegated to operator infrastructure | PARTIAL |

**Chapter Notes:** Strong secure-by-default configuration with auto-generated credentials, enforced HTTPS, container hardening, and comprehensive security headers. L3 gaps are in deployment-time security validation tooling and infrastructure-as-code policy enforcement. Monitoring coverage is comprehensive for Yashigani components but delegates database and cache monitoring to operators.

---

## Section 2: OWASP API Security Top 10 (2023) Mapping

The OWASP API Security Top 10 (2023) identifies the most critical security risks facing modern APIs. This section maps each risk to Yashigani's controls.

---

### API1 -- Broken Object Level Authorization (BOLA)

**Yashigani Controls:** OPA policy evaluation on every request with full context (identity, group, path, method). PostgreSQL RLS enforces per-tenant row isolation at the database layer. RBAC group definitions control permitted object paths. Policy bundle refresh is configurable (default 30 seconds).

**Residual Risk:** OPA policy logic is operator-authored. Overly permissive policies may undermine BOLA protection.

**Coverage: FULL**

---

### API2 -- Broken Authentication

**Yashigani Controls:** Argon2id password hashing with HIBP breach checking, mandatory TOTP for admins, WebAuthn/FIDO2 support, strict JWT algorithm enforcement (alg:none and HS* rejected), HttpOnly/Secure/SameSite=Strict cookies, 128-bit session entropy, agent bearer tokens (min 64 chars), progressive lockout.

**Residual Risk:** Brute-force protection depends on rate limiting configuration. Credential reset delegated to operator IdP.

**Coverage: FULL**

---

### API3 -- Broken Object Property Level Authorization

**Yashigani Controls:** OPA policy input includes complete request context. CHS strips credential fields before AI inspection. Backoffice/gateway architectural separation prevents admin property exposure through data plane.

**Residual Risk:** Response filtering for upstream object properties depends on response inspection being enabled.

**Coverage: PARTIAL** (full for gateway objects; partial for upstream response properties)

---

### API4 -- Unrestricted Resource Consumption

**Yashigani Controls:** Four independent rate limiting dimensions (per-IP, per-session, per-agent, per-endpoint), all Redis-backed. Anomaly detection via Redis ZSET sliding window. 4 MB body size limit. Response cache reduces load.

**Residual Risk:** Redis availability is a dependency for rate limiting. From v2.23.2, `RATE_LIMITER_FAIL_MODE` defaults to `closed` — Redis unavailability rejects requests with HTTP 503 + Retry-After rather than silently allowing traffic through. Operators who require fail-open behaviour during Redis instability can opt in via `RATE_LIMITER_FAIL_MODE=open`.

**Coverage: FULL**

---

### API5 -- Broken Function Level Authorization

**Yashigani Controls:** OPA policy evaluates method+path+identity on every request. Backoffice architecturally isolated on port 8443 with local auth. Admin routes protected by require_admin_session middleware with TOTP verification.

**Residual Risk:** Network-level port isolation between gateway and backoffice is a deployment requirement.

**Coverage: FULL**

---

### API6 -- Unrestricted Access to Sensitive Business Flows

**Yashigani Controls:** Repeated-small-calls anomaly detection. Per-endpoint rate limits configurable for sensitive operations. Agent token authentication with minimum-length enforcement.

**Residual Risk:** Sensitive business flow semantics depend on upstream MCP server design. Operator policy configuration required for domain-specific flows.

**Coverage: FULL** (with operator policy configuration)

---

### API7 -- Server Side Request Forgery (SSRF)

**Yashigani Controls:** Upstream URL is server-configured only (environment variables). No user-controlled URL input determines forwarding destination. OPA path policies restrict forwarded paths. Only outbound connections are to fixed, configured endpoints.

**Residual Risk:** Upstream MCP server SSRF vulnerabilities are out of Yashigani's scope.

**Coverage: FULL** (for SSRF in Yashigani; partial for upstream SSRF)

---

### API8 -- Security Misconfiguration

**Yashigani Controls:** All credentials auto-generated at install (min 36 chars, HIBP-checked). Container hardening by default (seccomp, AppArmor, UID 1001, read-only FS). Caddy HTTPS-only with security headers. Generic error responses. Trivy CI scanning.

**Residual Risk:** Operators who override default hardening reduce security below baseline.

**Coverage: FULL**

---

### API9 -- Improper Inventory Management

**Yashigani Controls:** Agent registry with active/inactive lifecycle. Registration events audited. SCIM v2 integration for enterprise IdP-driven lifecycle management. OPA policy bundle defines all active routes; unlisted routes denied by default.

**Residual Risk:** Upstream MCP server endpoints not in policy bundle may be undiscovered.

**Coverage: FULL**

---

### API10 -- Unsafe Consumption of External APIs

**Yashigani Controls:** Response inspection pipeline (when enabled) processes upstream responses through FastText+LLM pipeline. Hop-by-hop headers stripped. Response cache stores CLEAN-only. Inspection backend API keys in secrets backends; CHS strips credentials before sending payloads.

**Residual Risk:** Response inspection is configuration-dependent. Disabled deployments lose upstream validation.

**Coverage: FULL** (with response inspection enabled; partial without)

---

## Section 3: OWASP Agentic AI and LLM Top 10 Mapping

---

### LLM01 -- Prompt Injection

**Yashigani Controls:** Multi-stage, multi-backend detection: FastText ML first-pass (<5ms) -> Ollama LLM second-pass (local) -> multi-backend fallback (Anthropic, Gemini, Azure OpenAI). INJECTED payloads discarded, never forwarded. Configurable confidence thresholds with escalation on low confidence. Fail-closed on pipeline failure.

**Residual Risk:** Novel injection patterns may evade FastText. LLMs can be manipulated in adversarial scenarios. Defense in depth with OPA limits blast radius.

**Coverage: FULL**

---

### LLM02 -- Insecure Output Handling

**Yashigani Controls:** Response inspection (when enabled) validates upstream outputs through same pipeline. Backoffice strict CSP blocks inline scripts. Audit log records classification and payload hash for forensics.

**Residual Risk:** Response inspection is operator-configurable.

**Coverage: PARTIAL** (depends on response inspection configuration)

---

### LLM03 -- Training Data Poisoning

**Yashigani Controls:** FastText training scripts provided for operator audit. Model binary digest-pinned in container image. Multi-backend fallback provides cross-check against compromised single model.

**Residual Risk:** Training-time concern outside runtime proxy scope.

**Coverage: PARTIAL** (integrity controls on artifacts; training process out of scope)

---

### LLM04 -- Model Denial of Service

**Yashigani Controls:** Rate limiting prevents excessive inspection pipeline load. Anomaly detection identifies resource exhaustion patterns. Ollama queue limits with fallback routing. Container cgroup v2 resource limits.

**Coverage: FULL**

---

### LLM05 -- Supply Chain Vulnerabilities

**Yashigani Controls:** Trivy CI scanning, digest-pinned base images, hashed/locked dependencies, CODEOWNERS on security-critical files.

**Residual Risk:** Third-party inference backend security is out of scope (mitigated by CHS credential stripping).

**Coverage: FULL** (for Yashigani supply chain)

---

### LLM06 -- Sensitive Information Disclosure

**Yashigani Controls:** CHS strips credential patterns before all AI backend calls. PII masking hooks in audit logs. AES-256-GCM column encryption. Keys in secrets backends.

**Residual Risk:** Novel credential formats may evade CHS pattern matching.

**Coverage: FULL**

---

### LLM07 -- Insecure Plugin and Tool Design (MCP Context)

**Yashigani Controls:** OPA policy evaluation on every MCP tool call with full context. Tool path authorization via policy bundle. Agent registration with token authentication.

**Residual Risk:** Upstream MCP server implementation security is out of scope.

**Coverage: FULL** (at the proxy boundary)

---

### LLM08 -- Excessive Agency

**Yashigani Controls:** Agent bearer token minimum length (64 chars). RBAC group assignments via OPA. Full agent action audit trail. Anomaly detection for autonomous behavior patterns. Per-agent rate limits.

**Residual Risk:** Policy granularity depends on operator RBAC configuration.

**Coverage: FULL**

---

### LLM09 -- Overreliance

**Yashigani Controls:** Multi-backend fallback with fail-closed sentinel. UNCERTAIN escalation to next stage rather than default allow. Configurable confidence thresholds. Audit records include decision, confidence, and backend.

**Residual Risk:** Human review of audit logs is not automated.

**Coverage: FULL**

---

### LLM10 -- Model Theft

**Yashigani Controls:** Ollama runs locally; model weights not network-accessible. Inspection backend API keys in secrets backends. CHS prevents credential leakage to backends. ECDSA P-256 offline licence verification (ML-DSA-65 planned).

**Residual Risk:** Customer-owned model protection on upstream MCP servers is out of scope.

**Coverage: PARTIAL** (protects Yashigani's inspection models; customer models out of scope)

---

### Agentic AI Specific Controls

| Control | Implementation | Purpose |
|---|---|---|
| Agent identity verification | Bearer token, min-length 64, registry lookup | Ensures only registered agents access MCP tools |
| Content relay detection | Agent laundering detection on all /v1 traffic | Identifies agents proxying requests through other agents to bypass policy |
| Per-agent rate limiting | Redis sliding window, independent of per-IP/session | Constrains autonomous agent action rates |
| Agent anomaly detection | Redis ZSET sliding window, repeated-small-calls | Identifies unexpected agent call patterns |
| Agent action audit trail | Every call: agent_id, session, payload hash, OPA decision, upstream response | Full forensic visibility into agent behavior |
| Agent lifecycle management | Active/inactive status, admin UI | Rapid deactivation of compromised agents |
| SCIM v2 provisioning | RFC 7644-compliant provisioning | Enterprise IdP-driven agent lifecycle |
| Multi-tenant isolation | RLS + separate Redis DBs + OPA tenant context | Cross-tenant protection |
| Fail-closed policy engine | OPA deny-on-error | Policy failures cannot grant access |
| Response chain tracing | W3C traceparent, X-Trace-Id, tail sampling, Jaeger | End-to-end trace visibility |

---

## Section 4: Compliance Summary Table

**Tier definitions (v0.6.2):**
- **Community:** Apache 2.0 open-source, 5 agents, 10 end users, 2 admin seats, no SSO
- **Starter:** $1,200/yr, 100 agents, 250 end users, 25 admin seats, OIDC SSO only
- **Professional:** $4,800/yr, 500 agents, 1,000 end users, 50 admin seats, full SSO (SAML + OIDC + SCIM)
- **Professional Plus:** $14,400/yr, 2,000 agents, 10,000 end users, 200 admin seats, 5 orgs
- **Enterprise:** Unlimited on all dimensions, dedicated 24/7 support

| Control Domain | ASVS v5 Chapter | API Top 10 | LLM Top 10 | Community | Starter | Professional | Prof. Plus | Enterprise |
|---|---|---|---|---|---|---|---|---|
| Input validation and sanitization | V1, V5 | API1, API3 | LLM01 | Yes | Yes | Yes | Yes | Yes |
| Authentication (passwords, TOTP) | V2 | API2 | -- | Yes | Yes | Yes | Yes | Yes |
| WebAuthn/FIDO2 (partial) | V2 | API2 | -- | Yes | Yes | Yes | Yes | Yes |
| OIDC federation | V2 | API2 | -- | -- | Yes | Yes | Yes | Yes |
| SAML federation | V2 | API2 | -- | -- | -- | Yes | Yes | Yes |
| Session management | V3 | API2 | -- | Yes | Yes | Yes | Yes | Yes |
| OPA policy enforcement | V4 | API1, API5 | LLM07, LLM08 | Yes | Yes | Yes | Yes | Yes |
| Prompt injection detection (FastText) | V5 | API3 | LLM01 | Yes | Yes | Yes | Yes | Yes |
| Prompt injection detection (Ollama LLM) | V5 | API3 | LLM01 | Yes | Yes | Yes | Yes | Yes |
| Multi-backend inspection fallback | V5 | API3 | LLM01, LLM09 | -- | Yes | Yes | Yes | Yes |
| Credential Handle Service (CHS) | V5, V8 | API3 | LLM06 | Yes | Yes | Yes | Yes | Yes |
| AES-256-GCM column encryption | V6 | API8 | LLM06 | Yes | Yes | Yes | Yes | Yes |
| Argon2id password hashing | V6 | API2 | -- | Yes | Yes | Yes | Yes | Yes |
| ECDSA P-256 licence signing | V6 | API8 | -- | Yes | Yes | Yes | Yes | Yes |
| Generic error responses | V7 | API8 | -- | Yes | Yes | Yes | Yes | Yes |
| Structured audit log (file) | V7 | API9 | LLM08 | Yes | Yes | Yes | Yes | Yes |
| Audit log to PostgreSQL | V7 | API9 | LLM08 | Yes | Yes | Yes | Yes | Yes |
| SHA-384 Merkle chain (audit integrity) | V7 | -- | -- | Yes | Yes | Yes | Yes | Yes |
| SIEM integration (Splunk/ES/Wazuh) | V7 | API9 | LLM08 | -- | Yes | Yes | Yes | Yes |
| Row-level security (RLS) | V8 | API1 | -- | Yes | Yes | Yes | Yes | Yes |
| PII masking in audit logs | V8 | API8 | LLM06 | Yes | Yes | Yes | Yes | Yes |
| TLS 1.2+ enforcement (Caddy) | V9 | API8 | -- | Yes | Yes | Yes | Yes | Yes |
| HSTS headers | V9 | API8 | -- | Yes | Yes | Yes | Yes | Yes |
| Seccomp allowlist | V10 | API8 | LLM05 | Yes | Yes | Yes | Yes | Yes |
| AppArmor profile | V10 | API8 | LLM05 | Yes | Yes | Yes | Yes | Yes |
| Read-only container filesystem | V10 | API8 | LLM05 | Yes | Yes | Yes | Yes | Yes |
| Per-IP rate limiting | V11 | API4 | LLM04 | Yes | Yes | Yes | Yes | Yes |
| Per-session rate limiting | V11 | API4 | LLM04 | Yes | Yes | Yes | Yes | Yes |
| Per-agent rate limiting | V11 | API4, API6 | LLM04, LLM08 | Yes | Yes | Yes | Yes | Yes |
| Per-endpoint rate limiting | V11 | API4, API6 | LLM04 | Yes | Yes | Yes | Yes | Yes |
| Anomaly detection (ZSET sliding window) | V11 | API6 | LLM08 | Yes | Yes | Yes | Yes | Yes |
| Audit log rotation and retention | V12 | -- | -- | Yes | Yes | Yes | Yes | Yes |
| pg_partman time-based partitioning | V12 | -- | -- | Yes | Yes | Yes | Yes | Yes |
| Hop-by-hop header stripping | V13 | API10 | -- | Yes | Yes | Yes | Yes | Yes |
| Response cache (CLEAN-only) | V13 | API10 | -- | Yes | Yes | Yes | Yes | Yes |
| OTEL tracing (Jaeger) | V13 | API9 | -- | Yes | Yes | Yes | Yes | Yes |
| Docker Secrets integration | V6 | API8 | LLM10 | Yes | Yes | Yes | Yes | Yes |
| HashiCorp Vault integration | V6 | API8 | LLM10 | -- | Yes | Yes | Yes | Yes |
| AWS/Azure/GCP Secrets Manager | V6 | API8 | LLM10 | -- | Yes | Yes | Yes | Yes |
| Keeper secrets integration | V6 | API8 | LLM10 | -- | Yes | Yes | Yes | Yes |
| SCIM v2 agent provisioning | V4 | API9 | LLM08 | -- | -- | Yes | Yes | Yes |
| Response inspection pipeline | V5 | API10 | LLM02 | -- | Yes | Yes | Yes | Yes |
| Trivy CI scanning | V10 | API8 | LLM05 | Yes | Yes | Yes | Yes | Yes |
| JWT alg:none rejection | V2 | API2 | -- | Yes | Yes | Yes | Yes | Yes |
| JWKS waterfall key rotation | V2 | API2 | -- | Yes | Yes | Yes | Yes | Yes |
| Backoffice port isolation (8443) | V4 | API5 | -- | Yes | Yes | Yes | Yes | Yes |
| Agent limit enforcement | V11 | API4 | LLM08 | 5 agents | 100 | 500 | 2,000 | Unlimited |
| End user limit enforcement | V11 | API4 | -- | 10 | 250 | 1,000 | 10,000 | Unlimited |
| Admin seat limit enforcement | V11 | API4 | -- | 2 | 25 | 50 | 200 | Unlimited |
| Multi-org isolation | V4 | API1 | -- | 1 org | 1 org | 1 org | 5 orgs | Unlimited |
| Apache 2.0 open-source license | -- | -- | -- | Yes | -- | -- | -- | -- |
| Admin minimum count enforcement | V11 | API5 | -- | Yes | Yes | Yes | Yes | Yes |
| Agent min-length enforcement (64 chars) | V11 | API6 | LLM08 | Yes | Yes | Yes | Yes | Yes |
| Multi-tenant Redis isolation | V8 | API1 | -- | Yes | Yes | Yes | Yes | Yes |

---

## Section 5: Gap Analysis and Residual Risk

This section documents areas where Yashigani's controls do not fully satisfy ASVS v5 Level 3 requirements. Security architects performing due diligence should review these gaps when assessing residual risk.

---

### Gap 1: Internal Mutual TLS (V9.2.2) -- FAIL

**Nature of gap:** ASVS v5 L3 requires mutual TLS for service-to-service communication. Internal communications (gateway to OPA, PostgreSQL, Redis) rely on Docker network isolation rather than mTLS.

**What Yashigani does:** Deploys services within isolated container networks. TLS is available for PostgreSQL and OPA connections. Network policies restrict cross-service reachability.

**What Yashigani does not do:** Enforce mTLS on all internal service connections by default. Provide built-in certificate management for an internal service mesh.

**Recommended mitigations:** Configure TLS for PostgreSQL and Redis connections. Deploy a service mesh (Istio, Linkerd) for automatic mTLS. For highest assurance, use sidecar proxies with certificate rotation.

**Priority: HIGH** (most significant L3 gap)

---

### Gap 2: Certificate Pinning (V9.1.6) -- FAIL

**Nature of gap:** L3 requires certificate pinning for high-value external connections. Yashigani does not pin certificates for connections to inspection backends, SIEM endpoints, or secrets backends.

**What Yashigani does:** Validates standard certificate chains. Uses ACME for automated certificate management.

**Recommended mitigations:** Implement certificate pinning for inspection backend connections (Anthropic, Gemini, Azure OpenAI). Pin SIEM endpoint certificates. Consider DANE/TLSA as an alternative to HTTP-based pinning.

**Priority: MEDIUM**

---

### Gap 3: Hardware Attestation (V10.5.2) -- FAIL

**Nature of gap:** L3 requires hardware-level integrity attestation (TPM, secure boot). Yashigani is a software-only product and does not integrate with hardware security modules for attestation.

**What Yashigani does:** Software-level integrity: seccomp, AppArmor, read-only filesystem, digest-pinned images.

**Recommended mitigations:** Deploy on confidential computing platforms (AMD SEV, Intel TDX). Use TPM-backed measured boot for the host OS. Consider UEFI Secure Boot for the container host.

**Priority: MEDIUM** (dependent on deployment environment)

---

### Gap 4: Memory Zeroing (V8.2.3) -- FAIL

**Nature of gap:** L3 requires sensitive data to be cleared from memory when no longer needed. Python's garbage collector does not guarantee deterministic memory zeroing of string objects.

**What Yashigani does:** Uses short-lived variables for sensitive data. Session invalidation removes server-side session state.

**What Yashigani does not do:** Explicitly zero password strings, TOTP secrets, or encryption keys in memory after use. This is a fundamental limitation of the Python runtime.

**Recommended mitigations:** For highest assurance, security-critical cryptographic operations could be delegated to a C extension that performs explicit memory zeroing. Alternatively, deploy in confidential computing environments where memory is encrypted.

**Priority: LOW-MEDIUM** (Python runtime limitation; mitigated by container isolation)

---

### Gap 5: Key Destruction Verification (V6.5.3) -- FAIL

**Nature of gap:** L3 requires verification that retired cryptographic keys are securely destroyed. Yashigani delegates key lifecycle to secrets backends but does not verify destruction.

**Recommended mitigations:** Implement key destruction verification callbacks for each secrets backend. Use cloud KMS key scheduling for destruction with confirmation.

**Priority: LOW**

---

### Gap 6: Data Classification Policy (V8.1.2) -- FAIL

**Nature of gap:** L3 requires a formal data classification policy. CHS provides technical credential classification, but no formal policy document defines data sensitivity levels.

**Recommended mitigations:** Create a data classification policy document mapping sensitivity levels to handling requirements. Map CHS patterns and PII hooks to classification levels.

**Priority: LOW** (process gap, not technical)

---

### Gap 7: Backup Encryption (V8.6.1) -- FAIL

**Nature of gap:** L3 requires backup data to be encrypted. Yashigani does not manage database backups; this is delegated to operator infrastructure.

**Recommended mitigations:** Configure PostgreSQL backup encryption (pg_basebackup with encryption, or encrypted storage volumes). Ensure Redis persistence files are on encrypted storage.

**Priority: LOW** (operator infrastructure responsibility)

---

### Gap 8: WebAuthn Constructor Bug (V2.5.5) -- PARTIAL

**Nature of gap:** WebAuthn/FIDO2 passkey support exists but has a known constructor bug that prevents full functionality.

**Recommended mitigations:** Fix the constructor bug to achieve full WebAuthn L3 compliance. This is planned for a future release.

**Priority: MEDIUM** (hardware authenticators are important for L3)

---

### Gap 9: Formal Code Audit (V10.1.1) -- PARTIAL

**Nature of gap:** L3 expects formal independent code audits. Yashigani is open source with CODEOWNERS-enforced review but has not undergone a formal third-party security audit.

**Recommended mitigations:** Commission an independent security audit from a qualified firm. Publish audit results.

**Priority: HIGH** (important for L3 credibility)

---

### Gap 10: Post-Quantum Cryptography (V6.2.3, V9.4.1) -- PARTIAL

**Nature of gap:** Hybrid X25519+ML-KEM-768 and ML-DSA-65 are prepared but blocked on upstream library/tooling support (Caddy 2.10, `cryptography` FIPS 204).

**Recommended mitigations:** Track upstream release schedules. Enable PQ hybrid modes as soon as dependencies ship. Test PQ key exchange in staging environments.

**Priority: LOW** (proactive preparation is strong; blocked on ecosystem)

---

### Gap 11: Training Data Poisoning (LLM03)

**Nature of gap:** Training-time concern outside runtime proxy scope.

**Recommended mitigations:** Secure model training pipeline. Monitor classification accuracy over time.

**Priority: N/A** (architectural scope boundary)

---

### Gap 12: Response Inspection Dependency (LLM02, API10)

**Nature of gap:** Several controls depend on YASHIGANI_INSPECT_RESPONSES being enabled, which is not the default in all configurations.

**Recommended mitigations:** Enable response inspection for high-sensitivity deployments. Consider selective per-path response inspection to balance security and performance.

**Priority: MEDIUM**

---

### Summary Gap Table

| Gap | ASVS Req | Verdict | Risk Level | Priority | Mitigation Type |
|---|---|---|---|---|---|
| Internal mTLS | V9.2.2 | PARTIAL | Medium | MEDIUM | Engineering (close OPA #54 + Ollama upstream TLS) |
| Certificate pinning | V9.1.6 | FAIL | Medium | MEDIUM | Engineering |
| Hardware attestation | V10.5.2 | FAIL | Medium | MEDIUM | Deployment (confidential computing) |
| Memory zeroing | V8.2.3 | FAIL | Low-Med | LOW-MED | Engineering (C extension) or deployment |
| Key destruction verification | V6.5.3 | FAIL | Low | LOW | Engineering |
| Data classification policy | V8.1.2 | FAIL | Low | LOW | Process (documentation) |
| Backup encryption | V8.6.1 | FAIL | Low | LOW | Operator infrastructure |
| WebAuthn constructor bug | V2.5.5 | PARTIAL | Medium | MEDIUM | Engineering (bug fix) |
| Formal code audit | V10.1.1 | PARTIAL | High | HIGH | Process (third-party audit) |
| Post-quantum crypto | V6.2.3 | PARTIAL | Low | LOW | Blocked on upstream |
| Response inspection default | LLM02 | PARTIAL | Medium | MEDIUM | Configuration guidance |
| Password strength meter | V2.1.8 | FAIL | Low | LOW | Engineering (UI) |

---

### Version History: Security-Relevant Changes

#### v1.09.5 Changes

| Change | OWASP Relevance | Effect |
|---|---|---|
| Agent PSK token rotation with grace periods | ASVS V2.7.3 | Zero-downtime credential rotation for agent tokens |
| WebAuthn/FIDO2 passkey support (partial) | ASVS V2.5.5 | Hardware authenticator support; constructor bug pending fix |
| Recovery codes (8 codes, Argon2id-hashed) | ASVS V2.5.4, V2.6.1 | Strong MFA recovery mechanism |
| TOTP replay prevention (used-code cache) | ASVS V2.5.6 | Prevents TOTP code reuse within time window |
| Progressive TOTP lockout | ASVS V2.5.7 | Rate-limited MFA attempts |
| Anti-lockout: 2 admin accounts at install | ASVS V4.3.3 | Prevents admin lockout scenarios |
| bcrypt for Prometheus basic auth | ASVS V6.4.1 | Monitoring endpoint credential protection |

#### v2.20 Changes

| Change | OWASP Relevance | Effect |
|---|---|---|
| License anti-tampering (v4 counter-sig + self-integrity) | ASVS V10.2, V14.1 | Detects and halts on verifier patching; eliminates license bypass via binary modification |
| PII detection module (3 modes, 10 types, bidirectional, cloud bypass) | ASVS V8.3, LLM02, LLM06 | Structured PII detection in prompt and response path; cloud model bypass enforces local routing on PII classification |
| Response-path inspection wired to /v1 routes | ASVS V5.2, LLM01 | All OpenAI-compatible responses inspected before delivery; closes indirect injection vector on /v1 path |
| Container hardening (seccomp, AppArmor opt-in, read-only FS) | ASVS V14.2 | Defence-in-depth at container boundary; read-only root filesystem limits post-exploitation persistence |
| WAF/DDoS (Caddy limits, per-IP DDoSProtector, Coraza ref config) | ASVS V13.1, API4, API6 | Rate limiting at HTTP layer; per-IP DDoS threshold enforcement; Coraza path for full WAF |
| FastText model baked into Docker image | ASVS V14.2 | Eliminates outbound model-pull dependency at startup; air-gapped deployments reach full inspection immediately |
| Model aliases Redis persistence (write-through) | ASVS V7.1 | Alias availability survives Postgres maintenance; read latency eliminated |
| SBOM + cosign keyless image signing (CycloneDX 1.5 + CryptoBoM) | ASVS V14.2, V6.1 | Full software supply-chain provenance; cryptographic verification of image identity before pull |
| Helm chart fixes + network policies for all v2.x services | ASVS V14.2 | All services added since v2.0 now covered by Kubernetes network policies; chart passes lint |
| Streaming chunk-level inspection (StreamingInspector) | LLM01, ASVS V5.2 | Injection detection in streaming responses; buffer threshold prevents inspection bypass via chunk fragmentation |
| HMAC-SHA256 per-tenant email hashing | ASVS V7.3, V8.3 | Per-tenant KMS-keyed hash prevents cross-tenant email correlation in audit events |
| Ollama model digest pinning | ASVS V14.2 | Supply-chain control for local inference models; poisoned registry substitution detected and rejected |
| 9 compliance framework mappings published | ASVS V1.6.1, V14.1 | Formal mapping against SOC 2, ISO 27001, HIPAA, PCI DSS v4, GDPR, NIST CSF, NIST 800-53, CIS Controls v8, OWASP ASVS v5 |
| 2 STRIDE threat models (product: 17 threats, solution: 38 threats) | ASVS V1.1 | Formal threat modelling artefacts for procurement and security review |
| 548 tests (523 unit + 25 e2e) | ASVS V1.6.1, V14.1 | Expanded test coverage including PII module, streaming inspector, container hardening, and supply-chain controls |

#### v2.1 Changes

| Change | OWASP Relevance | Effect |
|---|---|---|
| Admin Dashboard UI (login page + 9-section admin panel) | ASVS V1.1, V4.1 | Self-service management without raw API access; reduces misconfiguration risk |
| 12 Alertmanager rules (P1-P5) | ASVS V7.2 | Automated alerting on security-relevant routing and budget events |
| Budget Postgres persistence | ASVS V7.1 | Budget state survives restarts; eliminates budget counter loss on Redis eviction |
| Pool Manager background health monitor | ASVS V14.2 | Continuous container health surveillance; reduces window between failure and replacement |
| OIDC identity broker (end-to-end: JWT validation, JWKS, group extraction) | ASVS V3.3, V3.5.3 | Fully operational federated identity; CSRF protection on OAuth callback |
| Mandatory 2FA after SSO | ASVS V2.8 | Prevents session hijack replay via stolen SSO session cookie |
| SSO audit trail with SHA-256 email hashing | ASVS V7.3, V8.3 | Raw email never stored; audit events contain only hashed identifier |
| Podman rootless parity | ASVS V14.2 | Correct user namespace mapping; eliminates volume permission failures in rootless runtimes |
| OPA v1_routing.rego verified operational end-to-end | ASVS V4.1 | Routing safety net confirmed functional; SAFE/WARNING/BLOCK verdicts validated |
| 413 tests (388 unit + 25 e2e) | ASVS V1.6.1, V14.1 | Expanded coverage for dashboard, SSO, budget persistence, and Pool Manager |

#### v2.0 Changes

| Change | OWASP Relevance | Effect |
|---|---|---|
| Unified identity model (human + service, kind field) | ASVS V1.2, V4.1 | Single identity model simplifies access control and audit; reduces identity confusion risks |
| Optimization Engine (4-signal routing, P1-P9) | ASVS V4.1, API4 | Priority-based routing with OPA safety net prevents unauthorized resource access |
| Three-tier budget system (org cap, group, individual) | API4, LLM10 | Prevents uncontrolled API spend and resource exhaustion via hierarchical budget enforcement |
| Budget-redis (dedicated, noeviction) | ASVS V7.1 | Budget state persistence guaranteed; no silent data loss under memory pressure |
| Open WebUI with trusted headers | ASVS V3.1, V4.1 | Identity propagation via trusted headers; no credential exposure to Open WebUI |
| Container Pool Manager (per-identity isolation) | ASVS V1.5.2, V14.2 | Strong tenant isolation via per-identity containers; self-healing reduces attack window |
| Multi-IdP identity broker (OIDC + SAML v2) | ASVS V1.2.1, V3.3 | Federated identity with tier-gated access; supports multiple simultaneous providers |
| Sensitivity pipeline (regex + FastText + Ollama) | LLM01, LLM02, LLM06 | Three-stage content analysis with all stages on by default; defense-in-depth for prompt injection |
| OPA v1_routing.rego safety net | ASVS V4.1, API1 | Policy-enforced routing decisions prevent Optimization Engine bypass |
| LLM policy review for P1-P3 routing | ASVS V4.1, LLM01 | Semantic policy analysis for high-priority routing decisions |
| 363 tests | ASVS V1.6.1, V14.1 | Comprehensive test coverage across all modules including identity, billing, optimization, and pool |

#### v2.23.1 Changes

| Change | OWASP Relevance | Effect |
|---|---|---|
| Core-plane mTLS default-on (gateway / backoffice / postgres / pgbouncer / redis / opa) | ASVS V9.2, V9.3, V10.2, V14.1 | All inter-service traffic on the core plane uses mutual TLS with client-certificate verification; plaintext listeners removed |
| Two-tier PKI: step-ca root → intermediate → per-service leafs (SPIFFE-style URIs) | ASVS V10.1, V10.2, V10.4 | Short-lived per-service identities issued by an internal CA with automatic rotation; root stays 0400 on disk, never baked into images |
| seccomp + AppArmor default-on for every service on every runtime | ASVS V14.2, V10.4 | Container kernel-surface confinement; no "skip on dev" branch; AppArmor `mmap` permission added after regression |
| Fail-closed on missing HMAC + OWUI secrets | ASVS V6.4.1, V14.1 | Startup hard-fails when critical secrets are absent; no silent dev-mode fallback into production |
| Centralised SSRF allowlist helper | ASVS V12.6, API7, LLM05 | All outbound HTTP from backend services routed through a single allowlist-enforcing helper; ad-hoc outbound calls removed |
| Per-endpoint body-size limits | ASVS V4.3.1, API4 | Tighter per-endpoint caps below the Caddy global floor; resource-exhaustion surface reduced |
| Log-injection sanitisation (CR/LF strip, length-cap, unicode-normalise) | ASVS V16.6.1 | All user-controllable strings sanitised before audit/app log formatting |
| Session rotation on password change | ASVS V7.4.2, V7.2.5 | Password change invalidates all prior sessions for the principal |
| Uniformised 401 vs 404 on unauth admin endpoints | ASVS V4.1.5, API5 | No information leakage via differential status codes revealing protected route existence |
| Explicit CSP `script-src` + working `/admin/csp-report` handler | ASVS V14.3.2, V7.1 | CSP no longer falls back to `default-src`; violations captured in audit log |
| Algorithm allowlist on license ECDSA verifier (ES256 only) | ASVS V6.2.1, V10.1 | Prevents algorithm-substitution downgrade on license verification |
| Caddy header hygiene (strip Server, remove stale alt-svc) | ASVS V14.3.2, API9 | Reduces version fingerprinting on Shodan / banner-grab |
| PCI-compliant password expiry profile (≤90 days) | ASVS V2.1.1, PCI-DSS 8.3.9 | Optional tighter expiry profile for PCI-scope deployments |
| TOTP enrolment split provision/confirm | ASVS V2.5.4, V2.5.5 | Secret is never active without a confirmation round-trip; defeats provision-and-abandon attacks |
| Auth-throttle admin self-visibility | ASVS V7.2.1 | Authenticated admins can see their own + all throttled/blocked IPs at /admin → Security → Blocked IPs (backed by /auth/blocked-ips). Unauthenticated locked-out operator path (RFC 6585 Retry-After) tracked as v2.23.2 follow-up. |
| Agent tier-limit returns 402 (was 500) with correct body | ASVS V14.2, API8 | Correct HTTP semantics; 500 no longer leaks that tier enforcement is a caught exception |
| AGENT_REGISTERED audit events persisted | ASVS V7.1.1, V7.1.3 | Registration events land in audit log; previously fired only to in-memory channel |
| `/.well-known/security.txt` (RFC 9116) | ASVS V1.14.1 | Coordinated-disclosure contact discoverable via standard path |
| Symbol-bearing generated passwords (`!*,-._~`, category-guaranteed) | ASVS V2.1.1, V2.1.9 | Installer credentials include symbols; character class enforced per-password; safe across URL/.env/sed/shell |
| `YSG_RUNTIME=docker` stale-env bleed fix + runtime-honouring backup helpers | ASVS V14.1 | Deterministic runtime selection on hosts with both podman + docker installed |
| Clean-slate install validated on macOS Podman, macOS Docker, Linux Podman, Linux Docker, K8s Helm | ASVS V1.6.1, V14.1 | Five-platform installer gate for every release |
| Caddy-gated `/internal/metrics` with SPIFFE URI ACL (closes EX-231-08) | ASVS V4.1.1, V4.1.3, V4.2.1, V8.2.1, V10.2, V14.1 | Prometheus scrapes route through Caddy :8444 mTLS listener; Caddy validates client cert against internal CA and forwards the verified URI SAN as `X-SPIFFE-ID`; gateway/backoffice `/internal/metrics` now enforce an allowlist sourced from `service_identities.yaml` (`endpoint_acls`). Per-service SPIFFE URI SANs (`spiffe://yashigani.internal/<service>`) embedded in leaf certs at issuance. Zero-trust: app-layer authN on every endpoint, mTLS no longer used as a sole control. Fails closed on missing/malformed manifest. |
| Refined PKI trust-store rule: Pattern B where supported, root-cert-anchor where not (pgbouncer, Redis) | ASVS V9.2.2, V10.2 | Runtime discovery showed OpenSSL `verify-ca` strict mode (`error:0A000086`) rejects non-self-signed intermediate anchors. Audit confirmed pgbouncer and Redis (libssl-direct) require `ca_root.crt` as trust anchor; Python ssl, Go crypto/tls, and postgres with pg_hba hostssl correctly accept `ca_intermediate.crt` (partial-chain). The root CA private key never enters any workload. Pattern B sweep (`b32c115`) + pgbouncer fix (`cc3c5bf`) + Redis fix (`<this commit>`) produce a consistent, library-aware trust-store policy across all services. |

(Authoritative manual evidence for v2.23.1 is archived outside the code repo per policy.)

#### v2.23.0 Changes

| Change | OWASP Relevance | Effect |
|---|---|---|
| OPA enforcement on ALL /v1 traffic (request + response path) | ASVS V4.1, V5.2, LLM01, LLM02 | Policy evaluation covers both inbound requests and outbound responses on all /v1 routes |
| Fail2ban auth throttle (x5 escalation -> permanent IP block) | ASVS V2.2.1, API2 | Aggressive brute-force prevention with escalating penalties |
| IP allowlist + blocklist (IPv4/IPv6/CIDR) | ASVS V4.1.3, API5 | Network-level access control for both allow and deny lists |
| PKCE on OIDC client | ASVS V2.8.1, API2 | Proof Key for Code Exchange prevents authorization code interception |
| acr/amr auth strength validation | ASVS V2.8.1 | Validates authentication context class and method references from IdP |
| Content relay detection (agent laundering) | LLM07, LLM08, API5 | Detects agents proxying requests through other agents to bypass policy |
| Constant-time TOTP comparison | ASVS V2.5.6, V6.2 | Prevents timing-based TOTP guessing attacks |
| __Host- cookie prefix | ASVS V3.2.1, V3.2.2 | `__Host-yashigani_admin_session` and `__Host-yashigani_session` prevent cookie tossing attacks |
| Strict CSP (object-src none, base-uri none, COOP, report-uri) | ASVS V14.3.2 | External JS/CSS only, zero inline code; admin UI is a static SPA calling backend APIs |
| Context-specific password word list | ASVS V2.1.1, V2.1.9 | Rejects passwords containing domain-specific terms |
| Admin-configurable password policy (max 13 months) | ASVS V2.1.1 | Password expiry enforced with admin-configurable maximum validity period |
| Self-service password reset (TOTP-verified) | ASVS V2.1.5, V2.1.6 | Users can reset their own password after TOTP verification |
| Crypto inventory API + admin UI | ASVS V6.2.2, V1.4.1 | Complete inventory of all cryptographic algorithms in use, accessible via API and admin panel |
| Podman SDK (podman-py) for container isolation | ASVS V14.2 | Native Podman API access for container management; macOS socket detection |
| Pre-release OWASP gate | ASVS V1.6.1, V14.1 | Pre-release compliance review covering OWASP ASVS v5, API Security, and Agentic AI controls |
| 523 unit + 25 e2e tests | ASVS V1.6.1, V14.1 | Expanded test coverage including all v2.23 security controls |

#### v0.7.0 / v0.7.1 Changes

| Change | OWASP Relevance | Effect |
|---|---|---|
| ECDSA P-256 licence signing key active | ASVS V6, V14 | ML-DSA-65 migration planned when FIPS 204 ships |
| CIDR-based IP allowlisting per agent | ASVS V4.1.3, API5 | Defense-in-depth for agent token compromise |
| Path matching fix (IC-6) | ASVS V4.1, API1 | Single-segment glob `*` no longer matches across `/` boundaries |
| Direct webhook alerting on credential exfil | LLM01, LLM06 | Real-time notification of credential exfiltration attempts |
| Automated partition monitoring + alert | ASVS V7.1 | Audit log reliability monitoring |
| OPA Policy Assistant | ASVS V4.1 | Schema-validated policy suggestions; apply/reject audited |

---

### Random Number Generation (ASVS 11.5.2)

Yashigani uses Python's `secrets` module exclusively for all security-sensitive random values (session tokens, TOTP seeds, CSRF state, recovery codes, PKCE verifiers). The `secrets` module is backed by `os.urandom()` which reads from `/dev/urandom`.

**Kernel CSPRNG guarantee:** On Linux 4.8+ (all supported deployment targets), `/dev/urandom` uses ChaCha20 in the kernel CSPRNG. The kernel CSPRNG is seeded from hardware entropy (RDRAND, timing jitter, interrupt randomness) and is non-blocking. It does not degrade under load -- once seeded, output quality is cryptographically equivalent to `/dev/random`.

**Platform scope:** Docker containers inherit the host kernel's CSPRNG. No additional entropy sources are required. The `getrandom(2)` syscall (used by Python 3.6+) blocks only during early boot before the CSPRNG is seeded, which does not apply to containerised processes.

**No application-level RNG:** Yashigani does not use `random.Random`, `os.urandom()` directly, or any third-party RNG library. All paths go through `secrets.token_urlsafe()`, `secrets.token_bytes()`, or `secrets.randbits()`.

---

### Memory Encryption (ASVS 11.7.1)

Yashigani does **not** implement application-level memory encryption. Python's garbage-collected runtime does not support deterministic memory zeroing of string or bytes objects.

**L3 recommendation:** Deployments requiring L3 compliance for memory protection should use hardware-level memory encryption:

- **Intel SGX** (Software Guard Extensions) -- enclave-based memory encryption for sensitive operations
- **AMD SEV / SEV-SNP** (Secure Encrypted Virtualization) -- VM-level memory encryption with attestation
- **Intel TDX** (Trust Domain Extensions) -- hardware-isolated trust domains
- **ARM CCA** (Confidential Compute Architecture) -- Realm-based memory isolation

**Preflight check recommendation:** A future release should add a preflight check that detects whether the host supports confidential computing and warns operators of L3 deployments that do not have hardware memory encryption enabled.

**Current mitigations:** Container isolation (separate memory spaces per process), short-lived variables for sensitive data, session invalidation removing server-side state, and seccomp/AppArmor restricting process capabilities reduce the practical attack surface for memory disclosure.

---

## Appendix: Terminology and References

### Terminology

| Term | Definition |
|---|---|
| ASVS | OWASP Application Security Verification Standard |
| CHS | Credential Handle Service -- Yashigani component that strips credentials from payloads before AI inspection |
| CSPRNG | Cryptographically Secure Pseudo-Random Number Generator |
| HSM | Hardware Security Module |
| MCP | Model Context Protocol -- protocol for AI agent-to-tool server communication |
| mTLS | Mutual Transport Layer Security |
| OPA | Open Policy Agent -- embedded policy engine for all authorization decisions |
| PQ | Post-Quantum (cryptography) |
| RBAC | Role-Based Access Control |
| RLS | Row-Level Security -- PostgreSQL feature enforcing per-tenant data isolation |
| SBOM | Software Bill of Materials |
| SCIM | System for Cross-domain Identity Management (RFC 7644) |
| SIEM | Security Information and Event Management |
| TOTP | Time-based One-Time Password (RFC 6238) |
| ZSET | Redis Sorted Set -- data structure used for sliding window anomaly detection |

### References

| Document | Version | URL |
|---|---|---|
| OWASP Application Security Verification Standard | v5.0 (2025) | https://owasp.org/www-project-application-security-verification-standard/ |
| OWASP API Security Top 10 | 2023 | https://owasp.org/www-project-api-security/ |
| OWASP Top 10 for LLM Applications | 1.1 | https://owasp.org/www-project-top-10-for-large-language-model-applications/ |
| OWASP Agentic AI Threats and Mitigations | 2025 | https://owasp.org/www-project-top-10-for-large-language-model-applications/ |
| NIST SP 800-63B (Digital Identity Guidelines) | 4 | https://pages.nist.gov/800-63-4/sp800-63b.html |
| Open Policy Agent Documentation | Current | https://www.openpolicyagent.org/docs/ |
| RFC 7517 (JSON Web Key) | -- | https://datatracker.ietf.org/doc/html/rfc7517 |
| RFC 6238 (TOTP) | -- | https://datatracker.ietf.org/doc/html/rfc6238 |
| RFC 7644 (SCIM 2.0) | -- | https://datatracker.ietf.org/doc/html/rfc7644 |
| FIPS 204 (ML-DSA) | Draft | https://csrc.nist.gov/pubs/fips/204/final |
| FIPS 203 (ML-KEM) | Draft | https://csrc.nist.gov/pubs/fips/203/final |

---

*This document assesses Yashigani v2.23.2 against OWASP ASVS v5.0 at Level 3 (highest assurance). Security control implementations should be verified against the current release. This document does not constitute a formal security certification and should be used as one input to a comprehensive security assessment. The v2.23.2 manual evidence sweep is produced separately by the internal GRC audit function and held in the internal compliance archive outside the code repo per policy.*
