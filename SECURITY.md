# Security Policy

## Supported Versions

A single release line is actively maintained on the `main` branch. Open WebUI is an optional flag (`--with-openwebui`), not a separate branch.

| Version | Supported | Notes |
|---------|-----------|-------|
| 3.1.x   | ✅ Current | Unified identity-ID authorization, role-tiered TOTP (admin SHA-512/8, user SHA-256/6), PII enforcement blocks at ingress, RBAC group-mutation step-up, capability-envelope MCP import ceremony, connection allow-list; full pre-release SAST + DAST + tooling security gate |
| 3.0.x   | ✅ Patch window | Document-content data protection (doc-OPA: pass/redact/pseudonymize/block), every-hop OPA agent orchestration, MCP hardening, OpenWebUI at root behind the owui-users gate |
| 2.25.x  | ❌ | Superseded by 3.0.x |
| 2.24.x  | ❌ | Superseded by 2.25.x |
| 2.23.x  | ❌ | Superseded by 2.24.x |
| < 2.23  | ❌ | End of life |

## Reporting a Vulnerability

Thank you for helping keep Yashigani secure.

**Please do not report security vulnerabilities via GitHub Issues.**

Report vulnerabilities by email to **bugs@agnosticsec.com** with:

1. A clear description of the vulnerability
2. Steps to reproduce
3. The version of Yashigani affected
4. Any proof-of-concept or supporting material

We aim to acknowledge all reports within **2 business days** and provide a remediation timeline within **7 business days**.

## Scope

Only vulnerabilities in Yashigani's own code are in scope. This includes the gateway, backoffice, admin UI/API, OPA policies, Optimization Engine, Budget System, Pool Manager, installer, and all bundled configuration (Caddyfile, compose files, Helm charts).

The following are **in scope**:

- Authentication and session management (OIDC, SAML, TOTP, WebAuthn, fail2ban throttle, __Host- cookies)
- OPA policy enforcement on /v1 traffic (request path and response path)
- Content inspection pipeline (scikit-learn ML classifier, LLM backends, PII detection, CHS)
- Sensitivity classification and routing (Optimization Engine, P1-P9 matrix)
- Budget enforcement (three-tier hierarchy, budget-redis)
- IP allowlist/blocklist enforcement (IPv4/IPv6/CIDR)
- Content relay detection (agent-to-agent laundering)
- CSP and security headers (strict CSP with no unsafe-inline)
- Crypto inventory (/admin/crypto/inventory)
- Internal CA (Smallstep step-ca for service-to-service TLS)
- Container-per-user isolation (Podman SDK)
- Admin service management (enable/disable services)
- Audit pipeline (file, PostgreSQL, Splunk, Elasticsearch, Wazuh)
- Domain-bound licensing (ECDSA P-256)

The following are **out of scope** — report directly to the respective maintainers:

- Vulnerabilities in third-party dependencies (unless Yashigani misconfigures them)
- Optional agent bundle containers: Lala (Langflow), Julietta (Letta), Scout (OpenClaw)
- Upstream MCP tool servers
- Open WebUI (when enabled via `--with-openwebui`)
- Wazuh, Grafana, Prometheus (when enabled via compose profiles)

## Disclosure Policy

We follow a **90-day coordinated disclosure** policy. After a fix is released we will publish a security advisory. We ask that you do not disclose the vulnerability publicly before the fix is available.

## Recognition

Agnostic Security does not operate a paid bug bounty programme. Researchers who report valid, in-scope vulnerabilities will be credited in the security advisory (with their consent).

## Release signing

Version tags are **SSH-signed** (`git config gpg.format ssh`) with the Agnostic
Security release key (Ed25519). Each `vX.Y.Z` tag is an annotated, signed tag;
verification shows `Good "git" signature with ED25519 key SHA256:…`.

**Verifying a signed tag:**

```sh
git fetch --tags --force origin
git tag -v vX.Y.Z
# Expect: Good "git" signature with ED25519 key SHA256:<release-key-fingerprint>
```

The release signer's public key is published in the repository's SSH
allowed-signers file (`.github/allowed_signers` / `docs/release-signing.md`); add
it to your local allowed-signers to validate the signer identity.

**Release-signing key fingerprint:** see `docs/release-signing.md` (the active
Ed25519 release key). Tags signed by any other key must be treated as untrusted.

**Scope note:** for FedRAMP High / strict paths, a hardware-backed key
(FIPS 140-2 token) is required; the standard release line uses the software
Ed25519 SSH key. Hardware-key integration is a separate workstream.
