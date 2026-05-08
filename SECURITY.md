# Security Policy

## Supported Versions

A single release line is actively maintained on the `main` branch. Open WebUI is an optional flag (`--with-openwebui`), not a separate branch.

| Version | Supported | Notes |
|---------|-----------|-------|
| 2.23.1  | ✅ Current | Core-plane mTLS default-on, two-tier PKI (step-ca), seccomp + AppArmor default-on, full pre-release security and QA hardening |
| 2.23.0  | ✅ Patch window | Single branch, API-first admin, strict CSP, compose profiles, opt-in internal CA |
| 2.22.x  | ✅ Patch window | OPA on /v1, Wazuh SIEM, Grafana/Prometheus admin access, agent personas |
| 2.20.x  | ❌ | Superseded by 2.22.x |
| 2.1.x   | ❌ | Superseded by 2.20.x |
| 2.0.x   | ❌ | Superseded by 2.1.x |
| < 2.0   | ❌ | End of life |

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
- Content inspection pipeline (FastText, LLM backends, PII detection, CHS)
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

Version tags and release artifacts are GPG-signed by the Agnostic Security release key.

**Required repository secrets** (configure in Settings → Secrets → Actions):

| Secret | Description |
|--------|-------------|
| `GPG_PRIVATE_KEY` | ASCII-armored RSA 4096 signing subkey, exported via `gpg --armor --export-secret-subkeys <subkey-id>!` |
| `GPG_PASSPHRASE` | Passphrase protecting the signing subkey |

**Graceful degradation:** if `GPG_PRIVATE_KEY` is not set, the release pipeline emits a `::warning::` annotation and the tag ships unsigned. No build step fails. Populate the secrets and re-run the release workflow to produce a signed tag.

**Verifying a signed tag:**

```sh
gpg --import docs/release-signing-key.asc
git fetch --tags --force origin
git tag -v vX.Y.Z
```

**Public key fingerprint:** TBD — populate `docs/release-signing-key.asc` and update this file after key generation.

**Key generation (one-time setup):**

```sh
# Generate a dedicated release signing subkey (RSA 4096)
gpg --full-generate-key

# Export the private signing subkey (subkey-id! notation selects subkey only)
gpg --armor --export-secret-subkeys <subkey-id>!

# Export the public key for repository consumers
gpg --armor --export releases@agnosticsec.com > docs/release-signing-key.asc
```

**Scope note:** for FedRAMP High/strict paths, a hardware-backed key (FIPS 140-2 token) is required. This pipeline supports software keys for standard releases; hardware key integration is a separate workstream.
