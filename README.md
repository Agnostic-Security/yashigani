<!-- last-updated: 2026-05-07T00:00:00+01:00 -->
# Yashigani
---

<html>
<body>
<div>
  <img src="https://github.com/agnosticsec-com/yashigani_img/blob/main/Yashiganymaster.png" alt="Yashigani" style="width:100%">
</div>
</body>
</html>

---
**Yashigani is the security enforcement gateway for MCP servers and agentic AI systems.**
---
*Yashigani — Security enforcement for agentic AI. Every call inspected. Every policy enforced. Every action audited.*
---
---
**Latest Tagged Release:** v2.23.2 (`2.23.x` branch, 2026-05-03) — Security hardening, supply-chain hygiene, ASVS L3 92%; all gates GREEN

> **Upgrade notice:** v2.23.2 ships a security hardening batch. Existing v2.23.1 deployments should upgrade.

> **Notable behaviour changes in v2.23.2:**
> - **Rate limiter fails closed** by default in v2.23.2 (was open in v2.23.1). Set `RATE_LIMITER_FAIL_MODE=open` if your deployment requires high-availability behaviour during Redis instability.

---
**Single branch:** `main` — all features, all tiers. Open WebUI, Wazuh, agent bundles, and the optional Smallstep step-ca runtime ACME service are all gated behind compose profiles / install flags. **Core-plane mTLS is default-on**: per-service leaf certificates are issued at install time by the in-tree two-tier PKI (`src/yashigani/pki/issuer.py`) — no optional services required.
---
**Document Date:** 2026-05-07
---
**Classification:** ***Public — Product Overview***
---


## Table of Contents

1. [What is Yashigani](#1-what-is-yashigani)
2. [The Problem It Solves](#2-the-problem-it-solves)
3. [Pre-flight Checklist](#3-pre-flight-checklist)
4. [How to Deploy](#4-how-to-deploy)
5. [Verifying a Release](#5-verifying-a-release)
6. [Compliance and Security Posture](#6-compliance-and-security-posture)
7. [Current Release Highlights](#7-current-release-highlights)
8. [Feature Matrix by Tier](#8-feature-matrix-by-tier)
9. [Our commitment to the OSS Community](#9-our-commitment-to-the-oss-community)

For architectural detail (request flow, components, network isolation, identity model), the full per-version feature history, the complete feature list, deployment topologies, and roadmap context, see [Architecture.md](Architecture.md).

---

## 1. What is Yashigani

Yashigani is a security enforcement gateway purpose-built for Model Context Protocol (MCP) servers and agentic AI systems. It operates as a reverse proxy, sitting between AI agents or human clients and the upstream MCP tool servers that those agents call. Every request passes through Yashigani before reaching a tool; every response is inspected before being returned. Nothing crosses the boundary without being authenticated, authorized, and inspected.

The **Model Context Protocol** is an open standard that allows AI agents — systems driven by large language models — to call external tools: file system operations, database queries, API calls, shell commands, and more. MCP enables genuinely powerful agentic behavior, but it also exposes a new and largely unaddressed attack surface. An LLM that can call tools is an LLM that can be manipulated into exfiltrating credentials, bypassing access controls, or executing unintended actions. The MCP specification itself defines the protocol, not the security envelope around it.

Yashigani fills that gap. It provides the security layer that MCP does not: authentication, fine-grained authorization via Open Policy Agent (OPA), ML-assisted prompt injection detection, credential exfiltration prevention, per-endpoint rate limiting, full audit trails with multi-sink delivery, encrypted secrets management, SSO/SCIM identity integration, enterprise-grade observability, intelligent model routing via the Optimization Engine, and three-tier budget governance. From a single developer running a local model to a large organization deploying hundreds of AI agents across multiple business units, Yashigani is the enforcement point that makes agentic AI deployments safe to operate in production.

### Coverage at a glance (verified April 2026)

Yashigani consolidates into a single Apache-2.0 stack the capabilities that would otherwise require integrating four or more separate open-source projects — and even that combined stack covers only around half of what Yashigani delivers out of the box, as of April 2026. Closing the remaining gap means deploying further products on top, plus custom-built modules for which there is no off-the-shelf substitute (multi-LLM prompt-injection adjudication, deterministic 4D sensitivity-aware routing, container-per-identity isolation with forensic post-mortem, and SHA-384 Merkle-chain audit tamper-evidence). The detailed coverage matrix vs. the top ten named competitors is maintained internally and reviewed every release.

---

## 2. The Problem It Solves

Agentic AI systems are not just chat interfaces. They call real tools, read real data, and execute real operations. This creates eight distinct classes of risk that traditional API gateways, network firewalls, and bolt-on AI wrappers were not designed to address. Yashigani solves all eight from a single enforcement point.

### 2.1 Unmonitored AI Access

AI agents and human users call LLMs — cloud and local — without inspection, audit, or policy enforcement. Prompts flow to models unchecked. Responses flow back unexamined. No one knows what was asked, what was answered, or whether any of it violated policy. Security teams have no visibility; compliance teams have no evidence.

**Yashigani's response:** Every prompt and every response passes through Yashigani's bidirectional inspection pipeline before reaching its destination. Inbound payloads are classified by a two-stage pipeline — a FastText ML classifier for low-latency first-pass detection (under 5ms, fully offline), followed by a configurable LLM-based deep inspection backend (Ollama, Anthropic Claude, Google Gemini, Azure OpenAI, or LM Studio). Responses are inspected on the return path with the same rigor. The pipeline is fail-closed: if all inspection backends are unavailable, the request is blocked by a sentinel policy, not passed through. Credential Harvesting Suppression (CHS) detects credential-shaped patterns in both directions. Every transaction produces a structured audit event written simultaneously to multiple sinks — local file, PostgreSQL (with row-level security and AES-256-GCM column encryption), and SIEM platforms (Splunk, Elasticsearch, Wazuh). Nothing passes uninspected. Nothing passes unrecorded.

### 2.2 Identity Sprawl

Enterprise AI deployments accumulate separate identity silos: user stores for the chat interface, agent registries for service accounts, API key tables for integrations, IdP configurations per department. Each silo has its own lifecycle, its own governance gap, and its own audit blind spot. When a security incident occurs, correlating "which entity did what" across disconnected registries is forensic archaeology.

**Yashigani's response:** Yashigani's unified identity model treats every entity — human user, AI agent, service account, API integration — as a first-class identity with a `kind` field. One registry, one governance framework, one audit trail. Humans and agents are subject to the same RBAC policies, the same rate limits, the same budget constraints, and the same audit depth. OPA policy enforcement is identity-aware across all entity types. There is no separate "agent management console" — because there is no separate identity class.

### 2.3 Uncontrolled AI Spend

Cloud LLM costs spiral without visibility or limits. A single team can burn through thousands in a day. A misconfigured agent can loop on expensive models indefinitely. CFOs discover the damage in the monthly invoice. Traditional rate limiting is too coarse — it caps requests, not dollars — and hard rejection breaks user workflows.

**Yashigani's response:** The three-tier budget system enforces spend governance with mathematical guarantees. Organization-level cloud caps set the hard ceiling. Group budgets allocate within that ceiling. Individual budgets constrain each user or agent. When a budget is exhausted at any tier, the system degrades gracefully to local inference via the Optimization Engine — the user's request is still served, just routed to a local model instead of a cloud API. Yashigani never rejects a request due to budget exhaustion. It never stops working. It just stops spending.

### 2.4 Data Leakage to Cloud Providers

Sensitive data — PII, PCI cardholder data, intellectual property, PHI — is sent to cloud LLM APIs without detection or classification. Once transmitted, data may be retained, logged, or used for training. Traditional DLP solutions were not designed for LLM payloads: they do not understand prompt structure, they cannot classify at inference speed, and they cannot enforce routing decisions based on sensitivity.

**Yashigani's response:** The three-layer sensitivity pipeline classifies every prompt before routing. Layer 1: regex pattern matching catches structured sensitive data (credit card numbers, SSNs, API keys). Layer 2: FastText ML classifier detects semantic sensitivity at under 5ms, fully offline. Layer 3: Ollama LLM classification provides deep contextual analysis for ambiguous cases. Data classified as CONFIDENTIAL or RESTRICTED is routed to local models only — this is an immutable rule enforced by the Optimization Engine. No override exists. No admin can bypass it. No configuration can disable it. CHS additionally strips credential-shaped patterns from payloads before any AI inspection backend sees them. The dedicated PII detection module (since v2.20) adds 10 entity types (SSN, credit card with Luhn validation, email, phone, IBAN, passport, NHS number, driver's licence, IP address, date of birth) with three enforcement modes: LOG (detect and audit), REDACT (replace with `[REDACTED:TYPE]` before forwarding to cloud), and BLOCK (reject requests containing PII destined for cloud models). PII filtering runs on both request and response paths — bidirectional, on all traffic, by default. Cloud bypass requires explicit admin opt-in.

### 2.5 Routing Opacity

When an AI request is routed to a cloud model versus a local model, no one knows why. When a particular model is selected over alternatives, there is no reasoning trail. Debugging cost anomalies, sensitivity violations, or performance issues requires guesswork. Auditors asking "why did this request go to OpenAI instead of staying local?" get no answer.

**Yashigani's response:** The Optimization Engine makes deterministic P1-P9 routing decisions based on four dimensions: sensitivity classification, request complexity, budget state, and model cost. Every routing decision is audited with a full reasoning chain — which factors were evaluated, what scores they produced, which priority level was assigned, and which model was selected. The decision is reproducible: given the same inputs, the same routing decision is made every time. Auditors, security teams, and cost analysts can trace any request from prompt to model selection to response, with complete justification at every step.

### 2.6 Multi-IdP Complexity

Enterprise deployments rarely have a single identity provider. Entra ID for corporate users in one country, a separate Entra ID tenant for another region, Okta for contractors, Google Workspace for a subsidiary acquired last year. Traditional approaches require deploying and maintaining an external identity broker like Keycloak — another service to secure, patch, and scale.

**Yashigani's response:** Yashigani IS the identity broker. Native support for OIDC and SAML v2 federation means multiple identity providers connect directly to the gateway. No external Keycloak instance, no additional infrastructure, no separate identity management surface. Users authenticate through their existing IdP; Yashigani maps the external identity to its unified identity model, applies consistent RBAC policies regardless of IdP origin, and produces a single audit trail across all authentication sources. One fewer service in the stack. One fewer attack surface.

### 2.7 Agent Data Isolation

When multiple users share an AI agent instance — or when a shared model runtime serves concurrent requests — data leaks between users. User A's context contaminates User B's session. Shared container filesystems mean one user's uploaded documents are accessible to another's agent process. This is not a theoretical concern; it is the default behavior of most agent deployment architectures.

**Yashigani's response:** Yashigani enforces container-per-identity isolation. Every user gets their own isolated container instance for agent execution. No shared instances. No shared filesystems. No shared model context. The Pool Manager provisions and manages these containers automatically — users do not need to request isolation, and administrators cannot disable it. This is a security product. Isolation is not a feature toggle; it is an architectural invariant.

### 2.8 Infrastructure Fragility

Containers crash. Models fail to load. Ollama instances run out of memory. Services go down without warning. In most AI deployments, a crashed container means a user is offline until someone notices and manually restarts it. Forensic evidence — logs, container state, filesystem changes — is destroyed on restart. Capacity planning for local model inference is guesswork.

**Yashigani's response:** The Pool Manager replaces broken containers instantly and transparently. Health checks detect failures; replacement containers are provisioned from the warm pool before the user notices the interruption. Ollama instances scale horizontally based on load. When a container fails, Yashigani preserves forensic evidence before cleanup — postmortem logs, container inspect output, and filesystem diffs are captured for root cause analysis. Dead containers are not just restarted; they are investigated. The warm pool ensures that replacement capacity is always available, and horizontal Ollama scaling ensures that local model inference does not become the bottleneck that forces premature cloud routing.

---

## 3. Pre-flight Checklist

Before any install on a new host, run the pre-flight checklist. It confirms host and runtime readiness — container runtime detection (Docker / Podman / Kubernetes), available disk and RAM, GPU detection (Apple Silicon M-series, NVIDIA, AMD, with `lspci` fallback) with model size recommendations based on VRAM, and inspection-pipeline prerequisites (regex, FastText, Ollama). The installer's preflight phase runs the same checks automatically; the standalone document is what an operator reads before kicking the installer off.

For a more detailed explanation, see the [Pre-flight Checklist](docs/preflight_check.md).

---

## 4. How to Deploy

The **Installation and Configuration Guide** is the primary deployment reference. It covers the full universal-installer flow on Docker Compose, Kubernetes via Helm, and Podman. Podman is supported as a first-class runtime since v0.8.4 — the installer auto-detects the runtime, picks the correct compose command (`docker compose`, `docker-compose`, or `podman compose`), and auto-applies the Podman Compose override file when Podman is active. The guide walks through TLS bootstrap (ACME / CA-signed / self-signed), KMS provisioning, optional service profiles (`--with-openwebui`, `--wazuh`, `--with-internal-ca`, `--agent-bundles`), and admin credential bootstrap. For a more detailed explanation, see the [Installation and Configuration Guide](docs/yashigani_install_config.md).

The **Kubernetes Deployment Guide** is the dedicated reference for production K8s deployments using the Helm chart. It covers KEDA-based horizontal autoscaling, multi-replica HA, Kubernetes network policies (the `allow-backoffice-ingress` and `allow-gateway-ingress` policies that admit only `yashigani-caddy` pods), pod disruption budgets, and the StatefulSet vs Deployment trade-offs across services (gateway, backoffice, postgres, redis, budget-redis, vault, observability stack, pool-manager DaemonSet). For a more detailed explanation, see the [Kubernetes Deployment Guide](docs/kubernetes_deployment.md).

For deployment topology diagrams and the full per-runtime breakdown, see [Architecture.md §6 Deployment Topologies](Architecture.md#6-deployment-topologies).

---

## 5. Verifying a Release

All Yashigani releases from v2.23.1 onward are cryptographically signed. Two signatures are provided for each release:

**Git tag signature (GPG)** — verifies the source commit is authentic and unchanged:

```sh
# Import the Agnostic Security release signing public key (once):
gpg --import docs/release-signing-key.asc

# Fetch tags (in case a tag was updated):
git fetch --tags --force origin

# Verify:
git tag -v v2.23.2
# Expected: "Good signature from 'Agnostic Security Releases <releases@agnosticsec.com>'"
```

**Container image signature (cosign / Sigstore)** — verifies the published container images match the release tag:

```sh
cosign verify \
  --certificate-identity-regexp='https://github.com/agnosticsec-com/.*' \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \
  ghcr.io/agnosticsec-com/yashigani-gateway:2.23.2
```

For the full release verification process and SBOM attestation commands, see [`docs/release-process.md §10`](docs/release-process.md).

---

## 6. Compliance and Security Posture

Yashigani publishes per-control compliance evidence under `docs/compliance/`. The compliance suite covers OWASP ASVS v5 Level 3 (all chapters), OWASP API Security, OWASP Agentic AI / LLM Top 10, plus framework-specific reports. Per-control verdicts are PASS / PARTIAL / FAIL / N/A with file:line evidence; open exceptions are tracked in the risk register (5×5 matrix with quantitative analysis). Pre-release gate: all PARTIAL/FAIL items must have an accepted-exception entry before any tag is created.

For a more detailed explanation, see the [Compliance Reports](docs/compliance/README.md).

---

## 7. Current Release Highlights

The v2.23 line currently ships three releases. v2.23.0 is the single-branch / API-first / strict-CSP foundation; v2.23.1 adds core-plane mTLS and the two-tier PKI; v2.23.2 delivers the security hardening batch, supply-chain controls, and N-1 upgrade validation. For the full per-version history (v0.1.0 → v2.22.x), see [Architecture.md §4 Security Features by Version](Architecture.md#4-security-features-by-version).

### v2.23.2 — Security Hardening, Supply-Chain Controls, and ASVS L3 92%

v2.23.2 is a security and quality hardening release on top of v2.23.1. It closes the remaining deferred findings from the v2.23.1 release cycle, strengthens the supply chain, hardens container and network posture, and introduces continuous install-and-upgrade validation. ASVS v5 L3 coverage reaches 92% (166/180) with zero release-blocking failures.

**XFF Spoofing Closed** -- The gateway no longer trusts `X-Forwarded-For` headers set by callers. Caddy is the sole edge: it strips any incoming XFF and sets a clean one before forwarding. Rate limiting and audit logging now bind to the address Caddy observed, not one the client claimed.

**Rate Limiter Fail-Closed Default** -- The rate limiter now defaults to `RATE_LIMITER_FAIL_MODE=closed`. When Redis is temporarily unreachable the request is rejected with `HTTP 503` and a `Retry-After` header rather than silently allowed through. Operators who need fail-open behaviour for specific environments can opt in explicitly. A human-readable recovery message is included in the 503 body.

**Login Throttle `Retry-After` Header** -- Locked-out callers now receive an RFC 6585-compliant `Retry-After` header on the login response, so automated tooling and administrators know exactly when to retry without polling.

**OPA and Jaeger mTLS** -- The OPA policy engine and Jaeger tracing collector are now gated with mutual TLS on both Docker Compose and Kubernetes Helm deployments. Service identities are verified by the in-tree PKI; plaintext access to these components from the data plane is no longer possible.

**Kyverno Admission Policies** -- Kubernetes deployments now ship Kyverno admission policies that enforce the container hardening posture at the cluster level: non-root UID, read-only root filesystem, dropped capabilities, and no privilege escalation. Policy violations block pod scheduling before containers start.

**Container Hardening: Uniform Non-Root UIDs** -- All services now run as non-root. The Ollama inference service, previously running as root for convenience, has been migrated to UID 1000. Combined with the Kyverno admission policies, this closes the root-in-container gap across the full stack.

**Caddy Reverse Proxy Coverage: All 73 Blocks** -- The Caddy verified-secret header (`X-Caddy-Verified-Secret`) is now injected on all 73 `reverse_proxy` blocks across all Caddyfile variants (selfsigned, ACME, CA, WAF) and the Kubernetes ConfigMap. A contract test asserts this on every CI run; a missing injection causes a test failure with a precise diff identifying the missing block.

**GPG Release Tag Signing** -- All releases from v2.23.1 onward are GPG-signed. The signing infrastructure (CI workflow, key ceremony procedure, public key in-repo) is complete and documented in `docs/release-process.md §9`. Verification: `git tag -v v2.23.2`.

**Supply-Chain Hardening** -- GitHub Actions workflow steps are pinned to SHA digest (not just tag). The `pip` package manager is removed from runtime images to reduce the CVE surface. A CI job annotates every Trivy scan with the exact image digest that was scanned. SBOM generation includes a service-identity SHA gate.

**Contract Tests as Anti-Rot** -- A new contract-test suite (`tests/contracts/`) asserts structural invariants across the Caddyfile family and Helm templates on every CI run. The cascade of Caddyfile drift that required multiple rounds of fixes in v2.23.1 is now caught before merge.

**Install + Upgrade Smoke Matrix** -- A CI matrix validates fresh installs and N-1 upgrades (v2.23.1 → v2.23.2) across four platform combinations: macOS Podman, macOS Docker, Linux Podman, and Linux Docker. The harness performs a real install, backs up, upgrades, restores, and verifies both admin accounts are reachable before marking the run green.

**Open-Redirect Hardening** -- The backslash-bypass variant of the `next=` open-redirect in the admin login flow is now blocked. A regression test suite covers the known bypass patterns.

**Safe Error Envelopes** -- All error responses from backoffice and gateway routes now go through a `safe_error_envelope` helper that strips exception class names and stack details from customer-visible responses, preventing information disclosure via error bodies.

**`/tmp` Elimination** -- All use of the host `/tmp` path in `install.sh`, `restore.sh`, and CI scripts has been removed. Temporary files are written to the working directory or to `RUNNER_TEMP` in CI, making the installer safe to use on macOS with strict filesystem sandboxing.

**OWASP ASVS v5 L3: 92% (166/180)** -- Zero release-blocking failures. All six failures carried over from v2.23.1 remain closed in v2.23.2. Per-chapter pass rates: V1 Encoding 89%, V2 Authentication 96%, V3 Session 100%, V4 Access Control 100%, V5 File Handling 63% (3 N/A due to gateway architecture), V6 Cryptography 100%, V7 Logging 100%, V8 Data Protection 89%, V9 Communications 100%, V10 Malicious Code 88%, V11 Business Logic 100%, V12 API 100%, V13 Config 100%, V14 Software Lifecycle 78% (2 manual items), V15 Architecture 100%, V16 Security Logging 100%, V17 WebRTC 0% (3 N/A by architecture).

### v2.23.1 — Core-Plane mTLS, Two-Tier PKI, and Release Hardening

v2.23.1 is a security-hardening release on top of v2.23.0. It makes mutual TLS mandatory for all core-plane services, introduces a two-tier internal PKI, enables mandatory container isolation (seccomp + AppArmor) on every install, and lands the full pre-release security and QA review findings. Every clean-slate gate (macOS Podman, macOS Docker, Linux Podman, Linux Docker, K8s Helm) has been re-tested on this release.

**Core-Plane mTLS (Default-On)** -- Gateway, backoffice, Postgres, PgBouncer, Redis, and OPA all terminate mutual TLS using per-service leaf certificates issued at install time by the in-tree PKI issuer (`src/yashigani/pki/issuer.py`). Clients present certificates; servers verify against the trusted CA. Plaintext traffic on the core plane is no longer possible, even for local debugging. mTLS is enabled regardless of the `--with-internal-ca` flag.

**Two-Tier Internal PKI** -- `yashigani.pki.issuer` generates a root CA, an intermediate CA, and short-lived per-service leaf certificates. Service identities use SPIFFE-style URIs. Rotation runs via `install.sh rotate-leaves|rotate-intermediate|rotate-root` or the `/admin/settings/internal-pki` API; the root key is stored 0400 on disk and never touches a workload image. The optional Smallstep step-ca compose service (`--with-internal-ca`) is a separate runtime ACME-issuance facility for deployments that prefer dynamic ACME-style cert lifecycle on top of (or instead of) the in-tree issuer.

**Container Isolation Default-On** -- seccomp profiles and AppArmor profiles (on Linux) are loaded for every service in every runtime. No "skip on dev" branch. On macOS / Windows runtimes without AppArmor, the equivalent runtime-specific confinement applies. A shared-library `mmap` permission was added to the AppArmor profile after a regression surfaced during gate #57.

**Fail-Closed on Missing Secrets** -- Missing HMAC or Open WebUI secrets now hard-fail at startup instead of silently falling through to a dev-mode default. Applies to all deploy targets.

**Centralised SSRF Allowlist** -- All outbound HTTP from backend services goes through a single helper that enforces an allowlist per destination category. Ad-hoc `requests.get` / `httpx.get` calls against variable URLs were removed.

**Per-Endpoint Body-Size Limits** -- Every endpoint declares its own body-size limit. The global Caddy cap remains as a floor; per-endpoint caps are tighter where appropriate (ASVS 4.3.1).

**Log-Injection Sanitisation** -- All user-controllable strings feeding audit logs and application logs are sanitised (CR/LF stripped, length-capped, unicode-normalised) before formatting. ASVS 16.6.1.

**Session Rotation on Password Change** -- Changing a password rotates the session token and invalidates all prior sessions for that principal (ASVS V7.4.2).

**Uniformised 401 vs 404** -- Unauth admin endpoints no longer leak the existence of protected routes via differential status codes.

**Explicit CSP `script-src`** -- CSP no longer falls back to `default-src`; `script-src` is explicit, and `/admin/csp-report` is wired to capture violations in the audit log.

**Algorithm Allowlist on License Verifier** -- The license ECDSA verifier now enforces an explicit algorithm allowlist (ES256), preventing algorithm-substitution downgrades.

**Caddy Header Hygiene** -- Server header stripped; stale `alt-svc` removed; no version leakage to Shodan-style fingerprinting.

**PCI Password Expiry Profile** -- Optional expiry profile of ≤90 days for deployments with PCI-DSS scope. Default remains admin-configurable per `YASHIGANI_PASSWORD_MAX_AGE_DAYS`.

**TOTP Enrolment Split** -- TOTP enrolment now follows a two-step provision/confirm flow. The secret is never active without a confirmation code round-trip.

**Auth-Throttle Admin Self-Visibility** -- Authenticated admins can see their own and other IPs' throttle and permanent-block state at `/admin → Security → Blocked IPs` (backed by `/auth/blocked-ips`, returns the caller's `self` block plus all currently throttled and permanently blocked IPs). The locked-out *unauthenticated* operator case (RFC 6585 `Retry-After` on the login response) is tracked as a v2.23.2 follow-up.

**Agent Tier-Limit Returns 402** -- Exceeding an agent tier limit now returns `402 Payment Required` (was `500`), with the correct error body.

**AGENT_REGISTERED Audit Persistence** -- Agent-registration events now persist to the audit log. Previously they fired only to the in-memory channel.

**`/.well-known/security.txt`** -- Published per RFC 9116, pointing at the coordinated-disclosure contact.

**Symbol-Bearing Generated Passwords** -- All installer-generated credentials (admin, Postgres, Redis, Grafana, Wazuh) now include at least one uppercase, lowercase, digit, and symbol from the safe set `! * , - . _ ~` (URL / `.env` / sed / shell safe; does not require percent-encoding in Postgres DSN userinfo).

**Runtime-Routing Fixes** -- `install.sh` correctly honours `YSG_RUNTIME=docker` on hosts where Podman is also installed. Stale `YSG_PODMAN_RUNTIME` env-var bleed from prior sessions is neutralised at every call. Backup helpers read the resolved runtime, not `command -v` heuristics.

**Installer Platform Coverage** -- Clean-slate installs are validated on macOS Podman, macOS Docker, Linux Podman (Ubuntu 24.04 aarch64), Linux Docker (Ubuntu 24.04 aarch64), and K8s Helm (Docker Desktop). All five platforms bring 15 containers to Healthy with mTLS active.

**Day 9-12 hardening additions (tip 8ed29e6):**

- **EX-231-10 Layer B re-implementation** (cf4e647, 00843b2) -- Caddy HMAC shared-secret middleware re-implemented as a single-author Caddy snippet (`inject-caddy-verified`) that sets `X-Caddy-Verified-Secret` on the forwarded request. The earlier Python-side verifier approach was reverted (35b51cb); the Caddy-native approach is simpler and does not require a Python middleware round-trip. A header-deletion bug (header_up `-X-Caddy-Verified-Secret` appearing before the set) was fixed in R4 (00843b2, 54e607a) to ensure the header reaches the upstream correctly.
- **cryptography 46.x pin** (39e0879, de66f6f) -- `cryptography<47` pinned across all images after `cryptography==47.0.0` raised SIGILL on Podman VM aarch64 (illegal instruction on some ARM cores). Images rebuilt at 39e0879; Helm values updated with new digests.
- **K8s Helm: gateway→postgres and backoffice→postgres NetworkPolicy** (b85aad1, 7023360) -- Two `NetworkPolicy` rules added to allow gateway and backoffice pods to reach the Postgres pod on port 5432. Previously absent, causing K8s gate failures during Alembic migration runs.
- **K8s Helm: ca_bundle.crt chain-verify anchor** (1a6db9f, 7023360) -- `ca_bundle.crt` (intermediate + root) mounted into gateway and backoffice pods via ConfigMap for Python `ssl` chain verification. Required because Python's `ssl` module is libssl-direct and rejects partial-chain without the root in the trust store.
- **K8s Helm: DSN_DIRECT for gateway** (1a6db9f) -- `YASHIGANI_DB_DSN_DIRECT` injected into the gateway pod so Alembic migrations bypass PgBouncer's transaction-pool mode during startup.
- **K8s Helm: secret lookup preserve on upgrade** (6c8f660) -- Helm `lookup` used to preserve existing secrets across `helm upgrade`; prevents `randAlphaNum` regenerating credentials on every upgrade cycle.
- **Caddy TLS 1.3 + GCM-only ciphers** (bc9cd0d, d7f6447) -- All Caddyfile variants (`Caddyfile`, `Caddyfile.ca`, `Caddyfile.waf`) and Helm ConfigMaps enforce `tls_min_version TLS1.3` with explicit GCM cipher suite list. Applies to all listeners including the WAF variant.
- **Caddyfile.ca: client_auth at site-level** (63c5351) -- `client_auth` directive moved from individual `handle` blocks to the site-level TLS block in `Caddyfile.ca`. Fixes a bypass where client cert verification could be skipped by routing to an unhandled block.
- **inject-caddy-verified on admin reverse_proxy blocks** (e0d3869) -- `import inject-caddy-verified` added to all admin `reverse_proxy` blocks in `Caddyfile.ca`, ensuring the verified-secret header is injected on admin paths as well as the main proxy path.
- **macOS Podman: chown warn-not-abort** (d5247b7) -- `_pki_chown_client_keys` in `install.sh` no longer aborts on chown failure under macOS Podman (TCC/permission restriction). A warning is logged and the install continues; the keys are still created with correct ownership where permissions allow.
- **restore.sh: chmod u+w sweep** (f1ecf11) -- `restore.sh` widens all secret files to `u+w` before `cp` to handle cases where the backup contains read-only secrets. Fixes restore failures on Linux Podman when secret files were 0400 in the backup archive.
- **install.sh: macOS Podman remote-client chown fallback** (17d369c) -- Installer detects the Podman remote-client case (macOS host, VM-backed socket) and falls back gracefully when `chown` cannot be applied from the host.
- **CI: v2.23.x branch filter** (8ed29e6) -- GitHub Actions workflow branch filter extended to cover `v2.23.x` release tracks, ensuring CI runs on release branches without manual filter edits.

### v2.23.0 — Single Branch, API-First Admin, Strict CSP, and Compose Profiles

v2.23.0 consolidates Yashigani to a single branch. The `release/1.x` branch is eliminated. Open WebUI is now an optional flag (`--with-openwebui`) rather than a separate release line. All features, all tiers, one branch.

**Branch Consolidation** -- The dual-branch model (v2.x on `main`, v1.x on `release/1.x`) is retired. Open WebUI, Wazuh, Internal CA, and agent bundles are optional compose profiles controlled by installer flags. Operators who do not want Open WebUI simply omit `--with-openwebui`. No separate branch to maintain, no backport overhead, no version confusion.

**API-First Admin UI** -- The admin dashboard was refactored from server-rendered Jinja2 templates with inline JavaScript and CSS to a static single-page application (SPA) with all JavaScript and CSS in external files. No inline code remains. This enables strict Content Security Policy headers and eliminates an entire class of XSS vectors. All admin logic lives in backend APIs; the UI is a thin client calling those APIs.

**Strict Content Security Policy** -- All pages served by Yashigani now enforce `script-src 'self'; style-src 'self'` with zero `unsafe-inline` exceptions. Additional hardening: `object-src none`, `base-uri none`, `cross-origin-opener-policy: same-origin`, and a CSP report endpoint for violation monitoring.

**Optional Services via Compose Profiles** -- Services that not every deployment needs are now gated behind compose profiles: `openwebui`, `wazuh`, `internal-ca`, `langflow`, `letta`, `openclaw`. The installer flags (`--with-openwebui`, `--wazuh`, `--with-internal-ca`, `--agent-bundles`) control which profiles are activated. The base stack is leaner; optional services are added without editing compose files.

**Admin Service Management** -- Administrators can enable or disable any optional service directly from the admin panel. No SSH access required. Service state changes are audited.

**Optional ACME runtime CA (Smallstep step-ca)** -- The Smallstep step-ca service is an opt-in compose profile (`--with-internal-ca`) providing ACME-style runtime cert management for deployments that prefer it. In v2.23.0 it was the only path for service-to-service TLS; in v2.23.1 the in-tree PKI issuer (`yashigani.pki.issuer`) generates the two-tier PKI and per-service leaves at install time, so step-ca is no longer required for default-on mTLS. The root CA stays 0400 on disk and is never baked into an image.

**Domain-Bound Licensing** -- License keys are now bound to the deployment domain using ECDSA P-256 signatures. A license issued for `example.com` will not activate on `other.com`.

**Additional v2.23 changes:**
- Podman socket detection on macOS (Darwin) via `podman machine inspect`
- Container socket mount is read-only
- `restore.sh` backup recovery script for secrets, `.env`, and Postgres dumps
- Admin-configurable password max age (`YASHIGANI_PASSWORD_MAX_AGE_DAYS`, max 13 months)

---

## 8. Feature Matrix by Tier

The table below lists only rows that **differ across tiers**. Rows that are identical across all seven tiers are listed in [§8.1 Common features](#81-common-features). For the complete per-feature breakdown by version, see [Architecture.md §5 Complete Feature List](Architecture.md#5-complete-feature-list).

| Feature | Community | Non-profit & Education | Igniter | Starter | Professional | Professional Plus | Enterprise |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Licensing** | | | | | | | |
| Free, no license key | Yes | — | — | — | — | — | — |
| Signed licence key required | — | Yes (verified) | Yes | Yes | Yes | Yes | Yes |
| Pricing | Free | Free (always) | £1,750/yr | £3,000/yr | £12,000/yr | £80,000/yr | From £200,000/yr |
| Max agents / MCP servers | 20 | Unlimited | 200 | 400 | 2,000 | 16,000 | Unlimited |
| Max end users | 5 | Unlimited | 50 | 100 | 500 | 4,000 | Unlimited |
| Max admin seats | 2 | Unlimited | 5 | 10 | 25 | 100 | Unlimited |
| Max organizations / domains | 1 | Unlimited | 1 | 1 | 1 | 5 | Unlimited |
| Apache 2.0 open-source license | Yes | — | — | — | — | — | — |
| Non-Profit / Education licence (verified) | — | Yes | — | — | — | — | — |
| CLA-covered contributions | Yes | — | — | — | — | — | — |
| **Authentication** | | | | | | | |
| OpenID Connect (OIDC) SSO | No | Yes (free) | Yes | Yes | Yes | Yes | Yes |
| SAML v2 SSO | No | Yes (free) | No | No | Yes | Yes | Yes |
| SCIM automated provisioning | No | Yes (free) | No | No | Yes | Yes | Yes |
| Multi-IdP Identity Broker (since v2.0) | Local only | Unlimited IdPs | 1 OIDC | 1 OIDC | 1 OIDC + 1 SAML | 5 IdPs | Unlimited |
| **Authorization** | | | | | | | |
| Multi-tenant org isolation | No | No | No | No | No | Partial (5 orgs) | Yes |
| **Deployment** | | | | | | | |
| Container Pool Manager (since v2.0) | 1/identity, 3 total | Unlimited | 1/identity, 5 total | 1/identity, 5 total | 3/identity, 15 total | 5/identity, 50 total | Unlimited |

**User-count bundles (paid tiers — ramped overflow premium):**

Paid tiers support optional 50- or 250-user bundles to grow within a tier before upgrading. The premium increases at higher tiers to create a natural upgrade trigger.

| Tier | Bundle size | Bundle price/yr | Users added | Agents added (4:1) | Max bundles | Tier cap at max bundles |
|---|---|---|---|---|---|---|
| Starter | 50 users | £1,627.50 | +50 | +200 | 5 | 350 users / £11,137.50 |
| Professional | 50 users | £1,350 | +50 | +200 | 50 | 3,000 users / £79,500 |
| Professional Plus | 250 users | £6,000 | +250 | +1,000 | 20 | 9,000 users / £200,000 |

Each tier's maximum bundle spend is set just below the next tier's base price — at that point, upgrading delivers more capacity, features, and better value per user. Igniter has no bundles; upgrade to Starter at 51+ users.

### 8.1 Common features

The following features are included in **all seven tiers** at parity. They are deliberately not gated by license tier — they are core to what Yashigani is.

**Authentication and identity**
- Username + password (Argon2 / bcrypt)
- TOTP / 2FA
- WebAuthn / Passkeys (since v0.9.0)
- API key authentication
- Session authentication
- Bearer token (agent routing)
- JWT introspection / JWKS waterfall
- Multiple admin accounts with minimum-count enforcement
- Admin lockout protection
- Unified identity model (since v2.0)

**Authorization and policy**
- OPA policy engine
- RBAC via OPA
- Per-tool / per-route policy
- OPA routing safety net + LLM policy review (since v2.0)

**Content inspection and AI safety**
- FastText ML classifier (offline, <5ms)
- Response-path inspection (since v0.9.0)
- All 5 inspection backends — Ollama, Anthropic Claude, Google Gemini, Azure OpenAI, LM Studio
- Fail-closed sentinel
- Prompt injection detection
- Credential Harvesting Suppression (CHS)
- Payload masking before AI inspection
- Response masking / sanitization
- Anomaly detection (Redis ZSET sliding window)
- Inference payload logging (AES-256-GCM encrypted)
- Sensitivity classification pipeline (since v2.0)
- Optimization Engine — 4D routing (since v2.0)

**Budget governance (since v2.0)**
- Three-tier budget system (org / group / individual)
- Budget-redis dedicated container (noeviction)
- Budget response headers

**Audit and compliance**
- Structured JSON audit log (file)
- PostgreSQL audit storage (RLS + AES-256-GCM)
- SHA-384 Merkle audit hash chain (since v0.9.0)
- Audit log search (7 filters, cursor pagination)
- Audit log export (CSV / JSON, 10k rows)
- Splunk SIEM integration
- Elasticsearch SIEM integration
- Wazuh SIEM integration
- Async SIEM delivery queue (since v0.9.0)
- Monthly partition management (pg_partman)
- P1-P5 alert severity with SIEM integration (since v2.0)
- Routing decisions as audit events (since v2.0)

**Rate limiting**
- Per-endpoint rate limiting (Redis)
- Response caching (CLEAN-only, SHA-256)

**Cryptography and secrets**
- TLS (ACME / CA-signed / self-signed)
- Offline licence verification (ECDSA P-256, v0.9.0)
- Multi-KMS (Docker, AWS, Azure, GCP, Keeper, Vault)
- AES-256-GCM column encryption (Postgres)
- Agent PSK auto-rotation (since v0.9.0)

**Observability**
- Prometheus metrics
- Grafana dashboards (12, including 3 v2.0 additions: budget / OE / pool manager)
- Real-time SSE inspection feed (since v0.9.0)
- OpenTelemetry / Jaeger tracing
- Loki + Promtail log aggregation
- Alertmanager escalation (Slack / email / PagerDuty)

**Deployment**
- Universal installer
- Docker Compose
- Kubernetes Helm charts
- KEDA autoscaling
- Multi-replica / HA deployment
- Container hardening (seccomp, AppArmor, non-root)
- Trivy container scanning
- Agent bundles (Langflow / Letta / OpenClaw)
- Open WebUI integration (since v2.0)

---

## 9. Our commitment to the OSS Community

Agnostic Security will donate 10% of the Yashigani platform sales profits to the open-source projects that we use, as long as they are registered as non-for-profit organizations.
We might also decide to sponsor other Open-Source projects that we use in some way.
