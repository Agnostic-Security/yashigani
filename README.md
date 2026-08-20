<!-- last-updated: 2026-08-19T00:00:00+00:00 -->
# Yashigani
---

<html>
<body>
<div>
  <img src="https://github.com/Agnostic-Security/yashigani_img/blob/main/Yashigani8bit.png" alt="Yashigani" style="width:100%">
</div>
</body>
</html>

---
**Yashigani is the security enforcement gateway for MCP servers and agentic AI systems.**
---
*Yashigani — Security enforcement for agentic AI. Every call inspected. Every policy enforced. Every action audited.*
---


**Latest Tagged Release:** v4.1.2 (2026-08-19) — First public release of Yashigani 4.x platform stack. Native UI, agent orchestration with human-in-the-loop, no-code workflow composer, multi-platform GPU support (NVIDIA/AMD/Apple Silicon/Intel), usage metering & caps, core-plane mTLS default-on with in-tree two-tier PKI, Langflow & Letta bundled behind compose profiles, single-branch deployment model. v4.1.2 adds security hardening: improved model authorization (positive-allowlist validation), RBAC group-membership enforcement, session security, dual-control hardening, Podman 6.x support, optional firewall auto-configuration. Full test matrix GREEN (macOS docker+podman, Linux docker+podman 4.9+5.x); see `CHANGELOG.md` for complete details.

---

---
*Comming Soon - Yashigani v5 Kuroshio*
---
<div>
  <img src="https://github.com/Agnostic-Security/yashigani_img/blob/main/Yashiganic5-Kuroshio.png" alt="Kuroshio" style="width:100%">
</div>

---
**Single branch:** `main` — all features, all tiers. Langflow and Letta are bundled and gated behind compose profiles / install flags. **Core-plane mTLS is default-on**: per-service leaf certificates are issued at install time by the in-tree two-tier PKI (`src/yashigani/pki/issuer.py`) — no optional services required.
---
**Document Date:** 2026-08-19
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

**Yashigani's response:** Every prompt and every response passes through Yashigani's bidirectional inspection pipeline before reaching its destination. Inbound payloads are classified by a two-stage pipeline — a scikit-learn ML classifier (TF-IDF + LogisticRegression, joblib serialised, sub-5ms latency, fully offline) for low-latency first-pass detection, followed by a configurable LLM-based deep inspection backend (Ollama, Anthropic Claude, Google Gemini, Azure OpenAI, or LM Studio). Responses are inspected on the return path with the same rigor. The pipeline is fail-closed: if all inspection backends are unavailable, the request is blocked by a sentinel policy, not passed through. Credential Harvesting Suppression (CHS) detects credential-shaped patterns in both directions. Every transaction produces a structured audit event written simultaneously to multiple sinks — local file, PostgreSQL (with row-level security and AES-256-GCM column encryption), and SIEM platforms (Splunk, Elasticsearch, Wazuh). Nothing passes uninspected. Nothing passes unrecorded.

### 2.2 Identity Sprawl

Enterprise AI deployments accumulate separate identity silos: user stores for the chat interface, agent registries for service accounts, API key tables for integrations, IdP configurations per department. Each silo has its own lifecycle, its own governance gap, and its own audit blind spot. When a security incident occurs, correlating "which entity did what" across disconnected registries is forensic archaeology.

**Yashigani's response:** Yashigani's unified identity model treats every entity — human user, AI agent, service account, API integration — as a first-class identity with a `kind` field. One registry, one governance framework, one audit trail. Humans and agents are subject to the same RBAC policies, the same rate limits, the same budget constraints, and the same audit depth. OPA policy enforcement is identity-aware across all entity types. There is no separate "agent management console" — because there is no separate identity class.

### 2.3 Uncontrolled AI Spend

Cloud LLM costs spiral without visibility or limits. A single team can burn through thousands in a day. A misconfigured agent can loop on expensive models indefinitely. CFOs discover the damage in the monthly invoice. Traditional rate limiting is too coarse — it caps requests, not dollars — and hard rejection breaks user workflows.

**Yashigani's response:** The three-tier budget system enforces spend governance with mathematical guarantees. Organization-level cloud caps set the hard ceiling. Group budgets allocate within that ceiling. Individual budgets constrain each user or agent. When a budget is exhausted at any tier, the system degrades gracefully to local inference via the Optimization Engine — the user's request is still served, just routed to a local model instead of a cloud API. Yashigani never rejects a request due to budget exhaustion. It never stops working. It just stops spending.

### 2.4 Data Leakage to Cloud Providers

Sensitive data — PII, PCI cardholder data, intellectual property, PHI — is sent to cloud LLM APIs without detection or classification. Once transmitted, data may be retained, logged, or used for training. Traditional DLP solutions were not designed for LLM payloads: they do not understand prompt structure, they cannot classify at inference speed, and they cannot enforce routing decisions based on sensitivity.

**Yashigani's response:** The three-layer sensitivity pipeline classifies every prompt before routing. Layer 1: regex pattern matching catches structured sensitive data (credit card numbers, SSNs, API keys). Layer 2: scikit-learn ML classifier (TF-IDF + LogisticRegression, joblib serialised) detects semantic sensitivity at under 5ms, fully offline. Layer 3: Ollama LLM classification provides deep contextual analysis for ambiguous cases. Data classified as CONFIDENTIAL or RESTRICTED is routed to local models only — this is an immutable rule enforced by the Optimization Engine. No override exists. No admin can bypass it. No configuration can disable it.

**Credential and PII Protection:** Two complementary mechanisms prevent data exfiltration:

1. **Credential Harvesting Suppression (CHS)** — Detects and removes credential-shaped patterns (API keys, passwords, SSH keys, tokens, secrets) from prompts and responses before any AI inspection backend or cloud model sees them. Every removal is audited with identity + timestamp + target model context.

2. **PII Detection & Enforcement (v4.1.2+)** — The dedicated PII module detects 10 entity types: SSN, credit card (with Luhn validation), email, phone, IBAN, passport, NHS number, driver's licence, IP address, date of birth. Runs on both request and response paths — bidirectional, on all traffic, by default. Offers five distinct enforcement modes:
   - **LOG mode:** Detect and audit; data passes through unchanged. Compliance teams see what PII was present, when, and from which identity.
   - **REDACT mode:** Replace identified PII with `[REDACTED:TYPE]` before forwarding to cloud models or external systems. Original data is discarded. Irreversible — useful when compliance requires data anonymization.
   - **PSEUDONYMIZE mode (v4.1.2+):** Replace PII with reversible tokens (gateway-bound, identity-bound, cryptographically keyed). The gateway maintains the reversibility mapping and can restore original values when needed for authorized downstream systems. Anti-known-text attack protection ensures dictionary attacks cannot crack pseudonym mappings. Useful for regulated workflows that require both anonymity (external systems see tokens) and audit traceability (internal systems can correlate back to source identity).
   - **ALLOW mode:** Explicitly permit PII in requests destined for authorized cloud models. Requires explicit policy configuration; default is deny. Used when the PII-containing request has compliance clearance.
   - **DENY mode:** Block requests containing PII before reaching cloud models. Fail-closed enforcement. The request is rejected with audit trail recording the PII type detected and blocking reason.

   Cloud-model bypass: when PII is detected in a prompt classified as cloud-destined, the system forces local routing by policy override — this is independent of the Optimization Engine's sensitivity decision. Critical for sectors where known PII cannot touch external APIs regardless of classification. ALLOW mode can override this when explicitly authorized.

   Admin configuration: all five modes are policy-configurable. Default is DENY for maximum protection. Every configuration change is audited.

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

Before any install on a new host, run the pre-flight checklist. It confirms host and runtime readiness — container runtime detection (Docker / Podman / Kubernetes), available disk and RAM, GPU detection (Apple Silicon M-series, NVIDIA, AMD, with `lspci` fallback) with model size recommendations based on VRAM, and inspection-pipeline prerequisites (regex, scikit-learn ML, Ollama). The installer's preflight phase runs the same checks automatically; the standalone document is what an operator reads before kicking the installer off.

For a more detailed explanation, see the [Pre-flight Checklist](docs/preflight_check.md).

---

## 4. How to Deploy

The **Installation and Configuration Guide** is the primary deployment reference. It covers the full universal-installer flow on Docker Compose, Kubernetes via Helm, and Podman. Podman is supported as a first-class runtime since v0.8.4 — the installer auto-detects the runtime, picks the correct compose command (`docker compose`, `docker-compose`, or `podman compose`), and auto-applies the Podman Compose override file when Podman is active. The guide walks through TLS bootstrap (ACME / CA-signed / self-signed), KMS provisioning, optional service profiles (`--with-openwebui`, `--wazuh`, `--with-internal-ca`, `--agent-bundles`), and admin credential bootstrap. For a more detailed explanation, see the [Installation and Configuration Guide](docs/yashigani_install_config.md).

The **Kubernetes Deployment Guide** is the dedicated reference for production K8s deployments using the Helm chart. It covers KEDA-based horizontal autoscaling, multi-replica HA, Kubernetes network policies (the `allow-backoffice-ingress` and `allow-gateway-ingress` policies that admit only `yashigani-caddy` pods), pod disruption budgets, and the StatefulSet vs Deployment trade-offs across services (gateway, backoffice, postgres, redis, budget-redis, vault, observability stack, pool-manager DaemonSet). For a more detailed explanation, see the [Kubernetes Deployment Guide](docs/kubernetes_deployment.md).

For deployment topology diagrams and the full per-runtime breakdown, see [Architecture.md §6 Deployment Topologies](Architecture.md#6-deployment-topologies).

---

## 5. Verifying a Release

All Yashigani releases from v4.1.2 onward are cryptographically signed with SSH keys. Two signatures are provided for each release:

**Git tag signature (SSH)** — verifies the source commit is authentic and unchanged:

```sh
# Fetch tags (in case a tag was updated):
git fetch --tags --force origin

# Verify the v4.1.2 tag signature:
git tag -v v4.1.2
# Expected: "Good signature from 'Maxine <maxine@agnosticsec.com>'" (SSH key)
```

**Container image signature (cosign / Sigstore)** — verifies the published container images match the release tag:

```sh
cosign verify \
  --certificate-identity-regexp='https://github.com/Agnostic-Security/.*' \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \
  ghcr.io/Agnostic-Security/yashigani-gateway:4.1.2
```

For SBOM attestation, every release artifact carries a Sigstore-signed SBOM published as a GitHub Release asset alongside the tag.

---

## 6. Security Architecture & Design Hardening

Yashigani's security posture is built into the design, not bolted on afterward. Every major component is threat-modeled, every attack surface is instrumented, and every policy decision is auditable. This section outlines our architectural security commitments.

### 6.1 OWASP ASVS v5 Level 3 Alignment

Yashigani aligns with OWASP Application Security Verification Standard (ASVS) v5 Level 3 across all 17 verification chapters:

- **V1 Architecture, Design & Threat Modeling** — Every component has a threat model documented; all data flows charted; attack surfaces identified and controlled
- **V2 Authentication** — Multi-factor authentication mandatory (TOTP), password history tracked, constant-time comparisons on all auth paths, step-up gates on sensitive operations
- **V3 Session Management** — Session rotation on password change, token invalidation on logout, secure cookie flags, CSRF tokens on all state-changing operations
- **V4 Access Control** — Fine-grained RBAC enforced at every hop via OPA, unified identity model (humans + agents + services), positive-allowlist authorization (deny-by-default)
- **V5 Input Validation** — All inputs validated at API boundaries; Pydantic schemas enforce strict types; per-endpoint body-size limits; log-injection sanitization
- **V6 Cryptography** — AES-256-GCM for data at rest, TLS 1.3 mandatory for data in transit, ECDSA P-256 (SHA-384) for audit chain tamper-evidence, fail-closed on crypto failures
- **V7 User Authentication & Password Management** — Password policies PCI-compliant (≤90 day expiry), symbol-bearing generated credentials, HIBP k-anonymity breach check
- **V8 Data Protection** — Column-level encryption for sensitive fields, reversible pseudonymization with anti-known-text protection, secure deletion (cryptoshred), bidirectional inspection on all data flows
- **V9 Communications** — mTLS default-on for core plane, Caddy edge security (XFF spoofing closed, verified-secret injection on all 73 reverse proxies, CSP explicit script-src)
- **V10 Malicious Code** — SBOM attestation (CycloneDX + CryptoBoM), keyless image signing (Sigstore cosign), GitHub Actions SHA-pinned, supply-chain scanning
- **V11 Business Logic** — Budget enforcement with graceful degradation (never reject on budget exhaustion), sensitivity-aware routing with immutable P1 rules
- **V12 File & Resource Access** — Read-only root filesystem for all containers, seccomp profiles, AppArmor enforcement, no mounted host sockets in backoffice
- **V13 API & Web Services** — Per-endpoint authentication/authorization, rate limiting fail-closed (Retry-After on 503), safe-error-envelopes (no stack traces), CORS locked to same-origin
- **V14 Configuration** — Secrets rotatable without restart, environment-variable validation, configuration drift detection, pre-release gate enforces clean install
- **V15 File Upload** — Document policy verification on ingestion (via OPA), file-type validation, size limits, antivirus scan optional via SIEM integration
- **V16 General Cryptographic Security** — Algorithm allowlist (ES256 for ECDSA, no downgrades), constant-time comparisons (TOTP, HMAC), entropy-sourced credential generation
- **V17 Error Handling & Logging** — Structured audit logs to multiple sinks (file, Postgres, SIEM), log encryption at rest, tamper-proof SHA-384 Merkle chaining, fail-closed on logging failure

### 6.2 Post-Quantum Cryptography (PQC) Roadmap

Yashigani is preparing for the post-quantum era. Current status and roadmap:

- **ML-KEM (Kyber) Key Exchange — LIVE (v4.1.2):** End-to-end encryption between agent contexts uses ML-KEM hybrid construction (combining classical ECDH with ML-KEM to defend against both quantum and classical attacks). All agent-to-agent encrypted channels use this hybrid.
- **ML-DSA (Dilithium) Signatures — ROADMAP (v5.0):** Mesh identity certificates will transition from ECDSA P-256 to ML-DSA for service-to-service mutual TLS. Planned for Yashigani v5.0 / KUROSHIO release (Q4 2026).
- **Hybrid Transition Strategy:** New deployments will issue dual certificates (classical + PQC) to future-proof against quantum key recording attacks. Existing installations can rotate certificates without changing policy logic.

This aligns with NIST SP 800-252 Post-Quantum Cryptography Migration roadmap. We monitor NIST standardization progress and will adopt finalized standards.

### 6.3 Industry Best Practices

**Defense-in-Depth:** Yashigani employs defense-in-depth across every layer:
- Network: Container isolation, network policies, egress mediation
- Application: Input validation, output encoding, OPA policy enforcement
- Data: Column-level encryption, reversible pseudonymization, secure deletion
- Audit: Multi-sink logging, Merkle chaining, fail-closed on log failure
- Identity: Unified model, RBAC + MFA, step-up gates on sensitive operations

**Principle of Least Privilege:** Every identity (human, agent, service) gets exactly the permissions it needs, no more. OPA enforces this uniformly across all entities. Denied access is the default.

**Fail-Closed Security:** When any inspection backend is unavailable (OPA, classifier, SIEM), the system blocks requests rather than allowing them through. Rate limiter unavailable → reject with 503. Crypto key unavailable → fail to start. Policy engine down → all requests denied until it recovers.

**Immutable Security Rules:** Highest-sensitivity data (classified as CONFIDENTIAL/RESTRICTED) is routed to local inference only. This rule cannot be overridden by admins, disabled by configuration, or bypassed by policy. It is an architectural invariant.

**Audit Trail Integrity:** Every security decision produces an audit event. Events are signed with SHA-384 Merkle chaining, making post-hoc tampering detectable. Events are written to multiple sinks simultaneously (local file + Postgres + SIEM) so loss of one sink does not erase the evidence.

**Zero-Trust on Agent Self-Reports:** Agent behavior is verified by the gateway, never trusted at face value. Every LLM response is re-inspected for PII/credentials before returning to the user. Agents cannot bypass inspection even if they are compromised.

### 6.4 OWASP API Security Top 10 Compliance

Yashigani is built as an API-first system. All operations available through the REST API (`/v1/*`) are also available through the Web UI (`/user/*`), and both are subject to identical policy enforcement. OWASP API Security Top 10 mitigations are architectural, not optional:

- **API1:2023 — Broken Object Level Authorization (BOLA):** ✅ **IMPLEMENTED** — OPA enforces per-identity authorization on all object access. Identity-bound audit trails prove who accessed what and when. Pentest verified: BOLA GREEN (v4.1.2).
- **API2:2023 — Broken Authentication:** ✅ **IMPLEMENTED** — Multi-factor authentication mandatory (TOTP v4.1.2+), password history tracked (CMMC L2 IA.L2-3.5.8), constant-time comparisons, step-up gates on sensitive operations (password change v4.1.2+, cloud override v4.1.2+, group mutations v3.1.2+).
- **API3:2023 — Broken Object Property Level Authorization (BOPLA):** ✅ **IMPLEMENTED** — Explicit deny-by-default Pydantic schemas (`model_config extra='forbid'`) on all list endpoints (v2.23.3+). Sensitive fields never serialized (password_hash, totp_secret, client_secret, private_key, PII claims).
- **API4:2023 — Unrestricted Resource Consumption:** ✅ **IMPLEMENTED** — Per-endpoint rate limiting fail-closed (Retry-After on 503 v2.23.2+), per-user RPS caps (100 RPS v2.24.1+), budget governance with graceful degradation (v2.0+), body-size limits per endpoint (v2.23.1+).
- **API5:2023 — Broken Function Level Authorization:** ✅ **IMPLEMENTED** — Every API operation requires OPA authorization at ingress (v2.0+). Endpoints do not leak existence via 401 vs 404 differentiation (v2.23.1+). Admin-only operations uniformly gated.
- **API6:2023 — Unrestricted Access to Sensitive Business Flows:** ✅ **IMPLEMENTED** — Cloud LLM routing decisions policy-enforced (Optimization Engine gated by OPA v2.0+). Budget exhaustion triggers local routing (v2.0+), never rejection. PII-containing requests blocked from cloud models (v2.20+ / v4.1.2+ enhanced).
- **API7:2023 — Server-Side Request Forgery (SSRF):** ✅ **IMPLEMENTED** — DNS-rebinding defense via pinned-resolver (v2.23.3+): hostname resolved once at entry, verified against SSRF allowlist, socket.getaddrinfo patched for transport. Centralised outbound HTTP allowlist per destination category. Audit event `SSRF_PINNED_RESOLVER_USED`.
- **API8:2023 — Security Misconfiguration:** ✅ **IMPLEMENTED** — Fail-closed on missing secrets (v2.23.1+, no silent dev-mode fallback), pre-flight gate enforces clean install, configuration drift detection, TLS 1.3 mandatory (v2.23.1+).
- **API9:2023 — Improper Inventory Management:** ✅ **IMPLEMENTED** — SBOM attestation on all release artifacts (CycloneDX + CryptoBoM v2.23.2+), keyless image signing via Sigstore cosign (v2.23.2+), GitHub Actions SHA-pinned (v2.23.2+), Trivy supply-chain scanning on every CI run.
- **API10:2023 — Unsafe Consumption of APIs:** ✅ **IMPLEMENTED** — All upstream API calls routed through Yashigani gateway inspection. External LLM calls inspected for PII/credentials before transmission (v2.20+). Responses re-inspected before returning to caller (v2.20+).

### 6.5 OWASP Agentic AI / LLM Top 10 Mitigation

Yashigani is purpose-built to address the unique risks of agentic AI systems. Every major threat from OWASP Agentic AI / LLM Top 10 is mitigated by architecture:

- **AI1 — Prompt Injection & Worms:** ✅ **IMPLEMENTED** — Three-layer defense against prompt injection, jailbreaks, and prompt-injection worms:
  - *Layer 1: Regex Detection (v2.0+)* — Patterns detect suspicious markers: `{INJECT}`, `SYSTEM:`, `IGNORE INSTRUCTIONS`, embedded base64/hex payloads, prompt-delimiter escapes.
  - *Layer 2: ML-Based Semantic Detection (v2.23.3+)* — scikit-learn TF-IDF + LogisticRegression classifier trained on prompt-injection patterns. Runs offline, sub-5ms latency. Detects injection attempts without waiting for external APIs. Catches encoded attacks, multi-hop injections, and worm-propagation markers.
  - *Layer 3: LLM-Based Deep Inspection (v5.0 roadmap)* — KUROSHIO provides contextual verification: is this a legitimate user request or an injected command? Semantic analysis catches sophisticated attacks that evade pattern matching.
  - *Multi-LLM Adjudication (v2.0+)* — When sensitivity classification indicates potential injection, multiple LLMs independently evaluate the request. Majority vote required to allow (fail-closed). Prevents any single LLM from being tricked.
  - *OPA Routing Safety Net (fail-closed v2.0+)* — If all inspection backends are unavailable or disagree, the request is blocked. No silent passthrough.
  - *Worm Propagation Defense* — Response inspection (v2.20+) blocks injected commands from being echoed back to other agents. Prompt-injection worms cannot chain between agent calls: each response is re-inspected before forwarding.
  - *Bidirectional Enforcement (v2.20+)* — Both request and response paths inspected. Attacks arriving in upstream LLM responses are caught before they reach the user or propagate to other agents.
- **AI2 — Insecure Output Handling:** ✅ **IMPLEMENTED** — Every LLM response inspected for PII (v2.20+), credentials (v4.1.2+), and policy violations (v2.0+) before returning to user. Sensitive data redacted or pseudonymized based on policy (v4.1.2+). Response inspection pipeline fail-closed (v2.20+).
- **AI3 — Training Data Poisoning:** ✅ **IMPLEMENTED** — Yashigani operates as a ring-fence, not a data aggregator (v2.0+). No base-model training on user data (architectural guarantee). Per-tenant data isolation (container-per-identity v2.0+) with cryptographic separation ensures no cross-contamination (v4.1.2+).
- **AI4 — Model Denial of Service:** ✅ **IMPLEMENTED** — Budget enforcement with hard caps at org/group/individual tiers (v2.0+). Graceful degradation to local inference when budget exhausted (v2.0+), never rejection. Rate limiting fail-closed (v2.23.2+). Per-user 100 RPS cap (v2.24.1+).
- **AI5 — Supply Chain Vulnerabilities:** ✅ **IMPLEMENTED** — All dependencies pinned. Runtime dependencies removed from container images (no `pip` v2.23.2+). Trivy scanning on all images. SBOM attestation with signed artifacts (v2.23.2+). CVE tracking and coordinated disclosure process.
- **AI6 — Sensitive Information Disclosure:** ✅ **IMPLEMENTED** — Reversible pseudonymization with anti-known-text protection (v4.1.2+). Irreversible redaction option for anonymization (v4.1.2+). Column-level encryption for sensitive fields (v2.23.4+). Audit logs encrypted at rest (v2.23.3+ with age encryption).
- **AI7 — Insecure Agent Handoff:** ✅ **IMPLEMENTED** — Every agent runs in isolated container with its own identity (v2.0+ Pool Manager). Uniform security sidecar applied to all agents (v4.0+). Agent-to-agent communication audited at ingress and egress (v3.0+, every-hop OPA). No shared filesystems or context bleed (architectural guarantee v2.0+).
- **AI8 — Excessive Agency:** ✅ **IMPLEMENTED** — OPA policies define what tools each agent can reach (v2.0+). Positive-allowlist enforcement (deny-by-default v2.23.1+). Every tool call inspected for policy compliance (v2.0+). Agents cannot exceed their declared capabilities (v3.0+ capability envelope).
- **AI9 — Misinformation & Hallucinations:** ⚠️ **NOT IN SCOPE** — Yashigani does not attempt to solve hallucinations (this is an LLM-training problem, not an application gateway). But we enforce: (1) responses inspected for credential-shaped patterns before returning (v4.1.2+), (2) PII removed (v2.20+), (3) policy violations blocked (v2.0+), (4) audit trail proves exactly what the LLM was asked and what it returned (v2.0+).
- **AI10 — Unbounded Consumption of External APIs:** ✅ **IMPLEMENTED** — MCP tool calls rate-limited per identity (v2.0+ with per-identity pool). Budget enforcement prevents runaway tool-call spending (v2.0+). Optimization Engine routes to local inference when budget exhausted (v2.0+). Every tool call audited with full reasoning chain (v2.0+).

### 6.6 Recent Attack Vectors (Beyond OWASP)

Emerging threats on LLM systems not yet formalized in OWASP frameworks:

- **Token Overflow / "Token Vomit" Attacks:** ✅ **DEFENDED** — Attackers craft inputs that trigger excessive token generation, causing context exhaustion or resource denial. Yashigani defends: (1) Per-endpoint body-size limits (v2.23.1+) cap input size, (2) Per-user RPS caps (v2.24.1+) prevent rapid-fire requests, (3) Budget enforcement triggers local routing when output costs spike (v2.0+), (4) Response length inspection (v2.20+) blocks abnormally large model outputs before returning to user.

- **Social Engineering via Interview/Scenario Injection:** ✅ **DEFENDED** — Attackers pose as legitimate users in multi-turn conversations, gradually establishing trust, then request sensitive actions (e.g., "as your IT manager, please run this command"). Yashigani defends: (1) Every inter-entity hop audited (v2.0+), with full context preserved, (2) OPA policies enforce that sensitive operations require fresh TOTP step-up regardless of conversation context (v4.1.2+), (3) Audit trail is immutable, proving the exact conversation flow (v2.0+), (4) Agent responses re-inspected for policy violations before returning (v2.20+) — even if an agent is socially engineered, its response is gated by policy.

- **Supply Chain Attacks via Compromised Agent Frameworks:** ✅ **DEFENDED** — Malicious packages in Langflow, Letta, or other bundled frameworks attempt to exfiltrate data or modify agent behavior. Yashigani defends: (1) All dependencies pinned (no transitive version drift), (2) Agent code runs in isolated containers with enforced read-only filesystems (v2.23.1+), (3) Container capabilities dropped (no CAP_NET_ADMIN, no CAP_SYS_ADMIN, no CAP_CHOWN v2.23.1+), (4) Agent network access restricted to explicitly allowed MCP servers (v3.0+), (5) Container-per-identity isolation prevents cross-agent lateral movement (v2.0+).

- **Context Bleed / Cross-Agent Data Leakage:** ✅ **DEFENDED** — Agents in the same cluster leak conversation context or user data to each other via timing side-channels, shared cache, or shared memory. Yashigani defends: (1) Container-per-identity isolation ensures no shared memory or filesystems (v2.0+), (2) Each agent has its own isolated Redis connection (not shared v2.0+), (3) No shared environment variables or secrets between agents (v2.0+), (4) Audit trail proves isolation (v2.0+) — every agent's requests/responses are independently logged with identity binding.

- **Model Confusion / Version Mismatch Exploits:** ✅ **DEFENDED** — Attacker trains a lookalike model or causes version confusion (e.g., inducing fallback to an older/weaker model), exploiting differences in model behavior. Yashigani defends: (1) Model alias resolution enforces canonical target before RBAC gates (v4.1.2+), (2) Model authorization uses positive-allowlist validation (no silent fallback v4.1.2+), (3) Optimization Engine routing decisions are audited with model-selection rationale (v2.0+), (4) Every model call logs exact model version and response characteristics (v2.0+).

- **Speculative Decoding / Early Exit Exploitation:** ✅ **DEFENDED** — Attackers exploit models using speculative decoding or early-exit mechanisms to trigger unintended behavior or bypass inspection. Yashigani defends: (1) Response inspection is applied to all model outputs regardless of generation mechanism (v2.20+), (2) Sensitivity classification of outputs (v2.0+) is independent of how the model generated tokens, (3) Audit logging captures model behavior markers (v2.0+) allowing post-hoc detection of unusual patterns.

---

---

## 7. Current Release Highlights

v4.1.2 is the current release (2026-08-19). Yashigani 4.x introduces a complete rearchitecture around a first-class native platform experience: native UI, agent orchestration with human-in-the-loop, no-code workflow composer, multi-platform GPU support, and usage metering with caps. For the complete per-version feature history, see `CHANGELOG.md`.

### Yashigani 4.x — First-Party Platform Stack (4.0, 4.1, 4.1.1, 4.1.2)

Yashigani 4.0 introduced a complete rearchitecture around a first-class native platform experience we build and own — not dependent on third-party UIs. Every agent runs in a uniform security sidecar with its own identity. Every action is policy-governed at ingress and egress. Compliance evidence is produced by enforcement, not assembled before audits.

**4.x Platform Features:**
- **Native UI & control plane** — First-class Yashigani experience: chat with agents and models, no-code visual agent builder (Langflow), stateful agent runtime (Letta), workflow composer with document policy verification
- **Uniform agent security sidecar** — Every agent wrapped with its own identity, governed both directions: ingress (what reaches it) and egress (what it can reach)
- **Agent orchestration with human-in-the-loop** — Agents, LLMs, APIs, MCPs all mediated through the gateway; every inter-entity hop adjudicated at ingress and egress
- **Multi-platform GPU support** — NVIDIA, AMD, Apple Silicon (Metal), Intel across Linux and macOS
- **Usage metering & caps** — Monitor usage per agent or enforce hard limits
- **Cloud-safe inference** — Self-hosted inference backend (ollama/LM Studio) with optional firewall auto-configuration and egress mediation through the gateway

**4.x Release Lineage:**
- **v4.0** — Initial release of the unified platform stack with native UI, agent orchestration framework, and human-in-the-loop control
- **v4.1** — Security hardening cycle; model authorization improvements; RBAC enforcement fixes; session security enhancements
- **v4.1.1** — Interim patch building toward v4.1.2; prepared for council review and validation
- **v4.1.2** (current) — **First public 4.x release**; production-ready platform with full security validation, multi-platform support (macOS docker/podman, Linux docker/podman 4.9/5.x), adversarial security testing (90+ vectors), and clean pentest (36 pass, BOLA GREEN, 0 Critical/High)

### v4.1.2 — Security Hardening & Platform Maturity

v4.1.2 is the first public release of the Yashigani 4.x platform stack. This release consolidates security hardening and platform maturity improvements detected during 4.1.1 validation, council review, and adversarial security testing.

**Security Fixes:**
- **Model authorization hardening** — Positive-allowlist validation rejects invalid model identifiers at parse time (no silent fallback to local defaults)
- **RBAC group-membership enforcement** — Fixed seam in chat API where group-tier access grants were not properly enforced
- **Model alias resolution** — Cloud-model aliases resolve to canonical target before RBAC gates, preventing alias-based bypass attempts
- **Session security improvements** — Complete logout with proper token invalidation across all active session types and correct session-cookie clearance
- **Dual-control hardening** — Cloud-override approval now binds to confirming fingerprint with durable audit log persistence

**Platform Improvements:**
- **Podman 6.x support** — Compose tool selection adapts to Podman version (6.x uses native `podman compose` v2; older versions use `podman-compose`)
- **Firewall auto-configuration** — Optional `--secure-backend-firewall` flag auto-detects and applies per-OS firewall rules for inference-backend security (macOS `pf`, Linux `ufw`/`firewalld`/etc.)
- **Operator documentation** — New guide `docs/security/securing-inference-backend.md` covers securing self-hosted inference backends (firewall rules, loopback binding, egress mediation)

**Validation & Testing:**
- **Full test matrix GREEN** — macOS (Docker, Podman 6.0.0), Linux (Docker, Podman 4.9, Podman 5.x)
- **Adversarial security testing** — 90+ vectors across RBAC and model-authorization changes (6-round pentest, re-verify cycles)
- **Pentest clear** — Laura: 36 pass, BOLA GREEN, 0 Critical/High findings

**Release Discipline:**
- SSH-signed tag with full release notes on GitHub
- Complete version consistency (code + documentation + installer)
- Pre-release gates: installation validation, documentation audit, artifact integrity

### v4.0.0 — Native UI Release, Complete UI Control (major milestone)

v4.0.0 introduced the native Yashigani UI, replacing the Open WebUI dependency. This marked the transition from infrastructure management to product control.

**Core Features:**
- **Native UI** — First-class Yashigani chat interface at `/chat/*`. Built-in, owned and controlled by Agnostic Security. Rules defined, changes owned, interface fully under our control.
- **Visual Agent Builder** — No-code workflow composition through native UI
- **Natural-Language Agent Generator** — Create agents by describing intent
- **Policy Verification on Document Ingestion** — Documents checked against OPA policies before ingestion into agent context
- **Full Gateway Integration** — Native UI routes all LLM calls through gateway inspection pipeline
- **Bundled Langflow & Letta** — Agent orchestration frameworks available via compose profiles

**Strategic Milestone:** v4.0 represented the inflection point where Yashigani owned the entire user-facing layer, eliminating dependency on upstream UI projects and enabling rapid policy enforcement and security posture changes without waiting for external releases.

---

### v3.1.2 — PII Enforcement, RBAC Hardening, Podman Deadlock Fix, Org Migration (prior release)

v3.1.2 is a security and reliability hardening release on top of v3.1.0. It adds PII enforcement at both ingress and egress, fixes RBAC group membership handling, corrects OpenWebUI identity verification, adds step-up to RBAC mutations, resolves Podman deadlock conditions, and migrates to the new GitHub org. Gate: Ava e2e + Laura 0 Crit / 0 High.

**PII Enforcement** — `input.data_tags` and `input.obligations` wired at both ingress and egress OPA calls. POL-004 blocks unredacted PII (dash-separated, spaced, encoded patterns) destined for cloud models. Fail-closed: OPA exception blocks rather than logs.

**RBAC Group Checks** — POL-001/002/003 now read group membership from `data.yashigani.rbac` instead of empty `input.identity.groups`. Restores group-based policy enforcement.

**OWUI Verify-User** — Membership check now uses identity-ID instead of email, fixing login failures.

**RBAC Step-Up** — `update_group` and `remove_member` require fresh TOTP step-up. Helm rbac.rego aligned with compose for K8s parity.

**Podman Init-Container Deadlock** — Resolved race condition in PKI issuer causing clean installs to hang.

**Org Migration** — All references updated from `agnosticsec-com` to `Agnostic-Security`.

### v3.0.0 — Document-Content Data Protection, Agent Orchestration, MCP Hardening (GA milestone)

v3.0.0 was the first public 3.x GA release, consolidating foundational agent orchestration, document-level policy enforcement, and MCP security hardening.

**Core Features:**
- **Document-Content Data Protection (doc-OPA)** — Policy-driven enforcement on document content: pass / redact (delete) / pseudonymise (reversible) / block. Self-describing verdict actions for compliance workflows.
- **Agent Orchestration with Every-Hop OPA** — Every inter-entity hop (agent↔agent, agent↔LLM, agent↔human, agent↔API, agent↔MCP) adjudicated at ingress AND egress. Gateway acts as sole mediator; no in-process shortcuts.
- **MCP Hardening** — Identity-JWT broker, import-binding verification, egress OPA enforcement, tool-poisoning / shadowing / confused-deputy mitigations. Demonstrated via cloud-9 MCP-injection demo with ResponseInspection egress block.
- **OpenWebUI at ROOT** — OpenWebUI served at `/` (not `/app/webui`) behind verify-user + owui-users access gate. Default user role enforced. RAG embeddings via `nomic-embed-text`.
- **Exhaustive QA Gate** — 83/83 Ava assertions (admin UI, user UI, API/WebUI parity, 4 demo scenarios, 11 security/adversarial tests). Clean-from-scratch install verified green.

**Release Discipline:** SSH-signed tag. Full pre-release security gate (Laura SAST+DAST+pentest: RELEASE-CLEAR).

---

### v2.23.4 — Cleanup-System Architectural Close, pgbouncer mTLS Sidecar, and KMS Posture Reframe (prior release)

v2.23.3 is a security and supply-chain hardening release on top of v2.23.2. It adds DNS-rebinding defence for outbound HTTP, a PKI admin UI with a BYO-CA driver for operator-controlled cert chains, full air-gap deployment support, OWASP API3 BOPLA per-property allowlists, age-encrypted backups, password-reuse history (CMMC L2 IA.L2-3.5.8), and a swap of the abandoned `fasttext-wheel` dependency in the prompt-injection classifier to scikit-learn. Tag SSH-signed.

**DNS-Rebinding Defence for Outbound HTTP** -- `yashigani.net.pinned_resolver` resolves the target hostname once at context entry, verifies the IP against the SSRF allowlist/blocklist, and patches `socket.getaddrinfo` for the transport so subsequent DNS changes cannot redirect the connection. OWUI agent push wired through pinned-resolver to defend against the admin-account-compromise pivot. New audit event type `SSRF_PINNED_RESOLVER_USED`. New security doc `docs/security/ssrf.md`. 18 + 8 new tests. Closes OWASP API7 SSRF DNS-rebinding gap (issue #91).

**PKI Admin UI + BYO-CA Driver** -- `/api/v1/admin/pki/*` endpoints expose chain inspection, leaf rotation (step-up TOTP), bundle download (PEM, private key never included), and all-services status. The BYO-CA driver (`YASHIGANI_PKI_CA_MODE=byo`) issues EC P-256 CSRs against an external signing endpoint (step-ca / Vault PKI), validates the returned chain, and atomically installs the new key. Auth modes: `token`, `mtls`, `none`. Fail-closed on any driver error — no silent fallback to the internal issuer. Closes issues #51 + #53.

**Air-Gap Deployment Support** -- Operators build an offline bundle from a pinned `airgap/manifest.yml` on a connected host via `scripts/prepare-airgap-bundle.sh`, transfer it, and install with `install.sh --air-gap --bundle <path>`. Per-image digest verification fail-closed at pull and load; `zstd`-compressed tar; SHA256 sidecar manifest for out-of-band integrity check. `--air-gap` implies `--offline` + `--tls-mode selfsigned`. Pre-flight G20 gate enforces bundle existence, manifest parse, zstd availability. Docs: `docs/operations/air-gap-install.md`. Closes issue #58.

**API3 BOPLA Per-Property Allowlist** -- New explicit deny-by-default public-view Pydantic schemas (`AdminAccountPublic`, `UserAccountPublic`, `SiemTargetPublic`, `IdPPublic`, `JWTConfigPublic`, `JWTTestResultPublic`) backed by `model_config extra='forbid'`. Sensitive fields (`password_hash`, `totp_secret`, `recovery_codes`, `failed_attempts`, `client_secret`, `auth_value`, `private_key`, PII claims) are never serialised on list endpoints. 54 regression tests. OWASP API3:2023, ASVS V4.2.1, CWE-213.

**Encrypted Backups** -- `scripts/backup.sh` produces age-encrypted `<timestamp>.tar.gz.age` backups via AES-256-GCM (age X25519). `restore.sh` extended with `--encrypted <identity.age> <archive>` path; legacy unencrypted archives accepted with deprecation warning. `age=1.2.1-1+b5` added to both Dockerfiles. Helm `backup-cronjob.yaml` + `backup-script` ConfigMap. Closes CMMC L2 product gap MP.L2-3.8.9 / CWE-312.

**Password Reuse History (CMMC L2 IA.L2-3.5.8)** -- Self-service password changes check the new password against the last `PASSWORD_HISTORY_DEPTH` (default 12, range 1–24) Argon2id hashes in the new `password_history` table (migration 0010). Reuse rejected HTTP 422 `password_reuse`. Audit event `PASSWORD_REUSE_REJECTED` emits `user_id` and `history_depth_checked` only — no password or hash ever logged.

**`fasttext-wheel` → scikit-learn Swap** -- The prompt-injection sensitivity classifier migrated from the abandoned `fasttext-wheel==0.9.2` (last upstream release Sep 2020) to `scikit-learn>=1.4` + `joblib>=1.3`. The trained model is now stored and loaded via joblib; equivalent classification quality with active upstream maintenance. Closes YSG-RISK-040.

**N-1 Upgrade Validation (v2.23.2 → v2.23.3)** -- The install-and-upgrade smoke matrix (introduced in v2.23.2) now validates the v2.23.2 → v2.23.3 upgrade path on the same four platform combinations (macOS Podman / macOS Docker / Linux Podman / Linux Docker). Backup, upgrade, restore, and both-admin reachability verified at every CI run.

### v2.23.2 — Security Hardening, Supply-Chain Controls, and ASVS L3 92%

v2.23.2 is a security and quality hardening release on top of v2.23.1. It closes the remaining deferred findings from the v2.23.1 release cycle, strengthens the supply chain, hardens container and network posture, and introduces continuous install-and-upgrade validation. ASVS v5 L3 coverage reaches 92% (166/180) with zero release-blocking failures.

**XFF Spoofing Closed** -- The gateway no longer trusts `X-Forwarded-For` headers set by callers. Caddy is the sole edge: it strips any incoming XFF and sets a clean one before forwarding. Rate limiting and audit logging now bind to the address Caddy observed, not one the client claimed.

**Rate Limiter Fail-Closed Default** -- The rate limiter now defaults to `RATE_LIMITER_FAIL_MODE=closed`. When Redis is temporarily unreachable the request is rejected with `HTTP 503` and a `Retry-After` header rather than silently allowed through. Operators who need fail-open behaviour for specific environments can opt in explicitly. A human-readable recovery message is included in the 503 body.

**Login Throttle `Retry-After` Header** -- Locked-out callers now receive an RFC 6585-compliant `Retry-After` header on the login response, so automated tooling and administrators know exactly when to retry without polling.

**OPA and Jaeger mTLS** -- The OPA policy engine and Jaeger tracing collector are now gated with mutual TLS on both Docker Compose and Kubernetes Helm deployments. Service identities are verified by the in-tree PKI; plaintext access to these components from the data plane is no longer possible.

**Kyverno Admission Policies** -- Kubernetes deployments now ship Kyverno admission policies that enforce the container hardening posture at the cluster level: non-root UID, read-only root filesystem, dropped capabilities, and no privilege escalation. Policy violations block pod scheduling before containers start.

**Container Hardening: Uniform Non-Root UIDs** -- All services now run as non-root. The Ollama inference service, previously running as root for convenience, has been migrated to UID 1000. Combined with the Kyverno admission policies, this closes the root-in-container gap across the full stack.

**Caddy Reverse Proxy Coverage: All 73 Blocks** -- The Caddy verified-secret header (`X-Caddy-Verified-Secret`) is now injected on all 73 `reverse_proxy` blocks across all Caddyfile variants (selfsigned, ACME, CA, WAF) and the Kubernetes ConfigMap. A contract test asserts this on every CI run; a missing injection causes a test failure with a precise diff identifying the missing block.

**GPG Release Tag Signing** -- All releases from v2.23.1 onward are GPG-signed. The signing public key is published in-repo at `docs/release-signing-key.asc`. Verification: `git tag -v v2.23.2`.

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

**Pricing:** see https://agnosticsec.com/yashigani

Each tier's maximum bundle spend is normally set just below the next tier's base price — at that point, upgrading delivers more capacity, features, and better value per user. **While Enterprise is in pre-launch, Professional Plus has no upper bundle cap** — keep adding 250-user bundles as you grow. When Enterprise becomes generally available, customers who've expanded beyond the typical Pro Plus envelope will be invited to migrate at GA. Igniter has no bundles; upgrade to Starter at 51+ users.

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
- scikit-learn ML classifier — TF-IDF + LogisticRegression, joblib serialised (offline, <5ms; replaced FastText in v2.23.3)
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

For the full attribution list of third-party open-source components Yashigani integrates with or ships pinned by the reference compose / Helm artefacts — including each upstream project, pinned version, SPDX license identifier, and any non-standard licensing notes — see [`docs/THIRD-PARTY-LICENSES.md`](docs/THIRD-PARTY-LICENSES.md).
