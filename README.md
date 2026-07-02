<!-- last-updated: 2026-06-25T00:00:00+01:00 -->
# Yashigani
---

<html>
<body>
<div>
  <img src="https://github.com/agnosticsec-com/yashigani_img/blob/main/Yashigani8bit.png" alt="Yashigani" style="width:100%">
</div>
</body>
</html>

---
**Yashigani is the proactive compliance enforcer for MCP servers and agentic AI systems.**
---
*Yashigani — Proactive compliance enforcement for agentic AI. Every call inspected. Every policy enforced. Every action audited.*
---
---
**Latest Tagged Release:** v2.25.5 (2026-06-25) — an auth/ingress rebuild (a single authenticated portal with role-based routing to `/admin` for admins and the chat surface at the root `/` for end users, end-user logout, deny-by-default preserved), a full admin-UX refinement layer, and a security hardening pass. The admin-UX layer brings working CRUD across the back office, a policy lifecycle (draft→staging→production) with an AI policy dry-run, plain-English detection-pattern authoring, a numeric sensitivity taxonomy with per-tenant labels, second-admin enforcement, self-hosted auth-gated OpenAPI/ReDoc docs, a Postgres-backed durable identity store, and a dashboard redesign. The hardening pass adds an SSRF guard on JWKS URL resolution (https-only + non-public-IP block), OPA decision-path normalisation (fixes the public MCP JWKS endpoint, previously failing closed), a fresh step-up requirement to re-provision an existing TOTP authenticator (first-time enrolment unaffected), and a single canonical Content-Security-Policy header. Open WebUI is now served at the root `/` for reliable rendering (v0.9.2), RAG file-upload embeddings are fixed (`nomic-embed-text` pulled on install), new user accounts are active by default, and a self-healing convergence gate plus a longer Postgres first-boot window let clean installs converge unattended. Built on v2.25.4 — gateway-mediated agent/tool orchestration (every inter-entity hop policy-adjudicated at ingress and egress) and model-allocation RBAC enforced on the inference path, with a visible model-pin deny, an identity-header trust gate, GPU-bound inference, and model warmup/keep-alive to remove cold-start latency. See `CHANGELOG.md` for the full release history.

---
### 🦀 Coming next — Yashigani 3.0 *(early-access beta)*

The next major release is now in **early-access beta**. What's coming:

- **File redaction & pseudonymisation, in-flight** — proportionate enforcement beyond log/block: sensitive data in prompts, responses and documents is **redacted or pseudonymised** as it crosses the gateway (`Log · Redact · Pseudonymise · Block`).

<div>
  <img src="https://github.com/agnosticsec-com/yashigani_img/blob/main/Yashigani%20Pseudonomization.png" alt="Yashigani" style="width:100%">
</div>
  
- **Security-mediated agent orchestration** — agents can fan out to other agents, LLMs and MCP tools, and **every hop is OPA-adjudicated at ingress *and* egress, up to 9 nested levels**; no agent ever holds direct network reach to an upstream.
- **Tool-result inspection** — a poisoned MCP tool result or a compromised API response is inspected and **blocked before it re-enters an agent's context**.
- **Multi-instance / HA** and **MCP capability-envelope pinning**.

Early-access beta is open to design partners — get in touch or watch this repo. **Watch this crab! 🦀**

> **Upgrade notice (v2.25.0+):** Backup format changed to dual-wrap AES-256-GCM with argon2id KEK; legacy age-encrypted archives are not forward-compatible — migrate before upgrading. TLS 1.2 is disabled on the internal mesh (TLS 1.3 minimum from v2.25.1); internal clients must support TLS 1.3.

> **Upgrade notice (v2.23.4):** OPA now fails-CLOSED on every exception path (timeout, 5xx, connection refused). Operators with intermittently-reachable OPA should alert on `yashigani_opa_response_check_failures_total`. Dev opt-in to prior fail-open behaviour: `YASHIGANI_OPA_OPTIONAL=true` (non-production only).

---
**Single branch:** `main` — all features, all tiers. Open WebUI, Wazuh, agent bundles, and the optional Smallstep step-ca runtime ACME service are all gated behind compose profiles / install flags. **Core-plane mTLS is default-on**: per-service leaf certificates are issued at install time by the in-tree two-tier PKI (`src/yashigani/pki/issuer.py`) — no optional services required.
---
**Document Date:** 2026-06-25
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

Yashigani is a **proactive compliance enforcer** purpose-built for Model Context Protocol (MCP) servers and agentic AI systems. It operates as a reverse proxy, sitting between AI agents or human clients and the upstream MCP tool servers that those agents call. Every request passes through Yashigani before reaching a tool; every response is inspected before being returned. Nothing crosses the boundary without being authenticated, authorized, and inspected.

The **Model Context Protocol** is an open standard that allows AI agents — systems driven by large language models — to call external tools: file system operations, database queries, API calls, shell commands, and more. MCP enables genuinely powerful agentic behavior, but it also exposes a new and largely unaddressed attack surface. An LLM that can call tools is an LLM that can be manipulated into exfiltrating credentials, bypassing access controls, or executing unintended actions. The MCP specification itself defines the protocol, not the security envelope around it.

Yashigani fills that gap. It provides the security layer that MCP does not: authentication, fine-grained authorization via Open Policy Agent (OPA), ML-assisted prompt injection detection, credential exfiltration prevention, per-endpoint rate limiting, full audit trails with multi-sink delivery, encrypted secrets management, SSO/SCIM identity integration, enterprise-grade observability, intelligent model routing via the Optimization Engine, and three-tier budget governance. From a single developer running a local model to a large organization deploying hundreds of AI agents across multiple business units, Yashigani is the enforcement point that makes agentic AI deployments safe to operate in production.

### Coverage at a glance

Yashigani consolidates into a single Apache-2.0 stack capabilities that would otherwise require integrating multiple separate open-source projects, alongside modules for which there is no off-the-shelf substitute: multi-LLM prompt-injection adjudication, deterministic 4D sensitivity-aware routing, container-per-identity isolation with forensic post-mortem, and SHA-384 Merkle-chain audit tamper-evidence.

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

**Yashigani's response:** The three-layer sensitivity pipeline classifies every prompt before routing. Layer 1: regex pattern matching catches structured sensitive data (credit card numbers, SSNs, API keys). Layer 2: scikit-learn ML classifier (TF-IDF + LogisticRegression, joblib serialised) detects semantic sensitivity at under 5ms, fully offline. Layer 3: Ollama LLM classification provides deep contextual analysis for ambiguous cases. Data classified as CONFIDENTIAL or RESTRICTED is routed to local models only — this is an immutable rule enforced by the Optimization Engine. No override exists. No admin can bypass it. No configuration can disable it. CHS additionally strips credential-shaped patterns from payloads before any AI inspection backend sees them. The dedicated PII detection module (since v2.20) adds 10 entity types (SSN, credit card with Luhn validation, email, phone, IBAN, passport, NHS number, driver's licence, IP address, date of birth) with three enforcement modes: LOG (detect and audit), REDACT (replace with `[REDACTED:TYPE]` before forwarding to cloud), and BLOCK (reject requests containing PII destined for cloud models). PII filtering runs on both request and response paths — bidirectional, on all traffic, by default. Cloud bypass requires explicit admin opt-in.

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

All Yashigani releases from v2.23.3 onward are cryptographically signed. Two signatures are provided for each release:

**Git tag signature (SSH)** — verifies the source commit is authentic and unchanged. Release tags are SSH-signed (the signing scheme moved from GPG to SSH as of 2026-05-25; the SSH allowed-signers file is published in-repo):

```sh
# Point git at the in-repo allowed-signers file (once):
git config gpg.ssh.allowedSignersFile docs/release-signing-key.pub

# Fetch tags (in case a tag was updated):
git fetch --tags --force origin

# Verify (any release tag from v2.23.3 onward):
git tag -v v2.25.5
# Expected: 'Good "git" signature' from the Agnostic Security release signing key
```

**Container image signature (cosign / Sigstore)** — verifies the published container images match the release tag:

```sh
cosign verify \
  --certificate-identity-regexp='https://github.com/agnosticsec-com/.*' \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \
  ghcr.io/agnosticsec-com/yashigani-gateway:2.25.5
```

For SBOM attestation, every release artifact carries a Sigstore-signed SBOM published as a GitHub Release asset alongside the tag.

---

## 6. Compliance and Security Posture

Yashigani is engineered against OWASP ASVS v5 Level 3 (all chapters), OWASP API Security, and OWASP Agentic AI / LLM Top 10, plus framework-specific controls. Open exceptions are tracked in an internal risk register (5×5 matrix with quantitative analysis). Pre-release gate: all PARTIAL/FAIL items must have an accepted-exception entry before any tag is created.

### Static analysis & secure-SDLC tooling

Yashigani is gated by a layered static-analysis toolchain, and the configuration for each tool is committed in-repo — public and auditable, so you can see exactly what is (and isn't) enforced:

| Tool | Config in repo | Scope |
|---|---|---|
| **Bandit** | `.bandit` | Python security linting (CWE patterns) |
| **Checkov** | `.checkov.yml` | IaC / Dockerfile / Helm misconfiguration |
| **Gitleaks** | `.gitleaks.toml` | Secret scanning |
| **Hadolint** | `.hadolint.yaml` | Dockerfile best-practice + security |
| **Trivy** | `trivy-agent-allowlist.json` | Container image CVE scanning, with an explicit reviewed allowlist |
| **opengrep** | `opengrep-rules/` | Bespoke AST rules (e.g. PKI/TLS anchors) |

These run alongside the supply-chain controls in §5 (SHA-pinned GitHub Actions, `pip` removed from runtime images, Sigstore-signed SBOMs, cosign image signatures).

---

## 7. Current Release Highlights

The current release is **v2.25.5**. The v2.23 line established the core security foundation (mTLS, OPA, PKI, audit chain, BOPLA, air-gap); the v2.24 series hardened the K8s/Helm path, shipped FIPS 140-3 alignment, signed+encrypted backups, and addressed pgbouncer auth cycles; the v2.25 series enforces TLS 1.3 on the internal mesh, ships the Wazuh SIEM full-stack integration, closes the audit DB and OPA hardening backlog, delivers gateway-mediated agent/tool orchestration with model-allocation RBAC, and lands the auth/ingress rebuild, the full admin-UX refinement layer, and a security hardening pass. For the full per-version history (v0.1.0 → v2.22.x), see [Architecture.md §4 Security Features by Version](Architecture.md#4-security-features-by-version).

### v2.25.5 — Auth/Ingress Rebuild, Admin-UX Refinement Layer, and Security Hardening Pass

v2.25.5 rebuilds the front door, refines the entire back-office admin experience, and lands a focused security hardening batch.

**Single Auth Portal + Open WebUI at Root** -- One authenticated login portal routes admins to `/admin` and end users to the chat surface served at the root `/`, with working end-user logout and deny-by-default preserved throughout. Open WebUI is now served at the root path (v0.9.2) for reliable rendering, replacing the earlier `/app/webui` subpath. All UI traffic continues to route through the gateway so OPA policy and identity-binding apply just as they do to API traffic.

**Admin-UX Refinement Layer** -- A top-to-bottom pass over the back office: working CRUD everywhere (agent edit; admin/user account edit with an email column; model-alias, allocation, budget, and client-policy-binding dropdowns that persist). Policy management gains template duplicate / edit / save-as, a server-enforced danger-confirm on core-policy edits, a draft→staging→production lifecycle with promote/archive, and an **AI policy dry-run** (admin describes an intent, the system returns block/allow plus rationale). New: **generate detection patterns from plain English**; RBAC path/method dropdowns with plain-language help; budget alerts with a default-on ≥85% threshold plus full custom-alert CRUD; audit verdict / entity / source-type filters; description panels across all monitoring dashboards; license-gating of enterprise authentication (OIDC/SAML surface a "requires [tier]" notice); Cryptography consolidated under PKI; and an opt-in "new version available" check that distinguishes major from security updates.

**Dashboard Redesign** -- A criticality-weighted per-service health semaphore, a five-level alert semaphore, a budget gauge (cloud/local with an 85% marker), and security + traffic widgets on a unified palette.

**Numeric Sensitivity Taxonomy** -- Sensitivity levels are canonical numbers with a per-tenant label/colour mapping; the OPA shim accepts both the numeric levels and the legacy string levels, and `OFFICIAL-SENSITIVE` is built in.

**Second-Admin Enforcement** -- A minimum of two admins is enforced; deleting or disabling the last remaining admin is blocked (`409`), with an enforcement-status endpoint and a back-office banner.

**Self-Hosted OpenAPI / API Map** -- Auth-gated API documentation: Swagger UI at `/admin/api-docs`, ReDoc at `/admin/api-redoc`, and `/admin/openapi.json`, plus gateway `/docs` and `/redoc`. Assets are served locally and render under the strict CSP.

**Durable Identity Store** -- A Postgres-backed durable mirror of the identity registry with a startup reconcile, so identities are re-hydrated if the Redis volume is lost. Install-time and on-demand backups are signed and encrypted.

**Security Hardening Batch** -- SSRF guard on JWKS URL resolution (YSG-RISK-083): the JWKS endpoint URL is validated before resolution — https-only (blocks `file://` and `http://`) and the resolved IP is checked against private/loopback/link-local/reserved ranges (blocks cloud-metadata and internal networks); egress-default-deny firewall and the mTLS mesh remain the primary compensating controls. OPA path normalisation (YSG-RISK-081): the OPA policy check now receives the leading-slash-normalised path consistently with every other gate, so rego rules keyed on paths with a leading slash (e.g. the public MCP `/.well-known/jwks.json` endpoint) match correctly instead of failing closed with a spurious 403. Step-up required to re-provision TOTP (YSG-RISK-082): replacing an *existing* TOTP authenticator now requires a fresh step-up TOTP verification before a new seed is issued; first-time enrolment is exempt as the bootstrap path. CSP header deduplication (YSG-RISK-080): the edge is now the sole source of the Content-Security-Policy header, removing the duplicate-header condition that could let the stricter of two policies silently win.

**Install + Open WebUI Reliability** -- RAG file-upload embeddings fixed: `nomic-embed-text` is pulled on install and set as the embedding model, resolving "No sources found" on file-upload RAG. New user accounts default to the `user` role (active), so accounts created after the first are not stuck pending activation. A self-healing convergence gate re-runs the deploy once and re-polls if the gateway health poll times out on a clean install, and the Postgres first-boot window is raised to 300 s — clean installs converge unattended under heavy parallel load. Tag SSH-signed.

### v2.25.4 — Gateway-Mediated Agent/Tool Orchestration and Model-Allocation RBAC

v2.25.4 routes multi-agent and tool-calling flows *through* the gateway so every inter-entity hop — agent↔agent, agent↔tool/MCP, agent↔LLM — is policy-adjudicated at ingress and egress rather than going direct. Phase 2 adds a reasoning leg (Letta) with deterministic exfiltration defence, plus Helm parity for the orchestration capabilities on Kubernetes. Model allocations granted to an identity are now enforced on the inference path, backed by a durable allocation store and pushed into OPA, with an admin **Access** panel managing per-identity allocations; an explicit model pin that is not permitted returns a visible `403` rather than silently substituting an allowed model. Requests arriving through Open WebUI carry the real end-user identity through to the gateway for per-user policy and allocation decisions, and the forwarded end-user identity header is only trusted behind the authenticated reverse-proxy boundary (closing a header-spoofing path). A content secret-detector module is added to the inspection pipeline. The bundled inference runtime is wired to the GPU via CDI (was running on CPU with idle GPUs), and model warmup + keep-alive (`OLLAMA_KEEP_ALIVE=-1`, post-deploy warmup, increased Caddy write timeout) eliminate first-request cold-load latency across compose, Helm, and the installer. Tag SSH-signed.

### v2.25.3 — MCP Broker Hardening, OPA Fail-Close Correctness, Install/Upgrade Robustness

v2.25.3 wires the MCP broker into the gateway runtime with OPA-gated tool access, registry, and codegen; shipped MCP server bundles are built as hardened images, every MCP hop is policy-adjudicated, and a hard chain-depth ceiling is enforced as a policy constant with parity tests across the Docker and Kubernetes OPA bundles. It corrects OPA fail-close behaviour (retires the deny-override anti-pattern that produced `eval_conflict` 500s, closes path-traversal and default-deny inversions, and makes v1 sub-decisions fail closed), runs the audit writer under a least-privilege runtime database role with `PostgresSink` on the append-only signed chain, fully codifies the Wazuh SIEM internal-CA mTLS provisioning into `install.sh` (no manual steps) with a TLS 1.3 floor on the indexer listener and internal mesh, and decodes response bodies before sensitivity classification on the inference path. A batch of clean-slate and upgrade-path install fixes lands alongside (GPU wired into Ollama via CDI on Podman, self-healing runtime-manifest bootstrap tokens, dual-wrap backup against read-only containers, rootless-Podman PKI fixes) plus a local install-path regression gate. The follow-up v2.25.3.1 hardened the agent registry for durability across restarts and added the `gateway.models.service_account_full_list` runtime setting (service-account identities receive a restricted `/v1/models` listing by default; operators opt in to the full listing for the Open WebUI model picker — this widens listing only, never call-authorisation). Tags SSH-signed.

### v2.25.2 — Wazuh Integration, Audit DB Least-Privilege, OPA Hardening, PII Decode-Before-Classify

v2.25.2 closes the Wazuh SIEM full-stack integration for Linux/Docker deployments (mTLS certificate auto-provisioning in `install.sh`, tar-over-exec backup with SHA-256 integrity check, configurable convergence-gate timeout), splits the PostgreSQL audit DB into least-privilege roles (`yashigani_admin` for schema management and `yashigani_app` for runtime access), wires the `PostgresSink` audit event path, hardens OPA (deny-override class fix, `mcp.rego` added to the Helm policy bundle, depth-limit test corrections), and adds decode-before-classify so PII inspection correctly processes base64/URL-encoded payloads. It also repairs the generic-proxy forward path (forwarded `Content-Length` header conflict caused 500s on upstream responses; forward-leg telemetry corrected) and fixes a metrics re-registration error that fired on every credential-exfiltration alert. Tag SSH-signed.

### v2.25.1 — TLS 1.3 Minimum on Internal Mesh

v2.25.1 enforces TLS 1.3 as the minimum protocol version across the Yashigani internal mTLS mesh, disabling TLS 1.2 on all internal service-to-service connections. External-facing listeners are unchanged. Tag SSH-signed.

### v2.25.0 — Kubernetes/Helm Parity (Wave 1–3), Signed + Encrypted Install-Time Backup

v2.25.0 completes three waves of Kubernetes/Helm parity with the Docker Compose deployment: container `securityContext` fields, resource limits, Helm chart `values.yaml` structure, and policy bundle consistency now match the compose reference across all three waves. The install-time backup is upgraded to dual-wrap AES-256-GCM encryption: argon2id-derived KEK1 from the operator passphrase, plus a per-install local key (KEK2) stored in a Docker named secret. This supersedes the prior `age` X25519 scheme. Tag SSH-signed.

### v2.24.4 — FIPS 140-3 Deployment Posture

v2.24.4 formally documents and enforces the FIPS 140-3 deployment posture (CMVP #4985). SHA-256 verification is handled via the OpenSSL FIPS Provider when `FIPS_MODE=1`. Algorithms and key sizes outside the FIPS-approved set are blocked at configuration load time. Operator guidance added at `docs/operations/fips-deployment.md`. Tag SSH-signed.

### v2.24.3 — pgbouncer cert+pg_ident mTLS, Podman Seccomp Fix

v2.24.3 closes the multi-cycle pgbouncer authentication hardening: `cert` auth method with `pg_ident` CN mapping (`pgb-auth-map`) gives the strongest posture — verify-full (chain + CN) with no SCRAM computation, resolving a platform-specific SCRAM client bug on ARM64/macOS Podman. Fixes the Podman `security_opt` override regression (relative seccomp path; `no-new-privileges` restored). Tag SSH-signed.

### v2.24.2 — Security Hardening Batch (Audit Chain, SoD, OPA Gaps, TOTP Counter, Caddy Egress)

v2.24.2 ships a batch of security hardening commits: audit chain cross-batch ordering stability (bigserial sequence column), admin/user separation-of-duties enforcement (collision checks on all auth creation paths), OPA conformance gap closures (GAP-001 `/v1/models` and GAP-002 `/v1/proxy` response leg), TOTP failure counter migrated to Redis (survives restarts, consistent across replicas), Caddy egress iptables OUTPUT allowlist with K8s NetworkPolicy equivalent, and runtime settings Phase 2 web UI. Tag SSH-signed.

### v2.24.1 — DDoSProtector, Per-User Rate Limit, Runtime Settings Phase 1

v2.24.1 instantiates `DDoSProtector` with per-IP defaults scaled to the installed licence tier, adds per-user 100 RPS rate limiting with Prometheus alerting and audit events, and ships Phase 1 of the runtime settings system (DB persistence, service layer, admin API, Redis pub/sub live-reload for three initial tunables). Tag SSH-signed.

### v2.24.0 — Separation-of-Duties, API Docs Gate, Caddyfile Parity Gate

v2.24.0 closes admin/user account-tier separation gaps, ships the OpenAPI schema drift gate (regenerates `docs/api/*.md` from live FastAPI schema and fails the build on drift), adds the Caddyfile family parity gate (caddy adapt across all compose + helm variants), and wires the Open WebUI → gateway in-mesh path through a dual-port gateway surface. Tag SSH-signed.

### v2.23.4 — Cleanup-System Architectural Close, pgbouncer mTLS Sidecar, and KMS Posture Reframe

v2.23.4 closes the v2.23.3 follow-up backlog and lands an architectural close of the install/uninstall cleanup-system class (state file + container-fallback rm + cross-UID handlers across the entire lifecycle). It ships the `letta-pgbouncer` mTLS sidecar, the Open WebUI in-mesh path through the gateway, `/me/api-key` self-service Bearer issuance, HUMAN identity registration on local-auth login, and the OPA fail-closed posture. Tag SSH-signed.

**Cleanup-System Architectural Close** -- Install and uninstall now share a persisted state file (`docker/.yashigani-install-state`, mode 0644, key=value with `RUNTIME` / `INSTALL_UID` / `INSTALL_USER`), eliminating runtime-detection and ownership-assumption heuristics. uninstall.sh's container-fallback `rm` (Alpine-image based, sudo-free) handles cross-UID chown'd dirs (`docker/{data,certs,logs}`) and secrets (`docker/secrets/*`) without requiring `sudo` on non-PTY SSH sessions. Dotfile-aware wipe glob (`.[!.]* + ..?*`) prevents `.pki-status` from surviving the wipe. `.env` cross-UID handler skips-with-WARN when host-side read fails; `docker compose down` proceeds via Docker socket. `_do_chgrp` hoisted to script scope.

**`letta-pgbouncer` mTLS Sidecar** -- Letta's postgres connection now routes through a dedicated session-mode pgbouncer sidecar (`edoburu/pgbouncer:v1.25.1-p0`, UID 70, `read_only:true`, `cap_drop:[ALL]`, `no-new-privileges`). The sidecar presents `letta-pgbouncer_client.crt` to postgres over mTLS; postgres `pg_hba.conf` catch-all (`hostssl all all 0.0.0.0/0 scram-sha-256 clientcert=verify-ca`) applies uniformly with no letta carveout. Closes the asyncpg+pg8000 client-cert-URI-param limitation at the sidecar boundary.

**KMS-Architectural Posture for Credentials** -- The cleartext `userlist.txt` is documented at `docs/yashigani_install_config.md` §6.1 as the non-KMS dev/standalone posture. Production deployments configure a KMS provider via `YASHIGANI_KMS_PROVIDER=vault|azure|aws|gcp|keeper`; the providers in `src/yashigani/kms/` fetch credentials at runtime, bypassing the cleartext-on-disk path entirely. The yashigani-internal Bearer is per-install (32-char charset-compliant token at `docker/secrets/yashigani_internal_bearer`, mode 0600) — the literal string `yashigani-internal` is gone from production source.

**Open WebUI → Gateway In-Mesh Path** -- The gateway exposes a dual-port surface: `:8080` for mTLS edge traffic and `:8081` for plain-HTTP in-mesh traffic carrying an `Authorization: Bearer yashigani-internal` token. Open WebUI joins the `caddy_internal` network and routes chat completions via the gateway rather than direct to Ollama, so OPA policy + identity-binding apply to UI traffic the same way they apply to API traffic. The Ollama default model `qwen2.5:3b` auto-pulls on first install with `--with-openwebui` so the chat UI works out of the box.

**`/me/api-key` Self-Service Bearer Issuance** -- Users can mint, list, and revoke their own API keys from the user UI. Step-up TOTP required for issuance (ASVS V6.8.4); `/auth/stepup` widened from admin-only to accept user sessions while preserving every existing guard (anonymous-rejection, replay-cache, per-session failure counter, cross-tenant guard, audit-event emission). API-key strings are hash-stored; `last4` shown in UI for identification.

**HUMAN Identity Registration on Local-Auth Login** -- Local password+TOTP users now get an identity-registry entry created automatically on first login, with tier-aware metadata. Closes the design gap where local-auth users had no identity-registry presence (previously only SSO-registered users were tracked).

**OPA Fail-Closed Posture** -- The OPA response-check in `gateway/openai_router.py` now returns `allow: False` on every exception path (timeout, 5xx, connection refused, `opa_not_configured`) instead of the prior `allow: True`. Helm enforces it at deploy-time via the `OPA-URL-001` violation when `global.environment=production` and `gateway.env.YASHIGANI_OPA_URL` is empty. New Prometheus counter `yashigani_opa_response_check_failures_total{outcome, reason}` registered. Behavioural break for upgrades from v2.23.3 with intermittently-reachable OPA (see CHANGELOG `Breaking Changes` for the dev opt-in via `YASHIGANI_OPA_OPTIONAL=true`).

**SAML BYOK Config-Load Surface** -- `broker.add_idp()` accepts SAML identity-provider configurations via `YASHIGANI_IDP_<N>_SAML_*` environment variables. `_assert_rsa_sp_key()` runs at config-load time, rejecting non-RSA SP keys at container startup rather than at first signature attempt. Mitigates the libgcrypt ECDH heap-overflow class (CVE-2026-41989) at the config-load boundary.

**Container Auto-Start on Host Reboot** -- Compose installs provision a user-scoped `systemd --user` unit under `loginctl enable-linger` so the gateway and backoffice come back up after a host reboot without operator intervention. Helm path already handled by Kubernetes.

**OPA + Helm Policy Bundle Alignment** -- The K8s helm chart previously shipped a stub OPA ConfigMap with package `yashigani.v1_routing` and no `decision` / `allow_v1` rules — the gateway read `result.get("allow", False)` against the empty result, returning 403 on every K8s chat request. Replaced with the verbatim compose `policy/{yashigani,v1_routing,rbac,agents}.rego` bundle so K8s and compose make the same policy decisions.


### v2.23.3 — DNS-Rebinding Defence, PKI Admin UI + BYO-CA, Air-Gap Deployment, API3 BOPLA, Encrypted Backups, and Password-History Reuse Rejection

v2.23.3 is a security and supply-chain hardening release on top of v2.23.2. It adds DNS-rebinding defence for outbound HTTP, a PKI admin UI with a BYO-CA driver for operator-controlled cert chains, full air-gap deployment support, OWASP API3 BOPLA per-property allowlists, age-encrypted backups, password-reuse history (CMMC L2 IA.L2-3.5.8), and a swap of the abandoned `fasttext-wheel` dependency in the prompt-injection classifier to scikit-learn. Tag SSH-signed.

**DNS-Rebinding Defence for Outbound HTTP** -- `yashigani.net.pinned_resolver` resolves the target hostname once at context entry, verifies the IP against the SSRF allowlist/blocklist, and patches `socket.getaddrinfo` for the transport so subsequent DNS changes cannot redirect the connection. OWUI agent push wired through pinned-resolver to defend against the admin-account-compromise pivot. New audit event type `SSRF_PINNED_RESOLVER_USED`. New security doc `docs/security/ssrf.md`. 18 + 8 new tests. Closes OWASP API7 SSRF DNS-rebinding gap (issue #91).

**PKI Admin UI + BYO-CA Driver** -- `/api/v1/admin/pki/*` endpoints expose chain inspection, leaf rotation (step-up TOTP), bundle download (PEM, private key never included), and all-services status. The BYO-CA driver (`YASHIGANI_PKI_CA_MODE=byo`) issues EC P-256 CSRs against an external signing endpoint (step-ca / Vault PKI), validates the returned chain, and atomically installs the new key. Auth modes: `token`, `mtls`, `none`. Fail-closed on any driver error — no silent fallback to the internal issuer. Closes issues #51 + #53.

**Air-Gap Deployment Support** -- Operators build an offline bundle from a pinned `airgap/manifest.yml` on a connected host via `scripts/prepare-airgap-bundle.sh`, transfer it, and install with `install.sh --air-gap --bundle <path>`. Per-image digest verification fail-closed at pull and load; `zstd`-compressed tar; SHA256 sidecar manifest for out-of-band integrity check. `--air-gap` implies `--offline` + `--tls-mode selfsigned`. Pre-flight G20 gate enforces bundle existence, manifest parse, zstd availability. Docs: `docs/operations/air-gap-install.md`. Closes issue #58.

**API3 BOPLA Per-Property Allowlist** -- New explicit deny-by-default public-view Pydantic schemas (`AdminAccountPublic`, `UserAccountPublic`, `SiemTargetPublic`, `IdPPublic`, `JWTConfigPublic`, `JWTTestResultPublic`) backed by `model_config extra='forbid'`. Sensitive fields (`password_hash`, `totp_secret`, `recovery_codes`, `failed_attempts`, `client_secret`, `auth_value`, `private_key`, PII claims) are never serialised on list endpoints. 54 regression tests. OWASP API3:2023, ASVS V4.2.1, CWE-213.

**Encrypted Backups** -- `scripts/backup.sh` produces age-encrypted `<timestamp>.tar.gz.age` backups via AES-256-GCM (age X25519). `restore.sh` extended with `--encrypted <identity.age> <archive>` path; legacy unencrypted archives accepted with deprecation warning. `age=1.2.1-1+b5` added to both Dockerfiles. Helm `backup-cronjob.yaml` + `backup-script` ConfigMap. Closes CMMC L2 product gap MP.L2-3.8.9 / CWE-312.

**Password Reuse History (CMMC L2 IA.L2-3.5.8)** -- Self-service password changes check the new password against the last `PASSWORD_HISTORY_DEPTH` (default 12, range 1–24) Argon2id hashes in the new `password_history` table (migration 0010). Reuse rejected HTTP 422 `password_reuse`. Audit event `PASSWORD_REUSE_REJECTED` emits `user_id` and `history_depth_checked` only — no password or hash ever logged.

**`fasttext-wheel` → scikit-learn Swap** -- The prompt-injection sensitivity classifier migrated from the abandoned `fasttext-wheel==0.9.2` (last upstream release Sep 2020) to `scikit-learn>=1.4` + `joblib>=1.3`. The trained model is now stored and loaded via joblib; equivalent classification quality with active upstream maintenance.

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

**Release Tag Signing** -- All releases from v2.23.3 onward are cryptographically signed. Tags are SSH-signed (scheme formally moved from GPG to SSH on 2026-05-25); the allowed-signers file is published in-repo at `docs/release-signing-key.pub`. Verification: see §5 "Verifying a Release".

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
