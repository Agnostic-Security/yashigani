<!-- last-updated: 2026-05-15T12:00:00+01:00 (docs: also clean v0.6.0 version-table cell — Linux/macOS/cloud/VM → Linux/macOS — v2.23.4) -->
<!-- last-updated: 2026-05-15T11:30:00+01:00 (docs: remove unimplemented bare-metal/no-container install claims — v2.23.4) -->
# Yashigani Architecture and Feature History

---

This document is the long-form companion to the top-level [README.md](README.md). It carries the architectural detail (request flow, components, network isolation, identity model), the full per-version feature history, the complete feature list, and the deployment topology reference. README.md focuses on the current release and the entry-point links operators need; everything historical or structural lives here.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Components](#2-components)
3. [Identity and Routing](#3-identity-and-routing)
4. [Security Features by Version](#4-security-features-by-version)
5. [Complete Feature List](#5-complete-feature-list)
6. [Deployment Topologies](#6-deployment-topologies)
7. [Roadmap Context](#7-roadmap-context)

---

## 1. Architecture Overview

Yashigani is structured as a two-plane system: a **data plane** that handles the real-time request path, and a **control plane** (backoffice) that manages configuration, identity, policies, and audit storage.

### 1.1 Request Flow

```
AI Agent / Human (via Open WebUI or API)
        |
        v
[ Caddy TLS Edge ]          <-- ACME / CA-signed / self-signed
        |                       /chat/* → Open WebUI
        |                       /admin/* → Backoffice
        |                       /v1/*, /agents/*, /* → Gateway
        v
[ Identity Broker ]         <-- Multi-IdP: OIDC + SAML v2 (since v2.0)
        |                       Unified identity model (kind field)
        v
[ Authentication Layer ]    <-- Session auth, API key, Bearer token,
        |                       TOTP/2FA, OIDC, SAML v2, JWT introspection
        v
[ RBAC / Authorization ]    <-- OPA policy engine, role resolution
        |
        v
[ PII Detection ]           <-- 10 PII types, LOG/REDACT/BLOCK (since v2.20)
        |                       Bidirectional, cloud bypass opt-in
        v
[ Sensitivity Pipeline ]    <-- Three layers (all ON by default):
        |                       1. Regex pattern matching
        |                       2. scikit-learn ML classifier (<5ms, v2.23.3: TF-IDF + LogisticRegression replaces FastText; baked into image)
        |                       3. Ollama LLM classification
        |                       + CHS credential detection
        |                       + Payload masking before AI send
        v
[ Optimization Engine ]     <-- Four-dimensional routing (since v2.0):
        |                       sensitivity + complexity + budget + cost
        |                       P1-P9 priority matrix
        |                       CONFIDENTIAL/RESTRICTED → always local
        |                       Budget exhaustion → degrade to local
        v
[ Budget Enforcement ]      <-- Three-tier hierarchy (since v2.0):
        |                       org cloud cap → group → individual
        |                       budget-redis (noeviction)
        v
[ Rate Limiting ]           <-- Redis fixed-window, per-endpoint
        |
        v
[ OPA Routing Safety Net ]  <-- Second OPA pass on routing decisions
        |                       + LLM policy review (since v2.0)
        v
[ Upstream LLM / MCP ]      <-- Cloud API / Ollama / MCP tool server
        |
        v
[ Response Inspection ]     <-- Sensitivity + PII scan on response (since v2.20)
        |                       Streaming: chunk-level inspection (since v2.20)
        |
        v
[ Audit Write ]             <-- File + PostgreSQL + SIEM (async)
        |                       P1-P5 alert severity (since v2.0)
        v
AI Agent / Human (response)
```

---

## 2. Components

| Component | Role |
|---|---|
| **Gateway (data plane)** | Reverse proxy, TLS, auth, inspection, rate limiting, routing, Optimization Engine |
| **Backoffice (control plane)** | Admin UI/API, identity management, policy editor, license validation, budget admin |
| **Open WebUI** | Chat interface at /chat/*, internal network only, all LLM calls through gateway (since v2.0) |
| **Optimization Engine** | Four-dimensional routing: sensitivity + complexity + budget + cost; P1-P9 priority matrix (since v2.0) |
| **Identity Broker** | Multi-IdP identity broker: OIDC + SAML v2; Caddy delegates auth (since v2.0) |
| **Pool Manager** | Per-identity container lifecycle: create, route, health, replace, scale, postmortem forensics (since v2.0) |
| **OPA Policy Engine** | Declarative, version-controlled authorization for every tool call; routing safety net with LLM policy review (since v2.0) |
| **Sensitivity Pipeline** | Three-layer classification: regex + scikit-learn ML + Ollama; all ON by default (since v2.0; ML backend swapped FastText → scikit-learn TF-IDF + LogisticRegression in v2.23.3) |
| **Inspection Pipeline** | scikit-learn ML + multi-backend LLM inspection with fail-closed sentinel |
| **Audit Pipeline** | Multi-sink writer: file, PostgreSQL, Splunk, Elasticsearch, Wazuh; P1-P5 alert severity with SIEM integration (since v2.0) |
| **PgBouncer** | PostgreSQL connection pooler, prevents connection exhaustion (password from .env since v1.09.5) |
| **Redis** | Rate limiting, response caching, anomaly detection sliding windows |
| **Budget Redis** | Dedicated budget counter store (noeviction policy), prevents counter eviction under memory pressure (since v2.0) |
| **Key Management System** | KMS integration: Keeper, AWS KMS, Azure Key Vault, GCP KMS, HashiCorp Vault |
| **Prometheus / Grafana** | Metrics collection and 12 dashboards (9 existing + 3 new: budget, OE, pool manager) (since v2.0) |
| **Loki / Promtail** | Log aggregation and shipping |
| **Alertmanager** | 3-channel escalation: Slack/email → PagerDuty |
| **OpenTelemetry / Jaeger** | Distributed tracing across gateway, inspection, and upstream |
| **Wazuh SIEM** | Full stack (manager + indexer + dashboard), optional compose profile (`--wazuh`) |
| **Optional ACME runtime CA (Smallstep)** | step-ca compose service for runtime ACME cert management; opt-in via `--with-internal-ca`. Not required for default-on mTLS — the in-tree PKI issuer handles install-time cert generation. |

### 2.1 Network Isolation (EX-231-10 — v2.23.1)

**Caddy is the sole ingress to backoffice and gateway.** No peer in the mesh reaches `:8443` or `:8080` directly.

**Compose:** four networks enforce this posture — `edge` (Caddy + host ports), `caddy_internal` (Caddy + gateway + backoffice; the only network where their listeners exist), `data` (backoffice/gateway outbound + all data deps), and `obs` (prometheus/grafana/loki/alertmanager/otel-collector/jaeger). Services on `data` or `obs` that do not share `caddy_internal` cannot resolve gateway/backoffice by name (Docker DNS scopes to shared networks), and Docker bridge L2 segmentation removes the ARP reachability path.

**Kubernetes:** `NetworkPolicy` resources enforce this at the kernel level. The `allow-backoffice-ingress` and `allow-gateway-ingress` policies admit only `yashigani-caddy` pods (plus nginx-ingress when `tlsMode=nginx`). Prometheus scrapes go exclusively through Caddy's SPIFFE-gated internal metrics listeners (`:8444`/`:8445`) — direct pod scrape egress is only emitted when those listeners are explicitly disabled.

**Belt-and-braces:** application-layer mTLS + SPIFFE middleware remains active on both listeners as a second layer of defence.

---

## 3. Identity and Routing

Yashigani v2.0 introduces a unified identity model: every entity — human or service — is an identity with a `kind` field. There are no separate user and agent stores. The same governance, budget enforcement, RBAC, and audit trail apply to all identities regardless of kind. Humans carry optional IdP federation metadata; services carry optional upstream URL, container configuration, system prompt, and capability declarations. Both are managed through the same Web UI and API.

Incoming bearer tokens identify the calling identity and the Optimization Engine determines routing based on four dimensions: data sensitivity classification, task complexity, remaining budget, and provider cost. The P1-P9 priority matrix governs routing decisions, with P1 (CONFIDENTIAL/RESTRICTED data) as the only immutable rule — such data always stays local. Budget exhaustion triggers graceful degradation to local inference; the system never rejects a request.

---

## 4. Security Features by Version

The current release narrative (v2.23.0 + v2.23.1 + v2.23.2 + v2.23.3 + v2.23.4) is in the [README](README.md#current-release-highlights). This section preserves the full per-version history.

### 4.1 Version Progression Summary

| Version | Theme | Key Additions |
|---|---|---|
| **v2.23.4** | **Cleanup-System Architectural Close, pgbouncer mTLS Sidecar, KMS Posture Reframe** | **Cleanup-system architectural close (state file `docker/.yashigani-install-state` mode 0644 records RUNTIME/UID/USER for cross-UID handoff; uninstall.sh state-file-beats-heuristic; container-fallback rm for `docker/{data,certs,logs}` and sudo-free secrets wipe; dotfile-aware wipe glob `.[!.]*` + `..?*`; rmdir after wipe; `.env` cross-UID skip-with-WARN; `log_info` helper restored; `_do_chgrp` hoisted to script scope — closes BACKLOG-V240-003/004/006 and root cause of 5 cascading uninstall blockers); `letta-pgbouncer` mTLS sidecar (`edoburu/pgbouncer:v1.25.1-p0`, UID 70, read_only:true, cap_drop:[ALL], session-mode, presents client cert to postgres — pg_hba catch-all `hostssl all all clientcert=verify-ca` applies with no letta carveout; closes YSG-RISK-048); KMS-architectural reframe for credentials (cleartext userlist.txt documented as non-KMS dev posture at `docs/yashigani_install_config.md` §6.1, YSG-RISK-049 ACCEPTED-LOW; production configures `YASHIGANI_KMS_PROVIDER=vault|azure|aws|gcp|keeper` to fetch via `src/yashigani/kms/` providers); Open WebUI in-mesh path (gateway dual-port :8080 mTLS edge + :8081 plain in-mesh w/ Bearer); Ollama default-model auto-pull on `--with-openwebui`; `/me/api-key` self-service Bearer issuance (step-up TOTP, ASVS V6.8.4); HUMAN identity registration on local-auth login; OPA fail-closed posture (all exception paths return `allow:False`, Prometheus `yashigani_opa_response_check_failures_total` counter, Helm validate-security `OPA-URL-001`); `yashigani-internal` Bearer rotated to per-install 36-char secret (literal gone from source); SAML BYOK config-load surface (`YASHIGANI_IDP_<N>_SAML_*`, RSA-key enforcement at __init__); container auto-start on host reboot (`systemd --user` + `loginctl enable-linger`); install.sh:5101 `\|\| true` cp-fallback guard; air-gap install Step 9 `.Id`-fallback for image-digest verification (docker load doesn't populate RepoDigests — closes YSG-RISK-038); uninstall.sh runtime detection prefers Podman with liveness probe (closes YSG-RISK-004); dead-code `fasttext_backend.py` removed (LU-YSG-009); air-gap docs `config/` added (closes YSG-RISK-039); pgbouncer admin console lockdown (`admin_users` empty + `stats_users` empty on yashigani-pgbouncer, Laura F2 sibling); Iris+Laura design-review-first sequencing across 10+ cycles persisted at `internal-docs/yashigani/iris-v234-*.md` + `laura-v234-*.md`; Ava E2E 13/13 PASS at tag (Phase 1 6/6 + Phase 2 6/6 + crucible test of `.env` cross-UID class-of-bug close).** |
| **v2.23.3** | **DNS-Rebinding Defence, PKI Admin UI + BYO-CA, Air-Gap Deployment, API3 BOPLA, Encrypted Backups, Password-History Reuse Rejection** | **DNS-rebinding defence for outbound HTTP (`yashigani.net.pinned_resolver` resolves hostname once at context entry, verifies against SSRF allow/block, patches `socket.getaddrinfo` for the transport so subsequent DNS changes can't redirect; OWUI agent push wired through; new audit event `SSRF_PINNED_RESOLVER_USED`; security doc `docs/security/ssrf.md`; closes issue #91 / OWASP API7); PKI admin UI + BYO-CA driver (`/api/v1/admin/pki/*` chain inspection / leaf rotation step-up TOTP / bundle download / status — private key never included; BYO-CA driver `YASHIGANI_PKI_CA_MODE=byo` issues EC P-256 CSR against external signing endpoint w/ step-ca/Vault PKI, validates chain, atomic install; auth modes token/mtls/none; fail-closed on driver error; closes #51 + #53); air-gap deployment support (`scripts/prepare-airgap-bundle.sh` builds offline bundle from pinned `airgap/manifest.yml`; `install.sh --air-gap --bundle <path>`; per-image digest verification fail-closed; zstd-compressed tar + SHA256 sidecar; pre-flight G20 gate; closes #58); OWASP API3 BOPLA per-property allowlist (explicit deny-by-default Pydantic public-view schemas w/ `model_config extra='forbid'` for admin/user accounts + SIEM target + IdP + JWT config/test — sensitive fields never serialised; 54 regression tests; ASVS V4.2.1, CWE-213); age-encrypted backups (`scripts/backup.sh` produces `<timestamp>.tar.gz.age` via AES-256-GCM/age X25519; `restore.sh --encrypted`; Helm `backup-cronjob.yaml`; closes CMMC L2 MP.L2-3.8.9 / CWE-312); password reuse history (`password_history` table migration 0010; default 12 Argon2id hashes range 1-24; HTTP 422 `password_reuse` + `PASSWORD_REUSE_REJECTED` audit; CMMC L2 IA.L2-3.5.8); `fasttext-wheel` → scikit-learn swap in prompt-injection classifier (closes YSG-RISK-040 abandoned dep); N-1 upgrade matrix v2.23.2→v2.23.3 across macOS+Linux × Podman+Docker.** |
| **v2.23.2** | **Security Hardening, Supply-Chain Controls, ASVS L3 92%** | **XFF spoofing closed (Caddy strips and re-sets `X-Forwarded-For`); rate-limiter fail-closed default with `Retry-After` on 503; login throttle `Retry-After` header (RFC 6585); OPA and Jaeger mTLS on Docker Compose and Kubernetes Helm; Kyverno admission policies (non-root UID, read-only root filesystem, no-new-privileges, dropped caps); all Ollama containers migrated to UID 1000; all 73 Caddy `reverse_proxy` blocks carry `X-Caddy-Verified-Secret` injection; Caddyfile contract test in CI (asserts inject-caddy-verified count, TLS 1.3 presence, client_auth placement); GPG release tag signing infrastructure complete (CI workflow + public key in-repo); GitHub Actions steps SHA-pinned; pip removed from runtime images (CVE surface reduction); SBOM service-identity SHA gate; install + N-1 upgrade smoke matrix (macOS Podman / macOS Docker / Linux Podman / Linux Docker); backslash open-redirect patch on admin `next=` with regression tests; safe_error_envelope for all error responses; host /tmp eliminated from install.sh + restore.sh + CI; OWASP ASVS v5 L3 92% (166/180), zero release-blocking FAILs** |
| **v2.23.1** | **Core-Plane mTLS + Two-Tier PKI + Release Hardening** | **Core-plane mTLS default-on across gateway / backoffice / postgres / pgbouncer / redis / opa (in-tree two-tier PKI issuer: root → intermediate → per-service leafs with SPIFFE-style URIs, automatic issuance + rotation; the optional Smallstep step-ca service `--with-internal-ca` provides separate ACME-style runtime cert management), seccomp + AppArmor default-on for all runtimes, fail-closed on missing HMAC + OWUI secrets (no silent dev-mode fallback), centralised SSRF allowlist helper for outbound HTTP, per-endpoint body-size limits (ASVS 4.3.1), log-injection sanitisation across audit/app logs, session rotation on password change (ASVS V7.4.2), uniformised 401 vs 404 on unauth admin endpoints, CSP explicit `script-src` + working `/admin/csp-report` handler, algorithm allowlist on license ECDSA verifier, Caddy header hygiene (stripped Server + stale alt-svc), PCI-compliant password expiry profile (≤90 days), TOTP enrolment API split provision/confirm, auth-throttle admin self-visibility (admin-session view of own + all throttled/blocked IPs), agent tier-limit returns 402 (was 500), AGENT_REGISTERED audit events now persisted, /.well-known/security.txt (RFC 9116), symbol-bearing generated passwords (`!*,-._~` with category guarantees), `YSG_RUNTIME` stale-env bleed fix, AppArmor mmap permission for shared libraries, ACS v3 dogfood-scan release-blocker batch closed (YSG-RISK-001 partition_maintenance SQLi, YSG-RISK-002 Alembic migration SQLi, YSG-RISK-003 OIDC scheme/host validation, YSG-RISK-004 compose mem_limit/cpus, YSG-RISK-005 Helm resources.limits/requests, YSG-RISK-006 OpenClaw 18789 loopback bind, YSG-RISK-007 SSRF allowlists across agents/oidc/audit), macOS Podman + Docker / Linux Podman + Docker / K8s Helm all clean-slate tested** |
| **v2.23.0** | **Single Branch, API-First Admin, Strict CSP, Compose Profiles, Internal CA** | **Branch consolidation (release/1.x eliminated — Open WebUI is `--with-openwebui` flag), API-first admin UI (static SPA, external JS/CSS, no Jinja2 templates, no inline code), strict CSP (`script-src 'self'; style-src 'self'`, zero `unsafe-inline`, object-src none, base-uri none, COOP same-origin, CSP report endpoint), optional services via compose profiles (openwebui, wazuh, internal-ca, langflow, letta, openclaw), admin service management (enable/disable any service from admin panel, no SSH), Internal CA (Smallstep step-ca for service-to-service TLS, `--with-internal-ca`), Podman socket detection on macOS, restore.sh backup recovery, admin-configurable password policy (max 13 months), domain-bound licensing (ECDSA P-256 signed), container socket mount read-only** |
| **v2.22.x** | **OPA on /v1, Agent Personas, Fail2ban, IP Access Control, OWASP Compliance Review** | **OPA policy enforcement on ALL /v1 traffic (request + response path, fail-closed), Podman SDK (podman-py) for container-per-user isolation, agent personas: Lala (Langflow), Julietta (Letta), Scout (OpenClaw) with descriptions + example prompts, agent chaining (@Scout to @Julietta to @qwen in one prompt, @Help chaining guide), fail2ban auth throttle (per-IP 3 failures + global 5 failures, x5 escalation 30s to 625m, permanent IP block), IP allowlist + blocklist (IPv4/IPv6/CIDR, admin manageable), content relay detection (agent-to-agent laundering), PKCE on OIDC (code_verifier/code_challenge), acr/amr validation on ID tokens, constant-time comparisons (hmac.compare_digest for TOTP), crypto inventory API (/admin/crypto/inventory + admin UI + JSON export), __Host- cookie prefix, context-specific password word list, self-service password reset (TOTP-verified), OWASP ASVS v5 (all 17 chapters) + API Security + Agentic AI compliance review, risk register (16 risks, 5x5 matrix), Grafana + Prometheus admin access (/admin/grafana/ and /admin/prometheus/), Monitoring tab, Wazuh SIEM full stack (--wazuh), budget allocation wiring (per-identity from Redis), Postgres migrations on startup, dashboard auto-refresh (15s), full agent registration form, audit log viewer with search/filter/export CSV, session timeout warning (10 min), first-run onboarding checklist, login branding (Agnostic Security footer)** |
| **v2.20** | **Security Hardening, PII Detection, and Compliance** | **License anti-tampering (v4 counter-sig + self-integrity check), PII detection module (3 modes, 10 entity types, bidirectional inspection, cloud-model bypass), response-path inspection wired to /v1 routes, container hardening (seccomp, AppArmor opt-in, read-only FS in compose), WAF/DDoS protection (Caddy timeouts + body limits, per-IP DDoSProtector), FastText model baked into Docker image, model aliases Redis persistence, SBOM (CycloneDX 1.5 + CryptoBoM 12 algorithms) + cosign keyless image signing, Helm K8s chart fixes + network policies, streaming chunk-level inspection (StreamingInspector), HMAC-SHA256 per-tenant email hashing, Ollama model digest pinning, Open WebUI "Powered by Open WebUI" branding, 548 tests (523 unit + 25 e2e), 9 compliance framework mappings, 2 STRIDE threat models** |
| **v2.1** | **Admin Dashboard + Alerting + SSO + Persistence** | **Admin Dashboard UI (login page + 9-section admin panel), 12 Alertmanager P1-P5 routing/budget alert rules, Budget Postgres persistence (survives restarts), Pool Manager background health monitor (daemon thread), OPA v1_routing.rego verified operational, OIDC identity broker wired end-to-end (JWT validation, JWKS discovery, group extraction), mandatory 2FA after SSO (anti-replay), Keycloak test IdP, SSO audit trail (SHA-256 email hashing), Podman rootless parity (volume permissions fix, e2e runtime auto-detection), 413 tests (388 unit + 25 e2e)** |
| **v2.0** | **First production-grade release** | **Unified Identity Model (kind field, no separate user/agent stores), Optimization Engine (4D routing: sensitivity + complexity + budget + cost, P1-P9 priority matrix), three-tier Budget System (org cap → group → individual, budget-redis noeviction), Open WebUI integration (/chat/*, internal only), Container Pool Manager (per-identity isolation, self-healing, postmortem forensics, Ollama horizontal scaling), Multi-IdP Identity Broker (OIDC + SAML v2), sensitivity classification pipeline (regex + FastText + Ollama, all ON by default), P1-P5 alert severity with SIEM integration, OPA routing safety net with LLM policy review, 17 core services + 3 optional agent bundles + dynamic per-identity containers, 363 tests (252 + 111 new), 12 Grafana dashboards** |
| v1.09.5 | Agent bundles GA + Podman | Agent bundles (LangGraph, Goose, OpenClaw) work out of the box with PSK auto-registration, first-class Podman support (runtime detection, compose command, auto-apply podman override), DNS fix for Ollama external network access, admin accounts with fun codenames (animal/nature themed), PgBouncer password from .env, Alembic migrations in backoffice image, 18-service full stack verified from clean slate |
| v0.9.4 | Final hardening | Classifier regex fix (security: nested braces in inspection response no longer misclassified as CLEAN), FastAPI lifespan migration, localhost defaults replaced with Docker service names, CI version consistency gate |
| v0.9.3 | Bugfix and hardening (45-issue audit) | Rate limiter bypass fix, OllamaPool stack overflow fix, Vault KMS provider fix, response inspection pipeline activation, ECDSA P-256 license key embedded, all Docker images pinned, WebAuthn migration, integration test suite, 18 bare-exception handlers replaced with logging, CI license key gate, Redis scan_iter, IPv6-safe IP masking |
| v0.9.2 | Installer env var and bash 3.2 compat fixes | Full `.env` writer sets all required vars before compose pull (fixes `UPSTREAM_MCP_URL` error); `update.sh` process substitution replaced with `find | while read` (bash 3.2 compat) |
| v0.9.1 | Installer security hardening — credential bootstrap | Dual admin accounts (random themed usernames) with TOTP 2FA at install, HIBP k-Anonymity breach check on all generated passwords, credential summary at install completion, secrets written to docker/secrets/ chmod 600 |
| v0.9.0 | Post-quantum cryptography + security hardening | ECDSA P-256 licence signing (ML-DSA-65 planned), hybrid TLS X25519+ML-KEM-768 (pending Caddy 2.10), response-path inspection (F-01), WebAuthn/Passkeys (S-01), break-glass dual-control, SHA-384 Merkle audit chain, async SIEM queue, agent PSK auto-rotation, real-time SSE inspection feed, searchable + exportable audit log, installer deployment modes redesign |
| v0.8.4 | Installer patch — macOS + GPU + Podman | Fixed platform detection, GPU detection (Apple Silicon/NVIDIA/AMD), bash 3.2 compat, Podman runtime, Docker Desktop CLI auto-fix, numbered agent bundles, runtime-agnostic compose, interactive fallbacks, `update.sh`, `test-installer.sh` |
| v0.8.0 | Optional agent bundles + agent UX | Opt-in LangGraph / Goose / OpenClaw containers (Compose profiles + Helm toggles), installer agent selection step with disclaimer, `GET /admin/agent-bundles` catalogue API, agent detail quickstart snippet endpoint, rate limit `last_changed` timestamp |
| v0.7.1 | Alert wiring + partition bootstrap | Direct alert dispatch on credential exfil + licence expiry monitor, partition bootstrap migration (2026-05 → 2027-06), full DB health unit test suite |
| v0.7.0 | Operational hardening + OPA Policy Assistant | ECDSA P-256 key active, DB partition automation + monitoring, OPA Policy Assistant (NL → RBAC JSON), MCP quick-start snippets, direct webhook alerting (Slack/Teams/PagerDuty), CIDR IP allowlisting per agent, path matching parity fix, runtime-configurable rate limit thresholds |
| v0.6.2 | Starter tier + three-dimensional limits | 5-tier model adds Starter (OIDC-only), max_end_users + max_admin_seats split, v3 license payload schema |
| v0.6.1 | Tier restructuring + open-source licensing | 4-tier model (Community/Professional/Professional Plus/Enterprise), Apache 2.0 community license, CLA framework |
| v0.6.0 | Universal installer + licensing | Linux/macOS installer (Docker/Podman runtime required), 3-tier licensing (Community/Professional/Enterprise), ECDSA P-256 license verification, feature gates |
| v0.5.0 | Data plane hardening + observability | PostgreSQL 16 RLS + AES-256-GCM, pg_partman, PgBouncer, JWT introspection (JWKS waterfall), multi-sink audit, OTEL/Jaeger, FastText ML, Vault KMS, Loki, Alertmanager, per-endpoint rate limiting, response caching, Wazuh, anomaly detection, inference logging, container hardening, structured JSON logging |
| v0.4.0 | Cloud-native operations | Kubernetes Helm charts, GitHub Actions CI/CD, KEDA autoscaling, pod disruption budgets, network policies, Trivy scanning, CODEOWNERS |
| v0.3.0 | Enterprise identity + inspection | RBAC via OPA, agent routing, multi-backend inspection (5 providers), OIDC + SAML v2 SSO, SCIM, fail-closed sentinel, response masking, payload masking |
| v0.2.0 | TLS and identity hardening | ACME/CA/self-signed TLS, Prometheus metrics, bcrypt, multi-admin with lockout protection |
| v0.1.0 | Core gateway | MCP proxy, prompt injection (Ollama), CHS, OPA, session/API key auth, audit log, Redis rate limiting, TOTP/2FA, Argon2 |

### 4.2 v2.22.x — OPA on /v1, Agent Personas, Fail2ban, IP Access Control, and OWASP Compliance Review

v2.22.x is a multi-release series that delivers OPA enforcement on all /v1 traffic, introduces agent personas with chaining support, adds fail2ban-style authentication throttling with IP access control, and lands a comprehensive OWASP compliance review.

**OPA on ALL /v1 Traffic** -- OPA policy enforcement is now active on every `/v1/chat/completions` request, both on the request path (authorization, routing policy) and the response path (content policy). The `v1_routing.rego` policy is fail-closed: if OPA is unreachable, the request is denied.

**Agent Personas and Chaining** -- The three agent bundles have user-facing personas: **Lala** (Langflow), **Julietta** (Letta), and **Scout** (OpenClaw). Each persona has a description and example prompts in the model dropdown. Agent chaining allows users to invoke multiple agents in a single prompt (e.g., `@Scout` -> `@Julietta` -> `@qwen`). The `@Help` agent provides a chaining guide.

**Fail2ban Auth Throttle** -- Per-IP rate limiting on authentication failures: 3 failures per IP triggers a 30-second ban. Global threshold: 5 failures across all IPs triggers system-wide escalation. Ban duration escalates x5 on each subsequent violation (30s -> 1m -> 5m -> 25m -> 2h -> 10h). Permanent IP block after maximum escalation.

**IP Allowlist and Blocklist** -- IPv4, IPv6, and CIDR range support for both allowlists and blocklists. Admin-manageable via the admin panel. Blocklist takes precedence over allowlist.

**Content Relay Detection** -- Detects agent-to-agent content laundering, where one agent relays content through another to bypass inspection policies.

**PKCE on OIDC** -- All OIDC authentication flows now use Proof Key for Code Exchange (code_verifier/code_challenge), preventing authorization code interception.

**acr/amr Validation** -- Authentication Context Class Reference (acr) and Authentication Methods Reference (amr) claims on ID tokens are validated to enforce authentication strength requirements.

**Constant-Time Comparisons** -- TOTP verification uses `hmac.compare_digest` for constant-time comparison, preventing timing side-channel attacks.

**Crypto Inventory API** -- `/admin/crypto/inventory` exposes a complete inventory of all cryptographic algorithms, key sizes, and usages across the deployment. The admin UI provides a dedicated view with JSON export.

**__Host- Cookie Prefix** -- Session cookies use the `__Host-` prefix, which enforces `Secure`, `Path=/`, and no `Domain` attribute — preventing cookie injection and fixation attacks.

**Context-Specific Password Word List** -- Password validation blocks context-specific terms: "yashigani", "admin", "password", and other deployment-related words.

**Self-Service Password Reset** -- Users can reset their own password using TOTP verification, without requiring an administrator.

**OWASP Compliance Review** -- per-control review against OWASP ASVS v5 (all 17 chapters), OWASP API Security, OWASP Agentic AI / LLM Top 10, and infrastructure controls. PASS / PARTIAL / FAIL / N/A verdicts with file:line evidence per control. Open exceptions are tracked in the risk register (5x5 matrix with quantitative analysis). Pre-release gate: all PARTIAL/FAIL items must have an accepted-exception entry before any tag is created.

**UX Improvements:**
- Dashboard auto-refresh (15-second interval)
- Full agent registration form (protocol, groups, CIDRs)
- Audit log viewer with search, filter, and CSV export
- Session timeout warning (10-minute banner before expiry)
- First-run onboarding checklist
- Login branding (Agnostic Security footer)
- Monitoring tab with Grafana dashboard links, Prometheus, and Wazuh

**Additional v2.22.x changes:**
- Podman SDK (podman-py) for container-per-user isolation
- Grafana + Prometheus accessible at `/admin/grafana/` and `/admin/prometheus/`
- Wazuh SIEM full stack as optional compose profile (`--wazuh`)
- Budget allocation wiring (per-identity from Redis, not hardcoded)
- Postgres migrations run on startup (pg_partman/pg_cron optional)
- Goose agent removed (ACP too slow on CPU)

### 4.3 v2.20 — Security Hardening, PII Detection, and Compliance

v2.20 is a focused security hardening release that closes multiple OWASP ASVS Level 3 gaps identified in the v2.1 compliance audit, ships production-grade PII detection, and adds the supply-chain assurance controls (SBOM, image signing) required for enterprise procurement.

**License Anti-Tampering** -- The license verifier now uses a v4 payload schema with a counter-signature that detects binary patching of the verifier itself. A self-integrity check runs at startup; any detected modification halts the process rather than silently degrading to an incorrect tier. This closes the license bypass vector that existed when the verifier was the only trust anchor.

**PII Detection Module** -- A new `pii/` module provides structured detection of personally identifiable information in both prompt and response payloads. Three operating modes are supported: `detect` (flag and log), `redact` (replace with typed placeholders before forwarding), and `block` (reject the request). Ten entity types are covered: name, email, phone, national ID, passport, date of birth, credit card, bank account, IP address, and physical address. Detection runs bidirectionally — on inbound prompts and on upstream responses. Cloud model bypass: when a prompt is classified as containing PII and the routing target is a cloud API, the PII module intercepts the routing decision and forces local inference, independently of the Optimization Engine's sensitivity classification. This provides defence-in-depth for the most common data exfiltration vector.

**Response-Path Inspection Wired to /v1 Routes** -- The `ResponseInspectionPipeline` introduced in v0.9.0 and activated in v0.9.3 is now wired to all `/v1/*` routes in addition to MCP routes. Every OpenAI-compatible response passing through the gateway is inspected before delivery.

**Container Hardening** -- `docker-compose.yml` now carries explicit `security_opt`, `cap_drop`, and `read_only` directives for all core services. The seccomp profile is embedded in the repository at `docker/seccomp/yashigani.json`. AppArmor profile loading is opt-in and documented as Ubuntu/Debian-only; a compose override (`docker-compose.apparmor.yml`) is provided for operators on supported hosts. Read-only root filesystem is enabled for all services that do not require writable state; tmpfs mounts cover the remaining write paths.

**WAF and DDoS Protection** -- Caddy request timeouts and body size limits are now set as hardened defaults in the Caddyfile. A `DDoSProtector` component tracks per-IP request rates in Redis and returns 429 with `Retry-After` when a configurable threshold is exceeded. For operators requiring a full Web Application Firewall, a `Caddyfile.waf` reference configuration using the Coraza WAF plugin is documented in `docs/`.

**FastText Model Baked Into Docker Image** -- The FastText classifier model is now included in the gateway Docker image at build time. The `ollama-init` model-pull step is no longer a blocking dependency for the inspection pipeline to reach operational status. Deployments with no outbound internet access reach full inspection capability immediately on container start.

**Model Aliases Redis Persistence** -- Model alias entries are now written through to Redis on every create, update, and delete operation, in addition to Postgres. Alias resolution uses Redis as the read path with Postgres as source of truth. This eliminates the alias lookup latency that affected high-throughput deployments and ensures alias availability survives Postgres maintenance windows.

**SBOM and Image Signing** -- Every Docker image built by the release pipeline now produces a CycloneDX 1.5 Software Bill of Materials (SBOM) and a CryptoBoM covering the 12 cryptographic algorithms in use. Images are signed using cosign keyless signing (Sigstore), tied to the GitHub Actions OIDC identity of the release workflow. Consumers can verify image provenance with `cosign verify` before pulling. The `release.yml` workflow publishes SBOMs as release artifacts.

**Helm Chart Fixes and Network Policies** -- The Helm chart passed `helm lint` for the first time in v2.20. Several `values.yaml` keys introduced in v2.0 (`budgetRedis`, `poolManager`, `openWebUI`) lacked corresponding template references; these were wired. Helm test hooks were added for gateway health, auth, and audit sinks. Kubernetes network policies now cover all services added in v2.0 and v2.1 that were missing policy coverage.

**Streaming Chunk-Level Inspection** -- The `StreamingInspector` provides chunk-level content inspection for streaming responses. Chunks are buffered up to a configurable token threshold; the inspection pipeline runs against the accumulated buffer at each threshold boundary. A `budget_header_limitation` note is documented: `X-Yashigani-Budget-*` headers cannot be emitted mid-stream and are appended as trailing headers where the client supports it. Environment variables `YASHIGANI_STREAMING_CHUNK_THRESHOLD` and `YASHIGANI_STREAMING_MAX_BUFFER` control buffering behaviour.

**HMAC-SHA256 Per-Tenant Email Hashing** -- SSO audit events previously used SHA-256 email hashing with a global salt. v2.20 replaces this with HMAC-SHA256 keyed with a per-tenant secret stored in the KMS. This ensures that email hashes from one tenant cannot be correlated with hashes from another, closing a cross-tenant correlation risk in multi-org deployments.

**Ollama Model Digest Pinning** -- The `ollama-init` model-pull step now records the SHA-256 digest of each pulled model and validates it on subsequent starts. A model that does not match the pinned digest is rejected and an alert is raised. This closes the supply-chain risk where a poisoned Ollama registry could silently replace a trusted model.

**Open WebUI Branding** -- The Open WebUI deployment now displays "Powered by Open WebUI" in the interface footer, meeting the Open WebUI project's attribution requirement for commercial deployments.

**Compliance Documentation** -- A 9-framework compliance mapping document (`Development & QA/Development/COMPLIANCE_MAPPINGS_v2.2.md`) maps Yashigani controls against SOC 2 Type II, ISO 27001:2022, HIPAA, PCI DSS v4, GDPR, NIST CSF 2.0, NIST SP 800-53, CIS Controls v8, and OWASP ASVS v5 Level 3. Two STRIDE threat models are published: one for the product boundary (17 threats) and one for the solution deployment (38 threats).

**Additional v2.20 changes:**
- 548 tests passing (523 unit + 25 e2e)
- 9 compliance framework mappings documented
- 2 STRIDE threat models (product: 17 threats; solution: 38 threats)

### 4.4 v2.1 — Admin Dashboard, Alerting, and Persistence

v2.1 adds the management layer that makes Yashigani self-service. The Admin Dashboard provides a login page and a 9-section admin panel covering identities, budgets, routing, policies, alerts, audit, models, agents, and system health. Operators no longer need curl or API knowledge to manage the platform.

**Admin Dashboard UI** -- A web-based admin panel served behind Caddy authentication. The login page authenticates against the backoffice identity broker. Nine sections provide full visibility and control: identity management, budget configuration and status, routing policy, OPA policy editor, alert configuration, audit log viewer, model alias management, agent registry, and system health overview.

**Alertmanager Rules** -- 12 Alertmanager rules covering P1-P5 severity levels for routing and budget conditions. Rules fire on sensitivity breaches, OPA overrides, classification conflicts, spending anomalies, budget exhaustion, and budget auto-switch events. All rules route through the existing SIEM integration pipeline.

**Budget Postgres Persistence** -- Budget counters are now persisted to PostgreSQL in addition to budget-redis. Budget state survives container restarts and Redis eviction. The persistence layer writes asynchronously to avoid adding latency to the request path.

**Pool Manager Background Health Monitor** -- The Pool Manager now runs a daemon thread that continuously monitors container health. Unhealthy containers are detected and replaced without waiting for a failed request to trigger self-healing.

**OIDC Identity Broker (end-to-end)** -- The identity broker's OIDC flow is now fully operational. `handle_oidc_callback()` delegates to `OIDCProvider.exchange_code()` with real JWT validation, JWKS discovery, and group extraction supporting Entra ID, Okta, Cognito, and Keycloak group claim patterns. SSO routes: `/auth/sso/select` (IdP picker), `/auth/sso/oidc/{idp_id}` (OIDC redirect), `/auth/sso/oidc/{idp_id}/callback` (code exchange + identity resolution). IdPs are configured via `YASHIGANI_IDP_<N>_*` environment variables. CSRF protection via Redis-backed state/nonce tokens with 10-minute TTL (ASVS V3.5.3). SSO audit events use SHA-256 email hashing — raw email never stored.

**Mandatory 2FA After SSO** -- Even after successful IdP authentication, users must complete Yashigani's own TOTP verification. This prevents session hijack and replay attacks — a stolen session cookie is useless without a valid TOTP code. Controlled via `YASHIGANI_SSO_2FA_REQUIRED` (default: `false` for testing, `true` recommended for production).

**Keycloak Test IdP** -- A Docker Compose `test-idp` profile provides a pre-configured Keycloak instance with OIDC and SAML clients, three test users (alice, bob, carol), and group mappers for ID token claims. Start with `docker compose --profile test-idp up -d keycloak`.

**Podman Rootless Parity** -- Full Podman rootless support with correct user namespace configuration. Root-running services (Ollama, Postgres, Redis, Caddy) no longer use `keep-id` which caused volume permission failures. E2E test suite auto-detects runtime (Podman or Docker) via `YASHIGANI_RUNTIME` env var or container probing. Chaos tests handle Podman's restart behavior (explicit restart after kill). 413 tests passed on both Docker and Podman deployments at the time of v2.1 release (548 tests as of v2.20).

**OPA v1_routing.rego Verified Operational** -- The OPA routing safety net policy (v1_routing.rego) has been verified end-to-end in the production configuration. Policy evaluation, LLM validation of policy changes, and SAFE/WARNING/BLOCK verdicts are all confirmed operational.

**Additional v2.1 changes:**
- 413 tests passing (388 unit + 25 e2e) — superseded by 548 tests (523 unit + 25 e2e) in v2.20

### 4.5 v2.0 — First Production-Grade Release

v2.0 is Yashigani's first production-grade release, adding five major subsystems that transform the gateway from a security enforcement proxy into a complete AI operations platform with intelligent routing, budget governance, and unified identity management.

**Unified Identity Model** -- Every entity in the system — human user, AI agent, service account — is now a single identity record with a `kind` field. There are no separate user and agent stores. The same governance, budget enforcement, RBAC rules, and audit trail apply uniformly to all identities. Human identities carry optional IdP federation metadata; service identities carry optional upstream URL, container configuration, system prompt, and capability declarations. Both are managed through the same Web UI and API, under the same rules.

**Optimization Engine** -- The gateway now performs four-dimensional routing on every LLM request, evaluating data sensitivity classification, task complexity, remaining budget, and provider cost to select the optimal backend. A P1-P9 priority matrix governs routing decisions. P1 is immutable: CONFIDENTIAL and RESTRICTED data always stays local — this is enforced by both the Optimization Engine and an OPA routing safety net that performs a second policy pass on every routing decision. Budget exhaustion triggers graceful degradation to local inference; the system always responds and never rejects a request. The OPA routing safety net additionally uses a local LLM to validate OPA policy changes before they are applied, checking for self-lock conditions, contradictions, scope issues, and routing conflicts, returning SAFE/WARNING/BLOCK verdicts.

**Three-Tier Budget System** -- A hierarchical budget model enforces cloud spend governance with mathematical guarantees. The org cloud cap is the hard ceiling. Group budgets are allocated beneath it. Individual budgets are allocated within groups. The sum of individual budgets never exceeds the group budget; the sum of group budgets never exceeds the org cap. Budget counters are stored in a dedicated budget-redis container configured with a noeviction policy to prevent counter loss under memory pressure. Budget state is exposed to clients via `X-Yashigani-Budget-*` response headers.

**Open WebUI Integration** -- Open WebUI is integrated at `/chat/*` behind Caddy, accessible only on the internal Docker network. Open WebUI holds zero LLM credentials — all inference calls (cloud and local) route through the gateway. Caddy delegates authentication to the backoffice, which acts as the identity broker, and forwards trusted headers (`WEBUI_AUTH_TRUSTED_EMAIL_HEADER`) to Open WebUI. Pipelines make LLM and MCP tool calls through the gateway.

**Container Pool Manager** -- The Pool Manager provides per-identity container isolation with a universal container lifecycle: create, route, health check, replace, scale, and postmortem. The operational philosophy is self-healing: broken containers are replaced, not fixed. Before a dead container is killed, postmortem evidence (logs, inspect output, filesystem diff) is preserved for forensic analysis. Ollama scales horizontally under load. The same replace-and-scale pattern applies to all stateless core containers. License tiers gate container limits: Community (1 per service per identity, 3 total), Non-profit & Education (3/15), Starter (1/5), Professional (3/15), Professional Plus (5/50), Enterprise (unlimited).

**Multi-IdP Identity Broker** -- Yashigani is the identity broker. It supports multiple identity providers natively via OIDC and SAML v2. Caddy delegates all authentication decisions to the backoffice. SCIM provisions users and groups. Group policies govern model and agent access. IdP limits are tier-gated: Community supports local auth only, Non-profit & Education supports 1 OIDC + 1 SAML (matching Professional, free with verification), Starter supports 1 OIDC provider, Professional supports 1 OIDC + 1 SAML, Professional Plus supports 5 IdPs, Enterprise is unlimited.

**Sensitivity Classification Pipeline** -- Every prompt passes through a three-layer sensitivity classification pipeline, all layers ON by default. Layer 1 (regex) matches patterns for PII, PCI, intellectual property, and PHI. Layer 2 (scikit-learn ML, TF-IDF + LogisticRegression since v2.23.3 — previously FastText) provides sub-5ms offline classification. Layer 3 (Ollama qwen2.5) performs deep semantic analysis. Administrators can customize patterns per tenant and opt out of the Ollama layer, but cannot disable regex. Classification results feed directly into the Optimization Engine's routing decisions.

**P1-P5 Alert Severity with SIEM Integration** -- Routing decisions are audit events written through the existing audit pipeline to all SIEM sinks. A P1-P5 severity scale triggers on specific conditions: sensitivity breach (P1), OPA override (P1), classification conflict (P2), spending anomaly (P2), budget auto-switch (P3), and others.

**Additional v2.0 changes:**
- 17 core services + 3 optional agent bundles + dynamic per-identity containers (up from 18 services in v1.09.5)
- 363 tests passing (252 original + 111 new)
- 12 Grafana dashboards (9 existing + 3 new: budget, Optimization Engine, Pool Manager)
- Model alias table: DB-driven via admin API, Postgres + Redis cache, CRUD at `/admin/models/aliases`
- Streaming: buffered mode (full response before delivery) for v2.0; response inspection completes before user sees anything; chunk-level streaming shipped in v2.20
- User API keys: 256-bit hex, bcrypt cost 12, max lifetime 1 year, default rotation 90 days, 7-day grace period

### 4.6 v1.09.5 — Agent Bundles GA and Podman Support

v1.09.5 makes agent bundles and Podman first-class citizens of the deployment experience. The three agent bundles — LangGraph, Goose, and OpenClaw — now work out of the box on a clean install: the installer auto-registers each selected bundle as an agent with a pre-shared key (PSK) token, eliminating the manual agent registration step that previously blocked new operators from reaching a working agent stack. The full stack now comprises 18 services (15 core + 3 agent bundles), all verified working from a clean-slate install.

Podman received first-class support: the installer performs runtime detection, selects the correct compose command (`podman compose` vs `docker compose`), and auto-applies the Podman override file where needed. This extends the v0.8.4 Podman groundwork into a fully automated experience.

A DNS fix resolved a networking issue where the `ollama` and `ollama-init` containers were unable to reach external model registries for model downloads. Both containers are now placed on the external network, restoring model registry access without compromising the internal service network isolation.

Admin account provisioning was enhanced: auto-generated accounts now use fun animal/nature-themed codenames as usernames, with TOTP pre-provisioned at install time. PgBouncer password handling was corrected to read the password from `.env` rather than using a hardcoded or missing value. Alembic database migrations are now included directly in the backoffice Docker image, ensuring schema migrations run automatically on container startup without requiring a separate migration step.

All services have verified health checks from a clean-slate installation using the following command:

```bash
bash install.sh --domain yashigani.local --tls-mode selfsigned --with-openwebui --agent-bundles all
```

### 4.7 v0.9.4 — Final Hardening Before v2.0

v0.9.4 is the final hardening release before v2.0 development begins. It closes the last known security-relevant bug in the inspection pipeline: the classifier's JSON extraction regex silently misclassified valid injection detections as CLEAN when the LLM response included nested objects in the `detected_payload_spans` field. The regex-based extraction was replaced with a brace-depth counting parser that correctly handles arbitrarily nested JSON. The FastAPI gateway migrated from the deprecated `@app.on_event` pattern to the recommended `lifespan` context manager, eliminating all deprecation warnings. Default service URLs throughout the codebase were standardized to Docker Compose service names (`redis`, `ollama`, `policy`) instead of `localhost`, preventing silent failures in containerized deployments where localhost does not resolve to the expected service. A CI gate was added to verify that `__init__.py` and `pyproject.toml` versions remain in sync. The installer's Prometheus hash generation was fixed for macOS: `passlib` crashes on `bcrypt` 5.x due to a removed API, so the hash generation was replaced with a three-method fallback chain (htpasswd, direct bcrypt module, hashlib PBKDF2) that works reliably on both macOS and Linux.

### 4.8 v0.9.3 — Full Codebase Audit and Hardening

v0.9.3 was the most comprehensive single-version quality pass in the project's history, addressing all 45 issues found in a full codebase audit. Three critical bugs were closed: an operator precedence error in the rate limiter that allowed unauthenticated sessions to bypass session-level rate limiting; an unbounded recursive call in `OllamaPool.classify()` that caused stack overflow when all Ollama backends were unhealthy simultaneously; and a Vault KMS provider that inherited from a nonexistent base class, preventing instantiation. The `ResponseInspectionPipeline` introduced in v0.9.0 was wired into the gateway but never invoked in the default request path — v0.9.3 activated it, closing the response-path injection vector that v0.9.0 had intended to address. The ECDSA P-256 production public key was embedded in the verifier, making license tier enforcement fully active for the first time since v0.7.0 shipped the key infrastructure. Every Docker image across `docker-compose.yml`, Helm charts, and the agent bundles catalogue was pinned to a specific version, eliminating mutable-tag supply-chain risk. A WebAuthn credentials Alembic migration was created so upgrades from v0.9.0–v0.9.2 apply cleanly. An integration smoke test suite was shipped. Eighteen bare `except Exception: pass` handlers throughout the gateway were replaced with structured debug logging. A CI gate was added to reject builds containing the placeholder license key. Redis `keys()` calls were replaced with `scan_iter()` to eliminate blocking keyspace scans. IPv6 address handling was corrected in session IP masking. All 32 pre-existing stale unit tests were updated to match the current production API signatures, bringing the test suite to 252 tests with 0 failures.

### 4.9 v0.9.2 — Installer Compatibility Fixes

v0.9.2 fixed two regressions introduced during the v0.9.0 installer redesign. The `.env` writer was incomplete: only the AES key was being written before `docker compose pull` ran, causing `UPSTREAM_MCP_URL` to be undefined in the compose environment and producing a startup error on fresh installs. The function was expanded into a full `.env` writer that sets all required variables — `UPSTREAM_MCP_URL`, `YASHIGANI_TLS_DOMAIN`, `YASHIGANI_ADMIN_EMAIL`, `YASHIGANI_ENV`, and the AES key — before compose is invoked. Demo mode defaults `UPSTREAM_MCP_URL` to `http://localhost:8080/echo`. Additionally, `update.sh` used a process substitution (`< <(find ...)`) that is a bash 4+ feature not available in macOS's default bash 3.2; this was replaced with a `find | while read` pipe that is fully compatible.

### 4.10 v0.9.1 — Installer Credential Bootstrap

v0.9.1 hardened the credential bootstrap process that v0.9.0's installer redesign had left incomplete. Rather than generating a single admin account and requiring operators to create additional accounts manually, the installer now creates two admin accounts at install time with randomly generated themed usernames — eliminating the single-admin lockout risk from day one. TOTP 2FA is fully provisioned for both accounts during installation: the TOTP secret and `otpauth://` URI are generated, displayed, and immediately ready for import into any authenticator app. All generated passwords are checked against the Have I Been Pwned breach database using SHA-1 k-Anonymity prefix lookup before use; any compromised password is automatically regenerated and rechecked. The same HIBP check was added to the backoffice password-change path, implementing OWASP ASVS V2.1.7. A one-time credential summary block is displayed at the end of install showing all passwords, TOTP secrets, URIs, and the AES key. All credentials are persisted to `docker/secrets/` with permissions 0600.

### 4.11 v0.9.0 — Post-Quantum Readiness and Security Hardening

v0.9.0 was the largest security-focused release since v0.5.0. ECDSA P-256 licence signing was shipped for offline, air-gapped licence verification with no call-home requirement (ML-DSA-65 post-quantum migration is planned when the Python `cryptography` library ships FIPS 204 support). A hybrid TLS X25519+ML-KEM-768 Caddyfile configuration was included but remains commented pending Caddy 2.10 support. The response-path injection vector was closed: `ResponseInspectionPipeline` applies FastText + LLM fallback classification to upstream responses, blocking tainted tool outputs before they reach the calling agent. WebAuthn/Passkey MFA was added, supporting Face ID, Touch ID, Windows Hello, and hardware security keys (YubiKey) — coexisting with TOTP so operators can choose their preferred second factor. Operations were hardened with break-glass dual-control (hard TTL, Redis-backed, tamper-evident audit trail), a SHA-384 Merkle audit hash chain with daily anchors and a CLI verification tool, and an async SIEM delivery queue with DLQ after 3 retries. Agent PSK auto-rotation via APScheduler and KMS push ensures long-lived tokens are cycled automatically. Real-time operator visibility arrived via a Server-Sent Events inspection feed and searchable/exportable audit logs. The installer was redesigned around three deployment modes: Demo, Production, and Enterprise.

### 4.12 v0.8.4 — Installer Hardening for macOS, GPU, and Podman

v0.8.4 addressed a cluster of installer failures discovered after v0.8.0 shipped — specifically on macOS with Apple Silicon, Podman, and Docker Desktop environments. Platform detection was fixed by correcting a variable naming mismatch (`DETECTED_*` vs `YSG_*`) that caused the platform summary to report incorrect values. GPU detection was added for Apple Silicon M-series (unified memory, Metal, ANE), NVIDIA, and AMD GPUs with an lspci fallback; Ollama model size recommendations are printed based on detected VRAM. The macOS `df -BG` (GNU-only) flag was replaced with `df -k` and compatible arithmetic. Podman became a first-class supported runtime alongside Docker Engine and Docker Desktop. A Docker Desktop CLI auto-fix was added for environments where Docker Desktop is installed but `docker` is not in PATH. Bash 3.2 compatibility was enforced throughout by replacing all `${var,,}` expansions with `tr`. Agent bundle selection was changed from individual y/n prompts to a numbered menu, eliminating typo-related crashes. A new `update.sh` script handles in-place upgrades with automatic backup, image pull, restart, and rollback on failure. A 7-test automated installer validation suite (`test-installer.sh`) covering 28 checks was added to CI.

### 4.13 v0.8.0 — Agent Ecosystem Integration

v0.8.0 addressed operator demand for first-class agentic framework support without forcing Yashigani's security boundary to become optional. LangGraph, Goose, and OpenClaw are available as opt-in Docker Compose profiles and Helm toggles — all agent traffic from these containers routes through Yashigani's enforcement layer and is subject to the same inspection, authorization, and audit pipeline as any other agent. A new `GET /admin/agent-bundles` endpoint exposes the bundle catalogue with metadata and a third-party disclaimer for the UI banner. `GET /admin/agents/{id}/quickstart` returns copy-paste curl, Python httpx, and health check snippets on the agent detail page, reducing time-to-first-call for new agent deployments. The rate limit config endpoint was extended with a `last_changed` timestamp, making threshold change history auditable without requiring a full audit log query.

### 4.14 v0.7.1 — Alert Wiring and Partition Bootstrap

v0.7.1 completed the three remaining code gaps from v0.7.0. The direct webhook alert dispatcher was wired to the two actual trigger points: credential exfil detections in the inspection pipeline now call `dispatcher.dispatch_sync()` immediately on detection, and a new background monitor (`licensing/expiry_monitor.py`) runs daily via APScheduler to fire a warning alert when the active licence is within the configured expiry window (default 14 days). A daily-rate guard prevents alert storms. An Alembic migration (`0003`) pre-creates all `audit_events` and `inference_events` partitions for 2026-05 through 2027-06, ensuring a clean bootstrap without relying on the CronJob to have run first. A full unit test suite for `db/health.py` was added covering all partition check paths including DB error handling.

### 4.15 v0.7.0 — Operational Hardening and OPA Policy Assistant

v0.7.0 closed three critical pre-production blockers and delivered the headline OPA Policy Assistant feature alongside five operational improvements.

The three blockers were: (1) the ECDSA P-256 public key placeholder in the license verifier was replaced with the real production key, making license tier enforcement active for the first time; (2) database partition automation was introduced — a maintenance script and Kubernetes CronJob pre-create monthly partitions for `audit_events` and `inference_events`, preventing silent write failures at month rollover; (3) a Prometheus gauge (`yashigani_audit_partition_missing`) and Alertmanager alert rule make missing partitions immediately observable.

The **OPA Policy Assistant** allows administrators to describe an access control requirement in plain English; an internal Ollama model (qwen2.5:3b) generates the RBAC data document JSON, which is validated against the schema and presented to the admin for review before anything is applied. Admins approve or reject; the entire flow is written to the audit log. The assistant generates only the data document — it never creates or modifies Rego policy files.

Additional improvements: agent registration now returns a `quick_start` snippet with curl, Python httpx, and health check examples using the live bearer token; direct webhook alerting to Slack, Microsoft Teams, and PagerDuty was added as a lightweight alternative to the full Alertmanager stack (configurable per-event: credential exfil, anomaly threshold, licence expiry); CIDR-based IP allowlisting was introduced per agent — requests from authenticated agents arriving from outside their CIDR list are blocked 403 and audited; a path matching bug (IC-6) that caused OPA's `_path_matches` to allow single-segment wildcards to cross `/` boundaries was fixed with a correct regex-based implementation; and rate limit RPI scale thresholds became runtime-configurable via the backoffice without a gateway restart.

### 4.16 v0.6.2 — Starter Tier and Three-Dimensional Limits

v0.6.2 completed the licensing model with three changes. First, a Starter tier (OIDC-only SSO, 100 agents) was added to fill the gap between Community and Professional for small teams with an SSO mandate. Second, the single user limit was split into two independent dimensions: `max_end_users` (people using AI tools through the gateway) and `max_admin_seats` (people managing the Yashigani control plane). Third, the license payload was updated to v3 schema with backwards-compat loading for v1/v2 license files.

### 4.17 v0.6.1 — Tier Restructuring and Open-Source Licensing

v0.6.1 restructured the licensing tiers to reflect real-world deployment segment sizing and formalised the community open-source licensing model. Four tiers replaced the previous three: Community (20 agents, free), Professional (500 agents, 1 org), Professional Plus (2,000 agents, 5 orgs), and Enterprise (unlimited). The community edition adopted the Apache License 2.0, and a Contributor License Agreement (CLA) framework was introduced to allow community contributions to flow into all commercial tiers without copyright or patent encumbrance.

### 4.18 v0.6.0 — Universal Installer and Licensing

Yashigani became self-distributable. The universal installer auto-detects OS, architecture, and cloud provider, then performs a full production-grade installation on Linux and macOS hosts (Docker or Podman runtime required). Three licensing tiers were introduced: Community (free, no key), Professional (paid, signed key), and Enterprise (paid, signed key with multi-tenancy). License verification uses ECDSA P-256 offline signature validation — no license server call-home required. Feature gates enforce SAML, OIDC, and SCIM access at the tier boundary. Agent and organization limits are enforced per tier.

### 4.19 v0.5.0 — Data Platform and Full Observability

The most feature-dense release. PostgreSQL 16 with row-level security and AES-256-GCM column encryption via pgcrypto became the primary audit and operational data store. pg_partman and pg_cron automated monthly partition management. PgBouncer was added for connection pooling. JWT introspection implemented a JWKS waterfall supporting three deployment streams (opensource, corporate, SaaS). The audit pipeline became multi-sink: file, PostgreSQL, Splunk, Elasticsearch, and Wazuh simultaneously. OpenTelemetry distributed tracing with OTLP export to Jaeger made end-to-end latency visible. FastText ML added a sub-5ms, fully offline first-pass classifier. Severak KMS's implemented to provided AppRole authentication and KV v2 secrets management. Loki + Promtail consolidated log aggregation. Alertmanager delivered 3-channel escalation. Per-endpoint rate limiting and clean-only response caching (SHA-256 keyed) were introduced. Anomaly detection using Redis ZSET sliding windows caught repeated-small-call enumeration patterns. Inference payloads were logged in AES-encrypted form in Postgres. Container hardening applied seccomp allowlists, AppArmor profiles, UID 1001 non-root execution, tmpfs mounts for `/tmp` and audit buffers, and read-only root filesystem.

### 4.20 v0.4.0 — Cloud-Native Operations

Kubernetes support arrived via production-ready Helm charts. GitHub Actions CI/CD pipelines automated build, test, and deployment workflows. KEDA-based horizontal autoscaling enabled the gateway to scale replica counts based on real load. Pod disruption budgets and network policies ensured high availability and network isolation in multi-tenant clusters. Trivy container scanning was integrated into the pipeline to catch CVEs before deployment. CODEOWNERS and branch protection enforced code review requirements on security-critical paths.

### 4.21 v0.3.0 — Enterprise Identity and Inspection

This version transformed Yashigani from a single-organization tool into an enterprise-capable gateway. RBAC via OPA enabled fine-grained, role-based tool authorization. Agent routing with bearer token authentication allowed multi-agent deployments behind a single gateway. The inspection pipeline expanded from Ollama-only to a full multi-backend chain covering Anthropic Claude, Google Gemini, Azure OpenAI, LM Studio, and Ollama — with a fail-closed sentinel ensuring that unavailability of all backends results in request denial, not pass-through. SSO via OIDC and SAML v2, SCIM automated provisioning, response masking, and payload masking before AI inspection rounded out the release.

### 4.22 v0.2.0 — Transport Security and Operational Robustness

TLS bootstrap was added with full support for ACME certificate provisioning (Let's Encrypt / ACME-compatible CAs), local CA signing, and self-signed certificates for air-gapped environments. Prometheus metrics provided the first visibility into gateway operations. Admin account management was strengthened: bcrypt was added alongside Argon2, multiple admin accounts became supported with minimum-count enforcement (preventing accidental lockout), and admin account lockout protection was implemented to resist brute-force attacks.

### 4.23 v0.1.0 — Core Security Gateway

The initial release established the core security envelope. Yashigani began as a functional MCP reverse proxy with a meaningful security stack: prompt injection detection using a locally-hosted Ollama model, credential harvesting suppression on all payloads, OPA-based policy enforcement, session and API key authentication, TOTP-based two-factor authentication, Argon2 password hashing, file-based audit logging, and Redis rate limiting. This version made it possible to safely expose MCP servers to agents in a controlled environment.

---

## 5. Complete Feature List

### 5.1 Authentication and Identity

- Username and password authentication (Argon2 and bcrypt hashing)
- TOTP / HOTP two-factor authentication (2FA)
- API key authentication
- Session-based authentication with secure cookie management
- Bearer token authentication for agent routing
- JWT introspection with JWKS waterfall (3 deployment streams: opensource / corporate / SaaS)
- OpenID Connect (OIDC) SSO — Starter and above
- SAML v2 SSO — Professional and above
- SCIM automated user provisioning and deprovisioning — Professional and above
- Multiple admin accounts with minimum-count enforcement
- **Dual admin accounts provisioned at install (v0.9.1, v1.09.5)** — two accounts with fun animal/nature-themed codenames created during installation; TOTP 2FA pre-provisioned for both at install time
- Admin account lockout protection (brute-force resistance)
- **HIBP k-Anonymity breach check on password change (since v0.9.1)** — `PasswordBreachedError` raised on known-breached passwords; OWASP ASVS V2.1.7 compliant; fail-open if API unreachable
- **Unified identity model (since v2.0)** — every entity (human or service) is an identity with a `kind` field; no separate user/agent stores; same governance, budget, RBAC, and audit for all identity kinds
- **Multi-IdP Identity Broker (since v2.0)** — Yashigani IS the identity broker; OIDC + SAML v2 native; Caddy delegates auth to backoffice; SCIM provisions users/groups; IdP limits tier-gated
- **User API keys (since v2.0)** — 256-bit hex, bcrypt cost 12, max lifetime 1 year hard limit, default rotation 90 days, 7-day grace period, 14-day warning
- **PKCE on OIDC (since v2.22)** — code_verifier/code_challenge on all OIDC flows; prevents authorization code interception
- **acr/amr validation (since v2.22)** — authentication strength enforcement on ID tokens
- **__Host- cookie prefix (since v2.22)** — session cookies enforce Secure, Path=/, no Domain attribute
- **Fail2ban auth throttle (since v2.22)** — per-IP (3 failures) + global (5 failures), x5 escalation (30s-625m), permanent IP block after max
- **Self-service password reset (since v2.22)** — TOTP-verified, no admin needed
- **Context-specific password word list (since v2.22)** — blocks "yashigani", "admin", "password" etc.
- **Password max age policy (since v2.23)** — admin-configurable via `YASHIGANI_PASSWORD_MAX_AGE_DAYS` (max 13 months)

### 5.2 Authorization and Policy

- Open Policy Agent (OPA) policy engine
- RBAC (Role-Based Access Control) via OPA
- Per-tool, per-route, per-agent policy enforcement
- URL allowlist enforcement (SSRF prevention)
- Hot-reloadable policies without gateway restarts
- Multi-organization support (Enterprise tier)
- Agent and organization limits enforced per license tier
- **OPA Policy Assistant** — natural language → RBAC JSON suggestion with admin approve/reject flow and full audit trail (since v0.7.0)
- **CIDR-based IP allowlisting per agent** — requests from authenticated agents outside their IP allowlist are blocked 403 and audited
- **OPA routing safety net (since v2.0)** — second OPA pass on every routing decision; local LLM validates OPA policy changes before applying (checks for self-lock, contradictions, scope issues, routing conflicts); SAFE/WARNING/BLOCK verdicts
- **OPA on ALL /v1 traffic (since v2.22)** — request path AND response path enforcement on every `/v1/chat/completions` request; fail-closed if OPA unreachable
- **IP allowlist + blocklist (since v2.22)** — IPv4/IPv6/CIDR, admin manageable; blocklist takes precedence
- **Content relay detection (since v2.22)** — agent-to-agent content laundering detection

### 5.3 Content Inspection and AI Safety

- scikit-learn ML first-pass classifier (TF-IDF + LogisticRegression, joblib serialised, offline, under 5ms latency; replaced FastText in v2.23.3)
- Multi-backend LLM inspection chain:
  - Ollama (local)
  - Anthropic Claude
  - Google Gemini
  - Azure OpenAI
  - LM Studio
- Inspection backend fallback chain with fail-closed sentinel
- Prompt injection detection
- Credential Harvesting Suppression (CHS) on request and response payloads
- Payload masking before AI inspection (secrets not sent to external LLM APIs)
- Response masking and sanitization
- Anomaly detection: repeated-small-call pattern detection (Redis ZSET sliding window)
- Inference payload logging (AES-256-GCM encrypted, stored in Postgres)
- **Sensitivity classification pipeline (since v2.0)** — three layers, all ON by default: regex pattern matching (PII, PCI, IP, PHI), scikit-learn ML classifier (TF-IDF + LogisticRegression since v2.23.3; FastText pre-v2.23.3), Ollama LLM classification; admin can opt out of Ollama but cannot disable regex; results feed into Optimization Engine routing
- **Optimization Engine (since v2.0)** — four-dimensional routing (sensitivity + complexity + budget + cost); P1-P9 priority matrix; CONFIDENTIAL/RESTRICTED always local; budget exhaustion degrades to local, never rejects
- **Model alias table (since v2.0)** — DB-driven via admin API, Postgres + Redis cache, CRUD at `/admin/models/aliases`
- **Agent personas (since v2.22)** — Lala (Langflow), Julietta (Letta), Scout (OpenClaw) with descriptions and example prompts
- **Agent chaining (since v2.22)** — invoke multiple agents in one prompt (e.g., `@Scout` -> `@Julietta` -> `@qwen`); `@Help` agent provides chaining guide

### 5.4 Audit and Compliance

- Structured JSON audit logging
- Multi-sink audit writer (simultaneous delivery):
  - Local file
  - PostgreSQL 16 (RLS + AES-256-GCM column encryption)
  - Splunk
  - Elasticsearch
  - Wazuh SIEM
- PostgreSQL audit tables with row-level security
- Monthly partition management via pg_partman, pg_cron, and Kubernetes CronJob (since v0.7.0)
- Partition bootstrap migration pre-creates 14 months of partitions at install time (since v0.7.1)
- Full request/response payload capture per audit event
- Inspection verdict recorded per audit event
- OPA policy decision recorded per audit event
- Agent identity recorded per audit event
- Wazuh self-hosted SIEM integration
- Audit events for: IP allowlist violations, rate limit threshold changes, OPA assistant generate/apply/reject (since v0.7.0)
- **Routing decisions as audit events (since v2.0)** — every OE routing decision written to all SIEM sinks via existing audit pipeline
- **P1-P5 alert severity scale (since v2.0)** — sensitivity breach (P1), OPA override (P1), classification conflict (P2), spending anomaly (P2), budget auto-switch (P3); SIEM integration for all severity levels
- **Audit log viewer (since v2.22)** — search, filter, and CSV export from the admin panel
- **OWASP compliance review (since v2.22)** — OWASP ASVS v5 (all 17 chapters) + API Security + Agentic AI / LLM Top 10; per-control verdicts with file:line evidence; pre-release gate
- **Risk register (since v2.22)** — 16 risks with 5x5 matrix and quantitative analysis

### 5.5 Rate Limiting and Abuse Prevention

- Per-endpoint rate limiting (Redis fixed-window)
- Response caching for CLEAN-only verdicts (SHA-256 keyed, Redis-backed)
- Anomaly detection for enumeration and bulk extraction patterns
- Admin account lockout on repeated failed authentication
- **Auth throttle (in-process, fail2ban-style)** — per-IP (3 failures) + global (5 failures) thresholds; ×5 delay escalation (30s → 60s → 300s → 1500s → 7500s, cap 37500s); IP block after maximum escalation. Implemented inline at `backoffice/routes/auth.py` — no separate fail2ban daemon required (since v2.22)
- **Runtime-configurable RPI scale thresholds** — tune medium/high/critical throttle multipliers from the backoffice without a gateway restart; changes audited (since v0.7.0)

### 5.6 Budget Governance (since v2.0)

- **Three-tier budget hierarchy** — org cloud cap → group budgets → individual budgets; math always enforced
- Sum of individual budgets never exceeds group budget; sum of group budgets never exceeds org cap
- Group-first provisioning: admin sets group budget, offers even distribution across individuals
- User-first provisioning: group budget auto-calculated from sum of individuals
- New user added to group: admin prompted to increase group budget or reduce existing individual budgets
- **Budget-redis** — dedicated Redis container with noeviction policy; prevents counter eviction under memory pressure
- **Budget response headers** — `X-Yashigani-Budget-*` headers expose remaining budget to clients
- Budget exhaustion triggers graceful degradation to local inference; system never rejects

### 5.7 Cryptography and Secrets

- Argon2 password hashing
- bcrypt password hashing
- AES-256-GCM column encryption in PostgreSQL via pgcrypto
- Several KMS supported - Keeper Security, AWS, GCP, Azure and HashiCorp Vault
- ECDSA P-256 offline licence signature verification (since v0.9.0) — ML-DSA-65 migration planned when cryptography library ships FIPS 204 support
- Hybrid TLS X25519+ML-KEM-768 Caddyfile config included (pending Caddy 2.10) (since v0.9.0)
- TLS bootstrap: ACME (Let's Encrypt / ACME-compatible), CA-signed, self-signed (demo)
- **Constant-time TOTP comparison (since v2.22)** — `hmac.compare_digest` prevents timing side-channel attacks
- **Crypto inventory API (since v2.22)** — `/admin/crypto/inventory` exposes all algorithms, key sizes, and usages; admin UI with JSON export
- **In-tree two-tier PKI (since v2.23.1)** — `yashigani.pki.issuer` generates root + intermediate + per-service leaves at install time; rotation via `install.sh rotate-*` or `/admin/settings/internal-pki` API
- **Optional ACME runtime CA (since v2.23)** — Smallstep step-ca compose service (`--with-internal-ca`) for deployments that want ACME-style runtime cert lifecycle on top of (or instead of) the in-tree issuer
- **Domain-bound licensing (since v2.23)** — license keys bound to deployment domain via ECDSA P-256 signatures

### 5.8 Observability and Alerting

- Prometheus metrics (gateway, inspection, rate limiting, policy, database)
- Grafana dashboards
- OpenTelemetry distributed tracing (OTLP export to Jaeger)
- Loki log aggregation + Promtail log shipping
- Alertmanager 3-channel escalation: Slack + email (level 1) → PagerDuty (level 2)
- **Direct webhook alerting** — Slack, Microsoft Teams, PagerDuty as lightweight sinks for P1 events, independent of Alertmanager (since v0.7.0)
- **`yashigani_audit_partition_missing` gauge** — fires when an upcoming monthly audit partition is absent; paired Alertmanager alert rule at `severity: critical` (since v0.7.0)
- **Licence expiry background monitor** — daily check dispatches warning/critical alert when licence is within configurable day threshold (since v0.7.1)
- Structured JSON logging throughout all components
- **12 Grafana dashboards (since v2.0)** — 9 existing + 3 new: budget monitoring, Optimization Engine routing, Pool Manager container lifecycle
- **Grafana + Prometheus admin access (since v2.22)** — accessible at `/admin/grafana/` and `/admin/prometheus/` via Caddy forward_auth
- **Monitoring tab (since v2.22)** — admin UI tab with Grafana dashboard links, Prometheus, and Wazuh
- **Wazuh SIEM full stack (since v2.22)** — manager + indexer + dashboard as optional compose profile (`--wazuh`)
- **Dashboard auto-refresh (since v2.22)** — 15-second interval on admin dashboard
- **Session timeout warning (since v2.22)** — 10-minute banner before session expiry
- **First-run onboarding checklist (since v2.22)** — guided setup for new installations
- **CSP report endpoint (since v2.23)** — Content Security Policy violation reporting

### 5.9 Infrastructure and Deployment

- Universal installer (Linux, macOS, cloud VM; auto-detects OS, arch, cloud provider, GPU, and container runtime)
- GPU detection at install time: Apple Silicon M-series (unified memory, Metal, ANE), NVIDIA (nvidia-smi, CUDA), AMD (rocm-smi, ROCm), lspci fallback; model recommendations printed based on detected VRAM (since v0.8.4)
- Podman support as first-class runtime alongside Docker Engine and Docker Desktop (v0.8.4; runtime detection, compose command selection, and auto-apply podman override in v1.09.5)
- Interactive fallback prompts when OS, runtime, or GPU detection fails (since v0.8.4)
- `update.sh` script for updating existing installations with automatic backup, pull, restart, and rollback (since v0.8.4)
- Docker Compose single-node deployment
- Kubernetes Helm charts (production-ready)
- KEDA horizontal autoscaling
- Pod disruption budgets (HA)
- Kubernetes network policies
- Multi-replica deployment support
- GitHub Actions CI/CD pipeline
- Trivy container vulnerability scanning
- CODEOWNERS and branch protection enforcement
- Container hardening:
  - seccomp allowlist
  - AppArmor profile
  - UID 1001 non-root execution
  - tmpfs mounts for `/tmp` and audit buffer
  - Read-only root filesystem
- PgBouncer PostgreSQL connection pooling
- **Agent bundle containers** (v0.8.0, GA in v1.09.5, personas in v2.22) — Lala (Langflow), Julietta (Letta), Scout (OpenClaw) as opt-in Docker Compose profiles; installer auto-registers bundles with PSK tokens; all agent traffic routes through Yashigani's enforcement layer; images are digest-pinned per release; third-party courtesy integrations (no support obligation)
  - **Lala** — Langflow (port 8000) — multi-agent orchestration framework; shares Postgres (separate DB) and Redis (DB 5)
  - **Julietta** — Letta (port 8283) — Stateful agent with persistent memory (formerly MemGPT)
  - **Scout** — OpenClaw (port 18789) — personal AI with 30+ messaging integrations; `OPENCLAW_CONFIG_JSON` routes through gateway
- **Agent chaining (since v2.22)** — invoke multiple agents in a single prompt (`@Scout` -> `@Julietta` -> `@qwen`); `@Help` agent provides chaining guide
- **Open WebUI integration (since v2.0)** — optional chat interface at `/chat/*` (`--with-openwebui`), internal Docker network only (no external port), all LLM calls through gateway, Caddy forwards trusted headers
- **Container Pool Manager (since v2.0)** — per-identity container isolation; universal lifecycle: create, route, health check, replace, scale, postmortem; self-healing (replace, don't fix); postmortem forensics (logs, inspect, filesystem diff preserved before kill); Ollama horizontal scaling on load
- **Dynamic per-identity containers (since v2.0)** — managed by Pool Manager; license tier gates container limits
- **17 always-on core services + 10 optional services via compose profiles (since v2.23)** — up from 18 in v1.09.5; plus dynamic per-identity containers managed by the Pool Manager
- **548 tests passing (since v2.20)** — 523 unit + 25 e2e
- **Optional services via compose profiles (since v2.23)** — openwebui, wazuh, internal-ca, langflow, letta, openclaw; controlled by installer flags
- **Admin service management (since v2.23)** — enable/disable any optional service from the admin panel without SSH
- **Optional ACME runtime CA (since v2.23)** — Smallstep step-ca compose service (`--with-internal-ca`) for deployments that want runtime ACME cert management; in-tree two-tier PKI issuer at install time provides default-on mTLS without it
- **Strict CSP (since v2.23)** — `script-src 'self'; style-src 'self'`, zero `unsafe-inline`, `object-src none`, `base-uri none`, `cross-origin-opener-policy: same-origin`
- **API-first admin UI (since v2.23)** — static SPA with external JS/CSS; all logic in backend APIs; no Jinja2 templates, no inline code
- **restore.sh (since v2.23)** — backup recovery for secrets, `.env`, and Postgres dumps
- **macOS Podman support (since v2.23)** — socket detection via `podman machine inspect`

### 5.10 Licensing and Tiers

- 6-tier licensing model: Community / Non-profit & Education / Starter / Professional / Professional Plus / Enterprise
- ECDSA P-256 offline license verification — no call-home, works air-gapped (since v0.9.0) — ML-DSA-65 migration planned when cryptography library ships FIPS 204 support
- Three independent limit dimensions: agents, end users, admin seats
- **Agent limits per tier:** Community (20), Non-profit & Education (1,500), Starter (300), Professional (1,500), Professional Plus (15,000), Enterprise (unlimited)
- **End-user limits per tier:** Community (5), Non-profit & Education (500), Starter (100), Professional (500), Professional Plus (5,000), Enterprise (unlimited)
- **Admin-seat limits per tier:** Community (2), Non-profit & Education (25), Starter (10), Professional (25), Professional Plus (100), Enterprise (unlimited)
- **Container limits per tier (since v2.0):** Community (1 per service per identity, 3 total), Non-profit & Education (3/15), Starter (1/5), Professional (3/15), Professional Plus (5/50), Enterprise (unlimited)
- **IdP limits per tier (since v2.0):** Community (local auth only), Non-profit & Education (1 OIDC; SAML available as optional add-on), Starter (1 OIDC), Professional (1 OIDC + 1 SAML), Professional Plus (5 IdPs), Enterprise (unlimited)
- Community tier: free, Apache 2.0, 20 agents, 5 end users, 2 admins, 1 org
- Non-profit & Education tier: £500/yr base (verified institution: 501(c)(3), registered charity, accredited educational institution, or .edu primary domain) — covers verification + admin ops cost. **Partnership waiver available** — fee waived in exchange for non-monetary contribution agreed via MOU (co-authored whitepaper, inclusion in research papers, designated consulting access from institutional experts, or equivalent value). Features: OIDC + SCIM, 1,500 agents, 500 end users, 25 admin seats. SAML v2 available as optional paid add-on
- Starter, Professional, Professional Plus, Enterprise: signed license key required
- See agnosticsec.com/pricing for current tier limits and pricing
- Apache 2.0 open-source community license with Contributor License Agreement (CLA)

---

## 6. Deployment Topologies

### 6.1 Docker Compose — Single Node

The simplest production-capable deployment. The universal installer generates a `docker-compose.yml` with all services pre-configured. The full stack comprises **17 always-on core services** plus **10 optional services** activated via compose profiles or installer flags, plus dynamic per-identity containers managed by the Pool Manager.

```
docker-compose.yml — 17 always-on core services
├── caddy                   # TLS termination / reverse proxy / auth delegation
├── gateway                 # Core proxy + Optimization Engine, port 8443 (TLS)
├── backoffice              # Admin API/UI + identity broker, port 8080 (includes Alembic migrations)
├── policy                  # OPA policy engine, port 8181
├── postgres                # Audit + config + identity store (pgvector/pgvector:pg16)
├── pgbouncer               # PostgreSQL connection pooler (password from .env)
├── redis                   # Rate limiting + response caching + anomaly detection
├── budget-redis            # Budget counters, port 6380 (noeviction policy, v2.0)
├── ollama                  # Local LLM inference
├── ollama-init             # Model pull on first start
├── prometheus              # Metrics scrape
├── grafana                 # 12 dashboards (9 existing + 3 new: budget, OE, pool manager)
├── loki                    # Log aggregation
├── promtail                # Log shipping
├── alertmanager            # Alert routing (P1-P5 severity)
├── otel-collector          # OpenTelemetry receiver (mTLS)
└── jaeger                  # Distributed tracing UI / OTLP exporter

10 optional services — activated via compose profile / installer flag
├── open-webui              # Chat interface, port 3000 (--with-openwebui)
├── keycloak                # Test IdP for SSO development (test-idp profile)
├── vault                   # HashiCorp Vault KMS backend (vault profile)
├── step-ca                 # Smallstep step-ca runtime ACME (--with-internal-ca)
├── wazuh-manager           # Wazuh SIEM manager (--wazuh)
├── wazuh-indexer           # Wazuh SIEM indexer (--wazuh)
├── wazuh-dashboard         # Wazuh SIEM dashboard (--wazuh)
│
│   Agent bundles (auto-registered with PSK tokens, --agent-bundles)
├── langflow                # Lala — multi-agent orchestration framework, port 8000
├── letta                   # Julietta — stateful agent with persistent memory, port 8283
└── openclaw                # Scout — personal AI with 30+ messaging integrations, port 18789

    Dynamic containers (v2.0 — managed by Pool Manager)
    Per-identity isolated containers, created/destroyed on demand
```

Suitable for: development, staging, small production workloads, air-gapped environments.

**Minimum hardware:** 4 vCPU, 8 GB RAM, 50 GB SSD.
**Recommended hardware:** 8 vCPU, 16 GB RAM, VRAM 8 GB (Ollama), 80 GB SSD.

### 6.2 Kubernetes — High-Availability Multi-Replica

Yashigani ships production-ready Helm charts for Kubernetes. The gateway deployment runs multiple replicas with KEDA-based horizontal autoscaling driven by Prometheus metrics. Pod disruption budgets prevent simultaneous eviction of all gateway replicas during node maintenance. Kubernetes network policies restrict lateral traffic: only the gateway can reach the inspection backends, only the audit writer can reach the database.

```
Namespace: yashigani
├── Deployment: gateway          (replicas: 3+, HPA via KEDA; includes OE)
├── Deployment: backoffice       (replicas: 2; identity broker)
├── Deployment: open-webui       (internal only, v2.0)
├── StatefulSet: postgres        (or external RDS/CloudSQL)
├── Deployment: pgbouncer
├── StatefulSet: redis           (or external ElastiCache)
├── StatefulSet: budget-redis    (noeviction, v2.0)
├── StatefulSet: vault           (or external HCP Vault)
├── Deployment: prometheus
├── Deployment: grafana          (12 dashboards)
├── StatefulSet: loki
├── DaemonSet: promtail
├── Deployment: alertmanager
├── Deployment: jaeger
└── DaemonSet: pool-manager      (per-identity containers, v2.0)
```

Suitable for: production workloads requiring high availability, rolling updates, and auto-scaling.

**Helm install:**
```bash
helm repo add yashigani https://charts.agnosticsec.com
helm install yashigani yashigani/yashigani \
  --namespace yashigani --create-namespace \
  --values values-production.yaml
```

### 6.3 Cloud Managed — AWS / GCP / Azure

The universal installer auto-detects the cloud provider via instance metadata and configures cloud-native service integrations:

| Component | AWS | GCP | Azure |
|---|---|---|---|
| Database | RDS PostgreSQL 16 | Cloud SQL | Azure Database for PostgreSQL |
| Cache | ElastiCache Redis | Memorystore | Azure Cache for Redis |
| Secrets | AWS Secrets Manager | Secret Manager | Azure Key Vault |
| TLS | ACM | Certificate Manager | App Gateway / Front Door |
| Metrics | CloudWatch + Prometheus | Cloud Monitoring | Azure Monitor |
| Load Balancer | ALB / NLB | Cloud Load Balancing | Azure Load Balancer |

Gateway nodes run on EC2 / GCE / Azure VMs or as Kubernetes deployments on EKS / GKE / AKS. All stateful services (Postgres, Redis, Vault) can be replaced with cloud-managed equivalents — the gateway configuration accepts standard connection strings.

---

## 7. Roadmap Context

Yashigani v2.23 is the current production release. v2.23 consolidates the product to a single branch (`main`). The `release/1.x` branch is retired. Open WebUI, Wazuh, the optional Smallstep step-ca runtime ACME service, and agent bundles are all optional compose profiles controlled by installer flags. The admin UI was refactored to a static SPA (API-first, external JS/CSS, no inline code), enabling strict Content Security Policy (`script-src 'self'; style-src 'self'`, zero `unsafe-inline`). Administrators can enable/disable services from the admin panel. The in-tree two-tier PKI (`yashigani.pki.issuer`) generates per-service leaves at install time so core-plane mTLS is default-on without external services. Domain-bound licensing ties keys to deployment domains.

v2.22.x delivered OPA enforcement on all /v1 traffic (request + response path), agent personas (Lala, Julietta, Scout) with chaining support, fail2ban-style auth throttling with IP allowlist/blocklist, and a comprehensive OWASP compliance review. Content relay detection, PKCE on OIDC, acr/amr validation, constant-time TOTP comparison, crypto inventory API, and __Host- cookie prefix rounded out the security hardening.

v2.20 closed OWASP ASVS Level 3 gaps with PII detection (3 modes, 10 entity types, bidirectional, cloud bypass), container hardening (seccomp, AppArmor, read-only filesystem), WAF/DDoS protection, streaming chunk-level inspection, SBOM + cosign image signing, and two STRIDE threat models. v2.1 added the Admin Dashboard. v2.0 introduced the Unified Identity Model, Optimization Engine, Budget System, Open WebUI integration, and Container Pool Manager.

**Single branch:** `main` — all features, all tiers. Optional services are compose profiles:
- `--with-openwebui` — Open WebUI chat interface
- `--wazuh` — Wazuh SIEM full stack
- `--with-internal-ca` — Smallstep step-ca compose service for runtime ACME cert management (the in-tree PKI issuer already provides default-on mTLS at install time)
- `--agent-bundles lala,julietta,scout` — Agent bundles (or `all`)

The progression from v0.1.0 through v2.23 reflects a deliberate security maturity arc: from a minimal viable security proxy to a full enterprise-grade AI operations platform with intelligent routing, budget governance, unified identity management, supply-chain assurance, strict CSP, OWASP ASVS v5 / API Security / Agentic AI compliance review, and an ecosystem of integrated third-party agents. Each version maintained backward compatibility while adding layers of defense. The result is a system where no single component failure — inspection backend unavailability, database outage, KMS unreachability, budget exhaustion — results in an insecure pass-through or silent rejection. Every failure mode has been designed to be fail-closed or gracefully degraded.

### 7.1 v2.23 Delivered

v2.23 consolidates Yashigani to a single branch and delivers the API-first admin refactor with strict CSP.

- **Branch consolidation** — `release/1.x` eliminated; Open WebUI is `--with-openwebui` flag, not a separate branch
- **API-first admin UI** — static SPA with external JS/CSS; no Jinja2 templates, no inline code; all logic in backend APIs
- **Strict CSP** — `script-src 'self'; style-src 'self'`, zero `unsafe-inline`; `object-src none`, `base-uri none`, `cross-origin-opener-policy: same-origin`, CSP report endpoint
- **Optional services via compose profiles** — openwebui, wazuh, internal-ca, langflow, letta, openclaw; controlled by installer flags
- **Admin service management** — enable/disable any service from admin panel (no SSH required)
- **In-tree two-tier PKI** — `yashigani.pki.issuer` generates root + intermediate + per-service leaves at install time; default-on mTLS without optional services
- **Optional ACME runtime CA** — Smallstep step-ca compose service (`--with-internal-ca`) for deployments preferring runtime ACME cert management
- **Domain-bound licensing** — ECDSA P-256 signed; license keys bound to deployment domain
- **Podman socket detection on macOS** — finds socket path from `podman machine inspect`
- **Container socket mount read-only** — macOS Podman compatibility
- **restore.sh** — backup recovery for secrets, `.env`, and Postgres dumps
- **Admin-configurable password policy** — `YASHIGANI_PASSWORD_MAX_AGE_DAYS` (max 13 months)

### 7.2 v2.22.x Delivered

v2.22.x is a multi-release series delivering OPA on /v1, agent personas, fail2ban, and the comprehensive OWASP compliance review.

- **OPA on ALL /v1 traffic** — request path AND response path enforcement on every `/v1/chat/completions` request; fail-closed if OPA unreachable
- **Agent personas** — Lala (Langflow), Julietta (Letta), Scout (OpenClaw) with descriptions and example prompts
- **Agent chaining** — `@Scout` -> `@Julietta` -> `@qwen` in one prompt; `@Help` agent provides chaining guide
- **Fail2ban auth throttle** — per-IP (3 failures) + global (5 failures), x5 escalation (30s -> 1m -> 5m -> 25m -> 2h -> 10h), permanent IP block after max
- **IP allowlist + blocklist** — IPv4/IPv6/CIDR, admin manageable; blocklist takes precedence
- **Content relay detection** — agent-to-agent content laundering detection
- **PKCE on OIDC** — code_verifier/code_challenge on all OIDC flows
- **acr/amr validation** — authentication strength enforcement on ID tokens
- **Constant-time comparisons** — `hmac.compare_digest` for TOTP verification
- **Crypto inventory API** — `/admin/crypto/inventory` + admin UI with JSON export
- **__Host- cookie prefix** — session cookies enforce Secure, Path=/, no Domain attribute
- **Context-specific password word list** — blocks "yashigani", "admin", "password" etc.
- **Self-service password reset** — TOTP-verified, no admin needed
- **OWASP compliance review** — OWASP ASVS v5 (all 17 chapters) + API Security + Agentic AI / LLM Top 10; per-control PASS / PARTIAL / FAIL / N/A with file:line evidence; open items tracked as accepted-risk exceptions in the risk register
- **Risk register** — 16 risks with 5x5 matrix and quantitative analysis; pre-release gate
- **Podman SDK** (podman-py) for container-per-user isolation
- **Grafana + Prometheus admin access** — `/admin/grafana/` and `/admin/prometheus/` via Caddy forward_auth
- **Monitoring tab** — Grafana dashboards + Prometheus + Wazuh links in admin UI
- **Wazuh SIEM full stack** — manager + indexer + dashboard as optional compose profile (`--wazuh`)
- **Budget allocation wiring** — per-identity from Redis, not hardcoded
- **Postgres migrations on startup** — pg_partman/pg_cron optional
- **Dashboard auto-refresh** (15s), full agent registration form, audit log viewer with search/filter/export CSV, session timeout warning (10 min), first-run onboarding checklist, login branding (Agnostic Security footer)
- Goose agent removed (ACP too slow on CPU)

### 7.3 v0.8.0 Delivered

v0.8.0 addressed operator demand for first-class agentic framework support without forcing Yashigani's security boundary to become optional. LangGraph, Goose, and OpenClaw are available as opt-in Docker Compose profiles and Helm toggles — all agent traffic from these containers routes through Yashigani's enforcement layer and is subject to the same inspection, authorization, and audit pipeline as any other agent. A new `GET /admin/agent-bundles` endpoint exposes the bundle catalogue with metadata and a third-party disclaimer for the UI banner. `GET /admin/agents/{id}/quickstart` returns copy-paste curl, Python httpx, and health check snippets on the agent detail page, reducing time-to-first-call for new agent deployments. The rate limit config endpoint was extended with a `last_changed` timestamp, making threshold change history auditable without requiring a full audit log query.

### 7.4 v0.8.4 Delivered

v0.8.4 addressed a cluster of installer failures discovered after v0.8.0 shipped — specifically on macOS with Apple Silicon, Podman, and Docker Desktop environments. Platform detection was fixed by correcting a variable naming mismatch (`DETECTED_*` vs `YSG_*`) that caused the platform summary to report incorrect values. GPU detection was added for Apple Silicon M-series (unified memory, Metal, ANE), NVIDIA, and AMD GPUs with an lspci fallback; Ollama model size recommendations are printed based on detected VRAM. The macOS `df -BG` (GNU-only) flag was replaced with `df -k` and compatible arithmetic. Podman became a first-class supported runtime alongside Docker Engine and Docker Desktop. A Docker Desktop CLI auto-fix was added for environments where Docker Desktop is installed but `docker` is not in PATH. Bash 3.2 compatibility was enforced throughout by replacing all `${var,,}` expansions with `tr`. Agent bundle selection was changed from individual y/n prompts to a numbered menu, eliminating typo-related crashes. A new `update.sh` script handles in-place upgrades with automatic backup, image pull, restart, and rollback on failure. A 7-test automated installer validation suite (`test-installer.sh`) covering 28 checks was added to CI.

### 7.5 v0.9.0 Delivered

**Phase 1 — Cryptography and Licensing**
- **ECDSA P-256 licence signing** — production key embedded across `keygen.py`, `sign_license.py`, and `verifier.py`; ML-DSA-65 (FIPS 204) migration planned when the cryptography library ships FIPS 204 support
- **`LicenseFeature` enum** — OIDC, SAML, SCIM feature gates replaced with typed enum (replaces `frozenset[str]`)
- **Academic / Non-Profit tier** — added to `LicenseTier` enum; full tier support in verifier and feature gate logic
- **Community tier limits** — updated to v0.8.4 values (5 agents, 10 users, 2 admins)
- **Hybrid TLS Caddyfile config** — X25519+ML-KEM-768 configuration included (commented — pending Caddy 2.10)

**Phase 2 — Response-Path Inspection (F-01)**
- **`ResponseInspectionPipeline`** — FastText + LLM fallback applied to upstream responses, closing the indirect prompt injection vector
- **Per-agent config** — `fasttext_only` flag and `exempt_content_types` (default: `application/json`) configurable per agent
- **BLOCKED → 502** — tainted upstream responses return 502 to the client; FLAGGED responses forwarded with `X-Yashigani-Response-Verdict` header
- **`response_inspection_verdict`** — added to all audit events; `RESPONSE_INJECTION_DETECTED` event type added

**Phase 3 — Production Hardening**
- **PH-A: Break-glass** — hard TTL (1–72h, default 4h), dual-control approval, Redis-backed activation state, tamper-evident audit events
- **PH-B: Audit hash chain** — SHA-384 Merkle chain with daily anchors, `audit_verify.py` CLI for chain integrity verification, Prometheus gauge for chain health
- **PH-C: Async SIEM queue** — Redis RPUSH/LPOP delivery queue, batched transmission, DLQ after 3 retries, Prometheus gauges for queue depth and DLQ size
- **PH-D: Agent PSK auto-rotation** — APScheduler cron-based rotation, KMS push on rotation, grace period for concurrent token acceptance, `token_last_rotated` field in agent API response

**Phase 6 — WebAuthn / Passkeys (S-01)**
- **`WebAuthnService`** — registration and authentication ceremonies via `py_webauthn`
- **`WebAuthnCredentialRow`** — DB model with `pgp_sym_encrypt` at-rest encryption
- **6 backoffice endpoints** — `/auth/webauthn/register/begin`, `/auth/webauthn/register/complete`, `/auth/webauthn/authenticate/begin`, `/auth/webauthn/authenticate/complete`, `/auth/webauthn/credentials`, `/auth/webauthn/credentials/{id}` (DELETE)
- **TOTP coexistence** — both TOTP and WebAuthn remain available; WebAuthn is preferred when a credential is registered
- **Audit events** — `WEBAUTHN_CREDENTIAL_REGISTERED`, `WEBAUTHN_CREDENTIAL_USED`, `WEBAUTHN_CREDENTIAL_DELETED`

**Phase 7 — Operator Visibility**
- **`EventBus`** — asyncio pub/sub with 512-entry per-subscriber queue; gateway publishes all inspection events
- **SSE real-time inspection feed** — `GET /admin/events/inspection-feed` streams live inspection verdicts with 15-second heartbeat
- **Audit log search** — `GET /admin/audit/search` with 7 filter parameters (event type, agent, user, verdict, date range, cursor) and cursor-based pagination
- **Audit log export** — `GET /admin/audit/export` delivers CSV or JSON with 10,000-row cap and streaming response

**Installer redesign**
- **Three deployment modes** — Demo (1) / Production (2) / Enterprise (3) via `--deploy` flag (replaces `--mode`)
- **AES key provisioning** — auto-generate (default) or BYOK with `--aes-key` flag
- **`--offline` flag** — air-gapped installation support
- **Demo mode** — localhost, self-signed, auto-generate everything, 1–2 prompts maximum

### 7.6 v0.9.1 Delivered

v0.9.1 hardened the credential bootstrap process that v0.9.0's installer redesign had left incomplete. Rather than generating a single admin account and requiring operators to create additional accounts manually, the installer now creates two admin accounts at install time with randomly generated themed usernames — eliminating the single-admin lockout risk from day one. TOTP 2FA is fully provisioned for both accounts during installation: the TOTP secret and `otpauth://` URI are generated, displayed, and immediately ready for import into any authenticator app. All generated passwords are checked against the Have I Been Pwned breach database using SHA-1 k-Anonymity prefix lookup before use; any compromised password is automatically regenerated and rechecked. The same HIBP check was added to the backoffice password-change path, implementing OWASP ASVS V2.1.7. A one-time credential summary block is displayed at the end of install showing all passwords, TOTP secrets, URIs, and the AES key with a prominent warning that the summary will not be shown again. All credentials are persisted to `docker/secrets/` with permissions 0600; existing secrets survive in-place upgrades.

### 7.7 v0.9.2 Delivered

v0.9.2 fixed two regressions introduced during the v0.9.0 installer redesign. The `.env` writer was incomplete: only the AES key was being written before `docker compose pull` ran, causing `UPSTREAM_MCP_URL` to be undefined in the compose environment and producing a startup error on fresh installs. The function was expanded into a full `.env` writer that sets all required variables — `UPSTREAM_MCP_URL`, `YASHIGANI_TLS_DOMAIN`, `YASHIGANI_ADMIN_EMAIL`, `YASHIGANI_ENV`, and the AES key — before compose is invoked. Demo mode defaults `UPSTREAM_MCP_URL` to `http://localhost:8080/echo`. Additionally, `update.sh` used a process substitution (`< <(find ...)`) that is a bash 4+ feature not available in macOS's default bash 3.2; this was replaced with a `find | while read` pipe that is fully compatible.

### 7.8 v0.9.3 Delivered

v0.9.3 was a structured 45-issue audit hardening release — the most comprehensive single-version quality pass in the project's history. Three functional blockers were closed: an authentication bypass in the per-endpoint rate limiting layer; a recursive call path in `OllamaPool` that caused a stack overflow under pool exhaustion; and a Vault KMS provider initialization failure on cold start. The `ResponseInspectionPipeline` introduced in v0.9.0 was wired into the gateway but never invoked in the default request path — v0.9.3 activated it, closing the response-path injection vector that v0.9.0 had intended to address. The ECDSA P-256 production public key was committed, making license tier enforcement fully active for all tiers for the first time since v0.7.0 shipped the key infrastructure. Every image in `docker-compose.yml` and the Helm charts was pinned to a digest, eliminating mutable-tag supply-chain risk. The `WebAuthnCredentialRow` Alembic migration was added so upgrades from v0.9.0–v0.9.2 apply cleanly without manual schema intervention. An end-to-end integration test suite was shipped covering auth, inspection, rate limiting, audit write, and license gate paths. Eighteen `except Exception: pass` bare-exception handlers were replaced with structured logging throughout the gateway and backoffice — previously silent failures became observable. A CI license key gate was added to validate the verifier before any build proceeds. Redis `keys()` calls were replaced with `scan_iter()` to eliminate blocking full-keyspace scans under load. IPv6 address handling was corrected in audit event IP masking and CHS.

### 7.9 v0.9.4 Delivered

v0.9.4 is the final hardening release before v2.0 development begins. It closes the last known security-relevant bug in the inspection pipeline: the classifier's JSON extraction regex silently misclassified valid injection detections as CLEAN when the LLM response included nested objects in the `detected_payload_spans` field. The regex-based extraction was replaced with a brace-depth counting parser that correctly handles arbitrarily nested JSON.

Additionally, the FastAPI gateway migrated from the deprecated `@app.on_event` pattern to the recommended `lifespan` context manager, eliminating all deprecation warnings. Default service URLs throughout the codebase were standardized to Docker Compose service names (`redis`, `ollama`, `policy`) instead of `localhost`, preventing silent failures in containerized deployments where localhost does not resolve to the expected service. A CI gate was added to verify that `__init__.py` and `pyproject.toml` versions remain in sync, preventing the version drift discovered during v0.9.3 QA.

### 7.10 v1.09.5 Delivered

v1.09.5 makes the agent bundle experience zero-friction and adds first-class Podman support. Key changes:

- **Agent bundles work out of the box** — the installer auto-registers Langflow, Letta, and OpenClaw as agents with pre-shared key (PSK) tokens during installation, eliminating manual agent registration. Bundles are selected via `--agent-bundles langflow,letta,openclaw`.
  - **Langflow** (port 8000): multi-agent orchestration framework; shares Postgres (separate database) and Redis (DB 5)
  - **Letta** (port 8283): Stateful agent with persistent memory; REST API
  - **OpenClaw** (port 18789): personal AI with 30+ messaging integrations; `OPENCLAW_CONFIG_JSON` routes through the gateway
- **First-class Podman support** — runtime detection identifies Docker Engine, Docker Desktop, or Podman; the correct compose command is selected automatically; the Podman override file is auto-applied when Podman is the active runtime
- **DNS fix for Ollama** — `ollama` and `ollama-init` containers are now on the external network, restoring model registry access for model downloads without compromising internal network isolation
- **Admin codenames** — auto-generated admin accounts use fun animal/nature-themed codenames as usernames, with TOTP pre-provisioned at install time
- **PgBouncer password fix** — PgBouncer now reads its password from `.env` instead of using a hardcoded or missing value
- **Alembic migrations in backoffice image** — database migrations are bundled in the backoffice Docker image and run automatically on container startup
- **18-service full stack verified** — all health checks pass from a clean-slate install (15 core + 3 agent bundles)

Full install command:

```bash
bash install.sh --domain yashigani.local --tls-mode selfsigned --with-openwebui --agent-bundles all --wazuh
```

### 7.11 v2.1 Delivered

v2.1 adds the management layer that makes Yashigani self-service. Key deliverables:

- **Admin Dashboard UI** — login page + 9-section admin panel (identities, budgets, routing, policies, alerts, audit, models, agents, system health); served behind Caddy authentication
- **12 Alertmanager rules** — P1-P5 severity for routing and budget conditions; fires on sensitivity breaches, OPA overrides, classification conflicts, spending anomalies, budget exhaustion, and budget auto-switch events
- **Budget Postgres persistence** — budget counters written to PostgreSQL in addition to budget-redis; state survives container restarts and Redis eviction; async write path to avoid request-path latency
- **Pool Manager background health monitor** — daemon thread continuously monitors container health; unhealthy containers detected and replaced without waiting for a failed request
- **OIDC identity broker (end-to-end)** — `handle_oidc_callback()` delegates to `OIDCProvider.exchange_code()` with real JWT validation, JWKS discovery, and group extraction supporting Entra ID, Okta, Cognito, and Keycloak; CSRF protection via Redis-backed state/nonce tokens (10-minute TTL, ASVS V3.5.3)
- **Mandatory 2FA after SSO** — TOTP verification required even after successful IdP authentication; controlled by `YASHIGANI_SSO_2FA_REQUIRED`
- **SSO audit trail** — SHA-256 email hashing on all SSO events; raw email never stored
- **Keycloak test IdP** — Docker Compose `test-idp` profile with pre-configured OIDC and SAML clients, three test users, and group mappers
- **Podman rootless parity** — correct user namespace configuration; root-running services no longer use `keep-id`; e2e test suite auto-detects runtime
- **OPA v1_routing.rego verified operational** — policy evaluation, LLM validation, and SAFE/WARNING/BLOCK verdicts confirmed end-to-end
- 413 tests (388 unit + 25 e2e)

### 7.12 v2.20 Delivered

v2.20 is a security hardening release closing ASVS Level 3 gaps identified post-v2.1, shipping production-grade PII detection, and adding supply-chain assurance controls. Key deliverables:

- **License anti-tampering** — v4 counter-signature detects binary patching of the verifier; self-integrity check halts the process on modification rather than silently degrading
- **PII detection module** — `pii/` module; 3 modes (detect / redact / block), 10 entity types, bidirectional (prompt + response), cloud model bypass forces local routing when PII is detected
- **Response-path inspection on /v1 routes** — `ResponseInspectionPipeline` now wired to all `/v1/*` routes; every OpenAI-compatible response inspected before delivery
- **Container hardening** — seccomp profile at `docker/seccomp/yashigani.json`; AppArmor opt-in via `docker-compose.apparmor.yml` (Ubuntu/Debian); read-only root filesystem for all core services; explicit `cap_drop` in compose
- **WAF and DDoS protection** — Caddy hardened timeouts and body size limits; per-IP `DDoSProtector` in Redis (429 + `Retry-After`); `Caddyfile.waf` reference config for Coraza WAF plugin
- **FastText model baked into Docker image** — no outbound pull required at startup; full inspection capability on container start in air-gapped environments
- **Model aliases Redis persistence** — write-through to Redis on every alias mutation; Redis is the read path, Postgres is the source of truth
- **SBOM + cosign image signing** — CycloneDX 1.5 SBOM + CryptoBoM (12 algorithms) per image; cosign keyless signing tied to GitHub Actions OIDC; `release.yml` publishes SBOMs as release artifacts; consumers verify with `cosign verify`
- **Helm chart fixes + network policies** — chart passes `helm lint`; v2.0/v2.1 values wired to templates; Helm test hooks added; network policies cover all services added since v2.0
- **Streaming chunk-level inspection** — `StreamingInspector` buffers chunks to configurable threshold and inspects at each boundary; budget headers delivered as trailing headers; env vars `YASHIGANI_STREAMING_CHUNK_THRESHOLD` and `YASHIGANI_STREAMING_MAX_BUFFER`
- **HMAC-SHA256 per-tenant email hashing** — SSO audit email hashes keyed with per-tenant KMS secret; closes cross-tenant correlation risk in multi-org deployments
- **Ollama model digest pinning** — `ollama-init` records pulled model SHA-256 digest; validates on subsequent starts; mismatched digest raises alert and rejects the model
- **Open WebUI branding** — "Powered by Open WebUI" attribution in interface footer
- **Compliance documentation** — 9-framework mapping doc; 2 STRIDE threat models (product: 17 threats, solution: 38 threats)
- 548 tests (523 unit + 25 e2e)

### 7.13 v2.0 Delivered

v2.0 is Yashigani's first production-grade release. It adds five major subsystems and transforms the platform from a security enforcement proxy into a complete AI operations platform.

**Unified Identity Model**
- Every entity (human or service) is an identity with a `kind` field — no separate user/agent stores
- Same governance, budget, RBAC, and audit for all identity kinds
- Humans: optional IdP federation metadata
- Services: optional upstream URL, container configuration, system prompt, capabilities
- Both managed through the same Web UI and API

**Optimization Engine**
- Four-dimensional routing: sensitivity + complexity + budget + cost
- P1-P9 priority matrix governs all routing decisions
- P1 is immutable: CONFIDENTIAL/RESTRICTED data always stays local
- Budget exhaustion degrades to local inference, never rejects
- Runs inside the gateway process (not a sidecar)
- Token threshold default: 2,000

**Three-Tier Budget System**
- Org cloud cap → group budgets → individual budgets
- Math always enforced: sum of individuals never exceeds group; sum of groups never exceeds org cap
- Budget-redis: dedicated container (port 6380, noeviction policy)
- Budget state via `X-Yashigani-Budget-*` response headers
- Admin API for budget management

**Open WebUI Integration**
- Chat interface at `/chat/*` behind Caddy
- Internal Docker network only — no external port
- All LLM calls (cloud and local) route through gateway
- Open WebUI holds zero LLM credentials
- Caddy delegates auth to backoffice (identity broker)
- Trusted headers: `WEBUI_AUTH_TRUSTED_EMAIL_HEADER`

**Container Pool Manager**
- Per-identity container isolation
- Universal lifecycle: create, route, health check, replace, scale, postmortem
- Self-healing: replace broken containers, never fix in place
- Postmortem forensics: logs, inspect output, filesystem diff preserved before kill
- Ollama horizontal scaling on load
- License tier container limits: Community (1/3), Non-profit & Education (3/15), Starter (1/5), Professional (3/15), Professional Plus (5/50), Enterprise (unlimited)

**Multi-IdP Identity Broker**
- Yashigani IS the identity broker
- OIDC + SAML v2 native support
- Caddy delegates all auth to backoffice
- SCIM provisions users and groups
- Group policies govern model and agent access
- IdP limits tier-gated

**Sensitivity Classification Pipeline**
- Three layers, all ON by default: regex + FastText + Ollama
- Regex: PII, PCI, intellectual property, PHI patterns
- FastText: sub-5ms offline ML classification
- Ollama: deep semantic analysis (qwen2.5)
- Admin can opt out of Ollama layer but cannot disable regex
- Results feed directly into OE routing

**OPA Routing Safety Net**
- Second OPA pass on every routing decision
- Local LLM validates policy changes before applying
- Checks for self-lock, contradictions, scope issues, routing conflicts
- SAFE/WARNING/BLOCK verdicts

**P1-P5 Alert Severity**
- Sensitivity breach: P1
- OPA override: P1
- Classification conflict: P2
- Spending anomaly: P2
- Budget auto-switch: P3
- All routing decisions written as audit events to SIEM sinks

**Additional v2.0 changes:**
- 17 core services + 3 optional agent bundles + dynamic per-identity containers
- 363 tests passing (252 original + 111 new)
- 12 Grafana dashboards (9 existing + 3 new: budget, Optimization Engine, Pool Manager)
- Model alias table: DB-driven, Postgres + Redis cache, CRUD at `/admin/models/aliases`
- Streaming: buffered mode for v2.0 (full response before delivery; chunk-level streaming shipped in v2.20)
- User API keys: 256-bit hex, bcrypt cost 12, max lifetime 1 year, default rotation 90 days, 7-day grace period

Organizations evaluating Yashigani for production deployment should begin with the Community tier (20 agents, 5 end users, Apache 2.0). Universities, registered charities, and accredited non-profits qualify for the Non-profit & Education tier — £500/yr symbolic cost (covers verification + admin ops) or fee waived via partnership MOU (whitepapers, research-paper inclusion, designated consulting access). Includes OIDC + SCIM, 1,500 agents, 500 end users, 25 admin seats; SAML v2 available as optional add-on. Teams with an SSO mandate but limited scale should consider the Starter tier (OIDC, 300 agents, 100 end users). Professional is the primary production tier for single-org deployments requiring full SSO and SCIM (1,500 agents, 500 end users). Professional Plus suits large single-company deployments needing up to 5,000 end users and 5 orgs. Enterprise provides unlimited scale with named support engineers and 24/7 SLA. The universal installer supports in-place tier upgrades via license key injection without data migration or service interruption.
