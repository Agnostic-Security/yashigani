# Changelog

All notable changes to Yashigani are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

For full release narratives, design rationale, and per-feature detail, see [`README.md`](README.md) section 4 (Security Features by Version).

---

## [v2.25.5] — 2026-06-25

Theme: **Auth/ingress rebuild + the full admin-UX refinement layer + security hardening pass** — a single authenticated portal with role-based routing, a top-to-bottom pass over the back-office admin experience, and a security hardening batch covering SSRF, OPA path normalisation, TOTP re-provision protection, and install robustness.

### Added

- **feat(auth): single auth portal with role-based routing** — one login portal routes admins to `/admin` and end users to `/app/webui`, with working end-user logout. Deny-by-default is preserved throughout.
- **feat(backoffice): admin UX refinement layer (R1–R26)** — full working CRUD across the back office: agent edit, admin/user account edit with an email column, model-alias dropdowns of pulled models, allocation and budget dropdowns with persistence, and client-policy binding dropdowns with an explicit "All". Policy management gains template duplicate / edit / save-as, a server-enforced danger-confirm on core-policy edits, a draft→staging→production lifecycle with promote/archive, and an **AI policy dry-run** (admin input → block/allow + rationale). New: **generate detection patterns from plain English** using the install-default model; RBAC path/method dropdowns with plain-language help; budget alerts at a default-on ≥85% threshold plus full custom-alert CRUD; audit verdict / entity / source-type filters; description panels across all monitoring dashboards; license-gating of enterprise authentication (OIDC/SAML surface a "requires [tier]" notice); Cryptography consolidated under PKI; an opt-in "new version available" check that distinguishes major vs. security updates.
- **feat(backoffice): dashboard redesign (R25)** — criticality-weighted per-service health semaphore, a five-level alert semaphore, a budget gauge (cloud/local with an 85% marker), and security + traffic widgets, on a unified palette.
- **feat(sensitivity): numeric canonical taxonomy** — sensitivity levels are canonical numbers with a per-tenant label/colour mapping; the OPA shim accepts both the numeric levels and the legacy string levels; `OFFICIAL-SENSITIVE` is built in.
- **feat(admin): second-admin enforcement (N1)** — a minimum of two admins is enforced; deleting or disabling the last remaining admin is blocked (`409`), with an `/admin/accounts/enforcement` status endpoint and a back-office banner.
- **feat(api): OpenAPI / API map (N2)** — self-hosted, auth-gated API documentation: Swagger UI at `/admin/api-docs`, ReDoc at `/admin/api-redoc`, and `/admin/openapi.json`, plus gateway `/docs` and `/redoc`. Assets are served locally and render under the strict CSP.
- **feat(identity): durable identity store** — a Postgres-backed durable mirror of the identity registry with a startup reconcile, so identities are re-hydrated if the Redis volume is lost.
- **feat(backup): signed + encrypted backup** — install-time and on-demand backups are signed and encrypted.

### Fixed

- **fix(install): preserve deployed profiles on `--upgrade`** — an `--upgrade` that does not re-pass `--wazuh` / `--with-openwebui` / `--agent-bundles` no longer resets the enabled-services set to empty (which made deployed services show as "Not Deployed"); the profile list is now seeded from the existing `.env` value and merged idempotently with any newly selected profiles.
- **fix(install): substitute the OpenClaw internal bearer at deploy time** — the OpenClaw runtime config is generated at install time with the real per-install bearer substituted in, so OpenClaw authenticates to the gateway out of the box (no manual step on upgrade).
- **fix(observability): metrics + log/metric routing** — ~40 metrics instrumented across services, with Loki and Prometheus wiring corrected.
- **fix(sensitivity): clean-result over-block regression** — a clean result is no longer over-classified; alias resolution corrected.
- **fix(deploy): assorted upgrade/demo fixes** — backup admin DSN, list-content schema, a durable-store array column type, and the MCP OpenTelemetry span processor.

### Security

- **sec(gateway): SSRF guard on JWKS URL resolution (YSG-RISK-083)** — the JWKS endpoint URL is now validated before resolution: https-only (blocks `file://` and `http://`) and the resolved IP is checked against RFC 1918/loopback/link-local/reserved ranges (blocks cloud-metadata 169.254.0.0/16 and internal networks). Primary compensating controls remain egress-default-deny firewall and mTLS mesh.
- **sec(gateway): OPA path normalisation (YSG-RISK-081)** — the OPA policy check now receives the leading-slash-normalised path (`norm_path`) consistently with every other gate in the request handler, so OPA rego rules keyed on paths with a leading slash (e.g. `/.well-known/jwks.json`) match correctly instead of failing-closed with a spurious 403.
- **sec(auth): step-up required to re-provision TOTP (YSG-RISK-082)** — replacing an existing TOTP authenticator (via `/auth/totp/provision/start`, `/auth/totp/provision/confirm`, or the atomic `/auth/totp/provision`) now requires a fresh step-up TOTP verification before issuing a new seed. First-time enrolment (`force_totp_provision=true` / no existing secret) is exempt — that is the bootstrap path.
- **sec(caddy): deduplicate Content-Security-Policy header (YSG-RISK-080)** — `header_down -Content-Security-Policy` added to every `reverse_proxy https://backoffice:8443` block in all three Caddyfiles, so the backoffice-emitted CSP header is stripped before Caddy injects its own. Previously both headers reached the browser, causing the stricter of the two to silently win (or duplicate-header CSP confusion). Caddy is now the sole CSP source on all paths.

### Fixed

- **fix(rag): RAG embeddings — nomic-embed-text pulled on install** — `ollama-init` now pulls `nomic-embed-text` after the primary model, and `RAG_EMBEDDING_MODEL: "nomic-embed-text"` is set on the open-webui service. Fixes "No sources found" on file-upload RAG (Ollama embed endpoint returned HTTP 404 when the model was absent).
- **fix(owui): default new-user role to `user`** — `WEBUI_DEFAULT_USER_ROLE: "user"` added to the open-webui service so user accounts created after the first are not stuck in "Account Activation Pending".
- **fix(install): self-healing convergence gate** — if the gateway health poll times out on a clean install (caused by postgres finishing initdb after its `start_period` elapsed under heavy parallel load, aborting the app tier to "Created"), `install.sh` now re-runs `compose up -d` once (profile-aware) and re-polls before failing. postgres `start_period` raised to 300 s (was 180 s) for additional headroom.

### Known issues

- The raw Prometheus expression-browser UI has a rendering quirk under the `/admin/prometheus` subpath; data and the API are unaffected, and **Grafana is the supported dashboard surface**.

---

## [v2.25.4] — 2026-06-12

Theme: **Gateway-mediated agent/tool orchestration + model-allocation RBAC actually enforced**.

### Added

- **feat(orchestration): gateway-mediated agent & tool orchestration (Phase 1 + Phase 2)** — multi-agent and tool-calling flows are routed *through* the gateway so every inter-entity hop (agent↔agent, agent↔tool/MCP, agent↔LLM) is policy-adjudicated at ingress and egress rather than going direct. Phase 2 adds a "brain" reasoning leg (Letta) with deterministic exfiltration defence, plus Helm parity for the four orchestration capabilities (Kubernetes leg). Regression coverage under `src/tests/unit/test_v2254_orchestration_phase1.py` and `…_phase2_letta.py`.
- **feat(rbac): model-allocation RBAC enforced (Track B1)** — model allocations granted to an identity are now enforced on the inference path, backed by a durable allocation store (migration `0019_model_allocations`) and pushed into OPA. An admin **Access** panel in the back office manages per-identity allocations.
- **feat(rbac): per-user identity through Open WebUI (Track C)** — requests arriving via Open WebUI carry the real end-user identity through to the gateway for per-user policy and allocation decisions, instead of collapsing to a single service principal.
- **feat(inspection): secret detector** — a content secret-detector module for the inspection pipeline.

### Security

- **security(rbac): visible model-pin deny + identity-header trust gate** — an explicit model pin that is not permitted now returns a visible `403` rather than silently substituting an allowed model, and the forwarded end-user identity header is only trusted when presented behind the authenticated reverse-proxy boundary (trust-gated), closing a header-spoofing path.
- **fix(caddy): restore public TLS edge** — default/fallback SNI handling on the client-cert-optional listener so the public TLS edge serves correctly alongside mTLS.

### Fixed

- **fix(gpu): wire Ollama to the GPU via CDI** — the bundled inference runtime now binds to the GPU (was running on CPU with idle GPUs).
- **perf(deploy): model warmup + keep-alive** — `OLLAMA_KEEP_ALIVE=-1`, a post-deploy model warmup step, and an increased Caddy write timeout eliminate first-request cold-load latency on the classifier/inference path (compose + Helm + installer parity).

---

## [v2.25.3.1] — 2026-06-08

Theme: **Durable agent registry + service-account model-listing control**.

### Added

- **feat(agents): durable agent registry** — the agent registry, reconciler, and durable store are hardened so registered agents survive a restart and reconcile cleanly. Migrations `0017_agent_registry_durable_shape` and `0018_drop_legacy_agent_name_unique` reshape the registry for durability. Regression coverage in `src/tests/regression/v2.25.3.1/test_agent_registry_durability.py`.
- **feat(gateway): `gateway.models.service_account_full_list` runtime setting** — service-account identities (e.g. Open WebUI authenticating with the shared internal service bearer) receive a **RESTRICTED** `GET /v1/models` listing by default (their `allowed_models` allowlist only) as part of the internal-topology-disclosure hardening. Operators opt in — via admin Runtime Settings (step-up TOTP, audited), the API, or `YASHIGANI_MODELS_SERVICE_ACCOUNT_FULL_LIST` at install time — to receive the FULL model/agent/service listing and populate the Open WebUI model picker. This widens model **listing** only; it never changes which models a request may **call**, and never affects human/admin principals. Documented at `docs/yashigani_install_config.md` §21.4.

### Changed

- **chore(audit): audit schema, sink, and writer refinements** carried forward from the v2.25.3 line.

---

## [v2.25.3] — 2026-06-07

Theme: **MCP broker hardening + OPA fail-close correctness + install/upgrade robustness**.

### Added

- **feat(mcp): MCP broker + signed server bundles through the gateway** — the MCP broker is wired into the gateway runtime with OPA-gated tool access, registry, and codegen; shipped server bundles are built as hardened images. Every MCP hop is policy-adjudicated, and a hard chain-depth ceiling is enforced as a policy constant with parity tests across the Docker and Kubernetes OPA bundles.

### Security

- **fix(opa): fail-close correctness** — retired the deny-override anti-pattern that produced `eval_conflict` 500s; closed path-traversal and default-deny inversions; made v1 sub-decisions fail closed; corrected stale chain-depth tests.
- **feat(audit): least-privilege audit DB role + signed chain** — the audit writer runs under a least-privilege runtime database role with `PostgresSink` on the write path, so events land in an append-only, signed chain.
- **fix(wazuh): TLS 1.3 floor on the SIEM link** — internal-CA mTLS provisioning for the Wazuh stack is fully codified into `install.sh` (no manual steps), with a TLS 1.3 minimum enforced on the indexer HTTP listener and the internal mesh.
- **fix(inspection): decode-before-classify on the inference path** — response bodies are decoded before sensitivity classification so the inspection pipeline evaluates the real content.

### Fixed

- **fix(install): clean-slate and upgrade-path robustness** — GPU wired into Ollama via CDI on Podman, self-healing runtime-manifest bootstrap tokens, dual-wrap backup against read-only containers, and rootless-Podman PKI fixes, plus a local install-path regression gate.

---

## [v2.25.2] — 2026-06-06

Theme: **Wazuh SIEM hardening + install-path reliability + audit least-privilege + OPA durability**.

### Added

- **feat(audit): least-privilege runtime DB role split** — `yashigani_admin` (DDL / migrations, superuser) and `yashigani_app` (runtime request paths, NOSUPERUSER) are now distinct roles. On upgrade from pre-2.25.2, migration `0015` demotes `yashigani_app` and reassigns table ownership. Audit tables (`audit_events`, `inference_events`, `audit_chain_checkpoints`) grant `yashigani_app` SELECT + INSERT only; UPDATE/DELETE are revoked. FORCE ROW LEVEL SECURITY ensures RLS applies even to previous table owners. Closes the gap where a superuser runtime role bypassed declared REVOKE and RLS constraints.
- **feat(audit): PostgresSink wired into the audit write path** — the PostgreSQL audit sink is now unconditionally instantiated and registered in the gateway write path. Previously the sink existed but was not wired, meaning audit events were only delivered to the file sink and in-memory sinks during normal operation.
- **feat(install): automated Wazuh mTLS provisioning** — `install.sh` now generates an internal-CA admin certificate (EC P-256, PKCS#8), a CA bundle, a re-PKI'd indexer HTTP certificate, a re-PKI'd `opensearch.yml` (updated `admin_dn`), and `internal_users.yml` with bcrypt hashes of the real generated admin/kibanaserver passwords. The Wazuh image's demo PKI (`admin/admin`) is removed at install time. All generated material lands in git-ignored `docker/wazuh-mtls/`. No manual steps required.
- **feat(install): `wazuh-security-init` one-shot sidecar** — runs `securityadmin` automatically once the indexer TLS listener is up. The Wazuh manager and dashboard gate on its completion. Previously this was a manual post-deploy step.

### Fixed

- **fix(gateway): generic-proxy forward path returned 500 on every upstream success** — the forward leg passed the inbound `Content-Length` header through while the HTTP client also derived one from the body, so the upstream connection failed with a header/body length conflict on every completed forward. `Content-Length` (and `Host`) are now stripped from forwarded headers, and the forward-leg telemetry calls (anomaly detection, inference logging) were corrected to the real synchronous APIs with defensive error handling. Regression test added.
- **fix(backoffice): "Duplicated timeseries" errors on credential-exfiltration alerts** — the backoffice package eagerly imported its FastAPI app (and its module-level Prometheus metrics) into any process that only needed shared state, causing metric re-registration errors on every exfiltration detection in the gateway. Replaced with a lazy module re-export; alerts now record cleanly. Regression test added.
- **fix(install): pre-upgrade backup works on read-only containers** — `docker cp` refuses `ReadonlyRootfs=true` containers in both directions (Docker 29). The backup step is replaced with tar-over-`exec` plus a sha256 integrity check on the streamed bundle. The LOCKED fail-closed crypto envelope is unchanged.
- **fix(install): pre-upgrade secrets backup non-fatal on root-owned files** — root/UID-owned client keys unreadable by a non-root install user no longer abort the upgrade under `set -e`.
- **fix(install): convergence-gate timeout raised from 60 s to 180 s** — 60 s was triggering false failures on first boot of healthy stacks. Configurable via `YSG_HEALTHZ_TIMEOUT_S`.
- **fix(install): `UPSTREAM_MCP_URL` reused on upgrade** — when `--upstream-url` is omitted during `--upgrade`, the value is read from the existing `.env`. A blank export previously broke the `${UPSTREAM_MCP_URL:?}` compose interpolation.
- **fix(install): CWE-732 secrets-perm guardrail self-heals** — the permission check tightens world-readable non-cert files rather than aborting the install.
- **fix(install): runtime is explicit on dual-runtime hosts** — on a host with both Docker and Podman, `install.sh` requires `--runtime docker` (or `YSG_RUNTIME`) instead of auto-selecting Podman. Prevents silent runtime mis-selection on development machines.
- **fix(opa): retire deny-override anti-pattern causing eval_conflict 500s** — OPA policies that combined `allow = true` and `allow = false` default rules in the same package produced `eval_conflict` errors (HTTP 500) on every policy evaluation. All affected policy files refactored to a single `allow` rule with explicit default-deny.
- **fix(opa): fail-closed defaults on all v1 sub-decisions** — OPA sub-decision rules that lacked explicit defaults could return undefined, which the gateway treated as deny but did not audit. All sub-decision rules now carry `default = false` so behaviour is explicit and auditable.
- **fix(opa): OPA response_decision defaults to false (fail-closed)** — two call sites in `openai_router.py` had `result.get("allow", True)`. An absent "allow" key (OPA bundle mismatch or partial load) resolved to ALLOW. Both defaults changed to `False`.
- **fix(helm): mcp.rego added to Kubernetes OPA bundle** — the Helm chart OPA ConfigMap was missing `mcp.rego`, causing MCP-specific policy rules to be silently absent in Kubernetes deployments. Now mirrors the Docker Compose policy bundle.
- **fix(opa): stale chain-depth test assertions corrected** — two tests asserted a maximum chain depth of 3 when the actual limit is 9. Corrected to match the implemented ceiling, preventing false passes.
- **fix(inspection): decode-before-classify on the inference path** — base64-encoded or percent-encoded payloads were previously classified as CLEAN because the classifier operated on the encoded form. The pipeline now decodes before classification, so encoding does not bypass PII detection or sensitivity classification.
- **fix(wazuh): HTTPS + healthcheck fixes for Linux / Docker 29.x** — the Wazuh compose overlay corrected manager and dashboard URLs from `http://` to `https://`, added filebeat certificate mounts, added a minimal `opensearch_dashboards.yml`, and fixed all three healthchecks to accept the HTTP 401/403 responses that a security-enabled indexer returns (the prior `-f` flag errored on ≥400 → permanent false-unhealthy → deadlock). Minimum capabilities for the Wazuh manager (`SYS_CHROOT`, `SETPCAP`) added to resolve Docker 29.x entrypoint failures.
- **fix(caddy): Dockerfile.caddy COPY path corrected** — a COPY directive referenced `caddy/caddy-entrypoint.sh` but `docker-compose.yml` sets `build.context: ..` (repo root). The correct path is `docker/caddy/caddy-entrypoint.sh`. The broken path caused `podman build` to exit 125 on all Podman-based installs.
- **fix(podman): relative seccomp path in Podman override** — `YASHIGANI_SECCOMP_PROFILE` set to an absolute path caused "file name too long" in podman-compose 1.5.0 on Mac. The Podman override file now uses a relative path `./seccomp/yashigani.json`, resolved from the compose file directory.
- **fix(postgres): cert + pg_ident CN map for pgbouncer_authenticator** — multiple iterations of the pgbouncer authentication carveout culminated in a `cert map=pgb-auth-map` approach: PG16 `cert` auth method (verify-full) plus `pg_ident.conf` CN mapping. This eliminates platform-specific SCRAM computation bugs and restricts authentication to the two named pgbouncer CN values, closing the lateral-pivot risk class definitively.
- **fix(openclaw): openclaw.json baseUrl and Helm OPENCLAW_UPSTREAM_URL corrected to :8081** — openclaw's gateway URL lived in a JSON config file, not an env var. The base-URL sweep that fixed langflow and letta in v2.24.x missed this path. Both the compose JSON config and the Helm value are now `:8081` (the in-mesh listener).

### Changed

- **security(opa): OPA RBAC groups survive gateway restart** — the `RBACStore` already persists write-through to Redis, but the backoffice never re-pushed that state to OPA on startup. RBAC groups now vanished from OPA after any policy- or upgrade-restart. The backoffice lifespan now re-pushes the store to OPA at startup (best-effort, retried, never blocks startup).
- **feat(runtime-settings): admin panel for live gateway tunables** — Phase 2 web UI ships the "Runtime Settings" admin panel, allowing operators to view and edit live gateway tunables (per-user RPS, DDoS per-IP limit, DDoS window) without a container restart. Phase 1 (DB persistence + admin API) shipped in v2.24.1.

---

## [v2.25.1] — 2026-06-01

Theme: **TLS 1.3 minimum on the internal mesh**.

### Changed

- **security(tls): TLS 1.3 minimum enforced on all internal mesh contexts** — `src/yashigani/pki/ssl_context.py` server, client, and CA-trust contexts updated to `minimum_version = TLSVersion.TLSv1_3`. Three operator scripts (`scripts/partition_maintenance.py`, `scripts/yashigani-manifest.py`, `scripts/yashigani-onboard.py`) pin `create_default_context` to TLS 1.3. All internal mesh peers support 1.3 (Postgres 16-alpine, Redis 7.4.9, pgbouncer 1.25.1, uvicorn/OpenSSL 3.x); there is no compatibility reason for a 1.2 floor. Surfaced by ACS v6 CBOM scan.

**Note:** Python's `ssl`/OpenSSL negotiates a classical key exchange even at TLS 1.3. Post-quantum key exchange is terminated at the Caddy edge (X25519MLKEM768). Internal east-west post-quantum key exchange is tracked separately.

---

## [v2.25.0] — 2026-05-28

Theme: **Kubernetes/Helm parity sweep + signed + encrypted install-time backup**.

### Added

- **feat(install): signed and encrypted install-time backup** — `install.sh` now produces a dual-wrap AES-256-GCM backup envelope before any upgrade or destructive operation. A random DEK encrypts the bundle; the DEK is wrapped under two independent KEKs so either can recover: KEK1 (admin password via argon2id + HKDF-SHA384) and KEK2 (license file or local DB key for community tier). An HMAC-SHA384 integrity tag is included. Under `FIPS_MODE=1` only wrap#2 is written (argon2id is not FIPS-approved). Closes CWE-311 (unencrypted backup) and CWE-345 (broken integrity control).
- **feat(helm): K8s/Helm parity sweep (Wave 1 critical)** — PKI rotate HMAC carry-forward; Grafana `:3443`; gateway `:8081` Ingress + pod-level bundle label; observability NetworkPolicies (otel/jaeger/alertmanager/loki); OPA `.Files.Get`; audit-log PVC; state-file + `.env.helm`.
- **feat(helm): K8s/Helm parity sweep (Wave 2 high/medium)** — image-digest guard; runtime FIPS attestation at `/admin/crypto/inventory`; nginx AND-semantics; Wazuh K8s not-supported guard; `OWUI_SECRET_KEY` injection; PSA baseline labels; ServiceAccount token gates (gateway conditional, Open WebUI hard-off); CMVP wiring; audit notes.
- **feat(helm): K8s/Helm parity sweep (Wave 3 high/medium)** — `/api/v1/admin/*` Caddyfile in Helm; agent-bundle state in backup CronJob; compose Caddyfile SPIFFE strip.
- **feat(fips): FIPS 140-3 deployment guide** — `docs/operations/fips-deployment.md` documents the FIPS 140-3 deployment posture, CMVP certificate reference, blocked algorithms (cosign/Sigstore, argon2id backup wrap), and a pre-deployment validation checklist.

### Fixed

- **fix(helm): NetworkPolicy port YAML strip bug** — a YAML rendering bug stripped port values from NetworkPolicy rules under certain value combinations. Fixed in chart templates.
- **fix(compose): agent-volume backup compose-prefix** — agent volumes named with the project prefix were not captured by the backup CronJob's volume enumeration.
- **fix(backup): CWE-732 backups/ world-readable** — backup output directory permissions tightened; `o+rX` bits pruned.
- **fix(compose): Caddyfile SPIFFE strip** — compose Caddyfile now strips the SPIFFE URI from the `X-Forwarded-Client-Cert` header before forwarding to backoffice.

---

## [v2.24.4] — 2026-05-26

Theme: **Post-v2.24.3 reliability and security fixes — IPv6, uninstall reliability, FIPS flag propagation, licensing on Kubernetes**.

### Fixed

- **fix(install): IPv6 egress parity** — iptables rules in the Caddy entrypoint now handle IPv6 addresses in the egress allowlist resolution; previously IPv6 addresses from DNS could be silently dropped from allow rules.
- **fix(caddy): ACME egress allowlist gated on TLS mode** — the ACME egress allowlist was applied unconditionally; it is now applied only when `TLS_MODE=acme`.
- **fix(caddy): IPv4+IPv6 parity** — Yashigani is IPv4-only by design on the internal mesh; external Caddy listener now correctly handles inbound IPv6 clients.
- **fix(uninstall): canonical network cleanup and final assertion** — uninstall.sh now correctly removes compose networks and asserts cleanup completion, preventing phantom networks blocking re-installs.
- **fix(uninstall): force-remove volumes and retry pass** — volume removal now includes a retry pass after container force-removal to handle the edge case where a container respawns during teardown.
- **fix(helm): networking — NetworkPolicy IPv6 alignment** — K8s NetworkPolicy rules updated for IPv6 parity.
- **fix(fips): FIPS_MODE propagation to gateway/backoffice/caddy** — `FIPS_MODE` env var was not forwarded to all container processes; now propagated consistently.
- **fix(helm): licensing Secret + mount** — Kubernetes installs now correctly enrol a paid licence via the licensing Secret; previously the Secret was absent on fresh K8s installs.
- **fix(tests): replace hardcoded developer-machine paths** — 7 unit tests contained paths from a specific developer's machine, causing failures on any other system.

### Security

- **fix(network): close IPv6 egress leak on OpenClaw NetworkPolicy** — a port-only IPv6 egress rule on the OpenClaw NetworkPolicy was overly permissive; corrected to match the intended IPv4-only internal mesh policy.

---

## [v2.24.3] — 2026-05-25

Theme: **Post-v2.24.2 reliability fixes — pgbouncer auth stability, Caddy build fix, OPA fail-closed hardening**.

### Fixed

- **fix(postgres): pgbouncer authentication hardened to cert + CN map** — multiple iterations (cycles 4–8) of the pgbouncer `pg_hba.conf` carveout resolved to `cert map=pgb-auth-map`: PG16 `cert` auth with `pg_ident.conf` CN mapping to `pgbouncer_authenticator`. This avoids platform-specific SCRAM computation defects in pgbouncer 1.25.1 on ARM64 and is stronger than the prior `verify-ca` posture (verify-full + CN-restricted). Contract test suite: 30 PASS / 1 SKIP.
- **fix(openclaw): openclaw.json baseUrl and Helm `OPENCLAW_UPSTREAM_URL` corrected to `:8081`** — openclaw's gateway URL was in a JSON config file, not an environment variable. The prior sweep fixed langflow and letta but missed this path. Contract test suite extended to cover JSON config surfaces and Helm value.
- **fix(caddy): Dockerfile.caddy COPY path corrected** — COPY path was relative to `docker/` but the build context is the repo root. Caused `podman build` to exit 125 on all Podman-based installs. Regression test asserts every COPY source path resolves from the build context root.
- **fix(podman): relative seccomp path in Podman compose override** — absolute `YASHIGANI_SECCOMP_PROFILE` path caused "file name too long" in podman-compose 1.5.0. Override now uses `./seccomp/yashigani.json` relative to the compose file directory. Contract test added.
- **fix(opa): OPA response_decision defaults to false (fail-closed)** — two `result.get("allow", True)` call sites in `openai_router.py` changed to `False`. An OPA bundle mismatch or partial load no longer silently allows traffic. Three unit tests added.
- **fix(tests): test comment-line parser strips whole-line comments** — a `_parse_canonical_volumes` helper in the uninstall test suite was treating words from inline bash comments as volume names, producing false-positive phantom-volume failures.

---

## [v2.24.2] — 2026-05-25

Theme: **Security hardening batch — agent secrets isolation, admin/user separation, OPA conformance, audit chain, TOTP Redis, DDoS throttling**.

### Added

- **feat(pool): Kubernetes API backend for PoolManager** — `KubernetesBackend` closes the gap where pool-managed agent dispatch returned 502 in K8s deployments without a Docker/Podman socket projection. The backend uses `CoreV1Api.create_namespaced_pod()` with managed labels. Helm: `poolManager.k8sBackend.{enabled, agentPort, podReadyTimeoutSeconds}` values; namespace-scoped RBAC Role + RoleBinding + NetworkPolicies for pool-pod isolation.
- **feat(gateway): per-user 100 RPS rate limit with admin alerting** — a per-authenticated-user rate limit (default 100 RPS, burst 200) is enforced at the gateway. Breach triggers a Prometheus metric (`yashigani_user_rate_limit_violations_total`) and an audit event (`USER_RATE_LIMIT_EXCEEDED`). Redis key `yashigani:rl:user:<hashed_user_id>` (DB 2). Configurable via `YASHIGANI_RATE_LIMIT_PER_USER_RPS`.
- **feat(gateway): DDoSProtector licence-scaled per-IP defaults** — per-IP connection limit scales with `max_end_users` from the licence state. Formula: `max(5000, max_end_users * 25)`. Enterprise/academic tier: 100 000. Configurable via `YASHIGANI_DDOS_PER_IP_LIMIT`.
- **feat(runtime-settings): Phase 1 admin API + DB persistence** — a new `runtime_settings` service provides DB-persisted, live-reloadable gateway tunables (per-user RPS, DDoS per-IP limit, DDoS window). Admin API: `GET/PUT /admin/runtime-settings/{key}` and `POST /admin/runtime-settings/{key}/reset`. Redis pub/sub for live reload without a container restart.
- **feat(auth): server-side `next=` redirect validator** — `GET /auth/post-login-redirect?next=<value>` enforces the same redirect-safety rules as the client-side JS guard: relative paths only, no `//`, no `\`, no absolute URLs, `@` blocked, 2048-character cap. Rejection emits `OPEN_REDIRECT_ATTEMPT_BLOCKED` audit event. ASVS V5.1.5 / CWE-601.
- **feat(audit): tamper-evident audit chain — bigserial sequence column** — migration `0014` adds a `BIGSERIAL seq` column to `audit_events` for strictly monotonic cross-batch ordering, independent of timestamp collisions. `run_daily_checkpoint` orders by `seq NULLS LAST`. Existing rows backfilled preserving wave-2 ordering. ASVS V7.3.3 / NIST AU-10.

### Fixed

- **fix(agents): Langflow and Letta `OPENAI_API_BASE` corrected to `:8081`** — both bundled agents had `gateway:8080` (the mTLS-only listener). Langflow and Letta carry no client certificate, so every LLM dispatch hit an mTLS handshake failure. Corrected to `gateway:8081` (the in-mesh plain-HTTP listener). Helm value updated in parallel.
- **fix(openwebui): `@Help` CHAINING_GUIDE half-implementation removed** — a model seeded as `@Help` appeared in the UI @-mention picker but was never registered as a real agent; any invocation returned 404.
- **fix(pgbouncer): compose-Helm `admin_users` / `stats_users` parity** — `helm/yashigani/files/pgbouncer.ini` was missing `admin_users =` and `stats_users =` directives, leaving the pgbouncer admin console accessible to any client authenticated as `yashigani_app`. Empty string disables both consoles in pgbouncer 1.21+.

### Security

- **security(secrets): per-key Docker named-secrets on agent containers** — the wholesale `./secrets:/run/secrets:ro` bind-mount removed from openclaw entirely (openclaw reads its bearer token from the JSON config; PKI material is inaccessible). Langflow and Letta use a single named Docker secret (`yashigani_internal_bearer`, mode 0440). `letta-pgbouncer` uses 4 named secrets covering exactly the files it consumes. Eliminates the class where a container RCE on an internet-adjacent agent could read the HMAC key and bypass the Caddy auth perimeter.
- **security(sod): admin/user separation-of-duties enforcement** — collision checks on all account creation paths (local auth, SCIM provision, SSO/SAML callback) prevent the same email/username appearing as both admin and user. `/auth/verify` (the Caddy forward_auth target) now rejects admin sessions with HTTP 403. A daily cron audits cross-store conflicts and emits `IDENTITY_STORE_CONFLICT` events. NIST AC-5 / SOC 2 CC6.3 / ISO 27001 A.5.16 / CMMC AC.L2-3.1.4.
- **security(opa): OPA conformance gaps closed** — `GET /v1/models` is now OPA-evaluated per principal (human/admin principals receive the full list; service-account principals receive a restricted list). The `/{path:path}` catch-all proxy response leg now has an OPA response-decision check mirroring the `/v1/chat/completions` pattern. Both gaps previously allowed traffic to bypass the OPA policy gate.
- **security(opa): response-content sensitivity classification** — `ResponseInspectionPipeline` now classifies the response body for sensitivity when configured, and the OPA response ceiling check uses the actual response sensitivity rather than the prompt sensitivity. `/agents/*` gained a response-leg OPA check with the same sensitivity model.
- **security(auth): TOTP failure counter migrated to Redis** — the in-process Python dict (`_totp_failures`) reset on every restart, allowing bypass of the 3-failure lockout by triggering a process kill. Migrated to Redis key `yashigani:totp_fail:<session_prefix>` with 1800 s TTL. Fail-closed: HTTP 503 when Redis is unavailable. ASVS V6.3.5 / CMMC IA.L2-3.5.7 / ISO 27001 A.5.17.
- **security(perimeter): Caddy egress restricted via iptables OUTPUT allowlist** — post-Caddy-RCE, an attacker cannot reach arbitrary internet endpoints for exfiltration or C2. The allowlist permits loopback, in-mesh bridge subnets, Docker DNS, and resolved IPs of the configured ACME/OCSP providers. A Kubernetes NetworkPolicy provides equivalent enforcement in K8s. `NET_ADMIN` capability added to Caddy (scoped to the container's network namespace). Operator override: `YASHIGANI_CADDY_EGRESS_ALLOWLIST`.
- **docs(release-signing): SSH-only signing scheme formally declared** — GPG CI path removed (hardware-backed key cannot sign in CI without the physical device). `docs/security/release-signing.md` documents the SSH verification recipe and key rotation procedure. `docs/release-signing-key.pub` is the operational verification artefact.

---

## [v2.24.1] — 2026-05-25

Theme: **Audit chain, OPA coverage, multi-tenant manifest, runtime rate limiting**.

### Added

- **feat(audit): tamper-evident hash-chained audit events** — migration `0011` adds `prev_hash` and `event_hash` (SHA-384) columns to `audit_events`. Every production insert computes and stores the chain links; the daily `run_daily_checkpoint` job anchors the Merkle root. ASVS V7.3.3 / NIST AU-10.
- **feat(audit): multi-tenant manifest registration ledger** — `manifest_registrations` table tracks the ceremony record for every agent manifest onboarding, providing an auditable chain of custody per agent identity.
- **feat(audit): operator identity attestation on `yashigani onboard`** — the onboarding command now records the attesting operator's admin identity in the manifest ceremony record.
- **feat(grc): machine-readable risk-register tooling + staleness gate** — risk tracking moved to a formalised machine-readable schema with an automated gate that fails when the register has not been updated within the configured window. (The register itself is an internal operations artefact and is not distributed with the public repository.)
- **feat(caddy): admin API moved to Unix socket** — Caddy's admin API migrated from TCP `:2019` to a Unix socket, eliminating the in-container TCP listener that could be reached by other services on the bridge network.
- **feat(fips): SHA-256 backup manifest routed through OpenSSL FIPS Provider** — when `FIPS_MODE=1`, the `MANIFEST.sha256` generation in `install.sh` routes through the OpenSSL FIPS Provider (`lib/yashigani-fips.sh`). Closes the route-integrity use case for FIPS 140-3 installations.

### Security

- **security(opa): GAP-1 fail-closed catch-all for unknown sensitivity ranks** — a Rego rule was added to treat any unrecognised `sensitivity_rank` string as RESTRICTED, preventing a crafted or unknown value from bypassing the sensitivity ceiling check.
- **security(kms): `YASHIGANI_KSM_PROVIDER` renamed to `YASHIGANI_KMS_PROVIDER`** — backward-compat shim retained for existing deployments.

---

## [v2.24.0] — 2026-05-25

Theme: **Audit chain foundation, agent secrets distribution, container supply-chain, RBAC/OPA depth**.

### Added

- **feat(pki): BYO intermediate RSA key acceptance** — `bootstrap()` now accepts a `byo_intermediate` CA source mode, allowing operators to provide an externally-generated RSA intermediate key.
- **feat(ci): Trivy agent-image CI gate** — a CI job scans bundled agent images (Langflow, Letta, OpenClaw) and fails on HIGH/CRITICAL CVEs not present in the allowlist (`trivy-agent-allowlist.json`).
- **feat(ci): agent image built-in component scan** — bandit and opengrep run against bundled agent image source at build time.

### Fixed

- **fix(postgres): pgbouncer_authenticator role + `pg_hba` auth carveout** — a dedicated `pgbouncer_authenticator` role with a `SECURITY DEFINER` auth-query function plus a targeted `pg_hba.conf` carveout allows pgbouncer to authenticate without requiring superuser privileges on the postgres user. Multiple iterations landed in this release; see v2.24.3 for the final stabilised form.
- **fix(secrets): per-consumer secret ownership** — secret files written by `install.sh` now use per-consumer UID:GID and mode rather than a single shared GID, closing the cross-secret-read class.
- **fix(install): VEB compose variable-expansion sanitisation** — variable-expansion bypass (`${PASS}` in compose files) and an installer strip-pattern that could mutate passwords containing special characters are both fixed.

### Documentation

- **docs**: `docs/operator-guide.md` created — OPA+inspection pairing recipe, XFF trust-boundary clarification, `PASSWORD_MAX_AGE_DAYS` fix, and admin/user separation guidance.
- **docs**: `docs/security/xff-trust-boundary.md` — documents XFF trust model and `TRUSTED_PROXY_CIDRS` configuration.
- **docs**: `docs/security/release-signing.md` and `docs/release-signing-key.pub` — SSH signing key and verification instructions.

---
## [v2.23.4] — 2026-05-21

> The v2.23.4 release closes the v2.23.3 follow-up backlog, ships the SAML BYOK
> config-load surface, multi-platform install robustness improvements, a
> new CI gate that prevents Caddyfile / service-identity drift between compose
> and Helm, an architectural close of the cleanup-system class (state file +
> container-fallback rm + cross-UID handlers across install/uninstall), the
> pgbouncer mTLS sidecar (`letta-pgbouncer`), and the
> KMS-architectural reframe for credential handling (non-KMS dev posture vs
> KMS-configured production posture documented at
> `docs/yashigani_install_config.md` §6.1).

### Added

- **Open WebUI → gateway in-mesh path** — gateway now exposes a dual-port
  surface: `:8080` for mTLS edge traffic and `:8081` for plain-HTTP in-mesh
  traffic from Open WebUI carrying an `Authorization: Bearer
  yashigani-internal` token. Open WebUI joins the `caddy_internal` network
  and routes chat completions via the gateway rather than direct to Ollama,
  so OPA policy + identity-binding apply to UI traffic just like to API
  traffic. Closes the "Open WebUI bypasses the gateway" architectural gap.
- **Installer use-case wizard** — interactive `install.sh` now asks whether
  Yashigani will be used by humans with a web UI (default `Y`, installs Open
  WebUI as the chat surface) or as an API/agent-only deployment (`N`,
  skips Open WebUI). Non-interactive `--with-openwebui` flag unchanged.
- **Ollama default-model auto-pull on `--with-openwebui`** — first install
  with Open WebUI now pulls `qwen2.5:3b` automatically so the chat UI works
  out of the box. Helm chart equivalent: `ollama-init` Job pulls the same
  model when `openWebui.enabled=true`. Skip with `--no-default-model`.
- **SAML BYOK config-load surface** — `broker.add_idp()` now accepts SAML
  identity-provider configurations via the `YASHIGANI_IDP_<N>_SAML_*`
  environment variables (idp metadata URL/XML, SP entity ID, ACS URL, SP
  private key, SP certificate). `_assert_rsa_sp_key()` runs at config-load
  time, rejecting non-RSA SP keys at container startup rather than at first
  signature attempt. Mitigates the libgcrypt ECDH heap-overflow class
  (CVE-2026-41989) at config-load.
- **HUMAN identity registration on local-auth login** — local password+TOTP
  users now get an identity-registry entry created automatically on first
  login, with tier-aware metadata. Closes the design gap where local-auth
  users had no identity-registry presence.
- **`/me/api-key` self-service Bearer issuance** — users can mint, list, and
  revoke their own API keys from the user UI. Step-up TOTP required for
  issuance (ASVS V6.8.4). API-key strings are hash-stored; `last4` shown in
  UI for identification.
- **Container auto-start on host reboot** — compose installs now provision a
  user-scoped `systemd --user` unit under `loginctl enable-linger` so the
  gateway and backoffice come back up after a host reboot without operator
  intervention. Helm path already handled by Kubernetes.
- **`--http-port` / `--https-port` CLI flags** — `install.sh` exposes port
  remapping for hosts where 80/443 are taken. Defaults unchanged.
- **Langflow + Letta in `agentBundles`** — Helm chart wires Langflow and Letta
  as opt-in agent-bundle services with per-bundle tokens, `securityContext`,
  and matching K8s Secrets. Disabled by default.
- **Email-as-username + suspended-identity reactivation flow** — local-auth
  accounts identify by email rather than free-form username; admin
  reactivation action covers the suspended-identity case.
- **Auth-gated OpenAPI / Swagger UI** — the Backoffice now exposes
  `GET /admin/openapi.json`, `GET /admin/api-docs` (Swagger UI), and
  `GET /admin/api-redoc` behind `require_admin_session`. The Gateway exposes
  `GET /openapi.json` and `GET /docs` behind identity resolution (same
  Bearer/SSO check as `/v1/*`). Anonymous access returns 401. Swagger UI
  assets are self-hosted from `static/swagger-ui/` (swagger-ui-dist 5.32.6)
  to satisfy `script-src 'self'` CSP.

### Fixed

- **Gateway pgbouncer-DSN advisory-lock deadlock** — `run_migrations()` in the
  gateway service used the pgbouncer DSN for the migration advisory lock.
  Under pgbouncer session-recycling the lock survived `lock_conn.close()`,
  leaving it held on a recycled backend pid; the backoffice's lifespan
  acquisition then deadlocked. Surfaced on Mac Podman (Linux VM was
  timing-lucky). Fix: gateway service now has `YASHIGANI_DB_DSN_DIRECT`
  pointing at postgres directly, matching the long-standing backoffice
  pattern.
- **Install — contaminated-volume detection** — `install.sh` now refuses to
  proceed when a leftover `docker_postgres_data` volume holds an old PKI CA
  bundle, because postgres DB-init scripts run only on an empty volume.
  Operator is directed to `uninstall.sh --remove-volumes` or
  `install.sh --upgrade`.
- **Uninstall — partial `.env` handling** — `uninstall.sh` now stubs missing
  required `:?` environment variables before `compose down`, covering the
  operator path where a prior install failed partway and left an incomplete
  `docker/.env`. Previously gated only on `.env` being entirely absent.
- **Uninstall — dependency-graph leak on `--remove-volumes`** — compose-down
  now force-removes containers in leaf-first dependency order before volume
  removal, then runs a final cleanup pass to catch redis straggler containers
  that respawn during Podman network teardown.
- **Uninstall — multi-user PKI cleanup** — `docker/secrets/` is now wiped on
  `--remove-volumes` so a subsequent install by a different Unix user does
  not fail on PKI key ownership.
- **macOS Podman — virtiofs `:U` ownership remap** — all bind-mounts of
  secret material apply `:U` (and ephemeral chown where needed) on macOS
  Podman. Linux Podman unaffected. Scoped to macOS Podman after a regression
  on rootful Linux.
- **Helm — OPA mTLS wired correctly on K8s install**, and OPA probes use the
  HTTPS scheme when `mtls.enabled=true`.
- **Helm — `tls_trusted_ca_certs` → `tls_trust_pool`** chart-side Caddyfile
  migration to caddy 2.11's replacement directive.
- **Helm — `admissionPolicies.enabled` default is now `false`** because the
  chart's Kyverno ClusterPolicy resources require Kyverno to be installed
  in the cluster. Default-on caused stock `helm install` to fail on clusters
  without Kyverno. Opt in with `--set admissionPolicies.enabled=true`; the
  chart now fails fast with a friendly error if Kyverno CRDs are missing.
- **SPA — inline styles removed; CSP tightened** with no `unsafe-inline` for
  `style-src`.
- **Auto-agent-registration — 401 on Layer B header path fixed** during
  installer-driven agent bundle registration.
- **Helm — K8s OPA policy bundle aligned with compose** — the helm chart
  previously shipped a stub OPA ConfigMap with package `yashigani.v1_routing`
  and no `decision` / `allow_v1` rules. Gateway read `result.get("allow",
  False)` against that empty result → 403 on every K8s chat request.
  Replaced with the verbatim compose `policy/{yashigani,v1_routing,rbac,
  agents}.rego` bundle so K8s and compose make the same policy decisions.
- **Compose — PKI bootstrap_token SHA-256 manifest mismatch** — the
  gateway failed closed with "Bootstrap token SHA-256 mismatch for 'gateway'"
  on macOS Podman because (a) `rotate_leaves()` discarded the recomputed
  hash return value and (b) Podman applehv's host→VM cp-back silently
  failed to update the host-side manifest. Fixed both: `rotate_leaves()`
  now persists the hash, and the install path verifies the host manifest
  matches the in-VM manifest before declaring the gateway ready.
- **Helm — bootstrap_token files in PKI Secret** — K8s PKI Secret now
  includes the `bootstrap_token` files referenced by OPA mTLS. Previously
  absent on K8s installs, which left the rotate-leaves path 503ing on
  upgrade. Skipped on K8s entrypoint where K8s-native mTLS handles
  identity binding.
- **Helm — `ollama-init` Job unblock** — three compounding K8s Job failures
  fixed: (1) the wait-for-ollama init container now uses a digest-pinned
  busybox image because the ollama image does not ship `wget` and the
  `/dev/tcp` shell probe is unreliable on K8s, (2) `allow-ollama-ingress`
  NetworkPolicy now permits ingress from the Job pod's labels, (3) new
  `allow-ollama-init-egress` NetworkPolicy permits DNS + ollama egress for
  the Job pod which was previously caught by `default-deny-egress`.
- **Open WebUI — network isolation + gateway connectivity** — Open WebUI
  joined the `caddy_internal` network; gateway connection uses HTTP (mesh
  port) not HTTPS to avoid certificate-of-internal-DN trust loops.
  `OPENAI_API_BASE_URL` and `OPENAI_API_KEY` env wiring routes through
  the gateway with the in-mesh Bearer.
- **Open WebUI — RAG embeddings via Ollama; HuggingFace offline** —
  `RAG_EMBEDDING_ENGINE=ollama` + `HF_HUB_OFFLINE=1` +
  `TRANSFORMERS_OFFLINE=1` so Open WebUI doesn't try to reach
  huggingface.co on startup in air-gapped installs.
- **Backoffice — WebAuthn service init signature** — `WebAuthnService.__init__`
  now correctly receives `config=WebAuthnConfig()` (was missing the
  positional argument, causing a deferred runtime crash on first WebAuthn
  registration attempt).
- **Linux aarch64 Podman rootless — template permission silent-noop** —
  `RUN chmod -R a+rX /usr/local/lib/python3.14/site-packages/yashigani/`
  added to gateway + backoffice Dockerfiles. Background: Podman rootless
  on Linux aarch64 silently drops the CAP_CHOWN that `pip install` relies
  on, leaving Python package files root:root mode 0640 — unreadable by the
  in-container yashigani UID 1001. Surface symptom was Jinja
  `TemplateNotFound` at first HTTP request.
- **Helm — Kyverno ClusterPolicy three bugs** — JMESPath expression
  malformed in one resource selector; `foreach` block referenced the wrong
  variable scope; APE rule referenced a field that may be absent on certain
  resource shapes. All three now fixed; admission-policies CI test exercises
  the corrected rules against fixtures.
- **Uninstall — wazuh-compose anonymous-volume leak** — wazuh add-on
  containers create anonymous volumes that survive `compose down -v`. The
  canonical uninstall volume list now includes them, plus a final
  `podman volume prune --filter dangling=true` pass.
- **Auth — `/auth/stepup` widened to accept user sessions** — previously
  only admin sessions could complete step-up TOTP verification. The
  `/me/api-key` self-service customer flow at `src/yashigani/backoffice/routes/me.py:215`
  requires `assert_fresh_stepup(session)`, but `/auth/stepup` at
  `auth.py:837` was gated to admin sessions only — making the customer
  feature unreachable for the user persona it was documented for.
  `AdminSession` → `AnySession` widens the dependency to accept any
  authenticated session while preserving every existing guard
  (anonymous-rejection, replay-cache, per-session failure counter at 5
  attempts, cross-tenant guard, audit-event emission). Closes a v2.23.4
  pre-tag finding (Gap B in `finding-me-api-key-unreachable.md`).
- **Caddy — `handle /me/*` block added to all 4 Caddyfiles** — compose
  selfsigned/acme/ca + the helm-rendered Caddyfile fragment now route
  `/me/*` to backoffice. Without this, `POST /me/api-key` returned HTTP
  405 from Caddy's default response (route was implemented in backoffice
  code but unreachable at the edge). Closes the other half of the
  pre-tag finding (Gap A in `finding-me-api-key-unreachable.md`). Each
  block matches its file-local `/auth/*` template — same mTLS,
  `inject-caddy-verified` HMAC, transport snippet.

### Security

- **SAML SP-key RSA enforcement at config-load** — non-RSA SP private keys
  rejected at `SAMLProvider.__init__`, preventing the EC-key path from
  reaching python3-saml. Mitigates the libgcrypt ECDH heap-overflow CVE
  class regardless of upstream patch availability.
- **python3-saml manual-re-audit gates** — `xmlparser.py` entity and
  DTD-resolution paths flagged for manual re-audit at every upstream bump.
- **Helm — `sslmode=require` fallback removed; fail-closed on misconfig**
  — `_build_ssl_context` in the partition-maintenance ConfigMap previously
  accepted `sslmode=require` (no server-cert validation). It now raises
  `ValueError` on any mode other than `verify-ca` / `verify-full` so a
  misconfigured DSN fails at startup rather than silently bypassing TLS
  certificate validation. New `validate-security.yaml` guard fails fast
  if `postgres.enabled=false` and `postgres.tls.ca` is unset in production
  or staging. 9-test regression suite at
  `tests/contracts/test_helm_sslmode.py`. Closes F-V232-002 (ASVS V14.4.1).
- **CI — gitleaks secret-scan workflow added** — `.github/workflows/secret-scan.yml`
  runs `gitleaks/gitleaks-action@ff98106` (v2.3.9) against PR diffs and the
  full history on push to release branches. `.gitleaks.toml` config covers
  AWS / Stripe / private-key / generic-API-key / Yashigani-specific
  patterns. Historical false-positives captured in
  `gitleaks-baseline.json` so CI only fails on **new** leaks. Closes
  F-V232-003 (ASVS V10.3.4).
- **CI — Checkov IaC scan on Helm template output** —
  `.github/workflows/helm-iac-scan.yml` runs
  `bridgecrewio/checkov-action@4048c97` against `helm template` output
  across the default + external-postgres value matrices. Allowlist in
  `.checkov.yml` (101 entries; each cites a YSG-RISK ID or ARCH/CLUSTER
  classification — no uncited suppressions). Closes F-V232-004 (ASVS V12.5.1).
- **Trivy base-CVE hygiene — `apt-get -y upgrade` in both Dockerfiles**
  — `docker/Dockerfile.gateway` and `docker/Dockerfile.backoffice` now
  run `apt-get -y upgrade` between `apt-get update` and `apt-get install`,
  so image builds pull Debian trixie security-updated base packages
  rather than only the snapshot baked into the `python:3.14.0-slim` base.
  Closes CVE-2026-29111 (systemd) and CVE-2026-4878 (libcap2) on both
  images. Remaining 3 CVEs (CVE-2025-69720 ncurses, CVE-2026-41989
  libgcrypt, CVE-2026-6732 libxml2) are all NOT-EXPLOITABLE-CVA per
  pre-existing verdicts independent of package version. Trivy rescan
  Post-fix Trivy rescan confirmed clean.
- **Admin/user tier separation regression test** — covered with a real
  fakeredis-backed integration test exercising the production registration
  path (not a mock).

### Changed

- **Version bumped 2.23.3 → 2.23.4** across `pyproject.toml`, `install.sh`,
  `docker-compose.yml` defaults, helm `values.yaml`, `airgap/manifest.yml`,
  and `AI_ASSETS.md`. The v2.23.4 branch was cut from v2.23.3 tip without
  the initial version bump; this closes the drift so `install.sh` against
  v2.23.4 source builds and deploys v2.23.4-tagged containers (rather than
  silently building `:2.23.3`-tagged ones from v2.23.4 code).

### CI / Tooling

- **Caddyfile family parity gate** — new workflow runs `caddy adapt` against
  each compose Caddyfile variant (`acme`, `ca`, `selfsigned`) plus the
  helm-rendered Caddyfile fragment, asserts exit 0, and verifies per-listener
  directive parity across the compose variants. Adds a `service_identities.yaml`
  dedup check (single source of truth via symlink) and a Helm env-var parity
  check that catches the gateway-DSN-DIRECT class of regression.
- **OpenAPI schema drift gate** (`api-docs-drift` CI job) — regenerates
  `docs/api/*.md` from the live FastAPI schema and fails the build if the
  committed markdown has drifted. Catches schema changes that aren't reflected
  in the published API reference.

### Documentation

- **API reference docs** (`docs/api/`) — three markdown files generated from
  the live OpenAPI schema: `gateway-api.md` (operator/agent-facing),
  `admin-api.md` (backoffice management plane), `auth-api.md` (shared auth
  endpoints). `docs/api/README.md` index links all three. Files are regenerated
  by `scripts/gen_api_docs.py` and drift-checked in CI.
- **Architecture cleanup** — removed unimplemented bare-metal install claims
  from `Architecture.md`. Bare-metal install was design intent that never
  shipped code.
- **`iptables FORWARD` precondition** for rootful Podman installs on test
  VMs documented (production hosts with sane FORWARD policy unaffected).
- **SHA-256-compatible authenticator app guidance** in post-install message
  — Yashigani uses HMAC-SHA-256 per the SHA-256 minimum policy; apps that
  ignore the `algorithm` parameter (e.g. older Google Authenticator) silently
  default to SHA-1 and produce wrong codes.

### Breaking Changes — review before upgrade from v2.23.3

- **OPA fail-closed posture** (`318a3db` + `f720857`) — the OPA response-check
  in `src/yashigani/gateway/openai_router.py` now returns
  `allow: False` on EVERY exception path (timeout, 5xx response, connection
  refused, `opa_not_configured`) instead of the prior `allow: True`. Helm
  enforces it at deploy-time via the `OPA-URL-001` violation when
  `global.environment=production` and `gateway.env.YASHIGANI_OPA_URL` is
  empty. **Operational impact:** an OPA outage now causes inference requests
  to be denied until OPA recovers, instead of silently allowing all traffic
  through. This is the correct zero-trust posture per the project's
  zero-trust default, but it IS a behavioural break for operators upgrading
  from v2.23.3 with intermittently-reachable OPA. Alert on
  `yashigani_opa_response_check_failures_total` rate (new Prometheus counter
  registered in `metrics/registry.py`) to spot OPA reachability issues early.
  Dev opt-in: set `YASHIGANI_OPA_OPTIONAL=true` AND keep `YASHIGANI_ENV` out
  of production / staging to preserve the prior fail-open behaviour during
  local development.

### Security (additional hardening)

- **`yashigani-internal` Bearer rotated to per-install secret** (`514316d`
  gateway env-var read + `27d46ab` `install.sh` token generation +
  compose+helm secret wiring on the pre-rebase `fcc551a`). The literal
  string `yashigani-internal` is gone from production source. `install.sh`
  generates a 36-char charset-compliant token at install time, written to
  `docker/secrets/yashigani_internal_bearer` at mode 0600; Helm equivalent
  via the `yashigani-agent-bearer` Secret with upgrade-safe `lookup`.
  Compose entrypoint shims export the secret to `OPENAI_API_KEY` for Open
  WebUI + Langflow + Letta service consumers. Gateway compare uses
  `hmac.compare_digest`.
- **`OPA_RESPONSE_CHECK_FAILED` audit-event type added** (`src/yashigani/audit/schema.py`,
  shipped in `318a3db`). New Prometheus counter
  `yashigani_opa_response_check_failures_total{outcome, reason}` registered
  at module load.
- **`account_tier` audit-accuracy comprehensive sweep** — across the
  v2.23.4 close-out the audit-event constructors in `src/yashigani/backoffice/routes/auth.py`
  and additional `_config_event` / `_full_reset_event` / similar helpers in
  `users.py`, `accounts.py`, `audit.py`, `ratelimit.py`, `inspection.py`,
  `kms.py`, `pg_auth.py`, `webauthn_v1.py` were widened to derive
  `account_tier` from the session/account record instead of hardcoding
  `"admin"`. With `/auth/stepup` now widened to accept user sessions, the
  hardcode would otherwise have written user-tier step-ups to audit log as
  admin-tier events (ASVS V7.3.4). Commits: `9007e11`, `9a50285`,
  `8682695`, `b55c8f1`, `c04627f`, `2379d19`.
- **Anonymous-caller upstream rejection** (`318a3db` step 1b). On
  `/v1/chat/completions` and adjacent inference endpoints, an unauthenticated
  caller is now rejected with HTTP 401 BEFORE the OPA response-check is
  reached. Previously, an `identity is None` caller would short-circuit the
  OPA check entirely via the `if _state.opa_url and identity` guard at
  line 1010; that guard is now `if _state.opa_url` because identity is
  guaranteed non-None by the new upstream gate. The `yashigani-internal`
  Bearer presents `kind=service` identity and passes the upstream gate
  unaffected.

### CI / Tooling — additional

- **`acs-v3-hardcoded-bearer-auth-bypass`** rule shipped on the ACS side
  (CWE-798, ASVS V6.3.2, OWASP A07:2021, OWASP API API2, NIST IA-5, CMMC
  IA.L2-3.5.2). Detects `if token == "<literal>"` / `if key in ("<literal>",)`
  / `hmac.compare_digest(<var>, "<literal>")` / lowercase-normalised
  comparisons / direct config-template literal assignments in
  auth-handling paths. Wired into 19 of 20 framework files (ACS rc2). New
  detection-lane that would have caught the `yashigani-internal` literal
  before it shipped.

### Documentation — additional

- **OPA fail-closed operator runbook** — `_opa_response_check` docstring
  in `openai_router.py` now describes the new fail-closed behaviour, the
  audit-event emission, the Prometheus counter, and the operator response
  when an OPA outage causes denials. Replaces the prior misleading
  docstring that claimed audit coverage that did not actually fire.

### Security (tag close-out addendum 2026-05-21)

- **`letta-pgbouncer` mTLS sidecar** — letta's postgres connection now
  routes through a dedicated `letta-pgbouncer` session-mode sidecar
  (`edoburu/pgbouncer:v1.25.1-p0`, UID 70, `read_only:true`, `cap_drop:[ALL]`,
  `no-new-privileges`). The sidecar presents `letta-pgbouncer_client.crt`
  to postgres over mTLS; the postgres `pg_hba.conf` catch-all
  (`hostssl all all 0.0.0.0/0 scram-sha-256 clientcert=verify-ca`) applies
  uniformly with no letta carveout. asyncpg+pg8000 limitation (cannot
  present client certs via URI params) is closed at the sidecar boundary.

- **pgbouncer `auth_type=plain` posture documented as non-KMS-only** — the cleartext userlist.txt is the expected posture for non-KMS dev/standalone deployments. Production deployments configure a KMS provider via `YASHIGANI_KMS_PROVIDER=vault|azure|aws|gcp|keeper` which fetches credentials at runtime — the cleartext-on-disk path is bypassed entirely in KMS-configured deployments. Documented at `docs/yashigani_install_config.md` §6.1.
- **GID 2002 cross-secret read (LOW)** — containers sharing GID 2002 can read all three shared secrets rather than only their own. No exploit chain in v2.23.4 (mitigated by cap_drop:ALL + read_only rootfs). Per-consumer credentials tracked for v2.24.0.
- **pgbouncer admin console lockdown** — both yashigani-pgbouncer and
  letta-pgbouncer `pgbouncer.ini` now set `admin_users =` empty and
  `stats_users =` empty, disabling the admin console (was inadvertently
  open to `yashigani_app` cred on yashigani-pgbouncer).

### Fixed (tag close-out addendum 2026-05-21)

- **Cleanup-system architectural close — state file + container-fallback rm
  + cross-UID handlers across install/uninstall.** Root cause of five
  cascading uninstall/clean-slate blockers: install.sh and uninstall.sh
  shared a working directory but shared no persisted state, forcing every
  cleanup heuristic (runtime detect, ownership assumption, stale-dir
  detection) to guess. Architectural close:
  - **State file** `docker/.yashigani-install-state` (mode 0644, key=value:
    `RUNTIME`, `INSTALL_UID`, `INSTALL_USER`, `INSTALL_TIMESTAMP`,
    `YASHIGANI_VERSION`) written by install.sh at install completion.
    Mode 0644 is correct (0600 would re-introduce the cross-UID problem).
    `.gitignore` entry added.
  - **uninstall.sh reads state file before auto-detect** — state-file
    `RUNTIME` value beats `podman info`/`docker info` heuristic on
    dual-runtime hosts. Falls back to auto-detect if state file absent
    (backwards-compatible with pre-v2.23.4 installs).
  - **Container-fallback rm for `docker/{data,certs,logs}`** — when host-side
    `rm -rf` fails on chown'd dirs (cycle-3 install-side chown to 1001:1001),
    fall back to `podman unshare rm` → ephemeral runtime container `rm -rf
    /t/*`. No sudo required.
  - **Sudo-free secrets wipe** — `sudo rm -rf
    docker/secrets/*` silently failed on non-PTY SSH. Replaced with the
    same three-tier fallback (direct → `podman unshare` → container-root
    `rm` against `docker/secrets:/t:rw`). Hard WARN on all-fail (no silent
    swallow). `${_ALPINE_IMAGE:?...}` guard against unset variable.
  - **Dotfile-aware wipe glob** — bare `rm -rf /t/*` does NOT match
    dotfiles. `.pki-status` (written by `_pki_run_issuer`) survived the
    wipe → `rmdir` then failed → blocker re-manifested. All three wipe
    tiers updated to POSIX-portable glob: `rm -rf /t/* /t/.[!.]* /t/..?*`
    (matches dotfiles excluding `.` and `..`; works in Alpine `sh`).
  - **`rmdir` after content wipe** — empty `docker/secrets/` dir rmdir
    works regardless of host owner; closes the stale-dir blocker.
  - **`uninstall.sh` `log_info` helper** — was missing from uninstall.sh,
    breaking the state-file detect block under `set -euo pipefail`. Helper
    restored.
  - **`.env` cross-UID handler** — now
    skip-with-WARN on unreadable `.env` (test-infra contamination scenario
    where a prior install ran as a different UID and wrote `docker/.env`
    as `root:root`). `docker compose down` proceeds via Docker socket
    without host-side `.env` read; `--env-file /dev/null` + process-env
    stubs satisfy `:?` declarations. Three `.env` read sites guarded.
  - **`_do_chgrp` hoisted to script scope** — bash nested-function bug
    where `_do_chgrp` was defined inside `_pki_chown_client_keys()` but
    called from `generate_secrets()` (earlier in install sequence) →
    `command not found` under `set -euo pipefail`. Lifted to top-level
    helper; sibling check confirmed `_do_chown` and `_do_chmod_dir` are
    still nested-only-callers from within `_pki_chown_client_keys`.
- **pgbouncer entrypoint CMD chain restored** — the MD5 shim experiment
  ended with `exec /entrypoint.sh` (no args). edoburu's entrypoint last
  line is `exec "$@"` — with empty `$@`, exec exits cleanly without
  launching pgbouncer. Fixed in all four sites (compose × 2 services +
  helm template + values.yaml sidecar): `exec /entrypoint.sh pgbouncer
  /etc/pgbouncer/pgbouncer.ini` restored.
- **pgbouncer `auth_file = /etc/pgbouncer/userlist.txt` directive restored
  in all three ini files** (`docker/pgbouncer/pgbouncer.ini`,
  `docker/pgbouncer/pgbouncer-letta.ini`,
  `helm/yashigani/files/pgbouncer.ini`). The SCRAM-revert dropped the
  directive entirely instead of restoring its pre-SCRAM value, leaving
  pgbouncer with no user lookup mechanism even though userlist.txt was on
  disk.
- **Air-gap install Step 9 image-digest verification** — `docker load`
  does not populate `RepoDigests`, so the prior verification loop reported
  silent `0 image(s) verified`. `scripts/prepare-airgap-bundle.sh` now
  captures `docker inspect --format '{{.Id}}'` at bundle-build time and
  writes an `id:` field into each manifest entry; install.sh verification
  falls back to `.Id` (content-addressable SHA-256) when `RepoDigests` is
  empty. Backwards-compatible for pre-extension manifests (warn-and-skip;
  bundle SHA + helm/compose digest-pin remain primary integrity controls).

- **`install.sh:5101` `|| true` guard on podman cp fallback** — the
  compose-cp/podman-cp fallback chain at lines 5100-5101 had `|| true`
  on the subsequent exec lines but not on the cp fallback itself. When
  open-webui is absent from `COMPOSE_PROFILES` (e.g.,
  `--agent-bundles letta,langflow` without `all`), the cp tried to copy
  into a non-existent container and hung indefinitely under
  `set -euo pipefail`. Closes the Phase 1 cp-hang.
- **uninstall.sh runtime detection prefers Podman with liveness probe** —
  was misdetecting runtime as Docker on Podman-only VMs (and via
  symmetrical inversion on dual-runtime hosts), calling `docker volume rm`
  against Podman volumes which silently no-oped. Detection now uses
  `podman info` liveness probe first, `docker info` fallback. Operator
  `--runtime=` override preserved.
- **uninstall.sh chown container-fallback for `docker/{data,certs,logs}`** —
  mirror of install-side cycle-3 container-fallback pattern. Closes


### Changed (tag close-out addendum 2026-05-21)

- **Dead-code `fasttext_backend.py` removed** — `src/yashigani/inspection/backends/fasttext_backend.py`
  deleted; was a 130-line vestigial leftover from the v2.23.3 fasttext→sklearn
  swap (`e966e55`). Zero live imports verified before removal (collected
  2511 tests collected with no import errors).
- **Air-gap install docs (`docs/operations/air-gap-install.md`)** — `config/`
  added to Step 2 transfer file list;
  v2.23.3 version refs swept to v2.23.4 in the same docs commit.

### Documentation — tag close-out addendum

- **KMS posture note** at `docs/yashigani_install_config.md` §6.1 — clarifies
  that the cleartext userlist.txt is the non-KMS dev/standalone posture and
  that production deployments configure `YASHIGANI_KMS_PROVIDER=vault|azure|aws|
  gcp|keeper` to bypass the cleartext-on-disk path entirely. Captures the



---

## [v2.23.3] — 2026-05-11

> **Tag:** `v2.23.3` → commit `8cff2f6f` — SSH-signed by maintainer key `~/.ssh/id_ed25519` (no GPG). Signature verifiable with `git tag -v v2.23.3` once the SSH allowed-signers file is configured locally; verifiable on GitHub once the maintainer's SSH pubkey is registered as a Signing Key on the personal account.
>
### Added

- **feat/v233-issue-91-ssrf-pinned-resolver** — DNS-rebinding defence for outbound HTTP
  (`yashigani.net.pinned_resolver`). Resolves the target hostname once at context entry,
  verifies the IP against the SSRF allowlist/blocklist, and patches `socket.getaddrinfo`
  for the transport so subsequent DNS changes cannot redirect the connection. OWUI agent
  push (`backoffice/routes/agents.py _push_openwebui_model`) wired through pinned-resolver
  to defend against admin-account-compromise pivot. Closes OWASP API7 SSRF DNS-rebinding
  gap (issue #91). New exports: `pinned_resolver` via `yashigani.net`. New audit event type
  `SSRF_PINNED_RESOLVER_USED` (DEBUG). New security doc `docs/security/ssrf.md`. 18 new tests
  in `src/tests/security/test_dns_rebinding.py` + 8 OWUI tests in `test_owui_dns_rebinding.py`.
- **feat/v233-pki-bundle** — PKI admin UI (`/api/v1/admin/pki/*`) and BYO-CA driver (`YASHIGANI_PKI_CA_MODE=byo`). Closes #51 + #53.
  - Admin endpoints: `GET /chain/{service}` (cert detail + SHA-256 fingerprint), `POST /rotate/{service}` (step-up TOTP, ASVS V6.8.4), `GET /bundle/{service}` (PEM download, private key never included / CWE-200), `GET /status` (all-services overview).
  - BYO-CA driver: EC P-256 CSR generation → HTTPS signing endpoint (step-ca / Vault PKI) → chain validation → atomic key install. Auth modes: `token`, `mtls`, `none`. Fail-closed: `DriverError` on any failure — no silent fallback to internal issuer.
  - Service name regex `[a-z][a-z0-9_\-]{0,63}$` — path traversal prevention. Body limit 256 bytes (ASVS 4.3.1). Audit events: `PKI_CERT_ROTATED`, `PKI_CERT_ROTATION_FAILED`.
  - 23 new unit tests (PKI-D-01…12, PKI-R-01…11). 10 Playwright e2e tests (PW-PKI-01…10).
  - Driver abstraction: `yashigani.pki.drivers.{base,internal_ca,byo_ca}` + `yashigani.pki.driver_factory`.

- **chore(helm): customer-builds pattern for own images** — `helm/yashigani/values.yaml`
  `adminBootstrap.image`, `gateway.image`, and `backoffice.image` now use tag-only references
  (`yashigani-gateway:2.23.3`, `yashigani-backoffice:2.23.3`) with no registry prefix and no
  digest pin. Agnostic Security does not build or distribute gateway/backoffice images;
  operators build locally via `install.sh` from the v2.23.3 tagged source (compose path), or
  build and push to their own private registry for K8s deployments — matching the air-gap
  design from PR #114. Operators running K8s should update the `repository` field to their
  registry path and add `@sha256:<digest>` for supply-chain attestation. Third-party images
  (caddy, redis, opa, grafana, etc.) remain pinned to `name:tag@sha256:<digest>` as before.

### Security (v2.23.3)

- **feat/v233-issue-58-airgap** — Air-gap deployment support: operators build an offline bundle from a pinned `airgap/manifest.yml` on a connected host via `scripts/prepare-airgap-bundle.sh`, transfer it to the isolated host, and install with `install.sh --air-gap --bundle <path>`. Supply-chain design: Agnostic Security ships only the manifest (kilobytes); customers pull from upstream registries under their own attestation chain. Bundle assembly: per-profile selection (core/full/observability/agents/wazuh/spire); per-image digest verification fail-closed at pull and at load; `zstd`-compressed tar; SHA256 sidecar manifest for out-of-band integrity check. Installer changes: `--air-gap` + `--bundle` flags; bundle SHA256 verified against sidecar; each loaded image digest verified against `airgap/manifest.yml`; all outbound fetches (registry, HIBP, ACME) blocked; `--air-gap` implies `--offline` + `--tls-mode selfsigned`. Pre-flight G20 gate: bundle existence, manifest presence + parse, zstd availability, sidecar presence (warn). HIBP skipped in air-gap mode with operator guidance for manual rotation. Docs: `docs/operations/air-gap-install.md`. Tests: `tests/install/test_air_gap.sh` (negative, dry-run, manifest schema, Linux netns). Closes #58.
- **feat/v233-issue-90-bopla** — API3 BOPLA per-property allowlist audit (#90): adds explicit deny-by-default public-view Pydantic schemas (`AdminAccountPublic`, `UserAccountPublic`, `SiemTargetPublic`, `IdPPublic`, `JWTConfigPublic`, `JWTTestResultPublic`) backed by `model_config extra='forbid'`. List endpoints for admin/user accounts now route through these schemas, guaranteeing `password_hash`, `totp_secret`, `recovery_codes`, `failed_attempts`, `locked_until`, `totp_failed_attempts`, `totp_backoff_until` are never serialised. SIEM target list explicitly excludes `auth_value` (bearer/HEC token). SSO IdP list excludes `client_secret`, `client_id`, `private_key`, `signing_cert`, `org_id`. JWT test result filtered via `SAFE_JWT_CLAIMS` allowlist stripping `email`, `phone_number`, `given_name`, `family_name`, `address` and other PII claims. One-time-delivery exceptions (admin/user create, agent register/rotate) documented in `docs/security/bopla-allowlist.md`. 54 regression tests in `test_v2233_bopla_allowlist.py`. OWASP API3:2023, ASVS V4.2.1, CWE-213.

- **feat/v233-backup-encryption** — `scripts/backup.sh` (new) produces age-encrypted `<timestamp>.tar.gz.age` backups via AES-256-GCM (age X25519). `restore.sh` extended with `--encrypted <identity.age> <archive>` path; legacy unencrypted archives accepted with deprecation warning. `age=1.2.1-1+b5` added to both Dockerfiles. Helm chart adds `backup-cronjob.yaml` CronJob + `backup-script` ConfigMap + values for `backup.recipientKeyConfigMap` / `backup.identitySecret`. `scripts/preflight.sh` Gate G19: age binary + recipient key validation. `docs/operations/backup.md` new Encryption section with key generation, rotation runbook, and K8s setup. Closes MP.L2-3.8.9 (CMMC L2 product gap) / CWE-312.
- **feat/v233-password-history** — Password reuse history (CMMC L2 IA.L2-3.5.8 / NIST SP 800-63B §5.1.1.2): self-service password changes now check the new password against the last `PASSWORD_HISTORY_DEPTH` (default 12, range 1–24) Argon2id hashes in the new `password_history` table (migration `0010`). Reuse rejected HTTP 422 `password_reuse`. On rejection emits `PASSWORD_REUSE_REJECTED` audit event with `user_id` and `history_depth_checked` — no password or hash ever logged. History pruned to `depth` entries per user after each successful change. Closes CMMC L2 product gap IA.L2-3.5.8.
- **fix/agents-urllib-through-httpclient** — `backoffice/routes/agents.py _push_openwebui_model()` previously used a hand-rolled `_assert_safe_owui_url()` with an inline SSRF allowlist (scheme check + `YASHIGANI_OWUI_HOSTNAMES` host allowlist). Replaced with a lazy singleton `_owui_http_client()` (HttpClient, `allow_http=True`, `YASHIGANI_OWUI_HOSTNAMES`-driven allowlist). `BlockedByPolicy` is caught and converted to `RuntimeError` (non-fatal). The hand-rolled helper is removed (yashigani-retro#95 / OWASP A10 / API7 SSRF).
- **extend-pr-112-owui-wrap** — OWUI agent push now uses `pinned_resolver` (DNS-rebinding defence against admin-account-compromise pivot). OWUI hostnames are admin-configurable per agent and can be attacker-influenced via licence-key compromise or admin-account takeover; `_push_openwebui_model()` now resolves the OWUI hostname once at context entry, verifies the IP, and pins the transport — subsequent DNS changes cannot redirect the connection. Replaces `urllib.request` with `httpx` via `pinned_resolver`. `SSRF_PINNED_RESOLVER_USED` logged at DEBUG on each OWUI push. New tests in `src/tests/security/test_owui_dns_rebinding.py` (OWASP API7 / issue #91).
- **fix/hibp-route-through-httpclient** — `auth/password.py check_hibp()` now routes through `HttpClient._check_policy()` with `allowlist=["api.pwnedpasswords.com"]` and `allow_http=False` before issuing the outbound HIBP request. The URL is hardcoded (no immediate SSRF risk), but defence-in-depth ensures any future change to `_HIBP_API_URL` is automatically caught by the centralised gate. Fail-open preserved: `BlockedByPolicy` → `return None`. The `_check_hibp_urllib` fallback is only invoked after the policy gate passes (yashigani-retro#95 / OWASP A10 / API7 SSRF).
- **fix/auth-logout-audit-emit** — `routes/auth.py logout()` now emits an `AdminLoginEvent(outcome="logout")` audit event before returning. Every other auth lifecycle outcome (login success/failure, totp_provision, stepup, self_reset) was already audited; logout was the only gap (yashigani-retro#95 / OWASP A09 / CMMC AU.L2-3.3.1). Guarded by `if state.audit_writer is not None` for partial-init safety.
- **fix/break-glass-audit-writer-required** — `auth/break_glass.py init_break_glass(audit_writer=None)` default removed; `audit_writer` is now a required positional argument. Calling without it raises `TypeError` at startup rather than silently creating an audit-silent break-glass manager. The one call site (`backoffice/entrypoint.py:474`) already passes `audit_writer` explicitly — no functional change there. `_emit_activated` and `_emit_expired` None-guards preserved for defence-in-depth (yashigani-retro#95 / OWASP A09 / CMMC AU.L2-3.3.1).
- **feat/v233-issue-95-product-gaps** (#95) — 5 ACS-surfaced product gaps closed: (1) *auth_log*: four new `EventType` variants (`AUTH_LOGIN_ATTEMPT`, `ACCOUNT_LOCKOUT`, `PASSWORD_CHANGED`, `SESSIONS_INVALIDATED`) + matching dataclasses in `audit/schema.py`; login-attempt events emitted at the route layer, lockout events emitted from `pg_auth.authenticate()` via a non-blocking `_emit_lockout_event()` helper; password-change and session-invalidation events emitted in `routes/auth.py change_password()` and `self_service_password_reset()`. (2) *Injection (SCIM)*: SCIM `?filter=` param now declared as typed `Query(max_length=256)` — FastAPI enforces length at the framework layer before any Python code runs; `_parse_filter_email()` enhanced with an explicit email regex (`_EMAIL_RE`) rejecting any value that is not a valid RFC 5321 address. (3) *BFLA*: `manage_service()` re-parameterised from `AdminSession` → `StepUpAdminSession`; enabling or disabling a compose-profile service now requires a fresh TOTP step-up (ASVS V6.8.4 / CMMC AC.L2-3.1.1). (4) *3rd-party response validation*: HIBP k-Anonymity response lines validated against `_HIBP_LINE_RE` (`^[0-9A-F]{35}:[0-9]+$`) before `int()` conversion — malformed lines logged and skipped rather than raising `ValueError`; OIDC discovery documents validated by `_validate_oidc_metadata()` (required fields: `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`; all must be non-empty `https://` strings) before being cached. (5) *CMMC AC.L2-3.1.1*: same root-cause fix as Gap 3 — `StepUpAdminSession` on `manage_service()`. 65 new unit tests in `tests/unit/test_v2233_acs_product_gaps.py`.

### Changed (v2.23.3)

- **fix(deps): replace `fasttext-wheel` with `scikit-learn` in sensitivity classifier** (PR #131, commit `e966e55`) — the PII/sensitivity classifier ML backend was swapped from `fasttext-wheel` (Facebook supervised text classifier) to a `scikit-learn` TF-IDF + LogisticRegression joblib pipeline. **Motivation:** `fasttext-wheel` was last uploaded 2020-09-03, archived by maintainer 2024-03-22, and its Python ABI pin blocked the ≤3.12 upgrade path. **scikit-learn** has no ABI constraint, ships pre-built wheels across all currently-supported Python versions, and the joblib artefact is ~28 KB vs ~1-2 MB FastText `.bin`. **Quality:** macro F1 0.9545 on the 220-example training corpus (no regression vs FastText on the same corpus). **API compat:** the surrounding-code slot name `fasttext_backend` is preserved as a backward-compat variable name; the implementation class is now `SklearnBackend` in `src/yashigani/inspection/backends/sklearn_backend.py`. **Build:** trainer Docker stage installs `scikit-learn>=1.4` + `joblib>=1.3` and bakes `sensitivity_classifier.joblib` at image build time. Docs updated: `Architecture.md`, `README.md`, `AI_ASSETS.md` §3.2.

---

## [v2.23.2.1] — 2026-05-08 — Helm chart digest pin fix

> **Chart-only patch. Code (gateway + backoffice binaries) is identical to v2.23.2.**
>
> **Tag:** `v2.23.2.1` → SHA `49b80fd` — [GitHub Release](https://github.com/agnosticsec-com/yashigani/releases/tag/v2.23.2.1)

### Fixed

- **(#77) Helm chart — image digest pointers corrected** — `helm/yashigani/values.yaml` referenced v2.23.1 image digests for `yashigani-gateway` and `yashigani-backoffice` after the v2.23.2 GA tag was cut. This caused Kubernetes Helm deployments to pull the v2.23.1 container images when running the v2.23.2 chart, producing a chart/binary version mismatch that was invisible to operators. The patch pins both images to the correct v2.23.2 GA digests:
  - `yashigani-gateway:2.23.2@sha256:7ffe5b92b23224a5fdcf86bf2570345d979ca2f9f06beda52447efc6ef5b688c`
  - `yashigani-backoffice:2.23.2@sha256:34f4e68dac35f6e045bfe6277cd9725340e0e662361cdfb81b2057d3a0ebd0dc`

  **Upgrade path:** Helm users on v2.23.2 should upgrade to v2.23.2.1 immediately (`helm upgrade --version 2.23.2.1`). No image rebuild or config change needed. Docker / Podman Compose deployments are unaffected (image pins in `docker-compose.release.yml` were already correct).

---

## [v2.23.2] — 2026-05-06

Theme: **Security Hardening + Supply-Chain Controls + ASVS L3 92% + Agentic AI Overreliance Controls**.

### Today's batch (2026-05-06)

- **#44** `72a93fa` — feat(security): OWASP Agentic AI T10 overreliance UX controls (F-T10-001) — three `X-Yashigani-*` response headers on every LLM/agent response; `math.isfinite` NaN/Inf clamp; env-var fallback on threshold; 16 regression tests
- **#43** `43ef0fa` — fix(images): pin all external images to multi-arch manifest INDEX digests — closes Podman parity P-8 (aarch64 exec-format crash) and smoke-gate V232-SMOKE-001
- **#47** `2b65b0a` — fix(install): non-interactive bind-mount mkdir — `install.sh` pre-creates bind-mount dirs; no sudo in installer body
- **#46** `8aacdae` — feat(uninstall): `--yes` / `-y` flag for unattended removal
- **#50** `39f6fee` — chore(release): Gate 6a specialist-per-language review codified in pre-flight checklist
- **#45** `057faa4` — chore(helm): grafana 12.4.3 → 13.0.1 + close `helm/charts/grafana/values.yaml` "latest" pinning gap
- **#52** `10864bd` — fix(compose): Podman healthcheck silent-drop (P-9) — rebased replacement for #49

### Previous batch (2026-05-03)

### Breaking Changes

- **Breaking default behaviour:** `RATE_LIMITER_FAIL_MODE` now defaults to `closed`. On Redis unavailability, the gateway returns HTTP 503 + Retry-After (auto-heal typically under 2 minutes) instead of silently passing traffic. High-availability operators who require pre-2.23.2 fail-open behaviour can opt back in by setting `RATE_LIMITER_FAIL_MODE=open` in the gateway environment. (F-LLM06-001)

### Security

- **XFF spoofing** — Right-to-left `X-Forwarded-For` chain-walk in application code (`gateway/proxy.py:_get_client_ip`) skips trusted-proxy CIDRs and stops at the first non-trusted hop; rate limiting and audit logging bind to the resolved client address, not caller-supplied headers. **Operators MUST set `TRUSTED_PROXY_CIDRS`** in the gateway environment to include their proxy/load-balancer CIDR range — the default trust boundary is loopback only. The CHANGELOG previously stated "Caddy strips and re-sets XFF" which was inaccurate; the defence is in app code, not Caddy config. See `docs/security/xff-trust-boundary.md`.
- **Rate limiter fail-closed default** — `RATE_LIMITER_FAIL_MODE` now defaults to `closed`; Redis errors produce `HTTP 503` + `Retry-After: 5` rather than silent allow-through. Fail-open opt-in is documented for operators who need it. Customer-facing recovery message included.
- **Login throttle `Retry-After` header** — RFC 6585-compliant `Retry-After` on 429/401 throttle responses; closes the locked-out operator information gap deferred from v2.23.1.
- **OPA and Jaeger mTLS** — Both services now require mutual TLS in Docker Compose and Kubernetes Helm deployments; plaintext access from the data plane is no longer possible.
- **Kyverno admission policies** — Kubernetes deployments enforce non-root UID, read-only root filesystem, no privilege escalation, and dropped capabilities at the admission level; policy violations block pod scheduling.
- **Ollama UID 1000** — Ollama inference service migrated from root to UID 1000, closing the last root-in-container exception.
- **All 73 Caddy `reverse_proxy` blocks gated** — `X-Caddy-Verified-Secret` injected on every `reverse_proxy` block across all Caddyfile variants and the Kubernetes ConfigMap. Asserted by contract test in CI.
- **Backslash open-redirect patch** — `next=` parameter in the admin login flow now rejects backslash-encoded path bypass variants. Regression test suite covers the known bypass patterns.
- **Safe error envelopes** — All backoffice and gateway error responses go through `safe_error_envelope`; exception class names and stack details are stripped from customer-visible responses.
- **Release tag signing** — CI workflow (`tag-sign.yml`) and one-time key ceremony procedure landed. Note: the originally planned GPG path via `tag-sign.yml` was blocked (hardware-backed Yubikey key cannot sign in CI without the physical device). Actual signing uses SSH (`git config gpg.format=ssh`). From v2.23.3 onward, all release tags are SSH-signed by `maxine@agnosticsec.com`; the public key is at `docs/release-signing-key.pub`. v2.23.2 is unsigned. To verify a tag: `git config gpg.ssh.allowedSignersFile docs/release-signing-key.pub && git tag -v v2.23.3`.
- **SSRF on alert webhook** — Host allowlist enforced on webhook SSRF guard in addition to the v2.23.1 SSRF batch.

### Supply Chain

- **GitHub Actions SHA pinning** — All workflow steps pinned to digest, not mutable tag.
- **`pip` removed from runtime images** — Eliminates pip CVE surface in production containers; package installs are build-time only.
- **SBOM service-identity SHA gate** — SBOM generation now includes a content-hash assertion on `service_identities.yaml`.
- **Trivy CI digest annotation** — Every Trivy scan annotates the job summary with the exact image digest scanned, creating an auditable linkage between scan result and image content.
- **CI `/tmp` path lint gate** — A CI check rejects any code path that writes to host `/tmp`; `RUNNER_TEMP` and working-directory temporaries are used throughout.

### Infrastructure / Ops

- **Install + N-1 upgrade smoke matrix** — CI validates fresh install and v2.23.1 → v2.23.2 upgrade across macOS Podman, macOS Docker, Linux Podman, and Linux Docker. Harness performs real install → backup → upgrade → restore → admin login verification.
- **Caddyfile contract test** — New test suite (`tests/contracts/test_caddyfile_family.py`) asserts `inject-caddy-verified` count, TLS 1.3 presence, cipher suite correctness, and `client_auth` placement on every CI run.
- **Host `/tmp` eliminated** — `install.sh`, `restore.sh`, and all CI scripts rewritten to use working-directory and `RUNNER_TEMP` paths.
- **Compose bind-mount auto-create** — `install.sh` now pre-creates bind-mount directories before starting the stack; eliminates a class of startup race on Docker rootful installs.
- **K8s Helm: `kubeconfig` to `RUNNER_TEMP`** — CI `deploy.yml` writes the kubeconfig to `RUNNER_TEMP` rather than `$HOME/.kube`, preventing credential leakage between concurrent runs.
- **`skip-pull` guard** — Installer detects when images are already present and skips the pull phase safely; prevents stale-image confusion on re-install.

### Compliance

- **OWASP ASVS v5 L3: 92% (166/180)** — Zero release-blocking FAILs. All six v2.23.1 FAILs remain closed. Per-chapter rates available at `docs/yashigani_owasp.md`.
- **OWASP API Security Top 10**: 9/10 PASS, 1/10 PARTIAL — no failures.
- **OWASP Agentic AI + LLM Top 10**: 22/25 PASS, 2/25 PARTIAL, 1/25 N/A (out-of-architecture) — no failures.

### Bug Fixes

- **Agent bundle SSRF guard wiring** — Optional agent bundles (Langflow, Letta, OpenClaw) silently failed to register on canonical install because `YASHIGANI_AGENT_UPSTREAM_HOSTNAMES` was empty and not pre-populated. The default is now `langflow,letta,openclaw` in Compose and Helm; SSRF guard code unchanged. (fix/v232-openclaw-upstream-hostnames-default)
- **str(exc) information disclosure** — `str(exc)` calls in internal result fields and error responses migrated to `safe_error_envelope` to prevent exception-class name leakage.
- **Agent-name path injection** — Regex + resolve guard prevents path traversal via crafted agent names.
- **CI workflow injection** — `env` indirection on `head_branch` + regex guard closes the GitHub Actions `workflow_run` injection vector.
- **Upgrade harness post-restore restart** — Network reconciliation bypass on post-restore restart prevents Compose from re-creating networks that already exist.
- **Postgres SSL injection** — Installer uses `podman cp` for postgres SSL cert injection when the bind-mount directory predates the certs, avoiding a startup ordering race.

---

## [v2.23.1] — 2026-05-02

Theme: **Core-Plane mTLS + Two-Tier PKI + Release Hardening**.

### Added
- Core-plane mTLS default-on across gateway, backoffice, postgres, pgbouncer, redis, opa
- Two-tier internal PKI (root → intermediate → per-service leaves) with SPIFFE-style URI SANs
- Automatic certificate issuance + rotation (admin-API + install.sh subcommands + Helm CronJob)
- Centralised SSRF allowlist helper for outbound HTTP (`yashigani.net.http_client`)
- Per-endpoint body-size limits (ASVS 4.3.1)
- Log-injection sanitisation across audit and application logs (ASVS 16.6.1)
- Algorithm allowlist on license ECDSA verifier (ES256 / SECP256R1 only)
- `/.well-known/security.txt` per RFC 9116
- Symbol-bearing generated passwords with category guarantees (`A-Za-z0-9!*,-._~`)
- AppArmor mmap permission for shared libraries (e.g. `libpython3.12.so`)

### Changed
- seccomp + AppArmor profiles default-on for all runtimes (Linux + macOS where applicable)
- Fail-closed on missing HMAC and Open WebUI secrets (no silent dev-mode fallback)
- Session rotation on password change invalidates all prior sessions (ASVS V7.4.2)
- 401 vs 404 uniformised on unauthenticated admin endpoints (no information disclosure)
- Caddy header hygiene: `Server` stripped, stale `alt-svc` removed
- TOTP enrolment split into separate provision/confirm endpoints
- Agent tier-limit returns 402 Payment Required (was 500 Internal Server Error)
- AGENT_REGISTERED events now persisted to the audit log (previously in-memory only)

### Fixed
- `YSG_RUNTIME` stale-env bleed across install invocations
- PKI trust-store mounts aligned per library compatibility (libssl-direct services use root anchor; partial-chain-capable services use intermediate; root private key never enters a workload container)

### Security
- PCI-compliant password expiry profile (≤90 days) selectable via `YASHIGANI_PROFILE=pci`. `YASHIGANI_PASSWORD_MAX_AGE_DAYS` is a separate integer override (e.g. `YASHIGANI_PASSWORD_MAX_AGE_DAYS=90`); setting it to the string `pci` raises `ValueError` at runtime — use `YASHIGANI_PROFILE=pci` instead. See `docs/operator-guide.md §4`.
- Auth-throttle admin self-visibility — authenticated admins see own + all throttled/blocked IPs at `/admin → Security → Blocked IPs` (backed by `/auth/blocked-ips`). Unauthenticated locked-out operator path (RFC 6585 `Retry-After` on login) deferred to v2.23.2.
- **CWE-89, HIGH** — replaced SQL f-string interpolation in `scripts/partition_maintenance.py` with safe identifier quoting (`_quote_ident()`, allowlist `[a-zA-Z_][a-zA-Z0-9_]*`). Date literals in the `PARTITION OF … FOR VALUES FROM … TO …` DDL clause are formatted via `date.isoformat()` (deterministic `YYYY-MM-DD`); asyncpg / PostgreSQL do not accept bind parameters in DDL parser positions. The date values are derived from Python `date` arithmetic, never from user input. Closing commits `75536a5` (identifier quoting) + `af114f7` (DDL date-literal exception).
- **CWE-89, MEDIUM** — replaced `op.execute(f"DROP TABLE IF EXISTS {name}")` in Alembic migration `0003_prepartition_audit_2026_2027.py` with `op.drop_table()` native API. Closing commit `9d867be`.
- **CWE-601, MEDIUM** — OIDC discovery validator now rejects `authorization_endpoint`, `token_endpoint`, and `jwks_uri` whose scheme is not `https` or whose host does not match the registered `discovery_url` host. Closes the post-admin-compromise open-redirect class (TA-3 insider). Closing commit `c5839e4`.
- **CWE-400, MEDIUM** — Docker Compose `mem_limit` and `cpus` now set on every service across `docker-compose.yml` (21 services) + `docker-compose.wazuh.yml` (3 services). Defaults documented in `docker/.env.example`; env-overridable via `YASHIGANI_<SERVICE>_MEM_LIMIT` / `YASHIGANI_<SERVICE>_CPU_LIMIT`. Closing commit `0143fb4`.
- **CWE-400, MEDIUM** — Helm chart `resources.limits.{memory,cpu}` AND `resources.requests.{memory,cpu}` set on every container in the chart; surfaced as tunables in `values.yaml`. Requests = 50% of limits to satisfy the K8s scheduler. Closing commit `6c35d28`.
- **CWE-668, MEDIUM** — OpenClaw host port binding moved from `0.0.0.0:18789` to `127.0.0.1:18789`. OpenClaw remains reachable from the gateway over the internal Docker bridge by service name; the host-side binding is loopback-only. OTEL collector `0.0.0.0:*` listeners confirmed bridge-only (no host `ports:` mapping). Closing commit `33f7318`.
- **CWE-918, HIGH worst-case** — SSRF allowlists added at every flagged call site:
  - **7-A** `agents.py:218,245` — `OWUI_API_URL` validated against `YASHIGANI_OWUI_HOSTNAMES` allowlist (default `open-webui,127.0.0.1,localhost`). Commit `84aab78`.
  - **7-B** `oidc.py:160,169` — discovery URL validated against `YASHIGANI_OIDC_DISCOVERY_HOSTS` allowlist; `jwks_uri` host MUST equal `discovery_url` host (case-insensitive) and MUST be `https`; re-asserted in `_get_jwks()` as defence-in-depth. Commit `64ec325`.
  - **7-C** `audit/writer.py:285` + `backoffice/routes/audit.py:326` — Pydantic v2 `field_validator` on `SiemTargetRequest.url` enforces `https` scheme and rejects RFC 1918 / loopback / link-local / multicast hosts at register-time AND test-fire-time. `YASHIGANI_TEST_MODE=1` skips DNS resolution but keeps the HTTPS requirement. Commit `1209055`.

### Deferred (accepted-risk, carried to v2.23.2 P1)
- **CWE-732/CWE-250, LOW-MEDIUM batch** — container-hardening absent-key gaps (no `read_only: true` in compose, no `readOnlyRootFilesystem: true` in Helm `securityContext`, no `security_opt: ["no-new-privileges:true"]`). Deferred (logged in risk register) with the rationale that adding YAML keys without OPA/Conftest/Kyverno admission control would be half-measure hardening; v2.23.2 ships both YAML keys AND admission policies together as proper end-to-end enforcement.

---

## [v2.22.3] — 2026-04-12

Theme: OPA on /v1, Agent Personas, Fail2ban, IP Access Control, OWASP Compliance Review.

### Added
- OPA policy enforcement on **all** `/v1/chat/completions` traffic (request + response paths, fail-closed)
- Agent personas with chaining: **Lala** (Langflow), **Julietta** (Letta), **Scout** (OpenClaw); `@Scout` → `@Julietta` → `@qwen` syntax (model strings starting with `@` are resolved as agent names in the registry)
- Fail2ban-style auth throttle: per-IP (3 failures) + global (5 failures), ×5 escalation (30s → 625m), permanent IP block after maximum
- IP allowlist + blocklist (IPv4 / IPv6 / CIDR, admin manageable; blocklist precedence)
- Content relay detection (agent-to-agent content laundering)
- Crypto inventory API (`/admin/crypto/inventory`) + admin UI with JSON export
- `__Host-` cookie prefix on session cookies (enforces Secure, Path=/, no Domain)
- Self-service password reset (TOTP-verified, no admin involvement)
- Wazuh SIEM full stack (`--wazuh`): manager + indexer + dashboard
- Grafana + Prometheus admin access at `/admin/grafana/` and `/admin/prometheus/` via Caddy forward_auth
- Monitoring tab in admin UI (Grafana / Prometheus / Wazuh links)
- OWASP compliance review (ASVS v5 all 17 chapters + API Security + Agentic AI / LLM Top 10) with per-control PASS / PARTIAL / FAIL / N/A verdicts and file:line evidence
- Risk register (5×5 quantitative-analysis matrix)
- Audit log viewer (search, filter, CSV export)
- Dashboard auto-refresh (15s), session-timeout warning (10 min), first-run onboarding checklist
- Podman SDK (`podman-py`) for container-per-user isolation

### Changed
- PKCE on all OIDC flows (`code_verifier` / `code_challenge`)
- `acr` / `amr` validation on ID tokens (auth-strength enforcement)
- Constant-time TOTP comparison (`hmac.compare_digest`)
- Context-specific password word list (blocks "yashigani", "admin", "password", etc.)
- Postgres migrations now run on startup (`pg_partman` / `pg_cron` optional)

### Removed
- **Goose** agent (ACP integration too slow on CPU; replaced by Letta/Julietta)

### Security
- Login branding (Agnostic Security footer)

## [v2.22.0] – [v2.22.2] — 2026-04-12

Patch sequence completing the v2.22.x feature set listed under v2.22.3.

---

## [v2.20] (untagged release line, 2026-04 series)

Theme: Security Hardening, PII Detection, and Compliance.

### Added
- License anti-tampering (v4 counter-signature schema; binary-patch-detecting self-integrity check at startup)
- PII detection module (`yashigani.pii`) — 10 entity types (SSN, credit card with Luhn validation, email, phone, IBAN, passport, NHS number, driver's licence, IP address, date of birth) — three modes: LOG / REDACT / BLOCK — bidirectional (request + response paths) — cloud bypass requires explicit admin opt-in
- Response-path inspection wired to all `/v1/*` routes (`ResponseInspectionPipeline` activation)
- WAF and DDoS protection: hardened Caddy timeouts and body limits + per-IP `DDoSProtector` (Redis-backed, 429 + `Retry-After`); `Caddyfile.waf` reference for Coraza WAF plugin
- Streaming chunk-level inspection (`StreamingInspector`) for `/v1/*` SSE responses
- HMAC-SHA256 per-tenant email hashing in SSO audit events (closes cross-tenant correlation risk)
- Ollama model digest pinning (validates SHA-256 on subsequent starts; alerts on mismatch)
- Open WebUI "Powered by Open WebUI" attribution (commercial-use compliance)
- 9-framework compliance mapping document; 2 STRIDE threat models (product: 17 threats; solution: 38 threats)
- Helm chart fixes (`helm lint` clean) + Kubernetes network policies covering all v2.0 / v2.1 services

### Changed
- Container hardening: explicit `security_opt`, `cap_drop`, `read_only` directives in compose; embedded seccomp profile at `docker/seccomp/yashigani.json`
- FastText classifier model baked into Docker image (no outbound dependency for inspection at startup)
- Model aliases: write-through to Redis on every CRUD operation; Redis read path with Postgres source-of-truth

### Security
- SBOM (CycloneDX 1.5) per image
- Cosign keyless image signing (Sigstore, GitHub Actions OIDC)
- 548 tests (523 unit + 25 e2e)

---

## [v2.1.0] — 2026-04-02

Theme: Admin Dashboard + Alerting + SSO + Persistence.

### Added
- Admin Dashboard UI (login page + 9-section admin panel)
- 12 Alertmanager rules covering P1-P5 severity for routing and budget conditions
- Budget Postgres persistence (counters survive container restarts and Redis eviction)
- Pool Manager background health monitor (daemon thread)
- OIDC identity broker — full end-to-end (`handle_oidc_callback()`, JWKS discovery, group extraction for Entra ID / Okta / Cognito / Keycloak)
- Mandatory 2FA after SSO (TOTP required even after IdP success)
- Keycloak test IdP (`test-idp` compose profile with three users: alice, bob, carol)

### Changed
- SSO email hashing standardised (SHA-256, raw email never stored)
- CSRF protection on OIDC flows via Redis-backed state/nonce tokens (10-minute TTL, ASVS V3.5.3)
- Podman rootless parity: corrected user namespace; `keep-id` removed from root-running services; e2e auto-detects runtime

### Security
- 413 tests (388 unit + 25 e2e)

---

## [v2.0.0] — 2026-04-02

Theme: First production-grade release. Five major subsystems transform Yashigani into a complete AI operations platform.

### Added
- **Unified Identity Model** — every entity (human or service) is a single identity record with a `kind` field; same governance, RBAC, budget, and audit for all kinds
- **Optimization Engine** — four-dimensional routing (sensitivity + complexity + budget + cost) with P1-P9 priority matrix; CONFIDENTIAL/RESTRICTED data always stays local (immutable)
- **Three-Tier Budget System** — org cloud cap → group → individual; budget-redis (noeviction policy); `X-Yashigani-Budget-*` response headers
- **Open WebUI Integration** — chat interface at `/chat/*` (internal Docker network only); all LLM calls route through gateway; Open WebUI holds zero LLM credentials
- **Container Pool Manager** — per-identity container isolation with universal lifecycle (create / route / health / replace / scale / postmortem); self-healing (replace, don't fix); forensic preservation before kill
- **Multi-IdP Identity Broker** — OIDC + SAML v2 native; Caddy delegates auth to backoffice; SCIM provisions users and groups
- **Sensitivity Classification Pipeline** — three layers ON by default: regex + FastText (sub-5ms offline) + Ollama (qwen2.5)
- **OPA Routing Safety Net** — second OPA pass on every routing decision; local-LLM policy validation with SAFE / WARNING / BLOCK verdicts
- **P1-P5 Alert Severity** — sensitivity breach (P1), OPA override (P1), classification conflict (P2), spending anomaly (P2), budget auto-switch (P3); SIEM integration for all
- 12 Grafana dashboards (9 existing + 3 new: budget, Optimization Engine, Pool Manager)

### Changed
- Open WebUI auth delegation via Caddy `WEBUI_AUTH_TRUSTED_EMAIL_HEADER`
- License tier container limits introduced

### Security
- 363 tests (252 original + 111 new)

---

## [v1.22.x] — 2026-04-12 (deprecated, end-of-life)

Final v1.x release line. **Branch `release/1.x` retired in v2.23.0** in favour of single-branch model where Open WebUI is `--with-openwebui` flag. Existing v1.x deployments should migrate to v2.x.

Tag history: `v1.22.0`, `v1.22.1`, `v1.22.2`, `v1.22.3`.

## [v1.10.x] — 2026-04-02 (deprecated, end-of-life)

Tag history: `v1.10.0`, `v1.10.1`.

## [v1.09.5] — 2026-04-01 (deprecated, end-of-life)

Theme: Agent bundles GA + first-class Podman support.

### Added
- Agent bundles auto-registered with PSK tokens at install time (`--agent-bundles`)
- First-class Podman runtime detection (compose command + override file)
- Animal/nature-themed admin codenames; TOTP pre-provisioned at install
- Alembic migrations bundled in backoffice Docker image

### Fixed
- DNS routing for `ollama` and `ollama-init` (external network for model registry access)
- PgBouncer reads password from `.env`

---

## [v0.9.4] — 2026-03-31

Theme: Final hardening before v2.0.

### Fixed
- Inspection classifier brace-depth parser replaces regex JSON extractor (fixes silent CLEAN misclassification of nested objects)

### Changed
- FastAPI gateway migrated to `lifespan` context manager (deprecates `@app.on_event`)
- Default service URLs use Docker Compose service names (`redis`, `ollama`, `policy`)

### Added
- CI gate enforcing `__init__.py` ↔ `pyproject.toml` version sync

## [v0.9.3] (untagged)

45-issue audit hardening release.

### Fixed
- Rate limiter operator-precedence bug (unauthenticated session bypass)
- `OllamaPool.classify()` recursive call → stack overflow under pool exhaustion
- Vault KMS provider initialisation failure on cold start
- 18× bare `except Exception: pass` handlers replaced with structured logging
- Redis `keys()` → `scan_iter()` (eliminates blocking keyspace scans)
- IPv6 address handling in session IP masking and CHS

### Added
- `ResponseInspectionPipeline` activated on default request path
- ECDSA P-256 production public key embedded in verifier
- Every Docker image digest-pinned across compose + Helm
- WebAuthn credentials Alembic migration
- End-to-end integration smoke test suite
- CI gate rejecting builds with placeholder license keys
- 252 tests (0 failures)

## [v0.9.2] (untagged)

### Fixed
- `.env` writer now sets all required vars before `docker compose pull` (fixes `UPSTREAM_MCP_URL` undefined on fresh installs)
- `update.sh` process substitution replaced with `find | while read` (bash 3.2 compat)

## [v0.9.1] (untagged)

### Added
- Two admin accounts at install time (eliminates single-admin lockout)
- TOTP 2FA fully provisioned at install with `otpauth://` URIs
- HIBP k-Anonymity breach check on all generated passwords
- HIBP check on backoffice password-change path (ASVS V2.1.7)
- One-time credential summary at install completion
- All credentials persisted to `docker/secrets/` with 0600 perms

## [v0.9.0] (untagged)

Theme: Post-quantum readiness and security hardening.

### Added
- ECDSA P-256 license signing (offline, air-gapped, no call-home)
- Hybrid TLS X25519+ML-KEM-768 Caddyfile config (commented, pending Caddy 2.10)
- Response-path inspection (`ResponseInspectionPipeline`)
- WebAuthn / Passkeys (Touch ID, Face ID, Windows Hello, YubiKey) coexisting with TOTP
- Break-glass dual-control (hard TTL, Redis-backed, tamper-evident audit trail)
- SHA-384 Merkle audit hash chain with daily anchors + `audit_verify.py` CLI
- Async SIEM delivery queue (Redis RPUSH/LPOP, batched, DLQ after 3 retries)
- Agent PSK auto-rotation via APScheduler with KMS push
- Real-time SSE inspection feed (`/admin/events/inspection-feed`)
- Searchable / exportable audit log (`/admin/audit/search`, `/admin/audit/export`)

### Changed
- Installer redesigned around three deployment modes: Demo / Production / Enterprise
- AES key provisioning: auto-generate by default, `--aes-key` BYOK option
- `--offline` flag for air-gapped installation

---

## [v0.8.4] (untagged)

### Fixed
- Platform-detection variable mismatch (`DETECTED_*` vs `YSG_*`)
- macOS `df -BG` (GNU-only) replaced with `df -k`
- Bash 3.2 compatibility throughout (`${var,,}` → `tr`)

### Added
- GPU detection (Apple Silicon / NVIDIA / AMD with lspci fallback)
- First-class Podman runtime support
- Docker Desktop CLI auto-fix (when Docker Desktop installed but `docker` not on PATH)
- `update.sh` script for in-place upgrades (backup → pull → restart → rollback on failure)
- 7-test installer validation suite (`test-installer.sh`, 28 checks)

## [v0.8.0] (untagged)

Theme: Optional agent bundles.

### Added
- Opt-in compose profiles + Helm toggles for LangGraph, Goose, OpenClaw
- `GET /admin/agent-bundles` catalogue API
- `GET /admin/agents/{id}/quickstart` snippet endpoint (curl / httpx / health)
- Rate-limit config endpoint extended with `last_changed` timestamp

## [v0.7.1] (untagged)

### Added
- Direct webhook alert dispatch on credential exfil detection
- Background license-expiry monitor (APScheduler, daily, configurable threshold)
- Alembic migration `0003` pre-creates all `audit_events` and `inference_events` partitions for 2026-05 → 2027-06
- Full unit-test suite for `db/health.py`

## [v0.7.0] (untagged)

Theme: Operational hardening + OPA Policy Assistant.

### Added
- ECDSA P-256 production public key replaces placeholder
- Database partition automation (maintenance script + Kubernetes CronJob)
- Prometheus gauge `yashigani_audit_partition_missing` with paired Alertmanager rule
- **OPA Policy Assistant** — natural language → RBAC JSON suggestion with admin approve/reject + full audit trail (uses Ollama qwen2.5:3b)
- Agent registration `quick_start` snippet (curl / httpx / health)
- Direct webhook alerting (Slack / Microsoft Teams / PagerDuty) as Alertmanager-independent sink
- CIDR-based IP allowlisting per agent
- Runtime-configurable rate-limit thresholds via backoffice (no gateway restart)

### Fixed
- OPA `_path_matches` regex bug (single-segment wildcards crossing `/` boundaries)

## [v0.6.2] (untagged)

### Added
- **Starter** tier (OIDC-only, 100 agents)
- Three-dimensional limits: `max_end_users` + `max_admin_seats` (split from single user limit)
- v3 license payload schema (with v1/v2 backwards-compat loading)

## [v0.6.1] (untagged)

### Changed
- Tier model restructured: Community / Professional / Professional Plus / Enterprise (replaces previous 3-tier scheme)
- Apache 2.0 community licence
- Contributor License Agreement (CLA) framework

## [v0.6.0] (untagged)

Theme: Universal installer + licensing.

### Added
- Universal installer (Linux, macOS, cloud VM — auto-detects OS, arch, cloud, GPU, runtime)
- Three licence tiers: Community (free, no key), Professional (paid, signed key), Enterprise (paid, signed key, multi-tenancy)
- ECDSA P-256 offline licence verification (no call-home)
- Feature gates: SAML, OIDC, SCIM tier-bounded

## [v0.5.0] (untagged)

Theme: Data-platform and full observability.

### Added
- PostgreSQL 16 with row-level security and `pgcrypto` AES-256-GCM column encryption (audit + operational store)
- `pg_partman` and `pg_cron` for monthly partition management
- PgBouncer connection pooling
- JWT introspection with JWKS waterfall (open-source / corporate / SaaS)
- Multi-sink audit pipeline (file + PostgreSQL + Splunk + Elasticsearch + Wazuh, simultaneous)
- OpenTelemetry distributed tracing with OTLP export to Jaeger
- FastText ML first-pass classifier (sub-5ms offline)
- HashiCorp Vault KMS integration (AppRole auth, KV v2 secrets)
- Loki + Promtail log aggregation
- Alertmanager 3-channel escalation (Slack / email → PagerDuty)
- Per-endpoint rate limiting (Redis fixed-window) + response caching (CLEAN-only, SHA-256 keyed)
- Redis ZSET sliding-window anomaly detection (enumeration / bulk-extraction patterns)
- Inference payload AES-encrypted logging in Postgres
- Container hardening (seccomp allowlist, AppArmor, UID 1001 non-root, tmpfs `/tmp`, read-only root)
- Structured JSON logging throughout

## [v0.4.0] (untagged)

Theme: Cloud-native operations.

### Added
- Production-ready Helm charts
- GitHub Actions CI/CD pipelines
- KEDA horizontal autoscaling
- Pod disruption budgets and Kubernetes network policies
- Trivy container scanning in CI
- CODEOWNERS + branch protection on security-critical paths

## [v0.3.0] (untagged)

Theme: Enterprise identity + multi-backend inspection.

### Added
- RBAC via OPA
- Agent routing with bearer token auth
- Multi-backend inspection: Anthropic Claude, Google Gemini, Azure OpenAI, LM Studio, Ollama
- Fail-closed sentinel (denies on all-backend unavailability)
- OIDC + SAML v2 SSO, SCIM provisioning
- Response masking + payload masking (pre-AI inspection)

## [v0.2.0] (untagged)

Theme: Transport security and admin hardening.

### Added
- TLS bootstrap: ACME (Let's Encrypt / ACME-compatible), CA-signed, self-signed
- Prometheus metrics
- bcrypt alongside Argon2 for password hashing
- Multiple admin accounts with minimum-count enforcement (anti-lockout)
- Admin lockout protection (brute-force resistance)

## [v0.1.0] (untagged)

Initial release. Core MCP gateway with prompt-injection detection, CHS, OPA, session/API-key auth, Argon2 hashing, TOTP/2FA, file-based audit log, Redis rate limiting.

---

## Notes on tag history

- `v0.9.4` (2026-03-31), `v1.09.5` (2026-04-01), `v1.10.x` + `v2.0.0` + `v2.1.0` (2026-04-02), `v1.22.x` + `v2.22.x` (2026-04-12) reflect parallel-branch parity for the v1.x line that has now been retired.
- The single-branch model (Open WebUI as `--with-openwebui` flag) shipped in v2.23.0; `release/1.x` is end-of-life.
- v2.20, v2.1, v2.0, and earlier carry untagged CHANGELOG entries reflecting the per-version content from `README.md` §4.
