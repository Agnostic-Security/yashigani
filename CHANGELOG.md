<!-- last-updated: 2026-05-16T18:30:00+01:00 (v2.23.4: draft [Unreleased] entry covering 62 commits since v2.23.3) -->
<!-- last-updated: 2026-05-15T16:10:00+01:00 (docs: remove docs/release-notes/ cross-references — internal release-engineering tree moved out of repo — v2.23.4) -->
<!-- last-updated: 2026-05-15T11:30:00+01:00 (docs: remove unimplemented bare-metal claim from v0.6.0 entry — v2.23.4) -->
<!-- last-updated: 2026-05-11T22:00:00+01:00 (v2.23.3 GA — flip [Unreleased] block to [v2.23.3]) -->

# Changelog

All notable changes to Yashigani are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

For full release narratives, design rationale, and per-feature detail, see [`README.md`](README.md) section 4 (Security Features by Version).

---

## [Unreleased] — v2.23.4 (pre-tag)

> The v2.23.4 release closes the v2.23.3 follow-up backlog, ships the SAML BYOK
> config-load surface, multi-platform install robustness improvements, and a
> new CI gate that prevents Caddyfile / service-identity drift between compose
> and Helm. Tag pending pre-flight gate completion.

### Added

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

### Security

- **SAML SP-key RSA enforcement at config-load** — non-RSA SP private keys
  rejected at `SAMLProvider.__init__`, preventing the EC-key path from
  reaching python3-saml. Mitigates the libgcrypt ECDH heap-overflow CVE
  class regardless of upstream patch availability.
- **python3-saml manual-re-audit gates** — `xmlparser.py` entity and
  DTD-resolution paths flagged for manual re-audit at every upstream bump.
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

### Documentation

- **Architecture cleanup** — removed unimplemented bare-metal install claims
  from `Architecture.md`. Bare-metal install was design intent that never
  shipped code.
- **`iptables FORWARD` precondition** for rootful Podman installs on test
  VMs documented (production hosts with sane FORWARD policy unaffected).
- **SHA-256-compatible authenticator app guidance** in post-install message
  — Yashigani uses HMAC-SHA-256 per the SHA-256 minimum policy; apps that
  ignore the `algorithm` parameter (e.g. older Google Authenticator) silently
  default to SHA-1 and produce wrong codes.

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

- **XFF spoofing** — Caddy strips and re-sets `X-Forwarded-For` at the edge; rate limiting and audit logging now bind to the Caddy-observed address, not caller-supplied headers.
- **Rate limiter fail-closed default** — `RATE_LIMITER_FAIL_MODE` now defaults to `closed`; Redis errors produce `HTTP 503` + `Retry-After: 5` rather than silent allow-through. Fail-open opt-in is documented for operators who need it. Customer-facing recovery message included.
- **Login throttle `Retry-After` header** — RFC 6585-compliant `Retry-After` on 429/401 throttle responses; closes the locked-out operator information gap deferred from v2.23.1.
- **OPA and Jaeger mTLS** — Both services now require mutual TLS in Docker Compose and Kubernetes Helm deployments; plaintext access from the data plane is no longer possible.
- **Kyverno admission policies** — Kubernetes deployments enforce non-root UID, read-only root filesystem, no privilege escalation, and dropped capabilities at the admission level; policy violations block pod scheduling.
- **Ollama UID 1000** — Ollama inference service migrated from root to UID 1000, closing the last root-in-container exception.
- **All 73 Caddy `reverse_proxy` blocks gated** — `X-Caddy-Verified-Secret` injected on every `reverse_proxy` block across all Caddyfile variants and the Kubernetes ConfigMap. Asserted by contract test in CI.
- **Backslash open-redirect patch** — `next=` parameter in the admin login flow now rejects backslash-encoded path bypass variants. Regression test suite covers the known bypass patterns.
- **Safe error envelopes** — All backoffice and gateway error responses go through `safe_error_envelope`; exception class names and stack details are stripped from customer-visible responses.
- **GPG release tag signing** — Signing infrastructure complete: CI workflow (`tag-sign.yml`), one-time key ceremony procedure, and public key (`docs/release-signing-key.asc`) all landed. `git tag -v v2.23.2` verifies the signature.
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
- PCI-compliant password expiry profile (≤90 days) selectable via `YASHIGANI_PASSWORD_MAX_AGE_DAYS=pci`
- Auth-throttle admin self-visibility — authenticated admins see own + all throttled/blocked IPs at `/admin → Security → Blocked IPs` (backed by `/auth/blocked-ips`). Unauthenticated locked-out operator path (RFC 6585 `Retry-After` on login) deferred to v2.23.2.
- **YSG-RISK-001 (CWE-89, HIGH)** — replaced SQL f-string interpolation in `scripts/partition_maintenance.py` with safe identifier quoting (`_quote_ident()`, allowlist `[a-zA-Z_][a-zA-Z0-9_]*`). Date literals in the `PARTITION OF … FOR VALUES FROM … TO …` DDL clause are formatted via `date.isoformat()` (deterministic `YYYY-MM-DD`); asyncpg / PostgreSQL do not accept bind parameters in DDL parser positions. The date values are derived from Python `date` arithmetic, never from user input. ACS v3 dogfood scan finding `acs-v3-sql-string-concat-exec`. Closing commits `75536a5` (identifier quoting) + `af114f7` (DDL date-literal exception; internal re-audit YCS-20260502-v2.23.1-CWE89-reaudit-001 PASS).
- **YSG-RISK-002 (CWE-89, MEDIUM)** — replaced `op.execute(f"DROP TABLE IF EXISTS {name}")` in Alembic migration `0003_prepartition_audit_2026_2027.py` with `op.drop_table()` native API. Closing commit `9d867be`.
- **YSG-RISK-003 (CWE-601, MEDIUM)** — OIDC discovery validator now rejects `authorization_endpoint`, `token_endpoint`, and `jwks_uri` whose scheme is not `https` or whose host does not match the registered `discovery_url` host. Closes the post-admin-compromise open-redirect class (TA-3 insider). Closing commit `c5839e4`.
- **YSG-RISK-004 (CWE-400, MEDIUM)** — Docker Compose `mem_limit` and `cpus` now set on every service across `docker-compose.yml` (21 services) + `docker-compose.wazuh.yml` (3 services). Defaults documented in `docker/.env.example`; env-overridable via `YASHIGANI_<SERVICE>_MEM_LIMIT` / `YASHIGANI_<SERVICE>_CPU_LIMIT`. Closing commit `0143fb4`.
- **YSG-RISK-005 (CWE-400, MEDIUM)** — Helm chart `resources.limits.{memory,cpu}` AND `resources.requests.{memory,cpu}` set on every container in the chart; surfaced as tunables in `values.yaml`. Requests = 50% of limits to satisfy the K8s scheduler. Closing commit `6c35d28`.
- **YSG-RISK-006 (CWE-668, MEDIUM)** — OpenClaw host port binding moved from `0.0.0.0:18789` to `127.0.0.1:18789`. OpenClaw remains reachable from the gateway over the internal Docker bridge by service name; the host-side binding is loopback-only. OTEL collector `0.0.0.0:*` listeners confirmed bridge-only (no host `ports:` mapping). Closing commit `33f7318`.
- **YSG-RISK-007 (CWE-918, HIGH worst-case)** — SSRF allowlists added at every flagged call site:
  - **7-A** `agents.py:218,245` — `OWUI_API_URL` validated against `YASHIGANI_OWUI_HOSTNAMES` allowlist (default `open-webui,127.0.0.1,localhost`). Commit `84aab78`.
  - **7-B** `oidc.py:160,169` — discovery URL validated against `YASHIGANI_OIDC_DISCOVERY_HOSTS` allowlist; `jwks_uri` host MUST equal `discovery_url` host (case-insensitive) and MUST be `https`; re-asserted in `_get_jwks()` as defence-in-depth. Commit `64ec325`.
  - **7-C** `audit/writer.py:285` + `backoffice/routes/audit.py:326` — Pydantic v2 `field_validator` on `SiemTargetRequest.url` enforces `https` scheme and rejects RFC 1918 / loopback / link-local / multicast hosts at register-time AND test-fire-time. `YASHIGANI_TEST_MODE=1` skips DNS resolution but keeps the HTTPS requirement. Commit `1209055`.

### Deferred (accepted-risk, carried to v2.23.2 P1)
- **YSG-RISK-008 (CWE-732/CWE-250, LOW-MEDIUM batch)** — container-hardening absent-key gaps (no `read_only: true` in compose, no `readOnlyRootFilesystem: true` in Helm `securityContext`, no `security_opt: ["no-new-privileges:true"]`). Deferred (logged in risk register) with the rationale that adding YAML keys without OPA/Conftest/Kyverno admission control would be half-measure hardening; v2.23.2 ships both YAML keys AND admission policies together as proper end-to-end enforcement.

---

## [v2.22.3] — 2026-04-12

Theme: OPA on /v1, Agent Personas, Fail2ban, IP Access Control, OWASP Compliance Review.

### Added
- OPA policy enforcement on **all** `/v1/chat/completions` traffic (request + response paths, fail-closed)
- Agent personas with chaining: **Lala** (Langflow), **Julietta** (Letta), **Scout** (OpenClaw); `@Scout` → `@Julietta` → `@qwen` syntax; `@Help` chaining guide
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
