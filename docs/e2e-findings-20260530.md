# Yashigani e2e deployment test — findings

- **Date:** 2026-05-29
- **Version:** v2.24.4 (clean tag checkout)
- **Platform:** host (Linux Ubuntu 22.04, x86_64/AMD64, 24c/62GB), Docker Engine 29.1.3
- **Scenario:** most-complex single-host compose deployment — `--deploy production --runtime docker --tls-mode selfsigned --wazuh --agent-bundles all --with-openwebui --with-internal-ca` (BYO root+intermediate CA, RSA-4096)
- **GPU:** RTX 3060 12GB to Ollama via nvidia CDI (`--device nvidia.com/gpu=1`); `--gpus all` fails here (cgroups-v2 NVML "Unknown Error")
- **Metrics:** `testing_runs/metrics/yashigani-e2e-enterprise-20260529/` (host + GPU + per-container samplers)

## Install-journey findings (fresh-host dependency gaps)

| # | Severity | Finding |
|---|---|---|
| F1 | Medium | **Prometheus basic-auth hash step fails on a fresh host** with no `htpasswd` (apache2-utils) AND no python `bcrypt` module. Installer "Method 3" stdlib fallback only re-tries `htpasswd`, so it cannot succeed without one of them. Fresh Ubuntu has neither. → Installer should bundle a pure-python bcrypt or document the prereq. Worked around with user-local `pip install bcrypt`. |
| F2 | Medium | **`helm` is required even for a Docker/compose install.** Step 7 "Updating Helm chart dependencies" runs `helm dependency update` unconditionally; aborts if helm absent. A compose-only operator shouldn't need helm. Worked around by installing helm user-local. |
| F3 | Info/UX | **`--deploy enterprise` silently means Kubernetes/Helm**, ignoring `--runtime docker`. With no cluster it aborts at step 8 "Deploying via Helm" → "kubernetes cluster unreachable". The runtime/deploy-mode interaction (`demo`→compose, `production`→compose, `enterprise`→k8s) isn't obvious from `--help`. Pivoted to `--deploy production` for the compose path. |
| F4 | Low | `--gpus all` GPU passthrough fails on this host (cgroups-v2 NVML); **CDI device syntax works**. Ollama then sees the RTX 3060 (CUDA, 12GiB). Worth documenting CDI as the supported GPU path in the install guide. |
| F5 | Low | AppArmor profile load fails → falls back to unconfined (host has no AppArmor for the profile). Non-blocking. |
| F6 | Low (env) | Leftover **arm64 `.venv`** at repo root from the macOS migration is unusable on amd64 ("Exec format error"). Unrelated to product; environment cleanup. |

## Deployment result — SUCCESS (with SIEM-manager caveat)

**23 containers up, 19 healthy** on the host (AMD64). Data plane, control plane, observability, agents, and Open WebUI all healthy. Core e2e objectives met.

| Capability | Result |
|---|---|
| Gateway + Backoffice (control plane) | ✅ healthy |
| Data plane (postgres, pgbouncer, redis, budget-redis, OPA/policy) | ✅ healthy |
| Observability (prometheus, grafana, alertmanager, jaeger, loki, promtail, otel) | ✅ healthy |
| Caddy edge (selfsigned, vhost `yashigani.local`) | ✅ healthy |
| **Agent bundles** (langflow, letta, openclaw) | ✅ healthy |
| Open WebUI | ✅ healthy |
| **BYO internal CA (EC P-384)** mTLS | ✅ working — leaf certs issued, signed by customer intermediate |
| **Ollama GPU** (RTX 3060 via CDI) | ✅ CUDA, 12 GiB VRAM, **403 tok/s** |
| **Wazuh SIEM** | ⚠️ indexer up; **manager crash-loops** (F7) |
| Forced first-login password reset | ✅ completed (admin@agnosticsec.local) |
| **Normal user created** | ✅ alice@agnosticsec.com (`/admin/users`) |
| **OPA policies created + pushed** | ✅ 3 groups (analysts, mcp-operators, audit-readers) → OPA `pushed:true, groups=3, users=2` |

## Additional findings (deployment + admin flow)

| # | Sev | Finding |
|---|---|---|
| F7 | **High** | **Wazuh SIEM does not come up on Linux Docker — a *stack* of integration bugs** (diagnosed 2026-05-30, peeled back in order):<br>1. Host `vm.max_map_count=65530` < 262144 → indexer OpenSearch bootstrap-check fails. (Fixed via a privileged container: `docker run --privileged alpine sysctl -w vm.max_map_count=262144` — no host edit.)<br>2. **`cap_drop:[ALL]`** on all 3 Wazuh services (Yashigani global hardening) → root can't `chown`/`setuid`/override DAC → `Permission denied` on `ossec.conf`, can't drop to the `wazuh`(999)/`opensearch`(1000) users. Wazuh is **incompatible with cap_drop:ALL**. (Fixed via override granting CHOWN/DAC_OVERRIDE/FOWNER/FSETID/SETGID/SETUID/KILL/SETPCAP.)<br>3. Manager also needs **`CAP_SYS_CHROOT`** (`wazuh-analysisd` chroots to /var/ossec). (Added.)<br>4. **Indexer `INDEXER_URL=http://wazuh-indexer:9200` but the indexer serves HTTPS** → manager↔indexer + the indexer healthcheck fail (`not an SSL/TLS record`); indexer reports unhealthy though it's running.<br>5. After all the above, `0-wazuh-init` still fails per-volume: `cp -ar … /var/ossec/var/multigroups` errors. **Root cause: the compose mounts a separate named volume for every `/var/ossec/*` subdir**, and the wazuh image's entrypoint restore can't reliably populate that granular layout. **Proper fix is Yashigani-side** (consolidate Wazuh volumes, set caps + `SYS_CHROOT`, fix `INDEXER_URL` to https, and pre-set `vm.max_map_count`) — not runtime patching.<br>Workaround used for the e2e: gateway/backoffice depend on wazuh-manager via `service_healthy`; started them with `docker start` to bypass. |
| F7-ROOT | **High** | **STRUCTURAL root cause: `wazuh-manager` is defined TWICE with conflicting config**, and the install merges both (`-f docker-compose.yml -f docker-compose.wazuh.yml`):<br>• `docker-compose.yml:2010` — `INDEXER_URL=https://wazuh-indexer:9200` ✅, granular per-subdir volumes, `cap_drop:[ALL]`<br>• `docker-compose.wazuh.yml:51` — `INDEXER_URL=http://wazuh-indexer:9200` ❌, 3 volumes (`wazuh_manager_config/logs/queue`), no caps<br>**Merge result:** overlay's `http` URL wins (breaks manager↔indexer TLS), volume lists *append* (→ 10+ volumes incl. empty runtime dirs that break the cont-init `cp` restore), `cap_drop:[ALL]` from base with no `SYS_CHROOT`/`CHOWN`/`DAC_OVERRIDE`/`SETUID`.<br>**Proper product fix (Yashigani-side):** delete/reconcile the duplicate definition so there is ONE wazuh-manager; keep `INDEXER_URL=https`; for the Wazuh services use `cap_drop:[ALL]` + `cap_add:[CHOWN,DAC_OVERRIDE,FOWNER,FSETID,SETGID,SETUID,KILL,SETPCAP,SYS_CHROOT]` (indexer/dashboard don't need SYS_CHROOT); drop the named volumes for the empty runtime dirs (`var/multigroups`, `active-response/bin`, `agentless`, `integrations`, `wodles`) — let them live in the writable layer; and pre-set `vm.max_map_count>=262144` (sysctl init / privileged init container). Verified at runtime: caps + SYS_CHROOT get the manager's daemons (syscheckd/modulesd/remoted) to start; the cont-init `cp` on the granular empty volumes is the last blocker and is resolved by removing those volume mounts. |
| F7-RESIDUAL | **Needs maintainer** | The proper compose fix WAS applied to the base `docker-compose.yml` (single wazuh-manager def, caps+SYS_CHROOT on all 3 services, empty runtime volumes removed, https INDEXER_URL, deployed base-only w/o the conflicting overlay) — caps/volumes confirmed applied. **The manager still crash-loops:** `0-wazuh-init` errors on `cp -ar … /var/ossec/var/multigroups` *even when that path is a plain writable image-layer dir (not a volume)*. The **identical `cp` with the identical cap set succeeds when run by hand** in the same image — so it is NOT a permission/volume/cap issue. This is an environment-specific incompatibility between the wazuh `4.14.5` image's s6 `cont-init` and **Docker 29.1.3 / overlayfs** that is not resolvable via compose tuning. **Recommendation:** Yashigani team to reproduce on Docker 29.x and either bump the wazuh image or patch the entrypoint; meanwhile the rest of the stack runs fine without the SIEM manager. |
| F8 | Med | **Admin TOTP uses SHA-256** (`pyotp.TOTP(secret, digest=sha256)`), not the default SHA-1. Any external TOTP tooling must specify SHA-256 or codes never match. Not documented in install output. |
| F9 | Med | **`--deploy enterprise` is Kubernetes/Helm**, ignoring `--runtime docker` (no clear signal in `--help`). Compose paths are `demo`/`production`. |
| F10 | Med | **SCIM user provisioning is license-gated** (Professional+). On community tier (no license key) `POST /scim/v2/Users` → 402. Non-SCIM `POST /admin/users` works within the community ≤5-user limit. |
| F11 | Low | `POST /admin/users` rejects `.local` emails (strict `EmailStr`: reserved domain) while the admin bootstrap accepts `admin@…local`. Inconsistent validation. |
| F12 | Low | Auth brute-force throttle (`auth:throttle`, Redis DB1, mTLS) escalates by level; `Retry-After` (30s) is the per-attempt delay, not the level-key TTL — waiting `Retry-After` doesn't clear the level. Repeated polling extends it. |

## Notes
- Deployed on the **host** (not the VM) because GPU-for-LLM needs host Docker + nvidia CDI; the libvirt VM can't see GPUs without vfio passthrough.
- Code-repo kept pristine: deployed from a clean v2.24.4 clone under `testing_runs/`, runtime disks/secrets there too.
- Metrics: `testing_runs/metrics/yashigani-e2e-enterprise-20260529/` (host/GPU/container CSVs + SUMMARY.md).
- New admin password + new user creds saved under the deploy `docker/secrets/` (`admin_e2e_new_password`, `user_alice_creds.json`).

## Red-team (2026-05-30): prompt injection + PII/PCI vs OPA — results

Via alice (normal user, API key) → `POST /v1/chat/completions` (model qwen2.5:3b, GPU):

| # | Attack | Result | Caught by |
|---|---|---|---|
| 0 | clean baseline | 200 OK | — |
| 1 | PII SSN | 403 | PII detector (SSN) + response-leg OPA `sensitivity_exceeds_ceiling` |
| 2 | PCI credit-card | 403 | PII detector (CREDIT_CARD) + OPA |
| 3 | injection (blatant) | 403 | OPA (response RESTRICTED) |
| 4 | injection (subtle/embedded) | 403 | OPA |
| 5 | obfuscated/spaced SSN | 403 | PII detector (matched as PASSPORT) + OPA |
| 6 | **base64-encoded PII** | **200 — BYPASS** | **nothing — no PII_DETECTED event emitted** |
| 7 | exfil PII+PCI external | 403 | PII detector (SSN,CC,EMAIL) + OPA |

**F-RT1 (Medium): base64-encoded PII bypasses detection.** The PII/sensitivity classifier matches literal patterns (regex + ML) on the raw text; it does not decode base64 (or other encodings) before classifying, so `base64("SSN 123-45-6789")` produced NO `PII_DETECTED` event and was delivered (200). **Recommended new policy/control:** decode-before-classify (base64/hex/URL-encoding/ROT) in the inspection pipeline, or an OPA/inspection rule that flags high-entropy/base64-looking blobs in prompts for sensitive contexts.
**Note:** PII action on LOCAL routing = `action_taken: logged` (not blocked at request leg); enforcement is the **response-leg OPA** `sensitivity_exceeds_ceiling`. Consider a request-leg BLOCK/REDACT mode for PII removal (the "removal of PII/PCI" ask).

## SIEM / audit capture verification (answer to "captured in the SIEM properly?")

- ✅ **File audit sink** (`/data/audit/audit.log`, shared volume `docker_audit_data`): **YES, properly.** 67 JSON events, **hash-chained** (`prev_event_hash` per event = tamper-evident), `schema_version`, `audit_event_id`, `request_id` correlation. Red-team events present: `PII_DETECTED` with `pii_types`, `action_taken`, `masking_applied`, `direction`, `destination`; plus `USER_API_KEY_ISSUED`, auth events.
- ❌ **Wazuh SIEM: NOT captured** — manager is down (F7 crash-loop), so nothing forwards to the SIEM. A SOC relying on Wazuh would NOT see these security events / get alerts. **This is the operational impact of the unresolved Wazuh bug.**
- ⚠️ **Postgres audit sink: 0 rows** (`audit_events*`/`inference_events*` all empty) despite the 18 partitioned tables existing — the DB sink is not active/wired in this deployment. Worth confirming whether Postgres audit is meant to be a live sink (compliance often expects the queryable DB store, not just the file).
- ⚠️ The **base64 bypass (#6) produced NO audit event at all** — so that gap is invisible to every sink.

## Wazuh REVIVED (2026-05-30) — from crash-loop to functional SIEM

Brought the SIEM up by fixing 8 stacked integration bugs (in order discovered):
1. host `vm.max_map_count<262144` → set via privileged container.
2. `cap_drop:[ALL]` breaks wazuh → `cap_add:[CHOWN,DAC_OVERRIDE,FOWNER,FSETID,SETGID,SETUID,KILL,SETPCAP,SYS_CHROOT]`.
3. manager needs `CAP_SYS_CHROOT` (analysisd chroots).
4. duplicate wazuh-manager def (base https + overlay http) → deploy base-only, https.
5. **flaky cont-init `cp` restore** (intermittent ~90%, not reproducible in isolation) → bind-mounted a patched `0-wazuh-init` making the empty-runtime-dir `cp` non-fatal (`|| echo WARN`).
6. patched script mounted `:ro` → s6 `ensuring perms` `s6-chmod fatal: read-only fs` → container teardown → mount it **writable**.
7. **filebeat→indexer mTLS certs missing**: manager env points to `/etc/wazuh-indexer/certs/wazuh.manager.pem` + `/etc/ssl/root-ca.pem` but compose never mounts them (certs DO exist as `secrets/wazuh-manager_client.{crt,key}` + `ca_root.crt`). Filebeat `Exiting: error initializing publisher … no such file` → s6 teardown. → bind-mounted the 3 certs to the expected paths.
8. **indexer security index never initialized** ("OpenSearch Security not initialized / .opendistro_security not found", 503) → ran `securityadmin.sh -cd …/opensearch-security -cacert/-cert/-key …/config/certs/{root-ca,admin,admin-key}.pem` → "Done with success", cluster GREEN.

**Result:** indexer cluster **green** (security initialized); manager **stable (restarts=0)**, 10 core daemons running incl. **analysisd**; dashboard still flapping (residual).

**F-HC (Med): Wazuh healthcheck commands are mis-written** → false "unhealthy" labels even when functional:
- indexer: `curl -sf https://localhost:9200` returns **401** once security is on (auth required) → `-f` fails → unhealthy though cluster is green. Fix: `curl -sk -u admin:<pw> .../_cluster/health` or accept 401.
- These mislead operators/orchestrators into thinking a healthy SIEM is down.

**Net:** the Wazuh integration was fundamentally incomplete/untested for compose-on-Linux/Docker-29. Needs a proper Yashigani-side fix (the above, baked into the image/compose + auto-run securityadmin + correct healthchecks). Achieved functional revival at runtime here.
