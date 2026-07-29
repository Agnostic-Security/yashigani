# Yashigani 6.0 inference engine — RUNTIME / CONTAINER / DEPLOYMENT layer

**Author:** Captain · **Date:** 2026-07-22 · **Status:** OFFLINE-AUTHORED, design + artifacts
only. No image was built, no container was run, no rig was touched (dispatch constraint).
Grounded in `internal-docs/yashigani/captain-infer-engine-runtime-redteam-20260722.md` (my own
red-team findings, cited as "Captain finding #N" throughout this tree),
`internal-docs/yashigani/RED-COUNCIL-infer-engine-untrusted-input-synthesis-20260722.md`, and
`AgnosticSecurity/Products/Yashigani/inference-engine-platform-requirements-20260722.md`.

This is a **standalone, pre-integration deploy tree** — it has not been merged into
`docker/`/`helm/yashigani` and does not modify Tom's `infer/src/yashigani_infer/` package.
Convergence into the main compose/Helm surfaces is a follow-up integration step, not done here.

## Directory map

```
infer/deploy/
├── manifests/llama-cpp-build-manifest.md   pinned-tag + build-flag record, per backend
├── docker/
│   ├── Dockerfile.infer-{cuda,rocm,vulkan,cpu}   lean per-backend serving images (item 1)
│   ├── Dockerfile.infer-puller                    blob-write-path-only, NO llama-server binary
│   ├── Dockerfile.infer-first-parse-jail          C1 jail image (item 2)
│   ├── entrypoint/{infer-entrypoint.sh,first-parse-jail-entrypoint.sh}
│   ├── seccomp/{infer-llama-server.json,infer-first-parse-jail.json}   (items 2, 4)
│   ├── apparmor/yashigani-infer-llama-server                          (item 4)
│   ├── Caddyfile.infer-front                       ring-fence front, single source (item 6)
│   ├── docker-compose.infer.yml                    base topology (items 3, 5, 6, 7)
│   └── docker-compose.infer.{cuda,rocm,vulkan,cpu,podman-override}.yml   image-SWAP overlays (item 7)
├── gpu/healthcheck-gpu-engaged.sh                  live re-measure healthcheck (item 8)
├── helm/yashigani-infer/                           standalone chart (items 3, 5, 6, 7)
└── scripts/{resolve-and-pin-digests,verify-seccomp-json,sync-infer-deploy-artifacts-to-helm,verify-offline}.sh
```

## Mapping to the 8 dispatch deliverables

1. **Per-backend Dockerfiles** — `docker/Dockerfile.infer-{cuda,rocm,vulkan,cpu}`. Lean (not
   `GGML_BACKEND_DL`), digest-pinned base image FROM lines (placeholders — see "Deferred"),
   pinned llama.cpp tag/commit (placeholder — see "Deferred"), build flags recorded in
   `manifests/llama-cpp-build-manifest.md`.
2. **C1 first-parse jail** — `Dockerfile.infer-first-parse-jail` +
   `seccomp/infer-first-parse-jail.json` (network-syscall-family fully absent, not merely
   policy-denied) + `docker-compose.infer.yml`'s `invoke-first-parse-jail` service
   (`network_mode: none`, ephemeral, `--rm`) + `helm/.../templates/job-first-parse-jail.yaml`
   (ephemeral k8s Job, `ttlSecondsAfterFinished`, `restartPolicy: Never`, `dnsPolicy: None`).
   Vendors ONLY Tom's existing pure-Python `gguf/header.py`/`quant_types.py` — no new parsing
   logic authored here (see "Wiring to Tom's seam" below for what remains).
3. **C3 scoped supervisor privilege** — `docker-compose.infer.yml`'s
   `infer-docker-socket-proxy` service (Tecnativa image, coarse RBAC: containers-only,
   POST-only, no exec/attach/images/networks/etc.) + `helm/.../templates/{serviceaccount,rbac}-supervisor.yaml`
   (namespaced Role, `pods`/`jobs` only, no `secrets`, no `bind`/`escalate`, no cluster scope)
   + `helm/.../templates/admission-policy-infer.yaml` (Kyverno ClusterPolicy denying
   hostPath/hostNetwork/hostPID/privileged/cap-add/`yashigani-pki` SA assumption — same family
   as the existing `restrict-pki-trust-plane`). **Both gated OFF by default** (`profiles:
   ["orchestration-v2"]` / `supervisorRbac.enabled: false`) — see "C3 residual gap" below.
4. **seccomp/AppArmor for llama-server** — `seccomp/infer-llama-server.json` (enumerated
   allow-list + explicit documented deny-list: ptrace, process_vm_readv/writev, unshare/clone-
   new-namespaces, mount family, keyctl family, bpf, perf_event_open, kexec, module load/unload,
   iopl/ioperm, syslog) + `apparmor/yashigani-infer-llama-server` (network tcp/unix only, blob
   read-only, scratch-only write, ptrace/mount deny).
5. **Resource bounds** — `docker-compose.infer.yml`: `mem_limit`/`pids_limit`/
   `mem_swappiness: 0`/`memswap_limit` per service (classifier 4GB/256 pids, chat 16GB/512
   pids); `entrypoint/infer-entrypoint.sh` self-raises `oom_score_adj` (defense-in-depth, not
   primary control). Helm: `resources.requests/limits` per Deployment (QoS-class is the k8s-
   native OOM-victim-selection mechanism — see inline comments). **Classifier-vs-user-model
   isolation is a separate Deployment/compose-service, MUST not "ideally"** — see next item.
6. **Classifier/chat/puller container split** (closes finding #4 concretely, see README
   section below for the reasoning) — three physically distinct containers/pods, not three
   processes in one container.
7. **Ring-fence + `Caddyfile.infer-front`** — single source, byte-identical `.Files.Get` mirror
   in `helm/yashigani-infer/files/` (synced by `scripts/sync-infer-deploy-artifacts-to-helm.sh`,
   verified live in this session — see "Offline verify results"). TLS 1.3 + PQ-hybrid curve +
   `client_auth require_and_verify`, caller-gate narrowed to gateway+egress-forwarders (stamped-
   header pattern, not CEL — Caddy 2.11.x `*url.URL` bug), `handle_path /infer/*`, default-deny
   404. `internal:true` bridge (compose) / default-deny-egress NetworkPolicy (k8s).
8. **GPU-engaged healthcheck** — `gpu/healthcheck-gpu-engaged.sh`: live `nvidia-smi`/`rocm-smi`
   query at PROBE TIME (never a cached load-time value), cross-checked against an
   operator-declared expected-VRAM-floor (policy-aware, not a bare `>0` check — closes the MoE
   partial-offload ambiguity). NVIDIA Container Toolkit CDI escape CVE class (CVE-2024-0132)
   noted in `manifests/llama-cpp-build-manifest.md`'s sibling concern — the digest-pin/scan gate
   for base images (item 1) is the mitigation; this is a host-escape risk independent of the
   ring-fence (a vulnerable toolkit version is not fixed by network isolation).

## Red Council fixes — 2026-07-29 session (deploy/GPU-side gates)

Findings from `internal-docs/yashigani/RED-COUNCIL-infer-6.0-design-synthesis-20260729.md` and
`internal-docs/yashigani/captain-infer-6.0-design-redcouncil-20260729.md` (Captain's own design
review, findings #1-#7). Each fix below is its own commit; live GPU validation (an actual Vulkan/
Intel or ROCm rig) remains test-later per the original dispatch — nothing in this section was
verified against real hardware.

- **H6 (HIGH, Captain finding #1) — Vulkan/Intel k8s device grant.** Previously `gpu.resourceName`
  left empty for `backend: vulkan` silently shipped CPU-only despite the platform doc's "GREEN"
  claim. Fixed: `values.yaml` documents the required `gpu.resourceName` value
  (`gpu.intel.com/i915` or `gpu.intel.com/xe`, Intel Device Plugin for Kubernetes — not installed
  by this chart) AND adds a `gpu.vulkanIcdHostPath` knob (required value:
  `/usr/share/vulkan/icd.d`, matching the compose overlay's own host ICD mount) that renders a
  read-only `hostPath` volume + mount on `infer-classifier`/`infer-chat` ONLY when
  `backend == "vulkan"` and the value is set. Both values must be set correctly for Vulkan to
  actually engage a GPU in k8s — left empty (default), the cell is CPU-only, now documented as
  such instead of silently claimed GREEN. Verified via `helm template` with/without the knob set
  (see gates below) — no live Intel GPU node available this session.

- **C1 deploy-side (Captain finding #4) — k8s `sessionAffinity`.** `infer-chat`'s Service now sets
  `sessionAffinity: ClientIP` so a caller sticks to one replica — defense-in-depth pairing with
  Tom's `cache_prompt=off`/`--parallel` engine-level slot hygiene. **This does NOT provide
  multi-tenant isolation on its own** — it only affects k8s load-balancing across
  `chat.replicas`; the actual KV-cache/prompt-prefix isolation guarantee (or lack of one before
  C3 lands) lives entirely in Tom's in-process llama-server slot-hygiene code. True per-tenant
  isolation remains container-per-model (C3, `supervisorRbac.enabled: false` /
  `admissionPolicies.enabled: false` by default — gated off, not yet wired to a real
  `ContainerOrchestrationHook` implementation). Documented here so this fix isn't mistaken for
  closing C1 outright.

- **Helm CPU-cascade (Captain finding #7) — `expectGpu` day-one healthz trap.** `values.yaml`'s
  `classifier.expectGpu`/`chat.expectGpu` defaulted `true` completely decoupled from
  `backend: cpu` — the compose CPU overlay already correctly forces
  `YSG_INFER_EXPECT_GPU: "false"`, but the Helm chart had no equivalent cascade, so a stock
  `helm install` (no `--set backend=...`, no GPU) shipped `YSG_INFER_EXPECT_GPU=true` into the
  env-var contract the GPU-engaged healthcheck consumes — a day-one `/healthz` hard-fail out of
  the box. Fixed: both Deployments now cascade `YSG_INFER_EXPECT_GPU` to `"false"` whenever
  `.Values.backend == "cpu"`, regardless of the `expectGpu` value's own top-level default.
  Verified with `helm template --set backend=cpu` (renders `"false"`) vs `--set backend=cuda`
  (renders the configured `"true"` default unchanged).

## Classifier / chat / puller container split — the actual mechanism (finding #4)

Tom's v1 supervisor (`supervisor/supervisor.py`, `supervisor/process.py`) is
**subprocess-based**: it spawns `llama-server` as a child process of whatever container the
FastAPI app runs in — there is no per-model container/pod boundary in the code today (the
`ContainerOrchestrationHook` in `containment/hooks.py` is a documented no-op seam for exactly
this reason). True dynamic per-user-model containerization needs that hook to gain a real
implementation calling into the C3-scoped socket-proxy/RBAC this dispatch provisions — **not
built here** (Python control-plane work, out of my lane).

What IS achievable at deploy layer today, without touching Tom's Python, and what this tree
ships as a **MUST** (per the brief, not "ideally"):

- **`infer-classifier`** and **`infer-chat`** are two separate compose services / k8s
  Deployments — two separate instances of the SAME control-plane process, statically
  configured (`YSG_INFER_ROLE=classifier|chat`) so the classifier never shares a container,
  cgroup, or PID namespace with any chat model. This closes finding #4's (a) vector (ptrace/
  `/proc/<pid>/mem` cross-read) via the container/pod boundary itself, and k8s additionally
  gets a `podAntiAffinity` preference against co-scheduling on the same node.
- **`infer-puller`** is a THIRD, separate container built from `Dockerfile.infer-puller`,
  which contains **no llama-server binary at all**. It is the only container with blob-store
  WRITE access and a wired `pull_resolver`. `Caddyfile.infer-front` routes `/infer/pull`
  exclusively to this upstream; even if a stray request reached its `/api/chat` route (it must
  not — routing is the primary control), `Supervisor.load`'s `ProcessRunner.spawn(binary=
  "llama-server", ...)` would fail closed (binary absent), not fail open on trust. This closes
  finding #4's (b) vector (write-path isolation) using the *existing* `pull_resolver=None`
  constructor parameter in `app.py` — zero Python changes required.

## C3 residual gap (documented, not silently closed)

The Tecnativa `docker-socket-proxy` gives **coarse** RBAC (allow container-lifecycle HTTP
verbs, deny everything else) — it does **not** enforce a per-image-digest allowlist or a
required `yashigani.infer.managed=true` label at the proxy layer (that image doesn't support
request-body inspection). The k8s side closes this gap fully via the Kyverno admission policy
(which DOES inspect the pod spec). The compose/socket-proxy side does not have an equivalent
today — recommended v2 hardening: a small custom authz sidecar (or Docker's Authorization
Plugin API) that inspects `POST /containers/create` bodies against a pinned `infer-*` digest +
label allowlist before forwarding to the proxy. Not built this session (scope: compose+Helm
scaffolding, not a new authz-plugin component) — flagged, not silently left unmentioned.
Both the socket-proxy and the Helm RBAC/admission-policy are shipped **disabled by default**
(`profiles: ["orchestration-v2"]` / `supervisorRbac.enabled: false`) because v1's subprocess
supervisor doesn't consume them yet — enabling either without a real caller just adds an
unused privileged surface.

## Coordination gap — ASGI entrypoint module — RESOLVED

Tom landed `infer/src/yashigani_infer/entrypoint.py` (`b61b494b`, "add ASGI wiring entrypoint
closing Captain's coordination gap") — `create_asgi_app` is now a real `uvicorn --factory`
target that parses the documented env-var contract and constructs the real `BlobStore`/
`Supervisor`/`HttpxUpstreamClient` graph, failing closed (`EntrypointConfigError`) on any
missing/invalid required value. The entrypoint scripts' fail-closed exit-78 path is now dead
code in practice (module exists) but left in place — it degrades gracefully to the same
fail-closed behaviour if the module is ever removed/renamed.

## Blob-store mount path — RESOLVED (2026-07-22, follow-up fix)

Tom's entrypoint module surfaced a real gap in this tree: `docker-compose.infer.yml` and the
three Helm Deployments never set `YSG_INFER_BLOB_STORE_ROOT`, so `BlobStore` defaulted to
`$HOME/.yashigani/infer/blobs` **inside the container** — pulled models would not survive a
restart, because that path is on the container's own (ephemeral/read-only) rootfs, not the
mounted volume.

**Root cause, checked against the actual code (not guessed):** `BlobStore.__init__`
(`blobstore/store.py`) creates `<root>/blobs/` **and** `<root>/meta/` under whatever root it's
given — the root itself is not a "blobs" directory. The original mount shape
(`infer_blobs:/data/blobs`) put the `blobs/` subdir on the named volume but left `meta/`
(the per-model provenance/metadata JSON read by `/api/tags`, `/api/show`, `/api/ps`,
`find_by_name`) on the container's own filesystem — losing metadata every restart even with
blob bytes persisted.

**Fix — value chosen and the mount it maps to:**

| | Compose | Helm |
|---|---|---|
| `YSG_INFER_BLOB_STORE_ROOT` | `/data/model-store` | `/data/model-store` |
| Mount | named volume `infer_model_store` (renamed from `infer_blobs`) → `/data/model-store` (classifier/chat `:ro`, puller `:rw`) | PVC `{{ fullname }}-blobs` → `/data/model-store` (classifier/chat `readOnly: true`, puller `readOnly: false`) |

Set identically on all three compose services and all three Helm Deployments (classifier,
chat, puller) — verified by `docker compose config` and `helm template` (see updated Offline-
verify table below). `docker/apparmor/yashigani-infer-llama-server` and every Dockerfile's
`mkdir -p` were updated from `/data/blobs` to `/data/model-store` to match.

**Cold-start ordering, closed too (not left as a landmine):** classifier/chat mount the volume
**read-only** (finding #4, no exception) — on a brand-new, empty volume, `BlobStore.__init__`'s
`mkdir(parents=True, exist_ok=True)` would try to create `blobs/`/`meta/` itself and fail
closed (`EROFS`) before any model is ever pulled. Compose: `depends_on: infer-puller:
condition: service_healthy` (puller mounts read-write and its own `BlobStore()` construction at
process startup creates both subdirs first). Helm: an `initContainer` on classifier/chat
mounts the same PVC read-write just to `mkdir -p` both subdirs before the main (read-only)
container starts — standard k8s per-container mount-mode pattern, no extra privilege.

**Also caught and fixed while verifying this (pre-existing, not introduced by this fix):**
`docker-compose.infer.yml`'s seccomp bind-mount source was `../deploy/docker/seccomp/...`,
which resolves relative to the compose file's own directory (`infer/deploy/docker/`) to a
nonexistent `infer/deploy/deploy/docker/seccomp/...` path. Fixed to `./seccomp/...`; confirmed
via `docker compose config` that the resolved `source:` now points at the real file.

## Day-one models — `infer-init` (2026-07-23, Captain, engine-side only)

Iris's cutover-prep map (`internal-docs/yashigani/iris-infer-6.0-to-5.0-cutover-prep-map-
20260723.md`, Seam 2, line 34) found this engine deploy shipped with **zero models** — no
equivalent of `release/5.0`'s `ollama-init` Job (the `SF-011` fix), so first-inference was
broken out of the box on a clean deploy. Closed via `templates/job-infer-init.yaml` (Helm) and
`docker-compose.infer.yml`'s `infer-init` service (compose, `profiles: ["init"]`).

**Mechanism differs from `ollama-init`.** `infer-puller` (see `deployment-puller.yaml` /
`docker-compose.infer.yml`) is already a long-running peer with a wired `/api/pull` route
(`app.py`) — unlike `ollama-init`'s self-contained temporary `ollama serve` process,
`infer-init` is a thin HTTP client: wait for `infer-puller` healthy, then `POST /api/pull` with
the configured model name. Both the Helm Job and the compose service reuse the `infer-puller`
image itself (python3 stdlib `urllib` only) — no new image to build or pin.

**CRITICAL — no hardcoded default model.** `inferInit.model` (Helm) / `YSG_INFER_INIT_MODEL`
(compose) default **EMPTY**. Which GGUF ships as the day-one default, and its signed
provenance manifest, is **Tiago's provenance/signing decision** — the same class of council
finding (Laura F2/F3, Nico #1, Lu SUPPLY-1) that shaped `adapters/huggingface.py`'s pinned-
revision + signed-catalog admission gate applies here too: choosing an unsigned default
ourselves would be exactly the "resolve a sha256 live from the repo you're trusting"
anti-pattern those findings closed. With the value empty:
  - **Helm:** the Job (and its two dedicated NetworkPolicy rules) are **not rendered at all**
    — `{{- if and .Values.inferInit.enabled (ne .Values.inferInit.model "") }}` — verified via
    `helm template` both ways (see Offline-verify table below).
  - **Compose:** the `infer-init` service always renders in `docker compose config` (compose
    has no Helm-style conditional resource omission), but its own script detects the empty
    model at runtime and exits 0 immediately as a no-op before attempting any HTTP call.

Before enabling day-one auto-pull in a real deploy: choose a default model, produce its signed
provenance manifest (Nico/catalog.py's `SignedCatalog` admission gate), THEN set
`inferInit.model` / `YSG_INFER_INIT_MODEL` to that model's name.

**Known v1-foundation limitation, not hidden:** `entrypoint.py` hardwires `pull_resolver=None`
regardless of role (see "Coordination gap" above) — no source adapter is wired into any deploy
yet. `/api/pull` therefore always responds `501` until that separate Python wiring lands. Both
`infer-init` scripts treat HTTP 501 specifically as a non-fatal, loudly-logged `WARNING` and
`exit 0` (retrying would never help — this is a permanent condition until the code changes,
not a transient one), rather than spending the Job's `backoffLimit` retrying a guaranteed
failure. Verified live this session (see below) against a stub server exercising exactly the
`/healthz` + `/api/pull` contract `app.py` implements, in all three states (`200` success,
`501` no-adapter, empty-model no-op) plus wait-for-ready.

**F1 convergence note (Iris Seam 3, line 48) — deliberately NOT built here:** `install.sh`'s
healthcheck-exemption / one-shot-job handling for `ollama-init` will need a sibling entry for
`infer-init` in `_exempt_patterns` at convergence time. That is `release/5.0`-side wiring —
out of scope for this engine-only dispatch (HARD CONSTRAINT: only files under `infer/`).
Flagged here so it isn't silently dropped when this tree merges into `helm/yashigani`.

**NetworkPolicy note (k8s only):** `infer-init`'s pod is deliberately **not** labeled
`yashigani.infer.managed=true` (that label denotes a supervisor-*created* serving pod per
`admission-policy-infer.yaml`'s own definition, not a static Helm-authored bootstrap Job).
`job-infer-init.yaml` ships its own dedicated egress rule (puller:8000 + DNS only) and a
companion ingress rule on `infer-puller` (alongside the existing Caddy-only allow), rather than
piggybacking on the shared `default-deny-egress` selector.

**Live verification this session (Docker, own scratch harness — no product image touched
beyond extracting its rendered scripts verbatim):**

| Scenario | Result |
|---|---|
| `wait-for-puller` initContainer script vs. a stub `/healthz` returning 200 | **PASS** — detects ready, exits 0 |
| `infer-init` container script, stub `/api/pull` returns 200 NDJSON | **PASS** — streams progress, exits 0 |
| `infer-init` container script, stub `/api/pull` returns 501 (no adapter wired) | **PASS** — logs WARNING, exits 0 (non-fatal, matches design) |
| compose `infer-init` service script, `YSG_INFER_INIT_MODEL` empty | **PASS** — no-op, exits 0, no HTTP call made |
| compose `infer-init` service script, model set, stub returns 200 | **PASS** — same as Helm case |
| Same pull script under full hardening (`--read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true --user 1000:1000`) | **PASS** — no permission errors |

## Offline-verify results (this session, `scripts/verify-offline.sh`)

| Gate | Result |
|---|---|
| hadolint (all 5 Dockerfiles) | **DL4006/SC2011/DL3003 fixed this session** (glob instead of `ls\|xargs`; `git -C src` instead of `cd src`). Residual: DL3008 (apt package version pin) + DL3013 (pip package version pin) — **matches the identical, pre-existing pattern in the shipped `docker/Dockerfile.gateway`** (confirmed by running the same `hadolint --config .hadolint.yaml` against it: same DL3008/DL3013 findings). Not a novel regression; not fixed here because pinning exact apt/pip version strings without live registry access would be fabricating versions (Verification Protocol #7 applies to package pins, not only image tags). |
| shellcheck (all 7 `.sh` files) | **PASS**, zero findings. |
| `helm lint helm/yashigani-infer` | **PASS**. |
| `helm template` (default: cpu backend) | **PASS**. |
| `helm template` (cuda + supervisorRbac + seccomp DaemonSet, all optional resources rendered) | **PASS** — 19 resources: 5 NetworkPolicy, ServiceAccount, 2 ConfigMap, PVC, Role, RoleBinding, 3 Service, DaemonSet, 3 Deployment, Job. |
| `helm template --set admissionPolicies.enabled=true` | **Fails closed as designed** (no live cluster → Kyverno CRD `lookup` returns empty → explicit `fail` with remediation message) — same guard pattern as the main `helm/yashigani` chart's `admission-policies.yaml`, confirmed working, not a bug. |
| `caddy adapt --adapter caddyfile` on `Caddyfile.infer-front` | **PASS** — parses to valid JSON config. Asserted: explicit `:11436` dial present, no `:80` anywhere, no `insecure_skip_verify` anywhere. |
| seccomp JSON validity (`jq`) | **PASS** — both profiles + the helm mirror parse and have `defaultAction: SCMP_ACT_ERRNO`. |
| Helm-mirror byte-parity (`sync-infer-deploy-artifacts-to-helm.sh --check`) | **PASS** — Caddyfile + seccomp JSON mirrors byte-identical to canonical. |
| Portability fix (this session) | `sync-infer-deploy-artifacts-to-helm.sh` originally used `declare -A` (bash 4+ associative arrays) — **fails on macOS's default bash 3.2**. Rewrote with parallel indexed arrays before first run; verified working on this Mac's actual `/bin/bash 3.2.57`. |
| `YSG_INFER_BLOB_STORE_ROOT` present on all 3 compose services | **PASS** — `docker compose -f docker-compose.infer.yml -f docker-compose.infer.cpu.yml config` shows `YSG_INFER_BLOB_STORE_ROOT: /data/model-store` on `infer-classifier`, `infer-chat`, `infer-puller`; mount `target: /data/model-store` matches on all three. |
| `YSG_INFER_BLOB_STORE_ROOT` present on all 3 Helm Deployments | **PASS** — `helm template` (cuda variant) shows `value: "/data/model-store"` on `infer-classifier`, `infer-chat`, `infer-puller` containers; `volumeMounts[].mountPath: /data/model-store` matches on all three. |

### `infer-init` gates (2026-07-23 session — this Mac has live `helm`/`docker`/`kubectl`, used them)

| Gate | Result |
|---|---|
| `helm lint` | **PASS**, `inferInit.model` empty (default) and set to a test value. |
| `helm template` — `inferInit.model=""` (default) | **PASS** — zero `infer-init` resources rendered (no Job, no NetworkPolicy); confirmed by grepping the full render for `infer-init`/`allow-puller-ingress-from-init` — no matches. |
| `helm template --set inferInit.model=qwen2.5-3b-instruct-q4_k_m` | **PASS** — Job + both NetworkPolicy rules render, hardened (`runAsNonRoot`, `runAsUser: 1000`, cap-drop ALL, `seccompProfile: RuntimeDefault`, `readOnlyRootFilesystem: true`, `automountServiceAccountToken: false`). Also confirmed with `networkPolicies.enabled=false` — Job renders, zero NetworkPolicy resources. |
| `kubectl apply --dry-run=server` (Docker Desktop's local cluster, `namespace=default` override) | **PASS** — all 18 rendered resources, including `job.batch/test-yashigani-infer-init` and the two new NetworkPolicy rules, accepted by a real API server. |
| Both inline Python scripts (`wait-for-puller` initContainer + `infer-init` container + compose equivalent) | **`compile()`-checked, zero SyntaxError** — extracted verbatim from the rendered/`docker compose config` output, not hand-retyped. |
| `docker compose -f docker-compose.infer.yml -f docker-compose.infer.cpu.yml --profile init config` — `YSG_INFER_INIT_MODEL` unset and set | **PASS** both ways. |
| Live functional test — own scratch Docker harness, stub server implementing exactly `app.py`'s `/healthz` + `/api/pull` contract (200-success / 501-no-adapter / unhealthy) | **PASS** all scenarios — see table above. Script extracted verbatim from the rendered Helm Job / `docker compose config` output before running (no hand-retyped copy), matching Verification Protocol #8's "full command must succeed against a running peer" discipline. |
| Same pull script under full container hardening (`--read-only --tmpfs /tmp:size=64m --cap-drop ALL --security-opt no-new-privileges:true --user 1000:1000`) | **PASS** — matches the Job/compose service's actual runtime security context; no permission errors. |

## Explicitly deferred to a live GPU build (nothing guessed)

1. Every `FROM ...@sha256:PLACEHOLDER-RESOLVE-AT-BUILD-TIME` digest — no registry access this
   session. `scripts/resolve-and-pin-digests.sh --check-only` greps for every remaining
   placeholder (offline-safe); `--cve-check`/`--emit-manifest` require network + a rig and are
   explicitly gated on Maxine/Tiago authorisation before running.
2. `LLAMA_CPP_TAG`/`LLAMA_CPP_COMMIT_SHA` resolution + the standing per-repin CVE gate against
   disclosed GGUF-loader advisories.
3. Actually building any of the 6 images (cuda/rocm/vulkan/cpu/puller/first-parse-jail) — no
   `docker build`/`podman build` was run.
4. Live `docker inspect`/`podman inspect` confirmation that the seccomp profile survives the
   `podman compose` v2 wrapper (YSG-RISK-074) rather than silently reverting to `unconfined` —
   this requires a running container.
5. Live GPU-engaged healthcheck testing against a real GPU (killing the GPU/driver mid-run
   and confirming the probe flips to unhealthy within one interval, per SOP 2's "verify by
   killing dependencies" discipline) — requires real GPU hardware.
6. K8s `Localhost` seccomp profile provisioning end-to-end (the DaemonSet + `localhostProfile`
   path is authored and `helm template`-verified, but was never applied to a live node).
7. Resolving `CUDA_ARCHITECTURES`/`AMDGPU_TARGETS` against the actual target fleet's real GPU
   generations (representative lists only, not confirmed against a real deploy target).
