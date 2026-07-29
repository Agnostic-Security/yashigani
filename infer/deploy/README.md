# Yashigani 6.0 inference engine — RUNTIME / CONTAINER / DEPLOYMENT layer

**Author:** Captain · **Date:** 2026-07-22 · **Status:** OFFLINE-AUTHORED, design + artifacts
only. No image was built, no container was run, no rig was touched (dispatch constraint).
Grounded in `internal-docs/yashigani/captain-infer-engine-runtime-redteam-20260722.md` (my own
red-team findings, cited as "Captain finding #N" throughout this tree),
`internal-docs/yashigani/RED-COUNCIL-infer-engine-untrusted-input-synthesis-20260722.md`, and
`AgnosticSecurity/Products/Yashigani/inference-engine-platform-requirements-20260722.md`.

This is a **standalone, pre-integration deploy tree** — it has not been merged into
`docker/`/`helm/yashigani` and does not modify Tom's `infer/src/kuroshio/` package.
Convergence into the main compose/Helm surfaces is a follow-up integration step, not done here.

## Directory map

```
infer/deploy/
├── manifests/llama-cpp-build-manifest.md   pinned-tag + build-flag record, per backend
├── docker/
│   ├── Dockerfile.infer-{cuda,rocm,vulkan,cpu}   lean per-backend serving images (item 1)
│   ├── Dockerfile.kuroshio-puller                    blob-write-path-only, NO llama-server binary
│   ├── Dockerfile.kuroshio-first-parse-jail          C1 jail image (item 2)
│   ├── entrypoint/{kuroshio-entrypoint.sh,first-parse-jail-entrypoint.sh}
│   ├── seccomp/{kuroshio-llama-server.json,kuroshio-first-parse-jail.json}   (items 2, 4)
│   ├── apparmor/yashigani-kuroshio-llama-server                          (item 4)
│   ├── Caddyfile.kuroshio-front                       ring-fence front, single source (item 6)
│   ├── docker-compose.kuroshio.yml                    base topology (items 3, 5, 6, 7)
│   ├── docker-compose.kuroshio.{cuda,rocm,vulkan,cpu,podman-override}.yml   image-SWAP overlays (item 7)
│   └── docker-compose.kuroshio.cuda-podman-devpath.yml   CDI-failure fallback (Iris RC-5, standalone
│                                                        alternative to cuda.yml, not layered on it)
├── gpu/healthcheck-gpu-engaged.sh                  live re-measure healthcheck (item 8)
├── helm/yashigani-kuroshio/                           standalone chart (items 3, 5, 6, 7)
└── scripts/{resolve-and-pin-digests,verify-seccomp-json,sync-kuroshio-deploy-artifacts-to-helm,verify-offline}.sh
```

## Mapping to the 8 dispatch deliverables

1. **Per-backend Dockerfiles** — `docker/Dockerfile.infer-{cuda,rocm,vulkan,cpu}`. Lean (not
   `GGML_BACKEND_DL`), digest-pinned base image FROM lines (placeholders — see "Deferred"),
   pinned llama.cpp tag/commit (placeholder — see "Deferred"), build flags recorded in
   `manifests/llama-cpp-build-manifest.md`.
2. **C1 first-parse jail** — `Dockerfile.kuroshio-first-parse-jail` +
   `seccomp/kuroshio-first-parse-jail.json` (network-syscall-family fully absent, not merely
   policy-denied) + `docker-compose.kuroshio.yml`'s `invoke-first-parse-jail` service
   (`network_mode: none`, ephemeral, `--rm`) + `helm/.../templates/job-first-parse-jail.yaml`
   (ephemeral k8s Job, `ttlSecondsAfterFinished`, `restartPolicy: Never`, `dnsPolicy: None`).
   Vendors ONLY Tom's existing pure-Python `gguf/header.py`/`quant_types.py` — no new parsing
   logic authored here (see "Wiring to Tom's seam" below for what remains).
3. **C3 scoped supervisor privilege** — `docker-compose.kuroshio.yml`'s
   `kuroshio-docker-socket-proxy` service (Tecnativa image, coarse RBAC: containers-only,
   POST-only, no exec/attach/images/networks/etc.) + `helm/.../templates/{serviceaccount,rbac}-supervisor.yaml`
   (namespaced Role, `pods`/`jobs` only, no `secrets`, no `bind`/`escalate`, no cluster scope)
   + `helm/.../templates/admission-policy-kuroshio.yaml` (Kyverno ClusterPolicy denying
   hostPath/hostNetwork/hostPID/privileged/cap-add/`yashigani-pki` SA assumption — same family
   as the existing `restrict-pki-trust-plane`). **Both gated OFF by default** (`profiles:
   ["orchestration-v2"]` / `supervisorRbac.enabled: false`) — see "C3 residual gap" below.
4. **seccomp/AppArmor for llama-server** — `seccomp/kuroshio-llama-server.json` (enumerated
   allow-list + explicit documented deny-list: ptrace, process_vm_readv/writev, unshare/clone-
   new-namespaces, mount family, keyctl family, bpf, perf_event_open, kexec, module load/unload,
   iopl/ioperm, syslog) + `apparmor/yashigani-kuroshio-llama-server` (network tcp/unix only, blob
   read-only, scratch-only write, ptrace/mount deny).
5. **Resource bounds** — `docker-compose.kuroshio.yml`: `mem_limit`/`pids_limit`/
   `mem_swappiness: 0`/`memswap_limit` per service (classifier 4GB/256 pids, chat 16GB/512
   pids); `entrypoint/kuroshio-entrypoint.sh` self-raises `oom_score_adj` (defense-in-depth, not
   primary control). Helm: `resources.requests/limits` per Deployment (QoS-class is the k8s-
   native OOM-victim-selection mechanism — see inline comments). **Classifier-vs-user-model
   isolation is a separate Deployment/compose-service, MUST not "ideally"** — see next item.
6. **Classifier/chat/puller container split** (closes finding #4 concretely, see README
   section below for the reasoning) — three physically distinct containers/pods, not three
   processes in one container.
7. **Ring-fence + `Caddyfile.kuroshio-front`** — single source, byte-identical `.Files.Get` mirror
   in `helm/yashigani-kuroshio/files/` (synced by `scripts/sync-kuroshio-deploy-artifacts-to-helm.sh`,
   verified live in this session — see "Offline verify results"). TLS 1.3 + PQ-hybrid curve +
   `client_auth require_and_verify`, caller-gate narrowed to gateway+egress-forwarders (stamped-
   header pattern, not CEL — Caddy 2.11.x `*url.URL` bug), `handle_path /kuroshio/*`, default-deny
   404. `internal:true` bridge (compose) / default-deny-egress NetworkPolicy (k8s).
8. **GPU-engaged healthcheck** — `gpu/healthcheck-gpu-engaged.sh`: live `nvidia-smi`/`rocm-smi`
   query at PROBE TIME (never a cached load-time value), cross-checked against an
   operator-declared expected-VRAM-floor (policy-aware, not a bare `>0` check — closes the MoE
   partial-offload ambiguity). NVIDIA Container Toolkit CDI escape CVE class (CVE-2024-0132)
   noted in `manifests/llama-cpp-build-manifest.md`'s sibling concern.
   **CORRECTION (Laura F3, Red Council 2026-07-29): the digest-pin/scan gate for base images
   (item 1) is NOT the mitigation for this CVE class — that claim was wrong as originally
   written here.** Digest-pinning `kuroshio-cuda`'s base image only pins what ships INSIDE the
   container (the CUDA runtime libraries); CVE-2024-0132 and its class live in the
   HOST-INSTALLED `nvidia-container-toolkit`/`libnvidia-container` version — the component
   that generates the CDI spec and mediates the ioctl-based GPU device grant — which sits
   entirely outside the container image's own supply chain. Pinning/scanning `kuroshio-cuda`'s
   digest gives zero assurance about the host toolkit version; `seccomp/kuroshio-llama-server.json`
   necessarily allow-lists `ioctl` (required for `/dev/nvidia*` functionality, correct and
   expected), which means no layer in this deploy tree actually gates on host toolkit version.
   The real mitigation is a HOST-SIDE preflight: check the installed
   `nvidia-container-toolkit`/`libnvidia-container` version against a documented minimum-safe
   floor before selecting the CUDA overlay, failing closed (fall back to `kuroshio-cpu`, or abort
   with a clear message) below that floor — the natural hook is `install.sh`'s GPU-dispatch
   function, same lane as the existing ollama CDI-vs-devpath probe
   (`install.sh` ~2302-2420/~7070-7193). **This preflight is explicitly NOT built here** —
   HARD CONSTRAINT for this dispatch is `infer/` files only; the host-toolkit-version gate is
   a `release/5.0`/`install.sh`-side cutover item, documented accurately here so it isn't
   silently mistaken for already-covered by the digest-pin gate.

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
  read-only `hostPath` volume + mount on `kuroshio-classifier`/`kuroshio-chat` ONLY when
  `backend == "vulkan"` and the value is set. Both values must be set correctly for Vulkan to
  actually engage a GPU in k8s — left empty (default), the cell is CPU-only, now documented as
  such instead of silently claimed GREEN. Verified via `helm template` with/without the knob set
  (see gates below) — no live Intel GPU node available this session.

- **C1 deploy-side (Captain finding #4) — k8s `sessionAffinity`.** `kuroshio-chat`'s Service now sets
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
  `YSG_KUROSHIO_EXPECT_GPU: "false"`, but the Helm chart had no equivalent cascade, so a stock
  `helm install` (no `--set backend=...`, no GPU) shipped `YSG_KUROSHIO_EXPECT_GPU=true` into the
  env-var contract the GPU-engaged healthcheck consumes — a day-one `/healthz` hard-fail out of
  the box. Fixed: both Deployments now cascade `YSG_KUROSHIO_EXPECT_GPU` to `"false"` whenever
  `.Values.backend == "cpu"`, regardless of the `expectGpu` value's own top-level default.
  Verified with `helm template --set backend=cpu` (renders `"false"`) vs `--set backend=cuda`
  (renders the configured `"true"` default unchanged).

- **NVIDIA CDI scoping (Captain finding #3) — least-privilege on multi-GPU hosts.**
  `docker-compose.kuroshio.cuda.yml` previously shared ONE `YSG_GPU_CDI` env var, identically
  defaulted to `nvidia.com/gpu=all`, across both `kuroshio-classifier` AND `kuroshio-chat` — harmless
  on a single-GPU host, but on any multi-GPU host every kuroshio container got CDI access to every
  physical GPU, including `kuroshio-chat` (the component this design explicitly treats as
  hostile — it runs untrusted, byte-authentic-but-behaviourally-poisoned models). Fixed:
  independent `YSG_KUROSHIO_GPU_CDI_CLASSIFIER` / `YSG_KUROSHIO_GPU_CDI_CHAT` vars, each now
  defaulting to `nvidia.com/gpu=0` (not `all`) — still correct on the common single-GPU host,
  no longer permissive-by-default on multi-GPU hosts. Multi-GPU operators must override both
  independently to pin distinct indices/UUIDs. `install.sh`-side automatic GPU-count/index
  detection to set these is deferred (5.0-side cutover work, out of scope for this
  infer/deploy-only dispatch). Verified via `docker compose config` — confirmed both default to
  scoped `gpu=0` and resolve independently when each var is overridden separately.

- **ROCm `group_add` GID stability (Captain finding #2).** `group_add: [video, render]`
  resolves the group NAME against the container's own `/etc/group` (the base image's baked-in
  GIDs) — for the grant to unlock `/dev/kfd`/`/dev/dri` on the host, that resolved GID must
  match the host device node's owning GID. `render` is dynamically allocated per-install with
  no cross-distro guarantee; a mismatch surfaces as `EACCES`, caught by the GPU-engaged
  healthcheck but undiagnosable as a GID issue without knowing to check. Fixed:
  `YSG_KUROSHIO_ROCM_VIDEO_GID` / `YSG_KUROSHIO_ROCM_RENDER_GID` env vars, defaulting to the
  pre-fix name-based behaviour (`video`/`render`, unchanged default) but overridable to
  numeric host GIDs (`stat -c '%g' /dev/kfd /dev/dri/renderD128`). `install.sh` host-GID-probe
  wiring to set these automatically is Su's lane, deferred (out of scope here). K8s is
  unaffected (AMD device-plugin manages device cgroup rules itself). Verified via
  `docker compose config` both with the default and with a numeric override.

- **Podman + CUDA CDI devpath fallback (Iris RC-5).** Some rootless-Podman + NVIDIA driver
  combinations fail `nvidia-ctk cdi generate` outright — install.sh already has this exact
  probe-and-fallback pattern for ollama, but the kuroshio engine's CUDA backend had no equivalent
  sibling file at all; a CDI-failure host had zero documented recovery path. New file
  `docker/docker-compose.kuroshio.cuda-podman-devpath.yml` mirrors ollama's
  `docker-compose.gpu-podman-devpath.yml` — direct `/dev/nvidia*` device-node passthrough,
  per-service scoped (same least-privilege fix as finding #3 above), applied **as a full
  standalone alternative to** `docker-compose.kuroshio.cuda.yml` (verified this session: Compose
  merges/appends `devices:` lists across files rather than replacing them, so layering on top
  of `cuda.yml` would leave both the broken CDI entry and the devpath entries present
  simultaneously — still fails on a genuine CDI-failure host; hence the standalone-file
  design, matching the same mutual-exclusivity convention already used for cuda/rocm/vulkan/
  cpu backend selection). `install.sh`-side CDI-probe wiring to select this file automatically
  is deferred (5.0-side cutover work, out of scope here).

  **Also fixed while gate-testing this** (pre-existing, discovered here, not introduced by
  this session): `docker-compose.kuroshio.podman-override.yml` re-declared `security_opt`
  byte-identical to the base file's own — Compose 29.4.1 treats exact-duplicate
  `security_opt` list entries across merged files as a hard validation error
  (`docker compose config` failed outright on the existing `cuda.yml` + `podman-override.yml`
  combination, with or without this session's new devpath file). Removed the redundant
  redeclaration; the base file's `security_opt` stands unchanged, and the YSG-RISK-074
  seccomp-persistence verification remains live-only (`podman inspect`) as
  `scripts/verify-offline.sh` already documents — a second textual declaration in another
  compose file was never able to catch a runtime wrapper bug anyway. Verified via
  `docker compose config` on all six overlay combinations (cuda, cuda+podman-override,
  cuda-podman-devpath standalone, rocm, vulkan, cpu) — all pass.

- **CVE-2024-0132 mitigation doc correction (Laura F3).** Item 8's original text claimed the
  digest-pin/scan gate for base images was "the mitigation" for the NVIDIA Container Toolkit
  CDI-escape CVE class — **wrong as written**: digest-pinning only pins what ships inside the
  image (CUDA runtime libs), while CVE-2024-0132's class lives in the HOST-installed
  `nvidia-container-toolkit`/`libnvidia-container` version, entirely outside the image's
  supply chain. Corrected item 8's text to state the real mitigation (a host-side toolkit
  version preflight, install.sh-side, gating the CUDA overlay selection) and explicitly mark
  it NOT built in this dispatch (HARD CONSTRAINT: `infer/`-only scope) rather than continuing
  to imply it's already covered. Documentation-only fix, no code/config change — nothing to
  gate beyond re-reading the corrected text.

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

- **`kuroshio-classifier`** and **`kuroshio-chat`** are two separate compose services / k8s
  Deployments — two separate instances of the SAME control-plane process, statically
  configured (`YSG_KUROSHIO_ROLE=classifier|chat`) so the classifier never shares a container,
  cgroup, or PID namespace with any chat model. This closes finding #4's (a) vector (ptrace/
  `/proc/<pid>/mem` cross-read) via the container/pod boundary itself, and k8s additionally
  gets a `podAntiAffinity` preference against co-scheduling on the same node.
- **`kuroshio-puller`** is a THIRD, separate container built from `Dockerfile.kuroshio-puller`,
  which contains **no llama-server binary at all**. It is the only container with blob-store
  WRITE access and a wired `pull_resolver`. `Caddyfile.kuroshio-front` routes `/kuroshio/pull`
  exclusively to this upstream; even if a stray request reached its `/api/chat` route (it must
  not — routing is the primary control), `Supervisor.load`'s `ProcessRunner.spawn(binary=
  "llama-server", ...)` would fail closed (binary absent), not fail open on trust. This closes
  finding #4's (b) vector (write-path isolation) using the *existing* `pull_resolver=None`
  constructor parameter in `app.py` — zero Python changes required.

## C3 residual gap (documented, not silently closed)

The Tecnativa `docker-socket-proxy` gives **coarse** RBAC (allow container-lifecycle HTTP
verbs, deny everything else) — it does **not** enforce a per-image-digest allowlist or a
required `yashigani.kuroshio.managed=true` label at the proxy layer (that image doesn't support
request-body inspection). The k8s side closes this gap fully via the Kyverno admission policy
(which DOES inspect the pod spec). The compose/socket-proxy side does not have an equivalent
today — recommended v2 hardening: a small custom authz sidecar (or Docker's Authorization
Plugin API) that inspects `POST /containers/create` bodies against a pinned `kuroshio-*` digest +
label allowlist before forwarding to the proxy. Not built this session (scope: compose+Helm
scaffolding, not a new authz-plugin component) — flagged, not silently left unmentioned.
Both the socket-proxy and the Helm RBAC/admission-policy are shipped **disabled by default**
(`profiles: ["orchestration-v2"]` / `supervisorRbac.enabled: false`) because v1's subprocess
supervisor doesn't consume them yet — enabling either without a real caller just adds an
unused privileged surface.

## Coordination gap — ASGI entrypoint module — RESOLVED

Tom landed `infer/src/kuroshio/entrypoint.py` (`b61b494b`, "add ASGI wiring entrypoint
closing Captain's coordination gap") — `create_asgi_app` is now a real `uvicorn --factory`
target that parses the documented env-var contract and constructs the real `BlobStore`/
`Supervisor`/`HttpxUpstreamClient` graph, failing closed (`EntrypointConfigError`) on any
missing/invalid required value. The entrypoint scripts' fail-closed exit-78 path is now dead
code in practice (module exists) but left in place — it degrades gracefully to the same
fail-closed behaviour if the module is ever removed/renamed.

## Blob-store mount path — RESOLVED (2026-07-22, follow-up fix)

Tom's entrypoint module surfaced a real gap in this tree: `docker-compose.kuroshio.yml` and the
three Helm Deployments never set `YSG_KUROSHIO_BLOB_STORE_ROOT`, so `BlobStore` defaulted to
`$HOME/.yashigani/kuroshio/blobs` **inside the container** — pulled models would not survive a
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
| `YSG_KUROSHIO_BLOB_STORE_ROOT` | `/data/model-store` | `/data/model-store` |
| Mount | named volume `kuroshio_model_store` (renamed from `infer_blobs`) → `/data/model-store` (classifier/chat `:ro`, puller `:rw`) | PVC `{{ fullname }}-blobs` → `/data/model-store` (classifier/chat `readOnly: true`, puller `readOnly: false`) |

Set identically on all three compose services and all three Helm Deployments (classifier,
chat, puller) — verified by `docker compose config` and `helm template` (see updated Offline-
verify table below). `docker/apparmor/yashigani-kuroshio-llama-server` and every Dockerfile's
`mkdir -p` were updated from `/data/blobs` to `/data/model-store` to match.

**Cold-start ordering, closed too (not left as a landmine):** classifier/chat mount the volume
**read-only** (finding #4, no exception) — on a brand-new, empty volume, `BlobStore.__init__`'s
`mkdir(parents=True, exist_ok=True)` would try to create `blobs/`/`meta/` itself and fail
closed (`EROFS`) before any model is ever pulled. Compose: `depends_on: kuroshio-puller:
condition: service_healthy` (puller mounts read-write and its own `BlobStore()` construction at
process startup creates both subdirs first). Helm: an `initContainer` on classifier/chat
mounts the same PVC read-write just to `mkdir -p` both subdirs before the main (read-only)
container starts — standard k8s per-container mount-mode pattern, no extra privilege.

**Also caught and fixed while verifying this (pre-existing, not introduced by this fix):**
`docker-compose.kuroshio.yml`'s seccomp bind-mount source was `../deploy/docker/seccomp/...`,
which resolves relative to the compose file's own directory (`infer/deploy/docker/`) to a
nonexistent `infer/deploy/deploy/docker/seccomp/...` path. Fixed to `./seccomp/...`; confirmed
via `docker compose config` that the resolved `source:` now points at the real file.

## Day-one models — `kuroshio-init` (2026-07-23, Captain, engine-side only)

Iris's cutover-prep map (`internal-docs/yashigani/iris-infer-6.0-to-5.0-cutover-prep-map-
20260723.md`, Seam 2, line 34) found this engine deploy shipped with **zero models** — no
equivalent of `release/5.0`'s `ollama-init` Job (the `SF-011` fix), so first-inference was
broken out of the box on a clean deploy. Closed via `templates/job-kuroshio-init.yaml` (Helm) and
`docker-compose.kuroshio.yml`'s `kuroshio-init` service (compose, `profiles: ["init"]`).

**Mechanism differs from `ollama-init`.** `kuroshio-puller` (see `deployment-puller.yaml` /
`docker-compose.kuroshio.yml`) is already a long-running peer with a wired `/api/pull` route
(`app.py`) — unlike `ollama-init`'s self-contained temporary `ollama serve` process,
`kuroshio-init` is a thin HTTP client: wait for `kuroshio-puller` healthy, then `POST /api/pull` with
the configured model name. Both the Helm Job and the compose service reuse the `kuroshio-puller`
image itself (python3 stdlib `urllib` only) — no new image to build or pin.

**CRITICAL — no hardcoded default model.** `kuroshioInit.model` (Helm) / `YSG_KUROSHIO_INIT_MODEL`
(compose) default **EMPTY**. Which GGUF ships as the day-one default, and its signed
provenance manifest, is **Tiago's provenance/signing decision** — the same class of council
finding (Laura F2/F3, Nico #1, Lu SUPPLY-1) that shaped `adapters/huggingface.py`'s pinned-
revision + signed-catalog admission gate applies here too: choosing an unsigned default
ourselves would be exactly the "resolve a sha256 live from the repo you're trusting"
anti-pattern those findings closed. With the value empty:
  - **Helm:** the Job (and its two dedicated NetworkPolicy rules) are **not rendered at all**
    — `{{- if and .Values.kuroshioInit.enabled (ne .Values.kuroshioInit.model "") }}` — verified via
    `helm template` both ways (see Offline-verify table below).
  - **Compose:** the `kuroshio-init` service always renders in `docker compose config` (compose
    has no Helm-style conditional resource omission), but its own script detects the empty
    model at runtime and exits 0 immediately as a no-op before attempting any HTTP call.

Before enabling day-one auto-pull in a real deploy: choose a default model, produce its signed
provenance manifest (Nico/catalog.py's `SignedCatalog` admission gate), THEN set
`kuroshioInit.model` / `YSG_KUROSHIO_INIT_MODEL` to that model's name.

**Known v1-foundation limitation, not hidden:** `entrypoint.py` hardwires `pull_resolver=None`
regardless of role (see "Coordination gap" above) — no source adapter is wired into any deploy
yet. `/api/pull` therefore always responds `501` until that separate Python wiring lands. Both
`kuroshio-init` scripts treat HTTP 501 specifically as a non-fatal, loudly-logged `WARNING` and
`exit 0` (retrying would never help — this is a permanent condition until the code changes,
not a transient one), rather than spending the Job's `backoffLimit` retrying a guaranteed
failure. Verified live this session (see below) against a stub server exercising exactly the
`/healthz` + `/api/pull` contract `app.py` implements, in all three states (`200` success,
`501` no-adapter, empty-model no-op) plus wait-for-ready.

**F1 convergence note (Iris Seam 3, line 48) — deliberately NOT built here:** `install.sh`'s
healthcheck-exemption / one-shot-job handling for `ollama-init` will need a sibling entry for
`kuroshio-init` in `_exempt_patterns` at convergence time. That is `release/5.0`-side wiring —
out of scope for this engine-only dispatch (HARD CONSTRAINT: only files under `infer/`).
Flagged here so it isn't silently dropped when this tree merges into `helm/yashigani`.

**NetworkPolicy note (k8s only):** `kuroshio-init`'s pod is deliberately **not** labeled
`yashigani.kuroshio.managed=true` (that label denotes a supervisor-*created* serving pod per
`admission-policy-kuroshio.yaml`'s own definition, not a static Helm-authored bootstrap Job).
`job-kuroshio-init.yaml` ships its own dedicated egress rule (puller:8000 + DNS only) and a
companion ingress rule on `kuroshio-puller` (alongside the existing Caddy-only allow), rather than
piggybacking on the shared `default-deny-egress` selector.

**Live verification this session (Docker, own scratch harness — no product image touched
beyond extracting its rendered scripts verbatim):**

| Scenario | Result |
|---|---|
| `wait-for-puller` initContainer script vs. a stub `/healthz` returning 200 | **PASS** — detects ready, exits 0 |
| `kuroshio-init` container script, stub `/api/pull` returns 200 NDJSON | **PASS** — streams progress, exits 0 |
| `kuroshio-init` container script, stub `/api/pull` returns 501 (no adapter wired) | **PASS** — logs WARNING, exits 0 (non-fatal, matches design) |
| compose `kuroshio-init` service script, `YSG_KUROSHIO_INIT_MODEL` empty | **PASS** — no-op, exits 0, no HTTP call made |
| compose `kuroshio-init` service script, model set, stub returns 200 | **PASS** — same as Helm case |
| Same pull script under full hardening (`--read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true --user 1000:1000`) | **PASS** — no permission errors |

## Offline-verify results (this session, `scripts/verify-offline.sh`)

| Gate | Result |
|---|---|
| hadolint (all 5 Dockerfiles) | **DL4006/SC2011/DL3003 fixed this session** (glob instead of `ls\|xargs`; `git -C src` instead of `cd src`). Residual: DL3008 (apt package version pin) + DL3013 (pip package version pin) — **matches the identical, pre-existing pattern in the shipped `docker/Dockerfile.gateway`** (confirmed by running the same `hadolint --config .hadolint.yaml` against it: same DL3008/DL3013 findings). Not a novel regression; not fixed here because pinning exact apt/pip version strings without live registry access would be fabricating versions (Verification Protocol #7 applies to package pins, not only image tags). |
| shellcheck (all 7 `.sh` files) | **PASS**, zero findings. |
| `helm lint helm/yashigani-kuroshio` | **PASS**. |
| `helm template` (default: cpu backend) | **PASS**. |
| `helm template` (cuda + supervisorRbac + seccomp DaemonSet, all optional resources rendered) | **PASS** — 19 resources: 5 NetworkPolicy, ServiceAccount, 2 ConfigMap, PVC, Role, RoleBinding, 3 Service, DaemonSet, 3 Deployment, Job. |
| `helm template --set admissionPolicies.enabled=true` | **Fails closed as designed** (no live cluster → Kyverno CRD `lookup` returns empty → explicit `fail` with remediation message) — same guard pattern as the main `helm/yashigani` chart's `admission-policies.yaml`, confirmed working, not a bug. |
| `caddy adapt --adapter caddyfile` on `Caddyfile.kuroshio-front` | **PASS** — parses to valid JSON config. Asserted: explicit `:11436` dial present, no `:80` anywhere, no `insecure_skip_verify` anywhere. |
| seccomp JSON validity (`jq`) | **PASS** — both profiles + the helm mirror parse and have `defaultAction: SCMP_ACT_ERRNO`. |
| Helm-mirror byte-parity (`sync-kuroshio-deploy-artifacts-to-helm.sh --check`) | **PASS** — Caddyfile + seccomp JSON mirrors byte-identical to canonical. |
| Portability fix (this session) | `sync-kuroshio-deploy-artifacts-to-helm.sh` originally used `declare -A` (bash 4+ associative arrays) — **fails on macOS's default bash 3.2**. Rewrote with parallel indexed arrays before first run; verified working on this Mac's actual `/bin/bash 3.2.57`. |
| `YSG_KUROSHIO_BLOB_STORE_ROOT` present on all 3 compose services | **PASS** — `docker compose -f docker-compose.kuroshio.yml -f docker-compose.kuroshio.cpu.yml config` shows `YSG_KUROSHIO_BLOB_STORE_ROOT: /data/model-store` on `kuroshio-classifier`, `kuroshio-chat`, `kuroshio-puller`; mount `target: /data/model-store` matches on all three. |
| `YSG_KUROSHIO_BLOB_STORE_ROOT` present on all 3 Helm Deployments | **PASS** — `helm template` (cuda variant) shows `value: "/data/model-store"` on `kuroshio-classifier`, `kuroshio-chat`, `kuroshio-puller` containers; `volumeMounts[].mountPath: /data/model-store` matches on all three. |

### `kuroshio-init` gates (2026-07-23 session — this Mac has live `helm`/`docker`/`kubectl`, used them)

| Gate | Result |
|---|---|
| `helm lint` | **PASS**, `kuroshioInit.model` empty (default) and set to a test value. |
| `helm template` — `kuroshioInit.model=""` (default) | **PASS** — zero `kuroshio-init` resources rendered (no Job, no NetworkPolicy); confirmed by grepping the full render for `kuroshio-init`/`allow-puller-ingress-from-init` — no matches. |
| `helm template --set kuroshioInit.model=qwen2.5-3b-instruct-q4_k_m` | **PASS** — Job + both NetworkPolicy rules render, hardened (`runAsNonRoot`, `runAsUser: 1000`, cap-drop ALL, `seccompProfile: RuntimeDefault`, `readOnlyRootFilesystem: true`, `automountServiceAccountToken: false`). Also confirmed with `networkPolicies.enabled=false` — Job renders, zero NetworkPolicy resources. |
| `kubectl apply --dry-run=server` (Docker Desktop's local cluster, `namespace=default` override) | **PASS** — all 18 rendered resources, including `job.batch/test-yashigani-kuroshio-init` and the two new NetworkPolicy rules, accepted by a real API server. |
| Both inline Python scripts (`wait-for-puller` initContainer + `kuroshio-init` container + compose equivalent) | **`compile()`-checked, zero SyntaxError** — extracted verbatim from the rendered/`docker compose config` output, not hand-retyped. |
| `docker compose -f docker-compose.kuroshio.yml -f docker-compose.kuroshio.cpu.yml --profile init config` — `YSG_KUROSHIO_INIT_MODEL` unset and set | **PASS** both ways. |
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
