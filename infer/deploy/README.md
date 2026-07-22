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

## Coordination gap — no ASGI entrypoint module exists yet

`infer/src/yashigani_infer/app.py`'s `create_app()` takes constructor keyword arguments
(`blob_store`, `supervisor`, `upstream`, `pull_resolver`, `output_inspection_hook`) — it is not
a bare `uvicorn --factory` target. Every Dockerfile's `ENTRYPOINT` (`docker/entrypoint/infer-
entrypoint.sh`) execs `uvicorn yashigani_infer.entrypoint:create_asgi_app --factory`, a module
that **does not exist in the package today**. The entrypoint script checks for it and **fails
closed with exit 78 (EX_CONFIG)** and a clear message rather than guessing a wiring invocation.
The exact env-var contract that module needs to honour is documented inline in
`infer-entrypoint.sh` (`YSG_INFER_ROLE`, `YSG_INFER_MAX_CTX`, `YSG_INFER_MAX_CONCURRENCY`,
etc.) — this is a named, build-blocking coordination item for Tom, not a deploy-layer bug.

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
