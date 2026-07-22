#!/bin/sh
# Yashigani inference engine — container entrypoint.
#
# Responsibilities (deploy layer only — never business logic):
#   1. OOM-score-adjust (Captain finding #3): raise this process's own
#      /proc/self/oom_score_adj so the kernel OOM-killer takes an infer container before
#      host-critical services (Caddy, PKI, audit sink) under memory pressure. A process may
#      always INCREASE its own oom_score_adj without CAP_SYS_RESOURCE (only decreasing below
#      the current value needs the capability) — safe as a non-root, no-new-privileges step.
#   2. --healthcheck / --healthcheck-puller: GPU-engaged + liveness probe (delegates to
#      gpu/healthcheck-gpu-engaged.sh for the GPU-specific live re-measure).
#   3. exec the ASGI entrypoint.
#
# set -e deliberately NOT used for the oom_score_adj write below — some sandboxed/rootless
# runtimes (gVisor, some CI containers) restrict /proc/self/oom_score_adj writes even for
# self-increase; this must degrade to a WARNING, never a container-start failure, on a
# control that is defense-in-depth, not the primary containment (finding #3 primary controls
# are the compose/k8s memory.max cgroup ceiling set at the orchestrator level, not this).

set -eu

OOM_SCORE_ADJ="${YSG_INFER_OOM_SCORE_ADJ:-500}"
if [ -w /proc/self/oom_score_adj ]; then
    if ! echo "${OOM_SCORE_ADJ}" > /proc/self/oom_score_adj 2>/dev/null; then
        echo "WARN: could not set oom_score_adj=${OOM_SCORE_ADJ} (non-fatal, defense-in-depth only)" >&2
    fi
else
    echo "WARN: /proc/self/oom_score_adj not writable in this runtime (non-fatal)" >&2
fi

case "${1:-}" in
    --healthcheck)
        # GPU backends (cuda/rocm/vulkan) ship /usr/local/bin/healthcheck-gpu-engaged.sh
        # (copied in at build time — see the per-backend Dockerfile). CPU backend does not
        # (no GPU to re-measure) and falls straight through to plain liveness.
        if [ -x /usr/local/bin/healthcheck-gpu-engaged.sh ]; then
            exec /usr/local/bin/healthcheck-gpu-engaged.sh
        fi
        exec python3 -c "
import sys, urllib.request
try:
    with urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=5) as r:
        sys.exit(0 if r.status == 200 else 1)
except Exception:
    sys.exit(1)
"
        ;;
    --healthcheck-puller)
        exec python3 -c "
import sys, urllib.request
try:
    with urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=5) as r:
        sys.exit(0 if r.status == 200 else 1)
except Exception:
    sys.exit(1)
"
        ;;
esac

# ─────────────────────────────────────────────────────────────────────────────
# COORDINATION GAP (flagged, not silently papered over — see infer/deploy/README.md
# "Deferred / coordination gaps"): infer/src/yashigani_infer/ has no ASGI entrypoint
# module yet. app.py's create_app() takes constructor keyword args (blob_store,
# supervisor, upstream, pull_resolver, output_inspection_hook) — it is not a bare
# uvicorn --factory target. Building that wiring module (env-var-driven construction
# of BlobStore/Supervisor/ProcessRunner/UpstreamClient + role-based pull_resolver
# selection per YSG_INFER_ROLE) is Python control-plane code and belongs in Tom's
# package (e.g. `yashigani_infer.entrypoint:create_asgi_app`), not authored here.
#
# The env-var contract this deploy layer expects that module to honour:
#   YSG_INFER_ROLE                  classifier | chat | puller
#   YSG_INFER_BLOB_STORE_ROOT       (already exists — config.py)
#   YSG_INFER_LLAMA_SERVER_BINARY   default "llama-server"; ABSENT in the puller image
#   YSG_INFER_MAX_CTX               hard n_ctx ceiling (clamp, never reject)
#   YSG_INFER_MAX_CONCURRENCY       ResourceLimits.max_concurrent_requests
#   YSG_INFER_MAX_TOKENS_PER_REQUEST ResourceLimits.max_tokens_per_request
#   YSG_INFER_IDLE_UNLOAD_SECONDS   Supervisor idle-unload timeout
#   YSG_INFER_MAX_RESIDENT_MODELS   Supervisor LRU ceiling
#   YSG_INFER_KEEP_ALIVE_PIN        "true" for the classifier role (WARMUP-001 analog)
#   YSG_INFER_EXPECT_GPU            "true" on GPU-tagged deployments (healthz hard-fail gate)
#   YSG_INFER_N_GPU_LAYERS / YSG_INFER_OVERRIDE_TENSOR   MoE offload passthrough
#
# Until that module exists, this ENTRYPOINT fails closed with a clear message rather than
# guessing a uvicorn invocation that would silently construct the wrong objects.
if ! python3 -c "import yashigani_infer.entrypoint" 2>/dev/null; then
    echo "FATAL: yashigani_infer.entrypoint module not found — no ASGI wiring entrypoint" >&2
    echo "       exists yet in the yashigani_infer package. This is a documented build-" >&2
    echo "       blocker (infer/deploy/README.md), not a deploy-layer bug. Refusing to" >&2
    echo "       start rather than guess a wiring invocation." >&2
    exit 78  # EX_CONFIG
fi

exec uvicorn yashigani_infer.entrypoint:create_asgi_app --factory \
    --host 0.0.0.0 --port 8000 --no-server-header
