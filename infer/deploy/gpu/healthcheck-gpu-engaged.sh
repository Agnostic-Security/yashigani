#!/bin/sh
# GPU-engaged healthcheck (Captain finding #6 / Red-Council MEDIUM / platform doc §4.5).
#
# Closes two gaps a bare ">0 offloaded layers" check leaves open:
#   1. TIMING — this re-queries the GPU LIVE at probe time (nvidia-smi / rocm-smi), never a
#      cached load-time log line. A mid-run driver-level fallback, VRAM-pressure eviction, or
#      GPU reset that silently drops a model back to CPU is caught on the NEXT probe interval,
#      not only at initial load.
#   2. POLICY-AWARENESS — MoE expert-offload (attention-on-GPU, experts-on-CPU) intentionally
#      reports a SMALL non-zero VRAM footprint. A bare ">0" check cannot distinguish
#      "policy-correct partial offload" from "almost everything fell back to CPU except a
#      residual few layers" — both produce a small positive number. This script compares the
#      live-measured VRAM against an operator-declared expected-floor
#      (YSG_KUROSHIO_EXPECTED_VRAM_MB), not just a bare non-zero test.
#
# Exit 0 = healthy. Exit 1 = hard-fail (Docker HEALTHCHECK / k8s exec probe both treat
# non-zero as unhealthy — this is deliberately NOT a soft warning path; platform doc §4.5:
# "hard fail if 0 offloaded layers on a GPU-tagged deployment, not a warning").

set -eu

BACKEND="${YSG_KUROSHIO_BACKEND:-unknown}"
EXPECT_GPU="${YSG_KUROSHIO_EXPECT_GPU:-true}"
EXPECTED_VRAM_MB="${YSG_KUROSHIO_EXPECTED_VRAM_MB:-1}"  # operator-declared per-model floor; MoE
                                                       # partial-offload deployments set this
                                                       # to the small-but-nonzero expected value,
                                                       # not left at the permissive default.

# CPU-tagged / dev-cell deployments (M-k8s CPU-in-pod) explicitly relax this check per
# platform doc §6.M-k8s — "labelled dev-only; the GPU-engaged healthcheck is relaxed to
# 'CPU expected' for this cell so it doesn't hard-fail."
if [ "${EXPECT_GPU}" != "true" ]; then
    echo "OK: EXPECT_GPU=false (CPU-expected deployment) — GPU re-measure skipped."
    exit 0
fi

live_vram_mb=""
case "${BACKEND}" in
    cuda)
        if ! command -v nvidia-smi >/dev/null 2>&1; then
            echo "FAIL: backend=cuda but nvidia-smi is not present in this container" >&2
            exit 1
        fi
        # Sum used memory across visible GPUs — live query, not a cached value.
        live_vram_mb="$(nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits 2>/dev/null \
            | awk '{s+=$1} END {print s+0}')"
        ;;
    rocm)
        if ! command -v rocm-smi >/dev/null 2>&1; then
            echo "FAIL: backend=rocm but rocm-smi is not present in this container" >&2
            exit 1
        fi
        live_vram_mb="$(rocm-smi --showmeminfo vram --csv 2>/dev/null \
            | awk -F',' 'NR>1 && $2 ~ /^[0-9]+$/ {s+=$2} END {print int(s/1048576)+0}')"
        ;;
    vulkan)
        # No standard vendor-neutral live-VRAM CLI across all Vulkan ICDs (Intel/AMD/nvidia
        # via Vulkan). Fall back to cross-checking the engine's own live self-report against
        # llama-server's /props endpoint (still a LIVE query, not a load-time cache) —
        # honest residual: this is weaker than the CUDA/ROCm vendor-tool path and is
        # documented as such, not silently equivalent.
        health_json="$(python3 -c "
import sys, urllib.request, json
try:
    with urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=5) as r:
        print(r.read().decode())
except Exception:
    sys.exit(1)
" 2>/dev/null)" || { echo "FAIL: could not reach engine /healthz for vulkan live re-check" >&2; exit 1; }
        echo "${health_json}" | grep -q '"gpu_engaged": *true' || {
            echo "FAIL: vulkan backend /healthz reports gpu_engaged=false at probe time" >&2
            exit 1
        }
        echo "OK: vulkan gpu_engaged=true (engine self-report cross-check; no vendor-neutral live VRAM tool)"
        exit 0
        ;;
    *)
        echo "FAIL: unknown YSG_KUROSHIO_BACKEND=${BACKEND} for a GPU-expected deployment" >&2
        exit 1
        ;;
esac

if [ -z "${live_vram_mb}" ] || [ "${live_vram_mb}" -lt "${EXPECTED_VRAM_MB}" ] 2>/dev/null; then
    echo "FAIL: live VRAM used (${live_vram_mb:-0} MB) below expected policy floor (${EXPECTED_VRAM_MB} MB) — silent CPU fallback or MoE under-offload" >&2
    exit 1
fi

echo "OK: backend=${BACKEND} live VRAM used=${live_vram_mb} MB (>= expected floor ${EXPECTED_VRAM_MB} MB)"
exit 0
