#!/usr/bin/env bats
# tests/install/test_pick_ollama_model_for_vram.bats
#
# YSG-RISK-178 (product-correctness / default-model precedence, 2026-07-30):
# out-of-box default = LOCAL, and the SPECIFIC local model must be
# auto-selected from the host's GPU/VRAM specs, not a hardcoded name.
#
# _pick_ollama_model_for_vram() (install.sh) is the function that produces
# the value written to docker/.env as OLLAMA_MODEL (Step 8b-ii, "write
# OLLAMA_MODEL to .env for the gateway + ui4 chat inference"), which the
# gateway (entrypoint.py: `model = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")`)
# reads as its LOCAL default model — the same value that ultimately becomes
# _state.default_model / OptimizationEngine.default_model. This test locks
# the VRAM-tier -> model mapping the rest of the default-resolution chain
# depends on, and specifically covers the RTX 3060 12GB tier this feature
# was live-verified against (12288 MiB -> llama3.1:8b, confirmed on the
# docker-leg test stack's docker/.env: OLLAMA_MODEL=llama3.1:8b).
#
# Functions under test:
#   _pick_ollama_model_for_vram — VRAM (MB) -> recommended OLLAMA_MODEL
#
# Tests are fully hermetic: function extracted from install.sh via
# brace-count awk (same technique as test_ollama_port_resolution.bats);
# _pick_ollama_model_for_vram has zero nested braces so extraction is exact.
#
# Requirements:
#   bats-core >= 1.10.0, bash 4.x+
#
# Run:
#   bats tests/install/test_pick_ollama_model_for_vram.bats

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
INSTALL_SH="${REPO_ROOT}/install.sh"

setup() {
  local fn_body
  fn_body="$(awk '
    /^_pick_ollama_model_for_vram\(\)[ \t]*\{/ { f=1 }
    f {
      print
      d += gsub(/{/, "{")
      d -= gsub(/}/, "}")
      if (f && d <= 0) { exit }
    }
  ' "${INSTALL_SH}")"
  if [[ -z "$fn_body" ]]; then
    echo "ERROR: _pick_ollama_model_for_vram() not found in ${INSTALL_SH}" >&2
    return 1
  fi
  eval "$fn_body"
}

@test "no GPU (0 MB VRAM) picks the small CPU-tolerant model" {
  YSG_GPU_VRAM_MB=0
  run _pick_ollama_model_for_vram
  [ "$status" -eq 0 ]
  [ "$output" = "qwen2.5:3b" ]
}

@test "8GB tier (8192 MB) picks llama3.1:8b" {
  YSG_GPU_VRAM_MB=8192
  run _pick_ollama_model_for_vram
  [ "$output" = "llama3.1:8b" ]
}

@test "RTX 3060 12GB (12288 MB) picks llama3.1:8b — matches docker-leg live install" {
  YSG_GPU_VRAM_MB=12288
  run _pick_ollama_model_for_vram
  [ "$output" = "llama3.1:8b" ]
}

@test "just below 16GB tier boundary (16383 MB) still picks llama3.1:8b" {
  YSG_GPU_VRAM_MB=16383
  run _pick_ollama_model_for_vram
  [ "$output" = "llama3.1:8b" ]
}

@test "16GB tier boundary (16384 MB) still picks llama3.1:8b (only >=32GB steps up)" {
  YSG_GPU_VRAM_MB=16384
  run _pick_ollama_model_for_vram
  [ "$output" = "llama3.1:8b" ]
}

@test "32GB tier (32768 MB) picks the 30b MoE model" {
  YSG_GPU_VRAM_MB=32768
  run _pick_ollama_model_for_vram
  [ "$output" = "qwen3:30b-a3b" ]
}

@test "unset YSG_GPU_VRAM_MB (variable never exported) defaults to the small model" {
  unset YSG_GPU_VRAM_MB
  run _pick_ollama_model_for_vram
  [ "$output" = "qwen2.5:3b" ]
}
