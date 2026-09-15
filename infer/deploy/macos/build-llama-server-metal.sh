#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
#
# Build `llama-server` for macOS / Apple Silicon (Metal) — Yashigani 6.0.
#
# This is the Mac counterpart to the Linux per-backend Dockerfiles
# (`infer/deploy/docker/Dockerfile.kuroshio-{cpu,cuda,rocm,vulkan}`) and is
# divergence **V-2** in the 6.0 cutover design: different accelerator, same
# provenance discipline. Everything that is not the accelerator flag is
# deliberately identical to the Linux build contract:
#
#   - pin by TAG **and** commit SHA, and refuse to build on any mismatch
#     (mirrors `Dockerfile.kuroshio-cpu:23-25`);
#   - `GGML_NATIVE=OFF` so a build host's own microarchitecture cannot be
#     baked into a binary that must run on every M-series Mac;
#   - measure the output and emit a manifest, so the artefact can be verified
#     later rather than trusted because of where it sits on disk.
#
# WHY A SCRIPT AND NOT A CONTAINER: Apple Silicon has no GPU passthrough into
# a Linux VM, so Metal is only reachable from a host-native process. See DoR
# D16/D22 — the container paths that DO reach Metal (krunkit/Venus, GGML API
# remoting) are disqualified for not being multitenant-safe, not for being
# impossible.
#
# PRIMARY PATH IS NOT THIS SCRIPT. Per D25 both platforms consume the verified
# upstream prebuilt via `infer/deploy/scripts/fetch-llama-server.sh`. This
# from-source build is retained for the one job the fetch cannot do: carrying
# OUR OWN patch when we fix something upstream has not yet released — which is
# the actual sovereignty argument, and what llama.cpp's SECURITY.md invites.
#
# NOT DONE HERE, deliberately:
#   - codesign / notarize (YSG-RISK-282 + the owed Developer-ID key-custody
#     model). This script produces an UNSIGNED binary. Signing is a separate,
#     custody-gated step and must not be folded into a build script.
#   - the CVE gate the Linux build manifest makes mandatory on every re-pin
#     (`resolve-and-pin-digests.sh --cve-check`) — that subcommand is an
#     `exit 3` stub today (YSG-RISK-302), so it cannot be invoked honestly.
#     Re-pinning without it is a known, recorded gap, not an oversight.

set -euo pipefail

# --- pin ---------------------------------------------------------------------
# Both must be set together. A tag alone is not a pin: tags move, and a moved
# tag is exactly how a supply-chain substitution arrives looking legitimate.
LLAMA_CPP_REPO="${LLAMA_CPP_REPO:-https://github.com/ggml-org/llama.cpp}"
LLAMA_CPP_TAG="${LLAMA_CPP_TAG:-PIN-ME}"
LLAMA_CPP_COMMIT_SHA="${LLAMA_CPP_COMMIT_SHA:-PIN-ME}"

BUILD_ROOT="${BUILD_ROOT:-$(pwd)/kuroshio-metal-build}"
OUT_DIR="${OUT_DIR:-${BUILD_ROOT}/out}"
JOBS="${JOBS:-$(sysctl -n hw.ncpu)}"

log() { printf '    --> %s\n' "$*"; }
die() { printf '!!  FATAL: %s\n' "$*" >&2; exit 1; }

# --- pre-flight: fail closed, never warn-and-continue -------------------------
# The installer's existing macOS Ollama preflight warns, sleeps 5 and carries
# on (YSG-RISK-283 class). A build that silently produces a CPU-only binary
# and calls it a Metal build is the same failure with a worse blast radius,
# so every check here aborts.

[[ "$(uname -s)" == "Darwin" ]] || die "macOS only (this is the Metal build)"
[[ "$(uname -m)" == "arm64"  ]] || die "Apple Silicon (arm64) required; got $(uname -m)"

[[ "${LLAMA_CPP_TAG}" != "PIN-ME" && "${LLAMA_CPP_COMMIT_SHA}" != "PIN-ME" ]] \
  || die "LLAMA_CPP_TAG and LLAMA_CPP_COMMIT_SHA must both be pinned — refusing to build against a moving ref"

command -v git >/dev/null   || die "git not found"
CMAKE="${CMAKE:-$(command -v cmake || true)}"
[[ -n "${CMAKE}" ]] || die "cmake not found — set CMAKE=/path/to/cmake"

# The Metal shader compiler ships as a separately-downloaded Xcode component
# and is absent on a stock install. Without it the build silently falls back
# to a CPU-only binary on some configurations — the exact silent-downgrade
# class YSG-RISK-301 is about, caught here at build time instead.
xcrun -sdk macosx metal --version >/dev/null 2>&1 \
  || die "Metal toolchain missing. Run: xcodebuild -downloadComponent MetalToolchain"

log "host: $(sysctl -n machdep.cpu.brand_string), $(sw_vers -productVersion), $(uname -m)"
log "cmake: $("${CMAKE}" --version | head -1)"

# --- fetch at the pinned ref, verify, refuse on mismatch ----------------------
mkdir -p "${BUILD_ROOT}"
SRC="${BUILD_ROOT}/src"
if [[ ! -d "${SRC}/.git" ]]; then
  log "cloning ${LLAMA_CPP_REPO} @ ${LLAMA_CPP_TAG}"
  git clone --depth 1 --branch "${LLAMA_CPP_TAG}" "${LLAMA_CPP_REPO}" "${SRC}"
fi

ACTUAL_SHA="$(git -C "${SRC}" rev-parse HEAD)"
[[ "${ACTUAL_SHA}" == "${LLAMA_CPP_COMMIT_SHA}" ]] || die \
  "pin mismatch: tag ${LLAMA_CPP_TAG} resolved to ${ACTUAL_SHA}, expected ${LLAMA_CPP_COMMIT_SHA}. \
The tag moved, or the pin is wrong. NOT building."
log "pin verified: ${LLAMA_CPP_TAG} = ${ACTUAL_SHA}"

# --- configure ----------------------------------------------------------------
#   GGML_METAL                ON  — explicit, though it defaults ON for Darwin.
#   GGML_METAL_EMBED_LIBRARY  ON  — embed the .metallib in the binary. Explicit
#                                   because we depend on it: a LaunchAgent runs
#                                   outside any .app bundle, so a loose
#                                   default.metallib beside the binary is both
#                                   a runtime-discovery risk and a tamper
#                                   surface that no signature would cover.
#   GGML_NATIVE               OFF — do not bake the build host's microarch in.
#                                   Less severe than on x86 (no AVX-family
#                                   fragmentation here; M1..M4 share an arm64
#                                   baseline) but the binary still ships to
#                                   machines that are not this one.
#   LLAMA_CURL                OFF — the engine must never fetch models itself;
#                                   pulls go through the control plane's
#                                   adapters, which are gated and audited.
"${CMAKE}" -S "${SRC}" -B "${BUILD_ROOT}/build" \
  -DCMAKE_BUILD_TYPE=Release \
  -DGGML_METAL=ON \
  -DGGML_METAL_EMBED_LIBRARY=ON \
  -DGGML_NATIVE=OFF \
  -DLLAMA_CURL=OFF \
  -DLLAMA_BUILD_TESTS=OFF \
  -DLLAMA_BUILD_EXAMPLES=OFF \
  -DLLAMA_BUILD_SERVER=ON

log "building llama-server with ${JOBS} jobs"
"${CMAKE}" --build "${BUILD_ROOT}/build" --config Release --target llama-server -j "${JOBS}"

BIN="$(find "${BUILD_ROOT}/build" -name llama-server -type f -perm -u+x | head -1)"
[[ -n "${BIN}" ]] || die "build reported success but no llama-server binary was produced"

# --- verify the artefact is what we asked for ---------------------------------
# "It compiled" is not evidence it is a Metal build, and three separate things
# have to hold. MEASURED, not assumed — an earlier version of this script
# checked `otool -L llama-server | grep Metal.framework` and correctly refused
# a perfectly good build, because that is the wrong binary to look at.
#
# llama.cpp on macOS produces a MULTI-DYLIB layout, not a static binary:
# llama-server links @rpath/libggml-metal.0.dylib, and it is THAT dylib which
# links Metal.framework. Consequences the 6.0 design did not anticipate and
# which are now load-bearing: the LaunchAgent must ship the dylibs with a
# correct @rpath, codesigning must cover every one of them rather than just
# the executable, and the manifest must measure the whole set.
BIN_DIR="$(dirname "${BIN}")"
METAL_DYLIB="${BIN_DIR}/libggml-metal.dylib"

otool -L "${BIN}" | grep -q "libggml-metal" \
  || die "llama-server does not link libggml-metal — CPU-only build, refusing to publish"
[[ -f "${METAL_DYLIB}" ]] \
  || die "libggml-metal.dylib missing from ${BIN_DIR} — the Metal backend was not built"
otool -L "${METAL_DYLIB}" | grep -qi "Metal.framework" \
  || die "libggml-metal.dylib does not link Metal.framework — refusing to publish"

# The strongest check available without loading a model: ask the binary what
# it can actually see. A CPU-only build lists no MTL device. This is also the
# mechanism YSG-RISK-301 needs — llama-server's HTTP API exposes NO device or
# offload information (verified against get_res_props() in
# tools/server/server-context.cpp), so /props cannot serve as that signal.
DEVICES="$("${BIN}" --list-devices 2>&1 || true)"
grep -qE '^\s*MTL[0-9]+:' <<<"${DEVICES}" \
  || die "llama-server --list-devices reports no Metal device. Output was:
${DEVICES}"
log "Metal device visible to the binary: $(grep -oE 'MTL[0-9]+: .*' <<<"${DEVICES}" | head -1)"

# --- publish the whole artefact set ------------------------------------------
mkdir -p "${OUT_DIR}"
cp "${BIN}" "${OUT_DIR}/llama-server"
# Follow the dylibs llama-server actually depends on, plus the ggml backends —
# shipping the executable alone produces a binary that cannot start.
find "${BIN_DIR}" -maxdepth 1 -name '*.dylib' -exec cp {} "${OUT_DIR}/" \;

DIGEST="$(shasum -a 256 "${OUT_DIR}/llama-server" | awk '{print $1}')"
ARTIFACT_DIGESTS="$(cd "${OUT_DIR}" && shasum -a 256 llama-server *.dylib \
  | awk '{printf "    {\"file\": \"%s\", \"sha256\": \"%s\"},\n", $2, $1}' | sed '$ s/,$//')"

cat > "${OUT_DIR}/llama-server.manifest.json" <<EOF
{
  "artifact": "llama-server",
  "platform": "darwin-arm64",
  "accelerator": "metal",
  "layout": "multi-dylib (llama-server + ggml backend dylibs, @rpath-linked)",
  "llama_cpp_repo": "${LLAMA_CPP_REPO}",
  "llama_cpp_tag": "${LLAMA_CPP_TAG}",
  "llama_cpp_commit_sha": "${ACTUAL_SHA}",
  "cmake_flags": "GGML_METAL=ON GGML_METAL_EMBED_LIBRARY=ON GGML_NATIVE=OFF LLAMA_CURL=OFF",
  "sha256": "${DIGEST}",
  "files": [
${ARTIFACT_DIGESTS}
  ],
  "built_on_macos": "$(sw_vers -productVersion)",
  "built_on_cpu": "$(sysctl -n machdep.cpu.brand_string)",
  "metal_devices": "$(grep -oE 'MTL[0-9]+: [^(]*' <<<"${DEVICES}" | head -1 | tr -d '\n')",
  "signed": false,
  "notarized": false,
  "cve_gate_run": false
}
EOF

log "artifact:  ${OUT_DIR}/llama-server (+ $(ls "${OUT_DIR}"/*.dylib | wc -l | tr -d ' ') dylibs)"
log "sha256:    ${DIGEST}"
log "manifest:  ${OUT_DIR}/llama-server.manifest.json"
log "UNSIGNED — codesign/notarize is a separate custody-gated step (YSG-RISK-282),"
log "           and must cover EVERY dylib above, not just the executable."
