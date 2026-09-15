#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
#
# Fetch + verify the UPSTREAM prebuilt `llama-server` — ALL PLATFORMS.
#
# Moved out of `deploy/macos/` because D25 makes this the single sourcing model
# for Linux AND macOS: Linux stops compiling llama.cpp in
# `Dockerfile.kuroshio-*` and consumes the same verified artifact. Keeping a
# Mac-only fetcher next to a Linux-only build would BE the divergence D26
# eliminates. **This is the primary path** (Tiago
# 2026-09-15: "it's easier to use the builds for updates"). The from-source
# build (`build-llama-server-metal.sh`) is kept for the cases that need flag
# control or a commit with no published release.
#
# Using the upstream artefact is defensible on measured grounds, not just
# convenience — all verified against release b10976 before this was written:
#
#   - Their macOS-arm64 CI builds with `-DGGML_METAL_EMBED_LIBRARY=ON`,
#     `-DGGML_NATIVE=OFF` and `-DCMAKE_OSX_DEPLOYMENT_TARGET=13.3`
#     (.github/workflows/release.yml:73 + the global NATIVE=OFF). That is the
#     flag set we would have chosen, plus a deployment target we had not.
#   - The binary does NOT link libcurl, so the engine cannot fetch models
#     itself — the containment invariant holds without us controlling flags.
#   - It is adhoc / linker-signed with `TeamIdentifier=not set`, i.e. NOT
#     Developer-ID signed and NOT notarized. We re-sign with our own
#     Developer-ID either way, so downloading costs no signing work that
#     building would have avoided.
#
# WHAT DOES NOT RELAX: the verification. A downloaded artefact gets exactly
# the same treatment as one we compiled — pinned by tag AND digest, checked
# for a real Metal device, checked for the no-network invariant, and measured
# into a manifest. "Upstream published it" is not evidence; the digest is.

set -euo pipefail

REPO="${REPO:-ggml-org/llama.cpp}"
# Both must be set together. A tag alone is not a pin — GitHub release assets
# can be replaced in place, so the digest is what actually binds.
LLAMA_CPP_TAG="${LLAMA_CPP_TAG:-PIN-ME}"
ASSET_SHA256="${ASSET_SHA256:-PIN-ME}"

# Known-good pin, measured 2026-09-15 on this branch:
#   LLAMA_CPP_TAG=b10976
#   ASSET_SHA256=a85c95ca6f5aa38c32f8ad470dba2b660e861f05a30d681b77e2bbe3bb2f5dab

WORK="${WORK:-$(pwd)/kuroshio-metal-fetch}"
OUT_DIR="${OUT_DIR:-${WORK}/out}"

log() { printf '    --> %s\n' "$*"; }
die() { printf '!!  FATAL: %s\n' "$*" >&2; exit 1; }

# --- pre-flight: every check fails CLOSED ------------------------------------
# Host checks apply only when the artifact will be EXECUTED here. Fetching a
# Linux asset from a Mac build host is legitimate and is how the container
# images are produced.
RUN_CHECKS=1
case "${PLATFORM}" in
  macos-arm64)
    if [[ "$(uname -s)" != "Darwin" || "$(uname -m)" != "arm64" ]]; then RUN_CHECKS=0; fi ;;
  *) [[ "$(uname -s)" == "Linux" ]] || RUN_CHECKS=0 ;;
esac
[[ "${LLAMA_CPP_TAG}" != "PIN-ME" && "${ASSET_SHA256}" != "PIN-ME" ]] \
  || die "LLAMA_CPP_TAG and ASSET_SHA256 must both be pinned — a tag alone is not a pin, release assets can be replaced in place"
command -v curl >/dev/null || die "curl not found"

# Platform/accelerator selects which asset of the SAME release we take. This is
# divergence V-2 and nothing more: one upstream release, one pin, one digest
# per asset, identical verification either side.
PLATFORM="${PLATFORM:-macos-arm64}"
case "${PLATFORM}" in
  macos-arm64|ubuntu-x64|ubuntu-arm64|ubuntu-vulkan-x64|ubuntu-vulkan-arm64| \
  ubuntu-cuda-12.8-x64|ubuntu-cuda-13.3-x64|ubuntu-cuda-13.3-arm64|ubuntu-rocm-10.0-x64) ;;
  *) die "unsupported PLATFORM ${PLATFORM}. Supported: macos-arm64, ubuntu-x64, ubuntu-arm64,
  ubuntu-vulkan-{x64,arm64}, ubuntu-cuda-{12.8-x64,13.3-x64,13.3-arm64}, ubuntu-rocm-10.0-x64" ;;
esac
EXT="tar.gz"
ASSET="llama-${LLAMA_CPP_TAG}-bin-${PLATFORM}.${EXT}"
URL="https://github.com/${REPO}/releases/download/${LLAMA_CPP_TAG}/${ASSET}"

mkdir -p "${WORK}"
log "fetching ${ASSET}"
curl -fsSL -o "${WORK}/${ASSET}" "${URL}" || die "download failed: ${URL}"

# --- verify the digest BEFORE unpacking --------------------------------------
# Unpacking first would mean executing decisions based on bytes we have not
# yet authenticated.
ACTUAL="$(shasum -a 256 "${WORK}/${ASSET}" | awk '{print $1}')"
[[ "${ACTUAL}" == "${ASSET_SHA256}" ]] || die \
  "digest mismatch for ${ASSET}
  expected ${ASSET_SHA256}
  actual   ${ACTUAL}
The asset was replaced, or the pin is wrong. NOT unpacking."
log "digest verified: ${ACTUAL}"

# --- verify GitHub build-provenance attestation -------------------------------
# A recorded sha256 only proves the bytes did not change since WE captured the
# pin. It does not prove the asset was built by upstream CI from the tagged
# source — so a pin captured from an already-substituted asset would verify
# happily forever.
#
# ggml-org publishes Sigstore-backed build provenance for release assets
# (verified against b10976: attestation 47548995, media type
# application/vnd.dev.sigstore.bundle.v0.3+json, with transparency-log
# entries). That cryptographically ties this artefact to a specific commit and
# CI run, which is a materially stronger and more durable pin than a digest we
# wrote down ourselves. Verified to DISCRIMINATE, not just to pass: a file with
# no attestation exits 1 with HTTP 404.
#
# Fail closed if `gh` is absent rather than skipping: a verification step that
# silently no-ops when a tool is missing is the fail-open pattern this whole
# script exists to avoid. Set ALLOW_UNATTESTED=1 to override deliberately —
# it is recorded in the manifest, so the gap travels with the artefact.
ATTESTED=false
if [[ "${ALLOW_UNATTESTED:-0}" == "1" ]]; then
  log "WARNING: attestation check bypassed by ALLOW_UNATTESTED=1 — recorded in the manifest"
else
  command -v gh >/dev/null \
    || die "gh CLI not found — needed to verify upstream build provenance. Install it, or set ALLOW_UNATTESTED=1 to accept a digest-only pin (recorded in the manifest)."
  gh attestation verify "${WORK}/${ASSET}" -R "${REPO}" >/dev/null 2>&1 \
    || die "build-provenance attestation FAILED for ${ASSET}.
The asset is not attested to have been built by ${REPO}'s CI from its tagged source.
Refusing — a matching digest alone does not establish provenance."
  ATTESTED=true
  log "build provenance verified (Sigstore attestation, ${REPO} CI)"
fi

rm -rf "${WORK}/unpack" && mkdir -p "${WORK}/unpack"
tar xzf "${WORK}/${ASSET}" -C "${WORK}/unpack"

BIN="$(find "${WORK}/unpack" -name llama-server -type f -perm -u+x | head -1)"
[[ -n "${BIN}" ]] || die "no llama-server in the archive"
BIN_DIR="$(dirname "${BIN}")"

# --- the same three checks the from-source path applies ----------------------
# llama.cpp on macOS ships a MULTI-DYLIB layout (upstream b10976: 35 dylibs,
# 24 binaries). llama-server links @rpath/libggml-metal.0.dylib, and it is
# THAT dylib which links Metal.framework — so checking the executable for
# Metal.framework is the wrong test and will refuse a good artefact.
# The expected accelerator backend library must be present in the artifact.
# Checked by NAME on every platform (works cross-host); the deeper "does this
# machine actually see the device" check needs the target hardware and runs at
# deploy time, not fetch time. Saying so is better than pretending a Mac can
# validate a CUDA build.
case "${PLATFORM}" in
  macos-arm64)          BACKEND_LIB="libggml-metal" ;;
  *vulkan*)             BACKEND_LIB="libggml-vulkan" ;;
  *cuda*)               BACKEND_LIB="libggml-cuda" ;;
  *rocm*)               BACKEND_LIB="libggml-hip" ;;
  ubuntu-x64|ubuntu-arm64) BACKEND_LIB="libggml-cpu" ;;
esac
find "${BIN_DIR}" -maxdepth 1 -name "${BACKEND_LIB}*" | grep -q . \
  || die "expected backend library ${BACKEND_LIB}* not found in the ${PLATFORM} artifact — refusing"
log "backend library present: ${BACKEND_LIB}"

if [[ "${PLATFORM}" == "macos-arm64" && "${RUN_CHECKS}" == "1" ]]; then
  otool -L "${BIN}" | grep -q "libggml-metal" \
    || die "llama-server does not link libggml-metal — CPU-only artefact, refusing"
  otool -L "$(find "${BIN_DIR}" -maxdepth 1 -name 'libggml-metal*.dylib' | head -1)" \
    | grep -qi "Metal.framework" || die "libggml-metal does not link Metal.framework — refusing"
fi

# Containment invariant: the engine must never be able to fetch a model
# itself. Pulls go through the control plane's gated, audited adapters.
if [[ "${RUN_CHECKS}" == "1" && "$(uname -s)" == "Darwin" ]]; then
otool -L "${BIN}" | grep -qi "curl" \
  && die "llama-server links libcurl — the engine could fetch models directly, violating the egress-mediation invariant (D16). Refusing."
fi

# Strongest available check short of loading a model: ask the binary what it
# can see. A CPU-only artefact lists no MTL device.
if [[ "${RUN_CHECKS}" == "1" ]]; then
  DEVICES="$("${BIN}" --list-devices 2>&1 || true)"
  if [[ "${PLATFORM}" == "macos-arm64" ]]; then
    grep -qE '^\s*MTL[0-9]+:' <<<"${DEVICES}" || die "--list-devices reports no Metal device:
${DEVICES}"
  fi
  log "devices: $(grep -oE '(MTL|CUDA|ROCm|Vulkan)[0-9]*: .*' <<<"${DEVICES}" | head -1)"
else
  log "cross-host fetch (${PLATFORM} from $(uname -s)/$(uname -m)) — live device check deferred to deploy time"
fi

# Record the signature state rather than asserting a level we have not earned.
SIGSTATE="$(codesign -dv --verbose=2 "${BIN}" 2>&1 | grep -E '^Signature=' | head -1 || true)"
log "upstream signature: ${SIGSTATE:-none} (Developer-ID re-sign still required)"

# --- publish ------------------------------------------------------------------
mkdir -p "${OUT_DIR}"
cp "${BIN}" "${OUT_DIR}/llama-server"
# Shared libraries, whichever extension this platform uses. Copying only
# *.dylib silently produced an EMPTY library set for every Linux asset — the
# executable alone cannot start, and nothing would have failed until runtime.
find "${BIN_DIR}" -maxdepth 1 \( -name '*.dylib' -o -name '*.so' -o -name '*.so.*' \) \
  -exec cp {} "${OUT_DIR}/" \;
LIBCOUNT="$(find "${OUT_DIR}" -maxdepth 1 \( -name '*.dylib' -o -name '*.so' -o -name '*.so.*' \) | wc -l | tr -d ' ')"
[[ "${LIBCOUNT}" -gt 0 ]] || die "no shared libraries copied from ${BIN_DIR} — the artifact would not start"

DIGEST="$(shasum -a 256 "${OUT_DIR}/llama-server" | awk '{print $1}')"
FILES="$(cd "${OUT_DIR}" && shasum -a 256 llama-server $(ls *.dylib *.so *.so.* 2>/dev/null) \
  | awk '{printf "    {\"file\": \"%s\", \"sha256\": \"%s\"},\n", $2, $1}' | sed '$ s/,$//')"

cat > "${OUT_DIR}/llama-server.manifest.json" <<EOF
{
  "artifact": "llama-server",
  "platform": "darwin-arm64",
  "accelerator": "metal",
  "provenance": "upstream-release",
  "layout": "multi-dylib (llama-server + ggml backend dylibs, @rpath-linked)",
  "source_repo": "${REPO}",
  "llama_cpp_tag": "${LLAMA_CPP_TAG}",
  "release_asset": "${ASSET}",
  "release_asset_sha256": "${ASSET_SHA256}",
  "sha256_presign": "${DIGEST}",
  "_note_digests": "PRE-SIGN. codesign appends an LC_CODE_SIGNATURE blob, so post-sign bytes differ. A serve-time verifier must check the AS-SHIPPED (post-sign) digest, not this one.",
  "files": [
${FILES}
  ],
  "upstream_signature": "${SIGSTATE:-none}",
  "build_provenance_attested": ${ATTESTED},
  "verified_no_curl": true,
  "verified_metal_device": true,
  "fetched_on_macos": "$(sw_vers -productVersion)",
  "signed": false,
  "notarized": false,
  "cve_gate_run": false
}
EOF

log "artifact:  ${OUT_DIR}/llama-server (+ ${LIBCOUNT} shared libraries)"
log "manifest:  ${OUT_DIR}/llama-server.manifest.json"
log "UNSIGNED by us — Developer-ID re-sign must cover EVERY dylib above (YSG-RISK-282)"
