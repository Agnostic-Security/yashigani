#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
#
# Fetch + verify the UPSTREAM prebuilt `llama-server` for macOS / Apple
# Silicon (Metal) — Yashigani 6.0. **This is the primary path** (Tiago
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
[[ "$(uname -s)" == "Darwin" ]] || die "macOS only"
[[ "$(uname -m)" == "arm64"  ]] || die "Apple Silicon (arm64) required; got $(uname -m)"
[[ "${LLAMA_CPP_TAG}" != "PIN-ME" && "${ASSET_SHA256}" != "PIN-ME" ]] \
  || die "LLAMA_CPP_TAG and ASSET_SHA256 must both be pinned — a tag alone is not a pin, release assets can be replaced in place"
command -v curl >/dev/null || die "curl not found"

ASSET="llama-${LLAMA_CPP_TAG}-bin-macos-arm64.tar.gz"
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
otool -L "${BIN}" | grep -q "libggml-metal" \
  || die "llama-server does not link libggml-metal — CPU-only artefact, refusing"
METAL_DYLIB="$(find "${BIN_DIR}" -maxdepth 1 -name 'libggml-metal*.dylib' | head -1)"
[[ -n "${METAL_DYLIB}" ]] || die "no libggml-metal dylib in the archive"
otool -L "${METAL_DYLIB}" | grep -qi "Metal.framework" \
  || die "libggml-metal does not link Metal.framework — refusing"

# Containment invariant: the engine must never be able to fetch a model
# itself. Pulls go through the control plane's gated, audited adapters.
otool -L "${BIN}" | grep -qi "curl" \
  && die "llama-server links libcurl — the engine could fetch models directly, violating the egress-mediation invariant (D16). Refusing."

# Strongest available check short of loading a model: ask the binary what it
# can see. A CPU-only artefact lists no MTL device.
DEVICES="$("${BIN}" --list-devices 2>&1 || true)"
grep -qE '^\s*MTL[0-9]+:' <<<"${DEVICES}" \
  || die "--list-devices reports no Metal device. Output:
${DEVICES}"
log "Metal device: $(grep -oE 'MTL[0-9]+: .*' <<<"${DEVICES}" | head -1)"

# Record the signature state rather than asserting a level we have not earned.
SIGSTATE="$(codesign -dv --verbose=2 "${BIN}" 2>&1 | grep -E '^Signature=' | head -1 || true)"
log "upstream signature: ${SIGSTATE:-none} (Developer-ID re-sign still required)"

# --- publish ------------------------------------------------------------------
mkdir -p "${OUT_DIR}"
cp "${BIN}" "${OUT_DIR}/llama-server"
find "${BIN_DIR}" -maxdepth 1 -name '*.dylib' -exec cp {} "${OUT_DIR}/" \;

DIGEST="$(shasum -a 256 "${OUT_DIR}/llama-server" | awk '{print $1}')"
FILES="$(cd "${OUT_DIR}" && shasum -a 256 llama-server *.dylib \
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

log "artifact:  ${OUT_DIR}/llama-server (+ $(ls "${OUT_DIR}"/*.dylib | wc -l | tr -d ' ') dylibs)"
log "manifest:  ${OUT_DIR}/llama-server.manifest.json"
log "UNSIGNED by us — Developer-ID re-sign must cover EVERY dylib above (YSG-RISK-282)"
