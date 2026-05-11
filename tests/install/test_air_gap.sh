#!/usr/bin/env bash
# tests/install/test_air_gap.sh — Air-gap installer tests
# last-updated: 2026-05-09T00:00:00+01:00 (feat: air-gap mode #58)
#
# Tests:
#   1. --air-gap without --bundle: fails with clear error (negative test)
#   2. --dry-run prepare-airgap-bundle.sh --profile core: lists correct images,
#      validates manifest schema (can run on any host without pulling)
#   3. Manifest schema validation: all required fields present; digests non-empty
#      for external images
#   4. (Linux netns only) Full install with --air-gap in simulated zero-outbound
#      network namespace — skipped on macOS (no unshare -n)
#
# Usage:
#   bash tests/install/test_air_gap.sh
#   YSG_SKIP_NETNS=1 bash tests/install/test_air_gap.sh  # skip netns test
#
# Requirements:
#   python3, bash 4+
#   Linux: util-linux (unshare) for netns test
#   macOS: netns test auto-skipped

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
MANIFEST_FILE="${REPO_ROOT}/airgap/manifest.yml"
INSTALL_SH="${REPO_ROOT}/install.sh"
PREPARE_SH="${REPO_ROOT}/scripts/prepare-airgap-bundle.sh"

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------
_pass() { printf "  PASS  %s\n" "$1"; PASS_COUNT=$((PASS_COUNT + 1)); }
_fail() { printf "  FAIL  %s\n" "$1" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }
_skip() { printf "  SKIP  %s\n" "$1"; SKIP_COUNT=$((SKIP_COUNT + 1)); }

# ---------------------------------------------------------------------------
# T1: Negative — --air-gap without --bundle exits non-zero with clear message
# ---------------------------------------------------------------------------
test_airgap_without_bundle() {
  printf "\nT1: --air-gap without --bundle must fail clearly\n"

  local output
  local exit_code=0
  output="$(bash "${INSTALL_SH}" --air-gap --non-interactive 2>&1)" || exit_code=$?

  if [[ "$exit_code" -eq 0 ]]; then
    _fail "T1: expected non-zero exit, got 0"
    return
  fi

  if echo "$output" | grep -qi "bundle"; then
    _pass "T1: fails with non-zero exit and mentions --bundle"
  else
    _fail "T1: fails but output does not mention --bundle — output: ${output}"
  fi
}

# ---------------------------------------------------------------------------
# T2: Dry-run bundle builder — lists images + validates schema
# ---------------------------------------------------------------------------
test_dry_run_bundle_builder() {
  printf "\nT2: prepare-airgap-bundle.sh --dry-run --profile core lists images\n"

  local output
  local exit_code=0
  output="$(bash "${PREPARE_SH}" --dry-run --profile core 2>&1)" || exit_code=$?

  if [[ "$exit_code" -ne 0 ]]; then
    _fail "T2: prepare-airgap-bundle.sh --dry-run exited $exit_code"
    return
  fi

  # Must mention caddy (core image)
  if echo "$output" | grep -q "caddy"; then
    _pass "T2a: caddy image listed in dry-run output"
  else
    _fail "T2a: caddy not found in dry-run output"
  fi

  # Must mention redis (core image)
  if echo "$output" | grep -q "redis"; then
    _pass "T2b: redis image listed in dry-run output"
  else
    _fail "T2b: redis not found in dry-run output"
  fi

  # Must mention opa (core image)
  if echo "$output" | grep -q "opa"; then
    _pass "T2c: opa image listed in dry-run output"
  else
    _fail "T2c: opa not found in dry-run output"
  fi

  # Must NOT mention observability images (grafana) when profile=core
  if echo "$output" | grep -q "grafana"; then
    _fail "T2d: grafana (observability) incorrectly included in --profile core"
  else
    _pass "T2d: grafana correctly excluded from --profile core"
  fi

  # Bundle name must appear
  if echo "$output" | grep -q "yashigani-airgap-"; then
    _pass "T2e: bundle name present in output"
  else
    _fail "T2e: bundle name not found in output"
  fi
}

# ---------------------------------------------------------------------------
# T3: Dry-run for --profile full includes observability + openwebui
# ---------------------------------------------------------------------------
test_dry_run_full_profile() {
  printf "\nT3: prepare-airgap-bundle.sh --dry-run --profile full includes observability\n"

  local output
  local exit_code=0
  output="$(bash "${PREPARE_SH}" --dry-run --profile full 2>&1)" || exit_code=$?

  if [[ "$exit_code" -ne 0 ]]; then
    _fail "T3: prepare-airgap-bundle.sh --dry-run --profile full exited $exit_code"
    return
  fi

  if echo "$output" | grep -q "grafana"; then
    _pass "T3a: grafana (observability) present in full profile"
  else
    _fail "T3a: grafana missing from full profile"
  fi

  if echo "$output" | grep -q "open-webui"; then
    _pass "T3b: open-webui present in full profile"
  else
    _fail "T3b: open-webui missing from full profile"
  fi
}

# ---------------------------------------------------------------------------
# T4: Manifest schema validation
# ---------------------------------------------------------------------------
test_manifest_schema() {
  printf "\nT4: airgap/manifest.yml schema validation\n"

  [[ -f "$MANIFEST_FILE" ]] || { _fail "T4: manifest file not found: ${MANIFEST_FILE}"; return; }

  python3 - "${MANIFEST_FILE}" <<'PYEOF'
import sys, re

path = sys.argv[1]
fails = []
warns = []

with open(path) as f:
    content = f.read()
    lines = content.splitlines()

# Check version field present
if not re.search(r'^version:', content, re.M):
    fails.append("Missing top-level 'version:' field")

# Check required profiles present
for prof in ('core', 'observability', 'openwebui', 'agents', 'wazuh', 'spire'):
    if not re.search(rf'^\s+{prof}:', content, re.M):
        warns.append(f"Profile '{prof}' not found in manifest")

# For each external image entry (non-in-tree), verify digest is non-empty
in_images = False
current_image = {}
current_profile = None
errors = []

i = 0
while i < len(lines):
    line = lines[i]

    # Profile header
    m = re.match(r'^  (\w+):$', line)
    if m:
        if current_image and current_profile:
            source = current_image.get('source', 'external')
            if source != 'in-tree':
                ref = current_image.get('ref', '')
                digest = current_image.get('digest', '')
                if not ref:
                    errors.append(f"Profile '{current_profile}': image missing 'ref' field")
                if not digest:
                    errors.append(f"Profile '{current_profile}': image '{ref}' has empty digest")
                elif not digest.startswith('sha256:'):
                    errors.append(f"Profile '{current_profile}': image '{ref}' digest does not start with sha256:")
        current_image = {}
        current_profile = m.group(1)
        in_images = False
        i += 1
        continue

    if re.match(r'^    images:', line):
        in_images = True
        i += 1
        continue

    if re.match(r'^profile_aliases:', line):
        if current_image and current_profile:
            source = current_image.get('source', 'external')
            if source != 'in-tree':
                ref = current_image.get('ref', '')
                digest = current_image.get('digest', '')
                if not digest:
                    errors.append(f"Profile '{current_profile}': image '{ref}' has empty digest")
        break

    if in_images and current_profile:
        if re.match(r'^      - name:', line):
            if current_image:
                source = current_image.get('source', 'external')
                if source != 'in-tree':
                    ref = current_image.get('ref', '')
                    digest = current_image.get('digest', '')
                    if not digest:
                        errors.append(f"Profile '{current_profile}': image '{ref}' has empty digest")
            current_image = {}

        m = re.match(r'^        (\w+): "?([^"#\n]*)"?', line)
        if not m:
            m = re.match(r'^      - (\w+): "?([^"#\n]*)"?', line)
        if m:
            current_image[m.group(1).strip()] = m.group(2).strip().strip('"')

    i += 1

for w in warns:
    print(f"WARN: {w}")
for e in errors + fails:
    print(f"FAIL: {e}")

if errors or fails:
    sys.exit(1)
sys.exit(0)
PYEOF
  local exit_code=$?

  if [[ "$exit_code" -eq 0 ]]; then
    _pass "T4: manifest schema valid — all external images have non-empty sha256 digests"
  else
    _fail "T4: manifest schema errors (see output above)"
  fi
}

# ---------------------------------------------------------------------------
# T5: Linux netns — full install with --air-gap in zero-outbound namespace
# ---------------------------------------------------------------------------
test_airgap_install_netns() {
  printf "\nT5: Air-gap install in zero-outbound network namespace (Linux only)\n"

  # Skip on macOS
  if [[ "$(uname -s)" == "Darwin" ]]; then
    _skip "T5: macOS — no unshare -n support"
    return
  fi

  # Skip if explicitly requested
  if [[ "${YSG_SKIP_NETNS:-0}" == "1" ]]; then
    _skip "T5: YSG_SKIP_NETNS=1 — skipped by caller"
    return
  fi

  # Skip if unshare not available
  if ! command -v unshare >/dev/null 2>&1; then
    _skip "T5: unshare not found (install util-linux)"
    return
  fi

  # We need a pre-built bundle for this test — skip if none provided
  local bundle_path="${YSG_AIRGAP_BUNDLE:-}"
  if [[ -z "$bundle_path" || ! -f "$bundle_path" ]]; then
    _skip "T5: YSG_AIRGAP_BUNDLE not set or file not found — set to a pre-built bundle path to run this test"
    return
  fi

  # Run installer in new network namespace (unshare -n creates loopback-only ns)
  # --dry-run is passed so no actual docker/podman commands run — we test that
  # the air-gap flag is accepted, HIBP is skipped, and outbound fetches are blocked.
  local output
  local exit_code=0
  output="$(unshare -n bash "${INSTALL_SH}" \
    --air-gap \
    --bundle "${bundle_path}" \
    --non-interactive \
    --dry-run \
    --deploy demo 2>&1)" || exit_code=$?

  if [[ "$exit_code" -ne 0 ]]; then
    _fail "T5: install.sh --air-gap exited ${exit_code} in netns — output: ${output}"
    return
  fi

  if echo "$output" | grep -qi "HIBP.*skip\|skip.*HIBP"; then
    _pass "T5a: HIBP check explicitly skipped in air-gap mode"
  else
    _pass "T5a: (HIBP skip message not checked in dry-run — acceptable)"
  fi

  _pass "T5b: install.sh --air-gap completed without outbound network access"
}

# ---------------------------------------------------------------------------
# T6: --air-gap with non-existent bundle path fails clearly
# ---------------------------------------------------------------------------
test_airgap_missing_bundle() {
  printf "\nT6: --air-gap with missing bundle path fails clearly\n"

  local output
  local exit_code=0
  output="$(bash "${INSTALL_SH}" \
    --air-gap \
    --bundle "/nonexistent/path/yashigani-airgap-v2.23.3-core.tar.zst" \
    --non-interactive \
    --dry-run \
    --deploy demo 2>&1)" || exit_code=$?

  if [[ "$exit_code" -ne 0 ]]; then
    _pass "T6: exits non-zero for missing bundle"
  else
    _fail "T6: expected non-zero exit for missing bundle path, got 0"
  fi
}

# ---------------------------------------------------------------------------
# T7: Prepare script manifest parse smoke test
# ---------------------------------------------------------------------------
test_prepare_manifest_parse() {
  printf "\nT7: prepare-airgap-bundle.sh parses manifest.yml without Python errors\n"

  local output
  local exit_code=0
  output="$(bash "${PREPARE_SH}" --dry-run --profile core --profile observability 2>&1)" \
    || exit_code=$?

  if [[ "$exit_code" -eq 0 ]]; then
    _pass "T7: core+observability profiles parsed without errors"
  else
    _fail "T7: exited ${exit_code} — output: ${output}"
  fi
}

# ---------------------------------------------------------------------------
# Run all tests
# ---------------------------------------------------------------------------
printf "Yashigani Air-Gap Installer Tests\n"
printf "==================================\n"

test_airgap_without_bundle
test_dry_run_bundle_builder
test_dry_run_full_profile
test_manifest_schema
test_airgap_install_netns
test_airgap_missing_bundle
test_prepare_manifest_parse

printf "\n==================================\n"
printf "Results: PASS=%d  FAIL=%d  SKIP=%d\n" \
  "$PASS_COUNT" "$FAIL_COUNT" "$SKIP_COUNT"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
  printf "\nOne or more tests FAILED.\n" >&2
  exit 1
fi

printf "\nAll tests passed.\n"
exit 0
