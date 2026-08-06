#!/usr/bin/env bats
# tests/install/test_pki_san_drift_runtime_manifest.bats
#
# FIND-IRIS-SAN-DRIFT (batch-fix 2026-08-04)
#
# _pki_detect_uri_san_drift() used to compare live leaf certs against the
# CANONICAL git-tracked template (docker/service_identities.yaml, hardcoded
# default trust domain "yashigani.internal") instead of the per-instance
# RUNTIME manifest install.sh itself maintains and rewrites
# (docker/var/runtime/service_identities.yaml, via
# _apply_trust_domain_to_runtime_manifest for any non-default trust domain /
# multi-instance deployment). Result: false-positive "URI SAN mismatch" on
# EVERY service on EVERY non-default-domain deployment, on every --upgrade,
# forcing an unnecessary full leaf rotation + 7-service restart every time.
#
# This test extracts the REAL function from install.sh (brace-count awk,
# same technique as test_backend_firewall.bats) and proves, with REAL
# self-signed certs + openssl (no live stack needed):
#   1. Pre-fix behaviour (checked out from d39dcf6e) reproduces the false
#      positive when certs are minted for a rewritten (non-default) trust
#      domain but the canonical template still says the default.
#   2. Fixed behaviour returns 0 (no spurious drift/rotation) for the exact
#      same certs, by comparing against the runtime manifest instead.
#   3. Genuine drift (a real mismatch) is still caught by the fixed function
#      — this is not a fix that also disables the detector.
#
# Run: bats tests/install/test_pki_san_drift_runtime_manifest.bats

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
INSTALL_SH="${REPO_ROOT}/install.sh"
MOCK_ROOT="${REPO_ROOT}/tests/install/.mock_san_drift"

setup() {
  rm -rf "${MOCK_ROOT}"
  mkdir -p "${MOCK_ROOT}/docker/var/runtime" "${MOCK_ROOT}/docker/secrets" "${MOCK_ROOT}/docker/secrets-caddy"

  # Canonical manifest: hardcoded default trust domain (mirrors the real
  # docker/service_identities.yaml shape for the two services this test uses).
  cat > "${MOCK_ROOT}/docker/service_identities.yaml" <<'EOF'
services:
  - name: caddy
    spiffe_id: spiffe://yashigani.internal/caddy
  - name: gateway
    spiffe_id: spiffe://yashigani.internal/gateway
EOF

  # Runtime manifest: rewritten trust domain, as
  # _apply_trust_domain_to_runtime_manifest would produce for a non-default
  # instance (e.g. PROJECT=testproj).
  cat > "${MOCK_ROOT}/docker/var/runtime/service_identities.yaml" <<'EOF'
services:
  - name: caddy
    spiffe_id: spiffe://testproj.yashigani.internal/caddy
  - name: gateway
    spiffe_id: spiffe://testproj.yashigani.internal/gateway
EOF

  # Leaf certs minted for the RUNTIME (rewritten) domain — this is what a
  # real PKI issuer run against a non-default trust domain actually produces.
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout /dev/null -out "${MOCK_ROOT}/docker/secrets-caddy/caddy_client.crt" \
    -days 1 -subj "/CN=caddy" \
    -addext "subjectAltName=URI:spiffe://testproj.yashigani.internal/caddy" 2>/dev/null
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout /dev/null -out "${MOCK_ROOT}/docker/secrets/gateway_client.crt" \
    -days 1 -subj "/CN=gateway" \
    -addext "subjectAltName=URI:spiffe://testproj.yashigani.internal/gateway" 2>/dev/null
}

teardown() {
  rm -rf "${MOCK_ROOT}"
}

_extract_fn_from() {
  local file="$1" fn_name="$2"
  awk -v fn="${fn_name}() {" '
    $0 == fn { f=1 }
    f {
      print
      d += gsub(/{/, "{")
      d -= gsub(/}/, "}")
      if (f && d <= 0) { exit }
    }
  ' "${file}"
}

_run_drift_fn() {
  local fn_src="$1"
  bash -c "
    log_info() { echo \"INFO: \$1\"; }
    log_warn() { echo \"WARN: \$1\"; }
    WORK_DIR='${MOCK_ROOT}'
    ${fn_src}
    _pki_detect_uri_san_drift
  "
}

# ---------------------------------------------------------------------------
# G-SYNTAX
# ---------------------------------------------------------------------------

@test "G-SYNTAX: install.sh passes bash -n" {
  run bash -n "${INSTALL_SH}"
  [ "$status" -eq 0 ]
}

@test "G-SYNTAX: _pki_detect_uri_san_drift reads the runtime manifest path" {
  local count
  count="$(_extract_fn_from "${INSTALL_SH}" "_pki_detect_uri_san_drift" \
      | grep -c 'docker/var/runtime/service_identities.yaml' || true)"
  [ "${count:-0}" -ge 1 ]
}

# ---------------------------------------------------------------------------
# G-REPRO / G-FIX
# ---------------------------------------------------------------------------

@test "G-REPRO: pre-fix function (d39dcf6e) false-positives drift for a rewritten trust domain" {
  git -C "${REPO_ROOT}" show d39dcf6e:install.sh > "${MOCK_ROOT}/baseline_install.sh"
  local fn_src
  fn_src="$(_extract_fn_from "${MOCK_ROOT}/baseline_install.sh" "_pki_detect_uri_san_drift")"
  run _run_drift_fn "$fn_src"
  # Pre-fix: compares against the canonical (default-domain) manifest ->
  # mismatch on both services -> non-zero (drift detected, forces rotation).
  [ "$status" -ne 0 ]
  [[ "$output" == *"URI SAN mismatch"* ]]
}

@test "G-FIX: current function returns 0 (no spurious drift) for the same certs, comparing against the runtime manifest" {
  local fn_src
  fn_src="$(_extract_fn_from "${INSTALL_SH}" "_pki_detect_uri_san_drift")"
  run _run_drift_fn "$fn_src"
  [ "$status" -eq 0 ]
  [[ "$output" == *"caddy: URI SAN OK"* ]]
  [[ "$output" == *"gateway: URI SAN OK"* ]]
}

@test "G-FIX: genuine drift is still caught (fix does not disable the detector)" {
  # Corrupt the runtime manifest's gateway spiffe_id so it disagrees with the
  # actual leaf cert minted above -> must still be flagged as drift.
  sed -i.bak 's#spiffe://testproj.yashigani.internal/gateway#spiffe://testproj.yashigani.internal/gateway-ROTATED#' \
    "${MOCK_ROOT}/docker/var/runtime/service_identities.yaml"
  local fn_src
  fn_src="$(_extract_fn_from "${INSTALL_SH}" "_pki_detect_uri_san_drift")"
  run _run_drift_fn "$fn_src"
  [ "$status" -ne 0 ]
  [[ "$output" == *"gateway: URI SAN mismatch"* ]]
  # caddy is untouched and must still read OK — proves the mismatch is
  # real/targeted, not a blanket failure.
  [[ "$output" == *"caddy: URI SAN OK"* ]]
}

@test "G-FIX: falls back to canonical manifest with a loud warning when the runtime manifest is absent" {
  rm -f "${MOCK_ROOT}/docker/var/runtime/service_identities.yaml"
  local fn_src
  fn_src="$(_extract_fn_from "${INSTALL_SH}" "_pki_detect_uri_san_drift")"
  run _run_drift_fn "$fn_src"
  [[ "$output" == *"runtime manifest missing"* ]]
}
