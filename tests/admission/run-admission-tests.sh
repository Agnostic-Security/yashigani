#!/usr/bin/env bash
# YSG-RISK-008 Admission Control Test Runner
# Last updated: 2026-05-02T00:00:00+01:00
#
# Applies compliant + non-compliant pod fixtures against the live cluster and
# verifies Kyverno policy enforcement. Requires:
#   - kubectl configured and pointing at the target cluster
#   - Kyverno installed (helm install kyverno ...)
#   - Kyverno policies applied (kubectl apply -f helm/yashigani/policies/admission/)
#   - yashigani namespace exists
#
# Usage: bash tests/admission/run-admission-tests.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PASS=0
FAIL=0
NS="yashigani"

_pass() { echo "  PASS: $1"; ((PASS++)); }
_fail() { echo "  FAIL: $1"; ((FAIL++)); }

echo "=== YSG-RISK-008 Admission Control Tests ==="
echo "Namespace: ${NS}"
echo "Cluster: $(kubectl config current-context 2>/dev/null || echo '<unknown>')"
echo ""

# Clean up any leftover test pods from previous runs
kubectl delete pod \
  yashigani-test-compliant \
  yashigani-test-noncompliant-root \
  yashigani-test-noncompliant-privesc \
  yashigani-test-noncompliant-no-seccomp \
  -n "${NS}" --ignore-not-found --wait=false 2>/dev/null || true
sleep 2

echo "--- Test 1: Compliant pod (must be admitted) ---"
if kubectl apply -f "${SCRIPT_DIR}/fixture-compliant.yaml" 2>&1; then
  _pass "Compliant pod admitted"
  kubectl delete pod yashigani-test-compliant -n "${NS}" --ignore-not-found 2>/dev/null || true
else
  _fail "Compliant pod was incorrectly rejected"
fi

echo ""
echo "--- Test 2: Non-compliant root user (must be rejected) ---"
output=$(kubectl apply -f "${SCRIPT_DIR}/fixture-noncompliant-root.yaml" 2>&1 || true)
if echo "${output}" | grep -qiE "denied|violation|YSG-RISK-008|restrict-root-user|run-as-non-root"; then
  _pass "Root pod rejected by admission policy"
  kubectl delete pod yashigani-test-noncompliant-root -n "${NS}" --ignore-not-found 2>/dev/null || true
else
  _fail "Root pod was NOT rejected — policies may not be enforcing"
  echo "  kubectl output: ${output}"
fi

echo ""
echo "--- Test 3: Non-compliant privilege escalation (must be rejected) ---"
output=$(kubectl apply -f "${SCRIPT_DIR}/fixture-noncompliant-privesc.yaml" 2>&1 || true)
if echo "${output}" | grep -qiE "denied|violation|YSG-RISK-008|privilege-escalation"; then
  _pass "PrivEsc pod rejected by admission policy"
  kubectl delete pod yashigani-test-noncompliant-privesc -n "${NS}" --ignore-not-found 2>/dev/null || true
else
  _fail "PrivEsc pod was NOT rejected — policies may not be enforcing"
  echo "  kubectl output: ${output}"
fi

echo ""
echo "--- Test 4: Non-compliant missing seccomp (must be rejected) ---"
output=$(kubectl apply -f "${SCRIPT_DIR}/fixture-noncompliant-no-seccomp.yaml" 2>&1 || true)
if echo "${output}" | grep -qiE "denied|violation|YSG-RISK-008|seccomp"; then
  _pass "No-seccomp pod rejected by admission policy"
  kubectl delete pod yashigani-test-noncompliant-no-seccomp -n "${NS}" --ignore-not-found 2>/dev/null || true
else
  _fail "No-seccomp pod was NOT rejected — policies may not be enforcing"
  echo "  kubectl output: ${output}"
fi

echo ""
echo "=== Results ==="
echo "  Passed: ${PASS}"
echo "  Failed: ${FAIL}"

if [[ "${FAIL}" -gt 0 ]]; then
  echo ""
  echo "GATE FAILED — ${FAIL} test(s) failed. See output above."
  exit 1
else
  echo ""
  echo "GATE PASSED — all admission tests passed."
  exit 0
fi
