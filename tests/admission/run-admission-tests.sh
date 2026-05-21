#!/usr/bin/env bash
# YSG-RISK-008 Admission Control Test Runner
# Last updated: 2026-05-17T00:00:00+01:00
#
# Tests Kyverno ClusterPolicy enforcement for the Yashigani admission control
# baseline. Applies compliant + non-compliant pod fixtures against a live cluster
# with Kyverno installed and the Yashigani ClusterPolicies active, then asserts
# the expected admission outcomes.
#
# PREREQUISITES:
#   1. kubectl configured and pointing at the target cluster context.
#   2. Kyverno installed:
#        helm repo add kyverno https://kyverno.github.io/kyverno/
#        helm repo update
#        helm install kyverno kyverno/kyverno -n kyverno --create-namespace
#        kubectl wait --for=condition=ready pod -l app.kubernetes.io/instance=kyverno \
#          -n kyverno --timeout=120s
#   3. Yashigani ClusterPolicies installed via Helm with admissionPolicies.enabled=true:
#        helm install yashigani helm/yashigani -n <NAMESPACE> --create-namespace \
#          --set admissionPolicies.enabled=true
#      ClusterPolicies scope to the Helm release namespace by default.
#      See tests/admission/README.md for full procedure.
#
# USAGE:
#   bash tests/admission/run-admission-tests.sh [NAMESPACE]
#
#   NAMESPACE defaults to "yashigani". Pass the Helm release namespace used above.
#   Example for CI test namespace:
#     bash tests/admission/run-admission-tests.sh yashigani-validate
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PASS=0
FAIL=0
NS="${1:-yashigani}"

_pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
_fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

echo "=== YSG-RISK-008 Admission Control Tests ==="
echo "Namespace: ${NS}"
echo "Cluster: $(kubectl config current-context 2>/dev/null || echo '<unknown>')"
echo ""

# Verify ClusterPolicies exist before running
POLICIES=$(kubectl get clusterpolicy --no-headers 2>/dev/null | grep -cE "require-run-as-non-root|require-no-privilege-escalation|require-seccomp-profile|require-drop-all-capabilities|restrict-root-user" || true)
if [[ "${POLICIES}" -lt 5 ]]; then
  echo "ERROR: Expected 5 Kyverno ClusterPolicies but found ${POLICIES}."
  echo "Install Kyverno and deploy Yashigani with --set admissionPolicies.enabled=true first."
  echo "See tests/admission/README.md for the full procedure."
  exit 1
fi
echo "ClusterPolicies present: ${POLICIES}/5"
echo ""

# Clean up any leftover test pods from previous runs
kubectl delete pod \
  yashigani-test-compliant \
  yashigani-test-noncompliant-root \
  yashigani-test-noncompliant-privesc \
  yashigani-test-noncompliant-no-seccomp \
  -n "${NS}" --ignore-not-found --wait=false 2>/dev/null || true
sleep 2

# Apply fixtures with namespace substitution.
# Fixture YAML files contain "namespace: yashigani" — substitute the target NS.
apply_with_ns() {
  local f="$1"
  kubectl apply -f - <<< "$(sed "s/namespace: yashigani$/namespace: ${NS}/" "${f}")"
}

echo "--- Test 1: Compliant pod (must be admitted) ---"
if apply_with_ns "${SCRIPT_DIR}/fixture-compliant.yaml" 2>&1; then
  _pass "Compliant pod admitted"
  kubectl delete pod yashigani-test-compliant -n "${NS}" --ignore-not-found 2>/dev/null || true
else
  _fail "Compliant pod was incorrectly rejected"
fi

echo ""
echo "--- Test 2: Non-compliant root user (must be rejected) ---"
output=$(apply_with_ns "${SCRIPT_DIR}/fixture-noncompliant-root.yaml" 2>&1 || true)
if echo "${output}" | grep -qiE "denied|violation|YSG-RISK-008|restrict-root-user|run-as-non-root"; then
  _pass "Root pod rejected by admission policy"
  kubectl delete pod yashigani-test-noncompliant-root -n "${NS}" --ignore-not-found 2>/dev/null || true
else
  _fail "Root pod was NOT rejected — policies may not be enforcing"
  echo "  kubectl output: ${output}"
fi

echo ""
echo "--- Test 3: Non-compliant privilege escalation (must be rejected) ---"
output=$(apply_with_ns "${SCRIPT_DIR}/fixture-noncompliant-privesc.yaml" 2>&1 || true)
if echo "${output}" | grep -qiE "denied|violation|YSG-RISK-008|privilege-escalation"; then
  _pass "PrivEsc pod rejected by admission policy"
  kubectl delete pod yashigani-test-noncompliant-privesc -n "${NS}" --ignore-not-found 2>/dev/null || true
else
  _fail "PrivEsc pod was NOT rejected — policies may not be enforcing"
  echo "  kubectl output: ${output}"
fi

echo ""
echo "--- Test 4: Non-compliant missing seccomp (must be rejected) ---"
output=$(apply_with_ns "${SCRIPT_DIR}/fixture-noncompliant-no-seccomp.yaml" 2>&1 || true)
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
