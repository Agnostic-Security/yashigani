# YSG-RISK-008 Admission Control Tests
<!-- Last updated: 2026-05-17T00:00:00+01:00 — v2.23.4 -->

Tests for the five Kyverno ClusterPolicies rendered by `helm/yashigani/templates/admission-policies.yaml` when `admissionPolicies.enabled=true`.

## Policies tested

| Policy | What it enforces |
|---|---|
| `<release>-require-run-as-non-root` | Pod must set `runAsNonRoot: true` or a non-zero `runAsUser` |
| `<release>-require-no-privilege-escalation` | Every container must explicitly set `allowPrivilegeEscalation: false` |
| `<release>-require-seccomp-profile` | Pod must set `seccompProfile.type: RuntimeDefault` or `Localhost` |
| `<release>-require-drop-all-capabilities` | Every container must set `capabilities.drop: [ALL]` |
| `<release>-restrict-root-user` | No `runAsUser: 0` at pod or container level |

## Prerequisites

1. A running K8s cluster with kubectl configured (Docker Desktop, kind, EKS, etc.).
2. Kyverno installed:
   ```
   helm repo add kyverno https://kyverno.github.io/kyverno/
   helm repo update
   helm install kyverno kyverno/kyverno -n kyverno --create-namespace
   kubectl wait --for=condition=ready pod -l app.kubernetes.io/instance=kyverno \
     -n kyverno --timeout=120s
   ```
3. Yashigani chart installed with `admissionPolicies.enabled=true`:
   ```
   helm install yashigani helm/yashigani -n yashigani --create-namespace \
     --set admissionPolicies.enabled=true \
     --set admissionPolicies.validationFailureAction=Enforce
   ```
   The ClusterPolicies scope to the Helm release namespace (`yashigani` by default).

## Running the tests

```bash
# Default namespace 'yashigani'
bash tests/admission/run-admission-tests.sh

# Override namespace (e.g. for CI test isolation)
bash tests/admission/run-admission-tests.sh yashigani-validate
```

Exit 0 = GATE PASSED. Exit 1 = GATE FAILED.

## What the tests verify

- **Test 1 (positive):** A fully compliant pod is admitted (not over-blocked).
- **Test 2 (negative):** A pod with `runAsUser: 0` is rejected.
- **Test 3 (negative):** A pod without explicit `allowPrivilegeEscalation: false` is rejected.
- **Test 4 (negative):** A pod without `seccompProfile` is rejected.

## CI gate

The test script is called by `.github/workflows/` during the K8s gate. A kind cluster is used with Kyverno pre-installed. The gate requires Exit 0 to pass.

## Known behaviour

- `allowPrivilegeEscalation` must be explicitly set to `false`. Omitting the field
  (which K8s defaults to `true`) is rejected by policy.
- Policies scope to the Helm release namespace — pods in other namespaces are not
  affected by these ClusterPolicies.
- `validationFailureAction: Enforce` hard-rejects. Set to `Audit` during rollout
  evaluation to log without blocking.
