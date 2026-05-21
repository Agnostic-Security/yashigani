# Yashigani Admission Control Policies

Last updated: 2026-05-02T00:00:00+01:00

## Overview

Kyverno ClusterPolicy resources that enforce the YSG-RISK-008 container
hardening baseline across the Yashigani namespace. These policies **REJECT**
pods that violate the security posture defined in CLAUDE.md §4.

## Prerequisites

Kyverno must be installed cluster-wide before applying these policies:

```
helm repo add kyverno https://kyverno.github.io/kyverno/
helm repo update
helm install kyverno kyverno/kyverno \
  --namespace kyverno \
  --create-namespace \
  --version 3.2.x \
  --set admissionController.replicas=1
```

## Applying policies

```
kubectl apply -f helm/yashigani/policies/admission/
```

## Policies included

| File | Enforces | Action |
|---|---|---|
| `require-run-as-non-root.yaml` | `runAsNonRoot: true` at pod or container level | Audit + Enforce |
| `require-no-privilege-escalation.yaml` | `allowPrivilegeEscalation: false` on every container | Audit + Enforce |
| `require-seccomp-runtime-default.yaml` | `seccompProfile.type: RuntimeDefault` or `Localhost` | Audit + Enforce |
| `require-drop-all-capabilities.yaml` | `capabilities.drop: [ALL]` on every container | Audit + Enforce |
| `restrict-root-user.yaml` | Blocks `runAsUser: 0` or unset + no `runAsNonRoot` | Audit + Enforce |

## Documented exceptions

Some containers carry documented exceptions — these are excluded via
`exclude.resources.namespaces` or namespace label selectors. See each
policy file for per-exception comments referencing risk register entries.

| Workload | Exception | Reason |
|---|---|---|
| `yashigani-ollama` | `runAsNonRoot`, ROFS | Image runs as root; opt-in only |
| `yashigani-pgbouncer` | ROFS | Writes userlist.txt at startup |
| `yashigani-postgres` | ROFS | Writes PGDATA, socket dir |

## Testing

See `tests/admission/` for compliant + non-compliant pod fixtures.
Apply non-compliant fixture — expect HTTP 403 / policy violation event.
Apply compliant fixture — expect admission.
