# Yashigani — Kubernetes Deployment Guide

Version: v2.23.3 | Chart version: 2.23.3 | Last updated: 2026-05-08T00:00:00+01:00

## Prerequisites

| Tool | Minimum version | Notes |
|------|-----------------|-------|
| kubectl | 1.28 | Configured for your target cluster |
| Helm | 3.14 | `helm version` to verify |
| cert-manager | 1.14 | Required for automatic TLS (`tlsMode: nginx`) |
| nginx-ingress | 1.10 | Required when `global.tlsMode: nginx` (default) |
| k3s or minikube | any recent | For local testing only |

Optional but recommended:

- **KEDA** — if `global.keda.enabled: true` (default). Required for event-driven autoscaling.
- **Prometheus Operator** — if you want ServiceMonitor CRDs; plain Prometheus works without it.

### Docker Desktop Kubernetes — Image Preflight

If you are testing on **Docker Desktop's built-in Kubernetes** (single-node, local development): a Docker Desktop restart, K8s reset, or Docker Engine upgrade evicts all images from the embedded containerd runtime. After any of these events, the gateway/backoffice images that Helm references will not be present locally and pods will hang in `ImagePullBackOff` (since `imagePullPolicy: IfNotPresent` is the chart default and no remote pull is configured for locally-built images).

Run this preflight before `helm install` / `helm upgrade` whenever Docker Desktop K8s has restarted:

```bash
# Rebuild local images
docker build -f docker/Dockerfile.gateway -t yashigani/gateway:2.23.2 .
docker build -f docker/Dockerfile.backoffice -t yashigani/backoffice:2.23.2 .

# Re-pull base images that DD K8s evicted alongside
docker pull redis:7-alpine
docker pull postgres:16-alpine
```

This step is **not required** on managed K8s (EKS/GKE/AKS/k3s/k8s-on-VMs) where the container runtime persists images across cluster restarts.

---

## Quick Install (recommended)

For most operators, the canonical entry point is the K8s install wrapper:

```bash
bash scripts/k8s-install.sh \
  --domain yashigani.example.com \
  --admin-email admin@example.com \
  --namespace yashigani \
  --deploy production
```

The wrapper sets Kubernetes-sensible defaults before delegating to `install.sh`:

| Default applied | Why |
|---|---|
| `--mode k8s` | Tells the installer to render Helm rather than docker-compose. |
| `--non-interactive` | K8s installs typically run in CI/CD with no TTY. |
| `YSG_RUNTIME=k8s` | Skips runtime-specific local checks (Podman / Docker daemon probes). |
| `helm install --qps 50 --no-hooks` | Avoids the default `qps=5` client-side rate limiter when applying the chart's many resources. |

Pre-conditions checked before delegating (hard-stop on failure):

1. `kubectl` is in `PATH` and reaches the target cluster.
2. `helm` is in `PATH`.
3. Either `--domain` or `YASHIGANI_DOMAIN` env is set.
4. Namespace is not `default` (accidental-deployment guard).

All flags are forwarded to `install.sh` unchanged. Use `--dry-run` to print the steps without applying.

If you need a fully manual flow (BYO secret management, custom Helm values, multi-cluster federation, etc.) follow the **Manual Quick Start** below instead.

---

## Manual Quick Start

### 1. Create the namespace and secrets

Yashigani requires several Kubernetes Secrets before install. Create them manually or with your secret management tool (External Secrets, Vault Agent, etc.).

```bash
# Namespace
kubectl create namespace yashigani

# Gateway secrets
kubectl create secret generic yashigani-gateway-secrets \
  -n yashigani \
  --from-literal=redis_password="$(openssl rand -hex 32)" \
  --from-literal=upstream_url="https://your-mcp-server.example.com"

# Backoffice secrets
kubectl create secret generic yashigani-backoffice-secrets \
  -n yashigani \
  --from-literal=redis_password="$(openssl rand -hex 32)" \
  --from-literal=admin_password="$(openssl rand -hex 24)"

# Redis shared secret (same password used above)
kubectl create secret generic yashigani-redis-secrets \
  -n yashigani \
  --from-literal=redis_password="<same-as-above>"

# Postgres
kubectl create secret generic yashigani-postgres-secrets \
  -n yashigani \
  --from-literal=postgres_password="$(openssl rand -hex 32)"

# DB credentials for partition maintenance CronJob
kubectl create secret generic yashigani-db-credentials \
  -n yashigani \
  --from-literal=url="postgresql://yashigani_app:<postgres_password>@yashigani-pgbouncer:5432/yashigani"

# Grafana
kubectl create secret generic yashigani-grafana-secrets \
  -n yashigani \
  --from-literal=grafana_admin_password="$(openssl rand -hex 24)"

# Open WebUI
kubectl create secret generic yashigani-open-webui-secrets \
  -n yashigani \
  --from-literal=secret_key="$(openssl rand -hex 32)"
```

### 2. Install the chart

```bash
helm install yashigani helm/yashigani/ \
  --namespace yashigani \
  --set global.tlsDomain=yashigani.example.com \
  --set global.acmeEmail=admin@example.com \
  --wait \
  --wait-for-jobs \
  --timeout 10m \
  --atomic \
  --burst-limit 1000 \
  --qps 500
```

> **Timeout guidance (v2.23.3+):** fresh installs use `--timeout 10m`; upgrades use `--timeout 5m`. Images must be pre-pulled into the node's containerd cache before installing — see the Docker Desktop preflight above. Override with `HELM_TIMEOUT=20m` when using `scripts/k8s-install.sh` on air-gap or slow-pull clusters.

### 3. Verify the release

```bash
# Check all pods are running
kubectl get pods -n yashigani

# Run Helm smoke tests
helm test yashigani -n yashigani --logs
```

---

## Configuration: Key values.yaml Parameters

### Global

| Key | Default | Description |
|-----|---------|-------------|
| `global.imageRegistry` | `ghcr.io` | Container registry prefix |
| `global.imageOwner` | `Agnostic-Security` | Registry namespace/org |
| `global.tlsDomain` | `yashigani.example.com` | **REQUIRED** — your public domain |
| `global.tlsMode` | `nginx` | `nginx` (cert-manager) or `caddy` (edge proxy) |
| `global.certManagerIssuer` | `letsencrypt-prod` | ClusterIssuer name for TLS |
| `global.acmeEmail` | `admin@example.com` | ACME registration email |
| `global.environment` | `production` | Passed to services as env hint |
| `global.keda.enabled` | `true` | Enable KEDA for event-driven scaling |
| `global.pdb.enabled` | `true` | Enable PodDisruptionBudgets |

### Gateway

| Key | Default | Description |
|-----|---------|-------------|
| `gateway.replicaCount` | `2` | Minimum replicas |
| `gateway.hpa.maxReplicas` | `10` | HPA ceiling |
| `gateway.env.upstreamUrl` | `""` | **REQUIRED** — upstream MCP server URL |
| `gateway.env.opaUrl` | `https://yashigani-policy:8181` | OPA policy endpoint (mTLS, v2.23.2+) |
| `gateway.env.ollamaUrl` | `http://ollama:11434` | Ollama inference endpoint |
| `gateway.existingSecretName` | `yashigani-gateway-secrets` | Secret with `redis_password` |

### Backoffice

| Key | Default | Description |
|-----|---------|-------------|
| `backoffice.replicaCount` | `2` | Minimum replicas |
| `backoffice.service.port` | `8443` | Internal service port |
| `backoffice.existingSecretName` | `yashigani-backoffice-secrets` | Admin credential secret |

### Redis

| Key | Default | Description |
|-----|---------|-------------|
| `redis.persistence.enabled` | `true` | Enable PVC for Redis data |
| `redis.persistence.size` | `1Gi` | PVC size |
| `redis.existingSecretName` | `yashigani-redis-secrets` | Secret with `redis_password` |

### Budget Redis

| Key | Default | Description |
|-----|---------|-------------|
| `budgetRedis.enabled` | `true` | Dedicated Redis for token budget counters |
| `budgetRedis.persistence.size` | `1Gi` | PVC size |
| `budgetRedis.existingSecretName` | `yashigani-redis-secrets` | Reuses same Redis secret |

### Ollama

| Key | Default | Description |
|-----|---------|-------------|
| `ollama.image.tag` | `0.6.2` | Pinned to match docker-compose |
| `ollama.replicaCount` | `2` | HA replicas |
| `ollama.persistence.size` | `20Gi` | Model storage PVC |
| `ollama.model` | `qwen2.5:3b` | Default model to use |

### PostgreSQL + PgBouncer

| Key | Default | Description |
|-----|---------|-------------|
| `postgres.enabled` | `true` | Deploy bundled Postgres |
| `postgres.persistence.size` | `20Gi` | Data PVC size |
| `postgres.existingSecretName` | `yashigani-postgres-secrets` | Secret with `postgres_password` |
| `pgbouncer.enabled` | `true` | Deploy PgBouncer connection pooler |
| `pgbouncer.env.poolMode` | `transaction` | PgBouncer pool mode |

---

## Agent Bundles

Agent bundles are opt-in and disabled by default. The current agent lineup is:

- **Lala** (Langflow) — visual flow-based agent orchestration
- **Julietta** (Letta) — memory-augmented conversational agent
- **Scout** (OpenClaw) — messaging-capable agent (exposes port 18789 for webhooks)

Agent chaining is supported: `@Scout` -> `@Julietta` -> `@qwen`. Model strings starting with `@` are resolved as agent names in the registry; chain them by passing the result of one agent as the model parameter of the next call.

> **Note:** Goose (ACP too slow) and LangGraph (replaced by Langflow) have been removed from the agent lineup.

Enable per-bundle at install or upgrade time:

```bash
# Enable Lala (Langflow — visual flow agent)
helm upgrade yashigani helm/yashigani/ -n yashigani \
  --set agentBundles.langflow.enabled=true \
  --set agentBundles.langflow.tokenSecretName=yashigani-langflow-token

# Enable Julietta (Letta — memory-augmented agent)
helm upgrade yashigani helm/yashigani/ -n yashigani \
  --set agentBundles.letta.enabled=true \
  --set agentBundles.letta.tokenSecretName=yashigani-letta-token

# Enable Scout (OpenClaw — exposes port 18789 for messaging webhooks)
helm upgrade yashigani helm/yashigani/ -n yashigani \
  --set agentBundles.openclaw.enabled=true \
  --set agentBundles.openclaw.tokenSecretName=yashigani-openclaw-token
```

Each enabled bundle creates a Deployment and (where applicable) a Service. All agent traffic routes through the Yashigani gateway — direct LLM access is blocked by NetworkPolicy.

---

## TLS: cert-manager Integration

The chart ships three ClusterIssuers (rendered by `clusterissuers.yaml`):

| Name | Use case |
|------|----------|
| `letsencrypt-prod` | Production (requires public DNS) |
| `letsencrypt-staging` | Rate-limit-safe testing |
| `selfsigned` | Local/dev — no DNS required |

Set the active issuer:

```bash
helm upgrade yashigani helm/yashigani/ -n yashigani \
  --set global.certManagerIssuer=letsencrypt-staging  # testing
```

To use nginx-ingress + cert-manager (default):

```bash
# Install cert-manager
helm repo add jetstack https://charts.jetstack.io
helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager --create-namespace \
  --set installCRDs=true

# Install nginx-ingress
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm install ingress-nginx ingress-nginx/ingress-nginx \
  --namespace ingress-nginx --create-namespace
```

To use Caddy as the TLS edge proxy instead (Docker-compose parity):

```bash
helm upgrade yashigani helm/yashigani/ -n yashigani \
  --set global.tlsMode=caddy \
  --set caddy.enabled=true
```

---

## Monitoring: Prometheus and Grafana Access

Prometheus and Grafana are deployed cluster-internally. Access via port-forward or via the Ingress `/admin` route.

```bash
# Prometheus port-forward
kubectl port-forward svc/yashigani-prometheus 9090:9090 -n yashigani

# Grafana port-forward
kubectl port-forward svc/yashigani-grafana 3000:3000 -n yashigani
# Default user: grafana-admin
# Password: from yashigani-grafana-secrets / grafana_admin_password
```

Via Ingress (if `global.tlsDomain` is set):

- Grafana: `https://yashigani.example.com/admin/grafana`
- Prometheus (federate, basic auth via Caddy): `https://yashigani.example.com/metrics-federate`

---

## Wazuh Integration (Helm)

To deploy Wazuh alongside Yashigani in Kubernetes, enable the Wazuh sub-chart:

```bash
helm upgrade yashigani helm/yashigani/ -n yashigani \
  --set wazuh.enabled=true
```

Wazuh requires additional resources: at least 5 GB disk for the indexer and 2 GB additional RAM. Ensure your cluster nodes can accommodate these before enabling. Wazuh admin credentials are auto-generated and stored in the `yashigani-wazuh-secrets` Kubernetes Secret.

---

## Internal CA (Smallstep step-ca)

For deployments that require an internal Certificate Authority (e.g., mTLS between services), enable the Internal CA sub-chart:

```bash
helm upgrade yashigani helm/yashigani/ -n yashigani \
  --set internalCA.enabled=true
```

This deploys Smallstep step-ca as an internal CA. Certificates are issued automatically for inter-service communication. The CA root certificate is stored in the `yashigani-internal-ca-secrets` Secret.

---

## Kubernetes Deployment Status

Kubernetes deployment was validated end-to-end for v2.23.1 on Docker Desktop K8s (aarch64). All five clean-slate gates GREEN: macOS Podman, macOS Docker, Linux Podman, Linux Docker, and K8s Helm. Risk R-015 is closed.

### v2.23.1 Helm requirements

Three requirements were added to the chart during the v2.23.1 release cycle (tip 7023360 / 1a6db9f) that operators must be aware of:

**NetworkPolicy: gateway → postgres and backoffice → postgres**
The chart now includes `NetworkPolicy` rules permitting gateway and backoffice pods to reach the `yashigani-postgres` pod on port 5432. These policies are required for Alembic migrations to run at startup. If you have cluster-level default-deny policies that supersede Helm-managed NetworkPolicies, ensure equivalent allow rules exist before installing.

**ca_bundle.crt trust anchor**
A `ConfigMap` containing `ca_bundle.crt` (the intermediate + root certificate chain) is mounted into gateway and backoffice pods. Python's `ssl` module requires the full chain in the trust store for mTLS verification — an intermediate-only bundle is rejected. This bundle is generated at install time by the in-tree PKI issuer and baked into the `yashigani-pki-config` ConfigMap by the mTLS bootstrap Job. No manual action required for new installs; for upgrades from pre-v2.23.1 charts, run `helm upgrade` and let the bootstrap Job re-execute.

**YASHIGANI_DB_DSN_DIRECT (gateway pod)**
The gateway pod now receives `YASHIGANI_DB_DSN_DIRECT` pointing directly at `yashigani-postgres:5432` (bypassing PgBouncer). This is required because Alembic migrations must run in session mode, not PgBouncer's default transaction-pool mode. The value is injected automatically from the `yashigani-postgres-secrets` Secret; no additional action is required unless you override the postgres service name.

---

## v2.2 Feature Flags

### PII Detection

```bash
helm upgrade yashigani helm/yashigani/ -n yashigani \
  --set pii.enabled=true \
  --set pii.mode=redact          # log | redact | block
```

Requires license feature `pii_log` (Community+) or `pii_redact` (Pro+). Configured at the backoffice level; values.yaml sets defaults only.

### DDoS Protection

Enabled by default. Tune thresholds:

```bash
helm upgrade yashigani helm/yashigani/ -n yashigani \
  --set ddosProtection.maxConnectionsPerIp=100 \
  --set ddosProtection.windowSeconds=30
```

### Response Inspection

Run the Ollama injection classifier over LLM responses (additional latency):

```bash
helm upgrade yashigani helm/yashigani/ -n yashigani \
  --set responseInspection.enabled=true
```

### SSO / Identity Provider

Configure IdPs via the backoffice UI at runtime. See `values.yaml` `sso.idps` for the static-config structure if you prefer GitOps-style IdP registration.

---

## Helm Smoke Tests

Three test Pods run after `helm test`:

| Test | What it checks |
|------|----------------|
| `test-gateway-health` | `GET /healthz` on gateway returns HTTP 200 |
| `test-backoffice-health` | `GET /healthz` on backoffice returns HTTP 200 |
| `test-redis-ping` | Both Redis instances respond to PING (auth expected in prod) |

```bash
helm test yashigani -n yashigani --logs
```

Test Pods are deleted on success (`hook-delete-policy: hook-succeeded`).

---

## Troubleshooting

### Pod stuck in Pending

```bash
kubectl describe pod <pod-name> -n yashigani
```

Common causes:
- PVC not bound — check `storageClass` in values.yaml; set `""` to use cluster default.
- Resource quota exceeded — check `kubectl describe resourcequota -n yashigani`.
- Node selector/affinity mismatch — check `topologySpread` settings.

### Gateway returns 502 Bad Gateway

- Check OPA policy pod: `kubectl logs -l app.kubernetes.io/name=yashigani-policy -n yashigani`
- Check Redis connectivity: `helm test yashigani -n yashigani`
- Verify `gateway.env.upstreamUrl` is set and reachable from within the cluster.

### TLS certificate not issued

```bash
kubectl describe certificaterequest -n yashigani
kubectl describe challenge -n yashigani
```

- Ensure `global.acmeEmail` is valid.
- For `letsencrypt-prod`, the domain must resolve publicly to the cluster's LoadBalancer IP.
- Use `letsencrypt-staging` for testing to avoid rate limits.

### Backoffice first-run credentials

On first boot, the backoffice generates admin credentials. Check:

```bash
kubectl logs -l app.kubernetes.io/name=yashigani-backoffice -n yashigani | grep -i "admin\|password\|credential"
```

### Agent bundle not routing through gateway

1. Verify `YASHIGANI_AGENT_TOKEN` secret is mounted correctly.
2. Check NetworkPolicy — agent bundles are only allowed to reach the gateway on port 8080.
3. Review gateway logs: `kubectl logs -l app.kubernetes.io/name=yashigani-gateway -n yashigani`

### Upgrade: legacy HPA cleanup

The `pre-upgrade` hook Job `delete-legacy-hpa` removes stale HPA objects before upgrade. If it fails:

```bash
kubectl get jobs -n yashigani
kubectl logs job/yashigani-delete-legacy-hpa -n yashigani
```

The Job requires the `yashigani` ServiceAccount to have `delete` on `horizontalpodautoscalers`. If RBAC is locked down, grant it temporarily or delete HPAs manually before upgrading.

### Re-install: stale PersistentVolume cleanup (local-path-provisioner)

On Docker Desktop K8s, kind, and k3s single-node clusters, PVs backed by local-path-provisioner may linger after `helm uninstall` or namespace deletion. On a subsequent `helm install`, Postgres can start against the old data directory with a mismatched password, causing `password authentication failed` on first startup.

**Before re-installing**, check for stale PVs:

```bash
kubectl get pv | grep yashigani
```

If any PVs remain in `Released` or `Bound` state referencing the old namespace, they must be deleted before re-installing.

> **Internal operator runbook:** Agnostic Security operators have a detailed step-by-step cleanup guide at `Internal/Compliance/yashigani/install-runbooks/k8s-pv-stale-data-cleanup.md` covering: how to identify stale PVs, when it is safe to delete, what data is permanently lost, how to confirm cleanup, and known failure modes (stuck `Terminating` namespaces, finalizer removal, local-path-provisioner backing directory cleanup).

A safe abbreviated flow for development clusters where all data is expendable:

```bash
NAMESPACE=yashigani

# Delete namespace (and its PVCs)
kubectl delete namespace ${NAMESPACE} --ignore-not-found
kubectl wait --for=delete namespace/${NAMESPACE} --timeout=120s 2>/dev/null || true

# Delete any lingering PVs that referenced this namespace
kubectl get pv -o custom-columns='NAME:.metadata.name,NS:.spec.claimRef.namespace' \
  --no-headers | awk -v ns="${NAMESPACE}" '$2==ns {print $1}' \
  | xargs -r kubectl delete pv

# Confirm clean state
kubectl get pv | grep yashigani || echo "No stale PVs — safe to re-install"
```

**This permanently destroys all data in those PVs.** Always take a backup first if the data is recoverable. See `restore.sh --k8s` for K8s-aware restore.
