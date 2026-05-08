# Yashigani Helm Charts

Umbrella chart at `helm/yashigani/` with sub-charts under `helm/charts/`.

## Prerequisites

- Helm 3.14+
- Kubernetes 1.28+
- [KEDA](https://keda.sh) installed in the cluster (`keda` namespace)
- [cert-manager](https://cert-manager.io) installed in the cluster (`cert-manager` namespace)
- nginx-ingress controller installed (for `global.tlsMode=nginx`)

### Install KEDA

```bash
helm repo add kedacore https://kedacore.github.io/charts
helm repo update
helm upgrade --install keda kedacore/keda --namespace keda --create-namespace
```

### Install cert-manager

Use the provided bootstrap script (handles temporary credentials securely):

```bash
bash scripts/install-cert-manager.sh
```

Or manually:

```bash
helm repo add jetstack https://charts.jetstack.io
helm repo update
helm upgrade --install cert-manager jetstack/cert-manager \
  --namespace cert-manager --create-namespace \
  --version v1.14.5 --set installCRDs=true --wait
```

---

## Pre-Install: Secrets

By default the chart auto-generates every secret it needs at install time
(see `templates/secrets.yaml` and the `mtls` / `adminBootstrap` Jobs). For
production you almost certainly want to pre-create them out of band so the
values land in your secret manager rather than the chart's `randAlphaNum`
generator. Each per-service block in `values.yaml` exposes an
`existingSecretName: ""` override for this purpose.

### Schema (when pre-creating)

The chart consumes one secret per service, with the keys below. Every key
uses an UNDERSCORE separator (`redis_password`, NOT `redis-password`) — the
templates reference these literal key names via `secretKeyRef.key`.

| Secret name (default)             | Required keys                                   | Override key                       |
|-----------------------------------|-------------------------------------------------|------------------------------------|
| `yashigani-postgres-secrets`      | `postgres_password`                             | `postgres.existingSecretName`      |
| `yashigani-redis-secrets`         | `redis_password`                                | `redis.existingSecretName`         |
| `yashigani-budget-redis-secrets`  | `redis_password`                                | `budgetRedis.existingSecretName`   |
| `yashigani-gateway-secrets`       | `jwt_secret`, `hmac_secret`                     | `gateway.existingSecretName`       |
| `yashigani-backoffice-secrets`    | `jwt_secret`, `hmac_secret`                     | `backoffice.existingSecretName`    |
| `yashigani-grafana-secrets`       | `grafana_admin_password`                        | `grafana.existingSecretName`       |
| `yashigani-open-webui-secrets`    | `secret_key`                                    | `openWebui.existingSecretName`     |

The mTLS plane and admin bootstrap have dedicated lifecycles — DO NOT
pre-create these unless you are running the issuer / minter out of band:

| Secret name (default)             | Lifecycle                                                                                          | Override key                              |
|-----------------------------------|----------------------------------------------------------------------------------------------------|-------------------------------------------|
| `yashigani-pki-certs`             | Filled by the PKI bootstrap Job. Leaf certs + CA public certs only (no CA keys). Mounted by every workload pod at `/run/secrets`. | `mtls.existingSecretName`                |
| `yashigani-pki-ca-keys`           | Retro #3aj. CA private keys only. Mounted only by the PKI bootstrap Job and rotation CronJob.       | (no override — managed by the chart)      |
| `yashigani-admin-bootstrap`       | Retro #3ap. Filled by the admin-bootstrap Job: `admin1_username`, `admin_initial_password`, `admin1_totp_secret`, `admin2_username`, `admin2_password`, `admin2_totp_secret`. | `adminBootstrap.existingSecretName` |

### Auto-generated default (recommended for staging / dev)

```bash
NAMESPACE=yashigani
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
helm upgrade --install yashigani helm/yashigani/ \
  --namespace "$NAMESPACE" \
  --create-namespace \
  --values helm/yashigani/values.yaml \
  --set global.tlsDomain=staging.yashigani.example.com \
  --wait \
  --wait-for-jobs \
  --timeout 10m \
  --atomic \
  --burst-limit 1000 \
  --qps 500
```

After the install completes, retrieve the bootstrap material:

```bash
# Both admin usernames + initial passwords + TOTP secrets:
for k in admin1_username admin_initial_password admin1_totp_secret \
         admin2_username admin2_password admin2_totp_secret; do
  printf "%-26s = " "$k"
  kubectl get secret yashigani-admin-bootstrap -n "$NAMESPACE" \
    -o "jsonpath={.data.$k}" | base64 -d ; echo
done
```

### Pre-creating with your own values

```bash
NAMESPACE=yashigani
REDIS_PASS=$(openssl rand -base64 27 | tr -d '=+/' | head -c 36)
POSTGRES_PASS=$(openssl rand -base64 27 | tr -d '=+/' | head -c 36)
GATEWAY_JWT=$(openssl rand -hex 32)
GATEWAY_HMAC=$(openssl rand -hex 32)
BACKOFFICE_JWT=$(openssl rand -hex 32)
BACKOFFICE_HMAC=$(openssl rand -hex 32)
GRAFANA_PASS=$(openssl rand -base64 27 | tr -d '=+/' | head -c 36)
WEBUI_KEY=$(openssl rand -hex 32)

kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

kubectl -n "$NAMESPACE" create secret generic yashigani-postgres-secrets \
  --from-literal=postgres_password="$POSTGRES_PASS" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n "$NAMESPACE" create secret generic yashigani-redis-secrets \
  --from-literal=redis_password="$REDIS_PASS" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n "$NAMESPACE" create secret generic yashigani-budget-redis-secrets \
  --from-literal=redis_password="$REDIS_PASS" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n "$NAMESPACE" create secret generic yashigani-gateway-secrets \
  --from-literal=jwt_secret="$GATEWAY_JWT" \
  --from-literal=hmac_secret="$GATEWAY_HMAC" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n "$NAMESPACE" create secret generic yashigani-backoffice-secrets \
  --from-literal=jwt_secret="$BACKOFFICE_JWT" \
  --from-literal=hmac_secret="$BACKOFFICE_HMAC" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n "$NAMESPACE" create secret generic yashigani-grafana-secrets \
  --from-literal=grafana_admin_password="$GRAFANA_PASS" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n "$NAMESPACE" create secret generic yashigani-open-webui-secrets \
  --from-literal=secret_key="$WEBUI_KEY" \
  --dry-run=client -o yaml | kubectl apply -f -
```

Then point each service at the pre-created secret with
`--set <service>.existingSecretName=<name>` on `helm install`.

---

## Dependency Update

Must be run before first install and after any sub-chart change:

```bash
helm dep update helm/yashigani/
```

---

## Install

### Staging

```bash
helm upgrade --install yashigani helm/yashigani/ \
  --namespace yashigani \
  --create-namespace \
  --values helm/yashigani/values.yaml \
  --set global.tlsDomain=staging.yashigani.example.com \
  --set global.acmeEmail=ops@example.com \
  --set global.certManagerIssuer=letsencrypt-staging \
  --set global.environment=staging \
  --wait \
  --wait-for-jobs \
  --timeout 10m \
  --atomic \
  --burst-limit 1000 \
  --qps 500
```

### Production

```bash
helm upgrade --install yashigani helm/yashigani/ \
  --namespace yashigani \
  --create-namespace \
  --values helm/yashigani/values.yaml \
  --set global.tlsDomain=yashigani.example.com \
  --set global.acmeEmail=ops@example.com \
  --set global.certManagerIssuer=letsencrypt-prod \
  --set global.environment=production \
  --wait \
  --wait-for-jobs \
  --timeout 10m \
  --atomic \
  --burst-limit 1000 \
  --qps 500
```

---

## Upgrade Procedure

1. Update the chart version in `helm/yashigani/Chart.yaml` and affected sub-charts.
2. Run `helm dep update helm/yashigani/` to refresh dependency archives.
3. Review changes with `helm diff upgrade` (requires helm-diff plugin):
   ```bash
   helm diff upgrade yashigani helm/yashigani/ --namespace yashigani
   ```
4. Apply the upgrade:
   ```bash
   helm upgrade yashigani helm/yashigani/ \
     --namespace yashigani \
     --wait \
     --wait-for-jobs \
     --timeout 5m \
     --atomic \
     --burst-limit 1000 \
     --qps 500
   ```
5. The `pre-upgrade` hook (`delete-legacy-hpa`) will run automatically to remove native HPAs before KEDA ScaledObjects are applied.

---

## Secret Rotation Procedure

Rotate a secret without downtime (rolling restart approach):

```bash
NAMESPACE=yashigani
NEW_REDIS_PASS=$(openssl rand -base64 27 | tr -d '=+/' | head -c 36)

# 1. Update the secret. Redis credentials live in yashigani-redis-secrets
# only — gateway/backoffice read it via secretKeyRef at runtime, so a
# single update is enough.
kubectl -n "$NAMESPACE" create secret generic yashigani-redis-secrets \
  --from-literal=redis_password="$NEW_REDIS_PASS" \
  --dry-run=client -o yaml | kubectl apply -f -

# 2. Rolling restart all affected deployments so they pick up the new env.
kubectl rollout restart deployment/yashigani-gateway -n "$NAMESPACE"
kubectl rollout restart deployment/yashigani-backoffice -n "$NAMESPACE"
kubectl rollout restart statefulset/yashigani-redis -n "$NAMESPACE"

---

## Loki + log shipping (retro #3aq)

The chart bundles Grafana Loki at `templates/loki.yaml` but does **not** ship
a log shipper as a DaemonSet — only the docker-compose stack runs Promtail.
On Kubernetes, prefer one of:

* the official `grafana/promtail` chart targeting our Loki Service, or
* the `vector` agent in DaemonSet mode, or
* an OpenTelemetry Collector pipeline (we already deploy `otel-collector`
  with a Loki exporter; for Pod stdout/stderr you can wire the
  `filelog` receiver into that pipeline rather than running a separate
  daemon).

`docker/service_identities.yaml` retains a `promtail` entry so the docker
flow can mint a cert for the docker-compose Promtail container. The Helm
chart inherits the same manifest verbatim for IaC parity, so the PKI Job
mints a `promtail_client.{crt,key}` pair into `yashigani-pki-certs` —
that pair is unused in K8s installs (no consumer pod). Carrying it costs
~4 KiB of Secret state and avoids a divergent service_identities.yaml.
A follow-up backlog item adds a chart-managed shipper or removes the cert
once the upstream choice is made.

# 3. Wait for rollout completion
kubectl rollout status deployment/yashigani-gateway -n "$NAMESPACE"
kubectl rollout status deployment/yashigani-backoffice -n "$NAMESPACE"

echo "Secret rotation complete. Monitor /healthz endpoints."
```

---

## Redis Cluster Migration (Phase 9)

When ready to migrate from single-node to Redis Cluster:

```bash
bash scripts/redis-migrate.sh
```

See `scripts/redis-migrate.sh` for full procedure with confirmation prompt.
