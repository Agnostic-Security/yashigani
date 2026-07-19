{{/*
  Yashigani Helm chart — template helpers.
  All named templates used across chart templates are defined here.
*/}}

{{/*
Expand the name of the chart.
*/}}
{{- define "yashigani.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
Truncated to 63 chars — Kubernetes name length limit.
*/}}
{{- define "yashigani.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart label (name + version).
*/}}
{{- define "yashigani.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels applied to every resource.
*/}}
{{- define "yashigani.labels" -}}
helm.sh/chart: {{ include "yashigani.chart" . }}
{{ include "yashigani.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels — used for matchLabels in Deployments/Services.
*/}}
{{- define "yashigani.selectorLabels" -}}
app.kubernetes.io/name: {{ include "yashigani.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
ServiceAccount name — uses the chart's own SA unless overridden.
*/}}
{{- define "yashigani.serviceAccountName" -}}
{{- if .Values.serviceAccount -}}
{{- if .Values.serviceAccount.name -}}
{{- .Values.serviceAccount.name -}}
{{- else -}}
{{- include "yashigani.fullname" . -}}
{{- end -}}
{{- else -}}
yashigani
{{- end -}}
{{- end }}

{{/*
yashigani.multiTenantAntiAffinity — node-per-tenant hard anti-affinity
(Enterprise/shared-cluster multi-tenant only).

Design authority: yashigani-k8s-dns-hardening-design-20260719.md §4
("Same-node hostile-neighbor" / node-per-tenant anti-affinity spec).

Emits a hard (requiredDuringSchedulingIgnoredDuringExecution — NOT
`preferred`, per §4: "a soft preference is not a segregation guarantee")
podAntiAffinity term that repels pods carrying a DIFFERENT tenant label from
the same node, keyed on multiTenant.tenantLabel/multiTenant.tenantId.
Renders nothing unless multiTenant.enabled=true AND multiTenant.tenantId is
set.

NOT YET WIRED into any Deployment/StatefulSet pod spec in this chart — this
is the reusable primitive only. Two dependencies must land before this can
be safely wired in:
  1. Per-tenant node-pool capacity planning (§4: "capacity planning is
     Lior/Captain's remit, not this design's") — a hard anti-affinity
     constraint that cannot be satisfied leaves pods Pending forever.
  2. Every wired pod template must ALSO carry
     `{{ .Values.multiTenant.tenantLabel }}: {{ .Values.multiTenant.tenantId }}`
     as an actual POD label (podAntiAffinity labelSelector matches pod
     labels, not namespace labels) — not added by this chart today, flagged
     as a cross-team dependency (coordinate with Lior on multi-tenant
     values-schema ownership, per the design doc's own note).

Usage once both dependencies are satisfied, under a Deployment/StatefulSet's
spec.template.spec.affinity.podAntiAffinity:
  {{ include "yashigani.multiTenantAntiAffinity" . | nindent N }}
*/}}
{{- define "yashigani.multiTenantAntiAffinity" -}}
{{- if and .Values.multiTenant.enabled .Values.multiTenant.tenantId }}
requiredDuringSchedulingIgnoredDuringExecution:
  - labelSelector:
      matchExpressions:
        - key: {{ .Values.multiTenant.tenantLabel }}
          operator: NotIn
          values:
            - {{ .Values.multiTenant.tenantId | quote }}
    topologyKey: kubernetes.io/hostname
{{- end }}
{{- end }}

{{/*
yashigani.ownImage — render an image ref for a customer-built image
(gateway, backoffice, adminBootstrap).

Agnostic Security does not distribute these images. Operators build
locally from tagged source (compose path) or push to their own private
registry (K8s path) and override global.imageRegistry / global.imageOwner.

Call with a dict of: registry, owner, repo, tag.
  - When global.imageRegistry is non-empty: "<registry>/<owner>/<repo>:<tag>"
  - When global.imageRegistry is empty:     "<repo>:<tag>"
    (image resolves from the node's local cache or the operator-configured
     imagePullSecrets / pull-through registry — no vendor-hosted registry assumed)

For supply-chain attestation, operators are encouraged to append
"@sha256:<digest>" to their tag value after building.
*/}}
{{- define "yashigani.ownImage" -}}
{{- $registry := index . "registry" -}}
{{- $owner    := index . "owner" -}}
{{- $repo     := index . "repo" -}}
{{- $tag      := index . "tag" -}}
{{- if $registry -}}
{{- printf "%s/%s/%s:%s" $registry $owner $repo $tag -}}
{{- else -}}
{{- printf "%s:%s" $repo $tag -}}
{{- end -}}
{{- end }}
