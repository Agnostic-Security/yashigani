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
