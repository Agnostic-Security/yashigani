{{/*
  yashigani-kuroshio — template helpers. Pattern mirrors helm/yashigani/templates/_helpers.tpl
  for eventual convergence.
*/}}

{{- define "yashigani-kuroshio.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "yashigani-kuroshio.fullname" -}}
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

{{- define "yashigani-kuroshio.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "yashigani-kuroshio.labels" -}}
helm.sh/chart: {{ include "yashigani-kuroshio.chart" . }}
{{ include "yashigani-kuroshio.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "yashigani-kuroshio.selectorLabels" -}}
app.kubernetes.io/name: {{ include "yashigani-kuroshio.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* Resolve the per-backend image repository:tag from values.images.<backend> */}}
{{- define "yashigani-kuroshio.image" -}}
{{- $backend := .Values.backend -}}
{{- $img := index .Values.images $backend -}}
{{- printf "%s:%s" $img.repository $img.tag -}}
{{- end }}

{{/*
Validate the selected backend. GPU is a minimum system requirement (Tiago
2026-09-15): the supervisor refuses to load without an accelerator
(YSG-RISK-301), so a CPU render would produce pods that cannot serve. Failing
at template time gives the operator the message at `helm install`, rather than
a CrashLoop they have to read logs to explain.
*/}}
{{- define "yashigani-kuroshio.validateBackend" -}}
{{- $b := .Values.backend | default "" -}}
{{- if eq $b "cpu" -}}
{{- fail "backend: cpu is not supported — GPU is a minimum system requirement for Kuroshio. CPU-only inference is not slow, it is unusable, and the supervisor refuses to load without an accelerator. Choose one of: cuda, rocm, vulkan." -}}
{{- end -}}
{{- if not (has $b (list "cuda" "rocm" "vulkan")) -}}
{{- fail (printf "backend must be one of cuda, rocm, vulkan (got %q). There is no default: GPU is a minimum system requirement and picking one for you would be picking your hardware for you." $b) -}}
{{- end -}}
{{- end -}}
