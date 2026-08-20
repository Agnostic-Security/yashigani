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
