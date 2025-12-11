{{/*
Expand the name of the chart.
*/}}
{{- define "archie-core-shopify-layer.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "archie-core-shopify-layer.fullname" -}}
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
Create chart name and version as used by the chart label.
*/}}
{{- define "archie-core-shopify-layer.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "archie-core-shopify-layer.labels" -}}
helm.sh/chart: {{ include "archie-core-shopify-layer.chart" . }}
{{ include "archie-core-shopify-layer.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
project: {{ .Values.labels.project }}
environment: {{ .Values.labels.environment }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "archie-core-shopify-layer.selectorLabels" -}}
app.kubernetes.io/name: {{ include "archie-core-shopify-layer.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app: {{ .Values.app.name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "archie-core-shopify-layer.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "archie-core-shopify-layer.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create namespace name
*/}}
{{- define "archie-core-shopify-layer.namespace" -}}
{{- if .Release.Namespace -}}
{{ .Release.Namespace }}
{{- else -}}
{{ .Values.namespace.name }}
{{- end -}}
{{- end }}

{{/*
Generate the full image name
*/}}
{{- define "archie-core-shopify-layer.image" -}}
{{- printf "%s:%s" .Values.image.repository .Values.image.tag }}
{{- end }}

{{/*
Common annotations for all resources
*/}}
{{- define "archie-core-shopify-layer.annotations" -}}
kubernetes.io/change-cause: "Deployment updated to {{ include "archie-core-shopify-layer.image" . }}"
{{- end }}

{{/*
Prometheus annotations for pods
*/}}
{{- define "archie-core-shopify-layer.prometheusAnnotations" -}}
prometheus.io/scrape: "true"
prometheus.io/port: "{{ .Values.app.port }}"
prometheus.io/path: "{{ .Values.monitoring.metricsPath }}"
{{- end }}

