{{- define "fluidbox.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "fluidbox.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "fluidbox.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "fluidbox.labels" -}}
app.kubernetes.io/name: {{ include "fluidbox.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "fluidbox.serverName" -}}{{ include "fluidbox.fullname" . }}-server{{- end -}}
{{- define "fluidbox.internalServiceName" -}}{{ include "fluidbox.fullname" . }}-internal{{- end -}}
{{- define "fluidbox.webName" -}}{{ include "fluidbox.fullname" . }}-web{{- end -}}
{{- define "fluidbox.litellmName" -}}{{ include "fluidbox.fullname" . }}-litellm{{- end -}}
{{- define "fluidbox.sandboxSA" -}}{{ include "fluidbox.fullname" . }}-sandbox{{- end -}}

{{/* The facade upstream URL: explicit external, else the bundled LiteLLM. */}}
{{- define "fluidbox.llmUpstreamUrl" -}}
{{- if .Values.llm.upstreamUrl -}}
{{- .Values.llm.upstreamUrl -}}
{{- else if .Values.litellm.enabled -}}
{{- printf "http://%s:4000" (include "fluidbox.litellmName" .) -}}
{{- else -}}
{{- "" -}}
{{- end -}}
{{- end -}}
