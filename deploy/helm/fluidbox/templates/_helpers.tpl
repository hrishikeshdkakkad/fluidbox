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

{{/* Image ref for a structured image ({repository, tag, digest}): a digest
     pin renders repository@sha256:… (the ":" of repo:tag is WRONG for
     digests), else repository:tag with the tag defaulting to the chart
     appVersion — `helm package --app-version` at release time binds the
     packaged chart to the images that release published. Call with
     (dict "image" .Values.images.server "ctx" $). */}}
{{- define "fluidbox.imageRef" -}}
{{- if .image.digest -}}
{{- $d := .image.digest | trimPrefix "@" -}}
{{- if not (regexMatch "^sha256:[0-9a-f]{64}$" $d) -}}
{{- fail (printf "images.*.digest must be \"sha256:<64 hex>\", got %q" .image.digest) -}}
{{- end -}}
{{- printf "%s@%s" .image.repository $d -}}
{{- else -}}
{{- printf "%s:%s" .image.repository (.image.tag | default .ctx.Chart.AppVersion) -}}
{{- end -}}
{{- end -}}

{{/* Full ref for a flat image value (sandboxRunner/codexRunner/collector):
     any non-empty value (tag or @sha256 ref) passes through verbatim; "" is
     the official GHCR image at the chart appVersion. Call with
     (dict "value" .Values.images.collector "name" "workspaced" "ctx" $). */}}
{{- define "fluidbox.flatImage" -}}
{{- if .value -}}
{{- .value -}}
{{- else -}}
{{- printf "ghcr.io/hrishikeshdkakkad/fluidbox-%s:%s" .name .ctx.Chart.AppVersion -}}
{{- end -}}
{{- end -}}

{{/* Comma-joined pull-secret NAMES for FLUIDBOX_K8S_IMAGE_PULL_SECRETS (the
     provider recreates the [{name: …}] refs on sandbox + probe pods). */}}
{{- define "fluidbox.pullSecretNames" -}}
{{- $names := list -}}
{{- range .Values.images.pullSecrets -}}{{- $names = append $names .name -}}{{- end -}}
{{- join "," $names -}}
{{- end -}}

{{/* values.sandbox.nodeSelector as k1=v1,k2=v2 for FLUIDBOX_K8S_NODE_SELECTOR
     (template `range` iterates map keys sorted, so the output is stable).
     ',' and '=' cannot ride this encoding — they are invalid in Kubernetes
     label keys/values anyway, so refuse them at render time instead of
     silently splitting one selector into several. */}}
{{- define "fluidbox.sandboxNodeSelector" -}}
{{- $sel := list -}}
{{- range $k, $v := .Values.sandbox.nodeSelector -}}
{{- $vs := $v | toString -}}
{{- if or (contains "," $k) (contains "=" $k) (contains "," $vs) (contains "=" $vs) -}}
{{- fail (printf "sandbox.nodeSelector %q=%q: ',' and '=' are invalid in label keys/values" $k $vs) -}}
{{- end -}}
{{- $sel = append $sel (printf "%s=%s" $k $vs) -}}
{{- end -}}
{{- join "," $sel -}}
{{- end -}}
