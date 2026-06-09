{{/*
Common labels + name helpers shared by all 6 micro-services.
*/}}

{{- define "mxsec.commonLabels" -}}
app.kubernetes.io/name: {{ .Release.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "mxsec.serviceLabels" -}}
{{ include "mxsec.commonLabels" .root }}
app.kubernetes.io/component: {{ .name }}
{{- end -}}

{{- define "mxsec.serviceName" -}}
{{- printf "%s-%s" .Release.Name .component | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Generate image reference. Prefers per-service .image.tag, falls back to global.imageTag.
Usage: include "mxsec.image" (dict "svc" .Values.manager "global" .Values.global)
*/}}
{{- define "mxsec.image" -}}
{{- $registry := .global.imageRegistry -}}
{{- $repo := .svc.image.repository -}}
{{- $tag := .svc.image.tag | default .global.imageTag -}}
{{- printf "%s/%s:%s" $registry $repo $tag -}}
{{- end -}}

{{/*
KMS env injection. Adds MXSEC_KMS_KEK_V1 from existing secret.
*/}}
{{- define "mxsec.kmsEnv" -}}
{{- if .Values.kms.enabled -}}
- name: MXSEC_KMS_KEK_V1
  valueFrom:
    secretKeyRef:
      name: {{ .Values.kms.existingSecret }}
      key: {{ .Values.kms.secretKey }}
{{- end -}}
{{- end -}}

{{/*
DB env injection.
*/}}
{{- define "mxsec.dbEnv" -}}
- name: MXSEC_MYSQL_HOST
  value: {{ .Values.externalServices.mysql.host | quote }}
- name: MXSEC_MYSQL_PORT
  value: {{ .Values.externalServices.mysql.port | quote }}
- name: MXSEC_MYSQL_DATABASE
  value: {{ .Values.externalServices.mysql.database | quote }}
- name: MXSEC_MYSQL_USER
  valueFrom:
    secretKeyRef:
      name: {{ .Values.externalServices.mysql.existingSecret }}
      key: {{ .Values.externalServices.mysql.userKey }}
- name: MXSEC_MYSQL_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ .Values.externalServices.mysql.existingSecret }}
      key: {{ .Values.externalServices.mysql.passwordKey }}
- name: MXSEC_REDIS_ADDR
  value: {{ printf "%s:%d" .Values.externalServices.redis.host (.Values.externalServices.redis.port | int) | quote }}
- name: MXSEC_REDIS_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ .Values.externalServices.redis.existingSecret }}
      key: {{ .Values.externalServices.redis.passwordKey }}
- name: MXSEC_KAFKA_BROKERS
  value: {{ .Values.externalServices.kafka.brokers | quote }}
{{- end -}}
