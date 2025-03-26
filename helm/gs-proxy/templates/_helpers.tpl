GS-Proxy Helm Chart
# Chart.yaml
apiVersion: v2
name: gs-proxy
description: A Helm chart for the Giant Swarm Proxy
type: application
version: 0.1.0
appVersion: "0.0.0-67b552750b5b469040624af55894527dcb4d6321"
annotations:
  application.giantswarm.io/team: "hackathon"

# values.yaml
name: gs-proxy
serviceType: "managed"
replicaCount: 1

image:
  repository: quay.io/giantswarm/gs-proxy
  tag: "0.0.0-67b552750b5b469040624af55894527dcb4d6321"
  pullPolicy: IfNotPresent

service:
  type: LoadBalancer
  port: 8000
  annotations:
    external-dns.alpha.kubernetes.io/hostname: "proxy.hackathon-dx.gaws.gigantic.io"
    service.beta.kubernetes.io/aws-load-balancer-internal: "true"
    giantswarm.io/external-dns: managed

securityContext:
  runAsUser: 1000
  runAsGroup: 1000
  runAsNonRoot: true
  seccompProfile:
    type: RuntimeDefault

containerSecurityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL

# templates/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Values.name }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "labels.common" . | nindent 4 }}
spec:
  replicas: {{ .Values.replicaCount }}
  selector:
    matchLabels:
      {{- include "labels.selector" . | nindent 6 }}
  template:
    metadata:
      labels:
        {{- include "labels.common" . | nindent 8 }}
    spec:
      securityContext:
        {{- toYaml .Values.securityContext | nindent 8 }}
      containers:
        - name: {{ .Values.name }}
          image: "{{ .Values.image.repository }}:{{ include "image.tag" . }}"
          imagePullPolicy: {{ .Values.image.pullPolicy }}
          ports:
            - containerPort: {{ .Values.service.port }}
          securityContext:
            {{- toYaml .Values.containerSecurityContext | nindent 12 }}

# templates/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: {{ .Values.name }}
  namespace: {{ .Release.Namespace }}
  annotations:
    {{- toYaml .Values.service.annotations | nindent 4 }}
  labels:
    {{- include "labels.common" . | nindent 4 }}
spec:
  type: {{ .Values.service.type }}
  ports:
    - port: {{ .Values.service.port }}
      targetPort: {{ .Values.service.port }}
  selector:
    {{- include "labels.selector" . | nindent 4 }}

# templates/_helpers.tpl
{{/*

Create chart name and version as used by the chart label.
*/}}
{{- define "chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels
*/}}
{{- define "labels.common" -}}
{{ include "labels.selector" . }}
app.kubernetes.io/managed-by: {{ .Release.Service | quote }}
app.kubernetes.io/name: {{ .Values.name | quote }}
app.kubernetes.io/instance: {{ .Release.Name | quote }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
application.giantswarm.io/team: {{ index .Chart.Annotations "application.giantswarm.io/team" | quote }}
giantswarm.io/service-type: "{{ .Values.serviceType }}"
helm.sh/chart: {{ include "chart" . | quote }}
{{- end -}}

{{/*
Selector labels
*/}}
{{- define "labels.selector" -}}
app: {{ .Values.name | quote }}
{{- end -}}

{{/*
Define image tag.
*/}}
{{- define "image.tag" -}}
{{- if .Values.image.tag }}
{{- .Values.image.tag }}
{{- else }}
{{- .Chart.AppVersion }}
{{- end }}
{{- end }}
