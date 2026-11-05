# proxysocks

A Helm chart for the Giant Swarm Proxy

**Homepage:** <https://github.com/giantswarm/proxysocks>

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| serviceType | string | `"managed"` |  |
| replicaCount | int | `2` |  |
| image.registry | string | `"gsoci.azurecr.io"` |  |
| image.name | string | `"giantswarm/proxysocks"` |  |
| image.tag | string | `""` |  |
| image.pullPolicy | string | `"IfNotPresent"` |  |
| auth.enabled | bool | `false` |  |
| auth.createSecret | bool | `true` |  |
| auth.existingSecret | string | `""` |  |
| auth.htpasswd | string | `""` |  |
| service.type | string | `"LoadBalancer"` |  |
| service.port | int | `8000` |  |
| service.annotations."service.beta.kubernetes.io/aws-load-balancer-internal" | string | `"true"` |  |
| metrics.port | int | `8090` |  |
| metrics.serviceMonitor.enabled | bool | `true` |  |
| networkPolicy.enabled | bool | `true` |  |
| podDisruptionBudget.enabled | bool | `true` |  |
| podDisruptionBudget.minAvailable | int | `1` |  |
| podSecurityContext.runAsUser | int | `1000` |  |
| podSecurityContext.runAsGroup | int | `1000` |  |
| podSecurityContext.runAsNonRoot | bool | `true` |  |
| podSecurityContext.seccompProfile.type | string | `"RuntimeDefault"` |  |
| securityContext.allowPrivilegeEscalation | bool | `false` |  |
| securityContext.readOnlyRootFilesystem | bool | `true` |  |
| securityContext.capabilities.drop[0] | string | `"ALL"` |  |
| resources.requests.cpu | string | `"100m"` |  |
| resources.requests.memory | string | `"100Mi"` |  |
| resources.limits.memory | string | `"200Mi"` |  |
