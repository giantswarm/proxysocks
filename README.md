# proxysocks

This application is a SOCKS5 proxy server that forwards traffic to a given HTTP proxy. It is intended to be used in environments where direct access to the internet is not possible, but an HTTP proxy is available.

## Deployment

This app can be deployed using the following CR:

```yaml
apiVersion: application.giantswarm.io/v1alpha1
kind: App
metadata:
  labels:
    giantswarm.io/cluster: <cluster-id>
  name: <cluster-id>-proxysocks
  namespace: <org-namespace>
spec:
  catalog: giantswarm-playground-test
  config:
    configMap:
      name: <cluster-id>-cluster-values
      namespace: <org-namespace>
    secret:
      name: ""
      namespace: ""
  kubeConfig:
    context:
      name: <cluster-id>-kubeconfig
    inCluster: false
    secret:
      name: <cluster-id>-kubeconfig
      namespace: <org-namespace>
  name: proxysocks
  namespace: proxysocks
  version: 0.1.0
```


### Configuration

TODO: Add config examples.

