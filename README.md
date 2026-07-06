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

#### Users

Authentication supports multiple users. Configure them via the `auth.users` list in the Helm values:

```yaml
auth:
  enabled: true
  users:
    - username: alice
      password: s3cr3t
    - username: bob
      password: hunter2
```

The chart renders these into a Secret and mounts it at `/etc/proxysocks/users.yaml`. To bring your own Secret instead, set `auth.createSecret: false` and `auth.existingSecret: <name>`; the Secret must contain a `users.yaml` key with the same format.

Credentials are loaded once at startup. Changing users requires updating the Secret and restarting the pod.

To disable authentication entirely, set `auth.enabled: false`.

