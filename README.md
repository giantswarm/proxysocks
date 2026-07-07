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

Authentication supports multiple users. Credentials are provided in [htpasswd](https://httpd.apache.org/docs/current/programs/htpasswd.html) format via the `auth.htpasswd` value. Only bcrypt hashes are supported, so generate entries with `htpasswd -nB <user>` and paste them in, one per line:

```yaml
auth:
  enabled: true
  htpasswd: |
    alice:$2y$05$Q0F...
    bob:$2y$05$9aB...
```

The chart renders this into a Secret and mounts it at `/etc/proxysocks/htpasswd`. To bring your own Secret instead, set `auth.createSecret: false` and `auth.existingSecret: <name>`; the Secret must contain an `htpasswd` key with the same format.

Credentials are loaded once at startup. Changing users requires updating the Secret and restarting the pod.

To disable authentication entirely, set `auth.enabled: false`.

