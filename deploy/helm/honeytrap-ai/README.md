# honeytrap-ai Helm chart

Deploy the HoneyTrap AI honeypot into any Kubernetes cluster.

## Install

```bash
helm install ht ./deploy/helm/honeytrap-ai -f my-values.yaml
```

## Common values

| Key                       | Default                                       | Description                                 |
| ------------------------- | --------------------------------------------- | ------------------------------------------- |
| `image.repository`        | `ghcr.io/redhoundinfosec/honeytrap-ai`        | OCI image repository.                       |
| `image.tag`               | `latest`                                      | Tag / digest.                               |
| `profile`                 | `web_server`                                  | Bundled profile name.                       |
| `dashboardMode`           | `none`                                        | `textual`, `rich`, or `none`.               |
| `replicaCount`            | `1`                                           | Usually 1 — honeypots are singletons.       |
| `persistence.enabled`     | `true`                                        | Mount a PVC at `/app/data`.                 |
| `healthProbes.enabled`    | `true`                                        | Wire `/healthz` and `/readyz` probes.       |
| `serviceMonitor.enabled`  | `false`                                       | Create a Prometheus Operator ServiceMonitor.|
| `networkPolicy.enabled`   | `false`                                       | Gate pod ingress via NetworkPolicy.         |

## Multi-node clusters

The chart can be installed in three roles via the `cluster.role` value:

| Role         | Purpose                                              | Values file                  |
| ------------ | ---------------------------------------------------- | ---------------------------- |
| `node`       | Runs honeypots, forwards events to a controller.     | `values-node.yaml`           |
| `controller` | Hosts the management API and stores fleet state.    | `values-controller.yaml`     |
| `mixed`      | Both at once (single-host demos).                    | `values.yaml` (manual flags) |

Typical install:

```bash
# 1. Deploy the controller.
helm install ht-controller ./deploy/helm/honeytrap-ai \
    -f deploy/helm/honeytrap-ai/values-controller.yaml \
    --set cluster.apiKeySecret.name=honeytrap-controller-key

# 2. Generate a node-role API key on the controller, store as a Secret:
kubectl create secret generic honeytrap-node-key --from-literal=api_key=htk_...

# 3. Deploy each node referencing the controller URL.
helm install ht-edge-01 ./deploy/helm/honeytrap-ai \
    -f deploy/helm/honeytrap-ai/values-node.yaml \
    --set cluster.controllerUrl=http://ht-controller-honeytrap-ai:9300
```

API keys are htk_-prefixed bearer tokens; node keys are limited to the
register / heartbeat / event-ingest endpoints by RBAC.

## Uninstall

```bash
helm uninstall ht
```
