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

## Uninstall

```bash
helm uninstall ht
```
