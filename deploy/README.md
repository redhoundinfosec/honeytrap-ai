# Deployment recipes

This directory bundles everything needed to run HoneyTrap AI outside a
developer checkout.

| Path                                | Purpose                                                 |
| ----------------------------------- | ------------------------------------------------------- |
| `docker-compose.yml`                | Single-host compose stack. `--profile with-prometheus` opts into scraping. |
| `prometheus.yml`                    | Scrape config used by the optional Prometheus container.|
| `helm/honeytrap-ai/`                | Helm chart for Kubernetes clusters.                     |
| `k8s/`                              | Plain manifests + `kustomization.yaml` for users without Helm. |
| `systemd/honeytrap.service`         | Hardened systemd unit.                                  |
| `systemd/install.sh`                | Idempotent installer: user, venv, service enablement.   |

See the top-level [README](../README.md#deployment) for a walkthrough of
each target.
