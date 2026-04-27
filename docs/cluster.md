# Multi-node deployment

HoneyTrap AI supports a hub-and-spoke topology: many honeypot **nodes**
report into a single **controller** that aggregates events, exposes a
unified management API, and renders cluster-wide views.

```
                       +----------------------+
                       |    controller        |
   admin / analyst <-->|  :9300 management    |
                       |  Fleet (SQLite)      |
                       +-----^------^---------+
                             |      |  htk_-keyed HTTP
              +--------------+      +--------------+
              |                                    |
        +-----+------+                       +-----+------+
        |  node      |   ...     ...         |  node      |
        |  edge-01   |                       |  edge-N    |
        |  honeypots |                       |  honeypots |
        +------------+                       +------------+
```

## Roles

The same `honeytrap` binary can run in three modes, selected via the
`cluster.role` config key:

| Role         | Runs honeypots? | Accepts uplink traffic? | Typical use |
| ------------ | --------------- | ----------------------- | ----------- |
| `node`       | yes             | no                      | One per region/cloud. |
| `controller` | no              | yes                     | One per fleet. |
| `mixed`      | yes             | yes                     | Single-host demo. |

## Configuration

Add a `cluster:` block to `honeytrap.yaml`:

```yaml
cluster:
  enabled: true
  role: node
  node_id: edge-01
  controller_url: https://controller.example.com:9300
  api_key: htk_xxxx
  heartbeat_interval: 30
  event_batch_size: 200
  event_flush_interval: 5
  spool_max_events: 10000
  spool_max_disk_bytes: 67108864
  tls_verify: true
  tags: [edge, us-east-1]
```

The validator rejects:

* `enabled: true` with no `controller_url`.
* `enabled: true` with no `api_key`.
* `api_key` that does not start with `htk_`.
* `controller_url` not in `http://` or `https://` form.
* Negative or zero values for any interval / batch / spool field.

## API key roles

Cycle 15 adds a `node` RBAC role. Node keys are isolated from the
existing `viewer`/`analyst`/`admin` ladder: a stolen node key cannot
read sessions, rotate keys, or query intel. Node keys can ONLY:

* `POST /api/v1/cluster/nodes` (register / refresh).
* `PUT /api/v1/cluster/nodes/{id}/heartbeat`.
* `POST /api/v1/cluster/events` (event ingest).

Generate a node key on the controller:

```bash
honeytrap api-keys create --role node --name edge-01
```

## Node uplink

Each node runs a small async client (the *uplink*) that:

1. Registers with the controller on startup.
2. Sends a heartbeat every `heartbeat_interval` seconds. Heartbeats
   contain version, uptime, queue depth, and any operator-supplied
   `extras`. They MUST NOT contain secrets or PII.
3. Drains a bounded in-memory event queue, batches events up to
   `event_batch_size` or every `event_flush_interval` seconds, and
   POSTs them to the controller.
4. On controller outage, events spill to a SQLite spool capped at
   `spool_max_events` rows / `spool_max_disk_bytes` bytes. When the
   controller comes back, the spool drains in FIFO order.
5. Backs off exponentially with jitter on persistent failures, capped
   at 60 s.

The `Cluster-Generation` response header increments on every fleet
change so dashboards can invalidate caches without polling.

## Operator commands

```bash
# Bootstrap a node config from CLI args.
honeytrap node register \
    --controller https://controller.example.com:9300 \
    --api-key htk_xxx \
    --node-id edge-01 \
    --tag edge --tag us-east

# Inspect the local uplink status.
honeytrap node uplink-status --api-key htk_admin

# From the controller side:
honeytrap controller list-nodes --api-key htk_admin
honeytrap controller list-events --protocol ssh --limit 50 --api-key htk_admin
honeytrap controller top-attackers --limit 10 --api-key htk_admin
honeytrap controller mitre-heatmap --api-key htk_admin
```

## Helm

The chart (`deploy/helm/honeytrap-ai`) ships with two role-specific
override files:

* `values-controller.yaml` -- controller-only deploy, exposes :9300.
* `values-node.yaml` -- node deploy, references controller via
  `cluster.controllerUrl` and reads the API key from a Secret.

See `deploy/helm/honeytrap-ai/README.md` for sample commands.

## Storage layout

```
$DATA_DIR/
  fleet.db          # controller-side: nodes + heartbeats + events
  uplink_spool.db   # node-side: SQLite overflow spool
```

`fleet.db` uses WAL journalling and is safe to back up via SQLite's
online backup API.

## Security notes

* Heartbeat snapshots are post-processed on the controller: keys named
  `secret`, `token`, `password`, `hash`, `api_key`, or `apikey` are
  replaced with `"<redacted>"` before persistence. This is
  defence-in-depth -- nodes should never send those values in the
  first place.
* Event payloads receive the same redaction.
* Node tokens cannot read any non-cluster API; they are denied at the
  RBAC layer regardless of route.
* When `cluster.tls_verify` is `false` the uplink prints a warning at
  startup. Disable only for staging.
