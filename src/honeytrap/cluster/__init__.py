"""Multi-node deployment subsystem for HoneyTrap AI.

This package implements Cycle 15's centralized management controller
plus a node-side uplink. Two roles share the same ``honeytrap`` binary
distinguished by configuration:

* **node** (default): runs honeypot protocols and forwards events to a
  controller via :class:`NodeUplink`.
* **controller**: hosts the management API plus the :class:`Fleet`
  subsystem that registers nodes, ingests forwarded events, and serves
  cluster-wide aggregate views.
* **mixed**: a controller that also runs honeypot protocols. The fleet
  registry and the local pipeline run side-by-side in one process.

The implementation is intentionally stdlib-only. HTTP I/O is performed
with :mod:`urllib.request` driven from an asyncio executor so the local
pipeline never blocks on a remote controller. State persistence uses
SQLite (``$DATA_DIR/fleet.db`` and ``$DATA_DIR/uplink_spool.db``).

Authentication reuses the existing API-key + HMAC system with a new
``Role.NODE`` leaf role limited to register / heartbeat / event-ingest.
"""

from __future__ import annotations

from honeytrap.cluster.config import ClusterConfig, ClusterRole, parse_cluster_config
from honeytrap.cluster.controller_fleet import Fleet, NodeRecord
from honeytrap.cluster.node_uplink import NodeUplink, UplinkStatus

__all__ = [
    "ClusterConfig",
    "ClusterRole",
    "Fleet",
    "NodeRecord",
    "NodeUplink",
    "UplinkStatus",
    "parse_cluster_config",
]
