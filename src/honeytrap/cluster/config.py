"""Cluster configuration dataclasses and YAML parsing.

The ``cluster:`` section is orthogonal to device profiles -- a node
running a ``web_server`` profile and a node running an ``iot_camera``
profile both share the same uplink shape. Three roles are recognised:

* ``node``        -- uplink-only honeypot (default).
* ``controller``  -- centralised management plane.
* ``mixed``       -- controller + local honeypot in one process.

Validation is intentionally strict: a node role without a controller URL
or API key is a configuration error, not a silent best-effort. Errors
are surfaced via :class:`honeytrap.exceptions.ConfigError` so the CLI
can render them with the same machinery as other config issues.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from honeytrap.exceptions import ConfigError

_NODE_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class ClusterRole(str, enum.Enum):
    """Process role within a cluster."""

    NODE = "node"
    CONTROLLER = "controller"
    MIXED = "mixed"

    @classmethod
    def from_str(cls, value: str | ClusterRole) -> ClusterRole:
        """Parse a case-insensitive role name, raising on unknown values."""
        if isinstance(value, ClusterRole):
            return value
        key = str(value).strip().lower()
        for member in cls:
            if member.value == key:
                return member
        raise ConfigError(f"Unknown cluster role: {value!r}")


@dataclass
class ClusterConfig:
    """Runtime configuration for the cluster subsystem.

    Attributes:
        enabled: When ``False``, the subsystem is dormant. Even a node
            role with a missing uplink target stays disabled rather than
            crashing the engine.
        role: Process role. Defaults to ``node``.
        node_id: Stable identity of this node. Generated on first
            registration when absent.
        controller_url: Base URL of the controller, including scheme.
            Required for ``node`` and ``mixed`` (mixed posts to itself
            for testability).
        api_key: API token used by the uplink. Must be a ``htk_``-prefixed
            token whose role on the controller is ``node``.
        heartbeat_interval: Seconds between heartbeats. Stale detection
            uses 3x this interval.
        event_batch_size: Maximum number of events forwarded per POST.
        event_flush_interval: Maximum seconds between flushes regardless
            of batch size. Bounds end-to-end latency.
        tls_verify: When ``True`` (default) the urllib client verifies
            controller TLS certificates. Disabling is a debug-only path
            and emits a warning.
        spool_max_events: Hard cap on the bounded in-memory spool.
        spool_max_disk_bytes: Hard cap on the SQLite spillover file.
    """

    enabled: bool = False
    role: ClusterRole = ClusterRole.NODE
    node_id: str | None = None
    controller_url: str | None = None
    api_key: str | None = None
    heartbeat_interval: float = 30.0
    event_batch_size: int = 200
    event_flush_interval: float = 5.0
    tls_verify: bool = True
    spool_max_events: int = 10_000
    spool_max_disk_bytes: int = 64 * 1024 * 1024
    tags: list[str] = field(default_factory=list)

    def validate(self) -> None:
        """Raise :class:`ConfigError` on any structural problem.

        The check is exhaustive so misconfigurations are caught at boot
        rather than the first uplink RPC.
        """
        if not self.enabled:
            return
        if self.heartbeat_interval <= 0:
            raise ConfigError("cluster.heartbeat_interval must be > 0")
        if self.event_batch_size <= 0:
            raise ConfigError("cluster.event_batch_size must be > 0")
        if self.event_flush_interval <= 0:
            raise ConfigError("cluster.event_flush_interval must be > 0")
        if self.spool_max_events <= 0:
            raise ConfigError("cluster.spool_max_events must be > 0")
        if self.spool_max_disk_bytes <= 0:
            raise ConfigError("cluster.spool_max_disk_bytes must be > 0")
        if self.role in (ClusterRole.NODE, ClusterRole.MIXED):
            if not self.controller_url:
                raise ConfigError(
                    f"cluster.controller_url is required for role {self.role.value!r}"
                )
            split = urlsplit(self.controller_url)
            if split.scheme not in ("http", "https"):
                raise ConfigError(
                    "cluster.controller_url must use http:// or https:// "
                    f"(got {self.controller_url!r})"
                )
            if not split.netloc:
                raise ConfigError("cluster.controller_url is missing a host")
            if self.role is ClusterRole.NODE and not self.api_key:
                raise ConfigError("cluster.api_key is required for role 'node'")
            if self.api_key and not self.api_key.startswith("htk_"):
                raise ConfigError(
                    "cluster.api_key must be a htk_-prefixed token (matches API key store)"
                )
        if self.node_id is not None and not _NODE_ID_RE.match(self.node_id):
            raise ConfigError("cluster.node_id must match [A-Za-z0-9._-]{1,64}")

    @property
    def is_controller(self) -> bool:
        """True for ``controller`` and ``mixed`` roles."""
        return self.role in (ClusterRole.CONTROLLER, ClusterRole.MIXED)

    @property
    def is_node(self) -> bool:
        """True for ``node`` and ``mixed`` roles (mixed forwards locally)."""
        return self.role in (ClusterRole.NODE, ClusterRole.MIXED)


def parse_cluster_config(data: Any) -> ClusterConfig:
    """Parse the ``cluster:`` YAML block into a :class:`ClusterConfig`.

    Unknown keys are ignored after a single warning to mirror the rest of
    the loader. ``enabled`` defaults to ``False`` so existing single-node
    deployments are unaffected. Tags are coerced to a list of strings.
    """
    cfg = ClusterConfig()
    if data is None:
        return cfg
    if not isinstance(data, dict):
        raise ConfigError("cluster: section must be a mapping")
    if "enabled" in data:
        cfg.enabled = bool(data["enabled"])
    if "role" in data:
        cfg.role = ClusterRole.from_str(str(data["role"]))
    if "node_id" in data and data["node_id"] is not None:
        cfg.node_id = str(data["node_id"]).strip() or None
    if "controller_url" in data and data["controller_url"] is not None:
        cfg.controller_url = str(data["controller_url"]).strip() or None
    if "api_key" in data and data["api_key"] is not None:
        cfg.api_key = str(data["api_key"]).strip() or None
    if "heartbeat_interval" in data:
        cfg.heartbeat_interval = float(data["heartbeat_interval"])
    if "event_batch_size" in data:
        cfg.event_batch_size = int(data["event_batch_size"])
    if "event_flush_interval" in data:
        cfg.event_flush_interval = float(data["event_flush_interval"])
    if "tls_verify" in data:
        cfg.tls_verify = bool(data["tls_verify"])
    if "spool_max_events" in data:
        cfg.spool_max_events = int(data["spool_max_events"])
    if "spool_max_disk_bytes" in data:
        cfg.spool_max_disk_bytes = int(data["spool_max_disk_bytes"])
    if "tags" in data and isinstance(data["tags"], list):
        cfg.tags = [str(t) for t in data["tags"] if isinstance(t, (str, int, float))]
    cfg.validate()
    return cfg
