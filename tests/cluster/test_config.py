"""Tests for ``honeytrap.cluster.config``."""

from __future__ import annotations

import pytest

from honeytrap.cluster.config import ClusterConfig, ClusterRole, parse_cluster_config
from honeytrap.exceptions import ConfigError


def test_disabled_skips_validation() -> None:
    cfg = ClusterConfig(enabled=False)
    cfg.validate()


def test_node_requires_controller_url() -> None:
    cfg = ClusterConfig(enabled=True, role=ClusterRole.NODE, api_key="htk_x")
    with pytest.raises(ConfigError, match="controller_url"):
        cfg.validate()


def test_node_requires_api_key() -> None:
    cfg = ClusterConfig(
        enabled=True,
        role=ClusterRole.NODE,
        controller_url="http://c.local:9300",
    )
    with pytest.raises(ConfigError, match="api_key"):
        cfg.validate()


def test_api_key_must_be_htk_prefixed() -> None:
    cfg = ClusterConfig(
        enabled=True,
        role=ClusterRole.NODE,
        controller_url="http://c.local:9300",
        api_key="not-htk",
    )
    with pytest.raises(ConfigError, match="htk_"):
        cfg.validate()


def test_invalid_url_scheme() -> None:
    cfg = ClusterConfig(
        enabled=True,
        role=ClusterRole.NODE,
        controller_url="ftp://c.local",
        api_key="htk_x",
    )
    with pytest.raises(ConfigError, match="http"):
        cfg.validate()


def test_invalid_node_id() -> None:
    cfg = ClusterConfig(
        enabled=True,
        role=ClusterRole.NODE,
        controller_url="http://c.local",
        api_key="htk_x",
        node_id="bad id with spaces",
    )
    with pytest.raises(ConfigError, match="node_id"):
        cfg.validate()


def test_negative_intervals_rejected() -> None:
    cfg = ClusterConfig(enabled=True, heartbeat_interval=0, role=ClusterRole.CONTROLLER)
    with pytest.raises(ConfigError, match="heartbeat_interval"):
        cfg.validate()
    cfg = ClusterConfig(
        enabled=True,
        role=ClusterRole.CONTROLLER,
        event_batch_size=0,
    )
    with pytest.raises(ConfigError, match="event_batch_size"):
        cfg.validate()
    cfg = ClusterConfig(
        enabled=True,
        role=ClusterRole.CONTROLLER,
        event_flush_interval=-1,
    )
    with pytest.raises(ConfigError, match="event_flush_interval"):
        cfg.validate()
    cfg = ClusterConfig(
        enabled=True,
        role=ClusterRole.CONTROLLER,
        spool_max_events=0,
    )
    with pytest.raises(ConfigError, match="spool_max_events"):
        cfg.validate()
    cfg = ClusterConfig(
        enabled=True,
        role=ClusterRole.CONTROLLER,
        spool_max_disk_bytes=0,
    )
    with pytest.raises(ConfigError, match="spool_max_disk_bytes"):
        cfg.validate()


def test_role_classification() -> None:
    node = ClusterConfig(role=ClusterRole.NODE)
    controller = ClusterConfig(role=ClusterRole.CONTROLLER)
    mixed = ClusterConfig(role=ClusterRole.MIXED)
    assert node.is_node and not node.is_controller
    assert controller.is_controller and not controller.is_node
    assert mixed.is_controller and mixed.is_node


def test_parse_full_block() -> None:
    raw = {
        "enabled": True,
        "role": "controller",
        "node_id": "edge-01",
        "controller_url": "http://c.local:9300",
        "api_key": "htk_abc",
        "heartbeat_interval": 5,
        "event_batch_size": 50,
        "event_flush_interval": 1,
        "tls_verify": False,
        "spool_max_events": 100,
        "spool_max_disk_bytes": 1024,
        "tags": ["edge", "us-east"],
    }
    cfg = parse_cluster_config(raw)
    assert cfg.enabled is True
    assert cfg.role is ClusterRole.CONTROLLER
    assert cfg.node_id == "edge-01"
    assert cfg.heartbeat_interval == 5
    assert cfg.event_batch_size == 50
    assert cfg.tls_verify is False
    assert cfg.tags == ["edge", "us-east"]


def test_parse_none_returns_default() -> None:
    cfg = parse_cluster_config(None)
    assert cfg.enabled is False
    assert cfg.role is ClusterRole.NODE


def test_parse_rejects_non_mapping() -> None:
    with pytest.raises(ConfigError, match="mapping"):
        parse_cluster_config([1, 2, 3])


def test_unknown_role_rejected() -> None:
    with pytest.raises(ConfigError, match="Unknown cluster role"):
        ClusterRole.from_str("guardian")


def test_role_from_str_passthrough() -> None:
    assert ClusterRole.from_str(ClusterRole.NODE) is ClusterRole.NODE
