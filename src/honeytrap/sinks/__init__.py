"""Pluggable log sinks for SIEM integration.

The package exposes a sink registry and factory used by the runtime
to build pipelines from declarative config. Each sink is independent
of the others and can be tested in isolation -- :mod:`pipeline`
provides shared backpressure, batching, and retry support.
"""

from __future__ import annotations

from typing import Any

from honeytrap.sinks.batcher import Batcher
from honeytrap.sinks.ecs import event_to_ecs
from honeytrap.sinks.elasticsearch import (
    ElasticsearchConfig,
    ElasticsearchSink,
    render_bulk_payload,
)
from honeytrap.sinks.file_jsonl import FileJsonlConfig, FileJsonlSink
from honeytrap.sinks.opensearch import OpenSearchSink
from honeytrap.sinks.pipeline import LogPipeline, OverflowPolicy
from honeytrap.sinks.retry import (
    BreakerState,
    CircuitBreaker,
    RetryPolicy,
    execute_with_retry,
)
from honeytrap.sinks.sink_base import Sink, SinkHealth
from honeytrap.sinks.splunk_hec import SplunkHecConfig, SplunkHecSink, render_hec_payload


def build_sink(spec: dict[str, Any]) -> Sink:
    """Construct a sink from a single ``targets`` config entry.

    Raises:
        ValueError: when the type is unknown or required fields are missing.
    """
    sink_type = str(spec.get("type", "")).lower()
    name = str(spec.get("name") or sink_type)
    if sink_type in {"elasticsearch", "es"}:
        return ElasticsearchSink(_es_config(spec), name=name)
    if sink_type == "opensearch":
        return OpenSearchSink(_es_config(spec), name=name)
    if sink_type in {"splunk", "splunk_hec"}:
        return SplunkHecSink(_splunk_config(spec), name=name)
    if sink_type in {"file", "file_jsonl"}:
        return FileJsonlSink(_file_config(spec), name=name)
    raise ValueError(f"Unknown sink type: {sink_type!r}")


def _es_config(spec: dict[str, Any]) -> ElasticsearchConfig:
    if not spec.get("url"):
        raise ValueError("Elasticsearch sink requires a 'url'")
    return ElasticsearchConfig(
        url=str(spec["url"]),
        index=str(spec.get("index", "honeytrap-events-{+YYYY.MM.dd}")),
        username_env=spec.get("username_env"),
        password_env=spec.get("password_env"),
        api_key_env=spec.get("api_key_env"),
        tls_verify=bool(spec.get("tls_verify", True)),
        ca_cert=spec.get("ca_cert"),
        timeout_seconds=float(spec.get("timeout_seconds", 10.0)),
        template_name=str(spec.get("template_name", "honeytrap-events")),
        install_template=bool(spec.get("install_template", True)),
    )


def _splunk_config(spec: dict[str, Any]) -> SplunkHecConfig:
    if not spec.get("url"):
        raise ValueError("Splunk HEC sink requires a 'url'")
    return SplunkHecConfig(
        url=str(spec["url"]),
        token_env=str(spec.get("token_env", "SPLUNK_HEC_TOKEN")),
        index=spec.get("index"),
        sourcetype=str(spec.get("sourcetype", "honeytrap:event")),
        source=str(spec.get("source", "honeytrap")),
        host=spec.get("host"),
        tls_verify=bool(spec.get("tls_verify", True)),
        ca_cert=spec.get("ca_cert"),
        timeout_seconds=float(spec.get("timeout_seconds", 10.0)),
    )


def _file_config(spec: dict[str, Any]) -> FileJsonlConfig:
    if not spec.get("path"):
        raise ValueError("file_jsonl sink requires a 'path'")
    return FileJsonlConfig(
        path=spec["path"],
        prefix=str(spec.get("prefix", "honeytrap")),
        use_ecs=bool(spec.get("use_ecs", True)),
    )


__all__ = [
    "Batcher",
    "BreakerState",
    "CircuitBreaker",
    "ElasticsearchConfig",
    "ElasticsearchSink",
    "FileJsonlConfig",
    "FileJsonlSink",
    "LogPipeline",
    "OpenSearchSink",
    "OverflowPolicy",
    "RetryPolicy",
    "Sink",
    "SinkHealth",
    "SplunkHecConfig",
    "SplunkHecSink",
    "build_sink",
    "event_to_ecs",
    "execute_with_retry",
    "render_bulk_payload",
    "render_hec_payload",
]
