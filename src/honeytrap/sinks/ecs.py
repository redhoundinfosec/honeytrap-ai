"""Map internal honeypot events to Elastic Common Schema (ECS) fields.

ECS gives Elastic and OpenSearch users a stable, dotted field
namespace. This module produces a flat dict using the v8.x conventions
the SIEM tier expects. Internal field names that don't have an ECS
equivalent are nested under a ``honeypot.*`` namespace so the original
context is preserved without polluting reserved ECS fields.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _iso(value: Any) -> str:
    """Coerce datetime/string into an ISO 8601 timestamp."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    if isinstance(value, str) and value:
        return value
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def event_to_ecs(event: dict[str, Any]) -> dict[str, Any]:
    """Project an internal event onto the ECS field set.

    The function is intentionally permissive: missing fields just don't
    appear in the output. Callers feed this into the ES/OpenSearch
    sink, which expects a flat dict of JSON-serialisable values.
    """
    timestamp = _iso(event.get("timestamp") or event.get("@timestamp") or event.get("started_at"))
    src_ip = event.get("source_ip") or event.get("remote_ip")
    dst_ip = event.get("dest_ip") or event.get("destination_ip")
    src_port = event.get("source_port") or event.get("remote_port")
    dst_port = event.get("dest_port") or event.get("local_port")
    protocol = event.get("protocol")
    kind = event.get("kind") or event.get("event_kind") or "session"
    action = event.get("action") or event.get("description")

    out: dict[str, Any] = {
        "@timestamp": timestamp,
        "event": {
            "kind": "event",
            "category": ["intrusion_detection"],
            "type": ["info"],
            "module": "honeytrap",
            "dataset": f"honeytrap.{protocol or kind}",
        },
        "honeypot": {
            "session_id": event.get("session_id"),
            "kind": kind,
            "node": event.get("node") or event.get("hostname"),
        },
    }
    if action:
        out["event"]["action"] = str(action)[:512]
    if src_ip:
        out["source"] = {"ip": str(src_ip)}
        if src_port:
            out["source"]["port"] = int(src_port)
    if dst_ip or dst_port:
        out["destination"] = {}
        if dst_ip:
            out["destination"]["ip"] = str(dst_ip)
        if dst_port:
            out["destination"]["port"] = int(dst_port)
    if protocol:
        out["network"] = {"protocol": str(protocol).lower(), "transport": "tcp"}
    if "bytes_in" in event:
        out.setdefault("source", {})["bytes"] = int(event["bytes_in"])
    if "bytes_out" in event:
        out.setdefault("destination", {})["bytes"] = int(event["bytes_out"])
    intel = event.get("intel") or {}
    if intel:
        out["intel"] = {
            "attck": intel.get("attck") or [],
            "iocs": intel.get("iocs") or [],
        }
    tls = event.get("tls") or {}
    if tls:
        out["tls"] = {
            "ja3": tls.get("ja3"),
            "ja4": tls.get("ja4"),
            "label": tls.get("label"),
        }
    extra = event.get("extra") or {}
    if extra and isinstance(extra, dict):
        out["honeypot"]["extra"] = dict(extra)
    return _strip_none(out)


def _strip_none(obj: Any) -> Any:
    """Recursively drop None values and empty containers to keep ECS records compact."""
    if isinstance(obj, dict):
        cleaned = {k: _strip_none(v) for k, v in obj.items() if v is not None}
        return {k: v for k, v in cleaned.items() if v != {} and v != []}
    if isinstance(obj, list):
        return [_strip_none(x) for x in obj if x is not None]
    return obj
