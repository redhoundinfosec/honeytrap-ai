"""Splunk HTTP Event Collector (HEC) sink.

Splunk HEC accepts batched events as concatenated JSON objects (one
envelope per event). The HEC token is read from an env-var named in
the config so it never lives on disk. Each event is wrapped in the
standard ``{time, host, source, sourcetype, index, event}`` envelope.
"""

from __future__ import annotations

import json
import logging
import os
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from honeytrap.sinks._http import (
    DEFAULT_TIMEOUT_SECONDS,
    HttpError,
    post_json,
    sleep_for_retry_after,
)
from honeytrap.sinks.ecs import event_to_ecs
from honeytrap.sinks.sink_base import Sink

logger = logging.getLogger(__name__)


@dataclass
class SplunkHecConfig:
    """Configuration for :class:`SplunkHecSink`."""

    url: str
    token_env: str = "SPLUNK_HEC_TOKEN"
    index: str | None = "main"
    sourcetype: str = "honeytrap:event"
    source: str = "honeytrap"
    host: str | None = None
    tls_verify: bool = True
    ca_cert: str | None = None
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS


def _epoch(timestamp: str | None) -> float:
    """Parse an ISO timestamp into Unix epoch seconds, fallback to now()."""
    if timestamp:
        try:
            cleaned = timestamp.rstrip("Z")
            dt = datetime.fromisoformat(cleaned)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            pass
    return datetime.now(timezone.utc).timestamp()


def render_hec_payload(events: list[dict[str, Any]], config: SplunkHecConfig) -> bytes:
    """Render a list of events as Splunk HEC concatenated JSON objects."""
    host = config.host or socket.gethostname()
    chunks: list[str] = []
    for event in events:
        envelope = {
            "time": _epoch(event.get("@timestamp") or event.get("timestamp")),
            "host": host,
            "source": config.source,
            "sourcetype": config.sourcetype,
            "event": event_to_ecs(event),
        }
        if config.index:
            envelope["index"] = config.index
        chunks.append(json.dumps(envelope, separators=(",", ":"), sort_keys=True))
    return "\n".join(chunks).encode("utf-8")


class SplunkHecSink(Sink):
    """Splunk HEC sink with envelope wrapping and Retry-After support."""

    def __init__(self, config: SplunkHecConfig, *, name: str = "splunk_hec") -> None:
        """Store config; the HEC token is resolved on every send."""
        super().__init__(name=name)
        self.config = config

    async def send_batch(self, batch: list[dict[str, Any]]) -> None:
        """POST the rendered envelope batch to ``/services/collector/event``."""
        if not batch:
            return
        token = os.environ.get(self.config.token_env, "").strip()
        if not token:
            raise RuntimeError(
                f"Splunk HEC token env var {self.config.token_env!r} is empty; refusing to send"
            )
        url = self.config.url.rstrip("/") + "/services/collector/event"
        body = render_hec_payload(batch, self.config)
        headers = {
            "Authorization": f"Splunk {token}",
            "Content-Type": "application/json",
        }
        try:
            response = await post_json(
                url,
                body,
                headers=headers,
                timeout=self.config.timeout_seconds,
                verify_tls=self.config.tls_verify,
                ca_cert=self.config.ca_cert,
            )
        except HttpError as exc:
            if exc.status == 429:
                await sleep_for_retry_after(exc.retry_after, default=1.0)
            raise
        # HEC returns {"text":"Success","code":0}; non-zero code => failure.
        if response.body:
            try:
                parsed = json.loads(response.body)
            except json.JSONDecodeError:
                return
            if isinstance(parsed, dict) and parsed.get("code", 0) != 0:
                raise HttpError(
                    response.status,
                    f"HEC reported error {parsed.get('code')}: {parsed.get('text', '')}",
                )
