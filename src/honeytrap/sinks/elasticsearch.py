"""Elasticsearch / OpenSearch bulk sink.

Each batch is rendered as NDJSON (action+document pairs) and POSTed to
``/_bulk``. The index name supports the ECS-style ``{+YYYY.MM.dd}``
date placeholder so daily rolling indices are easy to set up. Auth
credentials are read exclusively from environment variables so they
are never persisted in config files.

429 ``Retry-After`` is honored through a single in-line sleep before
re-raising so the pipeline's retry policy uses fresh backoff after.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
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

_DATE_PLACEHOLDER_RE = re.compile(r"\{\+([^}]+)\}")
_INDEX_TEMPLATE_BODY: dict[str, Any] = {
    "index_patterns": ["honeytrap-events-*"],
    "template": {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "event": {"type": "object"},
                "honeypot": {"type": "object", "dynamic": True},
                "source": {
                    "properties": {
                        "ip": {"type": "ip"},
                        "port": {"type": "long"},
                        "bytes": {"type": "long"},
                    }
                },
                "destination": {
                    "properties": {
                        "ip": {"type": "ip"},
                        "port": {"type": "long"},
                        "bytes": {"type": "long"},
                    }
                },
                "tls": {
                    "properties": {
                        "ja3": {"type": "keyword"},
                        "ja4": {"type": "keyword"},
                        "label": {"type": "keyword"},
                    }
                },
            }
        },
    },
}


@dataclass
class ElasticsearchConfig:
    """Configuration block for :class:`ElasticsearchSink`."""

    url: str
    index: str = "honeytrap-events-{+YYYY.MM.dd}"
    username_env: str | None = "ES_USER"
    password_env: str | None = "ES_PASS"
    api_key_env: str | None = None
    tls_verify: bool = True
    ca_cert: str | None = None
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    template_name: str = "honeytrap-events"
    install_template: bool = True


def _format_index(template: str, *, when: datetime | None = None) -> str:
    """Render ECS-style ``{+YYYY.MM.dd}`` placeholders into a real index name."""
    when = when or datetime.now(timezone.utc)

    def _sub(match: re.Match[str]) -> str:
        fmt = match.group(1)
        py_fmt = (
            fmt.replace("YYYY", "%Y")
            .replace("YY", "%y")
            .replace("MM", "%m")
            .replace("dd", "%d")
            .replace("HH", "%H")
            .replace("mm", "%M")
        )
        return when.strftime(py_fmt)

    return _DATE_PLACEHOLDER_RE.sub(_sub, template)


def _auth_header(config: ElasticsearchConfig) -> dict[str, str]:
    """Build the Authorization header without ever logging it."""
    if config.api_key_env:
        token = os.environ.get(config.api_key_env, "").strip()
        if token:
            return {"Authorization": f"ApiKey {token}"}
    if config.username_env and config.password_env:
        user = os.environ.get(config.username_env, "")
        pwd = os.environ.get(config.password_env, "")
        if user and pwd:
            blob = base64.b64encode(f"{user}:{pwd}".encode()).decode("ascii")
            return {"Authorization": f"Basic {blob}"}
    return {}


def render_bulk_payload(events: list[dict[str, Any]], index: str) -> bytes:
    """Render a list of events as ES ``_bulk`` NDJSON."""
    chunks: list[str] = []
    for event in events:
        ecs = event_to_ecs(event)
        chunks.append(json.dumps({"index": {"_index": index}}, separators=(",", ":")))
        chunks.append(json.dumps(ecs, separators=(",", ":"), sort_keys=True))
    chunks.append("")  # trailing newline
    return "\n".join(chunks).encode("utf-8")


class ElasticsearchSink(Sink):
    """Bulk-API sink for Elasticsearch / OpenSearch."""

    def __init__(self, config: ElasticsearchConfig, *, name: str = "elasticsearch") -> None:
        """Store config and remember whether the index template was installed."""
        super().__init__(name=name)
        self.config = config
        self._template_installed = False

    async def send_batch(self, batch: list[dict[str, Any]]) -> None:
        """Render NDJSON, POST to ``/_bulk``, and honor 429 Retry-After."""
        if not batch:
            return
        if self.config.install_template and not self._template_installed:
            await self._install_template()
        index = _format_index(self.config.index)
        url = self.config.url.rstrip("/") + "/_bulk"
        body = render_bulk_payload(batch, index)
        headers = {"Content-Type": "application/x-ndjson"}
        headers.update(_auth_header(self.config))
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
        if response.body:
            try:
                parsed = json.loads(response.body)
            except json.JSONDecodeError:
                return
            if isinstance(parsed, dict) and parsed.get("errors"):
                raise HttpError(207, "bulk response reported per-item errors")

    async def _install_template(self) -> None:
        """Idempotent index-template install. Failure is logged, never fatal."""
        url = self.config.url.rstrip("/") + f"/_index_template/{self.config.template_name}"
        body = json.dumps(_INDEX_TEMPLATE_BODY).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        headers.update(_auth_header(self.config))
        try:
            await post_json(
                url,
                body,
                headers=headers,
                timeout=self.config.timeout_seconds,
                verify_tls=self.config.tls_verify,
                ca_cert=self.config.ca_cert,
            )
        except HttpError as exc:
            logger.info("ES template install non-fatal failure: %s", exc)
        finally:
            self._template_installed = True
