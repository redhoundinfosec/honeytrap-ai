"""Tests for ECS, Elasticsearch, Splunk HEC, and file_jsonl sinks."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from honeytrap.sinks import (
    ElasticsearchConfig,
    ElasticsearchSink,
    FileJsonlConfig,
    FileJsonlSink,
    OpenSearchSink,
    SplunkHecConfig,
    SplunkHecSink,
    build_sink,
    event_to_ecs,
    render_bulk_payload,
    render_hec_payload,
)
from honeytrap.sinks._http import HttpError, HttpResponse

# ---------------------------------------------------------------------------
# ECS mapping
# ---------------------------------------------------------------------------


def test_event_to_ecs_basic_mapping() -> None:
    out = event_to_ecs(
        {
            "session_id": "abc",
            "protocol": "ssh",
            "source_ip": "203.0.113.5",
            "source_port": 12345,
            "dest_ip": "198.51.100.1",
            "dest_port": 22,
            "bytes_in": 100,
            "bytes_out": 50,
            "timestamp": "2026-04-23T10:00:00.000Z",
            "intel": {"attck": ["T1110"], "iocs": []},
            "tls": {"ja3": "abc", "ja4": "t13d"},
        }
    )
    assert out["@timestamp"] == "2026-04-23T10:00:00.000Z"
    assert out["source"] == {"ip": "203.0.113.5", "port": 12345, "bytes": 100}
    assert out["destination"] == {"ip": "198.51.100.1", "port": 22, "bytes": 50}
    assert out["network"] == {"protocol": "ssh", "transport": "tcp"}
    assert out["tls"]["ja3"] == "abc"
    assert out["honeypot"]["session_id"] == "abc"
    assert out["event"]["module"] == "honeytrap"


def test_event_to_ecs_drops_none_values() -> None:
    out = event_to_ecs({"session_id": "x", "tls": {"ja3": None}})
    assert "tls" not in out


# ---------------------------------------------------------------------------
# Elasticsearch
# ---------------------------------------------------------------------------


def test_render_bulk_payload_emits_action_and_doc() -> None:
    payload = render_bulk_payload(
        [
            {
                "session_id": "a",
                "protocol": "ssh",
                "source_ip": "1.2.3.4",
                "timestamp": "2026-04-23T10:00:00.000Z",
            }
        ],
        index="honeytrap-events-2026.04.23",
    )
    lines = payload.decode("utf-8").rstrip("\n").split("\n")
    assert json.loads(lines[0]) == {"index": {"_index": "honeytrap-events-2026.04.23"}}
    doc = json.loads(lines[1])
    assert doc["honeypot"]["session_id"] == "a"


@pytest.mark.asyncio
async def test_elasticsearch_sink_posts_bulk(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    async def _fake_post(url: str, body: bytes, **kwargs: Any) -> HttpResponse:
        captured.setdefault("calls", []).append((url, body, kwargs))
        return HttpResponse(status=200, body=b'{"took":1,"errors":false}', headers={})

    monkeypatch.setattr("honeytrap.sinks.elasticsearch.post_json", _fake_post)
    cfg = ElasticsearchConfig(
        url="https://es.example",
        index="honeytrap-events-{+YYYY.MM.dd}",
        install_template=False,
    )
    sink = ElasticsearchSink(cfg)
    await sink.send_batch([{"session_id": "a", "protocol": "ssh", "source_ip": "1.2.3.4"}])
    calls = captured["calls"]
    assert calls[0][0].endswith("/_bulk")


@pytest.mark.asyncio
async def test_elasticsearch_sink_honors_retry_after_on_429(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slept: list[float] = []

    async def _fake_post(*_a: Any, **_kw: Any) -> HttpResponse:
        raise HttpError(429, "throttled", retry_after=2.0)

    async def _fake_sleep(value: float) -> None:
        slept.append(value)

    monkeypatch.setattr("honeytrap.sinks.elasticsearch.post_json", _fake_post)
    monkeypatch.setattr(
        "honeytrap.sinks.elasticsearch.sleep_for_retry_after", lambda r, default: _fake_sleep(r)
    )
    cfg = ElasticsearchConfig(url="https://es.example", install_template=False)
    sink = ElasticsearchSink(cfg)
    with pytest.raises(HttpError):
        await sink.send_batch([{"session_id": "a"}])
    assert slept == [2.0]


@pytest.mark.asyncio
async def test_elasticsearch_sink_raises_on_partial_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _fake_post(*_a: Any, **_kw: Any) -> HttpResponse:
        return HttpResponse(status=200, body=b'{"errors":true,"items":[]}', headers={})

    monkeypatch.setattr("honeytrap.sinks.elasticsearch.post_json", _fake_post)
    cfg = ElasticsearchConfig(url="https://es.example", install_template=False)
    sink = ElasticsearchSink(cfg)
    with pytest.raises(HttpError):
        await sink.send_batch([{"session_id": "a"}])


def test_opensearch_sink_inherits_from_elasticsearch() -> None:
    sink = OpenSearchSink(ElasticsearchConfig(url="https://os.example"))
    assert sink.name == "opensearch"


# ---------------------------------------------------------------------------
# Splunk HEC
# ---------------------------------------------------------------------------


def test_render_hec_payload_wraps_envelope() -> None:
    cfg = SplunkHecConfig(url="https://splunk", index="main", host="hp")
    body = render_hec_payload([{"session_id": "a", "timestamp": "2026-04-23T10:00:00.000Z"}], cfg)
    parsed = json.loads(body.decode("utf-8"))
    assert parsed["index"] == "main"
    assert parsed["host"] == "hp"
    assert parsed["sourcetype"] == "honeytrap:event"
    assert parsed["event"]["honeypot"]["session_id"] == "a"


@pytest.mark.asyncio
async def test_splunk_hec_sink_requires_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SPLUNK_HEC_TOKEN", raising=False)
    sink = SplunkHecSink(SplunkHecConfig(url="https://splunk"))
    with pytest.raises(RuntimeError):
        await sink.send_batch([{"a": 1}])


@pytest.mark.asyncio
async def test_splunk_hec_sink_posts_with_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    async def _fake_post(url: str, body: bytes, **kwargs: Any) -> HttpResponse:
        captured.update({"url": url, "headers": kwargs.get("headers", {})})
        return HttpResponse(status=200, body=b'{"text":"Success","code":0}', headers={})

    monkeypatch.setattr("honeytrap.sinks.splunk_hec.post_json", _fake_post)
    monkeypatch.setenv("SPLUNK_HEC_TOKEN", "tok123")
    sink = SplunkHecSink(SplunkHecConfig(url="https://splunk"))
    await sink.send_batch([{"session_id": "a"}])
    assert captured["url"].endswith("/services/collector/event")
    assert captured["headers"]["Authorization"] == "Splunk tok123"


@pytest.mark.asyncio
async def test_splunk_hec_sink_raises_on_non_zero_code(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _fake_post(*_a: Any, **_kw: Any) -> HttpResponse:
        return HttpResponse(status=200, body=b'{"text":"Bad","code":13}', headers={})

    monkeypatch.setattr("honeytrap.sinks.splunk_hec.post_json", _fake_post)
    monkeypatch.setenv("SPLUNK_HEC_TOKEN", "x")
    sink = SplunkHecSink(SplunkHecConfig(url="https://splunk"))
    with pytest.raises(HttpError):
        await sink.send_batch([{"a": 1}])


# ---------------------------------------------------------------------------
# file_jsonl
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_file_jsonl_writes_ndjson(tmp_path: Path) -> None:
    sink = FileJsonlSink(FileJsonlConfig(path=str(tmp_path)))
    await sink.send_batch([{"session_id": "a", "protocol": "ssh"}])
    files = list(tmp_path.glob("*.jsonl"))
    assert len(files) == 1
    content = files[0].read_text(encoding="utf-8")
    assert content.endswith("\n")
    assert "session_id" in content


@pytest.mark.asyncio
async def test_file_jsonl_rotates_on_day_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sink = FileJsonlSink(FileJsonlConfig(path=str(tmp_path)))

    class _Clock:
        def __init__(self) -> None:
            self._t = datetime(2026, 4, 23, 23, 59, tzinfo=timezone.utc)

        def now(self, tz: Any = None) -> datetime:
            return self._t

    clock = _Clock()
    monkeypatch.setattr("honeytrap.sinks.file_jsonl.datetime", _PatchedDateTime(clock))
    await sink.send_batch([{"session_id": "a"}])
    clock._t = datetime(2026, 4, 24, 0, 1, tzinfo=timezone.utc)
    await sink.send_batch([{"session_id": "b"}])
    files = sorted(p.name for p in tmp_path.glob("*.jsonl"))
    assert files == [
        "honeytrap-2026-04-23.jsonl",
        "honeytrap-2026-04-24.jsonl",
    ]


class _PatchedDateTime:
    """Datetime stand-in that calls ``clock.now(tz)``."""

    def __init__(self, clock: Any) -> None:
        self._clock = clock

    def __getattr__(self, name: str) -> Any:
        return getattr(datetime, name)

    def now(self, tz: Any = None) -> datetime:
        return self._clock.now(tz)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def test_build_sink_factory_dispatch() -> None:
    es = build_sink({"type": "elasticsearch", "url": "https://es.example"})
    assert es.name == "elasticsearch"
    splunk = build_sink({"type": "splunk_hec", "url": "https://splunk", "name": "siem"})
    assert splunk.name == "siem"
    fjsonl = build_sink({"type": "file_jsonl", "path": "/tmp/jsonl-x"})
    assert fjsonl.name == "file_jsonl"
    with pytest.raises(ValueError):
        build_sink({"type": "redis"})
    with pytest.raises(ValueError):
        build_sink({"type": "elasticsearch"})  # missing url
