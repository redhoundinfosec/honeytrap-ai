# SIEM Log Sinks

HoneyTrap ships pluggable, asynchronous log sinks for shipping events to
SIEM and analytics back-ends. Four sinks are bundled:

- `elasticsearch` — bulk-index to Elasticsearch using the `_bulk` API.
- `opensearch` — same wire format, different default name.
- `splunk_hec` — Splunk HTTP Event Collector (`/services/collector/event`).
- `file_jsonl` — daily-rotated newline-delimited JSON files.

All sinks share a common delivery pipeline that gives them backpressure,
retry with exponential backoff, and a per-sink circuit breaker.

## Pipeline guarantees

```
producer -> queue (bounded) -> batcher -> retry/breaker -> sink
```

| Component | Default | Knob |
| --- | --- | --- |
| Queue capacity | 10,000 events | `sinks.queue_capacity` |
| Overflow policy | `drop_oldest` | `sinks.on_overflow` (`drop_oldest`, `drop_new`, `block`) |
| Batch size | 500 events | per-sink `batch_size` |
| Batch window | 1.0 s | per-sink `batch_window_seconds` |
| Retry backoff | 0.25 s -> 30 s, 5 attempts, jitter 10 % | `RetryPolicy` |
| Circuit breaker | open after 10 failures, cooldown 30 s | `CircuitBreaker` |

`drop_oldest` is the default because keeping the *newest* events is what
SOCs want during a flood; switch to `block` only when you're certain the
producer can pause.

## Configuration

```yaml
sinks:
  enabled: true
  queue_capacity: 10000
  on_overflow: drop_oldest
  targets:
    - type: elasticsearch
      name: es-prod
      url: https://es.example
      index: "honeytrap-events-{+YYYY.MM.dd}"
      api_key_env: ES_API_KEY
      install_template: true
    - type: splunk_hec
      name: splunk
      url: https://splunk.example
      token_env: SPLUNK_HEC_TOKEN
      index: main
      host: honeytrap-1
    - type: file_jsonl
      name: cold-storage
      path: /var/log/honeytrap/jsonl
```

Secrets are **never** read from the YAML. Each sink resolves credentials at
request time from the named environment variable. If the variable is unset
the sink raises a `RuntimeError` instead of sending blank credentials.

## ECS mapping

`elasticsearch`, `opensearch`, and `file_jsonl` (by default) project events
onto the [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current).
Source/destination IPs land under `source.*` / `destination.*`, the
honeypot-specific fields go under a `honeypot.*` namespace, and ATT&CK plus
IOC context lives at `intel.*`. None values are stripped to keep
documents compact.

## Index templates

If `install_template: true`, the Elasticsearch sink installs a template at
boot (idempotent) so dynamic field mapping doesn't explode on the first
ingest. The template targets the configured `index` pattern (with
`{+YYYY.MM.dd}` rolled to the current day for the alias).

## Splunk HEC

The HEC envelope is built per-event:

```json
{
  "time": 1714069200.123,
  "host": "honeytrap-1",
  "source": "honeytrap",
  "sourcetype": "honeytrap:event",
  "index": "main",
  "event": { ...ECS fields... }
}
```

The sink retries on 429 / 5xx and surfaces non-zero `code` values from
`/services/collector/event` as errors.

## file_jsonl rotation

Each day rolls the active file to `<prefix>-YYYY-MM-DD.jsonl`. Writes are
serialized through an `asyncio.Lock` so concurrent batches don't interleave
records. Files are flushed on every batch — there is no buffering at the OS
layer beyond the kernel page cache.

## CLI

```bash
honeytrap sinks test es-prod      # send a synthetic event through es-prod
honeytrap sinks health --json     # JSON snapshot of every sink
```

`sinks test` exits non-zero with a descriptive message if the named sink is
not configured or the round trip fails.

## Metrics

Per-sink counters and gauges:

- `honeytrap_sink_events_total{sink}` — successfully delivered batches.
- `honeytrap_sink_dropped_total{sink, reason}` — `drop_oldest` / `drop_new`.
- `honeytrap_sink_send_duration_seconds{sink}` — histogram.
- `honeytrap_sink_queue_depth{sink}` — gauge.
- `honeytrap_sink_circuit_state{sink}` — 0 closed, 1 half-open, 2 open.

## API

- `GET /api/v1/sinks` (viewer) — current health of every configured sink.
- `POST /api/v1/sinks/{name}/flush` (admin) — force-flush a single sink.
