# Per-protocol adaptive adapters

Cycle 16 introduces a single `BaseAdapter` contract and concrete adapters
for the five protocols that benefit most from adaptive AI: HTTP, SMTP,
Telnet, FTP, and SSH. They share the existing backend chain, response
cache, intent classifier, per-session memory, and safety filter — there
are zero new runtime dependencies.

## Pipeline

```
inbound bytes
   |
   v
ResponseCache  (per-protocol cache_key + 3-turn memory snapshot)
   |
   v
classify()  ->  intent + rationale  ->  SessionMemory.intent
   |
   v
ChainBackend  (template / openai / anthropic / ollama)
   |
   v
validate_shape()  (HTTP CL repair / SMTP \d{3}[ -]<text>\r\n / FTP
                   continuation lines / Telnet NUL strip)
   |
   v
safety_filter()  (passwords / JWTs / PEM / AWS keys / CC-shaped digit
                  runs / internal paths / dashboard ANSI escapes)
   |
   v
wire bytes
```

When the safety filter trims output, an `ai_safety` event is emitted via
`safety_event_callback` with `(protocol, reasons[], 128-byte sample)`.

## Hooks subclasses must implement

| Hook | Responsibility |
| ---- | -------------- |
| `template_response(prompt)` | deterministic, zero-network fallback |
| `validate_shape(response)`  | scrub or empty if wire-invalid |
| `cache_key(prompt)`         | stable key (excluding memory snapshot) |
| `safety_filter(response, prompt)` | optional override of the shared scrub |

## Adapter registry

```python
from honeytrap.ai.adapters import get_adapter

adapter = get_adapter("http", enabled=True)
response = await adapter.respond(session_id, prompt)
```

Canonical names: `http`, `https`, `smtp`, `telnet`, `ftp`, `ssh`.

Plugins can register additional adapters:

```python
from honeytrap.ai.adapters import register_adapter
register_adapter("modbus", MyModbusAdapter)
```

## Configuration

Per-protocol toggles live under `ai.adapters.<protocol>` in
`honeytrap.yaml`:

```yaml
ai:
  enabled: true
  adapters:
    http:    {enabled: true, max_tokens: 512, temperature: 0.3}
    smtp:    {enabled: true, max_tokens: 256, temperature: 0.2}
    telnet:  {enabled: true, max_tokens: 256, temperature: 0.4}
    ftp:     {enabled: true, max_tokens: 128, temperature: 0.2}
    ssh:     {enabled: true, max_tokens: 512, temperature: 0.4}
```

Setting `ai.adapters.<protocol>.enabled: false` keeps that protocol on
the legacy template path; the rest stay adaptive.

## OPSEC

* Inbound prompts go through `redact_prompt()` before forwarding to any
  network backend.
* Responses pass through `validate_shape()` before any cache write.
* Cache keys never include attacker-supplied secrets (digest is over the
  protocol-aware key plus the last three command-history entries).
* `safety_filter()` redacts secret-shaped tokens regardless of which
  backend produced them — the template, the LLM, and the cache hit all
  share the same scrub.
* `_DASHBOARD_ESCAPE` strips a leading ANSI sequence so a malicious
  payload echoed back through the dashboard cannot move the cursor or
  switch terminal modes.
