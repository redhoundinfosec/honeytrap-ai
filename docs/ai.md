# Adaptive AI Layer

HoneyTrap's adaptive AI layer gives every protocol handler a per-attacker
memory, a deterministic intent classifier, and a pluggable backend chain
so responses can become progressively more convincing without ever
stalling on an LLM outage.

```
 inbound bytes
      |
      v
 +----------------+       hit       +------------------+
 | ResponseCache  |---------------->| shape-validated  |
 +----------------+                 | bytes            |
      | miss                        +------------------+
      v                                      ^
 +----------------+                          |
 | classify()     |   intent + rationale     |
 +----------------+                          |
      |                                      |
      v                                      |
 +----------------+   +----------+    +------+-------+
 | ChainBackend   |-->| openai / |--> | Template     |
 |                |   | anthropic|    | fallback     |
 |                |   | ollama   |    | (always-on)  |
 +----------------+   +----------+    +--------------+
```

## Components

- `SessionMemory` keeps the rolling view of a single attacker session:
  commands, auth attempts, uploaded files, ATT&CK techniques,
  protocol history, and per-backend latency.
- `classify()` returns `(IntentLabel, confidence, rationale[:3])` from
  heuristic signals — no LLM required.
- `ResponseCache` is an LRU with TTL, keyed on
  `(protocol, normalized_inbound, memory_hash)`.
- `ChainBackend` tries each configured backend in order; a final
  `TemplateBackend` is always appended so a response is guaranteed.
- `ProtocolResponder.get_response()` is the single entry point.
  Protocol handlers call it via `BaseProtocol.adaptive_response()`.

## Intent labels

`RECON`, `BRUTE_FORCE`, `EXPLOIT_ATTEMPT`, `CREDENTIAL_HARVEST`,
`LATERAL_MOVEMENT`, `EXFILTRATION`, `PERSISTENCE`, `COIN_MINING`,
`WEB_SHELL`, `UNKNOWN`. The high-severity subset
(`EXPLOIT_ATTEMPT`, `EXFILTRATION`, `COIN_MINING`, `WEB_SHELL`,
`PERSISTENCE`) triggers a one-shot alert on transition.

## Configuration

```yaml
ai:
  adaptive_enabled: true
  memory_store: "sqlite"          # or "memory"
  memory_cap_ips: 10000
  memory_cap_sessions_per_ip: 20
  intent_enabled: true
  cache_enabled: true
  cache_capacity: 5000
  cache_ttl_seconds: 1800
  redact_secrets_in_prompts: true
  backends:
    - name: "openai"
      model: "gpt-4o-mini"
    - name: "ollama"
      model: "llama3.1:8b"
```

Environment overrides: `HONEYTRAP_AI_ADAPTIVE=1`,
`HONEYTRAP_AI_FORCE_BACKEND=template`.

CLI flags: `--ai-enabled / --no-ai`, `--ai-backend NAME`,
`--ai-dry-run`. The subcommand `honeytrap ai test` runs one synthetic
exchange per protocol against the configured chain.

## Safety controls

- Every prompt goes through `redact_prompt()` before leaving the
  process (passwords, bearer tokens, AWS keys, PEM blocks).
- Responses containing AI self-reference phrases (`"as an AI"`,
  `"language model"`, vendor names) are vetoed and the chain falls
  through to the template backend.
- HTTP status lines, SMTP 3-digit codes, and UTF-8 SSH output are
  shape-validated; anything that doesn't look like a valid wire
  response is replaced with the template.
- Every HTTP call has a mandatory timeout. The retry policy is
  bounded: one initial attempt plus two backoffs (0.5 s, 1.5 s).

## API endpoints

- `GET /api/v1/sessions/{id}/memory` — return the memory snapshot
  for one session (viewer role).
- `GET /api/v1/intel/intents` — histogram of classified intents.
- `GET /api/v1/ai/backends` — health and call counts per backend.

## Metrics

- `honeytrap_ai_cache_hit_ratio` (gauge)
- `honeytrap_ai_intent_total{label=...}` (counter)
- `honeytrap_ai_backend_used_total{backend=...}` (counter)
- `honeytrap_ai_memory_sessions` (gauge)
- `honeytrap_ai_memory_evictions_total` (counter)

## Per-protocol adapters (Cycle 16)

The per-protocol adapter package
(`src/honeytrap/ai/adapters/`) extends adaptive AI from SSH-only to
HTTP, SMTP, Telnet, and FTP. Each adapter implements four hooks:

- `template_response(prompt)` — deterministic, zero-network fallback
  that always succeeds and always produces a wire-correct response.
- `validate_shape(response)` — protocol-shape validator that scrubs
  output that would corrupt the wire dialogue (HTTP `Content-Length`,
  SMTP `\d{3}[ -]<text>\r\n`, FTP multi-line continuation, etc.).
- `cache_key(prompt)` — protocol-aware cache key (HTTP method+path,
  SMTP verb+target, Telnet command+cwd, FTP verb+profile, ...).
- `safety_filter(response, prompt)` — opsec scrub shared across all
  adapters: strips attacker-supplied secrets, JWT/PEM/AWS keys,
  internal hostnames/paths, and dashboard-targeting escape codes.

The adapter pipeline is identical to the SSH path:

```
ResponseCache -> classify() -> ChainBackend -> validate_shape()
              -> safety_filter() -> wire bytes
```

Per-protocol toggles live under `ai.adapters.<protocol>`:

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

When a safety filter trims output, an `ai_safety` event is emitted
with `protocol`, `reasons[]`, and a 128-byte sample of the original
content. Operators can wire this into the alerts subsystem for
real-time leak monitoring.
