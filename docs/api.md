# HoneyTrap Management API

The HoneyTrap management API exposes the running honeypot over HTTP under
`/api/v1`. It is designed for dashboards, orchestration scripts, and SOC
tooling. The implementation is stdlib-only (`http.server.ThreadingHTTPServer`
on a background thread), binds to `127.0.0.1` by default, and ships with
API-key auth, RBAC, optional HMAC signing, per-key rate limiting, a gzipped
JSONL audit log, and a self-hosted OpenAPI 3.1 / Rapidoc UI.

## Quickstart

```bash
# 1. Create an admin key (prints plaintext once; store it)
honeytrap api keys create --name ops-admin --role admin

# 2. Start the API on localhost:9300
honeytrap api start --bind 127.0.0.1 --port 9300

# 3. Call it
curl -H "X-API-Key: htk_..." http://127.0.0.1:9300/api/v1/sessions

# 4. Browse the docs
open http://127.0.0.1:9300/api/v1/docs
```

Dump the OpenAPI spec for offline tooling:

```bash
honeytrap api openapi > openapi.json
```

## Security model

The server refuses to start on a non-loopback address unless `--allow-external`
is supplied, and loudly recommends TLS in that case. Default posture:

| Control                | Default                               | Override                  |
| ---------------------- | ------------------------------------- | ------------------------- |
| Bind address           | `127.0.0.1`                           | `--bind`, `--allow-external` |
| TLS                    | off                                   | `--tls-cert`, `--tls-key` |
| HMAC signing required  | off                                   | `--require-hmac`          |
| Body size cap          | 1 MiB                                 | `APIConfig.max_body_bytes` |
| CORS                   | disabled                              | `APIConfig.cors_allow_origins` |
| Rate limits (req/min)  | viewer 60 / analyst 120 / admin 240   | `APIConfig.rate_limits`   |
| Audit log              | `.honeytrap/audit.log.jsonl.gz`       | `state_dir`               |

Response headers applied on every reply:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- `Cache-Control: no-store` on auth-related endpoints
- `Strict-Transport-Security: max-age=63072000; includeSubDomains` when TLS is on

## Authentication

Every non-public route requires an API key. Keys are generated server-side,
start with the prefix `htk_`, and are only shown once in plaintext. The
store persists the SHA-256 digest, never the token. The `id` is a short
random identifier safe to log.

```
Authorization model
  token     = "htk_" + 40 urlsafe base64 chars
  persisted = { id, name, role, prefix, sha256(token) }
  compared  = hmac.compare_digest(stored_hash, sha256(presented))
```

Send the key in the `X-API-Key` header:

```http
GET /api/v1/sessions HTTP/1.1
Host: 127.0.0.1:9300
X-API-Key: htk_abcdef...
```

### Roles

| Role    | Level | Grants                                                   |
| ------- | ----- | -------------------------------------------------------- |
| viewer  | 10    | Read-only: sessions, events, alerts, intel, metrics, profiles, config |
| analyst | 20    | Viewer + timeline/pcap/jsonl export + ack alerts         |
| admin   | 30    | Analyst + reload profile + manage API keys + control (pause/resume/shutdown) |

Role satisfaction is hierarchical: an admin key also satisfies analyst and
viewer. Each non-public route publishes the minimum role via the
`x-required-role` OpenAPI extension.

### HMAC request signing

When `--require-hmac` is set (or the client opts in), every authenticated
request must carry three headers:

- `X-API-Key: htk_...`
- `X-HT-Timestamp: <unix seconds>` — must be within ±300 s of server time
- `X-HT-Signature: <hex>` — HMAC-SHA256 over the canonical string

Canonical form:

```
METHOD|path|timestamp|sha256(body)
```

`path` includes the query string. `body` is the raw request bytes (empty
string when no body). `sha256(body)` is hex-encoded.

Replay protection: every `(key_id, signature)` pair is remembered for 10
minutes in a bounded LRU. Replays within that window are rejected with
`401 replay_detected`.

#### Python signing example

```python
import hashlib, hmac, time, requests

TOKEN = "htk_..."
HOST  = "https://honeypot.internal:9300"

def signed(method: str, path: str, body: bytes = b"") -> requests.Response:
    ts = str(int(time.time()))
    body_hash = hashlib.sha256(body).hexdigest()
    canonical = f"{method}|{path}|{ts}|{body_hash}".encode()
    sig = hmac.new(TOKEN.encode(), canonical, hashlib.sha256).hexdigest()
    return requests.request(
        method,
        HOST + path,
        data=body,
        headers={
            "X-API-Key": TOKEN,
            "X-HT-Timestamp": ts,
            "X-HT-Signature": sig,
        },
    )

r = signed("GET", "/api/v1/sessions")
print(r.status_code, r.json())
```

#### curl signing example

```bash
TOKEN="htk_..."
PATH_="/api/v1/sessions"
TS=$(date +%s)
BODY_HASH=$(printf '' | sha256sum | awk '{print $1}')
CANON="GET|${PATH_}|${TS}|${BODY_HASH}"
SIG=$(printf '%s' "$CANON" | openssl dgst -sha256 -hmac "$TOKEN" | awk '{print $2}')

curl -sS "http://127.0.0.1:9300${PATH_}" \
  -H "X-API-Key: ${TOKEN}" \
  -H "X-HT-Timestamp: ${TS}" \
  -H "X-HT-Signature: ${SIG}"
```

## Endpoint reference

All paths are prefixed with `/api/v1`. Brackets denote path parameters.

### Public (no key required)

| Method | Path            | Purpose                         |
| ------ | --------------- | ------------------------------- |
| GET    | `/health`       | Liveness probe (not audited)    |
| GET    | `/openapi.json` | OpenAPI 3.1 schema              |
| GET    | `/docs`         | Rapidoc HTML UI                 |

### Viewer

| Method | Path                          | Purpose                                   |
| ------ | ----------------------------- | ----------------------------------------- |
| GET    | `/sessions`                   | List sessions (filters: ip, protocol, since, until, limit, cursor) |
| GET    | `/sessions/{id}`              | Session detail                            |
| GET    | `/sessions/{id}/events`       | Paginated events                          |
| GET    | `/alerts`                     | List alerts (filters: severity, since, acknowledged) |
| GET    | `/intel/attck`                | ATT&CK technique counts                   |
| GET    | `/intel/iocs`                 | IOCs (filter: type)                       |
| GET    | `/intel/tls`                  | Top TLS fingerprints                      |
| GET    | `/metrics/prometheus`         | Prometheus text exposition                |
| GET    | `/metrics/summary`            | JSON metrics snapshot                     |
| GET    | `/profiles`                   | Device profile list                       |
| GET    | `/profiles/{name}`            | Profile detail                            |
| GET    | `/config`                     | Redacted effective config                 |

### Analyst

| Method | Path                            | Purpose                                |
| ------ | ------------------------------- | -------------------------------------- |
| GET    | `/sessions/{id}/timeline`       | Reconstructed timeline (`?text=1` for plain) |
| GET    | `/sessions/{id}/pcap`           | PCAP download (`application/vnd.tcpdump.pcap`) |
| GET    | `/sessions/{id}/jsonl.gz`       | Gzipped JSONL session dump             |
| POST   | `/alerts/{id}/ack`              | Acknowledge an alert (`{note?}`)       |

### Admin

| Method | Path                         | Purpose                              |
| ------ | ---------------------------- | ------------------------------------ |
| POST   | `/profiles/reload`           | Reload profile from disk             |
| GET    | `/apikeys`                   | List API keys (never returns hashes) |
| POST   | `/apikeys`                   | Create API key (`{name, role}`)      |
| DELETE | `/apikeys/{id}`              | Revoke an API key                    |
| POST   | `/control/pause`             | Pause new connections                |
| POST   | `/control/resume`            | Resume connections                   |
| POST   | `/control/shutdown`          | Request graceful shutdown            |

## Pagination

Any listing endpoint may return `next_cursor`. Pass it back as the `cursor`
query parameter for the next page. Cursors are opaque strings; do not parse
them.

```json
{
  "items": [ /* ... */ ],
  "next_cursor": "128"
}
```

## Error envelope

Errors always use this shape; the `request_id` is echoed in the
`X-Request-Id` response header and the audit log.

```json
{
  "error": {
    "code": "forbidden",
    "message": "role 'viewer' insufficient (needs 'admin')",
    "request_id": "req_0b4c..."
  }
}
```

Common codes: `bad_request`, `unauthorized`, `forbidden`, `not_found`,
`payload_too_large`, `rate_limited`, `replay_detected`, `internal`.

## Rate limiting

Per-key token bucket with capacity equal to the per-minute role limit. On
rejection the server sends `429 rate_limited` with a `Retry-After` header
in whole seconds.

## Audit log

Every authenticated request is recorded in a gzipped JSONL file
(`state_dir/audit.log.jsonl.gz`). Rotated at 100 MiB, 10 files retained.
Health checks are not audited.

```json
{
  "ts":          "2026-04-22T18:15:03.422Z",
  "request_id":  "req_0b4c...",
  "method":      "POST",
  "path":        "/api/v1/alerts/alert-1/ack",
  "status":      200,
  "key_id":      "key_xxxx",
  "key_name":    "ops-admin",
  "role":        "admin",
  "remote":      "127.0.0.1",
  "bytes_in":    34,
  "bytes_out":   189,
  "duration_ms": 2.7
}
```

Secrets are never recorded: neither the API token, nor request/response
bodies, nor HMAC signatures.

## CLI reference

```
honeytrap api start       [--bind HOST] [--port N] [--tls-cert F] [--tls-key F]
                          [--trusted-proxies CSV] [--allow-external]
                          [--require-hmac] [--state-dir DIR]

honeytrap api keys create --name NAME [--role viewer|analyst|admin]
                          [--state-dir DIR]
honeytrap api keys list   [--state-dir DIR]
honeytrap api keys revoke ID [--state-dir DIR]

honeytrap api openapi     [--state-dir DIR]
```

The `keys create` command is the only moment a plaintext token is ever
printed — store it immediately.
