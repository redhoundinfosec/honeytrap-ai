# 🍯 HoneyTrap AI

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/redhoundinfosec/honeytrap-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/redhoundinfosec/honeytrap-ai/actions/workflows/ci.yml)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-lightgrey)](https://github.com/redhoundinfosec/honeytrap-ai)

**AI-powered cross-platform honeypot framework** that simulates insecure network devices to attract, interact with, and profile attackers. Runs identically on Linux and Windows, uses LLM-driven dynamic responses that adapt based on attacker origin, and provides a live terminal dashboard plus automated attack reports.

---

## ✨ Features

- 🌐 **Multi-protocol honeypots** — 11 protocols: HTTP, SSH, FTP, SMB, Telnet, SMTP, MySQL, IMAP4, RDP (signature), MQTT, CoAP
- 🤖 **AI-driven responses** — Rule-based engine + optional LLM (OpenAI / Ollama / custom endpoints)
- 🗺️ **Geo-aware personalities** — Attacker sees a different server personality based on their origin country
- 📊 **Live terminal dashboard** — Built on Rich/Textual, real-time connection visualization
- 📈 **Automated reports** — Top attackers, credential analysis, geographic distribution, novel patterns
- 💾 **Smart log management** — Tiered retention, rotation, GZIP compression, SQLite persistence
- 🔌 **Zero-config start** — Interactive CLI menu: pick a device profile, begin listening
- 🛡️ **Cross-platform** — Identical behavior on Linux, Windows, macOS (Python 3.10+)
- 🧱 **Plug-in device profiles** — YAML-defined device types, trivial to add new ones

---

## 🚀 Quick Start

```bash
# Install
pip install honeytrap-ai

# Or install from source
git clone https://github.com/redhoundinfosec/honeytrap-ai
cd honeytrap-ai
pip install -e .

# Run the interactive setup
honeytrap
```

### Example session

```text
  🍯 HoneyTrap AI v0.1.0
  ──────────────────────────

  What device would you like to simulate?

  [1] 🌐 Web Server          — Apache with exposed admin panels (HTTP/SSH)
  [2] 📁 File Share          — NAS with open SMB shares (SMB/FTP)
  [3] 📷 IoT Camera          — IP camera with default creds (HTTP/Telnet)
  [4] 🗄️  Database Server    — MySQL with phpMyAdmin (MySQL/HTTP/SSH)
  [5] 📧 Mail Server         — Open relay + IMAP (SMTP/IMAP)
  [6] 🪟 Windows Workstation — RDP signature + SMB + IIS
  [7] 🏭 IoT Industrial      — Field gateway (MQTT + CoAP + HTTP)
  [8] 🏢 Full Enterprise     — All 11 protocols on one host
  [9] 🔧 Custom              — Load a custom profile YAML

  Select [1-9]: 1

  AI Response Engine:
  [1] Offline (rule-based only)
  [2] OpenAI API
  [3] Ollama (local LLM)
  [4] Custom endpoint

  Select [1-4]: 1

  ✓ Starting Web Server honeypot on 0.0.0.0
  ✓ HTTP listener on :80
  ✓ SSH listener on :22
  ✓ GeoIP resolver ready
  ✓ Dashboard starting...
```

### Dashboard mockup

```text
╔══════════════════════════════════════════════════════════════════╗
║  🍯 HoneyTrap AI — Live Dashboard        Profile: web_server    ║
╠══════════════════════════════════════════════════════════════════╣
║  ACTIVE CONNECTIONS (3)            STATS (last 24h)              ║
║  ┌──────────────────────────┐     ┌────────────────────────┐    ║
║  │ 185.220.101.4 (DE) → :80│     │ Total connections: 847 │    ║
║  │ 45.134.26.11 (RU) → :22 │     │ Unique IPs:       234  │    ║
║  │ 103.89.91.2 (CN) → :445 │     │ Brute force:      156  │    ║
║  └──────────────────────────┘     └────────────────────────┘    ║
║                                                                  ║
║  LIVE EVENT LOG                                                  ║
║  23:41:02 [HTTP ] 185.220.101.4 GET /wp-login.php                ║
║  23:41:01 [SSH  ] 45.134.26.11  AUTH root:admin123               ║
║  23:40:58 [SMB  ] 103.89.91.2   LIST \\Finance                    ║
╚══════════════════════════════════════════════════════════════════╝
  [Q]uit  [R]eport  [P]ause  [F]ilter  [E]xport
```

### Dashboard modes

Choose a dashboard flavor with ``--dashboard-mode``:

| Mode     | Description                                                                              |
| -------- | ---------------------------------------------------------------------------------------- |
| ``textual`` | Full-screen Textual TUI with filter, search, pause, session-detail modal (default). |
| ``rich``    | Legacy Rich Live dashboard (single scrolling pane).                                 |
| ``none``    | Headless — no UI, just listeners and logs.                                          |

If ``textual`` is selected and the dependency is not installed, the CLI
falls back to ``rich`` with a warning.

### Textual TUI keyboard shortcuts

| Key       | Action                                                   |
| --------- | -------------------------------------------------------- |
| ``q``     | Quit                                                     |
| ``f``     | Cycle event-log filter (All / HTTP / SSH / FTP / SMB / Telnet / SMTP / MySQL) |
| ``s`` or ``/`` | Open substring search across the event log          |
| ``r``     | Generate a report (terminal + HTML) and show toast       |
| ``p``     | Pause / resume live updates (honeypot keeps running)     |
| ``tab`` / ``shift+tab`` | Cycle focus between panels                 |
| ``enter`` | Open session detail modal on the selected connection     |
| ``escape``| Dismiss the session detail modal or hide the search bar  |

---

## 📦 Installation

### Minimal install (rule-based only)

```bash
pip install honeytrap-ai
```

### With optional extras

```bash
# Add LLM integration
pip install "honeytrap-ai[ai]"

# Add MaxMind GeoIP support
pip install "honeytrap-ai[geo]"

# Add SMB via impacket
pip install "honeytrap-ai[smb]"

# Everything
pip install "honeytrap-ai[full]"
```

### Platform notes

- **Linux**: ports < 1024 require root or `cap_net_bind_service`. The CLI will suggest alternative high ports if binding fails.
- **Windows**: run as administrator for low ports, or accept the auto-suggested high-port fallback (HTTP=8080, SSH=2222, FTP=2121, SMB=4450).
- **macOS**: same as Linux.

---

## 🧩 Device Profiles

Ships with five profiles out of the box; all are plain YAML files you can edit or clone.

| Profile | Services | Description |
|---|---|---|
| `web_server` | HTTP (80), SSH (22) | Vulnerable Apache with path traversal, exposed admin panels |
| `file_share` | SMB (445), FTP (21) | NAS device with open shares and weak credentials |
| `iot_camera` | HTTP (8080), Telnet (23) | IP camera with default credentials |
| `database_server` | MySQL (3306), HTTP (80) | Exposed MySQL with phpMyAdmin |
| `mail_server` | SMTP (25) | Misconfigured mail server with open relay |

Create your own profile by copying any YAML from `profiles/` and loading it with option `[6] Custom`.

---

## 🗺️ Geo-Aware Responses

The system can resolve attacker origin (via ip-api.com free tier or a local MaxMind DB) and present a different server personality based on their country. This enables research into attacker behavior variation:

| Origin | Personality | Example content |
|---|---|---|
| Russia | Russian SMB | ООО "ТехноГрупп", Cyrillic file names |
| China | Chinese enterprise | 华信科技有限公司, zh-CN locale |
| USA | US startup | TechNova Inc., en-US locale |
| Germany | German industrial | Müller Maschinenbau GmbH |
| Default | US startup | TechNova Inc. |

Toggle with `geo.vary_responses: true` in `honeytrap.yaml`.

---

## 📊 Reports

Generate a terminal or HTML report at any time:

```bash
honeytrap report --format html --out report.html
honeytrap report --format terminal
```

Reports include: executive summary, top attackers, geographic distribution, credential analysis, attack patterns, novel/flagged behaviors, geo-response comparison, and a timeline.

---

## 📦 Deployment

HoneyTrap AI ships with Docker, Docker Compose, Helm, raw Kubernetes, and
systemd recipes under `deploy/`. All targets expose a small health plane
(`/healthz`, `/readyz`, `/metrics`) that defaults to the loopback
interface — override `--health-host` deliberately if you want it
reachable outside the pod or container.

### Health and metrics endpoints

| Path       | Purpose                                                                 |
| ---------- | ----------------------------------------------------------------------- |
| `/healthz` | Liveness. Always 200 while the process is up. JSON payload.             |
| `/readyz`  | Readiness. 200 while the resource guardian is not refusing connections. |
| `/metrics` | Prometheus text exposition of connection/event counters and gauges.    |

CLI flags: `--health-host` (default `127.0.0.1`), `--health-port` (default
`9200`), `--health-disabled` to turn the server off entirely.

### Docker

```bash
docker build -t honeytrap-ai:local .
docker run --rm -p 127.0.0.1:9200:9200 -p 127.0.0.1:8080:80 \
    honeytrap-ai:local --profile web_server --dashboard-mode none --health-host 0.0.0.0
```

The runtime image is built from `python:3.12-slim` with a non-root
`honeytrap` (UID 10001) user and a baked-in HEALTHCHECK that hits
`/healthz`. Expect a final image around 240-280 MB.

### Docker Compose

```bash
docker compose -f deploy/docker-compose.yml up -d
# Optional: scrape /metrics with a bundled Prometheus container
docker compose -f deploy/docker-compose.yml --profile with-prometheus up -d
```

All honeypot ports are published on `127.0.0.1` by default so nothing is
exposed externally until you choose to bind to `0.0.0.0`.

### Kubernetes (Helm)

```bash
helm install ht ./deploy/helm/honeytrap-ai -f my-values.yaml
```

Ships with a `ServiceMonitor` for Prometheus Operator and an opt-in
`NetworkPolicy`. Pods run with `runAsNonRoot`, a read-only root
filesystem, and `capabilities.drop: [ALL]`.

### Kubernetes (raw manifests)

```bash
kubectl apply -k deploy/k8s
```

### Multi-node deployment

The same `honeytrap` binary can run as a sensor (`role: node`) that
forwards events to a central management plane (`role: controller`).

```
                       +----------------------+
                       |    controller        |
   admin / analyst <-->|  :9300 management    |
                       |  Fleet (SQLite)      |
                       +-----^------^---------+
                             |      |  htk_-keyed HTTP
              +--------------+      +--------------+
              |                                    |
        +-----+------+                       +-----+------+
        |  node      |   ...     ...         |  node      |
        |  edge-01   |                       |  edge-N    |
        |  honeypots |                       |  honeypots |
        +------------+                       +------------+
```

Bootstrap a node:

```bash
honeytrap node register \
    --controller https://controller.example.com:9300 \
    --api-key htk_xxx \
    --node-id edge-01
```

Inspect the fleet from the controller side:

```bash
honeytrap controller list-nodes --api-key htk_admin
honeytrap controller top-attackers --limit 10 --api-key htk_admin
honeytrap controller mitre-heatmap --api-key htk_admin
```

The Helm chart ships role-specific override files (`values-node.yaml`,
`values-controller.yaml`). See [`docs/cluster.md`](docs/cluster.md) for
the full operational guide and [`deploy/helm/honeytrap-ai/README.md`](deploy/helm/honeytrap-ai/README.md)
for chart usage.

### systemd

```bash
sudo ./deploy/systemd/install.sh
sudo systemctl status honeytrap.service
```

The unit is hardened with `ProtectSystem=strict`,
`MemoryDenyWriteExecute=yes`, a syscall filter, and narrow
`ReadWritePaths`. Binding to privileged ports requires uncommenting
`AmbientCapabilities=CAP_NET_BIND_SERVICE`.

---

## 🚨 Alerts

HoneyTrap AI can push structured alerts to operations tools when
interesting events happen (brute-force bursts, default-credential
hits, shell execution, known-bad IOCs, critical ATT&CK techniques,
…). Alerts are pluggable, rate-limited per channel, and honor a
minimum-severity threshold.

### Supported channels

| Channel           | Transport          | Notes                                                    |
|-------------------|--------------------|----------------------------------------------------------|
| Slack             | Incoming webhook   | Rich blocks + severity-colored attachment                |
| Discord           | Incoming webhook   | Embed with severity color                                |
| Microsoft Teams   | Incoming webhook   | MessageCard JSON                                         |
| Generic webhook   | HTTPS POST         | Optional HMAC-SHA256 `X-HoneyTrap-Signature` header      |
| Email (SMTP)      | SMTP + STARTTLS    | Multipart text + HTML, configurable from/to addresses    |

### Configuration

Enable alerts in your `honeytrap.yaml` or profile file. Secrets
should come from environment variables via `*_env` keys so they're
never committed:

```yaml
alerts:
  enabled: true
  min_severity: medium        # info|low|medium|high|critical
  dry_run: false              # log payloads instead of sending
  channels:
    - type: slack
      name: soc-slack
      webhook_url_env: HONEYTRAP_SLACK_WEBHOOK_URL
      min_severity: high
      rate_limit_per_minute: 20
    - type: webhook
      name: siem
      url_env: HONEYTRAP_WEBHOOK_URL
      secret_env: HONEYTRAP_WEBHOOK_SECRET
      headers: { X-Env: prod }
    - type: email
      smtp_host: smtp.example.com
      smtp_port: 587
      from_addr: honeytrap@example.com
      to_addrs: [soc@example.com]
      username_env: HONEYTRAP_SMTP_USER
      password_env: HONEYTRAP_SMTP_PASS
      starttls: true
```

### Environment variables

Copy `.env.example` to `.env` and fill in the endpoints you actually
use:

```
HONEYTRAP_SLACK_WEBHOOK_URL=
HONEYTRAP_DISCORD_WEBHOOK_URL=
HONEYTRAP_TEAMS_WEBHOOK_URL=
HONEYTRAP_WEBHOOK_URL=
HONEYTRAP_WEBHOOK_SECRET=
HONEYTRAP_SMTP_USER=
HONEYTRAP_SMTP_PASS=
```

### CLI flags

```
--alerts-enabled / --no-alerts      override alerts.enabled
--alerts-min-severity {info,low,medium,high,critical}
--alerts-dry-run                    log payloads instead of POSTing
```

### Security

- Channel secrets are read **only** from environment variables.
  Missing env vars result in a warning and the channel being skipped
  — never a crash.
- The generic webhook channel signs the JSON body with HMAC-SHA256
  when a `secret_env` is provided; verify
  `X-HoneyTrap-Signature: sha256=<hex>` on the receiver.
- HTTP delivery retries 5xx / network errors with exponential
  backoff (0.5s, 1s, 2s) and honors `Retry-After`. 4xx responses
  are **not** retried.
- Per-channel token-bucket rate limiting (default 20/min) prevents a
  noisy event from flooding a channel.
- Deliveries run concurrently; one failing channel never blocks the
  others.

### Metrics

Two Prometheus counters are exposed on `/metrics`:

- `honeytrap_alerts_sent_total{channel,severity}`
- `honeytrap_alerts_dropped_total{reason}` — `reason` is
  `rate-limited`, `below-min-severity`, `no-channels`, or `error`.

---

## 🕵 TLS Fingerprinting (JA3 / JA4)

HoneyTrap identifies attacker tooling from the first TLS ClientHello,
**before** any handshake completes. The pipeline:

```
+-------------+   peek 16 KB   +----------------+
| TCP listener|--------------->| tls_peek helper|
+-------------+                +-------+--------+
                                       |
                                       v
                             +---------+----------+
                             | ClientHello parser |
                             +------+------+------+
                                    |      |
                                    v      v
                                   JA3    JA4
                                    |      |
                                    v      v
                           +----------------------+
                           | FingerprintDatabase  |   <- bundled YAML
                           +----------+-----------+     (33+ entries)
                                      |
                                      v
          ATT&CK mapping - alerts - IOC SNI - Prom metrics - reports
```

Supported fingerprints today (**33 bundled**): curl, Python requests /
urllib3 / aiohttp, Go net/http, OpenSSL, nmap, masscan, zgrab2,
Firefox, Chrome, Safari, wget, Java HttpClient, Node.js, Cobalt
Strike Beacon, Metasploit Meterpreter, sqlmap, Burp Suite, Empire,
Havoc, Sliver, Merlin, Mirai/Mozi variants, and more.

### CLI flags

- `--tls-fingerprint-db PATH` — layer a custom YAML on top of the
  bundled database.
- `--disable-tls-fingerprinting` — turn the subsystem off entirely.

### YAML entry format

```yaml
fingerprints:
  - name: "Cobalt Strike Malleable C2 (default)"
    category: malware          # scanner | library | browser |
                               # malware | pentest_tool | bot | unknown
    confidence: high           # high | medium | low
    ja3: "72a589da586844d7f0818ce684948eea"
    ja4: "t13d1516h2_8daaf6152771_e5627efa2ab1"   # optional
    references:
      - "https://www.cobaltstrike.com/"
```

### Prometheus metric

- `honeytrap_tls_fingerprint_total{ja3_hash,category,name}` — bounded
  to the top 100 JA3s; overflow collapses to
  `ja3_hash="other",name="other"`.

---

## 🎬 Forensics & Replay

Every attacker session is captured byte-for-byte and can be replayed,
searched, or exported to PCAP for downstream forensic tools. The
recorder is passive — if disabled or under resource pressure it drops
frames silently without affecting the engine. See
[`docs/forensics.md`](docs/forensics.md) for the full operator guide.

```yaml
forensics:
  enabled: true
  store: jsonl                  # jsonl | sqlite
  path: ./sessions
  max_session_bytes: 10485760   # 10 MiB per session
  max_daily_bytes: 1073741824   # 1 GiB per day
  retention_days: 30
  record_tls_handshake: true
```

### Export from the CLI

```bash
honeytrap export list
honeytrap export pcap     --session ssh-7c1a8b --out cap.pcap
honeytrap export jsonl    --session ssh-7c1a8b --out cap.jsonl.gz
honeytrap export timeline --session ssh-7c1a8b
honeytrap export pcap     --ip 198.51.100.7 --since 2026-04-22T00:00:00Z --out campaign.pcap
```

### Replay in the TUI

Open the dashboard, press Enter on a session row, then switch to the
Replay tab:

| Key     | Action                      |
|---------|-----------------------------|
| `space` | Play / pause                |
| `right` | Step one frame forward      |
| `left`  | Step one frame back         |
| `>`     | Increase playback speed     |
| `<`     | Decrease playback speed     |
| `e`     | Export session as PCAP      |
| `E`     | Export session as JSONL     |

Speeds cycle through `0.25x, 0.5x, 1.0x, 2.0x, 4.0x, 8.0x`.

### PCAP-lite

The PCAP writer produces a valid libpcap capture (magic `0xa1b2c3d4`,
Ethernet linktype `1`) that opens cleanly in Wireshark and `tshark`.
Because the engine sees application-layer frames, the writer
synthesizes the missing transport: a SYN / SYN-ACK / ACK handshake,
MSS-sized TCP segments with monotonic sequence numbers, correct
one's-complement checksums, IPv4 *and* IPv6, and a FIN / ACK teardown.
IDS rules and content-carving work as on a real capture; RTT or
retransmit analysis does not.

### Prometheus metrics

- `honeytrap_sessions_recorded_total{protocol}`
- `honeytrap_sessions_truncated_total{reason}`
- `honeytrap_session_bytes_total{protocol,direction}`
- `honeytrap_pcap_exports_total`
- `honeytrap_session_duration_seconds` (histogram)

---

## 🛰️ Management API

HoneyTrap ships with a stdlib-only REST API under `/api/v1` for dashboards,
automation, and SOC tooling. Default bind is `127.0.0.1:9300`; the server
refuses non-loopback binds without `--allow-external` and supports optional
TLS and HMAC-signed requests.

```bash
# Mint an admin token (shown exactly once)
honeytrap api keys create --name ops --role admin

# Start the server (plaintext on loopback; add --tls-cert/--tls-key for HTTPS)
honeytrap api start --bind 127.0.0.1 --port 9300

# Call it
curl -H "X-API-Key: htk_..." http://127.0.0.1:9300/api/v1/sessions

# Live docs
open http://127.0.0.1:9300/api/v1/docs
```

Role matrix:

| Role    | Grants                                                              |
| ------- | ------------------------------------------------------------------- |
| viewer  | sessions, events, alerts, intel, metrics, profiles, config          |
| analyst | viewer + timeline/PCAP/JSONL export + alert acknowledge             |
| admin   | analyst + profile reload + API-key management + pause/resume/shutdown |

Built-in controls: API-key auth (SHA-256-only at rest, `htk_` prefix, shown
once), optional HMAC signing with 300 s skew and replay cache, per-key
token-bucket rate limits, 1 MiB body cap, gzipped JSONL audit log with
rotation, security headers on every response. Full endpoint reference and
signing examples in [docs/api.md](docs/api.md).

---

## Adaptive AI

Every protocol handler can route inbound bytes through an adaptive
response layer that combines per-session memory, a deterministic
intent classifier, and a pluggable backend chain.

```
 inbound ---> [ cache ] ---> [ classify ] ---> [ chain: openai / anthropic / ollama ] ---> [ template fallback ] ---> shape-validated bytes
```

- `SessionMemory` keeps a rolling view of the attacker (commands,
  auth attempts, ATT&CK techniques, protocol history).
- `classify()` maps the memory to one of 10 `IntentLabel` values
  with a confidence score — no LLM required.
- `ResponseCache` is an LRU with TTL keyed on
  `(protocol, normalized_inbound, memory_hash)`.
- The backend chain always ends in a `TemplateBackend`, so the
  honeypot never stalls on an LLM outage. Safety tripwires veto
  AI self-reference leaks.
- Every prompt is redacted before leaving the process; HTTP/SMTP
  wire shapes are validated on the way out.

Enable with `--ai-enabled` or `adaptive_enabled: true` in the
`ai:` config block. See [docs/ai.md](docs/ai.md) for full
details.

### Per-protocol adapters (Cycle 16)

Adaptive AI now extends to HTTP, SMTP, Telnet, and FTP through a
single `BaseAdapter` contract. Each adapter implements four hooks
(`template_response`, `validate_shape`, `cache_key`, `safety_filter`)
and shares the existing backend chain, response cache, and intent
classifier — no new runtime dependencies.

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

A shared safety filter strips attacker-secret echoes (passwords,
JWTs, PEM blocks, AWS/Google keys, CC-shaped digit runs), internal
host paths, and dashboard ANSI escapes; it emits an `ai_safety`
event on every trim. See
[src/honeytrap/ai/adapters/README.md](src/honeytrap/ai/adapters/README.md)
for the developer guide.

---

## 📡 Threat Intel Sharing (STIX 2.1 / TAXII 2.1)

HoneyTrap can publish observations as a STIX 2.1 bundle and serve
them through a read-only TAXII 2.1 root mounted on the management
API:

- `honeytrap export stix --session sess-1 --out bundle.json [--pretty]`
- `GET /api/v1/intel/stix?session_id=&ip=&since=&until=` (analyst role).
- `GET /taxii/2.1/` (discovery), `/taxii/2.1/honeytrap/collections/`,
  `/taxii/2.1/honeytrap/collections/{id}/objects/?limit=&next=`.

Five collections are exposed (stable ids): `indicators`,
`attack-patterns`, `observed-data`, `sightings`, `notes`. Bundles
include `infrastructure`, `campaign`, `observed-data`, `indicator`,
`attack-pattern`, and `note` SDOs (the latter carrying custom
`x_ja3` / `x_ja4` properties). All ids are deterministic UUID5 over
the natural key so re-emitting the same input produces byte-identical
output.

See [docs/stix.md](docs/stix.md) and [docs/taxii.md](docs/taxii.md)
for details.

---

## 🪣 SIEM Integration (Sinks)

HoneyTrap ships pluggable, asynchronous log sinks for shipping
events to Elasticsearch, OpenSearch, Splunk HEC, or rotated JSONL
files. All sinks share a backpressure pipeline with bounded queue
(`drop_oldest` / `drop_new` / `block` overflow), batcher
(500 events / 1 s), exponential-backoff retry with jitter, and a
per-sink circuit breaker.

```yaml
sinks:
  enabled: true
  queue_capacity: 10000
  on_overflow: drop_oldest
  targets:
    - { type: elasticsearch, name: es-prod, url: https://es.example,
        index: "honeytrap-events-{+YYYY.MM.dd}", api_key_env: ES_API_KEY }
    - { type: splunk_hec, name: splunk, url: https://splunk.example,
        token_env: SPLUNK_HEC_TOKEN, index: main, host: honeytrap-1 }
    - { type: file_jsonl, name: cold, path: /var/log/honeytrap/jsonl }
```

Operate from the CLI:

```bash
honeytrap sinks test es-prod
honeytrap sinks health --json
```

Or query the API: `GET /api/v1/sinks` (viewer),
`POST /api/v1/sinks/{name}/flush` (admin). Secrets are read from
env vars only — never from YAML.

See [docs/sinks.md](docs/sinks.md) for full configuration and ECS
mapping details.

---

## 🧪 Development

```bash
git clone https://github.com/redhoundinfosec/honeytrap-ai
cd honeytrap-ai
pip install -e ".[dev,full]"
pytest
ruff check .
```

### Quality & Testing

[![CI](https://img.shields.io/github/actions/workflow/status/redhoundinfosec/honeytrap-ai/ci.yml?branch=main&label=CI)](https://github.com/redhoundinfosec/honeytrap-ai/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![tests](https://img.shields.io/badge/tests-577%2B%20passing-brightgreen)](tests/)
[![coverage](https://img.shields.io/badge/coverage-%E2%89%A590%25-brightgreen)](tests/)
[![mypy](https://img.shields.io/badge/mypy-strict-blueviolet)](pyproject.toml)

The dev extras pull in `hypothesis`, `pytest-benchmark`, `pytest-cov`,
`mypy`, `pre-commit`, and `codespell` so the full quality gate runs
locally:

```bash
# Install dev dependencies (includes hypothesis, pytest-benchmark, mypy, ruff, pre-commit)
pip install -e ".[dev]"

# Register git hooks (ruff, ruff-format, mypy, codespell, file hygiene)
pre-commit install

# Run all hooks on the whole repo
pre-commit run --all-files

# Default test selection (unit + fuzz, excludes benchmarks) with coverage
pytest -m "not benchmark" --cov=src/honeytrap --cov-branch --cov-fail-under=90

# Only the property-based fuzz tests (Hypothesis)
pytest -m fuzz

# Skip the fuzz tests (e.g. on resource-constrained CI)
pytest -m "not fuzz"

# Run the performance benchmarks (NOT part of the default run)
pytest tests/bench/ --benchmark-only

# Save a benchmark baseline and diff future runs against it
pytest tests/bench/ --benchmark-only --benchmark-autosave
pytest-benchmark compare 0001 0002

# Strict mypy (enforced in CI)
mypy src/honeytrap
```

CI runs `lint`, `typecheck`, and `test` (Python 3.11 and 3.12) on every
push and PR; a separate nightly workflow exercises the fuzz suite with
`HYPOTHESIS_PROFILE=ci` (500 examples per property).

See `tests/README.md` for a tour of the layout (unit, fuzz, bench),
the full marker list, and the coverage policy.

---

## 🔒 Security

Honeypots should run on **isolated networks** or **dedicated cloud VMs**. See [SECURITY.md](SECURITY.md) for responsible deployment guidance and disclosure policy.

---

## 🤝 Contributing

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

---

## 📜 License

MIT — see [LICENSE](LICENSE).

Maintained by [redhoundinfosec](https://github.com/redhoundinfosec) · built by [@jph4cks](https://github.com/jph4cks)
