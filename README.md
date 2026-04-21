# 🍯 HoneyTrap AI

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/redhoundinfosec/honeytrap-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/redhoundinfosec/honeytrap-ai/actions/workflows/ci.yml)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-lightgrey)](https://github.com/redhoundinfosec/honeytrap-ai)

**AI-powered cross-platform honeypot framework** that simulates insecure network devices to attract, interact with, and profile attackers. Runs identically on Linux and Windows, uses LLM-driven dynamic responses that adapt based on attacker origin, and provides a live terminal dashboard plus automated attack reports.

---

## ✨ Features

- 🌐 **Multi-protocol honeypots** — HTTP, SSH, FTP, SMB (plus optional SMTP, Telnet, MySQL)
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

  [1] 🌐 Web Server       — Apache with exposed admin panels (HTTP/SSH)
  [2] 📁 File Share       — NAS with open SMB shares (SMB/FTP)
  [3] 📷 IoT Camera       — IP camera with default creds (HTTP/Telnet)
  [4] 🗄️  Database Server — MySQL with phpMyAdmin (MySQL/HTTP/SSH)
  [5] 📧 Mail Server      — Open relay mail server (SMTP/POP3/IMAP)
  [6] 🔧 Custom           — Load a custom profile YAML

  Select [1-6]: 1

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

## 🧪 Development

```bash
git clone https://github.com/redhoundinfosec/honeytrap-ai
cd honeytrap-ai
pip install -e ".[dev,full]"
pytest
ruff check .
```

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
