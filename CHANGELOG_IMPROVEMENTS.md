# HoneyTrap AI — Improvement Changelog

This file tracks every automated improvement cycle. Each entry documents what was changed, why, and which files were affected.

---

## Improvement Queue (Priority Order)

### Cycle 1: Security Hardening & Connection Management
- Per-IP connection rate limiting and concurrent connection caps
- Global resource limits (max memory, max connections, max sessions)
- Input sanitization on all protocol handlers (prevent buffer overflow / memory exhaustion)
- Graceful handling of malformed packets and protocol abuse
- Connection timeout enforcement across all handlers

### Cycle 2: MITRE ATT&CK Mapping & Threat Intelligence
- Map detected attacks to MITRE ATT&CK technique IDs
- Classify events by tactic (Initial Access, Execution, Credential Access, etc.)
- Add ATT&CK technique info to reports and database
- IOC extraction (IPs, hashes, URLs, domains)

### Cycle 3: SMTP & MySQL Protocol Handlers
- aiosmtpd-based SMTP honeypot (open relay simulation)
- MySQL protocol handler (auth + basic query simulation)
- New device profiles leveraging these protocols

### Cycle 4: Enhanced Reporting with Charts
- Matplotlib/Plotly chart generation for HTML reports
- Attack timeline charts, geographic heatmaps, protocol distribution pie charts
- PDF export option

### Cycle 5: Textual TUI Dashboard
- Migrate from Rich Live to full Textual app
- Filterable event log, session detail view, search
- Keyboard shortcuts, mouse support

### Cycle 6: Docker & Deployment
- Dockerfile and docker-compose.yml
- Helm chart for Kubernetes
- Deployment documentation

### Cycle 7: Webhook & Alert Integration
- Slack webhook notifications on high-severity events
- Generic webhook support (Discord, Teams, custom)
- Email alerts via SMTP

### Cycle 8: JA3/JA4 TLS Fingerprinting
- TLS fingerprint extraction on HTTPS connections
- Known scanner/bot fingerprint database
- Fingerprint-based attacker classification

### Cycle 9: Session Replay & Forensics
- Full session recording with replay capability
- PCAP-lite export per session
- Forensic timeline reconstruction

### Cycle 10: API Server
- REST API for remote management and data access
- API key authentication
- Prometheus metrics endpoint

---

## Completed Improvements

### 2026-04-20 — Cycle 3: SMTP & MySQL Protocol Handlers

Added two new zero-dependency protocol handlers so the honeypot can
impersonate mail and database servers — among the most commonly
targeted services on the internet — and introduced a combined
`full_enterprise` profile that runs five protocols in one process.

**What changed**

- **SMTP handler** (`src/honeytrap/protocols/smtp_handler.py`): custom
  asyncio implementation of a Postfix-style open relay. Speaks
  `HELO` / `EHLO`, `MAIL FROM`, `RCPT TO`, `DATA` (up to 10 MB,
  configurable), `RSET`, `NOOP`, `QUIT`, `VRFY` (252), `EXPN` (502),
  `HELP`. Advertises `SIZE 52428800`, `8BITMIME`, `PIPELINING`,
  `AUTH PLAIN LOGIN`, and `ENHANCEDSTATUSCODES`. `AUTH PLAIN` decodes
  the SASL triple and `AUTH LOGIN` walks the two-step base64 prompts;
  both log the decoded username/password and always return 235 to
  invite reuse. `DATA` parses `Subject` / `From` / `To` headers and
  records the body size without persisting the body. Malformed input
  is answered with 500 and logged. Emits `connection_open`,
  `greeting`, `auth_attempt`, `mail_from`, `rcpt_to`, `data_received`,
  `open_relay`, `vrfy`, `quit`, `unknown_command`, `connection_close`
  events.
- **MySQL handler** (`src/honeytrap/protocols/mysql_handler.py`):
  custom asyncio implementation of enough of the MySQL client/server
  protocol to convince scanners it is a real MySQL 5.7 / 8.0 server.
  Packet framing (`3 B length | 1 B seq`), handshake v10 with a
  random 20-byte scramble, capability flags, `mysql_native_password`
  plugin advertisement. Parses the protocol-41 handshake response,
  emits OK/ERR depending on whether the offered credentials match
  the profile's `weak_credentials`. Handles `COM_QUIT`, `COM_PING`,
  `COM_INIT_DB`, and `COM_QUERY`. Dispatches queries: `SELECT @@version`
  returns the configured version; `SELECT database()`, `SELECT user()`,
  `SHOW DATABASES`, `SHOW TABLES`, `DESCRIBE <table>`, and
  `SELECT * FROM users` all return realistic fake result sets built
  from profile data. Unknown queries fall back to an OK packet. Emits
  `connection_open`, `auth_attempt`, `query`, `quit`,
  `connection_close` events.
- **ATT&CK mapper extensions** (`src/honeytrap/intel/attack_mapper.py`):
  new techniques `T1071.003` (Application Layer Protocol: Mail
  Protocols) and `T1005` (Data from Local System). SMTP auth attempts
  map to `T1110` / `T1110.004` and any `mail_from` / `rcpt_to` /
  `data_received` / `open_relay` event maps to `T1071.003`. MySQL
  auth attempts map to `T1110` / `T1110.004`; MySQL queries containing
  SQL injection patterns map to `T1190`; `SELECT *` queries map to
  `T1005`.
- **Protocol registry** (`src/honeytrap/core/engine.py`): `smtp` and
  `mysql` are now recognized protocol keys that instantiate
  `SMTPHandler` and `MySQLHandler`.
- **Timeouts** (`src/honeytrap/core/config.py`, `base.py`): new
  `smtp_idle` (default 300 s) and `mysql_idle` (default 120 s) knobs
  wired through `ProtocolHandler.idle_timeout()`.
- **Profiles**:
  - `profiles/mail_server.yaml` — upgraded SMTP entry (hostname,
    max_data_bytes, capabilities) and commented POP3/IMAP
    placeholders for a future cycle.
  - `profiles/database_server.yaml` — added MySQL on port 3306 with
    weak credentials, fake databases, and fake tables.
  - `profiles/full_enterprise.yaml` — new combined profile running
    HTTP (80), SSH (22), FTP (21), SMTP (25), MySQL (3306) in one
    process.
- **Tests** (`tests/test_smtp.py`, `tests/test_mysql.py`): 28 new
  async integration tests covering EHLO capability advertising,
  HELO, MAIL FROM / RCPT TO, the DATA 354/250 flow, AUTH PLAIN base64
  decoding, AUTH LOGIN two-step flow, VRFY / EXPN responses, QUIT,
  malformed command handling, oversized DATA rejection, MySQL greeting
  packet parsing, auth success/failure, version / databases / tables
  / users / describe result sets, unknown-query fallback, idle timeout,
  SQL-injection query event emission, clean COM_QUIT, plus unit tests
  on helpers (address extraction, SASL decoding, header parsing,
  length-encoded integers, credential normalization). All 86 prior
  tests continue to pass (114 total).

**Files changed**

- Added: `src/honeytrap/protocols/smtp_handler.py`
- Added: `src/honeytrap/protocols/mysql_handler.py`
- Added: `tests/test_smtp.py`
- Added: `tests/test_mysql.py`
- Added: `profiles/full_enterprise.yaml`
- Modified: `src/honeytrap/protocols/__init__.py` (export new handlers)
- Modified: `src/honeytrap/protocols/base.py` (smtp/mysql timeouts)
- Modified: `src/honeytrap/core/engine.py` (register smtp + mysql)
- Modified: `src/honeytrap/core/config.py` (smtp_idle, mysql_idle)
- Modified: `src/honeytrap/intel/attack_mapper.py` (T1071.003, T1005,
  SMTP + MySQL dispatch rules)
- Modified: `profiles/mail_server.yaml` (fleshed-out SMTP entry +
  POP3/IMAP placeholders)
- Modified: `profiles/database_server.yaml` (MySQL service)
- Modified: `ROADMAP.md` (SMTP / MySQL / full_enterprise checked off)

---

### 2026-04-20 — Cycle 2: MITRE ATT&CK Mapping & Threat Intelligence

Transformed raw honeypot events into structured, actionable threat
intelligence by adding a rule-based MITRE ATT&CK classifier, an IOC
extractor, and persistence/reporting integrations across the stack.

**What changed**

- **ATT&CK mapper** (`src/honeytrap/intel/attack_mapper.py`): new
  `ATTACKMapping` dataclass plus a `TECHNIQUE_DB` with 16 Enterprise
  ATT&CK techniques (IDs, names, tactics, descriptions — all
  verified against the official framework). Rule-based `ATTACKMapper`
  classifies HTTP path traversal, admin-panel probing, `.env` / `.git`
  leakage attempts, SQL injection, Log4Shell, scanner user-agents
  (sqlmap / nikto / nuclei / gobuster / …), SSH/Telnet/FTP brute
  force (with a Mirai-style credential-stuffing list), SSH/Telnet
  command execution, `wget`/`curl`/`tftp` downloads, SMB share
  enumeration, FTP anonymous login, and port scanning. Events can
  match multiple techniques with independent confidence scores.
- **IOC extractor** (`src/honeytrap/intel/ioc_extractor.py`): regex
  extraction of IPv4, IPv6, URLs, domains, emails, MD5/SHA1/SHA256
  hashes, and user-agent fingerprints. Skips RFC1918 / loopback /
  IPv6 loopback. Deduplicates across sessions and maintains
  first/last-seen timestamps. Supports SHA-256 payload hashing for
  captured blobs.
- **Database** (`src/honeytrap/logging/database.py`): new
  `attack_mappings` and `iocs` tables with indexes and UNIQUE(type,
  value) dedup on IOCs. Added `record_attack_mapping`, `record_ioc`,
  `get_top_techniques`, `get_tactic_distribution`,
  `get_technique_to_attacker`, `get_attack_timeline`,
  `get_iocs_by_type`, `get_ioc_summary`, and `get_top_iocs`. Schema
  is created on startup; existing databases are upgraded in place
  via `CREATE TABLE IF NOT EXISTS`.
- **Engine integration** (`src/honeytrap/core/engine.py`): every
  emitted `Event` is classified and scanned for IOCs. Results are
  stored in `event.data` (so dashboards, subscribers, and the JSONL
  log all see them) and persisted to the new tables with the
  returning row id linking mappings to events.
- **Reporting** (`src/honeytrap/reporting/`): `AnalysisSnapshot`
  gains `top_techniques`, `tactic_distribution`,
  `technique_to_attacker`, `ioc_summary`, `top_iocs`, and
  `iocs_by_type`. Terminal report and HTML template both render a
  new "MITRE ATT&CK Coverage" section (with tactic distribution and
  technique × attacker correlation) and an "Indicators of
  Compromise" section.
- **Dashboard** (`src/honeytrap/ui/dashboard.py`): new "Threat
  Intel" panel showing the top five observed ATT&CK techniques (ID,
  name, event count) and IOC counts by type.
- **Tests** (`tests/test_intel.py`): 33 new tests covering
  per-technique rule coverage, multi-technique events, confidence
  scoring, credential-stuffing classification, IOC URL / IP /
  domain / hash / email / IPv6 extraction, dedup, SHA-256 payload
  hashing, and database persistence. All 53 prior tests still pass
  (86 total).

**Files changed**

- Added: `src/honeytrap/intel/__init__.py`
- Added: `src/honeytrap/intel/attack_mapper.py`
- Added: `src/honeytrap/intel/ioc_extractor.py`
- Added: `tests/test_intel.py`
- Modified: `src/honeytrap/core/engine.py` (mapper + extractor pipeline)
- Modified: `src/honeytrap/logging/database.py` (new tables, read/write APIs)
- Modified: `src/honeytrap/reporting/analyzer.py` (extended snapshot)
- Modified: `src/honeytrap/reporting/generator.py` (terminal + HTML sections)
- Modified: `src/honeytrap/reporting/templates/report.html` (ATT&CK + IOC sections)
- Modified: `src/honeytrap/ui/dashboard.py` (Threat Intel panel)
- Modified: `ROADMAP.md` (Phase 6 added and marked complete)

---

### 2026-04-20 — Cycle 1: Security Hardening & Connection Management

Added a production-grade security layer so the honeypot can survive
real-world scanner fleets and targeted DoS without resource-exhaustion.

**What changed**

- **Rate limiter** (`src/honeytrap/core/rate_limiter.py`): async-safe
  token-bucket limiter per source IP with configurable sustained rate
  (default 30/min) and burst (default 10). Enforces a global concurrent
  cap (default 500) and a per-IP concurrent cap (default 20). Stale IP
  entries are pruned after 10 minutes. Optional tarpit mode
  (``tarpit_on_limit``) slow-responds instead of dropping, so attackers
  pay socket time.
- **Input sanitizer** (`src/honeytrap/core/sanitizer.py`): enforces HTTP
  body (1 MB default) and non-HTTP payload (64 KB) size limits, HTTP
  header count/size caps, and a 4096-byte per-command ceiling for
  SSH/Telnet/FTP. Null-byte payloads are rejected and their raw hex is
  preserved in the security log so analysts can study them safely.
- **Resource guardian** (`src/honeytrap/core/guardian.py`): background
  asyncio monitor that reads process RSS (via psutil when present,
  falling back to ``/proc/self/status``), the global connection count,
  and the log directory size. When memory >= 256 MB or connections
  exceed the global cap, the guardian flips ``should_refuse`` and new
  connections are turned away with a protocol-appropriate error
  (HTTP 503, FTP 421, immediate disconnect for SSH/Telnet/SMB).
- **Base protocol handler** (`src/honeytrap/protocols/base.py`): new
  ``check_connection_allowed``, ``apply_tarpit``, ``log_rate_limit_event``,
  ``log_sanitizer_event``, ``log_timeout_event``, and ``idle_timeout``
  helpers so every protocol gets the security layer for free.
- **Per-protocol timeouts**: HTTP (120 s), SSH / Telnet (300 s),
  FTP / SMB (60 s) — applied at the idle-read level. Timeouts emit an
  ``idle_timeout`` event before closing.
- **Dashboard**: added a Security panel showing top rate-limited IPs,
  current memory / connection usage, log-dir size, and the guardian's
  refuse/accept status.
- **Config**: new ``rate_limiter``, ``timeouts``, ``sanitizer``, and
  ``guardian`` sections. ``honeytrap.example.yaml`` documents every
  knob.
- **Tests**: 25 new tests in ``tests/test_security.py`` covering
  limiter bucket math, burst behavior, concurrency caps, stale cleanup,
  sanitizer size / header / null-byte paths, guardian pressure and
  recovery, and idle-timeout helpers. All 28 original tests continue
  to pass (53 total).

**Files changed**

- Added: ``src/honeytrap/core/rate_limiter.py``
- Added: ``src/honeytrap/core/sanitizer.py``
- Added: ``src/honeytrap/core/guardian.py``
- Added: ``tests/test_security.py``
- Modified: ``src/honeytrap/core/config.py`` (+4 dataclasses)
- Modified: ``src/honeytrap/core/engine.py`` (wire security layer,
  start/stop guardian)
- Modified: ``src/honeytrap/protocols/base.py`` (shared helpers)
- Modified: ``src/honeytrap/protocols/http_handler.py`` (503 + 413 paths)
- Modified: ``src/honeytrap/protocols/ftp_handler.py`` (421 + timeout)
- Modified: ``src/honeytrap/protocols/ssh_handler.py`` (gate shell path)
- Modified: ``src/honeytrap/protocols/telnet_handler.py`` (gate + timeout)
- Modified: ``src/honeytrap/protocols/smb_handler.py`` (gate + size cap)
- Modified: ``src/honeytrap/ui/dashboard.py`` (Security panel)
- Modified: ``honeytrap.example.yaml`` (four new sections)
- Modified: ``ROADMAP.md`` (Phase 5 added and marked complete)

---

## 2026-04-20 — Cycle 4: Enhanced Reporting (Charts + PDF Export)

**Summary**

Transformed the basic HTML report into a professional, dark-themed intelligence
report with embedded matplotlib charts and optional PDF export. Reports now
feel like a SOC analyst's dashboard rather than a raw dump of tables, and can
be exported to PDF for stakeholder briefings and incident documentation.

**Highlights**

- New ``src/honeytrap/reporting/charts.py`` with seven embedded chart functions
  (attack timeline, protocol distribution, country distribution, ATT&CK
  techniques, tactic heatmap, top credentials, 7×24 day-of-week × hour-of-day
  activity grid). All charts return base64 PNGs for single-file HTML output
  and use a consistent dark palette (``#1a1a2e`` / ``#53d2dc`` / ``#e94560``).
- Rewritten ``report.html`` template with sidebar navigation, anchor-linked
  sections, summary stat cards, and print-friendly ``@media print`` styles.
- New ``src/honeytrap/reporting/pdf_export.py`` using WeasyPrint behind an
  optional ``[pdf]`` extra, with a graceful fallback message when the
  dependency is missing.
- ``ReportGenerator`` now exposes ``render_pdf`` and wires chart generation
  into ``render_html``, tolerating per-chart failures without breaking the
  rest of the report.
- ``Analyzer`` snapshots gained ``events_by_hour``, ``hourly_heatmap``, and
  ``time_range`` fields, backed by new ``AttackDatabase`` methods.
- CLI extended: ``honeytrap report --format terminal|html|pdf``.

**Test impact**

- Added ``tests/test_charts.py`` (17 tests covering every chart function with
  populated and empty inputs, asserting valid base64 PNG output).
- Extended ``tests/test_reporting.py`` with 12 new tests (HTML chart
  embedding, empty-database safety, new analyzer fields, PDF mock/missing-dep
  flows, graceful chart-failure handling).
- Full suite: 143 tests passing (up from 114).

**Files changed**

- Added: ``src/honeytrap/reporting/charts.py``
- Added: ``src/honeytrap/reporting/pdf_export.py``
- Added: ``tests/test_charts.py``
- Modified: ``src/honeytrap/reporting/analyzer.py`` (three new fields and
  helpers)
- Modified: ``src/honeytrap/reporting/generator.py`` (chart wiring,
  ``render_pdf``, version in footer)
- Modified: ``src/honeytrap/reporting/templates/report.html`` (dark theme,
  sidebar, embedded charts, print CSS)
- Modified: ``src/honeytrap/logging/database.py`` (``events_by_hour``,
  ``hourly_heatmap_data``, ``time_range``)
- Modified: ``src/honeytrap/cli.py`` (``--format pdf`` option)
- Modified: ``tests/test_reporting.py``
- Modified: ``pyproject.toml`` (``matplotlib`` added, new ``[pdf]`` extra)
- Modified: ``ROADMAP.md`` (Phase 7 added and marked complete)

---

## Cycle 5 — Textual TUI Dashboard (2026-04-21)

Introduced a full Textual-based terminal UI that coexists with the legacy
Rich Live dashboard. Users can now choose their flavor at launch time via a
new ``--dashboard-mode`` flag (``textual`` | ``rich`` | ``none``).

**Textual app highlights**

- Six live panels: header/status bar, active connections table, event log,
  combined stats/ATT&CK/IOC intel panel, resource-guardian panel, and a
  scrolling activity log plus footer shortcuts.
- Keyboard bindings: ``q`` quit, ``f`` cycle protocol filter, ``s``/``/``
  open substring search, ``r`` trigger reports, ``p`` pause/resume ingestion,
  ``tab``/``shift+tab`` focus cycling, ``enter`` on a connection row opens a
  modal with full session detail, ``escape`` dismisses the modal.
- Session detail modal shows metadata, event list, mapped ATT&CK techniques,
  extracted IOCs, and a hex dump of the most recent payload.
- Handles empty state, narrow terminals (<80 cols), and high-throughput
  bursts via a 10fps refresh throttle.
- Lazy import: ``cli.py`` only touches the Textual classes when the user
  actually picks ``textual`` mode. ``none`` mode doesn't import Textual at
  all.

**Shared event source abstraction**

- New ``DashboardEventSource`` Protocol and ``EngineDashboardSource`` adapter
  let both the Rich and Textual UIs consume the same event bus without
  duplicating engine-access logic.

**Test impact**

- Added ``tests/ui/test_dashboard_tui.py`` with 18 tests driven by Textual's
  ``App.run_test()`` harness (mount, panels, event updates, session
  add/remove, filter cycle, search, pause, modal open/close, ATT&CK + IOC
  rendering, clean quit, report callback, narrow-terminal warning,
  high-throughput burst, full filter cycle, Protocol surface, subprocess
  assertion that ``--dashboard-mode none`` never imports Textual, and an
  integration test that ``--dashboard-mode rich`` routes to the legacy
  Rich dashboard).
- Full suite: 161 tests passing (up from 143).

**Files changed**

- Added: ``src/honeytrap/ui/dashboard_tui.py``
- Added: ``tests/ui/__init__.py``, ``tests/ui/test_dashboard_tui.py``
- Modified: ``src/honeytrap/ui/__init__.py`` (lazy ``load_textual_app``)
- Modified: ``src/honeytrap/cli.py`` (``--dashboard-mode`` flag,
  ``_resolve_dashboard_mode``, ``_run_textual_dashboard``,
  ``_run_rich_dashboard``)
- Modified: ``README.md`` (new flag, keyboard shortcuts)
- Modified: ``ROADMAP.md`` (Textual dashboard checkbox ticked)

---

## Cycle 6 — Docker, Compose, Helm, K8s, systemd Packaging + Health/Metrics (2026-04-21)

**Title**: Docker, Compose, Helm, K8s, and systemd deployment packaging with
a first-class health and metrics plane.

Introduced production deployment targets for every common environment and a
tiny stdlib HTTP server exposing ``/healthz``, ``/readyz`` and ``/metrics``.
The Prometheus formatter is hand-rolled (no ``prometheus_client`` dep) and
all metrics are pre-registered so scrapers always see the full set, even
before the first event fires.

**Health / metrics server**

- New ``src/honeytrap/ops/health.py``: thread-backed ``http.server`` with a
  ``MetricsRegistry`` (thread-safe counters + gauges) and a minimal
  Prometheus text formatter.
- Defaults to ``127.0.0.1:9200`` so it stays off the attacker-facing
  network until the operator opts in to a non-loopback bind host.
- Exposed metrics: ``honeytrap_connections_total``,
  ``honeytrap_events_total``, ``honeytrap_active_sessions``,
  ``honeytrap_rate_limited_total``,
  ``honeytrap_resource_rejections_total``, ``honeytrap_uptime_seconds``.
- CLI flags: ``--health-host``, ``--health-port``, ``--health-disabled``.
- Engine wiring: ``emit_event`` increments the appropriate counters based
  on ``event_type`` / ``protocol``; active session gauge is refreshed on
  every ``/metrics`` scrape.

**Docker**

- Multi-stage ``Dockerfile`` (``python:3.12-slim`` builder + runtime),
  non-root ``honeytrap`` user (UID 10001), curl-based HEALTHCHECK,
  ``ENTRYPOINT ["honeytrap"]``.
- ``.dockerignore`` trims tests, caches, docs, ``deploy/helm``, ``deploy/k8s``,
  ``deploy/systemd`` out of the build context.

**Compose**

- ``deploy/docker-compose.yml``: read-only root FS, ``cap_drop: [ALL]``,
  tmpfs ``/tmp``, loopback-bound published ports, curl HEALTHCHECK.
- Optional ``with-prometheus`` profile launches a Prometheus sidecar
  scraping ``/metrics`` via ``deploy/prometheus.yml``.

**Helm chart** (``deploy/helm/honeytrap-ai/``)

- ``Chart.yaml``, ``values.yaml`` with opinionated hardened defaults
  (``runAsNonRoot``, ``readOnlyRootFilesystem``,
  ``capabilities.drop: [ALL]``, ``seccompProfile: RuntimeDefault``).
- Templates: ``deployment``, ``service``, ``pvc``, ``serviceaccount``,
  ``networkpolicy`` (opt-in), ``servicemonitor`` (opt-in), ``NOTES.txt``,
  ``_helpers.tpl``.
- ``README.md`` inside the chart.

**Raw Kubernetes manifests** (``deploy/k8s/``)

- ``namespace``, ``deployment``, ``service``, ``pvc``, ``networkpolicy``,
  ``servicemonitor``, ``kustomization.yaml``.

**systemd**

- ``deploy/systemd/honeytrap.service`` with ``NoNewPrivileges``,
  ``ProtectSystem=strict``, ``MemoryDenyWriteExecute``,
  ``SystemCallFilter=@system-service``, narrow ``ReadWritePaths``.
- ``deploy/systemd/install.sh`` — idempotent user / venv / unit installer.

**CI**

- New ``.github/workflows/docker.yml``: hadolint, helm lint, kubeconform,
  and buildx push to ``ghcr.io/redhoundinfosec/honeytrap-ai`` with
  ``:latest``, ``:sha`` and ``:tag`` on tags; uses GHA layer cache.

**Tests**

- Added ``tests/ops/test_health.py`` with 12 tests:
  ``/healthz`` JSON shape, ``/readyz`` happy and 503 paths,
  ``/metrics`` Prometheus format, counter increments across scrapes,
  configurable port, loopback default, clean shutdown, CLI flag parsing
  (``--health-disabled``, ``--health-port``), zero-counter emission, and
  monotonic uptime gauge.
- Added ``tests/ops/test_docker_smoke.py`` — opt-in build + ``--help``
  smoke test, skipped when Docker is unavailable (marked ``slow`` +
  ``docker`` in ``pyproject.toml``).
- Suite total: 173 passing (161 baseline + 12 new), 1 skipped
  (Docker smoke).

**Docs**

- ``README.md``: new "Deployment" section covering Docker, Compose,
  Helm, raw K8s, systemd, plus the health / metrics endpoint reference
  and CLI flag table.
- ``deploy/README.md`` — index into the deploy/ directory.
- ``ROADMAP.md`` — Phase 8 added and marked complete.

**Files added**

- ``src/honeytrap/ops/__init__.py``, ``src/honeytrap/ops/health.py``
- ``tests/ops/__init__.py``, ``tests/ops/test_health.py``,
  ``tests/ops/test_docker_smoke.py``
- ``Dockerfile``, ``.dockerignore``
- ``deploy/README.md``, ``deploy/docker-compose.yml``,
  ``deploy/prometheus.yml``
- ``deploy/helm/honeytrap-ai/Chart.yaml``,
  ``deploy/helm/honeytrap-ai/values.yaml``,
  ``deploy/helm/honeytrap-ai/README.md``
- ``deploy/helm/honeytrap-ai/templates/_helpers.tpl``,
  ``deployment.yaml``, ``service.yaml``, ``pvc.yaml``,
  ``serviceaccount.yaml``, ``networkpolicy.yaml``,
  ``servicemonitor.yaml``, ``NOTES.txt``
- ``deploy/k8s/namespace.yaml``, ``deployment.yaml``, ``service.yaml``,
  ``pvc.yaml``, ``networkpolicy.yaml``, ``servicemonitor.yaml``,
  ``kustomization.yaml``
- ``deploy/systemd/honeytrap.service``, ``deploy/systemd/install.sh``
- ``.github/workflows/docker.yml``

**Files modified**

- ``src/honeytrap/core/engine.py`` — metrics registry + emit_event
  counter updates.
- ``src/honeytrap/cli.py`` — ``--health-host/--health-port/--health-disabled``
  flags, health server start/stop in ``_run_engine``.
- ``pyproject.toml`` — ``slow`` and ``docker`` pytest markers.
- ``README.md`` — deployment section.
- ``ROADMAP.md`` — Phase 8 entry.

**Test counts**: 161 -> 173 passing (+12), 1 skipped.

---

## Cycle 7 — Pluggable Alerting (2026-04-21)

**Summary**

Introduced a pluggable alerting subsystem that pushes structured
notifications to Slack, Discord, Microsoft Teams, generic HTTPS
webhooks, and SMTP email when interesting honeypot events happen.
Alerts are generated by a rules engine, filtered by severity
thresholds, rate-limited per channel, and delivered concurrently
with isolation between channels.

**Alerts package** (``src/honeytrap/alerts/``)

- ``models.py`` — ``Alert`` dataclass (uuid4 id, UTC timestamp, severity,
  title, summary, source_ip, protocol, session_id, ATT&CK techniques,
  IOC dict, tags, raw event). ``AlertSeverity`` IntEnum
  (INFO < LOW < MEDIUM < HIGH < CRITICAL) with ``from_name`` and
  ordered comparison.
- ``rules.py`` — ``AlertRuleEngine`` plus 7 built-in rules:
  first-seen IP (LOW), brute force ≥10 fails/60s (MEDIUM), default
  credentials (HIGH), shell/command exec (HIGH), file upload/download
  (MEDIUM), blocklisted IOC (HIGH), critical ATT&CK techniques
  T1059/T1078/T1190 (HIGH) with CRITICAL escalation on multi-technique
  events. ``AlertRuleContext`` is thread-safe via a ``threading.Lock``.
- ``channels/base.py`` — ``AlertChannel`` ABC with min-severity gating,
  per-channel ``TokenBucket`` rate limiter, and cooperative shutdown.
- ``channels/slack.py``, ``discord.py``, ``teams.py``,
  ``generic_webhook.py``, ``email.py`` — per-protocol channels.
  Generic webhook optionally signs the JSON body with HMAC-SHA256 and
  attaches ``X-HoneyTrap-Signature: sha256=<hex>``. Email uses
  ``smtplib`` with STARTTLS / SSL + multipart ``text/html`` alternative
  through a pluggable ``smtp_factory`` for testability.
- ``templates.py`` — pure renderers
  (``render_slack``, ``render_discord``, ``render_teams``,
  ``render_generic``, ``render_email``) that truncate long fields and
  color-code by severity.
- ``http_client.py`` — ``post_json`` with 3 retries, exponential
  backoff (0.5s / 1s / 2s), 5s connect / 10s read timeouts,
  ``Retry-After`` handling. 5xx / network errors retry, 4xx short-circuit.
  ``aiohttp`` preferred, stdlib ``urllib`` fallback.
- ``manager.py`` — ``AlertManager`` subscribes to the engine event bus,
  fans out to channels via ``asyncio.gather(return_exceptions=True)``,
  tracks in-flight tasks for clean ``shutdown()``, supports ``dry_run``
  mode and a ``tui_notify`` hook for severity ≥ HIGH.
- ``config.py`` — ``parse_alerts_config`` turns the YAML ``alerts``
  block into channel objects. Secrets are resolved from env vars via
  ``*_env`` keys; missing vars yield warnings, never a crash.

**Integration**

- ``src/honeytrap/core/engine.py`` — starts the alert manager as an
  event-bus subscriber task, installs the TUI notify hook, flushes
  in-flight deliveries on ``stop()``.
- ``src/honeytrap/core/config.py`` — new ``AlertsConfigRaw`` piece of
  the YAML schema plus ``_apply_dict`` handling for the ``alerts``
  section.
- ``src/honeytrap/cli.py`` — ``--alerts-enabled``/``--no-alerts``
  mutex, ``--alerts-min-severity {info,low,medium,high,critical}``,
  ``--alerts-dry-run``; Textual dashboard installs the notify hook.
- ``src/honeytrap/ops/health.py`` — two new Prometheus counters:
  ``honeytrap_alerts_sent_total{channel,severity}`` and
  ``honeytrap_alerts_dropped_total{reason}``.

**Config**

- ``honeytrap.example.yaml`` — commented ``alerts`` block with
  enabled=false defaults.
- All six ``profiles/*.yaml`` — appended commented example covering
  slack/discord/teams/webhook/email.

**Tests**

- ``tests/alerts/test_models.py`` — round-trip serialization, severity
  ordering (2 tests).
- ``tests/alerts/test_rules.py`` — brute force threshold, shell command
  detection, first-seen fires once, multi-technique CRITICAL
  escalation, custom rule registration, default-creds only on success,
  manager min-severity filter (7 tests).
- ``tests/alerts/test_rate_limit.py`` — token-bucket burst, rejection
  + metric label, refill over time, non-positive rate rejection
  (4 tests, deterministic ``FakeClock``).
- ``tests/alerts/test_channels.py`` — Slack blocks, Discord embed
  color, Teams MessageCard shape, HMAC signature header, 5xx retry +
  4xx short-circuit, email STARTTLS multipart with fake SMTP
  (6 tests).
- ``tests/alerts/test_manager.py`` — dispatch by min severity, failing
  channel isolated, dry-run skips send, shutdown flushes, missing env
  var skipped, env secret resolved (6 tests).
- Suite total: 173 -> 198 passing (+25), 1 skipped unchanged.

**Docs**

- ``README.md`` — new "Alerts" section covering supported channels,
  YAML config, env var list, CLI flags, security notes on HMAC
  signing / env-only secrets, and Prometheus metrics.
- ``.env.example`` — template for the 7 alert-related env vars.
- ``ROADMAP.md`` — Phase 9 added and marked complete.

**Files added**

- ``src/honeytrap/alerts/__init__.py``, ``models.py``, ``rules.py``,
  ``templates.py``, ``http_client.py``, ``manager.py``, ``config.py``
- ``src/honeytrap/alerts/channels/__init__.py``, ``base.py``,
  ``slack.py``, ``discord.py``, ``teams.py``, ``generic_webhook.py``,
  ``email.py``
- ``tests/alerts/__init__.py``, ``test_models.py``, ``test_rules.py``,
  ``test_rate_limit.py``, ``test_channels.py``, ``test_manager.py``
- ``.env.example``

**Files modified**

- ``src/honeytrap/core/engine.py`` — alert manager wiring, TUI notify
  hook, graceful shutdown.
- ``src/honeytrap/core/config.py`` — ``AlertsConfigRaw`` and YAML
  merge.
- ``src/honeytrap/cli.py`` — alerts CLI flags + Textual hook install.
- ``src/honeytrap/ops/health.py`` — two new alert counters.
- ``honeytrap.example.yaml`` — example ``alerts`` section.
- ``profiles/database_server.yaml``, ``file_share.yaml``,
  ``full_enterprise.yaml``, ``iot_camera.yaml``, ``mail_server.yaml``,
  ``web_server.yaml`` — commented alerts block.
- ``README.md`` — "Alerts" section.
- ``ROADMAP.md`` — Phase 9 entry.

**Test counts**: 173 -> 198 passing (+25), 1 skipped.

---

## Cycle 8 — JA3 / JA4 TLS Client Fingerprinting (2026-04-22)

**Summary**

HoneyTrap can now identify attacker tooling from a single TLS
ClientHello, **before any handshake completes**. A zero-dependency
parser lifts every JA3/JA4-relevant field off raw bytes; two hashers
produce standard fingerprints per the salesforce/ja3 and FoxIO JA4
specs; a YAML-backed database ships 33 seeded entries covering
scanners (nmap, masscan, zgrab2), libraries (curl, requests, Go
net/http), browsers (Firefox, Chrome, Safari), pentest tools (Burp,
sqlmap, OpenSSL), and malware families (Cobalt Strike, Metasploit,
Sliver, Havoc, Empire, Merlin, Mirai/Mozi).

Matches are fed into the existing session event pipeline: ATT&CK
mapping (scanner/pentest_tool -> T1595.002), IOC extractor (SNI ->
domain IOC), the alerts rule engine (malware/bot -> HIGH,
scanner/pentest_tool -> MEDIUM), and a cardinality-bounded Prometheus
counter `honeytrap_tls_fingerprint_total{ja3_hash,category,name}`.

**Files added**

- ``src/honeytrap/intel/tls/__init__.py``
- ``src/honeytrap/intel/tls/clienthello.py`` — record + ClientHello
  parser, fails closed on malformed input
- ``src/honeytrap/intel/tls/ja3.py``
- ``src/honeytrap/intel/tls/ja4.py``
- ``src/honeytrap/intel/tls/database.py`` — YAML loader, schema
  validation, JA3/JA4 lookup
- ``src/honeytrap/intel/tls/fingerprinter.py`` — orchestrator with
  LRU cache
- ``src/honeytrap/intel/tls/metrics.py`` — top-100 bounded emitter
- ``src/honeytrap/intel/tls/certs.py`` — in-memory self-signed cert
- ``src/honeytrap/intel/tls/fingerprints.yaml`` — 33 seeded entries
- ``src/honeytrap/intel/tls/_selfsigned/cert.pem`` + ``key.pem``
- ``src/honeytrap/protocols/tls_peek.py`` — async 16 KB peek helper
- ``scripts/gen_selfsigned.py`` — regenerates the pre-baked cert
- ``tests/intel/tls/conftest.py``
- ``tests/intel/tls/test_clienthello.py`` (11 tests)
- ``tests/intel/tls/test_ja3.py`` (4 tests)
- ``tests/intel/tls/test_ja4.py`` (9 tests)
- ``tests/intel/tls/test_database.py`` (7 tests)
- ``tests/intel/tls/test_fingerprinter.py`` (4 tests)
- ``tests/protocols/test_tls_peek.py`` (5 tests)
- ``tests/alerts/test_tls_rules.py`` (4 tests)
- ``tests/fixtures/tls/*.bin`` — 9 deterministic ClientHello fixtures
- ``tests/fixtures/tls/_build_fixtures.py`` — regenerates fixtures

**Files modified**

- ``src/honeytrap/intel/attack_mapper.py`` — TLS match ->
  T1595.002 mapping.
- ``src/honeytrap/intel/ioc_extractor.py`` — SNI promoted to
  domain IOC.
- ``src/honeytrap/alerts/rules.py`` — ``rule_tls_fingerprint``
  rule added to ``DEFAULT_RULES``.
- ``src/honeytrap/core/config.py`` — ``TLSFingerprintConfig``
  dataclass.
- ``src/honeytrap/cli.py`` — ``--tls-fingerprint-db`` and
  ``--disable-tls-fingerprinting`` flags.
- ``src/honeytrap/ops/health.py`` — registered
  ``honeytrap_tls_fingerprint_total``.
- ``src/honeytrap/reporting/analyzer.py`` — optional
  ``top_tls_fingerprints`` field on the snapshot.
- ``pyproject.toml`` — package-data entries for the bundled YAML
  and self-signed PEM.
- ``README.md`` — new "TLS Fingerprinting" section with ASCII
  architecture diagram, CLI flags, YAML entry example, and the
  Prometheus metric.
- ``ROADMAP.md`` — Phase 10 marked complete.

**Test counts**: 198 -> 242 passing (+44), 1 skipped.

---

## Cycle 9 — Session Replay, PCAP-Lite Export & Forensic Timeline (2026-04-22)

**Goal**: capture every byte of every attacker session and let an
analyst replay, search, and export it in any format that downstream
tools speak.

**What shipped**

A new ``honeytrap.forensics`` subpackage that records byte-accurate
inbound/outbound frames for every session through a passive recorder,
persists them to a pluggable store (newline-delimited gzipped JSONL or
WAL-mode SQLite), and exposes three orthogonal export pipelines:

- **PCAP-lite** — synthesized TCP/IP framing (3-way handshake, MSS
  segmentation, FIN/ACK teardown, IPv4 + IPv6, correct one's
  complement checksums, Ethernet II linktype). Opens cleanly in
  Wireshark, ``tshark`` and any libpcap-aware tool.
- **JSONL** — one gzipped file per session containing the metadata
  open marker, every frame (base64 payload + timestamps), and the
  meta_close row. Concatenation-safe; multiple sessions stream into a
  single ``.jsonl.gz``.
- **Timeline** — chronological reconstruction with classified entries
  (CONNECT / AUTH_ATTEMPT / COMMAND / FILE_TRANSFER / TLS_HANDSHAKE /
  PAYLOAD_IN/OUT / DISCONNECT). Renders as plain text, JSON, or a
  self-contained dark-theme HTML page. Credentials are redacted from
  the human-readable description by default; the underlying frame
  payload is preserved for PCAP export.

The recorder enforces a 10 MiB per-session and 1 GiB per-day cap by
default and switches to *sampling* mode when a cap fires (keeps the
first 100 + last 100 frames and writes a ``truncated=true`` marker so
analysts never see silently dropped data). Disk writes are paused on
``ResourceGuardian`` pressure and resumed automatically.

The TUI session detail modal grew a Replay tab with a frame cursor,
hex dump of the selected frame, and one-key PCAP/JSONL export
(``e`` / ``E``). Playback bindings (``space`` / ``left`` / ``right`` /
``<`` / ``>``) advance through the recorded frames at six selectable
speeds.

The HTML report grew a ``Forensic Session Replays`` section that links
to one ``sessions/<id>.html`` page, ``sessions/<id>.pcap``, and
``sessions/<id>.jsonl.gz`` per recent session.

A new ``honeytrap export {pcap,jsonl,timeline,list}`` subcommand group
mirrors all of the above for headless workflows.

**Files added**

- ``src/honeytrap/forensics/__init__.py``
- ``src/honeytrap/forensics/recorder.py`` — frames, stores
  (JSONL + SQLite), recorder, retention sweep
- ``src/honeytrap/forensics/pcap.py`` — PCAP-lite writer/reader,
  TCP/IP synthesis, IPv4 + IPv6
- ``src/honeytrap/forensics/timeline.py`` — chronological
  reconstruction with redaction, text/JSON/HTML rendering
- ``src/honeytrap/forensics/cli.py`` — ``honeytrap export`` parser
  and dispatcher
- ``docs/forensics.md`` — operator/analyst guide
- ``tests/forensics/__init__.py``
- ``tests/forensics/test_recorder.py`` (10 tests)
- ``tests/forensics/test_sqlite_store.py`` (5 tests)
- ``tests/forensics/test_pcap.py`` (9 tests)
- ``tests/forensics/test_timeline.py`` (9 tests)
- ``tests/forensics/test_export_cli.py`` (5 tests)
- ``tests/forensics/test_replay_tui.py`` (6 tests)

**Files modified**

- ``src/honeytrap/core/config.py`` — ``ForensicsConfigRaw``
  dataclass with ``enabled``, ``store``, ``path``,
  ``max_session_bytes``, ``max_daily_bytes``, ``retention_days``,
  ``record_tls_handshake``.
- ``src/honeytrap/core/engine.py`` — wires the recorder, opens
  the configured store, schedules a 24-hour retention sweep, and
  closes the store on shutdown.
- ``src/honeytrap/cli.py`` — registers the ``export`` subparser
  group; dispatches to ``run_export`` after profile listing.
- ``src/honeytrap/ops/health.py`` — registers
  ``honeytrap_sessions_recorded_total``,
  ``honeytrap_sessions_truncated_total``,
  ``honeytrap_session_bytes_total``,
  ``honeytrap_pcap_exports_total``, and the histogram
  ``honeytrap_session_duration_seconds`` (with ``_bucket``,
  ``_count``, ``_sum`` Prometheus exposition).
- ``src/honeytrap/reporting/generator.py`` —
  ``render_html_with_sessions`` materializes per-session pages
  and PCAP/JSONL downloads alongside the main report.
- ``src/honeytrap/ui/dashboard_tui.py`` — Replay tab,
  PLAYBACK_SPEEDS, six new key bindings, ``_export_session``.
- ``README.md`` — new "Forensics & Replay" section.
- ``ROADMAP.md`` — Cycle 9 checked off.

**Test counts**: 242 -> 286 passing (+44), 1 skipped.

**Zero new runtime dependencies** — the entire subsystem is
stdlib-only (``gzip``, ``sqlite3``, ``socket``, ``struct``,
``threading``).
