# Roadmap

HoneyTrap AI is at an early beta. The four phases below mirror the original project plan.

## Phase 1 — Core Foundation ✅

- [x] CLI with device selection menu
- [x] HTTP honeypot with Apache simulation (path traversal, admin panels, .env leakage)
- [x] FTP honeypot with fake filesystem
- [x] Basic rule-based response engine
- [x] JSON log rotation + size management
- [x] SQLite attack database
- [x] Cross-platform high-port fallback

## Phase 2 — Intelligence Layer ✅

- [x] GeoIP resolution (ip-api free tier, optional MaxMind)
- [x] Geo-aware response personality variation
- [x] LLM integration (OpenAI / Ollama / custom endpoint)
- [x] Graceful fallback to rules when AI is unavailable
- [x] Pattern detection for scanners, brute force, exploit attempts

## Phase 3 — Dashboard & Reporting ✅

- [x] Rich live terminal dashboard
- [x] Real-time connection visualization
- [x] Terminal + HTML report generation
- [x] Top attackers, credential analysis, geographic distribution
- [x] Novel-pattern flagging
- [x] Geo-response comparison

## Phase 4 — Extended Protocols & Community

- [x] SSH handler (asyncssh)
- [x] SMB handler (lightweight asyncio)
- [x] Telnet handler (Mirai-style creds)
- [x] SMTP handler (custom asyncio, zero new deps — Postfix-style open relay)
- [x] MySQL handler (custom asyncio, speaks protocol v10 with handshake, auth, COM_QUERY)
- [x] Combined `full_enterprise` profile running HTTP + SSH + FTP + SMTP + MySQL in one process
- [ ] Full impacket-backed SMB share server
- [ ] POP3 / IMAP handlers (placeholders in `profiles/mail_server.yaml`)
- [x] Optional Textual-based interactive dashboard with filters (Cycle 5, 2026-04-21)
- [ ] GitHub community templates, PyPI release
- [ ] Docs site (mkdocs)

## Phase 5 — Security Hardening ✅

- [x] Per-IP token-bucket rate limiter with burst allowance
- [x] Global + per-IP concurrent connection caps
- [x] Automatic cleanup of stale IP entries
- [x] Tarpit (slow-response) mode for rate-limited traffic
- [x] Configurable idle timeouts per protocol (HTTP/SSH/Telnet/FTP/SMB)
- [x] Input sanitization layer (body/header/command size limits)
- [x] Binary / null-byte payload handling with raw-hex logging
- [x] Resource guardian — memory, connection, log-disk monitoring
- [x] Refuse new connections when under resource pressure
- [x] Rate-limited IP + resource stats on the dashboard

## Phase 6 — Threat Intelligence ✅

- [x] MITRE ATT&CK technique database (15+ techniques) with tactic metadata
- [x] Rule-based ATT&CK mapper for HTTP / SSH / FTP / SMB / Telnet events
- [x] Multi-technique classification per event with confidence scoring
- [x] IOC extractor for IPs, URLs, domains, hashes, emails, user-agents
- [x] SHA-256 payload hashing for captured blobs
- [x] IOC deduplication with first/last-seen tracking and sighting counts
- [x] SQLite persistence: `attack_mappings` and `iocs` tables with indexes
- [x] Technique-to-attacker correlation and attack timeline queries
- [x] "MITRE ATT&CK Coverage" + "Indicators of Compromise" sections in terminal and HTML reports
- [x] Top-ATT&CK and IOC-by-type panel on the live dashboard

## Phase 7 — Enhanced Reporting ✅

- [x] Matplotlib-based chart generator (timeline, protocol, country, technique, tactic, credentials, hourly)
- [x] Dark SOC-style HTML report template with embedded base64 PNG charts
- [x] Navigation sidebar with anchor links to every section
- [x] 7×24 day-of-week × hour-of-day activity heatmap
- [x] Print-friendly CSS (`@media print`) for browser-based PDF
- [x] WeasyPrint-backed PDF export (optional `[pdf]` extra)
- [x] `honeytrap report --format terminal|html|pdf` CLI switch
- [x] Analyzer snapshots include `events_by_hour`, `hourly_heatmap`, `time_range`

## Phase 8 — Deployment & Operations (Cycle 6, 2026-04-21)

- [x] Multi-stage Dockerfile (`python:3.12-slim`, non-root UID 10001, curl HEALTHCHECK)
- [x] `.dockerignore` excluding tests/build artifacts
- [x] `deploy/docker-compose.yml` with read-only root, cap drop, optional `with-prometheus` profile
- [x] Helm chart under `deploy/helm/honeytrap-ai/` (PVC, NetworkPolicy, ServiceMonitor, probes)
- [x] Plain Kubernetes manifests + `kustomization.yaml`
- [x] Hardened `honeytrap.service` systemd unit with syscall filter and idempotent `install.sh`
- [x] `/healthz`, `/readyz`, `/metrics` HTTP endpoints (stdlib, no new deps)
- [x] Prometheus counters for connections, events, rate-limited, resource rejections
- [x] GitHub Actions workflow: hadolint, helm lint, kubeconform, buildx push to GHCR

## Phase 9 — Alerting (Cycle 7, 2026-04-21)

- [x] Pluggable alert channel abstraction with per-channel rate limiting
- [x] Slack, Discord, Microsoft Teams, generic webhook, and SMTP email channels
- [x] HMAC-SHA256 signing for generic webhook payloads
- [x] Rules engine: first-seen IP, brute force, default creds, shell exec, file transfer, malicious IOC, critical ATT&CK techniques, multi-technique escalation
- [x] Severity thresholds (INFO / LOW / MEDIUM / HIGH / CRITICAL) enforced at manager and channel layers
- [x] Env-var-only secrets via `*_env` YAML keys
- [x] CLI flags: `--alerts-enabled` / `--no-alerts`, `--alerts-min-severity`, `--alerts-dry-run`
- [x] Textual TUI toast for severity ≥ HIGH
- [x] Prometheus counters: `honeytrap_alerts_sent_total`, `honeytrap_alerts_dropped_total`

## Phase 10 — TLS Client Fingerprinting (Cycle 8, 2026-04-22)

- [x] Zero-dependency TLS record + ClientHello parser (handles malformed input without raising)
- [x] JA3 hasher (salesforce/ja3 compatible, MD5 of decimal-encoded fields, GREASE filtered)
- [x] JA4 hasher (FoxIO spec: `t13d1516h2_…_…` with sha256/12 cipher and ext hashes)
- [x] YAML-backed `FingerprintDatabase` with 33+ seeded entries covering scanners, libraries, browsers, malware, pentest tools, and bots
- [x] `TLSFingerprinter` orchestrator with LRU cache and JSON-ready event output
- [x] `tls_peek` async helper: 16 KB cap, partial-read safe, non-TLS passthrough, timeout-tolerant
- [x] In-memory self-signed cert via `cryptography` (pre-baked fallback under `_selfsigned/`)
- [x] Session event enrichment (`tls_fingerprint` block) + SNI promoted to domain IOC
- [x] ATT&CK mapping: scanner / pentest_tool match -> T1595.002
- [x] Alert rule: malware/bot -> HIGH, scanner/pentest_tool -> MEDIUM
- [x] Prometheus counter `honeytrap_tls_fingerprint_total` with bounded cardinality (top 100)
- [x] CLI flags `--tls-fingerprint-db PATH`, `--disable-tls-fingerprinting`
