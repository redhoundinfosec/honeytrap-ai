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
- [x] IMAP4rev1 handler with STARTTLS + SASL PLAIN (Cycle 13, 2026-04-26)
- [x] RDP signature handler — TPKT/X.224, NTLM NEGOTIATE, JA3/JA4 capture (Cycle 13, 2026-04-26)
- [x] MQTT 3.1.1 + 5.0 broker shell with C2-topic + scanner detection (Cycle 13, 2026-04-26)
- [x] CoAP UDP (RFC 7252) listener with per-source rate limiting (Cycle 13, 2026-04-26)
- [x] `windows_workstation` and `iot_industrial` device profiles (Cycle 13, 2026-04-26)
- [ ] Full impacket-backed SMB share server
- [ ] POP3 handler (placeholder in `profiles/mail_server.yaml`)
- [ ] DTLS support for CoAP on UDP/5684 (port already listens in `iot_industrial` log-only mode)
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

## Phase 11 — Session Replay & Forensic Export (Cycle 9, 2026-04-22)

- [x] Byte-accurate `SessionRecorder` with passive event-bus subscription
- [x] Pluggable `SessionStore` ABC with `JsonlSessionStore` (gzipped per-session, date-partitioned) and `SqliteSessionStore` (WAL mode) backends
- [x] Per-session (10 MiB) and per-day (1 GiB) caps with sampling-mode truncation (keep first 100 + last 100 frames, `truncated=true` marker)
- [x] `ResourceGuardian` integration — pauses disk writes under pressure
- [x] `PcapWriter` with synthesized TCP three-way handshake, MSS segmentation, FIN/ACK teardown, IPv4 + IPv6, correct one's complement checksums
- [x] PCAP-lite reader for round-trip tests + CLI parity
- [x] `Timeline` reconstruction with classified entries, credential redaction (default on), text/JSON/HTML rendering
- [x] `Timeline.for_session`, `for_sessions`, `for_ip` factories + `filter` chain (direction/kind/substring/size)
- [x] `honeytrap export {pcap,jsonl,timeline,list}` subcommand group
- [x] HTML report `Forensic Session Replays` section with per-session pages and PCAP/JSONL downloads
- [x] TUI Replay tab — frame cursor, hex dump, six playback speeds, one-key PCAP/JSONL export
- [x] Retention sweep — runs at startup and every 24h, removes data older than `retention_days`
- [x] Prometheus metrics: `honeytrap_sessions_recorded_total`, `honeytrap_sessions_truncated_total`, `honeytrap_session_bytes_total`, `honeytrap_pcap_exports_total`, histogram `honeytrap_session_duration_seconds`
- [x] `forensics` config block (enabled/store/path/max_session_bytes/max_daily_bytes/retention_days/record_tls_handshake)
- [x] 44 new tests under `tests/forensics/` (recorder, stores, PCAP, timeline, CLI, replay TUI)

## Phase 12 — Management REST API (Cycle 10, 2026-04-22)

- [x] Stdlib-only `http.server.ThreadingHTTPServer` under `/api/v1` with background thread and clean shutdown
- [x] API-key auth: `htk_` prefix, SHA-256-only persistence, constant-time compare, shown-once semantics
- [x] RBAC with viewer/analyst/admin and hierarchical satisfaction
- [x] Optional HMAC request signing (`METHOD|path|timestamp|sha256(body)`, 300 s skew, bounded replay cache)
- [x] Per-key token-bucket rate limiter (role-based capacity), `Retry-After` on rejection
- [x] 1 MiB body cap, security headers, HSTS when TLS is on, no-CORS by default
- [x] Gzipped JSONL audit log with 100 MiB × 10 rotation; never logs secrets
- [x] Protocol-based `HoneytrapService` facade with `InMemoryService` for tests and future engine binding
- [x] 26 endpoints covering sessions, events, alerts, intel (ATT&CK/IOC/TLS), metrics, profiles, config, API-key admin, and pause/resume/shutdown controls
- [x] Forensic export passthroughs for PCAP and gzipped JSONL session dumps
- [x] OpenAPI 3.1 schema generated from the router registry (`x-required-role` extension) + Rapidoc UI at `/api/v1/docs`
- [x] `honeytrap api start|keys create|list|revoke|openapi` CLI subcommand tree, loopback-only by default, refuses external bind without `--allow-external`
- [x] 36 new tests under `tests/api/` covering auth, RBAC, HMAC + replay, rate limiting, body cap, security headers, endpoint behavior, OpenAPI validity, and live wire (`ThreadingHTTPServer`) round-trip

## Phase 13 — Per-Session AI Memory, Intent Classification, Adaptive Backends (Cycle 11, 2026-04-22)

- [x] `SessionMemory` dataclass with command/auth/upload history, intent, confidence, ATT&CK techniques, per-backend latency
- [x] `InMemoryStore` (OrderedDict LRU, per-IP + per-session caps) and `SqliteMemoryStore` (WAL, JSON blob payload)
- [x] `build_store()` factory dispatching on `memory_store` config (`memory` / `sqlite`)
- [x] Deterministic `classify()` with 10 `IntentLabel` values and `(label, confidence, rationale[:3])` return shape
- [x] ATT&CK bias: `T1078+T1059 -> CREDENTIAL_HARVEST`, `T1190 -> EXPLOIT_ATTEMPT`, `T1110 -> BRUTE_FORCE`, `T1496 -> COIN_MINING`
- [x] `ResponseCache` LRU with TTL, HTTP key case-fold + whitespace collapse, SSH case-sensitivity
- [x] `ChainBackend` with always-appended `TemplateBackend` safety net and safety tripwires against AI self-reference leaks
- [x] Concrete stdlib-only backends: `OpenAIBackend`, `AnthropicBackend`, `OllamaBackend` with bounded retry policy (0.5 s + 1.5 s)
- [x] `ProtocolResponder.get_response()` orchestration: cache → classify → chain → shape-validate
- [x] HTTP status line + SMTP 3-digit code + UTF-8 SSH shape validators
- [x] `redact_prompt()` scrubs passwords, bearer tokens, AWS keys, PEM blocks before prompts leave the process
- [x] Metrics: `honeytrap_ai_intent_total`, `honeytrap_ai_backend_used_total` counters; `honeytrap_ai_cache_hit_ratio` gauge
- [x] HIGH-severity intent transition alert callback (fires once per transition)
- [x] API: `GET /api/v1/sessions/{id}/memory`, `GET /api/v1/intel/intents`, `GET /api/v1/ai/backends`
- [x] CLI: `--ai-enabled/--no-ai`, `--ai-backend`, `--ai-dry-run`, and `honeytrap ai test` subcommand
- [x] `ai:` config block with `adaptive_enabled`, memory/intent/cache toggles, backends list, `redact_secrets_in_prompts`, `force_backend`
- [x] 48 new tests under `tests/ai/` covering memory, intent, cache, each backend, adapter shape + safety paths, and all three API endpoints

## Phase 14 — Threat Intel Sharing & SIEM Integration (Cycle 12, 2026-04-23)

- [x] STIX 2.1 bundle generator under `honeytrap.intel.stix` with deterministic UUID5 IDs and natural-key dedup
- [x] STIX SDOs: identity, indicator, observed-data, attack-pattern, malware, campaign, infrastructure, note (with `x_ja3` / `x_ja4` custom properties)
- [x] STIX SROs: relationship and sighting wiring sessions, campaigns, IOCs, and ATT&CK techniques
- [x] Stdlib-only structural validator raising `StixValidationError`
- [x] TAXII 2.1 read-only server mounted at `/taxii/2.1` reusing the management-API auth, RBAC, audit, and rate-limiting
- [x] TAXII discovery, root, collections, objects (paginated via `next` / `limit` / `added_after` / `match[*]`), single-object, manifest, status endpoints
- [x] Five stable-id collections split by SDO family (indicators, attack-patterns, observed-data, sightings, notes)
- [x] Pluggable log-sink pipeline: bounded queue (10,000), `drop_oldest`/`drop_new`/`block` overflow, batcher (500 / 1 s), retry (0.25 s..30 s, 5 attempts, jitter), circuit breaker (10 failures / 30 s cooldown)
- [x] Sinks: `elasticsearch` (bulk API + index template + 429 Retry-After), `opensearch` subclass, `splunk_hec` (envelope + token from env), `file_jsonl` (daily rotation)
- [x] ECS v8.x mapper used by ES/OS sinks and (by default) the JSONL sink
- [x] CLI: `honeytrap sinks test <name>`, `honeytrap sinks health [--json]`, `honeytrap export stix --session/--ip/--since/--until --out [--pretty]`
- [x] API: `GET /api/v1/intel/stix` (analyst), `GET /api/v1/sinks` (viewer), `POST /api/v1/sinks/{name}/flush` (admin)
- [x] Metrics: `honeytrap_stix_bundles_generated_total`, `honeytrap_stix_objects_total{type}`, `honeytrap_taxii_requests_total{endpoint,status}`, `honeytrap_sink_events_total`, `honeytrap_sink_dropped_total{sink,reason}`, `honeytrap_sink_send_duration_seconds`, `honeytrap_sink_queue_depth`, `honeytrap_sink_circuit_state`
- [x] Secrets only via env vars (`api_key_env`, `username_env`/`password_env`, `SPLUNK_HEC_TOKEN`)
- [x] 58 new tests covering builder, validator, pipeline, retry, breaker, ECS mapping, ES/HEC/JSONL IO, factory dispatch, CLI, and STIX/TAXII/sinks API endpoints
