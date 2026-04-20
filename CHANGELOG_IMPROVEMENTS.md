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
