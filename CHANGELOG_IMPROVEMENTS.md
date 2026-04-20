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
