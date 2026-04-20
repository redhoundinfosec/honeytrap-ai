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
- [ ] Full impacket-backed SMB share server
- [ ] SMTP handler (aiosmtpd)
- [ ] MySQL handler
- [ ] Optional Textual-based interactive dashboard with filters
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
