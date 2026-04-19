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
