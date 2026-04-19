"""Rule-based response engine and attack pattern detector.

The rule engine covers the common attack surface without any external
dependencies:

* HTTP path/UA pattern matching for admin panels, exploits, traversal, scanners.
* SSH credential-list hits.
* FTP anonymous/list detection.
* Shell-command pattern matching (for fake SSH shells).
* Scanner fingerprinting (Nmap, Masscan, ZGrab, Nikto, sqlmap…).
* Brute-force threshold detection (per-session).

The result of any :meth:`RuleEngine.match_*` call is a :class:`RuleMatch`
with a suggested response and one or more tags (``brute_force``,
``path_traversal``, ``scanner``, etc.).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from honeytrap.core.profile import DeviceProfile

logger = logging.getLogger(__name__)


@dataclass
class RuleMatch:
    """Outcome of a rule-engine match."""

    category: str  # e.g. "admin_panel", "path_traversal", "scanner"
    response: str  # text or HTML body suggested to the caller
    tags: list[str] = field(default_factory=list)
    status_code: int = 200
    metadata: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.5


_SCANNER_UA_PATTERNS = [
    (re.compile(r"(?i)\bnmap\b"), "nmap"),
    (re.compile(r"(?i)masscan"), "masscan"),
    (re.compile(r"(?i)zgrab"), "zgrab"),
    (re.compile(r"(?i)nikto"), "nikto"),
    (re.compile(r"(?i)sqlmap"), "sqlmap"),
    (re.compile(r"(?i)nuclei"), "nuclei"),
    (re.compile(r"(?i)acunetix"), "acunetix"),
    (re.compile(r"(?i)curl/"), "curl"),
    (re.compile(r"(?i)python-requests"), "python-requests"),
    (re.compile(r"(?i)go-http-client"), "go-http-client"),
    (re.compile(r"(?i)dirbuster"), "dirbuster"),
    (re.compile(r"(?i)gobuster"), "gobuster"),
    (re.compile(r"(?i)wpscan"), "wpscan"),
]

_PATH_TRAVERSAL_RE = re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|/\.\./|\.\.%2f)", re.IGNORECASE)
_SHELL_INJECTION_RE = re.compile(r"(;|\|\||\$\(|`|&&|%0a)", re.IGNORECASE)
_LOG4J_RE = re.compile(r"\$\{jndi:", re.IGNORECASE)
_SQLI_RE = re.compile(
    r"(?i)(union\s+select|or\s+1=1|';|--\s|/\*|benchmark\(|sleep\()",
)
_XSS_RE = re.compile(r"(?i)(<script|javascript:|onerror=)")

_ADMIN_PATHS = {
    "/admin",
    "/admin/",
    "/admin/login",
    "/manager/html",
    "/phpmyadmin",
    "/pma",
    "/dbadmin",
    "/wp-admin",
    "/wp-admin/",
    "/wp-login.php",
    "/administrator",
    "/cpanel",
    "/webmail",
}

_SENSITIVE_FILES = {
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/.svn/entries",
    "/config.php",
    "/wp-config.php",
    "/server-status",
    "/phpinfo.php",
    "/.aws/credentials",
    "/etc/passwd",
    "/etc/shadow",
}

_FAKE_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
    "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
    "sync:x:4:65534:sync:/bin:/bin/sync\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    "mysql:x:110:113:MySQL Server,,,:/nonexistent:/bin/false\n"
    "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
    "admin:x:1001:1001:Admin User:/home/admin:/bin/bash\n"
)


class RuleEngine:
    """Rule-based response engine + attack pattern tagger."""

    def __init__(self, profile: DeviceProfile) -> None:
        """Initialize the rule engine with built-in attack-pattern rules."""
        self.profile = profile
        # Track per-IP counters for brute-force detection.
        self._auth_attempts: dict[str, int] = {}
        self._path_hits: dict[str, int] = {}

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------
    def match_http(
        self,
        *,
        method: str,
        path: str,
        user_agent: str,
        remote_ip: str,
        body: str = "",
    ) -> RuleMatch:
        """Return the best-match response for an HTTP request."""
        tags: list[str] = []

        scanner = self._detect_scanner(user_agent)
        if scanner:
            tags.append("scanner")
            tags.append(f"tool:{scanner}")

        lower_path = path.lower()

        # Path traversal — CVE-2021-41773 style.
        if _PATH_TRAVERSAL_RE.search(path) or _PATH_TRAVERSAL_RE.search(body):
            tags.extend(["path_traversal", "exploit_attempt"])
            return RuleMatch(
                category="path_traversal",
                response=_FAKE_PASSWD,
                tags=tags,
                status_code=200,
                metadata={"content_type": "text/plain"},
                confidence=0.95,
            )

        if _LOG4J_RE.search(path) or _LOG4J_RE.search(body) or _LOG4J_RE.search(user_agent):
            tags.extend(["log4shell", "exploit_attempt"])
            return RuleMatch(
                category="log4shell",
                response="OK\n",
                tags=tags,
                status_code=200,
                confidence=0.95,
            )

        if _SQLI_RE.search(path) or _SQLI_RE.search(body):
            tags.extend(["sqli", "exploit_attempt"])

        if _XSS_RE.search(path) or _XSS_RE.search(body):
            tags.extend(["xss", "exploit_attempt"])

        if _SHELL_INJECTION_RE.search(path):
            tags.extend(["shell_injection", "exploit_attempt"])

        # Admin panel probes.
        for admin in _ADMIN_PATHS:
            if lower_path.startswith(admin):
                tags.extend(["admin_panel_probe"])
                return RuleMatch(
                    category="admin_panel",
                    response="",
                    tags=tags,
                    status_code=200,
                    metadata={"admin_path": admin},
                    confidence=0.9,
                )

        # Sensitive file exposure.
        if lower_path in _SENSITIVE_FILES:
            tags.extend(["sensitive_file_probe", "exploit_attempt"])
            content = self._sensitive_file_body(lower_path)
            return RuleMatch(
                category="sensitive_file",
                response=content,
                tags=tags,
                status_code=200,
                metadata={"content_type": "text/plain"},
                confidence=0.9,
            )

        # Default: generic 404 unless the path is "/"
        if path in {"", "/"}:
            return RuleMatch(
                category="default_page",
                response="",
                tags=tags,
                status_code=200,
                confidence=0.3,
            )
        return RuleMatch(
            category="not_found",
            response=self._apache_404(path),
            tags=tags,
            status_code=404,
            metadata={"content_type": "text/html"},
            confidence=0.3,
        )

    # ------------------------------------------------------------------
    # SSH / Telnet / FTP auth
    # ------------------------------------------------------------------
    def match_auth(
        self, *, protocol: str, username: str, password: str, remote_ip: str
    ) -> RuleMatch:
        """Return a rule match for a credential attempt."""
        count = self._auth_attempts.get(remote_ip, 0) + 1
        self._auth_attempts[remote_ip] = count
        tags = ["auth_attempt"]
        if count >= 5:
            tags.append("brute_force")

        service = self.profile.service(protocol)
        weak: list[dict[str, str]] = []
        if service:
            weak = service.data.get("weak_credentials", []) or []

        for entry in weak:
            if (
                entry.get("username") == username
                and entry.get("password") == password
            ):
                tags.append("weak_cred_hit")
                return RuleMatch(
                    category="auth_success",
                    response="",
                    tags=tags,
                    status_code=0,
                    metadata={"granted": True},
                    confidence=1.0,
                )

        return RuleMatch(
            category="auth_failure",
            response="",
            tags=tags,
            metadata={"granted": False},
            confidence=0.9,
        )

    # ------------------------------------------------------------------
    # Shell commands (for fake SSH/Telnet sessions)
    # ------------------------------------------------------------------
    def shell_response(self, command: str) -> str:
        """Return canned output for common shell commands."""
        cmd = command.strip()
        if not cmd:
            return ""
        first = cmd.split()[0].lower()

        canned = {
            "ls": "bin  boot  dev  etc  home  lib  mnt  opt  proc  root  sbin  srv  tmp  usr  var",
            "pwd": "/root",
            "whoami": "root",
            "id": "uid=0(root) gid=0(root) groups=0(root)",
            "uname": "Linux honeypot 5.15.0-88-generic #98-Ubuntu SMP x86_64 GNU/Linux",
            "hostname": "honeypot",
            "date": "Sun Apr 19 12:34:56 UTC 2026",
            "uptime": " 12:34:56 up 47 days,  6:12,  1 user,  load average: 0.08, 0.03, 0.01",
            "ps": (
                "  PID TTY          TIME CMD\n"
                "    1 ?        00:00:05 systemd\n"
                "  823 ?        00:00:00 sshd\n"
                " 1023 ?        00:00:02 apache2\n"
                " 1456 pts/0    00:00:00 bash\n"
                " 1500 pts/0    00:00:00 ps"
            ),
            "w": " 12:34:56 up 47 days,  load average: 0.08, 0.03, 0.01\nUSER     TTY      LOGIN@   IDLE  JCPU  PCPU WHAT\nroot     pts/0    12:00     0.00s 0.02s 0.00s w",
            "exit": "",
            "logout": "",
            "clear": "",
        }
        if first in canned:
            return canned[first]
        if first == "cat":
            if "/etc/passwd" in cmd:
                return _FAKE_PASSWD
            if "/etc/shadow" in cmd:
                return "cat: /etc/shadow: Permission denied"
            return ""
        if first == "wget" or first == "curl":
            # Pretend the download worked — record intent in metadata.
            return f"--2026-04-19 12:34:56--  {cmd.split()[-1]}\nResolving... 203.0.113.25\nConnecting... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: 0 [text/plain]\nSaving to: 'index.html'"
        if first == "echo":
            return cmd[4:].strip().strip("'\"")
        return f"{first}: command not found"

    # ------------------------------------------------------------------
    # Pattern detection
    # ------------------------------------------------------------------
    def _detect_scanner(self, user_agent: str) -> str | None:
        for pattern, name in _SCANNER_UA_PATTERNS:
            if pattern.search(user_agent or ""):
                return name
        return None

    def _sensitive_file_body(self, path: str) -> str:
        """Return canned fake contents for a 'leaked' sensitive file."""
        if path.endswith("/.env"):
            return (
                "APP_NAME=TechNova\n"
                "APP_ENV=production\n"
                "APP_KEY=base64:FAKE_KEY_DO_NOT_USE==\n"
                "DB_HOST=127.0.0.1\n"
                "DB_DATABASE=technova\n"
                "DB_USERNAME=technova_rw\n"
                "DB_PASSWORD=hunter2\n"
                "AWS_ACCESS_KEY_ID=AKIA0000EXAMPLE0000\n"
                "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            )
        if path.endswith("/.git/HEAD"):
            return "ref: refs/heads/main\n"
        if path.endswith("/.git/config"):
            return (
                "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n"
                "[remote \"origin\"]\n\turl = git@github.com:technova/internal.git\n"
                "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
            )
        if path.endswith("/etc/passwd"):
            return _FAKE_PASSWD
        if path.endswith("/phpinfo.php"):
            return "<html><body><h1>PHP Version 7.4.3</h1><p>Configuration intentionally omitted.</p></body></html>"
        if path.endswith("/server-status"):
            return (
                "<html><head><title>Apache Status</title></head><body>"
                "<h1>Apache Server Status for localhost</h1>"
                "<p>Server Version: Apache/2.4.49 (Ubuntu)</p>"
                "<p>Server uptime: 47 days 6 hours 12 minutes</p>"
                "</body></html>"
            )
        return ""

    def _apache_404(self, path: str) -> str:
        """Return an Apache-style 404 body."""
        safe_path = re.sub(r"[<>\"]", "", path)
        return (
            "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
            "<html><head>\n"
            "<title>404 Not Found</title>\n"
            "</head><body>\n"
            "<h1>Not Found</h1>\n"
            f"<p>The requested URL {safe_path} was not found on this server.</p>\n"
            "<hr>\n"
            "<address>Apache/2.4.49 (Ubuntu) Server at localhost Port 80</address>\n"
            "</body></html>\n"
        )
