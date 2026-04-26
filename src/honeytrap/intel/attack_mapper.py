"""MITRE ATT&CK technique mapping for honeypot events.

Every technique ID, name, and tactic here matches the official MITRE
ATT&CK Enterprise framework (v14). The mapper is deliberately
rule-based — it is fast, dependency-free, auditable, and produces
results that analysts can defend in a report.

Typical usage::

    mapper = ATTACKMapper()
    mappings = mapper.map_event(event.to_dict())
    for m in mappings:
        db.record_attack_mapping(event_id, m)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Technique database
# ---------------------------------------------------------------------------

TECHNIQUE_DB: dict[str, dict[str, str]] = {
    "T1190": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": (
            "Adversaries attempt to exploit a weakness in an Internet-facing "
            "computer or program using software, data, or commands in order to "
            "cause unintended or unanticipated behavior."
        ),
    },
    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may use brute force techniques to gain access to "
            "accounts when passwords are unknown or when password hashes are "
            "obtained."
        ),
    },
    "T1110.001": {
        "id": "T1110.001",
        "name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "description": (
            "Adversaries with no prior knowledge of legitimate credentials "
            "may guess passwords to attempt access to accounts."
        ),
    },
    "T1110.004": {
        "id": "T1110.004",
        "name": "Brute Force: Credential Stuffing",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may use credentials obtained from breach dumps of "
            "unrelated accounts to gain access to target accounts through "
            "credential overlap."
        ),
    },
    "T1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": (
            "Adversaries may abuse command and script interpreters to execute "
            "commands, scripts, or binaries."
        ),
    },
    "T1105": {
        "id": "T1105",
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": (
            "Adversaries may transfer tools or other files from an external "
            "system into a compromised environment."
        ),
    },
    "T1135": {
        "id": "T1135",
        "name": "Network Share Discovery",
        "tactic": "Discovery",
        "description": (
            "Adversaries may look for folders and drives shared on remote "
            "systems as a means of identifying sources of information to "
            "gather."
        ),
    },
    "T1046": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": (
            "Adversaries may attempt to get a listing of services running on "
            "remote hosts and local network infrastructure devices."
        ),
    },
    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may obtain and abuse credentials of existing accounts "
            "as a means of gaining Initial Access, Persistence, Privilege "
            "Escalation, or Defense Evasion."
        ),
    },
    "T1595": {
        "id": "T1595",
        "name": "Active Scanning",
        "tactic": "Reconnaissance",
        "description": (
            "Adversaries may execute active reconnaissance scans to gather "
            "information that can be used during targeting."
        ),
    },
    "T1595.002": {
        "id": "T1595.002",
        "name": "Active Scanning: Vulnerability Scanning",
        "tactic": "Reconnaissance",
        "description": (
            "Adversaries may scan victims for vulnerabilities that can be "
            "used during targeting, often using scanner tools that look for "
            "known weaknesses."
        ),
    },
    "T1071.001": {
        "id": "T1071.001",
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "description": (
            "Adversaries may communicate using application layer protocols "
            "associated with web traffic to avoid detection."
        ),
    },
    "T1021.002": {
        "id": "T1021.002",
        "name": "Remote Services: SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "description": (
            "Adversaries may use Valid Accounts to interact with a remote "
            "network share using Server Message Block (SMB)."
        ),
    },
    "T1021.004": {
        "id": "T1021.004",
        "name": "Remote Services: SSH",
        "tactic": "Lateral Movement",
        "description": (
            "Adversaries may use Valid Accounts to log into remote machines "
            "using Secure Shell (SSH)."
        ),
    },
    "T1083": {
        "id": "T1083",
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "description": (
            "Adversaries may enumerate files and directories or may search in "
            "specific locations of a host or network share for certain "
            "information within a file system."
        ),
    },
    "T1552.001": {
        "id": "T1552.001",
        "name": "Unsecured Credentials: Credentials In Files",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may search local file systems and remote file shares "
            "for files containing insecurely stored credentials."
        ),
    },
    "T1071.003": {
        "id": "T1071.003",
        "name": "Application Layer Protocol: Mail Protocols",
        "tactic": "Command and Control",
        "description": (
            "Adversaries may communicate using application layer protocols "
            "associated with electronic mail delivery to avoid detection."
        ),
    },
    "T1005": {
        "id": "T1005",
        "name": "Data from Local System",
        "tactic": "Collection",
        "description": (
            "Adversaries may search local system sources, such as file "
            "systems and configuration files or local databases, to find "
            "files of interest and sensitive data."
        ),
    },
    "T1114": {
        "id": "T1114",
        "name": "Email Collection",
        "tactic": "Collection",
        "description": ("Adversaries may target user email to collect sensitive information."),
    },
    "T1114.002": {
        "id": "T1114.002",
        "name": "Email Collection: Remote Email Collection",
        "tactic": "Collection",
        "description": (
            "Adversaries may target an Exchange or other mail server with "
            "valid accounts to collect sensitive information remotely."
        ),
    },
    "T1021.001": {
        "id": "T1021.001",
        "name": "Remote Services: Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "description": (
            "Adversaries may use Valid Accounts to log into a computer "
            "using the Remote Desktop Protocol (RDP)."
        ),
    },
    "T1071": {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": (
            "Adversaries may communicate using application layer protocols "
            "associated with operational network traffic to avoid detection."
        ),
    },
    "T1602": {
        "id": "T1602",
        "name": "Data from Configuration Repository",
        "tactic": "Collection",
        "description": (
            "Adversaries may collect data related to managed devices from "
            "configuration repositories."
        ),
    },
    "T1090": {
        "id": "T1090",
        "name": "Proxy",
        "tactic": "Command and Control",
        "description": (
            "Adversaries may use a connection proxy to direct network "
            "traffic between systems or act as an intermediary for "
            "network communications."
        ),
    },
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class ATTACKMapping:
    """A single MITRE ATT&CK classification for an observed event."""

    technique_id: str
    technique_name: str
    tactic: str
    sub_technique_id: str | None = None
    confidence: float = 0.8
    matched_on: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-ready representation."""
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "sub_technique_id": self.sub_technique_id,
            "confidence": self.confidence,
            "matched_on": self.matched_on,
        }

    @classmethod
    def from_technique(
        cls,
        technique_id: str,
        *,
        confidence: float = 0.8,
        matched_on: str = "",
    ) -> ATTACKMapping:
        """Build a mapping from the technique DB by ID."""
        meta = TECHNIQUE_DB.get(technique_id)
        if meta is None:
            raise KeyError(f"Unknown technique id: {technique_id}")
        parent_id = technique_id.split(".", 1)[0]
        sub_id = technique_id if "." in technique_id else None
        return cls(
            technique_id=parent_id,
            technique_name=meta["name"],
            tactic=meta["tactic"],
            sub_technique_id=sub_id,
            confidence=confidence,
            matched_on=matched_on,
        )


# ---------------------------------------------------------------------------
# Heuristics
# ---------------------------------------------------------------------------


_TRAVERSAL_RE = re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%252e%252e|/etc/passwd|/etc/shadow)", re.I)
_ADMIN_PANELS = (
    "/wp-admin",
    "/wp-login",
    "/phpmyadmin",
    "/admin",
    "/administrator",
    "/manager/html",
    "/cpanel",
    "/webmail",
    "/mysql",
    "/xmlrpc.php",
)
_SECRET_PATHS = (
    "/.env",
    "/.git",
    "/.aws",
    "/.ssh",
    "/.bash_history",
    "/config.php",
    "/wp-config.php",
    "/id_rsa",
)
_SQL_INJECTION_RE = re.compile(
    r"(union\s+select|or\s+1=1|'\s*or\s*'1'='1|select\s+.*from|information_schema|sleep\(\d+\))",
    re.I,
)
_LOG4SHELL_RE = re.compile(r"\$\{jndi:(ldap|rmi|dns|ldaps|iiop|nis|nds|corba)://", re.I)
_DOWNLOAD_RE = re.compile(r"\b(wget|curl|tftp|fetch|certutil)\b", re.I)
_PORT_SCAN_EVENT_TYPES = {"port_scan", "connection_attempt", "scan"}

_SCANNER_UAS = (
    "sqlmap",
    "nikto",
    "nmap",
    "nuclei",
    "gobuster",
    "dirbuster",
    "wpscan",
    "masscan",
    "zgrab",
    "acunetix",
    "burp",
    "fuzz",
    "feroxbuster",
    "arachni",
    "openvas",
)

_COMMON_WEAK_CREDS: set[tuple[str, str]] = {
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "1234"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("root", ""),
    ("root", "123456"),
    ("user", "user"),
    ("test", "test"),
    ("guest", "guest"),
    ("pi", "raspberry"),
    ("ubnt", "ubnt"),
    ("support", "support"),
    ("oracle", "oracle"),
    ("postgres", "postgres"),
}


def _lowercase(value: Any) -> str:
    return str(value or "").lower()


# ---------------------------------------------------------------------------
# Mapper
# ---------------------------------------------------------------------------


@dataclass
class ATTACKMapper:
    """Rule-based MITRE ATT&CK classifier for honeypot events."""

    technique_db: dict[str, dict[str, str]] = field(default_factory=lambda: dict(TECHNIQUE_DB))

    def describe(self, technique_id: str) -> dict[str, str] | None:
        """Return the TECHNIQUE_DB entry for ``technique_id`` if known."""
        return self.technique_db.get(technique_id)

    def map_event(self, event: dict[str, Any]) -> list[ATTACKMapping]:
        """Classify an event into zero or more ATT&CK mappings.

        ``event`` should follow the shape of :class:`honeytrap.logging.models.Event.to_dict`
        — specifically fields: ``protocol``, ``event_type``, ``path``,
        ``method``, ``user_agent``, ``username``, ``password``, ``message``,
        and ``data``.
        """

        protocol = _lowercase(event.get("protocol"))
        event_type = _lowercase(event.get("event_type"))
        path = _lowercase(event.get("path"))
        ua = _lowercase(event.get("user_agent"))
        username = str(event.get("username") or "")
        password = str(event.get("password") or "")
        message = _lowercase(event.get("message"))
        data = event.get("data") or {}
        payload = _lowercase(data.get("body") or data.get("payload") or data.get("raw") or "")
        combined = f"{path} {message} {payload}"

        mappings: list[ATTACKMapping] = []
        seen: set[str] = set()

        def add(technique_id: str, *, confidence: float = 0.8, matched_on: str = "") -> None:
            key = technique_id
            if key in seen:
                return
            seen.add(key)
            mappings.append(
                ATTACKMapping.from_technique(
                    technique_id, confidence=confidence, matched_on=matched_on
                )
            )

        # --------- HTTP ---------
        if protocol in {"http", "https"}:
            # Scanner fingerprint via User-Agent.
            for tool in _SCANNER_UAS:
                if tool in ua:
                    add("T1595.002", confidence=0.95, matched_on=f"ua={tool}")
                    break

            if _TRAVERSAL_RE.search(combined):
                add("T1190", confidence=0.9, matched_on="path-traversal")
                add("T1083", confidence=0.6, matched_on="path-traversal")

            if any(p in path for p in _ADMIN_PANELS):
                add("T1190", confidence=0.75, matched_on="admin-panel")

            if any(p in path for p in _SECRET_PATHS):
                add("T1190", confidence=0.85, matched_on="secret-path")
                add("T1552.001", confidence=0.8, matched_on="secret-path")

            if _SQL_INJECTION_RE.search(combined):
                add("T1190", confidence=0.9, matched_on="sql-injection")

            if _LOG4SHELL_RE.search(combined) or "jndi:" in combined:
                add("T1190", confidence=0.95, matched_on="log4shell")

            if _DOWNLOAD_RE.search(combined):
                add("T1105", confidence=0.75, matched_on="download-cmd")

            # Generic HTTP interaction (for any request).
            if event_type in {"http_request", "request"}:
                add("T1071.001", confidence=0.3, matched_on="http-request")

        # --------- SSH ---------
        if protocol == "ssh":
            if event_type == "auth_attempt":
                add("T1110.001", confidence=0.85, matched_on="ssh-auth")
                if (username, password) in _COMMON_WEAK_CREDS:
                    add("T1110.004", confidence=0.8, matched_on="credential-stuffing")
            if event_type in {"shell_command", "command", "exec"} or message.startswith("command:"):
                add("T1059", confidence=0.85, matched_on="ssh-command")
                if _DOWNLOAD_RE.search(combined):
                    add("T1105", confidence=0.9, matched_on="download-cmd")
            if event_type == "session_open":
                add("T1021.004", confidence=0.5, matched_on="ssh-session")

        # --------- Telnet ---------
        if protocol == "telnet":
            if event_type == "auth_attempt":
                add("T1110.001", confidence=0.85, matched_on="telnet-auth")
                if (username, password) in _COMMON_WEAK_CREDS:
                    add("T1110.004", confidence=0.85, matched_on="mirai-creds")
            if event_type in {"shell_command", "command"} or message.startswith("command:"):
                add("T1059", confidence=0.8, matched_on="telnet-command")
                if _DOWNLOAD_RE.search(combined):
                    add("T1105", confidence=0.9, matched_on="download-cmd")

        # --------- FTP ---------
        if protocol == "ftp" and event_type == "auth_attempt":
            add("T1110.001", confidence=0.8, matched_on="ftp-auth")
            if username.lower() == "anonymous":
                add("T1078", confidence=0.7, matched_on="anonymous-login")

        # --------- SMB ---------
        if protocol == "smb":
            if (
                event_type
                in {
                    "share_enum",
                    "tree_connect",
                    "list_shares",
                    "smb_enum",
                }
                or "share" in message
            ):
                add("T1135", confidence=0.85, matched_on="smb-share-enum")
            if event_type == "auth_attempt":
                add("T1110.001", confidence=0.75, matched_on="smb-auth")
            if event_type == "session_open":
                add("T1021.002", confidence=0.6, matched_on="smb-session")

        # --------- SMTP ---------
        if protocol == "smtp":
            if event_type == "auth_attempt":
                add("T1110.001", confidence=0.8, matched_on="smtp-auth")
                if (username.lower(), password) in _COMMON_WEAK_CREDS:
                    add("T1110.004", confidence=0.8, matched_on="credential-stuffing")
            if event_type in {"mail_from", "rcpt_to", "data_received", "open_relay"}:
                add("T1071.003", confidence=0.7, matched_on="smtp-traffic")

        # --------- MySQL ---------
        if protocol == "mysql":
            if event_type == "auth_attempt":
                add("T1110.001", confidence=0.85, matched_on="mysql-auth")
                if (username, password) in _COMMON_WEAK_CREDS:
                    add("T1110.004", confidence=0.85, matched_on="credential-stuffing")
            if event_type == "query":
                query_text = _lowercase(data.get("query") or message)
                if _SQL_INJECTION_RE.search(query_text):
                    add("T1190", confidence=0.9, matched_on="sql-injection")
                if "select *" in query_text or "select\t*" in query_text:
                    add("T1005", confidence=0.75, matched_on="data-exfil-query")

        # --------- IMAP ---------
        if protocol == "imap":
            if event_type == "auth_attempt":
                add("T1110.001", confidence=0.85, matched_on="imap-auth")
                if (username, password) in _COMMON_WEAK_CREDS:
                    add("T1110.004", confidence=0.85, matched_on="credential-stuffing")
                add("T1078", confidence=0.6, matched_on="imap-auth")
            if event_type in {"select", "examine", "fetch", "search", "list"}:
                add("T1114", confidence=0.7, matched_on=f"imap-{event_type}")
                add("T1114.002", confidence=0.75, matched_on=f"imap-{event_type}")
            if event_type == "starttls":
                add("T1071", confidence=0.4, matched_on="imap-starttls")

        # --------- RDP ---------
        if protocol == "rdp":
            if event_type in {"x224_connect_request", "connection_request"}:
                add("T1021.001", confidence=0.8, matched_on="rdp-x224-cr")
                cookie = _lowercase(data.get("mstshash") or data.get("cookie"))
                if cookie:
                    add("T1078", confidence=0.55, matched_on=f"mstshash={cookie[:32]}")
            if event_type in {"ntlm_negotiate", "credssp"}:
                add("T1021.001", confidence=0.85, matched_on="rdp-ntlm")
                add("T1078", confidence=0.7, matched_on="rdp-ntlm")
            if event_type == "auth_attempt":
                add("T1110.001", confidence=0.8, matched_on="rdp-auth")
                if (username, password) in _COMMON_WEAK_CREDS:
                    add("T1110.004", confidence=0.85, matched_on="credential-stuffing")
            proxy_flag = _lowercase(data.get("proxy") or data.get("relay"))
            if proxy_flag in {"true", "1", "yes"} or "proxy" in message:
                add("T1090", confidence=0.6, matched_on="rdp-proxy")

        # --------- MQTT ---------
        if protocol == "mqtt":
            if event_type in {"mqtt_connect", "connect"}:
                add("T1071", confidence=0.55, matched_on="mqtt-connect")
                if (username, password) in _COMMON_WEAK_CREDS:
                    add("T1110.004", confidence=0.8, matched_on="mqtt-weak-creds")
            if event_type == "auth_attempt":
                add("T1110.001", confidence=0.8, matched_on="mqtt-auth")
            if event_type in {"publish", "subscribe"}:
                add("T1071", confidence=0.6, matched_on=f"mqtt-{event_type}")
                topic = _lowercase(data.get("topic"))
                if any(
                    marker in topic
                    for marker in ("/cmd", "/exec", "/ota", "/firmware/upload", "/c2")
                ):
                    add("T1190", confidence=0.75, matched_on=f"mqtt-c2-topic:{topic[:40]}")

        # --------- CoAP ---------
        if protocol == "coap":
            if event_type in {"coap_request", "request"}:
                add("T1071.001", confidence=0.5, matched_on="coap-request")
                coap_path = _lowercase(data.get("uri_path") or path)
                if any(
                    marker in coap_path
                    for marker in (
                        "config",
                        "credential",
                        "secret",
                        "token",
                        ".well-known/core",
                    )
                ):
                    add("T1602", confidence=0.8, matched_on=f"coap-config:{coap_path[:40]}")
                if any(
                    marker in coap_path for marker in ("fw/upload", "fw/update", "firmware/upload")
                ):
                    add("T1190", confidence=0.85, matched_on="coap-firmware")
            if event_type in {"amplification_probe", "amplification"}:
                add("T1190", confidence=0.85, matched_on="coap-amplification")

        # --------- Port scanning (any protocol) ---------
        if event_type in _PORT_SCAN_EVENT_TYPES:
            add("T1046", confidence=0.75, matched_on=event_type)

        # --------- TLS fingerprint attribution ---------
        tls_fp = data.get("tls_fingerprint") or {}
        for match in tls_fp.get("matches") or []:
            category = str(match.get("category") or "").lower()
            if category in {"scanner", "pentest_tool"}:
                add(
                    "T1595.002",
                    confidence=0.9,
                    matched_on=f"ja3-{category}:{match.get('name', '')}",
                )

        return mappings
