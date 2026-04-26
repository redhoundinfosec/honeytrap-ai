"""Rule engine that converts honeypot events into :class:`Alert` objects.

The :class:`AlertRuleEngine` is stateless apart from the small amount of
memory required for the first-seen-IP and brute-force sliding-window
rules. Rules are implemented as plain functions returning zero or more
alerts; users can register custom rules via
:meth:`AlertRuleEngine.register_rule`.
"""

from __future__ import annotations

import logging
import threading
from collections import deque
from collections.abc import Callable
from typing import Any

from honeytrap.alerts.models import Alert, AlertSeverity

logger = logging.getLogger(__name__)


RuleFn = Callable[[dict[str, Any], "AlertRuleContext"], list[Alert]]


_DEFAULT_CREDS: set[tuple[str, str]] = {
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
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

_CRITICAL_TECHNIQUES: set[str] = {"T1059", "T1078", "T1190"}

_COMMAND_EVENT_TYPES = {"shell_command", "command", "exec"}
_UPLOAD_EVENT_TYPES = {"file_upload", "upload", "stor", "put_file"}
_DOWNLOAD_EVENT_TYPES = {"file_download", "download", "retr", "get_file"}


class AlertRuleContext:
    """Shared mutable state consulted by the built-in rules.

    Kept thread-safe because rules may be evaluated from asyncio tasks
    running on different threads when channel dispatch happens under
    an executor.
    """

    def __init__(
        self,
        *,
        brute_force_threshold: int = 10,
        brute_force_window_seconds: float = 60.0,
        ioc_blocklist: set[str] | None = None,
    ) -> None:
        """Create an empty rule context."""
        self._lock = threading.Lock()
        self._seen_ips: set[str] = set()
        self._failed_auth: dict[str, deque[float]] = {}
        self.brute_force_threshold = int(brute_force_threshold)
        self.brute_force_window_seconds = float(brute_force_window_seconds)
        self.ioc_blocklist: set[str] = {x.lower() for x in (ioc_blocklist or set())}

    def first_seen(self, ip: str) -> bool:
        """Record ``ip`` and return True the first time it is observed."""
        if not ip:
            return False
        with self._lock:
            if ip in self._seen_ips:
                return False
            self._seen_ips.add(ip)
            return True

    def record_failed_auth(self, ip: str, timestamp: float) -> int:
        """Record a failed auth for ``ip`` and return the count inside the window."""
        if not ip:
            return 0
        with self._lock:
            bucket = self._failed_auth.setdefault(ip, deque())
            bucket.append(timestamp)
            cutoff = timestamp - self.brute_force_window_seconds
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            return len(bucket)

    def reset(self) -> None:
        """Forget all accumulated state. Used from tests."""
        with self._lock:
            self._seen_ips.clear()
            self._failed_auth.clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _event_field(event: dict[str, Any], key: str, default: str = "") -> str:
    value = event.get(key, default)
    return str(value) if value is not None else default


def _collect_techniques(event: dict[str, Any]) -> list[str]:
    data = event.get("data") or {}
    raw = data.get("attack_techniques") or []
    out: list[str] = []
    for entry in raw:
        if isinstance(entry, dict):
            tid = entry.get("technique_id")
            if tid:
                out.append(str(tid))
            sub = entry.get("sub_technique_id")
            if sub:
                out.append(str(sub))
        elif isinstance(entry, str):
            out.append(entry)
    # de-dup while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for t in out:
        if t not in seen:
            seen.add(t)
            unique.append(t)
    return unique


def _collect_iocs(event: dict[str, Any]) -> dict[str, list[str]]:
    data = event.get("data") or {}
    raw = data.get("iocs") or []
    out: dict[str, list[str]] = {}
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        itype = str(entry.get("type") or "unknown")
        value = str(entry.get("value") or "")
        if not value:
            continue
        out.setdefault(itype, []).append(value)
    return out


def _timestamp(event: dict[str, Any]) -> float:
    from datetime import datetime

    ts = event.get("timestamp")
    if isinstance(ts, (int, float)):
        return float(ts)
    if isinstance(ts, str):
        try:
            return datetime.fromisoformat(ts).timestamp()
        except ValueError:
            return 0.0
    return 0.0


def _base_alert(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "source_ip": _event_field(event, "remote_ip"),
        "protocol": _event_field(event, "protocol"),
        "session_id": _event_field(event, "session_id"),
        "raw_event": dict(event),
    }


# ---------------------------------------------------------------------------
# Built-in rules
# ---------------------------------------------------------------------------


def rule_first_seen_ip(event: dict[str, Any], ctx: AlertRuleContext) -> list[Alert]:
    """Emit a LOW alert the first time a source IP is observed."""
    ip = _event_field(event, "remote_ip")
    if not ip or ip == "0.0.0.0":
        return []
    if not ctx.first_seen(ip):
        return []
    techniques = _collect_techniques(event)
    iocs = _collect_iocs(event)
    return [
        Alert(
            title=f"New source IP observed: {ip}",
            summary=f"First-seen IP {ip} on {_event_field(event, 'protocol') or 'unknown'}",
            severity=AlertSeverity.LOW,
            attck_techniques=techniques,
            iocs=iocs,
            tags={"first-seen-ip"},
            **_base_alert(event),
        )
    ]


def rule_brute_force(event: dict[str, Any], ctx: AlertRuleContext) -> list[Alert]:
    """Emit a MEDIUM alert when failed auths exceed the threshold inside the window."""
    if _event_field(event, "event_type") != "auth_attempt":
        return []
    data = event.get("data") or {}
    success = bool(data.get("success"))
    if success:
        return []
    ip = _event_field(event, "remote_ip")
    count = ctx.record_failed_auth(ip, _timestamp(event) or 0.0)
    if count < ctx.brute_force_threshold:
        return []
    return [
        Alert(
            title=f"Brute force suspected from {ip}",
            summary=(
                f"{count} failed auths from {ip} on "
                f"{_event_field(event, 'protocol') or 'unknown'} "
                f"within {int(ctx.brute_force_window_seconds)}s"
            ),
            severity=AlertSeverity.MEDIUM,
            attck_techniques=_collect_techniques(event),
            iocs=_collect_iocs(event),
            tags={"brute-force"},
            **_base_alert(event),
        )
    ]


def rule_default_creds(event: dict[str, Any], ctx: AlertRuleContext) -> list[Alert]:
    """Emit a HIGH alert when an attacker authenticates with known default creds."""
    if _event_field(event, "event_type") != "auth_attempt":
        return []
    data = event.get("data") or {}
    if not bool(data.get("success")):
        return []
    username = _event_field(event, "username")
    password = _event_field(event, "password")
    if (username, password) not in _DEFAULT_CREDS:
        return []
    return [
        Alert(
            title=f"Successful auth with default creds ({username}:{password})",
            summary=(
                f"Attacker authenticated as {username!r} with default password "
                f"on {_event_field(event, 'protocol') or 'unknown'}"
            ),
            severity=AlertSeverity.HIGH,
            attck_techniques=_collect_techniques(event),
            iocs=_collect_iocs(event),
            tags={"default-creds", "valid-accounts"},
            **_base_alert(event),
        )
    ]


def rule_shell_command(event: dict[str, Any], ctx: AlertRuleContext) -> list[Alert]:
    """Emit a HIGH alert when a shell command is executed in a session."""
    etype = _event_field(event, "event_type")
    message = _event_field(event, "message")
    if etype not in _COMMAND_EVENT_TYPES and not message.lower().startswith("command:"):
        return []
    cmd = (event.get("data") or {}).get("command") or message
    cmd_trimmed = str(cmd)[:200]
    return [
        Alert(
            title="Shell command executed",
            summary=f"Command observed: {cmd_trimmed}",
            severity=AlertSeverity.HIGH,
            attck_techniques=_collect_techniques(event),
            iocs=_collect_iocs(event),
            tags={"command-exec"},
            **_base_alert(event),
        )
    ]


def rule_file_transfer(event: dict[str, Any], ctx: AlertRuleContext) -> list[Alert]:
    """Emit a MEDIUM alert for file upload/download attempts."""
    etype = _event_field(event, "event_type")
    if etype in _UPLOAD_EVENT_TYPES:
        direction = "upload"
    elif etype in _DOWNLOAD_EVENT_TYPES:
        direction = "download"
    else:
        return []
    filename = (
        (event.get("data") or {}).get("filename")
        or (event.get("data") or {}).get("path")
        or _event_field(event, "path")
    )
    return [
        Alert(
            title=f"File {direction} attempted",
            summary=f"File {direction}: {filename or 'unknown'}",
            severity=AlertSeverity.MEDIUM,
            attck_techniques=_collect_techniques(event),
            iocs=_collect_iocs(event),
            tags={f"file-{direction}"},
            **_base_alert(event),
        )
    ]


def rule_malicious_ioc(event: dict[str, Any], ctx: AlertRuleContext) -> list[Alert]:
    """Emit a HIGH alert when an extracted IOC appears on the blocklist."""
    if not ctx.ioc_blocklist:
        return []
    iocs = _collect_iocs(event)
    hits: list[str] = []
    for values in iocs.values():
        for v in values:
            if v.lower() in ctx.ioc_blocklist:
                hits.append(v)
    if not hits:
        return []
    return [
        Alert(
            title="Known malicious indicator observed",
            summary=f"Blocklisted IOC(s): {', '.join(hits[:5])}",
            severity=AlertSeverity.HIGH,
            attck_techniques=_collect_techniques(event),
            iocs=iocs,
            tags={"ioc-hit", "blocklist"},
            **_base_alert(event),
        )
    ]


def rule_critical_techniques(event: dict[str, Any], ctx: AlertRuleContext) -> list[Alert]:
    """Emit HIGH/CRITICAL alerts when critical ATT&CK techniques are observed."""
    techniques = _collect_techniques(event)
    if not techniques:
        return []
    critical_present = [t for t in techniques if t in _CRITICAL_TECHNIQUES]
    # Multiple techniques in a single session -> CRITICAL
    distinct_parents = {t.split(".")[0] for t in techniques}
    alerts: list[Alert] = []
    if len(distinct_parents) >= 2:
        alerts.append(
            Alert(
                title="Multiple ATT&CK techniques in one session",
                summary=(
                    f"Techniques observed: {', '.join(sorted(distinct_parents))} "
                    f"on {_event_field(event, 'protocol') or 'unknown'}"
                ),
                severity=AlertSeverity.CRITICAL,
                attck_techniques=techniques,
                iocs=_collect_iocs(event),
                tags={"multi-technique"},
                **_base_alert(event),
            )
        )
    elif critical_present:
        alerts.append(
            Alert(
                title=f"Critical ATT&CK technique: {critical_present[0]}",
                summary=(
                    f"Technique {critical_present[0]} observed on "
                    f"{_event_field(event, 'protocol') or 'unknown'}"
                ),
                severity=AlertSeverity.HIGH,
                attck_techniques=techniques,
                iocs=_collect_iocs(event),
                tags={"critical-technique"},
                **_base_alert(event),
            )
        )
    return alerts


def rule_tls_fingerprint(event: dict[str, Any], ctx: AlertRuleContext) -> list[Alert]:
    """Emit HIGH/MEDIUM alerts for known-malicious or scanner TLS fingerprints."""
    tls = (event.get("data") or {}).get("tls_fingerprint") or {}
    matches = tls.get("matches") or []
    if not matches:
        return []
    alerts: list[Alert] = []
    for match in matches:
        category = str(match.get("category") or "").lower()
        name = str(match.get("name") or "unknown")
        ja3 = tls.get("ja3") or ""
        if category in {"malware", "bot"}:
            severity = AlertSeverity.HIGH
        elif category in {"scanner", "pentest_tool"}:
            severity = AlertSeverity.MEDIUM
        else:
            continue
        alerts.append(
            Alert(
                title=f"TLS fingerprint match: {name}",
                summary=(
                    f"JA3 {ja3} on {_event_field(event, 'protocol') or 'unknown'} "
                    f"matched {name} ({category})"
                ),
                severity=severity,
                attck_techniques=_collect_techniques(event),
                iocs=_collect_iocs(event),
                tags={"tls-fingerprint", f"tls-{category}"},
                **_base_alert(event),
            )
        )
    return alerts


_MQTT_C2_TOPIC_MARKERS = ("/cmd", "/exec", "/ota", "/firmware/upload", "/c2", "/control")
_COAP_SENSITIVE_PATHS = (
    "config",
    "credential",
    "secret",
    "token",
    "fw/upload",
    "fw/update",
    "firmware/upload",
)


def rule_rdp_scanner_cookie(event: dict[str, Any], ctx: AlertRuleContext) -> list[Alert]:
    """Emit a MEDIUM alert when an RDP CR-TPDU cookie looks scanner-generated."""
    if _event_field(event, "protocol") != "rdp":
        return []
    if _event_field(event, "event_type") not in {"x224_connect_request", "connection_request"}:
        return []
    data = event.get("data") or {}
    if not bool(data.get("scanner_like_cookie")):
        return []
    cookie = str(data.get("mstshash") or data.get("cookie") or "")
    return [
        Alert(
            title="RDP scanner cookie observed",
            summary=f"mstshash={cookie[:64]} matches a known scanner pattern",
            severity=AlertSeverity.MEDIUM,
            attck_techniques=_collect_techniques(event),
            iocs=_collect_iocs(event),
            tags={"rdp-scanner", "reconnaissance"},
            **_base_alert(event),
        )
    ]


def rule_mqtt_c2_topic(event: dict[str, Any], ctx: AlertRuleContext) -> list[Alert]:
    """Emit a HIGH alert when an MQTT publish/subscribe targets a C2-style topic."""
    if _event_field(event, "protocol") != "mqtt":
        return []
    if _event_field(event, "event_type") not in {"publish", "subscribe"}:
        return []
    topic = str((event.get("data") or {}).get("topic") or "").lower()
    if not topic:
        return []
    if not any(marker in topic for marker in _MQTT_C2_TOPIC_MARKERS):
        return []
    return [
        Alert(
            title="MQTT command-and-control topic targeted",
            summary=f"{_event_field(event, 'event_type')} on suspicious topic {topic[:80]}",
            severity=AlertSeverity.HIGH,
            attck_techniques=_collect_techniques(event),
            iocs=_collect_iocs(event),
            tags={"mqtt-c2", "command-control"},
            **_base_alert(event),
        )
    ]


def rule_mqtt_scanner_client(event: dict[str, Any], ctx: AlertRuleContext) -> list[Alert]:
    """Emit a MEDIUM alert when an MQTT CONNECT carries a scanner-style client_id."""
    if _event_field(event, "protocol") != "mqtt":
        return []
    if _event_field(event, "event_type") not in {"mqtt_connect", "connect"}:
        return []
    data = event.get("data") or {}
    if not bool(data.get("scanner_like_client_id")) and not bool(data.get("empty_client_id")):
        return []
    client_id = str(data.get("client_id") or "")
    return [
        Alert(
            title="MQTT scanner client_id",
            summary=f"client_id={client_id!r} matches a scanner pattern",
            severity=AlertSeverity.MEDIUM,
            attck_techniques=_collect_techniques(event),
            iocs=_collect_iocs(event),
            tags={"mqtt-scanner", "reconnaissance"},
            **_base_alert(event),
        )
    ]


def rule_coap_sensitive_path(event: dict[str, Any], ctx: AlertRuleContext) -> list[Alert]:
    """Emit a MEDIUM alert when a CoAP request targets a config/firmware-style path."""
    if _event_field(event, "protocol") != "coap":
        return []
    if _event_field(event, "event_type") not in {"coap_request", "request"}:
        return []
    data = event.get("data") or {}
    uri_path = str(data.get("uri_path") or _event_field(event, "path") or "").lower()
    if not uri_path:
        return []
    if not any(marker in uri_path for marker in _COAP_SENSITIVE_PATHS):
        return []
    return [
        Alert(
            title="CoAP sensitive path requested",
            summary=f"CoAP request targeted {uri_path[:80]}",
            severity=AlertSeverity.MEDIUM,
            attck_techniques=_collect_techniques(event),
            iocs=_collect_iocs(event),
            tags={"coap-sensitive-path"},
            **_base_alert(event),
        )
    ]


def rule_coap_amplification(event: dict[str, Any], ctx: AlertRuleContext) -> list[Alert]:
    """Emit a HIGH alert when a CoAP request looks like a reflection/amplification probe."""
    if _event_field(event, "protocol") != "coap":
        return []
    if _event_field(event, "event_type") not in {"amplification_probe", "amplification"}:
        return []
    data = event.get("data") or {}
    ratio = data.get("amplification_ratio")
    return [
        Alert(
            title="CoAP amplification probe",
            summary=(
                f"Suspicious CoAP request with amplification ratio "
                f"{ratio if ratio is not None else 'unknown'}"
            ),
            severity=AlertSeverity.HIGH,
            attck_techniques=_collect_techniques(event),
            iocs=_collect_iocs(event),
            tags={"coap-amplification", "reflection"},
            **_base_alert(event),
        )
    ]


DEFAULT_RULES: tuple[RuleFn, ...] = (
    rule_first_seen_ip,
    rule_brute_force,
    rule_default_creds,
    rule_shell_command,
    rule_file_transfer,
    rule_malicious_ioc,
    rule_critical_techniques,
    rule_tls_fingerprint,
    rule_rdp_scanner_cookie,
    rule_mqtt_c2_topic,
    rule_mqtt_scanner_client,
    rule_coap_sensitive_path,
    rule_coap_amplification,
)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class AlertRuleEngine:
    """Evaluates events against registered rules, returning :class:`Alert`\\ s."""

    def __init__(
        self,
        *,
        rules: tuple[RuleFn, ...] | None = None,
        context: AlertRuleContext | None = None,
    ) -> None:
        """Create an engine pre-loaded with the default rules (unless ``rules`` is given)."""
        self._rules: list[RuleFn] = list(rules if rules is not None else DEFAULT_RULES)
        self.context = context or AlertRuleContext()

    def register_rule(self, rule: RuleFn) -> None:
        """Append a custom rule to the evaluation chain."""
        if not callable(rule):
            raise TypeError("rule must be callable")
        self._rules.append(rule)

    def clear_rules(self) -> None:
        """Remove every registered rule (use sparingly, mostly for tests)."""
        self._rules.clear()

    @property
    def rules(self) -> tuple[RuleFn, ...]:
        """Return the current rule tuple (read-only view)."""
        return tuple(self._rules)

    def evaluate(self, event: dict[str, Any]) -> list[Alert]:
        """Run every rule against ``event`` and return the combined alerts."""
        out: list[Alert] = []
        for rule in self._rules:
            try:
                result = rule(event, self.context) or []
            except Exception as exc:  # noqa: BLE001
                logger.exception("Alert rule %s failed: %s", getattr(rule, "__name__", rule), exc)
                continue
            out.extend(result)
        return out
