"""Indicator of Compromise (IOC) extraction.

Scans honeypot event payloads for standard IOC types — IP addresses,
URLs, domains, file hashes, email addresses, user-agent strings — and
returns a normalized, deduplicated list.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Regexes
# ---------------------------------------------------------------------------

_URL_RE = re.compile(
    r"\b(?:https?|ftp|tftp|file|smb)://[^\s\"'<>()\[\]{}]+",
    re.I,
)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(
    r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}\b"
)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b",
    re.I,
)
_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b"
)
_HASH_RES: dict[str, re.Pattern[str]] = {
    "md5": re.compile(r"\b[a-f0-9]{32}\b", re.I),
    "sha1": re.compile(r"\b[a-f0-9]{40}\b", re.I),
    "sha256": re.compile(r"\b[a-f0-9]{64}\b", re.I),
}

_PRIVATE_IPV4_PREFIXES = ("10.", "127.", "192.168.", "172.")
_IGNORED_DOMAINS = {"localhost", "localdomain", "local"}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class IOC:
    """A deduplicated indicator of compromise."""

    type: str  # ip / ipv6 / url / domain / hash / email / user_agent
    value: str
    context: str = ""
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    confidence: float = 0.8
    session_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-ready representation."""
        return {
            "type": self.type,
            "value": self.value,
            "context": self.context,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "confidence": self.confidence,
            "session_id": self.session_id,
        }

    def key(self) -> tuple[str, str]:
        """Return the dedup key for this IOC."""
        return (self.type, self.value.lower())


# ---------------------------------------------------------------------------
# Extractor
# ---------------------------------------------------------------------------


def _is_valid_ipv4(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    return all(0 <= o <= 255 for o in octets)


def _is_routable_ipv4(ip: str) -> bool:
    """Filter out obvious local / private ranges but keep attacker-facing IPs."""
    if ip.startswith(_PRIVATE_IPV4_PREFIXES[:2]):  # 10., 127.
        return False
    if ip.startswith("192.168."):
        return False
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            if 16 <= second <= 31:
                return False
        except ValueError:
            pass
    return not (ip.startswith("0.") or ip == "255.255.255.255")


class IOCExtractor:
    """Regex-driven IOC extractor with deduplication across sessions."""

    def __init__(self) -> None:
        """Initialize the IOC extractor with an empty dedup store."""
        self._store: dict[tuple[str, str], IOC] = {}

    # ------------------------------------------------------------------
    # Public extraction entrypoints
    # ------------------------------------------------------------------
    def extract_from_event(self, event: dict[str, Any]) -> list[IOC]:
        """Extract and dedupe IOCs from a single event dict."""
        session_id = str(event.get("session_id") or "")
        context_proto = str(event.get("protocol") or "").lower() or "event"
        results: list[IOC] = []

        # Fields to mine for string-based IOCs.
        fields = [
            (event.get("path"), f"{context_proto}:path"),
            (event.get("message"), f"{context_proto}:message"),
            (event.get("user_agent"), f"{context_proto}:user_agent"),
        ]
        data = event.get("data") or {}
        for key in ("body", "payload", "raw", "host", "referer", "command"):
            if key in data:
                fields.append((data.get(key), f"{context_proto}:data.{key}"))

        for value, ctx in fields:
            if not value:
                continue
            results.extend(self._extract_from_text(str(value), ctx, session_id))

        # User-agent itself is an IOC (fingerprints attacker tools).
        ua = event.get("user_agent")
        if ua:
            results.append(self._add(IOC(
                type="user_agent",
                value=str(ua),
                context=f"{context_proto}:user_agent",
                session_id=session_id,
                confidence=0.6,
            )))

        # The attacker IP itself is always an IOC.
        remote_ip = event.get("remote_ip")
        if remote_ip:
            results.append(self._add(IOC(
                type="ip",
                value=str(remote_ip),
                context=f"{context_proto}:remote_ip",
                session_id=session_id,
                confidence=1.0,
            )))

        # Host header as a domain IOC (honeypot dns hit).
        host = data.get("host") if isinstance(data, dict) else None
        if host and not _IPV4_RE.fullmatch(str(host).split(":")[0]):
            domain = str(host).split(":")[0].lower()
            if domain not in _IGNORED_DOMAINS:
                results.append(self._add(IOC(
                    type="domain",
                    value=domain,
                    context=f"{context_proto}:host",
                    session_id=session_id,
                )))

        return [ioc for ioc in results if ioc is not None]

    def extract_from_text(
        self,
        text: str,
        *,
        context: str = "text",
        session_id: str = "",
    ) -> list[IOC]:
        """Extract IOCs from an arbitrary string. Deduplicates against the store."""
        return self._extract_from_text(text, context, session_id)

    @staticmethod
    def compute_hash(payload: bytes, *, algorithm: str = "sha256") -> str:
        """Compute a hex hash digest of a payload. Defaults to SHA256."""
        if algorithm not in {"md5", "sha1", "sha256"}:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
        h = hashlib.new(algorithm)
        h.update(payload)
        return h.hexdigest()

    def record_payload(
        self,
        payload: bytes,
        *,
        context: str = "payload",
        session_id: str = "",
    ) -> IOC:
        """Hash a raw payload and record the resulting SHA256 as an IOC."""
        digest = self.compute_hash(payload, algorithm="sha256")
        return self._add(IOC(
            type="hash",
            value=digest,
            context=context,
            session_id=session_id,
            confidence=1.0,
        ))

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------
    def all(self) -> list[IOC]:
        """Return every currently-tracked IOC."""
        return list(self._store.values())

    def by_type(self, ioc_type: str) -> list[IOC]:
        """Return every tracked IOC of the given type."""
        return [ioc for ioc in self._store.values() if ioc.type == ioc_type]

    def reset(self) -> None:
        """Clear the in-memory dedup store. Useful for tests."""
        self._store.clear()

    def __len__(self) -> int:
        return len(self._store)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _extract_from_text(
        self, text: str, context: str, session_id: str
    ) -> list[IOC]:
        results: list[IOC] = []

        # URLs first so their embedded domain/IP gets scooped up too.
        for match in _URL_RE.finditer(text):
            results.append(
                self._add(
                    IOC(
                        type="url",
                        value=match.group(0),
                        context=context,
                        session_id=session_id,
                    )
                )
            )

        # IPv4.
        for match in _IPV4_RE.finditer(text):
            ip = match.group(0)
            if not _is_valid_ipv4(ip) or not _is_routable_ipv4(ip):
                continue
            results.append(
                self._add(
                    IOC(
                        type="ip",
                        value=ip,
                        context=context,
                        session_id=session_id,
                    )
                )
            )

        # IPv6 (best-effort; regex is permissive).
        for match in _IPV6_RE.finditer(text):
            candidate = match.group(0)
            if candidate.count(":") < 2:
                continue
            if candidate.lower() in {"::1", "::"}:
                continue
            results.append(
                self._add(
                    IOC(
                        type="ipv6",
                        value=candidate,
                        context=context,
                        session_id=session_id,
                        confidence=0.6,
                    )
                )
            )

        # Domains (lower confidence — catches random words like example.com).
        for match in _DOMAIN_RE.finditer(text):
            domain = match.group(0).lower().rstrip(".")
            # Skip IPs already captured.
            if _IPV4_RE.fullmatch(domain):
                continue
            if domain in _IGNORED_DOMAINS:
                continue
            if "." not in domain:
                continue
            results.append(
                self._add(
                    IOC(
                        type="domain",
                        value=domain,
                        context=context,
                        session_id=session_id,
                        confidence=0.5,
                    )
                )
            )

        # Emails.
        for match in _EMAIL_RE.finditer(text):
            results.append(
                self._add(
                    IOC(
                        type="email",
                        value=match.group(0).lower(),
                        context=context,
                        session_id=session_id,
                    )
                )
            )

        # File hashes.
        for algo, pattern in _HASH_RES.items():
            for match in pattern.finditer(text):
                results.append(
                    self._add(
                        IOC(
                            type="hash",
                            value=match.group(0).lower(),
                            context=f"{context}:{algo}",
                            session_id=session_id,
                            confidence=0.7,
                        )
                    )
                )

        return results

    def _add(self, ioc: IOC) -> IOC:
        """Deduplicate and merge first/last seen timestamps."""
        key = ioc.key()
        existing = self._store.get(key)
        if existing is None:
            self._store[key] = ioc
            return ioc
        existing.last_seen = ioc.last_seen
        if ioc.session_id and not existing.session_id:
            existing.session_id = ioc.session_id
        # Promote confidence on re-observation.
        existing.confidence = max(existing.confidence, ioc.confidence)
        return existing
