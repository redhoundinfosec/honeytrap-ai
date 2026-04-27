"""SMTP adapter — produces RFC 5321 compliant reply lines.

Inputs come in via :attr:`AdapterPrompt.inbound` as a single SMTP verb
line (``EHLO mail.x``, ``MAIL FROM:<bob@x.com>``, ``DATA``, ...). The
adapter returns one or more CR/LF terminated reply lines that the
handler writes to the wire verbatim.

Capabilities advertised on EHLO are profile-aware:

* ``mail_server`` -> SIZE 52428800, STARTTLS, AUTH PLAIN LOGIN,
  PIPELINING, 8BITMIME, ENHANCEDSTATUSCODES.
* ``iot_*`` profiles -> a stripped capability list (no AUTH).

The DATA terminator (``\\r\\n.\\r\\n``) is enforced by
:meth:`validate_shape`.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone

from honeytrap.ai.adapters.base import AdapterPrompt, BaseAdapter

_SMTP_LINE_RE = re.compile(r"^\d{3}[ -].*\r\n", re.MULTILINE)
_VERB_RE = re.compile(r"^([A-Za-z]{4,8})(?:\s|$)")

_DEFAULT_CAPS = (
    "SIZE 52428800",
    "STARTTLS",
    "AUTH PLAIN LOGIN",
    "PIPELINING",
    "8BITMIME",
    "ENHANCEDSTATUSCODES",
)
_IOT_CAPS = ("SIZE 5242880", "8BITMIME", "ENHANCEDSTATUSCODES")


class SmtpAdapter(BaseAdapter):
    """SMTP wire adapter."""

    protocol = "smtp"

    def template_response(self, prompt: AdapterPrompt) -> str:
        """Return CR/LF reply line(s) for the inbound verb."""
        verb_match = _VERB_RE.match(prompt.inbound.strip())
        verb = verb_match.group(1).upper() if verb_match else ""
        host = self._helo_host(prompt)
        state = str(prompt.extra.get("state", ""))
        if state == "banner":
            return f"220 {host} ESMTP HoneyTrap (Postfix); ready\r\n"
        if verb == "HELO":
            return f"250 {host}\r\n"
        if verb == "EHLO":
            arg = prompt.inbound.split(" ", 1)[1].strip() if " " in prompt.inbound else "unknown"
            return self._ehlo_block(host, arg, prompt)
        if verb == "MAIL":
            return "250 2.1.0 Sender OK\r\n"
        if verb == "RCPT":
            address = self._extract_address(prompt.inbound)
            if self._is_blocked_recipient(address):
                return "550 5.1.1 <" + address + ">: Recipient address rejected: User unknown\r\n"
            return "250 2.1.5 Recipient OK\r\n"
        if verb == "DATA":
            return "354 End data with <CR><LF>.<CR><LF>\r\n"
        if verb == "STARTTLS":
            return "220 2.0.0 Ready to start TLS\r\n"
        if verb == "AUTH":
            return "334 VXNlcm5hbWU6\r\n"
        if verb == "VRFY":
            return "252 2.1.5 Cannot verify but will accept message\r\n"
        if verb == "EXPN":
            return "502 5.5.1 EXPN command not implemented\r\n"
        if verb == "RSET":
            return "250 2.0.0 Reset OK\r\n"
        if verb == "NOOP":
            return "250 2.0.0 OK\r\n"
        if verb == "QUIT":
            return f"221 2.0.0 {host} closing connection\r\n"
        if state == "data_sent":
            return f"250 2.0.0 Ok: queued as {self._queue_id(prompt)}\r\n"
        if state == "data_dot":
            return f"250 2.0.0 Ok: queued as {self._queue_id(prompt)}\r\n"
        return "500 5.5.2 Syntax error, command unrecognized\r\n"

    def validate_shape(self, response: str) -> str:
        """Accept replies whose every line is ``NNN[ -]<text>\\r\\n``."""
        if not response:
            return ""
        # Allow trailing single-dot DATA terminator if the caller wired it.
        out_lines: list[str] = []
        for raw in response.split("\r\n"):
            if not raw:
                continue
            if raw == ".":
                out_lines.append(".")
                continue
            if not re.match(r"^\d{3}[ -]", raw):
                # Reject any non-coded line — return empty so chain falls
                # back to template.
                return ""
            out_lines.append(raw)
        return "\r\n".join(out_lines) + "\r\n"

    def cache_key(self, prompt: AdapterPrompt) -> str:
        """Cache by verb only — argument distinctions handled by safety."""
        verb_match = _VERB_RE.match(prompt.inbound.strip())
        verb = verb_match.group(1).upper() if verb_match else "UNKNOWN"
        profile = str(prompt.persona.get("profile", "mail_server"))
        state = str(prompt.extra.get("state", ""))
        return f"{verb}|{profile}|{state}"

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _helo_host(self, prompt: AdapterPrompt) -> str:
        return str(
            prompt.persona.get("mail_helo") or prompt.persona.get("hostname", "mail.example.com")
        )

    def _ehlo_block(self, host: str, client: str, prompt: AdapterPrompt) -> str:
        profile = str(prompt.persona.get("profile", "mail_server"))
        caps = _IOT_CAPS if profile.startswith("iot_") else _DEFAULT_CAPS
        lines = [f"250-{host} Hello {client}"]
        for cap in caps[:-1]:
            lines.append(f"250-{cap}")
        lines.append(f"250 {caps[-1]}")
        return "\r\n".join(lines) + "\r\n"

    @staticmethod
    def _extract_address(line: str) -> str:
        m = re.search(r"<([^>]*)>", line)
        if not m:
            return ""
        return m.group(1).strip()

    @staticmethod
    def _is_blocked_recipient(address: str) -> bool:
        if not address:
            return True
        # Refuse to deliver to anything that smells like a relay test.
        return address.lower().endswith(("@spamhaus.org", "@example.invalid"))

    def _queue_id(self, prompt: AdapterPrompt) -> str:
        seed = (prompt.persona.get("session_id", "anon") or "anon") + datetime.now(
            tz=timezone.utc
        ).isoformat()
        return hashlib.sha1(seed.encode()).hexdigest()[:10].upper()
