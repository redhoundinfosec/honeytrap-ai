"""SMTP email alert channel using stdlib :mod:`smtplib`."""

from __future__ import annotations

import asyncio
import logging
import smtplib
import ssl
from email.message import EmailMessage
from typing import Any

from honeytrap.alerts.channels.base import AlertChannel
from honeytrap.alerts.models import Alert, AlertSeverity
from honeytrap.alerts.templates import render_email

logger = logging.getLogger(__name__)


class EmailChannel(AlertChannel):
    """Send alerts as multipart (text + HTML) email over SMTP.

    Supports explicit TLS (SMTPS, ``use_ssl=True``) and STARTTLS on the
    default port. Authentication is optional; when credentials are
    provided they are sent after the TLS handshake.
    """

    def __init__(
        self,
        *,
        smtp_host: str,
        smtp_port: int = 587,
        from_addr: str,
        to_addrs: list[str],
        username: str | None = None,
        password: str | None = None,
        starttls: bool = True,
        use_ssl: bool = False,
        timeout: float = 10.0,
        smtp_factory: Any = None,
        name: str = "email",
        min_severity: AlertSeverity = AlertSeverity.HIGH,
        rate_limit_per_minute: int = 5,
    ) -> None:
        """Record SMTP settings, recipients, and limits."""
        super().__init__(
            name,
            min_severity=min_severity,
            rate_limit_per_minute=rate_limit_per_minute,
        )
        if not smtp_host:
            raise ValueError("smtp_host is required for EmailChannel")
        if not from_addr:
            raise ValueError("from_addr is required for EmailChannel")
        if not to_addrs:
            raise ValueError("at least one to_addr is required for EmailChannel")
        self.smtp_host = smtp_host
        self.smtp_port = int(smtp_port)
        self.from_addr = from_addr
        self.to_addrs = list(to_addrs)
        self.username = username or None
        self.password = password or None
        self.starttls = bool(starttls) and not use_ssl
        self.use_ssl = bool(use_ssl)
        self.timeout = float(timeout)
        self._smtp_factory = smtp_factory

    async def _send(self, alert: Alert) -> None:
        """Compose the message off the event loop and deliver it."""
        subject, text_body, html_body = render_email(alert)
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            self._send_blocking,
            subject,
            text_body,
            html_body,
        )

    # ------------------------------------------------------------------
    # Blocking SMTP implementation (runs in default executor)
    # ------------------------------------------------------------------

    def _build_message(self, subject: str, text_body: str, html_body: str) -> EmailMessage:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = self.from_addr
        msg["To"] = ", ".join(self.to_addrs)
        msg.set_content(text_body)
        msg.add_alternative(html_body, subtype="html")
        return msg

    def _build_client(self) -> smtplib.SMTP:
        if self._smtp_factory is not None:
            return self._smtp_factory(self.smtp_host, self.smtp_port)
        if self.use_ssl:
            return smtplib.SMTP_SSL(
                self.smtp_host,
                self.smtp_port,
                timeout=self.timeout,
                context=ssl.create_default_context(),
            )
        return smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=self.timeout)

    def _send_blocking(self, subject: str, text_body: str, html_body: str) -> None:
        msg = self._build_message(subject, text_body, html_body)
        client = self._build_client()
        try:
            client.ehlo()
            if self.starttls:
                client.starttls(context=ssl.create_default_context())
                client.ehlo()
            if self.username and self.password:
                client.login(self.username, self.password)
            client.send_message(msg, from_addr=self.from_addr, to_addrs=self.to_addrs)
        finally:
            try:
                client.quit()
            except Exception as exc:  # noqa: BLE001 — best-effort cleanup
                logger.debug("SMTP quit failed: %s", exc)
