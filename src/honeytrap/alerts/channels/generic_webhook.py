"""Generic webhook alert channel with HMAC signing support."""

from __future__ import annotations

import hashlib
import hmac
import json

from honeytrap.alerts.channels.base import AlertChannel
from honeytrap.alerts.http_client import post_json
from honeytrap.alerts.models import Alert, AlertSeverity
from honeytrap.alerts.templates import render_generic

_SIGNATURE_HEADER = "X-HoneyTrap-Signature"


class GenericWebhookChannel(AlertChannel):
    """POST the canonical alert JSON to a user-supplied URL.

    When ``shared_secret`` is provided the HMAC-SHA256 signature of the
    raw request body is added to the ``X-HoneyTrap-Signature`` header as
    ``sha256=<hex>`` so the receiver can verify authenticity.
    """

    def __init__(
        self,
        url: str,
        *,
        name: str = "webhook",
        shared_secret: str | None = None,
        extra_headers: dict[str, str] | None = None,
        min_severity: AlertSeverity = AlertSeverity.MEDIUM,
        rate_limit_per_minute: int = 30,
    ) -> None:
        """Store URL, optional HMAC secret, and extra headers."""
        super().__init__(
            name,
            min_severity=min_severity,
            rate_limit_per_minute=rate_limit_per_minute,
        )
        if not url:
            raise ValueError("url is required for GenericWebhookChannel")
        self.url = url
        self.shared_secret = shared_secret or None
        self.extra_headers = dict(extra_headers or {})

    async def _send(self, alert: Alert) -> None:
        """Render and POST the alert, adding HMAC signature when configured."""
        payload = render_generic(alert)
        body = json.dumps(payload).encode("utf-8")
        headers = dict(self.extra_headers)
        if self.shared_secret:
            digest = hmac.new(
                self.shared_secret.encode("utf-8"),
                body,
                hashlib.sha256,
            ).hexdigest()
            headers[_SIGNATURE_HEADER] = f"sha256={digest}"
        response = await post_json(self.url, payload, headers=headers)
        if response.status >= 400:
            raise RuntimeError(f"Generic webhook returned {response.status}: {response.body[:200]}")
