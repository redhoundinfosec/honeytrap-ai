"""Microsoft Teams Incoming Webhook alert channel."""

from __future__ import annotations

from honeytrap.alerts.channels.base import AlertChannel
from honeytrap.alerts.http_client import post_json
from honeytrap.alerts.models import Alert, AlertSeverity
from honeytrap.alerts.templates import render_teams


class TeamsChannel(AlertChannel):
    """Post alerts to a Microsoft Teams Incoming Webhook URL."""

    def __init__(
        self,
        webhook_url: str,
        *,
        name: str = "teams",
        min_severity: AlertSeverity = AlertSeverity.MEDIUM,
        rate_limit_per_minute: int = 20,
    ) -> None:
        """Store webhook URL and limits."""
        super().__init__(
            name,
            min_severity=min_severity,
            rate_limit_per_minute=rate_limit_per_minute,
        )
        if not webhook_url:
            raise ValueError("webhook_url is required for TeamsChannel")
        self.webhook_url = webhook_url

    async def _send(self, alert: Alert) -> None:
        """Render the alert as a Teams MessageCard and POST it."""
        payload = render_teams(alert)
        response = await post_json(self.webhook_url, payload)
        if response.status >= 400:
            raise RuntimeError(f"Teams webhook returned {response.status}: {response.body[:200]}")
