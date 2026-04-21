"""Slack Incoming Webhook alert channel."""

from __future__ import annotations

from honeytrap.alerts.channels.base import AlertChannel
from honeytrap.alerts.http_client import post_json
from honeytrap.alerts.models import Alert, AlertSeverity
from honeytrap.alerts.templates import render_slack


class SlackChannel(AlertChannel):
    """Post alerts to a Slack Incoming Webhook URL."""

    def __init__(
        self,
        webhook_url: str,
        *,
        name: str = "slack",
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
            raise ValueError("webhook_url is required for SlackChannel")
        self.webhook_url = webhook_url

    async def _send(self, alert: Alert) -> None:
        """Render the alert as Slack blocks and POST it."""
        payload = render_slack(alert)
        response = await post_json(self.webhook_url, payload)
        if response.status >= 400:
            raise RuntimeError(f"Slack webhook returned {response.status}: {response.body[:200]}")
