"""Built-in alert channel implementations."""

from __future__ import annotations

from honeytrap.alerts.channels.base import AlertChannel, RateLimitExceeded, TokenBucket
from honeytrap.alerts.channels.discord import DiscordChannel
from honeytrap.alerts.channels.email import EmailChannel
from honeytrap.alerts.channels.generic_webhook import GenericWebhookChannel
from honeytrap.alerts.channels.slack import SlackChannel
from honeytrap.alerts.channels.teams import TeamsChannel

__all__ = [
    "AlertChannel",
    "DiscordChannel",
    "EmailChannel",
    "GenericWebhookChannel",
    "RateLimitExceeded",
    "SlackChannel",
    "TeamsChannel",
    "TokenBucket",
]
