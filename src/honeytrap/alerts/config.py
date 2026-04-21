"""Parse the ``alerts`` section of a YAML profile/config into channel objects.

Only YAML keys referenced here are consumed — anything else is ignored
with a warning so profile authors can add forward-looking keys without
the program crashing. Secrets must come from env vars using ``*_env``
keys to avoid accidentally committing them to the profile file.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any

from honeytrap.alerts.channels import (
    AlertChannel,
    DiscordChannel,
    EmailChannel,
    GenericWebhookChannel,
    SlackChannel,
    TeamsChannel,
)
from honeytrap.alerts.models import AlertSeverity

logger = logging.getLogger(__name__)


@dataclass
class AlertsConfig:
    """Parsed representation of the ``alerts`` YAML section."""

    enabled: bool = False
    min_severity: AlertSeverity = AlertSeverity.MEDIUM
    dry_run: bool = False
    channels: list[AlertChannel] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def summary(self) -> str:
        """One-line human summary for log lines and CLI output."""
        if not self.enabled:
            return "disabled"
        if not self.channels:
            return "enabled (no channels configured)"
        names = ", ".join(sorted({c.name for c in self.channels}))
        return f"enabled; channels: {names}; min_severity={self.min_severity.name}"


def _env_value(env_name: str | None) -> str | None:
    if not env_name:
        return None
    value = os.environ.get(str(env_name))
    if not value:
        return None
    return value


def _severity(value: Any, default: AlertSeverity) -> AlertSeverity:
    if value is None or value == "":
        return default
    try:
        return AlertSeverity.from_name(value)
    except ValueError:
        logger.warning("Unknown alert severity %r — using %s", value, default.name)
        return default


def _build_channel(entry: dict[str, Any], warnings: list[str]) -> AlertChannel | None:
    ctype = str(entry.get("type") or "").strip().lower()
    if not ctype:
        warnings.append("channel missing 'type' — skipped")
        return None

    name = str(entry.get("name") or ctype)
    min_sev = _severity(entry.get("min_severity"), AlertSeverity.MEDIUM)
    rate = int(entry.get("rate_limit_per_minute") or 20)

    if ctype == "slack":
        url = entry.get("webhook_url") or _env_value(entry.get("webhook_url_env"))
        if not url:
            warnings.append(f"slack channel {name!r} missing webhook_url/webhook_url_env — skipped")
            return None
        return SlackChannel(
            webhook_url=url, name=name, min_severity=min_sev, rate_limit_per_minute=rate
        )

    if ctype == "discord":
        url = entry.get("webhook_url") or _env_value(entry.get("webhook_url_env"))
        if not url:
            warnings.append(
                f"discord channel {name!r} missing webhook_url/webhook_url_env — skipped"
            )
            return None
        return DiscordChannel(
            webhook_url=url, name=name, min_severity=min_sev, rate_limit_per_minute=rate
        )

    if ctype == "teams":
        url = entry.get("webhook_url") or _env_value(entry.get("webhook_url_env"))
        if not url:
            warnings.append(f"teams channel {name!r} missing webhook_url/webhook_url_env — skipped")
            return None
        return TeamsChannel(
            webhook_url=url, name=name, min_severity=min_sev, rate_limit_per_minute=rate
        )

    if ctype in {"webhook", "generic", "generic_webhook"}:
        url = entry.get("url") or _env_value(entry.get("url_env"))
        if not url:
            warnings.append(f"webhook channel {name!r} missing url/url_env — skipped")
            return None
        secret = entry.get("secret") or _env_value(entry.get("secret_env"))
        extra = entry.get("headers") or {}
        if not isinstance(extra, dict):
            extra = {}
        return GenericWebhookChannel(
            url=url,
            name=name,
            shared_secret=secret,
            extra_headers={str(k): str(v) for k, v in extra.items()},
            min_severity=min_sev,
            rate_limit_per_minute=rate,
        )

    if ctype == "email":
        host = entry.get("smtp_host")
        port = int(entry.get("smtp_port") or 587)
        from_addr = entry.get("from_addr")
        to_addrs_raw = entry.get("to_addrs") or []
        if isinstance(to_addrs_raw, str):
            to_addrs = [to_addrs_raw]
        else:
            to_addrs = [str(x) for x in to_addrs_raw]
        username = entry.get("username") or _env_value(entry.get("username_env"))
        password = entry.get("password") or _env_value(entry.get("password_env"))
        if not host or not from_addr or not to_addrs:
            warnings.append(
                f"email channel {name!r} missing smtp_host/from_addr/to_addrs — skipped"
            )
            return None
        return EmailChannel(
            smtp_host=str(host),
            smtp_port=port,
            from_addr=str(from_addr),
            to_addrs=to_addrs,
            username=username,
            password=password,
            starttls=bool(entry.get("starttls", True)),
            use_ssl=bool(entry.get("use_ssl", False)),
            name=name,
            min_severity=min_sev,
            rate_limit_per_minute=rate,
        )

    warnings.append(f"unknown channel type {ctype!r} for {name!r} — skipped")
    return None


def parse_alerts_config(data: dict[str, Any] | None) -> AlertsConfig:
    """Build an :class:`AlertsConfig` from a raw YAML ``alerts`` mapping."""
    cfg = AlertsConfig()
    if not data:
        return cfg
    cfg.enabled = bool(data.get("enabled", False))
    cfg.min_severity = _severity(data.get("min_severity"), AlertSeverity.MEDIUM)
    cfg.dry_run = bool(data.get("dry_run", False))
    entries = data.get("channels") or []
    if not isinstance(entries, list):
        cfg.warnings.append("alerts.channels must be a list — ignored")
        return cfg
    for entry in entries:
        if not isinstance(entry, dict):
            cfg.warnings.append("alerts.channels entry must be a mapping — skipped")
            continue
        channel = _build_channel(entry, cfg.warnings)
        if channel is not None:
            cfg.channels.append(channel)
    return cfg
