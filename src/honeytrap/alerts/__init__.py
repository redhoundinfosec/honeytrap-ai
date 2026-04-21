"""HoneyTrap AI alerting subsystem.

The public surface is deliberately small:

* :class:`Alert` — the event currency
* :class:`AlertSeverity` — severity IntEnum
* :class:`AlertChannel` — ABC for new channels
* :class:`AlertManager` — dispatches alerts to channels
* :class:`AlertRuleEngine` — converts events to alerts
* :func:`parse_alerts_config` — YAML ``alerts`` section parser
"""

from __future__ import annotations

from honeytrap.alerts.channels.base import AlertChannel
from honeytrap.alerts.config import AlertsConfig, parse_alerts_config
from honeytrap.alerts.manager import AlertManager
from honeytrap.alerts.models import Alert, AlertSeverity
from honeytrap.alerts.rules import DEFAULT_RULES, AlertRuleContext, AlertRuleEngine

__all__ = [
    "Alert",
    "AlertChannel",
    "AlertManager",
    "AlertRuleContext",
    "AlertRuleEngine",
    "AlertSeverity",
    "AlertsConfig",
    "DEFAULT_RULES",
    "parse_alerts_config",
]
