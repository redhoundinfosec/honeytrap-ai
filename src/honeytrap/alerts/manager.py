"""The :class:`AlertManager` orchestrator.

The manager owns a set of registered :class:`AlertChannel`\\ s and an
:class:`AlertRuleEngine`. It can run either in foreground mode — where
:meth:`handle_event` drives evaluation synchronously — or attached to
an engine event bus where it runs its own loop in :meth:`run`.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from honeytrap.alerts.channels.base import AlertChannel, RateLimitExceeded
from honeytrap.alerts.models import Alert, AlertSeverity
from honeytrap.alerts.rules import AlertRuleEngine

logger = logging.getLogger(__name__)


MetricIncrement = Callable[[str, dict[str, str]], None]


def _noop_metric(_name: str, _labels: dict[str, str]) -> None:
    return None


class AlertManager:
    """Runs rules against events and dispatches alerts to channels."""

    def __init__(
        self,
        *,
        channels: list[AlertChannel] | None = None,
        rules: AlertRuleEngine | None = None,
        min_severity: AlertSeverity = AlertSeverity.INFO,
        dry_run: bool = False,
        metric_sent: MetricIncrement | None = None,
        metric_dropped: MetricIncrement | None = None,
        tui_notify: Callable[[Alert], Awaitable[None] | None] | None = None,
    ) -> None:
        """Store channels, rules engine, and observability hooks."""
        self.channels: list[AlertChannel] = list(channels or [])
        self.rules = rules or AlertRuleEngine()
        self.min_severity = AlertSeverity.from_name(min_severity)
        self.dry_run = bool(dry_run)
        self._metric_sent = metric_sent or _noop_metric
        self._metric_dropped = metric_dropped or _noop_metric
        self._tui_notify = tui_notify
        self._in_flight: set[asyncio.Task[None]] = set()
        self._closed = asyncio.Event()
        self._stopped = False

    # ------------------------------------------------------------------
    # Channel management
    # ------------------------------------------------------------------
    def add_channel(self, channel: AlertChannel) -> None:
        """Register a new channel. Safe to call after :meth:`handle_event`."""
        self.channels.append(channel)

    def remove_channel(self, name: str) -> None:
        """Remove every registered channel with the given ``name``."""
        self.channels = [c for c in self.channels if c.name != name]

    # ------------------------------------------------------------------
    # Event handling
    # ------------------------------------------------------------------
    async def handle_event(self, event: dict[str, Any]) -> list[Alert]:
        """Evaluate rules against ``event`` and dispatch produced alerts.

        Returns the list of alerts produced so callers can log or inspect
        them. Channels are dispatched concurrently; one failing channel
        never blocks the others.
        """
        if self._stopped:
            return []
        alerts = self.rules.evaluate(event)
        if not alerts:
            return []

        dispatched: list[Alert] = []
        for alert in alerts:
            if alert.severity < self.min_severity:
                self._metric_dropped("below-min-severity", {"severity": alert.severity.name})
                continue
            dispatched.append(alert)
            await self._dispatch(alert)
        return dispatched

    async def _dispatch(self, alert: Alert) -> None:
        if self._tui_notify is not None and alert.severity >= AlertSeverity.HIGH:
            try:
                result = self._tui_notify(alert)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as exc:  # noqa: BLE001
                logger.debug("TUI notification hook failed: %s", exc)

        if self.dry_run:
            logger.info(
                "alerts[dry-run] %s/%s: %s",
                alert.severity.name,
                alert.protocol or "?",
                alert.title,
            )
            for channel in self.channels:
                if channel.accepts(alert):
                    self._metric_sent(channel.name, {"severity": alert.severity.name})
            return

        tasks: list[asyncio.Task[None]] = []
        for channel in self.channels:
            if not channel.accepts(alert):
                continue
            task = asyncio.create_task(self._deliver(channel, alert))
            tasks.append(task)
            self._in_flight.add(task)
            task.add_done_callback(self._in_flight.discard)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _deliver(self, channel: AlertChannel, alert: Alert) -> None:
        try:
            await channel.send(alert)
            self._metric_sent(channel.name, {"severity": alert.severity.name})
        except RateLimitExceeded:
            self._metric_dropped("rate-limited", {"channel": channel.name})
            logger.warning(
                "Alert dropped — %s rate limit exceeded (severity=%s)",
                channel.name,
                alert.severity.name,
            )
        except Exception as exc:  # noqa: BLE001
            self._metric_dropped("channel-error", {"channel": channel.name})
            logger.exception("Channel %s failed to send alert: %s", channel.name, exc)

    # ------------------------------------------------------------------
    # Event bus loop
    # ------------------------------------------------------------------
    async def run_subscriber(self, queue: asyncio.Queue[Any]) -> None:
        """Consume Event objects from ``queue`` until shutdown.

        Each item must expose a ``.to_dict()`` method or already be a
        plain dict. Foreign items are silently skipped.
        """
        while not self._stopped:
            try:
                item = await queue.get()
            except asyncio.CancelledError:
                break
            if item is None:
                continue
            payload: dict[str, Any]
            if isinstance(item, dict):
                payload = item
            elif hasattr(item, "to_dict"):
                try:
                    payload = item.to_dict()
                except Exception as exc:  # noqa: BLE001
                    logger.debug("event.to_dict failed: %s", exc)
                    continue
            else:
                continue
            try:
                await self.handle_event(payload)
            except Exception as exc:  # noqa: BLE001
                logger.exception("AlertManager.handle_event failed: %s", exc)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def shutdown(self, timeout: float = 5.0) -> None:
        """Stop accepting new events and wait for pending deliveries."""
        self._stopped = True
        if self._in_flight:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*list(self._in_flight), return_exceptions=True),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                logger.warning("AlertManager shutdown timed out with pending deliveries")
        for channel in self.channels:
            try:
                await channel.close()
            except Exception as exc:  # noqa: BLE001
                logger.debug("Channel %s close failed: %s", channel.name, exc)
        self._closed.set()
