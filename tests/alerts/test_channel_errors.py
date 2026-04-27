"""Tests for alert channel error paths and constructor validation."""

from __future__ import annotations

from typing import Any

import pytest

from honeytrap.alerts import Alert, AlertSeverity
from honeytrap.alerts.channels import (
    DiscordChannel,
    GenericWebhookChannel,
    SlackChannel,
    TeamsChannel,
)
from honeytrap.alerts.http_client import HttpResponse


def _alert() -> Alert:
    return Alert(
        title="x",
        summary="y",
        severity=AlertSeverity.HIGH,
        source_ip="1.2.3.4",
        protocol="ssh",
        session_id="s",
    )


@pytest.mark.parametrize(
    "cls",
    [SlackChannel, DiscordChannel, TeamsChannel],
)
def test_webhook_channel_requires_url(cls: type) -> None:
    with pytest.raises(ValueError, match="webhook_url"):
        cls(webhook_url="")


def test_generic_webhook_requires_url() -> None:
    with pytest.raises(ValueError, match="url"):
        GenericWebhookChannel(url="")


@pytest.mark.parametrize(
    "cls",
    [SlackChannel, DiscordChannel, TeamsChannel],
)
async def test_webhook_channel_raises_on_error_status(
    cls: type, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fake_post(
        url: str, payload: Any, *, headers: dict[str, str] | None = None, **_: Any
    ) -> HttpResponse:
        return HttpResponse(500, "boom", {})

    monkeypatch.setattr("honeytrap.alerts.channels.slack.post_json", fake_post)
    monkeypatch.setattr("honeytrap.alerts.channels.discord.post_json", fake_post)
    monkeypatch.setattr("honeytrap.alerts.channels.teams.post_json", fake_post)

    ch = cls(webhook_url="https://x.example/webhook")
    with pytest.raises(RuntimeError, match="500"):
        await ch._send(_alert())


async def test_generic_webhook_raises_on_error_status(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_post(
        url: str, payload: Any, *, headers: dict[str, str] | None = None, **_: Any
    ) -> HttpResponse:
        return HttpResponse(503, "down", {})

    monkeypatch.setattr("honeytrap.alerts.channels.generic_webhook.post_json", fake_post)
    ch = GenericWebhookChannel(url="https://x.example/h")
    with pytest.raises(RuntimeError, match="503"):
        await ch._send(_alert())


async def test_generic_webhook_signs_payload_when_secret_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    async def fake_post(
        url: str, payload: Any, *, headers: dict[str, str] | None = None, **_: Any
    ) -> HttpResponse:
        seen["headers"] = dict(headers or {})
        return HttpResponse(200, "ok", {})

    monkeypatch.setattr("honeytrap.alerts.channels.generic_webhook.post_json", fake_post)
    ch = GenericWebhookChannel(
        url="https://x.example/h",
        shared_secret="topsecret",
        extra_headers={"X-Custom": "v"},
    )
    await ch._send(_alert())
    assert "X-HoneyTrap-Signature" in seen["headers"]
    assert seen["headers"]["X-Custom"] == "v"
