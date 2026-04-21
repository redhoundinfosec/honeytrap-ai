"""Tests for the built-in alert channels."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

import pytest

from honeytrap.alerts import Alert, AlertSeverity
from honeytrap.alerts.channels import (
    DiscordChannel,
    EmailChannel,
    GenericWebhookChannel,
    SlackChannel,
    TeamsChannel,
)
from honeytrap.alerts.http_client import HttpResponse


def _make_alert(severity: AlertSeverity = AlertSeverity.HIGH) -> Alert:
    return Alert(
        title="SSH brute force",
        summary="10 failed auths from 203.0.113.5",
        severity=severity,
        source_ip="203.0.113.5",
        protocol="ssh",
        session_id="s-1",
        attck_techniques=["T1110.001"],
        iocs={"ip": ["203.0.113.5"]},
        tags={"brute-force"},
    )


class _HttpRecorder:
    """Captures arguments passed to the http client and returns a scripted response."""

    def __init__(self, *responses: HttpResponse) -> None:
        """Queue up the responses returned on successive calls."""
        self.calls: list[tuple[str, dict[str, Any], dict[str, str]]] = []
        self._responses = list(responses) or [HttpResponse(200, "ok", {})]

    async def __call__(
        self,
        url: str,
        payload: dict[str, Any] | list[Any],
        *,
        headers: dict[str, str] | None = None,
        **_: Any,
    ) -> HttpResponse:
        self.calls.append(
            (url, dict(payload) if isinstance(payload, dict) else payload, dict(headers or {}))
        )
        if len(self._responses) > 1:
            return self._responses.pop(0)
        return self._responses[0]


async def test_slack_channel_posts_blocks_to_webhook(monkeypatch: pytest.MonkeyPatch) -> None:
    """SlackChannel should POST blocks/attachments to the webhook URL."""
    recorder = _HttpRecorder()
    monkeypatch.setattr("honeytrap.alerts.channels.slack.post_json", recorder)
    ch = SlackChannel("https://hooks.slack.example/ABC", min_severity=AlertSeverity.LOW)
    await ch.send(_make_alert())
    assert len(recorder.calls) == 1
    url, payload, _ = recorder.calls[0]
    assert url == "https://hooks.slack.example/ABC"
    assert "attachments" in payload
    assert payload["attachments"][0]["blocks"][0]["type"] == "header"
    assert "HIGH" in payload["text"]


async def test_discord_channel_posts_embed_with_severity_color(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DiscordChannel should color the embed according to severity."""
    recorder = _HttpRecorder()
    monkeypatch.setattr("honeytrap.alerts.channels.discord.post_json", recorder)
    ch = DiscordChannel("https://discord.example/webhook", min_severity=AlertSeverity.LOW)
    await ch.send(_make_alert(AlertSeverity.CRITICAL))
    _, payload, _ = recorder.calls[0]
    assert payload["embeds"][0]["color"] == 0xB80B0B


async def test_teams_channel_posts_messagecard(monkeypatch: pytest.MonkeyPatch) -> None:
    """TeamsChannel should send a valid MessageCard JSON payload."""
    recorder = _HttpRecorder()
    monkeypatch.setattr("honeytrap.alerts.channels.teams.post_json", recorder)
    ch = TeamsChannel("https://outlook.example/webhook", min_severity=AlertSeverity.LOW)
    await ch.send(_make_alert())
    _, payload, _ = recorder.calls[0]
    assert payload["@type"] == "MessageCard"
    assert payload["@context"].startswith("https://schema.org")
    assert payload["sections"][0]["facts"][0]["name"] == "Severity"


async def test_generic_webhook_adds_hmac_signature(monkeypatch: pytest.MonkeyPatch) -> None:
    """The generic channel should sign the body with HMAC-SHA256 when a secret is set."""
    recorder = _HttpRecorder()
    monkeypatch.setattr("honeytrap.alerts.channels.generic_webhook.post_json", recorder)
    secret = "topsecret"
    ch = GenericWebhookChannel(
        "https://webhook.example/inbox", shared_secret=secret, min_severity=AlertSeverity.LOW
    )
    await ch.send(_make_alert())
    assert len(recorder.calls) == 1
    url, payload, headers = recorder.calls[0]
    assert "X-HoneyTrap-Signature" in headers
    expected = hmac.new(
        secret.encode("utf-8"),
        json.dumps(payload).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    assert headers["X-HoneyTrap-Signature"] == f"sha256={expected}"


async def test_generic_webhook_retries_on_503_and_stops_on_400(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """http_client should retry on 5xx but stop immediately on 4xx."""
    from honeytrap.alerts import http_client as http

    # Scenario 1: 503 then 200 -> the client should retry and eventually succeed.
    responses: list[HttpResponse] = [
        HttpResponse(503, "busy", {"Retry-After": "0"}),
        HttpResponse(200, "ok", {}),
    ]
    calls: list[str] = []

    async def fake_post(
        url: str,
        body: bytes,
        headers: dict[str, str],
        *,
        connect_timeout: float,
        read_timeout: float,
    ) -> HttpResponse:
        calls.append(url)
        return responses.pop(0)

    monkeypatch.setattr(http, "_do_post", fake_post)

    async def no_sleep(_: float) -> None:
        return None

    result = await http.post_json("https://w.example/retry", {"a": 1}, sleeper=no_sleep)
    assert result.status == 200
    assert len(calls) == 2

    # Scenario 2: 400 -> no retry.
    calls.clear()
    responses[:] = [HttpResponse(400, "bad", {})]

    async def fake_post2(
        url: str,
        body: bytes,
        headers: dict[str, str],
        *,
        connect_timeout: float,
        read_timeout: float,
    ) -> HttpResponse:
        calls.append(url)
        return responses.pop(0)

    monkeypatch.setattr(http, "_do_post", fake_post2)
    result = await http.post_json("https://w.example/bad", {"a": 1}, sleeper=no_sleep)
    assert result.status == 400
    assert len(calls) == 1


def test_email_channel_uses_starttls_and_multipart() -> None:
    """EmailChannel should start TLS when configured and send multipart content."""

    captured: dict[str, Any] = {}

    class FakeSMTP:
        def __init__(self, host: str, port: int, timeout: float = 0.0) -> None:
            captured["host"] = host
            captured["port"] = port
            captured["starttls_calls"] = 0
            captured["login_calls"] = 0

        def ehlo(self) -> None:
            captured.setdefault("ehlo_calls", 0)
            captured["ehlo_calls"] += 1

        def starttls(self, context: Any = None) -> None:
            captured["starttls_calls"] += 1

        def login(self, username: str, password: str) -> None:
            captured["login_calls"] += 1
            captured["username"] = username
            captured["password"] = password

        def send_message(self, msg: Any, from_addr: str, to_addrs: list[str]) -> None:
            captured["msg"] = msg
            captured["from_addr"] = from_addr
            captured["to_addrs"] = to_addrs

        def quit(self) -> None:
            captured["quit"] = True

    def factory(host: str, port: int) -> FakeSMTP:
        return FakeSMTP(host, port)

    ch = EmailChannel(
        smtp_host="smtp.example.com",
        smtp_port=587,
        from_addr="honeytrap@example.com",
        to_addrs=["soc@example.com"],
        username="ht",
        password="pw",
        starttls=True,
        smtp_factory=factory,
        min_severity=AlertSeverity.LOW,
    )
    subject, text_body, html_body = ("Subject", "Text body", "<html>html body</html>")
    ch._send_blocking(subject, text_body, html_body)  # noqa: SLF001 — test hook

    assert captured["host"] == "smtp.example.com"
    assert captured["starttls_calls"] == 1
    assert captured["login_calls"] == 1
    assert captured["to_addrs"] == ["soc@example.com"]
    msg = captured["msg"]
    assert msg["Subject"] == "Subject"
    assert msg["From"] == "honeytrap@example.com"
    # Multipart with html alternative.
    assert msg.is_multipart()
    subtypes = {part.get_content_subtype() for part in msg.iter_parts()}
    assert "html" in subtypes
