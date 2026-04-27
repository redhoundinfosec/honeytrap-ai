"""Unit tests for ``honeytrap.alerts.config`` parsing."""

from __future__ import annotations

from honeytrap.alerts.channels import (
    DiscordChannel,
    EmailChannel,
    GenericWebhookChannel,
    SlackChannel,
    TeamsChannel,
)
from honeytrap.alerts.config import AlertsConfig, parse_alerts_config
from honeytrap.alerts.models import AlertSeverity


def test_parse_alerts_config_returns_default_when_data_is_none() -> None:
    cfg = parse_alerts_config(None)
    assert cfg.enabled is False
    assert cfg.channels == []
    assert cfg.summary() == "disabled"


def test_parse_alerts_config_enabled_no_channels_summary() -> None:
    cfg = parse_alerts_config({"enabled": True})
    assert cfg.enabled is True
    assert "no channels" in cfg.summary()


def test_parse_alerts_config_unknown_severity_falls_back_to_default() -> None:
    cfg = parse_alerts_config({"enabled": True, "min_severity": "EXTREME"})
    assert cfg.min_severity == AlertSeverity.MEDIUM


def test_parse_alerts_config_channels_must_be_list() -> None:
    cfg = parse_alerts_config({"enabled": True, "channels": "not-a-list"})
    assert any("must be a list" in w for w in cfg.warnings)


def test_parse_alerts_config_skips_non_mapping_entries() -> None:
    cfg = parse_alerts_config({"enabled": True, "channels": ["string", 1]})
    assert all(not c for c in cfg.channels)
    assert any("must be a mapping" in w for w in cfg.warnings)


def test_parse_alerts_config_slack_channel_via_env(monkeypatch) -> None:
    monkeypatch.setenv("MY_SLACK_HOOK", "https://hooks.slack.example/T/B/X")
    cfg = parse_alerts_config(
        {
            "enabled": True,
            "channels": [{"type": "slack", "name": "ops", "webhook_url_env": "MY_SLACK_HOOK"}],
        }
    )
    assert len(cfg.channels) == 1
    assert isinstance(cfg.channels[0], SlackChannel)


def test_parse_alerts_config_slack_missing_url_skipped() -> None:
    cfg = parse_alerts_config({"enabled": True, "channels": [{"type": "slack", "name": "ops"}]})
    assert cfg.channels == []
    assert any("slack" in w and "missing" in w for w in cfg.warnings)


def test_parse_alerts_config_discord_and_teams_direct_url() -> None:
    cfg = parse_alerts_config(
        {
            "enabled": True,
            "channels": [
                {"type": "discord", "webhook_url": "https://discord.example/x"},
                {"type": "teams", "webhook_url": "https://teams.example/x"},
            ],
        }
    )
    types = {type(c) for c in cfg.channels}
    assert DiscordChannel in types and TeamsChannel in types


def test_parse_alerts_config_generic_webhook_with_secret_and_headers() -> None:
    cfg = parse_alerts_config(
        {
            "enabled": True,
            "channels": [
                {
                    "type": "webhook",
                    "url": "https://example.com/h",
                    "secret": "abc",
                    "headers": {"X-Token": "v"},
                }
            ],
        }
    )
    assert len(cfg.channels) == 1
    ch = cfg.channels[0]
    assert isinstance(ch, GenericWebhookChannel)
    assert ch.shared_secret == "abc"
    assert ch.extra_headers == {"X-Token": "v"}


def test_parse_alerts_config_generic_webhook_invalid_headers_dropped() -> None:
    cfg = parse_alerts_config(
        {
            "enabled": True,
            "channels": [{"type": "generic_webhook", "url": "https://x", "headers": "bad"}],
        }
    )
    assert len(cfg.channels) == 1
    ch = cfg.channels[0]
    assert isinstance(ch, GenericWebhookChannel)
    assert ch.extra_headers == {}


def test_parse_alerts_config_email_full_round_trip() -> None:
    cfg = parse_alerts_config(
        {
            "enabled": True,
            "channels": [
                {
                    "type": "email",
                    "smtp_host": "mail.example",
                    "smtp_port": 465,
                    "from_addr": "alerts@example",
                    "to_addrs": "secops@example",
                    "username": "alerts",
                    "password": "secret",
                    "starttls": False,
                    "use_ssl": True,
                }
            ],
        }
    )
    assert len(cfg.channels) == 1
    ch = cfg.channels[0]
    assert isinstance(ch, EmailChannel)
    assert ch.to_addrs == ["secops@example"]
    assert ch.use_ssl is True


def test_parse_alerts_config_email_missing_required_fields_skipped() -> None:
    cfg = parse_alerts_config({"enabled": True, "channels": [{"type": "email", "smtp_host": "x"}]})
    assert cfg.channels == []
    assert any("email" in w for w in cfg.warnings)


def test_parse_alerts_config_unknown_type_warning() -> None:
    cfg = parse_alerts_config(
        {"enabled": True, "channels": [{"type": "carrier-pigeon", "name": "p1"}]}
    )
    assert cfg.channels == []
    assert any("unknown channel type" in w for w in cfg.warnings)


def test_parse_alerts_config_missing_type_warning() -> None:
    cfg = parse_alerts_config({"enabled": True, "channels": [{}]})
    assert any("missing 'type'" in w for w in cfg.warnings)


def test_alertsconfig_summary_lists_channel_names() -> None:
    cfg = AlertsConfig(
        enabled=True,
        channels=[
            SlackChannel(webhook_url="https://x", name="alpha", min_severity=AlertSeverity.LOW),
            DiscordChannel(webhook_url="https://y", name="bravo", min_severity=AlertSeverity.LOW),
        ],
    )
    summary = cfg.summary()
    assert "alpha" in summary and "bravo" in summary


def test_env_value_returns_none_when_unset(monkeypatch) -> None:
    monkeypatch.delenv("HT_TEST_ENV_X", raising=False)
    cfg = parse_alerts_config(
        {
            "enabled": True,
            "channels": [{"type": "slack", "webhook_url_env": "HT_TEST_ENV_X"}],
        }
    )
    assert cfg.channels == []


def test_parse_alerts_config_dry_run_flag() -> None:
    cfg = parse_alerts_config({"enabled": True, "dry_run": True})
    assert cfg.dry_run is True
