"""Tests for configuration loading."""

from __future__ import annotations

from pathlib import Path

import pytest

from honeytrap.core.config import Config, load_config
from honeytrap.exceptions import ConfigError


def test_default_config() -> None:
    cfg = load_config()
    assert isinstance(cfg, Config)
    assert cfg.general.bind_address == "0.0.0.0"
    assert cfg.general.max_log_size_mb == 500
    assert cfg.ai.enabled is False
    assert cfg.geo.enabled is True


def test_config_from_yaml(tmp_path: Path) -> None:
    path = tmp_path / "honeytrap.yaml"
    path.write_text(
        """
general:
  bind_address: 127.0.0.1
  max_log_size_mb: 10
ai:
  enabled: true
  provider: ollama
""",
        encoding="utf-8",
    )
    cfg = load_config(path)
    assert cfg.general.bind_address == "127.0.0.1"
    assert cfg.general.max_log_size_mb == 10
    assert cfg.ai.enabled is True
    assert cfg.ai.provider == "ollama"


def test_invalid_yaml(tmp_path: Path) -> None:
    path = tmp_path / "honeytrap.yaml"
    path.write_text("::: not yaml :::", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path)


def test_env_overrides(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HONEYTRAP_AI_KEY", "sk-test")
    monkeypatch.setenv("HONEYTRAP_AI_MODEL", "mymodel")
    cfg = load_config()
    assert cfg.ai.api_key == "sk-test"
    assert cfg.ai.model == "mymodel"
