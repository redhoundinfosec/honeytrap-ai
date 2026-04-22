"""Configuration loading and validation.

Configuration is layered:

1. Defaults baked into :class:`Config`.
2. Optional ``honeytrap.yaml`` in the current working directory.
3. Environment variables prefixed ``HONEYTRAP_``.
4. CLI-supplied overrides (applied at :func:`load_config` call site).

All fields are strongly typed with dataclasses so downstream code gets
IDE completion and predictable access.
"""

from __future__ import annotations

import logging
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

from honeytrap.exceptions import ConfigError

logger = logging.getLogger(__name__)


@dataclass
class GeneralConfig:
    """Top-level global settings."""

    bind_address: str = "0.0.0.0"
    log_directory: str = "./honeytrap_logs"
    max_log_size_mb: int = 500
    log_retention_days: int = 30
    dashboard: bool = True
    profile_path: str | None = None
    max_concurrent_connections: int = 500


@dataclass
class AIConfig:
    """Settings for the optional LLM layer."""

    enabled: bool = False
    provider: str = "openai"  # openai | ollama | custom
    endpoint: str = ""
    api_key: str = ""
    model: str = "gpt-4o-mini"
    timeout_seconds: float = 8.0
    fallback_to_rules: bool = True
    max_tokens: int = 400
    # ------------------------------------------------------------------
    # Cycle 11 adaptive-response fields
    # ------------------------------------------------------------------
    adaptive_enabled: bool = False
    memory_store: str = "memory"  # memory | sqlite
    memory_cap_ips: int = 10_000
    memory_cap_sessions_per_ip: int = 50
    intent_enabled: bool = True
    cache_enabled: bool = True
    cache_capacity: int = 5_000
    cache_ttl_seconds: int = 1_800
    backends: dict[str, Any] = field(default_factory=dict)
    prompts_dir: str | None = None
    redact_secrets_in_prompts: bool = True
    dry_run: bool = False
    force_backend: str | None = None


@dataclass
class GeoConfig:
    """Settings for the GeoIP resolver."""

    enabled: bool = True
    provider: str = "ip-api"  # ip-api | maxmind
    maxmind_db: str = ""
    vary_responses: bool = True
    cache_size: int = 4096


@dataclass
class ReportingConfig:
    """Settings for report generation."""

    auto_report_interval: int = 3600  # 0 disables
    html_export: bool = True
    top_n_attackers: int = 20
    output_directory: str = "./honeytrap_reports"


@dataclass
class RateLimiterConfig:
    """Settings for per-IP rate limiting and concurrent-connection caps."""

    enabled: bool = True
    max_per_minute: int = 30
    burst: int = 10
    global_concurrent: int = 500
    per_ip_concurrent: int = 20
    stale_after_seconds: float = 600.0
    tarpit_on_limit: bool = False
    tarpit_seconds: float = 2.0


@dataclass
class TimeoutsConfig:
    """Protocol-specific idle timeouts (seconds)."""

    http_idle: float = 120.0
    ssh_idle: float = 300.0
    telnet_idle: float = 300.0
    ftp_idle: float = 60.0
    smb_idle: float = 60.0
    smtp_idle: float = 300.0
    mysql_idle: float = 120.0


@dataclass
class SanitizerConfig:
    """Settings for the input sanitization layer."""

    enabled: bool = True
    http_body_max: int = 1024 * 1024
    other_body_max: int = 64 * 1024
    http_header_count_max: int = 100
    http_header_size_max: int = 8 * 1024
    command_max: int = 4096
    reject_null_bytes: bool = True


@dataclass
class GuardianConfig:
    """Settings for the resource guardian."""

    enabled: bool = True
    memory_limit_mb: int = 256
    check_interval_seconds: float = 5.0
    log_dir_warn_mb: int = 2048


@dataclass
class AlertsConfigRaw:
    """Raw representation of the ``alerts`` YAML block.

    The actual channels are built lazily by
    :func:`honeytrap.alerts.parse_alerts_config` so no alerts code is
    imported by the config loader unless the feature is needed.
    """

    enabled: bool = False
    min_severity: str = "MEDIUM"
    dry_run: bool = False
    channels: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        """Return a dict suitable for :func:`parse_alerts_config`."""
        return {
            "enabled": self.enabled,
            "min_severity": self.min_severity,
            "dry_run": self.dry_run,
            "channels": list(self.channels),
        }


@dataclass
class TLSFingerprintConfig:
    """Toggles for the JA3/JA4 TLS fingerprinting subsystem."""

    enabled: bool = True
    database_path: str | None = None


@dataclass
class ForensicsConfigRaw:
    """Configuration for the session-recording forensics subsystem.

    Mirrors :class:`honeytrap.forensics.recorder.ForensicsConfig` but
    lives here so the YAML loader can populate it without dragging the
    forensics package into the config module's import graph.
    """

    enabled: bool = True
    store: str = "jsonl"  # jsonl | sqlite
    path: str = "./sessions"
    max_session_bytes: int = 10 * 1024 * 1024
    max_daily_bytes: int = 1024 * 1024 * 1024
    retention_days: int = 30
    record_tls_handshake: bool = True


@dataclass
class Config:
    """Root configuration object."""

    general: GeneralConfig = field(default_factory=GeneralConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    geo: GeoConfig = field(default_factory=GeoConfig)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)
    rate_limiter: RateLimiterConfig = field(default_factory=RateLimiterConfig)
    timeouts: TimeoutsConfig = field(default_factory=TimeoutsConfig)
    sanitizer: SanitizerConfig = field(default_factory=SanitizerConfig)
    guardian: GuardianConfig = field(default_factory=GuardianConfig)
    alerts: AlertsConfigRaw = field(default_factory=AlertsConfigRaw)
    tls_fingerprint: TLSFingerprintConfig = field(default_factory=TLSFingerprintConfig)
    forensics: ForensicsConfigRaw = field(default_factory=ForensicsConfigRaw)

    def to_dict(self) -> dict[str, Any]:
        """Return the config as a plain dictionary."""
        return asdict(self)


def _apply_dict(cfg: Config, data: dict[str, Any]) -> Config:
    """Merge a dict into ``cfg`` without failing on unknown keys."""
    for section_name, section_data in data.items():
        if section_name == "alerts" and isinstance(section_data, dict):
            cfg.alerts.enabled = bool(section_data.get("enabled", cfg.alerts.enabled))
            cfg.alerts.min_severity = str(
                section_data.get("min_severity", cfg.alerts.min_severity)
            )
            cfg.alerts.dry_run = bool(section_data.get("dry_run", cfg.alerts.dry_run))
            channels = section_data.get("channels")
            if isinstance(channels, list):
                cfg.alerts.channels = [c for c in channels if isinstance(c, dict)]
            continue
        if not isinstance(section_data, dict):
            continue
        section = getattr(cfg, section_name, None)
        if section is None:
            logger.warning("Unknown config section %r — ignored", section_name)
            continue
        for key, value in section_data.items():
            if hasattr(section, key):
                setattr(section, key, value)
            else:
                logger.warning("Unknown config key %s.%s — ignored", section_name, key)
    return cfg


def _apply_env(cfg: Config) -> Config:
    """Apply ``HONEYTRAP_*`` environment overrides."""
    # A few well-known overrides map to typed fields.
    if (value := os.environ.get("HONEYTRAP_AI_ADAPTIVE")):
        cfg.ai.adaptive_enabled = value.lower() in {"1", "true", "yes", "on"}
    if (value := os.environ.get("HONEYTRAP_AI_FORCE_BACKEND")):
        cfg.ai.force_backend = value
    if (value := os.environ.get("HONEYTRAP_AI_KEY")):
        cfg.ai.api_key = value
    if (value := os.environ.get("HONEYTRAP_AI_ENDPOINT")):
        cfg.ai.endpoint = value
    if (value := os.environ.get("HONEYTRAP_AI_MODEL")):
        cfg.ai.model = value
    if (value := os.environ.get("HONEYTRAP_AI_PROVIDER")):
        cfg.ai.provider = value
    if (value := os.environ.get("HONEYTRAP_LOG_DIR")):
        cfg.general.log_directory = value
    if (value := os.environ.get("HONEYTRAP_MAXMIND_DB")):
        cfg.geo.maxmind_db = value
    return cfg


def load_config(path: str | Path | None = None) -> Config:
    """Load configuration from a YAML file if present, merging env overrides.

    Args:
        path: Optional path to ``honeytrap.yaml``. Defaults to cwd lookup.

    Returns:
        A fully populated :class:`Config` instance.
    """
    cfg = Config()

    candidate: Path | None = None
    if path:
        candidate = Path(path)
    else:
        cwd_file = Path.cwd() / "honeytrap.yaml"
        if cwd_file.exists():
            candidate = cwd_file

    if candidate and candidate.exists():
        try:
            with candidate.open("r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
            if not isinstance(data, dict):
                raise ConfigError(f"{candidate} must contain a YAML mapping")
            cfg = _apply_dict(cfg, data)
            logger.debug("Loaded config from %s", candidate)
        except yaml.YAMLError as exc:
            raise ConfigError(f"Invalid YAML in {candidate}: {exc}") from exc
        except OSError as exc:
            raise ConfigError(f"Unable to read {candidate}: {exc}") from exc

    cfg = _apply_env(cfg)
    return cfg
