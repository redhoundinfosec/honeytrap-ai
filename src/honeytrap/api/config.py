"""Configuration dataclass for the HoneyTrap management API server."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class APIConfig:
    """Runtime configuration for :class:`~honeytrap.api.server.APIServer`.

    All fields have safe-by-default values: loopback bind, plaintext
    refused on non-loopback without ``allow_external``, HMAC disabled,
    body cap 1 MiB, CORS disabled. The server refuses to start in any
    configuration that would silently expose it.
    """

    host: str = "127.0.0.1"
    port: int = 9300
    allow_external: bool = False
    tls_cert: str | None = None
    tls_key: str | None = None
    trusted_proxies: list[str] = field(default_factory=list)
    state_dir: Path = field(default_factory=lambda: Path(".honeytrap"))
    require_hmac: bool = False

    def __post_init__(self) -> None:
        """Coerce string inputs to :class:`pathlib.Path` for convenience."""
        if not isinstance(self.state_dir, Path):
            self.state_dir = Path(self.state_dir)

    hmac_skew_seconds: int = 300
    cors_allow_origins: list[str] = field(default_factory=list)
    max_body_bytes: int = 1 * 1024 * 1024
    rate_limits: dict[str, int] = field(
        default_factory=lambda: {"viewer": 60, "analyst": 120, "admin": 240}
    )
    audit_log_name: str = "audit.log.jsonl.gz"
    api_keys_name: str = "api_keys.json"

    def state_path(self, name: str) -> Path:
        """Return ``state_dir / name``, creating the directory if missing."""
        self.state_dir.mkdir(parents=True, exist_ok=True)
        return self.state_dir / name
