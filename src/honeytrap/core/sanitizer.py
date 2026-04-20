"""Input sanitization and payload-size enforcement.

Protocol handlers delegate to this module before they trust attacker-
supplied bytes. The rules are intentionally conservative: a honeypot
exists to be poked at, so the goal isn't to *block* malicious input but
to *cap* it at a point where it can no longer damage the honeypot
itself (memory exhaustion, log-disk blowout, crashes on undecodable
bytes).

Every rejection is surfaced as a :class:`SanitizerResult` so callers can
log a security event with a consistent shape.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


# Defaults are chosen to match common real-world attacker payload sizes
# while capping well below memory concerns. Tune via config.
DEFAULT_HTTP_BODY_MAX = 1024 * 1024  # 1 MB
DEFAULT_OTHER_BODY_MAX = 64 * 1024  # 64 KB
DEFAULT_HTTP_HEADER_COUNT_MAX = 100
DEFAULT_HTTP_HEADER_SIZE_MAX = 8 * 1024  # 8 KB per header
DEFAULT_COMMAND_MAX = 4096


@dataclass
class SanitizerResult:
    """Outcome of a sanitization check."""

    ok: bool
    reason: str = ""
    # Raw hex of the offending payload, trimmed — useful in security logs
    # because it lets you reason about exactly what arrived without
    # risking logfile injection from non-printable bytes.
    offending_hex: str = ""
    metadata: dict[str, Any] | None = None

    @classmethod
    def success(cls) -> SanitizerResult:
        """Build the canonical "all good" result."""
        return cls(ok=True)


class InputSanitizer:
    """Centralized input-validation helper shared by every handler."""

    def __init__(
        self,
        *,
        http_body_max: int = DEFAULT_HTTP_BODY_MAX,
        other_body_max: int = DEFAULT_OTHER_BODY_MAX,
        http_header_count_max: int = DEFAULT_HTTP_HEADER_COUNT_MAX,
        http_header_size_max: int = DEFAULT_HTTP_HEADER_SIZE_MAX,
        command_max: int = DEFAULT_COMMAND_MAX,
        reject_null_bytes: bool = True,
        enabled: bool = True,
    ) -> None:
        """Configure the sanitizer.

        Args:
            http_body_max: Maximum HTTP body size in bytes.
            other_body_max: Maximum body for non-HTTP protocols.
            http_header_count_max: Max HTTP headers per request.
            http_header_size_max: Max individual header value length.
            command_max: Max command length (SSH/Telnet/FTP).
            reject_null_bytes: If True, payloads with NUL are rejected;
                the raw hex is preserved for security logs either way.
            enabled: Global on/off switch.
        """
        self.enabled = enabled
        self.http_body_max = max(512, http_body_max)
        self.other_body_max = max(256, other_body_max)
        self.http_header_count_max = max(1, http_header_count_max)
        self.http_header_size_max = max(64, http_header_size_max)
        self.command_max = max(16, command_max)
        self.reject_null_bytes = reject_null_bytes

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------
    def check_http_body(self, body: bytes | str) -> SanitizerResult:
        """Validate an HTTP request body."""
        if not self.enabled:
            return SanitizerResult.success()
        raw = body.encode("utf-8", errors="replace") if isinstance(body, str) else body
        if len(raw) > self.http_body_max:
            return SanitizerResult(
                ok=False,
                reason=f"http_body_too_large:{len(raw)}>{self.http_body_max}",
                offending_hex=_hex_preview(raw),
                metadata={"size": len(raw), "limit": self.http_body_max},
            )
        return self._check_null_bytes(raw)

    def check_http_headers(self, headers: Any) -> SanitizerResult:
        """Validate an HTTP header mapping.

        Accepts any mapping with ``items()``; aiohttp's ``CIMultiDict`` and
        plain dicts both work.
        """
        if not self.enabled:
            return SanitizerResult.success()
        try:
            items = list(headers.items())
        except AttributeError:
            items = list(headers)
        if len(items) > self.http_header_count_max:
            return SanitizerResult(
                ok=False,
                reason=f"http_header_count_too_high:{len(items)}>{self.http_header_count_max}",
                metadata={"count": len(items)},
            )
        for name, value in items:
            size = len(str(name)) + len(str(value))
            if size > self.http_header_size_max:
                return SanitizerResult(
                    ok=False,
                    reason=f"http_header_too_large:{size}>{self.http_header_size_max}",
                    metadata={"header": str(name)[:64], "size": size},
                )
        return SanitizerResult.success()

    # ------------------------------------------------------------------
    # Non-HTTP protocols
    # ------------------------------------------------------------------
    def check_protocol_payload(self, payload: bytes) -> SanitizerResult:
        """Validate a binary payload for SSH/Telnet/FTP/SMB."""
        if not self.enabled:
            return SanitizerResult.success()
        if len(payload) > self.other_body_max:
            return SanitizerResult(
                ok=False,
                reason=f"payload_too_large:{len(payload)}>{self.other_body_max}",
                offending_hex=_hex_preview(payload),
                metadata={"size": len(payload), "limit": self.other_body_max},
            )
        return self._check_null_bytes(payload)

    def check_command(self, command: str | bytes) -> SanitizerResult:
        """Validate a shell-style command string from SSH/Telnet/FTP."""
        if not self.enabled:
            return SanitizerResult.success()
        raw = command.encode("utf-8", errors="replace") if isinstance(command, str) else command
        if len(raw) > self.command_max:
            return SanitizerResult(
                ok=False,
                reason=f"command_too_long:{len(raw)}>{self.command_max}",
                offending_hex=_hex_preview(raw),
                metadata={"size": len(raw), "limit": self.command_max},
            )
        return self._check_null_bytes(raw, hard_fail=False)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def sanitize_text(self, value: str, *, max_length: int | None = None) -> str:
        """Return ``value`` stripped of NULs and truncated to ``max_length``.

        Intended for fields that will be echoed back to attackers or
        written into logs. NUL is always removed; other control bytes are
        preserved because they're useful evidence in a real incident.
        """
        cleaned = value.replace("\x00", "\\x00")
        if max_length is not None and len(cleaned) > max_length:
            return cleaned[:max_length] + "..."
        return cleaned

    def _check_null_bytes(
        self, raw: bytes, *, hard_fail: bool = True
    ) -> SanitizerResult:
        """Flag payloads containing NUL bytes.

        Many handlers crash on unexpected NULs (they confuse C-backed
        decoders and can embed within strings unexpectedly). When
        ``hard_fail`` is False we record the hex for logs but still let
        the command through — useful for commands where NUL is occasional
        noise from terminals.
        """
        if b"\x00" not in raw:
            return SanitizerResult.success()
        hex_preview = _hex_preview(raw)
        if self.reject_null_bytes and hard_fail:
            return SanitizerResult(
                ok=False,
                reason="null_bytes_present",
                offending_hex=hex_preview,
                metadata={"null_count": raw.count(b"\x00")},
            )
        logger.debug("Sanitizer: NUL bytes observed (non-fatal) — %s", hex_preview)
        return SanitizerResult.success()


def _hex_preview(raw: bytes, limit: int = 128) -> str:
    """Return a hex preview capped at ``limit`` bytes.

    Security logs should retain the raw payload so analysts can recognize
    attack patterns, but we bound the length so a single hostile request
    can't blow the log line out.
    """
    sample = raw[:limit]
    suffix = "..." if len(raw) > limit else ""
    return sample.hex() + suffix
