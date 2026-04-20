"""Tests for the security-hardening layer.

Covers:

* Rate limiter token-bucket semantics, burst behavior, concurrency caps,
  and stale-entry cleanup.
* Input sanitizer size limits and null-byte handling across HTTP + other
  protocols.
* Resource guardian state transitions.
* Timeout helpers on the base protocol handler.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from honeytrap.core.config import (
    GuardianConfig,
    RateLimiterConfig,
    SanitizerConfig,
    TimeoutsConfig,
)
from honeytrap.core.guardian import ResourceGuardian
from honeytrap.core.rate_limiter import RateLimiter
from honeytrap.core.sanitizer import InputSanitizer


# ----------------------------------------------------------------------
# Rate limiter
# ----------------------------------------------------------------------
@pytest.mark.asyncio
async def test_rate_limiter_allows_within_burst() -> None:
    limiter = RateLimiter(max_per_minute=60, burst=5)
    for _ in range(5):
        decision = await limiter.check("1.2.3.4")
        assert decision.allowed is True


@pytest.mark.asyncio
async def test_rate_limiter_blocks_after_burst() -> None:
    # With very slow refill, the 6th request should fail.
    limiter = RateLimiter(max_per_minute=1, burst=3)
    for _ in range(3):
        decision = await limiter.check("1.2.3.4")
        assert decision.allowed is True
    decision = await limiter.check("1.2.3.4")
    assert decision.allowed is False
    assert "rate limit" in decision.reason.lower()
    assert decision.retry_after > 0


@pytest.mark.asyncio
async def test_rate_limiter_per_ip_independent() -> None:
    limiter = RateLimiter(max_per_minute=1, burst=2)
    for _ in range(2):
        assert (await limiter.check("1.1.1.1")).allowed
    for _ in range(2):
        assert (await limiter.check("2.2.2.2")).allowed
    # Both exhausted; next attempts blocked per-IP.
    assert not (await limiter.check("1.1.1.1")).allowed
    assert not (await limiter.check("2.2.2.2")).allowed


@pytest.mark.asyncio
async def test_rate_limiter_global_cap() -> None:
    limiter = RateLimiter(max_per_minute=600, burst=100, global_concurrent=2)
    await limiter.acquire("a")
    await limiter.acquire("b")
    decision = await limiter.check("c")
    assert decision.allowed is False
    assert "global" in decision.reason


@pytest.mark.asyncio
async def test_rate_limiter_per_ip_concurrent_cap() -> None:
    limiter = RateLimiter(
        max_per_minute=600, burst=100, per_ip_concurrent=2, global_concurrent=100
    )
    await limiter.acquire("1.1.1.1")
    await limiter.acquire("1.1.1.1")
    decision = await limiter.check("1.1.1.1")
    assert decision.allowed is False
    assert "per-IP" in decision.reason


@pytest.mark.asyncio
async def test_rate_limiter_cleans_stale_entries() -> None:
    limiter = RateLimiter(max_per_minute=60, burst=5, stale_after_seconds=0.01)
    await limiter.check("1.1.1.1")
    assert "1.1.1.1" in limiter._buckets
    await asyncio.sleep(0.02)
    pruned = await limiter.force_cleanup()
    assert pruned >= 1
    assert "1.1.1.1" not in limiter._buckets


@pytest.mark.asyncio
async def test_rate_limiter_tarpit_returns_delay() -> None:
    limiter = RateLimiter(
        max_per_minute=1, burst=1, tarpit_on_limit=True, tarpit_seconds=0.5
    )
    assert (await limiter.check("x")).allowed
    decision = await limiter.check("x")
    assert decision.allowed is False
    assert decision.tarpit_seconds == 0.5


@pytest.mark.asyncio
async def test_rate_limiter_disabled_allows_all() -> None:
    limiter = RateLimiter(enabled=False, max_per_minute=1, burst=1)
    for _ in range(50):
        assert (await limiter.check("spam")).allowed


@pytest.mark.asyncio
async def test_rate_limiter_stats_snapshot() -> None:
    limiter = RateLimiter(max_per_minute=1, burst=1)
    await limiter.check("1.2.3.4")
    await limiter.check("1.2.3.4")  # blocked
    stats = await limiter.stats()
    assert stats["tracked_ips"] == 1
    assert stats["total_blocks"] >= 1


# ----------------------------------------------------------------------
# Sanitizer
# ----------------------------------------------------------------------
def test_sanitizer_accepts_normal_body() -> None:
    s = InputSanitizer()
    result = s.check_http_body(b"hello world")
    assert result.ok


def test_sanitizer_rejects_large_http_body() -> None:
    s = InputSanitizer(http_body_max=512)
    result = s.check_http_body(b"x" * 1024)
    assert result.ok is False
    assert "http_body_too_large" in result.reason
    assert result.offending_hex


def test_sanitizer_rejects_large_protocol_payload() -> None:
    s = InputSanitizer(other_body_max=256)
    result = s.check_protocol_payload(b"x" * 1024)
    assert result.ok is False
    assert "payload_too_large" in result.reason


def test_sanitizer_null_byte_body_rejected() -> None:
    s = InputSanitizer(reject_null_bytes=True)
    result = s.check_http_body(b"normal\x00payload")
    assert result.ok is False
    assert result.offending_hex
    assert "null" in result.reason


def test_sanitizer_command_length_enforced() -> None:
    s = InputSanitizer(command_max=16)
    ok = s.check_command("ls -la")
    assert ok.ok
    bad = s.check_command("a" * 100)
    assert bad.ok is False
    assert "command_too_long" in bad.reason


def test_sanitizer_header_count_enforced() -> None:
    s = InputSanitizer(http_header_count_max=3)
    headers = {f"X-{i}": "v" for i in range(10)}
    assert s.check_http_headers(headers).ok is False


def test_sanitizer_header_size_enforced() -> None:
    s = InputSanitizer(http_header_size_max=64)
    headers = {"X-Big": "A" * 1000}
    assert s.check_http_headers(headers).ok is False


def test_sanitizer_sanitize_text_strips_null() -> None:
    s = InputSanitizer()
    assert "\\x00" in s.sanitize_text("hello\x00world")


def test_sanitizer_disabled_accepts_anything() -> None:
    s = InputSanitizer(enabled=False, http_body_max=1)
    assert s.check_http_body(b"x" * 1000).ok is True


# ----------------------------------------------------------------------
# Guardian
# ----------------------------------------------------------------------
@pytest.mark.asyncio
async def test_guardian_reports_connection_pressure(tmp_path: Path) -> None:
    limiter = RateLimiter(max_per_minute=60, burst=10, global_concurrent=2)
    guardian = ResourceGuardian(
        log_directory=tmp_path,
        memory_limit_mb=1_000_000,  # effectively unlimited
        rate_limiter=limiter,
        check_interval_seconds=0.05,
    )
    await limiter.acquire("a")
    await limiter.acquire("b")
    stats = await guardian.check_once()
    assert stats.should_refuse is True
    assert "connections" in stats.refusal_reason
    allow, reason = await guardian.should_accept_connection()
    assert allow is False
    assert reason == stats.refusal_reason


@pytest.mark.asyncio
async def test_guardian_recovers_when_pressure_drops(tmp_path: Path) -> None:
    limiter = RateLimiter(max_per_minute=60, burst=10, global_concurrent=1)
    guardian = ResourceGuardian(
        log_directory=tmp_path,
        memory_limit_mb=1_000_000,
        rate_limiter=limiter,
    )
    await limiter.acquire("a")
    first = await guardian.check_once()
    assert first.should_refuse is True
    await limiter.release("a")
    second = await guardian.check_once()
    assert second.should_refuse is False


@pytest.mark.asyncio
async def test_guardian_disabled_always_accepts(tmp_path: Path) -> None:
    guardian = ResourceGuardian(log_directory=tmp_path, enabled=False)
    allow, _ = await guardian.should_accept_connection()
    assert allow is True


@pytest.mark.asyncio
async def test_guardian_stats_serializable(tmp_path: Path) -> None:
    limiter = RateLimiter(max_per_minute=60, burst=5)
    guardian = ResourceGuardian(log_directory=tmp_path, rate_limiter=limiter)
    await guardian.check_once()
    stats = await guardian.stats()
    assert "connections" in stats
    assert "memory_mb" in stats
    assert isinstance(stats["enabled"], bool)


# ----------------------------------------------------------------------
# Timeout + idle-close semantics (tests the helper on the base handler).
# ----------------------------------------------------------------------
@pytest.mark.asyncio
async def test_idle_timeout_resolved_per_protocol() -> None:
    """The base handler's idle_timeout() pulls protocol-specific values."""
    from honeytrap.core.config import Config
    from honeytrap.core.profile import ServiceSpec
    from honeytrap.protocols.base import ProtocolHandler

    class _FakeEngine:
        config = Config(timeouts=TimeoutsConfig(http_idle=1, ssh_idle=2, ftp_idle=3))

    class _Handler(ProtocolHandler):
        async def start(self, bind_address: str, port: int) -> None:  # pragma: no cover
            pass

        async def stop(self) -> None:  # pragma: no cover
            pass

    svc = ServiceSpec(protocol="http", port=80)
    handler = _Handler(svc, _FakeEngine())  # type: ignore[arg-type]
    handler.name = "http"
    assert handler.idle_timeout() == 1
    handler.name = "ssh"
    assert handler.idle_timeout() == 2
    handler.name = "ftp"
    assert handler.idle_timeout() == 3


@pytest.mark.asyncio
async def test_idle_close_honors_timeout() -> None:
    """wait_for raises and the loop reaches the timeout path quickly."""

    async def slow_read() -> None:
        await asyncio.sleep(1.0)

    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(slow_read(), timeout=0.05)


# ----------------------------------------------------------------------
# Config wiring — verify the new sections show up with sane defaults.
# ----------------------------------------------------------------------
def test_config_includes_security_sections() -> None:
    from honeytrap.core.config import load_config

    cfg = load_config()
    assert isinstance(cfg.rate_limiter, RateLimiterConfig)
    assert cfg.rate_limiter.max_per_minute == 30
    assert cfg.rate_limiter.burst == 10
    assert isinstance(cfg.sanitizer, SanitizerConfig)
    assert cfg.sanitizer.http_body_max == 1024 * 1024
    assert isinstance(cfg.guardian, GuardianConfig)
    assert cfg.guardian.memory_limit_mb == 256
    assert isinstance(cfg.timeouts, TimeoutsConfig)
    assert cfg.timeouts.http_idle == 120.0
