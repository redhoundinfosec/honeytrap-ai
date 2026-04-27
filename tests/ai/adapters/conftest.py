"""Shared fixtures for the per-protocol adapter tests."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from typing import Any, TypeVar

T = TypeVar("T")


def run(coro: Awaitable[T]) -> T:
    """Run ``coro`` to completion in a fresh event loop."""
    return asyncio.run(coro)  # type: ignore[arg-type]


def make_extra(**kwargs: Any) -> dict[str, Any]:
    """Convenience helper to build the extra dict for AdapterPrompt."""
    return dict(kwargs)
