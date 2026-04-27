"""Shared Hypothesis strategies and pytest configuration for fuzz tests.

The fuzz tests live behind the ``fuzz`` marker so operators can run
``pytest -m "not fuzz"`` to skip them in low-resource environments.
By default they ARE included with a capped example budget so the suite
remains fast enough for CI.
"""

from __future__ import annotations

import os

from hypothesis import HealthCheck, settings
from hypothesis import strategies as st

# Hypothesis profiles. The "ci" profile is intended for the nightly fuzz
# workflow and bumps the example budget so we exercise rare branches.
settings.register_profile(
    "ci",
    max_examples=500,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)
settings.register_profile("default", max_examples=50, deadline=None)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "default"))


def random_buffer_strategy(max_size: int = 4096) -> st.SearchStrategy[bytes]:
    """Return a strategy producing arbitrary byte buffers up to ``max_size``.

    The buffers can be empty so parsers see truncated input as well as
    full-length payloads.
    """
    return st.binary(min_size=0, max_size=max_size)


def varint_byte_strategy() -> st.SearchStrategy[bytes]:
    """Return a strategy producing 1-5 byte sequences resembling varints.

    The resulting bytes have arbitrary continuation bits set, so this
    exercises both well-formed and malformed variable-byte encodings.
    """
    return st.binary(min_size=1, max_size=5)


def small_text_strategy(max_size: int = 64) -> st.SearchStrategy[str]:
    """Return a strategy producing short Unicode text values."""
    return st.text(min_size=0, max_size=max_size)


def option_pair_strategy() -> st.SearchStrategy[tuple[int, bytes]]:
    """Return a strategy for ``(option_number, value)`` CoAP option pairs."""
    return st.tuples(
        st.integers(min_value=0, max_value=65535),
        st.binary(min_size=0, max_size=64),
    )
