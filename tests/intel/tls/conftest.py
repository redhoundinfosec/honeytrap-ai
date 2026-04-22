"""Shared fixtures for the TLS intel test suite."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "tls"


def load(name: str) -> bytes:
    """Return the raw bytes of the fixture file ``name``."""
    return (FIXTURES / name).read_bytes()


@pytest.fixture
def firefox_bytes() -> bytes:
    return load("firefox.bin")


@pytest.fixture
def chrome_bytes() -> bytes:
    return load("chrome.bin")


@pytest.fixture
def curl_bytes() -> bytes:
    return load("curl.bin")


@pytest.fixture
def python_requests_bytes() -> bytes:
    return load("python_requests.bin")


@pytest.fixture
def go_http_bytes() -> bytes:
    return load("go_http.bin")


@pytest.fixture
def nmap_bytes() -> bytes:
    return load("nmap.bin")


@pytest.fixture
def masscan_bytes() -> bytes:
    return load("masscan.bin")


@pytest.fixture
def malformed_short_bytes() -> bytes:
    return load("malformed_short.bin")


@pytest.fixture
def non_tls_bytes() -> bytes:
    return load("non_tls.bin")
