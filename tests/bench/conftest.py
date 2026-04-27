"""Pytest configuration for the performance benchmark suite.

Every benchmark module in this directory carries
``pytestmark = pytest.mark.benchmark`` so the global ``addopts`` in
``pyproject.toml`` excludes them from default ``pytest`` runs.
"""

from __future__ import annotations
