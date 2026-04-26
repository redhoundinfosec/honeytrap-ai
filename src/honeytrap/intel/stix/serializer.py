"""Stable JSON serialization for STIX 2.1 bundles.

Two flavours are exposed:

* :func:`dump_compact` -- single-line, sorted-key JSON suitable for
  on-the-wire shipping (e.g. TAXII responses).
* :func:`dump_pretty`  -- two-space indented, sorted-key JSON suitable
  for CLI inspection or storage in git.

Both forms are byte-identical for identical inputs because the keys
are always sorted and timestamps use a fixed precision.
"""

from __future__ import annotations

import json
from typing import Any


def dump_compact(bundle: dict[str, Any]) -> str:
    """Return a compact, deterministic JSON string for ``bundle``."""
    return json.dumps(bundle, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def dump_pretty(bundle: dict[str, Any]) -> str:
    """Return a pretty-printed JSON string for ``bundle``."""
    return json.dumps(bundle, indent=2, sort_keys=True, ensure_ascii=False)
