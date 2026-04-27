"""Prompt redaction used before forwarding attacker input to remote LLMs.

We do want to keep attacker payloads in *forensic* logs — that is the
whole point — but forwarding raw credential material or API keys to a
third-party inference endpoint is a separate risk. Operators opt-in to
remote backends, and when they do this module scrubs obvious secret
patterns out of the outbound prompt without destroying the structural
hints the LLM needs to roleplay.

The redaction is deliberately coarse: we prefer to over-redact (replace
``password=hunter2`` with ``password=<redacted>``) rather than leak a
real secret. The inbound payload is still recorded verbatim in the
forensic log.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import TypeAlias

_Replacement: TypeAlias = "str | Callable[[re.Match[str]], str]"
_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], _Replacement], ...] = (
    (re.compile(r"(?i)(password|passwd|pwd|pass)\s*[:=]\s*[^\s&;]+"), r"\1=<redacted>"),
    (re.compile(r"(?i)(api[_-]?key|token|secret)\s*[:=]\s*[A-Za-z0-9_\-]+"), r"\1=<redacted>"),
    (
        re.compile(r"(?i)authorization:\s*bearer\s+[A-Za-z0-9_\-.=]+"),
        "Authorization: Bearer <redacted>",
    ),
    (
        re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]+"),
        "aws_secret_access_key=<redacted>",
    ),
    (
        re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----"),
        "<redacted-private-key>",
    ),
    (re.compile(r"\b[A-Za-z0-9]{32,}\b"), lambda m: _redact_long_tokens(m.group(0))),
)


def _redact_long_tokens(value: str) -> str:
    """Long homogeneous token -> redact; shortish ones (hashes shown in recon) -> keep."""
    if 32 <= len(value) <= 256 and value.isalnum():
        return "<redacted-token>"
    return value


def redact_prompt(text: str) -> str:
    """Scrub obvious secrets from ``text`` before forwarding to an LLM."""
    out = text
    for pattern, replacement in _SECRET_PATTERNS:
        if callable(replacement):
            out = pattern.sub(replacement, out)
        else:
            out = pattern.sub(replacement, out)
    return out
