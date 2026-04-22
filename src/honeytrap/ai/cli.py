"""Tiny ``honeytrap ai`` subcommand dispatcher."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from honeytrap.ai.backends import build_backend
from honeytrap.ai.memory import SessionMemory

if False:  # pragma: no cover - type-only
    from honeytrap.core.config import Config


def _resolve_input(raw: str) -> str:
    """Resolve a CLI ``@path`` reference; return plain string otherwise."""
    if raw.startswith("@"):
        path = Path(raw[1:])
        return path.read_text(encoding="utf-8", errors="replace")
    return raw


async def _async_ai_test(args: argparse.Namespace, cfg: "Config") -> int:
    from honeytrap.ai.backends import ResponseRequest

    chain = build_backend([{"type": args.backend}], prompts_dir=cfg.ai.prompts_dir)
    inbound = _resolve_input(args.ai_input)
    memory = SessionMemory(session_id="ai-cli", source_ip="127.0.0.1")
    request = ResponseRequest(
        protocol=args.protocol,
        inbound=inbound,
        memory_snapshot={"turn_count": 0},
        persona={},
        session_id=memory.session_id,
    )
    result = await chain.generate(request)
    payload: dict[str, Any] = {
        "backend": result.backend_name,
        "latency_ms": result.latency_ms,
        "shape_ok": result.shape_ok,
        "cached": result.cached,
        "content": result.content,
    }
    sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    return 0


def run_ai_command(args: argparse.Namespace, cfg: "Config") -> int:
    """Dispatch ``honeytrap ai ...`` subcommands."""
    sub = getattr(args, "ai_command", None)
    if sub == "test":
        return asyncio.run(_async_ai_test(args, cfg))
    sys.stderr.write("usage: honeytrap ai test --protocol <p> --input <@file|text>\n")
    return 2
