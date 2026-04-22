"""``honeytrap api`` subcommand implementation.

Three commands are exposed:

* ``honeytrap api start``  -- run the management API server.
* ``honeytrap api keys ...`` -- create / list / revoke keys.
* ``honeytrap api openapi`` -- dump the OpenAPI 3.1 schema to stdout.

All output is plain text so the CLI composes with shell pipelines (e.g.
``honeytrap api openapi > spec.json``).
"""

from __future__ import annotations

import argparse
import contextlib
import json
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any

from honeytrap.api import APIConfig, APIServer
from honeytrap.api.auth import APIKeyStore
from honeytrap.api.rbac import Role
from honeytrap.api.service import InMemoryService
from honeytrap.core.config import Config, load_config


def build_api_parser(subparsers: argparse._SubParsersAction[Any]) -> None:
    """Register the ``api`` subcommand tree on a top-level argparse group."""
    api_cmd = subparsers.add_parser(
        "api",
        help="Run or administer the HoneyTrap management REST API.",
    )
    api_sub = api_cmd.add_subparsers(dest="api_command", required=False)

    start = api_sub.add_parser("start", help="Start the management API server.")
    start.add_argument("--bind", default="127.0.0.1", help="Bind address (default: 127.0.0.1).")
    start.add_argument("--port", type=int, default=9300, help="TCP port (default: 9300).")
    start.add_argument("--tls-cert", default=None, help="Optional TLS certificate path.")
    start.add_argument("--tls-key", default=None, help="Optional TLS private key path.")
    start.add_argument(
        "--trusted-proxies",
        default="",
        help="Comma-separated proxy addresses allowed to set X-Forwarded-For.",
    )
    start.add_argument(
        "--allow-external",
        action="store_true",
        help="Permit bind to a non-loopback address.",
    )
    start.add_argument(
        "--require-hmac",
        action="store_true",
        help="Require HMAC signing on every authenticated request.",
    )
    start.add_argument(
        "--state-dir",
        default=".honeytrap",
        help="State directory for keys / audit log (default: .honeytrap).",
    )

    keys = api_sub.add_parser("keys", help="Administer API keys.")
    keys_sub = keys.add_subparsers(dest="keys_command", required=True)

    create = keys_sub.add_parser("create", help="Create a new API key.")
    create.add_argument("--name", required=True, help="Human-readable label.")
    create.add_argument(
        "--role",
        choices=[r.value for r in Role],
        default=Role.VIEWER.value,
        help="Privilege tier for the new key (default: viewer).",
    )
    create.add_argument("--state-dir", default=".honeytrap")

    list_cmd = keys_sub.add_parser("list", help="List all API keys (without secrets).")
    list_cmd.add_argument("--state-dir", default=".honeytrap")

    revoke = keys_sub.add_parser("revoke", help="Revoke an existing API key by id.")
    revoke.add_argument("id", help="API key id to revoke.")
    revoke.add_argument("--state-dir", default=".honeytrap")

    openapi = api_sub.add_parser("openapi", help="Print the OpenAPI 3.1 schema to stdout.")
    openapi.add_argument("--state-dir", default=".honeytrap")


def run_api_command(args: argparse.Namespace, cfg: Config) -> int:
    """Dispatch to the right ``api`` subcommand, returning an exit code."""
    del cfg  # reserved for future admin commands that read honeytrap config
    command = getattr(args, "api_command", None)
    if command == "start":
        return _cmd_start(args)
    if command == "keys":
        return _cmd_keys(args)
    if command == "openapi":
        return _cmd_openapi(args)
    # No subcommand given — mirror argparse's default help output.
    print("usage: honeytrap api {start,keys,openapi}")
    return 2


def _cmd_start(args: argparse.Namespace) -> int:
    trusted = [p.strip() for p in (args.trusted_proxies or "").split(",") if p.strip()]
    config = APIConfig(
        host=args.bind,
        port=args.port,
        allow_external=args.allow_external,
        tls_cert=args.tls_cert,
        tls_key=args.tls_key,
        trusted_proxies=trusted,
        state_dir=Path(args.state_dir),
        require_hmac=args.require_hmac,
    )
    service = InMemoryService()
    key_store = APIKeyStore(config.state_path(config.api_keys_name))
    server = APIServer(service, key_store, config)
    try:
        server.start()
    except (OSError, RuntimeError) as exc:
        print(f"Failed to start API server: {exc}", file=sys.stderr)
        return 1
    print(
        f"HoneyTrap API listening on "
        f"{'https' if server.tls_enabled else 'http'}://"
        f"{server.bound_host}:{server.bound_port}/api/v1/",
        file=sys.stderr,
    )
    stop_event = threading.Event()

    def _signal(*_args: Any) -> None:
        stop_event.set()

    for name in ("SIGINT", "SIGTERM"):
        if hasattr(signal, name):
            with contextlib.suppress(ValueError, OSError):
                signal.signal(getattr(signal, name), _signal)
    try:
        while not stop_event.is_set():
            if service.control.shutdown_requested:
                break
            time.sleep(0.25)
    finally:
        server.stop()
    return 0


def _cmd_keys(args: argparse.Namespace) -> int:
    config = APIConfig(state_dir=Path(args.state_dir))
    store = APIKeyStore(config.state_path(config.api_keys_name))
    sub = getattr(args, "keys_command", None)
    if sub == "create":
        record, plaintext = store.create(name=args.name, role=Role.from_str(args.role))
        print("WARNING: this is the only time the plaintext token will be shown.")
        print(f"Token: {plaintext}")
        print(json.dumps(_public_key_dict(record), indent=2))
        return 0
    if sub == "list":
        rows = [_public_key_dict(k) for k in store.list()]
        print(json.dumps(rows, indent=2))
        return 0
    if sub == "revoke":
        ok = store.revoke(args.id)
        if not ok:
            print(f"No API key with id {args.id}", file=sys.stderr)
            return 1
        print(f"Revoked {args.id}")
        return 0
    print("usage: honeytrap api keys {create,list,revoke}", file=sys.stderr)
    return 2


def _cmd_openapi(args: argparse.Namespace) -> int:
    config = APIConfig(state_dir=Path(args.state_dir))
    service = InMemoryService()
    store = APIKeyStore(config.state_path(config.api_keys_name))
    server = APIServer(service, store, config)
    json.dump(server.openapi_document(), sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


def _public_key_dict(record: Any) -> dict[str, Any]:
    """Render an API key for CLI output, never leaking the hash."""
    return {
        "id": record.id,
        "name": record.name,
        "role": record.role.value,
        "prefix": record.prefix,
        "created_at": record.created_at,
        "last_used_at": record.last_used_at,
        "revoked_at": record.revoked_at,
    }


def load_config_or_default() -> Config:
    """Return the honeytrap config, swallowing errors for offline commands."""
    try:
        return load_config(None)
    except Exception:  # noqa: BLE001 -- CLI should still run without a full config
        return Config()
