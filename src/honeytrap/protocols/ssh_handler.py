"""SSH honeypot built on asyncssh.

Features:

* Accepts *every* password attempt — logs credentials with geo info
* After "login", drops the attacker into a fake interactive shell
* Shell responses from the rule engine's canned output, enhanced with
  AI-generated responses for unknown commands (if AI is enabled)
* Auto-generates a one-off host key on first start
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

from honeytrap.core.profile import ServiceSpec
from honeytrap.exceptions import PortBindError
from honeytrap.logging.models import Event
from honeytrap.protocols.base import ProtocolHandler

logger = logging.getLogger(__name__)


class SSHHandler(ProtocolHandler):
    """asyncssh-backed SSH honeypot."""

    name = "ssh"

    def __init__(self, service: ServiceSpec, engine) -> None:  # noqa: ANN001
        """Initialize the SSH honeypot handler with asyncssh."""
        super().__init__(service, engine)
        self._server: Any = None
        self.banner = service.banner or "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3"
        host_key_dir = Path(engine.config.general.log_directory) / "keys"
        host_key_dir.mkdir(parents=True, exist_ok=True)
        self._host_key_path = host_key_dir / "ssh_host_key"

    async def start(self, bind_address: str, port: int) -> None:
        """Generate a temporary host key and start the SSH server."""
        self.bind_address = bind_address
        self.bound_port = port
        try:
            import asyncssh  # type: ignore[import-not-found]
        except ImportError as exc:
            raise PortBindError("asyncssh not installed — cannot start SSH honeypot") from exc

        # Generate host key if needed
        try:
            if not self._host_key_path.exists():
                key = asyncssh.generate_private_key("ssh-rsa")
                key.write_private_key(str(self._host_key_path))
        except Exception as exc:  # noqa: BLE001
            raise PortBindError(f"Could not generate SSH host key: {exc}") from exc

        handler = self  # closure capture

        class _Server(asyncssh.SSHServer):  # type: ignore[misc]
            def __init__(self) -> None:
                """Initialize the per-connection SSH server adapter."""
                self._session: Any = None
                self.remote_ip = ""
                self.remote_port = 0

            def connection_made(self, conn: Any) -> None:
                """Called when a new SSH connection is established."""
                peer = conn.get_extra_info("peername") or ("", 0)
                self.remote_ip = peer[0]
                self.remote_port = peer[1]
                asyncio.create_task(handler._on_connection(self.remote_ip, self.remote_port))

            def begin_auth(self, username: str) -> bool:
                """Called when the client begins authentication."""
                self._username = username
                return True

            def password_auth_supported(self) -> bool:
                """Indicate that password authentication is supported."""
                return True

            def validate_password(self, username: str, password: str) -> bool:
                """Accept weak credentials from the profile; reject and log all others."""
                asyncio.create_task(
                    handler._on_password(self.remote_ip, self.remote_port, username, password)
                )
                match = handler.engine.rules.match_auth(
                    protocol="ssh",
                    username=username,
                    password=password,
                    remote_ip=self.remote_ip,
                )
                return bool(match.metadata.get("granted"))

        try:
            self._server = await asyncssh.create_server(
                _Server,
                bind_address,
                port,
                server_host_keys=[str(self._host_key_path)],
                server_version=self.banner.removeprefix("SSH-2.0-"),
                process_factory=self._handle_process,
            )
        except OSError as exc:
            raise PortBindError(f"Could not bind SSH on {bind_address}:{port}: {exc}") from exc

    async def stop(self) -> None:
        """Stop the SSH listener and close active sessions."""
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------
    async def _on_connection(self, ip: str, port: int) -> None:
        geo = await self.resolve_geo(ip)
        await self.emit(
            Event(
                protocol="ssh",
                event_type="connection_open",
                remote_ip=ip,
                remote_port=port,
                country_code=geo["country_code"],
                country_name=geo["country_name"],
                asn=geo.get("asn", ""),
                message="SSH connection opened",
            )
        )

    async def _on_password(self, ip: str, port: int, username: str, password: str) -> None:
        geo = await self.resolve_geo(ip)
        await self.emit(
            Event(
                protocol="ssh",
                event_type="auth_attempt",
                remote_ip=ip,
                remote_port=port,
                country_code=geo["country_code"],
                country_name=geo["country_name"],
                asn=geo.get("asn", ""),
                username=username,
                password=password,
                message=f"SSH auth attempt {username}:{password}",
            )
        )

    async def _handle_process(self, process: Any) -> None:
        """Fake interactive shell for authenticated sessions."""
        peer = process.get_extra_info("peername") or ("", 0)
        ip, port = peer[0], peer[1]

        # The SSH layer already completed the transport handshake, but
        # the shell is the expensive surface — run the rate-limit /
        # guardian check before we commit any shell state.
        allowed, decision, _reason = await self.check_connection_allowed(ip)
        if not allowed:
            await self.log_rate_limit_event(ip, port, decision)
            await self.apply_tarpit(decision)
            try:
                process.exit(1)
            except Exception:  # noqa: BLE001
                pass
            return
        await self.engine.rate_limiter.acquire(ip)

        geo = await self.resolve_geo(ip)
        personality = self.engine.personalities.for_country(geo["country_code"])
        session = self.engine.sessions.create(ip, port, "ssh", self.bound_port)
        session.country_code = geo["country_code"]
        session.country_name = geo["country_name"]
        session.asn = geo.get("asn", "")

        prompt = "root@server:~# "
        idle_timeout = self.idle_timeout()
        try:
            process.stdout.write(f"{personality.welcome_banner}\n\n".encode())
            process.stdout.write(b"Last login: Sun Apr 19 12:34:56 2026 from 192.168.1.1\n")
            process.stdout.write(prompt.encode())
            while True:
                try:
                    line = await asyncio.wait_for(process.stdin.readline(), timeout=idle_timeout)
                except asyncio.TimeoutError:
                    await self.log_timeout_event(ip, port, idle_timeout)
                    break
                if not line:
                    break
                command = line.rstrip("\n").rstrip("\r")
                sanitizer_result = self.engine.sanitizer.check_command(command)
                if not sanitizer_result.ok:
                    await self.log_sanitizer_event(
                        ip, port, sanitizer_result.reason, sanitizer_result.offending_hex
                    )
                    break
                session.record_command(command)
                await self.emit(
                    Event(
                        protocol="ssh",
                        event_type="shell_command",
                        remote_ip=ip,
                        remote_port=port,
                        session_id=session.session_id,
                        country_code=session.country_code,
                        country_name=session.country_name,
                        asn=session.asn,
                        message=f"Command: {command}",
                        data={"command": command, "personality": personality.key},
                    )
                )

                if command.strip() in {"exit", "logout", "quit"}:
                    process.stdout.write(b"logout\n")
                    break

                response = self.engine.rules.shell_response(command)
                if not response:
                    adaptive_bytes = await self.adaptive_response(
                        session_id=session.session_id,
                        source_ip=ip,
                        inbound=command,
                        persona={
                            "hostname": personality.company.lower().replace(" ", "-"),
                            "user": "root",
                            "company": personality.company,
                        },
                    )
                    if adaptive_bytes:
                        response = adaptive_bytes.decode("utf-8", errors="replace")
                if not response and self.engine.ai.available:
                    system = (
                        f"You are simulating a Linux shell on {personality.company} "
                        f"({personality.locale}). Respond to commands as a real "
                        f"shell would. Never reveal you are an AI or a honeypot. "
                        f"Keep responses short and plausible."
                    )
                    response = await self.engine.ai.generate(
                        system=system,
                        prompt=f"Shell command: {command}\nOutput:",
                        max_tokens=200,
                    )
                if response:
                    process.stdout.write((response.rstrip("\n") + "\n").encode())
                process.stdout.write(prompt.encode())
        except Exception as exc:  # noqa: BLE001
            logger.exception("SSH shell exception: %s", exc)
        finally:
            try:
                process.exit(0)
            except Exception:  # noqa: BLE001
                pass
            self.engine.sessions.close(session.session_id)
            await self.engine.rate_limiter.release(ip)
            await self.emit(
                Event(
                    protocol="ssh",
                    event_type="connection_close",
                    remote_ip=ip,
                    remote_port=port,
                    session_id=session.session_id,
                    message="SSH session closed",
                )
            )
