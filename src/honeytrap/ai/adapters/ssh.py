"""SSH adapter — Cycle-16 wrapper around the legacy ``ProtocolResponder``.

The SSH protocol path predates the per-protocol adapter pattern. To
keep the existing SSH handler bit-for-bit compatible (and the 48 SSH AI
tests green), this adapter is a thin
:class:`~honeytrap.ai.adapters.base.BaseAdapter` subclass that returns
plain shell-style stdout for a single command. It does not change the
SSH wire protocol — that remains owned by the asyncssh-driven shell
loop in :mod:`honeytrap.protocols.ssh_handler` — but it provides a
unified shape so the four other adapters (HTTP/SMTP/Telnet/FTP) can
share infrastructure with SSH on the dashboard and metrics layers.
"""

from __future__ import annotations

from honeytrap.ai.adapters.base import AdapterPrompt, BaseAdapter
from honeytrap.ai.adapters.telnet import TelnetAdapter


class SshAdapter(BaseAdapter):
    """SSH shell-text adapter.

    SSH and Telnet share the same shell semantics for honeypot purposes
    — both emit plain stdout for an attacker-supplied command — so the
    SSH adapter delegates the actual command -> output mapping to the
    Telnet adapter. The two protocols still own different wire
    framings; that framing happens in their respective handlers.
    """

    protocol = "ssh"

    def __init__(self, *args: object, **kwargs: object) -> None:
        """Build a Telnet adapter under the hood for command rendering."""
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self._inner = TelnetAdapter(
            chain=self.chain,
            cache=None,
            enabled=self.enabled,
            redact_secrets=self.redact_secrets,
            safety_event_callback=self.safety_event_callback,
            max_inbound_bytes=self.max_inbound_bytes,
        )

    def template_response(self, prompt: AdapterPrompt) -> str:
        """Render shell stdout for the SSH command."""
        return self._inner.template_response(prompt)

    def validate_shape(self, response: str) -> str:
        """SSH shell text is byte-clean — only strip NULs."""
        return response.replace("\x00", "")

    def cache_key(self, prompt: AdapterPrompt) -> str:
        cmd = prompt.inbound.strip().split(" ", 1)[0]
        os_persona = str(prompt.persona.get("os_persona", "ubuntu-22.04"))
        cwd = str(prompt.extra.get("cwd", "/root"))
        return f"{cmd}|{os_persona}|{cwd}"
