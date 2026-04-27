"""Telnet adapter — simulates an interactive shell on top of telnet.

The adapter receives a single shell command via
:attr:`AdapterPrompt.inbound` and returns the emulated stdout. Per-OS
persona is read from ``persona["os_persona"]`` (e.g.
``ubuntu-22.04``, ``busybox``, ``cisco-ios``). Working-directory state
is tracked through the per-session memory; the handler passes the
``cwd`` via ``extra["cwd"]`` and can read the updated value from
``extra["new_cwd"]`` after :meth:`respond` returns.

The output never contains the host operator's real ``hostname`` or
absolute filesystem paths; the safety filter scrubs anything that
slips through.
"""

from __future__ import annotations

import shlex
from typing import Any

from honeytrap.ai.adapters.base import AdapterPrompt, BaseAdapter

_BUSYBOX_HELP = (
    "BusyBox v1.30.1 () built-in shell (ash)\nEnter 'help' for a list of built-in commands.\n"
)
_CISCO_HELP = "Switch>\n% Type help or '?' for a list of available commands.\n"


class TelnetAdapter(BaseAdapter):
    """Telnet shell adapter."""

    protocol = "telnet"

    def template_response(self, prompt: AdapterPrompt) -> str:
        """Render the simulated stdout for ``prompt.inbound``."""
        os_persona = str(prompt.persona.get("os_persona", "ubuntu-22.04"))
        state = str(prompt.extra.get("state", "shell"))
        if state == "login_banner":
            return self._login_banner(os_persona, prompt)
        if state == "motd":
            return self._motd(os_persona, prompt)
        cmd_line = prompt.inbound.strip()
        if not cmd_line:
            return ""
        return self._run_command(cmd_line, os_persona, prompt)

    def validate_shape(self, response: str) -> str:
        """Telnet is byte-clean — strip NUL and lone CR."""
        return response.replace("\x00", "").replace("\r\n", "\n")

    def cache_key(self, prompt: AdapterPrompt) -> str:
        cmd = prompt.inbound.strip().split(" ", 1)[0]
        os_persona = str(prompt.persona.get("os_persona", "ubuntu-22.04"))
        cwd = str(prompt.extra.get("cwd", "/"))
        state = str(prompt.extra.get("state", "shell"))
        return f"{cmd}|{os_persona}|{cwd}|{state}"

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _login_banner(self, os_persona: str, prompt: AdapterPrompt) -> str:
        host = str(prompt.persona.get("hostname", "localhost"))
        if os_persona.startswith("busybox"):
            return f"\n{host} login: "
        if os_persona.startswith("cisco"):
            return "\nUser Access Verification\n\nUsername: "
        return f"\nUbuntu 22.04.3 LTS {host} tty1\n\n{host} login: "

    def _motd(self, os_persona: str, prompt: AdapterPrompt) -> str:
        host = str(prompt.persona.get("hostname", "localhost"))
        if os_persona.startswith("busybox"):
            return _BUSYBOX_HELP
        if os_persona.startswith("cisco"):
            return _CISCO_HELP
        return (
            f"Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)\n\n"
            "  System information as of "
            f"{prompt.persona.get('login_time', 'Wed Apr 27 12:00:00 UTC 2026')}\n\n"
            "  System load:  0.08    Processes:           104\n"
            f"  Usage of /:   42.3%   Users logged in:     1\n"
            f"  Memory usage: 18%     IPv4 address for eth0: 10.0.0.5\n\n"
            "Last login: Wed Apr 27 11:54:22 UTC 2026 from 10.0.0.1\n"
            f"root@{host}:~# "
        )

    def _run_command(self, cmd_line: str, os_persona: str, prompt: AdapterPrompt) -> str:
        try:
            tokens = shlex.split(cmd_line)
        except ValueError:
            tokens = cmd_line.split()
        if not tokens:
            return ""
        verb = tokens[0]
        cwd = str(prompt.extra.get("cwd", "/root"))
        new_cwd = cwd
        if verb == "cd":
            new_cwd = self._resolve_cd(cwd, tokens[1] if len(tokens) > 1 else "")
            prompt.extra["new_cwd"] = new_cwd
            return ""
        if verb == "pwd":
            return cwd + "\n"
        if verb == "whoami":
            return str(prompt.persona.get("user", "root")) + "\n"
        if verb == "id":
            return "uid=0(root) gid=0(root) groups=0(root)\n"
        if verb == "uname":
            return self._uname(os_persona, tokens) + "\n"
        if verb == "ls":
            return self._ls(cwd, os_persona) + "\n"
        if verb == "cat" and len(tokens) > 1:
            return self._cat(tokens[1], os_persona, prompt) + "\n"
        if verb == "ps":
            return self._ps(os_persona) + "\n"
        if verb == "netstat":
            return self._netstat(os_persona) + "\n"
        if verb == "ifconfig":
            return self._ifconfig(os_persona) + "\n"
        if verb == "history":
            history = list(prompt.extra.get("history", []) or [])
            return "\n".join(f"   {i + 1}  {h}" for i, h in enumerate(history)) + "\n"
        if verb == "env":
            return "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nHOME=/root\nUSER=root\nSHELL=/bin/bash\n"
        if verb == "sudo":
            return "[sudo] password for root: \n"
        if verb in {"exit", "logout", "quit"}:
            return ""
        return f"-bash: {verb}: command not found\n"

    @staticmethod
    def _resolve_cd(cwd: str, target: str) -> str:
        if not target or target == "~":
            return "/root"
        if target.startswith("/"):
            return target.rstrip("/") or "/"
        parts = cwd.strip("/").split("/")
        for token in target.split("/"):
            if token in {"", "."}:
                continue
            if token == "..":
                if parts:
                    parts.pop()
            else:
                parts.append(token)
        return "/" + "/".join(p for p in parts if p)

    @staticmethod
    def _uname(os_persona: str, tokens: list[str]) -> str:
        if os_persona.startswith("busybox"):
            return "Linux iotcam 4.4.179 #1 SMP PREEMPT Tue Jul 28 10:29:33 UTC 2020 mips GNU/Linux"
        if os_persona.startswith("cisco"):
            return "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE5"
        return "Linux ubuntu 5.15.0-78-generic #85-Ubuntu SMP Thu Aug 3 15:43:41 UTC 2026 x86_64 GNU/Linux"

    @staticmethod
    def _ls(cwd: str, os_persona: str) -> str:
        if os_persona.startswith("busybox"):
            return "bin\nlib\nproc\nsbin\ntmp\nvar"
        if os_persona.startswith("cisco"):
            return "Directory of flash:/\n  1  -rw-  1234567  Apr 27 2026 c2960-lanbasek9-mz.150-2.SE5.bin"
        if cwd == "/" or cwd == "":
            return "bin  boot  dev  etc  home  lib  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var"
        if cwd.endswith("/root") or cwd == "/root":
            return ".bash_history  .bashrc  .profile  notes.txt"
        return "(empty)"

    @staticmethod
    def _cat(path: str, os_persona: str, prompt: AdapterPrompt) -> str:
        if path == "/etc/passwd":
            return (
                "root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
                "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
                "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash"
            )
        if path == "/etc/shadow":
            return "cat: /etc/shadow: Permission denied"
        if path == "/etc/hostname":
            return str(prompt.persona.get("hostname", "ubuntu"))
        if path.endswith("notes.txt"):
            return "Reminder: rotate the API key on the gateway next quarter."
        return f"cat: {path}: No such file or directory"

    @staticmethod
    def _ps(os_persona: str) -> str:
        return (
            "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
            "root         1  0.0  0.1 168120 11428 ?        Ss   12:00   0:01 /sbin/init\n"
            "root       342  0.0  0.0  72296  6088 ?        Ss   12:00   0:00 /usr/sbin/sshd -D\n"
            "root       512  0.0  0.0  18272  5012 ?        S    12:00   0:00 -bash"
        )

    @staticmethod
    def _netstat(os_persona: str) -> str:
        return (
            "Active Internet connections (servers and established)\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
            "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n"
            "tcp        0      0 10.0.0.5:22             10.0.0.1:54242          ESTABLISHED"
        )

    @staticmethod
    def _ifconfig(os_persona: str) -> str:
        return (
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
            "        inet 10.0.0.5  netmask 255.255.255.0  broadcast 10.0.0.255\n"
            "        inet6 fe80::5054:ff:fe11:2233  prefixlen 64  scopeid 0x20<link>\n"
            "        ether 52:54:00:11:22:33  txqueuelen 1000  (Ethernet)"
        )


def latency_cap_ms(persona: dict[str, Any]) -> float:
    """Return a deterministic upper-bound latency for a Telnet response."""
    base = float(persona.get("latency_ms", 50.0))
    return min(max(base, 5.0), 250.0)
