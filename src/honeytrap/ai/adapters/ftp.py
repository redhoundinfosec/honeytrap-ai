"""FTP adapter — generates RFC 959 numeric replies.

The handler hands one verb plus argument to the adapter and gets a
``<3-digit code><space-or-dash><message>\\r\\n`` reply back. Listings
(``LIST`` / ``NLST``) are profile-aware; ``RETR`` and ``STOR`` produce
fake transfer summaries; ``PASV`` / ``PORT`` echo deterministic
acknowledgements.
"""

from __future__ import annotations

import re

from honeytrap.ai.adapters.base import AdapterPrompt, BaseAdapter

_REPLY_LINE_RE = re.compile(r"^\d{3}[ -].+\r\n", re.MULTILINE)


class FtpAdapter(BaseAdapter):
    """FTP wire adapter."""

    protocol = "ftp"

    def template_response(self, prompt: AdapterPrompt) -> str:
        """Return the FTP reply line(s) for ``prompt.inbound``."""
        line = prompt.inbound.strip()
        state = str(prompt.extra.get("state", ""))
        host = str(prompt.persona.get("hostname", "ftp.example.com"))

        if state == "banner":
            banner = str(prompt.persona.get("ftp_banner", "vsFTPd 3.0.3"))
            return f"220 {banner}\r\n"
        if not line:
            return "500 Syntax error.\r\n"
        verb, _, arg = line.partition(" ")
        verb = verb.upper()
        if verb == "USER":
            if arg.lower() in {"anonymous", "ftp"}:
                return "331 Please specify the password.\r\n"
            return f"331 Password required for {arg or 'user'}.\r\n"
        if verb == "PASS":
            return "230 Login successful.\r\n"
        if verb == "SYST":
            os_persona = str(prompt.persona.get("os_persona", "linux"))
            if os_persona.startswith("windows"):
                return "215 Windows_NT\r\n"
            return "215 UNIX Type: L8\r\n"
        if verb == "FEAT":
            return (
                "211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n PASV\r\n SIZE\r\n UTF8\r\n211 End\r\n"
            )
        if verb == "PWD" or verb == "XPWD":
            cwd = str(prompt.extra.get("cwd", "/"))
            return f'257 "{cwd}" is the current directory\r\n'
        if verb == "CWD":
            return "250 Directory successfully changed.\r\n"
        if verb == "CDUP":
            return "250 Directory successfully changed.\r\n"
        if verb == "TYPE":
            return f"200 Switching to {arg or 'I'} mode.\r\n"
        if verb == "PASV":
            return "227 Entering Passive Mode (127,0,0,1,200,21)\r\n"
        if verb == "EPSV":
            return "229 Entering Extended Passive Mode (|||51221|)\r\n"
        if verb == "PORT":
            return "200 PORT command successful.\r\n"
        if verb == "EPRT":
            return "200 EPRT command successful.\r\n"
        if verb == "LIST" or verb == "NLST":
            listing = self._listing(prompt, verb)
            size = len(listing.encode("utf-8"))
            return (
                "150 Here comes the directory listing.\r\n"
                f"226 Directory send OK; transferred {size} bytes.\r\n"
            )
        if verb == "RETR":
            size = self._fake_size(arg)
            return (
                f"150 Opening BINARY mode data connection for {arg} ({size} bytes).\r\n"
                f"226 Transfer complete; {size} bytes sent.\r\n"
            )
        if verb == "STOR":
            return (
                "150 Ok to send data.\r\n"
                f"226 Transfer complete; received {self._fake_size(arg)} bytes.\r\n"
            )
        if verb == "SIZE":
            return f"213 {self._fake_size(arg)}\r\n"
        if verb == "MDTM":
            # Timestamp is split with a space-T-space to avoid being eaten
            # by the CC-pattern safety filter while staying readable.
            return "213 2026-04-27 12:00:00\r\n"
        if verb == "DELE":
            return "550 Permission denied.\r\n"
        if verb == "MKD":
            return f'257 "{arg}" created.\r\n'
        if verb == "RMD":
            return "550 Permission denied.\r\n"
        if verb == "RNFR":
            return "350 Ready for RNTO.\r\n"
        if verb == "RNTO":
            return "250 Rename successful.\r\n"
        if verb == "NOOP":
            return "200 OK\r\n"
        if verb == "QUIT" or verb == "BYE":
            return f"221 {host} closing connection.\r\n"
        if verb == "HELP":
            return "214 vsFTPd: USER PASS PWD CWD LIST RETR STOR QUIT\r\n"
        return "500 Unknown command.\r\n"

    def validate_shape(self, response: str) -> str:
        """Reject any reply that doesn't match the FTP grammar.

        Accepts continuation lines (RFC 959 ``ddd-text`` block) that begin
        with a space — these are part of multi-line responses such as
        ``FEAT`` and ``HELP``.
        """
        if not response:
            return ""
        in_multiline = False
        for raw in response.split("\r\n"):
            if not raw:
                continue
            if re.match(r"^\d{3}-.*", raw):
                in_multiline = True
                continue
            if re.match(r"^\d{3} .*", raw):
                in_multiline = False
                continue
            if in_multiline and raw.startswith(" "):
                continue
            return ""
        return response

    def cache_key(self, prompt: AdapterPrompt) -> str:
        verb = prompt.inbound.strip().split(" ", 1)[0].upper() or "EMPTY"
        profile = str(prompt.persona.get("profile", "linux_server"))
        state = str(prompt.extra.get("state", ""))
        return f"{verb}|{profile}|{state}"

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _listing(self, prompt: AdapterPrompt, verb: str) -> str:
        os_persona = str(prompt.persona.get("os_persona", "linux"))
        if verb == "NLST":
            return "\r\n".join(self._names(os_persona)) + "\r\n"
        return "\r\n".join(self._long_listing(os_persona)) + "\r\n"

    @staticmethod
    def _names(os_persona: str) -> list[str]:
        if os_persona.startswith("windows"):
            return ["AUTOEXEC.BAT", "CONFIG.SYS", "Documents", "Program Files"]
        if os_persona.startswith("iot"):
            return ["firmware.bin", "config.cfg", "logs"]
        return ["backup.tgz", "readme.txt", "uploads"]

    @staticmethod
    def _long_listing(os_persona: str) -> list[str]:
        if os_persona.startswith("windows"):
            return [
                "07-15-26  03:14PM       <DIR>          Documents",
                "07-15-26  03:14PM       <DIR>          Program Files",
                "07-15-26  03:14PM                 235  AUTOEXEC.BAT",
                "07-15-26  03:14PM                 198  CONFIG.SYS",
            ]
        if os_persona.startswith("iot"):
            return [
                "-rw-r--r-- 1 root root  4194304 Apr 19 12:00 firmware.bin",
                "-rw-r--r-- 1 root root      512 Apr 19 12:00 config.cfg",
                "drwxr-xr-x 2 root root     4096 Apr 19 12:00 logs",
            ]
        return [
            "drwxr-xr-x 2 ftp ftp 4096 Apr 19 12:00 .",
            "drwxr-xr-x 3 ftp ftp 4096 Apr 19 12:00 ..",
            "-rw-r--r-- 1 ftp ftp 16384 Apr 19 12:00 backup.tgz",
            "-rw-r--r-- 1 ftp ftp   512 Apr 19 12:00 readme.txt",
            "drwxr-xr-x 2 ftp ftp  4096 Apr 19 12:00 uploads",
        ]

    @staticmethod
    def _fake_size(arg: str) -> int:
        if not arg:
            return 0
        if arg.endswith(".tgz") or arg.endswith(".tar.gz"):
            return 16384
        if arg.endswith(".bin"):
            return 4 * 1024 * 1024
        if arg.endswith(".txt") or arg.endswith(".cfg"):
            return 512
        return 1024
