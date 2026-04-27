"""Telnet adapter tests — Cycle 16."""

from __future__ import annotations

from honeytrap.ai.adapters import AdapterPrompt, TelnetAdapter, latency_cap_ms

from .conftest import run


def _do(
    line: str,
    persona: dict[str, object] | None = None,
    extra: dict[str, object] | None = None,
) -> tuple[str, dict[str, object]]:
    a = TelnetAdapter(enabled=False)
    ex = dict(extra or {})
    out = run(a.respond("tel-1", AdapterPrompt(inbound=line, persona=persona or {}, extra=ex)))
    return out.content, ex


def test_login_banner_ubuntu_includes_lts_string() -> None:
    out, _ = _do(
        "",
        persona={"hostname": "edge-01", "os_persona": "ubuntu-22.04"},
        extra={"state": "login_banner"},
    )
    assert "Ubuntu 22.04" in out
    assert "edge-01 login: " in out


def test_login_banner_busybox_is_minimal() -> None:
    out, _ = _do(
        "",
        persona={"hostname": "iotcam", "os_persona": "busybox"},
        extra={"state": "login_banner"},
    )
    assert out.endswith("iotcam login: ")
    assert "Ubuntu" not in out


def test_login_banner_cisco_uses_username_prompt() -> None:
    out, _ = _do(
        "",
        persona={"hostname": "sw1", "os_persona": "cisco-ios"},
        extra={"state": "login_banner"},
    )
    assert "User Access Verification" in out
    assert out.endswith("Username: ")


def test_motd_ubuntu_shows_system_info() -> None:
    out, _ = _do(
        "",
        persona={"hostname": "edge-01", "os_persona": "ubuntu-22.04"},
        extra={"state": "motd"},
    )
    assert "Welcome to Ubuntu" in out
    assert "root@edge-01" in out


def test_motd_busybox_shows_builtin_help() -> None:
    out, _ = _do(
        "",
        persona={"os_persona": "busybox"},
        extra={"state": "motd"},
    )
    assert "BusyBox" in out


def test_pwd_returns_provided_cwd() -> None:
    out, _ = _do("pwd", extra={"cwd": "/var/log"})
    assert out == "/var/log\n"


def test_whoami_uses_persona_user() -> None:
    out, _ = _do("whoami", persona={"user": "admin"})
    assert out == "admin\n"


def test_uname_branches_on_os_persona() -> None:
    o1, _ = _do("uname -a", persona={"os_persona": "ubuntu-22.04"})
    o2, _ = _do("uname -a", persona={"os_persona": "busybox"})
    o3, _ = _do("uname -a", persona={"os_persona": "cisco-ios"})
    assert "Ubuntu" in o1 or "ubuntu" in o1
    assert "mips" in o2
    assert "Cisco IOS" in o3


def test_ls_in_root_lists_unix_dirs() -> None:
    out, _ = _do("ls", extra={"cwd": "/"})
    assert "etc" in out and "usr" in out


def test_ls_in_root_home_lists_dotfiles() -> None:
    out, _ = _do("ls -la", extra={"cwd": "/root"})
    assert ".bashrc" in out


def test_cat_etc_passwd_returns_unix_users() -> None:
    out, _ = _do("cat /etc/passwd")
    assert out.startswith("root:x:0:0:root:/root:/bin/bash")
    assert "ubuntu" in out


def test_cat_etc_shadow_is_permission_denied() -> None:
    out, _ = _do("cat /etc/shadow")
    assert "Permission denied" in out


def test_cat_unknown_file_emits_no_such_file() -> None:
    out, _ = _do("cat /tmp/nope")
    assert "No such file" in out


def test_ps_lists_init_and_sshd() -> None:
    out, _ = _do("ps auxf")
    assert "/sbin/init" in out
    assert "sshd" in out


def test_netstat_shows_listen_sockets() -> None:
    out, _ = _do("netstat -tnlp")
    assert "LISTEN" in out
    assert "0.0.0.0:22" in out


def test_ifconfig_shows_eth0() -> None:
    out, _ = _do("ifconfig")
    assert "eth0" in out
    assert "inet 10.0.0.5" in out


def test_history_renders_indexed_commands() -> None:
    out, _ = _do("history", extra={"history": ["ls", "id", "pwd"]})
    assert "   1  ls" in out
    assert "   3  pwd" in out


def test_env_lists_path_and_home() -> None:
    out, _ = _do("env")
    assert "PATH=" in out
    assert "HOME=/root" in out


def test_sudo_emits_password_prompt() -> None:
    out, _ = _do("sudo apt update")
    assert "[sudo] password" in out


def test_unknown_verb_emits_command_not_found() -> None:
    out, _ = _do("xyzzy")
    assert "command not found" in out


def test_cd_relative_updates_new_cwd() -> None:
    _, extra = _do("cd subdir", extra={"cwd": "/var/log"})
    assert extra["new_cwd"] == "/var/log/subdir"


def test_cd_absolute_replaces_cwd() -> None:
    _, extra = _do("cd /etc", extra={"cwd": "/root"})
    assert extra["new_cwd"] == "/etc"


def test_cd_dotdot_pops_one_segment() -> None:
    _, extra = _do("cd ..", extra={"cwd": "/var/log"})
    assert extra["new_cwd"] == "/var"


def test_cd_tilde_returns_to_root_home() -> None:
    _, extra = _do("cd ~", extra={"cwd": "/etc"})
    assert extra["new_cwd"] == "/root"


def test_exit_returns_empty_string() -> None:
    out, _ = _do("exit")
    assert out == ""


def test_validate_shape_normalizes_crlf_and_strips_nul() -> None:
    a = TelnetAdapter(enabled=False)
    raw = "hello\r\nworld\x00\r\n"
    fixed = a.validate_shape(raw)
    assert fixed == "hello\nworld\n"


def test_cache_key_changes_with_command_and_cwd() -> None:
    a = TelnetAdapter(enabled=False)
    p1 = AdapterPrompt(inbound="ls", persona={}, extra={"cwd": "/"})
    p2 = AdapterPrompt(inbound="ls", persona={}, extra={"cwd": "/etc"})
    p3 = AdapterPrompt(inbound="pwd", persona={}, extra={"cwd": "/"})
    assert a.cache_key(p1) != a.cache_key(p2)
    assert a.cache_key(p1) != a.cache_key(p3)


def test_safety_filter_strips_attacker_token_echo() -> None:
    class _Echo(TelnetAdapter):
        def template_response(self, prompt: AdapterPrompt) -> str:  # noqa: D401
            return "echo got: hunter2supersecret\n"

    e = _Echo(enabled=False)
    out = run(
        e.respond(
            "t",
            AdapterPrompt(
                inbound="curl http://x token=hunter2supersecret",
                persona={},
            ),
        )
    )
    assert "hunter2supersecret" not in out.content
    assert "[redacted]" in out.content


def test_empty_command_returns_empty_string() -> None:
    out, _ = _do("")
    assert out == ""


def test_motd_cisco_shows_help_prompt() -> None:
    out, _ = _do("", persona={"os_persona": "cisco-ios"}, extra={"state": "motd"})
    assert "Switch>" in out


def test_id_returns_uid_root() -> None:
    out, _ = _do("id")
    assert "uid=0(root)" in out


def test_cat_etc_hostname_uses_persona() -> None:
    out, _ = _do("cat /etc/hostname", persona={"hostname": "h-1"})
    assert "h-1" in out


def test_cat_notes_returns_reminder_string() -> None:
    out, _ = _do("cat /root/notes.txt")
    assert "Reminder" in out


def test_ls_in_etc_returns_empty_marker() -> None:
    out, _ = _do("ls", extra={"cwd": "/etc"})
    assert "(empty)" in out


def test_ls_busybox_lists_minimal_dirs() -> None:
    out, _ = _do("ls", persona={"os_persona": "busybox"})
    assert "bin" in out
    assert "sbin" in out


def test_latency_cap_clamps_to_bounds() -> None:
    assert latency_cap_ms({"latency_ms": 1000}) == 250.0
    assert latency_cap_ms({"latency_ms": 0.5}) == 5.0
    assert latency_cap_ms({"latency_ms": 50}) == 50.0
