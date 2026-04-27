"""FTP adapter tests — Cycle 16."""

from __future__ import annotations

from honeytrap.ai.adapters import AdapterPrompt, FtpAdapter

from .conftest import run


def _do(
    line: str,
    persona: dict[str, object] | None = None,
    extra: dict[str, object] | None = None,
) -> str:
    a = FtpAdapter(enabled=False)
    out = run(
        a.respond(
            "ftp-1",
            AdapterPrompt(inbound=line, persona=persona or {}, extra=dict(extra or {})),
        )
    )
    return out.content


def test_banner_state_emits_220_with_persona_banner() -> None:
    out = _do("", persona={"ftp_banner": "ProFTPD 1.3.5"}, extra={"state": "banner"})
    assert out.startswith("220 ProFTPD 1.3.5")
    assert out.endswith("\r\n")


def test_user_anonymous_yields_331() -> None:
    out = _do("USER anonymous")
    assert out.startswith("331 ")


def test_user_named_yields_331_with_account() -> None:
    out = _do("USER alice")
    assert out.startswith("331 ")
    assert "alice" in out


def test_pass_yields_230_login_successful() -> None:
    out = _do("PASS hunter2")
    assert out == "230 Login successful.\r\n"


def test_syst_for_linux_returns_unix() -> None:
    out = _do("SYST", persona={"os_persona": "linux"})
    assert "UNIX" in out


def test_syst_for_windows_returns_windows_nt() -> None:
    out = _do("SYST", persona={"os_persona": "windows"})
    assert "Windows_NT" in out


def test_feat_emits_multi_line_block() -> None:
    out = _do("FEAT")
    assert out.startswith("211-Features")
    assert "EPSV" in out
    assert out.endswith("211 End\r\n")


def test_pwd_uses_extra_cwd() -> None:
    out = _do("PWD", extra={"cwd": "/var/ftp/pub"})
    assert '"/var/ftp/pub"' in out
    assert out.startswith("257 ")


def test_cwd_returns_250() -> None:
    out = _do("CWD /pub")
    assert out.startswith("250 ")


def test_pasv_returns_227() -> None:
    out = _do("PASV")
    assert out.startswith("227 Entering Passive Mode")


def test_epsv_returns_229() -> None:
    out = _do("EPSV")
    assert out.startswith("229 Entering Extended Passive Mode")


def test_list_returns_150_then_226() -> None:
    out = _do("LIST")
    assert out.startswith("150 ")
    assert "226 Directory send OK" in out


def test_retr_returns_150_then_226_with_size() -> None:
    out = _do("RETR firmware.bin")
    assert out.startswith("150 Opening BINARY mode")
    assert "Transfer complete" in out


def test_stor_returns_150_then_226() -> None:
    out = _do("STOR upload.txt")
    assert out.startswith("150 Ok to send data.")
    assert "received 512 bytes" in out


def test_size_for_known_extension() -> None:
    out = _do("SIZE firmware.bin")
    assert out == "213 4194304\r\n"


def test_mdtm_returns_213_with_timestamp() -> None:
    out = _do("MDTM file.txt")
    assert out.startswith("213 ")
    assert "2026" in out


def test_dele_returns_550_permission_denied() -> None:
    out = _do("DELE secret.txt")
    assert out.startswith("550 ")


def test_mkd_returns_257_quoted_dirname() -> None:
    out = _do("MKD newdir")
    assert '"newdir"' in out
    assert out.startswith("257 ")


def test_quit_uses_persona_hostname() -> None:
    out = _do("QUIT", persona={"hostname": "ftp.test.local"})
    assert "ftp.test.local closing" in out
    assert out.startswith("221 ")


def test_unknown_verb_returns_500() -> None:
    out = _do("WHAT")
    assert out.startswith("500 ")


def test_validate_shape_rejects_freeform_lines() -> None:
    a = FtpAdapter(enabled=False)
    assert a.validate_shape("hello world\r\n") == ""


def test_validate_shape_accepts_multi_line_block() -> None:
    a = FtpAdapter(enabled=False)
    block = "211-Features:\r\n EPSV\r\n PASV\r\n211 End\r\n"
    assert a.validate_shape(block) == block
    block_ok = "220 OK\r\n200 OK\r\n"
    assert a.validate_shape(block_ok) == block_ok
    assert a.validate_shape("hello world\r\n") == ""


def test_cache_key_combines_verb_profile_state() -> None:
    a = FtpAdapter(enabled=False)
    p1 = AdapterPrompt(inbound="LIST", persona={"profile": "linux"}, extra={})
    p2 = AdapterPrompt(inbound="LIST", persona={"profile": "windows"}, extra={})
    p3 = AdapterPrompt(inbound="PWD", persona={"profile": "linux"}, extra={})
    assert a.cache_key(p1) != a.cache_key(p2)
    assert a.cache_key(p1) != a.cache_key(p3)


def test_empty_inbound_returns_500_syntax_error() -> None:
    out = _do("")
    assert out.startswith("500 ")


def test_cdup_returns_250() -> None:
    out = _do("CDUP")
    assert out.startswith("250 ")


def test_type_returns_200_with_mode() -> None:
    out = _do("TYPE A")
    assert "Switching to A" in out


def test_port_and_eprt_return_200() -> None:
    assert _do("PORT 1,2,3,4,5,6").startswith("200 ")
    assert _do("EPRT |1|10.0.0.1|22|").startswith("200 ")


def test_nlst_returns_simple_names() -> None:
    out = _do("NLST", persona={"os_persona": "linux"})
    assert "150 " in out
    assert "226 " in out


def test_list_for_windows_profile() -> None:
    out = _do("LIST", persona={"os_persona": "windows"})
    assert "150 " in out


def test_list_for_iot_profile() -> None:
    out = _do("LIST", persona={"os_persona": "iot"})
    assert "150 " in out


def test_rmd_returns_550_permission_denied() -> None:
    out = _do("RMD subdir")
    assert out.startswith("550 ")


def test_rnfr_then_rnto_succeeds() -> None:
    assert _do("RNFR a.txt").startswith("350 ")
    assert _do("RNTO b.txt").startswith("250 ")


def test_noop_returns_200_ok() -> None:
    assert _do("NOOP") == "200 OK\r\n"


def test_help_returns_214() -> None:
    out = _do("HELP")
    assert out.startswith("214 ")


def test_size_returns_correct_for_tgz_and_default() -> None:
    assert _do("SIZE backup.tgz").startswith("213 16384")
    assert _do("SIZE unknown").startswith("213 1024")


def test_safety_filter_strips_attacker_password_echo() -> None:
    class _Echo(FtpAdapter):
        def template_response(self, prompt: AdapterPrompt) -> str:  # noqa: D401
            return "230 logged in with password=topsekret123\r\n"

    e = _Echo(enabled=False)
    out = run(
        e.respond(
            "ftp",
            AdapterPrompt(inbound="PASS password=topsekret123", persona={}),
        )
    )
    assert "topsekret123" not in out.content
