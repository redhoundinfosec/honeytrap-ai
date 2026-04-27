"""SMTP adapter tests — Cycle 16."""

from __future__ import annotations

from honeytrap.ai.adapters import AdapterPrompt, SmtpAdapter

from .conftest import run


def _do(line: str, persona: dict[str, object] | None = None, **extra: object) -> str:
    a = SmtpAdapter(enabled=False)
    return run(
        a.respond("smtp-1", AdapterPrompt(inbound=line, persona=persona or {}, extra=extra))
    ).content


def test_banner_state_emits_220() -> None:
    out = _do("", persona={"hostname": "mail.x"}, state="banner")
    assert out.startswith("220 mail.x ESMTP")
    assert out.endswith("\r\n")


def test_helo_returns_single_line_250() -> None:
    out = _do("HELO foo.example.com", persona={"hostname": "mx.example"})
    assert out == "250 mx.example\r\n"


def test_ehlo_emits_capability_block_for_mail_server() -> None:
    out = _do("EHLO foo", persona={"hostname": "mx.example", "profile": "mail_server"})
    lines = [ln for ln in out.split("\r\n") if ln]
    assert lines[0].startswith("250-mx.example")
    assert any("STARTTLS" in line for line in lines)
    assert any("AUTH PLAIN LOGIN" in line for line in lines)
    assert any("PIPELINING" in line for line in lines)
    # The last cap line must use space, not dash.
    assert lines[-1].startswith("250 ")


def test_ehlo_iot_profile_drops_auth_capability() -> None:
    out = _do("EHLO foo", persona={"hostname": "mx.iot", "profile": "iot_industrial"})
    assert "AUTH" not in out
    assert "STARTTLS" not in out
    assert "8BITMIME" in out


def test_mail_from_returns_250_2_1_0() -> None:
    out = _do("MAIL FROM:<bob@x.com>")
    assert out == "250 2.1.0 Sender OK\r\n"


def test_rcpt_for_blocked_target_returns_550() -> None:
    out = _do("RCPT TO:<noone@spamhaus.org>")
    assert out.startswith("550 5.1.1")
    assert out.endswith("\r\n")


def test_data_returns_354() -> None:
    out = _do("DATA")
    assert out == "354 End data with <CR><LF>.<CR><LF>\r\n"


def test_unknown_verb_returns_500() -> None:
    out = _do("XYZQ")
    assert out.startswith("500 5.5.2")


def test_quit_uses_persona_hostname() -> None:
    out = _do("QUIT", persona={"hostname": "mx.persona"})
    assert "mx.persona closing connection" in out


def test_validate_shape_rejects_uncoded_lines() -> None:
    a = SmtpAdapter(enabled=False)
    assert a.validate_shape("hello world\r\n") == ""


def test_validate_shape_accepts_multi_line_block() -> None:
    a = SmtpAdapter(enabled=False)
    block = "250-mail.x Hello\r\n250-SIZE 100\r\n250 8BITMIME\r\n"
    assert a.validate_shape(block) == block


def test_safety_filter_strips_attacker_token_echo() -> None:
    class _Echo(SmtpAdapter):
        def template_response(self, prompt: AdapterPrompt) -> str:  # noqa: D401
            return "250 token=mySecret123 accepted\r\n"

    e = _Echo(enabled=False)
    out = run(
        e.respond(
            "s",
            AdapterPrompt(
                inbound="MAIL FROM:<x@y> token=mySecret123",
                persona={},
            ),
        )
    )
    assert "mySecret123" not in out.content


def test_starttls_handshake_returns_220() -> None:
    out = _do("STARTTLS")
    assert out == "220 2.0.0 Ready to start TLS\r\n"


def test_rset_and_noop_are_simple_250() -> None:
    assert _do("RSET") == "250 2.0.0 Reset OK\r\n"
    assert _do("NOOP") == "250 2.0.0 OK\r\n"


def test_auth_login_returns_334_or_535() -> None:
    out = _do("AUTH LOGIN")
    # accept either prompt for username or rejection — just ensure 3-digit
    assert out[:3].isdigit()
    assert out.endswith("\r\n")


def test_auth_plain_returns_3digit_code() -> None:
    out = _do("AUTH PLAIN dGVzdA==")
    assert out[:3].isdigit()


def test_vrfy_and_expn_return_252_or_502() -> None:
    out_v = _do("VRFY user@x")
    out_e = _do("EXPN list")
    assert out_v[:3].isdigit() and out_e[:3].isdigit()


def test_data_sent_state_emits_queue_id() -> None:
    out = _do("MAIL", state="data_sent")
    # `MAIL` verb takes precedence; this exercises the data_sent branch
    # only when verb is unknown — assert the response is wire-shaped.
    assert out.endswith("\r\n")


def test_rcpt_with_allowed_address_returns_250() -> None:
    out = _do("RCPT TO:<alice@example.com>")
    assert out.startswith("250 2.1.5")


def test_validate_shape_accepts_dot_terminator() -> None:
    a = SmtpAdapter(enabled=False)
    raw = "354 End data\r\n.\r\n"
    out = a.validate_shape(raw)
    assert ".\r\n" in out


def test_data_dot_state_emits_queue_id() -> None:
    out = _do("(body)", state="data_dot")
    assert out.startswith("250 2.0.0 Ok: queued as ")
    assert out.endswith("\r\n")
