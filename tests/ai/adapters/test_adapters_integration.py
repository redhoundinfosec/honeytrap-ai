"""Integration tests for the Cycle-16 adapter package.

These exercise the cache, classifier, safety-filter, and per-adapter
template rendering as a single unit so we can prove the pipeline produces
wire-correct output for representative attacker scripts.
"""

from __future__ import annotations

from honeytrap.ai.adapters import (
    AdapterPrompt,
    FtpAdapter,
    HttpAdapter,
    SmtpAdapter,
    SshAdapter,
    TelnetAdapter,
    get_adapter,
    supported_protocols,
)
from honeytrap.ai.cache import ResponseCache

from .conftest import make_extra, run


def test_registry_returns_correct_adapter_per_protocol() -> None:
    assert isinstance(get_adapter("http"), HttpAdapter)
    assert isinstance(get_adapter("HTTPS"), HttpAdapter)
    assert isinstance(get_adapter("smtp"), SmtpAdapter)
    assert isinstance(get_adapter("telnet"), TelnetAdapter)
    assert isinstance(get_adapter("ftp"), FtpAdapter)
    assert isinstance(get_adapter("ssh"), SshAdapter)
    assert {"http", "https", "smtp", "telnet", "ftp", "ssh"}.issubset(set(supported_protocols()))


def test_unknown_protocol_lookup_raises() -> None:
    import pytest

    with pytest.raises(KeyError):
        get_adapter("modbus")


def test_http_attacker_path_walk_yields_404_then_admin_401() -> None:
    a = HttpAdapter(enabled=False)
    extra = make_extra(method="GET", path="/.env")
    extra["headers"] = {}
    extra["body"] = ""
    out1 = run(
        a.respond(
            "atk-1",
            AdapterPrompt(inbound="GET /.env", extra=extra),
        )
    )
    assert "HTTP/1.1 404" in out1.content
    extra2 = make_extra(method="GET", path="/admin")
    extra2["headers"] = {}
    extra2["body"] = ""
    out2 = run(
        a.respond(
            "atk-1",
            AdapterPrompt(inbound="GET /admin", extra=extra2),
        )
    )
    assert "HTTP/1.1 401" in out2.content
    assert out2.intent.value != ""


def test_smtp_relay_probe_sequence_is_wire_clean() -> None:
    a = SmtpAdapter(enabled=False)
    lines = ["EHLO foo", "MAIL FROM:<x@y.com>", "RCPT TO:<root@spamhaus.org>", "QUIT"]
    outs: list[str] = []
    for line in lines:
        r = run(a.respond("smtp-int", AdapterPrompt(inbound=line, persona={})))
        outs.append(r.content)
    assert outs[0].startswith("250-")
    assert outs[1].startswith("250 ")
    assert outs[2].startswith("550 ")
    assert outs[3].startswith("221 ")


def test_telnet_attacker_recon_sequence_walks_state() -> None:
    a = TelnetAdapter(enabled=False)
    extra = {"cwd": "/root"}
    sequence = ["whoami", "uname -a", "cd /etc", "pwd", "cat /etc/passwd"]
    outputs: list[str] = []
    for step in sequence:
        r = run(
            a.respond(
                "tel-int",
                AdapterPrompt(inbound=step, persona={"os_persona": "ubuntu-22.04"}, extra=extra),
            )
        )
        outputs.append(r.content)
        if "new_cwd" in extra:
            extra["cwd"] = extra.pop("new_cwd")
    assert outputs[0].strip() == "root"
    assert "Ubuntu" in outputs[1] or "ubuntu" in outputs[1]
    # cd has no stdout
    assert outputs[2] == ""
    assert outputs[3].strip() == "/etc"
    assert outputs[4].startswith("root:x:0:0")


def test_ftp_anonymous_session_walk_is_correct() -> None:
    a = FtpAdapter(enabled=False)
    persona = {"hostname": "ftp.x.com", "ftp_banner": "vsFTPd 3.0"}
    banner = run(
        a.respond("ftp-int", AdapterPrompt(inbound="", persona=persona, extra={"state": "banner"}))
    )
    assert banner.content.startswith("220 ")
    user = run(a.respond("ftp-int", AdapterPrompt(inbound="USER anonymous", persona=persona)))
    assert user.content.startswith("331 ")
    pwd = run(
        a.respond("ftp-int", AdapterPrompt(inbound="PWD", persona=persona, extra={"cwd": "/pub"}))
    )
    assert '"/pub"' in pwd.content
    quit_r = run(a.respond("ftp-int", AdapterPrompt(inbound="QUIT", persona=persona)))
    assert "221 ftp.x.com" in quit_r.content


def test_cache_round_trip_serves_cached_hit() -> None:
    cache = ResponseCache(capacity=16)
    # ``enabled=True`` is required for the adapter to populate the cache.
    # The default chain is template-only, so this stays offline-safe.
    a = HttpAdapter(enabled=True, cache=cache)
    extra = make_extra(method="GET", path="/")
    extra["headers"] = {}
    extra["body"] = ""
    p = AdapterPrompt(inbound="GET /", extra=extra)
    first = run(a.respond("c-1", p))
    second = run(a.respond("c-1", p))
    assert first.content == second.content
    assert second.cached is True


def test_ssh_adapter_delegates_to_telnet_renderer() -> None:
    a = SshAdapter(enabled=False)
    out = run(a.respond("ssh-int", AdapterPrompt(inbound="whoami", persona={"user": "alice"})))
    assert out.content.strip() == "alice"


def test_ssh_adapter_validate_shape_strips_nul() -> None:
    a = SshAdapter(enabled=False)
    assert a.validate_shape("hello\x00world") == "helloworld"


def test_ssh_adapter_cache_key_combines_cmd_persona_cwd() -> None:
    a = SshAdapter(enabled=False)
    p1 = AdapterPrompt(
        inbound="ls -la", persona={"os_persona": "ubuntu-22.04"}, extra={"cwd": "/root"}
    )
    p2 = AdapterPrompt(
        inbound="ls -la", persona={"os_persona": "busybox"}, extra={"cwd": "/root"}
    )
    assert a.cache_key(p1) != a.cache_key(p2)


def test_safety_filter_pem_block_is_redacted_across_protocols() -> None:
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQ\n-----END RSA PRIVATE KEY-----"

    class _Leak(TelnetAdapter):
        def template_response(self, prompt: AdapterPrompt) -> str:  # noqa: D401
            return f"Here you go: {pem}\n"

    a = _Leak(enabled=False)
    out = run(a.respond("leak", AdapterPrompt(inbound="cat id_rsa")))
    assert "BEGIN RSA PRIVATE KEY" not in out.content
    assert "[redacted]" in out.content
