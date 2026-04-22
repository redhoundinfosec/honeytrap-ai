"""Heuristic attacker-intent classifier.

The classifier consumes a :class:`SessionMemory` and produces an
:class:`IntentLabel` with a confidence score and a short rationale.
It is purely deterministic — no LLM is required — so it can always run
on the hot path and feed the adaptive-response layer.

Signals are evaluated independently and scored; the top-scoring label
wins. Ties are broken in favor of higher-severity labels because a
false positive on EXPLOIT_ATTEMPT is less dangerous than missing one.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - circular import only in type checking
    from honeytrap.ai.memory import SessionMemory


class IntentLabel(str, Enum):
    """Canonical attacker-intent labels."""

    RECON = "RECON"
    BRUTE_FORCE = "BRUTE_FORCE"
    EXPLOIT_ATTEMPT = "EXPLOIT_ATTEMPT"
    CREDENTIAL_HARVEST = "CREDENTIAL_HARVEST"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    EXFILTRATION = "EXFILTRATION"
    PERSISTENCE = "PERSISTENCE"
    COIN_MINING = "COIN_MINING"
    WEB_SHELL = "WEB_SHELL"
    UNKNOWN = "UNKNOWN"


HIGH_SEVERITY_LABELS: frozenset[IntentLabel] = frozenset(
    {
        IntentLabel.EXPLOIT_ATTEMPT,
        IntentLabel.EXFILTRATION,
        IntentLabel.COIN_MINING,
        IntentLabel.WEB_SHELL,
        IntentLabel.PERSISTENCE,
    }
)


_RECON_TOKENS = (
    "whoami",
    "id",
    "uname",
    "cat /etc/passwd",
    "cat /etc/shadow",
    "netstat",
    "ss -ant",
    "ifconfig",
    "ipconfig",
    "ip a",
    "ip addr",
    "arp -a",
    "ls -la",
    "pwd",
    "hostname",
    "lscpu",
    "lsb_release",
    "systemctl",
    "ps aux",
    "env",
    "printenv",
    "nmap",
)

_EXPLOIT_PATTERNS = (
    re.compile(r"\$\{jndi:", re.IGNORECASE),
    re.compile(r"log4j", re.IGNORECASE),
    re.compile(r"\.\./\.\./"),
    re.compile(r"union\s+select", re.IGNORECASE),
    re.compile(r"or\s+1\s*=\s*1", re.IGNORECASE),
    re.compile(r"(?:;|\|)\s*(?:rm|wget|curl|bash|sh|nc)\s+", re.IGNORECASE),
    re.compile(r"<script[^>]*>", re.IGNORECASE),
    re.compile(r"onerror\s*=", re.IGNORECASE),
    re.compile(r"127\.0\.0\.1:\d+", re.IGNORECASE),
    re.compile(r"gopher://", re.IGNORECASE),
    re.compile(r"file:///etc/", re.IGNORECASE),
)

_CREDENTIAL_TOKENS = (
    "cat ~/.ssh/",
    "cat /root/.ssh/",
    "cat .bash_history",
    "cat ~/.aws/",
    ".aws/credentials",
    ".git-credentials",
    "/proc/self/environ",
)

_EXFIL_TOKENS = (
    "169.254.169.254",
    "metadata.google.internal",
    "scp ",
    "rsync ",
    "ftp -n",
    "base64 -w0",
    "tar czf - ",
)

_MINER_PATTERNS = (
    re.compile(r"xmrig", re.IGNORECASE),
    re.compile(r"stratum\+tcp", re.IGNORECASE),
    re.compile(r"monero", re.IGNORECASE),
    re.compile(r"cpuminer", re.IGNORECASE),
    re.compile(r"minerd\b", re.IGNORECASE),
    re.compile(r"--donate-level", re.IGNORECASE),
)

_PERSISTENCE_PATTERNS = (
    re.compile(r"wget[^|]+\|\s*(?:sh|bash)", re.IGNORECASE),
    re.compile(r"curl[^|]+\|\s*(?:sh|bash)", re.IGNORECASE),
    re.compile(r"chmod\s+\+x", re.IGNORECASE),
    re.compile(r"echo\s+[^|]+\|\s*base64\s+-d", re.IGNORECASE),
    re.compile(r"crontab\s+-e", re.IGNORECASE),
    re.compile(r"/etc/rc\.local", re.IGNORECASE),
    re.compile(r"systemctl\s+enable", re.IGNORECASE),
    re.compile(r"\bservice\s+[\w-]+\s+start\b", re.IGNORECASE),
)

_LATERAL_PATTERNS = (
    re.compile(r"\bpsexec\b", re.IGNORECASE),
    re.compile(r"\bwmic\b", re.IGNORECASE),
    re.compile(r"\bsc\s+create\b", re.IGNORECASE),
    re.compile(r"\bsmbclient\b", re.IGNORECASE),
    re.compile(r"\benum4linux\b", re.IGNORECASE),
    re.compile(r"\bwinrm\b", re.IGNORECASE),
    re.compile(r"\bnet\s+use\b", re.IGNORECASE),
)

_WEBSHELL_PATTERNS = (
    re.compile(r"<\?php[^?]*(?:eval|system|passthru|assert)", re.IGNORECASE),
    re.compile(r"base64_decode\s*\(", re.IGNORECASE),
    re.compile(r"\bassert\s*\(\s*\$_", re.IGNORECASE),
    re.compile(r"\bpreg_replace\s*\(\s*['\"].*?e['\"]", re.IGNORECASE),
    re.compile(r"c99shell|r57shell|b374k", re.IGNORECASE),
)


def _count_matches(patterns: tuple[re.Pattern[str], ...], haystack: str) -> int:
    """Return the number of distinct patterns that fire on ``haystack``."""
    return sum(1 for p in patterns if p.search(haystack))


def _count_tokens(tokens: tuple[str, ...], haystack: str) -> int:
    """Return the number of distinct tokens that appear in ``haystack``.

    Short tokens (no special chars) are matched on word boundaries so
    common substrings like ``pwd`` do not fire inside ``passwd``.
    """
    lower = haystack.lower()
    hits = 0
    for raw in tokens:
        needle = raw.lower()
        if needle.replace(" ", "").isalnum():
            if re.search(rf"(?:^|\W){re.escape(needle)}(?:\W|$)", lower):
                hits += 1
        elif needle in lower:
            hits += 1
    return hits


def classify(
    memory: SessionMemory,
) -> tuple[IntentLabel, float, list[str]]:
    """Score all labels against the memory and return the winner.

    Returns a ``(label, confidence, rationale)`` triple.

    ``confidence`` is on [0.0, 1.0]. The rationale holds the top three
    signals that drove the decision so the label is always explainable.
    """
    commands_blob = "\n".join(memory.command_history).strip()
    uploads_blob = "\n".join(memory.uploaded_files)
    combined = "\n".join([commands_blob, uploads_blob]).strip()

    scores: dict[IntentLabel, float] = {label: 0.0 for label in IntentLabel}
    rationale_map: dict[IntentLabel, list[str]] = {label: [] for label in IntentLabel}

    # Brute force: many failed auths on a single protocol.
    failed_auth = sum(1 for a in memory.auth_attempts if not a.success)
    if failed_auth >= 5:
        scores[IntentLabel.BRUTE_FORCE] += min(2.5, 0.3 * failed_auth)
        rationale_map[IntentLabel.BRUTE_FORCE].append(
            f"{failed_auth} failed auth attempts"
        )
    elif failed_auth >= 2:
        scores[IntentLabel.BRUTE_FORCE] += 0.6
        rationale_map[IntentLabel.BRUTE_FORCE].append(
            f"{failed_auth} failed auth attempts"
        )

    # Recon enumeration commands.
    recon_hits = _count_tokens(_RECON_TOKENS, combined)
    if recon_hits:
        scores[IntentLabel.RECON] += min(2.0, 0.4 * recon_hits)
        rationale_map[IntentLabel.RECON].append(
            f"{recon_hits} reconnaissance command tokens"
        )

    # Exploit attempts (HTTP payloads, shell injections, traversal).
    exploit_hits = _count_matches(_EXPLOIT_PATTERNS, combined)
    if exploit_hits:
        scores[IntentLabel.EXPLOIT_ATTEMPT] += min(3.0, 0.9 * exploit_hits)
        rationale_map[IntentLabel.EXPLOIT_ATTEMPT].append(
            f"{exploit_hits} exploit/injection patterns"
        )

    # Credential harvest.
    cred_hits = _count_tokens(_CREDENTIAL_TOKENS, combined)
    if cred_hits:
        scores[IntentLabel.CREDENTIAL_HARVEST] += min(2.5, 0.8 * cred_hits)
        rationale_map[IntentLabel.CREDENTIAL_HARVEST].append(
            f"{cred_hits} credential-access tokens"
        )

    # Exfiltration indicators.
    exfil_hits = _count_tokens(_EXFIL_TOKENS, combined)
    if exfil_hits:
        scores[IntentLabel.EXFILTRATION] += min(2.0, 0.6 * exfil_hits)
        rationale_map[IntentLabel.EXFILTRATION].append(
            f"{exfil_hits} exfiltration tokens"
        )

    # Coin mining.
    miner_hits = _count_matches(_MINER_PATTERNS, combined)
    if miner_hits:
        scores[IntentLabel.COIN_MINING] += min(3.0, 1.0 * miner_hits)
        rationale_map[IntentLabel.COIN_MINING].append(
            f"{miner_hits} coin-miner signatures"
        )

    # Persistence chains.
    persist_hits = _count_matches(_PERSISTENCE_PATTERNS, combined)
    if persist_hits:
        scores[IntentLabel.PERSISTENCE] += min(3.0, 0.9 * persist_hits)
        rationale_map[IntentLabel.PERSISTENCE].append(
            f"{persist_hits} persistence patterns"
        )

    # Lateral movement.
    lateral_hits = _count_matches(_LATERAL_PATTERNS, combined)
    if lateral_hits:
        scores[IntentLabel.LATERAL_MOVEMENT] += min(2.5, 0.8 * lateral_hits)
        rationale_map[IntentLabel.LATERAL_MOVEMENT].append(
            f"{lateral_hits} lateral-movement tokens"
        )

    # Web-shell artefacts.
    shell_hits = _count_matches(_WEBSHELL_PATTERNS, combined)
    if shell_hits:
        scores[IntentLabel.WEB_SHELL] += min(3.0, 1.2 * shell_hits)
        rationale_map[IntentLabel.WEB_SHELL].append(
            f"{shell_hits} web-shell artefacts"
        )

    # ATT&CK technique bias.
    techniques = memory.attck_techniques
    if "T1078" in techniques and "T1059" in techniques:
        scores[IntentLabel.CREDENTIAL_HARVEST] += 0.5
        rationale_map[IntentLabel.CREDENTIAL_HARVEST].append(
            "ATT&CK T1078 + T1059 co-occurrence"
        )
    if "T1190" in techniques:
        scores[IntentLabel.EXPLOIT_ATTEMPT] += 0.6
        rationale_map[IntentLabel.EXPLOIT_ATTEMPT].append(
            "ATT&CK T1190 observed"
        )
    if "T1110" in techniques:
        scores[IntentLabel.BRUTE_FORCE] += 0.4
        rationale_map[IntentLabel.BRUTE_FORCE].append("ATT&CK T1110 observed")
    if "T1496" in techniques:
        scores[IntentLabel.COIN_MINING] += 0.6
        rationale_map[IntentLabel.COIN_MINING].append("ATT&CK T1496 observed")

    # Pick the winner.
    best_label = IntentLabel.UNKNOWN
    best_score = 0.0
    for label, score in scores.items():
        if label == IntentLabel.UNKNOWN:
            continue
        if score > best_score or (
            score == best_score
            and score > 0
            and label in HIGH_SEVERITY_LABELS
            and best_label not in HIGH_SEVERITY_LABELS
        ):
            best_score = score
            best_label = label

    if best_score <= 0.0:
        return IntentLabel.UNKNOWN, 0.1, ["no classifiable signals yet"]

    confidence = min(0.99, 0.3 + best_score / 6.0)
    rationale = rationale_map[best_label][:3]
    return best_label, round(confidence, 3), rationale
