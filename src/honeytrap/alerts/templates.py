"""Pure renderers that turn :class:`Alert` objects into channel payloads.

Each renderer is a free function returning a JSON-serializable dict (or
plain text for the email bodies). Keeping them pure makes them trivial
to test and trivial to re-use from outside the channel classes.
"""

from __future__ import annotations

from typing import Any

from honeytrap.alerts.models import Alert, AlertSeverity

# Truncation limits — alerts are best-effort "tell me something happened"
# messages, not archive storage, so keep payloads compact.
_TITLE_MAX = 150
_SUMMARY_MAX = 800
_FIELD_MAX = 300


_SEVERITY_COLORS_HEX = {
    AlertSeverity.INFO: "#2EB5FF",
    AlertSeverity.LOW: "#8AC349",
    AlertSeverity.MEDIUM: "#F5A623",
    AlertSeverity.HIGH: "#F5452B",
    AlertSeverity.CRITICAL: "#B80B0B",
}

# Discord needs an integer color (decimal RGB).
_SEVERITY_COLORS_INT = {
    AlertSeverity.INFO: 0x2EB5FF,
    AlertSeverity.LOW: 0x8AC349,
    AlertSeverity.MEDIUM: 0xF5A623,
    AlertSeverity.HIGH: 0xF5452B,
    AlertSeverity.CRITICAL: 0xB80B0B,
}


def _trim(value: str, limit: int) -> str:
    if value is None:
        return ""
    s = str(value)
    if len(s) <= limit:
        return s
    return s[: max(0, limit - 1)] + "\u2026"


def _techniques_text(alert: Alert) -> str:
    if not alert.attck_techniques:
        return "none"
    return ", ".join(alert.attck_techniques[:10])


def _iocs_text(alert: Alert) -> str:
    if not alert.iocs:
        return "none"
    parts: list[str] = []
    for itype, values in alert.iocs.items():
        sample = ", ".join(values[:3])
        parts.append(f"{itype}: {sample}")
    return "; ".join(parts)


# ---------------------------------------------------------------------------
# Slack
# ---------------------------------------------------------------------------


def render_slack(alert: Alert) -> dict[str, Any]:
    """Render an alert as Slack blocks + attachment colored by severity."""
    color = _SEVERITY_COLORS_HEX.get(alert.severity, "#999999")
    title = _trim(alert.title, _TITLE_MAX)
    summary = _trim(alert.summary, _SUMMARY_MAX)
    fields = [
        {"type": "mrkdwn", "text": f"*Severity*\n{alert.severity.name}"},
        {"type": "mrkdwn", "text": f"*Source IP*\n{alert.source_ip or 'n/a'}"},
        {"type": "mrkdwn", "text": f"*Protocol*\n{alert.protocol or 'n/a'}"},
        {"type": "mrkdwn", "text": f"*Session*\n{alert.session_id or 'n/a'}"},
        {"type": "mrkdwn", "text": f"*Techniques*\n{_trim(_techniques_text(alert), _FIELD_MAX)}"},
        {"type": "mrkdwn", "text": f"*IOCs*\n{_trim(_iocs_text(alert), _FIELD_MAX)}"},
    ]
    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"[{alert.severity.name}] {title}"},
        },
        {"type": "section", "text": {"type": "mrkdwn", "text": summary}},
        {"type": "section", "fields": fields},
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"HoneyTrap AI alert `{alert.id}` at {alert.timestamp.isoformat()}",
                },
            ],
        },
    ]
    return {
        "text": f"[{alert.severity.name}] {title}",
        "attachments": [{"color": color, "blocks": blocks}],
    }


# ---------------------------------------------------------------------------
# Discord
# ---------------------------------------------------------------------------


def render_discord(alert: Alert) -> dict[str, Any]:
    """Render an alert as a Discord webhook embed."""
    color = _SEVERITY_COLORS_INT.get(alert.severity, 0x808080)
    embed = {
        "title": _trim(f"[{alert.severity.name}] {alert.title}", _TITLE_MAX),
        "description": _trim(alert.summary, _SUMMARY_MAX),
        "color": color,
        "timestamp": alert.timestamp.isoformat(),
        "fields": [
            {"name": "Source IP", "value": alert.source_ip or "n/a", "inline": True},
            {"name": "Protocol", "value": alert.protocol or "n/a", "inline": True},
            {"name": "Session", "value": alert.session_id or "n/a", "inline": True},
            {
                "name": "ATT&CK",
                "value": _trim(_techniques_text(alert), _FIELD_MAX),
                "inline": False,
            },
            {"name": "IOCs", "value": _trim(_iocs_text(alert), _FIELD_MAX), "inline": False},
        ],
        "footer": {"text": f"HoneyTrap AI alert {alert.id}"},
    }
    return {"username": "HoneyTrap AI", "embeds": [embed]}


# ---------------------------------------------------------------------------
# Microsoft Teams
# ---------------------------------------------------------------------------


def render_teams(alert: Alert) -> dict[str, Any]:
    """Render an alert as a Microsoft Teams MessageCard JSON payload."""
    color = _SEVERITY_COLORS_HEX.get(alert.severity, "999999").lstrip("#")
    facts = [
        {"name": "Severity", "value": alert.severity.name},
        {"name": "Source IP", "value": alert.source_ip or "n/a"},
        {"name": "Protocol", "value": alert.protocol or "n/a"},
        {"name": "Session", "value": alert.session_id or "n/a"},
        {"name": "Techniques", "value": _trim(_techniques_text(alert), _FIELD_MAX)},
        {"name": "IOCs", "value": _trim(_iocs_text(alert), _FIELD_MAX)},
    ]
    return {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": color,
        "summary": _trim(alert.title, _TITLE_MAX),
        "title": _trim(f"[{alert.severity.name}] {alert.title}", _TITLE_MAX),
        "text": _trim(alert.summary, _SUMMARY_MAX),
        "sections": [
            {"facts": facts, "markdown": True},
        ],
    }


# ---------------------------------------------------------------------------
# Generic webhook
# ---------------------------------------------------------------------------


def render_generic(alert: Alert) -> dict[str, Any]:
    """Render an alert as the canonical HoneyTrap webhook JSON payload."""
    payload = alert.to_dict()
    payload["title"] = _trim(payload["title"], _TITLE_MAX)
    payload["summary"] = _trim(payload["summary"], _SUMMARY_MAX)
    return payload


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------


def render_email(alert: Alert) -> tuple[str, str, str]:
    """Return ``(subject, text_body, html_body)`` for the email channel."""
    subject = _trim(f"[HoneyTrap {alert.severity.name}] {alert.title}", _TITLE_MAX)

    text_lines = [
        f"Severity: {alert.severity.name}",
        f"Title: {_trim(alert.title, _TITLE_MAX)}",
        f"Time: {alert.timestamp.isoformat()}",
        f"Source IP: {alert.source_ip or 'n/a'}",
        f"Protocol: {alert.protocol or 'n/a'}",
        f"Session: {alert.session_id or 'n/a'}",
        "",
        _trim(alert.summary, _SUMMARY_MAX),
        "",
        f"Techniques: {_trim(_techniques_text(alert), _FIELD_MAX)}",
        f"IOCs: {_trim(_iocs_text(alert), _FIELD_MAX)}",
        "",
        f"Alert ID: {alert.id}",
    ]
    text_body = "\n".join(text_lines)

    color = _SEVERITY_COLORS_HEX.get(alert.severity, "#666")
    html_body = (
        '<html><body style="font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif">'
        f'<div style="border-left:6px solid {color};padding:12px 18px">'
        f'<h2 style="margin:0;color:{color}">[{alert.severity.name}] '
        f"{_html_escape(_trim(alert.title, _TITLE_MAX))}</h2>"
        f'<p style="margin:4px 0 12px 0;color:#444">{_html_escape(alert.timestamp.isoformat())}</p>'
        f"<p>{_html_escape(_trim(alert.summary, _SUMMARY_MAX))}</p>"
        '<table style="border-collapse:collapse;font-size:13px">'
        f"<tr><td><b>Source IP</b></td><td>{_html_escape(alert.source_ip or 'n/a')}</td></tr>"
        f"<tr><td><b>Protocol</b></td><td>{_html_escape(alert.protocol or 'n/a')}</td></tr>"
        f"<tr><td><b>Session</b></td><td>{_html_escape(alert.session_id or 'n/a')}</td></tr>"
        f"<tr><td><b>Techniques</b></td><td>{_html_escape(_trim(_techniques_text(alert), _FIELD_MAX))}</td></tr>"
        f"<tr><td><b>IOCs</b></td><td>{_html_escape(_trim(_iocs_text(alert), _FIELD_MAX))}</td></tr>"
        f"<tr><td><b>Alert ID</b></td><td><code>{_html_escape(alert.id)}</code></td></tr>"
        "</table></div></body></html>"
    )
    return subject, text_body, html_body


def _html_escape(value: str) -> str:
    import html

    return html.escape(value or "", quote=True)
