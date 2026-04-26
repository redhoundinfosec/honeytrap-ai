"""Map HoneyTrap internal types into STIX 2.1 SDOs/SROs.

The functions here are deliberately small and composable. Each one
takes an internal datum (an IOC dict, an ATT&CK id, a session summary,
a TLS fingerprint match) plus a :class:`StixBundleBuilder`, registers
the right STIX objects and relationships, and returns the new
indicator/observation id so callers can chain SROs.

We treat the timestamps in the internal types as already-ISO; if a
datetime comes in we coerce to ISO/UTC.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

from honeytrap.intel.stix.builder import StixBundleBuilder
from honeytrap.intel.stix.patterns import pattern_for_ioc

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _iso(value: Any) -> str:
    """Coerce datetime / string into a millisecond ISO 8601 timestamp."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    if isinstance(value, str) and value:
        return value
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# ---------------------------------------------------------------------------
# Public mappers
# ---------------------------------------------------------------------------


def stix_from_ioc(builder: StixBundleBuilder, ioc: dict[str, Any]) -> str:
    """Map an internal IOC dict into an indicator + observed-data pair.

    Returns the indicator id; the observed-data is linked via a
    ``based-on`` relationship.
    """
    ioc_type = str(ioc.get("type", "")).lower()
    value = str(ioc.get("value", ""))
    if not ioc_type or not value:
        raise ValueError("IOC dict missing 'type' or 'value'")
    pattern = pattern_for_ioc(ioc_type, value)
    natural = f"{ioc_type}::{value.lower()}"
    indicator_id = builder.add_indicator(
        pattern=pattern,
        natural_key=natural,
        valid_from=_iso(ioc.get("first_seen")),
        confidence=int(round(float(ioc.get("confidence", 0.8)) * 100))
        if ioc.get("confidence") is not None
        else None,
        description=str(ioc.get("context") or "") or None,
    )
    obs_id = builder.add_observed_data(
        natural_key=f"obs::{natural}",
        first_observed=_iso(ioc.get("first_seen")),
        last_observed=_iso(ioc.get("last_seen") or ioc.get("first_seen")),
        number_observed=1,
        custom={"x_honeytrap_value": value, "x_honeytrap_ioc_type": ioc_type},
    )
    builder.add_relationship(
        source_ref=indicator_id,
        target_ref=obs_id,
        relationship_type="based-on",
    )
    return indicator_id


def stix_from_attck(
    builder: StixBundleBuilder,
    technique_id: str,
    *,
    name: str | None = None,
    tactic: str | None = None,
    description: str | None = None,
) -> str:
    """Map an ATT&CK technique id into an attack-pattern SDO."""
    kill_chain: list[dict[str, str]] | None = None
    if tactic:
        kill_chain = [
            {
                "kill_chain_name": "mitre-attack",
                "phase_name": tactic.lower().replace(" ", "-"),
            }
        ]
    return builder.add_attack_pattern(
        name=name or technique_id,
        external_id=technique_id,
        description=description,
        kill_chain_phases=kill_chain,
    )


def stix_from_tls(
    builder: StixBundleBuilder,
    *,
    ja3: str | None,
    ja4: str | None,
    matched_label: str | None = None,
    related_refs: Iterable[str] = (),
) -> str:
    """Carry a TLS fingerprint match as a note with custom x_ja3/x_ja4 fields.

    STIX 2.1 has no first-class TLS fingerprint object, so we follow
    the established convention: emit a ``note`` referring to the
    related observed-data with custom ``x_ja3`` / ``x_ja4`` properties.
    """
    refs = list(related_refs)
    if not refs:
        # Fall back to attaching the note to the honeypot identity.
        refs = [builder.identity_id]
    abstract = "TLS fingerprint match"
    pieces = []
    if ja3:
        pieces.append(f"ja3={ja3}")
    if ja4:
        pieces.append(f"ja4={ja4}")
    if matched_label:
        pieces.append(f"label={matched_label}")
    custom = {}
    if ja3:
        custom["x_ja3"] = ja3
    if ja4:
        custom["x_ja4"] = ja4
    return builder.add_note(
        content="; ".join(pieces) or "TLS fingerprint",
        object_refs=refs,
        abstract=abstract,
        custom=custom,
    )


def stix_from_session(
    builder: StixBundleBuilder,
    session: dict[str, Any],
    *,
    iocs: list[dict[str, Any]] | None = None,
    techniques: list[str | dict[str, Any]] | None = None,
    tls: dict[str, Any] | None = None,
) -> dict[str, str]:
    """Map a session into observed-data + campaign + relationships.

    Returns a dict with ``campaign``, ``observed_data``, and
    ``infrastructure`` ids so callers can wire further objects.
    """
    session_id = str(session.get("session_id") or session.get("id") or "")
    remote_ip = str(session.get("remote_ip") or session.get("source_ip") or "")
    started_at = _iso(session.get("started_at") or session.get("first_seen"))
    ended_at = _iso(session.get("ended_at") or started_at)
    protocol = str(session.get("protocol") or "")

    infra_id = builder.add_infrastructure(
        name=f"honeypot:{protocol}" if protocol else "honeypot",
        infrastructure_types=["honeypot"],
        description=f"HoneyTrap node serving {protocol or 'multi-protocol'}",
    )

    obs_id = builder.add_observed_data(
        natural_key=f"session::{session_id}",
        first_observed=started_at,
        last_observed=ended_at,
        number_observed=1,
        objects_refs=None,
        custom={
            "x_honeytrap_session_id": session_id,
            "x_honeytrap_remote_ip": remote_ip,
            "x_honeytrap_protocol": protocol,
        },
    )

    campaign_id: str | None = None
    if remote_ip:
        campaign_id = builder.add_campaign(
            name=f"attacker:{remote_ip}",
            description=f"Activity grouped by source IP {remote_ip}",
        )
        builder.add_relationship(
            source_ref=obs_id,
            target_ref=campaign_id,
            relationship_type="related-to",
        )
        builder.add_relationship(
            source_ref=campaign_id,
            target_ref=infra_id,
            relationship_type="targets",
        )

    indicator_ids: list[str] = []
    for ioc in iocs or []:
        try:
            indicator_ids.append(stix_from_ioc(builder, ioc))
        except (ValueError, KeyError):
            continue
    for ind_id in indicator_ids:
        builder.add_relationship(
            source_ref=ind_id,
            target_ref=obs_id,
            relationship_type="indicates",
        )
        if campaign_id:
            builder.add_relationship(
                source_ref=ind_id,
                target_ref=campaign_id,
                relationship_type="indicates",
            )

    technique_ids: list[str] = []
    for tech in techniques or []:
        if isinstance(tech, str):
            technique_ids.append(stix_from_attck(builder, tech))
        elif isinstance(tech, dict):
            tid = str(tech.get("id") or tech.get("technique_id") or "")
            if not tid:
                continue
            technique_ids.append(
                stix_from_attck(
                    builder,
                    tid,
                    name=tech.get("name"),
                    tactic=tech.get("tactic"),
                    description=tech.get("description"),
                )
            )
    for ap_id in technique_ids:
        builder.add_relationship(
            source_ref=obs_id,
            target_ref=ap_id,
            relationship_type="related-to",
        )
        for ind_id in indicator_ids:
            builder.add_relationship(
                source_ref=ind_id,
                target_ref=ap_id,
                relationship_type="indicates",
            )

    if tls and (tls.get("ja3") or tls.get("ja4")):
        stix_from_tls(
            builder,
            ja3=tls.get("ja3"),
            ja4=tls.get("ja4"),
            matched_label=tls.get("label"),
            related_refs=[obs_id],
        )

    return {
        "campaign": campaign_id or "",
        "observed_data": obs_id,
        "infrastructure": infra_id,
    }
