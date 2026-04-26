"""TAXII 2.1 read-only pull server.

The server implements the discovery / collections / objects / manifest
endpoints from the TAXII 2.1 specification, scoped to a single root
named ``honeytrap``. STIX bundles are produced on demand from the
in-memory service via :class:`TaxiiCollections`.

We deliberately implement only the read paths an analyst client needs
(no posting, no async status). Writes are not honored -- if a future
need arises, the place to extend is :class:`TaxiiCollections`.

The endpoints are mounted on the existing management API server so
all of the auth, RBAC, audit, and rate-limiting machinery is reused.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from honeytrap.intel.stix import (
    StixBundleBuilder,
    stix_from_attck,
    stix_from_ioc,
    stix_from_session,
    stix_from_tls,
    validate_bundle,
)

TAXII_PREFIX = "/taxii/2.1"
TAXII_CONTENT_TYPE = "application/taxii+json;version=2.1"
TAXII_API_ROOT = "honeytrap"

# Stable, deterministic collection ids so external clients can hard-code them.
COLLECTION_IDS: dict[str, str] = {
    "indicators": "12345678-0001-4000-8000-000000000001",
    "attack-patterns": "12345678-0002-4000-8000-000000000002",
    "observed-data": "12345678-0003-4000-8000-000000000003",
    "sightings": "12345678-0004-4000-8000-000000000004",
    "notes": "12345678-0005-4000-8000-000000000005",
}

COLLECTION_TITLES: dict[str, str] = {
    "indicators": "HoneyTrap Indicators",
    "attack-patterns": "HoneyTrap ATT&CK Patterns",
    "observed-data": "HoneyTrap Observations",
    "sightings": "HoneyTrap Sightings",
    "notes": "HoneyTrap Notes (TLS, context)",
}

COLLECTION_TYPES: dict[str, set[str]] = {
    "indicators": {"indicator", "relationship"},
    "attack-patterns": {"attack-pattern"},
    "observed-data": {"observed-data"},
    "sightings": {"sighting"},
    "notes": {"note", "identity", "infrastructure", "campaign", "malware"},
}


# ---------------------------------------------------------------------------
# Domain
# ---------------------------------------------------------------------------


@dataclass
class TaxiiCollections:
    """In-memory TAXII collections backed by a STIX bundle builder.

    The builder is rebuilt on every refresh; that's fine for tens of
    thousands of objects (the SIEM tier already deduplicates), and it
    avoids state bugs where a stale object lingers in a collection.
    """

    objects: list[dict[str, Any]] = field(default_factory=list)
    last_refreshed: str = ""

    def refresh(self, builder: StixBundleBuilder) -> None:
        """Replace the cached object list with the builder's output."""
        self.objects = builder.objects()
        self.last_refreshed = datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%f"
        )[:-3] + "Z"

    # -- helpers -----------------------------------------------------------
    def filter(
        self,
        collection_name: str,
        *,
        match_id: list[str] | None = None,
        match_type: list[str] | None = None,
        added_after: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return objects matching the TAXII filter parameters."""
        wanted_types = COLLECTION_TYPES.get(collection_name, set())
        out: list[dict[str, Any]] = []
        for obj in self.objects:
            if obj["type"] not in wanted_types:
                continue
            if match_id and obj.get("id") not in match_id:
                continue
            if match_type and obj.get("type") not in match_type:
                continue
            if added_after and obj.get("modified", "") <= added_after:
                continue
            out.append(obj)
        return out


# ---------------------------------------------------------------------------
# Bundle assembly from the in-memory service
# ---------------------------------------------------------------------------


def build_bundle_from_service(
    *,
    sessions: list[dict[str, Any]] | None = None,
    iocs: list[dict[str, Any]] | None = None,
    techniques: list[str | dict[str, Any]] | None = None,
    tls_matches: list[dict[str, Any]] | None = None,
    identity_name: str = "HoneyTrap",
) -> StixBundleBuilder:
    """Compose a STIX 2.1 bundle builder from internal collections."""
    builder = StixBundleBuilder(identity_name=identity_name)
    seen_iocs_per_session: dict[str, list[dict[str, Any]]] = {}
    if iocs:
        for ioc in iocs:
            sid = str(ioc.get("session_id") or "")
            seen_iocs_per_session.setdefault(sid, []).append(ioc)
    for sess in sessions or []:
        sid = str(sess.get("session_id") or "")
        stix_from_session(
            builder,
            sess,
            iocs=seen_iocs_per_session.get(sid, []),
            techniques=techniques,
            tls=sess.get("tls"),
        )
    for ioc in (iocs or []):
        if not ioc.get("session_id"):
            try:
                stix_from_ioc(builder, ioc)
            except ValueError:
                continue
    for tech in techniques or []:
        if isinstance(tech, str):
            stix_from_attck(builder, tech)
        elif isinstance(tech, dict) and (tech.get("id") or tech.get("technique_id")):
            tid = str(tech.get("id") or tech.get("technique_id"))
            stix_from_attck(
                builder,
                tid,
                name=tech.get("name"),
                tactic=tech.get("tactic"),
                description=tech.get("description"),
            )
    for tls in tls_matches or []:
        stix_from_tls(
            builder,
            ja3=tls.get("ja3"),
            ja4=tls.get("ja4"),
            matched_label=tls.get("label"),
        )
    validate_bundle(builder.build())
    return builder


# ---------------------------------------------------------------------------
# Endpoint payload builders (TAXII spec response shapes)
# ---------------------------------------------------------------------------


def discovery_payload() -> dict[str, Any]:
    """Return the TAXII 2.1 discovery document (api_roots list)."""
    return {
        "title": "HoneyTrap TAXII 2.1",
        "description": "Pull-based threat intel sharing for honeypot observations.",
        "default": f"{TAXII_PREFIX}/{TAXII_API_ROOT}/",
        "api_roots": [f"{TAXII_PREFIX}/{TAXII_API_ROOT}/"],
    }


def root_payload() -> dict[str, Any]:
    """Return the API-root metadata document."""
    return {
        "title": "HoneyTrap API Root",
        "description": "Read-only pull endpoint for HoneyTrap STIX 2.1 data.",
        "versions": ["application/taxii+json;version=2.1"],
        "max_content_length": 1048576,
    }


def collections_list_payload() -> dict[str, Any]:
    """Return the collections-list document for the configured collections."""
    return {
        "collections": [
            {
                "id": COLLECTION_IDS[name],
                "title": COLLECTION_TITLES[name],
                "description": f"HoneyTrap collection: {name}",
                "can_read": True,
                "can_write": False,
                "media_types": ["application/stix+json;version=2.1"],
            }
            for name in COLLECTION_IDS
        ]
    }


def collection_payload(name: str) -> dict[str, Any] | None:
    """Return the metadata for a single collection (by name) or None."""
    if name not in COLLECTION_IDS:
        return None
    return {
        "id": COLLECTION_IDS[name],
        "title": COLLECTION_TITLES[name],
        "description": f"HoneyTrap collection: {name}",
        "can_read": True,
        "can_write": False,
        "media_types": ["application/stix+json;version=2.1"],
    }


def objects_envelope(
    objects: list[dict[str, Any]],
    *,
    next_token: str | None = None,
    more: bool = False,
) -> dict[str, Any]:
    """Wrap a list of STIX objects in the TAXII envelope."""
    payload: dict[str, Any] = {
        "more": more,
        "objects": objects,
    }
    if next_token:
        payload["next"] = next_token
    return payload


def manifest_envelope(
    objects: list[dict[str, Any]],
    *,
    next_token: str | None = None,
    more: bool = False,
) -> dict[str, Any]:
    """Build a manifest envelope containing one entry per object."""
    entries = [
        {
            "id": obj["id"],
            "date_added": obj.get("created", ""),
            "version": obj.get("modified", ""),
            "media_type": "application/stix+json;version=2.1",
        }
        for obj in objects
    ]
    payload: dict[str, Any] = {"more": more, "objects": entries}
    if next_token:
        payload["next"] = next_token
    return payload


def status_payload(status_id: str) -> dict[str, Any]:
    """Return the synthetic TAXII status document (always 'complete')."""
    request_timestamp = datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%f"
    )[:-3] + "Z"
    return {
        "id": status_id or str(uuid.uuid4()),
        "status": "complete",
        "request_timestamp": request_timestamp,
        "total_count": 0,
        "success_count": 0,
        "failure_count": 0,
        "pending_count": 0,
    }


def find_collection_name(collection_id: str) -> str | None:
    """Resolve a collection UUID back to the configured short name."""
    for name, cid in COLLECTION_IDS.items():
        if cid == collection_id:
            return name
    return None


def paginate(
    items: list[dict[str, Any]],
    *,
    limit: int | None,
    cursor: str | None,
) -> tuple[list[dict[str, Any]], str | None, bool]:
    """Slice ``items`` according to TAXII ``limit`` / ``next`` semantics."""
    start = 0
    if cursor and cursor.isdigit():
        start = max(0, int(cursor))
    bound = max(1, min(int(limit), 1000)) if limit else len(items)
    end = start + bound
    page = items[start:end]
    has_more = end < len(items)
    next_token = str(end) if has_more else None
    return page, next_token, has_more


# ---------------------------------------------------------------------------
# Service refresh helper
# ---------------------------------------------------------------------------


@dataclass
class TaxiiState:
    """Singleton holding the currently-served TAXII collection cache."""

    collections: TaxiiCollections = field(default_factory=TaxiiCollections)

    def rebuild(
        self,
        *,
        sessions: list[dict[str, Any]] | None,
        iocs: list[dict[str, Any]] | None,
        techniques: list[str | dict[str, Any]] | None,
        tls_matches: list[dict[str, Any]] | None,
    ) -> None:
        """Rebuild the cache from the given internal collections."""
        builder = build_bundle_from_service(
            sessions=sessions,
            iocs=iocs,
            techniques=techniques,
            tls_matches=tls_matches,
        )
        self.collections.refresh(builder)


def make_taxii_state_factory(
    sessions_provider: Callable[[], list[dict[str, Any]]],
    iocs_provider: Callable[[], list[dict[str, Any]]],
    techniques_provider: Callable[[], list[str | dict[str, Any]]],
    tls_provider: Callable[[], list[dict[str, Any]]],
) -> Callable[[], TaxiiState]:
    """Return a factory that builds a fresh :class:`TaxiiState` per call."""

    def _factory() -> TaxiiState:
        state = TaxiiState()
        state.rebuild(
            sessions=sessions_provider(),
            iocs=iocs_provider(),
            techniques=techniques_provider(),
            tls_matches=tls_provider(),
        )
        return state

    return _factory
