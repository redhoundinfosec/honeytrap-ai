"""STIX 2.1 bundle builder.

The builder accumulates SDOs and SROs through high-level :meth:`add_*`
helpers, deduplicates objects by their natural keys, and finally emits
a STIX 2.1 bundle as a Python dict (or JSON string via the serializer).

We intentionally implement only the subset of the spec HoneyTrap uses
so we don't have to take a runtime dependency on ``stix2``. The shape
matches the parts of the spec consumed by Splunk, Elastic, MISP, OTX,
and the open-source TAXII clients.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any

STIX_SPEC_VERSION = "2.1"
DEFAULT_NAMESPACE_UUID = uuid.UUID("4dc9f7e2-3df8-4b89-9f1f-1cc1c8e5b9a4")


class StixValidationError(ValueError):
    """Raised when a STIX object or bundle fails structural validation."""


def _now_iso() -> str:
    """Return a UTC timestamp in ISO 8601 / RFC 3339 millisecond form."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _deterministic_id(stix_type: str, natural_key: str) -> str:
    """Derive a deterministic ``<type>--<uuid5>`` id from a natural key."""
    namespace = uuid.uuid5(DEFAULT_NAMESPACE_UUID, stix_type)
    return f"{stix_type}--{uuid.uuid5(namespace, natural_key)}"


def random_id(stix_type: str) -> str:
    """Return a random ``<type>--<uuid4>`` STIX id."""
    return f"{stix_type}--{uuid.uuid4()}"


# Required-field tables for the SDO/SRO subset we emit.
_REQUIRED_FIELDS: dict[str, tuple[str, ...]] = {
    "identity": ("id", "type", "spec_version", "created", "modified", "name", "identity_class"),
    "indicator": (
        "id",
        "type",
        "spec_version",
        "created",
        "modified",
        "pattern",
        "pattern_type",
        "valid_from",
    ),
    "observed-data": (
        "id",
        "type",
        "spec_version",
        "created",
        "modified",
        "first_observed",
        "last_observed",
        "number_observed",
    ),
    "attack-pattern": ("id", "type", "spec_version", "created", "modified", "name"),
    "malware": ("id", "type", "spec_version", "created", "modified", "name", "is_family"),
    "campaign": ("id", "type", "spec_version", "created", "modified", "name"),
    "infrastructure": (
        "id",
        "type",
        "spec_version",
        "created",
        "modified",
        "name",
        "infrastructure_types",
    ),
    "note": ("id", "type", "spec_version", "created", "modified", "content", "object_refs"),
    "relationship": (
        "id",
        "type",
        "spec_version",
        "created",
        "modified",
        "relationship_type",
        "source_ref",
        "target_ref",
    ),
    "sighting": ("id", "type", "spec_version", "created", "modified", "sighting_of_ref"),
}

_VALID_TYPES = frozenset(_REQUIRED_FIELDS.keys())

StixObject = dict[str, Any]


def validate_object(obj: StixObject) -> None:
    """Validate one STIX object against the subset schema.

    Raises:
        StixValidationError: when a required field is missing or the
            ``id`` does not match the ``type--uuid`` shape.
    """
    if not isinstance(obj, dict):
        raise StixValidationError(f"STIX object must be a dict, got {type(obj).__name__}")
    stix_type = obj.get("type")
    if not isinstance(stix_type, str):
        raise StixValidationError("STIX object missing 'type' string")
    if stix_type not in _VALID_TYPES:
        raise StixValidationError(f"Unsupported STIX type: {stix_type!r}")
    sid = obj.get("id")
    if (
        not isinstance(sid, str)
        or not sid.startswith(f"{stix_type}--")
        or len(sid) < len(stix_type) + 38
    ):
        raise StixValidationError(f"Bad STIX id for {stix_type}: {sid!r}")
    spec = obj.get("spec_version")
    if spec != STIX_SPEC_VERSION:
        raise StixValidationError(f"spec_version must be {STIX_SPEC_VERSION!r}, got {spec!r}")
    for field in _REQUIRED_FIELDS[stix_type]:
        if field not in obj:
            raise StixValidationError(f"Required field {field!r} missing from {stix_type} object")


def validate_bundle(bundle: dict[str, Any]) -> None:
    """Validate a STIX 2.1 bundle and every contained object.

    Raises:
        StixValidationError: when bundle fields are missing or any
            object inside the bundle is malformed.
    """
    if not isinstance(bundle, dict):
        raise StixValidationError("Bundle must be a dict")
    if bundle.get("type") != "bundle":
        raise StixValidationError("Bundle 'type' must be 'bundle'")
    bid = bundle.get("id")
    if not isinstance(bid, str) or not bid.startswith("bundle--"):
        raise StixValidationError(f"Bad bundle id: {bid!r}")
    objs = bundle.get("objects")
    if not isinstance(objs, list):
        raise StixValidationError("Bundle 'objects' must be a list")
    for obj in objs:
        validate_object(obj)


class StixBundleBuilder:
    """Accumulate STIX SDOs/SROs and emit a deduplicated 2.1 bundle.

    The builder keeps three caches:

    * ``_by_natural_key`` maps a natural key (e.g. ``"ipv4-addr:1.2.3.4"``)
      to the corresponding deterministic STIX id, so the same indicator
      across multiple sessions resolves to the same id.
    * ``_objects`` is the ordered list of unique STIX objects.
    * ``_seen_ids`` deduplicates by id at insertion time.
    """

    def __init__(
        self,
        *,
        identity_name: str = "HoneyTrap",
        identity_class: str = "system",
    ) -> None:
        """Initialise an empty builder, seeded with one identity SDO."""
        self._objects: list[StixObject] = []
        self._seen_ids: set[str] = set()
        self._by_natural_key: dict[str, str] = {}
        self._created_at = _now_iso()
        self._identity_id = self.add_identity(identity_name, identity_class=identity_class)

    # -- low-level helpers --------------------------------------------------
    def _add(self, obj: StixObject) -> str:
        """Add a fully-formed STIX object to the bundle (idempotent by id)."""
        validate_object(obj)
        sid = obj["id"]
        if sid in self._seen_ids:
            return sid
        self._seen_ids.add(sid)
        self._objects.append(obj)
        return sid

    def _resolve_id(self, stix_type: str, natural_key: str) -> str:
        """Resolve (or create) the deterministic id for a natural key."""
        cache_key = f"{stix_type}::{natural_key}"
        if cache_key in self._by_natural_key:
            return self._by_natural_key[cache_key]
        sid = _deterministic_id(stix_type, natural_key)
        self._by_natural_key[cache_key] = sid
        return sid

    def _common(self, stix_type: str, sid: str) -> StixObject:
        """Return the spec-required common fields for an SDO/SRO."""
        return {
            "type": stix_type,
            "spec_version": STIX_SPEC_VERSION,
            "id": sid,
            "created": self._created_at,
            "modified": self._created_at,
        }

    # -- SDO factories ------------------------------------------------------
    def add_identity(self, name: str, *, identity_class: str = "system") -> str:
        """Add an ``identity`` SDO (deduplicated by ``name``)."""
        sid = self._resolve_id("identity", f"identity::{name}::{identity_class}")
        obj = self._common("identity", sid)
        obj.update({"name": name, "identity_class": identity_class})
        self._add(obj)
        return sid

    def add_indicator(
        self,
        *,
        pattern: str,
        pattern_type: str = "stix",
        natural_key: str,
        labels: list[str] | None = None,
        valid_from: str | None = None,
        confidence: int | None = None,
        description: str | None = None,
    ) -> str:
        """Add an ``indicator`` SDO carrying a STIX pattern."""
        sid = self._resolve_id("indicator", natural_key)
        obj = self._common("indicator", sid)
        obj.update(
            {
                "pattern": pattern,
                "pattern_type": pattern_type,
                "valid_from": valid_from or self._created_at,
                "indicator_types": labels or ["malicious-activity"],
                "created_by_ref": self._identity_id,
            }
        )
        if confidence is not None:
            obj["confidence"] = max(0, min(100, int(confidence)))
        if description:
            obj["description"] = description
        self._add(obj)
        return sid

    def add_observed_data(
        self,
        *,
        natural_key: str,
        first_observed: str,
        last_observed: str,
        number_observed: int = 1,
        objects_refs: list[str] | None = None,
        custom: dict[str, Any] | None = None,
    ) -> str:
        """Add an ``observed-data`` SDO."""
        sid = self._resolve_id("observed-data", natural_key)
        obj = self._common("observed-data", sid)
        obj.update(
            {
                "first_observed": first_observed,
                "last_observed": last_observed,
                "number_observed": max(1, int(number_observed)),
                "created_by_ref": self._identity_id,
            }
        )
        if objects_refs:
            obj["object_refs"] = list(objects_refs)
        if custom:
            for key, value in custom.items():
                if key.startswith("x_"):
                    obj[key] = value
        self._add(obj)
        return sid

    def add_attack_pattern(
        self,
        *,
        name: str,
        external_id: str,
        description: str | None = None,
        kill_chain_phases: list[dict[str, str]] | None = None,
    ) -> str:
        """Add an ``attack-pattern`` SDO with MITRE external_references."""
        sid = self._resolve_id("attack-pattern", f"mitre::{external_id}")
        obj = self._common("attack-pattern", sid)
        obj.update(
            {
                "name": name,
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": external_id,
                        "url": f"https://attack.mitre.org/techniques/{external_id.replace('.', '/')}/",
                    }
                ],
            }
        )
        if description:
            obj["description"] = description
        if kill_chain_phases:
            obj["kill_chain_phases"] = list(kill_chain_phases)
        self._add(obj)
        return sid

    def add_malware(
        self,
        *,
        name: str,
        is_family: bool = False,
        malware_types: list[str] | None = None,
        description: str | None = None,
    ) -> str:
        """Add a ``malware`` SDO (deduplicated by ``name`` + family flag)."""
        sid = self._resolve_id("malware", f"malware::{name}::{is_family}")
        obj = self._common("malware", sid)
        obj.update({"name": name, "is_family": bool(is_family)})
        if malware_types:
            obj["malware_types"] = list(malware_types)
        if description:
            obj["description"] = description
        self._add(obj)
        return sid

    def add_campaign(self, *, name: str, description: str | None = None) -> str:
        """Add a ``campaign`` SDO grouped by an attacker IP / cluster id."""
        sid = self._resolve_id("campaign", f"campaign::{name}")
        obj = self._common("campaign", sid)
        obj.update({"name": name, "created_by_ref": self._identity_id})
        if description:
            obj["description"] = description
        self._add(obj)
        return sid

    def add_infrastructure(
        self,
        *,
        name: str,
        infrastructure_types: list[str] | None = None,
        description: str | None = None,
    ) -> str:
        """Add an ``infrastructure`` SDO (e.g. honeypot node)."""
        sid = self._resolve_id("infrastructure", f"infra::{name}")
        obj = self._common("infrastructure", sid)
        obj.update(
            {
                "name": name,
                "infrastructure_types": list(infrastructure_types or ["honeypot"]),
                "created_by_ref": self._identity_id,
            }
        )
        if description:
            obj["description"] = description
        self._add(obj)
        return sid

    def add_note(
        self,
        *,
        content: str,
        object_refs: list[str],
        abstract: str | None = None,
        custom: dict[str, Any] | None = None,
    ) -> str:
        """Add a ``note`` SDO referring to one or more SDOs."""
        if not object_refs:
            raise StixValidationError("note requires at least one object_ref")
        natural = hashlib.sha256(
            ("note::" + abstract + "::" + content + "::" + ",".join(sorted(object_refs))).encode(
                "utf-8"
            )
        ).hexdigest()
        sid = self._resolve_id("note", natural)
        obj = self._common("note", sid)
        obj.update(
            {
                "content": content,
                "object_refs": list(object_refs),
                "created_by_ref": self._identity_id,
            }
        )
        if abstract:
            obj["abstract"] = abstract
        if custom:
            for key, value in custom.items():
                if key.startswith("x_"):
                    obj[key] = value
        self._add(obj)
        return sid

    # -- SRO factories ------------------------------------------------------
    def add_relationship(
        self,
        *,
        source_ref: str,
        target_ref: str,
        relationship_type: str,
        description: str | None = None,
    ) -> str:
        """Add a ``relationship`` SRO between two SDOs."""
        natural = f"rel::{source_ref}::{relationship_type}::{target_ref}"
        sid = self._resolve_id("relationship", natural)
        obj = self._common("relationship", sid)
        obj.update(
            {
                "relationship_type": relationship_type,
                "source_ref": source_ref,
                "target_ref": target_ref,
                "created_by_ref": self._identity_id,
            }
        )
        if description:
            obj["description"] = description
        self._add(obj)
        return sid

    def add_sighting(
        self,
        *,
        sighting_of_ref: str,
        first_seen: str | None = None,
        last_seen: str | None = None,
        count: int = 1,
        observed_data_refs: list[str] | None = None,
    ) -> str:
        """Add a ``sighting`` SRO referring to a single SDO."""
        natural = f"sighting::{sighting_of_ref}::{first_seen}::{last_seen}"
        sid = self._resolve_id("sighting", natural)
        obj = self._common("sighting", sid)
        obj.update(
            {
                "sighting_of_ref": sighting_of_ref,
                "count": max(1, int(count)),
                "created_by_ref": self._identity_id,
            }
        )
        if first_seen:
            obj["first_seen"] = first_seen
        if last_seen:
            obj["last_seen"] = last_seen
        if observed_data_refs:
            obj["observed_data_refs"] = list(observed_data_refs)
        self._add(obj)
        return sid

    # -- emission ----------------------------------------------------------
    @property
    def identity_id(self) -> str:
        """Return the id of the auto-seeded honeypot identity."""
        return self._identity_id

    def objects(self) -> list[StixObject]:
        """Return the accumulated objects in insertion order (copy)."""
        return list(self._objects)

    def object_count_by_type(self) -> dict[str, int]:
        """Return a ``type -> count`` map for metric labelling."""
        out: dict[str, int] = {}
        for obj in self._objects:
            t = str(obj["type"])
            out[t] = out.get(t, 0) + 1
        return out

    def build(self) -> dict[str, Any]:
        """Return the complete bundle dict; validates before returning."""
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": list(self._objects),
        }
        validate_bundle(bundle)
        return bundle
