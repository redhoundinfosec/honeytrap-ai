# STIX 2.1 Bundle Export

HoneyTrap can serialise observed sessions, IOCs, ATT&CK techniques, and TLS
fingerprint matches as a [STIX 2.1](https://oasis-open.github.io/cti-documentation/stix/intro)
bundle for exchange with downstream threat-intel platforms (MISP, OpenCTI,
Anomali, etc.).

The implementation is dependency-free: the bundle builder, pattern grammar,
and structural validator live entirely under `honeytrap.intel.stix` and use
only the standard library.

## What gets emitted

For each session HoneyTrap produces:

- An `infrastructure` SDO describing the honeypot listener.
- An `observed-data` SDO snapshotting the connection (count=1).
- A `campaign` SDO keyed on the attacker IP so multiple sessions group.
- `relationship` SROs (`related-to`, `targets`, `based-on`) wiring the
  campaign, infrastructure, and observed data together.

For each IOC: a STIX `pattern` plus an `indicator` and `observed-data` linked
by `based-on`. ATT&CK technique IDs become `attack-pattern` SDOs with a
`mitre-attack` external reference. JA3/JA4 matches become `note` SDOs that
carry the custom `x_ja3` / `x_ja4` properties.

The bundle's `identity` SDO defaults to the literal string `HoneyTrap`; pass
`--identity <name>` to the CLI or `identity_name=` to the builder to change
it.

## Deterministic IDs

Every SDO id is a UUID5 derived from the natural key of the object — the
attacker IP for a campaign, `(type, value)` for an IOC, the technique id for
ATT&CK, etc. This means rebuilding the bundle from the same input twice
yields byte-identical output, which is convenient for diffing,
deduplication, and signature workflows.

## CLI

```bash
honeytrap export stix --session sess-1 --out bundle.json
honeytrap export stix --since 2026-04-01T00:00:00Z --out today.json --pretty
honeytrap export stix --ip 203.0.113.5 --out attacker.json
```

`--pretty` switches the serialiser from `dump_compact` (sorted keys, no
whitespace) to `dump_pretty` (indent=2). Compact output is what TAXII serves
and what makes downstream diffs sane; use pretty for human inspection only.

## API

`GET /api/v1/intel/stix?session_id=<id>&ip=<addr>&since=<iso>&until=<iso>`

Requires the **analyst** role. Returns a single bundle filtered by the same
options the CLI supports. Two metrics are emitted per request:

- `honeytrap_stix_bundles_generated_total` — counter
- `honeytrap_stix_objects_total{type=...}` — counter labelled by SDO type

## Library use

```python
from honeytrap.intel.stix import (
    StixBundleBuilder,
    stix_from_session,
    stix_from_ioc,
    stix_from_attck,
    dump_compact,
)

builder = StixBundleBuilder(identity_name="My Honeynet")
stix_from_session(
    builder,
    {"session_id": "s1", "remote_ip": "1.2.3.4", "protocol": "ssh"},
    iocs=[{"type": "ip", "value": "1.2.3.4", "session_id": "s1"}],
    techniques=["T1110"],
)
print(dump_compact(builder.build()))
```

Calling `stix_from_*` more than once with the same natural key returns the
existing SDO id rather than emitting a duplicate.
