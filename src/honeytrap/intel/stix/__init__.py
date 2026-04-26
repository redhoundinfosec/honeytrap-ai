"""STIX 2.1 bundle generation for HoneyTrap.

This package converts internal honeypot artefacts (sessions, IOCs,
ATT&CK mappings, TLS fingerprint matches) into STIX 2.1 bundles that
can be shipped over TAXII or imported into MISP / OpenCTI / Splunk ES.
"""

from honeytrap.intel.stix.builder import (
    STIX_SPEC_VERSION,
    StixBundleBuilder,
    StixObject,
    StixValidationError,
    validate_bundle,
    validate_object,
)
from honeytrap.intel.stix.mapping import (
    stix_from_attck,
    stix_from_ioc,
    stix_from_session,
    stix_from_tls,
)
from honeytrap.intel.stix.serializer import dump_compact, dump_pretty

__all__ = [
    "STIX_SPEC_VERSION",
    "StixBundleBuilder",
    "StixObject",
    "StixValidationError",
    "dump_compact",
    "dump_pretty",
    "stix_from_attck",
    "stix_from_ioc",
    "stix_from_session",
    "stix_from_tls",
    "validate_bundle",
    "validate_object",
]
