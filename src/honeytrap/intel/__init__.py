"""Threat intelligence layer.

Maps observed honeypot events to MITRE ATT&CK techniques and extracts
Indicators of Compromise (IOCs) from session payloads.
"""

from honeytrap.intel.attack_mapper import (
    TECHNIQUE_DB,
    ATTACKMapper,
    ATTACKMapping,
)
from honeytrap.intel.ioc_extractor import IOC, IOCExtractor

__all__ = [
    "IOC",
    "TECHNIQUE_DB",
    "ATTACKMapper",
    "ATTACKMapping",
    "IOCExtractor",
]
