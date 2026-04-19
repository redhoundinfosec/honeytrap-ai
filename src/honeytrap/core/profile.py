"""Device profile loader.

Device profiles are YAML files that describe the device the honeypot should
impersonate — services to open, banners, credential lists, AI personality
hints, and fake file systems. Profiles are loaded into :class:`DeviceProfile`
instances at startup.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from honeytrap.exceptions import ProfileError

logger = logging.getLogger(__name__)

_PROFILE_DIRS = [
    Path(__file__).resolve().parent.parent.parent.parent / "profiles",
    Path.cwd() / "profiles",
]


@dataclass
class ServiceSpec:
    """A single protocol/service entry inside a device profile."""

    protocol: str
    port: int
    banner: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    @property
    def ai_personality(self) -> str:
        """Return the free-form AI personality blurb for this service."""
        return str(self.data.get("ai_personality", ""))


@dataclass
class DeviceProfile:
    """A device profile describing services to simulate."""

    name: str
    description: str
    category: str
    services: list[ServiceSpec]
    source_path: Path | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def service(self, protocol: str) -> ServiceSpec | None:
        """Return the first service entry matching ``protocol`` (case-insensitive)."""
        for svc in self.services:
            if svc.protocol.lower() == protocol.lower():
                return svc
        return None


def _iter_candidate_paths(name: str) -> list[Path]:
    """Return possible filesystem locations for a bundled profile name."""
    results: list[Path] = []
    for directory in _PROFILE_DIRS:
        if not directory.exists():
            continue
        for candidate in (
            directory / f"{name}.yaml",
            directory / f"{name}.yml",
            directory / name,
        ):
            if candidate.exists():
                results.append(candidate)
    return results


def list_bundled_profiles() -> list[Path]:
    """Return every ``*.yaml`` profile that ships with the package."""
    seen: set[Path] = set()
    results: list[Path] = []
    for directory in _PROFILE_DIRS:
        if not directory.exists():
            continue
        for path in sorted(directory.glob("*.yaml")):
            if path.resolve() in seen:
                continue
            seen.add(path.resolve())
            results.append(path)
    return results


def load_profile(path_or_name: str | Path) -> DeviceProfile:
    """Load a device profile by absolute path or bundled name.

    Args:
        path_or_name: Filesystem path or bundled profile name (no extension).

    Raises:
        ProfileError: If the profile cannot be found or is malformed.
    """
    path: Path | None = None
    if isinstance(path_or_name, Path) or Path(path_or_name).is_file():
        path = Path(path_or_name)
    else:
        candidates = _iter_candidate_paths(str(path_or_name))
        if candidates:
            path = candidates[0]

    if path is None or not path.exists():
        raise ProfileError(f"Profile not found: {path_or_name}")

    try:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except yaml.YAMLError as exc:
        raise ProfileError(f"Invalid YAML in {path}: {exc}") from exc
    except OSError as exc:
        raise ProfileError(f"Unable to read profile {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise ProfileError(f"Profile {path} must be a YAML mapping")

    services_raw = data.get("services", [])
    if not isinstance(services_raw, list):
        raise ProfileError(f"Profile {path} has a non-list 'services' field")

    services: list[ServiceSpec] = []
    for entry in services_raw:
        if not isinstance(entry, dict):
            logger.warning("Skipping non-mapping service entry in %s", path)
            continue
        protocol = str(entry.get("protocol", "")).strip()
        if not protocol:
            logger.warning("Skipping service without protocol in %s", path)
            continue
        try:
            port = int(entry.get("port", 0))
        except (TypeError, ValueError):
            logger.warning("Skipping service with invalid port in %s", path)
            continue
        services.append(
            ServiceSpec(
                protocol=protocol,
                port=port,
                banner=str(entry.get("banner", "")),
                data={k: v for k, v in entry.items() if k not in {"protocol", "port", "banner"}},
            )
        )

    return DeviceProfile(
        name=str(data.get("name", path.stem)),
        description=str(data.get("description", "")),
        category=str(data.get("category", "generic")),
        services=services,
        source_path=path,
        raw=data,
    )
