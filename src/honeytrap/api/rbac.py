"""Role-based access control for the management API.

Three roles exist, ordered by privilege:

* ``viewer``  -- read-only access to sessions, alerts, intel, metrics.
* ``analyst`` -- viewer, plus exports and alert acknowledgement.
* ``admin``   -- full CRUD including API key management and control.

Role checks are hierarchical: an admin token satisfies any viewer or
analyst requirement. The comparison is built from an explicit integer
ladder so future roles can slot in without breaking callers.
"""

from __future__ import annotations

import enum


class Role(str, enum.Enum):
    """Hierarchical role for an :class:`~honeytrap.api.auth.APIKey`."""

    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMIN = "admin"

    @classmethod
    def from_str(cls, value: str | Role) -> Role:
        """Parse a case-insensitive role name, raising on unknown values."""
        if isinstance(value, Role):
            return value
        key = str(value).strip().lower()
        for member in cls:
            if member.value == key:
                return member
        raise ValueError(f"Unknown role: {value!r}")

    @property
    def level(self) -> int:
        """Return the privilege level. Higher = more privilege."""
        return _LEVELS[self]

    def satisfies(self, required: Role) -> bool:
        """Return True when this role's level >= ``required`` level."""
        return self.level >= required.level


_LEVELS: dict[Role, int] = {
    Role.VIEWER: 10,
    Role.ANALYST: 20,
    Role.ADMIN: 30,
}


def check_role(actual: Role, required: Role) -> bool:
    """Hierarchical role check: admin satisfies analyst/viewer, etc."""
    return actual.satisfies(required)
