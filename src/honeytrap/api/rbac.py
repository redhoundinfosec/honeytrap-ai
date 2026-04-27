"""Role-based access control for the management API.

Four roles exist, ordered by privilege:

* ``node``    -- machine-only role used by node uplinks; can register,
  send heartbeats, and POST event batches but cannot read anything.
* ``viewer``  -- read-only access to sessions, alerts, intel, metrics.
* ``analyst`` -- viewer, plus exports and alert acknowledgement.
* ``admin``   -- full CRUD including API key management and control.

Role checks are hierarchical: an admin token satisfies any viewer or
analyst requirement. The ``node`` role sits OUTSIDE this ladder -- it
is a leaf role for write-only fleet endpoints. ``check_role`` is the
canonical entry point: it understands that a node role does NOT satisfy
viewer/analyst/admin and vice versa, so a stolen node key cannot be used
to read sessions or rotate keys.
"""

from __future__ import annotations

import enum


class Role(str, enum.Enum):
    """Hierarchical role for an :class:`~honeytrap.api.auth.APIKey`."""

    NODE = "node"
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
        """Return True when this role's level >= ``required`` level.

        The :class:`Role.NODE` role is special: it is a leaf role with a
        unique level, so it neither satisfies VIEWER/ANALYST/ADMIN nor
        is satisfied by them. Comparisons across the divide always
        return False.
        """
        if self is Role.NODE and required is not Role.NODE:
            return False
        if required is Role.NODE and self is not Role.NODE:
            return False
        return self.level >= required.level


_LEVELS: dict[Role, int] = {
    Role.NODE: 5,
    Role.VIEWER: 10,
    Role.ANALYST: 20,
    Role.ADMIN: 30,
}


def check_role(actual: Role, required: Role) -> bool:
    """Hierarchical role check: admin satisfies analyst/viewer, etc.

    The ``node`` role is isolated: only a node key satisfies a node-only
    endpoint, and a node key cannot satisfy any other role requirement.
    """
    return actual.satisfies(required)
