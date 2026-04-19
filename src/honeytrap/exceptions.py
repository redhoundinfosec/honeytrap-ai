"""Exception hierarchy for HoneyTrap AI."""

from __future__ import annotations


class HoneyTrapError(Exception):
    """Base exception for all HoneyTrap errors."""


class PortBindError(HoneyTrapError):
    """Raised when a port cannot be bound."""


class ProtocolError(HoneyTrapError):
    """Raised when a protocol handler encounters an error."""


class ConfigError(HoneyTrapError):
    """Raised when configuration loading or validation fails."""


class ProfileError(HoneyTrapError):
    """Raised when a device profile cannot be loaded."""


class AIResponseError(HoneyTrapError):
    """Raised when the AI response layer fails (callers should fall back)."""


class GeoResolutionError(HoneyTrapError):
    """Raised when geo resolution fails (callers should default to Unknown)."""
