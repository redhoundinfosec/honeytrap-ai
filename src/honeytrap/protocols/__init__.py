"""Protocol handlers for HoneyTrap AI."""

from honeytrap.protocols.base import ProtocolHandler
from honeytrap.protocols.mysql_handler import MySQLHandler
from honeytrap.protocols.smtp_handler import SMTPHandler

__all__ = ["MySQLHandler", "ProtocolHandler", "SMTPHandler"]
