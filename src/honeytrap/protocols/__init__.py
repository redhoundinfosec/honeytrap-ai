"""Protocol handlers for HoneyTrap AI."""

from honeytrap.protocols.base import ProtocolHandler
from honeytrap.protocols.coap_handler import CoAPHandler
from honeytrap.protocols.imap_handler import IMAPHandler
from honeytrap.protocols.mqtt_handler import MQTTHandler
from honeytrap.protocols.mysql_handler import MySQLHandler
from honeytrap.protocols.rdp_handler import RDPHandler
from honeytrap.protocols.smtp_handler import SMTPHandler

__all__ = [
    "CoAPHandler",
    "IMAPHandler",
    "MQTTHandler",
    "MySQLHandler",
    "ProtocolHandler",
    "RDPHandler",
    "SMTPHandler",
]
