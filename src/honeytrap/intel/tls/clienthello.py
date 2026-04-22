"""Zero-dependency TLS ClientHello parser.

Operates on raw bytes captured from a TCP stream. Intentionally
lenient: any malformed or truncated input produces ``None`` rather
than raising, so a honeypot can safely feed attacker-controlled
bytes through this module without risking a crash.

Extensions parsed:

* ``server_name`` (``0x0000``) -- SNI
* ``supported_groups`` (``0x000a``)
* ``ec_point_formats`` (``0x000b``)
* ``signature_algorithms`` (``0x000d``)
* ``application_layer_protocol_negotiation`` (``0x0010``)
* ``supported_versions`` (``0x002b``)

GREASE values (``0x0a0a``, ``0x1a1a``, ... ``0xfafa``) are retained
in the parsed output; callers filter them when needed, to keep the
parser honest.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from typing import Final

logger = logging.getLogger(__name__)

TLS_RECORD_HANDSHAKE: Final[int] = 0x16
TLS_HANDSHAKE_CLIENT_HELLO: Final[int] = 0x01

# JA3/JA4 GREASE values per RFC 8701. Both bytes are equal nibbles.
GREASE_VALUES: Final[frozenset[int]] = frozenset(
    {
        0x0A0A,
        0x1A1A,
        0x2A2A,
        0x3A3A,
        0x4A4A,
        0x5A5A,
        0x6A6A,
        0x7A7A,
        0x8A8A,
        0x9A9A,
        0xAAAA,
        0xBABA,
        0xCACA,
        0xDADA,
        0xEAEA,
        0xFAFA,
    }
)

EXT_SERVER_NAME: Final[int] = 0x0000
EXT_SUPPORTED_GROUPS: Final[int] = 0x000A
EXT_EC_POINT_FORMATS: Final[int] = 0x000B
EXT_SIGNATURE_ALGORITHMS: Final[int] = 0x000D
EXT_ALPN: Final[int] = 0x0010
EXT_SUPPORTED_VERSIONS: Final[int] = 0x002B


@dataclass(frozen=True)
class ClientHello:
    """Parsed fields from a TLS ClientHello message."""

    legacy_version: int
    random: bytes
    session_id: bytes
    cipher_suites: tuple[int, ...]
    compression_methods: tuple[int, ...]
    extensions: tuple[int, ...]
    server_name: str | None = None
    supported_groups: tuple[int, ...] = field(default_factory=tuple)
    ec_point_formats: tuple[int, ...] = field(default_factory=tuple)
    signature_algorithms: tuple[int, ...] = field(default_factory=tuple)
    alpn_protocols: tuple[str, ...] = field(default_factory=tuple)
    supported_versions: tuple[int, ...] = field(default_factory=tuple)

    def highest_version(self) -> int:
        """Return the effective highest TLS version advertised.

        TLS 1.3 advertises its real version inside the
        ``supported_versions`` extension; the legacy version field
        is clamped to 1.2 for compatibility.
        """
        versions = [v for v in self.supported_versions if v not in GREASE_VALUES]
        if versions:
            return max(versions)
        return self.legacy_version


class _Reader:
    """Tiny bounded byte reader that raises on short reads."""

    __slots__ = ("_buf", "_pos")

    def __init__(self, buf: bytes) -> None:
        self._buf = buf
        self._pos = 0

    def remaining(self) -> int:
        return len(self._buf) - self._pos

    def read(self, n: int) -> bytes:
        if n < 0 or self._pos + n > len(self._buf):
            raise ValueError(f"short read: need {n}, have {self.remaining()}")
        data = self._buf[self._pos : self._pos + n]
        self._pos += n
        return data

    def read_u8(self) -> int:
        return self.read(1)[0]

    def read_u16(self) -> int:
        return struct.unpack(">H", self.read(2))[0]

    def read_u24(self) -> int:
        b = self.read(3)
        return (b[0] << 16) | (b[1] << 8) | b[2]

    def read_vec_u8(self) -> bytes:
        length = self.read_u8()
        return self.read(length)

    def read_vec_u16(self) -> bytes:
        length = self.read_u16()
        return self.read(length)


def _parse_u16_list(data: bytes) -> tuple[int, ...]:
    if len(data) % 2 != 0:
        raise ValueError("odd-length u16 list")
    return tuple(struct.unpack(">H", data[i : i + 2])[0] for i in range(0, len(data), 2))


def _parse_extensions(
    data: bytes,
) -> tuple[
    tuple[int, ...],
    str | None,
    tuple[int, ...],
    tuple[int, ...],
    tuple[int, ...],
    tuple[str, ...],
    tuple[int, ...],
]:
    """Return (ext_types, sni, groups, point_formats, sig_algs, alpn, supported_versions)."""
    r = _Reader(data)
    ext_types: list[int] = []
    sni: str | None = None
    groups: tuple[int, ...] = ()
    point_formats: tuple[int, ...] = ()
    sig_algs: tuple[int, ...] = ()
    alpn: list[str] = []
    versions: tuple[int, ...] = ()

    while r.remaining() >= 4:
        ext_type = r.read_u16()
        ext_body = r.read_vec_u16()
        ext_types.append(ext_type)

        if ext_type == EXT_SERVER_NAME:
            sni = _parse_sni(ext_body)
        elif ext_type == EXT_SUPPORTED_GROUPS:
            sub = _Reader(ext_body)
            body = sub.read_vec_u16()
            groups = _parse_u16_list(body)
        elif ext_type == EXT_EC_POINT_FORMATS:
            sub = _Reader(ext_body)
            body = sub.read_vec_u8()
            point_formats = tuple(body)
        elif ext_type == EXT_SIGNATURE_ALGORITHMS:
            sub = _Reader(ext_body)
            body = sub.read_vec_u16()
            sig_algs = _parse_u16_list(body)
        elif ext_type == EXT_ALPN:
            alpn = _parse_alpn(ext_body)
        elif ext_type == EXT_SUPPORTED_VERSIONS:
            versions = _parse_supported_versions(ext_body)

    return (
        tuple(ext_types),
        sni,
        groups,
        point_formats,
        sig_algs,
        tuple(alpn),
        versions,
    )


def _parse_sni(ext_body: bytes) -> str | None:
    r = _Reader(ext_body)
    list_body = r.read_vec_u16()
    sub = _Reader(list_body)
    while sub.remaining() >= 3:
        name_type = sub.read_u8()
        host = sub.read_vec_u16()
        if name_type == 0:
            try:
                return host.decode("ascii")
            except UnicodeDecodeError:
                return host.decode("utf-8", errors="replace")
    return None


def _parse_alpn(ext_body: bytes) -> list[str]:
    r = _Reader(ext_body)
    list_body = r.read_vec_u16()
    sub = _Reader(list_body)
    out: list[str] = []
    while sub.remaining() >= 1:
        proto = sub.read_vec_u8()
        try:
            out.append(proto.decode("ascii"))
        except UnicodeDecodeError:
            out.append(proto.decode("utf-8", errors="replace"))
    return out


def _parse_supported_versions(ext_body: bytes) -> tuple[int, ...]:
    # ClientHello variant: 1-byte length followed by list of u16 versions.
    r = _Reader(ext_body)
    try:
        list_body = r.read_vec_u8()
        return _parse_u16_list(list_body)
    except ValueError:
        return ()


def parse_tls_record(data: bytes) -> bytes | None:
    """Strip the TLS record layer and return the raw handshake payload.

    Returns ``None`` if ``data`` is not a TLS handshake record or is
    too short to extract the full record body.
    """
    if len(data) < 5:
        return None
    if data[0] != TLS_RECORD_HANDSHAKE:
        return None
    record_len = struct.unpack(">H", data[3:5])[0]
    end = 5 + record_len
    if end > len(data):
        # Return whatever we have; caller may have stitched a partial record.
        return data[5:]
    return data[5:end]


def parse_client_hello(data: bytes) -> ClientHello | None:
    """Parse a TLS ClientHello from raw bytes.

    ``data`` may be either a complete TLS record (starting with the
    5-byte record header) or the raw handshake payload. The parser
    auto-detects which form was given.

    Never raises: returns ``None`` on any structural error.
    """
    try:
        payload: bytes | None = (
            parse_tls_record(data) if data and data[0] == TLS_RECORD_HANDSHAKE else data
        )
        if not payload or len(payload) < 4:
            return None
        r = _Reader(payload)
        hs_type = r.read_u8()
        if hs_type != TLS_HANDSHAKE_CLIENT_HELLO:
            return None
        hs_len = r.read_u24()
        if hs_len > r.remaining():
            return None
        legacy_version = r.read_u16()
        random = r.read(32)
        session_id = r.read_vec_u8()
        ciphers = _parse_u16_list(r.read_vec_u16())
        compression = tuple(r.read_vec_u8())
        if r.remaining() < 2:
            # No extensions. Legal in TLS 1.0 but unusual today.
            return ClientHello(
                legacy_version=legacy_version,
                random=random,
                session_id=session_id,
                cipher_suites=ciphers,
                compression_methods=compression,
                extensions=(),
            )
        ext_blob = r.read_vec_u16()
        ext_types, sni, groups, point_formats, sig_algs, alpn, versions = _parse_extensions(
            ext_blob
        )
        return ClientHello(
            legacy_version=legacy_version,
            random=random,
            session_id=session_id,
            cipher_suites=ciphers,
            compression_methods=compression,
            extensions=ext_types,
            server_name=sni,
            supported_groups=groups,
            ec_point_formats=point_formats,
            signature_algorithms=sig_algs,
            alpn_protocols=alpn,
            supported_versions=versions,
        )
    except (ValueError, struct.error, IndexError) as exc:
        logger.debug("ClientHello parse failed: %s", exc)
        return None
