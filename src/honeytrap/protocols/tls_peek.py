"""Non-intrusive TLS ClientHello peek for honeypot listeners.

The helper reads up to 16 KiB of the first network record from an
attacker, classifies it as either TLS or plaintext, and (for TLS)
computes a JA3/JA4 fingerprint. The captured bytes are always
returned so the downstream protocol handler can still process the
connection -- for plaintext traffic this preserves the normal flow,
and for TLS traffic it lets a handler either complete a real
handshake against a self-signed cert or respond with a plausible
alert.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

from honeytrap.intel.tls.clienthello import TLS_RECORD_HANDSHAKE
from honeytrap.intel.tls.fingerprinter import FingerprintResult, TLSFingerprinter

logger = logging.getLogger(__name__)

MAX_PEEK_BYTES: int = 16 * 1024
DEFAULT_TIMEOUT_SECONDS: float = 5.0


@dataclass
class TLSPeekResult:
    """Outcome of a single peek.

    ``fingerprint`` is set when a ClientHello was observed and
    successfully parsed. ``consumed_bytes`` contains every byte read
    off the socket -- callers must hand these to the downstream
    handler so no data is lost.
    """

    consumed_bytes: bytes
    fingerprint: FingerprintResult | None
    is_tls: bool
    timed_out: bool = False


async def peek_tls_client_hello(
    reader: asyncio.StreamReader,
    fingerprinter: TLSFingerprinter,
    *,
    max_bytes: int = MAX_PEEK_BYTES,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> TLSPeekResult:
    """Peek at the beginning of a stream and classify it.

    * If the first byte is a TLS handshake content type (``0x16``),
      keep reading until the full record length is satisfied or the
      ``max_bytes`` cap is hit, then attempt to fingerprint.
    * Otherwise return the bytes read so the downstream handler can
      parse them as a plaintext protocol.

    Partial reads (short ``reader.read`` returns) are handled by an
    internal loop that respects both the byte cap and the per-peek
    timeout. A missed handshake never propagates an exception.
    """
    buf = bytearray()
    timed_out = False
    record_target: int | None = None
    try:
        while len(buf) < max_bytes:
            remaining = max_bytes - len(buf)
            chunk = await asyncio.wait_for(reader.read(remaining), timeout=timeout)
            if not chunk:
                break
            buf.extend(chunk)
            if not buf:
                break
            if buf[0] != TLS_RECORD_HANDSHAKE:
                # Not TLS; stop reading and hand everything back.
                return TLSPeekResult(consumed_bytes=bytes(buf), fingerprint=None, is_tls=False)
            if len(buf) >= 5 and record_target is None:
                record_target = 5 + ((buf[3] << 8) | buf[4])
                record_target = min(record_target, max_bytes)
            if record_target is not None and len(buf) >= record_target:
                break
    except asyncio.TimeoutError:
        timed_out = True
    except (ConnectionError, OSError) as exc:
        logger.debug("tls_peek read failed: %s", exc)

    if not buf:
        return TLSPeekResult(
            consumed_bytes=b"", fingerprint=None, is_tls=False, timed_out=timed_out
        )
    if buf[0] != TLS_RECORD_HANDSHAKE:
        return TLSPeekResult(
            consumed_bytes=bytes(buf), fingerprint=None, is_tls=False, timed_out=timed_out
        )
    result = fingerprinter.fingerprint(bytes(buf))
    return TLSPeekResult(
        consumed_bytes=bytes(buf),
        fingerprint=result,
        is_tls=True,
        timed_out=timed_out,
    )
