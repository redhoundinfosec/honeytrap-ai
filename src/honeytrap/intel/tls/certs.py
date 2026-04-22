"""Lightweight in-memory self-signed certificates for TLS listeners.

``cryptography`` is already present in our runtime environment via
transitive dependencies; we use it when available to avoid shipping a
binary certificate in the repo. When it is not importable we fall
back to the pre-baked certificate+key under ``_selfsigned/``, which
can be regenerated with ``scripts/gen_selfsigned.py``.
"""

from __future__ import annotations

import datetime as _dt
import logging
import ssl
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

_SELFSIGNED_DIR: Path = Path(__file__).with_name("_selfsigned")


def _try_generate_runtime() -> tuple[bytes, bytes] | None:
    """Generate a fresh self-signed cert with ``cryptography``.

    Returns ``(cert_pem, key_pem)`` or ``None`` if the dependency is
    not available or generation fails.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError:  # pragma: no cover - exercised only when cryptography missing
        return None
    try:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "honeytrap.local")])
        now = _dt.datetime.now(_dt.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(minutes=5))
            .not_valid_after(now + _dt.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("honeytrap.local")]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return cert_pem, key_pem
    except Exception as exc:  # noqa: BLE001 - never propagate, fall back to pre-baked
        logger.warning("Runtime self-signed cert generation failed: %s", exc)
        return None


def _load_prebaked() -> tuple[bytes, bytes] | None:
    cert = _SELFSIGNED_DIR / "cert.pem"
    key = _SELFSIGNED_DIR / "key.pem"
    if cert.is_file() and key.is_file():
        return cert.read_bytes(), key.read_bytes()
    return None


def build_server_context() -> ssl.SSLContext | None:
    """Return a server :class:`ssl.SSLContext` for TLS listeners.

    Prefers runtime-generated certificates; falls back to the
    pre-baked pair. Returns ``None`` when neither is available so
    callers can gracefully skip TLS listeners rather than crash.
    """
    material = _try_generate_runtime() or _load_prebaked()
    if material is None:
        logger.warning("No TLS certificate available; TLS listeners will be disabled")
        return None
    cert_pem, key_pem = material
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    with (
        tempfile.NamedTemporaryFile("wb", delete=False) as cert_file,
        tempfile.NamedTemporaryFile("wb", delete=False) as key_file,
    ):
        cert_file.write(cert_pem)
        cert_path = cert_file.name
        key_file.write(key_pem)
        key_path = key_file.name
    try:
        ctx.load_cert_chain(cert_path, key_path)
    finally:
        try:
            Path(cert_path).unlink(missing_ok=True)
            Path(key_path).unlink(missing_ok=True)
        except OSError:  # pragma: no cover - best-effort cleanup
            pass
    return ctx
