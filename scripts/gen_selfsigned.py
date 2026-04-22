"""Generate the pre-baked self-signed certificate shipped with the package.

Run manually when the embedded certificate approaches expiry::

    python scripts/gen_selfsigned.py

Writes ``src/honeytrap/intel/tls/_selfsigned/cert.pem`` and ``key.pem``.
Requires the ``cryptography`` package (already a transitive runtime
dependency via other libraries in the project).
"""

from __future__ import annotations

import datetime as _dt
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

OUT_DIR = (
    Path(__file__).resolve().parents[1] / "src" / "honeytrap" / "intel" / "tls" / "_selfsigned"
)


def main() -> None:
    """Emit a fresh cert+key pair to the bundled directory."""
    OUT_DIR.mkdir(parents=True, exist_ok=True)
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
        .not_valid_after(now + _dt.timedelta(days=3650))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("honeytrap.local")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    (OUT_DIR / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (OUT_DIR / "key.pem").write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    print(f"wrote {OUT_DIR}/cert.pem and key.pem")


if __name__ == "__main__":
    main()
