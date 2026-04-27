"""Generate synthetic but realistic ClientHello fixtures.

Rather than committing captured pcaps, we emit deterministic
ClientHello bytes that exercise every branch of the parser and the
JA3/JA4 hashers. Run this once to regenerate all ``*.bin`` files in
this directory.
"""

from __future__ import annotations

import struct
from pathlib import Path

HERE = Path(__file__).parent


def _u8(n: int) -> bytes:
    return bytes([n & 0xFF])


def _u16(n: int) -> bytes:
    return struct.pack(">H", n & 0xFFFF)


def _u24(n: int) -> bytes:
    return bytes([(n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])


def _vec_u8(data: bytes) -> bytes:
    return _u8(len(data)) + data


def _vec_u16(data: bytes) -> bytes:
    return _u16(len(data)) + data


def _u16_list(values: list[int]) -> bytes:
    return b"".join(_u16(v) for v in values)


def _extension(ext_type: int, body: bytes) -> bytes:
    return _u16(ext_type) + _vec_u16(body)


def _ext_sni(host: str) -> bytes:
    host_bytes = host.encode("ascii")
    server_name = _u8(0) + _vec_u16(host_bytes)
    return _extension(0x0000, _vec_u16(server_name))


def _ext_supported_groups(groups: list[int]) -> bytes:
    return _extension(0x000A, _vec_u16(_u16_list(groups)))


def _ext_ec_point_formats(formats: list[int]) -> bytes:
    return _extension(0x000B, _vec_u8(bytes(formats)))


def _ext_signature_algorithms(algs: list[int]) -> bytes:
    return _extension(0x000D, _vec_u16(_u16_list(algs)))


def _ext_alpn(protos: list[str]) -> bytes:
    body = b"".join(_vec_u8(p.encode("ascii")) for p in protos)
    return _extension(0x0010, _vec_u16(body))


def _ext_supported_versions(versions: list[int]) -> bytes:
    return _extension(0x002B, _vec_u8(_u16_list(versions)))


def _client_hello(
    *,
    legacy_version: int,
    ciphers: list[int],
    extensions: list[bytes],
    session_id: bytes = b"",
    random_byte: int = 0x11,
) -> bytes:
    random_ = bytes([random_byte]) * 32
    body = (
        _u16(legacy_version)
        + random_
        + _vec_u8(session_id)
        + _vec_u16(_u16_list(ciphers))
        + _vec_u8(bytes([0]))  # single compression method: null
        + _vec_u16(b"".join(extensions))
    )
    handshake = _u8(0x01) + _u24(len(body)) + body
    record = _u8(0x16) + _u16(0x0301) + _vec_u16(handshake)
    return record


def build_firefox() -> bytes:
    ciphers = [
        0x1301,
        0x1303,
        0x1302,
        0xC02B,
        0xC02F,
        0xCCA9,
        0xCCA8,
        0xC02C,
        0xC030,
        0xC013,
        0xC014,
        0x009C,
        0x009D,
        0x002F,
        0x0035,
    ]
    exts = [
        _ext_sni("www.mozilla.org"),
        _ext_supported_groups([0x001D, 0x0017, 0x0018]),
        _ext_ec_point_formats([0, 1, 2]),
        _ext_signature_algorithms([0x0403, 0x0503, 0x0603, 0x0804]),
        _ext_alpn(["h2", "http/1.1"]),
        _ext_supported_versions([0x0304, 0x0303]),
    ]
    return _client_hello(legacy_version=0x0303, ciphers=ciphers, extensions=exts)


def build_chrome() -> bytes:
    ciphers = [
        0x0A0A,  # GREASE, must be filtered
        0x1301,
        0x1302,
        0x1303,
        0xC02B,
        0xC02F,
        0xC02C,
        0xC030,
        0xCCA9,
        0xCCA8,
        0xC013,
        0xC014,
        0x009C,
        0x009D,
        0x002F,
        0x0035,
    ]
    exts = [
        _extension(0xAAAA, b""),  # GREASE extension
        _ext_sni("www.google.com"),
        _ext_supported_groups([0x1A1A, 0x001D, 0x0017]),
        _ext_ec_point_formats([0]),
        _ext_signature_algorithms([0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501]),
        _ext_alpn(["h2", "http/1.1"]),
        _ext_supported_versions([0x2A2A, 0x0304, 0x0303]),
    ]
    return _client_hello(legacy_version=0x0303, ciphers=ciphers, extensions=exts)


def build_curl() -> bytes:
    ciphers = [
        0x1302,
        0x1303,
        0x1301,
        0xC02C,
        0xC030,
        0x009F,
        0xCCA9,
        0xCCA8,
        0xCCAA,
        0xC02B,
    ]
    exts = [
        _ext_sni("example.com"),
        _ext_supported_groups([0x001D, 0x0017, 0x0018, 0x0019]),
        _ext_ec_point_formats([0, 1, 2]),
        _ext_signature_algorithms([0x0403, 0x0503, 0x0603]),
        _ext_alpn(["h2", "http/1.1"]),
        _ext_supported_versions([0x0304, 0x0303, 0x0302]),
    ]
    return _client_hello(legacy_version=0x0303, ciphers=ciphers, extensions=exts)


def build_python_requests() -> bytes:
    ciphers = [
        0xC02C,
        0xC030,
        0x009F,
        0xCCA9,
        0xCCA8,
        0xCCAA,
        0xC02B,
        0xC02F,
        0x009E,
        0xC024,
        0xC028,
        0x006B,
        0xC023,
        0xC027,
        0x0067,
        0xC00A,
        0xC014,
        0x0039,
        0xC009,
        0xC013,
        0x0033,
        0x009D,
        0x009C,
        0x003D,
        0x003C,
        0x0035,
        0x002F,
        0x00FF,
    ]
    exts = [
        _ext_sni("pypi.org"),
        _ext_supported_groups([0x001D, 0x0017, 0x001E, 0x0019, 0x0018]),
        _ext_ec_point_formats([0, 1, 2]),
        _ext_signature_algorithms([0x0603, 0x0503, 0x0403, 0x0203]),
        _ext_supported_versions([0x0303, 0x0302, 0x0301]),
    ]
    return _client_hello(legacy_version=0x0303, ciphers=ciphers, extensions=exts)


def build_go_http() -> bytes:
    ciphers = [
        0x1301,
        0x1302,
        0x1303,
        0xC02F,
        0xC02B,
        0xC030,
        0xC02C,
        0xCCA9,
        0xCCA8,
        0xC013,
        0xC009,
        0xC014,
        0xC00A,
        0x009C,
        0x009D,
        0x002F,
        0x0035,
        0xC012,
        0x000A,
    ]
    exts = [
        _ext_sni("golang.org"),
        _ext_supported_groups([0x001D, 0x0017, 0x0018]),
        _ext_ec_point_formats([0]),
        _ext_signature_algorithms([0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501]),
        _ext_alpn(["h2", "http/1.1"]),
        _ext_supported_versions([0x0304, 0x0303, 0x0302, 0x0301]),
    ]
    return _client_hello(legacy_version=0x0303, ciphers=ciphers, extensions=exts)


def build_nmap() -> bytes:
    # Small cipher set, no SNI, no supported_versions: tell-tale of
    # the nmap ssl-enum-ciphers probe.
    ciphers = [
        0xC02B,
        0xC02F,
        0xCCA9,
        0xCCA8,
        0xC013,
        0xC014,
        0x009C,
        0x002F,
        0x0035,
    ]
    exts = [
        _ext_supported_groups([0x0017, 0x0018]),
        _ext_ec_point_formats([0]),
        _ext_signature_algorithms([0x0403, 0x0503]),
    ]
    return _client_hello(legacy_version=0x0303, ciphers=ciphers, extensions=exts)


def build_masscan() -> bytes:
    # masscan sends a very small TLS 1.0 ClientHello with no
    # extensions beyond the minimal ones.
    ciphers = [0x002F, 0x0035]
    exts = [_ext_supported_groups([0x0017])]
    return _client_hello(legacy_version=0x0301, ciphers=ciphers, extensions=exts)


def build_malformed_short() -> bytes:
    return b"\x16\x03\x01"


def build_non_tls() -> bytes:
    return b"GET / HTTP/1.1\r\nHost: honeytrap.local\r\n\r\n"


def main() -> None:
    outputs: dict[str, bytes] = {
        "firefox.bin": build_firefox(),
        "chrome.bin": build_chrome(),
        "curl.bin": build_curl(),
        "python_requests.bin": build_python_requests(),
        "go_http.bin": build_go_http(),
        "nmap.bin": build_nmap(),
        "masscan.bin": build_masscan(),
        "malformed_short.bin": build_malformed_short(),
        "non_tls.bin": build_non_tls(),
    }
    for name, data in outputs.items():
        (HERE / name).write_bytes(data)
        print(f"wrote {name}: {len(data)} bytes")


if __name__ == "__main__":
    main()
