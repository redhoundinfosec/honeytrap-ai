# RDP signature honeypot

`honeytrap.protocols.rdp_handler` runs a *signature-only* RDP listener.
The handler intentionally never moves past the early handshake — it
captures the X.224 Connection Request, optionally completes the
Connection Confirm with `PROTOCOL_SSL`, then peeks at the attacker's
TLS ClientHello and any NTLM `NEGOTIATE_MESSAGE` carried inside the
CredSSP blob. After that the connection is closed.

This is the right design for a honeypot: real RDP is too complex to
emulate safely, but the handshake alone yields high-signal data —
`mstshash` cookies, requested security types, NTLM workstation/domain,
and a JA3/JA4 fingerprint of the attacker's TLS stack.

## What we capture

- `mstshash=` cookie from the X.224 CR-TPDU (often hand-set by
  scanners — *KALI*, *WIN-RANDOM*, *parrot*, etc.)
- `rdpNegReq` requested security types
- TLS ClientHello (JA3 / JA4) once the Connection Confirm chooses
  `PROTOCOL_SSL`
- NTLM `NEGOTIATE_MESSAGE` workstation, domain, and flags
- Auth attempts when the attacker tooling pushes credentials in the
  CredSSP layer

## Profile fields

```yaml
- protocol: rdp
  port: 3389
  server_name: "DESKTOP-N7K2P9X"
  domain: "WORKGROUP"
  os_version: "Windows 10 22H2 (build 19045)"
  request_tls: true
  nla_required: false
  weak_credentials:
    - { username: Administrator, password: P@ssw0rd }
```

## ATT&CK mappings

- `x224_connect_request` → T1021.001 (RDP), T1078 if a cookie is present
- `ntlm_negotiate` / `credssp` → T1021.001, T1078
- `auth_attempt` → T1110.001 (T1110.004 with weak creds)

## Alert rules

- `rule_rdp_scanner_cookie` — MEDIUM when the parsed cookie matches a
  known scanner pattern.

## Limits

- Per-connection input buffer cap: 256 KiB.
- Idle timeout: `timeouts.rdp_idle` (default 30 s).
