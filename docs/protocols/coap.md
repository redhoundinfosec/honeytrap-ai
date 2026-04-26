# CoAP honeypot

`honeytrap.protocols.coap_handler` implements a UDP
[CoAP / RFC 7252](https://datatracker.ietf.org/doc/html/rfc7252)
listener. The asyncio `DatagramProtocol` parses each datagram with
`parse_message`, dispatches into the resource handler, and replies with
a CoRE-format response built by `build_response` (delta-encoded
options).

## Resources we serve

- `/sensors/temp`, `/sensors/humidity` — randomized but stable values
- `/actuators/light`, `/actuators/relay/0` — stub endpoints
- `/fw/version` — fake firmware version string
- `/.well-known/core` — link-format directory of the above

## Sensitive-path detection

Any request whose URI path contains `config`, `credential`, `secret`,
`token`, `fw/upload`, `fw/update`, or `firmware/upload` raises a
MEDIUM alert via `rule_coap_sensitive_path`. Reflection-style probes
(very short request, very large response template) raise the
`amplification_probe` event and a HIGH `rule_coap_amplification` alert.

## Per-source rate limiting

`_PerSourceRateLimiter` caps each source IP at 60 packets per second
by default (`max_packets_per_second` in the profile). Excess packets
are dropped silently — CoAP runs over UDP, so silent drops are the
RFC-compliant response when the server is overloaded.

## Malformed input

Per RFC 7252 §4.2/§4.3:

- Malformed `CON` requests are answered with an RST.
- Malformed `NON` requests are silently dropped.

Both paths emit a `coap_malformed` event so analysts can still see the
attempt.

## DTLS (port 5684)

The current cycle implements clear-text CoAP only. The bundled
`iot_industrial` profile listens on UDP/5684 in a `log_only` mode that
records DTLS ClientHellos but does not complete the handshake — full
DTLS support is queued for the next cycle (see `ROADMAP.md`).

## Profile fields

```yaml
- protocol: coap
  port: 5683
  max_packets_per_second: 60
  temperature_c: 22.5
  humidity_pct: 51.0
  firmware_version: "industrial-gw-2.7.1"
  resources:
    - "</sensors/temp>;rt=\"temperature\";if=\"sensor\";obs"
    - "</fw/version>;rt=\"firmware\";if=\"info\""
```

## ATT&CK mappings

- `coap_request` → T1071.001
- Sensitive paths → T1602
- Firmware-upload paths → T1190
- `amplification_probe` → T1190
