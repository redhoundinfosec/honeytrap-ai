# MQTT honeypot

`honeytrap.protocols.mqtt_handler` exposes a TCP MQTT broker that
speaks both [MQTT 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html)
and [MQTT 5.0](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html).
The wire-format helpers (`parse_connect`, `parse_publish`,
`parse_subscribe`, `build_connack`, `build_suback`, `build_puback`,
`build_pubrec`, `build_pingresp`) are all exported so they can be
unit-tested without spinning up the listener.

## Captured artifacts

- `client_id`, `username`, `password`, `keepalive`, `flags`
- Will topic / payload (preview capped at 256 bytes; full size logged)
- Subscribed filters and their requested QoS
- PUBLISH topics, QoS, retain/dup flags, and a 512-byte payload
  preview
- Detection of scanner-like client IDs (`mosquitto_sub`,
  `mqtt-explorer`, `paho`, `iotsearch`, …) and empty client IDs
- Detection of C2-style topics (`/cmd`, `/exec`, `/ota`,
  `/firmware/upload`, `/c2`, `/control`)

## Profile fields

```yaml
- protocol: mqtt
  port: 1883
  server_name: "gateway-01"
  mqtt_version: "3.1.1"
  require_auth: true
  accept_any_credentials: true
  ghost_publishing: false
  ghost_messages:
    - { topic: "home/alarm/status", payload: "disabled" }
  weak_credentials:
    - { username: mqtt, password: mqtt }
```

## ATT&CK mappings

- `mqtt_connect` → T1071 (and T1110.004 with weak creds)
- `auth_attempt` → T1110.001
- `publish` / `subscribe` → T1071 (and T1190 if the topic looks C2)

## Alert rules

- `rule_mqtt_c2_topic` — HIGH when a publish/subscribe targets a
  C2-style topic.
- `rule_mqtt_scanner_client` — MEDIUM when the client_id matches a
  scanner prefix or is empty.

## Limits

- Per-connection input buffer cap: 256 KiB (handler-side).
- Idle timeout: `timeouts.mqtt_idle` (default 120 s).
