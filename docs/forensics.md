# Forensics & Replay

The `honeytrap.forensics` subsystem captures every byte of every
attacker session and lets you replay, search, or export it for use
with downstream forensic tools. Everything in this guide ships with
the base install — no extra dependencies are needed.

## What gets recorded

Every protocol handler emits inbound and outbound `SessionFrame`
records into a `SessionRecorder`. Each frame carries:

- a stable `session_id` for the conversation,
- a monotonic `timestamp_ns`,
- the raw `payload` bytes (untouched, unredacted),
- direction (`INBOUND` or `OUTBOUND`),
- 5-tuple (source/dest IP, port) and protocol name,
- an `is_tls_handshake` flag for the TLS peek bytes.

The recorder is *passive* — protocol handlers continue to write to
their existing event paths. If forensic recording is disabled or the
resource guardian is under pressure, frames are silently dropped and
the rest of the engine is unaffected.

## Configuration

```yaml
forensics:
  enabled: true              # turn the recorder on or off
  store: jsonl               # jsonl | sqlite
  path: ./sessions           # relative paths land under log_directory
  max_session_bytes: 10485760    # 10 MiB per session
  max_daily_bytes: 1073741824    # 1 GiB per day
  retention_days: 30
  record_tls_handshake: true     # set false to skip the peek bytes
```

When `path` is relative, the engine roots it under `general.log_directory`
so the data lives next to your existing logs.

## Storage backends

### `jsonl` (default)

One gzipped newline-delimited JSON file per session, partitioned by
UTC date:

```
sessions/
  2026/
    04/
      22/
        ssh-7c1a8b.jsonl.gz
        http-3f9e2d.jsonl.gz
```

Each file holds:

- a `meta` row at session open,
- one `frame` row per recorded payload (base64-encoded),
- a `meta_close` row at shutdown.

The file is concatenation-safe — multiple sessions can be merged into
one stream by appending the gzip blobs.

### `sqlite`

A single WAL-mode SQLite database at `path/sessions.db` with three
tables: `sessions`, `frames`, and `metadata`. Use this when you want
indexed lookups by `remote_ip`, `started_at`, or `session_id` and
can spare the slightly higher write cost.

## Truncation

Two caps protect the disk:

- **per-session** (default 10 MiB) — caps a single noisy attacker.
- **per-day** (default 1 GiB) — caps the whole node.

When either cap fires the recorder switches the affected session to
**sampling mode**: it keeps the first 100 and last 100 frames in
memory and writes a `truncated=true` marker so you always know the
record is incomplete. The tail frames are flushed when the session
closes; the head frames are flushed when sampling first kicks in.

## Replay & export

### CLI

```
honeytrap export list                                # show recorded sessions
honeytrap export pcap     --session ssh-7c1a8b --out cap.pcap
honeytrap export jsonl    --session ssh-7c1a8b --out cap.jsonl.gz
honeytrap export timeline --session ssh-7c1a8b              # text to stdout
honeytrap export timeline --session ssh-7c1a8b --format html --out tl.html
honeytrap export pcap     --ip 198.51.100.7 --since 2026-04-22T00:00:00Z \
                                                  --out campaign.pcap
```

Add `--no-redact` to `timeline` to keep credentials in the
human-readable description. Frame payloads are never redacted in any
export.

### HTML report

`render_html_with_sessions` materializes a `sessions/` directory next
to the main report containing:

- `sessions/<id>.html` — the timeline page (dark theme, no external
  assets),
- `sessions/<id>.pcap` — the PCAP-lite file,
- `sessions/<id>.jsonl.gz` — the gzipped JSONL.

A `Forensic Session Replays` table at the bottom of the main report
links to each.

### TUI

Open the dashboard, press Enter on a session row, and use the Replay
tab:

| Key       | Action                       |
|-----------|------------------------------|
| `space`   | Play / pause                 |
| `right`   | Step one frame forward       |
| `left`    | Step one frame back          |
| `>`       | Increase playback speed      |
| `<`       | Decrease playback speed      |
| `e`       | Export the session as PCAP   |
| `E`       | Export the session as JSONL  |

Speed cycles through `0.25x, 0.5x, 1.0x, 2.0x, 4.0x, 8.0x`. Exports
land in the working directory (or whichever directory the modal was
constructed with).

## PCAP-lite — what it is and isn't

The PCAP writer produces a libpcap capture (magic `0xa1b2c3d4`,
linktype `1` Ethernet) that opens cleanly in Wireshark and `tshark`.
Because the engine sees application-layer frames, the writer
*synthesizes* the missing transport metadata:

- a SYN / SYN-ACK / ACK three-way handshake,
- one TCP segment per MSS-sized chunk (default 1460 bytes) with
  monotonic per-side sequence numbers,
- correct IP and TCP one's complement checksums,
- a FIN / ACK / FIN / ACK / ACK teardown,
- IPv4 *and* IPv6 (the writer chooses based on the recorded
  addresses).

This is a *faithful reconstruction*, not a packet-for-packet trace.
Anything that depends on real TCP timing (retransmits, RTT analysis)
will be misleading. Everything that depends on the application bytes
(IDS rules, malware detonation, content carving) works exactly as it
would on a real capture.

## Metrics

```
honeytrap_sessions_recorded_total{protocol="ssh"}
honeytrap_sessions_truncated_total{reason="session_cap"}
honeytrap_session_bytes_total{protocol="ssh",direction="INBOUND"}
honeytrap_pcap_exports_total
honeytrap_session_duration_seconds_bucket{le="1.0"}
honeytrap_session_duration_seconds_count
honeytrap_session_duration_seconds_sum
```

The histogram uses the default Prometheus buckets. Counters are
labeled by protocol/direction so a Grafana dashboard can drill down
to a single handler.

## Retention

The engine runs `store.sweep_retention(retention_days)` once at
startup and then every 24 hours. The sweep removes session files
(JSONL) or rows (SQLite) whose start time is older than
`retention_days`. Set `retention_days: 0` to disable.

## Privacy & redaction

Recorded payloads are stored verbatim. The default `Timeline` output
redacts `password=`, `secret=`, `token=`, `Authorization:` headers,
and `USER … PASS …` pairs from the *human-readable description only*
— the underlying frame bytes are preserved so a PCAP export still
contains everything an analyst needs.

If you re-distribute exports outside the SOC, run them through your
existing redaction pipeline first.
