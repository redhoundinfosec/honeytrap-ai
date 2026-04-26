# IMAP4rev1 honeypot

`honeytrap.protocols.imap_handler` ships a custom asyncio implementation
of just enough of [RFC 3501](https://datatracker.ietf.org/doc/html/rfc3501)
and [RFC 2595](https://datatracker.ietf.org/doc/html/rfc2595) (STARTTLS)
to keep credential-spraying tooling and email-collection scrapers
engaged.

## Implemented commands

- `CAPABILITY`, `NOOP`, `LOGOUT`, `ID`, `ENABLE`
- `STARTTLS` (advertised — the cipher upgrade is captured via
  [`tls_peek`](../../src/honeytrap/protocols/tls_peek.py) so JA3/JA4 land
  in the same event the IMAP session is recorded in)
- `LOGIN` and `AUTHENTICATE PLAIN` (RFC 4616 SASL)
- `LIST`, `LSUB`, `STATUS`, `SELECT`, `EXAMINE`, `CLOSE`, `EXPUNGE`,
  `SEARCH`
- `FETCH N BODY[HEADER]` and `FETCH N RFC822`

Anything we do not recognize gets a tagged `BAD Unknown command` so the
connection stays alive long enough for an analyst to see what the
attacker tried next.

## Profile fields

```yaml
- protocol: imap
  port: 143
  banner: "* OK [CAPABILITY IMAP4rev1 STARTTLS ...] Dovecot ready."
  hostname: "mail.example.com"
  starttls_enabled: true
  capabilities: ["IMAP4rev1", "STARTTLS", "AUTH=PLAIN", ...]
  mailbox_fixture: "mailboxes/mail_server.yaml"   # YAML under profiles/
  weak_credentials:
    - { username: admin,      password: admin }
  ai_personality: |
    You are a Dovecot IMAP4rev1 server.
```

`mailbox_fixture` points at a YAML file under `profiles/` whose top
level is a `messages:` list — see
`profiles/mailboxes/mail_server.yaml` and
`profiles/mailboxes/full_enterprise.yaml` for examples.

## ATT&CK mappings

Every emitted event is run through the ATT&CK mapper:

- `auth_attempt` → T1110.001 (and T1110.004 with weak creds), T1078
- `select` / `examine` / `fetch` / `search` / `list` → T1114, T1114.002
- `starttls` → T1071

## Limits

- Per-connection input buffer cap: 256 KiB.
- Idle timeout: `timeouts.imap_idle` in `honeytrap.yaml`
  (default 300 s).
