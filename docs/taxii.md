# TAXII 2.1 Server

HoneyTrap serves a read-only TAXII 2.1 root at `/taxii/2.1` on the
existing management API. This lets analyst clients (OpenCTI, MISP, custom
SIEM connectors) pull STIX bundles using the same authentication model as
the rest of the API.

The implementation is read-only by design — there is no `POST /objects`
endpoint and no async write status. Writes are out of scope for a
honeypot-side feed.

## Endpoints

All endpoints require an API key with at least the `viewer` role. Responses
carry the spec-mandated `application/taxii+json;version=2.1` content type.

| Endpoint | Purpose |
| --- | --- |
| `GET /taxii/2.1/` | Discovery (lists `api_roots`). |
| `GET /taxii/2.1/honeytrap/` | API-root metadata. |
| `GET /taxii/2.1/honeytrap/collections/` | Collection list. |
| `GET /taxii/2.1/honeytrap/collections/{id}/` | Collection metadata. |
| `GET /taxii/2.1/honeytrap/collections/{id}/objects/` | Paginated STIX objects. |
| `GET /taxii/2.1/honeytrap/collections/{id}/objects/{oid}/` | Single object. |
| `GET /taxii/2.1/honeytrap/collections/{id}/manifest/` | Manifest entries. |
| `GET /taxii/2.1/honeytrap/status/{status_id}/` | Synthetic `complete` status. |

## Collections

Collections are split by SDO family so clients can subscribe to just the
slice they care about:

| Short name | Stable id | Object types |
| --- | --- | --- |
| `indicators` | `12345678-0001-4000-8000-000000000001` | `indicator`, `relationship` |
| `attack-patterns` | `12345678-0002-4000-8000-000000000002` | `attack-pattern` |
| `observed-data` | `12345678-0003-4000-8000-000000000003` | `observed-data` |
| `sightings` | `12345678-0004-4000-8000-000000000004` | `sighting` |
| `notes` | `12345678-0005-4000-8000-000000000005` | `note`, `identity`, `infrastructure`, `campaign`, `malware` |

The collection ids are stable across restarts so external clients can hard
code them.

## Filtering and pagination

`GET .../objects/` honours the spec query parameters:

- `match[id]=<stix-id>` — repeatable, OR semantics.
- `match[type]=<type>` — repeatable, OR semantics.
- `added_after=<iso-timestamp>` — return objects whose `modified` is later.
- `limit=<n>` — clamp the page size (1..1000).
- `next=<token>` — opaque cursor returned in the prior response.

The envelope returned is:

```json
{ "more": true, "next": "20", "objects": [...] }
```

When `more` is `false`, `next` is omitted.

## Metrics

Each request increments `honeytrap_taxii_requests_total{endpoint, status}`.
Endpoint labels are: `discovery`, `root`, `collections`, `collection`,
`objects`, `object`, `manifest`, `status`.

## Example session (curl)

```bash
TOKEN=$(honeytrap apikeys create viewer-bot viewer | jq -r .token)

curl -sH "X-API-Key: $TOKEN" https://api.example/taxii/2.1/ | jq .
curl -sH "X-API-Key: $TOKEN" \
  https://api.example/taxii/2.1/honeytrap/collections/12345678-0001-4000-8000-000000000001/objects/?limit=50 \
  | jq .
```
