# ShiatoAli SOC service (first vertical slice)

ShiatoAli is being added as an additive SOC operations layer inside Shadow313
NEXUS. This first service provides durable local event ingestion, a small
defensive detection pack, and queryable alerts.

## API

All endpoints require the existing Shadow313 API authentication dependency.

- `GET /api/shiatoali/health` — service and record counts
- `POST /api/shiatoali/events` — validate, persist, and evaluate one event
- `GET /api/shiatoali/events?limit=100&offset=0` — newest events
- `GET /api/shiatoali/alerts?limit=100&offset=0` — newest alerts

Example event:

```json
{
  "source": "windows",
  "host": "workstation-01",
  "event_type": "process_creation",
  "message": "powershell.exe -EncodedCommand <redacted>",
  "severity": "medium",
  "username": "analyst",
  "event_id": "source-generated-unique-id"
}
```

A source-generated `event_id` is recommended. Replays with the same ID are
idempotent. Five authentication failures for the same host in a rolling
10-minute window produce a brute-force alert. Other starter rules detect
encoded/suspicious PowerShell, possible web-shell indicators, and network
discovery utilities. These are triage signals, not proof of compromise.

## Storage and deployment

The service uses SQLite and the Python standard library by default. Set
`SHIAATOALI_DB_PATH` to choose a persistent path. The default is
`~/.shadow313/shiatoali.sqlite3`. Mount that directory as a persistent volume
when running in a container.

SQLite is suitable for a single-instance starter deployment. Before running
multiple API workers or replicas, migrate the store to PostgreSQL and add
distributed rate limits, migrations, retention policies, and a managed
backup/restore procedure.

## Current limitations

- No endpoint agent or automatic host isolation is included.
- No external reputation enrichment is performed.
- Detection rules are starter rules, not a full Sigma implementation.
- This service does not claim to provide a complete SIEM or production SOC.
- Keep the API behind authentication and TLS; do not expose the database file.
