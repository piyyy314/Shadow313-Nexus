# Platform event bus persistence and API security

The canonical `shadow313_platform.event_bus` publisher is backed by SQLite
with WAL journaling and bounded retention. The default database is
`~/.shadow313/platform-events.sqlite3`; override it with
`SHADOW313_EVENT_STORE_PATH`. The database file is created with owner-only
permissions. Configure persistent storage on a durable local volume before
relying on events for incident evidence.

The event REST API exposes a public, non-sensitive `/api/health` endpoint.
All event query, statistics, and publish endpoints require the
`x-api-key` header. If `SHADOW313_EVENT_BUS_API_KEY` is not configured,
data routes return HTTP 503 and remain unavailable. Invalid keys return 401.
Event payloads are capped at 64 KiB and metadata fields are validated.

Example request:

```bash
curl -H "x-api-key: $SHADOW313_EVENT_BUS_API_KEY" \
  -H "content-type: application/json" \
  -d '{"event_type":"detection.alert","source":"sensor-01","severity":"HIGH","payload":{"technique_id":"T1059"}}' \
  http://127.0.0.1:8000/api/events/publish
```

The service binds to loopback by default. If it must be exposed remotely, use
TLS termination, network access controls, key rotation, and a managed durable
volume. SQLite persistence is a local durable store, not a distributed event
stream or a replacement for a replicated message broker.
