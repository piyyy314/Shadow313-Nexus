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

The service uses SQLite by default. Set `SHIAATOALI_DB_PATH` to choose a
persistent path. The default is `~/.shadow313/shiatoali.sqlite3`. Mount that
directory as a persistent volume when running in a container.

For a shared PostgreSQL deployment, install `.[postgres]`, set
`SHIAATOALI_DATABASE_URL` to a `postgresql+psycopg://` URL, and apply the
schema first with `alembic -c alembic-shiatoali.ini upgrade head`. At startup,
the service selects PostgreSQL when this variable is set and fails clearly if
the schema is missing. Otherwise it continues using SQLite. The two settings
are mutually exclusive in practice: an explicitly supplied SQLite path takes
precedence for direct store construction.

The PostgreSQL adapter provides transactional database access, but production
readiness still requires real-PostgreSQL integration/concurrency testing,
distributed rate limits, retention policies, managed backups, monitoring,
restore drills, and deployment health checks.

## Current limitations

- No endpoint agent or automatic host isolation is included.
- No external reputation enrichment is performed.
- Detection rules are starter rules, not a full Sigma implementation.
- This service does not claim to provide a complete SIEM or production SOC.
- Keep the API behind authentication and TLS; do not expose the database file.

## Analyst case management

ShiatoAli also provides a basic analyst workflow. Cases can be created
independently or linked to an existing alert. Case detail responses include
linked alerts and an activity timeline.

- `POST /api/shiatoali/cases` — create a case; optionally supply `alert_id`
- `GET /api/shiatoali/cases` — list cases with alert counts
- `GET /api/shiatoali/cases/{case_id}` — retrieve the case, linked alerts, and activity
- `PATCH /api/shiatoali/cases/{case_id}` — update status/assignee and append a note

Supported case statuses are `open`, `investigating`, `contained`, `resolved`,
and `closed`. Priorities are `low`, `medium`, `high`, and `critical`.
Status changes, assignment changes, notes, and case creation are recorded in
the case activity table. This is an application-level activity history, not a
tamper-proof audit ledger; production use should add immutable external audit
storage and role-based authorization.

## Analyst console

A static browser console is available at `/docs/shiatoali-console.html` when
served from the project website. It reads live health, events, alerts, and cases
from the API and supports basic case creation and open/close transitions. The
The static website does not host the Python SOC API. Enter the base URL of a separately running Shadow313 FastAPI service and its API key; the key is held in page memory only
and is not written to browser storage. Serve the console over HTTPS and keep
the API behind TLS and authentication. If the website and API use different
origins, configure the API's CORS allowlist for the exact console origin before
connecting. Never embed a production API key in the HTML or source repository.
