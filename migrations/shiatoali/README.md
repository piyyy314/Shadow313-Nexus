# ShiatoAli PostgreSQL storage

The ShiatoAli store supports SQLite for a local single-instance deployment and
PostgreSQL for a shared deployment. The PostgreSQL adapter uses the same event,
alert, case, and activity operations as SQLite.

## Install

```bash
pip install -e ".[postgres]"
```

## Configure and migrate

Use a dedicated PostgreSQL database and a least-privileged migration role.
Do not commit credentials or put a production database URL in source control.

```bash
export SHIAATOALI_DATABASE_URL='postgresql+psycopg://USER:PASSWORD@HOST:5432/DATABASE'
alembic -c alembic-shiatoali.ini upgrade head
```

The application reads `SHIAATOALI_DATABASE_URL` at startup. When it is set,
ShiatoAli uses PostgreSQL and refuses to start if the migration has not been
applied. Without it, the existing `SHIAATOALI_DB_PATH` SQLite behavior remains.

Inspect the planned SQL without applying it:

```bash
alembic -c alembic-shiatoali.ini upgrade head --sql
```

Review the generated SQL and database permissions before applying migrations
to production. To inspect the current revision:

```bash
alembic -c alembic-shiatoali.ini current
```

## Docker Compose deployment

The default Compose file keeps the local SQLite setup. To run the API with a
dedicated PostgreSQL container and automatic one-shot migration, create a
private .env file and set the four SHIAATOALI_POSTGRES_* / SHIAATOALI_DATABASE_URL
values shown in .env.example. Generate a URL-safe password with
`openssl rand -hex 32` and use the same value in POSTGRES_PASSWORD and the
database URL. Do not commit .env.

Start the stack with:

```bash
docker compose -f docker-compose.yml -f docker-compose.postgres.yml up -d --build
```

Compose waits for PostgreSQL health, runs the Alembic migration service to
completion, and only then starts the API. The database is not published on a
host port. The Compose example is a single-host deployment baseline, not a
managed production database or backup solution. For production, use a managed
PostgreSQL service, separate migration and runtime roles, TLS verification,
automated backups, retention, monitoring, and tested restores.

## Data representation and operations

Timestamps are stored as normalized UTC ISO-8601 text so SQLite and PostgreSQL
share the same ordering and rolling-window behavior. Do not mix local-time
timestamp strings into the event stream.

The PostgreSQL adapter uses SQLAlchemy transactions and translates the small
set of SQLite-compatible parameterized statements used by this service.
PostgreSQL schema changes must be made through Alembic. Run integration tests
against a disposable PostgreSQL database before enabling this backend in
production. Configure backups, retention, monitoring, and restore drills
separately; the adapter does not provide those operational controls.
