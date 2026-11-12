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
