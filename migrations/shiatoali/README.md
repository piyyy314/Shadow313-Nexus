# ShiatoAli PostgreSQL schema migrations

This directory defines the first PostgreSQL schema for the ShiatoAli SOC
service. It mirrors the event, alert, case, case-alert link, and case activity
tables currently used by the SQLite development store.

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

Inspect the planned SQL without applying it:

```bash
alembic -c alembic-shiatoali.ini upgrade head --sql
```

Review the generated SQL and database permissions before applying migrations
to a production database. To inspect the current revision:

```bash
alembic -c alembic-shiatoali.ini current
```

## Important boundary

This adds a versioned PostgreSQL schema and migration workflow only. The
running ShiatoAli API still uses its existing SQLite store until a PostgreSQL
repository adapter, transaction/concurrency tests, configuration wiring, and
deployment health checks are implemented and validated. Running this migration
does not switch the application database automatically.
