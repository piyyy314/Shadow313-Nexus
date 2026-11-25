"""Persistent, authenticated event bus adapter for the Shadow313 platform."""
from __future__ import annotations

import hmac
import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .event_bus import (
    FASTAPI_AVAILABLE,
    EventPublisher,
    PlatformEvent,
    logger,
)

DEFAULT_DB_PATH = Path("~/.shadow313/platform-events.sqlite3").expanduser()
VALID_SEVERITIES = {"INFO", "MEDIUM", "HIGH", "CRITICAL"}


class SQLiteEventStore:
    """Thread-safe SQLite event store with WAL and bounded retention."""

    def __init__(
        self,
        db_path: str | Path | None = None,
        max_events: int = 10_000,
    ) -> None:
        self.path = Path(db_path or os.environ.get(
            "SHADOW313_EVENT_STORE_PATH",
            str(DEFAULT_DB_PATH),
        )).expanduser()
        if self.path.is_symlink():
            raise ValueError("Event database path must not be a symlink")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path = self.path.resolve()
        self.max_events = max(1, int(max_events))
        self._initialize()
        self.path.chmod(0o600)

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(
            self.path,
            timeout=5.0,
            isolation_level=None,
        )
        try:
            connection.execute("PRAGMA busy_timeout=5000")
            yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=NORMAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS platform_events (
                    event_id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    event_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_platform_events_type "
                "ON platform_events(event_type)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_platform_events_severity "
                "ON platform_events(severity)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_platform_events_timestamp "
                "ON platform_events(timestamp)"
            )

    @staticmethod
    def _decode(rows: list[tuple[str]]) -> list[PlatformEvent]:
        events = []
        for (event_json,) in rows:
            data = json.loads(event_json)
            events.append(PlatformEvent(**data))
        return events

    def append(self, event: PlatformEvent) -> None:
        with self._connection() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO platform_events
                (event_id, event_type, severity, timestamp, event_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.event_type,
                    event.severity,
                    event.timestamp,
                    event.to_json(),
                ),
            )
            connection.execute(
                """
                DELETE FROM platform_events
                WHERE event_id NOT IN (
                    SELECT event_id FROM platform_events
                    ORDER BY rowid DESC LIMIT ?
                )
                """,
                (self.max_events,),
            )

    def get_all(self) -> list[PlatformEvent]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT event_json FROM platform_events ORDER BY rowid"
            ).fetchall()
        return self._decode(rows)

    def get_by_type(self, event_type: str) -> list[PlatformEvent]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT event_json FROM platform_events "
                "WHERE event_type = ? ORDER BY rowid",
                (event_type,),
            ).fetchall()
        return self._decode(rows)

    def get_by_severity(self, severity: str) -> list[PlatformEvent]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT event_json FROM platform_events "
                "WHERE severity = ? ORDER BY rowid",
                (severity,),
            ).fetchall()
        return self._decode(rows)

    def get_recent(self, n: int = 100) -> list[PlatformEvent]:
        limit = max(0, min(int(n), 1000))
        if limit == 0:
            return []
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT event_json FROM platform_events "
                "ORDER BY rowid DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return list(reversed(self._decode(rows)))

    def clear(self) -> None:
        with self._connection() as connection:
            connection.execute("DELETE FROM platform_events")

    def __len__(self) -> int:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT COUNT(*) FROM platform_events"
            ).fetchone()
        return int(row[0])


class SecureEventPublisher(EventPublisher):
    """Persistent event publisher with authenticated REST endpoints."""

    def __init__(
        self,
        db_path: str | Path | None = None,
        max_events: int = 10_000,
    ) -> None:
        super().__init__()
        self._store = SQLiteEventStore(db_path, max_events=max_events)

    def build_app(self) -> Any:
        """Build an API that requires an API key for all event data operations."""
        if not FASTAPI_AVAILABLE:
            raise RuntimeError("FastAPI not installed. Install fastapi and uvicorn")

        from fastapi import FastAPI, HTTPException, Query, Request

        app = FastAPI(
            title="Shadow313 NEXUS Persistent Event Bus",
            description="Authenticated SQLite-backed platform event service",
            version="4.0.0",
        )

        async def require_api_key(request: Request) -> None:
            expected = os.environ.get("SHADOW313_EVENT_BUS_API_KEY", "")
            provided = request.headers.get("x-api-key", "")
            if not expected:
                raise HTTPException(
                    status_code=503,
                    detail="Event bus API is disabled: API key is not configured",
                )
            if not provided or not hmac.compare_digest(provided, expected):
                raise HTTPException(status_code=401, detail="Invalid event bus API key")

        @app.get("/api/events")
        async def get_events(
            event_type: str | None = None,
            severity: str | None = None,
            limit: int = Query(default=100, ge=1, le=1000),
            _: None = __import__("fastapi").Depends(require_api_key),
        ):
            events = self.get_events(event_type, severity, limit)
            return {"events": [event.to_dict() for event in events], "count": len(events)}

        @app.get("/api/events/stats")
        async def get_stats(
            _: None = __import__("fastapi").Depends(require_api_key),
        ):
            return self.stats()

        @app.post("/api/events/publish")
        async def publish_event(
            body: dict,
            _: None = __import__("fastapi").Depends(require_api_key),
        ):
            if len(json.dumps(body, default=str).encode("utf-8")) > 64 * 1024:
                raise HTTPException(status_code=413, detail="Event payload exceeds 64 KiB")
            event_type = body.get("event_type", "generic")
            source = body.get("source", "api")
            severity = str(body.get("severity", "INFO")).upper()
            payload = body.get("payload", {})
            if not isinstance(event_type, str) or not 1 <= len(event_type) <= 128:
                raise HTTPException(status_code=422, detail="Invalid event_type")
            if not isinstance(source, str) or not 1 <= len(source) <= 128:
                raise HTTPException(status_code=422, detail="Invalid source")
            if severity not in VALID_SEVERITIES:
                raise HTTPException(status_code=422, detail="Invalid severity")
            if not isinstance(payload, dict):
                raise HTTPException(status_code=422, detail="Event payload must be an object")

            event = PlatformEvent(
                event_type=event_type,
                source=source,
                severity=severity,
                payload=payload,
                bind_id=body.get("bind_id"),
            )
            self.publish(event)
            return {
                "status": "published",
                "event_id": event.event_id,
                "persisted": True,
            }

        @app.get("/api/health")
        async def health():
            return {
                "status": "healthy",
                "platform": "Shadow313 NEXUS",
                "version": "4.0.0",
                "events_stored": len(self._store),
                "persistence": "sqlite-wal",
                "event_api_authentication": "required",
            }

        self._app = app
        return app

    def serve(self, host: str = "127.0.0.1", port: int = 8000) -> None:
        """Start the persistent event API on loopback by default."""
        app = self.build_app()
        import uvicorn

        uvicorn.run(app, host=host, port=port)


# Public alias used by the package initializer.
EventStore = SQLiteEventStore
