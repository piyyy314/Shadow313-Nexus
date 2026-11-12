"""Persistent event ingestion and first-pass defensive detections.

The service supports SQLite for local use and an optional PostgreSQL backend
for shared deployments. PostgreSQL requires the versioned schema migration.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


class _CompatRow(dict[str, Any]):
    """Mapping row that also supports SQLite-style integer indexing."""

    def __getitem__(self, key: str | int) -> Any:
        if isinstance(key, int):
            return tuple(self.values())[key]
        return super().__getitem__(key)


class _CompatResult:
    def __init__(self, result: Any) -> None:
        self._result = result
        self.rowcount = result.rowcount

    def fetchone(self) -> _CompatRow | None:
        row = self._result.fetchone()
        return _CompatRow(row._mapping) if row is not None else None

    def fetchall(self) -> list[_CompatRow]:
        return [_CompatRow(row._mapping) for row in self._result.fetchall()]


class _EmptyResult:
    rowcount = 0

    @staticmethod
    def fetchone() -> None:
        return None

    @staticmethod
    def fetchall() -> list[Any]:
        return []


class _SQLAlchemyConnection:
    """Compatibility adapter for parameterized SQL shared by both stores."""

    def __init__(self, connection: Any, text_factory: Any) -> None:
        self._connection = connection
        self._text = text_factory

    def execute(self, statement: str, parameters: tuple[Any, ...] = ()) -> _CompatResult:
        if statement.lstrip().upper().startswith("PRAGMA "):
            return _CompatResult(_EmptyResult())
        sql = statement.strip()
        ignore_conflict = bool(re.match(r"INSERT\s+OR\s+IGNORE\s+INTO", sql, re.I))
        if ignore_conflict:
            sql = re.sub(
                r"INSERT\s+OR\s+IGNORE\s+INTO",
                "INSERT INTO",
                sql,
                count=1,
                flags=re.I,
            )
            sql = sql.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"
        values = {f"p{index}": value for index, value in enumerate(parameters)}
        index = iter(range(len(parameters)))
        sql = re.sub(r"\?", lambda _: f":p{next(index)}", sql)
        return _CompatResult(self._connection.execute(self._text(sql), values))


@dataclass(frozen=True)
class EventInput:
    source: str
    host: str
    event_type: str
    message: str
    severity: str = "low"
    username: str | None = None
    src_ip: str | None = None
    timestamp: str | None = None
    event_id: str | None = None
    raw: dict[str, Any] | None = None


RULES: tuple[dict[str, Any], ...] = (
    {
        "id": "SHIA-EXEC-001",
        "name": "Suspicious PowerShell command",
        "pattern": (
            r"powershell(?:\.exe)?[^\n]*(?:-enc(?:odedcommand)?\b|"
            r"invoke-expression|downloadstring)"
        ),
        "severity": "high",
        "risk": 85,
        "tactic": "Execution",
        "technique": "T1059.001",
    },
    {
        "id": "SHIA-WEB-001",
        "name": "Potential web shell activity",
        "pattern": r"(?:cmd=|/bin/sh\s+-c|powershell\s+-command).*(?:http|request|upload)",
        "severity": "high",
        "risk": 80,
        "tactic": "Persistence",
        "technique": "T1505.003",
    },
    {
        "id": "SHIA-DISC-001",
        "name": "Network discovery utility observed",
        "pattern": r"\b(?:nmap|masscan)\b",
        "severity": "medium",
        "risk": 55,
        "tactic": "Discovery",
        "technique": "T1046",
    },
)


def _now() -> datetime:
    return datetime.now(UTC)


def _parse_time(value: str | None) -> datetime:
    if not value:
        return _now()
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


class ShiatoAliStore:
    """SQLite/PostgreSQL event and alert store with idempotent ingestion."""

    def __init__(self, database_path: str | Path | None = None) -> None:
        configured_url = (
            None if database_path is not None else os.getenv("SHIAATOALI_DATABASE_URL")
        )
        self._engine: Any | None = None
        if configured_url:
            if not configured_url.startswith("postgresql+psycopg://"):
                raise ValueError(
                    "SHIAATOALI_DATABASE_URL must use postgresql+psycopg://"
                )
            try:
                from sqlalchemy import create_engine, text
            except ImportError as exc:
                raise RuntimeError(
                    "PostgreSQL support requires: pip install -e '.[postgres]'"
                ) from exc
            self._engine = create_engine(configured_url, pool_pre_ping=True)
            self._sql_text = text
            self.database_path = "<postgresql>"
            self._memory_uri = None
            self._memory_anchor = None
            self._initialize()
            return

        configured = database_path or os.getenv(
            "SHIAATOALI_DB_PATH",
            str(Path.home() / ".shadow313" / "shiatoali.sqlite3"),
        )
        self._memory_uri: str | None = None
        self._memory_anchor: sqlite3.Connection | None = None
        if str(configured) == ":memory:":
            # Each sqlite3.connect(":memory:") call creates a different database.
            # A shared-cache URI plus a keeper connection preserves the database
            # across this store's short-lived transactional connections.
            self.database_path = ":memory:"
            self._memory_uri = f"file:shiatoali-{uuid.uuid4().hex}?mode=memory&cache=shared"
            self._memory_anchor = sqlite3.connect(
                self._memory_uri, uri=True, timeout=10, check_same_thread=False
            )
        else:
            self.database_path = str(Path(configured).expanduser())
            Path(self.database_path).parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        if self._memory_uri is not None:
            connection = sqlite3.connect(
                self._memory_uri, uri=True, timeout=10, check_same_thread=False
            )
        else:
            connection = sqlite3.connect(self.database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    @contextmanager
    def _session(self) -> Iterator[Any]:
        if self._engine is not None:
            with self._engine.begin() as connection:
                yield _SQLAlchemyConnection(connection, self._sql_text)
            return

        db = self._connect()
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def _initialize(self) -> None:
        if self._engine is not None:
            from sqlalchemy import inspect

            inspector = inspect(self._engine)
            required_tables = {
                "shiatoali_events",
                "shiatoali_alerts",
                "shiatoali_cases",
                "shiatoali_case_alerts",
                "shiatoali_case_activity",
            }
            missing_tables = required_tables.difference(inspector.get_table_names())
            if missing_tables:
                missing = ", ".join(sorted(missing_tables))
                raise RuntimeError(
                    f"ShiatoAli PostgreSQL schema is incomplete ({missing}); run "
                    "'alembic -c alembic-shiatoali.ini upgrade head' first"
                )
            return

        with self._session() as db:
            db.execute("PRAGMA journal_mode = WAL")
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS shiatoali_events (
                    event_id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    host TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    message TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    username TEXT,
                    src_ip TEXT,
                    timestamp TEXT NOT NULL,
                    raw_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_shia_events_host_time
                    ON shiatoali_events(host, timestamp);
                CREATE INDEX IF NOT EXISTS idx_shia_events_type_time
                    ON shiatoali_events(event_type, timestamp);
                CREATE TABLE IF NOT EXISTS shiatoali_alerts (
                    alert_id TEXT PRIMARY KEY,
                    fingerprint TEXT NOT NULL UNIQUE,
                    event_id TEXT NOT NULL REFERENCES shiatoali_events(event_id),
                    rule_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    tactic TEXT NOT NULL,
                    technique TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open',
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_shia_alerts_created
                    ON shiatoali_alerts(created_at);
                CREATE TABLE IF NOT EXISTS shiatoali_cases (
                    case_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    priority TEXT NOT NULL DEFAULT 'medium',
                    status TEXT NOT NULL DEFAULT 'open',
                    assignee TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_shia_cases_status_updated
                    ON shiatoali_cases(status, updated_at);
                CREATE TABLE IF NOT EXISTS shiatoali_case_alerts (
                    case_id TEXT NOT NULL REFERENCES shiatoali_cases(case_id),
                    alert_id TEXT NOT NULL REFERENCES shiatoali_alerts(alert_id),
                    linked_at TEXT NOT NULL,
                    PRIMARY KEY (case_id, alert_id)
                );
                CREATE TABLE IF NOT EXISTS shiatoali_case_activity (
                    activity_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES shiatoali_cases(case_id),
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )

    @staticmethod
    def _event_dict(event: EventInput) -> dict[str, Any]:
        data = asdict(event)
        data["event_id"] = data["event_id"] or str(uuid.uuid4())
        data["timestamp"] = _parse_time(data["timestamp"]).isoformat()
        data["raw"] = data["raw"] or {}
        return data

    def ingest(self, event: EventInput) -> dict[str, Any]:
        data = self._event_dict(event)
        if data["severity"] not in {"informational", "low", "medium", "high", "critical"}:
            raise ValueError("severity must be informational, low, medium, high, or critical")
        if not all(data[key].strip() for key in ("source", "host", "event_type", "message")):
            raise ValueError("source, host, event_type, and message are required")

        created_at = _now().isoformat()
        inserted = False
        new_alerts: list[dict[str, Any]] = []
        with self._session() as db:
            cursor = db.execute(
                """INSERT OR IGNORE INTO shiatoali_events
                (event_id, source, host, event_type, message, severity, username,
                 src_ip, timestamp, raw_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    data["event_id"], data["source"], data["host"], data["event_type"],
                    data["message"], data["severity"], data["username"], data["src_ip"],
                    data["timestamp"], json.dumps(data["raw"], sort_keys=True), created_at,
                ),
            )
            inserted = cursor.rowcount == 1
            if inserted:
                new_alerts = self._detect(db, data)
            event_row = db.execute(
                "SELECT * FROM shiatoali_events WHERE event_id = ?", (data["event_id"],)
            ).fetchone()

        return {
            "status": "accepted" if inserted else "duplicate",
            "event": self._serialize_event(event_row),
            "alerts_created": new_alerts,
        }

    def _detect(self, db: sqlite3.Connection, event: dict[str, Any]) -> list[dict[str, Any]]:
        text = f'{event["event_type"]} {event["message"]}'.lower()
        matches: list[dict[str, Any]] = []
        for rule in RULES:
            if re.search(rule["pattern"], text, flags=re.IGNORECASE):
                matches.append(rule)

        if event["event_type"].lower() in {"authentication_failure", "login_failed"}:
            cutoff = (_parse_time(event["timestamp"]) - timedelta(minutes=10)).isoformat()
            failures = db.execute(
                """SELECT COUNT(*) FROM shiatoali_events
                WHERE host = ? AND COALESCE(username, '') = COALESCE(?, '')
                AND event_type IN ('authentication_failure', 'login_failed')
                AND timestamp >= ? AND timestamp <= ?""",
                (event["host"], event["username"], cutoff, event["timestamp"]),
            ).fetchone()[0]
            if failures >= 5:
                matches.append({
                    "id": "SHIA-ID-001",
                    "name": "Repeated authentication failures",
                    "severity": "high",
                    "risk": 80,
                    "tactic": "Credential Access",
                    "technique": "T1110",
                })

        created_alerts: list[dict[str, Any]] = []
        for rule in matches:
            fingerprint_source = f'{event["event_id"]}:{rule["id"]}'
            fingerprint = hashlib.sha256(fingerprint_source.encode()).hexdigest()
            db.execute(
                """INSERT OR IGNORE INTO shiatoali_alerts
                (alert_id, fingerprint, event_id, rule_id, title, severity,
                 risk_score, tactic, technique, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    str(uuid.uuid4()), fingerprint, event["event_id"], rule["id"],
                    rule["name"], rule["severity"], rule["risk"], rule["tactic"],
                    rule["technique"], _now().isoformat(),
                ),
            )
            row = db.execute(
                "SELECT * FROM shiatoali_alerts WHERE fingerprint = ?", (fingerprint,)
            ).fetchone()
            if row is not None:
                created_alerts.append(dict(row))
        return created_alerts

    @staticmethod
    def _serialize_event(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["raw"] = json.loads(result.pop("raw_json"))
        return result

    def list_events(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        with self._session() as db:
            rows = db.execute(
                "SELECT * FROM shiatoali_events ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [self._serialize_event(row) for row in rows]

    def list_alerts(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        with self._session() as db:
            rows = db.execute(
                """SELECT alerts.*, events.host
                FROM shiatoali_alerts AS alerts
                JOIN shiatoali_events AS events ON events.event_id = alerts.event_id
                ORDER BY alerts.created_at DESC LIMIT ? OFFSET ?""",
                (limit, offset),
            ).fetchall()
        return [dict(row) for row in rows]

    def health(self) -> dict[str, Any]:
        with self._session() as db:
            events = db.execute("SELECT COUNT(*) FROM shiatoali_events").fetchone()[0]
            alerts = db.execute("SELECT COUNT(*) FROM shiatoali_alerts").fetchone()[0]
        return {"service": "shiatoali-event-detection", "status": "ok",
                "events": events, "alerts": alerts}

    def create_case(
        self, title: str, description: str = "", priority: str = "medium",
        created_by: str = "system", alert_id: str | None = None,
    ) -> dict[str, Any]:
        title = title.strip()
        if not title:
            raise ValueError("case title is required")
        if priority not in {"low", "medium", "high", "critical"}:
            raise ValueError("priority must be low, medium, high, or critical")
        now = _now().isoformat()
        case_id = str(uuid.uuid4())
        with self._session() as db:
            if alert_id:
                alert = db.execute(
                    "SELECT alert_id FROM shiatoali_alerts WHERE alert_id = ?", (alert_id,)
                ).fetchone()
                if alert is None:
                    raise ValueError("alert not found")
            db.execute(
                """INSERT INTO shiatoali_cases
                (case_id, title, description, priority, status, created_by, created_at, updated_at)
                VALUES (?, ?, ?, ?, 'open', ?, ?, ?)""",
                (case_id, title, description, priority, created_by, now, now),
            )
            if alert_id:
                db.execute(
                    """INSERT INTO shiatoali_case_alerts
                    (case_id, alert_id, linked_at) VALUES (?, ?, ?)""",
                    (case_id, alert_id, now),
                )
            self._record_case_activity(db, case_id, created_by, "created", title, now)
            row = db.execute(
                "SELECT * FROM shiatoali_cases WHERE case_id = ?", (case_id,)
            ).fetchone()
        return self._serialize_case(row)

    @staticmethod
    def _record_case_activity(
        db: sqlite3.Connection, case_id: str, actor: str, action: str,
        details: str, created_at: str,
    ) -> None:
        db.execute(
            """INSERT INTO shiatoali_case_activity
            (activity_id, case_id, actor, action, details, created_at)
            VALUES (?, ?, ?, ?, ?, ?)""",
            (str(uuid.uuid4()), case_id, actor, action, details, created_at),
        )

    @staticmethod
    def _serialize_case(row: sqlite3.Row) -> dict[str, Any]:
        return dict(row)

    def list_cases(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        with self._session() as db:
            rows = db.execute(
                """SELECT c.*, COUNT(ca.alert_id) AS alert_count
                FROM shiatoali_cases c
                LEFT JOIN shiatoali_case_alerts ca ON ca.case_id = c.case_id
                GROUP BY c.case_id ORDER BY c.updated_at DESC LIMIT ? OFFSET ?""",
                (limit, offset),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        with self._session() as db:
            case = db.execute(
                "SELECT * FROM shiatoali_cases WHERE case_id = ?", (case_id,)
            ).fetchone()
            if case is None:
                return None
            alerts = db.execute(
                """SELECT a.* FROM shiatoali_alerts a
                JOIN shiatoali_case_alerts ca ON ca.alert_id = a.alert_id
                WHERE ca.case_id = ? ORDER BY a.created_at DESC""",
                (case_id,),
            ).fetchall()
            activity = db.execute(
                """SELECT actor, action, details, created_at
                FROM shiatoali_case_activity WHERE case_id = ?
                ORDER BY created_at ASC""",
                (case_id,),
            ).fetchall()
        result = dict(case)
        result["alerts"] = [dict(row) for row in alerts]
        result["activity"] = [dict(row) for row in activity]
        return result

    def update_case(
        self, case_id: str, actor: str = "analyst",
        status: str | None = None, assignee: str | None = None,
        note: str | None = None,
    ) -> dict[str, Any]:
        allowed_statuses = {"open", "investigating", "contained", "resolved", "closed"}
        if status is not None and status not in allowed_statuses:
            raise ValueError("invalid case status")
        if note is not None and len(note) > 5000:
            raise ValueError("case note must be 5000 characters or fewer")
        now = _now().isoformat()
        with self._session() as db:
            row = db.execute(
                "SELECT * FROM shiatoali_cases WHERE case_id = ?", (case_id,)
            ).fetchone()
            if row is None:
                raise KeyError("case not found")
            if status is not None and status != row["status"]:
                db.execute(
                    "UPDATE shiatoali_cases SET status = ?, updated_at = ? WHERE case_id = ?",
                    (status, now, case_id),
                )
                self._record_case_activity(
                    db, case_id, actor, "status_changed",
                    f'{row["status"]} -> {status}', now,
                )
            if assignee is not None and assignee != row["assignee"]:
                db.execute(
                    "UPDATE shiatoali_cases SET assignee = ?, updated_at = ? WHERE case_id = ?",
                    (assignee, now, case_id),
                )
                self._record_case_activity(
                    db, case_id, actor, "assigned", assignee or "unassigned", now,
                )
            if note:
                db.execute(
                    "UPDATE shiatoali_cases SET updated_at = ? WHERE case_id = ?",
                    (now, case_id),
                )
                self._record_case_activity(db, case_id, actor, "note", note, now)
            updated = db.execute(
                "SELECT * FROM shiatoali_cases WHERE case_id = ?", (case_id,)
            ).fetchone()
        return self._serialize_case(updated)
