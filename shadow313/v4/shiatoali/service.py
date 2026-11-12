"""Persistent event ingestion and first-pass defensive detections.

The service deliberately uses SQLite from the Python standard library so the
first vertical slice can run without adding infrastructure dependencies.
For multi-worker production deployments, replace this store with PostgreSQL.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterator


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
    """SQLite-backed event and alert store with idempotent event ingestion."""

    def __init__(self, database_path: str | Path | None = None) -> None:
        configured = database_path or os.getenv(
            "SHIAATOALI_DB_PATH",
            str(Path.home() / ".shadow313" / "shiatoali.sqlite3"),
        )
        self.database_path = (
            ":memory:" if str(configured) == ":memory:" else str(Path(configured).expanduser())
        )
        if self.database_path != ":memory:":
            Path(self.database_path).parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    @contextmanager
    def _session(self) -> Iterator[sqlite3.Connection]:
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
                AND timestamp >= ?""",
                (event["host"], event["username"], cutoff),
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
            matches[-1] = dict(row)
        return matches

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
                "SELECT * FROM shiatoali_alerts ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [dict(row) for row in rows]

    def health(self) -> dict[str, Any]:
        with self._session() as db:
            events = db.execute("SELECT COUNT(*) FROM shiatoali_events").fetchone()[0]
            alerts = db.execute("SELECT COUNT(*) FROM shiatoali_alerts").fetchone()[0]
        return {"service": "shiatoali-event-detection", "status": "ok",
                "events": events, "alerts": alerts}
