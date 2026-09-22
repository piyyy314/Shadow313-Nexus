"""
shadow313.threat_intel.ioc_store
──────────────────────────────────
IOC Store — persistent SQLite-backed indicator of compromise database.

Stores and queries:
  - IP addresses, domains, file hashes, URLs
  - Attribution metadata (actor, campaign, confidence)
  - MITRE ATT&CK technique mappings
  - First/last seen timestamps
"""
from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .ti_feed import ThreatIndicator

logger = logging.getLogger("shadow313.ioc_store")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class IOCStore:
    """
    SQLite-backed IOC store for persistent threat intelligence.

    Schema:
      iocs(ioc_id, ioc_type, value, source, confidence, severity,
           tags_json, ttps_json, actor, first_seen, last_seen)
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path("~/.shadow313/ioc_store.db").expanduser())
        self._db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        if self._conn is None:
            Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def _init_db(self) -> None:
        """Initialize the database schema."""
        try:
            conn = self._connect()
            conn.execute("""
                CREATE TABLE IF NOT EXISTS iocs (
                    ioc_id      TEXT PRIMARY KEY,
                    ioc_type    TEXT NOT NULL,
                    value       TEXT NOT NULL,
                    source      TEXT,
                    confidence  REAL DEFAULT 0.5,
                    severity    TEXT DEFAULT 'MEDIUM',
                    tags_json   TEXT DEFAULT '[]',
                    ttps_json   TEXT DEFAULT '[]',
                    actor       TEXT DEFAULT '',
                    first_seen  TEXT,
                    last_seen   TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ioc_type ON iocs(ioc_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ioc_value ON iocs(value)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_actor ON iocs(actor)")
            conn.commit()
        except Exception as exc:
            logger.warning("IOC store init failed: %s", exc)

    def add(self, indicator: ThreatIndicator) -> bool:
        """Add or update an IOC in the store."""
        try:
            conn = self._connect()
            conn.execute("""
                INSERT OR REPLACE INTO iocs
                (ioc_id, ioc_type, value, source, confidence, severity,
                 tags_json, ttps_json, actor, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                indicator.ioc_id,
                indicator.ioc_type,
                indicator.value,
                indicator.source,
                indicator.confidence,
                indicator.severity,
                json.dumps(indicator.tags),
                json.dumps(indicator.ttps),
                indicator.actor,
                indicator.first_seen,
                _now_iso(),
            ))
            conn.commit()
            return True
        except Exception as exc:
            logger.warning("IOC add failed: %s", exc)
            return False

    def lookup(self, ioc_type: str, value: str) -> Optional[ThreatIndicator]:
        """Look up an IOC by type and value."""
        try:
            conn = self._connect()
            row = conn.execute(
                "SELECT * FROM iocs WHERE ioc_type=? AND value=?",
                (ioc_type, value)
            ).fetchone()
            if row:
                return self._row_to_indicator(row)
        except Exception as exc:
            logger.debug("IOC lookup failed: %s", exc)
        return None

    def search(
        self,
        ioc_type: str = "",
        actor: str = "",
        severity: str = "",
        limit: int = 100,
    ) -> list[ThreatIndicator]:
        """Search IOCs with optional filters."""
        try:
            conn = self._connect()
            query = "SELECT * FROM iocs WHERE 1=1"
            params = []
            if ioc_type:
                query += " AND ioc_type=?"
                params.append(ioc_type)
            if actor:
                query += " AND actor LIKE ?"
                params.append(f"%{actor}%")
            if severity:
                query += " AND severity=?"
                params.append(severity)
            query += f" ORDER BY confidence DESC LIMIT {limit}"
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_indicator(r) for r in rows]
        except Exception as exc:
            logger.debug("IOC search failed: %s", exc)
            return []

    def _row_to_indicator(self, row) -> ThreatIndicator:
        return ThreatIndicator(
            ioc_type   = row["ioc_type"],
            value      = row["value"],
            source     = row["source"] or "",
            confidence = row["confidence"],
            severity   = row["severity"],
            tags       = json.loads(row["tags_json"] or "[]"),
            ttps       = json.loads(row["ttps_json"] or "[]"),
            actor      = row["actor"] or "",
            first_seen = row["first_seen"] or _now_iso(),
            last_seen  = row["last_seen"] or _now_iso(),
        )

    def count(self) -> int:
        """Return total number of IOCs in the store."""
        try:
            conn = self._connect()
            return conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
        except Exception:
            return 0

    def stats(self) -> dict:
        """Return store statistics."""
        try:
            conn = self._connect()
            total = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
            by_type = {}
            for row in conn.execute("SELECT ioc_type, COUNT(*) as cnt FROM iocs GROUP BY ioc_type"):
                by_type[row["ioc_type"]] = row["cnt"]
            return {"total": total, "by_type": by_type, "db_path": self._db_path}
        except Exception as exc:
            return {"total": 0, "error": str(exc)}

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None