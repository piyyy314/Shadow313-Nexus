"""shadow313.modules.vuln.cve_db — Local SQLite CVE mirror."""
from __future__ import annotations
import json
import sqlite3
from pathlib import Path
from urllib import request as urlreq

CVE_DB_PATH = Path("~/.shadow313/cve.db").expanduser()
NVD_API     = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CVEDatabase:
    def __init__(self, db_path: Path = CVE_DB_PATH) -> None:
        """Open or create the local CVE store, falling back to an in-memory database."""
        self.db_path = db_path
        self._conn = None
        self._init_db()

    def _get_conn(self):
        """Return the current connection, initializing a database if needed."""
        if self._conn is None:
            self._init_db()
        return self._conn

    def _init_db(self) -> None:
        """Create the database schema, using in-memory storage if file-backed setup fails.

        In-memory connection and schema initialization errors propagate.
        """
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            # WAL mode: allows concurrent readers + serialised writers (no "database is locked")
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA busy_timeout=5000")
        except Exception:
            self._conn = sqlite3.connect(":memory:", check_same_thread=False)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS cves (
                id TEXT PRIMARY KEY, description TEXT,
                cvss_v3 REAL, severity TEXT,
                published TEXT, modified TEXT,
                cpe TEXT, ref_urls TEXT
            )""")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS cpe_cve (
                cpe TEXT, cve TEXT, PRIMARY KEY (cpe, cve)
            )""")
        self._conn.commit()

    def search_by_keyword(self, keyword: str, limit: int = 20) -> list[dict]:
        """Return CVEs matching description or ID, sorted by descending CVSS score.

        keyword uses SQL LIKE semantics, including % and _ wildcards. limit
        follows SQLite LIMIT semantics. Database errors propagate.
        """
        cur = self._conn.execute(
            "SELECT id, description, cvss_v3, severity, published FROM cves "
            "WHERE description LIKE ? OR id LIKE ? ORDER BY cvss_v3 DESC LIMIT ?",
            (f"%{keyword}%", f"%{keyword}%", limit),
        )
        return [{"cve": r[0], "description": r[1][:200],
                 "cvss_v3": r[2], "severity": r[3], "published": r[4]}
                for r in cur.fetchall()]

    def search_by_cpe(self, cpe: str, limit: int = 20) -> list[dict]:
        """Return CVEs from matching CPE mapping rows, sorted by descending CVSS score.

        cpe uses SQL LIKE semantics, including wildcards; limit follows SQLite
        LIMIT semantics. Database errors propagate.
        """
        cur = self._conn.execute(
            "SELECT c.id, c.description, c.cvss_v3, c.severity FROM cves c "
            "JOIN cpe_cve m ON c.id = m.cve WHERE m.cpe LIKE ? "
            "ORDER BY c.cvss_v3 DESC LIMIT ?",
            (f"%{cpe}%", limit),
        )
        return [{"cve": r[0], "description": r[1][:200],
                 "cvss_v3": r[2], "severity": r[3]}
                for r in cur.fetchall()]

    def get_cve(self, cve_id: str) -> dict | None:
        """Return a CVE record or None if absent; database errors propagate.

        cpe and references remain their stored JSON strings.
        """
        cur = self._conn.execute(
            "SELECT id, description, cvss_v3, severity, published, modified, "
            "cpe, ref_urls FROM cves WHERE id = ?", (cve_id,)
        )
        row = cur.fetchone()
        if not row:
            return None
        return {"cve": row[0], "description": row[1], "cvss_v3": row[2],
                "severity": row[3], "published": row[4], "modified": row[5],
                "cpe": row[6], "references": row[7]}

    def insert_cve(self, cve: dict) -> None:
        """Replace the CVE row with the supplied id and commit immediately.

        Store cpe/references as JSON without updating the CPE mapping table.
        Serialization and database errors propagate.
        """
        self._conn.execute("""
            INSERT OR REPLACE INTO cves
            (id, description, cvss_v3, severity, published, modified, cpe, ref_urls)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cve.get("id"), cve.get("description", ""),
            cve.get("cvss_v3", 0.0), cve.get("severity", ""),
            cve.get("published", ""), cve.get("modified", ""),
            json.dumps(cve.get("cpe", [])),
            json.dumps(cve.get("references", [])),
        ))
        self._conn.commit()

    def record_count(self) -> int:
        """Return the number of stored CVE rows; database errors propagate."""
        cur = self._conn.execute("SELECT COUNT(*) FROM cves")
        return cur.fetchone()[0]

    def update_from_nvd(self, keyword: str = "critical", api_key: str = "") -> list[dict]:
        """Fetch and commit one NVD keyword-search page of up to 50 CVE records.

        An optional api_key is sent in the request header. Request and JSON
        decoding failures return a one-element error list. Record-processing
        and database errors propagate after any earlier records were committed.
        """
        headers: dict = {"User-Agent": "shadow313/2.0"}
        if api_key:
            headers["apiKey"] = api_key
        url = f"{NVD_API}?keywordSearch={keyword}&resultsPerPage=50"
        try:
            req = urlreq.Request(url, headers=headers)
            with urlreq.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
        except Exception as exc:
            return [{"error": str(exc)}]
        fetched = []
        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            cve_id   = cve_data.get("id", "")
            descs    = cve_data.get("descriptions", [])
            desc     = next((d["value"] for d in descs if d["lang"] == "en"), "")
            metrics  = cve_data.get("metrics", {})
            cvss_v3, severity = 0.0, "UNKNOWN"
            for key in ("cvssMetricV31", "cvssMetricV30"):
                if key in metrics and metrics[key]:
                    cvss_v3  = metrics[key][0]["cvssData"].get("baseScore", 0.0)
                    severity = metrics[key][0]["cvssData"].get("baseSeverity", "")
                    break
            record = {
                "id": cve_id, "description": desc, "cvss_v3": cvss_v3,
                "severity": severity, "published": cve_data.get("published", ""),
                "modified": cve_data.get("lastModified", ""), "cpe": [],
                "references": [r["url"] for r in cve_data.get("references", [])[:5]],
            }
            self.insert_cve(record)
            fetched.append(record)
        return fetched