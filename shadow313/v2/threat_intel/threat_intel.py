"""
shadow313.v2.threat_intel.threat_intel
Feature #16 — Threat Intelligence Feeds
Auto-sync MITRE ATT&CK, AlienVault OTX, Abuse.ch, Shodan InternetDB.
All data stored locally under ~/.shadow313/threat_intel/
"""
from __future__ import annotations
import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import request as urlreq, error as urlerr

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

INTEL_DIR      = Path("~/.shadow313/threat_intel").expanduser()
INTEL_DB       = INTEL_DIR / "threat_intel.db"

# Feed URLs
MITRE_ATT_URL  = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
ABUSECH_MALWARE_BAZAAR = "https://mb-api.abuse.ch/api/v1/"
ABUSECH_URLHAUS        = "https://urlhaus-api.abuse.ch/v1/"
ABUSECH_FEODO          = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
SHODAN_INTERNETDB      = "https://internetdb.shodan.io/{ip}"

# OTX requires an API key — free tier available
OTX_API_BASE   = "https://otx.alienvault.com/api/v1"

FEED_TTLS = {
    "mitre_attack":    86400 * 7,   # 7 days
    "abusech_feodo":   3600,         # 1 hour (C2 blocklist changes fast)
    "abusech_urlhaus": 3600,
    "shodan_ip":       86400,        # 24 hours
    "otx_pulse":       86400 * 2,   # 2 days
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _http_get(url: str, headers: dict | None = None,
              timeout: int = 30) -> bytes | None:
    try:
        req = urlreq.Request(
            url,
            headers=headers or {"User-Agent": "shadow313/2.0 (threat-intel)"},
        )
        with urlreq.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except Exception:
        return None


def _http_post_json(url: str, payload: dict,
                    headers: dict | None = None, timeout: int = 30) -> dict | None:
    import json as _json
    data = _json.dumps(payload).encode()
    h = {"Content-Type": "application/json",
         "User-Agent": "shadow313/2.0", **(headers or {})}
    try:
        req = urlreq.Request(url, data=data, headers=h, method="POST")
        with urlreq.urlopen(req, timeout=timeout) as resp:
            return _json.loads(resp.read().decode())
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

class ThreatIntelDB:
    def __init__(self, db_path: Path = INTEL_DB) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path))
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS ioc_ip (
                ip          TEXT PRIMARY KEY,
                tags        TEXT,
                malware     TEXT,
                country     TEXT,
                ports       TEXT,
                source      TEXT,
                first_seen  TEXT,
                fetched_at  TEXT
            );
            CREATE TABLE IF NOT EXISTS ioc_domain (
                domain      TEXT PRIMARY KEY,
                tags        TEXT,
                malware     TEXT,
                source      TEXT,
                first_seen  TEXT,
                fetched_at  TEXT
            );
            CREATE TABLE IF NOT EXISTS ioc_url (
                url         TEXT PRIMARY KEY,
                tags        TEXT,
                malware     TEXT,
                status      TEXT,
                source      TEXT,
                first_seen  TEXT,
                fetched_at  TEXT
            );
            CREATE TABLE IF NOT EXISTS ioc_hash (
                hash        TEXT PRIMARY KEY,
                hash_type   TEXT,
                malware     TEXT,
                tags        TEXT,
                source      TEXT,
                first_seen  TEXT,
                fetched_at  TEXT
            );
            CREATE TABLE IF NOT EXISTS mitre_techniques (
                id          TEXT PRIMARY KEY,
                name        TEXT,
                description TEXT,
                tactic      TEXT,
                platforms   TEXT,
                fetched_at  TEXT
            );
            CREATE TABLE IF NOT EXISTS feed_meta (
                feed        TEXT PRIMARY KEY,
                last_sync   TEXT,
                record_count INTEGER
            );
        """)
        self._conn.commit()

    def upsert_ip(self, ip: str, tags: list, malware: str,
                   country: str = '', ports: list = None, source: str = 'unknown') -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO ioc_ip
               (ip, tags, malware, country, ports, source, fetched_at)
               VALUES (?,?,?,?,?,?,?)""",
            (ip, json.dumps(tags), malware, country,
             json.dumps(ports), source, _now())
        )

    def upsert_domain(self, domain: str, tags: list, malware: str, source: str) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO ioc_domain
               (domain, tags, malware, source, fetched_at)
               VALUES (?,?,?,?,?)""",
            (domain, json.dumps(tags), malware, source, _now())
        )

    def upsert_url(self, url: str, tags: list, malware: str,
                    status: str, source: str) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO ioc_url
               (url, tags, malware, status, source, fetched_at)
               VALUES (?,?,?,?,?,?)""",
            (url[:1000], json.dumps(tags), malware, status, source, _now())
        )

    def upsert_hash(self, hash_val: str, hash_type: str,
                     malware: str, tags: list, source: str) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO ioc_hash
               (hash, hash_type, malware, tags, source, fetched_at)
               VALUES (?,?,?,?,?,?)""",
            (hash_val, hash_type, malware, json.dumps(tags), source, _now())
        )

    def upsert_technique(self, tid: str, name: str, description: str,
                          tactic: str, platforms: list) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO mitre_techniques
               (id, name, description, tactic, platforms, fetched_at)
               VALUES (?,?,?,?,?,?)""",
            (tid, name, description[:600], tactic,
             json.dumps(platforms), _now())
        )

    def commit(self) -> None:
        self._conn.commit()

    def update_meta(self, feed: str, count: int) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO feed_meta (feed, last_sync, record_count)
               VALUES (?,?,?)""",
            (feed, _now(), count)
        )
        self._conn.commit()

    def get_meta(self, feed: str) -> dict | None:
        cur = self._conn.execute(
            "SELECT last_sync, record_count FROM feed_meta WHERE feed=?", (feed,)
        )
        row = cur.fetchone()
        return {"last_sync": row[0], "count": row[1]} if row else None

    def lookup_ip(self, ip: str) -> dict | None:
        cur = self._conn.execute("SELECT * FROM ioc_ip WHERE ip=?", (ip,))
        row = cur.fetchone()
        if not row:
            return None
        cols = ["ip","tags","malware","country","ports","source","first_seen","fetched_at"]
        d = dict(zip(cols, row))
        d["tags"] = json.loads(d["tags"] or "[]")
        d["ports"] = json.loads(d["ports"] or "[]")
        return d

    def lookup_domain(self, domain: str) -> dict | None:
        cur = self._conn.execute(
            "SELECT * FROM ioc_domain WHERE domain=?", (domain,)
        )
        row = cur.fetchone()
        if not row:
            return None
        cols = ["domain","tags","malware","source","first_seen","fetched_at"]
        d = dict(zip(cols, row))
        d["tags"] = json.loads(d["tags"] or "[]")
        return d

    def lookup_hash(self, hash_val: str) -> dict | None:
        cur = self._conn.execute(
            "SELECT * FROM ioc_hash WHERE hash=?", (hash_val,)
        )
        row = cur.fetchone()
        if not row:
            return None
        cols = ["hash","hash_type","malware","tags","source","first_seen","fetched_at"]
        d = dict(zip(cols, row))
        d["tags"] = json.loads(d["tags"] or "[]")
        return d

    def search_ip(self, keyword: str, limit: int = 50) -> list[dict]:
        cur = self._conn.execute(
            "SELECT ip, malware, country, source FROM ioc_ip "
            "WHERE ip LIKE ? OR malware LIKE ? LIMIT ?",
            (f"%{keyword}%", f"%{keyword}%", limit)
        )
        return [{"ip": r[0], "malware": r[1], "country": r[2], "source": r[3]}
                for r in cur.fetchall()]

    def stats(self) -> dict:
        def _count(table):
            return self._conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        meta = {}
        for row in self._conn.execute("SELECT feed, last_sync, record_count FROM feed_meta"):
            meta[row[0]] = {"last_sync": row[1], "count": row[2]}
        ip_count     = _count("ioc_ip")
        domain_count = _count("ioc_domain")
        url_count    = _count("ioc_url")
        hash_count   = _count("ioc_hash")
        return {
            # New keys
            "ips":        ip_count,
            "domains":    domain_count,
            "urls":       url_count,
            "hashes":     hash_count,
            "techniques": _count("mitre_techniques"),
            "feeds":      meta,
            # Backward-compatible keys (table names)
            "ioc_ip":     ip_count,
            "ioc_domain": domain_count,
            "ioc_url":    url_count,
            "ioc_hash":   hash_count,
        }


# ---------------------------------------------------------------------------
# Feed syncer implementations
# ---------------------------------------------------------------------------

class FeodoTracker:
    """Abuse.ch Feodo Tracker — C2 IP blocklist."""

    def __init__(self, db: ThreatIntelDB) -> None:
        self.db = db

    def sync(self) -> dict:
        meta = self.db.get_meta("abusech_feodo")
        if meta:
            age = time.time() - datetime.fromisoformat(meta["last_sync"]).timestamp()
            if age < FEED_TTLS["abusech_feodo"]:
                return {"status": "cached", "count": meta["count"]}

        raw = _http_get(ABUSECH_FEODO, timeout=60)
        if not raw:
            return {"status": "error", "message": "Failed to fetch Feodo tracker"}

        try:
            data = json.loads(raw)
        except Exception:
            return {"status": "error", "message": "Invalid JSON from Feodo tracker"}

        count = 0
        for entry in data:
            ip      = entry.get("ip_address", "")
            malware = entry.get("malware", "")
            country = entry.get("country", "")
            if ip:
                self.db.upsert_ip(
                    ip=ip,
                    tags=["c2", "feodo", malware.lower()],
                    malware=malware,
                    country=country,
                    ports=[entry.get("port", 0)],
                    source="abusech_feodo",
                )
                count += 1
        self.db.commit()
        self.db.update_meta("abusech_feodo", count)
        return {"status": "ok", "synced": count, "source": "abusech_feodo"}


class URLhausSync:
    """Abuse.ch URLhaus — malicious URL feed."""

    def __init__(self, db: ThreatIntelDB) -> None:
        self.db = db

    def lookup_url(self, url: str) -> dict:
        """Real-time URLhaus URL lookup."""
        result = _http_post_json(
            ABUSECH_URLHAUS + "url/",
            {"url": url},
        )
        if not result:
            return {"status": "error"}
        if result.get("query_status") == "is_listed":
            self.db.upsert_url(
                url=url,
                tags=result.get("tags", []) or [],
                malware=result.get("urlhaus_reference", ""),
                status="malicious",
                source="urlhaus",
            )
            self.db.commit()
        return result

    def lookup_hash(self, sha256: str) -> dict:
        """Lookup a file hash in URLhaus."""
        result = _http_post_json(
            ABUSECH_URLHAUS + "payload/",
            {"sha256_hash": sha256},
        )
        return result or {}

    def sync_recent(self, limit: int = 1000) -> dict:
        """Sync recent malicious URLs."""
        result = _http_post_json(
            ABUSECH_URLHAUS + "urls/recent/",
            {"limit": limit}
        )
        if not result or "urls" not in result:
            return {"status": "error"}
        count = 0
        for entry in result.get("urls", []):
            url = entry.get("url", "")
            if url:
                self.db.upsert_url(
                    url=url,
                    tags=entry.get("tags", []) or [],
                    malware=entry.get("url_status", ""),
                    status=entry.get("url_status", ""),
                    source="urlhaus",
                )
                count += 1
        self.db.commit()
        self.db.update_meta("abusech_urlhaus", count)
        return {"status": "ok", "synced": count}


class MalwareBazaarSync:
    """Abuse.ch MalwareBazaar — malware sample hash feed."""

    def __init__(self, db: ThreatIntelDB) -> None:
        self.db = db

    def lookup_hash(self, sha256: str) -> dict:
        result = _http_post_json(
            ABUSECH_MALWARE_BAZAAR,
            {"query": "get_info", "hash": sha256},
        )
        if not result or result.get("query_status") != "ok":
            return {"status": "not_found", "hash": sha256}
        data = result.get("data", [{}])[0]
        self.db.upsert_hash(
            hash_val=sha256,
            hash_type="sha256",
            malware=data.get("signature", ""),
            tags=data.get("tags", []) or [],
            source="malware_bazaar",
        )
        self.db.commit()
        return {"status": "found", "data": data}

    def sync_recent(self, limit: int = 100) -> dict:
        result = _http_post_json(
            ABUSECH_MALWARE_BAZAAR,
            {"query": "get_recent", "selector": "100"},
        )
        if not result or result.get("query_status") != "ok":
            return {"status": "error"}
        count = 0
        for entry in result.get("data", []):
            h = entry.get("sha256_hash", "")
            if h:
                self.db.upsert_hash(
                    hash_val=h,
                    hash_type="sha256",
                    malware=entry.get("signature", ""),
                    tags=entry.get("tags", []) or [],
                    source="malware_bazaar",
                )
                count += 1
        self.db.commit()
        self.db.update_meta("malware_bazaar", count)
        return {"status": "ok", "synced": count}


class ShodanInternetDB:
    """Shodan InternetDB — passive host intelligence (no API key required)."""

    def __init__(self, db: ThreatIntelDB) -> None:
        self.db = db

    def lookup(self, ip: str) -> dict:
        """Lookup a single IP in Shodan InternetDB."""
        cached = self.db.lookup_ip(ip)
        if cached and cached.get("source") == "shodan":
            fetched_at = cached.get("fetched_at", "")
            if fetched_at:
                try:
                    age = time.time() - datetime.fromisoformat(fetched_at).timestamp()
                    if age < FEED_TTLS["shodan_ip"]:
                        return {"status": "cached", "ip": ip, "data": cached}
                except Exception:
                    pass

        raw = _http_get(SHODAN_INTERNETDB.format(ip=ip), timeout=15)
        if not raw:
            return {"status": "error", "ip": ip}

        try:
            data = json.loads(raw)
        except Exception:
            return {"status": "error", "ip": ip}

        if "detail" in data:   # 404 / not found
            return {"status": "not_found", "ip": ip}

        # Parse and store
        tags    = data.get("tags", []) or []
        vulns   = data.get("vulns", []) or []
        ports   = data.get("ports", []) or []
        hostnames = data.get("hostnames", []) or []
        cpes    = data.get("cpes", []) or []

        self.db.upsert_ip(
            ip=ip,
            tags=tags + (["vulns"] if vulns else []),
            malware=", ".join(vulns[:10]),
            country="",
            ports=ports,
            source="shodan",
        )
        self.db.commit()

        return {
            "status":    "found",
            "ip":        ip,
            "ports":     ports,
            "hostnames": hostnames,
            "tags":      tags,
            "vulns":     vulns,
            "cpes":      cpes,
            "is_malicious": bool(tags),
        }


class OTXSync:
    """AlienVault OTX — Open Threat Exchange pulses."""

    def __init__(self, db: ThreatIntelDB, api_key: str = "") -> None:
        self.db      = db
        self.api_key = api_key

    def _headers(self) -> dict:
        h = {"User-Agent": "shadow313/2.0"}
        if self.api_key:
            h["X-OTX-API-KEY"] = self.api_key
        return h

    def lookup_ip(self, ip: str) -> dict:
        url = f"{OTX_API_BASE}/indicators/IPv4/{ip}/general"
        raw = _http_get(url, headers=self._headers(), timeout=20)
        if not raw:
            return {"status": "error", "ip": ip}
        try:
            data = json.loads(raw)
        except Exception:
            return {"status": "error"}
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        if pulse_count > 0:
            self.db.upsert_ip(
                ip=ip,
                tags=["otx"] + [p.get("name","")[:30]
                                  for p in data.get("pulse_info",{}).get("pulses",[])[:5]],
                malware=data.get("country_name",""),
                country=data.get("country_code",""),
                ports=[],
                source="otx",
            )
            self.db.commit()
        return {
            "status":       "ok",
            "ip":           ip,
            "pulse_count":  pulse_count,
            "reputation":   data.get("reputation", 0),
            "is_malicious": pulse_count > 0,
        }

    def sync_subscribed_pulses(self, days: int = 7) -> dict:
        """Sync recent pulses from OTX subscriptions."""
        if not self.api_key:
            return {"status": "no_api_key", "message": "Set OTX_API_KEY in config"}
        url = f"{OTX_API_BASE}/pulses/subscribed?modified_since={days}d"
        raw = _http_get(url, headers=self._headers(), timeout=60)
        if not raw:
            return {"status": "error"}
        data = json.loads(raw)
        count = 0
        for pulse in data.get("results", []):
            for ioc in pulse.get("indicators", []):
                itype = ioc.get("type", "")
                val   = ioc.get("indicator", "")
                if itype in ("IPv4", "IPv6") and val:
                    self.db.upsert_ip(val, ["otx"], pulse.get("name",""),
                                      "", [], "otx")
                    count += 1
                elif itype in ("domain", "hostname") and val:
                    self.db.upsert_domain(val, ["otx"], pulse.get("name",""), "otx")
                    count += 1
                elif itype in ("FileHash-SHA256",) and val:
                    self.db.upsert_hash(val, "sha256", pulse.get("name",""),
                                        ["otx"], "otx")
                    count += 1
        self.db.commit()
        self.db.update_meta("otx_pulse", count)
        return {"status": "ok", "synced": count}


# ---------------------------------------------------------------------------
# ThreatIntelManager — Feature #16 unified facade
# ---------------------------------------------------------------------------

class ThreatIntelManager:
    """
    Unified threat intelligence manager.
    Orchestrates sync, lookup, and enrichment across all feeds.
    """

    def __init__(self, otx_api_key: str = "",
                 db_path: Path | None = None) -> None:
        self.db       = ThreatIntelDB(db_path or INTEL_DB)
        self.feodo    = FeodoTracker(self.db)
        self.urlhaus  = URLhausSync(self.db)
        self.bazaar   = MalwareBazaarSync(self.db)
        self.shodan   = ShodanInternetDB(self.db)
        self.otx      = OTXSync(self.db, otx_api_key)

    def sync_all(self, sources: list[str] | None = None) -> dict:
        """Sync all (or selected) threat intel feeds."""
        sources = sources or ["feodo", "urlhaus", "bazaar"]
        results = {}
        if "feodo" in sources:
            results["feodo"]   = self.feodo.sync()
        if "urlhaus" in sources:
            results["urlhaus"] = self.urlhaus.sync_recent()
        if "bazaar" in sources:
            results["bazaar"]  = self.bazaar.sync_recent()
        if "otx" in sources:
            results["otx"]     = self.otx.sync_subscribed_pulses()
        return results

    def enrich_ip(self, ip: str) -> dict:
        """Enrich an IP with all available threat intel."""
        local  = self.db.lookup_ip(ip)
        shodan = self.shodan.lookup(ip)
        otx    = self.otx.lookup_ip(ip)
        is_malicious = bool(local) or shodan.get("is_malicious") or otx.get("is_malicious")
        return {
            "ip":          ip,
            "is_malicious":is_malicious,
            "local_ioc":   local,
            "shodan":      shodan,
            "otx":         otx,
            "threat_score":self._threat_score(local, shodan, otx),
        }

    def enrich_findings(self, findings: list[dict]) -> list[dict]:
        """Add threat intel context to a list of findings."""
        for f in findings:
            # Enrich IP-based findings
            for field in ("src_ip", "dst_ip", "ip", "host"):
                ip = f.get(field, "")
                if ip and ":" not in ip:  # skip IPv6 for now
                    intel = self.enrich_ip(ip)
                    f["threat_intel"] = intel
                    break
            # Hash lookups
            for field in ("sha256", "hash", "md5"):
                h = f.get(field, "")
                if h:
                    f["hash_intel"] = self.db.lookup_hash(h)
                    break
        return findings

    def lookup_ioc(self, value: str) -> dict:
        """Auto-detect IOC type and look it up."""
        import re
        # IPv4
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value):
            return self.enrich_ip(value)
        # SHA256
        if re.match(r"^[0-9a-f]{64}$", value, re.I):
            local = self.db.lookup_hash(value)
            bazaar = self.bazaar.lookup_hash(value)
            return {"type": "sha256", "value": value,
                    "local": local, "bazaar": bazaar}
        # URL
        if value.startswith(("http://", "https://")):
            return {"type": "url", "value": value,
                    "urlhaus": self.urlhaus.lookup_url(value)}
        # Domain
        return {"type": "domain", "value": value,
                "local": self.db.lookup_domain(value),
                "otx": self.otx.lookup_ip(value)}   # OTX handles domains too

    def _threat_score(self, local: dict | None,
                       shodan: dict, otx: dict) -> int:
        score = 0
        if local:
            score += 50
        if shodan.get("is_malicious"):
            score += 25
        if shodan.get("vulns"):
            score += len(shodan["vulns"]) * 5
        if otx.get("is_malicious"):
            score += 30
        score += min(otx.get("pulse_count", 0) * 2, 50)
        return min(score, 100)

    def stats(self) -> dict:
        return self.db.stats()


# ── Backward-compatibility helpers ────────────────────────────────────────────
import re as _re

# SQL injection protection — allowlist of valid table names
ALLOWED_TABLES = frozenset({
    "ioc_ip", "ioc_domain", "ioc_url", "ioc_hash",
    "mitre_techniques", "feed_meta",
})

def _validate_table(table: str) -> str:
    """Validate table name against allowlist to prevent SQL injection."""
    if table not in ALLOWED_TABLES:
        raise ValueError(f"Invalid table name: {table!r}")
    return table


def _detect_ioc_type(value: str) -> str:
    """Detect IOC type from value string."""
    # IPv4
    if _re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
        return "ip"
    # IPv6
    if ':' in value and _re.match(r'^[0-9a-fA-F:]+$', value):
        return "ipv6"
    # MD5
    if _re.match(r'^[a-fA-F0-9]{32}$', value):
        return "md5"
    # SHA1
    if _re.match(r'^[a-fA-F0-9]{40}$', value):
        return "sha1"
    # SHA256
    if _re.match(r'^[a-fA-F0-9]{64}$', value):
        return "sha256"
    # URL
    if value.startswith(('http://', 'https://', 'ftp://')):
        return "url"
    # Email
    if '@' in value and '.' in value.split('@')[-1]:
        return "email"
    # CVE
    if _re.match(r'^CVE-\d{4}-\d+$', value, _re.IGNORECASE):
        return "cve"
    # Domain
    if '.' in value and not value.startswith('/'):
        return "domain"
    return "unknown"
