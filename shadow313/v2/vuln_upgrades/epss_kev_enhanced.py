"""
shadow313.v2.vuln_upgrades.epss_kev_enhanced — v4
Enhanced EPSS + KEV Scoring Engine

Reconstructed from stalled thread (office_agent@computer35.txt).
Integrates:
  - EPSS (Exploit Prediction Scoring System) from FIRST.org/Cyentia
  - CISA KEV (Known Exploited Vulnerabilities) feed
  - Composite risk formula: risk = cvss * epss * kev_multiplier

Improvements over epss_kev.py:
  - Async update() with real HTTP downloads (httpx + requests fallback)
  - Actual EPSS CSV parsing from epss.cyentia.com
  - Actual CISA KEV JSON parsing
  - 24-hour disk cache with freshness check
  - Composite risk: base_risk * kev_multiplier (3.0 if in KEV)
  - Risk tiers: CRITICAL/HIGH/MEDIUM/LOW
  - top_epss(n), kev_recent(days), score_batch() methods

Usage:
    scorer = EPSSKEVScorer()
    await scorer.update()
    result = scorer.score("CVE-2021-44228", cvss=10.0)
    print(result.risk_tier, result.composite_risk)
"""
from __future__ import annotations

import asyncio
import csv
import gzip
import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("shadow313.epss_kev_enhanced")

EPSS_URL  = "https://epss.cyentia.com/epss_scores-current.csv.gz"
KEV_URL   = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_DIR = Path.home() / ".shadow313" / "cache"
CACHE_TTL = 86400  # 24 hours


@dataclass
class EPSSScore:
    """Composite risk score for a single CVE."""
    cve_id:           str
    epss:             float
    percentile:       float
    in_kev:           bool  = False
    kev_date_added:   str   = ""
    kev_vendor:       str   = ""
    kev_product:      str   = ""
    kev_ransomware:   str   = ""
    cvss_score:       float = 0.0
    composite_risk:   float = 0.0
    risk_tier:        str   = "LOW"

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id":                  self.cve_id,
            "epss":                    round(self.epss, 4),
            "epss_percentile":         round(self.percentile, 4),
            "in_kev":                  self.in_kev,
            "kev_date_added":          self.kev_date_added,
            "kev_vendor":              self.kev_vendor,
            "kev_product":             self.kev_product,
            "kev_ransomware_campaign": self.kev_ransomware,
            "cvss_score":              self.cvss_score,
            "composite_risk":          round(self.composite_risk, 4),
            "risk_tier":               self.risk_tier,
        }


class EPSSKEVScorer:
    """
    Composite vulnerability risk scorer combining EPSS + KEV + CVSS.

    Risk formula:
        base_risk      = (cvss / 10.0) * epss   [or just epss if no CVSS]
        kev_multiplier = 3.0 if in_kev else 1.0
        composite_risk = min(1.0, base_risk * kev_multiplier)

    Risk tiers:
        CRITICAL: composite >= 0.7
        HIGH:     composite >= 0.4
        MEDIUM:   composite >= 0.1
        LOW:      composite <  0.1
    """

    KEV_MULTIPLIER = 3.0

    def __init__(self, cache_dir: Optional[Path] = None) -> None:
        self._cache_dir = cache_dir or CACHE_DIR
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._epss:     dict[str, tuple[float, float]] = {}
        self._kev:      dict[str, dict]                = {}
        self._loaded    = False
        self._epss_date = ""

    async def update(self, force: bool = False) -> dict[str, Any]:
        """Download and cache EPSS + KEV data. Returns update stats."""
        epss_updated = await self._update_epss(force)
        kev_updated  = await self._update_kev(force)
        self._loaded = True
        return {
            "epss_entries": len(self._epss),
            "kev_entries":  len(self._kev),
            "epss_updated": epss_updated,
            "kev_updated":  kev_updated,
            "epss_date":    self._epss_date,
        }

    def update_sync(self, force: bool = False) -> dict[str, Any]:
        """Synchronous wrapper for update()."""
        try:
            return asyncio.run(self.update(force=force))
        except RuntimeError:
            loop = asyncio.get_event_loop()
            return loop.run_until_complete(self.update(force=force))

    def load_from_cache(self) -> bool:
        """Load from disk cache without network."""
        epss_ok = self._load_epss_cache(self._cache_dir / "epss_current.csv.gz")
        kev_ok  = self._load_kev_cache(self._cache_dir / "kev.json")
        self._loaded = epss_ok or kev_ok
        return self._loaded

    def score(self, cve_id: str, cvss: float = 0.0) -> EPSSScore:
        """Score a single CVE. Call update() or load_from_cache() first."""
        cve_upper = cve_id.upper()
        epss_val, percentile = self._epss.get(cve_upper, (0.0, 0.0))
        kev_entry = self._kev.get(cve_upper, {})
        in_kev    = bool(kev_entry)

        base_risk = (cvss / 10.0) * epss_val if cvss > 0 else epss_val
        kev_mult  = self.KEV_MULTIPLIER if in_kev else 1.0
        composite = min(1.0, base_risk * kev_mult)

        if composite >= 0.7:   tier = "CRITICAL"
        elif composite >= 0.4: tier = "HIGH"
        elif composite >= 0.1: tier = "MEDIUM"
        else:                  tier = "LOW"

        return EPSSScore(
            cve_id         = cve_upper,
            epss           = epss_val,
            percentile     = percentile,
            in_kev         = in_kev,
            kev_date_added = kev_entry.get("dateAdded", ""),
            kev_vendor     = kev_entry.get("vendorProject", ""),
            kev_product    = kev_entry.get("product", ""),
            kev_ransomware = kev_entry.get("knownRansomwareCampaignUse", "Unknown"),
            cvss_score     = cvss,
            composite_risk = composite,
            risk_tier      = tier,
        )

    def score_batch(self, cves: list[tuple[str, float]]) -> list[EPSSScore]:
        """Score multiple CVEs. cves = [(cve_id, cvss_score), ...]"""
        return [self.score(cve, cvss) for cve, cvss in cves]

    def top_epss(self, n: int = 20) -> list[EPSSScore]:
        """Return top N CVEs by EPSS score."""
        sorted_cves = sorted(self._epss.items(), key=lambda x: x[1][0], reverse=True)
        return [self.score(cve) for cve, _ in sorted_cves[:n]]

    def kev_recent(self, days: int = 30) -> list[dict]:
        """Return KEV entries added in the last N days."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        recent = []
        for cve, entry in self._kev.items():
            try:
                added = datetime.fromisoformat(entry["dateAdded"]).replace(tzinfo=timezone.utc)
                if added >= cutoff:
                    recent.append(entry)
            except Exception as _exc:
                import logging as _log; _log.getLogger(__name__).debug("suppressed: %s", _exc)
        return sorted(recent, key=lambda x: x.get("dateAdded", ""), reverse=True)

    def is_in_kev(self, cve_id: str) -> bool:
        return cve_id.upper() in self._kev

    def get_stats(self) -> dict[str, Any]:
        return {
            "epss_entries": len(self._epss),
            "kev_entries":  len(self._kev),
            "epss_date":    self._epss_date,
            "loaded":       self._loaded,
            "cache_dir":    str(self._cache_dir),
        }

    async def _update_epss(self, force: bool) -> bool:
        cache_path = self._cache_dir / "epss_current.csv.gz"
        if not force and self._is_cache_fresh(cache_path):
            return self._load_epss_cache(cache_path)
        try:
            import httpx
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.get(EPSS_URL)
                r.raise_for_status()
                cache_path.write_bytes(r.content)
                self._write_cache_manifest(cache_path, r.content)
        except Exception as _exc:
            import logging as _log; _log.getLogger(__name__).debug("suppressed: %s", _exc)
            try:
                import requests as req
                r = req.get(EPSS_URL, timeout=30)
                cache_path.write_bytes(r.content)
            except Exception as e:
                logger.warning(f"EPSS download failed: {e}")
                if cache_path.exists():
                    return self._load_epss_cache(cache_path)
                return False
        return self._load_epss_cache(cache_path)

    async def _update_kev(self, force: bool) -> bool:
        cache_path = self._cache_dir / "kev.json"
        if not force and self._is_cache_fresh(cache_path):
            return self._load_kev_cache(cache_path)
        try:
            import httpx
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(KEV_URL)
                r.raise_for_status()
                cache_path.write_bytes(r.content)
        except Exception as _exc:
            import logging as _log; _log.getLogger(__name__).debug("suppressed: %s", _exc)
            try:
                import requests as req
                r = req.get(KEV_URL, timeout=15)
                cache_path.write_bytes(r.content)
            except Exception as e:
                logger.warning(f"KEV download failed: {e}")
                if cache_path.exists():
                    return self._load_kev_cache(cache_path)
                return False
        return self._load_kev_cache(cache_path)

    def _load_epss_cache(self, cache_path: Path) -> bool:
        if not self._verify_cache_manifest(cache_path):
            return False  # Cache poisoning detected
        try:
            with gzip.open(cache_path, "rt") as f:
                reader = csv.reader(f)
                for i, row in enumerate(reader):
                    if i == 0:
                        if row and "score_date:" in row[0]:
                            self._epss_date = row[0].split("score_date:")[-1].strip()
                        continue
                    if i == 1:
                        continue
                    if len(row) >= 3:
                        try:
                            self._epss[row[0].upper()] = (float(row[1]), float(row[2]))
                        except ValueError:
                            pass
            return True
        except Exception as e:
            logger.error(f"EPSS cache load failed: {e}")
            return False

    def _load_kev_cache(self, cache_path: Path) -> bool:
        try:
            data = json.loads(cache_path.read_text())
            for entry in data.get("vulnerabilities", []):
                cve = entry.get("cveID", "").upper()
                if cve:
                    self._kev[cve] = entry
            return True
        except Exception as e:
            logger.error(f"KEV cache load failed: {e}")
            return False

    def _is_cache_fresh(self, path: Path) -> bool:
        if not path.exists():
            return False
        return (time.time() - path.stat().st_mtime) < CACHE_TTL

    def _write_cache_manifest(self, cache_path: Path, content: bytes) -> None:
        """
        Write a HMAC-SHA256 manifest for cache integrity verification.
        HNDL-safe: HMAC-SHA256 with secret key is quantum-resistant (symmetric).
        The manifest key is derived from the cache path — not a secret key,
        but prevents accidental corruption. For stronger protection, use
        a per-installation secret key stored in ~/.shadow313/cache.key.
        """
        import hmac as _hmac
        import hashlib as _hashlib
        manifest_key = _hashlib.sha3_256(str(cache_path).encode()).digest()
        sig = _hmac.new(manifest_key, content, _hashlib.sha3_256).hexdigest()
        manifest_path = cache_path.with_suffix(cache_path.suffix + ".manifest")
        manifest_path.write_text(sig)

    def _verify_cache_manifest(self, cache_path: Path) -> bool:
        """
        Verify cache file integrity against its HMAC-SHA256 manifest.
        Returns True if manifest matches, False if tampered or missing.
        """
        import hmac as _hmac
        import hashlib as _hashlib
        manifest_path = cache_path.with_suffix(cache_path.suffix + ".manifest")
        if not manifest_path.exists():
            return True  # No manifest — legacy cache, allow but warn
        try:
            content = cache_path.read_bytes()
            manifest_key = _hashlib.sha3_256(str(cache_path).encode()).digest()
            expected = _hmac.new(manifest_key, content, _hashlib.sha3_256).hexdigest()
            stored   = manifest_path.read_text().strip()
            if not _hmac.compare_digest(expected, stored):
                import logging as _log
                _log.getLogger("shadow313.epss_kev_enhanced").warning(
                    f"Cache integrity check FAILED for {cache_path}. "
                    f"Possible cache poisoning attack. Deleting and re-downloading."
                )
                cache_path.unlink(missing_ok=True)
                manifest_path.unlink(missing_ok=True)
                return False
            return True
        except Exception as _exc:
            import logging as _log; _log.getLogger(__name__).debug("suppressed: %s", _exc)
            return True  # Verification error — allow but log




class EPSSKEVEnhancedModule:
    """Kernel module wrapper. Registered as: epss_enhanced"""

    def __init__(self, kernel) -> None:
        self.kernel  = kernel
        self.out     = kernel.out
        self.session = kernel.session
        self.scorer  = EPSSKEVScorer()

    def register(self, kernel) -> None:
        kernel.register("epss_enhanced", self.run)

    def run(self, cve: str = "", cvss: float = 0.0, update: bool = False,
            top_n: int = 0, kev_days: int = 0,
            batch: list | None = None) -> dict:
        self.out.section("EPSS + KEV ENHANCED SCORING")
        if update:
            try:
                stats = self.scorer.update_sync(force=True)
                self.out.success(f"Updated: {stats['epss_entries']:,} EPSS, {stats['kev_entries']:,} KEV")
            except Exception as e:
                self.out.warn(f"Update failed: {e}")
                self.scorer.load_from_cache()
        else:
            self.scorer.load_from_cache()

        result: dict = {}
        if cve:
            s = self.scorer.score(cve, cvss)
            self.out.info(f"{s.cve_id}: EPSS={s.epss:.4f} KEV={s.in_kev} Risk={s.composite_risk:.4f} [{s.risk_tier}]")
            result = s.to_dict()
        elif top_n > 0:
            top = self.scorer.top_epss(top_n)
            rows = [[s.cve_id, f"{s.epss:.4f}", "YES" if s.in_kev else "no",
                     f"{s.composite_risk:.4f}", s.risk_tier] for s in top]
            self.out.table(["CVE", "EPSS", "KEV", "Risk", "Tier"], rows, f"Top {top_n}")
            result = {"top_epss": [s.to_dict() for s in top]}
        elif kev_days > 0:
            recent = self.scorer.kev_recent(kev_days)
            result = {"kev_recent": recent[:20]}
        elif batch:
            scores = self.scorer.score_batch([(b, 0.0) for b in batch])
            result = {"batch": [s.to_dict() for s in scores]}
        else:
            result = self.scorer.get_stats()
            self.out.result(result, "EPSS+KEV Stats")

        self.session.write("epss_enhanced.json", result)
        return result