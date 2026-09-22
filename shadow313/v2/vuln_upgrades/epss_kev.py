"""
Shadow313 v2 - EPSS + KEV Scoring Engine
=========================================
Integrates EPSS scores and CISA KEV feed for composite risk scoring.
"""
from __future__ import annotations

import csv
import gzip
import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("shadow313.epss_kev")

EPSS_URL  = "https://epss.cyentia.com/epss_scores-current.csv.gz"
KEV_URL   = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_DIR = Path.home() / ".shadow313" / "cache"
CACHE_TTL = 86400  # 24 hours


@dataclass
class EPSSScore:
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
    data_unavailable: bool  = False

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
            "data_unavailable":        self.data_unavailable,
        }


class EPSSKEVScorer:
    """
    Composite vulnerability risk scorer combining EPSS + KEV + CVSS.

    Risk formula:
        base_risk      = (cvss / 10.0) * epss
        kev_multiplier = 3.0 if in_kev else 1.0
        composite_risk = min(1.0, base_risk * kev_multiplier)

    When feeds are unavailable, score() returns data_unavailable=True
    so callers can detect degraded state and refuse to triage.
    """

    def __init__(self, cache_dir: Path | None = None):
        self._cache_dir = cache_dir or CACHE_DIR
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._epss:     dict[str, tuple[float, float]] = {}
        self._kev:      dict[str, dict] = {}
        self._loaded    = False
        self._epss_date = ""

    # ── Public API ────────────────────────────────────────────────────────────

    def score(self, cve_id: str, cvss: float = 0.0) -> EPSSScore:
        """Score a single CVE. Returns data_unavailable=True when feeds are down."""
        cve_upper = cve_id.upper()

        if not self._loaded and not self._epss and not self._kev:
            return EPSSScore(
                cve_id=cve_upper,
                epss=0.0,
                percentile=0.0,
                data_unavailable=True,
                risk_tier="UNKNOWN",
            )

        epss_val, percentile = self._epss.get(cve_upper, (0.0, 0.0))
        kev_entry = self._kev.get(cve_upper, {})
        in_kev    = bool(kev_entry)

        base_risk = (cvss / 10.0) * epss_val if cvss > 0 else epss_val
        kev_mult  = 3.0 if in_kev else 1.0
        composite = min(1.0, base_risk * kev_mult)

        if composite >= 0.7:
            tier = "CRITICAL"
        elif composite >= 0.4:
            tier = "HIGH"
        elif composite >= 0.1:
            tier = "MEDIUM"
        else:
            tier = "LOW"

        return EPSSScore(
            cve_id=cve_upper,
            epss=epss_val,
            percentile=percentile,
            in_kev=in_kev,
            kev_date_added=kev_entry.get("dateAdded", ""),
            kev_vendor=kev_entry.get("vendorProject", ""),
            kev_product=kev_entry.get("product", ""),
            kev_ransomware=kev_entry.get("knownRansomwareCampaignUse", "Unknown"),
            cvss_score=cvss,
            composite_risk=composite,
            risk_tier=tier,
        )

    def score_batch(self, cves: list[tuple[str, float]]) -> list[EPSSScore]:
        return [self.score(cve, cvss) for cve, cvss in cves]

    def is_in_kev(self, cve_id: str) -> bool:
        return cve_id.upper() in self._kev

    @property
    def is_data_available(self) -> bool:
        return bool(self._epss or self._kev)

    def get_stats(self) -> dict[str, Any]:
        return {
            "epss_entries":   len(self._epss),
            "kev_entries":    len(self._kev),
            "epss_date":      self._epss_date,
            "loaded":         self._loaded,
            "data_available": self.is_data_available,
        }

    def load_from_cache(self) -> bool:
        """Load EPSS and KEV from local cache files if available."""
        epss_ok = self._load_epss_cache(self._cache_dir / "epss_current.csv.gz")
        kev_ok  = self._load_kev_cache(self._cache_dir / "kev.json")
        if epss_ok or kev_ok:
            self._loaded = True
        return epss_ok or kev_ok

    # ── Internal ──────────────────────────────────────────────────────────────

    def _load_epss_cache(self, cache_path: Path) -> bool:
        if not cache_path.exists():
            return False
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
            logger.info("EPSS loaded: %d entries", len(self._epss))
            return True
        except Exception as e:
            logger.error("EPSS cache load failed: %s", e)
            return False

    def _load_kev_cache(self, cache_path: Path) -> bool:
        if not cache_path.exists():
            return False
        try:
            data = json.loads(cache_path.read_text())
            for entry in data.get("vulnerabilities", []):
                cve = entry.get("cveID", "").upper()
                if cve:
                    self._kev[cve] = entry
            logger.info("KEV loaded: %d entries", len(self._kev))
            return True
        except Exception as e:
            logger.error("KEV cache load failed: %s", e)
            return False

    def _is_cache_fresh(self, path: Path) -> bool:
        if not path.exists():
            return False
        return (time.time() - path.stat().st_mtime) < CACHE_TTL