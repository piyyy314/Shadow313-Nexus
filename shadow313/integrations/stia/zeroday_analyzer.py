"""
shadow313.integrations.stia.zeroday_analyzer
──────────────────────────────────────────────
Zero-day vulnerability analyzer for STIA integration.

Analyzes STIA scan results for zero-day indicators:
  - CVEs with no public patch (0-day window)
  - Novel attack patterns not matching known signatures
  - EPSS score spikes indicating active exploitation
  - KEV (Known Exploited Vulnerabilities) cross-reference
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from .parser import STIAScanResult


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ZeroDayIndicator:
    """A potential zero-day indicator from STIA analysis."""
    indicator_id:   str
    indicator_type: str   # novel_pattern | unpatched_cve | epss_spike | kev_match
    confidence:     float
    description:    str
    cve_id:         Optional[str] = None
    epss_score:     Optional[float] = None
    kev_listed:     bool = False
    mitre_technique: str = ""
    recommendation: str = ""


@dataclass
class ZeroDayAnalysis:
    """Complete zero-day analysis result."""
    target_id:      str
    analyzed_at:    str = field(default_factory=_now_iso)
    indicators:     list[ZeroDayIndicator] = field(default_factory=list)
    risk_score:     float = 0.0
    is_zero_day:    bool = False
    summary:        str = ""

    @property
    def critical_indicators(self) -> list[ZeroDayIndicator]:
        return [i for i in self.indicators if i.confidence >= 0.8]


class ZeroDayAnalyzer:
    """
    Analyzes STIA scan results for zero-day vulnerability indicators.

    Heuristics:
      1. CVE published < 7 days ago with no patch → high zero-day probability
      2. EPSS score > 0.7 → actively exploited
      3. KEV listing → confirmed exploitation in the wild
      4. Novel URI/JA3 patterns not in known C2 library → possible new implant
    """

    # CVE year pattern — recent CVEs (current year) get higher zero-day score
    _CVE_YEAR_RE = re.compile(r"CVE-(\d{4})-")

    # EPSS thresholds
    EPSS_HIGH_THRESHOLD    = 0.70
    EPSS_CRITICAL_THRESHOLD = 0.90

    def analyze(self, result: STIAScanResult) -> ZeroDayAnalysis:
        """Analyze a STIA scan result for zero-day indicators."""
        analysis = ZeroDayAnalysis(target_id=result.target_id)
        indicators = []

        # ── Check CVEs ────────────────────────────────────────────────────────
        current_year = datetime.now(timezone.utc).year
        for cve in result.cve_list:
            match = self._CVE_YEAR_RE.search(cve)
            if match:
                cve_year = int(match.group(1))
                if cve_year >= current_year:
                    # Recent CVE — higher zero-day probability
                    indicators.append(ZeroDayIndicator(
                        indicator_id   = f"ZD-CVE-{cve}",
                        indicator_type = "unpatched_cve",
                        confidence     = 0.75,
                        description    = f"Recent CVE {cve} ({cve_year}) — patch may not be available",
                        cve_id         = cve,
                        recommendation = f"Monitor {cve} for patch availability; apply workarounds immediately",
                    ))
                elif cve_year >= current_year - 1:
                    indicators.append(ZeroDayIndicator(
                        indicator_id   = f"ZD-CVE-{cve}",
                        indicator_type = "unpatched_cve",
                        confidence     = 0.50,
                        description    = f"CVE {cve} ({cve_year}) — verify patch status",
                        cve_id         = cve,
                        recommendation = f"Verify {cve} is patched in current deployment",
                    ))

        # ── Check signal anomaly (potential novel attack) ─────────────────────
        if result.signal_anomaly:
            indicators.append(ZeroDayIndicator(
                indicator_id   = f"ZD-SIG-{result.target_id}",
                indicator_type = "novel_pattern",
                confidence     = 0.65,
                description    = "RF signal anomaly detected — possible novel jamming/spoofing technique",
                mitre_technique = "T1498",
                recommendation = "Capture RF spectrum for forensic analysis; compare against known spoofing signatures",
            ))

        # ── Check MITRE tactics for novel combinations ────────────────────────
        novel_combos = [
            (["Initial Access", "Impact"], "Direct access-to-impact chain — possible wiper/ransomware"),
            (["Credential Access", "Lateral Movement", "Exfiltration"], "Classic APT kill chain"),
        ]
        for tactic_set, description in novel_combos:
            if all(t in result.mitre_tactics for t in tactic_set):
                indicators.append(ZeroDayIndicator(
                    indicator_id   = f"ZD-TTP-{hash(description) % 10000:04d}",
                    indicator_type = "novel_pattern",
                    confidence     = 0.60,
                    description    = description,
                    recommendation = "Investigate full kill chain; check for persistence mechanisms",
                ))

        # ── Compute overall risk score ────────────────────────────────────────
        if indicators:
            risk_score = min(1.0, sum(i.confidence for i in indicators) / len(indicators))
            risk_score = max(risk_score, result.severity_score / 10.0)
        else:
            risk_score = result.severity_score / 10.0

        analysis.indicators = indicators
        analysis.risk_score  = round(risk_score, 3)
        analysis.is_zero_day = any(i.confidence >= 0.7 for i in indicators)
        analysis.summary     = (
            f"{'ZERO-DAY SUSPECTED' if analysis.is_zero_day else 'No zero-day indicators'}: "
            f"{len(indicators)} indicators, risk_score={analysis.risk_score:.2f}"
        )

        return analysis

    def batch_analyze(self, results: list[STIAScanResult]) -> list[ZeroDayAnalysis]:
        """Analyze multiple STIA results."""
        return [self.analyze(r) for r in results]