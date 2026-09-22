"""
Shadow313 Nexus v3 — Predictive Threat Scoring Engine
======================================================
Combines EPSS + KEV + behavioral signals + TI feed data
to generate 24-hour threat forecasts per host and technique.

Formula:
  threat_score = (epss × 0.35) + (kev_multiplier × 0.25) +
                 (behavioral × 0.25) + (ti_confidence × 0.15)

  Where:
    epss:           Exploit Prediction Scoring System (FIRST.org)
    kev_multiplier: 1.0 if in CISA KEV, 0.0 if not
    behavioral:     normalized anomaly score from NEXUS ML engine
    ti_confidence:  IOC match confidence from TI feed

Output:
  - Per-host 24h risk forecast
  - Per-technique exploitation probability
  - Prioritized remediation queue
  - Early warning for emerging threats
"""

from __future__ import annotations

import json
import math
import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple


# ── EPSS data (simulated — real data from api.first.org/epss) ─────────────────
# Format: CVE → (epss_score, percentile)
EPSS_DATABASE: Dict[str, Tuple[float, float]] = {
    "CVE-2024-3400":  (0.971, 99.8),   # PAN-OS command injection
    "CVE-2023-46604": (0.934, 99.5),   # Apache ActiveMQ RCE
    "CVE-2024-21762": (0.891, 99.1),   # Fortinet SSL-VPN
    "CVE-2024-1709":  (0.867, 98.8),   # ConnectWise ScreenConnect
    "CVE-2023-44487": (0.823, 98.2),   # HTTP/2 Rapid Reset DDoS
    "CVE-2021-44228": (0.975, 99.9),   # Log4Shell
    "CVE-2022-30190": (0.912, 99.3),   # Follina MSDT
    "CVE-2026-3392":  (0.743, 97.1),   # TR-069 CWMP (your VSAT finding)
    "CVE-2024-27198": (0.681, 96.4),   # JetBrains TeamCity
    "CVE-2023-23397": (0.654, 95.8),   # Microsoft Outlook NTLM
}

# CISA Known Exploited Vulnerabilities (subset)
CISA_KEV: set = {
    "CVE-2024-3400",
    "CVE-2023-46604",
    "CVE-2024-21762",
    "CVE-2024-1709",
    "CVE-2021-44228",
    "CVE-2022-30190",
    "CVE-2026-3392",
}

# ATT&CK technique base risk scores
TECHNIQUE_BASE_RISK: Dict[str, float] = {
    "T1190":     0.85,   # Exploit Public-Facing Application
    "T1566.001": 0.72,   # Spearphishing Attachment
    "T1059.001": 0.68,   # PowerShell
    "T1486":     0.91,   # Data Encrypted for Impact (ransomware)
    "T1003.001": 0.88,   # LSASS Memory
    "T1071.001": 0.65,   # Web Protocols C2
    "T1071.004": 0.71,   # DNS C2
    "T1546.003": 0.74,   # WMI Event Subscription
    "T1195.002": 0.89,   # Supply Chain
    "T1021.002": 0.76,   # SMB/Windows Admin Shares
    "T1110.004": 0.62,   # Credential Stuffing
    "T1498":     0.58,   # DDoS
}


@dataclass
class HostRiskProfile:
    """24-hour risk forecast for a single host."""
    host:              str
    forecast_window:   str        # "24h", "48h", "7d"
    overall_risk:      float      # 0-1
    risk_level:        str        # CRITICAL/HIGH/MEDIUM/LOW
    top_techniques:    List[dict]
    matched_cves:      List[dict]
    behavioral_score:  float
    ti_matches:        int
    forecast_generated: str
    recommendations:   List[str]


@dataclass
class TechniqueForecast:
    """Exploitation probability forecast for an ATT&CK technique."""
    technique_id:    str
    technique_name:  str
    base_risk:       float
    epss_boost:      float
    kev_boost:       float
    behavioral_boost: float
    final_score:     float
    probability_24h: float        # P(exploitation in next 24h)
    trend:           str          # rising/stable/declining
    related_cves:    List[str]


class ThreatPredictor:
    """
    Predictive threat scoring engine.

    Combines multiple signal sources into a unified
    24-hour threat forecast per host and technique.

    Usage:
        predictor = ThreatPredictor()
        predictor.ingest_behavioral(host, anomaly_score, techniques)
        predictor.ingest_ti_match(host, ioc_confidence, mitre)
        forecast = predictor.forecast_host(host)
        queue = predictor.get_remediation_queue()
    """

    def __init__(self):
        self._behavioral:  Dict[str, List[dict]] = {}  # host → events
        self._ti_matches:  Dict[str, List[dict]] = {}  # host → IOC matches
        self._cve_matches: Dict[str, List[str]]  = {}  # host → CVEs
        self._forecasts:   Dict[str, HostRiskProfile] = {}

    # ── Signal ingestion ───────────────────────────────────────────────────────
    def ingest_behavioral(
        self,
        host:          str,
        anomaly_score: float,
        techniques:    List[str],
        timestamp:     Optional[float] = None,
    ) -> None:
        """Ingest a behavioral signal from the NEXUS ML engine."""
        if host not in self._behavioral:
            self._behavioral[host] = []
        self._behavioral[host].append({
            "anomaly_score": anomaly_score,
            "techniques":    techniques,
            "timestamp":     timestamp or time.time(),
        })
        # Keep last 100 events per host
        self._behavioral[host] = self._behavioral[host][-100:]

    def ingest_ti_match(
        self,
        host:       str,
        confidence: int,
        mitre:      str,
        ioc_value:  str = "",
        source:     str = "",
    ) -> None:
        """Ingest a TI feed IOC match for a host."""
        if host not in self._ti_matches:
            self._ti_matches[host] = []
        self._ti_matches[host].append({
            "confidence": confidence,
            "mitre":      mitre,
            "ioc_value":  ioc_value,
            "source":     source,
            "timestamp":  time.time(),
        })

    def ingest_cve(self, host: str, cve_id: str) -> None:
        """Record a CVE match for a host."""
        if host not in self._cve_matches:
            self._cve_matches[host] = []
        if cve_id not in self._cve_matches[host]:
            self._cve_matches[host].append(cve_id)

    # ── Scoring ────────────────────────────────────────────────────────────────
    def _compute_epss_score(self, cves: List[str]) -> float:
        """Get max EPSS score across matched CVEs."""
        if not cves:
            return 0.0
        scores = [EPSS_DATABASE.get(cve, (0.0, 0.0))[0] for cve in cves]
        return max(scores) if scores else 0.0

    def _compute_kev_multiplier(self, cves: List[str]) -> float:
        """1.0 if any CVE is in CISA KEV, 0.0 otherwise."""
        return 1.0 if any(cve in CISA_KEV for cve in cves) else 0.0

    def _compute_behavioral_score(self, host: str) -> float:
        """Compute normalized behavioral risk from recent events."""
        events = self._behavioral.get(host, [])
        if not events:
            return 0.0
        # Weight recent events more heavily
        now = time.time()
        weighted_scores = []
        for ev in events[-20:]:
            age_hours = (now - ev["timestamp"]) / 3600
            weight    = math.exp(-age_hours / 6)  # decay over 6 hours
            weighted_scores.append(ev["anomaly_score"] * weight)
        return min(1.0, sum(weighted_scores) / max(1, len(weighted_scores)))

    def _compute_ti_score(self, host: str) -> float:
        """Compute TI signal strength from IOC matches."""
        matches = self._ti_matches.get(host, [])
        if not matches:
            return 0.0
        # Average confidence, normalized to [0,1]
        avg_conf = sum(m["confidence"] for m in matches[-10:]) / len(matches[-10:])
        return avg_conf / 100.0

    def _compute_threat_score(
        self,
        epss:       float,
        kev:        float,
        behavioral: float,
        ti:         float,
    ) -> float:
        """
        Unified threat score formula.
        Weights: EPSS 35%, KEV 25%, Behavioral 25%, TI 15%
        """
        return min(1.0,
            epss       * 0.35 +
            kev        * 0.25 +
            behavioral * 0.25 +
            ti         * 0.15
        )

    def _risk_level(self, score: float) -> str:
        if score >= 0.80: return "CRITICAL"
        if score >= 0.60: return "HIGH"
        if score >= 0.35: return "MEDIUM"
        return "LOW"

    # ── Forecasting ────────────────────────────────────────────────────────────
    def forecast_host(self, host: str) -> HostRiskProfile:
        """Generate 24-hour risk forecast for a host."""
        cves       = self._cve_matches.get(host, [])
        epss       = self._compute_epss_score(cves)
        kev        = self._compute_kev_multiplier(cves)
        behavioral = self._compute_behavioral_score(host)
        ti         = self._compute_ti_score(host)
        score      = self._compute_threat_score(epss, kev, behavioral, ti)
        level      = self._risk_level(score)

        # Top techniques from behavioral events
        technique_counts: Dict[str, int] = {}
        for ev in self._behavioral.get(host, []):
            for t in ev.get("techniques", []):
                technique_counts[t] = technique_counts.get(t, 0) + 1

        top_techniques = [
            {
                "technique": t,
                "count":     c,
                "base_risk": TECHNIQUE_BASE_RISK.get(t, 0.5),
            }
            for t, c in sorted(technique_counts.items(),
                                key=lambda x: -x[1])[:5]
        ]

        # CVE details
        matched_cves = []
        for cve in cves:
            epss_score, percentile = EPSS_DATABASE.get(cve, (0.0, 0.0))
            matched_cves.append({
                "cve":        cve,
                "epss":       epss_score,
                "percentile": percentile,
                "in_kev":     cve in CISA_KEV,
            })

        # Recommendations
        recs = []
        if kev > 0:
            kev_cves = [c for c in cves if c in CISA_KEV]
            recs.append(f"IMMEDIATE: Patch {', '.join(kev_cves)} — in CISA KEV")
        if epss > 0.8:
            recs.append(f"HIGH: EPSS {epss:.1%} — active exploitation likely within 24h")
        if behavioral > 0.7:
            recs.append("HIGH: Elevated behavioral anomaly — investigate host immediately")
        if ti > 0.6:
            recs.append("MEDIUM: IOC matches from TI feed — check network connections")
        if not recs:
            recs.append("Continue monitoring — no immediate action required")

        profile = HostRiskProfile(
            host              = host,
            forecast_window   = "24h",
            overall_risk      = round(score, 4),
            risk_level        = level,
            top_techniques    = top_techniques,
            matched_cves      = matched_cves,
            behavioral_score  = round(behavioral, 4),
            ti_matches        = len(self._ti_matches.get(host, [])),
            forecast_generated= datetime.now(timezone.utc).isoformat(),
            recommendations   = recs,
        )
        self._forecasts[host] = profile
        return profile

    def forecast_technique(self, technique_id: str) -> TechniqueForecast:
        """Generate exploitation probability forecast for an ATT&CK technique."""
        base_risk = TECHNIQUE_BASE_RISK.get(technique_id, 0.5)

        # Find CVEs related to this technique
        related_cves = [
            cve for cve, (score, _) in EPSS_DATABASE.items()
            if score > 0.7  # high-risk CVEs
        ][:3]

        epss_boost = self._compute_epss_score(related_cves) * 0.3
        kev_boost  = self._compute_kev_multiplier(related_cves) * 0.2

        # Behavioral boost from all hosts
        all_behavioral = []
        for host_events in self._behavioral.values():
            for ev in host_events:
                if technique_id in ev.get("techniques", []):
                    all_behavioral.append(ev["anomaly_score"])
        behavioral_boost = (sum(all_behavioral) / len(all_behavioral) * 0.2
                            if all_behavioral else 0.0)

        final_score = min(1.0, base_risk + epss_boost + kev_boost + behavioral_boost)

        # 24h exploitation probability (simplified Poisson model)
        lambda_rate = final_score * 0.3  # expected events per day
        prob_24h    = 1 - math.exp(-lambda_rate)

        # Trend (simplified)
        trend = "rising" if final_score > base_risk + 0.1 else \
                "declining" if final_score < base_risk - 0.1 else "stable"

        return TechniqueForecast(
            technique_id     = technique_id,
            technique_name   = f"ATT&CK {technique_id}",
            base_risk        = round(base_risk, 4),
            epss_boost       = round(epss_boost, 4),
            kev_boost        = round(kev_boost, 4),
            behavioral_boost = round(behavioral_boost, 4),
            final_score      = round(final_score, 4),
            probability_24h  = round(prob_24h, 4),
            trend            = trend,
            related_cves     = related_cves,
        )

    def get_remediation_queue(self) -> List[dict]:
        """
        Return prioritized remediation queue across all hosts.
        Sorted by threat score descending.
        """
        queue = []
        all_hosts = set(
            list(self._behavioral.keys()) +
            list(self._ti_matches.keys()) +
            list(self._cve_matches.keys())
        )
        for host in all_hosts:
            profile = self.forecast_host(host)
            queue.append({
                "host":        host,
                "risk_score":  profile.overall_risk,
                "risk_level":  profile.risk_level,
                "top_action":  profile.recommendations[0] if profile.recommendations else "",
                "cve_count":   len(profile.matched_cves),
                "kev_count":   sum(1 for c in profile.matched_cves if c.get("in_kev")),
            })
        return sorted(queue, key=lambda x: -x["risk_score"])

    def print_forecast(self, profile: HostRiskProfile) -> None:
        """Print formatted host risk forecast."""
        level_colors = {
            "CRITICAL": "\033[91m", "HIGH": "\033[93m",
            "MEDIUM": "\033[94m",   "LOW":  "\033[92m",
        }
        c   = level_colors.get(profile.risk_level, "")
        rst = "\033[0m"

        print(f"\n  \033[96m{'─'*55}\033[0m")
        print(f"  \033[96m24H THREAT FORECAST — {profile.host}\033[0m")
        print(f"  \033[96m{'─'*55}\033[0m")
        print(f"  Risk Score:    {c}{profile.overall_risk:.1%} [{profile.risk_level}]{rst}")
        print(f"  Behavioral:    {profile.behavioral_score:.1%}")
        print(f"  TI Matches:    {profile.ti_matches}")
        print(f"  CVEs Matched:  {len(profile.matched_cves)}")

        if profile.matched_cves:
            print(f"\n  CVE Details:")
            for cve in profile.matched_cves[:3]:
                kev = " ⚠️ KEV" if cve["in_kev"] else ""
                print(f"    {cve['cve']}: EPSS {cve['epss']:.1%} "
                      f"(p{cve['percentile']:.0f}){kev}")

        if profile.top_techniques:
            print(f"\n  Top Techniques:")
            for t in profile.top_techniques[:3]:
                print(f"    {t['technique']}: {t['count']} events, "
                      f"base risk {t['base_risk']:.0%}")

        print(f"\n  Recommendations:")
        for i, rec in enumerate(profile.recommendations[:3], 1):
            print(f"    {i}. {rec}")

