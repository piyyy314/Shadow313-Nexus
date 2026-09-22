"""
shadow313.integrations.stia.parser
────────────────────────────────────
Parses STIA (Satellite Threat Intelligence & Analysis) scan results
into structured STIAScanResult objects.

Supports three input formats:
  1. Raw text  (copy-paste from STIA UI)
  2. JSON string (STIA export)
  3. Python dict (programmatic)
"""
from __future__ import annotations

import json
import re
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger("shadow313.stia.parser")


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class STIAScanResult:
    """
    Structured representation of a STIA scan result.

    Fields mirror the STIA UI output format and are normalised
    for downstream consumption by the NEXUS detection pipeline.
    """

    # Identity
    target_id:          str = ""
    target_name:        str = ""
    target_type:        str = ""          # satellite | ground_station | vsat | network

    # Threat assessment
    threat_profile:     str = ""          # e.g. "APT29 — Cozy Bear"
    risk_level:         str = "UNKNOWN"   # CRITICAL | HIGH | MEDIUM | LOW | NONE
    severity_score:     float = 0.0       # 0.0 – 10.0
    status:             str = "UNKNOWN"   # ACTIVE | NEUTRALIZED | MONITORING | UNKNOWN
    is_neutralized:     bool = False

    # Findings
    cve_list:           list[str] = field(default_factory=list)
    mitre_tactics:      list[str] = field(default_factory=list)
    mitre_techniques:   list[str] = field(default_factory=list)
    forensic_artifacts: list[dict] = field(default_factory=list)
    mitigations:        list[dict] = field(default_factory=list)
    telemetry_events:   list[dict] = field(default_factory=list)

    # Ghost-Watch / WE-FORGE
    ghost_stream:       bool = False
    watermark_ids:      list[str] = field(default_factory=list)

    # Satellite-specific
    frequency_mhz:      Optional[float] = None
    orbital_slot:       Optional[str] = None
    transponder_id:     Optional[str] = None
    snr_db:             Optional[float] = None
    signal_anomaly:     bool = False

    # Metadata
    parsed_at:          str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    raw_source:         str = ""
    parse_warnings:     list[str] = field(default_factory=list)

    # ── Derived helpers ───────────────────────────────────────────────────────

    def to_nexus_findings(self) -> list[dict]:
        """Convert to NEXUS finding format for threat_detector ingestion."""
        findings = []
        for cve in self.cve_list:
            findings.append({
                "type":       "cve",
                "id":         cve,
                "source":     "STIA",
                "target":     self.target_id,
                "risk_level": self.risk_level,
                "severity":   self.severity_score,
            })
        for tactic in self.mitre_tactics:
            findings.append({
                "type":       "mitre_tactic",
                "id":         tactic,
                "source":     "STIA",
                "target":     self.target_id,
                "risk_level": self.risk_level,
            })
        for artifact in self.forensic_artifacts:
            findings.append({
                "type":       "forensic_artifact",
                "source":     "STIA",
                "target":     self.target_id,
                **artifact,
            })
        return findings

    def to_bind_payload(self) -> dict:
        """Serialise to 313-BIND payload dict."""
        return {
            "target_id":          self.target_id,
            "target_name":        self.target_name,
            "target_type":        self.target_type,
            "threat_profile":     self.threat_profile,
            "risk_level":         self.risk_level,
            "severity_score":     self.severity_score,
            "status":             self.status,
            "is_neutralized":     self.is_neutralized,
            "cve_list":           self.cve_list,
            "mitre_tactics":      self.mitre_tactics,
            "mitre_techniques":   self.mitre_techniques,
            "forensic_artifacts": self.forensic_artifacts,
            "mitigations":        self.mitigations,
            "telemetry_events":   self.telemetry_events,
            "ghost_stream":       self.ghost_stream,
            "watermark_ids":      self.watermark_ids,
            "frequency_mhz":      self.frequency_mhz,
            "orbital_slot":       self.orbital_slot,
            "snr_db":             self.snr_db,
            "signal_anomaly":     self.signal_anomaly,
            "parsed_at":          self.parsed_at,
        }

    def severity_label(self) -> str:
        """Human-readable severity label."""
        if self.severity_score >= 9.0:
            return "CRITICAL"
        if self.severity_score >= 7.0:
            return "HIGH"
        if self.severity_score >= 4.0:
            return "MEDIUM"
        if self.severity_score >= 1.0:
            return "LOW"
        return "NONE"


# ── Parser ────────────────────────────────────────────────────────────────────

class STIAParser:
    """
    Parses STIA scan output in three formats:
      - Raw text (from STIA UI copy-paste)
      - JSON string (STIA export)
      - Python dict (programmatic / API)
    """

    # ── CVE pattern ──────────────────────────────────────────────────────────
    _CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

    # ── MITRE ATT&CK tactic names ────────────────────────────────────────────
    _TACTIC_NAMES = {
        "initial access", "execution", "persistence", "privilege escalation",
        "defense evasion", "credential access", "discovery", "lateral movement",
        "collection", "command and control", "exfiltration", "impact",
        "reconnaissance", "resource development",
    }

    # ── Risk level keywords ───────────────────────────────────────────────────
    _RISK_LEVELS = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"}

    # ── MITRE technique pattern ───────────────────────────────────────────────
    _TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)

    # ── Watermark ID pattern ──────────────────────────────────────────────────
    _WATERMARK_RE = re.compile(r"WM-[0-9A-Fa-f]{8,16}")

    def parse_text(self, text: str) -> STIAScanResult:
        """Parse raw STIA text output."""
        result = STIAScanResult(raw_source=text[:500])
        warnings: list[str] = []

        lines = text.splitlines()

        for line in lines:
            stripped = line.strip()
            low = stripped.lower()

            # Target identification
            if not result.target_id and ("target:" in low or "target id:" in low):
                val = self._extract_value(stripped)
                if val:
                    result.target_id = val
                    result.target_name = val

            # Threat profile
            if "threat profile:" in low or "threat actor:" in low:
                val = self._extract_value(stripped)
                if val:
                    result.threat_profile = val

            # Risk level
            for lvl in self._RISK_LEVELS:
                if lvl in stripped.upper():
                    if "risk" in low or "level" in low or "severity" in low:
                        result.risk_level = lvl
                        break

            # Severity score
            score_match = re.search(r"severity[:\s]+(\d+(?:\.\d+)?)", low)
            if score_match:
                try:
                    result.severity_score = float(score_match.group(1))
                except ValueError:
                    pass

            # Status
            if "neutralized" in low:
                result.status = "NEUTRALIZED"
                result.is_neutralized = True
            elif "active" in low and "status" in low:
                result.status = "ACTIVE"
            elif "monitoring" in low and "status" in low:
                result.status = "MONITORING"

            # CVEs
            cves = self._CVE_RE.findall(stripped)
            for cve in cves:
                if cve.upper() not in result.cve_list:
                    result.cve_list.append(cve.upper())

            # MITRE techniques
            techs = self._TECHNIQUE_RE.findall(stripped)
            for t in techs:
                t_upper = t.upper()
                if t_upper not in result.mitre_techniques:
                    result.mitre_techniques.append(t_upper)

            # MITRE tactics (by name)
            for tactic in self._TACTIC_NAMES:
                if tactic in low:
                    tactic_title = tactic.title()
                    if tactic_title not in result.mitre_tactics:
                        result.mitre_tactics.append(tactic_title)

            # Ghost-Watch stream
            if "ghost" in low and ("stream" in low or "watch" in low):
                result.ghost_stream = True

            # Watermark IDs
            wm_ids = self._WATERMARK_RE.findall(stripped)
            for wm in wm_ids:
                if wm not in result.watermark_ids:
                    result.watermark_ids.append(wm)

            # Signal anomaly
            if "signal anomaly" in low or "spoofing" in low or "jamming" in low:
                result.signal_anomaly = True

            # SNR
            snr_match = re.search(r"snr[:\s]+(-?\d+(?:\.\d+)?)\s*db", low)
            if snr_match:
                try:
                    result.snr_db = float(snr_match.group(1))
                except ValueError:
                    pass

            # Frequency
            freq_match = re.search(r"(\d+(?:\.\d+)?)\s*mhz", low)
            if freq_match:
                try:
                    result.frequency_mhz = float(freq_match.group(1))
                except ValueError:
                    pass

            # Orbital slot
            slot_match = re.search(r"(\d+(?:\.\d+)?[°]?\s*[EW])", stripped)
            if slot_match and not result.orbital_slot:
                result.orbital_slot = slot_match.group(1)

        result.parse_warnings = warnings
        result = self._post_process(result)
        return result

    def parse_json(self, json_str: str) -> STIAScanResult:
        """Parse STIA JSON export string."""
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as exc:
            logger.warning("STIA JSON parse error: %s", exc)
            result = STIAScanResult()
            result.parse_warnings.append(f"JSON parse error: {exc}")
            return result
        return self.parse_dict(data)

    def parse_dict(self, data: dict) -> STIAScanResult:
        """Parse STIA result from a Python dict."""
        result = STIAScanResult()

        # Direct field mapping
        result.target_id          = str(data.get("target_id", data.get("target", "")))
        result.target_name        = str(data.get("target_name", result.target_id))
        result.target_type        = str(data.get("target_type", ""))
        result.threat_profile     = str(data.get("threat_profile", data.get("threat_actor", "")))
        result.risk_level         = str(data.get("risk_level", "UNKNOWN")).upper()
        result.status             = str(data.get("status", "UNKNOWN")).upper()
        result.is_neutralized     = bool(data.get("is_neutralized", False))
        result.ghost_stream       = bool(data.get("ghost_stream", False))
        result.signal_anomaly     = bool(data.get("signal_anomaly", False))

        # Numeric fields
        try:
            result.severity_score = float(data.get("severity_score", 0.0))
        except (TypeError, ValueError):
            result.severity_score = 0.0

        try:
            result.snr_db = float(data["snr_db"]) if "snr_db" in data else None
        except (TypeError, ValueError):
            result.snr_db = None

        try:
            result.frequency_mhz = float(data["frequency_mhz"]) if "frequency_mhz" in data else None
        except (TypeError, ValueError):
            result.frequency_mhz = None

        result.orbital_slot    = data.get("orbital_slot")
        result.transponder_id  = data.get("transponder_id")

        # List fields
        result.cve_list           = list(data.get("cve_list", data.get("cves", [])))
        result.mitre_tactics      = list(data.get("mitre_tactics", []))
        result.mitre_techniques   = list(data.get("mitre_techniques", []))
        result.forensic_artifacts = list(data.get("forensic_artifacts", []))
        result.mitigations        = list(data.get("mitigations", []))
        result.telemetry_events   = list(data.get("telemetry_events", []))
        result.watermark_ids      = list(data.get("watermark_ids", []))

        result = self._post_process(result)
        return result

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _extract_value(self, line: str) -> str:
        """Extract value after colon in 'Key: Value' lines."""
        if ":" in line:
            return line.split(":", 1)[1].strip()
        return ""

    def _post_process(self, result: STIAScanResult) -> STIAScanResult:
        """Normalise and derive fields after parsing."""
        # Normalise risk level
        if result.risk_level not in self._RISK_LEVELS:
            result.risk_level = "UNKNOWN"

        # Derive severity score from risk level if not set
        if result.severity_score == 0.0 and result.risk_level != "UNKNOWN":
            result.severity_score = {
                "CRITICAL": 9.5,
                "HIGH":     7.5,
                "MEDIUM":   5.0,
                "LOW":      2.5,
                "NONE":     0.0,
            }.get(result.risk_level, 0.0)

        # Derive risk level from severity score if not set
        if result.risk_level == "UNKNOWN" and result.severity_score > 0:
            result.risk_level = result.severity_label()

        # Derive is_neutralized from status
        if result.status == "NEUTRALIZED":
            result.is_neutralized = True

        # Ensure target_id is set
        if not result.target_id:
            result.target_id = f"STIA-{result.parsed_at[:10]}"
            result.parse_warnings.append("target_id not found — using generated ID")

        return result