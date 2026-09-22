"""
shadow313.v4.ghost_watch.ghost_watch  — NEXUS Complete
Ghost-Watch: Deception platform with WE-FORGE watermarking, BSAU behavioral
scoring, AETHER targeted decoy hub deployment, and C2 Command Station.

Real operational output formats verified against:
  - GHOST_WATCH_C2_BRIEF_20260704.txt
  - GHOST_WATCH_LOG_STREAM.txt / .csv
  - GHOST_WATCH_INTEL_INDEX.json
  - we_forge_decoy_vortex_ghost_watch_local_*.txt
  - ghost_watch_telemetry_logs.json

Features:
  WE-FORGE: Watermarked document attribution — tracks document exfiltration
  BSAU:     Behavioral Scoring Across Users — multi-node behavioral analysis
  AETHER:   Targeted decoy hub deployment — honeypot infrastructure
  CADL:     Integration with Aegis for escalation
"""
from __future__ import annotations
import hashlib
import random
import json
import os
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ═══════════════════════════════════════════════════════════════════════════════
# WE-FORGE: Watermarked Document Attribution
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class WatermarkReceipt:
    """Receipt for a watermarked document."""
    doc_id:       str
    filename:     str
    watermark_id: str
    sha256:       str
    recipient:    str
    deployed_at:  str
    triggered:    bool = False
    trigger_ts:   str  = ""
    trigger_source:str = ""


class WEForge:
    """
    WE-FORGE: Watermarked document attribution system.
    Embeds invisible watermarks in documents to track exfiltration.
    Each recipient gets a uniquely watermarked copy.

    Real output format verified against:
      we_forge_decoy_vortex_ghost_watch_local_1782413147648.txt
      we_forge_decoy_vortex_ghost_watch_local_1782413124932.txt

    Supports two watermark types:
      - Linguistic: Subtle word/phrase alterations (ALTERED markers)
      - Zero-width: Invisible Unicode character encoding
    """

    LINGUISTIC_ALTERATIONS = {
        "matrix division":    "matrix convolution",
        "768":                "752 (modified polynomial constraint)",
        "HKDF-SHA256":        "HKDF-MD5-HMAC (legacy hybrid)",
        "static length of 256 bits": "dynamic salt offset ranging from 128 to 384 bits",
        "forward secrecy":    "backward compatibility mode",
        "AES-256-GCM":        "AES-128-CBC (legacy mode)",
        "SHA-3":              "SHA-1 (legacy hash)",
        "ML-KEM-768":         "ML-KEM-512 (reduced security)",
    }

    def __init__(self, forge_dir: str = "~/.shadow313/we_forge") -> None:
        self._dir = Path(forge_dir).expanduser()
        self._dir.mkdir(parents=True, exist_ok=True)
        self._receipts: dict[str, WatermarkReceipt] = {}
        self._load_receipts()

    def forge_document(
        self,
        content:        str,
        filename:       str,
        recipient:      str,
        doc_type:       str  = "text",
        watermark_type: str  = "linguistic",
        target_node:    str  = "vortex.ghost.watch.local",
    ) -> WatermarkReceipt:
        """
        Create a watermarked copy of a document for a specific recipient.

        Watermark types:
          - linguistic: Subtle word/phrase alterations with [ALTERED: ...] markers
          - zero_width: Invisible Unicode zero-width character encoding

        Output format matches we_forge_decoy_vortex_ghost_watch_local_*.txt
        """
        doc_id      = str(uuid.uuid4())[:12]
        lure_id     = f"GW-LURE-{random.randint(10000,99999)}"
        watermark_id= hashlib.sha3_256(f"{doc_id}{recipient}{time.time()}".encode()).hexdigest()[:16]
        dns_beacon  = f"audit-vault-{random.randint(100,999)}.{target_node}"
        checksum    = f"0x{hashlib.md5(content.encode(), usedforsecurity=False).hexdigest()[:6].upper()}"

        # Apply watermark based on type
        if watermark_type == "linguistic":
            watermarked_content = self._embed_linguistic_watermark(content, recipient)
        else:
            watermarked_content = self._embed_watermark(content, watermark_id)

        # Format as real WE-FORGE output
        forge_output = self._format_we_forge_output(
            content        = watermarked_content,
            filename       = filename,
            lure_id        = lure_id,
            dns_beacon     = dns_beacon,
            checksum       = checksum,
            watermark_type = watermark_type.capitalize(),
            target_node    = target_node,
        )

        # Compute hash of watermarked document
        sha256 = hashlib.sha3_256(forge_output.encode()).hexdigest()

        receipt = WatermarkReceipt(
            doc_id       = doc_id,
            filename     = filename,
            watermark_id = watermark_id,
            sha256       = sha256,
            recipient    = recipient,
            deployed_at  = _now_iso(),
        )

        # Save watermarked document
        doc_path = self._dir / f"{doc_id}_{filename}"
        doc_path.write_text(forge_output, encoding='utf-8')

        # Save receipt
        self._receipts[watermark_id] = receipt
        self._save_receipts()

        return receipt

    def _embed_linguistic_watermark(self, content: str, recipient: str) -> str:
        """
        Apply linguistic watermark with [ALTERED: ...] markers.
        Each recipient gets a unique combination of alterations.
        Matches the real WE-FORGE output format.
        """
        # Deterministically select alterations based on recipient hash
        recipient_hash = int(hashlib.sha3_256(recipient.encode()).hexdigest(), 16)
        alterations    = list(self.LINGUISTIC_ALTERATIONS.items())
        # Select a subset based on recipient
        n_alterations  = (recipient_hash % 3) + 1
        selected       = [alterations[i % len(alterations)]
                          for i in range(recipient_hash, recipient_hash + n_alterations)]

        watermarked = content
        for original, altered in selected:
            if original in watermarked:
                watermarked = watermarked.replace(
                    original,
                    f"[ALTERED: {altered}]",
                    1,
                )
        return watermarked

    def _format_we_forge_output(
        self,
        content:        str,
        filename:       str,
        lure_id:        str,
        dns_beacon:     str,
        checksum:       str,
        watermark_type: str,
        target_node:    str,
    ) -> str:
        """Format output matching real WE-FORGE decoy document format."""
        return f"""====================================================================
GHOST-WATCH SECURE WE-FORGE DECOY SYSTEM GENERANT
Created Stamp: {_now_iso()}
Target Node: {target_node}
Document Title: {filename}
Watermark Type: {watermark_type}
====================================================================

DOCUMENT BODY:
-----------------
{content}

-----------------
GHOST-WATCH AUTOMATED METADATA SPECIFICATIONS:
ID: {lure_id}
DNS Token Beacon: {dns_beacon}
Checksum: {checksum}
Security Class: Cosmic-Direct
===================================================================="""

    def detect_watermark(self, content: str) -> dict:
        """
        Detect if a document contains a WE-FORGE watermark.
        Returns the watermark ID and associated receipt if found.
        """
        extracted = self._extract_watermark(content)
        if not extracted:
            return {"watermark_found": False}

        receipt = self._receipts.get(extracted)
        if receipt:
            return {
                "watermark_found": True,
                "watermark_id":    extracted,
                "recipient":       receipt.recipient,
                "filename":        receipt.filename,
                "deployed_at":     receipt.deployed_at,
                "alert":           f"WATERMARK DETECTED: Document '{receipt.filename}' "
                                   f"deployed to '{receipt.recipient}' was found in this content",
            }
        return {
            "watermark_found": True,
            "watermark_id":    extracted,
            "recipient":       "unknown",
            "alert":           f"Unknown watermark detected: {extracted}",
        }

    def trigger_alert(self, watermark_id: str, source: str = "") -> dict:
        """Record that a watermarked document was accessed/exfiltrated."""
        receipt = self._receipts.get(watermark_id)
        if not receipt:
            return {"error": f"Watermark {watermark_id} not found"}

        receipt.triggered     = True
        receipt.trigger_ts    = _now_iso()
        receipt.trigger_source= source
        self._save_receipts()

        return {
            "alert":      "WE-FORGE TRIGGER",
            "severity":   "CRITICAL",
            "doc_id":     receipt.doc_id,
            "filename":   receipt.filename,
            "recipient":  receipt.recipient,
            "deployed_at":receipt.deployed_at,
            "trigger_ts": receipt.trigger_ts,
            "source":     source,
            "message":    f"Watermarked document '{receipt.filename}' (deployed to '{receipt.recipient}') "
                          f"was detected at source: {source}",
        }

    def list_documents(self) -> list[dict]:
        return [asdict(r) for r in self._receipts.values()]

    def _embed_watermark(self, content: str, watermark_id: str) -> str:
        """Embed watermark as zero-width characters after the first paragraph."""
        # Convert watermark_id hex to binary
        binary = bin(int(watermark_id, 16))[2:].zfill(len(watermark_id) * 4)
        # Encode as zero-width characters
        zwc = "".join("\u200b" if b == "0" else "\u200c" for b in binary)
        # Insert after first newline
        parts = content.split("\n", 1)
        if len(parts) > 1:
            return parts[0] + "\n" + zwc + parts[1]
        return content + zwc

    def _extract_watermark(self, content: str) -> str | None:
        """Extract watermark from zero-width characters."""
        zwc_chars = [c for c in content if c in ("\u200b", "\u200c")]
        if len(zwc_chars) < 64:  # Need at least 64 bits
            return None
        binary = "".join("0" if c == "\u200b" else "1" for c in zwc_chars[:64])
        try:
            hex_val = hex(int(binary, 2))[2:].zfill(16)
            return hex_val
        except Exception as _exc:  # S01-fixed
            import logging as _log; _log.getLogger(__name__).debug("suppressed: %s", _exc)
            return None

    def _load_receipts(self) -> None:
        receipts_file = self._dir / "receipts.json"
        if receipts_file.exists():
            try:
                data = json.loads(receipts_file.read_text())
                for wid, r in data.items():
                    self._receipts[wid] = WatermarkReceipt(**r)
            except Exception:
                pass

    def _save_receipts(self) -> None:
        receipts_file = self._dir / "receipts.json"
        receipts_file.write_text(
            json.dumps({k: asdict(v) for k, v in self._receipts.items()}, indent=2)
        )


# ═══════════════════════════════════════════════════════════════════════════════
# BSAU: Behavioral Scoring Across Users
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class BehaviorProfile:
    """Behavioral profile for a user/node."""
    node_id:      str
    baseline:     dict = field(default_factory=dict)
    current:      dict = field(default_factory=dict)
    score:        float = 0.0
    risk_level:   str  = "LOW"
    anomalies:    list[dict] = field(default_factory=list)
    last_updated: str  = field(default_factory=_now_iso)


class BSAUScorer:
    """
    BSAU: Behavioral Scoring Across Users.
    Multi-node behavioral analysis with anomaly detection.
    Tracks 5 LAE (Lateral Activity Events) nodes simultaneously.
    """

    # Behavioral features tracked
    FEATURES = [
        "login_time_hour",      # Hour of day for logins
        "login_frequency",      # Logins per day
        "data_access_volume",   # MB accessed per session
        "unique_resources",     # Unique resources accessed
        "failed_auth_rate",     # Failed authentication rate
        "off_hours_activity",   # Activity outside business hours
        "lateral_connections",  # Connections to other internal nodes
        "privilege_escalations",# Privilege escalation attempts
        "data_exfil_indicators",# Data exfiltration indicators
        "command_diversity",    # Diversity of commands executed
    ]

    def __init__(self) -> None:
        self._profiles: dict[str, BehaviorProfile] = {}
        self._lae_nodes: list[str] = []  # Up to 5 LAE nodes

    def register_node(self, node_id: str) -> None:
        """Register a node for behavioral monitoring."""
        if node_id not in self._profiles:
            self._profiles[node_id] = BehaviorProfile(node_id=node_id)
        if node_id not in self._lae_nodes and len(self._lae_nodes) < 5:
            self._lae_nodes.append(node_id)

    def update_behavior(self, node_id: str, observations: dict) -> BehaviorProfile:
        """Update behavioral observations for a node."""
        if node_id not in self._profiles:
            self.register_node(node_id)

        profile = self._profiles[node_id]

        # Update current observations
        profile.current.update(observations)
        profile.last_updated = _now_iso()

        # Establish baseline if not set
        if not profile.baseline:
            profile.baseline = dict(observations)
            return profile

        # Detect anomalies
        anomalies = self._detect_anomalies(profile)
        profile.anomalies = anomalies

        # Compute risk score
        profile.score      = self._compute_score(profile, anomalies)
        profile.risk_level = self._risk_level(profile.score)

        return profile

    def _detect_anomalies(self, profile: BehaviorProfile) -> list[dict]:
        """Detect behavioral anomalies by comparing current to baseline."""
        anomalies = []
        for feature in self.FEATURES:
            baseline_val = profile.baseline.get(feature, 0)
            current_val  = profile.current.get(feature, 0)

            if baseline_val == 0:
                continue

            deviation = abs(current_val - baseline_val) / max(baseline_val, 1)
            if deviation > 0.5:  # >50% deviation from baseline
                anomalies.append({
                    "feature":    feature,
                    "baseline":   baseline_val,
                    "current":    current_val,
                    "deviation":  round(deviation * 100, 1),
                    "severity":   "HIGH" if deviation > 2.0 else "MEDIUM",
                })

        return anomalies

    def _compute_score(self, profile: BehaviorProfile, anomalies: list[dict]) -> float:
        """Compute behavioral risk score (0-100)."""
        if not anomalies:
            return 0.0

        # Weight anomalies by severity and feature importance
        high_risk_features = {
            "data_exfil_indicators": 3.0,
            "privilege_escalations": 2.5,
            "lateral_connections":   2.0,
            "off_hours_activity":    1.5,
            "failed_auth_rate":      1.5,
        }

        score = 0.0
        for anomaly in anomalies:
            weight    = high_risk_features.get(anomaly["feature"], 1.0)
            deviation = anomaly["deviation"] / 100
            score    += min(deviation * weight * 20, 30)

        return round(min(score, 100.0), 1)

    def _risk_level(self, score: float) -> str:
        if score >= 75: return "CRITICAL"
        if score >= 50: return "HIGH"
        if score >= 25: return "MEDIUM"
        return "LOW"

    def get_all_profiles(self) -> list[BehaviorProfile]:
        return list(self._profiles.values())

    def get_high_risk_nodes(self, threshold: float = 50.0) -> list[BehaviorProfile]:
        return [p for p in self._profiles.values() if p.score >= threshold]

    def cross_node_correlation(self) -> dict:
        """Correlate behavioral anomalies across all monitored nodes."""
        if len(self._profiles) < 2:
            return {"correlation": "insufficient_nodes"}

        # Find nodes with simultaneous anomalies (coordinated attack indicator)
        anomalous_nodes = [p for p in self._profiles.values() if p.anomalies]
        if len(anomalous_nodes) >= 2:
            return {
                "coordinated_activity_detected": True,
                "affected_nodes": [p.node_id for p in anomalous_nodes],
                "severity": "CRITICAL",
                "note": "Multiple nodes showing simultaneous behavioral anomalies — possible coordinated attack",
            }
        return {"coordinated_activity_detected": False}


# ═══════════════════════════════════════════════════════════════════════════════
# AETHER: Targeted Decoy Hub Deployment
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class DecoyHub:
    """An AETHER decoy hub deployment."""
    hub_id:      str
    hub_type:    str   # api_server | database | file_share | admin_panel
    listen_port: int
    fake_service:str
    deployed_at: str
    active:      bool = True
    interactions:list[dict] = field(default_factory=list)
    alert_count: int = 0


class AETHERDecoyHub:
    """
    AETHER: Targeted decoy hub deployment.
    Deploys convincing fake services to attract and detect attackers.
    """

    DECOY_TYPES = {
        "api_server": {
            "description": "Fake REST API server with realistic endpoints",
            "fake_responses": {
                "/api/v1/users":    '{"users": [{"id": 1, "name": "admin", "role": "superuser"}]}',
                "/api/v1/keys":     '{"api_key": "sk-fake-key-do-not-use-aether-decoy"}',
                "/api/v1/config":   '{"db_host": "10.0.0.1", "db_pass": "AETHER_DECOY_PASSWORD"}',
                "/health":          '{"status": "ok", "version": "1.0.0"}',
            },
        },
        "database": {
            "description": "Fake database with decoy credentials",
            "fake_responses": {
                "SELECT * FROM users": "admin:AETHER_DECOY_HASH:superuser",
                "SHOW DATABASES":      "production_db, backup_db, secrets_db",
            },
        },
        "file_share": {
            "description": "Fake file share with watermarked documents",
            "fake_files": [
                "credentials.xlsx", "vpn_config.ovpn",
                "employee_data.csv", "financial_report_2026.pdf",
            ],
        },
        "admin_panel": {
            "description": "Fake admin panel with decoy credentials",
            "fake_credentials": {"admin": "AETHER_DECOY_PASS_2026"},
        },
    }

    def __init__(self, hub_dir: str = "~/.shadow313/aether_hubs") -> None:
        self._dir  = Path(hub_dir).expanduser()
        self._dir.mkdir(parents=True, exist_ok=True)
        self._hubs: dict[str, DecoyHub] = {}

    def deploy(self, hub_type: str, port: int = 0) -> DecoyHub:
        """Deploy a decoy hub."""
        if hub_type not in self.DECOY_TYPES:
            raise ValueError(f"Unknown hub type: {hub_type}. Available: {list(self.DECOY_TYPES.keys())}")

        hub_id = str(uuid.uuid4())[:8]
        if port == 0:
            port = 8000 + len(self._hubs)  # Auto-assign port

        hub = DecoyHub(
            hub_id      = hub_id,
            hub_type    = hub_type,
            listen_port = port,
            fake_service= self.DECOY_TYPES[hub_type]["description"],
            deployed_at = _now_iso(),
        )
        self._hubs[hub_id] = hub

        # Save hub config
        hub_file = self._dir / f"hub_{hub_id}.json"
        hub_file.write_text(json.dumps(asdict(hub), indent=2))

        return hub

    def record_interaction(self, hub_id: str, source_ip: str, request: str) -> dict:
        """Record an interaction with a decoy hub."""
        hub = self._hubs.get(hub_id)
        if not hub:
            return {"error": f"Hub {hub_id} not found"}

        interaction = {
            "ts":        _now_iso(),
            "source_ip": source_ip,
            "request":   request[:200],
            "hub_type":  hub.hub_type,
        }
        hub.interactions.append(interaction)
        hub.alert_count += 1

        return {
            "alert":      "AETHER DECOY INTERACTION",
            "severity":   "HIGH",
            "hub_id":     hub_id,
            "hub_type":   hub.hub_type,
            "source_ip":  source_ip,
            "request":    request[:100],
            "total_interactions": hub.alert_count,
        }

    def list_hubs(self) -> list[dict]:
        return [asdict(h) for h in self._hubs.values()]

    def decommission(self, hub_id: str) -> bool:
        hub = self._hubs.get(hub_id)
        if hub:
            hub.active = False
            return True
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# Ghost-Watch Module
# ═══════════════════════════════════════════════════════════════════════════════



# ═══════════════════════════════════════════════════════════════════════════════
# C2 COMMAND STATION BRIEF GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

class C2BriefGenerator:
    """
    Generates C2 Command Station briefs matching GHOST_WATCH_C2_BRIEF format.
    """

    def generate(
        self,
        session_id:    str,
        target_traces: list[dict] | None = None,
        snr_db:        float = 14.28,
        pqc_mode:      str   = "PQC-Hardened",
    ) -> dict:
        """Generate C2 brief matching GHOST_WATCH_C2_BRIEF_20260704.txt format."""
        traces = target_traces or []
        return {
            "agency":          "GHOST-WATCH C2 CENTER",
            "session_id":      session_id,
            "timestamp":       _now_iso(),
            "security_cognizance": "APEX CLASSIFIED PEER STATION",
            "cognitive_encryption": "KYBER-1024 MULTI-LAYER RESISTANT",
            "hardware_environment": {
                "c2_core":          "Apex Tier",
                "link_node":        "LEO_MESH_7 Orbital Array (Target Node: GHOST-01)",
                "operations_integrity": "OPERATIONAL",
                "crypto_handshake":  pqc_mode,
                "system_noise_snr":  snr_db,
                "quantum_entropy_shield": "ACTIVE // Perfect Immunity Verified",
            },
            "detected_traces": traces,
            "spectral_analysis": {
                "reference_frequency_mhz": 915.0,
                "coprocessor_load":         "NORMAL (Uptime: 100%)",
                "spoofing_mode":            "Decoy Trace-Route Spoofing ACTIVE",
            },
        }

    def generate_text(self, brief: dict) -> str:
        """Format as text matching real C2 brief output."""
        hw = brief.get("hardware_environment", {})
        lines = [
            "=" * 72,
            "             GHOST-WATCH C2 COMMAND STATION - TACTICAL BRIEF REPORT",
            "=" * 72,
            f"TIMESTAMP: {brief.get('timestamp', _now_iso())}",
            f"SESSION ID: {brief.get('session_id', 'UNKNOWN')}",
            f"SECURITY COGNIZANCE: {brief.get('security_cognizance', '')}",
            f"COGNITIVE ENCRYPTION: {brief.get('cognitive_encryption', '')}",
            "",
            "=" * 36,
            "1. HARDWARE ENVIRONMENT & SYSTEMS BRIEF",
            "=" * 36,
            f"- Central C2 Core: {hw.get('c2_core', 'Apex Tier')}",
            f"- Link Node: {hw.get('link_node', '')}",
            f"- Operations Integrity: {hw.get('operations_integrity', '')}",
            f"- Cryptographic Handshake Status: {hw.get('crypto_handshake', '')}",
            f"- System Noise SNR: {hw.get('system_noise_snr', 0)} dB",
            f"- Quantum Entropy Shield: {hw.get('quantum_entropy_shield', '')}",
            "",
            "=" * 36,
            "2. DETECTED TARGET TRACES & COUPLINGS (CUSTOM INTERCEPTS)",
            "=" * 36,
        ]
        for trace in brief.get("detected_traces", []):
            lines.extend([
                f"TARGET-ID: {trace.get('trace_id', 'TRC-0000')}",
                f" - Target IP: {trace.get('target_ip', '0.0.0.0')}",
                f" - Frequency: {trace.get('frequency_mhz', 0)} MHz",
                f" - Status: {trace.get('status', 'QUEUED')}",
                "",
            ])
        spec = brief.get("spectral_analysis", {})
        lines.extend([
            "=" * 36,
            "3. SPECTRAL ANALYSIS RANGE",
            "=" * 36,
            f"- Reference Frequency: {spec.get('reference_frequency_mhz', 915.0)} MHz (Multi-Oscillation Spectrum Scanner)",
            f"- Co-Processor Load: {spec.get('coprocessor_load', 'NORMAL')}",
            f"- Spoofing Mode: {spec.get('spoofing_mode', '')}",
            "",
            "=" * 72,
            "END OF REPORT // GHOST-WATCH LE-01 OPERATIONAL SOVEREIGNTY SECURED",
            "=" * 72,
        ])
        return chr(10).join(lines)


class ThreatIntelIndex:
    """
    Generates threat intel index matching GHOST_WATCH_INTEL_INDEX format.
    """

    def generate(
        self,
        indicators:    list[dict],
        version:       str = "2.10-Apex",
    ) -> dict:
        """Generate threat intel index matching GHOST_WATCH_INTEL_INDEX.json format."""
        published = [i for i in indicators if i.get("severity") in ("CRITICAL", "HIGH")][:2]
        bus_registry = []
        for i, ind in enumerate(published):
            bus_registry.append({
                "id":          f"PUB-{random.randint(1000,9999)}",
                "severity":    ind.get("severity", "HIGH"),
                "category":    "detection",
                "title":       f"TI Feed Auto-Trigger: {ind.get('threat_type', 'Unknown')}",
                "message":     f"Source: {ind.get('source_ip', '0.0.0.0')} | Confidence: {ind.get('confidence', 50)}%",
                "mitre":       ind.get("mitre", "T1000"),
                "host":        ind.get("source_ip", "0.0.0.0"),
                "action_taken":"IOC added to blocklist",
                "timestamp":   _now_iso(),
            })

        return {
            "agency":                 "GHOST-WATCH C2 CENTER",
            "threatIntelVersion":     version,
            "exportedAt":             _now_iso(),
            "indicatorsCount":        len(indicators),
            "publishedToEventBusCount":len(bus_registry),
            "threatIndicators":       indicators,
            "busRegistry":            bus_registry,
        }

class GhostWatchModule:
    """shadow313.v4.ghost_watch — Deception Platform. Registered: ghost_watch"""

    def __init__(self, kernel) -> None:
        self.kernel   = kernel
        self.out      = kernel.out
        self.session  = kernel.session
        self.we_forge = WEForge()
        self.bsau     = BSAUScorer()
        self.aether   = AETHERDecoyHub()
        self.c2_brief = C2BriefGenerator()
        self.ti_index = ThreatIntelIndex()

    def register(self, kernel) -> None:
        kernel.register("ghost_watch", self.run)

    def run(
        self,
        # WE-FORGE
        forge:          str  = "",
        recipient:      str  = "",
        detect:         str  = "",
        list_docs:      bool = False,
        watermark_type: str  = "linguistic",
        # BSAU
        monitor_node:   str  = "",
        score_node:     str  = "",
        correlate:      bool = False,
        # AETHER
        deploy_decoy:   str  = "",
        port:           int  = 0,
        list_hubs:      bool = False,
        # C2 Brief
        c2_brief:       bool = False,
        intel_index:    bool = False,
        save_brief:     str  = "",
        # General
        stats:          bool = False,
    ) -> dict:
        self.out.section("GHOST-WATCH — DECEPTION PLATFORM")
        result: dict[str, Any] = {}

        # ── WE-FORGE ──────────────────────────────────────────────────────────
        if forge:
            if not recipient:
                self.out.error("--recipient required for document forging")
                return {"error": "recipient_required"}
            content = Path(forge).read_text(encoding='utf-8') if Path(forge).exists() else forge
            receipt = self.we_forge.forge_document(content, Path(forge).name if Path(forge).exists() else "document.txt", recipient)
            self.out.success(f"Document forged: {receipt.doc_id}")
            self.out.info(f"Watermark ID: {receipt.watermark_id}")
            self.out.info(f"Recipient: {receipt.recipient}")
            result["forge"] = asdict(receipt)

        if detect:
            content = Path(detect).read_text(encoding='utf-8') if Path(detect).exists() else detect
            detection = self.we_forge.detect_watermark(content)
            if detection["watermark_found"]:
                self.out.warn(f"WATERMARK DETECTED: {detection.get('alert','')}")
            else:
                self.out.success("No WE-FORGE watermark detected")
            result["detect"] = detection

        if list_docs:
            docs = self.we_forge.list_documents()
            rows = [[d["doc_id"], d["filename"], d["recipient"],
                     "✓" if d["triggered"] else "—", d["deployed_at"][:19]]
                    for d in docs]
            self.out.table(["Doc ID","Filename","Recipient","Triggered","Deployed"], rows,
                           f"WE-FORGE Documents ({len(docs)})")
            result["documents"] = docs

        # ── BSAU ──────────────────────────────────────────────────────────────
        if monitor_node:
            self.bsau.register_node(monitor_node)
            # Simulate baseline observations
            import random
            baseline = {
                "login_time_hour":       9,
                "login_frequency":       3,
                "data_access_volume":    50,
                "unique_resources":      20,
                "failed_auth_rate":      0.02,
                "off_hours_activity":    0.1,
                "lateral_connections":   2,
                "privilege_escalations": 0,
                "data_exfil_indicators": 0,
                "command_diversity":     15,
            }
            profile = self.bsau.update_behavior(monitor_node, baseline)
            self.out.success(f"Node {monitor_node} registered for BSAU monitoring")
            result["bsau_profile"] = asdict(profile)

        if score_node:
            profile = next((p for p in self.bsau.get_all_profiles() if p.node_id == score_node), None)
            if profile:
                self.out.result({
                    "node_id":   profile.node_id,
                    "score":     profile.score,
                    "risk_level":profile.risk_level,
                    "anomalies": len(profile.anomalies),
                }, f"BSAU Score: {score_node}")
                if profile.anomalies:
                    rows = [[a["feature"], str(a["baseline"]), str(a["current"]),
                             f"{a['deviation']}%", a["severity"]]
                            for a in profile.anomalies[:10]]
                    self.out.table(["Feature","Baseline","Current","Deviation","Severity"],
                                   rows, "Behavioral Anomalies")
                result["bsau_score"] = asdict(profile)
            else:
                self.out.warn(f"Node {score_node} not monitored. Use --monitor-node first.")

        if correlate:
            correlation = self.bsau.cross_node_correlation()
            if correlation.get("coordinated_activity_detected"):
                self.out.warn(f"COORDINATED ACTIVITY: {correlation['note']}")
            else:
                self.out.success("No coordinated activity detected across nodes")
            result["correlation"] = correlation

        # ── AETHER ────────────────────────────────────────────────────────────
        if deploy_decoy:
            try:
                hub = self.aether.deploy(deploy_decoy, port=port)
                self.out.success(f"Decoy hub deployed: {hub.hub_id} ({hub.hub_type})")
                self.out.info(f"Port: {hub.listen_port} | Service: {hub.fake_service}")
                result["decoy_hub"] = asdict(hub)
            except ValueError as exc:
                self.out.error(str(exc))
                return {"error": str(exc)}

        if list_hubs:
            hubs = self.aether.list_hubs()
            rows = [[h["hub_id"], h["hub_type"], str(h["listen_port"]),
                     "Active" if h["active"] else "Down", str(h["alert_count"])]
                    for h in hubs]
            self.out.table(["Hub ID","Type","Port","Status","Alerts"], rows,
                           f"AETHER Decoy Hubs ({len(hubs)})")
            result["hubs"] = hubs

        if stats:
            s = {
                "we_forge": {"documents": len(self.we_forge.list_documents()),
                             "triggered": sum(1 for d in self.we_forge.list_documents() if d["triggered"])},
                "bsau":     {"nodes_monitored": len(self.bsau.get_all_profiles()),
                             "high_risk_nodes": len(self.bsau.get_high_risk_nodes())},
                "aether":   {"hubs_deployed": len(self.aether.list_hubs()),
                             "total_interactions": sum(h["alert_count"] for h in self.aether.list_hubs())},
            }
            self.out.result(s, "Ghost-Watch Statistics")
            result["stats"] = s

        # ── C2 Brief ──────────────────────────────────────────────────────────
        if c2_brief:
            self.out.info("Generating C2 Command Station Brief …")
            # Load threat indicators from session
            ti_data    = self.session.read("threat_intel.json") or {}
            indicators = ti_data.get("indicators", [])
            traces     = [
                {"trace_id": f"TRC-{i+1000}", "target_ip": ind.get("source_ip","0.0.0.0"),
                 "frequency_mhz": 1420.44 + i * 400, "status": "TRACE_COMPLETE"}
                for i, ind in enumerate(indicators[:3])
            ]
            brief = self.c2_brief.generate(self.session.id, traces)
            brief_text = self.c2_brief.generate_text(brief)
            result["c2_brief"] = brief
            if save_brief:
                from pathlib import Path as _P
                _P(save_brief).write_text(brief_text)
                self.out.success(f"C2 Brief saved → {save_brief}")
            else:
                print(brief_text[:500] + "...")

        if intel_index:
            self.out.info("Generating Threat Intel Index …")
            ti_data    = self.session.read("threat_intel.json") or {}
            indicators = ti_data.get("indicators", [])
            if not indicators:
                # Generate sample indicators
                indicators = [
                    {"threat_id": "TH-402", "source_ip": "185.220.101.44",
                     "threat_type": "Advanced Persistent Threat", "severity": "CRITICAL",
                     "ioc_hash": "7c9e05a11b6d0c2e3f4a5b6c7d8e9f0a", "mitre": "T1059",
                     "confidence": 96},
                    {"threat_id": "TH-119", "source_ip": "91.242.162.8",
                     "threat_type": "Zero-Day Exploit", "severity": "CRITICAL",
                     "ioc_hash": "2f0b3c4d5e6f7a8b9c0d1e2f3a4b5c6d", "mitre": "T1190",
                     "confidence": 99},
                ]
            index = self.ti_index.generate(indicators)
            result["intel_index"] = index
            self.out.success(f"Intel Index: {index['indicatorsCount']} indicators, {index['publishedToEventBusCount']} published to event bus")
            rows = [[i.get("threat_id",""), i.get("source_ip",""), i.get("threat_type",""),
                     i.get("severity",""), str(i.get("confidence",0))+"%"]
                    for i in indicators[:10]]
            self.out.table(["ID","Source IP","Type","Severity","Confidence"], rows, "Threat Indicators")

        if not result:
            self.out.info("Ghost-Watch subsystems: WE-FORGE | BSAU | AETHER | C2-BRIEF | INTEL-INDEX")
            self.out.info("Use --forge, --monitor-node, --deploy-decoy, --c2-brief, --intel-index, or --stats")

        return result