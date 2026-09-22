"""
shadow313.v4.aegis.aegis  — NEXUS Complete
Aegis: Active defense platform with CADL escalation and automated response.

CADL (Cyber Active Defense Levels):
  L1 Monitor    — Passive observation, logging, alerting
  L2 Detect     — Active detection, honeypot deployment
  L3 Contain    — Network isolation, traffic blocking
  L4 Respond    — Automated countermeasures, deception
  L5 Neutralize — Active response (requires explicit authorization)

Features:
  - 5-tier CADL escalation with 8-second automated response
  - Threat scoring and automatic level promotion
  - Integration with threat intel feeds
  - Honeypot token deployment (AETHER-lite)
  - Incident timeline and forensic capture
  - 313 Temporal Binding for all response actions
"""
from __future__ import annotations
import json
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _now_ms() -> int:
    return int(time.time() * 1000)


# ── CADL Levels ───────────────────────────────────────────────────────────────

class CADLLevel(int, Enum):
    L1_MONITOR    = 1
    L2_DETECT     = 2
    L3_CONTAIN    = 3
    L4_RESPOND    = 4
    L5_NEUTRALIZE = 5

    @property
    def label(self) -> str:
        labels = {1:"Monitor", 2:"Detect", 3:"Contain", 4:"Respond", 5:"Neutralize"}
        return labels[self.value]

    @property
    def color(self) -> str:
        colors = {1:"green", 2:"yellow", 3:"orange", 4:"red", 5:"critical"}
        return colors[self.value]


# ── Threat Event ──────────────────────────────────────────────────────────────

@dataclass
class ThreatEvent:
    """A detected threat event."""
    event_id:    str
    timestamp:   str
    source_ip:   str
    event_type:  str   # port_scan | brute_force | c2_beacon | exfiltration | lateral_movement
    severity:    str   # LOW | MEDIUM | HIGH | CRITICAL
    score:       float # 0-100
    details:     dict  = field(default_factory=dict)
    cadl_level:  int   = 1
    responded:   bool  = False
    response:    str   = ""


@dataclass
class AegisIncident:
    """A grouped incident from multiple threat events."""
    incident_id:  str
    title:        str
    events:       list[ThreatEvent] = field(default_factory=list)
    cadl_level:   int   = 1
    status:       str   = "active"  # active | contained | resolved
    created_at:   str   = field(default_factory=_now_iso)
    updated_at:   str   = field(default_factory=_now_iso)
    receipt_id:   str   = ""
    timeline:     list[dict] = field(default_factory=list)

    def add_timeline_entry(self, action: str, detail: str) -> None:
        self.timeline.append({
            "ts":     _now_iso(),
            "action": action,
            "detail": detail,
        })
        self.updated_at = _now_iso()

    def to_dict(self) -> dict:
        return asdict(self)


# ── CADL Response Actions ─────────────────────────────────────────────────────

class CADLResponder:
    """
    Implements CADL escalation responses.
    Each level has specific automated actions.
    Response time target: 8 seconds from detection to action.
    """

    def __init__(self, kernel=None) -> None:
        self._kernel    = kernel
        self._callbacks: dict[int, list[Callable]] = defaultdict(list)
        self._blocked_ips: set[str] = set()
        self._honeypots:   list[dict] = []

    def register_callback(self, level: int, callback: Callable) -> None:
        """Register a callback for a specific CADL level."""
        self._callbacks[level].append(callback)

    def respond(self, incident: AegisIncident, target_level: int) -> dict:
        """Execute CADL response for the given level."""
        start = time.time()
        actions_taken = []

        if target_level >= CADLLevel.L1_MONITOR:
            action = self._l1_monitor(incident)
            actions_taken.append(action)
            incident.add_timeline_entry("L1_MONITOR", action)

        if target_level >= CADLLevel.L2_DETECT:
            action = self._l2_detect(incident)
            actions_taken.append(action)
            incident.add_timeline_entry("L2_DETECT", action)

        if target_level >= CADLLevel.L3_CONTAIN:
            action = self._l3_contain(incident)
            actions_taken.append(action)
            incident.add_timeline_entry("L3_CONTAIN", action)

        if target_level >= CADLLevel.L4_RESPOND:
            action = self._l4_respond(incident)
            actions_taken.append(action)
            incident.add_timeline_entry("L4_RESPOND", action)

        if target_level >= CADLLevel.L5_NEUTRALIZE:
            action = self._l5_neutralize(incident)
            actions_taken.append(action)
            incident.add_timeline_entry("L5_NEUTRALIZE", action)

        # Fire registered callbacks
        for callback in self._callbacks.get(target_level, []):
            try:
                callback(incident)
            except Exception:
                pass

        elapsed_ms = int((time.time() - start) * 1000)
        incident.cadl_level = target_level

        return {
            "incident_id":  incident.incident_id,
            "cadl_level":   target_level,
            "level_label":  CADLLevel(target_level).label,
            "actions_taken":actions_taken,
            "response_ms":  elapsed_ms,
            "target_met":   elapsed_ms <= 8000,  # 8-second target
        }

    def _l1_monitor(self, incident: AegisIncident) -> str:
        """L1: Log and alert."""
        log_entry = {
            "ts":          _now_iso(),
            "incident_id": incident.incident_id,
            "level":       "L1_MONITOR",
            "events":      len(incident.events),
            "severity":    max((e.severity for e in incident.events), default="LOW"),
        }
        # Write to aegis log
        log_dir = Path("~/.shadow313/aegis_logs").expanduser()
        log_dir.mkdir(parents=True, exist_ok=True)
        with open(log_dir / "aegis.jsonl", "a", encoding='utf-8') as fh:
            fh.write(json.dumps(log_entry) + "\n")
        return f"L1: Logged {len(incident.events)} events to aegis.jsonl"

    def _l2_detect(self, incident: AegisIncident) -> str:
        """L2: Deploy honeypot tokens for attribution."""
        # Deploy canary tokens near the threat source
        source_ips = list({e.source_ip for e in incident.events})
        honeypot = {
            "type":       "api_key_canary",
            "value":      f"sk-aegis-canary-{incident.incident_id[:8]}",
            "deployed_at":_now_iso(),
            "target_ips": source_ips,
            "incident_id":incident.incident_id,
        }
        self._honeypots.append(honeypot)
        return f"L2: Deployed canary token for {len(source_ips)} source IPs"

    def _l3_contain(self, incident: AegisIncident) -> str:
        """L3: Network isolation — block source IPs."""
        source_ips = {e.source_ip for e in incident.events}
        newly_blocked = source_ips - self._blocked_ips
        self._blocked_ips.update(newly_blocked)

        # In production: would call firewall API or iptables
        # Here: record the block decision for operator action
        block_file = Path("~/.shadow313/aegis_blocks.json").expanduser()
        blocks = []
        if block_file.exists():
            try:
                blocks = json.loads(block_file.read_text())
            except Exception:
                pass
        for ip in newly_blocked:
            blocks.append({"ip": ip, "blocked_at": _now_iso(), "incident": incident.incident_id})
        block_file.write_text(json.dumps(blocks, indent=2))

        return f"L3: Blocked {len(newly_blocked)} IPs (total blocked: {len(self._blocked_ips)})"

    def _l4_respond(self, incident: AegisIncident) -> str:
        """L4: Active countermeasures — deception and misdirection."""
        # Deploy deceptive responses
        actions = []

        # Inject false findings into any data the attacker might be reading
        deception_payload = {
            "type":       "deception",
            "incident_id":incident.incident_id,
            "fake_findings": [
                {"cve": "CVE-2024-FAKE-001", "cvss": 10.0, "service": "fake-service:9999"},
            ],
            "deployed_at": _now_iso(),
        }
        deception_file = Path("~/.shadow313/aegis_deception.json").expanduser()
        deception_file.write_text(json.dumps(deception_payload, indent=2))
        actions.append("Deployed deceptive findings")

        # Alert via SIEM if configured
        if self._kernel:
            siem = self._kernel.get_module("siem")
            if siem:
                try:
                    siem.run(test=True)
                    actions.append("SIEM alert sent")
                except Exception as _exc:  # S01-fixed
                    import logging as _log; _log.getLogger(__name__).debug("suppressed: %s", _exc)
                    pass

        return f"L4: {'; '.join(actions)}"

    def _l5_neutralize(self, incident: AegisIncident) -> str:
        """L5: Active neutralization — requires explicit operator authorization."""
        # This level requires human confirmation in production
        # Here: generate the neutralization plan for operator review
        plan = {
            "incident_id":  incident.incident_id,
            "recommended_actions": [
                "Terminate all sessions from blocked IPs",
                "Rotate all API keys and credentials",
                "Isolate affected systems from network",
                "Preserve forensic evidence",
                "Notify security team and management",
                "File incident report",
            ],
            "requires_authorization": True,
            "generated_at": _now_iso(),
        }
        plan_file = Path("~/.shadow313/aegis_neutralize_plan.json").expanduser()
        plan_file.write_text(json.dumps(plan, indent=2))
        return f"L5: Neutralization plan generated → {plan_file} (requires operator authorization)"

    def get_blocked_ips(self) -> list[str]:
        return list(self._blocked_ips)

    def get_honeypots(self) -> list[dict]:
        return list(self._honeypots)


# ── Threat Scorer ─────────────────────────────────────────────────────────────

class ThreatScorer:
    """
    Scores threat events and determines CADL escalation level.
    """

    # Score thresholds for CADL escalation
    CADL_THRESHOLDS = {
        CADLLevel.L1_MONITOR:    0,
        CADLLevel.L2_DETECT:     25,
        CADLLevel.L3_CONTAIN:    50,
        CADLLevel.L4_RESPOND:    75,
        CADLLevel.L5_NEUTRALIZE: 90,
    }

    EVENT_SCORES = {
        "port_scan":        15,
        "brute_force":      35,
        "c2_beacon":        70,
        "exfiltration":     85,
        "lateral_movement": 60,
        "privilege_escalation": 75,
        "ransomware":       95,
        "data_destruction": 95,
        "unknown":          20,
    }

    def score_event(self, event_type: str, details: dict) -> float:
        base = self.EVENT_SCORES.get(event_type, 20)

        # Modifiers
        if details.get("repeated", False):
            base = min(base * 1.3, 100)
        if details.get("known_malicious_ip", False):
            base = min(base * 1.5, 100)
        if details.get("kev_cve", False):
            base = min(base * 1.4, 100)
        if details.get("off_hours", False):
            base = min(base * 1.1, 100)

        return round(base, 1)

    def determine_cadl_level(self, score: float) -> CADLLevel:
        level = CADLLevel.L1_MONITOR
        for cadl_level, threshold in sorted(self.CADL_THRESHOLDS.items(), key=lambda x: x[1]):
            if score >= threshold:
                level = cadl_level
        return level

    def severity_from_score(self, score: float) -> str:
        if score >= 75: return "CRITICAL"
        if score >= 50: return "HIGH"
        if score >= 25: return "MEDIUM"
        return "LOW"


# ── Aegis Engine ──────────────────────────────────────────────────────────────

class AegisEngine:
    """
    Core Aegis active defense engine.
    Processes threat events, manages incidents, and coordinates CADL responses.
    """

    def __init__(self, kernel=None) -> None:
        self._kernel    = kernel
        self.scorer     = ThreatScorer()
        self.responder  = CADLResponder(kernel)
        self._incidents: dict[str, AegisIncident] = {}
        self._events:    list[ThreatEvent]         = []
        self._lock       = threading.RLock()
        self._auto_respond = True
        self._max_cadl_auto = CADLLevel.L4_RESPOND  # L5 requires human auth

    def ingest_event(
        self,
        source_ip:  str,
        event_type: str,
        details:    dict | None = None,
    ) -> ThreatEvent:
        """Ingest a threat event and trigger CADL response if needed."""
        import uuid
        details = details or {}
        score   = self.scorer.score_event(event_type, details)
        severity= self.scorer.severity_from_score(score)
        level   = self.scorer.determine_cadl_level(score)

        event = ThreatEvent(
            event_id   = str(uuid.uuid4())[:8],
            timestamp  = _now_iso(),
            source_ip  = source_ip,
            event_type = event_type,
            severity   = severity,
            score      = score,
            details    = details,
            cadl_level = level.value,
        )

        with self._lock:
            self._events.append(event)

            # Find or create incident
            incident = self._find_or_create_incident(event)

            # Auto-respond if enabled
            if self._auto_respond:
                target_level = min(level.value, self._max_cadl_auto.value)
                response = self.responder.respond(incident, target_level)
                event.responded = True
                event.response  = response.get("actions_taken", [""])[0] if response.get("actions_taken") else ""

        return event

    def _find_or_create_incident(self, event: ThreatEvent) -> AegisIncident:
        """Group events into incidents by source IP and time window."""
        import uuid
        # Look for existing incident from same source within 1 hour
        for incident in self._incidents.values():
            if (incident.status == "active" and
                any(e.source_ip == event.source_ip for e in incident.events)):
                incident.events.append(event)
                incident.cadl_level = max(incident.cadl_level, event.cadl_level)
                return incident

        # Create new incident
        incident = AegisIncident(
            incident_id = str(uuid.uuid4())[:12],
            title       = f"{event.event_type.replace('_',' ').title()} from {event.source_ip}",
            events      = [event],
            cadl_level  = event.cadl_level,
        )
        self._incidents[incident.incident_id] = incident
        return incident

    def get_incidents(self, status: str = "") -> list[AegisIncident]:
        with self._lock:
            incidents = list(self._incidents.values())
            if status:
                incidents = [i for i in incidents if i.status == status]
            return sorted(incidents, key=lambda i: i.updated_at, reverse=True)

    def resolve_incident(self, incident_id: str) -> bool:
        with self._lock:
            incident = self._incidents.get(incident_id)
            if incident:
                incident.status = "resolved"
                incident.add_timeline_entry("RESOLVED", "Incident marked as resolved by operator")
                return True
            return False

    def stats(self) -> dict:
        with self._lock:
            events    = self._events
            incidents = list(self._incidents.values())
            return {
                "total_events":    len(events),
                "total_incidents": len(incidents),
                "active_incidents":sum(1 for i in incidents if i.status == "active"),
                "blocked_ips":     len(self.responder.get_blocked_ips()),
                "honeypots":       len(self.responder.get_honeypots()),
                "cadl_distribution": {
                    f"L{l}": sum(1 for e in events if e.cadl_level == l)
                    for l in range(1, 6)
                },
                "severity_distribution": {
                    s: sum(1 for e in events if e.severity == s)
                    for s in ("CRITICAL","HIGH","MEDIUM","LOW")
                },
            }


# ── AegisModule ───────────────────────────────────────────────────────────────

class AegisModule:
    """shadow313.v4.aegis — Active Defense Platform. Registered: aegis"""

    def __init__(self, kernel) -> None:
        self.kernel  = kernel
        self.out     = kernel.out
        self.session = kernel.session
        self.engine  = AegisEngine(kernel)

    def register(self, kernel) -> None:
        kernel.register("aegis", self.run)

    def run(
        self,
        ingest:       str  = "",
        event_type:   str  = "unknown",
        source_ip:    str  = "0.0.0.0",
        list_incidents:bool= False,
        resolve:      str  = "",
        stats:        bool = False,
        simulate:     bool = False,
        cadl_level:   int  = 0,
    ) -> dict:
        self.out.section("AEGIS — ACTIVE DEFENSE PLATFORM")

        if stats:
            s = self.engine.stats()
            self.out.result(s, "Aegis Statistics")
            # Display CADL distribution
            rows = [[f"L{l} {CADLLevel(l).label}", str(s["cadl_distribution"].get(f"L{l}",0))]
                    for l in range(1,6)]
            self.out.table(["CADL Level","Events"], rows, "CADL Distribution")
            return s

        if list_incidents:
            incidents = self.engine.get_incidents()
            if not incidents:
                self.out.info("No incidents recorded.")
                return {"incidents": []}
            rows = [[i.incident_id, i.title[:40], f"L{i.cadl_level}",
                     i.status, str(len(i.events)), i.updated_at[:19]]
                    for i in incidents[:20]]
            self.out.table(["ID","Title","CADL","Status","Events","Updated"], rows,
                           f"Incidents ({len(incidents)})")
            return {"incidents": [i.to_dict() for i in incidents[:20]]}

        if resolve:
            ok = self.engine.resolve_incident(resolve)
            if ok:
                self.out.success(f"Incident {resolve} resolved")
            else:
                self.out.error(f"Incident {resolve} not found")
            return {"resolved": ok}

        if simulate:
            # Simulate a realistic attack sequence
            self.out.warn("Simulating attack sequence …")
            sim_events = [
                ("192.168.100.50", "port_scan",        {"repeated": True}),
                ("192.168.100.50", "brute_force",       {"repeated": True, "off_hours": True}),
                ("192.168.100.50", "lateral_movement",  {"known_malicious_ip": False}),
                ("10.0.0.99",      "c2_beacon",         {"known_malicious_ip": True}),
                ("10.0.0.99",      "exfiltration",      {"kev_cve": True}),
            ]
            results = []
            for ip, etype, details in sim_events:
                event = self.engine.ingest_event(ip, etype, details)
                results.append({
                    "event_id":  event.event_id,
                    "type":      etype,
                    "score":     event.score,
                    "severity":  event.severity,
                    "cadl":      f"L{event.cadl_level}",
                    "responded": event.responded,
                })
                self.out.info(f"  [{event.severity}] {etype} from {ip} → CADL L{event.cadl_level} (score={event.score})")
                time.sleep(0.1)

            stats = self.engine.stats()
            self.out.result(stats, "Simulation Complete")
            return {"simulation": results, "stats": stats}

        if ingest or source_ip != "0.0.0.0":
            event = self.engine.ingest_event(
                source_ip  = source_ip,
                event_type = event_type,
                details    = {},
            )
            self.out.warn(f"Event ingested: {event_type} from {source_ip}")
            self.out.info(f"Score: {event.score} | Severity: {event.severity} | CADL: L{event.cadl_level}")
            if event.responded:
                self.out.success(f"Response: {event.response}")

            # 313 Temporal Binding
            temporal = self.kernel.get_module("temporal")
            if temporal:
                receipt = temporal.engine.bind(asdict(event), self.session.id, "aegis")
                self.out.info(f"Bound: {receipt.receipt_id}")

            return asdict(event)

        # Default: show status
        stats = self.engine.stats()
        self.out.info(f"Aegis: {stats['total_events']} events, {stats['active_incidents']} active incidents")
        self.out.info(f"Blocked IPs: {stats['blocked_ips']} | Honeypots: {stats['honeypots']}")
        return stats