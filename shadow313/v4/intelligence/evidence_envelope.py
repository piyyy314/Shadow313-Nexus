"""
shadow313.v4.intelligence.evidence_envelope
Canonical Evidence Envelope — Shadow313 NEXUS v4

Implements the canonical signed evidence schema from the 90-Day Roadmap (G-02).
Every platform observation and action is wrapped in a signed, classified,
attributable evidence envelope.

Provenance classes (from roadmap):
  REAL_OBSERVATION  — live sensor data from AEGIS/eBPF/honeypot
  SYNTHETIC_TEST    — generated test data
  SIMULATION        — simulation output (SIM-2026-*)
  DEMO              — demonstration data
  REPLAY            — replayed historical event
  MODEL_GENERATED   — output from PE-7 or other ML model
  EXTERNAL_SOURCE   — third-party threat intel feed

Minimum fields (from Governance doc):
  event_id, schema_version, source_system, source_identity
  tenant, environment, observed_at, ingested_at
  event_type, severity, confidence, provenance_class
  evidence_hash, signature, trusted_timestamp, sequence/loss state
  secret_redaction_status, chain_of_custody, validation_status
"""
from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


# ── Provenance Classification ─────────────────────────────────────────────────

class ProvenanceClass(str, Enum):
    """Mandatory provenance classification for all evidence records."""
    REAL_OBSERVATION = "REAL_OBSERVATION"   # Live sensor data
    SYNTHETIC_TEST   = "SYNTHETIC_TEST"     # Generated test data
    SIMULATION       = "SIMULATION"         # Simulation output
    DEMO             = "DEMO"               # Demonstration data
    REPLAY           = "REPLAY"             # Replayed historical event
    MODEL_GENERATED  = "MODEL_GENERATED"    # ML model output
    EXTERNAL_SOURCE  = "EXTERNAL_SOURCE"    # Third-party threat intel


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class ValidationStatus(str, Enum):
    PENDING   = "PENDING"
    VERIFIED  = "VERIFIED"
    REJECTED  = "REJECTED"
    DISPUTED  = "DISPUTED"


class RedactionStatus(str, Enum):
    CLEAN     = "CLEAN"       # No secrets detected
    REDACTED  = "REDACTED"    # Secrets found and redacted
    PENDING   = "PENDING"     # Not yet scanned
    FLAGGED   = "FLAGGED"     # Secrets found, not yet redacted


# ── Evidence Envelope ─────────────────────────────────────────────────────────

@dataclass
class EvidenceEnvelope:
    """
    Canonical signed evidence envelope — Shadow313 NEXUS v4.

    Every platform observation, detection, action, and forensic export
    must be wrapped in this envelope before storage or transmission.

    Schema version: 1.0 (Evidence Envelope v1 from 90-Day Roadmap)
    """
    # ── Identity ──────────────────────────────────────────────────────────────
    event_id:         str
    schema_version:   str = "1.0"
    source_system:    str = ""   # AEGIS | APC | NEXUS | Ghost-Watch | Honeypot | eBPF
    source_identity:  str = ""   # Sensor/agent ID

    # ── Tenancy ───────────────────────────────────────────────────────────────
    tenant:           str = "shadow313-nexus"
    environment:      str = "production"  # production | staging | test | demo

    # ── Timing ────────────────────────────────────────────────────────────────
    observed_at:      str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    ingested_at:      str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # ── Classification ────────────────────────────────────────────────────────
    event_type:       str = ""
    severity:         str = Severity.INFO.value
    confidence:       float = 1.0
    provenance_class: str = ProvenanceClass.REAL_OBSERVATION.value

    # ── References ────────────────────────────────────────────────────────────
    asset:            Optional[str] = None
    workload:         Optional[str] = None
    process:          Optional[str] = None
    source_ip:        Optional[str] = None
    technique:        Optional[str] = None  # ATT&CK technique ID
    tactic:           Optional[str] = None

    # ── Versions ──────────────────────────────────────────────────────────────
    rule_version:     Optional[str] = None
    model_version:    Optional[str] = None
    policy_version:   Optional[str] = None

    # ── Action ────────────────────────────────────────────────────────────────
    action_requested:  Optional[str] = None
    action_authorized: Optional[str] = None
    action_executed:   Optional[str] = None
    action_result:     Optional[str] = None

    # ── Payload ───────────────────────────────────────────────────────────────
    payload:          Optional[dict] = None

    # ── Integrity ─────────────────────────────────────────────────────────────
    evidence_hash:    str = ""
    signature:        str = ""
    trusted_timestamp: str = ""
    sequence_number:  int  = 0
    loss_indicator:   bool = False

    # ── Governance ────────────────────────────────────────────────────────────
    secret_redaction_status: str = RedactionStatus.PENDING.value
    chain_of_custody:        list[str] = field(default_factory=list)
    validation_status:       str = ValidationStatus.PENDING.value
    review_status:           str = "UNREVIEWED"

    def to_dict(self) -> dict:
        return {
            "event_id":               self.event_id,
            "schema_version":         self.schema_version,
            "source_system":          self.source_system,
            "source_identity":        self.source_identity,
            "tenant":                 self.tenant,
            "environment":            self.environment,
            "observed_at":            self.observed_at,
            "ingested_at":            self.ingested_at,
            "event_type":             self.event_type,
            "severity":               self.severity,
            "confidence":             self.confidence,
            "provenance_class":       self.provenance_class,
            "asset":                  self.asset,
            "workload":               self.workload,
            "process":                self.process,
            "source_ip":              self.source_ip,
            "technique":              self.technique,
            "tactic":                 self.tactic,
            "rule_version":           self.rule_version,
            "model_version":          self.model_version,
            "action_requested":       self.action_requested,
            "action_authorized":      self.action_authorized,
            "action_executed":        self.action_executed,
            "action_result":          self.action_result,
            "payload":                self.payload,
            "evidence_hash":          self.evidence_hash,
            "signature":              self.signature,
            "trusted_timestamp":      self.trusted_timestamp,
            "sequence_number":        self.sequence_number,
            "loss_indicator":         self.loss_indicator,
            "secret_redaction_status": self.secret_redaction_status,
            "chain_of_custody":       self.chain_of_custody,
            "validation_status":      self.validation_status,
            "review_status":          self.review_status,
        }


# ── Evidence Factory ──────────────────────────────────────────────────────────

class EvidenceFactory:
    """
    Creates and signs evidence envelopes for all Shadow313 NEXUS subsystems.

    Usage:
        factory = EvidenceFactory(source_system="AEGIS", tenant="shadow313")

        # From honeypot event
        env = factory.from_honeypot_event(source_ip="185.220.101.5", ...)

        # From eBPF intercept
        env = factory.from_ebpf_event(comm="curl", syscall="execve", ...)

        # From detection finding
        env = factory.from_detection(technique="T1505.003", score=0.99, ...)

        # From simulation result
        env = factory.from_simulation(sim_id="SIM-2026-1001", ...)
    """

    SCHEMA_VERSION = "1.0"
    _sequence: int = 0

    def __init__(
        self,
        source_system:   str = "NEXUS",
        source_identity: str = "shadow313-nexus-v4",
        tenant:          str = "shadow313-nexus",
        environment:     str = "production",
    ) -> None:
        self.source_system   = source_system
        self.source_identity = source_identity
        self.tenant          = tenant
        self.environment     = environment

    def _next_seq(self) -> int:
        EvidenceFactory._sequence += 1
        return EvidenceFactory._sequence

    def _make_event_id(self) -> str:
        return f"EVT-{secrets.token_hex(6).upper()}"

    def _compute_hash(self, envelope: EvidenceEnvelope) -> str:
        """Compute SHA3-256 hash of envelope content."""
        import json
        content = json.dumps({
            "event_id":       envelope.event_id,
            "event_type":     envelope.event_type,
            "observed_at":    envelope.observed_at,
            "source_system":  envelope.source_system,
            "provenance_class": envelope.provenance_class,
            "payload":        envelope.payload,
        }, sort_keys=True, default=str)
        return "sha3_256:" + hashlib.sha3_256(content.encode()).hexdigest()

    def _sign(self, envelope: EvidenceEnvelope) -> str:
        """Simulated SLH-DSA signature (real implementation uses pyspx)."""
        ts = time.time_ns()
        ts = int(str(ts)[:-3] + "313")
        return f"SLH-DSA-SIM:{ts}:{envelope.evidence_hash[:16]}"

    def _trusted_timestamp(self) -> str:
        """313-BIND style trusted timestamp."""
        ts = time.time_ns()
        ts = int(str(ts)[:-3] + "313")
        return f"313-TS:{ts}"

    def _finalize(self, envelope: EvidenceEnvelope) -> EvidenceEnvelope:
        """Compute hash, sign, and add trusted timestamp."""
        envelope.sequence_number  = self._next_seq()
        envelope.evidence_hash    = self._compute_hash(envelope)
        envelope.signature        = self._sign(envelope)
        envelope.trusted_timestamp = self._trusted_timestamp()
        envelope.chain_of_custody.append(
            f"{self.source_system}:{datetime.now(timezone.utc).isoformat()}"
        )
        return envelope

    def from_honeypot_event(
        self,
        source_ip:  str,
        service:    str,
        action:     str,
        technique:  Optional[str] = None,
        severity:   str = Severity.HIGH.value,
        blocked:    bool = True,
        payload:    Optional[dict] = None,
    ) -> EvidenceEnvelope:
        """Create evidence envelope from honeypot event."""
        env = EvidenceEnvelope(
            event_id=self._make_event_id(),
            schema_version=self.SCHEMA_VERSION,
            source_system=f"HONEYPOT-{service}",
            source_identity=self.source_identity,
            tenant=self.tenant,
            environment=self.environment,
            event_type=f"honeypot.{service.lower()}.intercept",
            severity=severity,
            confidence=0.99,
            provenance_class=ProvenanceClass.REAL_OBSERVATION.value,
            source_ip=source_ip,
            technique=technique,
            action_requested=action,
            action_executed="BLOCK" if blocked else "MONITOR",
            action_result="BLOCKED" if blocked else "LOGGED",
            payload=payload or {"action": action, "service": service},
            secret_redaction_status=RedactionStatus.CLEAN.value,
            validation_status=ValidationStatus.VERIFIED.value,
        )
        return self._finalize(env)

    def from_ebpf_event(
        self,
        comm:     str,
        syscall:  str,
        args:     str,
        pid:      int = 0,
        status:   str = "intercepted",
        severity: str = Severity.HIGH.value,
    ) -> EvidenceEnvelope:
        """Create evidence envelope from eBPF kernel intercept."""
        env = EvidenceEnvelope(
            event_id=self._make_event_id(),
            schema_version=self.SCHEMA_VERSION,
            source_system="AEGIS-EBPF",
            source_identity=self.source_identity,
            tenant=self.tenant,
            environment=self.environment,
            event_type=f"ebpf.syscall.{syscall}",
            severity=severity,
            confidence=0.98,
            provenance_class=ProvenanceClass.REAL_OBSERVATION.value,
            process=f"{comm}[{pid}]",
            action_requested=f"{syscall}({args})",
            action_executed=status.upper(),
            action_result=status.upper(),
            payload={"comm": comm, "syscall": syscall, "args": args, "pid": pid},
            secret_redaction_status=RedactionStatus.CLEAN.value,
            validation_status=ValidationStatus.VERIFIED.value,
        )
        return self._finalize(env)

    def from_detection(
        self,
        technique:    str,
        tactic:       str,
        score:        float,
        source_ip:    Optional[str] = None,
        rule_id:      Optional[str] = None,
        description:  str = "",
        severity:     str = Severity.HIGH.value,
    ) -> EvidenceEnvelope:
        """Create evidence envelope from detection finding."""
        env = EvidenceEnvelope(
            event_id=self._make_event_id(),
            schema_version=self.SCHEMA_VERSION,
            source_system=self.source_system,
            source_identity=self.source_identity,
            tenant=self.tenant,
            environment=self.environment,
            event_type="detection.finding",
            severity=severity,
            confidence=score,
            provenance_class=ProvenanceClass.REAL_OBSERVATION.value,
            source_ip=source_ip,
            technique=technique,
            tactic=tactic,
            rule_version=rule_id,
            payload={"technique": technique, "score": score, "description": description},
            secret_redaction_status=RedactionStatus.CLEAN.value,
            validation_status=ValidationStatus.VERIFIED.value,
        )
        return self._finalize(env)

    def from_simulation(
        self,
        sim_id:       str,
        threat_id:    str,
        detected:     bool,
        score:        float,
        technique:    str = "",
    ) -> EvidenceEnvelope:
        """Create evidence envelope from simulation result — SIMULATION provenance."""
        env = EvidenceEnvelope(
            event_id=self._make_event_id(),
            schema_version=self.SCHEMA_VERSION,
            source_system="NEXUS-SIM",
            source_identity=self.source_identity,
            tenant=self.tenant,
            environment="simulation",  # Never production
            event_type="simulation.threat.result",
            severity=Severity.INFO.value,
            confidence=score,
            provenance_class=ProvenanceClass.SIMULATION.value,  # CRITICAL: not REAL
            technique=technique,
            payload={
                "sim_id":   sim_id,
                "threat_id": threat_id,
                "detected": detected,
                "score":    score,
            },
            secret_redaction_status=RedactionStatus.CLEAN.value,
            validation_status=ValidationStatus.VERIFIED.value,
        )
        return self._finalize(env)

    def from_weforge_decoy(
        self,
        decoy_id:    str,
        target_node: str,
        dns_beacon:  str,
        watermark:   str,
    ) -> EvidenceEnvelope:
        """Create evidence envelope from WE-FORGE decoy trigger."""
        env = EvidenceEnvelope(
            event_id=self._make_event_id(),
            schema_version=self.SCHEMA_VERSION,
            source_system="GHOST-WATCH",
            source_identity=self.source_identity,
            tenant=self.tenant,
            environment=self.environment,
            event_type="deception.decoy.triggered",
            severity=Severity.MEDIUM.value,
            confidence=0.95,
            provenance_class=ProvenanceClass.REAL_OBSERVATION.value,
            technique="T1598",
            tactic="reconnaissance",
            payload={
                "decoy_id":    decoy_id,
                "target_node": target_node,
                "dns_beacon":  dns_beacon,
                "watermark":   watermark,
            },
            secret_redaction_status=RedactionStatus.CLEAN.value,
            validation_status=ValidationStatus.VERIFIED.value,
        )
        return self._finalize(env)


# ── Provenance Classifier ─────────────────────────────────────────────────────

class ProvenanceClassifier:
    """
    Classifies evidence records by provenance class.
    Ensures synthetic/simulation data is never mixed with real observations.

    From 90-Day Roadmap requirement:
    'Synthetic and simulation data are excluded from production and audit views by default.'
    """

    PRODUCTION_CLASSES = {
        ProvenanceClass.REAL_OBSERVATION,
        ProvenanceClass.EXTERNAL_SOURCE,
    }

    EXCLUDED_FROM_PRODUCTION = {
        ProvenanceClass.SYNTHETIC_TEST,
        ProvenanceClass.SIMULATION,
        ProvenanceClass.DEMO,
        ProvenanceClass.REPLAY,
        ProvenanceClass.MODEL_GENERATED,
    }

    @classmethod
    def is_production_eligible(cls, envelope: EvidenceEnvelope) -> bool:
        """Check if evidence is eligible for production/audit views."""
        return ProvenanceClass(envelope.provenance_class) in cls.PRODUCTION_CLASSES

    @classmethod
    def classify_from_source(cls, source_system: str, environment: str) -> ProvenanceClass:
        """Auto-classify provenance from source system and environment."""
        if environment in ("simulation", "test", "demo"):
            if "sim" in source_system.lower():
                return ProvenanceClass.SIMULATION
            if "demo" in source_system.lower():
                return ProvenanceClass.DEMO
            return ProvenanceClass.SYNTHETIC_TEST

        if "honeypot" in source_system.lower():
            return ProvenanceClass.REAL_OBSERVATION
        if "ebpf" in source_system.lower() or "aegis" in source_system.lower():
            return ProvenanceClass.REAL_OBSERVATION
        if "ghost-watch" in source_system.lower():
            return ProvenanceClass.REAL_OBSERVATION
        if "misp" in source_system.lower() or "otx" in source_system.lower():
            return ProvenanceClass.EXTERNAL_SOURCE
        if "model" in source_system.lower() or "pe7" in source_system.lower():
            return ProvenanceClass.MODEL_GENERATED

        return ProvenanceClass.REAL_OBSERVATION

    @classmethod
    def filter_for_production(cls, envelopes: list[EvidenceEnvelope]) -> list[EvidenceEnvelope]:
        """Filter evidence list to production-eligible records only."""
        return [e for e in envelopes if cls.is_production_eligible(e)]

    @classmethod
    def audit_provenance_coverage(cls, envelopes: list[EvidenceEnvelope]) -> dict:
        """Audit provenance classification coverage across a set of envelopes."""
        counts: dict[str, int] = {}
        unclassified = 0

        for env in envelopes:
            try:
                pc = ProvenanceClass(env.provenance_class)
                counts[pc.value] = counts.get(pc.value, 0) + 1
            except ValueError:
                unclassified += 1

        total = len(envelopes)
        return {
            "total":          total,
            "classified":     total - unclassified,
            "unclassified":   unclassified,
            "coverage_pct":   round((total - unclassified) / total * 100, 1) if total else 0,
            "by_class":       counts,
            "production_eligible": sum(
                v for k, v in counts.items()
                if ProvenanceClass(k) in cls.PRODUCTION_CLASSES
            ),
        }
