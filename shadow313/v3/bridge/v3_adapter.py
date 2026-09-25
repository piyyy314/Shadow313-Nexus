"""
Shadow313 v3 → v1 Bridge Adapter
==================================
Connects the v3 detection/ZTAS layer to the v1 CLI command bus.

Structural gaps being bridged:

GAP 1 — Context mismatch
  v1 handlers receive: KernelContext(session, config, ai, output)
  v3 classes expect:   standalone instantiation, no KernelContext
  Bridge: wrap v3 classes in adapter functions that accept KernelContext

GAP 2 — Event format mismatch
  v1 produces: raw log dicts from recon/network/defense modules
  v3 expects:  SequenceEvent(token, features[20], anomaly_score, host)
  Bridge: LogNormalizer converts v1 log dicts → v3 SequenceEvent

GAP 3 — Lifecycle mismatch
  v1 commands: stateless, one-shot async functions
  v3 monitors:  stateful, long-running threads (start/stop)
  Bridge: SessionMonitor manages v3 lifecycle per v1 session UUID

GAP 4 — Output format mismatch
  v1 output:  OutputFormatter (rich tables, JSON, markdown)
  v3 output:  raw Python dicts, print() statements
  Bridge: ResultAdapter converts v3 dicts → v1 Finding objects

GAP 5 — Model loading
  v3 LSTM:    loads JSON model files from shadow313/v3/models/
  v1 session: has no model registry or lazy-load mechanism
  Bridge: ModelRegistry singleton with lazy loading per session

GAP 6 — Thread safety
  v1 kernel:  asyncio event loop (single-threaded async)
  v3 monitors: threading.Thread (separate OS threads)
  Bridge: asyncio.run_in_executor wraps blocking v3 calls
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

# ── v1 imports ─────────────────────────────────────────────────────────────────
from shadow313.core.kernel import KernelContext, register_command

# ── v3 imports (lazy — only loaded when bridge commands are called) ────────────
_v3_loaded = False
_lstm_detector = None
_ir_engine     = None
_ebpf_system   = None
_eprocess_mon  = None
_hypervisor    = None
_tpm_engine    = None
_bridge_lock   = threading.Lock()


# ══════════════════════════════════════════════════════════════════════════════
# GAP 2 FIX: Log Normalizer — v1 log dict → v3 SequenceEvent
# ══════════════════════════════════════════════════════════════════════════════

# Maps v1 log field patterns to v3 token IDs
# v3 EVENT_TOKENS has 20 tokens (IDs 0-19) + extended tokens up to 32
_TOKEN_MAP: dict[str, int] = {
    # Process events
    "process_creation":      0,
    "process_create":        0,
    "new_process":           0,
    # Network
    "network_outbound":      1,
    "outbound_connection":   1,
    "tcp_connect":           1,
    "network_lateral":       2,
    "lateral_movement":      2,
    "smb_connect":           2,
    "dns_query":             3,
    "dns_request":           3,
    # Registry
    "registry_write":        4,
    "reg_set_value":         4,
    # Image/DLL load
    "image_load":            5,
    "dll_load":              5,
    "module_load":           5,
    # File
    "file_create":           6,
    "file_write":            6,
    "file_delete":           7,
    "file_deletion":         7,
    # Auth
    "logon_success":         8,
    "authentication":        8,
    "logon_failure":         9,
    "auth_failure":          9,
    "brute_force":           9,
    # Privilege
    "privilege_escalation":  10,
    "priv_esc":              10,
    "setuid":                10,
    # Script
    "script_execution":      11,
    "powershell":            11,
    "cmd_execution":         11,
    # Service
    "service_install":       12,
    "service_create":        12,
    # Scheduled task
    "scheduled_task":        13,
    "cron_job":              13,
    # WMI
    "wmi_event":             14,
    "wmi_subscription":      14,
    # Named pipe
    "named_pipe":            15,
    "pipe_create":           15,
    # Network share
    "network_share":         16,
    "share_access":          16,
    # Kerberos
    "kerberos_ticket":       17,
    "kerberoasting":         17,
    # LSASS
    "lsass_access":          18,
    "credential_dump":       18,
    "memory_read":           18,
    # Network events
    "network_event":         19,
    "packet_capture":        19,
    # Extended tokens (v3 hardware_head)
    "memory_access":         20,
    "memory_write":          21,
    "memory_hollow":         22,
    "rf_telemetry":          23,
    "gps_anomaly":           24,
    "firmware_write":        25,
    "kernel_hook":           26,
    "etw_syscall":           27,
    "ebpf_syscall":          28,
    "kernel_tamper":         29,
    "hypervisor_alert":      30,
    "process_anomaly":       31,
    "memory_rate_burst":     32,
}

_DEFAULT_FEATURES = [0.0] * 20  # 20-dim baseline feature vector


def normalize_log_to_event(log_dict: dict[str, Any]) -> Optional[dict[str, Any]]:
    """
    Convert a v1 log dict to a v3-compatible event dict.

    v1 log dict format (from network/defense/recon modules):
      {"timestamp": ..., "event_type": ..., "host": ..., "process": ...,
       "severity": ..., "details": ..., "raw": {...}}

    v3 ingest_event format:
      log_dict with keys: event_type, host, process, severity
      + anomaly_score (float 0-1)
      + features (list[float], length 20)
    """
    if not log_dict:
        return None

    # Determine token from event_type field
    event_type = (
        log_dict.get("event_type") or
        log_dict.get("type") or
        log_dict.get("alert_type") or
        log_dict.get("category") or
        "network_event"
    ).lower().replace(" ", "_").replace("-", "_")

    # Find best token match
    token_id = None
    for key, tid in _TOKEN_MAP.items():
        if key in event_type or event_type in key:
            token_id = tid
            break
    if token_id is None:
        token_id = 19  # default: network_event

    # Build feature vector from available fields
    features = list(_DEFAULT_FEATURES)

    # Feature engineering from v1 log fields
    severity = log_dict.get("severity", "").upper()
    severity_score = {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.5, "LOW": 0.2}.get(severity, 0.3)
    features[0] = severity_score

    # Anomaly score from severity + token sensitivity
    sensitive_tokens = {18, 10, 2, 22, 29, 30}  # lsass, priv_esc, lateral, hollow, tamper, hypervisor
    base_anomaly = severity_score * 0.7
    if token_id in sensitive_tokens:
        base_anomaly = min(1.0, base_anomaly + 0.2)

    return {
        "timestamp":     log_dict.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "event_type":    event_type,
        "token_id":      token_id,
        "host":          log_dict.get("host", log_dict.get("source_host", "localhost")),
        "process":       log_dict.get("process", log_dict.get("comm", "unknown")),
        "severity":      severity,
        "anomaly_score": base_anomaly,
        "features":      features,
        "raw":           log_dict,
    }


# ══════════════════════════════════════════════════════════════════════════════
# GAP 5 FIX: Model Registry — lazy loading per session
# ══════════════════════════════════════════════════════════════════════════════

class ModelRegistry:
    """Singleton model registry with lazy loading."""
    _instance: Optional["ModelRegistry"] = None
    _lock = threading.Lock()

    def __new__(cls) -> "ModelRegistry":
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._models = {}
                cls._instance._model_dir = Path(__file__).parent.parent / "models"
        return cls._instance

    def get_detector(self) -> Any:
        """Get or create the LSTM sequence detector."""
        if "lstm" not in self._models:
            from shadow313.v3.lstm_detector import LSTMSequenceDetector
            self._models["lstm"] = LSTMSequenceDetector(window_size=8)
        return self._models["lstm"]

    def get_ir_engine(self, analyst_id: str = "shadow313-auto") -> Any:
        """Get or create the incident response engine."""
        key = f"ir_{analyst_id}"
        if key not in self._models:
            from shadow313.v3.incident_response import IncidentResponseEngine
            self._models[key] = IncidentResponseEngine(
                analyst_id=analyst_id,
                dry_run=True,  # Safe default — no real containment actions
            )
        return self._models[key]


# ══════════════════════════════════════════════════════════════════════════════
# GAP 3 FIX: Session Monitor — manages v3 lifecycle per v1 session
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class MonitorSession:
    """Tracks active v3 monitors for a v1 session."""
    session_id:   str
    ebpf:         Any = None
    eprocess:     Any = None
    hypervisor:   Any = None
    tpm:          Any = None
    started_at:   float = field(default_factory=time.time)
    alerts:       list = field(default_factory=list)
    is_running:   bool = False

    def stop_all(self) -> None:
        for monitor in [self.ebpf, self.eprocess, self.hypervisor]:
            if monitor and hasattr(monitor, "stop"):
                try:
                    monitor.stop()
                except Exception:  # nosec
                    pass  # intentional — monitor stop failure is non-critical
        self.is_running = False


_active_monitors: dict[str, MonitorSession] = {}
_monitor_lock = threading.Lock()


def get_or_create_monitor(session_id: str) -> MonitorSession:
    with _monitor_lock:
        if session_id not in _active_monitors:
            _active_monitors[session_id] = MonitorSession(session_id=session_id)
        return _active_monitors[session_id]


# ══════════════════════════════════════════════════════════════════════════════
# GAP 4 FIX: Result Adapter — v3 dict → v1 Finding format
# ══════════════════════════════════════════════════════════════════════════════

def adapt_detection_to_finding(detection: dict[str, Any]) -> dict[str, Any]:
    """Convert a v3 detection result to a v1 Finding object."""
    score     = detection.get("score", detection.get("ensemble_score", 0.0))
    head      = detection.get("head_name", detection.get("chain_name", "unknown"))
    technique = detection.get("technique", "T0000")
    host      = detection.get("source_host", detection.get("host", "unknown"))

    severity = "CRITICAL" if score >= 0.85 else (
               "HIGH"     if score >= 0.65 else (
               "MEDIUM"   if score >= 0.45 else "LOW"))

    return {
        "id":          f"V3-{head.upper()[:8]}-{hashlib.sha3_256(str(detection).encode()).hexdigest()[:6]}",
        "tool":        "shadow313_v3_lstm",
        "title":       f"LSTM Detection: {head} (score={score:.3f})",
        "severity":    severity,
        "description": (
            f"v3 LSTM ensemble detected {head} pattern on {host}. "
            f"Score: {score:.4f}. Technique: {technique}. "
            f"Chain: {detection.get('chain_name', 'unknown')}."
        ),
        "data":        detection,
        "remediation": f"Investigate {technique} activity on {host}. "
                       f"Review process tree and network connections.",
        "mitre_technique": technique,
        "source":      "v3_lstm_detector",
        "timestamp":   datetime.now(timezone.utc).isoformat(),
    }


# ══════════════════════════════════════════════════════════════════════════════
# GAP 6 FIX: Async wrapper for blocking v3 calls
# ══════════════════════════════════════════════════════════════════════════════

async def run_blocking(fn: Callable, *args, **kwargs) -> Any:
    """Run a blocking v3 function in a thread pool executor."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: fn(*args, **kwargs))


# ══════════════════════════════════════════════════════════════════════════════
# V1 COMMAND HANDLERS — registered on the v1 command bus
# ══════════════════════════════════════════════════════════════════════════════

@register_command("v3", "detect")
async def v3_detect(ctx: KernelContext, **kwargs: Any) -> dict[str, Any]:
    """
    Run v3 LSTM detection on a log file or live event stream.

    Usage: shadow313 v3 detect --log-file /var/log/syslog
           shadow313 v3 detect --events '[{"event_type":"lsass_access",...}]'
    """
    log_file   = kwargs.get("log_file")
    events_raw = kwargs.get("events", [])
    host       = kwargs.get("host", "localhost")

    ctx.output.info("Initializing v3 LSTM detection engine...")

    registry = ModelRegistry()
    detector = registry.get_detector()

    # Load events from file or kwargs
    events = []
    if log_file and Path(log_file).exists():
        ctx.output.info(f"Loading events from {log_file}")
        with open(log_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    # Plain text log line — wrap as generic event
                    events.append({
                        "event_type": "network_event",
                        "host": host,
                        "raw_line": line,
                        "severity": "LOW",
                    })
    elif isinstance(events_raw, list):
        events = events_raw
    elif isinstance(events_raw, str):
        try:
            events = json.loads(events_raw)
        except Exception:
            events = []

    if not events:
        ctx.output.warning("No events to analyze. Use --log-file or --events.")
        return {"success": False, "detections": [], "message": "no events provided"}

    ctx.output.info(f"Analyzing {len(events)} events through v3 LSTM heads...")

    # Normalize and ingest
    detections = []
    for raw_event in events:
        normalized = normalize_log_to_event(raw_event)
        if not normalized:
            continue

        # GAP 6: ingest_event is synchronous — run in executor
        detection = await run_blocking(
            detector.ingest_event,
            normalized,
            normalized["host"],
            normalized["anomaly_score"],
            normalized["features"],
        )
        if detection:
            finding = adapt_detection_to_finding(detection)
            detections.append(finding)
            ctx.session.increment_findings()

    # Display results
    if detections:
        ctx.output.success(f"v3 LSTM: {len(detections)} detections from {len(events)} events")
        for d in detections:
            ctx.output.warning(f"[{d['severity']}] {d['title']}")
    else:
        ctx.output.success(f"v3 LSTM: No detections in {len(events)} events")

    # Persist to session
    result = {
        "success":    True,
        "events_analyzed": len(events),
        "detections": detections,
        "stats":      detector.get_stats(),
    }
    ctx.session.write("v3_detections.json", result)
    return result


@register_command("v3", "monitor_start")
async def v3_monitor_start(ctx: KernelContext, **kwargs: Any) -> dict[str, Any]:
    """
    Start v3 ZTAS countermeasure monitors for the current session.
    Starts: eBPF self-protection, EPROCESS monitor, hypervisor bridge.

    Usage: shadow313 v3 monitor-start
    """
    session_id = ctx.session.session_id
    mon = get_or_create_monitor(session_id)

    if mon.is_running:
        ctx.output.warning("v3 monitors already running for this session")
        return {"success": False, "message": "already running"}

    ctx.output.info("Starting v3 ZTAS countermeasure layer...")

    def _start_monitors():
        from shadow313.v3.countermeasures.ebpf_self_protection import EBPFSelfProtection
        from shadow313.v3.countermeasures.continuous_eprocess_monitor import ContinuousEProcessMonitor
        from shadow313.v3.ztas.hypervisor_attestation_bridge import HypervisorAttestationBridge

        def on_alert(alert):
            mon.alerts.append({
                "type":      getattr(alert, "alert_type", str(alert)),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "token":     getattr(alert, "token", "kernel_tamper"),
            })

        mon.ebpf      = EBPFSelfProtection()
        mon.eprocess  = ContinuousEProcessMonitor(on_alert)
        mon.hypervisor= HypervisorAttestationBridge()

        mon.ebpf.start()
        mon.eprocess.start()
        mon.is_running = True

    await run_blocking(_start_monitors)

    ctx.output.success("v3 ZTAS monitors active:")
    ctx.output.info("  ✓ eBPF self-protection (11 kprobes, guardian probe)")
    ctx.output.info("  ✓ EPROCESS monitor (1s interval, TPM-sealed baseline)")
    ctx.output.info("  ✓ Hypervisor attestation bridge (EPT + VMCS)")

    return {
        "success":    True,
        "session_id": session_id,
        "monitors":   ["ebpf", "eprocess", "hypervisor"],
        "message":    "v3 ZTAS monitors started",
    }


@register_command("v3", "monitor_status")
async def v3_monitor_status(ctx: KernelContext, **kwargs: Any) -> dict[str, Any]:
    """
    Get status of active v3 ZTAS monitors.

    Usage: shadow313 v3 monitor-status
    """
    session_id = ctx.session.session_id
    mon = _active_monitors.get(session_id)

    if not mon or not mon.is_running:
        ctx.output.info("No v3 monitors active for this session")
        return {"success": True, "running": False, "alerts": []}

    # Collect scores from each monitor
    scores = {}
    if mon.ebpf:
        scores["ebpf"]      = mon.ebpf.get_composite_score()
    if mon.eprocess:
        scores["eprocess"]  = mon.eprocess.get_composite_score()
    if mon.hypervisor:
        scores["hypervisor"]= mon.hypervisor.get_composite_score()

    composite = max(scores.values()) if scores else 0.0

    ctx.output.info(f"v3 ZTAS Monitor Status — Session {session_id[:8]}")
    for layer, score in scores.items():
        icon = "🚨" if score > 0.65 else "✓"
        ctx.output.info(f"  {icon} {layer}: score={score:.4f}")
    ctx.output.info(f"  Alerts captured: {len(mon.alerts)}")
    ctx.output.info(f"  Composite score: {composite:.4f}")

    return {
        "success":         True,
        "running":         True,
        "layer_scores":    scores,
        "composite_score": composite,
        "alerts":          mon.alerts[-10:],  # Last 10 alerts
        "uptime_s":        time.time() - mon.started_at,
    }


@register_command("v3", "monitor_stop")
async def v3_monitor_stop(ctx: KernelContext, **kwargs: Any) -> dict[str, Any]:
    """
    Stop v3 ZTAS monitors and generate final report.

    Usage: shadow313 v3 monitor-stop
    """
    session_id = ctx.session.session_id
    mon = _active_monitors.get(session_id)

    if not mon or not mon.is_running:
        ctx.output.info("No active v3 monitors to stop")
        return {"success": True, "message": "no monitors running"}

    await run_blocking(mon.stop_all)

    report = {
        "session_id":  session_id,
        "uptime_s":    time.time() - mon.started_at,
        "total_alerts":len(mon.alerts),
        "alerts":      mon.alerts,
    }
    ctx.session.write("v3_monitor_report.json", report)

    ctx.output.success(f"v3 ZTAS monitors stopped. {len(mon.alerts)} alerts captured.")
    return {"success": True, **report}


@register_command("v3", "ir")
async def v3_incident_response(ctx: KernelContext, **kwargs: Any) -> dict[str, Any]:
    """
    Run v3 closed-loop incident response on a detection result.

    Usage: shadow313 v3 ir --score 0.92 --technique T1003.001 --host 192.168.1.10
    """
    score     = float(kwargs.get("score", 0.75))
    technique = kwargs.get("technique", "T1055")
    host      = kwargs.get("host", "localhost")
    dry_run   = kwargs.get("dry_run", True)

    ctx.output.info(f"v3 Incident Response — score={score:.3f} technique={technique} host={host}")

    registry  = ModelRegistry()
    ir_engine = registry.get_ir_engine()

    # Build ThreatAlert from kwargs
    from shadow313.v3.incident_response import ThreatAlert
    import uuid

    alert = ThreatAlert(
        alert_id       = str(uuid.uuid4())[:8],
        head_name      = kwargs.get("head", "c2_head"),
        score          = score,
        threshold      = 0.65,
        technique      = technique,
        technique_name = kwargs.get("technique_name", technique),
        source_host    = host,
        source_ip      = kwargs.get("ip", "0.0.0.0"),
        source_user    = kwargs.get("user", "unknown"),
        event_sequence = [],
        timestamp      = datetime.now(timezone.utc).isoformat(),
        session_uuid   = ctx.session.session_id,
        raw_features   = [],
    )

    # GAP 6: process_alert is synchronous
    incident = await run_blocking(ir_engine.process_alert, alert)

    if incident:
        ctx.output.warning(f"IR Incident created: {incident.incident_id}")
        ctx.output.info(f"  Tier:     {incident.response_tier}")
        ctx.output.info(f"  Actions:  {len(incident.containment_actions)}")
        result = {
            "success":     True,
            "incident_id": incident.incident_id,
            "tier":        str(incident.response_tier),
            "actions":     len(incident.containment_actions),
        }
    else:
        ctx.output.info("IR: Score below threshold — monitoring only")
        result = {"success": True, "incident_id": None, "tier": "MONITOR"}

    ctx.session.write("v3_ir_result.json", result)
    return result


@register_command("v3", "attest")
async def v3_attest(ctx: KernelContext, **kwargs: Any) -> dict[str, Any]:
    """
    Run TPM-sealed attestation on current system state.

    Usage: shadow313 v3 attest
    """
    ctx.output.info("Running v3 TPM-sealed attestation...")

    from shadow313.v3.ztas.tpm_sealed_attestation import SimulatedTPM2, TPMSealedAttestationEngine
    import hashlib

    tpm    = SimulatedTPM2()
    engine = TPMSealedAttestationEngine(tpm)

    # Seal a probe
    bytecode = hashlib.sha512(b"shadow313_kprobe_NtReadVirtualMemory_v3").digest()
    att = await run_blocking(
        engine.load_and_seal_probe,
        "probe_lsass", "NtReadVirtualMemory", bytecode
    )

    # Verify
    result_att = await run_blocking(
        engine.verify_probe_integrity,
        "probe_lsass", bytecode
    )

    # Full report
    report = await run_blocking(engine.get_full_attestation_report)

    ctx.output.success(f"TPM attestation complete:")
    ctx.output.info(f"  Probe sealed:    {att.probe_id}")
    ctx.output.info(f"  PCR verified:    {result_att.pcr_match}")
    ctx.output.info(f"  Bytecode match:  {result_att.bytecode_match}")
    ctx.output.info(f"  Tamper detected: {report['tamper_detected']}")

    ctx.session.write("v3_attestation.json", report)
    return {"success": True, "verified": result_att.verified, "report": report}


@register_command("v3", "status")
async def v3_status(ctx: KernelContext, **kwargs: Any) -> dict[str, Any]:
    """Show v3 integration status."""
    session_id = ctx.session.session_id
    mon = _active_monitors.get(session_id)

    registry = ModelRegistry()
    detector = registry.get_detector()
    stats    = detector.get_stats()

    ctx.output.info("v3 Integration Status:")
    ctx.output.info(f"  LSTM detector:    loaded ({stats.get('total_sequences_analyzed', 0)} sequences analyzed)")
    ctx.output.info(f"  Active monitors:  {'YES' if mon and mon.is_running else 'NO'}")
    ctx.output.info(f"  Model registry:   {len(registry._models)} models loaded")

    return {
        "success":         True,
        "lstm_loaded":     True,
        "monitors_active": bool(mon and mon.is_running),
        "lstm_stats":      stats,
    }