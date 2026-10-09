"""
Shadow313 SDK v2 — Core data models.

All models use dataclasses for immutability inside plugin boundaries.
The core engine passes frozen copies; plugins must not mutate inputs.
"""
from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


# ──────────────────────────── Enumerations ────────────────────────────

class Severity(str, Enum):
    DEBUG    = "DEBUG"
    INFO     = "INFO"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class TargetType(str, Enum):
    FILESYSTEM = "FILESYSTEM"
    CONTAINER  = "CONTAINER"
    REPO       = "REPO"
    ENV        = "ENV"
    MEMORY     = "MEMORY"


class SecretType(str, Enum):
    API_KEY      = "API_KEY"
    PRIVATE_KEY  = "PRIVATE_KEY"
    PASSWORD     = "PASSWORD"
    TOKEN        = "TOKEN"
    CERT         = "CERT"
    HIGH_ENTROPY = "HIGH_ENTROPY"
    UNKNOWN      = "UNKNOWN"


class ScanStatus(str, Enum):
    RUNNING   = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED    = "FAILED"
    ABORTED   = "ABORTED"


class BaselineType(str, Enum):
    PROCESS_LIST      = "PROCESS_LIST"
    FILE_INTEGRITY    = "FILE_INTEGRITY"
    NETWORK_CONNECTIONS = "NETWORK_CONNECTIONS"
    SYSCALL_PROFILE   = "SYSCALL_PROFILE"
    SERVICE_CONFIG    = "SERVICE_CONFIG"
    USER_ACCOUNTS     = "USER_ACCOUNTS"
    CRON_JOBS         = "CRON_JOBS"
    KERNEL_MODULES    = "KERNEL_MODULES"


class CheckStatus(str, Enum):
    PASS            = "PASS"
    FAIL            = "FAIL"
    WARN            = "WARN"
    NOT_APPLICABLE  = "NOT_APPLICABLE"
    ERROR           = "ERROR"


class LogLevel(str, Enum):
    DEBUG     = "DEBUG"
    INFO      = "INFO"
    NOTICE    = "NOTICE"
    WARN      = "WARN"
    ERROR     = "ERROR"
    CRITICAL  = "CRITICAL"
    ALERT     = "ALERT"
    EMERGENCY = "EMERGENCY"


# ──────────────────────────── Event Bus Models ────────────────────────────

@dataclass(frozen=True)
class Event:
    """Immutable event envelope used on the Shadow313 Event Bus."""
    event_id:       str
    topic:          str
    source_tool:    str
    timestamp:      datetime
    severity:       Severity
    payload:        dict[str, Any]
    correlation_id: str | None = None
    trace_id:       str | None = None

    @classmethod
    def create(
        cls,
        topic: str,
        source_tool: str,
        severity: Severity,
        payload: dict[str, Any],
        correlation_id: str | None = None,
        trace_id: str | None = None,
    ) -> "Event":
        return cls(
            event_id=str(uuid.uuid4()),
            topic=topic,
            source_tool=source_tool,
            timestamp=datetime.now(tz=timezone.utc),
            severity=severity,
            payload=payload,
            correlation_id=correlation_id,
            trace_id=trace_id,
        )


# ──────────────────────────── VaultScan Models ────────────────────────────

@dataclass(frozen=True)
class ScanTarget:
    target_id:        str
    target_type:      TargetType
    path:             str | None          = None
    image_ref:        str | None          = None
    repo_url:         str | None          = None
    depth:            int                 = -1
    exclude_patterns: tuple[str, ...]     = field(default_factory=tuple)


@dataclass(frozen=True)
class FileChunk:
    """A chunk of file content passed to detector plugins."""
    file_path:    str
    content:      bytes
    encoding:     str | None
    chunk_index:  int
    total_chunks: int
    metadata:     dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class VaultScanConfig:
    entropy_threshold:    float        = 4.5
    confidence_threshold: float        = 0.7
    max_file_size_mb:     int          = 50
    chunk_size_kb:        int          = 512
    concurrency:          int          = 8
    rules_dir:            str          = "rules/vaultscan/"
    ml_model_path:        str | None   = None
    stream_to_siem:       bool         = False
    extra:                dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanContext:
    """
    Context object injected into every detector plugin call.
    Provides helpers for creating findings and accessing scan metadata.
    """
    scan_id:  str
    target:   ScanTarget
    config:   VaultScanConfig
    _bus:     Any  # EventBus — typed as Any to avoid circular import in SDK

    def new_id(self) -> str:
        """Generate a new UUIDv4 string."""
        return str(uuid.uuid4())

    def now(self) -> datetime:
        """Return current UTC datetime."""
        return datetime.now(tz=timezone.utc)

    def hash_value(self, value: bytes) -> str:
        """SHA-256 hash of a secret value. NEVER store plaintext."""
        return hashlib.sha256(value).hexdigest()

    def make_finding(
        self,
        *,
        detector: str,
        secret_type: SecretType | str,
        severity: Severity | str,
        confidence: float,
        file_path: str,
        rule_id: str,
        remediation: str,
        line_number: int | None = None,
        column_number: int | None = None,
        matched_value: bytes | None = None,
        context_snippet: str = "[REDACTED]",
    ) -> "SecretFinding":
        """Convenience factory for SecretFinding — hashes matched_value automatically."""
        return SecretFinding(
            finding_id=self.new_id(),
            target_id=self.target.target_id,
            scan_id=self.scan_id,
            detector=detector,
            secret_type=SecretType(secret_type) if isinstance(secret_type, str) else secret_type,
            severity=Severity(severity) if isinstance(severity, str) else severity,
            confidence=confidence,
            file_path=file_path,
            line_number=line_number,
            column_number=column_number,
            matched_value_hash=self.hash_value(matched_value) if matched_value else "",
            context_snippet=context_snippet,
            rule_id=rule_id,
            remediation=remediation,
            first_seen=self.now(),
        )

    async def publish_finding(self, finding: "SecretFinding") -> None:
        """Publish a real-time finding event to the Event Bus."""
        await self._bus.publish(
            f"s313.vaultscan.finding",
            Event.create(
                topic="s313.vaultscan.finding",
                source_tool="vaultscan",
                severity=finding.severity,
                payload={"finding_id": finding.finding_id, "rule_id": finding.rule_id},
            ),
        )


@dataclass
class SecretFinding:
    finding_id:          str
    target_id:           str
    scan_id:             str
    detector:            str
    secret_type:         SecretType
    severity:            Severity
    confidence:          float
    file_path:           str
    line_number:         int | None
    column_number:       int | None
    matched_value_hash:  str
    context_snippet:     str
    rule_id:             str
    remediation:         str
    first_seen:          datetime
    suppressed:          bool     = False
    suppression_reason:  str | None = None


# ──────────────────────────── SentinelBaseline Models ────────────────────────────

@dataclass
class DriftItem:
    item_type:       str           # ADDED | REMOVED | MODIFIED
    field_path:      str
    expected_value:  str | None
    observed_value:  str | None
    risk_score:      float         # 0.0–10.0


# ──────────────────────────── LogForge Models ────────────────────────────

@dataclass
class ThreatIndicator:
    indicator_type: str
    value:          str
    feed_source:    str
    confidence:     float
    tags:           list[str]
    first_seen:     datetime
    last_seen:      datetime


@dataclass
class SourceMeta:
    source_id:   str
    source_type: str
    host:        str
    port:        int | None
    tls:         bool
    extra:       dict[str, Any] = field(default_factory=dict)


@dataclass
class UnifiedLogRecord:
    record_id:          str
    source_id:          str
    source_type:        str
    raw_message:        str
    timestamp:          datetime
    ingested_at:        datetime
    host:               str
    service:            str | None
    pid:                int | None
    level:              LogLevel
    category:           str
    message:            str
    fields:             dict[str, Any]
    tags:               list[str]
    enrichments:        dict[str, Any]
    threat_indicators:  list[ThreatIndicator]
    fingerprint:        str


# ──────────────────────────── HoneywireNet Models ────────────────────────────

@dataclass
class HoneypotConfig:
    honeypot_id:        str
    honeypot_type:      str
    bind_address:       str
    bind_port:          int
    emulated_service:   str
    fake_credentials:   list[dict[str, Any]] | None
    response_templates: dict[str, Any]
    tags:               list[str]
    enabled:            bool = True
    low_interaction:    bool = True


@dataclass
class HoneypotInteraction:
    interaction_id:        str
    honeypot_id:           str
    attacker_ip:           str
    attacker_port:         int
    protocol:              str
    timestamp:             datetime
    duration_ms:           int
    payload_raw:           bytes | None
    decoded_payload:       dict[str, Any] | None
    credentials_attempted: dict[str, str] | None
    interaction_type:      str
    threat_score:          float


@dataclass
class HoneypotStatus:
    honeypot_id:        str
    running:            bool
    bind_address:       str
    bind_port:          int
    interactions_total: int
    last_interaction:   datetime | None
    error:              str | None


# ──────────────────────────── ConfigAudit Models ────────────────────────────

@dataclass
class AuditConfig:
    host_id:     str
    benchmark_id: str
    extra:        dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditCheck:
    check_id:     str
    benchmark_id: str
    title:        str
    description:  str
    status:       CheckStatus
    expected:     str
    actual:       str
    severity:     Severity
    remediation:  str
    script:       str | None
    references:   list[str]
