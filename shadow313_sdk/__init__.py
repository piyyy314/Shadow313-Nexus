"""
Shadow313 SDK v2 — Public API surface.
Import everything you need from here.
"""
from shadow313_sdk.models import (
    # Enumerations
    Severity, TargetType, SecretType, ScanStatus, BaselineType,
    CheckStatus, LogLevel,
    # Event Bus
    Event,
    # VaultScan
    ScanTarget, FileChunk, VaultScanConfig, ScanContext, SecretFinding,
    # SentinelBaseline
    DriftItem,
    # LogForge
    ThreatIndicator, SourceMeta, UnifiedLogRecord,
    # HoneywireNet
    HoneypotConfig, HoneypotInteraction, HoneypotStatus,
    # ConfigAudit
    AuditConfig, AuditCheck,
)
from shadow313_sdk.plugins import (
    SecretDetectorPlugin,
    BaselineCollectorPlugin,
    LogParserPlugin,
    LogEnricherPlugin,
    HoneypotPlugin,
    BenchmarkPlugin,
)

__version__ = "2.0.0"
__author__  = "mohamad matar"
__all__ = [
    "Severity","TargetType","SecretType","ScanStatus","BaselineType",
    "CheckStatus","LogLevel","Event","ScanTarget","FileChunk",
    "VaultScanConfig","ScanContext","SecretFinding","DriftItem",
    "ThreatIndicator","SourceMeta","UnifiedLogRecord","HoneypotConfig",
    "HoneypotInteraction","HoneypotStatus","AuditConfig","AuditCheck",
    "SecretDetectorPlugin","BaselineCollectorPlugin","LogParserPlugin",
    "LogEnricherPlugin","HoneypotPlugin","BenchmarkPlugin",
]
