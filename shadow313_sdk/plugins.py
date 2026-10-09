"""
Shadow313 SDK v2 — Plugin base classes.

Import the relevant base class, subclass it, implement the abstract methods,
and declare your plugin_id and plugin_version class attributes.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from shadow313_sdk.models import (
    AuditCheck,
    AuditConfig,
    BaselineType,
    DriftItem,
    FileChunk,
    HoneypotConfig,
    HoneypotInteraction,
    HoneypotStatus,
    ScanContext,

    SecretFinding,
    SourceMeta,
    TargetType,
    UnifiedLogRecord,
)


# ─── VaultScan ───────────────────────────────────────────────────────────────

class SecretDetectorPlugin(ABC):
    """
    Base class for VaultScan secret detector plugins.

    Implement `detect()` to scan file chunks for secrets.
    Optional lifecycle hooks: `on_scan_start`, `on_scan_end`.
    """
    plugin_id:       str
    plugin_version:  str
    supported_types: list[TargetType | str]

    @abstractmethod
    def detect(self, chunk: FileChunk, context: ScanContext) -> list[SecretFinding]:
        """
        Scan a file chunk for secrets.

        Args:
            chunk:   A slice of file content. Never mutate this object.
            context: Scan-scoped helpers (hashing, ID generation, event publishing).

        Returns:
            A list of SecretFinding objects. Return [] if nothing found.
            NEVER include plaintext secret values — use context.hash_value().
        """
        ...

    def on_scan_start(self, target: Any) -> None:
        """Optional: Called once when a scan of a target begins."""

    def on_scan_end(self, result: Any) -> None:
        """Optional: Called once when a scan of a target completes (pass or fail)."""


# ─── SentinelBaseline ────────────────────────────────────────────────────────

class BaselineCollectorPlugin(ABC):
    """
    Base class for SentinelBaseline collector plugins.

    Implement `collect()` to gather host state data for a specific baseline type.
    Implement `diff()` to compare baseline and live data and produce DriftItems.
    """
    baseline_type: BaselineType | str

    @abstractmethod
    async def collect(self, host_id: str, config: Any) -> dict[str, Any]:
        """
        Collect current host state for this baseline type.

        Args:
            host_id: Identifier of the host to collect from.
            config:  SentinelConfig object (typed as Any to avoid circular import).

        Returns:
            A JSON-serializable dict representing the current state.
        """
        ...

    @abstractmethod
    def diff(self, baseline: dict[str, Any], current: dict[str, Any]) -> list[DriftItem]:
        """
        Compare baseline (stored) and current (live) data.

        Args:
            baseline: Previously captured snapshot data dict.
            current:  Freshly collected data dict.

        Returns:
            A list of DriftItem objects describing every detected change.
            Return [] if no drift detected.
        """
        ...

    def risk_score(self, drift_item: DriftItem) -> float:
        """
        Assign a risk score (0.0–10.0) to a drift item.
        Override for type-specific scoring logic.
        Default: 5.0 (medium).
        """
        return 5.0


# ─── LogForge ────────────────────────────────────────────────────────────────

class LogParserPlugin(ABC):
    """
    Base class for LogForge parser plugins.

    Implement `parse()` to convert a raw log string into a UnifiedLogRecord.
    Override `can_parse()` for fast pre-filtering before full parse attempt.
    """
    parser_id:       str
    source_patterns: list[str]   # glob patterns matched against source_id

    @abstractmethod
    def parse(self, raw: str, source_meta: SourceMeta) -> UnifiedLogRecord | None:
        """
        Parse a raw log string into a UnifiedLogRecord.

        Args:
            raw:         The raw log string as received from the source.
            source_meta: Metadata about the source (host, port, TLS, etc.).

        Returns:
            A populated UnifiedLogRecord, or None if the record cannot be parsed
            (will be counted as a parse error for this source).
        """
        ...

    def can_parse(self, raw: str, source_meta: SourceMeta) -> bool:
        """
        Fast pre-filter: return False to skip this parser for a given record.
        Default: attempt all records (return True).
        """
        return True


class LogEnricherPlugin(ABC):
    """
    Base class for LogForge enricher plugins.

    Implement `enrich()` to add fields to a UnifiedLogRecord.
    Lower priority values run earlier in the enrichment chain.
    """
    enricher_id: str
    priority:    int = 50

    @abstractmethod
    async def enrich(self, record: UnifiedLogRecord) -> UnifiedLogRecord:
        """
        Enrich a normalized log record.

        Args:
            record: The normalized log record. Do not mutate — return a new record.

        Returns:
            A new UnifiedLogRecord with additional enrichments populated.
        """
        ...


# ─── HoneywireNet ────────────────────────────────────────────────────────────

class HoneypotPlugin(ABC):
    """
    Base class for HoneywireNet honeypot protocol plugins.

    Implement `start()` and `stop()` for lifecycle management.
    Implement `get_status()` to report current state.
    Override `on_interaction()` for custom interaction handling.
    """
    honeypot_type: str

    @abstractmethod
    async def start(self, config: HoneypotConfig, bus: Any) -> None:
        """
        Start the honeypot listener.

        Args:
            config: Honeypot configuration (bind address, port, emulation settings).
            bus:    EventBus instance — publish interactions as they arrive.
        """
        ...

    @abstractmethod
    async def stop(self) -> None:
        """Gracefully stop the honeypot listener. Must be idempotent."""
        ...

    @abstractmethod
    def get_status(self) -> HoneypotStatus:
        """Return the current status of this honeypot instance."""
        ...

    def on_interaction(self, interaction: HoneypotInteraction) -> None:
        """
        Called for every honeypot interaction.
        Default: no-op (event published to bus by core).
        Override for custom side effects (e.g., packet capture, active response).
        """


# ─── ConfigAudit ─────────────────────────────────────────────────────────────

class BenchmarkPlugin(ABC):
    """
    Base class for ConfigAudit benchmark plugins.

    Implement `run_checks()` to execute all benchmark checks against a host.
    Override `generate_remediation_script()` to produce fix scripts for failed checks.
    """
    benchmark_id:      str
    benchmark_version: str
    target_os:         list[str]

    @abstractmethod
    async def run_checks(self, host_id: str, config: AuditConfig) -> list[AuditCheck]:
        """
        Execute all benchmark checks against a host.

        Args:
            host_id: Identifier of the host to audit.
            config:  Audit configuration.

        Returns:
            A list of AuditCheck results. Every defined check must appear in output,
            even if its status is NOT_APPLICABLE or ERROR.
        """
        ...

    def generate_remediation_script(self, failed_checks: list[AuditCheck]) -> str:
        """
        Generate a shell remediation script for failed/warn checks.
        Default: concatenate .script fields. Override for custom templating.
        """
        lines = ["#!/usr/bin/env bash", "# Auto-generated by ConfigAudit — review before running", "set -euo pipefail", ""]
        for check in failed_checks:
            if check.script:
                lines.append(f"# {check.check_id} — {check.title}")
                lines.append(check.script)
                lines.append("")
        return "\n".join(lines)
