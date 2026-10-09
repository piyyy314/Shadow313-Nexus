"""PluginTestHarness — isolated test runner for Shadow313 plugins."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from shadow313_sdk.models import (
    FileChunk, ScanContext, SecretFinding, VaultScanConfig
)
from shadow313_sdk.plugins import SecretDetectorPlugin
from shadow313_sdk.testing.bus import MockEventBus
from shadow313_sdk.testing.factories import make_chunk, make_context


@dataclass
class DetectorTestResult:
    """Result of a PluginTestHarness.run_detect() call."""
    findings:       list[SecretFinding]
    bus:            MockEventBus
    error:          Exception | None = None

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def findings_by_severity(self, severity: str) -> list[SecretFinding]:
        return [f for f in self.findings if f.severity.value == severity]

    def finding_by_rule(self, rule_id: str) -> SecretFinding | None:
        return next((f for f in self.findings if f.rule_id == rule_id), None)


class PluginTestHarness:
    """
    Isolated test harness for SecretDetectorPlugin implementations.

    Usage:
        harness = PluginTestHarness(MyDetector())
        result  = harness.run_detect(make_chunk(content=b"SECRET=abc123"))
        assert result.finding_count == 1
    """

    def __init__(
        self,
        plugin: SecretDetectorPlugin,
        config: VaultScanConfig | None = None,
    ) -> None:
        self.plugin = plugin
        self.config = config or VaultScanConfig()

    def run_detect(
        self,
        chunk: FileChunk,
        *,
        context: ScanContext | None = None,
    ) -> DetectorTestResult:
        """
        Run the plugin's detect() method synchronously.

        Args:
            chunk:   The file chunk to scan.
            context: Optional custom ScanContext. A default one is created if omitted.

        Returns:
            DetectorTestResult with findings and captured bus events.
        """
        bus = MockEventBus()
        ctx = context or make_context(bus=bus, config=self.config)
        try:
            findings = self.plugin.detect(chunk, ctx)
            return DetectorTestResult(findings=findings, bus=bus)
        except Exception as exc:
            return DetectorTestResult(findings=[], bus=bus, error=exc)

    def run_detect_many(
        self,
        chunks: list[FileChunk],
        *,
        context: ScanContext | None = None,
    ) -> DetectorTestResult:
        """Run detect() over multiple chunks, aggregating all findings."""
        bus = MockEventBus()
        ctx = context or make_context(bus=bus, config=self.config)
        all_findings: list[SecretFinding] = []
        error = None
        for chunk in chunks:
            try:
                all_findings.extend(self.plugin.detect(chunk, ctx))
            except Exception as exc:
                error = exc
                break
        return DetectorTestResult(findings=all_findings, bus=bus, error=error)
