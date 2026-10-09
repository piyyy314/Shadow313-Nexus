"""Factory helpers for creating test fixtures."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from shadow313_sdk.models import (
    FileChunk, ScanContext, ScanTarget, TargetType, VaultScanConfig, SourceMeta
)
from shadow313_sdk.testing.bus import MockEventBus


def make_chunk(
    *,
    content: bytes = b"",
    file_path: str = "test/fixture_file.py",
    encoding: str | None = "utf-8",
    chunk_index: int = 0,
    total_chunks: int = 1,
    metadata: dict[str, Any] | None = None,
) -> FileChunk:
    """Create a FileChunk test fixture."""
    return FileChunk(
        file_path=file_path,
        content=content,
        encoding=encoding,
        chunk_index=chunk_index,
        total_chunks=total_chunks,
        metadata=metadata or {},
    )


def make_context(
    *,
    scan_id: str | None = None,
    target_id: str = "test-target",
    target_type: TargetType = TargetType.FILESYSTEM,
    target_path: str = "/tmp/test",
    config: VaultScanConfig | None = None,
    bus: MockEventBus | None = None,
) -> ScanContext:
    """Create a ScanContext test fixture with a MockEventBus."""
    target = ScanTarget(
        target_id=target_id,
        target_type=target_type,
        path=target_path,
    )
    return ScanContext(
        scan_id=scan_id or str(uuid.uuid4()),
        target=target,
        config=config or VaultScanConfig(),
        _bus=bus or MockEventBus(),
    )


def make_source_meta(
    *,
    source_id: str = "test-source",
    source_type: str = "SYSLOG_TCP",
    host: str = "localhost",
    port: int | None = 514,
    tls: bool = False,
    extra: dict[str, Any] | None = None,
) -> SourceMeta:
    """Create a SourceMeta test fixture."""
    return SourceMeta(
        source_id=source_id,
        source_type=source_type,
        host=host,
        port=port,
        tls=tls,
        extra=extra or {},
    )
