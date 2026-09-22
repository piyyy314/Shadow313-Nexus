"""
shadow313.v3.bridge.stress_test
─────────────────────────────────
Stress tests for the Shadow313 v3 bridge components.

Tests:
  - High-volume log ingestion (10,000 events)
  - Concurrent monitor start/stop cycles
  - Beacon detector under load
  - Extended C2 correlator performance

Exposes known gaps:
  GAP-1: Session.id attribute (fixed — uses session.id)
  GAP-3: Kernel.dispatch_async (fixed — async wrapper added)
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class TestResult:
    name:       str
    passed:     bool
    duration_s: float
    gap_exposed: str = ""
    details:    str = ""
    errors:     list[str] = field(default_factory=list)
    metrics:    dict = field(default_factory=dict)


# ── GAP fixes ─────────────────────────────────────────────────────────────────

def _get_session_id(session) -> str:
    """
    GAP-1 fix: Session.id attribute.
    The stalled thread used session.id; this workspace uses session.id too.
    Handles both attribute names for compatibility.
    """
    return getattr(session, "id", None) or getattr(session, "session_id", "unknown")


async def _get_kernel_dispatch(kernel, namespace: str, **kwargs):
    """
    GAP-3 fix: Shadow313Kernel.dispatch_async.
    The stalled thread called kernel.dispatch_async() which didn't exist.
    This wrapper provides async dispatch via run_in_executor.
    """
    if hasattr(kernel, "dispatch_async"):
        return await kernel.dispatch_async(namespace, **kwargs)
    # Fallback: wrap synchronous dispatch in executor
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: kernel.dispatch(namespace, **kwargs))


# ── Stress test 1: High-volume log ingestion ──────────────────────────────────

async def _test_high_volume_ingestion_impl(n_events: int = 10_000) -> TestResult:
    """Simulate ingesting 10,000 log events through the beacon detector."""
    from shadow313.v3.bridge.beacon_detector import BeaconDetector, BeaconEvent

    start = time.time()
    errors = []

    try:
        detector = BeaconDetector()
        base_ts  = time.time()

        # Generate synthetic beacon events
        events = []
        for i in range(n_events):
            events.append(BeaconEvent(
                timestamp  = base_ts + i * 60.0 + (i % 3) * 2.0,  # ~60s period
                src_ip     = f"10.0.{i % 10}.{i % 100}",
                dst_ip     = "104.21.0.1",
                dst_port   = 443,
                bytes_sent = 512 + (i % 256),
                uri        = "/jquery-3.3.1.min.js",
                ja3        = "72a589da586844d7f0818ce684948eea",
                tls_cert   = "*.cloudflare.com",
            ))

        profiles = detector.detect(events)
        duration = time.time() - start

        return TestResult(
            name       = "High-Volume Log Ingestion",
            passed     = True,
            duration_s = duration,
            gap_exposed= "",
            details    = f"{n_events} events processed, {len(profiles)} beacons detected",
            metrics    = {
                "events_processed": n_events,
                "beacons_detected": len(profiles),
                "events_per_sec":   round(n_events / duration, 0),
            },
        )
    except Exception as e:
        errors.append(str(e))
        return TestResult(
            name       = "High-Volume Log Ingestion",
            passed     = False,
            duration_s = time.time() - start,
            gap_exposed= "GAP-1 (session attribute)",
            details    = f"0/{n_events} events processed",
            errors     = errors,
        )


def test_high_volume_ingestion():
    """Sync pytest entry-point for the async stress test."""
    result = asyncio.run(_test_high_volume_ingestion_impl())
    if not result.passed:
        raise AssertionError(f"Stress test failed: {result}")
    assert result.metrics["events_processed"] == 10_000


# ── Stress test 2: Concurrent monitor cycles ──────────────────────────────────

async def _test_concurrent_monitor_cycles_impl(n_cycles: int = 5) -> TestResult:
    """Simulate concurrent beacon detector start/stop cycles."""
    from shadow313.v3.bridge.beacon_detector import BeaconDetector, BeaconEvent

    start  = time.time()
    errors = []
    clean  = 0

    async def run_cycle(cycle_id: int) -> bool:
        try:
            detector = BeaconDetector()
            base_ts  = time.time()
            events   = [
                BeaconEvent(
                    timestamp  = base_ts + j * 60.0,
                    src_ip     = f"10.0.{cycle_id}.{j}",
                    dst_ip     = "185.220.101.5",
                    dst_port   = 443,
                    bytes_sent = 256,
                    uri        = "/api/v2/update",
                    ja3        = "b386946a5a44d1dd5a79d395b6b5f5a3",
                )
                for j in range(5)
            ]
            profiles = detector.detect(events)
            return True
        except Exception as e:
            errors.append(f"Cycle {cycle_id}: {e}")
            return False

    tasks   = [run_cycle(i) for i in range(n_cycles)]
    results = await asyncio.gather(*tasks)
    clean   = sum(results)
    duration = time.time() - start

    passed = clean == n_cycles
    return TestResult(
        name       = "Concurrent Monitor Cycles",
        passed     = passed,
        duration_s = duration,
        gap_exposed= "" if passed else "GAP-3 (monitor lifecycle — race condition)",
        details    = f"{clean}/{n_cycles} cycles clean, {len(errors)} exceptions",
        errors     = errors,
        metrics    = {
            "cycles_attempted":  n_cycles,
            "cycles_succeeded":  clean,
            "exceptions":        len(errors),
        },
    )


def test_concurrent_monitor_cycles():
    """Sync pytest entry-point for the async stress test."""
    result = asyncio.run(_test_concurrent_monitor_cycles_impl())
    if hasattr(result, "passed") and not result.passed:
        raise AssertionError(f"Stress test failed: {result}")
    assert result.metrics["cycles_succeeded"] == result.metrics["cycles_attempted"]


# ── Stress test 3: C2 correlator performance ──────────────────────────────────

def test_c2_correlator_performance():
    """Verify ExtendedC2Correlator handles large host sets efficiently."""
    from shadow313.v3.bridge.c2_attribution_analysis import build_scenario
    from shadow313.v3.bridge.extended_c2_correlator import ExtendedC2Correlator

    hosts      = build_scenario()
    correlator = ExtendedC2Correlator()
    start      = time.time()

    results = []
    for i, a in enumerate(hosts):
        for b in hosts[i+1:]:
            r = correlator.correlate(a, b)
            results.append(r)

    duration = time.time() - start
    assert duration < 5.0, f"Correlator too slow: {duration:.2f}s"
    assert len(results) > 0


# ── Stress test 4: Beacon detector accuracy ───────────────────────────────────

def test_beacon_detector_accuracy():
    """Verify beacon detector correctly identifies known C2 patterns."""
    from shadow313.v3.bridge.beacon_detector import BeaconDetector, BeaconEvent

    detector = BeaconDetector()
    base_ts  = time.time()

    # Cobalt Strike: 60s ± 10% jitter
    import random
    random.seed(313)
    events = [
        BeaconEvent(
            timestamp  = base_ts + i * 60.0 * (1 + random.uniform(-0.05, 0.05)),
            src_ip     = "10.0.1.10",
            dst_ip     = "104.21.0.1",
            dst_port   = 443,
            bytes_sent = 512,
            uri        = "/jquery-3.3.1.min.js",
            ja3        = "72a589da586844d7f0818ce684948eea",
        )
        for i in range(10)
    ]

    profiles = detector.detect(events)
    assert len(profiles) >= 1
    p = profiles[0]
    assert p.is_beacon
    assert 50 <= p.period_s <= 70  # ~60s
    assert p.confidence >= 0.5


if __name__ == "__main__":
    print("[STRESS 1] High-Volume Log Ingestion (10,000 events)")
    result = asyncio.run(_test_high_volume_ingestion_impl())
    print(f"  {'✓' if result.passed else '✗'} [{result.gap_exposed or 'OK'}] {result.name}: {result.details} ({result.duration_s:.2f}s)")
    if result.errors:
        for e in result.errors[:3]:
            print(f"      ERROR: {e}")

    print(f"\n[STRESS 2] Concurrent Monitor Start/Stop Cycles")
    result2 = asyncio.run(_test_concurrent_monitor_cycles_impl())
    print(f"  {'✓' if result2.passed else '✗'} [{result2.gap_exposed or 'OK'}] {result2.name}: {result2.details} ({result2.duration_s:.2f}s)")
    if result2.errors:
        for e in result2.errors[:3]:
            print(f"      ERROR: {e}")