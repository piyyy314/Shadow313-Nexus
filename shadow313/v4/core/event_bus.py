"""
shadow313.v4.core.event_bus
─────────────────────────────
FastAPI-based event bus for Shadow313 NEXUS v4.

Provides async pub/sub event routing between modules:
  - Threat detection events → enforcement engine
  - Aegis telemetry → LIF detector
  - Ledger entries → IPFS anchoring
  - Plugin lifecycle events → trust registry

Uses asyncio queues internally; FastAPI WebSocket for external consumers.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional

logger = logging.getLogger("shadow313.event_bus")


@dataclass
class Event:
    """A single event on the bus."""
    topic:      str
    payload:    Any
    source:     str = ""
    timestamp:  str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_id:   str = field(default_factory=lambda: f"evt-{int(time.time_ns())}")
    priority:   int = 5   # 1=highest, 10=lowest


class EventBus:
    """
    Async event bus for inter-module communication.

    Usage:
        bus = EventBus()

        # Subscribe
        @bus.subscribe("threat.detected")
        async def handle_threat(event: Event):
            await enforcement.kill_process(event.payload["pid"])

        # Publish
        await bus.publish(Event(topic="threat.detected", payload={"pid": 1234}))
    """

    def __init__(self) -> None:
        self._subscribers: dict[str, list[Callable]] = {}
        self._queue:       asyncio.Queue = asyncio.Queue(maxsize=10_000)
        self._running:     bool = False
        self._event_count: int  = 0
        self._error_count: int  = 0

    def subscribe(self, topic: str):
        """Decorator to subscribe a handler to a topic."""
        def decorator(fn: Callable) -> Callable:
            self._subscribers.setdefault(topic, []).append(fn)
            logger.debug("Subscribed %s to topic '%s'", fn.__name__, topic)
            return fn
        return decorator

    def subscribe_fn(self, topic: str, fn: Callable) -> None:
        """Subscribe a handler function to a topic (non-decorator form)."""
        self._subscribers.setdefault(topic, []).append(fn)

    async def publish(self, event: Event) -> None:
        """Publish an event to the bus."""
        await self._queue.put(event)
        self._event_count += 1

    def publish_sync(self, event: Event) -> None:
        """Synchronous publish — use from non-async contexts."""
        try:
            self._queue.put_nowait(event)
            self._event_count += 1
        except asyncio.QueueFull:
            logger.warning("Event bus queue full — dropping event: %s", event.topic)

    async def _dispatch(self, event: Event) -> None:
        """Dispatch an event to all subscribers."""
        handlers = self._subscribers.get(event.topic, [])
        # Also check wildcard subscribers
        handlers += self._subscribers.get("*", [])

        for handler in handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(event)
                else:
                    handler(event)
            except Exception as exc:
                self._error_count += 1
                logger.warning("Handler %s failed for topic %s: %s",
                               handler.__name__, event.topic, exc)

    async def run(self) -> None:
        """Run the event bus dispatch loop."""
        self._running = True
        logger.info("Event bus started")
        while self._running:
            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                await self._dispatch(event)
                self._queue.task_done()
            except asyncio.TimeoutError:
                continue
            except Exception as exc:
                logger.warning("Event bus dispatch error: %s", exc)
                self._error_count += 1

    def stop(self) -> None:
        """Stop the event bus."""
        self._running = False

    def status(self) -> dict:
        """Return bus status metrics."""
        return {
            "running":       self._running,
            "queue_size":    self._queue.qsize(),
            "events_total":  self._event_count,
            "errors_total":  self._error_count,
            "topics":        list(self._subscribers.keys()),
            "subscribers":   {t: len(h) for t, h in self._subscribers.items()},
        }


# ── Standard topics ───────────────────────────────────────────────────────────

class Topics:
    """Standard event topic constants."""
    THREAT_DETECTED      = "threat.detected"
    THREAT_RESOLVED      = "threat.resolved"
    PROCESS_KILLED       = "process.killed"
    LEDGER_ENTRY         = "ledger.entry"
    PLUGIN_LOADED        = "plugin.loaded"
    PLUGIN_REJECTED      = "plugin.rejected"
    RECEIPT_CREATED      = "receipt.created"
    AEGIS_ALERT          = "aegis.alert"
    SCAN_COMPLETED       = "scan.completed"
    KEY_ROTATION         = "key.rotation"
    CRQC_ALERT           = "crqc.alert"
    DEPLOYMENT_STEP      = "deployment.step"


# ── Global singleton ──────────────────────────────────────────────────────────

_bus: Optional[EventBus] = None


def get_event_bus() -> EventBus:
    """Get or create the global event bus singleton."""
    global _bus
    if _bus is None:
        _bus = EventBus()
    return _bus