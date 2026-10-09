"""Mock Event Bus for plugin testing."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
from shadow313_sdk.models import Event

@dataclass
class MockEventBus:
    """In-memory event bus for unit tests."""
    events: list[Event] = field(default_factory=list)

    async def publish(self, topic: str, event: Event) -> None:
        self.events.append(event)

    def events_by_topic(self, topic: str) -> list[Event]:
        return [e for e in self.events if e.topic == topic]

    def clear(self) -> None:
        self.events.clear()

    @property
    def event_count(self) -> int:
        return len(self.events)
