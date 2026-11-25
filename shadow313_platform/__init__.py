"""Shadow313 Platform package with persistent authenticated event-bus defaults."""
from . import event_bus as _event_bus
from .event_bus_security import SQLiteEventStore, SecureEventPublisher

_event_bus.EventStore = SQLiteEventStore
_event_bus.EventPublisher = SecureEventPublisher
