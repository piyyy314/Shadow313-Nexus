"""
shadow313.v4.ghost_watch.cadl
CADL: Cognitive-Adaptive Deception Layer — 5-tier escalation pipeline.
L1 Monitor → L2 Delay → L3 Reroute → L4 Degrade → L5 Neutralize
"""
from __future__ import annotations
import time
import logging
from enum import IntEnum
from typing import Callable

logger = logging.getLogger("shadow313.cadl")


class CADLLevel(IntEnum):
    L1_MONITOR    = 1
    L2_DELAY      = 2
    L3_REROUTE    = 3
    L4_DEGRADE    = 4
    L5_NEUTRALIZE = 5


class CADLEngine:
    """Event-driven 5-level CADL escalation orchestrator."""

    def __init__(self):
        self.current_level: CADLLevel = CADLLevel.L1_MONITOR
        self.event_log: list = []
        self.escalation_hooks: dict = {l: [] for l in CADLLevel}
        self.session_active: bool = True

    def register_hook(self, level: CADLLevel, fn: Callable) -> None:
        self.escalation_hooks[level].append(fn)

    def process_event(self, event: dict) -> dict:
        score = event.get("score", 0.0)
        self._log_event(event)
        new_level = self._compute_level(score)
        if new_level > self.current_level:
            self._escalate(new_level, event)
        return self._apply_level(event)

    def _compute_level(self, score: float) -> CADLLevel:
        if score >= 0.95: return CADLLevel.L5_NEUTRALIZE
        if score >= 0.80: return CADLLevel.L4_DEGRADE
        if score >= 0.65: return CADLLevel.L3_REROUTE
        if score >= 0.45: return CADLLevel.L2_DELAY
        return CADLLevel.L1_MONITOR

    def _escalate(self, new_level: CADLLevel, event: dict) -> None:
        logger.warning(f"CADL escalating: L{self.current_level} to L{new_level}")
        self.current_level = new_level
        for hook in self.escalation_hooks.get(new_level, []):
            try:
                hook(event)
            except Exception as e:
                logger.error(f"Hook error at L{new_level}: {e}")

    def _apply_level(self, event: dict) -> dict:
        level = self.current_level
        result = {
            "level": int(level),
            "level_name": level.name,
            "event_id": event.get("id", "unknown"),
        }
        if level == CADLLevel.L1_MONITOR:
            result["action"] = "passive_log"
        elif level == CADLLevel.L2_DELAY:
            result["action"] = "inject_latency"
            result["delay_ms"] = 500
        elif level == CADLLevel.L3_REROUTE:
            result["action"] = "redirect_to_honeypot"
            result["honeypot"] = "aether-decoy-01"
        elif level == CADLLevel.L4_DEGRADE:
            result["action"] = "return_poisoned_data"
            result["poison_type"] = "pqc_noise"
        elif level == CADLLevel.L5_NEUTRALIZE:
            result["action"] = "terminate_session"
            self.session_active = False
        return result

    def _log_event(self, event: dict) -> None:
        self.event_log.append({
            "ts": time.time(),
            "event": event,
            "level": int(self.current_level),
        })

    def reset(self) -> None:
        self.current_level = CADLLevel.L1_MONITOR
        self.session_active = True

    def status(self) -> dict:
        return {
            "current_level": int(self.current_level),
            "level_name": self.current_level.name,
            "session_active": self.session_active,
            "events_processed": len(self.event_log),
        }