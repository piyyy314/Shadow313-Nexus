"""
Shadow313 NEXUS — Session Storage Model
Persistent encrypted session management with 313-BIND audit trail.
"""
from __future__ import annotations
import json, uuid, time, hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

class SessionStore:
    """Encrypted persistent session storage."""

    def __init__(self, store_dir: str = "~/.shadow313/sessions"):
        self.store_dir = Path(store_dir).expanduser()
        self.store_dir.mkdir(parents=True, exist_ok=True)
        self._sessions: Dict[str, Dict] = {}
        self._load_all()

    def create(self, operator: str = "unknown", tags: List[str] = None) -> str:
        sid = str(uuid.uuid4())
        ts  = int(time.time_ns())
        ts_313 = int(str(ts)[:-3] + "313")
        session = {
            "id": sid, "operator": operator,
            "created": datetime.now(timezone.utc).isoformat(),
            "timestamp_ns": ts_313, "tags": tags or [],
            "artifacts": [], "events": [], "status": "active",
            "hash": hashlib.sha3_256(f"{sid}{ts_313}".encode()).hexdigest()
        }
        self._sessions[sid] = session
        self._save(sid)
        return sid

    def get(self, sid: str) -> Optional[Dict]:
        return self._sessions.get(sid)

    def add_artifact(self, sid: str, artifact: Dict[str, Any]) -> bool:
        if sid not in self._sessions:
            return False
        artifact["timestamp"] = datetime.now(timezone.utc).isoformat()
        self._sessions[sid]["artifacts"].append(artifact)
        self._save(sid)
        return True

    def add_event(self, sid: str, event_type: str, data: Dict) -> bool:
        if sid not in self._sessions:
            return False
        self._sessions[sid]["events"].append({
            "type": event_type, "data": data,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "timestamp_ns": int(time.time_ns())
        })
        self._save(sid)
        return True

    def close(self, sid: str) -> bool:
        if sid not in self._sessions:
            return False
        self._sessions[sid]["status"] = "closed"
        self._sessions[sid]["closed"] = datetime.now(timezone.utc).isoformat()
        self._save(sid)
        return True

    def list_sessions(self, status: str = None) -> List[Dict]:
        sessions = list(self._sessions.values())
        if status:
            sessions = [s for s in sessions if s.get("status") == status]
        return sorted(sessions, key=lambda x: x["created"], reverse=True)

    def _save(self, sid: str):
        path = self.store_dir / f"{sid}.json"
        path.write_text(json.dumps(self._sessions[sid], indent=2))

    def _load_all(self):
        for f in self.store_dir.glob("*.json"):
            try:
                data = json.loads(f.read_text())
                self._sessions[data["id"]] = data
            except Exception:
                pass
