"""
Shadow313 NEXUS — CHRONOS
Temporal snapshot reversion engine with 313-BIND integrity.
"""
from __future__ import annotations
import hashlib, json, time, uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional
from pathlib import Path

class CHRONOSEngine:
    def __init__(self, snapshot_dir: str = "~/.shadow313/snapshots"):
        self.snapshot_dir = Path(snapshot_dir).expanduser()
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)
        self._snapshots: Dict[str, Dict] = {}
        self._reversions: List[Dict] = []

    def create_snapshot(self, node_id: str, state: Dict) -> str:
        snap_id = str(uuid.uuid4())
        ts_ns   = int(time.time_ns())
        ts_313  = int(str(ts_ns)[:-3] + "313")
        snapshot = {"id":snap_id,"node_id":node_id,"timestamp_ns":ts_313,
                    "timestamp":datetime.now(timezone.utc).isoformat(),"state":state,
                    "hash":hashlib.sha3_256(json.dumps(state,sort_keys=True).encode()).hexdigest(),
                    "chain_hash":hashlib.sha3_512(f"{snap_id}{ts_313}".encode()).hexdigest()}
        self._snapshots[snap_id] = snapshot
        (self.snapshot_dir / f"{snap_id}.json").write_text(json.dumps(snapshot,indent=2))
        return snap_id

    def revert(self, node_id: str, snap_id: str = None) -> Dict:
        if snap_id:
            snapshot = self._snapshots.get(snap_id)
        else:
            node_snaps = [s for s in self._snapshots.values() if s["node_id"]==node_id]
            snapshot = max(node_snaps, key=lambda x: x["timestamp_ns"]) if node_snaps else None
        if not snapshot:
            return {"success":False,"error":"No snapshot found"}
        state_hash = hashlib.sha3_256(json.dumps(snapshot["state"],sort_keys=True).encode()).hexdigest()
        if state_hash != snapshot["hash"]:
            return {"success":False,"error":"Integrity check failed — tampered"}
        reversion = {"id":str(uuid.uuid4()),"node_id":node_id,"snapshot_id":snapshot["id"],
                     "timestamp":datetime.now(timezone.utc).isoformat(),"success":True}
        self._reversions.append(reversion)
        return reversion

    def list_snapshots(self, node_id: str = None) -> List[Dict]:
        snaps = list(self._snapshots.values())
        if node_id: snaps = [s for s in snaps if s["node_id"]==node_id]
        return sorted(snaps, key=lambda x: x["timestamp_ns"], reverse=True)
