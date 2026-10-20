"""
shadow313.v4.federated_mesh.mesh
Core federated mesh node — P2P threat intelligence sharing.
"""
from __future__ import annotations
import hashlib, time, uuid
from typing import Optional


class FederatedMeshNode:
    """Core mesh node for P2P threat intelligence federation."""

    def __init__(self, node_id: Optional[str] = None, trust_threshold: float = 0.6):
        self.node_id = node_id or f"node-{uuid.uuid4().hex[:8]}"
        self.trust_threshold = trust_threshold
        self.peers: dict = {}
        self.intel_store: list = []
        self.quarantined: set = set()

    def add_peer(self, peer_id: str, trust: float = 0.5) -> None:
        self.peers[peer_id] = {"id": peer_id, "trust": trust, "last_seen": time.time()}

    def emit(self, intel: dict) -> dict:
        pkg = {
            "id": f"INTEL-{uuid.uuid4().hex[:8].upper()}",
            "source": self.node_id,
            "data": intel,
            "sig": hashlib.sha3_256(str(intel).encode()).hexdigest()[:32],
            "ts": time.time(),
        }
        self.intel_store.append(pkg)
        return pkg

    def receive(self, pkg: dict) -> dict:
        src = pkg.get("source", "unknown")
        if src in self.quarantined:
            return {"accepted": False, "reason": "quarantined"}
        trust = self.peers.get(src, {}).get("trust", 0.0)
        if trust < self.trust_threshold:
            return {"accepted": False, "reason": "low_trust", "trust": trust}
        self.intel_store.append(pkg)
        return {"accepted": True, "id": pkg.get("id")}

    def status(self) -> dict:
        return {"node_id": self.node_id, "peers": len(self.peers), "intel": len(self.intel_store)}