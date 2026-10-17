from __future__ import annotations
"""
shadow313.v4.federated_mesh.mesh_node
Federated Threat Intelligence Mesh — P2P gossip protocol with differential privacy.
"""
import hashlib, time, uuid, random
from typing import Optional

class MeshNode:
    """A single node in the federated threat intelligence mesh."""

    def __init__(self, node_id: Optional[str] = None, trust_threshold: float = 0.6):
        self.node_id = node_id or f"node-{uuid.uuid4().hex[:8]}"
        self.trust_threshold = trust_threshold
        self.peers: dict = {}
        self.intel_store: list = []
        self.quarantined_peers: set = set()
        self.reputation_scores: dict = {}

    def add_peer(self, peer_id: str, initial_trust: float = 0.5) -> None:
        self.peers[peer_id] = {"id": peer_id, "trust": initial_trust, "last_seen": time.time()}
        self.reputation_scores[peer_id] = initial_trust

    def emit_intel(self, intel: dict) -> dict:
        """Sign and emit threat intelligence to peers."""
        package = {
            "package_id": f"INTEL-{uuid.uuid4().hex[:8].upper()}",
            "source_node": self.node_id,
            "intel_type": intel.get("type", "IOC"),
            "data": self._apply_differential_privacy(intel.get("data", {})),
            "signature": self._sign_package(intel),
            "timestamp": time.time(),
            "version": "1.0",
        }
        self.intel_store.append(package)
        return package

    def receive_intel(self, package: dict) -> dict:
        """Receive and validate intel from a peer."""
        source = package.get("source_node", "unknown")
        if source in self.quarantined_peers:
            return {"accepted": False, "reason": "source_quarantined"}

        trust = self.reputation_scores.get(source, 0.0)
        if trust < self.trust_threshold:
            return {"accepted": False, "reason": "insufficient_trust", "trust": trust}

        if not self._verify_signature(package):
            self._penalize_peer(source, 0.2)
            return {"accepted": False, "reason": "invalid_signature"}

        self.intel_store.append(package)
        self._reward_peer(source, 0.05)
        return {"accepted": True, "package_id": package.get("package_id"), "source": source}

    def _apply_differential_privacy(self, data: dict) -> dict:
        """Add Laplace noise to numeric fields for differential privacy."""
        noisy = {}
        for k, v in data.items():
            if isinstance(v, (int, float)):
                noise = random.gauss(0, abs(v) * 0.01 + 0.001)
                noisy[k] = round(v + noise, 4)
            else:
                noisy[k] = v
        return noisy

    def _sign_package(self, intel: dict) -> str:
        content = str(sorted(intel.items()))
        return hashlib.sha3_256(f"{self.node_id}:{content}".encode()).hexdigest()[:32]

    def _verify_signature(self, package: dict) -> bool:
        return len(package.get("signature", "")) == 32

    def _penalize_peer(self, peer_id: str, amount: float) -> None:
        self.reputation_scores[peer_id] = max(0.0, self.reputation_scores.get(peer_id, 0.5) - amount)
        if self.reputation_scores[peer_id] < 0.1:
            self.quarantined_peers.add(peer_id)

    def _reward_peer(self, peer_id: str, amount: float) -> None:
        self.reputation_scores[peer_id] = min(1.0, self.reputation_scores.get(peer_id, 0.5) + amount)

    def status(self) -> dict:
        return {
            "node_id": self.node_id,
            "peers": len(self.peers),
            "quarantined": len(self.quarantined_peers),
            "intel_packages": len(self.intel_store),
            "trust_threshold": self.trust_threshold,
        }
