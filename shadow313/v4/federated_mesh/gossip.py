"""
shadow313.v4.federated_mesh.gossip
Gossip protocol for federated mesh — epidemic broadcast with anti-entropy.
"""
from __future__ import annotations
import random, time
from typing import Optional


class GossipProtocol:
    """Epidemic gossip broadcast for threat intel propagation."""

    def __init__(self, fanout: int = 3, ttl: int = 5):
        self.fanout = fanout
        self.ttl = ttl
        self.seen_messages: set = set()
        self.message_log: list = []

    def broadcast(self, message: dict, peers: list) -> list:
        msg_id = message.get("id", "unknown")
        if msg_id in self.seen_messages:
            return []
        self.seen_messages.add(msg_id)
        message["ttl"] = message.get("ttl", self.ttl)
        if message["ttl"] <= 0:
            return []
        message["ttl"] -= 1
        targets = random.sample(peers, min(self.fanout, len(peers)))
        self.message_log.append({"msg_id": msg_id, "targets": len(targets), "ts": time.time()})
        return targets

    def anti_entropy(self, local_ids: set, remote_ids: set) -> dict:
        missing_local = remote_ids - local_ids
        missing_remote = local_ids - remote_ids
        return {"need_from_remote": list(missing_local), "can_send_to_remote": list(missing_remote)}

    def status(self) -> dict:
        return {"seen": len(self.seen_messages), "broadcasts": len(self.message_log), "fanout": self.fanout}