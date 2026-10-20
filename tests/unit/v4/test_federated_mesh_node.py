"""Unit tests — shadow313.v4.federated_mesh.mesh_node"""
import pytest

class TestMeshNode:
    def test_importable(self):
        from shadow313.v4.federated_mesh.mesh_node import MeshNode
        assert MeshNode is not None

    def test_node_creation(self):
        from shadow313.v4.federated_mesh.mesh_node import MeshNode
        node = MeshNode(node_id="node-test-001")
        assert node.node_id == "node-test-001"
        assert node.trust_threshold == 0.6

    def test_peer_management(self):
        from shadow313.v4.federated_mesh.mesh_node import MeshNode
        node = MeshNode()
        node.add_peer("peer-001", initial_trust=0.7)
        assert "peer-001" in node.peers
        assert node.reputation_scores["peer-001"] == 0.7

    def test_intel_emission(self):
        from shadow313.v4.federated_mesh.mesh_node import MeshNode
        node = MeshNode()
        package = node.emit_intel({"type": "IOC", "data": {"ip": "185.220.101.42", "count": 5}})
        assert "package_id" in package
        assert package["source_node"] == node.node_id
        assert "signature" in package
        assert len(package["signature"]) == 32

    def test_intel_reception_trusted(self):
        from shadow313.v4.federated_mesh.mesh_node import MeshNode
        sender = MeshNode(node_id="sender-001")
        receiver = MeshNode(node_id="receiver-001")
        receiver.add_peer("sender-001", initial_trust=0.8)
        package = sender.emit_intel({"type": "IOC", "data": {"domain": "evil.com"}})
        result = receiver.receive_intel(package)
        assert result["accepted"] is True

    def test_intel_rejection_low_trust(self):
        from shadow313.v4.federated_mesh.mesh_node import MeshNode
        sender = MeshNode(node_id="sender-002")
        receiver = MeshNode(node_id="receiver-002")
        receiver.add_peer("sender-002", initial_trust=0.1)
        package = sender.emit_intel({"type": "IOC", "data": {}})
        result = receiver.receive_intel(package)
        assert result["accepted"] is False
        assert result["reason"] == "insufficient_trust"

    def test_quarantine_on_repeated_violations(self):
        from shadow313.v4.federated_mesh.mesh_node import MeshNode
        node = MeshNode()
        node.add_peer("bad-peer", initial_trust=0.5)
        for _ in range(5):
            node._penalize_peer("bad-peer", 0.15)
        assert "bad-peer" in node.quarantined_peers

    def test_differential_privacy(self):
        from shadow313.v4.federated_mesh.mesh_node import MeshNode
        node = MeshNode()
        original = {"count": 100, "score": 0.85}
        noisy = node._apply_differential_privacy(original)
        # Values should be close but not identical
        assert abs(noisy["count"] - original["count"]) < 10
        assert abs(noisy["score"] - original["score"]) < 0.1

class TestIdentityEngine:
    def test_importable(self):
        from shadow313.v4.identity.identity_engine import IdentityEngine
        assert IdentityEngine is not None

    def test_identity_registration(self):
        from shadow313.v4.identity.identity_engine import IdentityEngine
        engine = IdentityEngine()
        identity = engine.register_identity("user-001", "human", {"department": "security"})
        assert identity["id"] == "user-001"
        assert identity["type"] == "human"

    def test_authentication_success(self):
        from shadow313.v4.identity.identity_engine import IdentityEngine
        engine = IdentityEngine()
        engine.register_identity("user-002", "human")
        factors = [{"type": "password"}, {"type": "totp"}, {"type": "hardware_token"}]
        result = engine.authenticate("user-002", factors)
        assert result["authenticated"] is True
        assert "session_id" in result

    def test_authentication_failure_no_identity(self):
        from shadow313.v4.identity.identity_engine import IdentityEngine
        engine = IdentityEngine()
        result = engine.authenticate("nonexistent", [{"type": "password"}])
        assert result["authenticated"] is False

    def test_authorization_check(self):
        from shadow313.v4.identity.identity_engine import IdentityEngine
        engine = IdentityEngine()
        engine.register_identity("user-003", "human")
        factors = [{"type": "password"}, {"type": "totp"}, {"type": "hardware_token"}]
        auth = engine.authenticate("user-003", factors)
        if auth["authenticated"]:
            authz = engine.authorize(auth["session_id"], "/api/status", "read")
            assert "authorized" in authz

    def test_status(self):
        from shadow313.v4.identity.identity_engine import IdentityEngine
        engine = IdentityEngine()
        engine.register_identity("user-004", "workload")
        status = engine.status()
        assert status["identities_registered"] == 1
