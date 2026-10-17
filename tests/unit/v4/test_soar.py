"""Unit tests — shadow313.v4.soar"""
import pytest

class TestSOAREngine:
    def test_soar_engine_importable(self):
        try:
            from shadow313.v4.soar.soar_engine import SOAREngine
            engine = SOAREngine()
            assert engine is not None
        except ImportError:
            pytest.skip("soar_engine not available")

    def test_builtin_playbooks(self):
        from shadow313.v4.soar.soar_engine import BUILTIN_PLAYBOOKS
        assert len(BUILTIN_PLAYBOOKS) >= 5
        assert "malicious_ip_block" in BUILTIN_PLAYBOOKS
        assert "ransomware_response" in BUILTIN_PLAYBOOKS

    def test_playbook_execution(self):
        from shadow313.v4.soar.soar_engine import SOAREngine
        engine = SOAREngine()
        result = engine.execute_playbook("malicious_ip_block", {"ip": "185.220.101.42", "type": "CRITICAL_ALERT"})
        assert result["status"] == "completed"
        assert "incident_id" in result
        assert result["steps_executed"] > 0

    def test_alert_trigger(self):
        from shadow313.v4.soar.soar_engine import SOAREngine
        engine = SOAREngine()
        result = engine.trigger({"type": "RANSOMWARE_DETECTED", "host": "victim-01"})
        assert result.get("status") == "completed" or result.get("status") == "no_playbook"

    def test_metrics(self):
        from shadow313.v4.soar.soar_engine import SOAREngine
        engine = SOAREngine()
        engine.execute_playbook("malicious_ip_block", {"ip": "1.2.3.4"})
        metrics = engine.get_metrics()
        assert metrics["executions"] >= 1
        assert "avg_response_ms" in metrics

    def test_custom_playbook_registration(self):
        from shadow313.v4.soar.soar_engine import SOAREngine
        engine = SOAREngine()
        engine.register_playbook("custom_test", {"name": "Custom Test", "steps": ["step1", "step2"]})
        assert "custom_test" in engine.playbooks
