"""
Unit tests — shadow313.v4.quantum_nexus (full suite)
Covers: qkd_bb84, orbital_dsp, omega_purge, lif_snn,
        aeon_engine, ceqs_engine, qebim_engine, nvl72_telemetry
"""
from __future__ import annotations
import pytest
import numpy as np


# ── QKD BB84 ──────────────────────────────────────────────────────────────────

class TestQKDBB84:
    def test_importable(self):
        from shadow313.v4.quantum_nexus.qkd_bb84 import BB84Simulator
        assert BB84Simulator is not None

    def test_safe_session_zero_qber(self):
        from shadow313.v4.quantum_nexus.qkd_bb84 import BB84Simulator
        sim = BB84Simulator(key_length=256)
        result = sim.simulate_protocol(under_attack=False)
        assert result["qber"] == 0.0
        assert result["security_status"] == "SECURE"
        assert result["eve_key_interception_rate"] == 0.0

    def test_apd_blinding_attack(self):
        from shadow313.v4.quantum_nexus.qkd_bb84 import BB84Simulator
        sim = BB84Simulator(key_length=1024)
        result = sim.simulate_protocol(under_attack=True)
        assert result["attack_type"] == "APD_BLINDING"
        assert result["eve_key_interception_rate"] == 1.0

    def test_qber_threshold_default(self):
        from shadow313.v4.quantum_nexus.qkd_bb84 import BB84Simulator
        sim = BB84Simulator()
        assert sim.qber_threshold == 0.11

    def test_comparison_run(self):
        from shadow313.v4.quantum_nexus.qkd_bb84 import BB84Simulator
        sim = BB84Simulator(key_length=512)
        comparison = sim.run_comparison()
        assert "safe_session" in comparison
        assert "attacked_session" in comparison
        assert "vulnerability_confirmed" in comparison

    def test_session_log_tracked(self):
        from shadow313.v4.quantum_nexus.qkd_bb84 import BB84Simulator
        sim = BB84Simulator(key_length=128)
        sim.simulate_protocol(under_attack=False)
        sim.simulate_protocol(under_attack=True)
        assert len(sim.session_log) == 2


# ── ORBITAL DSP ───────────────────────────────────────────────────────────────

class TestOrbitalDSP:
    def test_importable(self):
        from shadow313.v4.quantum_nexus.orbital_dsp import OrbitalDSP
        assert OrbitalDSP is not None

    def test_bpsk_signal_shape(self):
        from shadow313.v4.quantum_nexus.orbital_dsp import OrbitalDSP
        dsp = OrbitalDSP(sample_rate=1e6)
        bits = np.random.randint(0, 2, 100)
        signal = dsp.generate_bpsk_signal(bits, doppler_hz=5000)
        assert len(signal) == 100
        assert signal.dtype == complex

    def test_intercept_ber_range(self):
        from shadow313.v4.quantum_nexus.orbital_dsp import OrbitalDSP
        dsp = OrbitalDSP()
        bits = np.random.randint(0, 2, 500)
        result = dsp.intercept(bits, doppler_hz=5000)
        assert 0.0 <= result["ber"] <= 1.0
        assert "intercept_success" in result

    def test_intercept_log_tracked(self):
        from shadow313.v4.quantum_nexus.orbital_dsp import OrbitalDSP
        dsp = OrbitalDSP()
        bits = np.random.randint(0, 2, 200)
        dsp.intercept(bits)
        assert len(dsp.intercept_log) == 1


# ── OMEGA PURGE ───────────────────────────────────────────────────────────────

class TestOmegaPurge:
    def test_importable(self):
        from shadow313.v4.quantum_nexus.omega_purge import OmegaPurgePanel, StableQuantumFilter
        assert OmegaPurgePanel is not None
        assert StableQuantumFilter is not None

    def test_qr_logdet_success(self):
        from shadow313.v4.quantum_nexus.omega_purge import OmegaPurgePanel, StableQuantumFilter
        monitor = OmegaPurgePanel(vram_limit_gb=30000)
        qfilter = StableQuantumFilter(monitor)
        matrix = (np.random.randn(64, 64) * 0.05).astype(np.float16)
        result = qfilter.calculate_qr_logdet(matrix)
        assert result["status"] == "SUCCESS"
        assert isinstance(result["logdet"], float)

    def test_vram_limit_enforced(self):
        from shadow313.v4.quantum_nexus.omega_purge import OmegaPurgePanel
        monitor = OmegaPurgePanel(vram_limit_gb=0.0001)
        with pytest.raises(MemoryError):
            monitor.check_vram_overhead((10000, 10000), 4)

    def test_vram_released_after_operation(self):
        from shadow313.v4.quantum_nexus.omega_purge import OmegaPurgePanel, StableQuantumFilter
        monitor = OmegaPurgePanel(vram_limit_gb=30000)
        qfilter = StableQuantumFilter(monitor)
        matrix = (np.random.randn(32, 32) * 0.05).astype(np.float16)
        qfilter.calculate_qr_logdet(matrix)
        assert monitor.current_vram_gb == 0.0


# ── LIF SNN ───────────────────────────────────────────────────────────────────

class TestLIFSNN:
    def test_importable(self):
        from shadow313.v4.quantum_nexus.lif_snn import LIFNeuronSOC, APTBeaconDetector
        assert LIFNeuronSOC is not None
        assert APTBeaconDetector is not None

    def test_spike_on_accumulated_signal(self):
        from shadow313.v4.quantum_nexus.lif_snn import LIFNeuronSOC
        neuron = LIFNeuronSOC(threshold=0.5, leak_rate=0.95)
        traffic = [0.01] * 50
        traffic[10] = 0.4
        traffic[11] = 0.4
        traffic[12] = 0.4
        result = neuron.process_stream(traffic)
        assert result["detection"] is True
        assert len(result["spikes"]) > 0

    def test_no_spike_on_low_signal(self):
        from shadow313.v4.quantum_nexus.lif_snn import LIFNeuronSOC
        neuron = LIFNeuronSOC(threshold=1.0, leak_rate=0.5)
        traffic = [0.01] * 100
        result = neuron.process_stream(traffic)
        assert result["detection"] is False

    def test_neuron_reset(self):
        from shadow313.v4.quantum_nexus.lif_snn import LIFNeuronSOC
        neuron = LIFNeuronSOC()
        neuron.voltage = 0.9
        neuron.reset()
        assert neuron.voltage == 0.0

    def test_apt_beacon_detector(self):
        from shadow313.v4.quantum_nexus.lif_snn import APTBeaconDetector
        detector = APTBeaconDetector(threshold=0.5, leak_rate=0.95)
        traffic = [0.01] * 50
        beacon_indices = [10, 11, 12, 13]
        for i in beacon_indices:
            traffic[i] = 0.35
        result = detector.analyze_traffic(traffic, beacon_indices)
        assert "snn_alerts" in result
        assert "siem_alerts" in result
        assert "snn_true_positives" in result


# ── AEON ENGINE ───────────────────────────────────────────────────────────────

class TestAeonEngine:
    def test_importable(self):
        try:
            import shadow313.v4.quantum_nexus.aeon_engine as mod
            assert mod is not None
        except ImportError:
            pytest.skip("aeon_engine not available")

    def test_module_has_public_attrs(self):
        import shadow313.v4.quantum_nexus.aeon_engine as mod
        public = [a for a in dir(mod) if not a.startswith("_")]
        assert len(public) >= 1


# ── CEQS ENGINE ───────────────────────────────────────────────────────────────

class TestCEQSEngine:
    def test_importable(self):
        try:
            import shadow313.v4.quantum_nexus.ceqs_engine as mod
            assert mod is not None
        except ImportError:
            pytest.skip("ceqs_engine not available")

    def test_module_has_public_attrs(self):
        import shadow313.v4.quantum_nexus.ceqs_engine as mod
        public = [a for a in dir(mod) if not a.startswith("_")]
        assert len(public) >= 1


# ── QEBIM ENGINE ──────────────────────────────────────────────────────────────

class TestQEBIMEngine:
    def test_importable(self):
        try:
            import shadow313.v4.quantum_nexus.qebim_engine as mod
            assert mod is not None
        except ImportError:
            pytest.skip("qebim_engine not available")

    def test_module_has_public_attrs(self):
        import shadow313.v4.quantum_nexus.qebim_engine as mod
        public = [a for a in dir(mod) if not a.startswith("_")]
        assert len(public) >= 1


# ── NVL72 TELEMETRY ───────────────────────────────────────────────────────────

class TestNVL72Telemetry:
    def test_importable(self):
        try:
            import shadow313.v4.quantum_nexus.nvl72_telemetry as mod
            assert mod is not None
        except ImportError:
            pytest.skip("nvl72_telemetry not available")

    def test_module_has_public_attrs(self):
        import shadow313.v4.quantum_nexus.nvl72_telemetry as mod
        public = [a for a in dir(mod) if not a.startswith("_")]
        assert len(public) >= 1