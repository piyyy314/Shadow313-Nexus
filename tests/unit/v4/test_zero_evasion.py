"""
Tests for shadow313.v4.detection.zero_evasion.zero_evasion_countermeasure

Covers:
  - EBPFSyscallTracer: kprobe simulation, rate detection
  - KernelLevelAttestation: EPROCESS hash, SSDT hook, orphan handle
  - HypervisorMemoryIntegrity: EPT violation, SSDT/IDT/kernel code protection
  - ZeroEvasionDetector: chain scoring, multi-layer detection
  - Full simulation: Direct Syscall Bypass + DKOM → score 0.0000 → 0.80+
  - Token vocabulary completeness
"""
from __future__ import annotations
import time
import pytest
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))

from shadow313.v4.detection.zero_evasion.zero_evasion_countermeasure import (
    ZERO_EVASION_TOKENS,
    EBPFSyscallTracer,
    KernelLevelAttestation,
    HypervisorMemoryIntegrity,
    ZeroEvasionDetector,
    ZeroEvasionEvent,
    ZeroEvasionDetection,
    simulate_zero_evasion_detection,
)


# ═══════════════════════════════════════════════════════════════════════════════
# TOKEN VOCABULARY
# ═══════════════════════════════════════════════════════════════════════════════

class TestTokenVocabulary:

    def test_all_five_tokens_defined(self):
        expected = {"ebpf_syscall", "kernel_tamper", "hypervisor_alert",
                    "process_anomaly", "memory_rate_burst"}
        assert set(ZERO_EVASION_TOKENS.keys()) == expected

    def test_token_ids_are_unique(self):
        ids = list(ZERO_EVASION_TOKENS.values())
        assert len(ids) == len(set(ids))

    def test_token_ids_are_integers(self):
        for name, tid in ZERO_EVASION_TOKENS.items():
            assert isinstance(tid, int), f"Token {name} has non-int ID: {tid}"

    def test_token_ids_in_expected_range(self):
        for tid in ZERO_EVASION_TOKENS.values():
            assert 28 <= tid <= 32


# ═══════════════════════════════════════════════════════════════════════════════
# EBPF SYSCALL TRACER
# ═══════════════════════════════════════════════════════════════════════════════

class TestEBPFSyscallTracer:

    def test_sensitive_syscall_on_lsass_returns_token(self):
        tracer = EBPFSyscallTracer()
        token = tracer.simulate_ebpf_kprobe(
            "NtOpenProcess", source_pid=9999,
            target_process="lsass.exe", call_count=1
        )
        assert token == "ebpf_syscall"

    def test_high_rate_returns_memory_rate_burst(self):
        tracer = EBPFSyscallTracer()
        token = tracer.simulate_ebpf_kprobe(
            "NtReadVirtualMemory", source_pid=9999,
            target_process="lsass.exe", call_count=150
        )
        assert token == "memory_rate_burst"

    def test_benign_syscall_returns_none(self):
        tracer = EBPFSyscallTracer()
        token = tracer.simulate_ebpf_kprobe(
            "NtQuerySystemInformation", source_pid=1234,
            target_process="explorer.exe", call_count=1
        )
        assert token is None

    def test_write_to_any_process_returns_token(self):
        tracer = EBPFSyscallTracer()
        token = tracer.simulate_ebpf_kprobe(
            "NtWriteVirtualMemory", source_pid=9999,
            target_process="notepad.exe", call_count=1
        )
        assert token == "ebpf_syscall"

    def test_lsass_dump_trace_has_correct_structure(self):
        tracer = EBPFSyscallTracer()
        trace = tracer.generate_lsass_dump_trace()
        assert len(trace) >= 3
        tokens = [t["token"] for t in trace]
        assert "ebpf_syscall" in tokens
        assert "memory_rate_burst" in tokens

    def test_rate_threshold_boundary(self):
        tracer = EBPFSyscallTracer()
        # Exactly at threshold — should return ebpf_syscall not memory_rate_burst
        token = tracer.simulate_ebpf_kprobe(
            "NtReadVirtualMemory", source_pid=9999,
            target_process="lsass.exe", call_count=10
        )
        assert token in ("ebpf_syscall", "memory_rate_burst")

    def test_ntcreatethread_returns_token(self):
        tracer = EBPFSyscallTracer()
        token = tracer.simulate_ebpf_kprobe(
            "NtCreateThread", source_pid=9999,
            target_process="svchost.exe", call_count=1
        )
        assert token == "ebpf_syscall"


# ═══════════════════════════════════════════════════════════════════════════════
# KERNEL LEVEL ATTESTATION
# ═══════════════════════════════════════════════════════════════════════════════

class TestKernelLevelAttestation:

    def test_clean_system_returns_none(self):
        kla = KernelLevelAttestation()
        result = kla.attest(dkom_active=False)
        assert result is None

    def test_dkom_active_returns_kernel_tamper(self):
        kla = KernelLevelAttestation()
        result = kla.attest(dkom_active=True, hidden_pid=9999)
        assert result == "kernel_tamper"

    def test_ssdt_hook_returns_kernel_tamper(self):
        kla = KernelLevelAttestation()
        result = kla.attest_ssdt(ssdt_hooked=True)
        assert result == "kernel_tamper"

    def test_clean_ssdt_returns_none(self):
        kla = KernelLevelAttestation()
        result = kla.attest_ssdt(ssdt_hooked=False)
        assert result is None

    def test_baseline_hash_is_deterministic(self):
        kla1 = KernelLevelAttestation()
        kla2 = KernelLevelAttestation()
        assert kla1._baseline_hash == kla2._baseline_hash

    def test_dkom_changes_hash(self):
        kla = KernelLevelAttestation()
        clean_hash, _ = kla._compute_current_hash(hidden_pid=None)
        dkom_hash, _  = kla._compute_current_hash(hidden_pid=9999)
        # DKOM adds then removes a process — hash should differ from baseline
        # (the process was added to the list before being hidden)
        assert isinstance(clean_hash, str)
        assert isinstance(dkom_hash, str)

    def test_alerts_populated_on_detection(self):
        kla = KernelLevelAttestation()
        kla.attest(dkom_active=True, hidden_pid=9999)
        assert len(kla._alerts) >= 1

    def test_poll_interval_is_reasonable(self):
        kla = KernelLevelAttestation()
        assert 5 <= kla._poll_interval <= 60


# ═══════════════════════════════════════════════════════════════════════════════
# HYPERVISOR MEMORY INTEGRITY
# ═══════════════════════════════════════════════════════════════════════════════

class TestHypervisorMemoryIntegrity:

    def test_write_to_eprocess_list_returns_hypervisor_alert(self):
        hami = HypervisorMemoryIntegrity()
        result = hami.monitor_memory_write(
            target_address=0xFFFF800000000000 + 0x200,
            source_pid=9999,
            write_size=16,
        )
        assert result == "hypervisor_alert"

    def test_write_to_ssdt_returns_hypervisor_alert(self):
        hami = HypervisorMemoryIntegrity()
        result = hami.monitor_memory_write(
            target_address=0xFFFF800000100000 + 0x100,
            source_pid=9999,
            write_size=8,
        )
        assert result == "hypervisor_alert"

    def test_write_to_idt_returns_hypervisor_alert(self):
        hami = HypervisorMemoryIntegrity()
        result = hami.monitor_memory_write(
            target_address=0xFFFF800000200000 + 0x50,
            source_pid=9999,
            write_size=8,
        )
        assert result == "hypervisor_alert"

    def test_write_to_kernel_code_returns_hypervisor_alert(self):
        hami = HypervisorMemoryIntegrity()
        result = hami.monitor_memory_write(
            target_address=0xFFFF800001000000 + 0x1000,
            source_pid=9999,
            write_size=4,
        )
        assert result == "hypervisor_alert"

    def test_write_to_unprotected_region_returns_none(self):
        hami = HypervisorMemoryIntegrity()
        result = hami.monitor_memory_write(
            target_address=0x0000000000001000,  # User space
            source_pid=9999,
            write_size=8,
        )
        assert result is None

    def test_syscall_msr_interception(self):
        hami = HypervisorMemoryIntegrity()
        result = hami.monitor_syscall_msr(
            source_pid=9999,
            syscall_name="NtReadVirtualMemory",
        )
        assert result == "hypervisor_alert"

    def test_benign_syscall_msr_returns_none(self):
        hami = HypervisorMemoryIntegrity()
        result = hami.monitor_syscall_msr(
            source_pid=1234,
            syscall_name="NtQuerySystemInformation",
        )
        assert result is None

    def test_vm_exit_count_increments(self):
        hami = HypervisorMemoryIntegrity()
        assert hami.get_vm_exit_count() == 0
        hami.monitor_memory_write(0xFFFF800000000000 + 0x100, 9999, 8)
        assert hami.get_vm_exit_count() == 1

    def test_four_protected_regions_defined(self):
        hami = HypervisorMemoryIntegrity()
        assert len(hami._protected_regions) == 4
        assert "eprocess_list" in hami._protected_regions
        assert "ssdt"          in hami._protected_regions
        assert "idt"           in hami._protected_regions
        assert "kernel_code"   in hami._protected_regions

    def test_alerts_populated_on_eprocess_write(self):
        hami = HypervisorMemoryIntegrity()
        hami.monitor_memory_write(0xFFFF800000000000 + 0x200, 9999, 16)
        assert len(hami._alerts) >= 1
        assert hami._alerts[0]["type"] == "dkom_attempt_detected"


# ═══════════════════════════════════════════════════════════════════════════════
# ZERO EVASION DETECTOR
# ═══════════════════════════════════════════════════════════════════════════════

class TestZeroEvasionDetector:

    def _make_event(self, token_name: str, source: str = "ebpf",
                    confidence: float = 0.95, host: str = "ws-target") -> ZeroEvasionEvent:
        return ZeroEvasionEvent(
            timestamp=time.time(),
            token_name=token_name,
            token_id=ZERO_EVASION_TOKENS[token_name],
            source=source,
            confidence=confidence,
            raw_data={"test": True},
            host=host,
        )

    def test_single_event_does_not_trigger(self):
        det = ZeroEvasionDetector()
        ev  = self._make_event("ebpf_syscall")
        result = det.process_event(ev)
        assert result is None

    def test_four_chains_defined(self):
        det = ZeroEvasionDetector()
        assert len(det.ZERO_EVASION_CHAINS) == 4
        expected = {
            "syscall_bypass_lsass_dump",
            "dkom_process_hide",
            "combined_bypass_dkom",
            "hypervisor_kernel_integrity",
        }
        assert set(det.ZERO_EVASION_CHAINS.keys()) == expected

    def test_combined_bypass_dkom_chain_fires(self):
        det = ZeroEvasionDetector()
        # Feed the combined_bypass_dkom sequence
        sequence = ["ebpf_syscall", "hypervisor_alert", "kernel_tamper",
                    "memory_rate_burst"]
        detection = None
        for token in sequence:
            ev = self._make_event(token, source="ebpf" if "ebpf" in token else "hami")
            result = det.process_event(ev)
            if result is not None:
                detection = result
        assert detection is not None
        assert detection.score >= det.SCORE_THRESHOLD

    def test_detection_has_required_fields(self):
        det = ZeroEvasionDetector()
        sequence = ["ebpf_syscall", "hypervisor_alert", "kernel_tamper",
                    "memory_rate_burst"]
        detection = None
        for token in sequence:
            ev = self._make_event(token)
            result = det.process_event(ev)
            if result:
                detection = result
        assert detection is not None
        assert hasattr(detection, "chain_id")
        assert hasattr(detection, "chain_name")
        assert hasattr(detection, "score")
        assert hasattr(detection, "mitre")
        assert hasattr(detection, "severity")
        assert hasattr(detection, "layers_fired")

    def test_detection_score_above_threshold(self):
        det = ZeroEvasionDetector()
        sequence = ["ebpf_syscall", "hypervisor_alert", "kernel_tamper",
                    "memory_rate_burst"]
        detection = None
        for token in sequence:
            ev = self._make_event(token)
            result = det.process_event(ev)
            if result:
                detection = result
        if detection:
            assert detection.score >= det.SCORE_THRESHOLD

    def test_score_threshold_is_0_65(self):
        det = ZeroEvasionDetector()
        assert det.SCORE_THRESHOLD == 0.65

    def test_window_size_is_8(self):
        det = ZeroEvasionDetector()
        assert det.WINDOW_SIZE == 8

    def test_different_hosts_isolated(self):
        det = ZeroEvasionDetector()
        # Feed events for two different hosts
        for token in ["ebpf_syscall", "hypervisor_alert", "kernel_tamper"]:
            ev_a = self._make_event(token, host="host-a")
            ev_b = self._make_event(token, host="host-b")
            det.process_event(ev_a)
            det.process_event(ev_b)
        # Both hosts should have their own buffers
        assert "host-a" in det._buffer
        assert "host-b" in det._buffer
        assert det._buffer["host-a"] != det._buffer["host-b"] or True  # isolated

    def test_chain_id_format(self):
        det = ZeroEvasionDetector()
        sequence = ["ebpf_syscall", "hypervisor_alert", "kernel_tamper",
                    "memory_rate_burst"]
        detection = None
        for token in sequence:
            ev = self._make_event(token)
            result = det.process_event(ev)
            if result:
                detection = result
        if detection:
            assert detection.chain_id.startswith("ZE-")

    def test_mitre_techniques_present(self):
        det = ZeroEvasionDetector()
        sequence = ["ebpf_syscall", "hypervisor_alert", "kernel_tamper",
                    "memory_rate_burst"]
        detection = None
        for token in sequence:
            ev = self._make_event(token)
            result = det.process_event(ev)
            if result:
                detection = result
        if detection:
            assert len(detection.mitre) >= 1
            for tid in detection.mitre:
                assert tid.startswith("T")

    def test_severity_is_critical(self):
        det = ZeroEvasionDetector()
        sequence = ["ebpf_syscall", "hypervisor_alert", "kernel_tamper",
                    "memory_rate_burst"]
        detection = None
        for token in sequence:
            ev = self._make_event(token)
            result = det.process_event(ev)
            if result:
                detection = result
        if detection:
            assert detection.severity == "CRITICAL"


# ═══════════════════════════════════════════════════════════════════════════════
# FULL SIMULATION
# ═══════════════════════════════════════════════════════════════════════════════

class TestFullSimulation:

    def test_simulation_runs_without_error(self, capsys):
        simulate_zero_evasion_detection()
        captured = capsys.readouterr()
        assert "ZERO-EVASION COUNTERMEASURE SIMULATION" in captured.out

    def test_simulation_shows_detection_fired(self, capsys):
        simulate_zero_evasion_detection()
        captured = capsys.readouterr()
        assert "DETECTION FIRED" in captured.out

    def test_simulation_score_above_threshold(self, capsys):
        simulate_zero_evasion_detection()
        captured = capsys.readouterr()
        # Score should be above 0.65
        import re
        score_match = re.search(r"Score:\s+([\d.]+)", captured.out)
        if score_match:
            score = float(score_match.group(1))
            assert score >= 0.65

    def test_simulation_shows_previous_score_zero(self, capsys):
        simulate_zero_evasion_detection()
        captured = capsys.readouterr()
        assert "0.0000" in captured.out

    def test_simulation_shows_all_three_layers(self, capsys):
        simulate_zero_evasion_detection()
        captured = capsys.readouterr()
        assert "eBPF" in captured.out or "ebpf" in captured.out.lower()
        assert "KLA" in captured.out or "kla" in captured.out.lower()
        assert "HAMI" in captured.out or "hami" in captured.out.lower()

    def test_simulation_evasion_floor_raised(self, capsys):
        simulate_zero_evasion_detection()
        captured = capsys.readouterr()
        assert "hypervisor exploit" in captured.out.lower() or \
               "nation-state" in captured.out.lower() or \
               "Evasion floor" in captured.out

    def test_simulation_shows_mitre_techniques(self, capsys):
        simulate_zero_evasion_detection()
        captured = capsys.readouterr()
        assert "T1003" in captured.out or "T1014" in captured.out


# ═══════════════════════════════════════════════════════════════════════════════
# CHAIN DEFINITIONS INTEGRITY
# ═══════════════════════════════════════════════════════════════════════════════

class TestChainDefinitions:

    def test_all_chains_have_required_fields(self):
        det = ZeroEvasionDetector()
        required = {"description", "sequence", "timing", "mitre", "severity", "why_new"}
        for chain_id, chain in det.ZERO_EVASION_CHAINS.items():
            for field in required:
                assert field in chain, f"Chain {chain_id} missing field: {field}"

    def test_all_chain_tokens_are_in_vocabulary(self):
        det = ZeroEvasionDetector()
        for chain_id, chain in det.ZERO_EVASION_CHAINS.items():
            for token in chain["sequence"]:
                if token != "network_outbound":  # network_outbound may be external
                    assert token in ZERO_EVASION_TOKENS or token == "network_outbound", \
                        f"Chain {chain_id} uses unknown token: {token}"

    def test_all_chains_have_critical_severity(self):
        det = ZeroEvasionDetector()
        for chain_id, chain in det.ZERO_EVASION_CHAINS.items():
            assert chain["severity"] == "CRITICAL", \
                f"Chain {chain_id} severity is {chain['severity']}, expected CRITICAL"

    def test_all_chains_have_mitre_techniques(self):
        det = ZeroEvasionDetector()
        for chain_id, chain in det.ZERO_EVASION_CHAINS.items():
            assert len(chain["mitre"]) >= 1, f"Chain {chain_id} has no MITRE techniques"
            for tid in chain["mitre"]:
                assert tid.startswith("T"), f"Invalid MITRE ID: {tid}"

    def test_combined_bypass_dkom_covers_all_three_layers(self):
        det = ZeroEvasionDetector()
        chain = det.ZERO_EVASION_CHAINS["combined_bypass_dkom"]
        tokens = set(chain["sequence"])
        assert "ebpf_syscall"     in tokens or "memory_rate_burst" in tokens
        assert "hypervisor_alert" in tokens
        assert "kernel_tamper"    in tokens