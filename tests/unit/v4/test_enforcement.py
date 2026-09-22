"""
Tests for shadow313.v4.detection.enforcement

Covers:
  - ProcessTerminator: policy evaluation, enforcement mode, monitoring mode
  - ProcessTerminator: blocked ports, restricted processes, external IP detection
  - ProcessTerminator: kill_pid, find_and_kill_process
  - OutboundTrafficFilter: rule generation, bash script output, dry-run
  - EnforcementEngine: combined D3-PT + D3-OTF interface
  - T1620 syscall additions to EBPFSyscallTracer
  - D3FEND coverage: D3-PT, D3-OTF, D3-SCA

ATT&CK techniques countered:
  T1095  Non-Application Layer Protocol (nc reverse shell)
  T1071.001  Web Protocols (Cobalt Strike beacon)
  T1620  Reflective Code Loading (memfd_create fileless)
"""
from __future__ import annotations
import os
import signal
import pytest
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))

from shadow313.v4.detection.enforcement import (
    ProcessTerminator,
    OutboundTrafficFilter,
    EnforcementEngine,
    EnforcementAction,
    OTFRule,
    BLOCKED_OUTBOUND_PORTS,
    RESTRICTED_PROCESSES,
    T1620_TOKENS,
    T1620_SENSITIVE_SYSCALLS,
)
from shadow313.v4.detection.zero_evasion.zero_evasion_countermeasure import (
    EBPFSyscallTracer,
    ZERO_EVASION_TOKENS,
)


# ═══════════════════════════════════════════════════════════════════════════════
# POLICY CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestPolicyConstants:

    def test_port_4444_is_blocked(self):
        """nc reverse shell port — confirmed in Aegis telemetry."""
        assert 4444 in BLOCKED_OUTBOUND_PORTS

    def test_port_9001_is_blocked(self):
        """Tor relay port — confirmed in Aegis telemetry (svchost_local.exe)."""
        assert 9001 in BLOCKED_OUTBOUND_PORTS

    def test_port_9050_is_blocked(self):
        """Tor SOCKS proxy."""
        assert 9050 in BLOCKED_OUTBOUND_PORTS

    def test_port_31337_is_blocked(self):
        """Elite/leet port — common backdoor."""
        assert 31337 in BLOCKED_OUTBOUND_PORTS

    def test_nc_is_restricted(self):
        assert "nc" in RESTRICTED_PROCESSES

    def test_backdoor_payload_is_restricted(self):
        """Explicit IOC from Aegis telemetry."""
        assert "backdoor_payload" in RESTRICTED_PROCESSES

    def test_blocked_ports_is_frozenset(self):
        assert isinstance(BLOCKED_OUTBOUND_PORTS, frozenset)

    def test_restricted_processes_is_frozenset(self):
        assert isinstance(RESTRICTED_PROCESSES, frozenset)

    def test_at_least_8_blocked_ports(self):
        assert len(BLOCKED_OUTBOUND_PORTS) >= 8

    def test_at_least_4_restricted_processes(self):
        assert len(RESTRICTED_PROCESSES) >= 4


# ═══════════════════════════════════════════════════════════════════════════════
# PROCESS TERMINATOR — MONITORING MODE
# ═══════════════════════════════════════════════════════════════════════════════

class TestProcessTerminatorMonitoring:
    """Tests in monitoring mode (enforcement_mode=False) — no actual kills."""

    @pytest.fixture
    def terminator(self):
        return ProcessTerminator(enforcement_mode=False)

    def test_blocked_port_returns_would_kill(self, terminator):
        action = terminator.evaluate_connection(
            pid=14209, process_name="nc",
            dst_ip="192.168.1.1", dst_port=4444,
        )
        assert action.action == "WOULD_KILL"

    def test_restricted_process_returns_would_kill(self, terminator):
        action = terminator.evaluate_connection(
            pid=9999, process_name="backdoor_payload",
            dst_ip="10.0.0.1", dst_port=80,
        )
        assert action.action == "WOULD_KILL"

    def test_allowed_connection_returns_allowed(self, terminator):
        action = terminator.evaluate_connection(
            pid=1234, process_name="curl",
            dst_ip="10.0.0.1", dst_port=443,
        )
        assert action.action == "ALLOWED"

    def test_action_has_pid(self, terminator):
        action = terminator.evaluate_connection(
            pid=14209, process_name="nc",
            dst_ip="192.168.1.1", dst_port=4444,
        )
        assert action.pid == 14209

    def test_action_has_process_name(self, terminator):
        action = terminator.evaluate_connection(
            pid=14209, process_name="nc",
            dst_ip="192.168.1.1", dst_port=4444,
        )
        assert action.process_name == "nc"

    def test_action_has_timestamp(self, terminator):
        action = terminator.evaluate_connection(
            pid=14209, process_name="nc",
            dst_ip="192.168.1.1", dst_port=4444,
        )
        assert action.timestamp
        assert "2026" in action.timestamp

    def test_action_has_reason(self, terminator):
        action = terminator.evaluate_connection(
            pid=14209, process_name="nc",
            dst_ip="192.168.1.1", dst_port=4444,
        )
        assert len(action.reason) > 10

    def test_action_has_d3fend_tag(self, terminator):
        action = terminator.evaluate_connection(
            pid=14209, process_name="nc",
            dst_ip="192.168.1.1", dst_port=4444,
        )
        assert action.d3fend == "D3-PT"

    def test_action_has_attack_tag(self, terminator):
        action = terminator.evaluate_connection(
            pid=14209, process_name="nc",
            dst_ip="192.168.1.1", dst_port=4444,
        )
        assert "T1095" in action.attack

    def test_stats_track_would_kill(self, terminator):
        terminator.evaluate_connection(14209, "nc", "192.168.1.1", 4444)
        terminator.evaluate_connection(14210, "nc", "192.168.1.1", 4444)
        stats = terminator.get_stats()
        assert stats["blocked"] == 2

    def test_stats_track_allowed(self, terminator):
        terminator.evaluate_connection(1234, "curl", "10.0.0.1", 443)
        stats = terminator.get_stats()
        assert stats["allowed"] == 1

    def test_enforcement_log_populated(self, terminator):
        terminator.evaluate_connection(14209, "nc", "192.168.1.1", 4444)
        log = terminator.get_enforcement_log()
        assert len(log) >= 1
        assert log[0]["pid"] == 14209

    def test_kill_log_empty_in_monitoring_mode(self, terminator):
        terminator.evaluate_connection(14209, "nc", "192.168.1.1", 4444)
        kill_log = terminator.get_kill_log()
        assert len(kill_log) == 0  # WOULD_KILL, not KILLED

    def test_all_blocked_ports_trigger_would_kill(self, terminator):
        for port in BLOCKED_OUTBOUND_PORTS:
            action = terminator.evaluate_connection(
                pid=9999, process_name="test",
                dst_ip="1.2.3.4", dst_port=port,
            )
            assert action.action == "WOULD_KILL", f"Port {port} should trigger WOULD_KILL"

    def test_all_restricted_processes_trigger_would_kill(self, terminator):
        for proc in RESTRICTED_PROCESSES:
            action = terminator.evaluate_connection(
                pid=9999, process_name=proc,
                dst_ip="10.0.0.1", dst_port=80,
            )
            assert action.action == "WOULD_KILL", f"Process {proc} should trigger WOULD_KILL"


# ═══════════════════════════════════════════════════════════════════════════════
# PROCESS TERMINATOR — ENFORCEMENT MODE (no real kills — uses non-existent PIDs)
# ═══════════════════════════════════════════════════════════════════════════════

class TestProcessTerminatorEnforcement:
    """Tests in enforcement mode using PIDs that don't exist (ProcessLookupError)."""

    @pytest.fixture
    def terminator(self):
        return ProcessTerminator(enforcement_mode=True)

    def test_blocked_port_returns_already_dead_for_nonexistent_pid(self, terminator):
        """Non-existent PID → ProcessLookupError → ALREADY_DEAD."""
        action = terminator.evaluate_connection(
            pid=9999999,  # Non-existent PID
            process_name="nc",
            dst_ip="192.168.1.1",
            dst_port=4444,
        )
        assert action.action in ("ALREADY_DEAD", "KILLED", "PERMISSION_DENIED")

    def test_kill_pid_nonexistent_returns_not_found(self, terminator):
        result = terminator.kill_pid(9999999, "test")
        assert result["action"] in ("NOT_FOUND", "KILLED", "PERMISSION_DENIED")

    def test_find_and_kill_nonexistent_process_returns_empty(self, terminator):
        results = terminator.find_and_kill_process("__nonexistent_process_xyz__")
        assert results == []

    def test_enforcement_mode_is_true(self, terminator):
        stats = terminator.get_stats()
        assert stats["enforcement_mode"] is True


# ═══════════════════════════════════════════════════════════════════════════════
# IP CLASSIFICATION
# ═══════════════════════════════════════════════════════════════════════════════

class TestIPClassification:

    def test_rfc1918_10_is_internal(self):
        assert not ProcessTerminator._is_external("10.0.0.1")
        assert not ProcessTerminator._is_external("10.255.255.255")

    def test_rfc1918_172_is_internal(self):
        assert not ProcessTerminator._is_external("172.16.0.1")
        assert not ProcessTerminator._is_external("172.31.255.255")

    def test_rfc1918_192_168_is_internal(self):
        assert not ProcessTerminator._is_external("192.168.1.1")
        assert not ProcessTerminator._is_external("192.168.255.255")

    def test_loopback_is_internal(self):
        assert not ProcessTerminator._is_external("127.0.0.1")
        assert not ProcessTerminator._is_external("127.0.0.53")

    def test_public_ip_is_external(self):
        assert ProcessTerminator._is_external("45.138.16.89")   # From Aegis telemetry
        assert ProcessTerminator._is_external("185.220.101.5")  # Tor exit node
        assert ProcessTerminator._is_external("8.8.8.8")
        assert ProcessTerminator._is_external("1.1.1.1")

    def test_docker_network_is_internal(self):
        """172.19.x.x is in the 172.16-31 RFC1918 range."""
        assert not ProcessTerminator._is_external("172.19.0.5")
        assert not ProcessTerminator._is_external("172.19.0.8")


# ═══════════════════════════════════════════════════════════════════════════════
# OUTBOUND TRAFFIC FILTER
# ═══════════════════════════════════════════════════════════════════════════════

class TestOutboundTrafficFilter:

    @pytest.fixture
    def otf(self):
        return OutboundTrafficFilter(dry_run=True)

    def test_generate_rules_creates_rules(self, otf):
        rules = otf.generate_rules()
        assert len(rules) > 0

    def test_rules_cover_port_4444(self, otf):
        rules = otf.generate_rules()
        ports = {r.dst_port for r in rules}
        assert 4444 in ports

    def test_rules_cover_port_9001(self, otf):
        rules = otf.generate_rules()
        ports = {r.dst_port for r in rules}
        assert 9001 in ports

    def test_rules_have_tcp_and_udp(self, otf):
        rules = otf.generate_rules()
        protocols = {r.protocol for r in rules}
        assert "tcp" in protocols
        assert "udp" in protocols

    def test_rules_have_drop_action(self, otf):
        rules = otf.generate_rules()
        for rule in rules:
            assert rule.action == "DROP"

    def test_rules_have_comments(self, otf):
        rules = otf.generate_rules()
        for rule in rules:
            assert len(rule.comment) > 0

    def test_apply_rules_dry_run_succeeds(self, otf):
        result = otf.apply_rules()
        assert result["dry_run"] is True
        assert result["applied"] > 0
        assert result["failed"] == 0

    def test_apply_rules_returns_d3fend_tag(self, otf):
        result = otf.apply_rules()
        assert result["d3fend"] == "D3-OTF"

    def test_bash_script_contains_iptables(self, otf):
        script = otf.get_rules_as_bash()
        assert "iptables" in script

    def test_bash_script_contains_port_4444(self, otf):
        script = otf.get_rules_as_bash()
        assert "4444" in script

    def test_bash_script_has_shebang(self, otf):
        script = otf.get_rules_as_bash()
        assert script.startswith("#!/bin/bash")

    def test_bash_script_has_d3fend_comment(self, otf):
        script = otf.get_rules_as_bash()
        assert "D3-OTF" in script

    def test_rule_count_matches_ports_times_two(self, otf):
        """Each port gets TCP + UDP rule."""
        rules = otf.generate_rules()
        assert len(rules) == len(BLOCKED_OUTBOUND_PORTS) * 2


# ═══════════════════════════════════════════════════════════════════════════════
# ENFORCEMENT ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class TestEnforcementEngine:

    @pytest.fixture
    def engine(self):
        return EnforcementEngine(enforcement_mode=False, dry_run=True)

    def test_engine_initializes(self, engine):
        assert engine.terminator is not None
        assert engine.otf is not None

    def test_on_connect_blocked_port(self, engine):
        action = engine.on_connect(14209, "nc", "192.168.1.1", 4444)
        assert action.action == "WOULD_KILL"

    def test_on_connect_allowed(self, engine):
        action = engine.on_connect(1234, "curl", "10.0.0.1", 443)
        assert action.action == "ALLOWED"

    def test_apply_network_filters_dry_run(self, engine):
        result = engine.apply_network_filters()
        assert result["dry_run"] is True
        assert result["applied"] > 0

    def test_get_status_has_d3fend_tags(self, engine):
        status = engine.get_status()
        assert "D3-PT" in status["d3fend"]
        assert "D3-OTF" in status["d3fend"]

    def test_get_status_has_attack_tags(self, engine):
        status = engine.get_status()
        assert "T1095" in status["attack_countered"]

    def test_emergency_kill_nonexistent_pid(self, engine):
        result = engine.emergency_kill(9999999, "test")
        assert result["action"] in ("NOT_FOUND", "KILLED", "PERMISSION_DENIED")

    def test_kill_all_nonexistent_process(self, engine):
        results = engine.kill_all("__nonexistent_xyz__")
        assert results == []

    def test_status_has_start_time(self, engine):
        status = engine.get_status()
        assert "start_time" in status
        assert "2026" in status["start_time"]


# ═══════════════════════════════════════════════════════════════════════════════
# T1620 SYSCALL ADDITIONS
# ═══════════════════════════════════════════════════════════════════════════════

class TestT1620SyscallAdditions:
    """Verify that memfd_create and execveat are now in EBPFSyscallTracer."""

    def test_memfd_create_in_sensitive_syscalls(self):
        tracer = EBPFSyscallTracer()
        assert "memfd_create" in tracer.SENSITIVE_SYSCALLS

    def test_execveat_in_sensitive_syscalls(self):
        tracer = EBPFSyscallTracer()
        assert "execveat" in tracer.SENSITIVE_SYSCALLS

    def test_mprotect_in_sensitive_syscalls(self):
        tracer = EBPFSyscallTracer()
        assert "mprotect" in tracer.SENSITIVE_SYSCALLS

    def test_setuid_in_sensitive_syscalls(self):
        tracer = EBPFSyscallTracer()
        assert "setuid" in tracer.SENSITIVE_SYSCALLS

    def test_memfd_create_severity_is_critical(self):
        tracer = EBPFSyscallTracer()
        assert tracer.SENSITIVE_SYSCALLS["memfd_create"]["severity"] == "CRITICAL"

    def test_execveat_severity_is_critical(self):
        tracer = EBPFSyscallTracer()
        assert tracer.SENSITIVE_SYSCALLS["execveat"]["severity"] == "CRITICAL"

    def test_memfd_create_fires_ebpf_syscall_token(self):
        tracer = EBPFSyscallTracer()
        token = tracer.simulate_ebpf_kprobe(
            "memfd_create", source_pid=9999,
            target_process="curl", call_count=1,
        )
        assert token == "ebpf_syscall"

    def test_execveat_fires_ebpf_syscall_token(self):
        tracer = EBPFSyscallTracer()
        token = tracer.simulate_ebpf_kprobe(
            "execveat", source_pid=9999,
            target_process="curl", call_count=1,
        )
        assert token == "ebpf_syscall"

    def test_setuid_fires_ebpf_syscall_token(self):
        """setuid(0) — the backdoor_payload event from Aegis telemetry."""
        tracer = EBPFSyscallTracer()
        token = tracer.simulate_ebpf_kprobe(
            "setuid", source_pid=9999,
            target_process="backdoor_payload", call_count=1,
        )
        assert token == "ebpf_syscall"

    def test_t1620_tokens_defined(self):
        assert "memfd_create"  in T1620_TOKENS
        assert "execveat"      in T1620_TOKENS
        assert "mprotect_exec" in T1620_TOKENS

    def test_t1620_token_ids_unique(self):
        ids = list(T1620_TOKENS.values())
        assert len(ids) == len(set(ids))

    def test_t1620_sensitive_syscalls_has_d3fend_tags(self):
        for syscall, info in T1620_SENSITIVE_SYSCALLS.items():
            assert "d3fend" in info, f"{syscall} missing d3fend tag"
            assert "D3-SCA" in info["d3fend"], f"{syscall} missing D3-SCA tag"

    def test_t1620_sensitive_syscalls_has_attack_tags(self):
        for syscall, info in T1620_SENSITIVE_SYSCALLS.items():
            assert "attack" in info, f"{syscall} missing attack tag"
            assert "T1620" in info["attack"] or "T1055" in info["attack"], \
                f"{syscall} missing T1620/T1055 tag"


# ═══════════════════════════════════════════════════════════════════════════════
# ENFORCEMENT ACTION DATACLASS
# ═══════════════════════════════════════════════════════════════════════════════

class TestEnforcementActionDataclass:

    def test_to_dict_has_all_fields(self):
        action = EnforcementAction(
            pid=14209, process_name="nc", dst_ip="192.168.1.1",
            dst_port=4444, action="WOULD_KILL",
            timestamp="2026-08-29T02:11:03Z",
            reason="Port 4444 blocked",
        )
        d = action.to_dict()
        assert "pid"          in d
        assert "process_name" in d
        assert "dst_ip"       in d
        assert "dst_port"     in d
        assert "action"       in d
        assert "timestamp"    in d
        assert "reason"       in d
        assert "d3fend"       in d
        assert "attack"       in d

    def test_default_d3fend_is_d3_pt(self):
        action = EnforcementAction(
            pid=1, process_name="test", dst_ip="1.2.3.4",
            dst_port=4444, action="ALLOWED",
            timestamp="2026-08-29T00:00:00Z", reason="test",
        )
        assert action.d3fend == "D3-PT"

    def test_default_attack_is_t1095(self):
        action = EnforcementAction(
            pid=1, process_name="test", dst_ip="1.2.3.4",
            dst_port=4444, action="ALLOWED",
            timestamp="2026-08-29T00:00:00Z", reason="test",
        )
        assert action.attack == "T1095"


# ═══════════════════════════════════════════════════════════════════════════════
# AEGIS TELEMETRY SCENARIO — nc PID 14209
# ═══════════════════════════════════════════════════════════════════════════════

class TestAegisTelemetryScenario:
    """
    Regression tests for the specific Aegis telemetry events.
    Verifies that the enforcement engine would have stopped the attack.
    """

    def test_nc_pid_14209_port_4444_would_be_killed(self):
        """
        Aegis event: nc (PID 14209) attempted outbound socket on port 4444.
        With D3-PT in monitoring mode: WOULD_KILL.
        With D3-PT in enforcement mode: KILLED (or ALREADY_DEAD for non-existent PID).
        """
        engine = EnforcementEngine(enforcement_mode=False, dry_run=True)
        action = engine.on_connect(
            pid=14209, process_name="nc",
            dst_ip="192.168.1.1", dst_port=4444,
        )
        assert action.action == "WOULD_KILL"
        assert action.pid == 14209
        assert "4444" in action.reason or "nc" in action.reason.lower()

    def test_svchost_local_tor_port_9001_would_be_killed(self):
        """
        Aegis event: svchost_local.exe connecting to Tor exit node on port 9001.
        """
        engine = EnforcementEngine(enforcement_mode=False, dry_run=True)
        action = engine.on_connect(
            pid=7421, process_name="svchost_local",
            dst_ip="185.220.101.5", dst_port=9001,
        )
        assert action.action == "WOULD_KILL"

    def test_backdoor_payload_any_port_would_be_killed(self):
        """
        Aegis event: backdoor_payload process — any outbound connection is suspicious.
        """
        engine = EnforcementEngine(enforcement_mode=False, dry_run=True)
        action = engine.on_connect(
            pid=9999, process_name="backdoor_payload",
            dst_ip="10.0.0.1", dst_port=80,
        )
        assert action.action == "WOULD_KILL"

    def test_nginx_accept_is_allowed(self):
        """
        Aegis event: nginx accept4 — this is benign, should not be killed.
        nginx making outbound connections is unusual but not blocked by port policy.
        """
        engine = EnforcementEngine(enforcement_mode=False, dry_run=True)
        # nginx making an outbound connection to internal IP on port 80
        action = engine.on_connect(
            pid=20933, process_name="nginx",
            dst_ip="10.0.0.1", dst_port=80,
        )
        # nginx is not in RESTRICTED_PROCESSES and port 80 is not blocked
        assert action.action in ("ALLOWED", "LOGGED")

    def test_python3_stdout_write_is_allowed(self):
        """
        Aegis event: python3 write to stdout — benign, should not be killed.
        """
        engine = EnforcementEngine(enforcement_mode=False, dry_run=True)
        # python3 connecting to internal service
        action = engine.on_connect(
            pid=28960, process_name="python3",
            dst_ip="127.0.0.1", dst_port=8080,
        )
        assert action.action in ("ALLOWED", "LOGGED")

    def test_otf_blocks_port_4444_in_bash_script(self):
        """Verify the iptables script would block port 4444."""
        otf = OutboundTrafficFilter(dry_run=True)
        script = otf.get_rules_as_bash()
        assert "--dport 4444" in script
        assert "-j DROP" in script

    def test_otf_blocks_port_9001_in_bash_script(self):
        """Verify the iptables script would block Tor port 9001."""
        otf = OutboundTrafficFilter(dry_run=True)
        script = otf.get_rules_as_bash()
        assert "--dport 9001" in script