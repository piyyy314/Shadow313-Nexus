"""Unit tests for the new CLI orchestrators with their I/O collaborators mocked."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from shadow313.modules.defense.defense_module import DefenseModule
from shadow313.modules.docs.docs_module import DocsModule
from shadow313.modules.docs.man_page import generate_man_page, write_man_pages
from shadow313.modules.exploit.exploit_module import ExploitModule
from shadow313.modules.network.network_module import NetworkModule
from shadow313.modules.plugins.plugins_module import PluginManager
from shadow313.modules.quantum.quantum_module import QuantumModule
from shadow313.modules.recon.recon_module import ReconModule
from shadow313.modules.vuln.vuln_module import VulnModule


@pytest.fixture
def kernel(tmp_path):
    session = Mock(id="test-session")
    session.path.side_effect = lambda name: tmp_path / name
    session.write.side_effect = lambda name, data: tmp_path / name
    session.read.return_value = None
    config = Mock()
    config.get.side_effect = lambda section, default=None: (
        {"dir": str(tmp_path / "plugins")} if section == "plugins" else {}
    )
    return SimpleNamespace(
        out=Mock(),
        ai=Mock(chat=Mock(return_value="AI response")),
        session=session,
        config=config,
        register=Mock(),
    )


@pytest.mark.parametrize(
    ("mode", "ports_called", "subdomains_called"),
    [
        ("full", True, True),
        ("active", True, False),
        ("passive", False, True),
    ],
)
def test_recon_modes_and_downstream_summary(
    kernel, monkeypatch, mode, ports_called, subdomains_called
):
    root = "shadow313.modules.recon.recon_module."
    monkeypatch.setattr(root + "WHOISLookup", Mock(return_value=Mock(lookup=Mock(return_value={}))))
    monkeypatch.setattr(
        root + "DNSEnumerator", Mock(return_value=Mock(resolve=Mock(return_value={})))
    )
    subdomains = Mock(return_value=[f"sub{i}.invalid" for i in range(25)])
    monkeypatch.setattr(root + "SubdomainDiscoverer", Mock(return_value=Mock(scan=subdomains)))
    ports = Mock(return_value=[{"port": 22, "state": "open", "banner": "ssh"}])
    monkeypatch.setattr(root + "AsyncPortScanner.scan", ports)
    result = ReconModule(kernel).run("example.invalid", mode=mode, ports="22")
    assert result["host"] == "example.invalid"
    assert ports.called is ports_called
    assert subdomains.called is subdomains_called
    kernel.session.set_target.assert_called_once_with("example.invalid")
    writes = {call.args[0]: call.args[1] for call in kernel.session.write.call_args_list}
    assert writes["recon.json"] == result
    assert writes["target.json"]["host"] == "example.invalid"
    assert len(writes["target.json"]["subdomains"]) == (20 if subdomains_called else 0)


def test_defense_level2_compliance_and_ansible_remediation(kernel, tmp_path, monkeypatch):
    root = "shadow313.modules.defense.defense_module."
    monkeypatch.setattr(
        root + "SystemInfo", Mock(return_value=Mock(collect=Mock(return_value={"os": "test"})))
    )
    findings = [
        {"check": "SSH Configuration", "status": "FAIL"},
        {"check": "ASLR", "status": "PASS"},
        {"check": "Firewall Status", "status": "WARN"},
    ]
    checker = Mock(return_value=Mock(run_all=Mock(return_value=findings)))
    monkeypatch.setattr(root + "CISBenchmarkChecker", checker)
    result = DefenseModule(kernel).run(
        audit=True, profile="cis-level2", generate_remediation="ansible"
    )
    checker.assert_called_once_with(level=2)
    assert result["compliance_score"] == 33.3
    assert result["findings"] == findings
    assert (tmp_path / "remediation.yml").exists()
    assert "PermitRootLogin no" in (tmp_path / "remediation.yml").read_text()
    kernel.session.write.assert_called_once_with("compliance.json", result)


def test_defense_empty_audit_has_zero_score_without_remediation(kernel, monkeypatch):
    root = "shadow313.modules.defense.defense_module."
    monkeypatch.setattr(root + "SystemInfo", Mock(return_value=Mock(collect=Mock(return_value={}))))
    monkeypatch.setattr(
        root + "CISBenchmarkChecker", Mock(return_value=Mock(run_all=Mock(return_value=[])))
    )
    result = DefenseModule(kernel).run(audit=True)
    assert result["compliance_score"] == 0
    assert "remediation_script" not in result


@pytest.mark.parametrize(
    ("lab_mode", "confirmation", "authorized", "error"),
    [
        (False, "", True, "lab_mode_required"),
        (True, "", False, "target_not_in_scope"),
        (False, "AUTHORIZED", False, "target_not_in_scope"),
    ],
)
def test_exploit_gates_return_before_ai_or_persistence(
    kernel, lab_mode, confirmation, authorized, error
):
    module = ExploitModule(kernel)
    module.scope = Mock(is_target_authorized=Mock(return_value=authorized))
    result = module.run(
        target="example.invalid", lab_mode=lab_mode, confirm_scope=confirmation, cve="CVE-TEST"
    )
    assert result["error"] == error
    kernel.ai.chat.assert_not_called()
    kernel.session.write.assert_not_called()


def test_exploit_advisory_has_watermark_and_conversions(kernel):
    module = ExploitModule(kernel)
    module.scope = Mock(is_target_authorized=Mock(return_value=True))
    result = module.run(
        lab_mode=True,
        target="example.invalid",
        decode="6869",
        ops="hex_decode, reverse",
        payload="reverse_shell_bash",
        assist="post",
        platform="unsupported",
    )
    assert result["mode"] == "advisory"
    assert result["decode"]["hex_decode"] == "hi"
    assert "test-session" in result["payload_template"]
    assert "ADVISORY ONLY" in result["payload_template"]
    assert "privesc_checks" in result["post_exploit_checklist"]
    kernel.session.write.assert_called_once_with("exploit_guide.json", result)


def test_network_permission_denied_stops_before_parsing_or_persistence(kernel, monkeypatch):
    module = NetworkModule(kernel)
    capture = Mock(side_effect=PermissionError("requires root"))
    parser = Mock()
    monkeypatch.setattr(module, "_live_capture", capture)
    monkeypatch.setattr("shadow313.modules.network.network_module.PCAPParser", parser)
    result = module.run(interface="eth-test", duration=2, capture_filter="tcp")
    capture.assert_called_once_with("eth-test", 2, "tcp")
    assert "flows" not in result
    parser.assert_not_called()
    kernel.session.write.assert_not_called()


def test_network_analysis_saves_flows_and_alerts(kernel, monkeypatch):
    packet = {
        "src_ip": "10.0.0.1",
        "dst_ip": "192.168.1.1",
        "sport": 1234,
        "dport": 4444,
        "length": 100,
        "protocol": "TCP",
        "ts": 1,
    }
    parser = Mock(
        parse=Mock(return_value=[packet]),
        extract_dns_queries=Mock(return_value=[]),
        extract_http_hosts=Mock(return_value=[]),
    )
    monkeypatch.setattr(
        "shadow313.modules.network.network_module.PCAPParser", Mock(return_value=parser)
    )
    result = NetworkModule(kernel).run(analyze="synthetic.pcap", ai_score=True)
    assert result["packet_count"] == 1
    assert result["flow_count"] == 1
    assert result["flows"][0]["bytes"] == 100
    assert result["alerts"][0]["type"] == "SUSPICIOUS_PORT"
    assert result["ai_analysis"] == "AI response"
    writes = {call.args[0]: call.args[1] for call in kernel.session.write.call_args_list}
    assert writes["flows.json"] == result["flows"]
    assert writes["alerts.json"] == result["alerts"]


def test_quantum_code_scan_builds_mapping_timeline_and_reference_report(kernel, tmp_path):
    path = tmp_path / "crypto.py"
    path.write_text("RSA.generate(2048)\nRSA.generate(4096)\n")
    result = QuantumModule(kernel).run(scan_code=str(path), report=True)
    assert len(result["findings"]) == 2
    assert result["threat_timeline"]["risk_level"] == "CRITICAL"
    assert len(result["pqc_mapping"]) == 1
    assert result["pqc_mapping"][0]["priority"] == "IMMEDIATE"
    assert result["pqc_mapping"][0]["fips"] == "FIPS 203"
    assert "nist_pqc_standards" in result
    kernel.session.write.assert_called_once_with("quantum_report.json", result)


def test_vuln_quick_mode_skips_exploits_and_orders_risk_matrix(kernel, monkeypatch):
    database = Mock()
    database.search_by_keyword.return_value = [
        {"cve": "CVE-TEST-LOW", "cvss_v3": 2.0, "severity": "LOW"},
        {"cve": "CVE-TEST-HIGH", "cvss_v3": 9.8, "severity": "CRITICAL"},
    ]
    monkeypatch.setattr(
        "shadow313.modules.vuln.vuln_module.CVEDatabase", Mock(return_value=database)
    )
    module = VulnModule(kernel)
    module.checker = Mock()
    result = module.run(target="widget", quick=True)
    module.checker.check.assert_not_called()
    assert [f["risk_score"] for f in result["risk_matrix"]] == [9.8, 2.0]
    assert all(f["has_poc"] is False for f in result["risk_matrix"])


def test_vuln_service_mapping_deduplicates_cves_and_adds_contextual_risk(kernel, monkeypatch):
    database = Mock()
    database.search_by_keyword.side_effect = lambda *args, **kwargs: [
        {"cve": "CVE-TEST-1", "cvss_v3": 5.0, "severity": "MEDIUM"},
    ]
    monkeypatch.setattr(
        "shadow313.modules.vuln.vuln_module.CVEDatabase", Mock(return_value=database)
    )
    kernel.session.read.return_value = {
        "ports": [
            {"port": 22, "banner": "OpenSSH test"},
            {"port": 2222, "banner": "OpenSSH test"},
        ]
    }
    module = VulnModule(kernel)
    module.checker = Mock(check=Mock(return_value={"poc_count": 1}))
    result = module.run(internet_facing=True)
    assert len(result["findings"]) == 1
    assert result["findings"][0]["port"] == 22
    assert result["risk_matrix"][0]["risk_score"] == 7.2
    assert result["risk_matrix"][0]["has_poc"] is True
    module.checker.check.assert_called_once_with("CVE-TEST-1")


def test_plugin_manager_scaffold_install_enable_disable_remove(kernel):
    manager = PluginManager(kernel)
    scaffold = manager.run(new="sample")["scaffold_path"]
    # Install into a second manager's directory to keep source and destination separate.
    kernel.config.get.side_effect = None
    kernel.config.get.return_value = {"dir": scaffold + "-installed"}
    installed = PluginManager(kernel)
    assert installed.run(install=scaffold)["installed"] == scaffold
    installed.run(enable="sample")
    assert installed.ai_context() == {"module": "plugins", "installed_count": 1, "enabled_count": 1}
    installed.run(disable="sample")
    assert installed.ai_context()["enabled_count"] == 0
    installed.run(remove="sample")
    assert installed.run(list_plugins=True)["plugins"] == []


@pytest.mark.parametrize("stream", [True, False])
def test_docs_ask_streaming_and_chat_preserve_answers(kernel, stream, capsys):
    kernel.ai.stream.return_value = iter(["hello ", "world"])
    kernel.ai.chat.return_value = "hello world"
    result = DocsModule(kernel).ask("question", stream=stream)
    assert result == {"question": "question", "answer": "hello world"}
    if stream:
        assert "hello world" in capsys.readouterr().out
        kernel.ai.chat.assert_not_called()
    else:
        kernel.ai.stream.assert_not_called()


def test_docs_empty_unknown_topic_and_tutorial_step_are_safe(kernel, capsys):
    docs = DocsModule(kernel)
    assert docs.ask() == {}
    kernel.ai.chat.assert_not_called()
    assert docs.show_docs(topic="missing") == {}
    assert docs.learn(module="missing") == {}
    assert docs.learn(module="RECON", step=2) == {}
    printed = capsys.readouterr().out
    assert "A, AAAA, MX, NS, TXT, CNAME, and SOA" in printed
    assert "Start with a domain" not in printed


def test_man_pages_render_flags_limit_examples_and_write_files(tmp_path):
    doc = {
        "title": "Test Module",
        "description": "Description",
        "flags": {"--flag": "Flag help"},
        "commands": [(f"shadow313 test {i}", f"Example {i}") for i in range(7)],
    }
    text = generate_man_page("test", doc)
    assert '.TH "SHADOW313-TEST"' in text
    assert ".B --flag\nFlag help" in text
    assert "Example 4" in text
    assert "Example 5" not in text
    files = write_man_pages({"test": doc}, str(tmp_path))
    assert files == [str(tmp_path / "man/shadow313-test.1")]
    assert (tmp_path / "man/shadow313-test.1").read_text() == text
