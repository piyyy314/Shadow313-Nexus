"""Isolated hardening checks and remediation generation introduced in PR #86."""

import os
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import yaml

from shadow313.modules.defense.cis_checker import CISBenchmarkChecker
from shadow313.modules.defense.firewall import FirewallAnalyzer
from shadow313.modules.defense.remediation import FileEncryptionRateMonitor, RemediationGenerator
from shadow313.modules.defense.system_info import SystemInfo, _run


@pytest.mark.parametrize(
    ("error", "code", "message"),
    [
        (FileNotFoundError(), 127, "Command not found: tool"),
        (subprocess.TimeoutExpired("tool", 1), 1, "Timeout"),
        (PermissionError("denied"), 1, "denied"),
    ],
)
def test_system_command_failure_contract(monkeypatch, error, code, message):
    monkeypatch.setattr(
        "shadow313.modules.defense.system_info.subprocess.run", Mock(side_effect=error)
    )
    assert _run(["tool"], timeout=1) == ("", message, code)


def test_system_command_preserves_output_and_exit_code(monkeypatch):
    run = Mock(return_value=SimpleNamespace(stdout="out", stderr="err", returncode=3))
    monkeypatch.setattr("shadow313.modules.defense.system_info.subprocess.run", run)
    assert _run(["tool", "arg"], timeout=2) == ("out", "err", 3)
    assert run.call_args.kwargs == {
        "capture_output": True,
        "text": True,
        "timeout": 2,
        "errors": "replace",
        "check": False,
    }


def test_system_info_user_parsing_skips_bad_rows_and_marks_service_accounts(monkeypatch):
    accounts = "alice:x:1000:1000::/home/alice:/bin/bash\nservice:x:bad:1::/:/sbin/nologin\nbad\n"
    monkeypatch.setattr(
        "shadow313.modules.defense.system_info._run", Mock(return_value=(accounts, "", 0))
    )
    assert SystemInfo()._users() == [
        {
            "username": "alice",
            "uid": 1000,
            "shell": "/bin/bash",
            "home": "/home/alice",
            "has_login": True,
        },
        {
            "username": "service",
            "uid": -1,
            "shell": "/sbin/nologin",
            "home": "/",
            "has_login": False,
        },
    ]


@pytest.fixture
def system_files(tmp_path, monkeypatch):
    """Redirect only the checker's absolute filesystem paths into a fixture root."""

    def resolve(path):
        return tmp_path / str(path).lstrip("/")

    monkeypatch.setattr("shadow313.modules.defense.cis_checker.Path", resolve)

    def write(path, content):
        destination = resolve(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content)
        return destination

    return write


@pytest.mark.parametrize(
    ("text", "status", "severity", "issues"),
    [
        (
            "PermitRootLogin no\nPasswordAuthentication no\nX11Forwarding no\nMaxAuthTries 3\n",
            "PASS",
            "INFO",
            0,
        ),
        ("# PermitRootLogin no\nPasswordAuthentication no\nMaxAuthTries 3\n", "FAIL", "MEDIUM", 1),
        ("PermitRootLogin yes\nPasswordAuthentication yes\nX11Forwarding yes\n", "FAIL", "HIGH", 4),
    ],
)
def test_ssh_configuration_ignores_comments_and_grades_issues(
    system_files, text, status, severity, issues
):
    system_files("/etc/ssh/sshd_config", text)
    result = CISBenchmarkChecker().check_ssh_config()
    assert result["status"] == status
    assert result["severity"] == severity
    assert len(result["issues"]) == issues


def test_missing_ssh_and_yama_are_skipped(system_files):
    checker = CISBenchmarkChecker()
    assert checker.check_ssh_config()["status"] == "SKIP"
    assert checker.check_yama_ptrace()["status"] == "SKIP"


@pytest.mark.parametrize(
    ("value", "status", "severity"),
    [
        ("0", "FAIL", "HIGH"),
        ("1", "FAIL", "MEDIUM"),
        ("2", "PASS", "INFO"),
    ],
)
def test_aslr_requires_full_randomization(system_files, value, status, severity):
    system_files("/proc/sys/kernel/randomize_va_space", value)
    result = CISBenchmarkChecker().check_randomize_va()
    assert (result["status"], result["severity"]) == (status, severity)


@pytest.mark.parametrize(
    ("path", "status"),
    [
        ("/usr/bin:/bin", "PASS"),
        (".:/usr/bin", "FAIL"),
        ("/usr/bin:", "FAIL"),
        ("../:/bin", "PASS"),
        ("..:/bin", "FAIL"),
    ],
)
def test_root_path_detects_empty_and_relative_entries(monkeypatch, path, status):
    monkeypatch.setenv("PATH", path)
    assert CISBenchmarkChecker().check_root_path()["status"] == status


def test_cis_level_selection_and_exception_isolation(monkeypatch):
    checker = CISBenchmarkChecker(level=2)
    checks = [name for name in dir(checker) if name.startswith("check_")]
    for name in checks:
        monkeypatch.setattr(checker, name, Mock(return_value={"check": name, "status": "PASS"}))
    broken = Mock(side_effect=PermissionError("denied"))
    broken.__name__ = "check_ssh_config"
    monkeypatch.setattr(checker, "check_ssh_config", broken)
    results = checker.run_all()
    assert len(results) == 18
    assert results[0] == {
        "check": "check_ssh_config",
        "status": "ERROR",
        "detail": "denied",
        "severity": "INFO",
    }
    checker.check_auditd.assert_called_once()
    checker.level = 1
    assert len(checker.run_all()) == 14
    assert checker.check_auditd.call_count == 1


def test_firewall_auto_falls_back_and_reports_inactive_ufw(monkeypatch):
    run = Mock(side_effect=[("", "missing", 127), ("ACCEPT 0.0.0.0/0", "", 0)])
    monkeypatch.setattr("shadow313.modules.defense.firewall._run", run)
    result = FirewallAnalyzer().analyse()
    assert result["tool"] == "iptables"
    assert result["issues"] == ["Permissive ACCEPT rules for 0.0.0.0/0 detected"]
    assert run.call_count == 2
    run.side_effect = None
    run.return_value = ("Status: inactive", "", 0)
    assert FirewallAnalyzer().analyse("ufw")["issues"] == ["UFW is INACTIVE"]
    assert "error" in FirewallAnalyzer().analyse("unknown")


def test_remediation_only_generates_fixes_for_failed_or_warned_supported_checks():
    findings = [
        {"check": "SSH Configuration", "status": "PASS"},
        {"check": "ASLR (randomize_va_space)", "status": "FAIL"},
        {"check": "Firewall Status", "status": "WARN"},
        {"check": "Unknown check", "status": "FAIL"},
    ]
    generator = RemediationGenerator()
    script = generator.bash_script(findings)
    assert script.startswith("#!/usr/bin/env bash")
    assert "set -euo pipefail" in script
    assert "randomize_va_space = 2" in script
    assert "ufw enable" in script
    assert "systemctl restart sshd" not in script
    play = yaml.safe_load(generator.ansible_playbook(findings))[0]
    assert play["become"] is True
    assert len(play["tasks"]) == 2
    assert play["tasks"][0]["sysctl"] == {"name": "kernel.randomize_va_space", "value": "2"}


def test_encryption_scan_filters_old_files_and_current_rate_expires(tmp_path, monkeypatch):
    recent, old = tmp_path / "recent", tmp_path / "old"
    recent.touch()
    old.touch()
    os.utime(recent, (99, 99))
    os.utime(old, (90, 90))
    monkeypatch.setattr("shadow313.modules.defense.remediation._time.time", Mock(return_value=100))
    monitor = FileEncryptionRateMonitor(
        [str(tmp_path), str(tmp_path / "absent")], window_s=10, poll_interval_s=2
    )
    assert monitor._scan() == [(100, str(recent))]
    monitor._events = [(89, "expired"), (90, "boundary"), (100, "recent")]
    assert monitor.current_rate() == pytest.approx(0.2)


def test_encryption_monitor_loop_prunes_and_alerts_at_threshold(monkeypatch):
    alert = Mock()
    monitor = FileEncryptionRateMonitor(
        ["/unused"], threshold_per_s=0.2, window_s=10, alert_callback=alert
    )
    monitor._events = [(89, "expired"), (90, "boundary")]
    monitor._running = True
    monkeypatch.setattr(monitor, "_scan", Mock(return_value=[(100, "new")]))
    monkeypatch.setattr("shadow313.modules.defense.remediation._time.time", Mock(return_value=100))
    monkeypatch.setattr(
        "shadow313.modules.defense.remediation._time.sleep",
        lambda interval: setattr(monitor, "_running", False),
    )
    monitor._monitor_loop()
    alert.assert_called_once_with(0.2, "new")
    assert monitor.current_rate() == pytest.approx(0.2)
