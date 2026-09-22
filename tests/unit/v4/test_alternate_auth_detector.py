"""
Tests for shadow313.v4.detection.alternate_auth_detector — T1550/T1558
"""
from __future__ import annotations
import pytest
from shadow313.v4.detection.alternate_auth_detector import (
    AlternateAuthDetector, AlternateAuthAlert,
    PTH_TOOL_PATTERNS, PTT_TOOL_PATTERNS, KERBEROASTING_PATTERNS,
    NTLM_HASH_RE, NTLM_PAIR_RE,
)


@pytest.fixture
def detector():
    return AlternateAuthDetector()


class TestAlternateAuthDetectorBasics:

    def test_instantiates(self, detector):
        assert detector is not None

    def test_clean_command_no_alert(self, detector):
        alert = detector.analyze_command("net user administrator")
        assert alert is None

    def test_clean_event_no_alert(self, detector):
        alert = detector.analyze_event({
            "event_id": 4624,
            "username": "user",
            "source_ip": "10.0.0.1",
            "logon_type": 2,  # Interactive — normal
        })
        assert alert is None

    def test_get_stats_empty(self, detector):
        stats = detector.get_stats()
        assert stats["total_alerts"] == 0

    def test_clear(self, detector):
        detector.analyze_command("sekurlsa::pth /user:admin /domain:corp /ntlm:aabbccdd1122334455667788aabbccdd /run:cmd.exe")
        detector.clear()
        assert len(detector.get_alerts()) == 0


class TestPassTheHashDetection:

    def test_mimikatz_sekurlsa_pth(self, detector):
        alert = detector.analyze_command(
            "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:aabbccdd1122334455667788aabbccdd /run:cmd.exe",
            source_ip="10.0.0.1",
            username="attacker",
        )
        assert alert is not None
        assert alert.technique == "T1550.002"
        assert alert.attack_type == "pth"

    def test_impacket_psexec_hashes(self, detector):
        alert = detector.analyze_command(
            "psexec.py -hashes aabbccdd1122334455667788aabbccdd:aabbccdd1122334455667788aabbccdd corp.local/admin@10.0.0.1",
            source_ip="10.0.0.2",
        )
        assert alert is not None
        assert alert.technique == "T1550.002"

    def test_crackmapexec_hash(self, detector):
        alert = detector.analyze_command(
            "crackmapexec smb 10.0.0.0/24 -u admin -H aabbccdd1122334455667788aabbccdd",
            source_ip="10.0.0.1",
        )
        assert alert is not None
        assert alert.attack_type == "pth"

    def test_ntlm_hash_pair_in_command(self, detector):
        alert = detector.analyze_command(
            "wmiexec.py aabbccdd1122334455667788aabbccdd:aabbccdd1122334455667788aabbccdd@10.0.0.1",
            source_ip="10.0.0.1",
        )
        assert alert is not None
        assert alert.attack_type == "pth"

    def test_pth_alert_is_critical_or_high(self, detector):
        alert = detector.analyze_command(
            "sekurlsa::pth /user:admin /domain:corp /ntlm:aabbccdd1122334455667788aabbccdd /run:cmd.exe"
        )
        assert alert.severity in ("CRITICAL", "HIGH")

    def test_pth_recommendations_not_empty(self, detector):
        alert = detector.analyze_command(
            "psexec.py -hashes aabbccdd:aabbccdd1122334455667788aabbccdd corp/admin@10.0.0.1"
        )
        assert len(alert.recommendations) > 0

    def test_event_4624_logon_type_9(self, detector):
        alert = detector.analyze_event({
            "event_id": 4624,
            "username": "administrator",
            "source_ip": "10.0.0.50",
            "logon_type": 9,  # NewCredentials — PtH indicator
        })
        assert alert is not None
        assert alert.technique == "T1550.002"
        assert alert.attack_type == "pth"

    def test_event_4624_logon_type_9_localhost_no_alert(self, detector):
        alert = detector.analyze_event({
            "event_id": 4624,
            "username": "user",
            "source_ip": "127.0.0.1",
            "logon_type": 9,
        })
        assert alert is None


class TestPassTheTicketDetection:

    def test_mimikatz_kerberos_ptt(self, detector):
        alert = detector.analyze_command(
            "kerberos::ptt ticket.kirbi",
            source_ip="10.0.0.1",
        )
        assert alert is not None
        assert alert.technique == "T1550.003"
        assert alert.attack_type == "ptt"

    def test_rubeus_ptt(self, detector):
        alert = detector.analyze_command(
            "rubeus.exe ptt /ticket:doIFuj...",
            source_ip="10.0.0.1",
        )
        assert alert is not None
        assert alert.technique == "T1550.003"

    def test_rubeus_asktgt(self, detector):
        alert = detector.analyze_command(
            "rubeus.exe asktgt /user:admin /password:Password1 /domain:corp.local",
            source_ip="10.0.0.1",
        )
        assert alert is not None

    def test_kirbi_file_pattern(self, detector):
        alert = detector.analyze_command(
            "kerberos::ptt C:\\Users\\user\\Desktop\\admin.kirbi"
        )
        assert alert is not None
        assert alert.attack_type == "ptt"

    def test_ptt_alert_is_critical(self, detector):
        alert = detector.analyze_command("kerberos::ptt ticket.kirbi")
        assert alert.severity in ("CRITICAL", "HIGH")

    def test_ptt_recommendations_mention_krbtgt(self, detector):
        alert = detector.analyze_command("kerberos::ptt ticket.kirbi")
        recs = " ".join(alert.recommendations).lower()
        assert "kerberos" in recs or "ticket" in recs or "krbtgt" in recs


class TestKerberoastingDetection:

    def test_rubeus_kerberoast(self, detector):
        alert = detector.analyze_command(
            "rubeus.exe kerberoast /outfile:hashes.txt",
            source_ip="10.0.0.1",
            username="user",
        )
        assert alert is not None
        assert alert.technique == "T1558.003"
        assert alert.attack_type == "kerberoasting"

    def test_impacket_getuserspns(self, detector):
        alert = detector.analyze_command(
            "python3 GetUserSPNs.py corp.local/user:Password1 -outputfile hashes.txt",
            source_ip="10.0.0.1",
        )
        assert alert is not None
        assert alert.attack_type == "kerberoasting"

    def test_invoke_kerberoast(self, detector):
        alert = detector.analyze_command(
            "Invoke-Kerberoast -OutputFormat Hashcat | Out-File hashes.txt",
            source_ip="10.0.0.1",
        )
        assert alert is not None

    def test_event_4769_rc4_single_no_alert(self, detector):
        """Single RC4 SPN request should not alert."""
        alert = detector.analyze_event({
            "event_id": 4769,
            "username": "user",
            "source_ip": "10.0.0.1",
            "ticket_encryption": 0x17,  # RC4
        })
        assert alert is None  # Only 1 request — not enough

    def test_event_4769_rc4_multiple_alerts(self, detector):
        """Multiple RC4 SPN requests = Kerberoasting."""
        for _ in range(5):
            detector.analyze_event({
                "event_id": 4769,
                "username": "attacker",
                "source_ip": "10.0.0.1",
                "ticket_encryption": 0x17,
            })
        alerts = [a for a in detector.get_alerts() if a.attack_type == "kerberoasting"]
        assert len(alerts) >= 1

    def test_event_4769_aes_no_alert(self, detector):
        """AES-encrypted SPN requests are not Kerberoastable."""
        alert = detector.analyze_event({
            "event_id": 4769,
            "username": "user",
            "source_ip": "10.0.0.1",
            "ticket_encryption": 0x12,  # AES256
        })
        assert alert is None

    def test_kerberoasting_recommendations_mention_spn(self, detector):
        alert = detector.analyze_command("rubeus.exe kerberoast /outfile:hashes.txt")
        recs = " ".join(alert.recommendations).lower()
        assert "spn" in recs or "service account" in recs or "kerberos" in recs


class TestGoldenTicketDetection:

    def test_mimikatz_golden(self, detector):
        alert = detector.analyze_command(
            "kerberos::golden /user:administrator /domain:corp.local /sid:S-1-5-21-1234567890 /krbtgt:aabbccdd1122334455667788aabbccdd /id:500",
            source_ip="10.0.0.1",
        )
        assert alert is not None
        assert alert.technique == "T1558.001"
        assert alert.attack_type == "golden_ticket"

    def test_mimikatz_silver(self, detector):
        alert = detector.analyze_command(
            "kerberos::silver /user:administrator /domain:corp.local /sid:S-1-5-21-1234567890 /target:dc01.corp.local /service:cifs /rc4:aabbccdd1122334455667788aabbccdd",
            source_ip="10.0.0.1",
        )
        assert alert is not None

    def test_impacket_ticketer(self, detector):
        alert = detector.analyze_command(
            "python3 ticketer.py -nthash aabbccdd1122334455667788aabbccdd -domain-sid S-1-5-21-1234567890 -domain corp.local administrator",
            source_ip="10.0.0.1",
        )
        assert alert is not None
        assert alert.attack_type == "golden_ticket"

    def test_golden_ticket_is_critical(self, detector):
        alert = detector.analyze_command(
            "kerberos::golden /user:admin /domain:corp.local /sid:S-1-5-21-1234567890 /krbtgt:aabbccdd1122334455667788aabbccdd"
        )
        assert alert.severity == "CRITICAL"

    def test_golden_ticket_recommendations_mention_krbtgt(self, detector):
        alert = detector.analyze_command(
            "kerberos::golden /user:admin /domain:corp.local /sid:S-1-5-21-1234567890 /krbtgt:aabbccdd1122334455667788aabbccdd"
        )
        recs = " ".join(alert.recommendations).upper()
        assert "KRBTGT" in recs or "DOMAIN" in recs


class TestCookieTheftDetection:

    def test_chrome_cookie_access(self, detector):
        alert = detector.analyze_command(
            "copy C:\\Users\\user\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies C:\\temp\\cookies.db",
            source_ip="10.0.0.1",
        )
        assert alert is not None
        assert alert.technique == "T1550.004"
        assert alert.attack_type == "cookie_theft"

    def test_evilginx_pattern(self, detector):
        alert = detector.analyze_command(
            "evilginx2 -p /etc/evilginx/phishlets",
            source_ip="10.0.0.1",
        )
        assert alert is not None
        assert alert.attack_type == "cookie_theft"


class TestAlertProperties:

    def test_alert_to_dict(self, detector):
        alert = detector.analyze_command(
            "sekurlsa::pth /user:admin /domain:corp /ntlm:aabbccdd1122334455667788aabbccdd /run:cmd.exe"
        )
        d = alert.to_dict()
        assert isinstance(d, dict)
        assert "technique" in d
        assert "attack_type" in d
        assert "risk_score" in d

    def test_risk_score_bounded(self, detector):
        alert = detector.analyze_command(
            "kerberos::golden /user:admin /domain:corp.local /sid:S-1-5-21-1234567890 /krbtgt:aabbccdd1122334455667788aabbccdd"
        )
        assert 0.0 <= alert.risk_score <= 1.0

    def test_get_stats_after_detections(self, detector):
        detector.analyze_command("sekurlsa::pth /user:admin /domain:corp /ntlm:aabbccdd1122334455667788aabbccdd /run:cmd.exe")
        detector.analyze_command("kerberos::ptt ticket.kirbi")
        detector.analyze_command("rubeus.exe kerberoast /outfile:hashes.txt")
        stats = detector.get_stats()
        assert stats["total_alerts"] == 3
        assert "pth" in stats["by_type"]
        assert "ptt" in stats["by_type"]
        assert "kerberoasting" in stats["by_type"]

    def test_ntlm_hash_regex(self):
        assert NTLM_HASH_RE.search("aabbccdd1122334455667788aabbccdd")
        assert not NTLM_HASH_RE.search("short")

    def test_ntlm_pair_regex(self):
        assert NTLM_PAIR_RE.search("aabbccdd1122334455667788aabbccdd:aabbccdd1122334455667788aabbccdd")
        assert not NTLM_PAIR_RE.search("aabbccdd1122334455667788aabbccdd")