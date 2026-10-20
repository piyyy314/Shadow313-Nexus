"""Tests for SatExpert313 integration modules - 16 tests."""
import pytest, math

class TestLinkBudgetCalculator:
    def setup_method(self):
        from shadow313.integrations.satexpert.link_budget import LinkBudgetCalculator
        self.calc = LinkBudgetCalculator()
    def test_nominal_link(self):
        r = self.calc.calculate(11.7, 38000, 5.0, 1.2)
        assert r.fspl_db > 200 and r.status in ("NOMINAL","DEGRADED","CRITICAL")
    def test_fspl_increases_with_distance(self):
        r1 = self.calc.calculate(11.7, 36000, 5.0, 1.2)
        r2 = self.calc.calculate(11.7, 40000, 5.0, 1.2)
        assert r2.fspl_db > r1.fspl_db
    def test_result_fields_present(self):
        r = self.calc.calculate(14.25, 39401, 5.0, 1.2)
        for attr in ["fspl_db","eb_no_db","g_t_db","ber","snr_db","link_margin_db"]:
            assert hasattr(r, attr)
    def test_ber_valid_probability(self):
        r = self.calc.calculate(11.7, 38000, 5.0, 1.2)
        assert 0.0 <= r.ber <= 1.0
    def test_advisory_present(self):
        r = self.calc.calculate(11.7, 38000, 5.0, 1.2)
        assert r.advisory and len(r.advisory) > 5

class TestSpoofTracer:
    def setup_method(self):
        from shadow313.integrations.satexpert.spoof_tracer import SpoofTracer
        self.tracer = SpoofTracer()
    def test_authentic_signal(self):
        r = self.tracer.analyze_nmea(hdop=2.5,pdop=3.1,vdop=2.0,satellites=12,speed_knots=0.5,fix_quality=1)
        assert r.verdict in ("AUTHENTIC","SUSPICIOUS","SPOOFED") and 0.0 <= r.confidence <= 1.0
    def test_spoofed_signal_future_date(self):
        from datetime import date, timedelta
        future = date.today() + timedelta(days=365)
        nmea_date = f"{future.day:02d}{future.month:02d}{str(future.year)[2:]}"
        r = self.tracer.analyze_nmea(hdop=1.1,pdop=2.1,vdop=1.8,satellites=7,speed_knots=0.024,fix_quality=1,date_str=nmea_date)
        assert r.temporal_anomaly is True and r.confidence > 0.3
    def test_clean_dop_flagged(self):
        r = self.tracer.analyze_nmea(hdop=1.1,pdop=2.109,vdop=1.8,satellites=7,speed_knots=0.0,fix_quality=1)
        assert r.dop_anomaly is True
    def test_low_satellite_count_flagged(self):
        r = self.tracer.analyze_nmea(hdop=2.0,pdop=3.0,vdop=2.2,satellites=5,speed_knots=0.1,fix_quality=1)
        assert r.constellation_anomaly is True
    def test_indicators_list(self):
        r = self.tracer.analyze_nmea(hdop=1.0,pdop=2.0,vdop=1.7,satellites=6,speed_knots=0.0,fix_quality=1)
        assert isinstance(r.indicators, list)

class TestYARAScanner:
    def setup_method(self):
        from shadow313.integrations.satexpert.yara_scanner import YARAScanner
        self.scanner = YARAScanner()
    def test_clean_firmware(self):
        r = self.scanner.scan_bytes(b"\x7fELF" + b"\x00"*100 + b"normal_firmware")
        assert r.clean is True and r.risk_score == 0
    def test_telnet_detection(self):
        r = self.scanner.scan_bytes(b"\x7fELF" + b"\x00"*50 + b"telnetd" + b"\x00"*50)
        assert not r.clean and "TELNET_DAEMON" in [m.rule_name for m in r.matches]
    def test_cwmp_detection(self):
        r = self.scanner.scan_bytes(b"\x7fELF" + b"\x00"*50 + b"cwmp_handler" + b"\x00"*50)
        assert not r.clean and "UNSIGNED_CWMP_HANDLER" in [m.rule_name for m in r.matches]
    def test_sha256_computed(self):
        import hashlib; data = b"test_firmware"
        r = self.scanner.scan_bytes(data)
        assert r.sha256 == hashlib.sha256(data).hexdigest()
    def test_risk_score_bounded(self):
        r = self.scanner.scan_bytes(b"telnetd cwmp backdoor " * 10)
        assert 0 <= r.risk_score <= 100
    def test_match_fields(self):
        r = self.scanner.scan_bytes(b"telnetd" + b"\x00"*20)
        if r.matches:
            m = r.matches[0]
            assert hasattr(m,"rule_name") and hasattr(m,"severity") and hasattr(m,"offset")
