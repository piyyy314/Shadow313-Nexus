"""Regression tests for risk scoring, monitors, firmware, JA3, SQL guards and plugins."""

from __future__ import annotations

import sys
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


# ── P-19: Composite Z-Score ───────────────────────────────────────────────────
class TestCompositeRisk:
    """Preserve EPSSKEVScorer's documented multiplicative risk contract."""

    @pytest.mark.parametrize(
        "epss,cvss,kev,expected,tier",
        [
            (1.0, 10.0, True, 1.0, "CRITICAL"),
            (0.5, 8.0, False, 0.4, "HIGH"),
            (0.5, 8.0, True, 1.0, "CRITICAL"),
            (0.2, 5.0, False, 0.1, "MEDIUM"),
            (0.01, 5.0, False, 0.005, "LOW"),
            (0.8, 0.0, False, 0.8, "CRITICAL"),
        ],
    )
    def test_risk_formula(self, tmp_path, epss, cvss, kev, expected, tier):
        from shadow313.v2.vuln_upgrades.epss_kev import EPSSKEVScorer

        scorer = EPSSKEVScorer(cache_dir=tmp_path)
        scorer._epss["CVE-2021-44228"] = (epss, 0.99)
        if kev:
            scorer._kev["CVE-2021-44228"] = {"vendorProject": "Example"}
        result = scorer.score("cve-2021-44228", cvss)
        assert result.composite_risk == pytest.approx(expected)
        assert result.risk_tier == tier and result.in_kev == kev
        assert result.data_unavailable is False

    def test_missing_feeds_are_explicit(self, tmp_path):
        from shadow313.v2.vuln_upgrades.epss_kev import EPSSKEVScorer

        scorer = EPSSKEVScorer(cache_dir=tmp_path)
        result = scorer.score("CVE-2021-44228", 10.0)
        assert result.data_unavailable is True and result.risk_tier == "UNKNOWN"
        assert not scorer.is_data_available


# ── P-20: FileEncryptionRateMonitor ──────────────────────────────────────────
class TestFileEncryptionRateMonitor(unittest.TestCase):
    def setUp(self):
        from shadow313.modules.defense.remediation import FileEncryptionRateMonitor

        self.Monitor = FileEncryptionRateMonitor

    def test_instantiation(self):
        m = self.Monitor()
        self.assertIsNotNone(m)
        self.assertEqual(m.threshold_per_s, 50.0)

    def test_custom_threshold(self):
        m = self.Monitor(threshold_per_s=100.0)
        self.assertEqual(m.threshold_per_s, 100.0)

    def test_start_stop(self):
        m = self.Monitor(watch_dirs=["/tmp"])
        m.start()
        self.assertTrue(m._running)
        m.stop()
        self.assertFalse(m._running)

    def test_double_start_safe(self):
        """Starting twice should not create two threads"""
        m = self.Monitor(watch_dirs=["/tmp"])
        m.start()
        t1 = m._thread
        m.start()
        t2 = m._thread
        self.assertIs(t1, t2)
        m.stop()

    def test_current_rate_zero_initially(self):
        m = self.Monitor(watch_dirs=["/tmp"])
        self.assertEqual(m.current_rate(), 0.0)

    def test_alert_callback_called(self):
        alerts = []
        m = self.Monitor(
            threshold_per_s=1.0,
            window_s=10.0,
            poll_interval_s=0.1,
            alert_callback=lambda rate, path: alerts.append((rate, path)),
            watch_dirs=["/tmp"],
        )
        # Manually inject events to trigger alert
        now = time.time()
        with m._lock:
            m._events = [(now - i * 0.1, "/tmp/test.locked") for i in range(20)]
        rate = m.current_rate()
        self.assertGreater(rate, 0)

    def test_events_pruned_outside_window(self):
        m = self.Monitor(window_s=5.0)
        old_time = time.time() - 100  # 100 seconds ago — outside 5s window
        with m._lock:
            m._events = [(old_time, "/tmp/old.file")]
        rate = m.current_rate()
        self.assertEqual(rate, 0.0)


# ── P-21: RoutingTableMonitor ─────────────────────────────────────────────────
class TestRoutingTableMonitor(unittest.TestCase):
    def setUp(self):
        from shadow313.modules.network.topology import RoutingTableMonitor

        self.Monitor = RoutingTableMonitor

    def test_instantiation(self):
        m = self.Monitor()
        self.assertIsNotNone(m)

    def test_baseline_creates_snapshot(self):
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            snap_path = Path(f.name)
        m = self.Monitor(snapshot_path=snap_path)
        with patch.object(m, "_get_routes", return_value=["10.0.0.0/8 via 192.168.1.1"]):
            result = m.baseline()
        self.assertEqual(result["baselined"], 1)
        self.assertTrue(snap_path.exists())
        snap_path.unlink(missing_ok=True)

    def test_check_detects_new_route(self):
        import tempfile

        alerts = []
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            snap_path = Path(f.name)
        m = self.Monitor(
            snapshot_path=snap_path,
            alert_callback=lambda routes: alerts.extend(routes),
        )
        # Baseline with one route
        with patch.object(m, "_get_routes", return_value=["default via 10.0.0.1"]):
            m.baseline()
        # Check with new route added
        with patch.object(
            m,
            "_get_routes",
            return_value=[
                "default via 10.0.0.1",
                "10.100.0.0/16 via 192.168.1.254",  # NEW — cross-segment
            ],
        ):
            result = m.check()
        self.assertEqual(len(result["new_routes"]), 1)
        self.assertIn("10.100.0.0/16 via 192.168.1.254", result["new_routes"])
        self.assertTrue(result["alerted"])
        self.assertEqual(len(alerts), 1)
        snap_path.unlink(missing_ok=True)

    def test_check_no_change_no_alert(self):
        import tempfile

        alerts = []
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            snap_path = Path(f.name)
        m = self.Monitor(
            snapshot_path=snap_path,
            alert_callback=lambda routes: alerts.extend(routes),
        )
        routes = ["default via 10.0.0.1", "192.168.0.0/24 dev eth0"]
        with patch.object(m, "_get_routes", return_value=routes):
            m.baseline()
        with patch.object(m, "_get_routes", return_value=routes):
            result = m.check()
        self.assertEqual(result["new_routes"], [])
        self.assertFalse(result["alerted"])
        self.assertEqual(len(alerts), 0)
        snap_path.unlink(missing_ok=True)

    def test_check_removed_routes_tracked(self):
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            snap_path = Path(f.name)
        m = self.Monitor(snapshot_path=snap_path)
        with patch.object(
            m, "_get_routes", return_value=["10.0.0.0/8 via 192.168.1.1", "default via 10.0.0.1"]
        ):
            m.baseline()
        with patch.object(m, "_get_routes", return_value=["default via 10.0.0.1"]):
            result = m.check()
        self.assertEqual(len(result["removed_routes"]), 1)
        snap_path.unlink(missing_ok=True)

    def test_empty_snapshot_no_crash(self):
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            snap_path = Path(f.name)
        snap_path.unlink()  # No snapshot file
        m = self.Monitor(snapshot_path=snap_path)
        with patch.object(m, "_get_routes", return_value=["default via 10.0.0.1"]):
            result = m.check()
        self.assertEqual(len(result["new_routes"]), 1)
        snap_path.unlink(missing_ok=True)


# ── P-22: OutboundVolumeMonitor / UserFileAccessMonitor ──────────────────────
class TestOutboundVolumeMonitor(unittest.TestCase):
    def setUp(self):
        from shadow313.modules.network.flow_tracker import OutboundVolumeMonitor

        self.Monitor = OutboundVolumeMonitor

    def test_approved_domain_no_alert(self):
        alerts = []
        m = self.Monitor(alert_callback=lambda *a: alerts.append(a))
        result = m.record("10.0.0.1", "sharepoint.com", 2_000_000_000)
        self.assertFalse(result)
        self.assertEqual(len(alerts), 0)

    def test_approved_subdomain_no_alert(self):
        alerts = []
        m = self.Monitor(alert_callback=lambda *a: alerts.append(a))
        result = m.record("10.0.0.1", "tenant.sharepoint.com", 2_000_000_000)
        self.assertFalse(result)
        self.assertEqual(len(alerts), 0)

    def test_unapproved_domain_below_threshold_no_alert(self):
        alerts = []
        m = self.Monitor(threshold_bytes=1_073_741_824, alert_callback=lambda *a: alerts.append(a))
        result = m.record("10.0.0.1", "evil-exfil.com", 500_000_000)  # 500MB < 1GB
        self.assertFalse(result)
        self.assertEqual(len(alerts), 0)

    def test_unapproved_domain_above_threshold_alerts(self):
        alerts = []
        m = self.Monitor(threshold_bytes=1_073_741_824, alert_callback=lambda *a: alerts.append(a))
        result = m.record("10.0.0.1", "evil-exfil.com", 1_100_000_000)  # 1.1GB > 1GB
        self.assertTrue(result)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0][0], "10.0.0.1")
        self.assertEqual(alerts[0][1], "evil-exfil.com")

    def test_cumulative_transfers_trigger_alert(self):
        """Multiple small transfers that cumulatively exceed threshold"""
        alerts = []
        m = self.Monitor(threshold_bytes=1_000_000, alert_callback=lambda *a: alerts.append(a))
        for _ in range(5):
            m.record("10.0.0.2", "attacker.com", 250_000)  # 5 × 250KB = 1.25MB
        self.assertGreater(len(alerts), 0)

    def test_stats_returns_list(self):
        m = self.Monitor()
        m.record("10.0.0.1", "evil.com", 100_000)
        stats = m.stats()
        self.assertIsInstance(stats, list)
        self.assertEqual(len(stats), 1)
        self.assertEqual(stats[0]["src_ip"], "10.0.0.1")

    def test_different_endpoints_tracked_separately(self):
        alerts = []
        m = self.Monitor(threshold_bytes=1_000_000, alert_callback=lambda *a: alerts.append(a))
        m.record("10.0.0.1", "evil.com", 600_000)
        m.record("10.0.0.2", "evil.com", 600_000)
        # Neither alone exceeds threshold
        self.assertEqual(len(alerts), 0)


class TestUserFileAccessMonitor(unittest.TestCase):
    def setUp(self):
        from shadow313.modules.network.flow_tracker import UserFileAccessMonitor

        self.Monitor = UserFileAccessMonitor

    def test_no_alert_without_baseline(self):
        alerts = []
        m = self.Monitor(alert_callback=lambda *a: alerts.append(a))
        for _ in range(1000):
            m.record_access("alice", "/data/file.txt")
        self.assertEqual(len(alerts), 0)  # No baseline yet

    def test_alert_when_exceeds_multiplier(self):
        alerts = []
        m = self.Monitor(
            alert_multiplier=3.0, min_baseline=10, alert_callback=lambda *a: alerts.append(a)
        )
        # Seed 7 days of baseline: 100 files/day
        m.set_baseline("bob", [100] * 7)
        # Today: 400 files (4× baseline > 3× threshold)
        for _ in range(400):
            m.record_access("bob", "/sensitive/file.txt")
        self.assertGreater(len(alerts), 0)

    def test_no_alert_below_multiplier(self):
        alerts = []
        m = self.Monitor(
            alert_multiplier=3.0, min_baseline=10, alert_callback=lambda *a: alerts.append(a)
        )
        m.set_baseline("carol", [100] * 7)
        # Today: 250 files (2.5× baseline < 3× threshold)
        for _ in range(250):
            m.record_access("carol", "/data/file.txt")
        self.assertEqual(len(alerts), 0)

    def test_min_baseline_prevents_false_positive(self):
        """Low baseline (< min_baseline) should not trigger alerts"""
        alerts = []
        m = self.Monitor(
            alert_multiplier=3.0, min_baseline=100, alert_callback=lambda *a: alerts.append(a)
        )
        m.set_baseline("dave", [5] * 7)  # Only 5 files/day baseline
        for _ in range(50):
            m.record_access("dave", "/file.txt")
        self.assertEqual(len(alerts), 0)

    def test_end_of_day_rotates_counts(self):
        m = self.Monitor()
        m.set_baseline("eve", [50] * 7)
        m.record_access("eve", "/file.txt")
        self.assertEqual(m._today["eve"], 1)
        m.end_of_day()
        self.assertEqual(m._today.get("eve", 0), 0)
        self.assertIn(1, m._history["eve"])

    def test_set_baseline_caps_at_30_days(self):
        m = self.Monitor()
        m.set_baseline("frank", list(range(50)))  # 50 days
        self.assertLessEqual(len(m._history["frank"]), 30)


# ── P-23: FirmwareAuditor ─────────────────────────────────────────────────────
class TestFirmwareAuditor(unittest.TestCase):
    def setUp(self):
        from shadow313.v2.network_upgrades.firmware_auditor import FirmwareAuditor

        self.Auditor = FirmwareAuditor

    def test_verified_version(self):
        a = self.Auditor()
        result = a.verify_version("watchguard", "fireware", "12.9.2")
        self.assertEqual(result["status"], "VERIFIED")
        self.assertTrue(result["known_good"])

    def test_unknown_version_not_in_db(self):
        a = self.Auditor()
        result = a.verify_version("watchguard", "fireware", "12.9.1-mod")
        self.assertEqual(result["status"], "VERSION_NOT_IN_DB")
        self.assertFalse(result["known_good"])

    def test_unknown_product(self):
        a = self.Auditor()
        result = a.verify_version("watchguard", "unknown-product", "1.0.0")
        self.assertEqual(result["status"], "UNKNOWN_PRODUCT")

    def test_unknown_vendor(self):
        a = self.Auditor()
        result = a.verify_version("unknown-vendor", "product", "1.0.0")
        self.assertEqual(result["status"], "UNKNOWN_PRODUCT")

    def test_audit_host_verified_no_alert(self):
        alerts = []
        a = self.Auditor(alert_callback=lambda *args: alerts.append(args))
        with patch.object(a, "get_running_version", return_value="12.9.2"):
            result = a.audit_host("192.168.1.1", "watchguard", "fireware")
        self.assertEqual(result["status"], "VERIFIED")
        self.assertFalse(result["alert"])
        self.assertEqual(len(alerts), 0)

    def test_audit_host_modified_firmware_alerts(self):
        alerts = []
        a = self.Auditor(alert_callback=lambda *args: alerts.append(args))
        with patch.object(a, "get_running_version", return_value="12.9.1-mod"):
            result = a.audit_host("192.168.1.1", "watchguard", "fireware")
        self.assertTrue(result["alert"])
        self.assertEqual(len(alerts), 1)
        self.assertIn("192.168.1.1", alerts[0])

    def test_audit_host_version_undetectable(self):
        a = self.Auditor()
        with patch.object(a, "get_running_version", return_value=None):
            result = a.audit_host("192.168.1.1", "watchguard", "fireware")
        self.assertEqual(result["status"], "VERSION_UNDETECTABLE")
        self.assertFalse(result["alert"])

    def test_audit_host_manual_version(self):
        alerts = []
        a = self.Auditor(alert_callback=lambda *args: alerts.append(args))
        result = a.audit_host("192.168.1.1", "watchguard", "fireware", version="12.9.2")
        self.assertEqual(result["version_source"], "manual")
        self.assertEqual(result["status"], "VERIFIED")

    def test_audit_batch(self):
        a = self.Auditor()
        targets = [
            {
                "host": "10.0.0.1",
                "vendor": "watchguard",
                "product": "fireware",
                "version": "12.9.2",
            },
            {"host": "10.0.0.2", "vendor": "fortinet", "product": "fortios", "version": "7.4.3"},
            {
                "host": "10.0.0.3",
                "vendor": "watchguard",
                "product": "fireware",
                "version": "12.9.1-mod",
            },
        ]
        results = a.audit_batch(targets)
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0]["status"], "VERIFIED")
        self.assertEqual(results[1]["status"], "VERIFIED")
        self.assertEqual(results[2]["status"], "VERSION_NOT_IN_DB")

    def test_summary(self):
        a = self.Auditor()
        results = [
            {"status": "VERIFIED", "alert": False},
            {"status": "VERIFIED", "alert": False},
            {"status": "VERSION_NOT_IN_DB", "alert": True},
            {"status": "VERSION_UNDETECTABLE", "alert": False},
        ]
        s = a.summary(results)
        self.assertEqual(s["total"], 4)
        self.assertEqual(s["verified"], 2)
        self.assertEqual(s["alerted"], 1)
        self.assertEqual(s["unknown"], 1)
        self.assertAlmostEqual(s["alert_rate"], 0.25, places=2)

    def test_all_vendors_in_db(self):
        a = self.Auditor()
        for vendor in ("watchguard", "fortinet", "paloalto", "cisco"):
            self.assertIn(vendor, a.known_good)

    def test_fortinet_verified(self):
        a = self.Auditor()
        result = a.verify_version("fortinet", "fortios", "7.4.3")
        self.assertEqual(result["status"], "VERIFIED")

    def test_paloalto_verified(self):
        a = self.Auditor()
        result = a.verify_version("paloalto", "pan-os", "11.1.3")
        self.assertEqual(result["status"], "VERIFIED")


# ── P-24: JA3 MD5 usedforsecurity=False ──────────────────────────────────────
class TestJA3MD5Fix(unittest.TestCase):
    def test_client_and_server_fingerprints(self):
        import hashlib

        from shadow313.v2.network_upgrades.ja3_fingerprint import _ja3_hash, _ja3s_hash

        client = _ja3_hash(771, [49195, 49199], [0, 23], [29, 23], [0])
        self.assertEqual(
            client, hashlib.md5(b"771,49195-49199,23,29-23,0", usedforsecurity=False).hexdigest()
        )
        self.assertEqual(
            _ja3s_hash(771, 49195, [0, 23]),
            hashlib.md5(b"771,49195,23", usedforsecurity=False).hexdigest(),
        )

    def test_fingerprints_use_md5_for_nonsecurity_purpose(self):
        import hashlib

        from shadow313.v2.network_upgrades.ja3_fingerprint import _ja3_hash, _ja3s_hash

        with patch("hashlib.md5", wraps=hashlib.md5) as md5:
            _ja3_hash(771, [49195], [], [], [])
            _ja3s_hash(771, 49195, [])
        self.assertEqual(md5.call_count, 2)
        for invocation in md5.call_args_list:
            self.assertIs(invocation.kwargs["usedforsecurity"], False)


# ── P-25: SQL injection guard in threat_intel.py ─────────────────────────────
class TestThreatIntelSQLGuard:
    def test_stats_only_queries_internal_tables(self, tmp_path):
        from shadow313.v2.threat_intel.threat_intel import ThreatIntelDB

        db = ThreatIntelDB(tmp_path / "intel.db")
        queries = []
        db._conn.set_trace_callback(queries.append)
        stats = db.stats()
        db._conn.close()
        counts = [q for q in queries if q.startswith("SELECT COUNT(*)")]
        assert set(counts) == {
            f"SELECT COUNT(*) FROM {table}"
            for table in ("ioc_ip", "ioc_domain", "ioc_url", "ioc_hash", "mitre_techniques")
        }
        assert all(
            stats[k] == 0 for k in ("ioc_ip", "ioc_domain", "ioc_url", "ioc_hash", "techniques")
        )
        assert stats["feeds"] == {}

    @pytest.mark.parametrize(
        "table", ["ioc_ip; DROP TABLE ioc_ip", "feed_meta WHERE 1=1", "unknown"]
    )
    def test_table_allowlist_rejects_sql_input(self, table):
        from shadow313.v2.threat_intel.threat_intel import _validate_table

        with pytest.raises(ValueError):
            _validate_table(table)


# ── P-26: W0106 expression-not-assigned fixes ────────────────────────────────
class TestW0106Fixes(unittest.TestCase):
    def test_plugins_module_install_calls_success_on_ok(self):
        """plugins_module install path calls out.success when ok=True"""
        from shadow313.modules.plugins.plugins_module import PluginManager

        pm = PluginManager.__new__(PluginManager)
        pm.out = MagicMock()
        pm.session = MagicMock()
        pm.registry = MagicMock()
        pm.registry.install.return_value = (True, "Installed OK")
        pm.registry.list_all.return_value = []
        pm.scaffolder = MagicMock()
        pm.run(install="my-plugin")
        pm.out.success.assert_called_once_with("Installed OK")
        pm.out.error.assert_not_called()

    def test_plugins_module_install_calls_error_on_fail(self):
        """plugins_module install path calls out.error when ok=False"""
        from shadow313.modules.plugins.plugins_module import PluginManager

        pm = PluginManager.__new__(PluginManager)
        pm.out = MagicMock()
        pm.session = MagicMock()
        pm.registry = MagicMock()
        pm.registry.install.return_value = (False, "Install failed")
        pm.registry.list_all.return_value = []
        pm.scaffolder = MagicMock()
        pm.run(install="bad-plugin")
        pm.out.error.assert_called_once_with("Install failed")
        pm.out.success.assert_not_called()

    def test_plugin_signer_success_records_trust(self):
        import tempfile

        from shadow313.v2.plugin_signing.plugin_signer import PluginSigner

        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "plugin.yaml"
            manifest.write_text("name: synthetic-plugin\n")
            signer = PluginSigner.__new__(PluginSigner)
            signer._hmac = MagicMock()
            signer._trust = MagicMock()
            result = signer.sign(directory)
            self.assertEqual(result["status"], "signed")
            self.assertEqual(result["method"], "hmac-sha256")
            signer._hmac.sign.assert_called_once_with(manifest)
            signer._trust.trust.assert_called_once()

    def test_plugin_signer_missing_manifest_returns_error(self):
        import tempfile

        from shadow313.v2.plugin_signing.plugin_signer import PluginSigner

        signer = PluginSigner.__new__(PluginSigner)
        signer._hmac = MagicMock()
        signer._trust = MagicMock()
        with tempfile.TemporaryDirectory() as directory:
            result = signer.sign(directory)
        self.assertEqual(result["status"], "error")
        signer._hmac.sign.assert_not_called()
        signer._trust.trust.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
