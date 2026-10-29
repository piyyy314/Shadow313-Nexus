"""Firmware discovery, verification, alerting and batch fault isolation."""

from unittest.mock import Mock

import pytest

from shadow313.v2.network_upgrades.firmware_auditor import FirmwareAuditor, _extract_version


@pytest.fixture
def auditor():
    return FirmwareAuditor({"vendor": {"product": {"1.2.3": "synthetic-hash"}}}, Mock())


@pytest.mark.parametrize(
    ("vendor", "product", "version", "status"),
    [
        ("VENDOR", "PRODUCT", "1.2.3", "VERIFIED"),
        ("vendor", "product", "9.9.9", "VERSION_NOT_IN_DB"),
        ("unknown", "product", "1.2.3", "UNKNOWN_PRODUCT"),
        ("vendor", "unknown", "1.2.3", "UNKNOWN_PRODUCT"),
    ],
)
def test_firmware_verification_status_and_case_normalization(
    auditor, vendor, product, version, status
):
    result = auditor.verify_version(vendor, product, version)
    assert result["status"] == status
    assert result["known_good"] is (status == "VERIFIED")
    assert result["expected_hash"] == ("synthetic-hash" if status == "VERIFIED" else None)


def test_manual_version_skips_discovery_and_alerts_only_when_unrecognized(auditor, monkeypatch):
    discover = Mock(side_effect=AssertionError("must not probe"))
    monkeypatch.setattr(auditor, "get_running_version", discover)
    good = auditor.audit_host("192.0.2.1", "vendor", "product", "1.2.3")
    assert good["version_source"] == "manual"
    assert good["status"] == "VERIFIED"
    assert good["alert"] is False
    auditor.alert_callback.assert_not_called()
    bad = auditor.audit_host("192.0.2.1", "vendor", "product", "0.0.1")
    assert bad["alert"] is True
    auditor.alert_callback.assert_called_once_with("192.0.2.1", "vendor", "0.0.1", bad["detail"])
    discover.assert_not_called()


def test_discovery_prefers_snmp_then_falls_back_to_http(auditor, monkeypatch):
    snmp = Mock(return_value="1.2.3")
    http = Mock(return_value="4.5.6")
    monkeypatch.setattr(auditor, "_get_version_snmp", snmp)
    monkeypatch.setattr(auditor, "_get_version_http", http)
    assert auditor.get_running_version("192.0.2.1", "vendor") == "1.2.3"
    http.assert_not_called()
    snmp.return_value = None
    assert auditor.get_running_version("192.0.2.1", "vendor") == "4.5.6"
    http.assert_called_once_with("192.0.2.1")


def test_http_discovery_tries_management_ports_until_success(auditor, monkeypatch):
    fetch = Mock(side_effect=[None, None, "1.2.3"])
    monkeypatch.setattr("shadow313.v2.network_upgrades.firmware_auditor._http_get_version", fetch)
    assert auditor._get_version_http("192.0.2.1") == "1.2.3"
    assert [call.kwargs["port"] for call in fetch.call_args_list] == [443, 8443, 8080]


def test_undetectable_version_is_not_misreported_as_verified(auditor, monkeypatch):
    monkeypatch.setattr(auditor, "get_running_version", Mock(return_value=None))
    result = auditor.audit_host("192.0.2.1", "vendor", "product")
    assert result["status"] == "VERSION_UNDETECTABLE"
    assert result["version_source"] == "snmp_or_http"
    assert result["alert"] is False
    auditor.alert_callback.assert_not_called()


def test_batch_continues_after_malformed_target_and_summary_counts_outcomes(auditor):
    results = auditor.audit_batch(
        [
            {"host": "good", "vendor": "vendor", "product": "product", "version": "1.2.3"},
            {},
            {"host": "bad", "vendor": "vendor", "product": "product", "version": "9.9.9"},
            {"host": "unknown", "version": "1.2.3"},
        ]
    )
    assert [r["status"] for r in results] == [
        "VERIFIED",
        "ERROR",
        "VERSION_NOT_IN_DB",
        "UNKNOWN_PRODUCT",
    ]
    assert auditor.summary(results) == {
        "total": 4,
        "verified": 1,
        "alerted": 2,
        "unknown": 1,
        "alert_rate": 0.5,
    }
    assert auditor.summary([]) == {
        "total": 0,
        "verified": 0,
        "alerted": 0,
        "unknown": 0,
        "alert_rate": 0,
    }


@pytest.mark.parametrize(
    ("text", "version"),
    [
        ("Vendor OS version 12.9.2 build 100", "12.9.2"),
        ("v7.4", "7.4"),
        ("unknown", None),
    ],
)
def test_version_extraction(text, version):
    assert _extract_version(text) == version
