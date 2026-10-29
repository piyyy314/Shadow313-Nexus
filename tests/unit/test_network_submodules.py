"""Packet decoding, flow accounting and monitor boundaries from PR #86."""

import hashlib
import json
import socket
import struct
from datetime import UTC, datetime
from unittest.mock import Mock

import pytest

from shadow313.modules.network.anomaly import AnomalyDetector
from shadow313.modules.network.flow_tracker import (
    FlowTracker,
    OutboundVolumeMonitor,
    UserFileAccessMonitor,
)
from shadow313.modules.network.pcap_parser import PCAPParser
from shadow313.modules.network.topology import RoutingTableMonitor, TopologyMapper


def _frame(protocol=6, payload=b"", ip_options=b"", tcp_options=b""):
    """Build Ethernet/IPv4 frames with explicit transport header offsets."""
    ethernet = bytes.fromhex("ffffffffffff0011223344550800")
    if protocol == 6:
        transport = struct.pack(
            "!HHLLBBHHH", 1234, 80, 0, 0, ((20 + len(tcp_options)) // 4) << 4, 0x18, 1024, 0, 0
        )
        transport += tcp_options
    else:
        transport = struct.pack("!HHHH", 53000, 53, 8 + len(payload), 0)
    length = 20 + len(ip_options) + len(transport) + len(payload)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x40 | ((20 + len(ip_options)) // 4),
        0,
        length,
        0,
        0,
        64,
        protocol,
        0,
        socket.inet_aton("10.0.0.1"),
        socket.inet_aton("8.8.8.8"),
    )
    return ethernet + ip + ip_options + transport + payload


def _pcap(frames):
    data = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for index, frame in enumerate(frames):
        data += struct.pack("<IIII", 100 + index, 250000, len(frame), len(frame)) + frame
    return data


def test_pcap_decodes_header_offsets_payloads_and_aggregated_flows(tmp_path):
    payload = b"GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n"
    tcp = _frame(payload=payload, ip_options=b"\x01" * 4, tcp_options=b"\x01" * 4)
    udp = _frame(protocol=17, payload=b"dns-query")
    path = tmp_path / "traffic.pcap"
    path.write_bytes(_pcap([tcp, tcp, udp]))
    parser = PCAPParser(str(path))
    packets = parser.parse()
    assert len(packets) == 3
    assert packets[0]["ts"] == 100.25
    assert packets[0]["src_mac"] == "00:11:22:33:44:55"
    assert packets[0]["src_ip"] == "10.0.0.1"
    assert packets[0]["dport"] == 80
    assert packets[0]["flags"] == 0x18
    assert packets[0]["payload_preview"] == payload.decode()
    assert packets[2]["protocol"] == "UDP"
    flows = parser.get_flows()
    assert flows[0]["packets"] == 2
    assert flows[0]["bytes"] == 2 * (len(tcp) - 14)
    assert flows[0]["duration"] == 1
    assert flows[1]["dport"] == 53
    assert parser.extract_dns_queries() == ["dns-query"]
    assert parser.extract_http_hosts() == ["Host: example.invalid"]


@pytest.mark.parametrize(
    "suffix", [b"", b"\x01" * 15, struct.pack("<IIII", 1, 0, 100, 100) + b"short"]
)
def test_pcap_tolerates_incomplete_records_after_valid_packet(tmp_path, suffix):
    path = tmp_path / "partial.pcap"
    path.write_bytes(_pcap([_frame()]) + suffix)
    assert len(PCAPParser(str(path)).parse()) == 1


@pytest.mark.parametrize("data", [b"", b"short", b"\x00" * 23])
def test_pcap_short_global_header(tmp_path, data):
    path = tmp_path / "short.pcap"
    path.write_bytes(data)
    assert PCAPParser(str(path)).parse() == []


def test_pcap_invalid_magic_arp_short_frames_and_payload_limit(tmp_path):
    path = tmp_path / "invalid.pcap"
    path.write_bytes(b"\x00" * 24)
    assert PCAPParser(str(path)).parse() == [{"error": "Not a valid PCAP file"}]
    arp = bytes.fromhex("ffffffffffff0011223344550806") + b"\x00" * 28
    path.write_bytes(_pcap([b"tiny", arp, _frame(payload=b"x" * 100)]))
    parser = PCAPParser(str(path))
    packets = parser.parse()
    assert len(packets) == 2
    assert packets[0]["protocol"] == "ARP"
    assert len(packets[1]["payload_preview"]) == 80
    assert len(parser.get_flows()) == 1


def test_flow_tracker_distinguishes_direction_protocol_and_computes_rates():
    tracker = FlowTracker()
    packet = {
        "src_ip": "10.0.0.1",
        "dst_ip": "8.8.8.8",
        "sport": 1234,
        "dport": 443,
        "protocol": "TCP",
        "ts": 10,
        "length": 100,
    }
    tracker.update({"protocol": "ARP"})
    tracker.update(packet)
    tracker.update({**packet, "ts": 12, "length": 300})
    tracker.update({**packet, "protocol": "UDP", "length": 10})
    tracker.update({**packet, "src_ip": "8.8.8.8", "dst_ip": "10.0.0.1", "length": 20})
    flows = tracker.get_flows()
    assert len(flows) == 3
    assert flows[0]["bytes"] == 400
    assert flows[0]["packets"] == 2
    assert flows[0]["duration"] == 2
    assert flows[0]["packet_rate"] == 1
    assert flows[0]["byte_rate"] == 200
    assert flows[-1]["duration"] == 0.001


def _flow(**overrides):
    return {
        "src_ip": "10.0.0.1",
        "dst_ip": "8.8.8.8",
        "dport": 443,
        "sport": 1234,
        "bytes": 0,
        **overrides,
    }


@pytest.mark.parametrize(("count", "beacons"), [(4, 0), (5, 1)])
def test_beacon_threshold_and_private_destination_exclusion(count, beacons):
    alerts = AnomalyDetector([_flow() for _ in range(count)]).detect()
    hits = [a for a in alerts if a["type"] == "BEACONING"]
    assert len(hits) == beacons
    if hits:
        assert hits[0]["count"] == 5
    assert AnomalyDetector([_flow(dst_ip="172.16.0.1") for _ in range(10)]).detect() == []


@pytest.mark.parametrize(("ports", "scans"), [(19, 0), (20, 1)])
def test_port_scan_counts_unique_ports_per_source(ports, scans):
    flows = [_flow(dport=port) for port in range(ports)]
    flows.extend([_flow(dport=1)] * 10)
    flows.extend([_flow(src_ip="10.0.0.2", dport=100 + port) for port in range(5)])
    hits = [a for a in AnomalyDetector(flows).detect() if a["type"] == "PORT_SCAN"]
    assert len(hits) == scans
    if hits:
        assert hits[0]["port_count"] == 20
        assert hits[0]["src_ip"] == "10.0.0.1"


@pytest.mark.parametrize(("total", "expected"), [(999999, False), (1000000, True)])
def test_exfiltration_aggregates_by_external_destination(total, expected):
    flows = [
        _flow(bytes=500000),
        _flow(src_ip="10.0.0.2", bytes=total - 500000),
        _flow(dst_ip="192.168.1.1", bytes=2000000),
    ]
    hits = [a for a in AnomalyDetector(flows).detect() if a["type"] == "DATA_EXFILTRATION"]
    assert bool(hits) is expected
    if hits:
        assert hits[0]["bytes"] == total
        assert hits[0]["severity"] == "CRITICAL"


def test_volume_monitor_allowlist_window_boundary_and_endpoint_isolation(monkeypatch):
    clock = Mock()
    clock.now.return_value.timestamp.return_value = 100
    monkeypatch.setattr("shadow313.modules.network.flow_tracker._datetime", clock)
    alert = Mock()
    monitor = OutboundVolumeMonitor(100, 10, {"approved.invalid"}, alert)
    assert monitor.record("one", "UPPER.approved.invalid", 999) is False
    assert monitor.record("one", "evilapproved.invalid", 60) is False
    assert monitor.record("two", "evilapproved.invalid", 60) is False
    clock.now.return_value.timestamp.return_value = 110
    assert monitor.record("one", "evilapproved.invalid", 40) is True
    alert.assert_called_once_with("one", "evilapproved.invalid", 100)
    assert monitor.stats()[0]["event_count"] == 2
    clock.now.return_value.timestamp.return_value = 111
    assert monitor.record("one", "evilapproved.invalid", 10) is False
    assert monitor.stats()[0]["total_bytes"] == 50
    clock.now.return_value.timestamp.return_value = 122
    assert monitor.stats() == []


def test_user_access_requires_history_and_rotates_daily_counts():
    alert = Mock()
    monitor = UserFileAccessMonitor(alert_multiplier=2, min_baseline=2, alert_callback=alert)
    monitor.set_baseline("alice", [2] * 7)
    monitor.set_baseline("bob", [2] * 6)
    monitor.set_baseline("low", [1] * 7)
    for user in ("alice", "bob", "low"):
        assert [monitor.record_access(user) for _ in range(4)] == (
            [False, False, False, True] if user == "alice" else [False] * 4
        )
    alert.assert_called_once_with("alice", 4, 2)
    monitor.end_of_day()
    assert monitor.record_access("alice") is False


def test_user_access_baseline_discards_days_older_than_thirty():
    alert = Mock()
    monitor = UserFileAccessMonitor(2, 2, alert)
    monitor.set_baseline("alice", [10000] * 10 + [2] * 30)
    assert [monitor.record_access("alice") for _ in range(4)] == [False] * 3 + [True]
    alert.assert_called_once_with("alice", 4, 2)


def test_route_monitor_persists_baseline_and_alerts_only_on_additions(tmp_path, monkeypatch):
    alert = Mock()
    path = tmp_path / "state/routes.json"
    monitor = RoutingTableMonitor(path, alert)
    current = Mock(return_value=["route-a", "route-b"])
    monkeypatch.setattr(monitor, "_get_routes", current)
    assert monitor.baseline()["baselined"] == 2
    saved = json.loads(path.read_text())
    assert saved["hash"] == hashlib.sha256(b"route-a\nroute-b").hexdigest()
    assert datetime.fromisoformat(saved["captured_at"]).tzinfo == UTC
    current.return_value = ["route-b", "route-c"]
    assert monitor.check() == {
        "new_routes": ["route-c"],
        "removed_routes": ["route-a"],
        "unchanged": 1,
        "total_routes": 2,
        "alerted": True,
    }
    alert.assert_called_once_with(["route-c"])
    assert monitor.check()["alerted"] is False
    current.return_value = ["route-b"]
    assert monitor.check()["removed_routes"] == ["route-c"]
    assert alert.call_count == 1


def test_route_monitor_recovers_corrupt_snapshot(tmp_path, monkeypatch):
    path = tmp_path / "routes.json"
    path.write_text("invalid json")
    monitor = RoutingTableMonitor(path, Mock())
    monkeypatch.setattr(monitor, "_get_routes", Mock(return_value=["new-route"]))
    assert monitor.check()["new_routes"] == ["new-route"]
    assert json.loads(path.read_text())["routes"] == ["new-route"]


def test_topology_sweep_only_resolves_live_hosts(monkeypatch):
    mapper = TopologyMapper("192.168.1.0/30")
    ping = Mock(side_effect=[False, True])
    reverse = Mock(return_value="device.invalid")
    monkeypatch.setattr(mapper, "_ping", ping)
    monkeypatch.setattr(mapper, "_reverse_dns", reverse)
    hosts = mapper.sweep()
    assert hosts == [{"ip": "192.168.1.2", "hostname": "device.invalid", "state": "up"}]
    reverse.assert_called_once_with("192.168.1.2")
    assert "192.168.1.2  (device.invalid)" in mapper.ascii_graph(hosts)
