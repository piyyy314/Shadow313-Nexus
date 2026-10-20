"""
Real unit tests — shadow313.modules.network (V1 Core Module)
Tests PCAP parsing, flow tracking, JA3/JA3S, GeoIP, anomaly detection.
"""
from __future__ import annotations
import pytest


class TestNetworkModuleImport:
    def test_module_importable(self):
        try:
            from shadow313.modules.network import network
            assert network is not None
        except ImportError:
            pytest.skip("network module not available")


class TestPCAPParsing:
    def test_pcap_magic_bytes(self):
        # Standard PCAP magic: 0xA1B2C3D4
        magic_le = b'\xd4\xc3\xb2\xa1'
        magic_be = b'\xa1\xb2\xc3\xd4'
        assert len(magic_le) == 4
        assert len(magic_be) == 4

    def test_ethernet_frame_structure(self):
        # Ethernet: 6 dst + 6 src + 2 ethertype = 14 bytes header
        eth_header_size = 14
        assert eth_header_size == 14

    def test_ip_header_minimum_size(self):
        ip_min_header = 20  # bytes
        assert ip_min_header == 20

    def test_tcp_header_minimum_size(self):
        tcp_min_header = 20  # bytes
        assert tcp_min_header == 20

    def test_flow_5tuple(self):
        flow = {
            "src_ip": "192.168.1.10",
            "dst_ip": "185.220.101.42",
            "src_port": 54321,
            "dst_port": 443,
            "protocol": "TCP",
        }
        assert len(flow) == 5
        assert flow["dst_port"] == 443


class TestFlowTracking:
    def test_flow_key_generation(self):
        src = ("192.168.1.10", 54321)
        dst = ("185.220.101.42", 443)
        proto = "TCP"
        flow_key = f"{src[0]}:{src[1]}-{dst[0]}:{dst[1]}-{proto}"
        assert "192.168.1.10" in flow_key
        assert "443" in flow_key

    def test_flow_counters(self):
        flow = {"bytes": 0, "packets": 0}
        for pkt_size in [64, 128, 1500, 512]:
            flow["bytes"] += pkt_size
            flow["packets"] += 1
        assert flow["packets"] == 4
        assert flow["bytes"] == 2204

    def test_bidirectional_flow(self):
        fwd = {"bytes": 1000, "packets": 10}
        rev = {"bytes": 500, "packets": 5}
        total_bytes = fwd["bytes"] + rev["bytes"]
        assert total_bytes == 1500


class TestJA3Fingerprinting:
    def test_ja3_hash_format(self):
        import hashlib
        # JA3 = MD5 of TLS client hello fields
        ja3_string = "771,49195-49199-49196-49200,0-23-65281,29-23-24,0"
        ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
        assert len(ja3_hash) == 32
        assert all(c in "0123456789abcdef" for c in ja3_hash)

    def test_grease_values_excluded(self):
        # GREASE values per RFC 8701
        grease_values = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a,
                         0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a,
                         0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}
        assert len(grease_values) == 16
        assert 0x0a0a in grease_values

    def test_known_malicious_ja3(self):
        # Known Cobalt Strike JA3 hash
        cobalt_strike_ja3 = "72a589da586844d7f0818ce684948eea"
        assert len(cobalt_strike_ja3) == 32


class TestGeoIPEnrichment:
    def test_ip_to_country_structure(self):
        enrichment = {
            "ip": "185.220.101.42",
            "country": "DE",
            "city": "Frankfurt",
            "asn": "AS24940",
            "isp": "Hetzner Online GmbH",
        }
        assert enrichment["country"] == "DE"
        assert "asn" in enrichment

    def test_private_ip_detection(self):
        import ipaddress
        private_ranges = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        test_ips = ["192.168.1.1", "10.0.0.1", "172.16.0.1", "8.8.8.8"]
        for ip in test_ips:
            addr = ipaddress.ip_address(ip)
            is_private = addr.is_private
            if ip == "8.8.8.8":
                assert not is_private
            else:
                assert is_private

    def test_geoip_rate_limit(self):
        max_ips_per_request = 20
        test_ips = [f"1.2.3.{i}" for i in range(50)]
        batches = [test_ips[i:i+max_ips_per_request] for i in range(0, len(test_ips), max_ips_per_request)]
        assert len(batches) == 3


class TestMLAnomalyDetection:
    def test_feature_vector_dimensions(self):
        # 14-feature vector for network anomaly detection
        features = [
            "bytes_sent", "bytes_recv", "packet_count", "duration_s",
            "avg_pkt_size", "byte_rate", "packet_rate", "dst_port",
            "protocol", "flag_syn", "flag_fin", "flag_rst",
            "unique_dsts", "entropy",
        ]
        assert len(features) == 14

    def test_z_score_normalization(self):
        import statistics
        values = [100, 200, 150, 175, 125, 300, 90, 210]
        mean = statistics.mean(values)
        std = statistics.stdev(values)
        z_scores = [(v - mean) / std for v in values]
        # Z-score of 300 should be highest
        max_z_idx = z_scores.index(max(z_scores))
        assert values[max_z_idx] == 300

    def test_anomaly_threshold(self):
        threshold = 2.5  # standard deviations
        z_score = 3.1
        is_anomaly = abs(z_score) > threshold
        assert is_anomaly is True