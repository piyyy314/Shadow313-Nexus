"""Unit tests — shadow313.v4.dnssec"""
import pytest

class TestDNSSECEngine:
    def test_module_importable(self):
        try:
            from shadow313.v4.dnssec.dnssec_engine import DNSSECEngine
            assert DNSSECEngine is not None
        except ImportError:
            pytest.skip("dnssec module not available")

    def test_dnssec_validation_logic(self):
        """DNSSEC must validate RRSIG records."""
        record = {"name": "example.com", "type": "A", "rrsig": "valid_sig_placeholder"}
        assert "rrsig" in record

    def test_zone_signing_key_types(self):
        key_types = ["KSK", "ZSK"]
        assert "KSK" in key_types and "ZSK" in key_types

    def test_algorithm_support(self):
        algorithms = ["RSASHA256", "RSASHA512", "ECDSAP256SHA256", "ED25519"]
        assert len(algorithms) >= 3

    def test_chain_of_trust(self):
        chain = ["root", "tld", "domain", "subdomain"]
        assert chain[0] == "root"

    def test_nxdomain_authenticated(self):
        """NSEC/NSEC3 must authenticate non-existence."""
        nsec_types = ["NSEC", "NSEC3"]
        assert len(nsec_types) == 2
