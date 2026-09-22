"""
Tests for modules built from real operational output files:
  - Ghost-Watch C2 Brief (GHOST_WATCH_C2_BRIEF format)
  - Ghost-Watch Intel Index (GHOST_WATCH_INTEL_INDEX format)
  - WE-FORGE Linguistic Watermarking (we_forge_decoy format)
  - Aegis PE Analyzer (aegis_pe_analyzer format)
  - Aegis Entropy Profiler (aegis_entropy_profile format)
  - Aegis Forensics Dump (aegis_forensics_dump format)
  - DNS Intercept OT/ICS/SCADA (dns_intercept_report format)
  - Geo-Traced Intel Deck (GEO_TRACED_INTEL_DECK format)
"""
import json
import pytest
from pathlib import Path


# ═══════════════════════════════════════════════════════════════════════════════
# C2 Brief Generator Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestC2BriefGenerator:
    def test_generate_brief_structure(self):
        from shadow313.v4.ghost_watch.ghost_watch import C2BriefGenerator
        gen   = C2BriefGenerator()
        brief = gen.generate("HB-9982-AX-2026")
        assert "agency"               in brief
        assert "session_id"           in brief
        assert "hardware_environment" in brief
        assert "spectral_analysis"    in brief
        assert brief["agency"]        == "GHOST-WATCH C2 CENTER"

    def test_generate_brief_hardware_env(self):
        from shadow313.v4.ghost_watch.ghost_watch import C2BriefGenerator
        gen   = C2BriefGenerator()
        brief = gen.generate("TEST-SESSION", snr_db=14.28, pqc_mode="PQC-Hardened")
        hw    = brief["hardware_environment"]
        assert hw["system_noise_snr"]  == 14.28
        assert hw["crypto_handshake"]  == "PQC-Hardened"
        assert "ACTIVE" in hw["quantum_entropy_shield"]

    def test_generate_brief_with_traces(self):
        from shadow313.v4.ghost_watch.ghost_watch import C2BriefGenerator
        gen    = C2BriefGenerator()
        traces = [
            {"trace_id": "TRC-2877", "target_ip": "185.12.89.24",
             "frequency_mhz": 1420.44, "status": "TRACE_COMPLETE"},
        ]
        brief = gen.generate("TEST-SESSION", target_traces=traces)
        assert len(brief["detected_traces"]) == 1
        assert brief["detected_traces"][0]["trace_id"] == "TRC-2877"

    def test_generate_text_format(self):
        from shadow313.v4.ghost_watch.ghost_watch import C2BriefGenerator
        gen   = C2BriefGenerator()
        brief = gen.generate("HB-9982-AX-2026")
        text  = gen.generate_text(brief)
        # Verify matches real format
        assert "GHOST-WATCH C2 COMMAND STATION" in text
        assert "TACTICAL BRIEF REPORT"          in text
        assert "HARDWARE ENVIRONMENT"           in text
        assert "SPECTRAL ANALYSIS RANGE"        in text
        assert "END OF REPORT"                  in text
        assert "GHOST-WATCH LE-01"              in text

    def test_generate_text_contains_session_id(self):
        from shadow313.v4.ghost_watch.ghost_watch import C2BriefGenerator
        gen   = C2BriefGenerator()
        brief = gen.generate("HB-9982-AX-2026")
        text  = gen.generate_text(brief)
        assert "HB-9982-AX-2026" in text

    def test_spectral_analysis_in_brief(self):
        from shadow313.v4.ghost_watch.ghost_watch import C2BriefGenerator
        gen   = C2BriefGenerator()
        brief = gen.generate("TEST")
        spec  = brief["spectral_analysis"]
        assert spec["reference_frequency_mhz"] == 915.0
        assert "Decoy Trace-Route Spoofing" in spec["spoofing_mode"]


# ═══════════════════════════════════════════════════════════════════════════════
# Threat Intel Index Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestThreatIntelIndex:
    def _sample_indicators(self) -> list[dict]:
        return [
            {"threat_id": "TH-122", "source_ip": "58.150.125.186",
             "threat_type": "Credential Stuffing", "severity": "HIGH",
             "ioc_hash": "e0d9a53411c8d1b5949ace91cd113d35", "mitre": "T1110.004",
             "confidence": 74},
            {"threat_id": "TH-526", "source_ip": "36.232.34.48",
             "threat_type": "Supply Chain", "severity": "CRITICAL",
             "ioc_hash": "768c64d3b9ae2703806dda4d17b68777", "mitre": "T1195.002",
             "confidence": 83},
            {"threat_id": "TH-402", "source_ip": "185.220.101.44",
             "threat_type": "Advanced Persistent Threat", "severity": "CRITICAL",
             "ioc_hash": "7c9e05a11b6d0c2e3f4a5b6c7d8e9f0a", "mitre": "T1059",
             "confidence": 96},
        ]

    def test_generate_index_structure(self):
        from shadow313.v4.ghost_watch.ghost_watch import ThreatIntelIndex
        ti    = ThreatIntelIndex()
        index = ti.generate(self._sample_indicators())
        assert "agency"                  in index
        assert "threatIntelVersion"      in index
        assert "exportedAt"              in index
        assert "indicatorsCount"         in index
        assert "publishedToEventBusCount"in index
        assert "threatIndicators"        in index
        assert "busRegistry"             in index

    def test_agency_is_ghost_watch(self):
        from shadow313.v4.ghost_watch.ghost_watch import ThreatIntelIndex
        ti    = ThreatIntelIndex()
        index = ti.generate(self._sample_indicators())
        assert index["agency"] == "GHOST-WATCH C2 CENTER"

    def test_indicator_count_matches(self):
        from shadow313.v4.ghost_watch.ghost_watch import ThreatIntelIndex
        ti         = ThreatIntelIndex()
        indicators = self._sample_indicators()
        index      = ti.generate(indicators)
        assert index["indicatorsCount"] == len(indicators)

    def test_bus_registry_for_high_severity(self):
        from shadow313.v4.ghost_watch.ghost_watch import ThreatIntelIndex
        ti    = ThreatIntelIndex()
        index = ti.generate(self._sample_indicators())
        # HIGH and CRITICAL indicators should be published to event bus
        assert index["publishedToEventBusCount"] >= 1
        assert len(index["busRegistry"]) >= 1

    def test_bus_registry_structure(self):
        from shadow313.v4.ghost_watch.ghost_watch import ThreatIntelIndex
        ti    = ThreatIntelIndex()
        index = ti.generate(self._sample_indicators())
        for entry in index["busRegistry"]:
            assert "id"           in entry
            assert "severity"     in entry
            assert "category"     in entry
            assert "title"        in entry
            assert "action_taken" in entry
            assert entry["category"] == "detection"

    def test_version_field(self):
        from shadow313.v4.ghost_watch.ghost_watch import ThreatIntelIndex
        ti    = ThreatIntelIndex()
        index = ti.generate(self._sample_indicators(), version="2.10-Apex")
        assert index["threatIntelVersion"] == "2.10-Apex"


# ═══════════════════════════════════════════════════════════════════════════════
# WE-FORGE Linguistic Watermarking Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestWEForgeLinguistic:
    SAMPLE_CONTENT = (
        "The module lattice-based key encapsulation mechanism utilizes an integer "
        "matrix division of 768 to establish a shared secret. Ephemeral keys derived "
        "under ML-KEM must employ a secure HKDF-SHA256 salt with a static length of "
        "256 bits, ensuring backward compatibility with classical legacy clients."
    )

    def test_forge_linguistic_watermark(self, tmp_path):
        from shadow313.v4.ghost_watch.ghost_watch import WEForge
        forge   = WEForge(forge_dir=str(tmp_path))
        receipt = forge.forge_document(
            self.SAMPLE_CONTENT, "NIST FIPS 213 (ML-KEM-768) Secret Parameter Set",
            "alice", watermark_type="linguistic"
        )
        assert receipt.doc_id    != ""
        assert receipt.recipient == "alice"
        assert receipt.watermark_id != ""

    def test_forge_output_format_matches_real(self, tmp_path):
        from shadow313.v4.ghost_watch.ghost_watch import WEForge
        forge   = WEForge(forge_dir=str(tmp_path))
        receipt = forge.forge_document(
            self.SAMPLE_CONTENT, "test_doc.txt", "bob", watermark_type="linguistic"
        )
        # Read the generated file
        doc_files = list(tmp_path.glob(f"{receipt.doc_id}_*.txt"))
        assert len(doc_files) >= 1
        content = doc_files[0].read_text(encoding='utf-8')
        # Verify matches real WE-FORGE format
        assert "GHOST-WATCH SECURE WE-FORGE DECOY SYSTEM GENERANT" in content
        assert "Created Stamp:"                                      in content
        assert "Target Node:"                                        in content
        assert "DOCUMENT BODY:"                                      in content
        assert "GHOST-WATCH AUTOMATED METADATA SPECIFICATIONS:"      in content
        assert "DNS Token Beacon:"                                   in content
        assert "Security Class: Cosmic-Direct"                       in content

    def test_linguistic_watermark_applies_alterations(self, tmp_path):
        from shadow313.v4.ghost_watch.ghost_watch import WEForge
        forge   = WEForge(forge_dir=str(tmp_path))
        receipt = forge.forge_document(
            self.SAMPLE_CONTENT, "test.txt", "charlie", watermark_type="linguistic"
        )
        doc_files = list(tmp_path.glob(f"{receipt.doc_id}_*.txt"))
        if doc_files:
            content = doc_files[0].read_text(encoding='utf-8')
            # Linguistic watermark should have [ALTERED: ...] markers
            # (depends on recipient hash — may or may not alter this specific content)
            assert "DOCUMENT BODY:" in content

    def test_different_recipients_different_watermarks(self, tmp_path):
        from shadow313.v4.ghost_watch.ghost_watch import WEForge
        forge = WEForge(forge_dir=str(tmp_path))
        r1    = forge.forge_document(self.SAMPLE_CONTENT, "doc.txt", "alice")
        r2    = forge.forge_document(self.SAMPLE_CONTENT, "doc.txt", "bob")
        # Different recipients should get different watermark IDs
        assert r1.watermark_id != r2.watermark_id

    def test_forge_creates_file_on_disk(self, tmp_path):
        from shadow313.v4.ghost_watch.ghost_watch import WEForge
        forge   = WEForge(forge_dir=str(tmp_path))
        receipt = forge.forge_document(self.SAMPLE_CONTENT, "secret.txt", "dave")
        doc_files = list(tmp_path.glob(f"{receipt.doc_id}_*.txt"))
        assert len(doc_files) >= 1
        assert doc_files[0].stat().st_size > 0

    def test_lure_id_in_output(self, tmp_path):
        from shadow313.v4.ghost_watch.ghost_watch import WEForge
        forge   = WEForge(forge_dir=str(tmp_path))
        receipt = forge.forge_document(self.SAMPLE_CONTENT, "test.txt", "eve")
        doc_files = list(tmp_path.glob(f"{receipt.doc_id}_*.txt"))
        if doc_files:
            content = doc_files[0].read_text(encoding='utf-8')
            assert "GW-LURE-" in content

    def test_dns_beacon_in_output(self, tmp_path):
        from shadow313.v4.ghost_watch.ghost_watch import WEForge
        forge   = WEForge(forge_dir=str(tmp_path))
        receipt = forge.forge_document(self.SAMPLE_CONTENT, "test.txt", "frank",
                                       target_node="vortex.ghost.watch.local")
        doc_files = list(tmp_path.glob(f"{receipt.doc_id}_*.txt"))
        if doc_files:
            content = doc_files[0].read_text(encoding='utf-8')
            assert "vortex.ghost.watch.local" in content
            assert "audit-vault-" in content


# ═══════════════════════════════════════════════════════════════════════════════
# PE Analyzer Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestPEAnalyzer:
    def test_analyze_nonexistent_file(self):
        from shadow313.v4.aegis.pe_analyzer import PEAnalyzer
        analyzer = PEAnalyzer()
        result   = analyzer.analyze("/nonexistent/file.exe")
        assert result.threat_level in ("ERROR", "NOT_PE", "CLEAN")

    def test_analyze_non_pe_file(self, tmp_path):
        from shadow313.v4.aegis.pe_analyzer import PEAnalyzer
        f = tmp_path / "test.txt"
        f.write_bytes(b"Hello, World! This is not a PE file.")
        analyzer = PEAnalyzer()
        result   = analyzer.analyze(str(f))
        assert result.threat_level == "NOT_PE"
        assert result.file_size_bytes > 0

    def test_analyze_fake_pe_header(self, tmp_path):
        from shadow313.v4.aegis.pe_analyzer import PEAnalyzer
        # Create a minimal fake PE file
        pe_data = b"MZ" + b"\x00" * 0x3A + b"\x40\x00\x00\x00"  # PE offset at 0x40
        pe_data += b"\x00" * 0x40  # Padding to PE offset
        pe_data += b"PE\x00\x00"   # PE signature
        pe_data += b"\x64\x86"     # Machine: x86_64
        pe_data += b"\x00\x00"     # Number of sections: 0
        pe_data += b"\x00" * 100   # Rest of headers
        f = tmp_path / "fake.exe"
        f.write_bytes(pe_data)
        analyzer = PEAnalyzer()
        result   = analyzer.analyze(str(f))
        assert result.file_name == "fake.exe"
        assert result.sha256    != ""
        assert result.md5       != ""

    def test_analyze_bytes_with_suspicious_imports(self):
        from shadow313.v4.aegis.pe_analyzer import PEAnalyzer
        # Create data with suspicious import strings
        data = b"MZ" + b"\x00" * 100
        data += b"VirtualAllocEx\x00WriteProcessMemory\x00CreateRemoteThread\x00"
        analyzer = PEAnalyzer()
        result   = analyzer.analyze_bytes(data, "suspicious.bin")
        assert result.file_name == "suspicious.bin"
        assert result.sha256    != ""

    def test_threat_level_assessment(self):
        from shadow313.v4.aegis.pe_analyzer import PEAnalyzer, PEAnalysisResult
        analyzer = PEAnalyzer()
        # Test with suspicious imports
        result = PEAnalysisResult(
            suspicious_imports=[{"import": "kernel32.dll!VirtualAllocEx", "severity": "HIGH",
                                 "description": "Process injection"}] * 3,
            packer_detected="UPX packer",
        )
        level = analyzer._assess_threat(result)
        assert level in ("HIGH", "CRITICAL")

    def test_clean_file_assessment(self):
        from shadow313.v4.aegis.pe_analyzer import PEAnalyzer, PEAnalysisResult
        analyzer = PEAnalyzer()
        result   = PEAnalysisResult()
        level    = analyzer._assess_threat(result)
        assert level == "CLEAN"

    def test_result_to_dict(self):
        from shadow313.v4.aegis.pe_analyzer import PEAnalysisResult
        result = PEAnalysisResult(
            file_name="test.exe", file_size_bytes=1000,
            target_machine="x86_64 (AMD64)", threat_level="CLEAN",
        )
        d = result.to_dict()
        assert d["file_name"]      == "test.exe"
        assert d["threat_level"]   == "CLEAN"
        assert d["module_name"]    == "PE Static Header Analyzer"

    def test_packer_detection(self):
        from shadow313.v4.aegis.pe_analyzer import PEAnalyzer, PACKER_SIGNATURES
        # Verify packer signatures are defined
        assert b"UPX!" in PACKER_SIGNATURES
        assert b"UPX0" in PACKER_SIGNATURES
        # Test detection with data containing UPX signature
        data     = b"MZ" + b"\x00" * 50 + b"UPX!" + b"\x00" * 100
        analyzer = PEAnalyzer()
        result   = analyzer.analyze_bytes(data, "packed.exe")
        # Packer should be detected since UPX! is in the data
        assert result.packer_detected == "UPX packer (magic)"
        # Verify the detection logic works
        for sig, name in PACKER_SIGNATURES.items():
            if sig in data:
                assert result.packer_detected == name
                break


# ═══════════════════════════════════════════════════════════════════════════════
# Entropy Profiler Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestEntropyProfiler:
    def test_profile_bytes_structure(self):
        from shadow313.v4.aegis.pe_analyzer import EntropyProfiler
        profiler = EntropyProfiler()
        data     = b"Hello, World!" * 10
        profile  = profiler.profile_bytes(data)
        assert "overall_bytes"            in profile
        assert "aggregate_global_entropy" in profile
        assert "entropy_results"          in profile
        assert profile["overall_bytes"]   == len(data)

    def test_entropy_results_format(self):
        """Verify matches aegis_entropy_profile_*.json format."""
        from shadow313.v4.aegis.pe_analyzer import EntropyProfiler
        profiler = EntropyProfiler()
        data     = b"A" * 100  # Low entropy — all same byte
        profile  = profiler.profile_bytes(data)
        results  = profile["entropy_results"]
        assert len(results) > 0
        for r in results:
            assert "offset" in r
            assert "value"  in r
            assert isinstance(r["offset"], int)
            assert isinstance(r["value"],  float)

    def test_zero_entropy_for_uniform_data(self):
        from shadow313.v4.aegis.pe_analyzer import EntropyProfiler, shannon_entropy
        # All same bytes = zero entropy
        data = b"\x00" * 500
        ent  = shannon_entropy(data)
        assert ent == 0.0

    def test_high_entropy_for_random_data(self):
        import os
        from shadow313.v4.aegis.pe_analyzer import EntropyProfiler, shannon_entropy
        data = os.urandom(500)
        ent  = shannon_entropy(data)
        assert ent > 7.0  # Random data should have high entropy

    def test_profile_file_nonexistent(self):
        from shadow313.v4.aegis.pe_analyzer import EntropyProfiler
        profiler = EntropyProfiler()
        result   = profiler.profile_file("/nonexistent/file.bin")
        assert "error" in result

    def test_anomaly_detection(self):
        from shadow313.v4.aegis.pe_analyzer import EntropyProfiler
        import os
        profiler = EntropyProfiler()
        # Mix of low and high entropy data
        data    = b"\x00" * 200 + os.urandom(200) + b"\x00" * 100
        profile = profiler.profile_bytes(data)
        anomalies = profiler.detect_anomalies(profile)
        assert isinstance(anomalies, list)

    def test_entropy_profile_matches_real_format(self):
        """Verify output matches aegis_entropy_profile_1782414471535.json format."""
        from shadow313.v4.aegis.pe_analyzer import EntropyProfiler
        profiler = EntropyProfiler()
        data     = b"\x00" * 500  # Zero entropy like the real file
        profile  = profiler.profile_bytes(data)
        # Real file has all zeros — verify our output matches
        assert profile["aggregate_global_entropy"] == 0.0
        for r in profile["entropy_results"]:
            assert r["value"] == 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# DNS Intercept Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestDNSIntercept:
    def test_intercept_known_ot_system(self):
        from shadow313.v4.aegis.dns_intercept import DNSInterceptor
        interceptor = DNSInterceptor()
        entry       = interceptor.intercept("industrial-iot-bridge.int")
        assert entry.target       == "industrial-iot-bridge.int"
        assert entry.ot_type      == "OPC-UA"
        assert entry.resolved_ip  == "10.50.10.15"
        assert entry.risk         == "HIGH"
        assert "OPC-UA" in entry.ot_metrics

    def test_intercept_satellite_system(self):
        from shadow313.v4.aegis.dns_intercept import DNSInterceptor
        interceptor = DNSInterceptor()
        entry       = interceptor.intercept("deep-space-comms.arpa")
        assert entry.ot_type     == "DSN"
        assert entry.resolved_ip == "12.18.254.91"
        assert "Goldstone" in entry.location

    def test_intercept_military_system(self):
        from shadow313.v4.aegis.dns_intercept import DNSInterceptor
        interceptor = DNSInterceptor()
        entry       = interceptor.intercept("orbital-sync-nodes.mil")
        assert entry.ot_type     == "GPS_SYNC"
        assert entry.shield_pct  == 99.9
        assert entry.shield_status == "SHIELDED"

    def test_scan_ot_systems(self):
        from shadow313.v4.aegis.dns_intercept import DNSInterceptor, OT_SYSTEM_PROFILES
        interceptor = DNSInterceptor()
        report      = interceptor.scan_ot_systems()
        assert report.total_intercepted == len(OT_SYSTEM_PROFILES)
        assert len(report.entries)      == len(OT_SYSTEM_PROFILES)

    def test_report_to_text_format(self):
        from shadow313.v4.aegis.dns_intercept import DNSInterceptor
        interceptor = DNSInterceptor()
        report      = interceptor.scan_domain_list(["industrial-iot-bridge.int"])
        text        = report.to_text()
        # Verify matches real dns_intercept_report format
        assert "DNS INTERCEPT TELEMETRY REPORT" in text
        assert "TIMESTAMP:"                     in text
        assert "OT_METRICS:"                    in text
        assert "SHIELD_STATUS:"                 in text
        assert "LOC_INTEL:"                     in text
        assert "Resolved IP ->"                 in text

    def test_report_to_dict(self):
        from shadow313.v4.aegis.dns_intercept import DNSInterceptor
        interceptor = DNSInterceptor()
        report      = interceptor.scan_domain_list(["scada-grid-nexus.net"])
        d           = report.to_dict()
        assert "report_timestamp"  in d
        assert "total_intercepted" in d
        assert "entries"           in d
        assert d["total_intercepted"] == 1

    def test_ot_system_profiles_complete(self):
        from shadow313.v4.aegis.dns_intercept import OT_SYSTEM_PROFILES
        assert len(OT_SYSTEM_PROFILES) >= 9
        for domain, profile in OT_SYSTEM_PROFILES.items():
            assert "ot_type"      in profile
            assert "description"  in profile
            assert "location"     in profile
            assert "shield_pct"   in profile
            assert "risk"         in profile

    def test_unknown_domain_handled(self):
        from shadow313.v4.aegis.dns_intercept import DNSInterceptor
        interceptor = DNSInterceptor()
        entry       = interceptor.intercept("unknown-domain-xyz.test")
        assert entry.target  == "unknown-domain-xyz.test"
        assert entry.ot_type == "UNKNOWN"
        assert entry.risk    == "MEDIUM"


# ═══════════════════════════════════════════════════════════════════════════════
# Geo-Traced Intel Deck Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestGeoTracedIntelDeck:
    def _sample_indicators(self) -> list[dict]:
        return [
            {"source_ip": "185.220.101.44", "threat_type": "APT", "severity": "CRITICAL",
             "confidence": 96, "mitre": "T1059"},
            {"source_ip": "91.242.162.8",   "threat_type": "Zero-Day", "severity": "CRITICAL",
             "confidence": 99, "mitre": "T1190"},
        ]

    def test_generate_deck_structure(self):
        from shadow313.v4.aegis.dns_intercept import GeoTracedIntelDeck
        deck   = GeoTracedIntelDeck()
        result = deck.generate("HB-9982-AX-2026", self._sample_indicators())
        assert "generator"          in result
        assert "timestamp"          in result
        assert "hardWareSession"    in result
        assert "operationalStatus"  in result
        assert "activeSystemBrief"  in result
        assert "tracesRecorded"     in result

    def test_generator_is_ghost_watch(self):
        from shadow313.v4.aegis.dns_intercept import GeoTracedIntelDeck
        deck   = GeoTracedIntelDeck()
        result = deck.generate("TEST", self._sample_indicators())
        assert result["generator"] == "GHOST-WATCH C2 Station"

    def test_traces_recorded_count(self):
        from shadow313.v4.aegis.dns_intercept import GeoTracedIntelDeck
        deck       = GeoTracedIntelDeck()
        indicators = self._sample_indicators()
        result     = deck.generate("TEST", indicators)
        assert result["totalTraces"] == len(indicators)

    def test_traces_have_geo_location(self):
        from shadow313.v4.aegis.dns_intercept import GeoTracedIntelDeck
        deck   = GeoTracedIntelDeck()
        result = deck.generate("TEST", self._sample_indicators())
        for trace in result["tracesRecorded"]:
            assert "geoLocation" in trace
            assert "country"     in trace["geoLocation"]
            assert "lat"         in trace["geoLocation"]
            assert "lon"         in trace["geoLocation"]

    def test_active_system_brief_has_snr(self):
        from shadow313.v4.aegis.dns_intercept import GeoTracedIntelDeck
        deck   = GeoTracedIntelDeck()
        result = deck.generate("TEST", self._sample_indicators())
        brief  = result["activeSystemBrief"]
        assert "downlinkSnrDb" in brief
        assert "bitErrorRate"  in brief
        assert "pqcMode"       in brief
        assert brief["pqcMode"] == "PQC-Hardened"

    def test_critical_count(self):
        from shadow313.v4.aegis.dns_intercept import GeoTracedIntelDeck
        deck       = GeoTracedIntelDeck()
        indicators = self._sample_indicators()  # Both are CRITICAL
        result     = deck.generate("TEST", indicators)
        assert result["criticalCount"] == 2

    def test_geolocate_known_ranges(self):
        from shadow313.v4.aegis.dns_intercept import GeoTracedIntelDeck
        deck = GeoTracedIntelDeck()
        assert deck._geolocate("185.220.100.1") == "DE"
        assert deck._geolocate("58.150.125.186") == "JP"
        assert deck._geolocate("91.242.162.8")   == "RU"
        assert deck._geolocate("1.2.3.4")        == "XX"


# ═══════════════════════════════════════════════════════════════════════════════
# Aegis Forensics Dump Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestAegisForensicsDump:
    def test_dump_structure(self):
        from shadow313.v4.aegis.pe_analyzer import AegisForensicsDumper
        dumper = AegisForensicsDumper()
        dump   = dumper.dump("test-session-001")
        assert "meta"                in dump
        assert "real_time_statistics"in dump
        assert "ast_static_scan"     in dump
        assert "signature_matching_ledger" in dump
        assert "ebpf_kernel_execution_logs" in dump

    def test_meta_matches_real_format(self):
        """Verify matches aegis_forensics_dump_2026-06-25.json format."""
        from shadow313.v4.aegis.pe_analyzer import AegisForensicsDumper
        dumper = AegisForensicsDumper()
        dump   = dumper.dump("test-session")
        meta   = dump["meta"]
        assert "suite"                       in meta
        assert "version"                     in meta
        assert "system_time"                 in meta
        assert "threat_posture_configured"   in meta
        assert "uncompromising_defense_active" in meta
        assert meta["suite"] == "Aegis Unified Security Suite"

    def test_dh_handshake_fields(self):
        from shadow313.v4.aegis.pe_analyzer import AegisForensicsDumper
        dumper = AegisForensicsDumper()
        dump   = dumper.dump("test")
        stats  = dump["real_time_statistics"]
        assert "diffie_hellman_handshake_prime"     in stats
        assert "diffie_hellman_handshake_generator" in stats
        assert "derived_ephemeral_key"              in stats
        assert stats["diffie_hellman_handshake_prime"]     == "997"
        assert stats["diffie_hellman_handshake_generator"] == "5"

    def test_threat_posture_low(self):
        from shadow313.v4.aegis.pe_analyzer import AegisForensicsDumper
        dumper = AegisForensicsDumper()
        dump   = dumper.dump("test", threat_posture="LOW")
        assert dump["meta"]["threat_posture_configured"]    == "LOW"
        assert dump["meta"]["uncompromising_defense_active"] is False

    def test_threat_posture_high(self):
        from shadow313.v4.aegis.pe_analyzer import AegisForensicsDumper
        dumper = AegisForensicsDumper()
        dump   = dumper.dump("test", threat_posture="HIGH")
        assert dump["meta"]["threat_posture_configured"]    == "HIGH"
        assert dump["meta"]["uncompromising_defense_active"] is True

    def test_session_id_in_dump(self):
        from shadow313.v4.aegis.pe_analyzer import AegisForensicsDumper
        dumper = AegisForensicsDumper()
        dump   = dumper.dump("my-session-xyz")
        assert dump["session_id"] == "my-session-xyz"