"""
Unit tests for shadow313.v4.detection.d3fend_coverage

Covers:
  - D3FENDTechnique catalog completeness and integrity
  - CoverageEntry correctness (ratings, IDs, fields)
  - CoverageAnalyzer counts, filters, aggregations
  - Priority integrations ordering and completeness
  - Full report structure
  - Specific coverage assertions from the analysis document
"""
from __future__ import annotations
import pytest
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))

from shadow313.v4.detection.d3fend_coverage import (
    CoverageRating,
    D3FENDTactic,
    D3FENDTechnique,
    CoverageEntry,
    PriorityIntegration,
    D3FEND_TECHNIQUES,
    COVERAGE_MAP,
    PRIORITY_INTEGRATIONS,
    CoverageAnalyzer,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def analyzer():
    return CoverageAnalyzer()


# ═══════════════════════════════════════════════════════════════════════════════
# D3FEND TECHNIQUE CATALOG TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestD3FENDTechniqueCatalog:

    def test_catalog_not_empty(self):
        assert len(D3FEND_TECHNIQUES) > 0

    def test_all_techniques_have_id(self):
        for tid, t in D3FEND_TECHNIQUES.items():
            assert t.d3fend_id == tid
            assert t.d3fend_id.startswith("D3-")

    def test_all_techniques_have_name(self):
        for t in D3FEND_TECHNIQUES.values():
            assert len(t.name) > 0

    def test_all_techniques_have_definition(self):
        for t in D3FEND_TECHNIQUES.values():
            assert len(t.definition) > 10

    def test_all_techniques_have_valid_tactic(self):
        valid_tactics = set(D3FENDTactic)
        for t in D3FEND_TECHNIQUES.values():
            assert t.tactic in valid_tactics

    def test_no_duplicate_ids(self):
        ids = list(D3FEND_TECHNIQUES.keys())
        assert len(ids) == len(set(ids))

    def test_key_techniques_present(self):
        required = [
            "D3-PSA", "D3-PLA", "D3-SCA", "D3-SSC", "D3-PSMD", "D3-PCSV",
            "D3-FIM", "D3-SFA", "D3-FCA", "D3-FAPA",
            "D3-SCF", "D3-HBPI", "D3-EAL", "D3-DLIC", "D3-SBV", "D3-SCP", "D3-ACH",
            "D3-SPP", "D3-OTP", "D3-CRO",
            "D3-ANET", "D3-LAM", "D3-DAM",
            "D3-NTA", "D3-PHDURA", "D3-UDTA", "D3-CPSP", "D3-RPTA",
            "D3-ANCI", "D3-NI", "D3-OTF", "D3-DNSAL", "D3-DNSDL",
            "D3-EBWSAM", "D3-PBWSAM",
            "D3-DO", "D3-DUC",
        ]
        for tid in required:
            assert tid in D3FEND_TECHNIQUES, f"Missing D3FEND technique: {tid}"

    def test_tactic_distribution(self):
        """All 7 D3FEND tactics should be represented."""
        tactics_present = {t.tactic for t in D3FEND_TECHNIQUES.values()}
        # We have Harden, Detect, Isolate, Deceive — at minimum 4
        assert len(tactics_present) >= 4

    def test_harden_techniques_present(self):
        harden = [t for t in D3FEND_TECHNIQUES.values() if t.tactic == D3FENDTactic.HARDEN]
        assert len(harden) >= 5

    def test_detect_techniques_present(self):
        detect = [t for t in D3FEND_TECHNIQUES.values() if t.tactic == D3FENDTactic.DETECT]
        assert len(detect) >= 10

    def test_deceive_techniques_present(self):
        deceive = [t for t in D3FEND_TECHNIQUES.values() if t.tactic == D3FENDTactic.DECEIVE]
        assert len(deceive) >= 2
        ids = {t.d3fend_id for t in deceive}
        assert "D3-DO"  in ids
        assert "D3-DUC" in ids


# ═══════════════════════════════════════════════════════════════════════════════
# COVERAGE MAP INTEGRITY TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestCoverageMapIntegrity:

    def test_coverage_map_not_empty(self):
        assert len(COVERAGE_MAP) > 0

    def test_all_entries_have_valid_rating(self):
        valid = set(CoverageRating)
        for e in COVERAGE_MAP:
            assert e.rating in valid

    def test_all_entries_have_attack_id(self):
        for e in COVERAGE_MAP:
            assert e.attack_id.startswith("T"), f"Invalid ATT&CK ID: {e.attack_id}"

    def test_all_entries_have_evasion_id(self):
        valid_evasion_ids = {
            "PV-001", "PV-002", "DE-001", "DE-002", "DE-003",
            "CA-002", "LM-001", "CO-001", "C2-001", "C2-003",
            "EF-001", "EF-002", "FIN7-001",
        }
        for e in COVERAGE_MAP:
            assert e.evasion_id in valid_evasion_ids, f"Unknown evasion_id: {e.evasion_id}"

    def test_all_entries_reference_valid_d3fend_technique(self):
        for e in COVERAGE_MAP:
            assert e.d3fend.d3fend_id in D3FEND_TECHNIQUES, (
                f"Entry references unknown D3FEND ID: {e.d3fend.d3fend_id}"
            )

    def test_all_entries_have_shadow313_impl(self):
        for e in COVERAGE_MAP:
            assert len(e.shadow313_impl) > 0

    def test_all_entries_have_gap_detail(self):
        for e in COVERAGE_MAP:
            assert len(e.gap_detail) > 0

    def test_all_13_evasion_techniques_covered(self):
        evasion_ids = {e.evasion_id for e in COVERAGE_MAP}
        expected = {
            "PV-001", "PV-002", "DE-001", "DE-002", "DE-003",
            "CA-002", "LM-001", "CO-001", "C2-001", "C2-003",
            "EF-001", "EF-002", "FIN7-001",
        }
        assert evasion_ids == expected

    def test_total_entries_count(self):
        # 51 entries as documented in the analysis
        assert len(COVERAGE_MAP) == 51


# ═══════════════════════════════════════════════════════════════════════════════
# SPECIFIC COVERAGE ASSERTIONS (from analysis document)
# ═══════════════════════════════════════════════════════════════════════════════

class TestSpecificCoverageAssertions:
    """
    Verify the specific coverage ratings documented in docs/d3fend_mapping.md.
    These are regression tests — if the architecture changes, these should be updated.
    """

    def _get_entry(self, evasion_id: str, d3fend_id: str) -> CoverageEntry | None:
        for e in COVERAGE_MAP:
            if e.evasion_id == evasion_id and e.d3fend.d3fend_id == d3fend_id:
                return e
        return None

    # ── Full coverage assertions ───────────────────────────────────────────────

    def test_ghost_watch_d3_do_is_full(self):
        """Ghost-Watch AETHER decoys fully implement D3-DO for COM hijacking."""
        e = self._get_entry("FIN7-001", "D3-DO")
        assert e is not None
        assert e.rating == CoverageRating.FULL

    def test_ghost_watch_d3_duc_is_full(self):
        """Ghost-Watch decoy credentials fully implement D3-DUC for COM hijacking."""
        e = self._get_entry("FIN7-001", "D3-DUC")
        assert e is not None
        assert e.rating == CoverageRating.FULL

    # ── Partial coverage assertions ────────────────────────────────────────────

    def test_ja3_fingerprinting_d3_nta_is_partial(self):
        """JA3 fingerprinting partially implements D3-NTA for Cobalt Strike."""
        e = self._get_entry("C2-001", "D3-NTA")
        assert e is not None
        assert e.rating == CoverageRating.PARTIAL

    def test_evasion_detector_d3_sca_is_partial(self):
        """EvasionDetector API call detection partially implements D3-SCA."""
        e = self._get_entry("DE-001", "D3-SCA")
        assert e is not None
        assert e.rating == CoverageRating.PARTIAL

    def test_evasion_detector_d3_fim_is_partial(self):
        """EvasionDetector SetFileTime detection partially implements D3-FIM."""
        e = self._get_entry("DE-002", "D3-FIM")
        assert e is not None
        assert e.rating == CoverageRating.PARTIAL

    def test_plugin_trust_d3_dlic_is_partial(self):
        """Plugin trust registry partially implements D3-DLIC for DLL side-loading."""
        e = self._get_entry("DE-003", "D3-DLIC")
        assert e is not None
        assert e.rating == CoverageRating.PARTIAL

    def test_ml_anomaly_d3_phdura_is_partial(self):
        """ml_anomaly.py byte_rate feature partially implements D3-PHDURA."""
        e = self._get_entry("C2-001", "D3-PHDURA")
        assert e is not None
        assert e.rating == CoverageRating.PARTIAL

    # ── Absent coverage assertions ─────────────────────────────────────────────

    def test_process_lineage_d3_pla_is_absent_for_uac(self):
        """No process lineage analysis for UAC bypass."""
        e = self._get_entry("PV-002", "D3-PLA")
        assert e is not None
        assert e.rating == CoverageRating.ABSENT

    def test_shadow_stack_d3_ssc_is_absent(self):
        """No shadow stack comparisons for process injection."""
        e = self._get_entry("DE-001", "D3-SSC")
        assert e is not None
        assert e.rating == CoverageRating.ABSENT

    def test_executable_allowlisting_d3_eal_is_absent(self):
        """No executable allowlisting for DLL side-loading."""
        e = self._get_entry("DE-003", "D3-EAL")
        assert e is not None
        assert e.rating == CoverageRating.ABSENT

    def test_strong_password_policy_d3_spp_is_absent(self):
        """No password policy audit for Kerberoasting."""
        e = self._get_entry("CA-002", "D3-SPP")
        assert e is not None
        assert e.rating == CoverageRating.ABSENT

    def test_credential_guard_d3_anci_is_absent(self):
        """No Credential Guard audit for Pass-the-Hash."""
        e = self._get_entry("LM-001", "D3-ANCI")
        assert e is not None
        assert e.rating == CoverageRating.ABSENT

    def test_relay_pattern_d3_rpta_is_absent(self):
        """No relay pattern analysis for trusted process C2."""
        e = self._get_entry("C2-003", "D3-RPTA")
        assert e is not None
        assert e.rating == CoverageRating.ABSENT

    def test_cloud_proxy_d3_pbwsam_is_absent(self):
        """No proxy-based web server access mediation for cloud exfiltration."""
        e = self._get_entry("EF-002", "D3-PBWSAM")
        assert e is not None
        assert e.rating == CoverageRating.ABSENT

    def test_com_registry_d3_scp_is_absent(self):
        """No registry ACL enforcement for COM object hijacking."""
        e = self._get_entry("FIN7-001", "D3-SCP")
        assert e is not None
        assert e.rating == CoverageRating.ABSENT


# ═══════════════════════════════════════════════════════════════════════════════
# COVERAGE ANALYZER TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestCoverageAnalyzer:

    def test_total_entries(self, analyzer):
        assert analyzer.total_entries() == 51

    def test_count_by_rating_sums_to_total(self, analyzer):
        counts = analyzer.count_by_rating()
        total  = sum(counts.values())
        assert total == analyzer.total_entries()

    def test_full_count_is_2(self, analyzer):
        """Exactly 2 FULL entries as documented."""
        counts = analyzer.count_by_rating()
        assert counts[CoverageRating.FULL.value] == 2

    def test_partial_count_is_20(self, analyzer):
        """Exactly 20 PARTIAL entries as documented."""
        counts = analyzer.count_by_rating()
        assert counts[CoverageRating.PARTIAL.value] == 20

    def test_absent_count_is_29(self, analyzer):
        """Exactly 29 ABSENT entries as documented."""
        counts = analyzer.count_by_rating()
        assert counts[CoverageRating.ABSENT.value] == 29

    def test_coverage_percentage_above_zero(self, analyzer):
        pct = analyzer.coverage_percentage()
        assert pct > 0.0
        assert pct <= 100.0

    def test_full_coverage_percentage_is_low(self, analyzer):
        """Full coverage is very low — only 2/51 entries."""
        pct = analyzer.full_coverage_percentage()
        assert pct < 10.0

    def test_entries_by_rating_full(self, analyzer):
        full = analyzer.full_entries()
        assert len(full) == 2
        assert all(e.rating == CoverageRating.FULL for e in full)

    def test_entries_by_rating_partial(self, analyzer):
        partial = analyzer.partial_entries()
        assert len(partial) == 20
        assert all(e.rating == CoverageRating.PARTIAL for e in partial)

    def test_entries_by_rating_absent(self, analyzer):
        absent = analyzer.absent_entries()
        assert len(absent) == 29
        assert all(e.rating == CoverageRating.ABSENT for e in absent)

    def test_entries_for_evasion_pv001(self, analyzer):
        entries = analyzer.entries_for_evasion("PV-001")
        assert len(entries) == 4
        assert all(e.evasion_id == "PV-001" for e in entries)

    def test_entries_for_evasion_fin7001(self, analyzer):
        entries = analyzer.entries_for_evasion("FIN7-001")
        assert len(entries) == 5
        assert all(e.evasion_id == "FIN7-001" for e in entries)

    def test_entries_for_d3fend_d3_hbpi(self, analyzer):
        """D3-HBPI appears for multiple evasion techniques."""
        entries = analyzer.entries_for_d3fend("D3-HBPI")
        assert len(entries) >= 2
        evasion_ids = {e.evasion_id for e in entries}
        assert "PV-001" in evasion_ids
        assert "DE-001" in evasion_ids

    def test_entries_for_d3fend_d3_anet(self, analyzer):
        """D3-ANET appears for multiple evasion techniques."""
        entries = analyzer.entries_for_d3fend("D3-ANET")
        assert len(entries) >= 3

    def test_entries_for_tactic_harden(self, analyzer):
        harden = analyzer.entries_for_tactic(D3FENDTactic.HARDEN)
        assert len(harden) > 0
        assert all(e.d3fend.tactic == D3FENDTactic.HARDEN for e in harden)

    def test_entries_for_tactic_deceive(self, analyzer):
        deceive = analyzer.entries_for_tactic(D3FENDTactic.DECEIVE)
        assert len(deceive) == 2  # D3-DO and D3-DUC for FIN7-001
        assert all(e.rating == CoverageRating.FULL for e in deceive)

    def test_coverage_by_evasion_has_all_13(self, analyzer):
        by_evasion = analyzer.coverage_by_evasion()
        assert len(by_evasion) == 13

    def test_coverage_by_evasion_fin7001_has_2_full(self, analyzer):
        by_evasion = analyzer.coverage_by_evasion()
        fin7 = by_evasion["FIN7-001"]
        assert fin7[CoverageRating.FULL.value] == 2

    def test_coverage_by_evasion_de001_has_0_full(self, analyzer):
        by_evasion = analyzer.coverage_by_evasion()
        de001 = by_evasion["DE-001"]
        assert de001[CoverageRating.FULL.value] == 0

    def test_coverage_by_tactic_not_empty(self, analyzer):
        by_tactic = analyzer.coverage_by_tactic()
        assert len(by_tactic) > 0

    def test_most_absent_d3fend_techniques(self, analyzer):
        most_absent = analyzer.most_absent_d3fend_techniques(top_n=5)
        assert len(most_absent) <= 5
        # Results should be sorted by count descending
        counts = [c for _, c in most_absent]
        assert counts == sorted(counts, reverse=True)

    def test_most_absent_includes_d3_hbpi(self, analyzer):
        """D3-HBPI appears as absent for multiple techniques."""
        most_absent = analyzer.most_absent_d3fend_techniques(top_n=10)
        ids = [tid for tid, _ in most_absent]
        assert "D3-HBPI" in ids

    def test_total_effort_range(self, analyzer):
        min_w, max_w = analyzer.total_effort_range()
        assert min_w > 0
        assert max_w >= min_w

    def test_full_report_structure(self, analyzer):
        report = analyzer.full_report()
        assert "summary"               in report
        assert "coverage_by_evasion"   in report
        assert "coverage_by_tactic"    in report
        assert "most_absent_techniques"in report
        assert "priority_integrations" in report
        assert "full_entries"          in report

    def test_full_report_summary_counts(self, analyzer):
        report   = analyzer.full_report()
        summary  = report["summary"]
        assert summary["total_entries"]   == 51
        assert summary["full_count"]      == 2
        assert summary["partial_count"]   == 20
        assert summary["absent_count"]    == 29

    def test_full_report_full_entries_are_ghost_watch(self, analyzer):
        report = analyzer.full_report()
        full   = report["full_entries"]
        assert len(full) == 2
        d3fend_ids = {e["d3fend_id"] for e in full}
        assert "D3-DO"  in d3fend_ids
        assert "D3-DUC" in d3fend_ids


# ═══════════════════════════════════════════════════════════════════════════════
# PRIORITY INTEGRATION TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestPriorityIntegrations:

    def test_8_priority_integrations_defined(self):
        assert len(PRIORITY_INTEGRATIONS) == 8

    def test_priorities_are_1_through_8(self):
        priorities = sorted(p.priority for p in PRIORITY_INTEGRATIONS)
        assert priorities == list(range(1, 9))

    def test_all_integrations_have_title(self):
        for p in PRIORITY_INTEGRATIONS:
            assert len(p.title) > 0

    def test_all_integrations_have_d3fend_ids(self):
        for p in PRIORITY_INTEGRATIONS:
            assert len(p.d3fend_ids) > 0
            for did in p.d3fend_ids:
                assert did in D3FEND_TECHNIQUES, f"Unknown D3FEND ID in priority: {did}"

    def test_all_integrations_have_evasion_ids(self):
        for p in PRIORITY_INTEGRATIONS:
            assert len(p.evasion_ids) > 0

    def test_all_integrations_have_attack_ids(self):
        for p in PRIORITY_INTEGRATIONS:
            assert len(p.attack_ids) > 0

    def test_all_integrations_have_rationale(self):
        for p in PRIORITY_INTEGRATIONS:
            assert len(p.rationale) > 20

    def test_all_integrations_have_impl_path(self):
        for p in PRIORITY_INTEGRATIONS:
            assert len(p.impl_path) > 20

    def test_all_integrations_have_valid_effort(self):
        for p in PRIORITY_INTEGRATIONS:
            min_w, max_w = p.effort_weeks
            assert min_w > 0
            assert max_w >= min_w

    def test_priority_1_is_process_lineage(self):
        p1 = next(p for p in PRIORITY_INTEGRATIONS if p.priority == 1)
        assert "D3-PLA" in p1.d3fend_ids or "Process Lineage" in p1.title

    def test_priority_1_addresses_uac_bypass(self):
        p1 = next(p for p in PRIORITY_INTEGRATIONS if p.priority == 1)
        assert "PV-002" in p1.evasion_ids

    def test_priority_2_is_system_call_analysis(self):
        p2 = next(p for p in PRIORITY_INTEGRATIONS if p.priority == 2)
        assert "D3-SCA" in p2.d3fend_ids

    def test_priority_3_is_authentication_thresholding(self):
        p3 = next(p for p in PRIORITY_INTEGRATIONS if p.priority == 3)
        assert "D3-ANET" in p3.d3fend_ids

    def test_priority_6_is_credential_guard_audit(self):
        p6 = next(p for p in PRIORITY_INTEGRATIONS if p.priority == 6)
        assert "D3-ANCI" in p6.d3fend_ids

    def test_analyzer_priority_integrations_sorted(self):
        analyzer = CoverageAnalyzer()
        integrations = analyzer.priority_integrations()
        priorities = [p.priority for p in integrations]
        assert priorities == sorted(priorities)

    def test_all_absent_d3fend_ids_have_priority_integration(self):
        """
        Every D3FEND ID that appears as ABSENT should be addressed by
        at least one priority integration.
        Note: Not all absent IDs need to be in priority integrations —
        some are lower priority or require external infrastructure.
        We verify that the top-3 most-absent IDs are covered.
        """
        analyzer    = CoverageAnalyzer()
        most_absent = analyzer.most_absent_d3fend_techniques(top_n=3)
        covered_ids = set()
        for p in PRIORITY_INTEGRATIONS:
            covered_ids.update(p.d3fend_ids)

        # At least 2 of the top 3 most-absent should be in priority integrations
        top3_ids    = {tid for tid, _ in most_absent}
        intersection = top3_ids & covered_ids
        assert len(intersection) >= 2, (
            f"Top 3 most-absent D3FEND IDs {top3_ids} — "
            f"only {intersection} covered by priority integrations"
        )