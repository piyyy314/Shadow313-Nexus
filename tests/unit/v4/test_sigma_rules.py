"""
tests/unit/v4/test_sigma_rules.py
Tests for Shadow313 NEXUS Sigma Rules Registry
NEXUS-REF-2026-001 | 15 Sigma rules | SPL/KQL/Elastic/YARA
"""
from __future__ import annotations
import pytest

from shadow313.v4.detection.sigma_rules import (
    SIGMA_RULES, SPL_QUERIES, KQL_QUERIES, ELASTIC_QUERIES, YARA_RULES,
    get_rule_by_id, get_rules_by_technique, get_rules_by_tactic,
    get_critical_rules, export_sigma_yaml,
)
from shadow313.v4.detection.sigma_rules.rules import COVERAGE_SUMMARY


# ── Rule count ────────────────────────────────────────────────────────────────

class TestRuleCounts:
    def test_sigma_rules_count(self):
        assert len(SIGMA_RULES) == 15

    def test_spl_queries_count(self):
        assert len(SPL_QUERIES) == 6

    def test_kql_queries_count(self):
        assert len(KQL_QUERIES) == 5

    def test_elastic_queries_count(self):
        assert len(ELASTIC_QUERIES) == 2

    def test_yara_rules_count(self):
        assert len(YARA_RULES) == 3

    def test_coverage_summary_correct(self):
        assert COVERAGE_SUMMARY["total_sigma_rules"]   == 15
        assert COVERAGE_SUMMARY["total_spl_queries"]   == 6
        assert COVERAGE_SUMMARY["total_kql_queries"]   == 5
        assert COVERAGE_SUMMARY["total_yara_rules"]    == 3


# ── Sigma rule structure ──────────────────────────────────────────────────────

class TestSigmaRuleStructure:
    def test_all_rules_have_required_fields(self):
        required = ["id", "display_id", "title", "technique", "tactic",
                    "level", "status", "tags", "description", "sigma_yaml"]
        for rule in SIGMA_RULES:
            for field in required:
                assert field in rule, f"{rule['id']} missing field: {field}"

    def test_all_rules_production_status(self):
        for rule in SIGMA_RULES:
            assert rule["status"] == "production", f"{rule['id']} not production"

    def test_all_rules_have_valid_level(self):
        valid_levels = {"critical", "high", "medium", "low"}
        for rule in SIGMA_RULES:
            assert rule["level"] in valid_levels

    def test_all_rules_have_attck_technique(self):
        for rule in SIGMA_RULES:
            assert rule["technique"].startswith("T"), f"{rule['id']} invalid technique"

    def test_all_rules_have_sigma_yaml(self):
        for rule in SIGMA_RULES:
            assert len(rule["sigma_yaml"]) > 100, f"{rule['id']} sigma_yaml too short"
            assert "detection:" in rule["sigma_yaml"]
            assert "logsource:" in rule["sigma_yaml"]

    def test_all_rules_have_nexus_tag(self):
        for rule in SIGMA_RULES:
            nexus_tags = [t for t in rule["tags"] if t.startswith("nexus.")]
            assert len(nexus_tags) >= 1, f"{rule['id']} missing nexus tag"

    def test_tpr_values_valid(self):
        for rule in SIGMA_RULES:
            if "tpr" in rule:
                assert 0.0 <= rule["tpr"] <= 1.0


# ── Specific rule validation ──────────────────────────────────────────────────

class TestSpecificRules:
    def test_sig001_lsass_dump(self):
        rule = get_rule_by_id("nexus-sig-001")
        assert rule is not None
        assert rule["technique"] == "T1003.001"
        assert rule["level"] == "critical"
        assert "lsass" in rule["sigma_yaml"].lower()
        assert "0x1010" in rule["sigma_yaml"]

    def test_sig002_kerberoasting(self):
        rule = get_rule_by_id("nexus-sig-002")
        assert rule is not None
        assert rule["technique"] == "T1558.003"
        assert "4769" in rule["sigma_yaml"]
        assert "0x17" in rule["sigma_yaml"]

    def test_sig003_password_spraying(self):
        rule = get_rule_by_id("nexus-sig-003")
        assert rule is not None
        assert rule["technique"] == "T1110.003"
        assert "4625" in rule["sigma_yaml"]

    def test_sig004_dcsync(self):
        rule = get_rule_by_id("nexus-sig-004")
        assert rule is not None
        assert rule["technique"] == "T1003.006"
        assert rule["level"] == "critical"
        assert "1131f6aa" in rule["sigma_yaml"]

    def test_sig005_encoded_powershell(self):
        rule = get_rule_by_id("nexus-sig-005")
        assert rule is not None
        assert rule["technique"] == "T1059.001"
        assert "-EncodedCommand" in rule["sigma_yaml"]

    def test_sig007_vss_deletion(self):
        rule = get_rule_by_id("nexus-sig-007")
        assert rule is not None
        assert rule["technique"] == "T1490"
        assert rule["level"] == "critical"
        assert "vssadmin" in rule["sigma_yaml"]
        assert "shadowcopy" in rule["sigma_yaml"].lower()

    def test_sig008_lolbas(self):
        rule = get_rule_by_id("nexus-sig-008")
        assert rule is not None
        assert rule["technique"] == "T1218"
        assert "certutil" in rule["sigma_yaml"]
        assert "mshta" in rule["sigma_yaml"]

    def test_sig010_pass_the_hash(self):
        rule = get_rule_by_id("nexus-sig-010")
        assert rule is not None
        assert rule["technique"] == "T1550.002"
        assert rule["level"] == "critical"
        assert "NTLM" in rule["sigma_yaml"]
        assert "KeyLength" in rule["sigma_yaml"]

    def test_sig011_dns_tunneling(self):
        rule = get_rule_by_id("nexus-sig-011")
        assert rule is not None
        assert rule["technique"] == "T1572"
        assert "cloudfront" in rule["sigma_yaml"]

    def test_sig014_createremotethread(self):
        rule = get_rule_by_id("nexus-sig-014")
        assert rule is not None
        assert rule["technique"] == "T1055.001"
        assert rule["level"] == "critical"
        assert "lsass" in rule["sigma_yaml"].lower()

    def test_sig015_uac_bypass(self):
        rule = get_rule_by_id("nexus-sig-015")
        assert rule is not None
        assert rule["technique"] == "T1548.002"
        assert "fodhelper" in rule["sigma_yaml"]


# ── Query functions ───────────────────────────────────────────────────────────

class TestQueryFunctions:
    def test_get_rule_by_id_lowercase(self):
        rule = get_rule_by_id("nexus-sig-001")
        assert rule is not None
        assert rule["id"] == "nexus-sig-001"

    def test_get_rule_by_id_uppercase(self):
        rule = get_rule_by_id("NEXUS-SIG-001")
        assert rule is not None

    def test_get_rule_by_id_not_found(self):
        rule = get_rule_by_id("nexus-sig-999")
        assert rule is None

    def test_get_rules_by_technique_t1003(self):
        rules = get_rules_by_technique("T1003")
        assert len(rules) >= 2  # SIG-001 (T1003.001) and SIG-004 (T1003.006)

    def test_get_rules_by_technique_t1059(self):
        rules = get_rules_by_technique("T1059")
        assert len(rules) >= 1

    def test_get_rules_by_tactic_credential_access(self):
        rules = get_rules_by_tactic("credential_access")
        assert len(rules) == 4  # SIG-001, 002, 003, 004

    def test_get_rules_by_tactic_impact(self):
        rules = get_rules_by_tactic("impact")
        assert len(rules) >= 1

    def test_get_critical_rules(self):
        critical = get_critical_rules()
        assert len(critical) >= 4
        for rule in critical:
            assert rule["level"] == "critical"

    def test_export_sigma_yaml(self):
        yaml = export_sigma_yaml("nexus-sig-001")
        assert yaml is not None
        assert "lsass" in yaml.lower()
        assert "detection:" in yaml

    def test_export_sigma_yaml_not_found(self):
        yaml = export_sigma_yaml("nexus-sig-999")
        assert yaml is None


# ── SPL queries ───────────────────────────────────────────────────────────────

class TestSPLQueries:
    def test_spl_queries_have_required_fields(self):
        for q in SPL_QUERIES:
            assert "id"        in q
            assert "title"     in q
            assert "technique" in q
            assert "query"     in q

    def test_spl001_lsass_query(self):
        q = next(q for q in SPL_QUERIES if q["id"] == "SPL-001")
        assert "lsass" in q["query"].lower()
        assert "GrantedAccess" in q["query"]

    def test_spl005_ransomware_query(self):
        q = next(q for q in SPL_QUERIES if q["id"] == "SPL-005")
        assert "vssadmin" in q["query"]
        assert "RANSOMWARE" in q["query"]

    def test_spl006_kerberoasting_query(self):
        q = next(q for q in SPL_QUERIES if q["id"] == "SPL-006")
        assert "4769" in q["query"]
        assert "0x17" in q["query"]


# ── KQL queries ───────────────────────────────────────────────────────────────

class TestKQLQueries:
    def test_kql_queries_have_required_fields(self):
        for q in KQL_QUERIES:
            assert "id"        in q
            assert "title"     in q
            assert "technique" in q
            assert "query"     in q

    def test_kql001_lsass(self):
        q = next(q for q in KQL_QUERIES if q["id"] == "KQL-001")
        assert "lsass" in q["query"].lower()
        assert "DeviceProcessEvents" in q["query"]

    def test_kql004_vss_deletion(self):
        q = next(q for q in KQL_QUERIES if q["id"] == "KQL-004")
        assert "vssadmin" in q["query"]
        assert "RANSOMWARE" in q["query"]

    def test_kql005_pass_the_hash(self):
        q = next(q for q in KQL_QUERIES if q["id"] == "KQL-005")
        assert "NTLM" in q["query"]
        assert "KeyLength" in q["query"]


# ── YARA rules ────────────────────────────────────────────────────────────────

class TestYARARules:
    def test_yara_rules_have_required_fields(self):
        for y in YARA_RULES:
            assert "id"           in y
            assert "title"        in y
            assert "technique"    in y
            assert "threat_level" in y
            assert "rule"         in y

    def test_yara001_mimikatz(self):
        y = next(y for y in YARA_RULES if y["id"] == "YARA-001")
        assert "mimikatz" in y["rule"].lower()
        assert "sekurlsa" in y["rule"]
        assert y["threat_level"] == 10

    def test_yara002_ransomware(self):
        y = next(y for y in YARA_RULES if y["id"] == "YARA-002")
        assert "encrypted" in y["rule"].lower()
        assert "chacha" in y["rule"].lower()
        assert y["threat_level"] == 10

    def test_yara003_dns_tunnel(self):
        y = next(y for y in YARA_RULES if y["id"] == "YARA-003")
        assert "dnscat" in y["rule"].lower()
        assert "blindingcan" in y["rule"].lower() or "42 4C 49 4E" in y["rule"]
        assert y["threat_level"] == 8

    def test_yara_rules_valid_syntax_markers(self):
        for y in YARA_RULES:
            assert "rule " in y["rule"]
            assert "strings:" in y["rule"]
            assert "condition:" in y["rule"]


# ── Coverage metrics ──────────────────────────────────────────────────────────

class TestCoverageMetrics:
    def test_avg_tpr_above_80_percent(self):
        assert COVERAGE_SUMMARY["avg_tpr"] >= 0.80

    def test_critical_rules_count(self):
        assert COVERAGE_SUMMARY["critical_rules"] >= 4

    def test_techniques_covered(self):
        assert COVERAGE_SUMMARY["techniques_covered"] >= 12

    def test_tactics_covered(self):
        assert COVERAGE_SUMMARY["tactics_covered"] >= 6

    def test_all_ids_unique(self):
        ids = [r["id"] for r in SIGMA_RULES]
        assert len(ids) == len(set(ids)), "Duplicate rule IDs found"

    def test_all_display_ids_unique(self):
        display_ids = [r["display_id"] for r in SIGMA_RULES]
        assert len(display_ids) == len(set(display_ids))
