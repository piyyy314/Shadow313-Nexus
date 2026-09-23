"""
shadow313.v4.detection.sigma_rules
NEXUS Shadow313 — Production Sigma Rules & SIEM Detection Queries
Document ID: NEXUS-REF-2026-001 | Version: 2.0.1 | Date: 2026-09-22

15 Sigma rules covering:
- Credential Access (SIG-001 to SIG-004)
- Execution & Persistence (SIG-005 to SIG-009)
- Lateral Movement & C2 (SIG-010 to SIG-015)

Coverage: 37 ATT&CK techniques | 48 production rules | 84.1% avg confidence
"""
from shadow313.v4.detection.sigma_rules.rules import (
    SIGMA_RULES,
    SPL_QUERIES,
    KQL_QUERIES,
    ELASTIC_QUERIES,
    YARA_RULES,
    get_rule_by_id,
    get_rules_by_technique,
    get_rules_by_tactic,
    get_critical_rules,
    export_sigma_yaml,
)

__all__ = [
    "SIGMA_RULES",
    "SPL_QUERIES",
    "KQL_QUERIES",
    "ELASTIC_QUERIES",
    "YARA_RULES",
    "get_rule_by_id",
    "get_rules_by_technique",
    "get_rules_by_tactic",
    "get_critical_rules",
    "export_sigma_yaml",
]
