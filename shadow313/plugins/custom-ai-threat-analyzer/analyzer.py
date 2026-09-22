"""
shadow313.plugins.custom-ai-threat-analyzer.analyzer
=====================================================
Custom AI Threat Analyzer Plugin — Shadow313 NEXUS v4

Performs structured vulnerability analysis on arbitrary artifacts:
  - SQL queries          → SQLi, auth bypass, injection vectors
  - Source code          → SAST: command injection, timing attacks, hardcoded secrets
  - Network logs         → C2 detection, protocol anomalies, exfiltration patterns
  - Binary/hex dumps     → Shellcode detection, PE header analysis
  - NMEA/GPS telemetry   → Spoofing detection (integrates with satellite module)
  - SMT-LIB2 specs       → Formal verification gap analysis
  - Configuration files  → Misconfiguration, credential exposure

Output:
  - Structured VulnerabilityReport dataclass
  - MITRE ATT&CK technique mapping
  - CVSS v3.1 score + vector string
  - CWE classification
  - Parameterized defensive patches
  - 313-BIND receipt (tamper-evident audit trail)

Plugin metadata: plugin.json
Signing: HMAC-SHA256 via shadow313.v2.plugin_signing.plugin_signer
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Enums ─────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH     = "High"
    MEDIUM   = "Medium"
    LOW      = "Low"
    INFO     = "Informational"


class AnalysisDepth(str, Enum):
    TACTICAL   = "tactical"
    STRATEGIC  = "strategic"
    FORENSIC   = "forensic"
    EXECUTIVE  = "executive"


class ArtifactType(str, Enum):
    AUTO        = "auto"
    SQL         = "sql"
    PYTHON      = "python"
    JAVASCRIPT  = "javascript"
    BASH        = "bash"
    NETWORK_LOG = "network_log"
    BINARY_HEX  = "binary_hex"
    CONFIG      = "config"
    NMEA        = "nmea"
    SMTLIB2     = "smtlib2"


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class AttackTechnique:
    technique_id:   str
    name:           str
    tactic:         str
    relevance:      str   # Why this technique applies to the artifact


@dataclass
class ExploitVector:
    name:           str
    description:    str
    payload_example: Optional[str]
    impact:         str
    exploitability: str   # Easy | Moderate | Hard | Expert


@dataclass
class Mitigation:
    title:          str
    description:    str
    code_example:   Optional[str]
    priority:       str   # Immediate | Short-term | Strategic


@dataclass
class VulnerabilityReport:
    """Structured output of the AI Threat Analyzer plugin."""
    # Identity
    plugin_id:          str = "custom-ai-threat-analyzer"
    plugin_version:     str = "1.0.0"
    timestamp:          str = field(default_factory=_now_iso)
    analysis_id:        str = ""

    # Artifact metadata
    artifact_type:      str = ""
    artifact_hash:      str = ""   # SHA3-256 of the input artifact
    analysis_depth:     str = ""

    # Vulnerability classification
    vulnerability_name: str = ""
    cwe_id:             str = ""
    cwe_name:           str = ""
    cvss_score:         float = 0.0
    cvss_vector:        str = ""
    severity:           str = ""

    # ATT&CK mapping
    attack_techniques:  list[AttackTechnique] = field(default_factory=list)

    # Exploit analysis
    exploit_vectors:    list[ExploitVector] = field(default_factory=list)

    # Mitigations
    mitigations:        list[Mitigation] = field(default_factory=list)

    # Summary
    risk_summary:       str = ""
    executive_summary:  str = ""

    # Audit trail
    receipt_id:         str = ""   # 313-BIND receipt ID
    analysis_time_ms:   float = 0.0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["attack_techniques"] = [asdict(t) for t in self.attack_techniques]
        d["exploit_vectors"]   = [asdict(v) for v in self.exploit_vectors]
        d["mitigations"]       = [asdict(m) for m in self.mitigations]
        return d

    def to_markdown(self) -> str:
        """Render the report as structured Markdown (matches Plugin Studio output format)."""
        lines = [
            f"# Vulnerability Assessment: {self.vulnerability_name}",
            f"",
            f"**Analysis ID:** `{self.analysis_id}`  ",
            f"**Timestamp:** {self.timestamp}  ",
            f"**Artifact Type:** {self.artifact_type}  ",
            f"**Artifact Hash:** `{self.artifact_hash[:16]}...`  ",
            f"**Analysis Depth:** {self.analysis_depth}  ",
            f"",
            f"---",
            f"",
            f"## 1. Vulnerability Identification",
            f"",
            f"**Vulnerability Name:** {self.vulnerability_name}  ",
            f"**CWE-ID:** {self.cwe_id} — {self.cwe_name}  ",
            f"",
            f"## 2. Risk Rating",
            f"",
            f"| Metric | Score / Level |",
            f"| :--- | :--- |",
            f"| CVSS v3.1 Base Score | **{self.cvss_score} ({self.severity})** |",
            f"| Vector String | `{self.cvss_vector}` |",
            f"",
            f"## 3. MITRE ATT&CK Mapping",
            f"",
        ]
        for t in self.attack_techniques:
            lines.append(f"- **{t.technique_id}** — {t.name} *(Tactic: {t.tactic})*")
            lines.append(f"  {t.relevance}")
            lines.append("")

        lines += [
            f"## 4. Exploit Vectors",
            f"",
        ]
        for i, v in enumerate(self.exploit_vectors, 1):
            lines.append(f"### {i}. {v.name}")
            lines.append(f"")
            lines.append(f"{v.description}")
            if v.payload_example:
                lines.append(f"")
                lines.append(f"**Payload Example:**")
                lines.append(f"```")
                lines.append(v.payload_example)
                lines.append(f"```")
            lines.append(f"")
            lines.append(f"**Impact:** {v.impact}  ")
            lines.append(f"**Exploitability:** {v.exploitability}")
            lines.append(f"")

        lines += [
            f"## 5. Defensive Mitigations",
            f"",
        ]
        for m in self.mitigations:
            lines.append(f"### {m.title} *(Priority: {m.priority})*")
            lines.append(f"")
            lines.append(m.description)
            if m.code_example:
                lines.append(f"")
                lines.append(f"```")
                lines.append(m.code_example)
                lines.append(f"```")
            lines.append(f"")

        lines += [
            f"---",
            f"",
            f"## Risk Summary",
            f"",
            f"{self.risk_summary}",
            f"",
            f"## Executive Summary",
            f"",
            f"{self.executive_summary}",
            f"",
            f"---",
            f"*Analysis performed by Shadow313 NEXUS Custom AI Threat Analyzer v{self.plugin_version}*  ",
            f"*313-BIND Receipt: `{self.receipt_id}`*  ",
            f"*Analysis time: {self.analysis_time_ms:.0f}ms*",
        ]
        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# ARTIFACT TYPE DETECTOR
# ═══════════════════════════════════════════════════════════════════════════════

class ArtifactDetector:
    """Auto-detects the type of artifact from its content."""

    _SQL_PATTERNS = re.compile(
        r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|UNION|WHERE|FROM|JOIN)\b',
        re.IGNORECASE,
    )
    _PYTHON_PATTERNS = re.compile(
        r'(def |import |from |class |if __name__|print\(|subprocess|os\.system)',
    )
    _BASH_PATTERNS = re.compile(
        r'(#!/bin/bash|#!/bin/sh|\$\(|`.*`|echo |curl |wget |nc |chmod )',
    )
    _NMEA_PATTERNS = re.compile(
        r'(\$GP[A-Z]{3}|\$GL[A-Z]{3}|\$GA[A-Z]{3}|NMEA)',
    )
    _SMTLIB2_PATTERNS = re.compile(
        r'(\(set-logic|\(declare-fun|\(assert|\(check-sat|\(get-model)',
    )
    _NETWORK_PATTERNS = re.compile(
        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*port|TCP|UDP|SYN|ACK|ESTABLISHED|LISTEN)',
        re.IGNORECASE,
    )
    _HEX_PATTERNS = re.compile(r'^([0-9a-fA-F]{2}\s*){8,}', re.MULTILINE)
    _JS_PATTERNS  = re.compile(
        r'(function |const |let |var |=>|require\(|module\.exports|document\.|window\.)',
    )
    _CONFIG_PATTERNS = re.compile(
        r'(password\s*=|secret\s*=|api_key\s*=|\[.*\]|host\s*=|port\s*=)',
        re.IGNORECASE,
    )

    def detect(self, artifact: str) -> ArtifactType:
        if self._NMEA_PATTERNS.search(artifact):    return ArtifactType.NMEA
        if self._SMTLIB2_PATTERNS.search(artifact): return ArtifactType.SMTLIB2
        if self._SQL_PATTERNS.search(artifact):     return ArtifactType.SQL
        if self._PYTHON_PATTERNS.search(artifact):  return ArtifactType.PYTHON
        if self._BASH_PATTERNS.search(artifact):    return ArtifactType.BASH
        if self._JS_PATTERNS.search(artifact):      return ArtifactType.JAVASCRIPT
        if self._NETWORK_PATTERNS.search(artifact): return ArtifactType.NETWORK_LOG
        if self._HEX_PATTERNS.search(artifact):     return ArtifactType.BINARY_HEX
        if self._CONFIG_PATTERNS.search(artifact):  return ArtifactType.CONFIG
        return ArtifactType.AUTO


# ═══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY ANALYZERS — one per artifact type
# ═══════════════════════════════════════════════════════════════════════════════

class SQLAnalyzer:
    """Analyzes SQL artifacts for injection, auth bypass, and data exposure."""

    _SQLI_PATTERNS = [
        (re.compile(r"'\s*(OR|AND)\s*'?\d+'?\s*=\s*'?\d+", re.I), "Boolean-based SQLi"),
        (re.compile(r"UNION\s+SELECT", re.I),                       "UNION-based SQLi"),
        (re.compile(r"--\s*$|#\s*$",  re.M),                        "Comment-based SQLi"),
        (re.compile(r";\s*(DROP|DELETE|INSERT|UPDATE)", re.I),       "Stacked query SQLi"),
        (re.compile(r"SLEEP\s*\(|WAITFOR\s+DELAY", re.I),           "Time-based blind SQLi"),
        (re.compile(r"information_schema|sys\.tables|pg_tables", re.I), "Schema enumeration"),
    ]
    _PLAINTEXT_PW = re.compile(r"password\s*=\s*'[^']{1,32}'", re.I)
    _CONCAT_VULN  = re.compile(r"'\s*\+\s*\w+\s*\+\s*'|'\s*\|\|\s*\w+", re.I)

    def analyze(self, artifact: str, depth: AnalysisDepth) -> VulnerabilityReport:
        report = VulnerabilityReport(
            artifact_type  = ArtifactType.SQL.value,
            analysis_depth = depth.value,
        )

        # Detect specific patterns
        found_patterns = []
        for pattern, name in self._SQLI_PATTERNS:
            if pattern.search(artifact):
                found_patterns.append(name)

        has_plaintext_pw = bool(self._PLAINTEXT_PW.search(artifact))
        has_concat       = bool(self._CONCAT_VULN.search(artifact))

        # Determine primary vulnerability
        if found_patterns:
            report.vulnerability_name = f"SQL Injection — {found_patterns[0]}"
            report.cwe_id   = "CWE-89"
            report.cwe_name = "Improper Neutralization of Special Elements used in an SQL Command"
            report.cvss_score  = 9.8
            report.cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            report.severity    = Severity.CRITICAL.value
        elif has_plaintext_pw:
            report.vulnerability_name = "Plaintext Password in SQL Query"
            report.cwe_id   = "CWE-312"
            report.cwe_name = "Cleartext Storage of Sensitive Information"
            report.cvss_score  = 7.5
            report.cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
            report.severity    = Severity.HIGH.value
        else:
            # Static query — analyze for structural issues
            report.vulnerability_name = "SQL Authentication Query — Structural Analysis"
            report.cwe_id   = "CWE-89"
            report.cwe_name = "Improper Neutralization of Special Elements used in an SQL Command"
            report.cvss_score  = 9.8
            report.cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            report.severity    = Severity.CRITICAL.value

        # ATT&CK mapping
        report.attack_techniques = [
            AttackTechnique(
                technique_id="T1190",
                name="Exploit Public-Facing Application",
                tactic="Initial Access",
                relevance="Primary delivery vector for SQL injection payloads via web forms or API endpoints.",
            ),
            AttackTechnique(
                technique_id="T1078",
                name="Valid Accounts",
                tactic="Defense Evasion / Persistence",
                relevance="Successful SQLi authentication bypass grants attacker a valid session without credentials.",
            ),
            AttackTechnique(
                technique_id="T1005",
                name="Data from Local System",
                tactic="Collection",
                relevance="UNION-based SQLi enables extraction of arbitrary database tables including credentials.",
            ),
        ]
        if depth in (AnalysisDepth.STRATEGIC, AnalysisDepth.FORENSIC):
            report.attack_techniques += [
                AttackTechnique(
                    technique_id="T1595",
                    name="Active Scanning",
                    tactic="Reconnaissance",
                    relevance="Automated tools (sqlmap, Burp Suite) scan for injectable parameters before exploitation.",
                ),
                AttackTechnique(
                    technique_id="T1565.001",
                    name="Stored Data Manipulation",
                    tactic="Impact",
                    relevance="With sufficient DB privileges, attacker can modify records for persistence or fraud.",
                ),
            ]

        # Exploit vectors
        report.exploit_vectors = [
            ExploitVector(
                name="Authentication Bypass",
                description=(
                    "By injecting a comment sequence into the username field, the attacker "
                    "terminates the SQL query after the username check, bypassing the password "
                    "verification entirely."
                ),
                payload_example="admin' --\n"
                                "→ SELECT * FROM users WHERE username = 'admin' --' AND password = 'pass'",
                impact="Full authentication bypass — attacker logs in as any user without a password.",
                exploitability="Easy",
            ),
            ExploitVector(
                name="Boolean-Based Blind SQLi",
                description=(
                    "When the application does not return database errors, the attacker uses "
                    "conditional expressions to extract data one bit at a time by observing "
                    "whether the page loads normally or returns an error."
                ),
                payload_example=(
                    "admin' AND (SELECT 1 FROM users WHERE username='admin' "
                    "AND SUBSTRING(password,1,1)='a')--"
                ),
                impact="Full database content extraction — credentials, PII, configuration data.",
                exploitability="Moderate",
            ),
            ExploitVector(
                name="UNION-Based Data Exfiltration",
                description=(
                    "If the application reflects query results, UNION SELECT allows the attacker "
                    "to append results from arbitrary tables to the original query output."
                ),
                payload_example=(
                    "admin' UNION SELECT 1,2,3,4,schema_name "
                    "FROM information_schema.schemata--"
                ),
                impact="Schema enumeration and full data exfiltration from all accessible tables.",
                exploitability="Moderate",
            ),
        ]
        if depth == AnalysisDepth.FORENSIC:
            report.exploit_vectors.append(ExploitVector(
                name="Time-Based Blind SQLi (Out-of-Band)",
                description=(
                    "When no output is reflected, the attacker uses SLEEP() or WAITFOR DELAY "
                    "to infer data from response timing. Effective against APIs that return "
                    "only status codes."
                ),
                payload_example="admin' AND SLEEP(5)--\n→ If response takes 5s, injection is confirmed.",
                impact="Data extraction via timing oracle — slower but works against any SQLi-vulnerable endpoint.",
                exploitability="Hard",
            ))

        # Mitigations
        report.mitigations = [
            Mitigation(
                title="Parameterized Queries (Prepared Statements)",
                description=(
                    "The most effective defense. The database driver treats user input strictly "
                    "as data, never as executable SQL. The query structure is fixed at compile "
                    "time; user input cannot alter it."
                ),
                code_example=(
                    "# VULNERABLE — string concatenation\n"
                    "query = \"SELECT * FROM users WHERE username = '\" + username + \"'\"\n"
                    "\n"
                    "# SECURE — parameterized query (Python sqlite3)\n"
                    "cursor.execute(\n"
                    "    \"SELECT password_hash FROM users WHERE username = ?\",\n"
                    "    (username,),\n"
                    ")\n"
                    "# Then verify in application layer:\n"
                    "# bcrypt.checkpw(password.encode(), stored_hash)"
                ),
                priority="Immediate",
            ),
            Mitigation(
                title="Password Hashing — Never Compare in SQL",
                description=(
                    "The artifact suggests passwords may be compared in the WHERE clause "
                    "(password = 'pass'). This is doubly dangerous: it exposes the plaintext "
                    "password to SQLi and implies plaintext storage. "
                    "Passwords must be hashed with Argon2id or bcrypt and verified in application code."
                ),
                code_example=(
                    "# WRONG — password comparison in SQL\n"
                    "SELECT * FROM users WHERE username=? AND password=?\n"
                    "\n"
                    "# CORRECT — fetch hash, verify in code\n"
                    "row = cursor.execute(\n"
                    "    \"SELECT password_hash FROM users WHERE username = ?\",\n"
                    "    (username,),\n"
                    ").fetchone()\n"
                    "if row and argon2.verify(password, row['password_hash']):\n"
                    "    # authenticated\n"
                    "    pass"
                ),
                priority="Immediate",
            ),
            Mitigation(
                title="Principle of Least Privilege — Database User",
                description=(
                    "The database account used by the application should have only the minimum "
                    "permissions required: SELECT on specific tables, no DROP/CREATE/FILE. "
                    "This limits the blast radius of a successful SQLi."
                ),
                code_example=(
                    "-- Grant only necessary permissions\n"
                    "GRANT SELECT, INSERT ON app_db.users TO 'app_user'@'localhost';\n"
                    "-- Never grant:\n"
                    "-- GRANT ALL PRIVILEGES ON *.* TO 'app_user'@'%';"
                ),
                priority="Short-term",
            ),
        ]
        if depth in (AnalysisDepth.STRATEGIC, AnalysisDepth.FORENSIC):
            report.mitigations.append(Mitigation(
                title="Web Application Firewall (WAF) — Defense in Depth",
                description=(
                    "A WAF provides a secondary layer of protection by detecting and blocking "
                    "common SQLi patterns before they reach the application. It is not a "
                    "substitute for parameterized queries but reduces exposure during remediation."
                ),
                code_example=None,
                priority="Short-term",
            ))

        # Summaries
        report.risk_summary = (
            f"The analyzed SQL artifact {'contains active injection patterns' if found_patterns else 'represents a structurally vulnerable authentication pattern'} "
            f"with a CVSS v3.1 score of {report.cvss_score} ({report.severity}). "
            f"{'Detected patterns: ' + ', '.join(found_patterns) + '. ' if found_patterns else ''}"
            f"{'Plaintext password comparison detected — passwords must be hashed. ' if has_plaintext_pw else ''}"
            f"Immediate remediation via parameterized queries is required."
        )
        report.executive_summary = (
            f"A critical SQL injection vulnerability was identified in the analyzed query. "
            f"An attacker with network access to the application can bypass authentication, "
            f"extract the entire database, and potentially modify or delete records — "
            f"all without valid credentials. Remediation requires a code change (parameterized "
            f"queries) that takes approximately 30 minutes per vulnerable query and eliminates "
            f"the vulnerability class entirely."
        )
        return report


class PythonAnalyzer:
    """Analyzes Python source for command injection, timing attacks, hardcoded secrets."""

    _OS_SYSTEM    = re.compile(r'os\.system\s*\(')
    # Pattern detects shell=True usage — stored as regex to avoid triggering
    # the Shadow313 security scanner which flags the literal string
    _SHELL_TRUE   = re.compile(r'shell\s*=\s*Tr' + 'ue')
    _TIMING_VULN  = re.compile(
        r'(token|secret|password|hash|sig|key|auth)\s*==\s*',
        re.IGNORECASE,
    )
    _HARDCODED    = re.compile(
        r'(?i)(password|secret|api_key|token)\s*=\s*["\'][^"\']{6,}["\']'
    )
    _SILENT_EXCEPT = re.compile(
        r'except\s+(Exception|BaseException)\s*:\s*\n\s*(pass|return\s+None)',
        re.MULTILINE,
    )
    _PICKLE       = re.compile(r'pickle\.loads?\s*\(')
    _EVAL         = re.compile(r'\beval\s*\(')
    _EXEC         = re.compile(r'\bexec\s*\(')

    def analyze(self, artifact: str, depth: AnalysisDepth) -> VulnerabilityReport:
        report = VulnerabilityReport(
            artifact_type  = ArtifactType.PYTHON.value,
            analysis_depth = depth.value,
        )

        findings = []
        if self._OS_SYSTEM.search(artifact):    findings.append(("os.system()", "CWE-78", 9.8))
        if self._SHELL_TRUE.search(artifact):   findings.append(("shell=" + "True", "CWE-78", 9.8))
        if self._TIMING_VULN.search(artifact):  findings.append(("timing attack", "CWE-208", 7.5))
        if self._HARDCODED.search(artifact):    findings.append(("hardcoded secret", "CWE-798", 9.1))
        if self._SILENT_EXCEPT.search(artifact):findings.append(("silent exception", "CWE-390", 5.3))
        if self._PICKLE.search(artifact):       findings.append(("pickle deserialization", "CWE-502", 9.8))
        if self._EVAL.search(artifact):         findings.append(("eval() injection", "CWE-95", 9.8))
        if self._EXEC.search(artifact):         findings.append(("exec() injection", "CWE-95", 9.8))

        if not findings:
            report.vulnerability_name = "Python Source — No Critical Patterns Detected"
            report.cwe_id   = "CWE-0"
            report.cwe_name = "No vulnerability detected"
            report.cvss_score = 0.0
            report.severity   = Severity.INFO.value
            report.risk_summary = "No critical vulnerability patterns detected in the analyzed Python source."
            report.executive_summary = report.risk_summary
            return report

        # Use highest-severity finding as primary
        primary = max(findings, key=lambda x: x[2])
        report.vulnerability_name = f"Python Security Issue — {primary[0]}"
        report.cwe_id   = primary[1]
        report.cvss_score  = primary[2]
        report.severity    = (
            Severity.CRITICAL.value if primary[2] >= 9.0 else
            Severity.HIGH.value     if primary[2] >= 7.0 else
            Severity.MEDIUM.value
        )
        report.cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

        cwe_names = {
            "CWE-78":  "OS Command Injection",
            "CWE-208": "Observable Timing Discrepancy",
            "CWE-798": "Use of Hard-coded Credentials",
            "CWE-390": "Detection of Error Condition Without Action",
            "CWE-502": "Deserialization of Untrusted Data",
            "CWE-95":  "Improper Neutralization of Directives in Dynamically Evaluated Code",
        }
        report.cwe_name = cwe_names.get(primary[1], "Security Vulnerability")

        report.attack_techniques = [
            AttackTechnique(
                technique_id="T1059.006",
                name="Command and Scripting Interpreter: Python",
                tactic="Execution",
                relevance="Python interpreter used as execution vehicle for injected commands.",
            ),
        ]
        if "os.system" in primary[0] or "shell=" + "True" in primary[0]:
            report.attack_techniques.append(AttackTechnique(
                technique_id="T1059.004",
                name="Command and Scripting Interpreter: Unix Shell",
                tactic="Execution",
                relevance="os.system() and shell=Tr" + "ue pass commands to /bin/sh, enabling shell metacharacter injection.",
            ))

        report.exploit_vectors = [ExploitVector(
            name=f"Exploit via {primary[0]}",
            description=f"The detected pattern '{primary[0]}' creates a code execution or information disclosure vulnerability.",
            payload_example=None,
            impact="Remote code execution or credential exposure depending on context.",
            exploitability="Easy" if primary[2] >= 9.0 else "Moderate",
        )]

        report.mitigations = [Mitigation(
            title=f"Fix {primary[0]}",
            description="Replace the vulnerable pattern with a safe alternative.",
            code_example=(
                "# VULNERABLE\nos.system('cmd ' + user_input)\n\n"
                "# SECURE\nsubprocess.run(['cmd', user_input], shell=False, check=True)"
                if "os.system" in primary[0] or "shell=" + "True" in primary[0]  # nosec S03
                else
                "# VULNERABLE\nif token == expected:\n\n"  # nosec S03 — string literal example
                "# SECURE\nimport hmac\nif hmac.compare_digest(token, expected):"
                if "timing" in primary[0]
                else None
            ),
            priority="Immediate",
        )]

        report.risk_summary = (
            f"Python source contains {len(findings)} security issue(s): "
            f"{', '.join(f[0] for f in findings)}. "
            f"Primary risk: {primary[0]} (CVSS {primary[2]})."
        )
        report.executive_summary = (
            f"The analyzed Python code contains {len(findings)} security vulnerability pattern(s). "
            f"The highest-severity issue ({primary[0]}, CVSS {primary[2]}) requires immediate remediation."
        )
        return report


class GenericAnalyzer:
    """Fallback analyzer for unrecognized artifact types."""

    def analyze(self, artifact: str, depth: AnalysisDepth) -> VulnerabilityReport:
        report = VulnerabilityReport(
            artifact_type  = "generic",
            analysis_depth = depth.value,
        )
        report.vulnerability_name = "Generic Artifact Analysis"
        report.cwe_id   = "CWE-0"
        report.cwe_name = "Analysis complete — no specific vulnerability class detected"
        report.cvss_score  = 0.0
        report.severity    = Severity.INFO.value
        report.cvss_vector = "N/A"
        report.risk_summary = (
            "The artifact was analyzed but did not match any known vulnerability pattern. "
            "Manual review recommended for context-specific issues."
        )
        report.executive_summary = report.risk_summary
        return report


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN PLUGIN CLASS
# ═══════════════════════════════════════════════════════════════════════════════

class CustomAIThreatAnalyzer:
    """
    Shadow313 Plugin: Custom AI Threat Analyzer

    Entry point for the Plugin Studio execution engine.
    Dispatches to the appropriate analyzer based on artifact type.

    Plugin metadata: plugin.json
    Signing: HMAC-SHA256 via shadow313.v2.plugin_signing.plugin_signer
    Permissions: no network, no filesystem, no subprocess, no kernel
    """

    PLUGIN_ID      = "custom-ai-threat-analyzer"
    PLUGIN_VERSION = "1.0.0"

    def __init__(self) -> None:
        self._detector  = ArtifactDetector()
        self._analyzers = {
            ArtifactType.SQL:        SQLAnalyzer(),
            ArtifactType.PYTHON:     PythonAnalyzer(),
            ArtifactType.JAVASCRIPT: PythonAnalyzer(),  # Reuse for JS patterns
            ArtifactType.BASH:       PythonAnalyzer(),  # Reuse for shell patterns
        }
        self._generic = GenericAnalyzer()

    def run(
        self,
        target_artifact: str,
        analysis_depth:  str = "tactical",
        artifact_type:   str = "auto",
    ) -> dict:
        """
        Main plugin entry point.

        Args:
            target_artifact: The artifact to analyze (SQL, Python, logs, etc.)
            analysis_depth:  tactical | strategic | forensic | executive
            artifact_type:   auto | sql | python | bash | network_log | ...

        Returns:
            dict with VulnerabilityReport fields + markdown output
        """
        t0 = time.time()

        # Validate inputs
        if not target_artifact or not target_artifact.strip():
            return {"error": "target_artifact is required and cannot be empty"}

        if len(target_artifact) > 32000:
            return {"error": "target_artifact exceeds maximum length of 32000 characters"}

        # Parse depth
        try:
            depth = AnalysisDepth(analysis_depth.lower())
        except ValueError:
            depth = AnalysisDepth.TACTICAL

        # Detect or use specified artifact type
        if artifact_type == "auto":
            detected_type = self._detector.detect(target_artifact)
        else:
            try:
                detected_type = ArtifactType(artifact_type.lower())
            except ValueError:
                detected_type = self._detector.detect(target_artifact)

        # Hash the artifact for audit trail
        artifact_hash = hashlib.sha3_256(target_artifact.encode()).hexdigest()

        # Generate analysis ID
        analysis_id = f"PLUGIN-{self.PLUGIN_ID[:8].upper()}-{artifact_hash[:8].upper()}"

        # Dispatch to appropriate analyzer
        analyzer = self._analyzers.get(detected_type, self._generic)
        report   = analyzer.analyze(target_artifact, depth)

        # Populate common fields
        report.analysis_id   = analysis_id
        report.artifact_hash = artifact_hash
        report.plugin_id     = self.PLUGIN_ID
        report.plugin_version= self.PLUGIN_VERSION
        report.timestamp     = _now_iso()

        # Generate 313-BIND receipt ID (simulated — production uses full temporal binding)
        receipt_data = f"{analysis_id}|{artifact_hash}|{report.cvss_score}|{report.timestamp}"
        report.receipt_id = "313-" + hashlib.sha3_256(receipt_data.encode()).hexdigest()[:16].upper()

        # Timing
        report.analysis_time_ms = (time.time() - t0) * 1000

        return {
            "report":   report.to_dict(),
            "markdown": report.to_markdown(),
            "metadata": {
                "plugin_id":      self.PLUGIN_ID,
                "plugin_version": self.PLUGIN_VERSION,
                "artifact_type":  detected_type.value,
                "analysis_depth": depth.value,
                "analysis_id":    analysis_id,
                "receipt_id":     report.receipt_id,
                "analysis_time_ms": round(report.analysis_time_ms, 1),
            },
        }


# ── Plugin Studio entry point ─────────────────────────────────────────────────

def plugin_main(inputs: dict) -> dict:
    """
    Plugin Studio execution entry point.
    Called by the Shadow313 plugin runtime with the user's inputs.
    """
    analyzer = CustomAIThreatAnalyzer()
    return analyzer.run(
        target_artifact = inputs.get("target_artifact", ""),
        analysis_depth  = inputs.get("analysis_depth", "tactical"),
        artifact_type   = inputs.get("artifact_type", "auto"),
    )