"""
shadow313.v4.detection.webshell_detector
Web Shell Detector — T1505.003

Detects web shell deployment and execution across multiple languages:
- PHP web shells (cmd, eval, base64, passthru, system)
- ASP/ASPX web shells (eval, execute, shell commands)
- JSP web shells (Runtime.exec, ProcessBuilder)
- Python/Perl CGI shells
- File upload indicators and suspicious web paths
- Chopper, China Chopper, WSO, b374k, r57 signatures

ATT&CK: T1505.003 (Server Software Component: Web Shell)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


# ── Web Shell Signatures ──────────────────────────────────────────────────────

WEBSHELL_SIGNATURES: dict[str, dict] = {
    # PHP shells
    "php_eval_base64": {
        "technique": "T1505.003",
        "name": "PHP Eval+Base64 Shell",
        "risk": 0.97,
        "patterns": [
            r"eval\s*\(\s*base64_decode\s*\(",
            r"eval\s*\(\s*gzinflate\s*\(",
            r"eval\s*\(\s*str_rot13\s*\(",
            r"eval\s*\(\s*gzuncompress\s*\(",
            r"eval\s*\(\s*rawurldecode\s*\(",
        ],
        "description": "PHP eval+obfuscation — classic web shell execution pattern",
    },
    "php_system_cmd": {
        "technique": "T1505.003",
        "name": "PHP System/Exec Shell",
        "risk": 0.95,
        "patterns": [
            r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[.*?\].*?(?:system|exec|passthru|shell_exec|popen|proc_open)",
            r"(?:system|exec|passthru|shell_exec)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)",
            r"passthru\s*\(\s*base64_decode",
            r"proc_open\s*\(\s*\$_(?:GET|POST|REQUEST)",
        ],
        "description": "PHP system/exec with user-controlled input — direct RCE",
    },
    "php_preg_replace_e": {
        "technique": "T1505.003",
        "name": "PHP preg_replace /e Shell",
        "risk": 0.93,
        "patterns": [
            r"preg_replace\s*\(\s*['\"].*?/e['\"]",
            r"preg_replace\s*\(.*?/e\b.*?\$_(?:GET|POST|REQUEST)",
        ],
        "description": "PHP preg_replace with /e modifier — deprecated RCE vector",
    },
    "php_assert_shell": {
        "technique": "T1505.003",
        "name": "PHP Assert Shell",
        "risk": 0.92,
        "patterns": [
            r"assert\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)",
            r"assert\s*\(\s*base64_decode",
            r"assert\s*\(\s*stripslashes\s*\(\s*\$_",
        ],
        "description": "PHP assert() with user input — code execution via assertion",
    },
    "china_chopper": {
        "technique": "T1505.003",
        "name": "China Chopper Web Shell",
        "risk": 0.99,
        "patterns": [
            r"eval\s*\(\s*\$_POST\s*\[.{1,20}?\]\s*\)\s*;?\s*\?>?$",
            r"@eval\s*\(\s*\$_POST",
            r"@preg_replace\s*\(.*?/e.*?\$_POST",
            r"<\?php\s+@?eval\s*\(\s*\$_POST\s*\[",
        ],
        "description": "China Chopper signature — one-liner PHP web shell",
    },
    "wso_shell": {
        "technique": "T1505.003",
        "name": "WSO Web Shell",
        "risk": 0.98,
        "patterns": [
            r"WSO\s+\d+\.\d+",
            r"wso_version",
            r"\$auth_pass\s*=\s*['\"][a-f0-9]{32}['\"]",
            r"FilesMan|Web Shell by oRb",
        ],
        "description": "WSO (Web Shell by oRb) — feature-rich PHP web shell",
    },
    "b374k_r57": {
        "technique": "T1505.003",
        "name": "b374k/r57 Shell",
        "risk": 0.98,
        "patterns": [
            r"b374k\s+shell",
            r"r57shell",
            r"\$b374k",
            r"r57_version\s*=",
            r"shell_name\s*=\s*['\"]r57",
        ],
        "description": "b374k or r57 web shell signature",
    },
    # ASP/ASPX shells
    "aspx_eval_shell": {
        "technique": "T1505.003",
        "name": "ASPX Eval Shell",
        "risk": 0.96,
        "patterns": [
            r"<%.*?eval\s*request\s*\(",
            r"<%.*?execute\s*request\s*\(",
            r"Response\.Write\s*\(\s*eval\s*\(",
            r"<%@\s*Page.*?%>.*?<%.*?eval\s*\(",
            r"System\.Diagnostics\.Process\.Start\s*\(",
        ],
        "description": "ASP/ASPX eval/execute with request input — classic ASP shell",
    },
    "aspx_cmd_shell": {
        "technique": "T1505.003",
        "name": "ASPX Command Shell",
        "risk": 0.95,
        "patterns": [
            r"cmd\.exe.*?/c.*?Request\[",
            r"Process\.Start\s*\(.*?Request\.",
            r"Shell\s*\(.*?Request\.",
            r"WScript\.Shell.*?Request\.",
        ],
        "description": "ASPX shell executing cmd.exe with request parameters",
    },
    # JSP shells
    "jsp_runtime_exec": {
        "technique": "T1505.003",
        "name": "JSP Runtime.exec Shell",
        "risk": 0.96,
        "patterns": [
            r"Runtime\.getRuntime\(\)\.exec\s*\(",
            r"ProcessBuilder\s*\(.*?request\.getParameter",
            r"new\s+ProcessBuilder\s*\(\s*request\.getParameter",
            r"Runtime\.exec\s*\(\s*request\.getParameter",
        ],
        "description": "JSP Runtime.exec with request parameter — Java web shell",
    },
    "jsp_classloader": {
        "technique": "T1505.003",
        "name": "JSP ClassLoader Shell",
        "risk": 0.94,
        "patterns": [
            r"ClassLoader.*?defineClass",
            r"URLClassLoader.*?request\.getParameter",
            r"defineClass\s*\(\s*.*?Base64",
        ],
        "description": "JSP ClassLoader abuse — dynamic class loading from request",
    },
    # Python/Perl CGI shells
    "python_cgi_shell": {
        "technique": "T1505.003",
        "name": "Python CGI Shell",
        "risk": 0.93,
        "patterns": [
            r"import\s+cgi.*?os\.system\s*\(",
            r"cgi\.FieldStorage.*?os\.popen",
            r"os\.system\s*\(\s*form\.getvalue",
            r"subprocess\.call\s*\(\s*form\[",
            r"exec\s*\(\s*base64\.b64decode",
        ],
        "description": "Python CGI script executing OS commands from form input",
    },
    "perl_cgi_shell": {
        "technique": "T1505.003",
        "name": "Perl CGI Shell",
        "risk": 0.92,
        "patterns": [
            r"use\s+CGI.*?system\s*\(\s*\$ENV",
            r"\$cmd\s*=\s*\$ENV\{.*?QUERY_STRING",
            r"system\s*\(\s*\$q->param",
            r"open\s*\(.*?\|\s*\$q->param",
        ],
        "description": "Perl CGI script with OS command execution from query string",
    },
    # File upload + web path indicators
    "suspicious_upload_path": {
        "technique": "T1505.003",
        "name": "Suspicious Upload Path",
        "risk": 0.80,
        "patterns": [
            r"(?:uploads?|images?|media|static|assets|files?|tmp|temp)/[^/]+\.(?:php|asp|aspx|jsp|jspx|cfm|cgi|pl|py|rb)\b",
            r"(?:wp-content|wp-includes)/[^/]+\.php\b",
            r"/(?:shell|cmd|exec|backdoor|hack|pwn)\.",
        ],
        "description": "Script file in upload/media directory — potential web shell drop",
    },
    # Generic obfuscation patterns
    "hex_char_obfuscation": {
        "technique": "T1505.003",
        "name": "Hex/Char Obfuscation Shell",
        "risk": 0.85,
        "patterns": [
            r"\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}",
            r"chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+\s*\)",
            r"(?:chr|ord)\s*\(.*?\)\s*[\.\+]\s*(?:chr|ord)\s*\(.*?\)\s*[\.\+]\s*(?:chr|ord)",
        ],
        "description": "Heavy hex/char obfuscation — typical web shell evasion",
    },
}

# ── Web server access log patterns ───────────────────────────────────────────

WEBSHELL_ACCESS_PATTERNS: list[dict] = [
    {
        "name": "POST to static file",
        "pattern": r"POST\s+/[^\s]*\.(?:jpg|jpeg|png|gif|ico|css|js|txt|pdf)\s+HTTP",
        "risk": 0.75,
        "description": "POST request to static file — possible web shell disguised as image",
    },
    {
        "name": "Shell command in URL",
        "pattern": r"(?:cmd=|command=|exec=|execute=|run=|shell=|c=|q=)(?:cat\s|ls\s|id\b|whoami|uname|wget|curl|nc\s|bash|sh\s)",
        "risk": 0.95,
        "description": "Shell command in URL parameter — active web shell usage",
    },
    {
        "name": "Encoded shell command",
        "pattern": r"(?:cmd=|command=|exec=|execute=|c=|q=)(?:[A-Za-z0-9+/]{10,}={0,2})",
        "risk": 0.82,
        "description": "Base64-encoded command in URL parameter",
    },
    {
        "name": "Web shell user agent",
        "pattern": r"(?:antSword|Behinder|Godzilla|CKnife|WebShell|AntSword|chopper|b374k|r57shell)",
        "risk": 0.99,
        "description": "Known web shell client user agent detected",
    },
    {
        "name": "Rapid sequential requests",
        "pattern": r"(?:(?:GET|POST)\s+/[^\s]+\s+HTTP/\d\.\d.*?\n){5,}",
        "risk": 0.70,
        "description": "Rapid sequential requests — possible automated web shell activity",
    },
]


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class WebShellFinding:
    """A single web shell detection finding."""
    signature_id:   str
    signature_name: str
    technique:      str
    risk_score:     float
    matched_pattern: str
    matched_text:   str
    file_path:      Optional[str]
    line_number:    Optional[int]
    description:    str
    timestamp:      str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "signature_id":    self.signature_id,
            "signature_name":  self.signature_name,
            "technique":       self.technique,
            "risk_score":      self.risk_score,
            "matched_pattern": self.matched_pattern,
            "matched_text":    self.matched_text[:200],
            "file_path":       self.file_path,
            "line_number":     self.line_number,
            "description":     self.description,
            "timestamp":       self.timestamp,
        }


@dataclass
class WebShellDetectionResult:
    """Aggregated result from WebShellDetector."""
    findings:       list[WebShellFinding] = field(default_factory=list)
    score:          float = 0.0
    detected:       bool  = False
    technique:      str   = "T1505.003"
    technique_name: str   = "Server Software Component: Web Shell"
    scan_target:    str   = ""
    lines_scanned:  int   = 0
    timestamp:      str   = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "detected":        self.detected,
            "score":           round(self.score, 4),
            "technique":       self.technique,
            "technique_name":  self.technique_name,
            "scan_target":     self.scan_target,
            "lines_scanned":   self.lines_scanned,
            "finding_count":   len(self.findings),
            "findings":        [f.to_dict() for f in self.findings],
            "timestamp":       self.timestamp,
        }


# ── Detector ──────────────────────────────────────────────────────────────────

class WebShellDetector:
    """
    Detects web shell deployment and execution (T1505.003).

    Supports two scan modes:
    1. Content scan  — scan raw file/log content as a string
    2. Access log    — scan web server access log lines for shell usage patterns

    Usage:
        detector = WebShellDetector()

        # Scan file content
        result = detector.scan_content(content, file_path="uploads/image.php")

        # Scan access log
        result = detector.scan_access_log(log_lines)

        # Score a single event dict (pipeline-compatible)
        score = detector.score_event(event)
    """

    DETECTION_THRESHOLD: float = 0.65

    def __init__(self, threshold: float = DETECTION_THRESHOLD) -> None:
        self.threshold = threshold
        self._compiled_sigs:    dict[str, list[re.Pattern]] = {}
        self._compiled_access:  list[tuple[dict, re.Pattern]] = []
        self._compile_patterns()

    # ── Setup ─────────────────────────────────────────────────────────────────

    def _compile_patterns(self) -> None:
        """Pre-compile all regex patterns for performance."""
        for sig_id, sig in WEBSHELL_SIGNATURES.items():
            self._compiled_sigs[sig_id] = [
                re.compile(p, re.IGNORECASE | re.MULTILINE)
                for p in sig["patterns"]
            ]
        for ap in WEBSHELL_ACCESS_PATTERNS:
            self._compiled_access.append(
                (ap, re.compile(ap["pattern"], re.IGNORECASE | re.MULTILINE))
            )

    # ── Public API ────────────────────────────────────────────────────────────

    def scan_content(
        self,
        content: str,
        file_path: Optional[str] = None,
    ) -> WebShellDetectionResult:
        """
        Scan file content for web shell signatures.

        Args:
            content:   Raw file content as string
            file_path: Optional path for reporting

        Returns:
            WebShellDetectionResult with all findings
        """
        result = WebShellDetectionResult(
            scan_target=file_path or "<content>",
            lines_scanned=content.count("\n") + 1,
        )

        lines = content.splitlines()

        for sig_id, patterns in self._compiled_sigs.items():
            sig = WEBSHELL_SIGNATURES[sig_id]
            for pattern in patterns:
                for match in pattern.finditer(content):
                    # Find line number
                    line_no = content[:match.start()].count("\n") + 1
                    matched_text = match.group(0)

                    finding = WebShellFinding(
                        signature_id=sig_id,
                        signature_name=sig["name"],
                        technique=sig["technique"],
                        risk_score=sig["risk"],
                        matched_pattern=pattern.pattern,
                        matched_text=matched_text,
                        file_path=file_path,
                        line_number=line_no,
                        description=sig["description"],
                    )
                    result.findings.append(finding)
                    break  # one match per pattern per sig is enough

        result.score    = self._aggregate_score(result.findings)
        result.detected = result.score >= self.threshold
        return result

    def scan_access_log(
        self,
        log_content: str,
        source: str = "<access_log>",
    ) -> WebShellDetectionResult:
        """
        Scan web server access log for web shell usage patterns.

        Args:
            log_content: Raw access log content
            source:      Log source identifier

        Returns:
            WebShellDetectionResult with all findings
        """
        result = WebShellDetectionResult(
            scan_target=source,
            lines_scanned=log_content.count("\n") + 1,
        )

        for ap, pattern in self._compiled_access:
            for match in pattern.finditer(log_content):
                line_no = log_content[:match.start()].count("\n") + 1
                finding = WebShellFinding(
                    signature_id=f"access_{ap['name'].lower().replace(' ', '_')}",
                    signature_name=ap["name"],
                    technique="T1505.003",
                    risk_score=ap["risk"],
                    matched_pattern=pattern.pattern,
                    matched_text=match.group(0),
                    file_path=source,
                    line_number=line_no,
                    description=ap["description"],
                )
                result.findings.append(finding)
                break  # one match per access pattern

        result.score    = self._aggregate_score(result.findings)
        result.detected = result.score >= self.threshold
        return result

    def score_event(self, event: dict) -> float:
        """
        Score a single event dict for web shell indicators.
        Pipeline-compatible interface matching other v4 detectors.

        Checks:
        - file_path / url fields for suspicious extensions in upload paths
        - command_line / content fields for shell signatures
        - user_agent for known web shell clients
        - http_method + file_extension combinations

        Returns:
            float in [0.0, 1.0]
        """
        score = 0.0

        # Check file path / URL
        file_path = str(event.get("file_path", event.get("url", "")))
        if file_path:
            result = self.scan_content(file_path, file_path=file_path)
            if result.detected:
                score = max(score, result.score * 0.8)

        # Check command line or content
        content = str(event.get("command_line", event.get("content", event.get("body", ""))))
        if content and len(content) > 10:
            result = self.scan_content(content)
            if result.detected:
                score = max(score, result.score)

        # Check user agent
        ua = str(event.get("user_agent", event.get("http_user_agent", "")))
        if ua:
            for ap, pattern in self._compiled_access:
                if "user agent" in ap["name"].lower() and pattern.search(ua):
                    score = max(score, ap["risk"])

        # HTTP POST to non-script file
        method = str(event.get("http_method", event.get("method", ""))).upper()
        if method == "POST" and file_path:
            ext = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
            if ext in {"jpg", "jpeg", "png", "gif", "ico", "css", "txt", "pdf"}:
                score = max(score, 0.75)

        # Event type: file_create in web root
        event_type = str(event.get("event_type", ""))
        if event_type in {"file_create", "file_write"} and file_path:
            ext = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
            if ext in {"php", "asp", "aspx", "jsp", "jspx", "cfm", "cgi", "pl"}:
                web_root_indicators = [
                    "wwwroot", "htdocs", "public_html", "web", "www",
                    "uploads", "images", "media", "static", "assets",
                ]
                if any(ind in file_path.lower() for ind in web_root_indicators):
                    score = max(score, 0.88)

        return min(score, 1.0)

    # ── Internal ──────────────────────────────────────────────────────────────

    @staticmethod
    def _aggregate_score(findings: list[WebShellFinding]) -> float:
        """
        Aggregate multiple findings into a single risk score.
        Uses diminishing returns to avoid score inflation.
        """
        if not findings:
            return 0.0
        scores = sorted([f.risk_score for f in findings], reverse=True)
        # Highest score + diminishing contribution from additional findings
        total = scores[0]
        for i, s in enumerate(scores[1:], 1):
            total += s * (0.5 ** i)
        return min(total, 1.0)


# ── Extended Signatures (v4.1 — Gap Closure) ─────────────────────────────────

WEBSHELL_SIGNATURES_EXTENDED: dict[str, dict] = {

    # ── PHP Modern Evasion ────────────────────────────────────────────────────
    "php_create_function": {
        "technique": "T1505.003",
        "name": "PHP create_function Shell",
        "risk": 0.96,
        "patterns": [
            r"create_function\s*\(\s*['\"].*?['\"]\s*,\s*\$_(?:GET|POST|REQUEST|COOKIE)",
            r"create_function\s*\(\s*['\"][^'\"]*['\"]\s*,\s*['\"].*?(?:system|exec|passthru)",
            r"\$\w+\s*=\s*create_function\s*\(.*?\$_(?:GET|POST|REQUEST)",
        ],
        "description": "PHP create_function() abuse — deprecated but still deployed as shell vector",
    },
    "php_variable_function": {
        "technique": "T1505.003",
        "name": "PHP Variable Function Shell",
        "risk": 0.94,
        "patterns": [
            r"\$\w+\s*=\s*['\"](?:system|exec|passthru|shell_exec|popen)['\"];\s*\$\w+\s*\(",
            r"\$\{.*?\}\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)",
            r"\$\w+\s*=\s*\$_(?:GET|POST|REQUEST)\[.*?\];\s*\$\w+\s*\(",
            r"(?:call_user_func|call_user_func_array)\s*\(\s*\$_(?:GET|POST|REQUEST)",
        ],
        "description": "PHP variable function / call_user_func with user input — dynamic dispatch shell",
    },
    "php_array_callback": {
        "technique": "T1505.003",
        "name": "PHP Array Callback Shell",
        "risk": 0.93,
        "patterns": [
            r"array_map\s*\(\s*['\"](?:system|exec|passthru|shell_exec)['\"]",
            r"array_filter\s*\(\s*\$_(?:GET|POST|REQUEST).*?['\"](?:system|exec)['\"]",
            r"array_walk\s*\(\s*.*?['\"](?:system|exec|passthru)['\"]",
            r"usort\s*\(\s*.*?create_function",
        ],
        "description": "PHP array_map/array_filter/array_walk with shell callback — evasion via functional style",
    },
    "php_mail_shell": {
        "technique": "T1505.003",
        "name": "PHP mail() 5th Param Shell",
        "risk": 0.95,
        "patterns": [
            r"mail\s*\(.*?-X\s*/",
            r"mail\s*\(.*?-X\s*\$_(?:GET|POST|REQUEST)",
            r"mail\s*\([^,]+,[^,]+,[^,]+,[^,]+,\s*['\"].*?-X",
            r"mail\s*\(.*?-UX\s*/tmp",
        ],
        "description": "PHP mail() 5th parameter -X flag — writes PHP file via sendmail debug",
    },
    "php_reflection_shell": {
        "technique": "T1505.003",
        "name": "PHP ReflectionFunction Shell",
        "risk": 0.91,
        "patterns": [
            r"ReflectionFunction\s*\(\s*\$_(?:GET|POST|REQUEST)",
            r"new\s+ReflectionFunction\s*\(\s*['\"](?:system|exec|passthru)['\"]",
            r"ReflectionMethod.*?invoke\s*\(.*?\$_(?:GET|POST|REQUEST)",
        ],
        "description": "PHP ReflectionFunction/ReflectionMethod abuse — OOP-based shell evasion",
    },
    "php_string_concat_obfuscation": {
        "technique": "T1505.003",
        "name": "PHP String Concatenation Obfuscation",
        "risk": 0.88,
        "patterns": [
            r"['\"]s['\"][.\+]['\"]y['\"][.\+]['\"]s['\"][.\+]['\"]t['\"][.\+]['\"]e['\"][.\+]['\"]m['\"]",
            r"['\"]sy['\"][.\+]['\"]st['\"][.\+]['\"]em['\"]",
            r"(?:chr\(\d+\)\.){4,}",
            r"\$\w+\s*=\s*['\"][a-z]['\"];\s*\$\w+\s*\.=\s*['\"][a-z]['\"]",
        ],
        "description": "PHP string concatenation to build function names — evades static signature matching",
    },
    "php_variable_variable": {
        "technique": "T1505.003",
        "name": "PHP Variable Variable Shell",
        "risk": 0.92,
        "patterns": [
            r"\$\$\w+\s*=\s*['\"](?:system|exec|passthru|shell_exec)['\"]",
            r"\$\{\$\w+\}\s*\(\s*\$_(?:GET|POST|REQUEST)",
            r"\$\$_(?:GET|POST|REQUEST)\[.*?\]\s*\(",
        ],
        "description": "PHP variable variables ($$var) — double-dollar obfuscation for shell calls",
    },
    "php_memory_shell": {
        "technique": "T1505.003",
        "name": "PHP Memory Shell (Fileless)",
        "risk": 0.97,
        "patterns": [
            r"register_shutdown_function\s*\(\s*['\"](?:system|exec|passthru)['\"]",
            r"register_tick_function\s*\(\s*['\"](?:system|exec)['\"]",
            r"auto_prepend_file.*?php://input",
            r"stream_wrapper_register.*?eval",
        ],
        "description": "PHP fileless memory shell — persists via shutdown/tick functions without file on disk",
    },

    # ── JSP / Java Extended ───────────────────────────────────────────────────
    "jsp_scriptengine": {
        "technique": "T1505.003",
        "name": "JSP ScriptEngine Shell",
        "risk": 0.95,
        "patterns": [
            r"ScriptEngineManager\s*\(\s*\).*?getEngineByName",
            r"getEngineByName\s*\(\s*['\"](?:js|javascript|nashorn|rhino)['\"].*?eval\s*\(",
            r"javax\.script\.ScriptEngine.*?eval\s*\(\s*request\.getParameter",
            r"new\s+ScriptEngineManager.*?eval\s*\(",
        ],
        "description": "JSP ScriptEngine (Nashorn/Rhino) eval — JavaScript engine abuse for RCE",
    },
    "jsp_memshell": {
        "technique": "T1505.003",
        "name": "JSP Memory Shell (Fileless)",
        "risk": 0.98,
        "patterns": [
            r"addServlet\s*\(.*?request\.getParameter",
            r"addFilter\s*\(.*?request\.getParameter",
            r"StandardContext.*?addServletMappingDecoded",
            r"WebappClassLoader.*?defineClass.*?Base64",
            r"Thread\.currentThread\(\)\.getContextClassLoader\(\).*?defineClass",
        ],
        "description": "JSP in-memory shell — injects servlet/filter without writing file to disk",
    },
    "spring_shell": {
        "technique": "T1505.003",
        "name": "Spring Framework Shell",
        "risk": 0.96,
        "patterns": [
            r"@RequestMapping.*?Runtime\.getRuntime\(\)\.exec",
            r"RequestMappingHandlerMapping.*?addMapping",
            r"ApplicationContext.*?registerBean.*?exec",
            r"SpelExpressionParser.*?parseExpression.*?exec",
            r"StandardEvaluationContext.*?exec\s*\(",
        ],
        "description": "Spring MVC controller injection or SpEL expression injection — Java web shell",
    },
    "godzilla_shell": {
        "technique": "T1505.003",
        "name": "Godzilla Web Shell",
        "risk": 0.99,
        "patterns": [
            r"Godzilla",
            r"godzilla.*?shell",
            r"xc\s*\(\s*base64_decode\s*\(\s*\$_POST",
            r"@ini_set\s*\(\s*['\"]error_reporting['\"].*?@eval\s*\(\s*\$_POST",
        ],
        "description": "Godzilla web shell signature — modern encrypted web shell framework",
    },
    "behinder_shell": {
        "technique": "T1505.003",
        "name": "Behinder Web Shell",
        "risk": 0.99,
        "patterns": [
            r"Behinder",
            r"behinder",
            r"new\s+javax\.crypto\.spec\.SecretKeySpec.*?AES",
            r"Cipher\.getInstance\s*\(\s*['\"]AES['\"].*?request\.getSession",
            r"getSession\(\)\.getAttribute\s*\(\s*['\"]u['\"]",
        ],
        "description": "Behinder (冰蝎) web shell — AES-encrypted Java/PHP web shell framework",
    },
    "shiro_deser_shell": {
        "technique": "T1505.003",
        "name": "Apache Shiro Deserialization Shell",
        "risk": 0.97,
        "patterns": [
            r"rememberMe=.*?[A-Za-z0-9+/]{100,}",
            r"org\.apache\.shiro.*?deserialize",
            r"AesCipherService.*?decrypt.*?Base64",
            r"CookieRememberMeManager.*?deserialize",
        ],
        "description": "Apache Shiro rememberMe deserialization — CVE-2016-4437 / CVE-2019-12422 pattern",
    },
    "tomcat_filter_shell": {
        "technique": "T1505.003",
        "name": "Tomcat Filter/Valve Shell",
        "risk": 0.96,
        "patterns": [
            r"StandardContext.*?addFilterDef",
            r"FilterDef.*?setFilterClass.*?exec",
            r"Valve.*?invoke.*?request\.getParameter.*?exec",
            r"org\.apache\.catalina\.core\.StandardContext.*?createFilter",
        ],
        "description": "Tomcat filter/valve injection — memory shell via Tomcat internals",
    },

    # ── Node.js Shells ────────────────────────────────────────────────────────
    "nodejs_child_process": {
        "technique": "T1505.003",
        "name": "Node.js child_process Shell",
        "risk": 0.96,
        "patterns": [
            r"require\s*\(\s*['\"]child_process['\"]\s*\).*?exec\s*\(\s*req\.",
            r"child_process.*?execSync\s*\(\s*req\.(?:body|query|params)",
            r"spawn\s*\(\s*req\.(?:body|query|params)",
            r"execFile\s*\(\s*req\.(?:body|query|params)",
            r"require\(['\"]child_process['\"]\)\.exec\(req\.",
        ],
        "description": "Node.js child_process.exec with request input — Express/Node web shell",
    },
    "nodejs_eval_shell": {
        "technique": "T1505.003",
        "name": "Node.js eval-injection Shell",
        "risk": 0.95,
        "patterns": [
            r"eval\s*\(\s*req\.(?:body|query|params)",
            r"new\s+Function\s*\(\s*req\.(?:body|query|params)",
            r"vm\.runInNewContext\s*\(\s*req\.",
            r"vm\.runInThisContext\s*\(\s*req\.",
        ],
        "description": "Node.js eval-injection/Function/vm with request input — server-side JS injection",
    },

    # ── Ruby / Rails Shells ───────────────────────────────────────────────────
    "ruby_cgi_shell": {
        "technique": "T1505.003",
        "name": "Ruby CGI Shell",
        "risk": 0.93,
        "patterns": [
            r"require\s+['\"]cgi['\"].*?system\s*\(\s*params\[",
            r"`#{params\[.*?\]}`",
            r"system\s*\(\s*params\[.*?\]\s*\)",
            r"exec\s*\(\s*params\[.*?\]\s*\)",
            r"IO\.popen\s*\(\s*params\[",
        ],
        "description": "Ruby CGI/Rack shell — system()/exec() with params input",
    },
    "ruby_eval_shell": {
        "technique": "T1505.003",
        "name": "Ruby eval-injection Shell",
        "risk": 0.94,
        "patterns": [
            r"eval\s*\(\s*params\[.*?\]\s*\)",
            r"eval\s*\(\s*request\.(?:body|params)",
            r"instance_eval\s*\(\s*params\[",
            r"class_eval\s*\(\s*params\[",
            r"Kernel\.eval\s*\(\s*params\[",
        ],
        "description": "Ruby eval-injection/instance_eval with request params — Ruby web shell",
    },

    # ── ColdFusion Shells ─────────────────────────────────────────────────────
    "coldfusion_cfexecute": {
        "technique": "T1505.003",
        "name": "ColdFusion CFExecute Shell",
        "risk": 0.97,
        "patterns": [
            r"<cfexecute\s+name\s*=\s*['\"]?(?:cmd\.exe|/bin/sh|/bin/bash|powershell)",
            r"<cfexecute\s+name\s*=\s*#URL\.",
            r"<cfexecute\s+name\s*=\s*#FORM\.",
            r"cfexecute.*?variable\s*=\s*['\"]?#",
        ],
        "description": "ColdFusion <cfexecute> tag — direct OS command execution",
    },
    "coldfusion_evaluate": {
        "technique": "T1505.003",
        "name": "ColdFusion evaluate-injection Shell",
        "risk": 0.95,
        "patterns": [
            r"evaluate\s*\(\s*URL\.",
            r"evaluate\s*\(\s*FORM\.",
            r"IIF\s*\(\s*.*?evaluate\s*\(",
            r"<cfset\s+.*?=\s*evaluate\s*\(\s*URL\.",
        ],
        "description": "ColdFusion evaluate() with URL/FORM input — CFML code injection",
    },

    # ── Unicode / Advanced Obfuscation ────────────────────────────────────────
    "unicode_obfuscation": {
        "technique": "T1505.003",
        "name": "Unicode/UTF-8 Obfuscation Shell",
        "risk": 0.87,
        "patterns": [
            r"\\u0073\\u0079\\u0073\\u0074\\u0065\\u006d",   # \u0073ystem
            r"\\u0065\\u0076\\u0061\\u006c",                  # \u0065val
            r"\\x73\\x79\\x73\\x74\\x65\\x6d",               # \x73ystem (hex)
            r"(?:\\u[0-9a-fA-F]{4}){5,}",                    # 5+ unicode escapes
        ],
        "description": "Unicode/hex escape obfuscation of shell function names",
    },
    "aspx_memory_shell": {
        "technique": "T1505.003",
        "name": "ASPX Memory Shell (Fileless)",
        "risk": 0.98,
        "patterns": [
            r"HttpApplication.*?PostAcquireRequestState",
            r"IHttpModule.*?Init.*?context\.PostAcquireRequestState",
            r"Assembly\.Load\s*\(\s*Convert\.FromBase64String",
            r"AppDomain\.CurrentDomain\.GetAssemblies.*?GetType.*?Invoke",
        ],
        "description": "ASPX fileless memory shell — injects IHttpModule without writing .aspx file",
    },
}

# Merge extended signatures into main dict
WEBSHELL_SIGNATURES.update(WEBSHELL_SIGNATURES_EXTENDED)

# ── Extended Access Log Patterns ──────────────────────────────────────────────

WEBSHELL_ACCESS_PATTERNS_EXTENDED: list[dict] = [
    {
        "name": "WebSocket upgrade to shell",
        "pattern": r"GET\s+/[^\s]*\.(?:php|asp|aspx|jsp)\s+HTTP.*?Upgrade:\s*websocket",
        "risk": 0.78,
        "description": "WebSocket upgrade to script file — possible shell tunneling via WS",
    },
    {
        "name": "Unusual HTTP verb to script",
        "pattern": r"(?:TRACK|TRACE|DEBUG|MOVE|COPY|PROPFIND)\s+/[^\s]*\.(?:php|asp|aspx|jsp)",
        "risk": 0.82,
        "description": "Unusual HTTP verb to script file — WebDAV/TRACE abuse for shell access",
    },
    {
        "name": "Behinder/Godzilla encrypted POST",
        "pattern": r"POST\s+/[^\s]*\.(?:php|jsp|aspx)\s+HTTP.*?Content-Length:\s*(?:[3-9]\d{2}|[1-9]\d{3,})",
        "risk": 0.72,
        "description": "Large encrypted POST to script — Behinder/Godzilla encrypted shell traffic",
    },
    {
        "name": "Shell tool scanner UA",
        "pattern": r"(?:sqlmap|nikto|dirsearch|gobuster|ffuf|wfuzz|nuclei|masscan|zgrab)",
        "risk": 0.70,
        "description": "Known web scanner user agent — reconnaissance preceding shell upload",
    },
    {
        "name": "Double extension upload",
        "pattern": r"(?:POST|PUT)\s+/[^\s]*\.\w+\.(?:php|asp|aspx|jsp|jspx)\s+HTTP",
        "risk": 0.88,
        "description": "Double extension file upload (e.g. image.jpg.php) — upload filter bypass",
    },
]

WEBSHELL_ACCESS_PATTERNS.extend(WEBSHELL_ACCESS_PATTERNS_EXTENDED)


# ── FN Patches (corpus validation fixes) ─────────────────────────────────────

WEBSHELL_SIGNATURES_FN_PATCHES: dict[str, dict] = {

    # FN-1: tennc_php_003 — two-step base64 variable function
    # $a = base64_decode("c3lzdGVt"); $a($_GET[0]);
    "php_base64_var_function": {
        "technique": "T1505.003",
        "name": "PHP Base64 Variable Function Shell",
        "risk": 0.96,
        "patterns": [
            r"\$\w+\s*=\s*base64_decode\s*\([^)]+\)\s*;.*?\$\w+\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)",
            r"\$\w+\s*=\s*base64_decode\s*\([^)]+\);\s*\$\w+\s*\(",
            r"\$\w+\s*=\s*(?:str_rot13|rawurldecode|gzinflate|gzuncompress)\s*\([^)]+\)\s*;.*?\$\w+\s*\(\s*\$_",
        ],
        "description": "PHP two-step variable function — decode to var then call var() with user input",
    },

    # FN-2: tennc_php_005 — array_map with assert callback
    "php_array_assert": {
        "technique": "T1505.003",
        "name": "PHP array_map assert Shell",
        "risk": 0.95,
        "patterns": [
            r"array_map\s*\(\s*['\"]assert['\"]",
            r"array_map\s*\(\s*['\"](?:assert|system|exec|passthru|shell_exec|popen)['\"]",
            r"array_filter\s*\(\s*.*?['\"]assert['\"]",
            r"array_walk\s*\(\s*.*?['\"]assert['\"]",
        ],
        "description": "PHP array_map/filter with assert callback — evades system/exec signature matching",
    },

    # FN-3: aspx_002 — Hafnium StartInfo pattern
    "aspx_startinfo_shell": {
        "technique": "T1505.003",
        "name": "ASPX StartInfo Command Shell",
        "risk": 0.97,
        "patterns": [
            r"StartInfo\.FileName\s*=\s*['\"]cmd\.exe['\"]",
            r"StartInfo\.FileName\s*=\s*['\"](?:cmd\.exe|powershell\.exe|/bin/sh|/bin/bash)['\"]",
            r"StartInfo\.Arguments\s*=.*?Request\s*\[",
            r"StartInfo\.FileName.*?StartInfo\.Arguments.*?Request",
            r"ProcessStartInfo\s*\(.*?['\"]cmd\.exe['\"].*?\).*?Request\[",
        ],
        "description": "ASPX ProcessStartInfo shell — Hafnium Exchange attack pattern (MSTIC 2021)",
    },

    # FN-4: jsp_002 — Behinder JSP AES session pattern
    "jsp_behinder_aes": {
        "technique": "T1505.003",
        "name": "Behinder JSP AES Shell",
        "risk": 0.99,
        "patterns": [
            r"session\.(?:putValue|setAttribute)\s*\(\s*['\"]u['\"]",
            r"Cipher\.getInstance\s*\(\s*['\"]AES['\"]\s*\).*?session\.",
            r"defineClass\s*\(.*?doFinal\s*\(",
            r"new\s+SecretKeySpec\s*\(.*?getBytes\s*\(\s*\)\s*,\s*['\"]AES['\"]",
            r"ClassLoader.*?defineClass.*?BASE64Decoder",
        ],
        "description": "Behinder JSP AES encrypted shell — session key + ClassLoader defineClass pattern",
    },

    # FN-5: nodejs_001 — destructured child_process import
    "nodejs_destructured_exec": {
        "technique": "T1505.003",
        "name": "Node.js Destructured child_process Shell",
        "risk": 0.96,
        "patterns": [
            r"\{\s*exec\s*\}\s*=\s*require\s*\(\s*['\"]child_process['\"]\s*\)",
            r"\{\s*execSync\s*\}\s*=\s*require\s*\(\s*['\"]child_process['\"]\s*\)",
            r"\{\s*spawn\s*\}\s*=\s*require\s*\(\s*['\"]child_process['\"]\s*\)",
            r"exec\s*\(\s*req\.(?:query|body|params)\.",
            r"execSync\s*\(\s*req\.(?:query|body|params)\.",
        ],
        "description": "Node.js destructured child_process import — exec(req.query.cmd) pattern",
    },

    # FN-6: ruby_003 — Rack req.params backtick
    "ruby_rack_backtick": {
        "technique": "T1505.003",
        "name": "Ruby Rack/Request Backtick Shell",
        "risk": 0.95,
        "patterns": [
            r"`#\{req(?:uest)?\.params\[",
            r"`#\{env\[.*?QUERY_STRING",
            r"`#\{request\.(?:params|query_string|body)\[",
            r"IO\.popen\s*\(\s*req(?:uest)?\.params\[",
            r"system\s*\(\s*req(?:uest)?\.params\[",
        ],
        "description": "Ruby Rack shell — backtick/system with req.params or request.params",
    },

    # FN-7: obf_002 — PHP heredoc variable function
    "php_heredoc_shell": {
        "technique": "T1505.003",
        "name": "PHP Heredoc Variable Function Shell",
        "risk": 0.91,
        "patterns": [
            r"<<<\w+\s*\n\s*(?:system|exec|passthru|shell_exec|assert)\s*\n\s*\w+\s*;.*?\$\w+\s*\(",
            r"\$\w+\s*=\s*<<<\w+\s*\n(?:system|exec|passthru|shell_exec)\s*\n\w+\s*;\s*\$\w+\s*\(\s*\$_",
            r"<<<[A-Z]+\s*\n\s*(?:system|exec|passthru)\s*\n\s*[A-Z]+\s*;",
        ],
        "description": "PHP heredoc assigns shell function name to var — evades string-based detection",
    },
}

# Merge FN patches into main signatures dict
WEBSHELL_SIGNATURES.update(WEBSHELL_SIGNATURES_FN_PATCHES)
