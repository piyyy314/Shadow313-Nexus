"""
Shadow313 — GhostHTTP
HTTP fingerprinting engine. Extracts server secrets from timing
side-channels, error messages, header inconsistencies, and behavioral
analysis. Identifies hidden technologies, WAF presence, and
information disclosure vulnerabilities.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

try:
    from shadow313.core.kernel import KernelContext, register_command
except ImportError:
    KernelContext = object
    def register_command(*a, **kw): pass  # nosec

try:
    from shadow313.tools.base import BaseTool, ToolResult
except ImportError:
    BaseTool = object
    class ToolResult:  # nosec
        def __init__(self, **kw): self.__dict__.update(kw)

# ── Probe paths for technology detection ──────────────────────────────────
TECH_PROBES: list[dict[str, Any]] = [
    # CMS Detection
    {"path": "/wp-login.php",           "tech": "WordPress",      "indicator": "wp-login"},
    {"path": "/wp-admin/",              "tech": "WordPress",      "indicator": "WordPress"},
    {"path": "/administrator/",         "tech": "Joomla",         "indicator": "Joomla"},
    {"path": "/user/login",             "tech": "Drupal",         "indicator": "Drupal"},
    {"path": "/typo3/",                 "tech": "TYPO3",          "indicator": "TYPO3"},
    # Framework Detection
    {"path": "/rails/info/properties",  "tech": "Ruby on Rails",  "indicator": "Rails"},
    {"path": "/actuator/health",        "tech": "Spring Boot",    "indicator": "status"},
    {"path": "/api/swagger.json",       "tech": "Swagger/OpenAPI","indicator": "swagger"},
    {"path": "/swagger-ui.html",        "tech": "Swagger UI",     "indicator": "swagger"},
    {"path": "/.env",                   "tech": "Env File",       "indicator": "APP_"},
    {"path": "/config.php",             "tech": "PHP Config",     "indicator": "<?php"},
    {"path": "/phpinfo.php",            "tech": "PHP Info",       "indicator": "phpinfo"},
    # Admin Panels
    {"path": "/admin",                  "tech": "Admin Panel",    "indicator": "admin"},
    {"path": "/admin/login",            "tech": "Admin Login",    "indicator": "login"},
    {"path": "/phpmyadmin/",            "tech": "phpMyAdmin",     "indicator": "phpMyAdmin"},
    {"path": "/adminer.php",            "tech": "Adminer",        "indicator": "adminer"},
    # API Endpoints
    {"path": "/api/v1/",                "tech": "REST API v1",    "indicator": None},
    {"path": "/graphql",                "tech": "GraphQL",        "indicator": "graphql"},
    {"path": "/.well-known/security.txt","tech": "Security.txt",  "indicator": "Contact"},
    # Version Files
    {"path": "/CHANGELOG.md",           "tech": "Changelog",      "indicator": None},
    {"path": "/VERSION",                "tech": "Version File",   "indicator": None},
    {"path": "/robots.txt",             "tech": "Robots.txt",     "indicator": None},
    {"path": "/sitemap.xml",            "tech": "Sitemap",        "indicator": None},
    # Cloud/Infrastructure
    {"path": "/.git/HEAD",              "tech": "Git Repo",       "indicator": "ref:"},
    {"path": "/.git/config",            "tech": "Git Config",     "indicator": "[core]"},
    {"path": "/.svn/entries",           "tech": "SVN Repo",       "indicator": None},
    {"path": "/server-status",          "tech": "Apache Status",  "indicator": "Apache"},
    {"path": "/nginx_status",           "tech": "Nginx Status",   "indicator": "Active connections"},
]

# ── WAF fingerprints ───────────────────────────────────────────────────────
WAF_SIGNATURES: dict[str, dict[str, Any]] = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
        "body": ["cloudflare", "cf-browser-verification"],
        "status_codes": [403, 503],
    },
    "AWS WAF": {
        "headers": ["x-amzn-requestid", "x-amz-cf-id"],
        "body": ["aws", "request blocked"],
        "status_codes": [403],
    },
    "Akamai": {
        "headers": ["x-akamai-transformed", "akamai-origin-hop"],
        "body": ["akamai", "reference #"],
        "status_codes": [403],
    },
    "Imperva/Incapsula": {
        "headers": ["x-iinfo", "x-cdn"],
        "body": ["incapsula", "imperva"],
        "status_codes": [403],
    },
    "F5 BIG-IP": {
        "headers": ["x-wa-info", "x-cnection"],
        "body": ["the requested url was rejected", "f5"],
        "status_codes": [403],
    },
    "ModSecurity": {
        "headers": ["x-mod-security"],
        "body": ["mod_security", "not acceptable"],
        "status_codes": [406, 501],
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "body": ["sucuri", "access denied"],
        "status_codes": [403],
    },
}

# ── Information disclosure patterns ───────────────────────────────────────
INFO_DISCLOSURE_PATTERNS = [
    (r"(?i)mysql.*error|sql syntax|ORA-\d+|pg_query|sqlite_",
     "Database Error Disclosure", "CRITICAL"),
    (r"(?i)stack trace|traceback|exception in|at line \d+",
     "Stack Trace Disclosure", "HIGH"),
    (r"(?i)internal server error.*version|server.*apache/[\d.]+|nginx/[\d.]+",
     "Server Version Disclosure", "MEDIUM"),
    (r"(?i)debug.*true|app_debug.*true|display_errors.*on",
     "Debug Mode Enabled", "HIGH"),
    (r"(?i)password|passwd|secret|api_key|token.*=.*['\"][^'\"]{8,}",
     "Credential Disclosure", "CRITICAL"),
    (r"(?i)aws_access_key|aws_secret|AKIA[0-9A-Z]{16}",
     "AWS Credential Disclosure", "CRITICAL"),
    (r"(?i)private key|BEGIN RSA|BEGIN EC PRIVATE",
     "Private Key Disclosure", "CRITICAL"),
    (r"(?i)phpinfo\(\)|php version|php/[\d.]+",
     "PHP Version Disclosure", "MEDIUM"),
    (r"(?i)x-powered-by.*php|x-powered-by.*asp",
     "Technology Disclosure via Header", "LOW"),
    (r"(?i)server.*microsoft-iis|server.*apache|server.*nginx",
     "Server Software Disclosure", "LOW"),
]


class GhostHTTP(BaseTool):
    """
    GhostHTTP — HTTP Fingerprinting Engine

    Capabilities:
    - Technology stack detection via behavioral probing
    - WAF/CDN identification and bypass hints
    - Information disclosure detection (errors, debug, credentials)
    - Timing side-channel analysis
    - HTTP header security assessment
    - Hidden endpoint discovery
    - Git/SVN repository exposure detection
    - API endpoint enumeration
    """

    TOOL_NAME = "ghosthttp"
    TEAM = "redteam"
    DESCRIPTION = "HTTP fingerprinting engine — WAF detection, info disclosure, timing analysis"

    async def run(self, target: str, **kwargs: Any) -> ToolResult:
        result = ToolResult(tool_name=self.TOOL_NAME, target=target)

        # Normalize URL
        base_url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        self.output.section("GHOSTHTTP", f"HTTP Fingerprinting — {base_url}")

        async with httpx.AsyncClient(
            timeout=10,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (compatible; Shadow313/2.0)"},
        ) as client:

            # ── Baseline request ───────────────────────────────────────────
            self.output.info("Establishing baseline...")
            baseline = await self._baseline_request(client, base_url)

            # ── Header analysis ────────────────────────────────────────────
            self.output.info("Analyzing HTTP headers...")
            header_findings = self._analyze_headers(baseline, base_url)
            result.findings.extend(header_findings)

            # ── WAF detection ──────────────────────────────────────────────
            self.output.info("Detecting WAF/CDN...")
            waf_result = await self._detect_waf(client, base_url, baseline)

            # ── Technology probing ─────────────────────────────────────────
            self.output.info(f"Probing {len(TECH_PROBES)} technology endpoints...")
            tech_findings, discovered_paths = await self._probe_technologies(client, base_url)
            result.findings.extend(tech_findings)

            # ── Information disclosure ─────────────────────────────────────
            self.output.info("Scanning for information disclosure...")
            disclosure_findings = await self._scan_info_disclosure(client, base_url, discovered_paths)
            result.findings.extend(disclosure_findings)

            # ── Timing analysis ────────────────────────────────────────────
            self.output.info("Running timing side-channel analysis...")
            timing_data = await self._timing_analysis(client, base_url)

            # ── Error page analysis ────────────────────────────────────────
            error_findings = await self._analyze_error_pages(client, base_url)
            result.findings.extend(error_findings)

            # ── Security headers ───────────────────────────────────────────
            sec_header_findings = self._check_security_headers(baseline)
            result.findings.extend(sec_header_findings)

        result.data = {
            "base_url": base_url,
            "baseline": {
                "status_code": baseline.get("status_code"),
                "server": baseline.get("server", ""),
                "technologies": baseline.get("technologies", []),
                "https": base_url.startswith("https://"),
            },
            "waf": waf_result,
            "discovered_paths": discovered_paths,
            "timing": timing_data,
            "total_findings": len(result.findings),
        }

        self._display_results(result)
        return result

    def ai_context(self, result: ToolResult) -> str:
        return f"""
Analyze these GhostHTTP fingerprinting results for {result.data.get('base_url')}.

Server: {result.data.get('baseline', {}).get('server', 'unknown')}
Technologies: {result.data.get('baseline', {}).get('technologies', [])}
WAF Detected: {result.data.get('waf', {}).get('detected', False)} — {result.data.get('waf', {}).get('waf_name', 'none')}
Discovered Paths: {result.data.get('discovered_paths', [])}
Timing Anomalies: {result.data.get('timing', {}).get('anomalies', [])}

Findings ({len(result.findings)} total):
{json.dumps([{'title': f['title'], 'severity': f['severity']} for f in result.findings[:10]], indent=2)}

Provide:
1. **Technology Stack Assessment** — what's running and what vulnerabilities are likely
2. **WAF Bypass Strategies** — if WAF detected, suggest bypass techniques for authorized testing
3. **Information Disclosure Impact** — what the disclosed information reveals about the target
4. **Attack Surface** — which discovered paths/endpoints are highest priority to test
5. **Quick Wins** — vulnerabilities most likely to yield results in the next 30 minutes
""".strip()

    # ── Baseline Request ───────────────────────────────────────────────────

    async def _baseline_request(self, client: httpx.AsyncClient, url: str) -> dict[str, Any]:
        """Make baseline request and extract all useful information."""
        result: dict[str, Any] = {
            "status_code": None, "headers": {}, "server": "",
            "technologies": [], "title": "", "body_hash": "",
            "response_time_ms": 0,
        }
        try:
            t0 = time.monotonic()
            r = await client.get(url)
            result["response_time_ms"] = round((time.monotonic() - t0) * 1000, 1)
            result["status_code"] = r.status_code
            result["headers"] = dict(r.headers)
            result["server"] = r.headers.get("server", "")
            result["body_hash"] = hashlib.md5(r.content).hexdigest()

            # Extract title
            title_match = re.search(r"<title[^>]*>([^<]+)</title>", r.text, re.I)
            if title_match:
                result["title"] = title_match.group(1).strip()

            # Detect technologies from headers
            techs = []
            powered_by = r.headers.get("x-powered-by", "")
            if powered_by:
                techs.append(powered_by)
            if "wp-" in r.text.lower():
                techs.append("WordPress")
            if "drupal" in r.text.lower():
                techs.append("Drupal")
            result["technologies"] = techs

        except Exception as e:
            result["error"] = str(e)
        return result

    # ── Header Analysis ────────────────────────────────────────────────────

    def _analyze_headers(self, baseline: dict[str, Any], url: str) -> list[dict[str, Any]]:
        """Extract intelligence from HTTP response headers."""
        findings = []
        headers = baseline.get("headers", {})
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # Version disclosure in Server header
        server = headers_lower.get("server", "")
        if server and re.search(r"[\d.]+", server):
            findings.append(self._finding(
                title=f"Server Version Disclosure: {server}",
                severity="LOW",
                description=f"Server header reveals version: '{server}'. This aids attacker reconnaissance.",
                data={"header": "Server", "value": server},
                remediation="Configure server to return generic 'Server: webserver' header",
                mitre_technique="T1592.002",
            ))

        # X-Powered-By disclosure
        powered_by = headers_lower.get("x-powered-by", "")
        if powered_by:
            findings.append(self._finding(
                title=f"Technology Disclosure: X-Powered-By: {powered_by}",
                severity="LOW",
                description=f"X-Powered-By header reveals: '{powered_by}'",
                data={"header": "X-Powered-By", "value": powered_by},
                remediation="Remove X-Powered-By header from server configuration",
                mitre_technique="T1592.002",
            ))

        # Internal IP disclosure
        for header_name, header_val in headers_lower.items():
            ip_match = re.search(r"\b(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b", header_val)
            if ip_match:
                findings.append(self._finding(
                    title=f"Internal IP Disclosure in Header: {header_name}",
                    severity="MEDIUM",
                    description=f"Header '{header_name}' reveals internal IP: {ip_match.group(0)}",
                    data={"header": header_name, "ip": ip_match.group(0)},
                    remediation=f"Remove or sanitize the {header_name} header",
                    mitre_technique="T1590.005",
                ))

        return findings

    # ── WAF Detection ──────────────────────────────────────────────────────

    async def _detect_waf(
        self, client: httpx.AsyncClient, url: str, baseline: dict[str, Any]
    ) -> dict[str, Any]:
        """Detect WAF/CDN presence via header and behavioral analysis."""
        result = {"detected": False, "waf_name": None, "confidence": 0.0, "bypass_hints": []}

        headers_lower = {k.lower(): v.lower() for k, v in baseline.get("headers", {}).items()}

        # Send a WAF-triggering payload
        waf_payload = "/?id=1' OR '1'='1"
        try:
            r = await client.get(urljoin(url, waf_payload))
            waf_body = r.text.lower()
            waf_headers = {k.lower(): v.lower() for k, v in r.headers.items()}
            waf_status = r.status_code
        except Exception:
            waf_body, waf_headers, waf_status = "", {}, 0

        # Check signatures
        for waf_name, sig in WAF_SIGNATURES.items():
            score = 0
            for header in sig["headers"]:
                if header in headers_lower or header in waf_headers:
                    score += 2
            for indicator in sig["body"]:
                if indicator in waf_body:
                    score += 2
            if waf_status in sig["status_codes"]:
                score += 1

            if score >= 2:
                result["detected"] = True
                result["waf_name"] = waf_name
                result["confidence"] = min(1.0, score / 5)
                result["bypass_hints"] = self._get_waf_bypass_hints(waf_name)
                break

        return result

    def _get_waf_bypass_hints(self, waf_name: str) -> list[str]:
        """Return WAF-specific bypass hints for authorized testing."""
        hints = {
            "Cloudflare": [
                "Use origin IP directly if discoverable via DNS history",
                "Try HTTP/2 requests — some CF rules only apply to HTTP/1.1",
                "Encode payloads with double URL encoding",
                "Use case variation: SeLeCt instead of SELECT",
            ],
            "ModSecurity": [
                "Try comment injection: SE/**/LECT",
                "Use HTTP parameter pollution",
                "Encode with Unicode normalization",
                "Try chunked transfer encoding",
            ],
            "AWS WAF": [
                "Check for IP-based bypass via X-Forwarded-For header",
                "Try JSON-based SQL injection payloads",
                "Use AWS WAF rule set gaps for specific payload types",
            ],
        }
        return hints.get(waf_name, ["Try encoding variations", "Use HTTP parameter pollution"])

    # ── Technology Probing ─────────────────────────────────────────────────

    async def _probe_technologies(
        self, client: httpx.AsyncClient, base_url: str
    ) -> tuple[list[dict[str, Any]], list[str]]:
        """Probe for technology-specific paths and endpoints."""
        findings = []
        discovered_paths = []

        async def probe_path(probe: dict[str, Any]) -> None:
            url = urljoin(base_url, probe["path"])
            try:
                r = await client.get(url)
                if r.status_code in (200, 301, 302, 403):
                    body = r.text[:2000]
                    indicator = probe.get("indicator")
                    matched = (
                        not indicator or
                        indicator.lower() in body.lower() or
                        indicator.lower() in r.headers.get("content-type", "").lower()
                    )

                    if matched or r.status_code == 200:
                        discovered_paths.append(probe["path"])
                        sev = self._path_severity(probe["path"], probe["tech"], r.status_code)

                        # Special handling for critical exposures
                        if probe["tech"] in ("Git Repo", "Git Config", "Env File", "PHP Info"):
                            sev = "CRITICAL"
                            findings.append(self._finding(
                                title=f"Critical Exposure: {probe['tech']} at {probe['path']}",
                                severity=sev,
                                description=(
                                    f"{probe['tech']} accessible at {url} "
                                    f"(HTTP {r.status_code}). "
                                    f"This may expose source code, credentials, or configuration."
                                ),
                                data={"path": probe["path"], "status": r.status_code,
                                      "tech": probe["tech"], "preview": body[:200]},
                                remediation=f"Immediately restrict access to {probe['path']}",
                                mitre_technique="T1552.001",
                            ))
                        elif r.status_code == 200 and sev in ("HIGH", "MEDIUM"):
                            findings.append(self._finding(
                                title=f"Discovered: {probe['tech']} ({probe['path']})",
                                severity=sev,
                                description=f"{probe['tech']} found at {url} (HTTP {r.status_code})",
                                data={"path": probe["path"], "status": r.status_code, "tech": probe["tech"]},
                                remediation=f"Restrict access to {probe['path']} if not required",
                                mitre_technique="T1083",
                            ))
            except Exception as _e:  # nosec
                pass  # intentional — probe failure is non-critical

        # Run probes concurrently in batches
        batch_size = 10
        for i in range(0, len(TECH_PROBES), batch_size):
            batch = TECH_PROBES[i:i + batch_size]
            await asyncio.gather(*[probe_path(p) for p in batch])
            await asyncio.sleep(0.1)

        return findings, discovered_paths

    def _path_severity(self, path: str, tech: str, status: int) -> str:
        critical_paths = ["/.git/", "/.env", "/phpinfo", "/.svn/", "/config.php"]
        high_paths = ["/admin", "/phpmyadmin", "/adminer", "/server-status", "/actuator"]
        if any(cp in path for cp in critical_paths):
            return "CRITICAL"
        if any(hp in path for hp in high_paths):
            return "HIGH"
        if status == 200:
            return "MEDIUM"
        return "LOW"

    # ── Information Disclosure ─────────────────────────────────────────────

    async def _scan_info_disclosure(
        self, client: httpx.AsyncClient, base_url: str, discovered_paths: list[str]
    ) -> list[dict[str, Any]]:
        """Scan discovered paths for information disclosure."""
        findings = []
        paths_to_scan = ["/"] + discovered_paths[:10]

        for path in paths_to_scan:
            url = urljoin(base_url, path)
            try:
                r = await client.get(url)
                body = r.text[:5000]
                for pattern, title, severity in INFO_DISCLOSURE_PATTERNS:
                    match = re.search(pattern, body)
                    if match:
                        findings.append(self._finding(
                            title=f"{title} at {path}",
                            severity=severity,
                            description=(
                                f"{title} detected at {url}. "
                                f"Matched: '{match.group(0)[:100]}'"
                            ),
                            data={"path": path, "pattern": pattern, "match": match.group(0)[:100]},
                            remediation=f"Fix {title.lower()} at {path}",
                            mitre_technique="T1552",
                        ))
            except Exception as _e:  # nosec
                pass  # intentional — probe failure is non-critical

        return findings

    # ── Timing Analysis ────────────────────────────────────────────────────

    async def _timing_analysis(
        self, client: httpx.AsyncClient, base_url: str
    ) -> dict[str, Any]:
        """Analyze response timing for side-channel information."""
        timings = []
        anomalies = []

        # Measure response times for different paths
        test_paths = ["/", "/admin", "/login", "/api", "/nonexistent_path_xyz"]
        for path in test_paths:
            url = urljoin(base_url, path)
            try:
                t0 = time.monotonic()
                r = await client.get(url)
                elapsed = round((time.monotonic() - t0) * 1000, 1)
                timings.append({"path": path, "ms": elapsed, "status": r.status_code})
            except Exception as _e:  # nosec
                pass  # intentional — probe failure is non-critical

        # Detect timing anomalies
        if timings:
            avg_time = sum(t["ms"] for t in timings) / len(timings)
            for t in timings:
                if t["ms"] > avg_time * 3 and t["ms"] > 500:
                    anomalies.append({
                        "path": t["path"],
                        "ms": t["ms"],
                        "avg_ms": round(avg_time, 1),
                        "description": (
                            f"Path {t['path']} responds in {t['ms']}ms vs avg {avg_time:.0f}ms. "
                            "Timing difference may indicate backend processing (auth check, DB query)."
                        ),
                    })

        return {"timings": timings, "anomalies": anomalies, "avg_ms": round(avg_time if timings else 0, 1)}

    # ── Error Page Analysis ────────────────────────────────────────────────

    async def _analyze_error_pages(
        self, client: httpx.AsyncClient, base_url: str
    ) -> list[dict[str, Any]]:
        """Trigger and analyze error pages for information disclosure."""
        findings = []
        error_triggers = [
            "/nonexistent_page_xyz_404",
            "/admin/../../../../etc/passwd",
            "/?id=1'",
        ]

        for path in error_triggers:
            url = urljoin(base_url, path)
            try:
                r = await client.get(url)
                body = r.text[:3000]

                for pattern, title, severity in INFO_DISCLOSURE_PATTERNS:
                    if re.search(pattern, body, re.I):
                        findings.append(self._finding(
                            title=f"{title} in Error Response",
                            severity=severity,
                            description=f"Error page at {url} reveals: {title}",
                            data={"trigger": path, "status": r.status_code},
                            remediation="Configure custom error pages that don't reveal stack traces or server info",
                            mitre_technique="T1592",
                        ))
                        break
            except Exception as _e:  # nosec
                pass  # intentional — probe failure is non-critical

        return findings

    # ── Security Headers ───────────────────────────────────────────────────

    def _check_security_headers(self, baseline: dict[str, Any]) -> list[dict[str, Any]]:
        """Check for missing or misconfigured security headers."""
        findings = []
        headers_lower = {k.lower(): v for k, v in baseline.get("headers", {}).items()}

        security_headers = {
            "strict-transport-security": {
                "title": "Missing HSTS Header",
                "severity": "MEDIUM",
                "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            },
            "content-security-policy": {
                "title": "Missing Content-Security-Policy Header",
                "severity": "MEDIUM",
                "remediation": "Add a restrictive CSP header to prevent XSS attacks",
            },
            "x-frame-options": {
                "title": "Missing X-Frame-Options Header",
                "severity": "LOW",
                "remediation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
            },
            "x-content-type-options": {
                "title": "Missing X-Content-Type-Options Header",
                "severity": "LOW",
                "remediation": "Add: X-Content-Type-Options: nosniff",
            },
            "permissions-policy": {
                "title": "Missing Permissions-Policy Header",
                "severity": "LOW",
                "remediation": "Add Permissions-Policy to restrict browser feature access",
            },
        }

        for header, info in security_headers.items():
            if header not in headers_lower:
                findings.append(self._finding(
                    title=info["title"],
                    severity=info["severity"],
                    description=f"Security header '{header}' is not set.",
                    data={"missing_header": header},
                    remediation=info["remediation"],
                    mitre_technique="T1059.007",
                ))

        return findings

    # ── Display ────────────────────────────────────────────────────────────

    def _display_results(self, result: ToolResult) -> None:
        data = result.data
        waf = data.get("waf", {})

        self.output.kv_table({
            "Target": data.get("base_url", ""),
            "Status": str(data.get("baseline", {}).get("status_code", "")),
            "Server": data.get("baseline", {}).get("server", "unknown"),
            "Technologies": ", ".join(data.get("baseline", {}).get("technologies", [])) or "none detected",
            "WAF": f"{waf.get('waf_name', 'None')} (confidence: {waf.get('confidence', 0):.0%})" if waf.get("detected") else "Not detected",
            "Paths Discovered": str(len(data.get("discovered_paths", []))),
            "Timing Anomalies": str(len(data.get("timing", {}).get("anomalies", []))),
            "Total Findings": str(data.get("total_findings", 0)),
        }, title="GhostHTTP Results")

        if result.findings:
            self.output.findings_table(
                sorted(result.findings, key=lambda f: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(f["severity"], 4))[:12],
                title="HTTP Findings"
            )


@register_command("tools", "ghosthttp")
async def run_ghosthttp(ctx: KernelContext, **kwargs: Any) -> dict[str, Any]:
    """GhostHTTP — HTTP fingerprinting engine."""
    target = kwargs.get("target", "")
    if not target:
        ctx.output.error("No target specified")
        return {}
    tool = GhostHTTP(ctx)
    result = await tool.run_with_ai(target, **kwargs)
    return result.to_dict()