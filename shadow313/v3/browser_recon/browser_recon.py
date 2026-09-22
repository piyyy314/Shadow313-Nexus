"""
shadow313.v3.browser_recon.browser_recon  — v4
Playwright-powered fingerprinting of JavaScript-heavy SPAs.
Dynamic content extraction, CSP analysis, SPA framework detection.

Falls back to requests-based static analysis when Playwright is unavailable.
"""
from __future__ import annotations
import json
import re
import socket
import ssl
from typing import Any
from urllib import request as urlreq


# ── Static fallback fingerprinter ─────────────────────────────────────────────

class StaticFingerprinter:
    """HTTP-based fingerprinting without browser (fallback)."""

    SPA_SIGNATURES = {
        "React":      ["__reactFiber", "react.development.js", "react.production.min.js"],
        "Vue":        ["__vue__", "vue.min.js", "vue.esm.js"],
        "Angular":    ["ng-version", "angular.min.js", "ng-app"],
        "Svelte":     ["__svelte", "svelte.js"],
        "Next.js":    ["__NEXT_DATA__", "_next/static"],
        "Nuxt.js":    ["__nuxt", "__NUXT__"],
        "Gatsby":     ["gatsby-chunk", "___gatsby"],
        "Ember":      ["ember.min.js", "Ember.VERSION"],
        "Backbone":   ["Backbone.VERSION", "backbone.js"],
    }

    CSP_DIRECTIVES = [
        "default-src", "script-src", "style-src", "img-src",
        "connect-src", "font-src", "object-src", "frame-src",
        "base-uri", "form-action",
    ]

    def fingerprint(self, url: str) -> dict:
        if not url.startswith("http"):
            url = f"https://{url}"
        result: dict[str, Any] = {"url": url, "method": "static"}
        try:
            req = urlreq.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (shadow313/4.0 security-research)",
                "Accept": "text/html,application/xhtml+xml",
            })
            with urlreq.urlopen(req, timeout=15) as resp:
                body    = resp.read().decode("utf-8", errors="replace")
                headers = dict(resp.headers)
                result["status_code"] = resp.status
        except Exception as exc:
            result["error"] = str(exc)
            return result

        # SPA detection
        detected_spas = []
        for spa, sigs in self.SPA_SIGNATURES.items():
            if any(sig.lower() in body.lower() for sig in sigs):
                detected_spas.append(spa)
        result["spa_frameworks"] = detected_spas

        # CSP analysis
        csp_header = headers.get("Content-Security-Policy", "")
        result["csp"] = self._analyse_csp(csp_header)

        # Security headers
        result["security_headers"] = {
            "Strict-Transport-Security": headers.get("Strict-Transport-Security", "MISSING"),
            "Content-Security-Policy":   csp_header or "MISSING",
            "X-Frame-Options":           headers.get("X-Frame-Options", "MISSING"),
            "X-Content-Type-Options":    headers.get("X-Content-Type-Options", "MISSING"),
            "Referrer-Policy":           headers.get("Referrer-Policy", "MISSING"),
            "Permissions-Policy":        headers.get("Permissions-Policy", "MISSING"),
        }

        # Extract inline scripts (first 5)
        scripts = re.findall(r"<script[^>]*>(.*?)</script>", body, re.DOTALL | re.IGNORECASE)
        result["inline_scripts"] = [s[:200] for s in scripts[:5]]

        # Extract external script sources
        ext_scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.IGNORECASE)
        result["external_scripts"] = ext_scripts[:20]

        # API endpoint hints
        api_hints = re.findall(r'["\']/(api|v\d+|graphql|rest)[^"\']*["\']', body, re.IGNORECASE)
        result["api_hints"] = list(set(api_hints))[:10]

        return result

    def _analyse_csp(self, csp: str) -> dict:
        if not csp:
            return {"present": False, "issues": ["CSP header missing"]}
        issues = []
        if "'unsafe-inline'" in csp:
            issues.append("unsafe-inline allows XSS")
        if "'unsafe-eval'" in csp:
            issues.append("unsafe-eval allows code injection")
        if "data:" in csp:
            issues.append("data: URI scheme may allow injection")
        if "*" in csp:
            issues.append("Wildcard (*) in CSP is overly permissive")
        directives = {}
        for directive in self.CSP_DIRECTIVES:
            m = re.search(rf"{directive}\s+([^;]+)", csp)
            if m:
                directives[directive] = m.group(1).strip()
        return {
            "present":    True,
            "directives": directives,
            "issues":     issues,
            "score":      max(0, 10 - len(issues) * 2),
        }


# ── Playwright fingerprinter ──────────────────────────────────────────────────

class PlaywrightFingerprinter:
    """Playwright-based dynamic fingerprinting for SPAs."""

    def __init__(self) -> None:
        self._available = False
        try:
            import playwright  # noqa: F401
            self._available = True
        except ImportError:
            pass

    @property
    def available(self) -> bool:
        return self._available

    def fingerprint(self, url: str) -> dict:
        if not self._available:
            return {"error": "playwright not installed — pip install playwright && playwright install chromium"}
        if not url.startswith("http"):
            url = f"https://{url}"
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page    = browser.new_page()

                # Collect network requests
                requests_made: list[str] = []
                page.on("request", lambda req: requests_made.append(req.url))

                page.goto(url, wait_until="networkidle", timeout=30000)

                # Extract dynamic content
                title   = page.title()
                content = page.content()

                # JavaScript evaluation
                js_globals = page.evaluate("""() => {
                    return {
                        react:   typeof window.__reactFiber !== 'undefined' || typeof window.React !== 'undefined',
                        vue:     typeof window.__vue__ !== 'undefined' || typeof window.Vue !== 'undefined',
                        angular: typeof window.ng !== 'undefined',
                        jquery:  typeof window.jQuery !== 'undefined',
                        next:    typeof window.__NEXT_DATA__ !== 'undefined',
                        nuxt:    typeof window.__NUXT__ !== 'undefined',
                    }
                }""")

                # Extract API calls from network requests
                api_calls = [r for r in requests_made if "/api/" in r or "/graphql" in r]

                # CSP from meta tag
                csp_meta = page.evaluate("""() => {
                    const meta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
                    return meta ? meta.getAttribute('content') : '';
                }""")

                browser.close()

                static = StaticFingerprinter()
                return {
                    "url":             url,
                    "method":          "playwright",
                    "title":           title,
                    "spa_frameworks":  [k for k, v in js_globals.items() if v],
                    "api_calls":       api_calls[:20],
                    "csp_meta":        csp_meta,
                    "csp":             static._analyse_csp(csp_meta),
                    "network_requests":len(requests_made),
                    "content_length":  len(content),
                }
        except Exception as exc:
            return {"error": str(exc), "url": url}


# ── BrowserReconModule ────────────────────────────────────────────────────────

class BrowserReconModule:
    """shadow313.v3.browser_recon — Browser-based recon. Registered: browser_recon"""

    def __init__(self, kernel) -> None:
        self.kernel   = kernel
        self.out      = kernel.out
        self.session  = kernel.session
        self._pw      = PlaywrightFingerprinter()
        self._static  = StaticFingerprinter()

    def register(self, kernel) -> None:
        kernel.register("browser_recon", self.run)

    def run(
        self,
        target: str = "",
        use_playwright: bool = False,
        csp_audit: bool = False,
    ) -> dict:
        self.out.section("BROWSER RECON")
        if not target:
            self.out.error("--target required")
            return {}

        if use_playwright and self._pw.available:
            self.out.info(f"Playwright fingerprinting: {target} …")
            result = self._pw.fingerprint(target)
        else:
            if use_playwright:
                self.out.warn("Playwright not available — using static analysis")
            self.out.info(f"Static fingerprinting: {target} …")
            result = self._static.fingerprint(target)

        if result.get("spa_frameworks"):
            self.out.success(f"SPA frameworks detected: {', '.join(result['spa_frameworks'])}")

        if csp_audit or True:
            csp = result.get("csp", {})
            if csp.get("issues"):
                for issue in csp["issues"]:
                    self.out.warn(f"CSP: {issue}")
            else:
                self.out.success("CSP looks well-configured")

        sec_headers = result.get("security_headers", {})
        if sec_headers:
            missing = [h for h, v in sec_headers.items() if v == "MISSING"]
            if missing:
                self.out.warn(f"Missing security headers: {', '.join(missing)}")

        # AI analysis
        result["ai_analysis"] = self.kernel.ai.chat(
            "Analyse this browser fingerprint for security issues. "
            "Focus on: missing security headers, CSP weaknesses, exposed API endpoints, "
            "and SPA-specific attack surface.",
            context=result,
        )
        self.out.ai_response(result["ai_analysis"], "Browser Security Analysis")

        self.session.write("browser_recon.json", result)
        return result