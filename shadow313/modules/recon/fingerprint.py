"""shadow313.modules.recon.fingerprint — Web technology fingerprinting."""
from __future__ import annotations
from urllib import request as urlreq


def _http_get(url: str, timeout: int = 10) -> dict:
    try:
        req = urlreq.Request(url, headers={"User-Agent": "shadow313/2.0 (security-research)"})
        with urlreq.urlopen(req, timeout=timeout) as resp:
            return {
                "status":  resp.status,
                "body":    resp.read().decode("utf-8", errors="replace"),
                "headers": dict(resp.headers),
            }
    except Exception as exc:
        return {"status": 0, "body": "", "error": str(exc), "headers": {}}


class WebFingerprinter:
    TECH_SIGS: dict[str, list[str]] = {
        "WordPress":  ["wp-content", "wp-includes", "WordPress"],
        "Drupal":     ["Drupal.settings", "drupal.org"],
        "Joomla":     ["/components/com_", "Joomla!"],
        "Django":     ["csrfmiddlewaretoken", "__admin_media_prefix__"],
        "Laravel":    ["laravel_session", "X-Powered-By: PHP", "laravel"],
        "React":      ["react.development.js", "react.production.min.js", "__reactFiber"],
        "Angular":    ["ng-version", "angular.min.js"],
        "Vue":        ["vue.min.js", "__vue__"],
        "jQuery":     ["jquery.min.js", "jQuery v"],
        "Bootstrap":  ["bootstrap.min.css", "bootstrap.min.js"],
        "Nginx":      ["nginx"],
        "Apache":     ["Apache"],
        "IIS":        ["IIS", "X-Powered-By: ASP.NET"],
        "ASP.NET":    ["__VIEWSTATE", "ASP.NET"],
        "PHP":        ["X-Powered-By: PHP", ".php"],
        "Node.js":    ["X-Powered-By: Express"],
        "Tomcat":     ["Apache Tomcat", "Coyote"],
        "Flask":      ["Werkzeug", "flask"],
        "Express":    ["X-Powered-By: Express"],
        "Cloudflare": ["cf-ray", "cloudflare"],
    }

    SECURITY_HEADERS = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ]

    def __init__(self, url: str) -> None:
        self.url = url if url.startswith("http") else f"https://{url}"

    def fingerprint(self) -> dict:
        res = _http_get(self.url)
        if not res.get("body") and not res.get("headers"):
            return {"url": self.url, "error": res.get("error", "unreachable"), "tech": []}
        combined = res["body"][:50000] + " ".join(
            f"{k}: {v}" for k, v in res["headers"].items()
        )
        detected = [
            tech for tech, sigs in self.TECH_SIGS.items()
            if any(sig.lower() in combined.lower() for sig in sigs)
        ]
        return {
            "url":          self.url,
            "status_code":  res["status"],
            "server":       res["headers"].get("Server", ""),
            "x_powered":    res["headers"].get("X-Powered-By", ""),
            "content_type": res["headers"].get("Content-Type", ""),
            "tech":         detected,
            "headers":      dict(list(res["headers"].items())[:20]),
        }

    def check_security_headers(self) -> dict[str, str]:
        res = _http_get(self.url)
        headers = res.get("headers", {})
        return {h: headers.get(h, "MISSING") for h in self.SECURITY_HEADERS}