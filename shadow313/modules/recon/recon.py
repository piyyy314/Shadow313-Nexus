"""
shadow313.modules.recon
Passive + active reconnaissance — DNS, subdomain, port scan, WHOIS,
web fingerprinting, OSINT aggregation, AI target profiling.
"""
from __future__ import annotations
import asyncio
import json
import socket
import ssl
import time
import re
from datetime import datetime, timezone
from typing import Any
from urllib import request as urlreq, error as urlerr


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _http_get(url: str, timeout: int = 10, headers: dict | None = None) -> dict:
    """Simple HTTP GET; returns {status, body, headers}."""
    try:
        req = urlreq.Request(url, headers=headers or {
            "User-Agent": "shadow313/1.0 (security-research)"
        })
        with urlreq.urlopen(req, timeout=timeout) as resp:
            return {
                "status":  resp.status,
                "body":    resp.read().decode("utf-8", errors="replace"),
                "headers": dict(resp.headers),
            }
    except Exception as exc:
        return {"status": 0, "body": "", "error": str(exc), "headers": {}}


# ── DNS resolver ──────────────────────────────────────────────────────────────

class DNSEnumerator:
    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    def __init__(self, domain: str) -> None:
        self.domain = domain

    def resolve(self) -> dict[str, list[str]]:
        results: dict[str, list[str]] = {}
        for rtype in self.RECORD_TYPES:
            records = self._query(rtype)
            if records:
                results[rtype] = records
        return results

    def _query(self, rtype: str) -> list[str]:
        """Use system resolver via socket for A records, stub others."""
        if rtype == "A":
            try:
                info = socket.getaddrinfo(self.domain, None, socket.AF_INET)
                return list({i[4][0] for i in info})
            except Exception:
                return []
        if rtype == "AAAA":
            try:
                info = socket.getaddrinfo(self.domain, None, socket.AF_INET6)
                return list({i[4][0] for i in info})
            except Exception:
                return []
        # For MX/NS/TXT/etc. — attempt via dns.resolver if dnspython installed
        try:
            import dns.resolver
            answers = dns.resolver.resolve(self.domain, rtype, lifetime=5)
            return [r.to_text() for r in answers]
        except ImportError:
            return ["[dnspython not installed — pip install dnspython]"]
        except Exception:
            return []


# ── Subdomain discovery ───────────────────────────────────────────────────────

class SubdomainScanner:
    CT_LOG_URL = "https://crt.sh/?q={domain}&output=json"
    DEFAULT_WORDLIST = [
        "www", "mail", "ftp", "api", "dev", "staging", "test",
        "admin", "vpn", "remote", "portal", "static", "cdn",
        "app", "beta", "secure", "login", "dashboard", "internal",
    ]

    def __init__(self, domain: str, wordlist: list[str] | None = None,
                 stealth: bool = False) -> None:
        import threading
        self._lock = threading.RLock()
        self.domain    = domain
        self.wordlist  = wordlist or self.DEFAULT_WORDLIST
        self.stealth   = stealth
        self.found: list[str] = []

    def from_ct_logs(self) -> list[str]:
        """Pull subdomains from certificate transparency logs."""
        url = self.CT_LOG_URL.format(domain=f"%.{self.domain}")
        res = _http_get(url, timeout=15)
        if not res.get("body"):
            return []
        try:
            entries = json.loads(res["body"])
            subs = set()
            for entry in entries:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lstrip("*.")
                    if sub.endswith(self.domain) and sub != self.domain:
                        subs.add(sub)
            with self._lock:
                self.found.extend(subs)
            return list(subs)
        except Exception:
            return []

    def from_wordlist(self) -> list[str]:
        """Resolve wordlist subdomains against DNS."""
        found = []
        for word in self.wordlist:
            candidate = f"{word}.{self.domain}"
            try:
                socket.getaddrinfo(candidate, None)
                found.append(candidate)
                if self.stealth:
                    time.sleep(0.5)
            except socket.gaierror:
                pass
        with self._lock:
            self.found.extend(found)
        return found

    def scan(self) -> list[str]:
        ct     = self.from_ct_logs()
        wl     = self.from_wordlist()
        unique = list({*ct, *wl})
        self.found = unique
        return unique


# ── Port scanner ──────────────────────────────────────────────────────────────

class PortScanner:
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
        443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443,
    ]

    def __init__(self, host: str, ports: list[int] | None = None,
                 timeout: float = 1.0, stealth: bool = False) -> None:
        self.host    = host
        self.ports   = ports or self.COMMON_PORTS
        self.timeout = timeout
        self.stealth = stealth

    async def _probe(self, port: int) -> dict | None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, port), timeout=self.timeout
            )
            banner = ""
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                banner = data.decode("utf-8", errors="replace").strip()
            except Exception:
                pass
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return {"port": port, "state": "open", "banner": banner[:200]}
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None

    async def scan_async(self) -> list[dict]:
        if self.stealth:
            # Sequential in stealth mode
            results = []
            for p in self.ports:
                r = await self._probe(p)
                if r:
                    results.append(r)
                await asyncio.sleep(0.3)
            return results
        tasks   = [self._probe(p) for p in self.ports]
        raw     = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in raw if isinstance(r, dict)]

    def scan(self) -> list[dict]:
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    future = pool.submit(asyncio.run, self.scan_async())
                    return future.result()
        except RuntimeError:
            pass
        return asyncio.run(self.scan_async())


# ── Web fingerprinter ─────────────────────────────────────────────────────────

class WebFingerprinter:
    TECH_SIGS: dict[str, list[str]] = {
        "WordPress":  ["wp-content", "wp-includes", "WordPress"],
        "Drupal":     ["Drupal.settings", "drupal.org"],
        "Joomla":     ["/components/com_", "Joomla!"],
        "Django":     ["csrfmiddlewaretoken", "__admin_media_prefix__"],
        "React":      ["react.development.js", "react.production.min.js", "__reactFiber"],
        "Angular":    ["ng-version", "angular.min.js"],
        "Vue":        ["vue.min.js", "__vue__"],
        "jQuery":     ["jquery.min.js", "jQuery v"],
        "Bootstrap":  ["bootstrap.min.css", "bootstrap.min.js"],
        "Nginx":      ["nginx"],
        "Apache":     ["Apache"],
        "IIS":        ["IIS", "X-Powered-By: ASP.NET"],
        "PHP":        ["X-Powered-By: PHP", ".php"],
        "Node.js":    ["X-Powered-By: Express"],
        "Cloudflare": ["cf-ray", "cloudflare"],
    }

    def __init__(self, url: str) -> None:
        self.url = url if url.startswith("http") else f"https://{url}"

    def fingerprint(self) -> dict:
        res = _http_get(self.url)
        if not res.get("body") and not res.get("headers"):
            return {"url": self.url, "error": res.get("error", "unreachable"), "tech": []}

        combined = res["body"][:50000] + " ".join(
            f"{k}: {v}" for k, v in res["headers"].items()
        )
        detected = []
        for tech, sigs in self.TECH_SIGS.items():
            if any(sig.lower() in combined.lower() for sig in sigs):
                detected.append(tech)

        return {
            "url":         self.url,
            "status_code": res["status"],
            "server":      res["headers"].get("Server", ""),
            "x_powered":   res["headers"].get("X-Powered-By", ""),
            "content_type":res["headers"].get("Content-Type", ""),
            "tech":        detected,
            "headers":     dict(list(res["headers"].items())[:20]),
        }

    def check_security_headers(self) -> dict[str, str]:
        res = _http_get(self.url)
        headers = res.get("headers", {})
        wanted = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
        ]
        return {h: headers.get(h, "MISSING") for h in wanted}


# ── WHOIS ─────────────────────────────────────────────────────────────────────

class WHOISLookup:
    WHOIS_SERVER = ("whois.iana.org", 43)

    def __init__(self, target: str) -> None:
        self.target = target

    def lookup(self) -> dict:
        try:
            import whois as python_whois  # python-whois package
            w = python_whois.whois(self.target)
            return {
                "domain":     self.target,
                "registrar":  str(w.registrar or ""),
                "created":    str(w.creation_date or ""),
                "expires":    str(w.expiration_date or ""),
                "updated":    str(w.updated_date or ""),
                "name_servers": w.name_servers or [],
                "status":     w.status or [],
                "emails":     w.emails or [],
                "org":        str(w.org or ""),
            }
        except ImportError:
            return self._raw_whois()
        except Exception as exc:
            return {"domain": self.target, "error": str(exc)}

    def _raw_whois(self) -> dict:
        """Fallback raw WHOIS socket query."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(10)
                s.connect(self.WHOIS_SERVER)
                s.send(f"{self.target}\r\n".encode())
                raw = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    raw += chunk
            text = raw.decode("utf-8", errors="replace")
            return {"domain": self.target, "raw": text[:3000]}
        except Exception as exc:
            return {"domain": self.target, "error": str(exc)}


# ── GeoIP & ASN ───────────────────────────────────────────────────────────────

def geoip_lookup(ip: str) -> dict:
    """Free GeoIP lookup via ip-api.com (no key required)."""
    url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,query"
    res = _http_get(url, timeout=8)
    if res.get("body"):
        try:
            return json.loads(res["body"])
        except Exception:
            pass
    return {"query": ip, "error": "GeoIP lookup failed"}


# ── Main ReconModule ──────────────────────────────────────────────────────────

class ReconModule:
    """
    shadow313.recon — Passive + active reconnaissance.
    Registered commands: recon
    """

    def __init__(self, kernel) -> None:
        self.kernel  = kernel
        self.config  = kernel.config.get("recon", default={})
        self.out     = kernel.out
        self.ai      = kernel.ai
        self.session = kernel.session

    def register(self, kernel) -> None:
        kernel.register("recon", self.run)

    # ── Entry point ───────────────────────────────────────────────────────────
    def run(self, target: str, mode: str = "full", ports: str = "",
            stealth: bool = False, output: str = "rich",
            wordlist: list[str] | None = None) -> dict:
        self.out.section(f"RECON  ▸  {target}")
        self.session.audit("recon", "start", target)
        self.session.set_target(target)

        host   = self._parse_host(target)
        result: dict[str, Any] = {
            "target":     target,
            "host":       host,
            "timestamp":  _now(),
            "mode":       mode,
        }

        # 1. WHOIS
        self.out.info("Running WHOIS lookup …")
        result["whois"] = WHOISLookup(host).lookup()

        # 2. DNS
        self.out.info("Enumerating DNS records …")
        result["dns"] = DNSEnumerator(host).resolve()

        # 3. Subdomains
        if mode in ("full", "passive"):
            self.out.info("Discovering subdomains via CT logs + wordlist …")
            result["subdomains"] = SubdomainScanner(
                host, wordlist=wordlist, stealth=stealth
            ).scan()

        # 4. Port scan (full mode only)
        if mode in ("full", "active"):
            self.out.info("Scanning ports …")
            port_list = self._parse_ports(ports)
            result["ports"] = PortScanner(host, ports=port_list,
                                          stealth=stealth).scan()
            self._print_ports(result["ports"])

        # 5. Web fingerprint (if HTTP/S target or port 80/443 open)
        open_ports = {p["port"] for p in result.get("ports", [])}
        if 80 in open_ports or 443 in open_ports or target.startswith("http"):
            self.out.info("Fingerprinting web stack …")
            fp = WebFingerprinter(target)
            result["web"] = fp.fingerprint()
            result["security_headers"] = fp.check_security_headers()
            if result["web"].get("tech"):
                self.out.success(f"Detected: {', '.join(result['web']['tech'])}")

        # 6. GeoIP for resolved IPs
        ips = result["dns"].get("A", [])
        if ips:
            self.out.info(f"GeoIP lookup for {ips[0]} …")
            result["geoip"] = geoip_lookup(ips[0])

        # 7. AI target profile
        self.out.info("Generating AI target profile …")
        result["ai_profile"] = self._ai_profile(result)
        self.out.ai_response(result["ai_profile"], "AI Target Profile")

        # Persist
        path = self.session.write("recon.json", result)
        self.out.success(f"Recon saved → {path}")
        self.session.audit("recon", "complete", str(path))
        return result

    # ── Helpers ───────────────────────────────────────────────────────────────
    @staticmethod
    def _parse_host(target: str) -> str:
        t = target.split("://")[-1].split("/")[0].split(":")[0]
        return t

    @staticmethod
    def _parse_ports(ports_str: str) -> list[int]:
        if not ports_str:
            return PortScanner.COMMON_PORTS
        result = []
        for part in ports_str.split(","):
            part = part.strip()
            if "-" in part:
                lo, hi = part.split("-", 1)
                result.extend(range(int(lo), int(hi) + 1))
            else:
                result.append(int(part))
        return result

    def _print_ports(self, ports: list[dict]) -> None:
        if not ports:
            self.out.warn("No open ports found.")
            return
        rows = [[p["port"], p["state"], p.get("banner", "")[:60]] for p in ports]
        self.out.table(["Port", "State", "Banner"], rows, title="Open Ports")

    def _ai_profile(self, data: dict) -> str:
        ctx = {
            "target":     data.get("target"),
            "dns":        data.get("dns"),
            "subdomains": (data.get("subdomains") or [])[:20],
            "open_ports": data.get("ports", []),
            "web_tech":   data.get("web", {}).get("tech", []),
            "geoip":      data.get("geoip", {}),
        }
        return self.ai.chat(
            "Analyse this reconnaissance data and generate a structured target profile. "
            "Include: attack surface summary, interesting services, potential entry points, "
            "and recommended follow-up actions. Be precise and avoid speculation.",
            context=ctx,
        )