"""shadow313.modules.recon.recon_module — ReconModule orchestrator."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any

from .dns_enum     import DNSEnumerator
from .subdomain    import SubdomainDiscoverer
from .port_scan    import AsyncPortScanner
from .fingerprint  import WebFingerprinter
from .whois_lookup import WHOISLookup
from .geoip        import GeoIPEnricher


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ReconModule:
    """shadow313.recon — Passive + active reconnaissance."""

    def __init__(self, kernel) -> None:
        self.kernel  = kernel
        self.config  = kernel.config.get("recon", default={})
        self.out     = kernel.out
        self.ai      = kernel.ai
        self.session = kernel.session
        self._geoip  = GeoIPEnricher()

    def register(self, kernel) -> None:
        kernel.register("recon", self.run)

    def run(self, target: str, mode: str = "full", ports: str = "",
            stealth: bool = False, wordlist: list[str] | None = None,
            output: str = "rich") -> dict:
        self.out.section(f"RECON  ▸  {target}")
        self.session.audit("recon", "start", target)
        self.session.set_target(target)

        host   = self._parse_host(target)
        result: dict[str, Any] = {
            "target":    target,
            "host":      host,
            "timestamp": _now(),
            "mode":      mode,
        }

        self.out.info("Running WHOIS lookup …")
        result["whois"] = WHOISLookup(host).lookup()

        self.out.info("Enumerating DNS records …")
        result["dns"] = DNSEnumerator(host).resolve()

        if mode in ("full", "passive"):
            self.out.info("Discovering subdomains via CT logs + wordlist …")
            rate = self.config.get("stealth_rps", 10)
            result["subdomains"] = SubdomainDiscoverer(
                host, wordlist=wordlist, stealth=stealth, rate_rps=rate
            ).scan()

        if mode in ("full", "active"):
            self.out.info("Scanning ports …")
            port_list = AsyncPortScanner.parse_ports(
                ports or self.config.get("default_ports", "")
            )
            result["ports"] = AsyncPortScanner(host, ports=port_list, stealth=stealth).scan()
            self._print_ports(result["ports"])

        open_ports = {p["port"] for p in result.get("ports", [])}
        if 80 in open_ports or 443 in open_ports or target.startswith("http"):
            self.out.info("Fingerprinting web stack …")
            fp = WebFingerprinter(target)
            result["web"]              = fp.fingerprint()
            result["security_headers"] = fp.check_security_headers()
            if result["web"].get("tech"):
                self.out.success(f"Detected: {', '.join(result['web']['tech'])}")

        ips = result["dns"].get("A", [])
        if ips:
            self.out.info(f"GeoIP lookup for {ips[0]} …")
            result["geoip"] = self._geoip.lookup(ips[0])

        self.out.info("Generating AI target profile …")
        result["ai_profile"] = self._ai_profile(result)
        self.out.ai_response(result["ai_profile"], "AI Target Profile")

        path = self.session.write("recon.json", result)
        # Condensed target summary for downstream modules
        self.session.write("target.json", {
            "host":      host,
            "ips":       ips,
            "ports":     result.get("ports", []),
            "tech":      result.get("web", {}).get("tech", []),
            "subdomains": result.get("subdomains", [])[:20],
        })
        self.out.success(f"Recon saved → {path}")
        self.session.audit("recon", "complete", str(path))
        return result

    def ai_context(self) -> dict:
        data = self.session.read("recon.json") or {}
        return {
            "module":    "recon",
            "target":    data.get("target", ""),
            "dns":       data.get("dns", {}),
            "ports":     data.get("ports", [])[:10],
            "tech":      data.get("web", {}).get("tech", []),
            "subdomains": data.get("subdomains", [])[:10],
        }

    def _parse_host(self, target: str) -> str:
        return target.split("://")[-1].split("/")[0].split(":")[0]

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