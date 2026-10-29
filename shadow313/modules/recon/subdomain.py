"""shadow313.modules.recon.subdomain — Subdomain discovery via CT logs + wordlist."""
from __future__ import annotations
import json
import socket
import time
from urllib import request as urlreq


class SubdomainDiscoverer:
    CT_LOG_URL = "https://crt.sh/?q={domain}&output=json"
    DEFAULT_WORDLIST = [
        "www", "mail", "ftp", "api", "dev", "staging", "test", "admin",
        "vpn", "remote", "portal", "static", "cdn", "app", "beta",
        "secure", "login", "dashboard", "internal", "ns1", "ns2",
        "smtp", "pop", "imap", "webmail", "mx", "autodiscover",
    ]

    def __init__(self, domain: str, wordlist: list[str] | None = None,
                 stealth: bool = False, rate_rps: int = 10) -> None:
        self.domain   = domain
        self.wordlist = wordlist or self.DEFAULT_WORDLIST
        self.stealth  = stealth
        self.delay    = 1.0 / max(rate_rps, 1)
        self.found: list[str] = []

    def from_ct_logs(self) -> list[str]:
        url = self.CT_LOG_URL.format(domain=f"%.{self.domain}")
        try:
            req = urlreq.Request(url, headers={"User-Agent": "shadow313/2.0"})
            with urlreq.urlopen(req, timeout=15) as resp:
                entries = json.loads(resp.read())
            subs: set[str] = set()
            for entry in entries:
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.")
                    if name.endswith(self.domain) and name != self.domain:
                        subs.add(name)
            self.found.extend(subs)
            return list(subs)
        except Exception:
            return []

    def from_wordlist(self) -> list[str]:
        found = []
        for word in self.wordlist:
            candidate = f"{word}.{self.domain}"
            try:
                socket.getaddrinfo(candidate, None)
                found.append(candidate)
            except socket.gaierror:
                pass
            if self.stealth:
                time.sleep(self.delay)
        self.found.extend(found)
        return found

    def scan(self) -> list[str]:
        ct = self.from_ct_logs()
        wl = self.from_wordlist()
        unique = list({*ct, *wl})
        self.found = unique
        return unique