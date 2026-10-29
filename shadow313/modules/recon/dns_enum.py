"""shadow313.modules.recon.dns_enum — DNS record enumeration."""
from __future__ import annotations
import socket
from typing import Any


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
        try:
            import dns.resolver
            answers = dns.resolver.resolve(self.domain, rtype, lifetime=5)
            return [r.to_text() for r in answers]
        except ImportError:
            return ["[dnspython not installed]"]
        except Exception:
            return []