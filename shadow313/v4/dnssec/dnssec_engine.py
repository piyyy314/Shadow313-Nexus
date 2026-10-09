"""
Shadow313 NEXUS — DNSSEC Engine
DNS Security Extensions validation and DNS tunneling detection.
"""
from __future__ import annotations
import math, hashlib
from datetime import datetime, timezone
from typing import Dict, List, Optional

class DNSSECEngine:
    RECORD_TYPES = {1:"A",2:"NS",5:"CNAME",15:"MX",28:"AAAA",43:"DS",46:"RRSIG",48:"DNSKEY"}

    def __init__(self):
        self._cache: Dict[str, Dict] = {}

    def validate_domain(self, domain: str) -> Dict:
        result = {
            "domain": domain, "timestamp": datetime.now(timezone.utc).isoformat(),
            "dnssec_enabled": False, "has_dnskey": False, "has_rrsig": False,
            "chain_valid": False, "risk_level": "UNKNOWN", "findings": [], "mitre_ttps": []
        }
        try:
            import dns.resolver
            for rtype, key in [(48,"has_dnskey"),(46,"has_rrsig"),(43,"has_ds")]:
                try:
                    dns.resolver.resolve(domain, self.RECORD_TYPES.get(rtype,"A"), lifetime=5)
                    result[key] = True
                    result["dnssec_enabled"] = True
                except Exception:
                    pass
        except ImportError:
            result["findings"].append("dnspython not installed — install: pip install dnspython")

        if result["has_dnskey"] and result["has_rrsig"]:
            result["chain_valid"] = True
            result["risk_level"]  = "LOW"
        elif result["has_dnskey"]:
            result["risk_level"] = "MEDIUM"
            result["mitre_ttps"].append("T1584.002")
        else:
            result["risk_level"] = "HIGH"
            result["mitre_ttps"].extend(["T1584.002","T1557"])

        self._cache[domain] = result
        return result

    def detect_dns_tunneling(self, queries: List[str]) -> Dict:
        score = 0.0; findings = []
        for q in queries:
            sub = q.split(".")[0] if "." in q else q
            h   = self._entropy(sub)
            if h > 3.5:
                score += 0.3
                findings.append(f"High entropy subdomain: {sub} (H={h:.2f})")
        if any(len(q.split(".")[0]) > 40 for q in queries):
            score += 0.4; findings.append("Long subdomain labels detected")
        if len(queries) > 100:
            score += 0.3; findings.append(f"High query volume: {len(queries)}")
        return {"technique":"T1071.004","score":min(score,1.0),"detected":score>0.5,"findings":findings}

    def _entropy(self, s: str) -> float:
        if not s: return 0.0
        freq = {}
        for c in s: freq[c] = freq.get(c,0)+1
        return -sum((f/len(s))*math.log2(f/len(s)) for f in freq.values())
