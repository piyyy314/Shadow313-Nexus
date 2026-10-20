"""YARA Scanner - Python port of SatExpert313 YARAScanner.tsx"""
from __future__ import annotations
import re, hashlib
from dataclasses import dataclass
from typing import Optional

@dataclass
class YARAMatch:
    rule_name: str; severity: str; description: str
    offset: int; matched_bytes: str; cve: Optional[str] = None

@dataclass
class YARAScanResult:
    target: str; sha256: str; matches: list; clean: bool; risk_score: int

class YARAScanner:
    RULES = [
        {"name":"VSAT_FIRMWARE_BACKDOOR","pattern":rb"\x00{4}.{0,16}backdoor","severity":"CRITICAL","description":"Firmware backdoor signature","cve":"CVE-2026-3392"},
        {"name":"HARDCODED_CREDENTIALS","pattern":rb"(admin|root|password)\x00{0,4}(admin|1234|password)","severity":"HIGH","description":"Hardcoded credentials","cve":None},
        {"name":"REVERSE_SHELL_PAYLOAD","pattern":rb"(nc\s+-e\s+/bin/sh|bash\s+-i\s+>&)","severity":"CRITICAL","description":"Reverse shell payload","cve":None},
        {"name":"UNSIGNED_CWMP_HANDLER","pattern":rb"cwmp|tr-069|acs_url","severity":"HIGH","description":"TR-069 CWMP handler without signature verification","cve":"CVE-2026-3392"},
        {"name":"TELNET_DAEMON","pattern":rb"telnetd|/usr/sbin/telnet","severity":"HIGH","description":"Telnet daemon present","cve":None},
    ]
    def scan_bytes(self, data: bytes, target_name: str = "firmware.bin") -> YARAScanResult:
        sha256 = hashlib.sha256(data).hexdigest(); matches = []; risk_score = 0
        for rule in self.RULES:
            for m in re.finditer(rule["pattern"], data, re.IGNORECASE|re.DOTALL):
                matches.append(YARAMatch(rule["name"],rule["severity"],rule["description"],
                                         m.start(),data[m.start():m.start()+16].hex(),rule.get("cve")))
                risk_score += {"CRITICAL":40,"HIGH":25,"MEDIUM":10}.get(rule["severity"],5)
        return YARAScanResult(target_name, sha256, matches, len(matches)==0, min(risk_score,100))
    def scan_file(self, path: str) -> YARAScanResult:
        import os; return self.scan_bytes(open(path,"rb").read(), os.path.basename(path))
