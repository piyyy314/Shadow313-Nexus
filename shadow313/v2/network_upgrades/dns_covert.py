"""
shadow313.v2.network_upgrades.dns_covert  — v4
DNS covert channel / tunneling detection: 6 heuristic rules + DoH detection.

BUG FIXES:
  - Shannon entropy calculation divided by log(2) but used log() without base —
    fixed to use math.log2() for correct bits-per-character.
  - _extract_dns_queries() iterated over all packets including non-DNS ones
    causing false positives from HTTP payloads — added port 53 filter.
  - High-rate detection used wall-clock time but PCAP timestamps are relative —
    now uses PCAP packet timestamps for rate calculation.
  - Known tunnel tool pattern matching was case-sensitive — fixed to lowercase.
"""
from __future__ import annotations
import math
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

# Known DNS tunnel tool signatures (lowercase for case-insensitive match)
_TUNNEL_SIGNATURES = [
    "iodine", "dnscat", "dns2tcp", "heyoka", "ozymandns",
    "dnscapy", "tuns", "dns-shell", "dnsexfil",
]

# Known DoH provider IPs
# Known DoH provider IPs — intentionally hardcoded as detection signatures
_DOH_PROVIDERS = {
    "1.1.1.1", "1.0.0.1",          # Cloudflare
    "8.8.8.8", "8.8.4.4",          # Google
    "9.9.9.9", "149.112.112.112",   # Quad9
    "208.67.222.222",               # OpenDNS
    "94.140.14.14",                 # AdGuard
}

# Detection thresholds
_ENTROPY_THRESHOLD    = 3.8   # bits/char — high entropy subdomain
_LABEL_LEN_THRESHOLD  = 40    # chars — long subdomain label
_TXT_SIZE_THRESHOLD   = 512   # bytes — oversized TXT response
_UNIQUE_SUB_THRESHOLD = 20    # unique subdomains per apex
_RATE_THRESHOLD       = 50    # queries/min from single source


def _shannon_entropy(s: str) -> float:
    """
    Shannon entropy in bits per character.
    FIX: use math.log2() instead of math.log() / math.log(2).
    """
    if not s:
        return 0.0
    freq: dict[str, int] = defaultdict(int)
    for c in s:
        freq[c] += 1
    n = len(s)
    return -sum((count / n) * math.log2(count / n) for count in freq.values() if count > 0)


def _extract_apex(domain: str) -> str:
    """Extract apex domain (last two labels)."""
    parts = domain.rstrip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def _extract_subdomain(domain: str) -> str:
    """Extract subdomain portion (everything before apex)."""
    parts = domain.rstrip(".").split(".")
    if len(parts) > 2:
        return ".".join(parts[:-2])
    return ""


# ── DNS wire format parser ────────────────────────────────────────────────────

def _parse_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    """Parse DNS wire-format name with pointer support."""
    labels = []
    visited: set[int] = set()
    while offset < len(data):
        if offset in visited:
            break
        visited.add(offset)
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            # Pointer
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            offset += 2
            name, _ = _parse_dns_name(data, ptr)
            labels.append(name)
            break
        else:
            offset += 1
            end = offset + length
            if end > len(data):
                break
            labels.append(data[offset:end].decode("ascii", errors="replace"))
            offset = end
    return ".".join(labels), offset


def _parse_dns_payload(payload: bytes) -> dict | None:
    """Parse DNS UDP payload. Returns dict with queries and answers."""
    try:
        if len(payload) < 12:
            return None
        import struct
        txid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", payload[:12])
        qr = (flags >> 15) & 1  # 0=query, 1=response

        offset = 12
        queries = []
        for _ in range(qdcount):
            name, offset = _parse_dns_name(payload, offset)
            if offset + 4 > len(payload):
                break
            qtype, qclass = struct.unpack("!HH", payload[offset:offset+4])
            offset += 4
            queries.append({"name": name, "type": qtype})

        answers = []
        for _ in range(ancount):
            name, offset = _parse_dns_name(payload, offset)
            if offset + 10 > len(payload):
                break
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", payload[offset:offset+10])
            offset += 10
            rdata = payload[offset:offset+rdlen]
            offset += rdlen
            answers.append({"name": name, "type": rtype, "rdlen": rdlen, "rdata": rdata})

        return {"txid": txid, "qr": qr, "queries": queries, "answers": answers}
    except Exception as _exc:  # S01-fixed
        import logging as _log; _log.getLogger(__name__).debug("suppressed: %s", _exc)
        return None


# ── Detection rules ───────────────────────────────────────────────────────────

class DNSCovertDetector:
    """6 heuristic rules for DNS covert channel detection."""

    def __init__(self) -> None:
        self._alerts: list[dict] = []

    def analyse_packets(self, packets: list[dict]) -> list[dict]:
        """
        Analyse packet list from PCAPParser.
        FIX: filter to DNS ports only; use PCAP timestamps for rate calculation.
        """
        self._alerts = []

        # FIX: filter to DNS traffic only (port 53)
        dns_packets = [
            p for p in packets
            if p.get("dport") == 53 or p.get("sport") == 53
        ]

        # Collect DNS queries from payloads
        queries: list[dict] = []
        for pkt in dns_packets:
            payload_str = pkt.get("payload_preview", "")
            if not payload_str:
                continue
            raw = payload_str.encode("latin-1", errors="replace")
            parsed = _parse_dns_payload(raw)
            if parsed:
                for q in parsed.get("queries", []):
                    queries.append({
                        "name":    q["name"],
                        "type":    q["type"],
                        "src_ip":  pkt.get("src_ip", ""),
                        "ts":      pkt.get("ts", 0.0),
                    })
                for a in parsed.get("answers", []):
                    if a["type"] == 16:  # TXT record
                        self._check_txt_size(a, pkt)

        self._check_entropy(queries)
        self._check_long_labels(queries)
        self._check_unique_subdomains(queries)
        self._check_high_rate(queries)
        self._check_tunnel_signatures(queries)

        return self._alerts

    def analyse_flows(self, flows: list[dict]) -> list[dict]:
        """Analyse flow table for DoH anomalies."""
        self._alerts = []
        self._check_doh(flows)
        return self._alerts

    # ── Rule 1: High-entropy subdomain ────────────────────────────────────────
    def _check_entropy(self, queries: list[dict]) -> None:
        for q in queries:
            sub = _extract_subdomain(q["name"])
            if not sub:
                continue
            entropy = _shannon_entropy(sub)
            if entropy >= _ENTROPY_THRESHOLD:
                self._alerts.append({
                    "rule":     "HIGH_ENTROPY_SUBDOMAIN",
                    "severity": "HIGH",
                    "detail":   f"High-entropy subdomain '{sub}' (entropy={entropy:.2f} bits/char) "
                                f"from {q['src_ip']} — possible DNS tunneling",
                    "domain":   q["name"],
                    "entropy":  round(entropy, 3),
                    "src_ip":   q["src_ip"],
                })

    # ── Rule 2: Long subdomain label ──────────────────────────────────────────
    def _check_long_labels(self, queries: list[dict]) -> None:
        for q in queries:
            for label in q["name"].split("."):
                if len(label) >= _LABEL_LEN_THRESHOLD:
                    self._alerts.append({
                        "rule":     "LONG_SUBDOMAIN_LABEL",
                        "severity": "MEDIUM",
                        "detail":   f"Subdomain label length {len(label)} chars in '{q['name']}' "
                                    f"from {q['src_ip']} — possible data encoding",
                        "domain":   q["name"],
                        "label_len":len(label),
                        "src_ip":   q["src_ip"],
                    })

    # ── Rule 3: Oversized TXT record ──────────────────────────────────────────
    def _check_txt_size(self, answer: dict, pkt: dict) -> None:
        if answer["rdlen"] > _TXT_SIZE_THRESHOLD:
            self._alerts.append({
                "rule":     "OVERSIZED_TXT_RECORD",
                "severity": "HIGH",
                "detail":   f"TXT record size {answer['rdlen']} bytes for '{answer['name']}' "
                            f"— exceeds {_TXT_SIZE_THRESHOLD} byte threshold",
                "domain":   answer["name"],
                "rdlen":    answer["rdlen"],
                "src_ip":   pkt.get("src_ip", ""),
            })

    # ── Rule 4: Known tunnel tool signatures ──────────────────────────────────
    def _check_tunnel_signatures(self, queries: list[dict]) -> None:
        for q in queries:
            # FIX: lowercase comparison
            name_lower = q["name"].lower()
            for sig in _TUNNEL_SIGNATURES:
                if sig in name_lower:
                    self._alerts.append({
                        "rule":     "TUNNEL_TOOL_SIGNATURE",
                        "severity": "CRITICAL",
                        "detail":   f"Known DNS tunnel tool signature '{sig}' in query '{q['name']}' "
                                    f"from {q['src_ip']}",
                        "domain":   q["name"],
                        "signature":sig,
                        "src_ip":   q["src_ip"],
                    })

    # ── Rule 5: High unique subdomain count ───────────────────────────────────
    def _check_unique_subdomains(self, queries: list[dict]) -> None:
        apex_subs: dict[str, set] = defaultdict(set)
        apex_src:  dict[str, str] = {}
        for q in queries:
            apex = _extract_apex(q["name"])
            sub  = _extract_subdomain(q["name"])
            if sub:
                apex_subs[apex].add(sub)
                apex_src[apex] = q.get("src_ip", "")
        for apex, subs in apex_subs.items():
            if len(subs) >= _UNIQUE_SUB_THRESHOLD:
                self._alerts.append({
                    "rule":     "HIGH_UNIQUE_SUBDOMAIN_COUNT",
                    "severity": "HIGH",
                    "detail":   f"{len(subs)} unique subdomains under '{apex}' "
                                f"— possible DNS tunneling",
                    "apex":     apex,
                    "count":    len(subs),
                    "src_ip":   apex_src.get(apex, ""),
                })

    # ── Rule 6: High DNS query rate ───────────────────────────────────────────
    def _check_high_rate(self, queries: list[dict]) -> None:
        """FIX: use PCAP timestamps (ts field) for rate calculation."""
        src_queries: dict[str, list[float]] = defaultdict(list)
        for q in queries:
            src_queries[q["src_ip"]].append(float(q.get("ts", 0)))

        for src_ip, timestamps in src_queries.items():
            if len(timestamps) < 2:
                continue
            timestamps.sort()
            duration_sec = max(timestamps[-1] - timestamps[0], 1.0)
            rate_per_min = (len(timestamps) / duration_sec) * 60
            if rate_per_min >= _RATE_THRESHOLD:
                self._alerts.append({
                    "rule":     "HIGH_DNS_QUERY_RATE",
                    "severity": "MEDIUM",
                    "detail":   f"{rate_per_min:.0f} DNS queries/min from {src_ip} "
                                f"— exceeds threshold of {_RATE_THRESHOLD}",
                    "src_ip":   src_ip,
                    "rate":     round(rate_per_min, 1),
                })

    # ── DoH detection ─────────────────────────────────────────────────────────
    def _check_doh(self, flows: list[dict]) -> None:
        """Detect DNS-over-HTTPS traffic to known DoH providers."""
        doh_flows: dict[str, int] = defaultdict(int)
        for flow in flows:
            dst = flow.get("dst_ip", "")
            if dst in _DOH_PROVIDERS and flow.get("dport") == 443:
                doh_flows[dst] += flow.get("packets", 1)

        for dst_ip, pkt_count in doh_flows.items():
            if pkt_count > 10:
                self._alerts.append({
                    "rule":     "DOH_TRAFFIC_DETECTED",
                    "severity": "MEDIUM",
                    "detail":   f"DNS-over-HTTPS traffic to {dst_ip} ({pkt_count} packets) "
                                f"— may bypass DNS monitoring",
                    "dst_ip":   dst_ip,
                    "packets":  pkt_count,
                })


# ── DNSCovertModule ───────────────────────────────────────────────────────────

class DNSCovertModule:
    """shadow313.v2.network_upgrades.dns_covert — DNS covert channel detection. Registered: dns_covert"""

    def __init__(self, kernel) -> None:
        self.kernel   = kernel
        self.out      = kernel.out
        self.session  = kernel.session
        self.detector = DNSCovertDetector()

    def register(self, kernel) -> None:
        kernel.register("dns_covert", self.run)

    def run(
        self,
        analyze: str = "",
        _prev_result: dict | None = None,
    ) -> dict:
        self.out.section("DNS COVERT CHANNEL DETECTION")
        result: dict[str, Any] = {}

        packets: list[dict] = []
        flows:   list[dict] = []

        if _prev_result:
            packets = _prev_result.get("packets", [])
            flows   = _prev_result.get("flows", [])
        elif analyze:
            try:
                from shadow313.modules.network.network import PCAPParser
                parser  = PCAPParser(analyze)
                packets = parser.parse()
                flows   = parser.get_flows()
            except Exception as exc:
                self.out.error(f"PCAP parse error: {exc}")
                return {}
        else:
            net     = self.session.read("network.json") or {}
            packets = net.get("packets", [])
            flows   = net.get("flows", [])

        if not packets and not flows:
            self.out.warn("No packet/flow data available.")
            return {}

        self.out.info(f"Analysing {len(packets)} packets for DNS covert channels …")
        pkt_alerts  = self.detector.analyse_packets(packets)
        flow_alerts = self.detector.analyse_flows(flows)
        all_alerts  = pkt_alerts + flow_alerts

        result["alerts"]      = all_alerts
        result["alert_count"] = len(all_alerts)

        if all_alerts:
            self.out.warn(f"{len(all_alerts)} DNS covert channel alert(s)!")
            rows = [[a["rule"], a["severity"], a["detail"][:80]] for a in all_alerts[:20]]
            self.out.table(["Rule", "Severity", "Detail"], rows, "DNS Covert Channel Alerts")
        else:
            self.out.success("No DNS covert channel activity detected.")

        self.session.write("dns_covert_alerts.json", result)
        return result