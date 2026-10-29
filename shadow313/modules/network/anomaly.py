"""shadow313.modules.network.anomaly — Heuristic anomaly detector."""
from __future__ import annotations
from collections import defaultdict


class AnomalyDetector:
    BEACONING_THRESHOLD = 5
    PORT_SCAN_THRESHOLD = 20
    EXFIL_BYTES         = 1_000_000
    SUSPICIOUS_PORTS    = {4444, 1337, 31337, 12345, 6666, 9001, 9050}

    def __init__(self, flows: list[dict]) -> None:
        """Retain directional flow records for heuristic analysis."""
        self.flows = flows

    def detect(self) -> list[dict]:
        """Return beaconing, port-scan, exfiltration, and suspicious-port alerts."""
        alerts = []
        alerts.extend(self._check_beaconing())
        alerts.extend(self._check_port_scan())
        alerts.extend(self._check_exfiltration())
        alerts.extend(self._check_suspicious_ports())
        return alerts

    def _check_beaconing(self) -> list[dict]:
        """Alert when a nonprivate destination reaches the flow-count threshold."""
        dst_counts: dict[str, int] = defaultdict(int)
        for f in self.flows:
            dst_counts[f["dst_ip"]] += 1
        alerts = []
        for dst, cnt in dst_counts.items():
            if cnt >= self.BEACONING_THRESHOLD and not self._is_private(dst):
                alerts.append({
                    "type":     "BEACONING",
                    "severity": "HIGH",
                    "detail":   f"Repeated connections to {dst} ({cnt}x) — possible C2 beaconing",
                    "dst_ip":   dst,
                    "count":    cnt,
                })
        return alerts

    def _check_port_scan(self) -> list[dict]:
        """Alert when a source reaches the distinct destination-port threshold."""
        src_ports: dict[str, set] = defaultdict(set)
        for f in self.flows:
            src_ports[f["src_ip"]].add(f["dport"])
        alerts = []
        for src, ports in src_ports.items():
            if len(ports) >= self.PORT_SCAN_THRESHOLD:
                alerts.append({
                    "type":       "PORT_SCAN",
                    "severity":   "MEDIUM",
                    "detail":     f"Port scan from {src} — {len(ports)} unique destination ports",
                    "src_ip":     src,
                    "port_count": len(ports),
                })
        return alerts

    def _check_exfiltration(self) -> list[dict]:
        """Alert when summed bytes to a nonprivate destination reach EXFIL_BYTES."""
        dst_bytes: dict[str, int] = defaultdict(int)
        for f in self.flows:
            if not self._is_private(f["dst_ip"]):
                dst_bytes[f["dst_ip"]] += f.get("bytes", 0)
        alerts = []
        for dst, total in dst_bytes.items():
            if total >= self.EXFIL_BYTES:
                alerts.append({
                    "type":     "DATA_EXFILTRATION",
                    "severity": "CRITICAL",
                    "detail":   f"{total:,} bytes sent to {dst} — possible data exfiltration",
                    "dst_ip":   dst,
                    "bytes":    total,
                })
        return alerts

    def _check_suspicious_ports(self) -> list[dict]:
        """Return alerts for suspicious destination ports, falling back to source if falsy."""
        alerts = []
        for f in self.flows:
            port = f.get("dport") or f.get("sport")
            if port in self.SUSPICIOUS_PORTS:
                alerts.append({
                    "type":     "SUSPICIOUS_PORT",
                    "severity": "HIGH",
                    "detail":   f"Traffic on suspicious port {port} — often associated with malware/RATs",
                    "flow":     f,
                })
        return alerts

    @staticmethod
    def _is_private(ip: str) -> bool:
        """Recognize IPv4 prefixes 10/8, 172.16/12, 192.168/16, and 127/8; else return False."""
        try:
            parts = [int(x) for x in ip.split(".")]
            if parts[0] == 10:
                return True
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            if parts[0] == 192 and parts[1] == 168:
                return True
            if parts[0] == 127:
                return True
        except Exception:
            pass
        return False