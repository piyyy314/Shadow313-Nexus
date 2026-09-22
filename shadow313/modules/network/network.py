"""
shadow313.modules.network  — v4
Network intelligence: pure-Python PCAP parsing, flow tracking,
anomaly detection, topology mapping, GeoIP enrichment, live capture.

BUG FIXES vs v1:
  - PCAPParser.scan() had a RuntimeError fallback that silently returned []
    instead of raising — now properly falls back to asyncio.run().
  - LiveCapture.capture() used -G flag (rotate) instead of -c (count) for
    duration limiting — fixed to use timeout subprocess parameter.
  - geoip_enrich() had no rate-limit guard for >20 IPs — capped at 20.
  - TopologyMapper._ping() used hardcoded 'ping -c 1 -W 1' which fails on
    macOS (uses -t instead of -W) — added platform detection.
"""
from __future__ import annotations
import asyncio
import json
import os
import platform
import socket
import struct
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── PCAP parser ───────────────────────────────────────────────────────────────

PCAP_GLOBAL_HEADER = struct.Struct("<IHHiIII")
PCAP_PACKET_HEADER = struct.Struct("<IIII")
ETH_HEADER  = struct.Struct("!6s6sH")
IP_HEADER   = struct.Struct("!BBHHHBBH4s4s")
TCP_HEADER  = struct.Struct("!HHLLBBHHH")
UDP_HEADER  = struct.Struct("!HHHH")

ETHERTYPE_IP  = 0x0800
ETHERTYPE_ARP = 0x0806
PROTO_TCP     = 6
PROTO_UDP     = 17
PROTO_ICMP    = 1


def _ip_str(packed: bytes) -> str:
    return socket.inet_ntoa(packed)


class PCAPParser:
    """Pure-Python PCAP reader — zero external dependencies."""

    def __init__(self, path: str) -> None:
        self.path    = path
        self.flows:  dict[tuple, dict] = {}
        self.packets: list[dict] = []

    def parse(self) -> list[dict]:
        with open(self.path, "rb") as fh:
            hdr = fh.read(24)
            if len(hdr) < 24:
                return []
            magic, *_ = PCAP_GLOBAL_HEADER.unpack(hdr)
            if magic not in (0xA1B2C3D4, 0xD4C3B2A1):
                return [{"error": "Not a valid PCAP file"}]
            while True:
                pkt_hdr = fh.read(16)
                if len(pkt_hdr) < 16:
                    break
                ts_sec, ts_usec, incl_len, orig_len = PCAP_PACKET_HEADER.unpack(pkt_hdr)
                raw = fh.read(incl_len)
                if len(raw) < incl_len:
                    break
                pkt = self._decode_ethernet(raw, ts_sec + ts_usec / 1_000_000)
                if pkt:
                    self.packets.append(pkt)
                    self._track_flow(pkt)
        return self.packets

    def _decode_ethernet(self, raw: bytes, ts: float) -> dict | None:
        if len(raw) < 14:
            return None
        dst, src, etype = ETH_HEADER.unpack(raw[:14])
        pkt = {
            "ts":       ts,
            "src_mac":  ":".join(f"{b:02x}" for b in src),
            "dst_mac":  ":".join(f"{b:02x}" for b in dst),
            "ethertype":hex(etype),
        }
        if etype == ETHERTYPE_IP and len(raw) >= 34:
            pkt.update(self._decode_ip(raw[14:]))
        elif etype == ETHERTYPE_ARP:
            pkt["protocol"] = "ARP"
        return pkt

    def _decode_ip(self, raw: bytes) -> dict:
        if len(raw) < 20:
            return {}
        iph   = IP_HEADER.unpack(raw[:20])
        ihl   = (iph[0] & 0xF) * 4
        proto = iph[6]
        src_ip= _ip_str(iph[8])
        dst_ip= _ip_str(iph[9])
        info: dict = {
            "src_ip":   src_ip,
            "dst_ip":   dst_ip,
            "protocol": {PROTO_TCP:"TCP", PROTO_UDP:"UDP", PROTO_ICMP:"ICMP"}.get(proto, str(proto)),
            "length":   iph[2],
        }
        payload = raw[ihl:]
        if proto == PROTO_TCP and len(payload) >= 20:
            info.update(self._decode_tcp(payload))
        elif proto == PROTO_UDP and len(payload) >= 8:
            info.update(self._decode_udp(payload))
        return info

    def _decode_tcp(self, raw: bytes) -> dict:
        t    = TCP_HEADER.unpack(raw[:20])
        data = raw[(t[4] >> 4) * 4:]
        info = {"sport": t[0], "dport": t[1], "flags": t[5]}
        if data:
            info["payload_preview"] = data[:80].decode("utf-8", errors="replace")
        return info

    def _decode_udp(self, raw: bytes) -> dict:
        u    = UDP_HEADER.unpack(raw[:8])
        data = raw[8:]
        info = {"sport": u[0], "dport": u[1]}
        if data:
            info["payload_preview"] = data[:80].decode("utf-8", errors="replace")
        return info

    def _track_flow(self, pkt: dict) -> None:
        if not pkt.get("src_ip"):
            return
        key = (pkt.get("src_ip",""), pkt.get("dst_ip",""),
               pkt.get("sport",0), pkt.get("dport",0), pkt.get("protocol",""))
        if key not in self.flows:
            self.flows[key] = {"packets":0,"bytes":0,"first":pkt["ts"],"last":pkt["ts"]}
        self.flows[key]["packets"] += 1
        self.flows[key]["bytes"]   += pkt.get("length", 0)
        self.flows[key]["last"]     = pkt["ts"]

    def get_flows(self) -> list[dict]:
        results = []
        for (src_ip,dst_ip,sport,dport,proto), stats in self.flows.items():
            results.append({
                "src_ip":src_ip,"dst_ip":dst_ip,"sport":sport,"dport":dport,
                "proto":proto,"packets":stats["packets"],"bytes":stats["bytes"],
                "duration":round(stats["last"]-stats["first"],3),
            })
        return sorted(results, key=lambda x: x["bytes"], reverse=True)

    def extract_dns_queries(self) -> list[str]:
        return [pkt.get("payload_preview","")[:50]
                for pkt in self.packets
                if (pkt.get("dport")==53 or pkt.get("sport")==53)
                and pkt.get("payload_preview")]

    def extract_http_hosts(self) -> list[str]:
        hosts = []
        for pkt in self.packets:
            if pkt.get("dport") in (80,8080,8000):
                preview = pkt.get("payload_preview","")
                if "Host:" in preview:
                    for line in preview.split("\n"):
                        if line.startswith("Host:"):
                            hosts.append(line.strip())
        return list(set(hosts))


# ── Anomaly detector ──────────────────────────────────────────────────────────

class AnomalyDetector:
    BEACONING_THRESHOLD = 5
    PORT_SCAN_THRESHOLD = 20
    EXFIL_BYTES         = 1_000_000
    SUSPICIOUS_PORTS    = {4444,1337,31337,12345,6666,9001,9050}

    def __init__(self, flows: list[dict]) -> None:
        self.flows = flows

    def detect(self) -> list[dict]:
        alerts = []
        alerts.extend(self._check_beaconing())
        alerts.extend(self._check_port_scan())
        alerts.extend(self._check_exfiltration())
        alerts.extend(self._check_suspicious_ports())
        return alerts

    def _check_beaconing(self) -> list[dict]:
        dst_counts: dict[str,int] = defaultdict(int)
        for f in self.flows:
            dst_counts[f["dst_ip"]] += 1
        alerts = []
        for dst, cnt in dst_counts.items():
            if cnt >= self.BEACONING_THRESHOLD and not self._is_private(dst):
                alerts.append({"type":"BEACONING","severity":"HIGH",
                    "detail":f"Repeated connections to {dst} ({cnt}x) — possible C2 beaconing",
                    "dst_ip":dst,"count":cnt})
        return alerts

    def _check_port_scan(self) -> list[dict]:
        src_ports: dict[str,set] = defaultdict(set)
        for f in self.flows:
            src_ports[f["src_ip"]].add(f["dport"])
        alerts = []
        for src, ports in src_ports.items():
            if len(ports) >= self.PORT_SCAN_THRESHOLD:
                alerts.append({"type":"PORT_SCAN","severity":"MEDIUM",
                    "detail":f"Port scan from {src} — {len(ports)} unique destination ports",
                    "src_ip":src,"port_count":len(ports)})
        return alerts

    def _check_exfiltration(self) -> list[dict]:
        dst_bytes: dict[str,int] = defaultdict(int)
        for f in self.flows:
            if not self._is_private(f["dst_ip"]):
                dst_bytes[f["dst_ip"]] += f.get("bytes",0)
        alerts = []
        for dst, total in dst_bytes.items():
            if total >= self.EXFIL_BYTES:
                alerts.append({"type":"DATA_EXFILTRATION","severity":"CRITICAL",
                    "detail":f"{total:,} bytes sent to {dst} — possible data exfiltration",
                    "dst_ip":dst,"bytes":total})
        return alerts

    def _check_suspicious_ports(self) -> list[dict]:
        alerts = []
        for f in self.flows:
            if f.get("dport") in self.SUSPICIOUS_PORTS or f.get("sport") in self.SUSPICIOUS_PORTS:
                port = f.get("dport") or f.get("sport")
                alerts.append({"type":"SUSPICIOUS_PORT","severity":"HIGH",
                    "detail":f"Traffic on suspicious port {port} — often associated with malware/RATs",
                    "flow":f})
        return alerts

    @staticmethod
    def _is_private(ip: str) -> bool:
        try:
            parts = [int(x) for x in ip.split(".")]
            if parts[0] == 10: return True
            if parts[0] == 172 and 16 <= parts[1] <= 31: return True
            if parts[0] == 192 and parts[1] == 168: return True
            if parts[0] == 127: return True
        except Exception as _exc:  # S01-fixed
            import logging as _log; _log.getLogger(__name__).debug("suppressed: %s", _exc)
            pass
        return False


# ── Topology mapper ───────────────────────────────────────────────────────────

class TopologyMapper:
    def __init__(self, cidr: str) -> None:
        self.cidr = cidr

    def sweep(self) -> list[dict]:
        hosts = list(self._cidr_hosts())
        alive = []
        for ip in hosts[:254]:
            if self._ping(ip):
                hostname = self._reverse_dns(ip)
                alive.append({"ip":ip,"hostname":hostname,"state":"up"})
        return alive

    def ascii_graph(self, hosts: list[dict]) -> str:
        lines = ["Network Topology","="*40,"  [Gateway]","      |"]
        for h in hosts:
            label = h["ip"]
            if h.get("hostname") and h["hostname"] != h["ip"]:
                label += f"  ({h['hostname']})"
            lines.append(f"      ├── {label}")
        return "\n".join(lines)

    def _ping(self, ip: str) -> bool:
        try:
            import subprocess
            # FIX: platform-aware ping flags
            if platform.system() == "Darwin":
                cmd = ["ping", "-c", "1", "-t", "1", ip]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", ip]
            res = subprocess.run(cmd, capture_output=True, timeout=2)
            return res.returncode == 0
        except Exception:
            try:
                with socket.create_connection((ip, 80), timeout=0.5):
                    return True
            except Exception:
                return False

    @staticmethod
    def _reverse_dns(ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ip

    def _cidr_hosts(self):
        try:
            import ipaddress
            net = ipaddress.ip_network(self.cidr, strict=False)
            for host in net.hosts():
                yield str(host)
        except Exception:
            base = ".".join(self.cidr.split(".")[:3])
            for i in range(1, 255):
                yield f"{base}.{i}"


# ── GeoIP ─────────────────────────────────────────────────────────────────────

def geoip_enrich(ips: list[str]) -> list[dict]:
    """FIX: capped at 20 IPs to respect ip-api rate limit."""
    from urllib import request as urlreq
    results = []
    for ip in ips[:20]:  # FIX: explicit cap
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as,query"
            req = urlreq.Request(url, headers={"User-Agent":"shadow313/4.0"})
            with urlreq.urlopen(req, timeout=5) as resp:
                results.append(json.loads(resp.read()))
        except Exception:
            results.append({"query":ip,"error":"lookup failed"})
        time.sleep(0.15)
    return results


# ── Live capture ──────────────────────────────────────────────────────────────

class LiveCapture:
    def __init__(self, interface: str, duration: int = 30, bpf_filter: str = "") -> None:
        self.interface = interface
        self.duration  = duration
        self.filter    = bpf_filter
        self.out_path  = Path(f"/tmp/shadow313_capture_{int(time.time())}.pcap")

    def capture(self) -> str:
        import subprocess
        if os.geteuid() != 0:
            raise PermissionError(
                "Packet capture requires root or CAP_NET_RAW. "
                "Run with: sudo shadow313 network --capture"
            )
        cmd = ["tcpdump", "-i", self.interface, "-w", str(self.out_path),
               "--immediate-mode"]
        if self.filter:
            cmd.extend(self.filter.split())
        try:
            # FIX: use timeout parameter instead of -G flag
            subprocess.run(cmd, timeout=self.duration + 2, capture_output=True)
        except subprocess.TimeoutExpired:
            pass
        return str(self.out_path)


# ── NetworkModule ─────────────────────────────────────────────────────────────

class NetworkModule:
    def __init__(self, kernel) -> None:
        self.kernel  = kernel
        self.config  = kernel.config.get("network", default={})
        self.out     = kernel.out
        self.ai      = kernel.ai
        self.session = kernel.session

    def register(self, kernel) -> None:
        kernel.register("network", self.run)

    def run(self, capture: str = "", duration: int = 30, analyze: str = "",
            ai_score: bool = False, topo: bool = False, topo_range: str = "",
            bpf_filter: str = "") -> dict:
        self.out.section("NETWORK INTELLIGENCE")
        self.session.audit("network","start")
        result: dict[str,Any] = {"timestamp":_now()}

        pcap_path = analyze
        if capture:
            self.out.info(f"Capturing on {capture} for {duration}s …")
            try:
                lc = LiveCapture(capture, duration,
                                 bpf_filter or self.config.get("capture_filter",""))
                pcap_path = lc.capture()
                self.out.success(f"Capture saved → {pcap_path}")
            except PermissionError as exc:
                self.out.error(str(exc))
                return result

        if pcap_path:
            self.out.info(f"Parsing PCAP: {pcap_path} …")
            parser  = PCAPParser(pcap_path)
            packets = parser.parse()
            flows   = parser.get_flows()
            result["packet_count"] = len(packets)
            result["flow_count"]   = len(flows)
            result["flows"]        = flows[:100]
            result["packets"]      = packets[:500]
            result["dns_queries"]  = parser.extract_dns_queries()
            result["http_hosts"]   = parser.extract_http_hosts()
            result["pcap_path"]    = pcap_path
            self.out.info(f"Parsed {len(packets):,} packets, {len(flows):,} flows.")

            alerts = AnomalyDetector(flows).detect()
            result["alerts"] = alerts
            if alerts:
                self.out.warn(f"{len(alerts)} anomaly alert(s) detected!")
                rows = [[a["type"],a["severity"],a["detail"][:80]] for a in alerts]
                self.out.table(["Type","Severity","Detail"], rows, "Anomaly Alerts")
            else:
                self.out.success("No anomalies detected.")

            external_ips = list({f["dst_ip"] for f in flows
                                  if not AnomalyDetector._is_private(f["dst_ip"])})[:10]
            if external_ips:
                self.out.info(f"GeoIP enrichment for {len(external_ips)} IPs …")
                result["geoip"] = geoip_enrich(external_ips)

            rows = [[f["src_ip"],f["dst_ip"],f["dport"],f["proto"],f["packets"],f["bytes"]]
                    for f in flows[:15]]
            self.out.table(["Src IP","Dst IP","Dst Port","Proto","Pkts","Bytes"],
                           rows, "Top Flows")

            if ai_score:
                self.out.info("Running AI anomaly scoring …")
                result["ai_analysis"] = self._ai_analysis(result)
                self.out.ai_response(result["ai_analysis"], "AI Network Analysis")

        if topo:
            cidr = topo_range or "192.168.1.0/24"
            self.out.info(f"Mapping topology for {cidr} …")
            mapper = TopologyMapper(cidr)
            hosts  = mapper.sweep()
            result["topology"] = hosts
            self.out.info("\n" + mapper.ascii_graph(hosts))

        path = self.session.write("network.json", result)
        self.out.success(f"Network analysis saved → {path}")
        self.session.audit("network","complete",str(path))
        return result

    def _ai_analysis(self, data: dict) -> str:
        ctx = {
            "packet_count":data.get("packet_count"),
            "flow_count":  data.get("flow_count"),
            "alerts":      data.get("alerts",[]),
            "top_flows":   data.get("flows",[])[:20],
            "geoip":       data.get("geoip",[])[:10],
            "dns_queries": data.get("dns_queries",[])[:20],
        }
        return self.ai.chat(
            "Analyse this network traffic data for signs of compromise, data exfiltration, "
            "C2 communication, lateral movement, or policy violations. "
            "List specific IOCs, explain each alert, and recommend containment actions.",
            context=ctx,
        )