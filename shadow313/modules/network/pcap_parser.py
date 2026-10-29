"""shadow313.modules.network.pcap_parser — Pure-Python PCAP parser (no scapy)."""
from __future__ import annotations
import socket
import struct

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
        self.flows:   dict[tuple, dict] = {}
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
            "ethertype": hex(etype),
        }
        if etype == ETHERTYPE_IP and len(raw) >= 34:
            pkt.update(self._decode_ip(raw[14:]))
        elif etype == ETHERTYPE_ARP:
            pkt["protocol"] = "ARP"
        return pkt

    def _decode_ip(self, raw: bytes) -> dict:
        if len(raw) < 20:
            return {}
        iph    = IP_HEADER.unpack(raw[:20])
        ihl    = (iph[0] & 0xF) * 4
        proto  = iph[6]
        src_ip = _ip_str(iph[8])
        dst_ip = _ip_str(iph[9])
        info: dict = {
            "src_ip":   src_ip,
            "dst_ip":   dst_ip,
            "protocol": {PROTO_TCP: "TCP", PROTO_UDP: "UDP",
                         PROTO_ICMP: "ICMP"}.get(proto, str(proto)),
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
        key = (pkt.get("src_ip", ""), pkt.get("dst_ip", ""),
               pkt.get("sport", 0), pkt.get("dport", 0),
               pkt.get("protocol", ""))
        if key not in self.flows:
            self.flows[key] = {"packets": 0, "bytes": 0,
                               "first": pkt["ts"], "last": pkt["ts"]}
        self.flows[key]["packets"] += 1
        self.flows[key]["bytes"]   += pkt.get("length", 0)
        self.flows[key]["last"]     = pkt["ts"]

    def get_flows(self) -> list[dict]:
        results = []
        for (src_ip, dst_ip, sport, dport, proto), stats in self.flows.items():
            results.append({
                "src_ip":   src_ip, "dst_ip":  dst_ip,
                "sport":    sport,  "dport":   dport,
                "proto":    proto,
                "packets":  stats["packets"],
                "bytes":    stats["bytes"],
                "duration": round(stats["last"] - stats["first"], 3),
            })
        return sorted(results, key=lambda x: x["bytes"], reverse=True)

    def extract_dns_queries(self) -> list[str]:
        return [pkt.get("payload_preview", "")[:50]
                for pkt in self.packets
                if pkt.get("dport") == 53 or pkt.get("sport") == 53
                if pkt.get("payload_preview")]

    def extract_http_hosts(self) -> list[str]:
        hosts = []
        for pkt in self.packets:
            if pkt.get("dport") in (80, 8080, 8000):
                preview = pkt.get("payload_preview", "")
                if "Host:" in preview:
                    for line in preview.split("\n"):
                        if line.startswith("Host:"):
                            hosts.append(line.strip())
        return list(set(hosts))