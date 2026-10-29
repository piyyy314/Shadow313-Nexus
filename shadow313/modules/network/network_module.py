"""shadow313.modules.network.network_module — NetworkModule orchestrator."""
from __future__ import annotations
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .pcap_parser  import PCAPParser
from .flow_tracker import FlowTracker
from .anomaly      import AnomalyDetector
from .topology     import TopologyMapper


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class NetworkModule:
    """shadow313.network — Traffic analysis, anomaly detection, topology."""

    def __init__(self, kernel) -> None:
        self.kernel  = kernel
        self.config  = kernel.config.get("network", default={})
        self.out     = kernel.out
        self.ai      = kernel.ai
        self.session = kernel.session

    def register(self, kernel) -> None:
        kernel.register("network", self.run)

    def run(self, capture: str = "", duration: int = 30,
            analyze: str = "", ai_score: bool = False,
            topo: bool = False, topo_range: str = "",
            bpf_filter: str = "", interface: str = "",
            capture_filter: str = "") -> dict:
        self.out.section("NETWORK INTELLIGENCE")
        self.session.audit("network", "start")

        result: dict[str, Any] = {"timestamp": _now()}

        # Live capture
        iface     = capture or interface
        pcap_path = analyze
        if iface:
            self.out.info(f"Capturing on {iface} for {duration}s …")
            try:
                pcap_path = self._live_capture(
                    iface, duration,
                    bpf_filter or capture_filter or self.config.get("capture_filter", "")
                )
                self.out.success(f"Capture saved → {pcap_path}")
            except PermissionError as exc:
                self.out.error(str(exc))
                return result

        # PCAP analysis
        if pcap_path:
            self.out.info(f"Parsing PCAP: {pcap_path} …")
            parser  = PCAPParser(pcap_path)
            packets = parser.parse()
            tracker = FlowTracker()
            flows   = tracker.from_packets(packets)

            result["packet_count"] = len(packets)
            result["flow_count"]   = len(flows)
            result["flows"]        = flows[:100]
            result["dns_queries"]  = parser.extract_dns_queries()
            result["http_hosts"]   = parser.extract_http_hosts()

            self.out.info(f"Parsed {len(packets):,} packets, {len(flows):,} flows.")

            alerts = AnomalyDetector(flows).detect()
            result["alerts"] = alerts
            if alerts:
                self.out.warn(f"{len(alerts)} anomaly alert(s) detected!")
                rows = [[a["type"], a["severity"], a["detail"][:80]] for a in alerts]
                self.out.table(["Type", "Severity", "Detail"], rows, "Anomaly Alerts")
            else:
                self.out.success("No anomalies detected.")

            # GeoIP enrichment
            from shadow313.modules.recon.geoip import GeoIPEnricher
            geoip = GeoIPEnricher()
            external_ips = list({
                f["dst_ip"] for f in flows
                if not AnomalyDetector._is_private(f["dst_ip"])
            })[:10]
            if external_ips:
                self.out.info(f"GeoIP enrichment for {len(external_ips)} IPs …")
                result["geoip"] = geoip.lookup_bulk(external_ips)

            rows = [[f["src_ip"], f["dst_ip"], f["dport"],
                     f["proto"], f["packets"], f["bytes"]]
                    for f in flows[:15]]
            self.out.table(
                ["Src IP", "Dst IP", "Dst Port", "Proto", "Pkts", "Bytes"],
                rows, "Top Flows"
            )

            if ai_score:
                self.out.info("Running AI anomaly scoring …")
                result["ai_analysis"] = self._ai_analysis(result)
                self.out.ai_response(result["ai_analysis"], "AI Network Analysis")

        # Topology mapping
        if topo:
            cidr = topo_range or self.config.get("default_interface", "192.168.1.0/24")
            self.out.info(f"Mapping topology for {cidr} …")
            mapper = TopologyMapper(cidr)
            hosts  = mapper.sweep()
            result["topology"] = hosts
            self.out.info("\n" + mapper.ascii_graph(hosts))

        path = self.session.write("network.json", result)
        self.session.write("flows.json",  result.get("flows", []))
        self.session.write("alerts.json", result.get("alerts", []))
        self.out.success(f"Network analysis saved → {path}")
        self.session.audit("network", "complete", str(path))
        return result

    def ai_context(self) -> dict:
        data = self.session.read("network.json") or {}
        return {
            "module":       "network",
            "packet_count": data.get("packet_count", 0),
            "flow_count":   data.get("flow_count", 0),
            "alert_count":  len(data.get("alerts", [])),
            "top_alerts":   data.get("alerts", [])[:3],
        }

    def _live_capture(self, interface: str, duration: int, bpf_filter: str) -> str:
        if os.geteuid() != 0:
            raise PermissionError(
                "Packet capture requires root or CAP_NET_RAW. "
                "Run with: sudo shadow313 network --capture"
            )
        out_path = f"/tmp/shadow313_capture_{int(time.time())}.pcap"
        cmd = ["tcpdump", "-i", interface, "-w", out_path,
               "-G", str(duration), "-W", "1", "--immediate-mode"]
        if bpf_filter:
            cmd.append(bpf_filter)
        try:
            subprocess.run(cmd, timeout=duration + 5, capture_output=True, check=False)
        except subprocess.TimeoutExpired:
            pass
        return out_path

    def _ai_analysis(self, data: dict) -> str:
        ctx = {
            "packet_count": data.get("packet_count"),
            "flow_count":   data.get("flow_count"),
            "alerts":       data.get("alerts", []),
            "top_flows":    data.get("flows", [])[:20],
            "geoip":        data.get("geoip", [])[:10],
            "dns_queries":  data.get("dns_queries", [])[:20],
        }
        return self.ai.chat(
            "Analyse this network traffic data for signs of compromise, data exfiltration, "
            "C2 communication, lateral movement, or policy violations. "
            "List specific IOCs, explain each alert, and recommend containment actions.",
            context=ctx,
        )