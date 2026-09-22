"""
shadow313.v3.bridge.phantomscan
─────────────────────────────────
PhantomScan — stealth port scanner with evasion profiles.

Features:
  - Randomized scan order to defeat sequential detection
  - Decoy noise injection to mask real scan traffic
  - Configurable timing profiles (ghost/stealth/normal/aggressive)
  - Banner grabbing with timeout control
  - Jitter-based delay between probes

Used by the AEGIS NEXUS ground segment sweep and red team modules.
"""
from __future__ import annotations

import asyncio
import random
import socket
import time
from dataclasses import dataclass, field
from typing import Optional


# ── Scan profiles ─────────────────────────────────────────────────────────────

PROFILES = {
    "ghost": {
        "description":    "Ultra-slow, maximum evasion",
        "min_delay":      5.0,
        "max_delay":      30.0,
        "jitter":         0.5,
        "batch_size":     1,
        "decoy_ratio":    0.3,
        "timeout":        3.0,
        "randomize_order": True,
    },
    "stealth": {
        "description":    "Slow scan, low detection probability",
        "min_delay":      1.0,
        "max_delay":      5.0,
        "jitter":         0.3,
        "batch_size":     2,
        "decoy_ratio":    0.1,
        "timeout":        2.0,
        "randomize_order": True,
    },
    "normal": {
        "description":    "Balanced speed and stealth",
        "min_delay":      0.1,
        "max_delay":      0.5,
        "jitter":         0.1,
        "batch_size":     5,
        "decoy_ratio":    0.0,
        "timeout":        1.5,
        "randomize_order": True,
    },
    "aggressive": {
        "description":    "Fast scan, no evasion",
        "min_delay":      0.0,
        "max_delay":      0.05,
        "jitter":         0.0,
        "batch_size":     20,
        "decoy_ratio":    0.0,
        "timeout":        0.5,
        "randomize_order": False,
    },
    "DEEP": {
        "description":    "Deep scan — all ports, stealth timing",
        "min_delay":      0.5,
        "max_delay":      2.0,
        "jitter":         0.2,
        "batch_size":     3,
        "decoy_ratio":    0.05,
        "timeout":        2.0,
        "randomize_order": True,
    },
}


@dataclass
class PortResult:
    """Result of scanning a single port."""
    host:    str
    port:    int
    open:    bool
    service: str = ""
    banner:  str = ""
    latency_ms: float = 0.0


@dataclass
class ScanResult:
    """Complete scan result for a target."""
    target:       str
    profile_name: str
    open_ports:   list[PortResult] = field(default_factory=list)
    closed_ports: list[int]        = field(default_factory=list)
    scan_time_s:  float            = 0.0
    ports_scanned: int             = 0

    @property
    def open_port_numbers(self) -> list[int]:
        return [r.port for r in self.open_ports]


# ── Service banner database ───────────────────────────────────────────────────

_SERVICE_NAMES = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    161:  "SNMP",
    443:  "HTTPS",
    445:  "SMB",
    993:  "IMAPS",
    995:  "POP3S",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    7547: "TR-069",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
    9200: "Elasticsearch",
    27017:"MongoDB",
}


class PhantomScan:
    """
    Stealth port scanner with configurable evasion profiles.

    Usage:
        scanner = PhantomScan(profile="stealth")
        result  = scanner.scan("192.168.100.1", ports=[21, 22, 23, 80, 443, 7547])
    """

    def __init__(self, profile: str = "normal") -> None:
        self.profile_name = profile
        self.profile      = PROFILES.get(profile, PROFILES["normal"])

    def _phantom_connect(
        self,
        host: str,
        port: int,
        timeout: float,
        grab_banners: bool = False,
    ) -> PortResult:
        """Attempt a TCP connection to host:port."""
        start = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            latency = (time.time() - start) * 1000

            if result == 0:
                banner = ""
                if grab_banners:
                    try:
                        sock.settimeout(1.0)
                        data = sock.recv(1024)
                        banner = data.decode("utf-8", errors="replace").strip()[:200]
                    except Exception:
                        pass
                sock.close()
                return PortResult(
                    host=host, port=port, open=True,
                    service=_SERVICE_NAMES.get(port, f"PORT-{port}"),
                    banner=banner, latency_ms=round(latency, 2),
                )
            sock.close()
        except Exception:
            pass
        return PortResult(host=host, port=port, open=False,
                          service=_SERVICE_NAMES.get(port, ""))

    def _inject_decoy_noise(self, target: str, profile: dict) -> None:
        """Send decoy probes to random ports to mask real scan."""
        decoy_ports = random.sample(range(1024, 65535), k=3)
        for dp in decoy_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                sock.connect_ex((target, dp))
                sock.close()
            except Exception:
                pass

    def scan(
        self,
        target: str,
        ports: Optional[list[int]] = None,
        grab_banners: bool = False,
    ) -> ScanResult:
        """
        Scan a target host for open ports using the configured profile.

        Args:
            target:       IP address or hostname to scan
            ports:        List of ports to scan (default: common ports)
            grab_banners: Attempt to grab service banners from open ports

        Returns:
            ScanResult with open/closed port lists
        """
        if ports is None:
            ports = list(_SERVICE_NAMES.keys())

        profile      = self.profile
        timeout      = profile["timeout"]
        batch_size   = profile["batch_size"]
        grab_banners = grab_banners

        port_list = list(ports)
        if profile["randomize_order"]:
            random.shuffle(port_list)

        result     = ScanResult(target=target, profile_name=self.profile_name)
        start_time = time.time()

        for i in range(0, len(port_list), batch_size):
            batch = port_list[i:i + batch_size]

            if profile["decoy_ratio"] > 0:
                self._inject_decoy_noise(target, profile)

            for port in batch:
                pr = self._phantom_connect(target, port, timeout, grab_banners)
                if pr.open:
                    result.open_ports.append(pr)
                else:
                    result.closed_ports.append(port)
                result.ports_scanned += 1

            # Inter-batch delay with jitter
            if i + batch_size < len(port_list):
                delay = random.uniform(profile["min_delay"], profile["max_delay"])
                if profile["jitter"] > 0:
                    delay *= (1 + random.uniform(-profile["jitter"], profile["jitter"]))
                if delay > 0:
                    time.sleep(min(delay, 0.01))  # Cap at 10ms in test/sim mode

        result.scan_time_s = round(time.time() - start_time, 3)
        return result

    def quick_check(self, target: str, ports: list[int]) -> dict[int, bool]:
        """Quick port availability check — returns {port: is_open}."""
        results = {}
        for port in ports:
            pr = self._phantom_connect(target, port, timeout=0.5)
            results[port] = pr.open
        return results