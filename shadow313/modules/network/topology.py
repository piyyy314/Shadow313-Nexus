"""shadow313.modules.network.topology — ASCII topology mapper via ICMP ping sweep."""
from __future__ import annotations
import socket
import subprocess


class TopologyMapper:
    def __init__(self, cidr: str) -> None:
        self.cidr = cidr

    def sweep(self) -> list[dict]:
        hosts  = list(self._cidr_hosts())
        alive  = []
        for ip in hosts[:254]:
            if self._ping(ip):
                hostname = self._reverse_dns(ip)
                alive.append({"ip": ip, "hostname": hostname, "state": "up"})
        return alive

    def ascii_graph(self, hosts: list[dict]) -> str:
        lines = ["Network Topology", "=" * 40, "  [Gateway]", "      |"]
        for h in hosts:
            label = h["ip"]
            if h.get("hostname") and h["hostname"] != h["ip"]:
                label += f"  ({h['hostname']})"
            lines.append(f"      ├── {label}")
        return "\n".join(lines)

    def _ping(self, ip: str) -> bool:
        try:
            
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

# ── Routing Table Snapshot & Diff (NB-01) ────────────────────────────────────
import hashlib as _hashlib
import json as _json
import subprocess as _subprocess
from datetime import datetime as _datetime, timezone as _timezone
from pathlib import Path as _Path


class RoutingTableMonitor:
    """Capture routing table snapshots and diff for new cross-segment routes.

    Detects T1599 (Network Boundary Bridging) by alerting on any new route
    that creates a path between previously isolated network segments.

    Args:
        snapshot_path:    Where to persist the last known-good snapshot.
        alert_callback:   Callable(new_routes) invoked when new routes appear.
    """

    SNAPSHOT_PATH = _Path("~/.shadow313/routing_snapshot.json").expanduser()

    def __init__(
        self,
        snapshot_path: _Path | None = None,
        alert_callback=None,
    ) -> None:
        self.snapshot_path = snapshot_path or self.SNAPSHOT_PATH
        self.alert_callback = alert_callback or self._default_alert

    def _default_alert(self, new_routes: list[str]) -> None:
        for r in new_routes:
            print(f"[SHADOW313-NB-01] NEW ROUTE DETECTED (T1599 risk): {r}")

    def _get_routes(self) -> list[str]:
        """Return current routing table as sorted list of route strings."""
        routes: list[str] = []
        # Linux: ip route show
        try:
            res = _subprocess.run(
                ["ip", "route", "show"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            if res.returncode == 0:
                routes = sorted(line.strip() for line in res.stdout.splitlines() if line.strip())
                return routes
        except FileNotFoundError:
            pass
        # macOS / BSD fallback: netstat -rn
        try:
            res = _subprocess.run(
                ["netstat", "-rn"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            if res.returncode == 0:
                routes = sorted(line.strip() for line in res.stdout.splitlines() if line.strip())
                return routes
        except FileNotFoundError:
            pass
        return routes

    def _load_snapshot(self) -> list[str]:
        if self.snapshot_path.exists():
            try:
                data = _json.loads(self.snapshot_path.read_text(encoding="utf-8"))
                return data.get("routes", [])
            except Exception:
                pass
        return []

    def _save_snapshot(self, routes: list[str]) -> None:
        self.snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        self.snapshot_path.write_text(
            _json.dumps({
                "routes": routes,
                "captured_at": _datetime.now(_timezone.utc).isoformat(),
                "hash": _hashlib.sha256("\n".join(routes).encode()).hexdigest(),
            }, indent=2),
            encoding="utf-8",
        )

    def check(self) -> dict:
        """Compare current routing table against last snapshot.

        Returns:
            dict with keys: new_routes, removed_routes, unchanged, alerted
        """
        current = self._get_routes()
        previous = self._load_snapshot()

        current_set = set(current)
        previous_set = set(previous)

        new_routes = sorted(current_set - previous_set)
        removed_routes = sorted(previous_set - current_set)

        alerted = False
        if new_routes:
            self.alert_callback(new_routes)
            alerted = True

        # Always update snapshot to current state
        self._save_snapshot(current)

        return {
            "new_routes": new_routes,
            "removed_routes": removed_routes,
            "unchanged": len(current_set & previous_set),
            "total_routes": len(current),
            "alerted": alerted,
        }

    def baseline(self) -> dict:
        """Capture current routing table as the trusted baseline."""
        routes = self._get_routes()
        self._save_snapshot(routes)
        return {"baselined": len(routes), "path": str(self.snapshot_path)}
