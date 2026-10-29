"""shadow313.modules.recon.port_scan — Async TCP port scanner."""
from __future__ import annotations
import asyncio
import time


class AsyncPortScanner:
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
        443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900,
        6379, 8080, 8443, 8888, 9200, 27017,
    ]

    def __init__(self, host: str, ports: list[int] | None = None,
                 timeout: float = 1.0, stealth: bool = False) -> None:
        self.host    = host
        self.ports   = ports or self.COMMON_PORTS
        self.timeout = timeout
        self.stealth = stealth

    async def _probe(self, port: int) -> dict | None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, port), timeout=self.timeout
            )
            banner = ""
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                banner = data.decode("utf-8", errors="replace").strip()
            except Exception:
                pass
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return {"port": port, "state": "open", "banner": banner[:200]}
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None

    async def scan_async(self) -> list[dict]:
        if self.stealth:
            results = []
            for p in self.ports:
                r = await self._probe(p)
                if r:
                    results.append(r)
                await asyncio.sleep(0.3)
            return results
        tasks = [self._probe(p) for p in self.ports]
        raw   = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in raw if isinstance(r, dict)]

    def scan(self) -> list[dict]:
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    future = pool.submit(asyncio.run, self.scan_async())
                    return future.result()
        except RuntimeError:
            pass
        return asyncio.run(self.scan_async())

    @staticmethod
    def parse_ports(ports_str: str) -> list[int]:
        if not ports_str:
            return AsyncPortScanner.COMMON_PORTS
        result = []
        for part in ports_str.split(","):
            part = part.strip()
            if "-" in part:
                lo, hi = part.split("-", 1)
                result.extend(range(int(lo), int(hi) + 1))
            else:
                result.append(int(part))
        return result