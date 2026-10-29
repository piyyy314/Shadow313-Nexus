"""shadow313.modules.recon.geoip — GeoIP enrichment via ip-api.com with session cache."""
from __future__ import annotations
import json
import time
from urllib import request as urlreq


class GeoIPEnricher:
    API_URL = "http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,query"

    def __init__(self) -> None:
        """Initialize an empty instance-local GeoIP result cache."""
        self._cache: dict[str, dict] = {}

    def lookup(self, ip: str) -> dict:
        """Return a cached or fetched GeoIP result, caching failures as well as successes."""
        if ip in self._cache:
            return self._cache[ip]
        result = self._fetch(ip)
        self._cache[ip] = result
        return result

    def lookup_bulk(self, ips: list[str], delay: float = 0.15) -> list[dict]:
        """Look up at most 20 IPs, sleeping delay seconds after each, including cache hits.

        Invalid sleep durations raise ValueError.
        """
        results = []
        for ip in ips[:20]:
            results.append(self.lookup(ip))
            time.sleep(delay)
        return results

    def _fetch(self, ip: str) -> dict:
        """Query ip-api.com, returning an error mapping on request or JSON decoding failure."""
        url = self.API_URL.format(ip=ip)
        try:
            req = urlreq.Request(url, headers={"User-Agent": "shadow313/2.0"})
            with urlreq.urlopen(req, timeout=8) as resp:
                return json.loads(resp.read())
        except Exception:
            return {"query": ip, "error": "GeoIP lookup failed"}

    @staticmethod
    def is_private(ip: str) -> bool:
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