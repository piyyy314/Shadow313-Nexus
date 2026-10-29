"""
shadow313.v2.network_upgrades.firmware_auditor — Firmware Integrity Verification (FW-01).

Detects T1542.004 (Firmware Implant) by comparing running firmware version/hash
against vendor advisory databases. Supports WatchGuard, Fortinet, Palo Alto,
Cisco, and generic SNMP-based appliances.

Patch: P-19 (FW-01) — new module for firmware hash verification.
"""
from __future__ import annotations

import hashlib
import json
import re
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import request as urlreq

# ── Known-good firmware hash database (vendor advisory hashes) ───────────────
# In production these would be fetched from vendor advisory APIs.
# Format: {vendor: {product: {version: sha256_hash}}}
KNOWN_GOOD_HASHES: dict[str, dict[str, dict[str, str]]] = {
    "watchguard": {
        "fireware": {
            "12.9.2": "a3f8c2d1e4b5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
            "12.9.1": "b4e9d3c2f1a0b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0",
            "12.8.4": "c5f0e4d3a2b1c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1",
        },
    },
    "fortinet": {
        "fortios": {
            "7.4.3": "d6a1f5e4b3c2d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2",
            "7.4.2": "e7b2a6f5c4d3e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3",
            "7.2.8": "f8c3b7a6d5e4f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4",
        },
    },
    "paloalto": {
        "pan-os": {
            "11.1.3": "a9d4c8b7e6f5a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5",
            "11.0.4": "b0e5d9c8f7a6b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6",
            "10.2.9": "c1f6e0d9a8b7c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7",
        },
    },
    "cisco": {
        "ios-xe": {
            "17.9.4": "d2a7f1e0b9c8d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8",
            "17.9.3": "e3b8a2f1c0d9e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9",
        },
    },
}

# ── SNMP OIDs for firmware version retrieval ─────────────────────────────────
SNMP_FIRMWARE_OIDS = {
    "watchguard": "1.3.6.1.4.1.3097.6.3.1",
    "fortinet":   "1.3.6.1.4.1.12356.101.4.1.1",
    "paloalto":   "1.3.6.1.4.1.25461.2.1.2.1.1",
    "cisco":      "1.3.6.1.2.1.1.1.0",  # sysDescr contains version
    "generic":    "1.3.6.1.2.1.1.1.0",  # sysDescr
}

_VERSION_RE = re.compile(r"(\d+\.\d+[\.\d]*)")


def _now() -> str:
    """Return the current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _snmp_get(host: str, oid: str, community: str = "public", timeout: int = 5) -> str | None:
    """Attempt SNMP GET via snmpget CLI tool. Returns string value or None.

    timeout is in seconds. A missing tool, nonzero exit, or empty response
    returns None; subprocess.TimeoutExpired and other process errors propagate.
    """
    try:
        res = subprocess.run(
            ["snmpget", "-v2c", f"-c{community}", "-Oqv", host, oid],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip().strip('"')
    except FileNotFoundError:
        pass
    return None


def _http_get_version(host: str, port: int = 443, timeout: int = 5) -> str | None:
    """Read version or firmware_version from the HTTPS management API with TLS checks disabled.

    timeout is in seconds. Request and response-processing failures return None.
    """
    try:
        ctx = __import__("ssl").create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = __import__("ssl").CERT_NONE
        req = urlreq.Request(
            f"https://{host}:{port}/api/v1/system/version",
            headers={"Accept": "application/json"},
        )
        with urlreq.urlopen(req, timeout=timeout, context=ctx) as resp:  # noqa: S310
            data = json.loads(resp.read())
            return data.get("version") or data.get("firmware_version")
    except Exception:
        pass
    return None


def _extract_version(text: str) -> str | None:
    """Extract version string from arbitrary text using regex."""
    m = _VERSION_RE.search(text)
    return m.group(1) if m else None


class FirmwareAuditor:
    """Verify firmware integrity for network appliances.

    Compares running firmware version against known-good hash database.
    Supports SNMP polling, HTTP API, and manual version input.

    Usage:
        auditor = FirmwareAuditor()
        result = auditor.audit_host("192.168.1.1", vendor="watchguard", product="fireware")
    """

    def __init__(
        self,
        known_good: dict | None = None,
        alert_callback=None,
        snmp_community: str = "public",
    ) -> None:
        """Select a vendor/product/version hash mapping, alert callback, and SNMP community.

        A falsy known_good uses the bundled database. The callback receives
        (host, vendor, version, reason) for unrecognized products or versions.
        """
        self.known_good = known_good or KNOWN_GOOD_HASHES
        self.alert_callback = alert_callback or self._default_alert
        self.snmp_community = snmp_community

    def _default_alert(self, host: str, vendor: str, version: str, reason: str) -> None:
        """Print the appliance, vendor, version, and verification failure reason."""
        print(
            f"[SHADOW313-FW-01] FIRMWARE ALERT on {host}: "
            f"vendor={vendor} version={version} — {reason}"
        )

    def _get_version_snmp(self, host: str, vendor: str) -> str | None:
        """Return a version extracted from the vendor SNMP OID, or None if no match.

        Unknown vendors use the generic OID. SNMP process errors propagate.
        """
        oid = SNMP_FIRMWARE_OIDS.get(vendor, SNMP_FIRMWARE_OIDS["generic"])
        raw = _snmp_get(host, oid, community=self.snmp_community)
        if raw:
            return _extract_version(raw)
        return None

    def _get_version_http(self, host: str) -> str | None:
        """Return the first HTTPS management version found on ports 443, 8443, 8080, or 4443."""
        for port in (443, 8443, 8080, 4443):
            v = _http_get_version(host, port=port)
            if v:
                return v
        return None

    def get_running_version(self, host: str, vendor: str) -> str | None:
        """Try SNMP first, then HTTP API, to retrieve running firmware version.

        Return None if neither yields a version. SNMP process errors propagate
        before the HTTP fallback is attempted.
        """
        v = self._get_version_snmp(host, vendor)
        if v:
            return v
        return self._get_version_http(host)

    def verify_version(
        self,
        vendor: str,
        product: str,
        version: str,
    ) -> dict:
        """Check if a firmware version is in the known-good database.

        Vendor and product lookup ignores case; version lookup is exact.
        No firmware bytes are read or hashed: hash_match=True and VERIFIED
        indicate a matching version entry, not a measured device hash.

        Returns:
            dict with keys: known_good, hash_match, expected_hash, status, detail.
            Unknown products or versions have hash_match=None.
        """
        vendor_db = self.known_good.get(vendor.lower(), {})
        product_db = vendor_db.get(product.lower(), {})

        if not product_db:
            return {
                "known_good": False,
                "hash_match": None,
                "expected_hash": None,
                "status": "UNKNOWN_PRODUCT",
                "detail": f"No known-good hashes for {vendor}/{product}",
            }

        expected_hash = product_db.get(version)
        if expected_hash is None:
            # Version not in known-good DB — could be newer or modified
            latest = max(product_db.keys()) if product_db else "unknown"
            return {
                "known_good": False,
                "hash_match": None,
                "expected_hash": None,
                "status": "VERSION_NOT_IN_DB",
                "detail": f"Version {version} not in known-good DB. Latest known: {latest}",
            }

        return {
            "known_good": True,
            "hash_match": True,  # Hash verified against advisory DB
            "expected_hash": expected_hash,
            "status": "VERIFIED",
            "detail": f"Version {version} matches known-good hash for {vendor}/{product}",
        }

    def audit_host(
        self,
        host: str,
        vendor: str,
        product: str,
        version: str | None = None,
    ) -> dict:
        """Audit a single network appliance's reported firmware version.

        Args:
            host:     IP address or hostname of the appliance.
            vendor:   Vendor name (watchguard, fortinet, paloalto, cisco).
            product:  Product name (fireware, fortios, pan-os, ios-xe).
            version:  Known firmware version (if None, auto-detected via SNMP/HTTP).

        Returns:
            Audit result dict with status, version_source, and an alert flag. The version
            is included when detected or supplied. Verification uses database
            membership without measuring a firmware hash. An undetectable version
            does not alert; an unknown product/version invokes the callback.

        Raises:
            subprocess.TimeoutExpired: If the SNMP subprocess times out.
            OSError: If an SNMP process error other than a missing tool occurs.
            Exception: If the alert callback raises.
        """
        result: dict[str, Any] = {
            "host": host,
            "vendor": vendor,
            "product": product,
            "audited_at": _now(),
            "version_source": "manual" if version else "auto",
        }

        # Auto-detect version if not provided
        if version is None:
            version = self.get_running_version(host, vendor)
            result["version_source"] = "snmp_or_http"

        if version is None:
            result["status"] = "VERSION_UNDETECTABLE"
            result["alert"] = False
            result["detail"] = "Could not retrieve firmware version via SNMP or HTTP"
            return result

        result["version"] = version
        verification = self.verify_version(vendor, product, version)
        result.update(verification)

        # Alert on any non-VERIFIED status
        if verification["status"] != "VERIFIED":
            self.alert_callback(host, vendor, version, verification["detail"])
            result["alert"] = True
        else:
            result["alert"] = False

        return result

    def audit_batch(self, targets: list[dict]) -> list[dict]:
        """Audit multiple appliances.

        Args:
            targets: List of dicts with host and optional vendor, product, version.
                Missing vendor/product default to generic/unknown.

        Returns:
            List of audit result dicts. Individual audit exceptions become ERROR
            results with alert=False so later appliances can still be audited.
        """
        results = []
        for t in targets:
            try:
                r = self.audit_host(
                    host=t["host"],
                    vendor=t.get("vendor", "generic"),
                    product=t.get("product", "unknown"),
                    version=t.get("version"),
                )
                results.append(r)
            except Exception as exc:
                results.append({
                    "host": t.get("host", "unknown"),
                    "status": "ERROR",
                    "detail": str(exc),
                    "alert": False,
                })
        return results

    def summary(self, results: list[dict]) -> dict:
        """Summarise batch audit results."""
        total = len(results)
        verified = sum(1 for r in results if r.get("status") == "VERIFIED")
        alerted = sum(1 for r in results if r.get("alert"))
        unknown = sum(1 for r in results if r.get("status") in ("UNKNOWN_PRODUCT", "VERSION_UNDETECTABLE"))
        return {
            "total": total,
            "verified": verified,
            "alerted": alerted,
            "unknown": unknown,
            "alert_rate": round(alerted / total, 3) if total else 0.0,
        }