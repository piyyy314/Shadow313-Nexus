"""
shadow313.v4.stix.stix_handler  — v4
STIX 2.1 bundle import/export, IOC extraction, ATT&CK STIX integration.
"""
from __future__ import annotations
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_STIX_TYPES = {
    "indicator", "malware", "threat-actor", "attack-pattern",
    "campaign", "course-of-action", "identity", "intrusion-set",
    "observed-data", "report", "tool", "vulnerability", "relationship",
    "sighting", "bundle",
}

_IPV4_RE   = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
_SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")
_DOMAIN_RE = re.compile(r"[a-zA-Z0-9][\w\-]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}")
_CVE_RE    = re.compile(r"CVE-\d{4}-\d{4,7}")


class STIXParser:
    """Parse STIX 2.1 bundles and extract IOCs."""

    def parse_bundle(self, bundle: dict) -> dict:
        if bundle.get("type") != "bundle":
            return {"error": "Not a STIX bundle"}

        objects = bundle.get("objects", [])
        result: dict[str, Any] = {
            "bundle_id":  bundle.get("id", ""),
            "spec_version": bundle.get("spec_version", ""),
            "object_count": len(objects),
            "indicators":   [],
            "malware":      [],
            "threat_actors":[],
            "iocs":         {"ips": [], "domains": [], "hashes": [], "cves": []},
        }

        for obj in objects:
            obj_type = obj.get("type", "")
            if obj_type == "indicator":
                result["indicators"].append(self._parse_indicator(obj))
            elif obj_type == "malware":
                result["malware"].append({
                    "id":   obj.get("id", ""),
                    "name": obj.get("name", ""),
                    "types":obj.get("malware_types", []),
                })
            elif obj_type == "threat-actor":
                result["threat_actors"].append({
                    "id":   obj.get("id", ""),
                    "name": obj.get("name", ""),
                    "aliases": obj.get("aliases", []),
                })

        # Extract IOCs from all objects
        bundle_text = json.dumps(bundle)
        result["iocs"]["ips"]     = list(set(_IPV4_RE.findall(bundle_text)))[:50]
        result["iocs"]["hashes"]  = list(set(_SHA256_RE.findall(bundle_text)))[:20]
        result["iocs"]["cves"]    = list(set(_CVE_RE.findall(bundle_text)))[:20]

        return result

    def _parse_indicator(self, obj: dict) -> dict:
        pattern = obj.get("pattern", "")
        ioc_type = "unknown"
        ioc_value = ""

        # Parse STIX pattern
        if "ipv4-addr:value" in pattern:
            ioc_type = "ip"
            m = re.search(r"'([^']+)'", pattern)
            if m:
                ioc_value = m.group(1)
        elif "domain-name:value" in pattern:
            ioc_type = "domain"
            m = re.search(r"'([^']+)'", pattern)
            if m:
                ioc_value = m.group(1)
        elif "file:hashes" in pattern:
            ioc_type = "hash"
            m = re.search(r"'([0-9a-fA-F]{32,64})'", pattern)
            if m:
                ioc_value = m.group(1)
        elif "url:value" in pattern:
            ioc_type = "url"
            m = re.search(r"'([^']+)'", pattern)
            if m:
                ioc_value = m.group(1)

        return {
            "id":         obj.get("id", ""),
            "name":       obj.get("name", ""),
            "ioc_type":   ioc_type,
            "ioc_value":  ioc_value,
            "pattern":    pattern,
            "valid_from": obj.get("valid_from", ""),
            "labels":     obj.get("labels", []),
        }

    def parse_file(self, path: str) -> dict:
        p = Path(path)
        if not p.exists():
            return {"error": f"File not found: {path}"}
        try:
            bundle = json.loads(p.read_text())
            return self.parse_bundle(bundle)
        except Exception as exc:
            return {"error": str(exc)}


class STIXBuilder:
    """Build STIX 2.1 bundles from Shadow313 findings."""

    def findings_to_bundle(self, findings: list[dict], session_id: str = "") -> dict:
        """Convert Shadow313 findings to STIX 2.1 bundle."""
        objects = []
        now = datetime.now(timezone.utc).isoformat()

        # Identity object for Shadow313
        identity = {
            "type":             "identity",
            "id":               "identity--shadow313-nexus",
            "spec_version":     "2.1",
            "name":             "Shadow313 NEXUS",
            "identity_class":   "system",
            "created":          now,
            "modified":         now,
        }
        objects.append(identity)

        for f in findings:
            cve = f.get("cve", "")
            if not cve:
                continue

            # Vulnerability object
            vuln = {
                "type":         "vulnerability",
                "id":           f"vulnerability--{cve.lower().replace('-','_')}",
                "spec_version": "2.1",
                "name":         cve,
                "description":  f.get("description", "")[:500],
                "created":      now,
                "modified":     now,
                "external_references": [{
                    "source_name": "cve",
                    "external_id": cve,
                    "url":         f"https://nvd.nist.gov/vuln/detail/{cve}",
                }],
            }
            objects.append(vuln)

            # Indicator if we have a service/port
            port = f.get("port")
            if port:
                indicator = {
                    "type":         "indicator",
                    "id":           f"indicator--{cve.lower().replace('-','_')}-port{port}",
                    "spec_version": "2.1",
                    "name":         f"{cve} on port {port}",
                    "pattern":      f"[network-traffic:dst_port = {port}]",
                    "pattern_type": "stix",
                    "valid_from":   now,
                    "created":      now,
                    "modified":     now,
                    "labels":       ["malicious-activity"],
                }
                objects.append(indicator)

        return {
            "type":         "bundle",
            "id":           f"bundle--shadow313-{session_id or 'export'}",
            "spec_version": "2.1",
            "objects":      objects,
        }


class STIXModule:
    """shadow313.v4.stix — STIX 2.1 handler. Registered: stix"""

    def __init__(self, kernel) -> None:
        self.kernel  = kernel
        self.out     = kernel.out
        self.session = kernel.session
        self._parser = STIXParser()
        self._builder= STIXBuilder()

    def register(self, kernel) -> None:
        kernel.register("stix", self.run)

    def run(
        self,
        import_file: str = "",
        export: bool = False,
        export_path: str = "",
        ingest_threat_intel: bool = False,
    ) -> dict:
        self.out.section("STIX 2.1 HANDLER")
        result: dict[str, Any] = {}

        if import_file:
            self.out.info(f"Parsing STIX bundle: {import_file} …")
            parsed = self._parser.parse_file(import_file)
            result["parsed"] = parsed

            if "error" not in parsed:
                self.out.success(f"Parsed {parsed['object_count']} STIX objects")
                self.out.info(f"Indicators: {len(parsed['indicators'])}")
                self.out.info(f"Malware:    {len(parsed['malware'])}")
                self.out.info(f"IOCs:       {sum(len(v) for v in parsed['iocs'].values())}")

                rows = [[i["name"], i["ioc_type"], i["ioc_value"][:40], ", ".join(i["labels"])]
                        for i in parsed["indicators"][:20]]
                if rows:
                    self.out.table(["Name","Type","Value","Labels"], rows, "STIX Indicators")

                # Optionally ingest IOCs into threat intel DB
                if ingest_threat_intel:
                    ti_module = self.kernel.get_module("threat_intel")
                    if ti_module:
                        for ip in parsed["iocs"]["ips"]:
                            ti_module.manager._db.upsert_ip(ip, "stix_import", "malicious")
                        self.out.success(f"Ingested {len(parsed['iocs']['ips'])} IPs into threat intel DB")

        if export:
            self.out.info("Exporting session findings as STIX bundle …")
            findings = (self.session.read("findings.json") or {}).get("findings", [])
            bundle   = self._builder.findings_to_bundle(findings, self.session.id)
            result["bundle"] = bundle

            out_path = export_path or str(self.session.path("stix_export.json"))
            Path(out_path).write_text(json.dumps(bundle, indent=2))
            self.out.success(f"STIX bundle exported → {out_path}")
            self.out.info(f"Objects: {len(bundle['objects'])}")

        return result