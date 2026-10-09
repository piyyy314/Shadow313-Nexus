"""
Shadow313 NEXUS — AI Documentation System
Interactive documentation with AI assistance via local Ollama.
"""
from __future__ import annotations
import json
from typing import Dict, List, Optional

MODULE_DOCS = {
    "recon":   {"name":"Recon Module","desc":"DNS enum, subdomain discovery, port scan, OSINT, AI profiling",
                "cmds":["shadow313 recon --target example.com --mode full"],"outputs":["recon.json","target.json"]},
    "vuln":    {"name":"Vuln Module","desc":"CVE/NVD, CVSS v3.1, EPSS, KEV, AI triage",
                "cmds":["shadow313 vuln --target example.com"],"outputs":["vuln.json"]},
    "network": {"name":"Network Module","desc":"PCAP, JA3/JARM, flow tracking, anomaly detection",
                "cmds":["shadow313 network --pcap capture.pcap"],"outputs":["flows.json"]},
    "defense": {"name":"Defense Module","desc":"24 CIS checks, SSH hardening, AI remediation",
                "cmds":["shadow313 defense --target localhost --cis-level 2"],"outputs":["defense_report.json"]},
    "quantum": {"name":"Quantum Module","desc":"FIPS 203/204/205, SLH-DSA, 313-BIND receipts",
                "cmds":["shadow313 quantum --target example.com --audit"],"outputs":["quantum_audit.json"]},
}

class AIDocsSystem:
    def __init__(self, ollama_url: str = "http://localhost:11434"):
        self.ollama_url = ollama_url

    def get_module_docs(self, module: str) -> Optional[Dict]:
        return MODULE_DOCS.get(module)

    def list_modules(self) -> List[str]:
        return list(MODULE_DOCS.keys())

    def search(self, query: str) -> List[Dict]:
        q = query.lower()
        return [{"module":n,"doc":d} for n,d in MODULE_DOCS.items()
                if q in d["name"].lower() or q in d["desc"].lower()]

    def generate_man_page(self, module: str) -> str:
        doc = self.get_module_docs(module)
        if not doc: return f"No docs for: {module}"
        return f"NAME\n    shadow313 {module} — {doc['name']}\n\nDESCRIPTION\n    {doc['desc']}\n\nCOMMANDS\n    " + "\n    ".join(doc["cmds"])

    def ai_help(self, question: str, module: str = None) -> str:
        context = ""
        if module and module in MODULE_DOCS:
            d = MODULE_DOCS[module]
            context = f"Module: {d['name']}\nDescription: {d['desc']}\n"
        try:
            import urllib.request
            payload = json.dumps({"model":"matarmohamad313/shadow313-nexus",
                                  "prompt":f"{context}\nQ: {question}\nA:","stream":False})
            req = urllib.request.Request(f"{self.ollama_url}/api/generate",
                                         data=payload.encode(),headers={"Content-Type":"application/json"})
            with urllib.request.urlopen(req, timeout=10) as r:
                return json.loads(r.read()).get("response","No response")
        except Exception as e:
            return f"AI unavailable: {e}"
