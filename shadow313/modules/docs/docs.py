"""
shadow313.modules.docs  — v4
Documentation, AI ask command, tutorials, man page generation, glossary.
"""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


MODULE_DOCS: dict[str,dict] = {
    "recon": {
        "title":       "Reconnaissance Module",
        "description": "Passive and active reconnaissance — DNS, subdomains, port scanning, OSINT, AI profiling.",
        "commands": [
            ("shadow313 recon --target example.com",                    "Full recon against a domain"),
            ("shadow313 recon --target 192.168.1.10 --mode active",     "Active scan"),
            ("shadow313 recon --target example.com --mode passive",      "Passive only"),
            ("shadow313 recon --target example.com --stealth",           "Stealth mode"),
        ],
        "flags": {
            "--target":  "Target domain, IP, CIDR, or URL",
            "--mode":    "Scan mode: full | active | passive (default: full)",
            "--ports":   "Port range: 1-1024 or 80,443,8080",
            "--stealth": "Rate-limit requests",
            "--output":  "Output format: rich | json | markdown",
        },
        "outputs": ["recon.json","target.json"],
    },
    "vuln": {
        "title":       "Vulnerability Analysis Module",
        "description": "CVE correlation, CVSS scoring, exploit availability, dependency auditing, AI triage.",
        "commands": [
            ("shadow313 vuln --from-session <uuid>",            "Analyse recon output from a session"),
            ("shadow313 vuln --audit-deps requirements.txt",    "Audit Python dependencies"),
            ("shadow313 vuln --audit-deps package.json",        "Audit Node.js dependencies"),
            ("shadow313 vuln --target apache --quick",          "Quick keyword CVE search"),
            ("shadow313 update --db cve",                       "Update local CVE database"),
        ],
        "flags": {
            "--from-session":  "Session UUID to load recon data from",
            "--target":        "Service/keyword for CVE search",
            "--audit-deps":    "Path to dependency file",
            "--quick":         "Skip exploit availability check",
            "--epss":          "Enrich with EPSS scores",
            "--kev":           "Check CISA KEV catalog",
        },
        "outputs": ["findings.json","risk_matrix.json"],
    },
    "exploit": {
        "title":       "Exploitation Assistance Module (Advisory)",
        "description": "AI-guided exploitation assistance — lab mode only. No autonomous attack execution.",
        "commands": [
            ("shadow313 exploit --cve CVE-2024-1234 --lab-mode",                    "CVE walkthrough (lab)"),
            ("shadow313 exploit --assist ctf --challenge 'Buffer overflow ELF'",    "CTF solver"),
            ("shadow313 exploit --payload reverse_shell_python --lab-mode",         "Payload template"),
            ("shadow313 exploit --post-exploit --platform linux --lab-mode",        "Post-exploit checklist"),
            ("shadow313 exploit --assist scope-init",                               "Create scope.yaml"),
        ],
        "flags": {
            "--lab-mode":  "REQUIRED — enables advisory mode",
            "--cve":       "CVE ID to research",
            "--assist":    "Assistance mode: ctf | post | scope-init",
            "--payload":   "Payload template name (or 'list')",
            "--platform":  "Target platform: linux | windows",
        },
        "outputs": ["exploit_guide.json"],
        "safety_note": "Requires --lab-mode. Only for authorized pen-tests and CTFs.",
    },
    "network": {
        "title":       "Network Intelligence Module",
        "description": "Live capture, PCAP analysis, anomaly detection, topology mapping, GeoIP enrichment.",
        "commands": [
            ("sudo shadow313 network --capture eth0 --duration 60",         "Live capture (requires root)"),
            ("shadow313 network --analyze ./capture.pcap",                   "Analyse PCAP file"),
            ("shadow313 network --analyze ./capture.pcap --ai-score",        "PCAP + AI anomaly scoring"),
            ("shadow313 network --topo --range 192.168.1.0/24",              "Topology map"),
        ],
        "flags": {
            "--capture":   "Network interface for live capture (requires root)",
            "--duration":  "Capture duration in seconds (default: 30)",
            "--analyze":   "Path to .pcap file",
            "--ai-score":  "Enable AI anomaly scoring",
            "--topo":      "Run topology mapper",
            "--range":     "CIDR range for topology sweep",
        },
        "outputs": ["network.json","flows.json","alerts.json"],
    },
    "defense": {
        "title":       "Defensive Hardening Module",
        "description": "CIS benchmark audits, firewall analysis, SSH hardening, AI remediation plans.",
        "commands": [
            ("shadow313 defense --audit",                          "CIS Level 1 benchmark audit"),
            ("shadow313 defense --audit --profile cis-level2",     "CIS Level 2 audit"),
            ("shadow313 defense --remediate --output bash",        "Generate bash remediation script"),
            ("shadow313 defense --remediate --output ansible",     "Generate Ansible playbook"),
        ],
        "flags": {
            "--audit":    "Run CIS benchmark checks",
            "--profile":  "Benchmark profile: cis-level1 | cis-level2",
            "--remediate":"Generate remediation output",
            "--output":   "Remediation format: bash | ansible",
            "--apply":    "Execute remediation script (requires root)",
        },
        "outputs": ["compliance.json","remediation.sh","remediation.yml"],
    },
    "quantum": {
        "title":       "Quantum Cryptography Audit Module",
        "description": "Assess systems for post-quantum readiness. Detects quantum-vulnerable algorithms.",
        "commands": [
            ("shadow313 quantum --scan-host example.com:443",      "TLS endpoint quantum audit"),
            ("shadow313 quantum --audit-certs ./certs/",           "Certificate directory audit"),
            ("shadow313 quantum --scan-code ./src/ --lang python",  "Source code crypto scan"),
        ],
        "flags": {
            "--scan-host":    "Host:port TLS endpoint to scan",
            "--audit-certs":  "Path to certificate file or directory",
            "--scan-code":    "Source code directory to scan",
            "--lang":         "Language filter: python | javascript | java | go",
            "--report":       "Include full NIST PQC reference data",
        },
        "outputs": ["quantum_report.json","migration_plan.md"],
        "nist_refs": ["FIPS 203 (ML-KEM)","FIPS 204 (ML-DSA)","FIPS 205 (SLH-DSA)"],
    },
    "temporal": {
        "title":       "313 Temporal Binding Protocol (NEXUS)",
        "description": "Cryptographic provenance for every computation. Every finding is a verifiable fact.",
        "commands": [
            ("shadow313 temporal --bind-session",          "Bind current session with 313 receipt"),
            ("shadow313 temporal --verify 313-v4-00000001","Verify a receipt"),
            ("shadow313 temporal --list-receipts",         "List all receipts"),
        ],
        "flags": {
            "--bind":          "Bind arbitrary content",
            "--bind-session":  "Bind current session findings",
            "--verify":        "Verify a receipt by ID",
            "--list-receipts": "List all 313-BIND receipts",
        },
        "outputs": ["~/.shadow313/receipts/"],
    },
}

GLOSSARY: dict[str,str] = {
    "CVE":         "Common Vulnerabilities and Exposures — unique ID for publicly known security vulnerabilities",
    "CVSS":        "Common Vulnerability Scoring System — 0-10 severity scoring standard (CVSS v3.1)",
    "EPSS":        "Exploit Prediction Scoring System — ML-based exploitation probability score (FIRST.org)",
    "KEV":         "Known Exploited Vulnerabilities — CISA's catalog of actively exploited CVEs",
    "OSINT":       "Open Source Intelligence — gathering info from publicly available sources",
    "PQC":         "Post-Quantum Cryptography — algorithms designed to resist quantum computer attacks",
    "SARIF":       "Static Analysis Results Interchange Format — OASIS standard for security tool output",
    "IOC":         "Indicator of Compromise — observable artifacts indicating a breach",
    "CIS":         "Center for Internet Security — non-profit producing security benchmarks",
    "FIPS":        "Federal Information Processing Standard — US government cryptography standards",
    "CRQC":        "Cryptographically Relevant Quantum Computer — theoretical machine that breaks RSA/ECC",
    "CRYSTALS-Kyber":"NIST FIPS 203 ML-KEM — post-quantum key encapsulation mechanism",
    "CRYSTALS-Dilithium":"NIST FIPS 204 ML-DSA — post-quantum digital signature algorithm",
    "SPHINCS+":    "NIST FIPS 205 SLH-DSA — hash-based post-quantum signature scheme",
    "313-BIND":    "Shadow313 NEXUS temporal binding receipt — cryptographic proof of computation",
    "SLH-DSA":     "Stateless Hash-based Digital Signature Algorithm — FIPS 205 standard",
    "HNDL":        "Harvest Now Decrypt Later — threat strategy targeting future quantum decryption",
    "JA3":         "TLS fingerprinting method hashing Client Hello parameters",
    "RAG":         "Retrieval-Augmented Generation — AI architecture grounding responses in factual context",
    "STIX":        "Structured Threat Information eXpression — cyber threat intelligence format",
    "TAXII":       "Trusted Automated eXchange of Intelligence Information — STIX transport protocol",
    "HMAC":        "Hash-based Message Authentication Code — cryptographic MAC using a secret key",
    "PBKDF2":      "Password-Based Key Derivation Function 2 — key stretching algorithm",
    "AES-GCM":     "Advanced Encryption Standard in Galois/Counter Mode — authenticated encryption",
    "BPF":         "Berkeley Packet Filter — low-level network packet filtering language",
    "PCAP":        "Packet Capture — file format for storing network traffic",
    "SUID":        "Set User ID — Unix file permission bit that runs a binary as its owner",
    "ASLR":        "Address Space Layout Randomization — memory protection against exploits",
    "MAC":         "Mandatory Access Control — kernel-enforced access policies (AppArmor, SELinux)",
    "Shor":        "Quantum algorithm that factors integers — breaks RSA/ECC",
    "Grover":      "Quantum algorithm that quadratically speeds up searching — halves symmetric key strength",
    "KEM":         "Key Encapsulation Mechanism — PQC equivalent of key exchange protocols",
    "TLS":         "Transport Layer Security — cryptographic protocol for secure communications",
    "Zero-Day":    "Software vulnerability unknown to the vendor with no available patch",
}

TUTORIALS: dict[str,list[dict]] = {
    "recon": [
        {"step":1,"title":"Target Definition","content":"Start with a domain:\nshadow313 recon --target example.com --mode passive\nPassive mode queries DNS and CT logs without sending traffic to the target."},
        {"step":2,"title":"DNS Enumeration","content":"Shadow313 resolves A, AAAA, MX, NS, TXT, CNAME, and SOA records.\nResults stored in sessions/<uuid>/recon.json under the 'dns' key."},
        {"step":3,"title":"Subdomain Discovery","content":"Combines certificate transparency logs (crt.sh) with wordlist bruteforce.\nAdd --stealth to rate-limit requests."},
        {"step":4,"title":"Port Scanning","content":"Full mode adds async port scanning:\nshadow313 recon --target example.com --mode full\nScan specific ports: shadow313 recon --target example.com --ports 80,443,8080"},
        {"step":5,"title":"AI Target Profile","content":"After data collection, the AI engine synthesises a structured target profile.\nPipe into vuln: shadow313 vuln --from-session <uuid>"},
    ],
    "quantum": [
        {"step":1,"title":"Understanding Quantum Risk","content":"Shor's algorithm (on a CRQC) breaks RSA and ECC. Grover's halves symmetric key strength.\nState actors may 'harvest now, decrypt later'."},
        {"step":2,"title":"Scan Your TLS Endpoints","content":"shadow313 quantum --scan-host your-domain.com:443\nChecks TLS version, cipher suite, and certificate algorithm."},
        {"step":3,"title":"Audit Source Code","content":"shadow313 quantum --scan-code ./src/ --lang python\nFinds RSA, ECDSA, DH, MD5, SHA-1 usage in your codebase."},
        {"step":4,"title":"NIST PQC Migration Path","content":"RSA/ECDH → CRYSTALS-Kyber (FIPS 203)\nRSA/ECDSA → CRYSTALS-Dilithium (FIPS 204)\nHash-based sigs → SPHINCS+ (FIPS 205)"},
    ],
    "nexus": [
        {"step":1,"title":"313 Temporal Binding","content":"Every Shadow313 computation produces a 313-BIND receipt.\nshadow313 temporal --bind-session\nThis creates a cryptographic proof of your scan results."},
        {"step":2,"title":"Verify a Receipt","content":"shadow313 temporal --verify 313-v4-00000001\nVerifies the SLH-DSA signature and IPFS anchor."},
        {"step":3,"title":"Insider Attack Immunity","content":"shadow313 nexus --insider-attack-demo\nDemonstrates why SHA-3 chained logs can be bypassed in <1ms\nand how 313-BIND prevents it."},
    ],
}


class DocsModule:
    def __init__(self, kernel) -> None:
        self.kernel  = kernel
        self.out     = kernel.out
        self.ai      = kernel.ai
        self.session = kernel.session

    def register(self, kernel) -> None:
        kernel.register("docs",  self.show_docs)
        kernel.register("ask",   self.ask)
        kernel.register("learn", self.learn)

    def show_docs(self, topic: str = "", glossary: bool = False,
                  man: bool = False, output_dir: str = ".") -> dict:
        self.out.section("SHADOW313 NEXUS DOCUMENTATION")
        if glossary:
            self._print_glossary()
            return {"glossary": GLOSSARY}
        if topic:
            return self._show_module_docs(topic)
        rows = [[name,info["title"],info["description"][:60]] for name,info in MODULE_DOCS.items()]
        self.out.table(["Module","Title","Description"], rows, "Available Modules")
        self.out.info("\nFor detailed docs: shadow313 docs --topic <module>")
        self.out.info("For AI help:       shadow313 ask 'your question'")
        self.out.info("For tutorial:      shadow313 learn --module recon")
        if man:
            self._generate_man_pages(output_dir)
        return {"modules": list(MODULE_DOCS.keys())}

    def _show_module_docs(self, topic: str) -> dict:
        doc = MODULE_DOCS.get(topic.lower())
        if not doc:
            self.out.error(f"Module '{topic}' not found. Available: {', '.join(MODULE_DOCS)}")
            return {}
        self.out.section(doc["title"])
        self.out.info(doc["description"])
        if doc.get("commands"):
            rows = [[cmd,desc] for cmd,desc in doc["commands"]]
            self.out.table(["Command","Description"], rows, "Commands")
        if doc.get("flags"):
            rows = [[flag,desc] for flag,desc in doc.get("flags",{}).items()]
            self.out.table(["Flag","Description"], rows, "Flags")
        if doc.get("outputs"):
            self.out.info(f"Output files: {', '.join(doc['outputs'])}")
        if doc.get("safety_note"):
            self.out.warn(f"⚠ Safety: {doc['safety_note']}")
        if doc.get("nist_refs"):
            self.out.info(f"NIST Standards: {', '.join(doc['nist_refs'])}")
        return doc

    def ask(self, question: str = "", stream: bool = True) -> dict:
        if not question:
            self.out.info("Usage: shadow313 ask 'your security question'")
            return {}
        self.out.section(f"ASK  ▸  {question[:80]}")
        self.session.audit("docs","ask",question[:100])
        system = (
            "You are Shadow313 NEXUS's embedded AI security assistant. "
            "Answer security engineering questions accurately and concisely. "
            "Reference Shadow313 CLI commands where relevant. "
            "Use Markdown formatting. Cite NIST/CVE/OWASP standards when applicable."
        )
        if stream:
            answer_parts = []
            print()
            for token in self.ai.stream(question, system_prompt=system):
                print(token, end="", flush=True)
                answer_parts.append(token)
            print("\n")
            answer = "".join(answer_parts)
        else:
            answer = self.ai.chat(question, system_prompt=system)
            self.out.ai_response(answer, "Answer")
        return {"question": question, "answer": answer}

    def learn(self, module: str = "", interactive: bool = False, step: int = 0) -> dict:
        if not module:
            self.out.info("Available tutorials: " + ", ".join(TUTORIALS.keys()))
            self.out.info("Start with: shadow313 learn --module recon --interactive")
            return {}
        steps = TUTORIALS.get(module.lower())
        if not steps:
            self.out.error(f"No tutorial for '{module}'. Available: {', '.join(TUTORIALS)}")
            return {}
        self.out.section(f"TUTORIAL  ▸  {module.upper()}")
        if step:
            s = next((s for s in steps if s["step"] == step), None)
            if s:
                self._print_step(s, len(steps))
            return {}
        if interactive:
            self._run_interactive(steps, module)
        else:
            for s in steps:
                self._print_step(s, len(steps))
            self.out.info(f"\nRun interactively: shadow313 learn --module {module} --interactive")
        return {"module": module, "steps": len(steps)}

    def _print_step(self, step: dict, total: int) -> None:
        self.out.section(f"Step {step['step']}/{total}: {step['title']}")
        print(step["content"])
        print()

    def _run_interactive(self, steps: list[dict], module: str) -> None:
        total = len(steps)
        for step in steps:
            self._print_step(step, total)
            if step["step"] < total:
                try:
                    inp = input("  Press Enter to continue (q to quit) > ").strip()
                    if inp.lower() == "q":
                        self.out.info(f"Tutorial paused. Resume with: shadow313 learn --module {module} --step {step['step']+1}")
                        break
                except (KeyboardInterrupt, EOFError):
                    break
        else:
            self.out.success(f"Tutorial complete! Next: shadow313 {module} --help")

    def _print_glossary(self) -> None:
        self.out.section("SECURITY GLOSSARY")
        rows = [[term,definition[:80]] for term,definition in sorted(GLOSSARY.items())]
        self.out.table(["Term","Definition"], rows, "Glossary")

    def _generate_man_pages(self, output_dir: str) -> None:
        base = Path(output_dir) / "man"
        base.mkdir(parents=True, exist_ok=True)
        for module, doc in MODULE_DOCS.items():
            man  = self._build_man_page(module, doc)
            path = base / f"shadow313-{module}.1"
            path.write_text(man)
        self.out.success(f"Man pages generated → {base}/")

    @staticmethod
    def _build_man_page(module: str, doc: dict) -> str:
        date = datetime.now(timezone.utc).strftime("%B %Y")
        lines = [
            f'.TH "SHADOW313-{module.upper()}" "1" "{date}" "shadow313 4.0.0" "Shadow313 NEXUS Manual"',
            ".SH NAME",
            f"shadow313-{module} \\- {doc['title']}",
            ".SH SYNOPSIS",
            f".B shadow313 {module}",
            "[OPTIONS]",
            ".SH DESCRIPTION",
            f".P\n{doc['description']}",
            ".SH OPTIONS",
        ]
        for flag, desc in doc.get("flags",{}).items():
            lines.append(f".TP\n.B {flag}\n{desc}")
        lines.append(".SH EXAMPLES")
        for cmd, desc in doc.get("commands",[])[:5]:
            lines.append(f".PP\n{desc}:\n.nf\n{cmd}\n.fi")
        lines.append(".SH SEE ALSO")
        lines.append("shadow313(1), " + ", ".join(f"shadow313-{m}(1)" for m in MODULE_DOCS if m != module))
        return "\n".join(lines)