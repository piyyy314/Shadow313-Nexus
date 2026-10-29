"""shadow313.modules.docs.docs_module — DocsModule orchestrator."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any

from .glossary  import GLOSSARY
from .tutorials import TUTORIALS
from .man_page  import write_man_pages

MODULE_DOCS: dict[str, dict] = {
    "recon": {
        "title": "Reconnaissance Module",
        "description": "Passive and active reconnaissance — DNS, subdomains, port scanning, OSINT, AI profiling.",
        "commands": [
            ("shadow313 recon --target example.com", "Full recon against a domain"),
            ("shadow313 recon --target 192.168.1.10 --mode active", "Active scan"),
            ("shadow313 recon --target example.com --mode passive", "Passive only"),
            ("shadow313 recon --target example.com --stealth", "Stealth mode"),
        ],
        "flags": {
            "--target":  "Target domain, IP, CIDR, or URL",
            "--mode":    "Scan mode: full | active | passive (default: full)",
            "--ports":   "Port range: 1-1024 or 80,443,8080",
            "--stealth": "Rate-limit requests",
            "--output":  "Output format: rich | json | markdown",
        },
        "outputs": ["recon.json", "target.json"],
    },
    "vuln": {
        "title": "Vulnerability Analysis Module",
        "description": "CVE correlation, CVSS scoring, exploit availability, dependency auditing, AI triage.",
        "commands": [
            ("shadow313 vuln --from-session <uuid>", "Analyse recon output from a session"),
            ("shadow313 vuln --audit-deps requirements.txt", "Audit Python dependencies"),
            ("shadow313 update --db cve", "Update local CVE database"),
        ],
        "flags": {
            "--from-session":  "Session UUID to load recon data from",
            "--audit-deps":    "Path to dependency file",
            "--quick":         "Skip exploit availability check",
            "--internet-facing": "Mark target as internet-facing",
        },
        "outputs": ["findings.json", "risk_matrix.json"],
    },
    "network": {
        "title": "Network Intelligence Module",
        "description": "Pure-Python PCAP parsing, flow tracking, anomaly detection, topology mapping.",
        "commands": [
            ("shadow313 network --analyze ./capture.pcap --ai-score", "Analyse PCAP file"),
            ("sudo shadow313 network --capture eth0 --duration 60", "Live capture"),
            ("shadow313 network --topo --range 192.168.1.0/24", "Topology map"),
        ],
        "flags": {
            "--analyze":   "Path to .pcap file",
            "--capture":   "Network interface for live capture (requires root)",
            "--duration":  "Capture duration in seconds",
            "--ai-score":  "Enable AI anomaly scoring",
            "--topo":      "Run topology mapper",
        },
        "outputs": ["network.json", "flows.json", "alerts.json"],
    },
    "defense": {
        "title": "Defensive Hardening Module",
        "description": "CIS benchmark audits, firewall analysis, SSH hardening, AI remediation plans.",
        "commands": [
            ("shadow313 defense --audit", "CIS Level 1 benchmark audit"),
            ("shadow313 defense --audit --profile cis-level2", "CIS Level 2 audit"),
            ("shadow313 defense --generate-remediation bash", "Generate bash remediation script"),
        ],
        "flags": {
            "--audit":                "Run CIS benchmark checks",
            "--profile":              "Benchmark profile: cis-level1 | cis-level2",
            "--firewall-check":       "Analyse firewall rules",
            "--generate-remediation": "Generate remediation output: bash | ansible",
        },
        "outputs": ["compliance.json", "remediation.sh", "remediation.yml"],
    },
    "quantum": {
        "title": "Quantum Cryptography Audit Module",
        "description": "Assess systems for post-quantum readiness. Detects quantum-vulnerable algorithms.",
        "commands": [
            ("shadow313 quantum --scan-host example.com:443", "TLS endpoint quantum audit"),
            ("shadow313 quantum --scan-cert ./certs/", "Certificate directory audit"),
            ("shadow313 quantum --scan-code ./src/ --lang python", "Source code crypto scan"),
        ],
        "flags": {
            "--scan-host":  "Host:port TLS endpoint to scan",
            "--scan-cert":  "Path to certificate file or directory",
            "--scan-code":  "Source code directory to scan",
            "--lang":       "Language filter: python | javascript | java | go",
            "--report":     "Include full NIST PQC reference data",
        },
        "outputs": ["quantum_report.json", "migration_plan.md"],
    },
}


def _now() -> str:
    """Return the current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


class DocsModule:
    """shadow313.docs — Documentation, AI ask, tutorials, man pages."""

    def __init__(self, kernel) -> None:
        """Bind documentation commands to kernel output, AI, and session services."""
        self.kernel  = kernel
        self.out     = kernel.out
        self.ai      = kernel.ai
        self.session = kernel.session

    def register(self, kernel) -> None:
        """Register the docs, ask, and learn commands with the supplied kernel."""
        kernel.register("docs",  self.show_docs)
        kernel.register("ask",   self.ask)
        kernel.register("learn", self.learn)

    def show_docs(self, topic: str = "", glossary: bool = False,
                  man: bool = False, output_dir: str = ".") -> dict:
        """Display documentation and return glossary, topic data, or available module names.

        Glossary and topic requests take precedence over man page generation.
        Otherwise man=True writes pages under output_dir/man; I/O errors propagate.
        """
        self.out.section("SHADOW313 DOCUMENTATION")
        if glossary:
            self._print_glossary()
            return {"glossary": GLOSSARY}
        if topic:
            return self._show_module_docs(topic)
        rows = [[name, info["title"], info["description"][:60]]
                for name, info in MODULE_DOCS.items()]
        self.out.table(["Module", "Title", "Description"], rows, "Available Modules")
        self.out.info("\nFor detailed docs: shadow313 docs --topic <module>")
        self.out.info("For AI help:       shadow313 ask 'your question'")
        self.out.info("For tutorial:      shadow313 learn --module recon")
        if man:
            written = write_man_pages(MODULE_DOCS, output_dir)
            self.out.success(f"Man pages generated: {len(written)} files")
        return {"modules": list(MODULE_DOCS.keys())}

    def ask(self, question: str = "", stream: bool = True) -> dict:
        """Display an AI answer and return the question and assembled answer.

        stream prints chunks as they arrive. An empty question returns {}.
        """
        if not question:
            self.out.info("Usage: shadow313 ask 'your security question'")
            return {}
        self.out.section(f"ASK  ▸  {question[:80]}")
        self.session.audit("docs", "ask", question[:100])
        system = (
            "You are Shadow313's embedded AI security assistant. "
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
        """Display a module tutorial and return its module name and step count.

        A nonzero step selects that numbered step and returns {}, taking
        precedence over interactive mode. Missing or unknown modules return {}.
        """
        if not module:
            self.out.info("Available tutorials: " + ", ".join(TUTORIALS.keys()))
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
        return {"module": module, "steps": len(steps)}

    def ai_context(self) -> dict:
        """Return the available documentation module names for AI requests."""
        return {"module": "docs", "available_modules": list(MODULE_DOCS.keys())}

    def _show_module_docs(self, topic: str) -> dict:
        """Display a topic and return its documentation, or {} for an unknown topic."""
        doc = MODULE_DOCS.get(topic.lower())
        if not doc:
            self.out.error(f"Module '{topic}' not found. Available: {', '.join(MODULE_DOCS)}")
            return {}
        self.out.section(doc["title"])
        self.out.info(doc["description"])
        if doc.get("commands"):
            rows = [[cmd, desc] for cmd, desc in doc["commands"]]
            self.out.table(["Command", "Description"], rows, "Commands")
        if doc.get("flags"):
            rows = [[flag, desc] for flag, desc in doc.get("flags", {}).items()]
            self.out.table(["Flag", "Description"], rows, "Flags")
        if doc.get("outputs"):
            self.out.info(f"Output files: {', '.join(doc['outputs'])}")
        return doc

    def _print_glossary(self) -> None:
        """Display glossary terms alphabetically with abbreviated definitions."""
        self.out.section("SECURITY GLOSSARY")
        rows = [[term, definition[:80]] for term, definition in sorted(GLOSSARY.items())]
        self.out.table(["Term", "Definition"], rows, "Glossary")

    def _print_step(self, step: dict, total: int) -> None:
        """Display one tutorial step and its position in the tutorial."""
        self.out.section(f"Step {step['step']}/{total}: {step['title']}")
        print(step["content"])
        print()

    def _run_interactive(self, steps: list[dict], module: str) -> None:
        """Display steps with prompts between them; q, EOF, or interruption ends the tutorial."""
        total = len(steps)
        for step in steps:
            self._print_step(step, total)
            if step["step"] < total:
                try:
                    inp = input("  Press Enter to continue (q to quit) > ").strip()
                    if inp.lower() == "q":
                        break
                except (KeyboardInterrupt, EOFError):
                    break