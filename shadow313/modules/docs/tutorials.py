"""shadow313.modules.docs.tutorials — Interactive step-by-step tutorials."""
from __future__ import annotations

TUTORIALS: dict[str, list[dict]] = {
    "recon": [
        {"step": 1, "title": "Target Definition",
         "content": "Start with a domain: shadow313 recon --target example.com --mode passive\n"
                    "Passive mode queries DNS and CT logs without sending traffic to the target."},
        {"step": 2, "title": "DNS Enumeration",
         "content": "Shadow313 resolves A, AAAA, MX, NS, TXT, CNAME, and SOA records.\n"
                    "Results are stored in sessions/<uuid>/recon.json under the 'dns' key."},
        {"step": 3, "title": "Subdomain Discovery",
         "content": "Combines certificate transparency logs (crt.sh) with wordlist bruteforce.\n"
                    "Add --stealth to rate-limit requests."},
        {"step": 4, "title": "Port Scanning",
         "content": "Full mode adds async port scanning: shadow313 recon --target example.com --mode full\n"
                    "Scan specific ports: shadow313 recon --target example.com --ports 80,443,8080"},
        {"step": 5, "title": "AI Target Profile",
         "content": "After data collection, the AI engine synthesises a structured target profile.\n"
                    "Pipe into vuln: shadow313 vuln --from-session <uuid>"},
    ],
    "network": [
        {"step": 1, "title": "PCAP Analysis (No Root Needed)",
         "content": "Analyse an existing capture file:\n"
                    "shadow313 network --analyze ./capture.pcap --ai-score"},
        {"step": 2, "title": "Flow Extraction",
         "content": "Shadow313 parses packets into 5-tuple flows (src_ip, dst_ip, sport, dport, proto).\n"
                    "Top flows are shown sorted by byte count."},
        {"step": 3, "title": "Anomaly Detection",
         "content": "Heuristic checks: beaconing, port scanning, data exfiltration, suspicious ports."},
        {"step": 4, "title": "Live Capture (Root Required)",
         "content": "sudo shadow313 network --capture eth0 --duration 60\n"
                    "Uses tcpdump internally. Output saved as PCAP then analysed automatically."},
    ],
    "quantum": [
        {"step": 1, "title": "Understanding Quantum Risk",
         "content": "Shor's algorithm (on a CRQC) breaks RSA and ECC. Grover's halves symmetric key strength.\n"
                    "State actors may 'harvest now, decrypt later'."},
        {"step": 2, "title": "Scan Your TLS Endpoints",
         "content": "shadow313 quantum --scan-host your-domain.com:443\n"
                    "Checks TLS version, cipher suite, and certificate algorithm."},
        {"step": 3, "title": "Audit Source Code",
         "content": "shadow313 quantum --scan-code ./src/ --lang python\n"
                    "Finds RSA, ECDSA, DH, MD5, SHA-1 usage in your codebase."},
        {"step": 4, "title": "NIST PQC Migration Path",
         "content": "RSA/ECDH -> CRYSTALS-Kyber (FIPS 203)\n"
                    "RSA/ECDSA -> CRYSTALS-Dilithium (FIPS 204)\n"
                    "Hash-based sigs -> SPHINCS+ (FIPS 205)"},
    ],
}