> **Distribution rename:** the intended PyPI install name is `shadow313-nexus`.
> The CLI command remains `shadow313`, and Python imports remain `shadow313`.
> This repository change does not publish or reserve a PyPI name. Do not install
> an unrelated package named `shadow313` expecting this project's code.
> See [release instructions](docs/distribution-rename.md).

> **Runtime/release status:** The public website is static documentation and browser
> demonstrations, not a running Python scanner, quantum computer, or automatic
> connection to your local Ollama. Older feature tables, test counters, receipts,
> and certification-like badges below are historical claims, not current proof.
> Read [the repair handoff](docs/audit-repair-handoff.md) before remote exposure or
> publishing a release. Local CLI integrations can make network requests.

# Shadow313 NEXUS v4.0.0

> **Local-First AI-Powered Security Intelligence CLI — NEXUS Edition**

```
  ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗██████╗
  ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║╚════██╗
  ███████╗███████║███████║██║  ██║██║   ██║██║  ▄███╔╝
  ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║ ▄██╔╝
  ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝██║ ██████╗
  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═╝╚═════╝
  v4.0.0-NEXUS  |  Post-Quantum Security Intelligence
```

<div align="center">

[![Build Status](https://img.shields.io/github/actions/workflow/status/piyyy314/Shadow313-Nexus/shadow313-ci.yml?branch=master&style=for-the-badge&logo=github-actions&label=CI%20Build)](https://github.com/piyyy314/Shadow313-Nexus/actions)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg?style=for-the-badge&logo=python)](https://www.python.org/)
**PyPI publication pending — install from the reviewed source checkout.**
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)

</div>

Shadow313 NEXUS is a Python security-intelligence toolkit with a CLI, API,
optional local Ollama integration, and static documentation site. Some modules
require optional dependencies or external services; network activity is not
guaranteed to remain local. Use only on systems you own or are authorized to
assess. The CI badge above links to the current workflow result; this README
does not publish a fixed test count or claim a passing result.

## Repository map

| Path | Contents |
|---|---|
| `shadow313/` | Main Python package, API, CLI, modules, and versioned components |
| `shadow313_sdk/`, `shadow313_platform/`, `nexus_toolkit/` | SDK, platform, and toolkit packages |
| `tests/` | Unit, integration, and simulation tests |
| `docs/`, `assets/`, `index.html` | Static website and documentation |
| `api/` | Static-site API adapter and OpenAPI contract; backend-dependent website routes return `200` with an explicit unavailable status |
| `docker/`, `docker-compose.yml`, `Dockerfile` | Optional local Ollama, Open WebUI, API, and proxy stack |
| `scripts/` | Repository checks, site generation, and maintenance utilities |

## Development and tests

Use Python 3.11 or newer. From a fresh virtual environment:

```bash
python -m pip install -e ".[dev]"
python -m pytest tests/ -q --tb=short --ignore=tests/integration --timeout=120
```

For the API and dashboard extras, install `.[dashboard]`; other optional
features may require their corresponding extras. Check the live CI workflow
for the authoritative status of a specific commit.

## Local AI and API

The default AI backend is local Ollama at `http://localhost:11434`. Select it
with `SHADOW313_AI_BACKEND=ollama`, and configure `SHADOW313_AI_MODEL` and
`SHADOW313_AI_ENDPOINT` as needed. The optional OpenAI-compatible gateway
requires `AI_GATEWAY_API_KEY`; `OPENAI_API_KEY` is used only for the OpenAI
backend and is not reused for the gateway.

The Python API listens on port `8313` when run in Docker Compose. Compose keeps
the API internal to its Docker network; the static site adapter does not host
the Python backend and returns `200` with an explicit unavailable status for
backend-dependent routes. The Python API also reports unavailable integrations
in a `200` response after authentication; authentication and routing errors keep
their appropriate error statuses.

---

## 🆕 What's New in v4.0.0 NEXUS

| Feature | Description |
|---------|-------------|
| **313 Temporal Binding** | Every computation produces a cryptographic receipt signed with SLH-DSA (FIPS 205), anchored to IPFS |
| **NEXUS Platform** | Post-Quantum Security Intelligence — every finding is a cryptographic fact |
| **Insider Attack Immunity** | Documented SHA-3 chain bypass attack + SLH-DSA countermeasure |
| **STIX 2.1 Handler** | Import/export threat intelligence bundles |
| **Mobile API** | REST API for iOS/Android companion app |
| **LoRA Fine-Tune** | Generate training configs for Shadow313-7B security LLM |
| **Browser Recon** | Playwright-powered SPA fingerprinting + CSP analysis |
| **Container Scanning** | Dockerfile linting + OCI image CVE analysis (Trivy/Grype) |
| **AD Auditor** | Kerberoasting, AS-REP roasting, unconstrained delegation detection |
| **SIEM Integration** | Forward findings to Splunk HEC, Elasticsearch, Wazuh |
| **Collaborative Sessions** | Multi-user session sharing with E2E encryption |
| **Malware Sandbox** | YARA-like pattern matching + Docker behavioral analysis |

---

## ✨ Full Feature Matrix

### V1 Core Modules (9)
| Module | Capability |
|--------|-----------|
| **Recon** | DNS enum, subdomain discovery, async port scan, WHOIS, OSINT, AI profiling |
| **Vuln** | CVE correlation, CVSS scoring, exploit availability, dependency audit, AI triage |
| **Exploit** | Advisory-mode CVE research, payload templates, CTF solver (lab mode required) |
| **Network** | Live capture, PCAP analysis, anomaly detection, topology mapping |
| **Defense** | CIS benchmark audit (18 checks), firewall analysis, AI remediation (bash/Ansible) |
| **Quantum** | Post-quantum crypto audit, TLS/cert/code scanning, NIST PQC migration roadmap |
| **Plugins** | Sandboxed community/custom extensions, 10 lifecycle hooks |
| **CI/CD** | SARIF output, 13-pattern secret scanning, GitHub Actions / GitLab CI integration |
| **Docs** | AI `ask` command, interactive tutorials, man page generation |

### V2 Advanced Modules (17)
| Module | Capability |
|--------|-----------|
| **RAG** | ChromaDB/TF-IDF vector store, 5 knowledge namespaces, LoRA fine-tune config |
| **Agent** | Agentic auto-chain loop, 4 built-in plans, approval gates, plan persistence |
| **EPSS** | FIRST.org EPSS v3 scoring, batch API, SQLite cache with 24h TTL |
| **KEV** | CISA Known Exploited Vulnerabilities catalog, 12h TTL, auto-CRITICAL promotion |
| **ATT&CK** | 70+ keyword→technique mappings, Navigator v4 JSON export |
| **ML Anomaly** | IsolationForest → ONNX → z-score fallback chain, 14-feature vector |
| **JA3/JA3S** | Pure-Python TLS fingerprinting, 9 known-malicious signatures |
| **DNS Covert** | 6 heuristic rules, DoH detection, DNS tunnel tool signatures |
| **Campaign** | Asyncio-parallel multi-target scanning, configurable concurrency |
| **Graph** | NetworkX intelligence graph, 9 node types, risk ranking, GraphML/GEXF export |
| **Dashboard** | FastAPI + HTMX, dark terminal aesthetic, SSE live feed, RAG AI chat |
| **Reports** | HTML/PDF security reports, AI executive summaries, 313-BIND receipts |
| **Plugin Signing** | HMAC-SHA256 + cosign/sigstore, plugin trust registry |
| **Threat Intel** | FeodoTracker, URLhaus, MalwareBazaar, Shodan InternetDB, OTX feeds |
| **Docker Sandbox** | CVE reproduction, 6 security constraints, 8 pre-mapped CVEs |
| **Cloud Hardening** | AWS (7 checks), Kubernetes (7 checks), Terraform (11 rules) |
| **Crypto Agility** | 7 PQC migration snippets, 11 NIST algorithms, hybrid TLS testing |

### V3 Advanced Modules (6)
| Module | Capability |
|--------|-----------|
| **Browser Recon** | Playwright SPA fingerprinting, CSP analysis, API endpoint discovery |
| **Container Scan** | Dockerfile linting (12 rules), Trivy/Grype CVE scanning, base image risk |
| **AD Auditor** | Kerberoasting, AS-REP roasting, unconstrained delegation, password policy |
| **SIEM** | Splunk HEC, Elasticsearch bulk, Wazuh REST API integration |
| **Collab** | Multi-user sessions, finding sharing, collaborative notes, timeline |
| **Malware Sandbox** | YARA-like matching (10 rules), static analysis, Docker behavioral execution |

### V4 NEXUS Modules (5)
| Module | Capability |
|--------|-----------|
| **313 Temporal Binding** | Nanosecond-precise cryptographic receipts, SLH-DSA signatures, IPFS anchoring |
| **NEXUS** | Platform orchestration, insider attack demo, security posture reports |
| **STIX 2.1** | Bundle import/export, IOC extraction, ATT&CK STIX integration |
| **Mobile API** | FastAPI REST server for iOS/Android companion app |
| **Fine-Tune UI** | LoRA/QLoRA config generator, Unsloth training script, GGUF export |

---

## 🚀 Quick Start

### Install from reviewed source (PyPI publication pending)

First clone this repository, review/check out the intended commit, and change
into its directory. Use a fresh virtual environment; the command below installs
that checkout, not a package name from PyPI. No registry ownership is asserted.

```bash
pip install .
```

### Optional full extra from reviewed source
```bash
pip install ".[full]"
```

### Install (from source)
```bash
git clone https://github.com/piyyy314/Shadow313-Nexus
cd Shadow313-Nexus
pip install -e ".[full]"
```

### Docker (NEXUS)
```bash
docker pull piyyy314/shadow313-nexus:4.0.0-nexus
docker run --rm -it piyyy314/shadow313-nexus:4.0.0-nexus recon --target example.com --mode passive
```

### Docker Compose (full stack)
```bash
cp .env.example .env
# Replace the example secrets before starting the API services.
docker compose up -d
# Open WebUI through the nginx development listener: http://localhost:8080
# Nginx HTTPS listener: https://localhost
# Ollama and the Python API are internal to the Compose network by default.
```

### AI Setup (Ollama — local, recommended)
```bash
# Install Ollama: https://ollama.com
ollama pull mistral:7b
# Set SHADOW313_AI_ENDPOINT=http://localhost:11434 for a native CLI process.
```

---

## 📖 Usage

### V1 Core Commands
```bash
# Reconnaissance
shadow313 recon --target example.com --mode full
shadow313 recon --target 192.168.1.0/24 --mode active --stealth

# Vulnerability Analysis
shadow313 vuln --from-session <uuid> --epss --kev
shadow313 vuln --audit-deps requirements.txt
shadow313 update --db cve

# Exploitation Assistance (LAB MODE ONLY)
shadow313 exploit --cve CVE-2024-1234 --lab-mode
shadow313 exploit --assist ctf --challenge "Buffer overflow 64-bit ELF" --lab-mode

# Network Intelligence
sudo shadow313 network --capture eth0 --duration 60
shadow313 network --analyze ./capture.pcap --ai-score --ml-anomaly --ja3 --dns-covert

# Defensive Hardening
shadow313 defense --audit --profile cis-level2
shadow313 defense --remediate --output ansible

# Quantum Crypto Audit
shadow313 quantum --scan-host example.com:443
shadow313 quantum --scan-code ./src/ --lang python

# AI-Powered Q&A
shadow313 ask "what NIST algorithms replace RSA in post-quantum?"
shadow313 learn --module quantum --interactive
```

### V2 Advanced Commands
```bash
# Agentic Auto-Chain
shadow313 agent --plan full_pentest --target example.com
shadow313 agent --plan crypto_audit --target example.com --approval auto

# Multi-Target Campaigns
shadow313 campaign --targets targets.txt --modules recon,vuln,epss --concurrency 5

# Intelligence Graph
shadow313 graph --ingest-session <uuid>
shadow313 graph --risk-ranking
shadow313 graph --export graphml graph.graphml

# Web Dashboard
shadow313 serve
shadow313 serve --port 8080 --host 0.0.0.0

# Security Reports
shadow313 report --from-session <uuid> --format pdf

# Threat Intelligence
shadow313 threat-intel --sync
shadow313 threat-intel --lookup 185.220.100.252
shadow313 threat-intel --enrich-session <uuid>

# Cloud Hardening
shadow313 cloud --scan-aws
shadow313 cloud --scan-k8s
shadow313 cloud --scan-terraform ./infrastructure/

# PQC Migration
shadow313 crypto-agility --scan ./src/
shadow313 crypto-agility --snippet rsa-python
shadow313 crypto-agility --test-tls example.com:443
shadow313 crypto-agility --migration-plan

# RAG Knowledge Base
shadow313 rag --ingest-nvd nvd_feed.json
shadow313 rag --ingest-mitre
shadow313 rag --query "what techniques does APT29 use?"
```

### V4 NEXUS Commands
```bash
# 313 Temporal Binding
shadow313 temporal --bind-session
shadow313 temporal --verify 313-v4-00000001
shadow313 temporal --list-receipts

# NEXUS Platform
shadow313 nexus --status
shadow313 nexus --bind-all
shadow313 nexus --insider-attack-demo
shadow313 nexus --posture-report

# STIX 2.1
shadow313 stix --import threat_bundle.json
shadow313 stix --export --export-path findings.stix.json

# Container & Browser
shadow313 container-scan --image nginx:latest
shadow313 container-scan --dockerfile ./Dockerfile
shadow313 browser-recon --target example.com --use-playwright

# Active Directory
shadow313 ad-audit --server dc01.corp.local --domain corp.local --username admin

# SIEM Integration
shadow313 siem --forward-session <uuid>
shadow313 siem --test

# Malware Analysis
shadow313 malware --file suspicious.exe --yara-only
shadow313 malware --file suspicious.elf --execute --lab-mode

# Fine-Tuning
shadow313 finetune --generate-config
shadow313 finetune --generate-dataset --dataset-size 500
```

---

## 🏗️ Architecture

```
shadow313/
├── cli/main.py                    # argparse entry point (50+ commands)
├── core/
│   ├── kernel.py                  # Singleton kernel, command bus
│   ├── config.py                  # YAML + env-var config loader
│   ├── session.py                 # UUID session management
│   ├── ai_engine.py               # Ollama/OpenAI/disabled backends
│   ├── output.py                  # rich/JSON/MD/plain formatter
│   └── crypto_store.py            # AES-256-GCM encrypted sessions
├── modules/                       # V1 core modules (9)
│   ├── recon/, vuln/, exploit/
│   ├── network/, defense/, quantum/
│   ├── plugins/, cicd/, docs/
├── v2/                            # V2 advanced modules (17)
│   ├── rag/, agent/, vuln_upgrades/
│   ├── network_upgrades/, campaign/
│   ├── graph/, dashboard/, reports/
│   ├── plugin_signing/, threat_intel/
│   ├── docker_sandbox/, cloud_hardening/
│   └── crypto_agility/
├── v3/                            # V3 modules (6)
│   ├── browser_recon/, container_scan/
│   ├── ad_auditor/, siem/
│   ├── collab/, malware_sandbox/
└── v4/                            # V4 NEXUS modules (5)
    ├── temporal_binding/          # 313 Temporal Binding Protocol
    ├── nexus/                     # NEXUS orchestration
    ├── stix/                      # STIX 2.1 handler
    ├── mobile_api/                # REST API for mobile
    └── finetune_ui/               # LoRA fine-tune config
```

---

## 🔐 313 Temporal Binding Protocol

Shadow313 NEXUS is the **only security platform where every finding is a cryptographic fact**.

Every scan produces a **313-BIND receipt**:
1. Waits for a nanosecond timestamp ending in `...313`
2. Computes SHA3-512 of content + timestamp
3. Signs with **SLH-DSA (SPHINCS+, FIPS 205)** — post-quantum secure
4. Anchors to **IPFS** for permanent public verifiability

```
Receipt: 313-v4-00000042
  Timestamp:  1783515056138000313 (ends in ...313)
  SHA3-512:   a7f3e9b2...
  Algorithm:  SLH-DSA-SHA2-128f (FIPS 205)
  IPFS CID:   QmX9f...a3b7
```

**Why this matters:**
- A finding from 6 months ago can be proven to have existed at that exact moment
- No insider can alter historical findings without detection
- Customers can prove to auditors that their security posture was assessed on a specific date
- In legal proceedings, Shadow313 findings are cryptographically admissible

---

## ⚙️ Configuration

Edit `~/.shadow313/config.yaml`:

```yaml
shadow313:
  ai:
    backend:  ollama          # ollama | openai | disabled
    model:    mistral:7b
    endpoint: http://localhost:11434
  storage:
    encrypt: false            # Enable AES-256-GCM session encryption
  temporal_binding:
    enabled: true             # 313 Temporal Binding Protocol
    sign_receipts: true
  dashboard:
    port: 7313
    host: 127.0.0.1
  threat_intel:
    otx_api_key: ""           # AlienVault OTX (free tier)
    enabled_feeds:
      - feodo
      - urlhaus
      - malwarebazaar
      - shodan
```

---

## ⚠️ Ethics & Legal

- The **Exploit module** is advisory-only — it does NOT execute exploits autonomously
- All exploit assistance requires `--lab-mode` flag + a valid `scope.yaml`
- The **Malware Sandbox** requires `--lab-mode` for execution mode
- The **Docker Sandbox** requires `--lab-mode` for CVE reproduction
- Only use against systems you own or have written authorization to test
- All sessions are audit-logged for accountability
- This tool is for security professionals, researchers, and CTF participants

---

## 📜 License

MIT — see [LICENSE](LICENSE)

---

## 🗺️ Roadmap

| Feature | Target |
|---------|--------|
| ✅ 313 Temporal Binding Protocol | v4.0.0 |
| ✅ NEXUS Platform | v4.0.0 |
| ✅ STIX 2.1 Handler | v4.0.0 |
| ✅ Mobile API | v4.0.0 |
| ✅ Browser Recon (Playwright) | v4.0.0 |
| ✅ Container Scanning | v4.0.0 |
| ✅ AD Auditor | v4.0.0 |
| ✅ SIEM Integration | v4.0.0 |
| ✅ Malware Sandbox | v4.0.0 |
| Autonomous Vulnerability Chains | v4.1 |
| Threat Actor Profiling | v4.1 |
| Custom LLM Fine-Tuning UI | v4.2 |
| iOS/Android Companion App | v4.2 |
| Collaborative Sessions (E2E) | v4.1 |
| SIEM Integration (Splunk/Elastic) | v4.0.0 ✅ |

---

*Shadow313 NEXUS v4.0.0 — Ottawa, ON, Canada · 2026*
*"The only security platform where every finding is a cryptographic fact."*



