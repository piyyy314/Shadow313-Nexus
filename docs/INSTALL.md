# Shadow313 NEXUS — Install & Activation Guide
**Version:** v4.0.0 | **Date:** 2026-08-31  
**Quantum-Ready CLI · 313 Temporal Binding · Ghost-Watch Apex Tier**

---

## Quick Start (3 commands)

```bash
git clone https://github.com/shadow313/shadow313.git
cd shadow313
pip install -e . && shadow313
```

---

## 1. Check if Shadow313 is already installed

**Linux / macOS:**
```bash
ls ~/shadow313
# Look for: shadow313/, pyproject.toml, README.md
```

**Windows (PowerShell):**
```powershell
ls $HOME\shadow313
```

If you see project files → already cloned. If "No such file or directory" → proceed to Step 2.

---

## 2. Download Shadow313

```bash
# Linux / macOS
cd ~
git clone https://github.com/shadow313/shadow313.git
cd shadow313

# Windows (PowerShell)
cd $HOME
git clone https://github.com/shadow313/shadow313.git
cd shadow313
```

---

## 3. Create and activate a virtual environment

```bash
# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate

# Windows (PowerShell)
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Your prompt will show `(.venv)` when active.

---

## 4. Install Shadow313

```bash
pip install --upgrade pip
pip install -e .
```

This installs:
- Shadow313 CLI (`shadow313` command)
- All v4 modules (103 Python modules)
- PQC dependencies (pyspx for SLH-DSA, argon2-cffi for Argon2id)
- Optional: `pip install -e ".[quantum]"` for Qiskit/qiskit-aer

---

## 5. Verify kernel activation

```bash
python3 - << 'EOF'
from shadow313.temporal313 import Temporal313Protocol
from shadow313.quantum_middleware import QuantumMiddleware
from shadow313.thought_engine import QuantumThoughtEngine

print("Shadow313 kernel imports OK")
EOF
```

**Expected output:**
```
Shadow313 kernel imports OK
```

**What these map to in v4:**

| v1 Import | v4 Module | Purpose |
|-----------|-----------|---------|
| `temporal313.Temporal313Protocol` | `TemporalBindingEngine` | 313-BIND receipt chain |
| `quantum_middleware.QuantumMiddleware` | `QuantumNEXUSModule` | QKD + HNDL analysis |
| `thought_engine.QuantumThoughtEngine` | `AgentOrchestrator` | Agentic auto-chain |

---

## 6. Run the Shadow313 CLI

```bash
shadow313
```

**Expected output:**
```
============================================================
 SHADOW313 NEXUS v4 — Local-First Security Intelligence CLI
============================================================
Commands:
  recon    - Reconnaissance (DNS, ports, subdomains)
  vuln     - Vulnerability analysis (CVE, EPSS, KEV)
  network  - Network forensics (PCAP, flows, anomalies)
  defense  - CIS benchmark audit + hardening
  quantum  - Post-quantum cryptography audit
  temporal - 313-BIND temporal binding receipts
  plugins  - Plugin management (ML-DSA-65 signed)
  exit     - Quit
============================================================
(shadow313) #>
```

---

## 7. Verify PQC stack (optional)

```bash
python3 - << 'EOF'
from shadow313.v4.temporal_binding.temporal_binding import TemporalBindingEngine, _sign_slh_dsa

# Test SLH-DSA signing
sig, algo = _sign_slh_dsa(b"shadow313 activation test")
print(f"Signing algorithm: {algo}")
print(f"Signature length: {len(sig)//2} bytes")

# Test 313-BIND receipt
engine = TemporalBindingEngine()
receipt = engine.bind({"activation": "test", "version": "4.0.0"})
print(f"Receipt ID: {receipt.receipt_id}")
print(f"Timestamp ends in 313: {receipt.timestamp % 1000 == 313}")
print(f"PQC stack: ACTIVE")
EOF
```

**Expected output:**
```
Signing algorithm: SLH-DSA-SHAKE-128f (FIPS 205, pyspx pure-Python)
Signature length: 17088 bytes
Receipt ID: 313-v4-XXXXXXXX
Timestamp ends in 313: True
PQC stack: ACTIVE
```

---

## 8. Run the test suite (optional — verifies full installation)

```bash
python -m pytest --tb=short -q
# Expected: 2071 passed
```

---

## 9. Run the security posture scanner (optional)

```bash
python scripts/shadow313_posture_scanner.py
# Expected: Overall Posture: GREEN (CRIT=0 HIGH=0)
```

---

## 10. Reactivating Shadow313 later

```bash
# Linux / macOS
cd ~/shadow313
source .venv/bin/activate
shadow313

# Windows (PowerShell)
cd $HOME\shadow313
.\.venv\Scripts\Activate.ps1
shadow313
```

---

## Optional Dependencies

| Feature | Install Command | Purpose |
|---------|----------------|---------|
| Quantum circuits | `pip install qiskit qiskit-aer` | Qiskit classifier |
| C-accelerated PQC | `pip install pqcrypto` | Faster SLH-DSA (requires C build) |
| Real ML-DSA-65 | `pip install liboqs-python` | DW-1 production upgrade |
| HSM support | `pip install python-pkcs11` | DW-2 key storage |
| PDF reports | `pip install weasyprint` | PDF export |
| ChromaDB RAG | `pip install chromadb` | Vector knowledge base |

---

## Troubleshooting

| Error | Fix |
|-------|-----|
| `No module named 'shadow313'` | Run `pip install -e .` inside the project directory |
| `No module named 'pytest'` | Run `pip install pytest pytest-asyncio` |
| `pyspx not found` | Run `pip install pyspx` (pure-Python SLH-DSA fallback) |
| `Posture: RED — pytest not importable` | Run `pip install pytest` |
| `shadow313: command not found` | Activate venv: `source .venv/bin/activate` |
| `HMAC-SHA256 (fallback)` in signing | Install pyspx: `pip install pyspx` |

---

## Architecture Overview

```
shadow313/
├── cli/main.py              ← Entry point: shadow313 command
├── core/                    ← Kernel: session, config, AI engine, crypto
│   ├── crypto_store.py      ← AES-256-GCM + Argon2id
│   ├── binding_sdk/         ← 313-BIND SDK (Binder313, BindReceipt)
│   └── intelligence_graph.py
├── v4/                      ← NEXUS v4 modules (103 total)
│   ├── temporal_binding/    ← 313-BIND + SLH-DSA + IPFS anchoring
│   ├── ghost_watch/         ← ACTS/WE-FORGE + CADL + TARTARUS + VALKYRIE
│   ├── aegis/               ← CADL engine + PE analyzer + DNS intercept
│   ├── detection/           ← NEXUS ML + LIF + enforcement + zero-evasion
│   ├── quantum_nexus/       ← QKD + HNDL + Qiskit classifier
│   └── satellite/           ← VSAT + ground segment sweep + CWMP hardening
├── temporal313.py           ← v1 shim → TemporalBindingEngine
├── quantum_middleware.py    ← v1 shim → QuantumNEXUSModule
└── thought_engine.py        ← v1 shim → AgentOrchestrator
```

---

*Shadow313 NEXUS v4 · Ottawa, ON, Canada · 2026 · All rights reserved*  
*PQC: FIPS 203/204/205 · 313-BIND · Ghost-Watch Apex Tier · CMMC Level 2*