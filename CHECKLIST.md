# Shadow313 NEXUS — Master Build Checklist
*Last updated: 2026-09-25 | No push until all items checked*

## ✅ DONE — Do Not Touch
- [x] 392 Python files · 3,554 tests passing · 0 failed
- [x] 9 core modules (recon, vuln, exploit, network, defense, quantum, plugins, cicd, docs)
- [x] 35 proprietary tools (LogForge, HoneyWireNet, VaultScan, DetectionForge, NexusRAG, etc.)
- [x] v4 detectors (WebShell 45 sigs F1=1.000, KernelGap 18 detectors, ThreatHardening, LSTM)
- [x] 313-BIND protocol (SLH-DSA + IPFS + nanosecond ...313 entropy)
- [x] CRQC patches 12/14 closed
- [x] GitHub Actions CI (pytest-timeout fixed, conftest.py)
- [x] Vercel deployment (45 routes, all working)
- [x] Docker Compose (nginx, ollama, openwebui)
- [x] Ollama model (matarmohamad313/shadow313-nexus pushed)
- [x] Linear MCP connected
- [x] Security blind spots patched (BS-02 SSRF, BS-05 timing, BS-06 random, BS-07 path traversal)
- [x] 45 Vercel routes · 23 HTML dashboards · 44 local bundle files

## 🔴 PRIORITY 1 — Missing Python Modules
- [x] Federated Mesh Python module (mesh.py, gossip.py, signing.py, privacy.py, trust.py — 92 tests) (shadow313/v4/federated_mesh/)
- [x] Identity Platform module (identity.py, auth.py, mfa.py, rbac.py, session.py, audit.py — 313-BIND signed) (shadow313/v4/identity/)
- [x] Advanced SOAR (advanced_soar.py — ML-triggered, 5 playbooks, STIX gen, safe condition eval) (shadow313/v4/soar/advanced_soar.py)
- [x] VSAT Monitor (vsat_monitor.py — RF metrics, QKD BB84, CVE-2026-3392) (shadow313/v4/satellite/vsat_monitor.py)
- [x] ML Threat Predictor (predictor.py — Markov chain, ORACLE, 313-BIND receipts) (shadow313/v4/threat_predictor/)

## 🟠 PRIORITY 2 — Missing HTML Dashboards (9 needed)
- [ ] Ghost Watch Dashboard (WE-FORGE, CADL L1-L5, lure injection)
- [ ] Identity Platform Dashboard (user mgmt, MFA, sessions, RBAC)
- [ ] SOAR Playbook Builder (visual editor, 50+ templates)
- [ ] ML Threat Predictor Dashboard (Markov chain, ORACLE)
- [ ] Plugin Studio (build/test/sign/publish plugins)
- [ ] Quantum Lab (Qiskit Aer, QKD BB84, PQC benchmarks)
- [ ] Red Team Operations (APT profiles, kill chain builder)
- [ ] Blue Team SOC (alert triage, SIEM, Sigma builder)
- [ ] Purple Team Exercise (ATT&CK tracker, gap analysis)

## 🟡 PRIORITY 3 — Integrations
- [ ] Telegram Bot (alert notifications, SOAR approval gates)
- [ ] GitHub Pages (enable in repo Settings → Pages → GitHub Actions)
- [ ] PyPI Publishing (run workflow, publish shadow313 package)
- [ ] WireGuard VPN (Hetzner VPS setup)
- [ ] Hetzner VPS (provision, deploy, nginx)
- [ ] 313-BIND real IPFS (connect to actual IPFS node)
- [ ] Atlassian/Jira (finish OAuth, create issues from SOAR)

## 🟢 PRIORITY 4 — Test Coverage Gaps
- [ ] FastAPI server tests (/api/status, /api/scan/recon, /api/detect, /api/bind/create)
- [ ] Ghost Watch tests (WE-FORGE, CADL, attribution)
- [ ] Ledger engine tests (append-only, hash chain, tamper detect)
- [ ] VSAT monitor tests (RF metrics, QKD QBER, CVE-2026-3392)
- [ ] Federated mesh tests (peer discovery, signing, trust)

## 🔵 PRIORITY 5 — Site/UX Polish
- [ ] Update index.html with Ghost Watch, Identity, SOAR Builder, Quantum Lab cards
- [ ] Update local_bundle with all new pages
- [ ] Update vercel.json with new dashboard routes
- [ ] Update GitHub Pages workflow for new directories
- [ ] Ollama model retrain with full ATT&CK context
- [ ] README.md update (45 routes, new modules, install guide)

## ⚫ PRIORITY 6 — Laptop Setup Remaining
- [ ] Kali Linux tool installation complete
- [ ] Docker sign in + containers configured
- [ ] WireGuard tunnel on laptop
- [ ] Windows Terminal all profiles in one window

## 📐 RECENTLY BUILT (this session, not yet pushed)
- [x] docs/module-design-doc.html — 10-slide interactive presentation (cyan aesthetic)
- [x] docs/vsat-tactical-suite.html — Rebuilt, no CDN deps, fully interactive
- [x] docs/federated-mesh.html — Federated Threat Intelligence Mesh page
- [x] local_bundle/ — 44 files with relative links for offline use
- [x] /module-design + /mdd routes added
- [x] index.html updated with Module Design Doc + Federated Mesh cards
- [x] Security patches: BS-02 SSRF, BS-05 timing, BS-06 random, BS-07 path traversal
- [x] Import ordering fixes (ti_feed.py, beacon_detector.py, audit_server.py)

## 🎯 NEXT BUILD ORDER (tell me which to start)
1. Ghost Watch Dashboard (highest visual impact)
2. Red Team / Blue Team / Purple Team dashboards
3. SOAR Playbook Builder (interactive, high value)
4. Quantum Lab (unique differentiator)
5. Federated Mesh Python module
6. Identity Platform module
7. Telegram Bot
8. Test coverage gaps
9. Final push + PyPI publish
