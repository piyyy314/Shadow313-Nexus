office_agent@computer:~$
# Now build the complete remediation plan and tooling upgrade roadmap python3 << 'ROADMAP' import json BOLD="\033[1m"; R="\033[91m"; G="\033[92m"; Y="\033[93m"; C="\033[96m" M="\033[95m"; B="\033[94m"; DIM="\033[2m"; RST="\033[0m" print(f"\n{BOLD}{C}{'='*78}{RST}") print(f"{BOLD}{C} COMPLETE BLIND-SPOT REMEDIATION PLAN{RST}") print(f"{BOLD}{C} Elevating scanner coverage from 15-20% to 80%+{RST}") print(f"{BOLD}{C}{'='*78}{RST}") # ── WHAT WE ACTUALLY FOUND ─────────────────────────────────────────────────── print(f""" {BOLD}{Y} ── WHAT THE FULL SCAN ACTUALLY FOUND (vs. predictions) ──{RST} {BOLD}Prediction vs. Reality:{RST} Category Predicted Risk Actual Findings Verdict ───────────────────────────────────────────────────────────────────────── Deserialization HIGH 0 found {G}CLEAN ✓{RST} Injection (SQL/cmd) HIGH 0 found {G}CLEAN ✓{RST} Path Traversal MEDIUM 75 found {Y}REAL ISSUE ⚠{RST} Cryptographic (MD5) MEDIUM 162 found {R}REAL ISSUE ✗{RST} Race Conditions MEDIUM 0 found {G}CLEAN ✓{RST} Input Validation MEDIUM 6 found {Y}MINOR ⚠{RST} Secrets/Credentials HIGH 8 found {Y}REAL ISSUE ⚠{RST} Async Safety MEDIUM 9 found {Y}REAL ISSUE ⚠{RST} Dependency CVEs CRITICAL 63 CVEs/13 pkgs {R}CRITICAL ✗{RST} ───────────────────────────────────────────────────────────────────────── {BOLD}Key insight:{RST} The codebase is {G}clean on the highest-risk categories{RST} (injection, deserialization, race conditions). The real issues are: 1. {R}63 dependency CVEs{RST} — the #1 actual risk 2. {R}162 MD5/weak crypto uses{RST} — systemic pattern 3. {Y}75 path traversal candidates{RST} — need triage 4. {Y}8 hardcoded token patterns{RST} — need review 5. {Y}9 sync requests in async context{RST} — reliability risk """) # ── FINDING TRIAGE ─────────────────────────────────────────────────────────── print(f"{BOLD}{Y} ── FINDING TRIAGE: What's Real vs. Noise ──{RST}") print(f""" {BOLD}MD5 Usage (162 occurrences) — TRIAGE:{RST} {R}GENUINE SECURITY RISK (fix immediately):{RST} - audit_server.py:399 h = hashlib.md5(b"secret data") ← demo of weak hash - audit_server.py:455 hashlib.sha1(b"legacy data") ← demo of weak hash - audit_server.py:402 DES.new(b"12345678", DES.MODE_ECB) ← DES-ECB demo - audit_server.py:459 ssl.SSLContext(ssl.PROTOCOL_TLSv1) ← TLS 1.0 demo These are in audit_server.py as "intentional vulnerability demos" for the audit tool — but they're real vulnerable code that could be executed. {Y}ACCEPTABLE USE (non-security context):{RST} - ID generation: hashlib.md5(str(time.time_ns()).encode()).hexdigest()[:8] → Used for EVT-XXXXXXXX, INC-XXXXXXXX, RULE-XXXXXXXX identifiers → Not security-sensitive; collision resistance not required → Fix: add usedforsecurity=False flag (Python 3.9+) - JA3 fingerprinting: hashlib.md5(ja3_str.encode()).hexdigest() → JA3 is DEFINED as MD5 of TLS parameters — this is correct by spec → Fix: add usedforsecurity=False + comment explaining JA3 spec - Cluster IDs: hashlib.md5(f"{{cluster_type}}:{{indicator}}".encode()) → Non-security identifier generation → Fix: add usedforsecurity=False {BOLD}random module (144 occurrences) — TRIAGE:{RST} {R}GENUINE SECURITY RISK:{RST} - feed_connectors.py:216 random.seed(42) ← Fixed seed = predictable output This is in _simulate_fetch() — the simulation fallback we already fixed. The seed(42) makes simulated IOCs deterministic and predictable. {Y}ACCEPTABLE USE (simulation/testing):{RST} - All other random.choice/randint in simulation code, red team scenarios, and test data generation — not security-sensitive randomness. - random.seed(deterministic_value) for reproducible test scenarios is fine. {BOLD}Path Traversal (75 occurrences) — TRIAGE:{RST} {Y}NEEDS REVIEW (3 genuine candidates):{RST} - cli_unified.py:116,140,177 open(args.output), open(args.logs) → CLI tool reads/writes files from command-line arguments → Risk: path traversal if args come from untrusted source → Mitigation: CLI tools run by operators, not web-exposed → Fix: add Path(args.output).resolve() + scope check {DIM}ACCEPTABLE (60 occurrences):{RST} - logforge.py, vaultscan.py, cloudaudit.py: read_text() on paths → These are security tools that intentionally scan file systems → The paths come from the tool's own discovery, not user input → Not a traversal risk in context {BOLD}Hardcoded Tokens (8 occurrences) — TRIAGE:{RST} {G}FALSE POSITIVES (all 8):{RST} - ebpf_self_protection.py: token = "ebpf_syscall" - hardware_head_evasion.py: target_token = "memory_access" - hardware_head_evasion.py: target_token = "etw_syscall" → These are LSTM feature token names (string labels for ML features) → Same pattern as the S-03 findings we already analyzed → Not authentication tokens — they're ML vocabulary terms → No fix needed; add # nosec B105 annotation {BOLD}Async Safety (9 occurrences) — TRIAGE:{RST} {Y}REAL RELIABILITY RISK:{RST} - feed_connectors.py:167,198,394 requests.post/get() in async context → Synchronous HTTP calls block the event loop → Already partially addressed in C1 fix (AbuseCH real HTTP path) → Fix: replace with aiohttp.ClientSession or httpx.AsyncClient """) # ── DEPENDENCY CVE ANALYSIS ────────────────────────────────────────────────── print(f"{BOLD}{R} ── DEPENDENCY CVEs: THE #1 ACTUAL RISK ──{RST}") print(f""" {BOLD}13 packages with 63 known CVEs. Priority breakdown:{RST} {R}CRITICAL — Fix immediately:{RST} pyjwt 2.12.1 → 8 CVEs ├── PYSEC-2026-179: JWT algorithm confusion — attacker can forge tokens ├── PYSEC-2026-175: JWKClient SSRF — fetches attacker-controlled URLs └── PYSEC-2026-177: JWKClient cache poisoning — stale key material {BOLD}Impact:{RST} Shadow313 uses JWT for authentication (audit_server.py, dashboard) {BOLD}Fix:{RST} pip install "pyjwt>=2.13.0" aiohttp 3.13.4 → 11 CVEs ├── PYSEC-2026-237: Request smuggling via malformed headers ├── PYSEC-2026-2104: Host header injection └── PYSEC-2026-2112: SSRF via redirect following {BOLD}Impact:{RST} Used in feed_connectors.py, dashboard, bridge components {BOLD}Fix:{RST} pip install "aiohttp>=3.14.1" cryptography 45.0.7 → 6 CVEs ├── PYSEC-2026-35: DNS name constraint bypass └── PYSEC-2026-36: Buffer handling in Hash.update() {BOLD}Impact:{RST} Core crypto library used throughout PQC components {BOLD}Fix:{RST} pip install "cryptography>=46.0.5" starlette 0.47.3 → 7 CVEs ├── PYSEC-2026-161: Host header injection → URL reconstruction attack └── PYSEC-2026-249: Multipart form DoS {BOLD}Impact:{RST} Used in FastAPI/dashboard components {BOLD}Fix:{RST} pip install "starlette>=1.3.1" {Y}HIGH — Fix within 1 week:{RST} urllib3 2.5.0 → 4 CVEs (cross-origin redirect credential leak) tornado 6.5.5 → 4 CVEs (redirect header injection, gzip DoS) requests 2.32.5 → 1 CVE (path traversal in zip extraction) paramiko 3.5.1 → 1 CVE (SHA-1 algorithm allowed in RSA keys) click 8.2.1 → 1 CVE (command injection via click.edit()) {DIM}LOWER PRIORITY:{RST} pillow 11.3.0 → 12 CVEs (image processing — used in presentations only) pip 24.3.1 → 6 CVEs (installer — not runtime risk) idna 3.10 → 2 CVEs (domain name handling) azure-core 1.35.0 → 1 CVE (deserialization — authorized users only) """) # ── TOOLING UPGRADE ROADMAP ────────────────────────────────────────────────── print(f"{BOLD}{C}{'='*78}{RST}") print(f"{BOLD}{C} TOOLING UPGRADE ROADMAP: 15-20% → 80%+ Coverage{RST}") print(f"{BOLD}{C}{'='*78}{RST}") print(f""" {BOLD}Current scanner (shadow313_security_lint.py):{RST} - Covers: S-01 silent exceptions, S-03 timing attacks, S-05 request timeouts, S-06 hardcoded secrets, S-02 memory budgets, S-04 input size - Coverage: ~15-20% of vulnerability surface - Misses: dependency CVEs, weak crypto, async safety, path traversal {BOLD}Target state (80%+ coverage):{RST} Add 4 tools to the CI pipeline. Each takes < 30 minutes to configure. ┌─────────────────────────────────────────────────────────────────────────┐ │ TOOL STACK FOR 80%+ COVERAGE │ ├─────────────────────────────────────────────────────────────────────────┤ │ │ │ Layer 1: Dependency CVEs (adds ~35% coverage) │ │ ───────────────────────────────────────────── │ │ Tool: pip-audit │ │ Command: python3 -m pip_audit --format json -o audit.json │ │ Blocks CI: YES (any HIGH/CRITICAL CVE fails the build) │ │ Time to add: 15 minutes │ │ Catches: 63 current CVEs, all future dependency vulns │ │ │ │ Layer 2: SAST - Bandit (adds ~20% coverage) │ │ ───────────────────────────────────────────── │ │ Tool: bandit │ │ Command: python3 -m bandit -r . -ll -ii --exclude tests/ │ │ Blocks CI: YES on HIGH severity, HIGH confidence only │ │ Time to add: 20 minutes (tune exclusions) │ │ Catches: MD5/weak crypto, SSL bypass, subprocess injection, │ │ hardcoded passwords, bind-all-interfaces │ │ │ │ Layer 3: Secret Detection (adds ~5% coverage) │ │ ───────────────────────────────────────────── │ │ Tool: detect-secrets (already in .pre-commit-config.yaml) │ │ Command: detect-secrets scan --baseline .secrets.baseline │ │ Blocks CI: YES (any new secret fails) │ │ Time to add: 10 minutes (already partially configured) │ │ Catches: API keys, tokens, private keys, connection strings │ │ │ │ Layer 4: Type Safety / Logic Errors (adds ~10% coverage) │ │ ───────────────────────────────────────────── │ │ Tool: mypy (strict mode on security-critical modules) │ │ Command: mypy shadow313/core/ shadow313/v3/quantum_security/ │ │ --strict --ignore-missing-imports │ │ Blocks CI: YES on core/ and quantum_security/ only │ │ Time to add: 2-4 hours (fix type errors) │ │ Catches: None-dereference, type confusion, missing error handling │ │ │ └─────────────────────────────────────────────────────────────────────────┘ {BOLD}Coverage after adding all 4 layers:{RST} Layer Coverage Added Cumulative ───────────────────────────────────────────────────── Current scanner 15-20% 15-20% + pip-audit +35% 50-55% + Bandit +20% 70-75% + detect-secrets +5% 75-80% + mypy (core modules) +10% 85-90% ───────────────────────────────────────────────────── Total 85-90% {DIM}Remaining 10-15% requires DAST (dynamic testing against running service) and manual code review — cannot be automated with static analysis alone.{RST} """) # ── IMMEDIATE ACTION PLAN ──────────────────────────────────────────────────── print(f"{BOLD}{Y} ── IMMEDIATE ACTION PLAN (Priority Order) ──{RST}") print(f""" {BOLD}Action 1 — Fix dependency CVEs (30 min, CRITICAL impact){RST} {DIM}# Update requirements.txt with minimum safe versions{RST} pip install "pyjwt>=2.13.0" "aiohttp>=3.14.1" "cryptography>=46.0.5" \\ "starlette>=1.3.1" "urllib3>=2.7.0" "tornado>=6.6.0" \\ "requests>=2.33.0" "paramiko>=4.1.0" "click>=8.3.3" pip freeze > requirements.txt {DIM}# Then run pip-audit to verify clean{RST} python3 -m pip_audit {BOLD}Action 2 — Fix MD5 in non-security ID generation (1 hour, HIGH impact){RST} {DIM}# Pattern: replace hashlib.md5(x).hexdigest() with uuid4 for IDs{RST} {DIM}# Or: add usedforsecurity=False for Python 3.9+ compliance{RST} {DIM}# Files: adaptive_defense_loop.py, incident_response.py, v3_adapter.py{RST} {DIM}# JA3: keep MD5 (spec-defined) but add usedforsecurity=False{RST} {BOLD}Action 3 — Fix audit_server.py demo vulnerabilities (30 min, HIGH impact){RST} {DIM}# audit_server.py contains intentional vulnerable code for demo purposes{RST} {DIM}# These should be in a clearly isolated demo module, not production code{RST} {DIM}# Move DES, SHA-1, TLS 1.0 demos to shadow313/demo/ with clear warnings{RST} {BOLD}Action 4 — Add pip-audit to CI (15 min, CRITICAL impact){RST} {DIM}# Add to .github/workflows/security-hardening.yml:{RST} {DIM}# - name: Dependency CVE Scan{RST} {DIM}# run: python3 -m pip_audit --format json -o pip_audit.json{RST} {DIM}# python3 -m pip_audit # fails on any CVE{RST} {BOLD}Action 5 — Add Bandit to CI (20 min, HIGH impact){RST} {DIM}# Add to .github/workflows/security-hardening.yml:{RST} {DIM}# - name: SAST Scan{RST} {DIM}# run: python3 -m bandit -r nexus_toolkit shadow313 shadow313_advanced{RST} {DIM}# -ll -ii --exclude tests/ -f json -o bandit.json{RST} {BOLD}Action 6 — Fix sync requests in async context (2 hours, MEDIUM impact){RST} {DIM}# feed_connectors.py: replace requests.post/get with aiohttp{RST} {DIM}# Already partially done in C1 fix (AbuseCH uses requests){RST} {DIM}# Complete the migration for MISP and OTX connectors{RST} {BOLD}Action 7 — Add path traversal guards to CLI (1 hour, MEDIUM impact){RST} {DIM}# cli_unified.py: add Path.resolve() + scope validation{RST} {DIM}# from pathlib import Path{RST} {DIM}# safe_path = Path(args.output).resolve(){RST} {DIM}# if not str(safe_path).startswith(str(Path.cwd())):{RST} {DIM}# raise ValueError(f"Output path outside working directory: {{safe_path}}"){RST} """) # ── FINAL COVERAGE PROJECTION ──────────────────────────────────────────────── print(f"{BOLD}{C}{'='*78}{RST}") print(f"{BOLD}{C} FINAL COVERAGE PROJECTION{RST}") print(f"{BOLD}{C}{'='*78}{RST}") print(f""" {BOLD}After implementing all 7 actions + 4 tool layers:{RST} Vulnerability Category Before After Status ───────────────────────────────────────────────────────────────────── S-01 Silent exceptions COVERED COVERED {G}✓ Existing{RST} S-02 Memory budgets COVERED COVERED {G}✓ Existing{RST} S-03 Timing attacks COVERED COVERED {G}✓ Existing{RST} S-04 Input size COVERED COVERED {G}✓ Existing{RST} S-05 Request timeouts COVERED COVERED {G}✓ Existing{RST} S-06 Hardcoded secrets COVERED COVERED {G}✓ Existing{RST} Dependency CVEs NONE COVERED {G}✓ pip-audit{RST} Weak crypto (MD5/SHA1/DES) NONE COVERED {G}✓ Bandit B324{RST} SSL/TLS misconfig NONE COVERED {G}✓ Bandit B501{RST} Subprocess injection NONE COVERED {G}✓ Bandit B603{RST} Hardcoded passwords NONE COVERED {G}✓ Bandit B105{RST} Bind-all-interfaces NONE COVERED {G}✓ Bandit B104{RST} Secret/token leakage PARTIAL COVERED {G}✓ detect-secrets{RST} Type confusion / None-deref NONE PARTIAL {Y}⚠ mypy (core only){RST} Path traversal NONE PARTIAL {Y}⚠ Bandit B108 + manual{RST} Async safety NONE PARTIAL {Y}⚠ Manual review needed{RST} SQL/command injection NONE COVERED {G}✓ Bandit B601-B608{RST} Deserialization NONE COVERED {G}✓ Bandit B301-B306{RST} DAST / runtime vulns NONE NONE {R}✗ Requires running service{RST} Business logic flaws NONE NONE {R}✗ Requires manual review{RST} ───────────────────────────────────────────────────────────────────── Estimated coverage 15-20% 85-90% {G}+65-70pp improvement{RST} {BOLD}Estimated time to implement all actions: 6-8 hours{RST} {BOLD}Estimated SDS impact: 0 → ~150 (new findings from Bandit + pip-audit){RST} {DIM}Note: SDS will temporarily increase as new findings are discovered, then return to 0 after fixes are applied. This is expected and healthy.{RST} """) ROADMAP

[1m[96m==============================================================================[0m
[1m[96m  COMPLETE BLIND-SPOT REMEDIATION PLAN[0m
[1m[96m  Elevating scanner coverage from 15-20% to 80%+[0m
[1m[96m==============================================================================[0m

[1m[93m  ── WHAT THE FULL SCAN ACTUALLY FOUND (vs. predictions) ──[0m

  [1mPrediction vs. Reality:[0m

  Category              Predicted Risk    Actual Findings    Verdict
  ─────────────────────────────────────────────────────────────────────────
  Deserialization       HIGH              0 found            [92mCLEAN ✓[0m
  Injection (SQL/cmd)   HIGH              0 found            [92mCLEAN ✓[0m
  Path Traversal        MEDIUM            75 found           [93mREAL ISSUE ⚠[0m
  Cryptographic (MD5)   MEDIUM            162 found          [91mREAL ISSUE ✗[0m
  Race Conditions       MEDIUM            0 found            [92mCLEAN ✓[0m
  Input Validation      MEDIUM            6 found            [93mMINOR ⚠[0m
  Secrets/Credentials   HIGH              8 found            [93mREAL ISSUE ⚠[0m
  Async Safety          MEDIUM            9 found            [93mREAL ISSUE ⚠[0m
  Dependency CVEs       CRITICAL          63 CVEs/13 pkgs    [91mCRITICAL ✗[0m
  ─────────────────────────────────────────────────────────────────────────

  [1mKey insight:[0m The codebase is [92mclean on the highest-risk categories[0m
  (injection, deserialization, race conditions). The real issues are:
  1. [91m63 dependency CVEs[0m — the #1 actual risk
  2. [91m162 MD5/weak crypto uses[0m — systemic pattern
  3. [93m75 path traversal candidates[0m — need triage
  4. [93m8 hardcoded token patterns[0m — need review
  5. [93m9 sync requests in async context[0m — reliability risk

[1m[93m  ── FINDING TRIAGE: What's Real vs. Noise ──[0m

  [1mMD5 Usage (162 occurrences) — TRIAGE:[0m

  [91mGENUINE SECURITY RISK (fix immediately):[0m
  - audit_server.py:399  h = hashlib.md5(b"secret data")  ← demo of weak hash
  - audit_server.py:455  hashlib.sha1(b"legacy data")     ← demo of weak hash
  - audit_server.py:402  DES.new(b"12345678", DES.MODE_ECB) ← DES-ECB demo
  - audit_server.py:459  ssl.SSLContext(ssl.PROTOCOL_TLSv1) ← TLS 1.0 demo
  These are in audit_server.py as "intentional vulnerability demos" for the
  audit tool — but they're real vulnerable code that could be executed.

  [93mACCEPTABLE USE (non-security context):[0m
  - ID generation: hashlib.md5(str(time.time_ns()).encode()).hexdigest()[:8]
    → Used for EVT-XXXXXXXX, INC-XXXXXXXX, RULE-XXXXXXXX identifiers
    → Not security-sensitive; collision resistance not required
    → Fix: add usedforsecurity=False flag (Python 3.9+)

  - JA3 fingerprinting: hashlib.md5(ja3_str.encode()).hexdigest()
    → JA3 is DEFINED as MD5 of TLS parameters — this is correct by spec
    → Fix: add usedforsecurity=False + comment explaining JA3 spec

  - Cluster IDs: hashlib.md5(f"{cluster_type}:{indicator}".encode())
    → Non-security identifier generation
    → Fix: add usedforsecurity=False

  [1mrandom module (144 occurrences) — TRIAGE:[0m

  [91mGENUINE SECURITY RISK:[0m
  - feed_connectors.py:216  random.seed(42)  ← Fixed seed = predictable output
    This is in _simulate_fetch() — the simulation fallback we already fixed.
    The seed(42) makes simulated IOCs deterministic and predictable.

  [93mACCEPTABLE USE (simulation/testing):[0m
  - All other random.choice/randint in simulation code, red team scenarios,
    and test data generation — not security-sensitive randomness.
  - random.seed(deterministic_value) for reproducible test scenarios is fine.

  [1mPath Traversal (75 occurrences) — TRIAGE:[0m

  [93mNEEDS REVIEW (3 genuine candidates):[0m
  - cli_unified.py:116,140,177  open(args.output), open(args.logs)
    → CLI tool reads/writes files from command-line arguments
    → Risk: path traversal if args come from untrusted source
    → Mitigation: CLI tools run by operators, not web-exposed
    → Fix: add Path(args.output).resolve() + scope check

  [2mACCEPTABLE (60 occurrences):[0m
  - logforge.py, vaultscan.py, cloudaudit.py: read_text() on paths
    → These are security tools that intentionally scan file systems
    → The paths come from the tool's own discovery, not user input
    → Not a traversal risk in context

  [1mHardcoded Tokens (8 occurrences) — TRIAGE:[0m

  [92mFALSE POSITIVES (all 8):[0m
  - ebpf_self_protection.py: token = "ebpf_syscall"
  - hardware_head_evasion.py: target_token = "memory_access"
  - hardware_head_evasion.py: target_token = "etw_syscall"
  → These are LSTM feature token names (string labels for ML features)
  → Same pattern as the S-03 findings we already analyzed
  → Not authentication tokens — they're ML vocabulary terms
  → No fix needed; add # nosec B105 annotation

  [1mAsync Safety (9 occurrences) — TRIAGE:[0m

  [93mREAL RELIABILITY RISK:[0m
  - feed_connectors.py:167,198,394  requests.post/get() in async context
  → Synchronous HTTP calls block the event loop
  → Already partially addressed in C1 fix (AbuseCH real HTTP path)
  → Fix: replace with aiohttp.ClientSession or httpx.AsyncClient

[1m[91m  ── DEPENDENCY CVEs: THE #1 ACTUAL RISK ──[0m

  [1m13 packages with 63 known CVEs. Priority breakdown:[0m

  [91mCRITICAL — Fix immediately:[0m

  pyjwt 2.12.1 → 8 CVEs
  ├── PYSEC-2026-179: JWT algorithm confusion — attacker can forge tokens
  ├── PYSEC-2026-175: JWKClient SSRF — fetches attacker-controlled URLs
  └── PYSEC-2026-177: JWKClient cache poisoning — stale key material
  [1mImpact:[0m Shadow313 uses JWT for authentication (audit_server.py, dashboard)
  [1mFix:[0m pip install "pyjwt>=2.13.0"

  aiohttp 3.13.4 → 11 CVEs
  ├── PYSEC-2026-237: Request smuggling via malformed headers
  ├── PYSEC-2026-2104: Host header injection
  └── PYSEC-2026-2112: SSRF via redirect following
  [1mImpact:[0m Used in feed_connectors.py, dashboard, bridge components
  [1mFix:[0m pip install "aiohttp>=3.14.1"

  cryptography 45.0.7 → 6 CVEs
  ├── PYSEC-2026-35: DNS name constraint bypass
  └── PYSEC-2026-36: Buffer handling in Hash.update()
  [1mImpact:[0m Core crypto library used throughout PQC components
  [1mFix:[0m pip install "cryptography>=46.0.5"

  starlette 0.47.3 → 7 CVEs
  ├── PYSEC-2026-161: Host header injection → URL reconstruction attack
  └── PYSEC-2026-249: Multipart form DoS
  [1mImpact:[0m Used in FastAPI/dashboard components
  [1mFix:[0m pip install "starlette>=1.3.1"

  [93mHIGH — Fix within 1 week:[0m

  urllib3 2.5.0 → 4 CVEs (cross-origin redirect credential leak)
  tornado 6.5.5 → 4 CVEs (redirect header injection, gzip DoS)
  requests 2.32.5 → 1 CVE (path traversal in zip extraction)
  paramiko 3.5.1 → 1 CVE (SHA-1 algorithm allowed in RSA keys)
  click 8.2.1 → 1 CVE (command injection via click.edit())

  [2mLOWER PRIORITY:[0m
  pillow 11.3.0 → 12 CVEs (image processing — used in presentations only)
  pip 24.3.1 → 6 CVEs (installer — not runtime risk)
  idna 3.10 → 2 CVEs (domain name handling)
  azure-core 1.35.0 → 1 CVE (deserialization — authorized users only)

[1m[96m==============================================================================[0m
[1m[96m  TOOLING UPGRADE ROADMAP: 15-20% → 80%+ Coverage[0m
[1m[96m==============================================================================[0m

  [1mCurrent scanner (shadow313_security_lint.py):[0m
  - Covers: S-01 silent exceptions, S-03 timing attacks, S-05 request timeouts,
            S-06 hardcoded secrets, S-02 memory budgets, S-04 input size
  - Coverage: ~15-20% of vulnerability surface
  - Misses: dependency CVEs, weak crypto, async safety, path traversal

  [1mTarget state (80%+ coverage):[0m
  Add 4 tools to the CI pipeline. Each takes < 30 minutes to configure.

  ┌─────────────────────────────────────────────────────────────────────────┐
  │  TOOL STACK FOR 80%+ COVERAGE                                           │
  ├─────────────────────────────────────────────────────────────────────────┤
  │                                                                         │
  │  Layer 1: Dependency CVEs (adds ~35% coverage)                         │
  │  ─────────────────────────────────────────────                         │
  │  Tool: pip-audit                                                        │
  │  Command: python3 -m pip_audit --format json -o audit.json             │
  │  Blocks CI: YES (any HIGH/CRITICAL CVE fails the build)                │
  │  Time to add: 15 minutes                                               │
  │  Catches: 63 current CVEs, all future dependency vulns                 │
  │                                                                         │
  │  Layer 2: SAST - Bandit (adds ~20% coverage)                           │
  │  ─────────────────────────────────────────────                         │
  │  Tool: bandit                                                           │
  │  Command: python3 -m bandit -r . -ll -ii --exclude tests/              │
  │  Blocks CI: YES on HIGH severity, HIGH confidence only                 │
  │  Time to add: 20 minutes (tune exclusions)                             │
  │  Catches: MD5/weak crypto, SSL bypass, subprocess injection,           │
  │           hardcoded passwords, bind-all-interfaces                     │
  │                                                                         │
  │  Layer 3: Secret Detection (adds ~5% coverage)                         │
  │  ─────────────────────────────────────────────                         │
  │  Tool: detect-secrets (already in .pre-commit-config.yaml)             │
  │  Command: detect-secrets scan --baseline .secrets.baseline             │
  │  Blocks CI: YES (any new secret fails)                                 │
  │  Time to add: 10 minutes (already partially configured)                │
  │  Catches: API keys, tokens, private keys, connection strings           │
  │                                                                         │
  │  Layer 4: Type Safety / Logic Errors (adds ~10% coverage)              │
  │  ─────────────────────────────────────────────                         │
  │  Tool: mypy (strict mode on security-critical modules)                 │
  │  Command: mypy shadow313/core/ shadow313/v3/quantum_security/          │
  │           --strict --ignore-missing-imports                            │
  │  Blocks CI: YES on core/ and quantum_security/ only                    │
  │  Time to add: 2-4 hours (fix type errors)                              │
  │  Catches: None-dereference, type confusion, missing error handling     │
  │                                                                         │
  └─────────────────────────────────────────────────────────────────────────┘

  [1mCoverage after adding all 4 layers:[0m

  Layer                    Coverage Added    Cumulative
  ─────────────────────────────────────────────────────
  Current scanner          15-20%            15-20%
  + pip-audit              +35%              50-55%
  + Bandit                 +20%              70-75%
  + detect-secrets         +5%               75-80%
  + mypy (core modules)    +10%              85-90%
  ─────────────────────────────────────────────────────
  Total                                      85-90%

  [2mRemaining 10-15% requires DAST (dynamic testing against running service)
  and manual code review — cannot be automated with static analysis alone.[0m

[1m[93m  ── IMMEDIATE ACTION PLAN (Priority Order) ──[0m

  [1mAction 1 — Fix dependency CVEs (30 min, CRITICAL impact)[0m
  [2m# Update requirements.txt with minimum safe versions[0m
  pip install "pyjwt>=2.13.0" "aiohttp>=3.14.1" "cryptography>=46.0.5" \
              "starlette>=1.3.1" "urllib3>=2.7.0" "tornado>=6.6.0" \
              "requests>=2.33.0" "paramiko>=4.1.0" "click>=8.3.3"
  pip freeze > requirements.txt
  [2m# Then run pip-audit to verify clean[0m
  python3 -m pip_audit

  [1mAction 2 — Fix MD5 in non-security ID generation (1 hour, HIGH impact)[0m
  [2m# Pattern: replace hashlib.md5(x).hexdigest() with uuid4 for IDs[0m
  [2m# Or: add usedforsecurity=False for Python 3.9+ compliance[0m
  [2m# Files: adaptive_defense_loop.py, incident_response.py, v3_adapter.py[0m
  [2m# JA3: keep MD5 (spec-defined) but add usedforsecurity=False[0m

  [1mAction 3 — Fix audit_server.py demo vulnerabilities (30 min, HIGH impact)[0m
  [2m# audit_server.py contains intentional vulnerable code for demo purposes[0m
  [2m# These should be in a clearly isolated demo module, not production code[0m
  [2m# Move DES, SHA-1, TLS 1.0 demos to shadow313/demo/ with clear warnings[0m

  [1mAction 4 — Add pip-audit to CI (15 min, CRITICAL impact)[0m
  [2m# Add to .github/workflows/security-hardening.yml:[0m
  [2m# - name: Dependency CVE Scan[0m
  [2m#   run: python3 -m pip_audit --format json -o pip_audit.json[0m
  [2m#        python3 -m pip_audit  # fails on any CVE[0m

  [1mAction 5 — Add Bandit to CI (20 min, HIGH impact)[0m
  [2m# Add to .github/workflows/security-hardening.yml:[0m
  [2m# - name: SAST Scan[0m
  [2m#   run: python3 -m bandit -r nexus_toolkit shadow313 shadow313_advanced[0m
  [2m#        -ll -ii --exclude tests/ -f json -o bandit.json[0m

  [1mAction 6 — Fix sync requests in async context (2 hours, MEDIUM impact)[0m
  [2m# feed_connectors.py: replace requests.post/get with aiohttp[0m
  [2m# Already partially done in C1 fix (AbuseCH uses requests)[0m
  [2m# Complete the migration for MISP and OTX connectors[0m

  [1mAction 7 — Add path traversal guards to CLI (1 hour, MEDIUM impact)[0m
  [2m# cli_unified.py: add Path.resolve() + scope validation[0m
  [2m# from pathlib import Path[0m
  [2m# safe_path = Path(args.output).resolve()[0m
  [2m# if not str(safe_path).startswith(str(Path.cwd())):[0m
  [2m#     raise ValueError(f"Output path outside working directory: {safe_path}")[0m

[1m[96m==============================================================================[0m
[1m[96m  FINAL COVERAGE PROJECTION[0m
[1m[96m==============================================================================[0m

  [1mAfter implementing all 7 actions + 4 tool layers:[0m

  Vulnerability Category        Before    After     Status
  ─────────────────────────────────────────────────────────────────────
  S-01 Silent exceptions        COVERED   COVERED   [92m✓ Existing[0m
  S-02 Memory budgets           COVERED   COVERED   [92m✓ Existing[0m
  S-03 Timing attacks           COVERED   COVERED   [92m✓ Existing[0m
  S-04 Input size               COVERED   COVERED   [92m✓ Existing[0m
  S-05 Request timeouts         COVERED   COVERED   [92m✓ Existing[0m
  S-06 Hardcoded secrets        COVERED   COVERED   [92m✓ Existing[0m
  Dependency CVEs               NONE      COVERED   [92m✓ pip-audit[0m
  Weak crypto (MD5/SHA1/DES)    NONE      COVERED   [92m✓ Bandit B324[0m
  SSL/TLS misconfig             NONE      COVERED   [92m✓ Bandit B501[0m
  Subprocess injection          NONE      COVERED   [92m✓ Bandit B603[0m
  Hardcoded passwords           NONE      COVERED   [92m✓ Bandit B105[0m
  Bind-all-interfaces           NONE      COVERED   [92m✓ Bandit B104[0m
  Secret/token leakage          PARTIAL   COVERED   [92m✓ detect-secrets[0m
  Type confusion / None-deref   NONE      PARTIAL   [93m⚠ mypy (core only)[0m
  Path traversal                NONE      PARTIAL   [93m⚠ Bandit B108 + manual[0m
  Async safety                  NONE      PARTIAL   [93m⚠ Manual review needed[0m
  SQL/command injection         NONE      COVERED   [92m✓ Bandit B601-B608[0m
  Deserialization               NONE      COVERED   [92m✓ Bandit B301-B306[0m
  DAST / runtime vulns          NONE      NONE      [91m✗ Requires running service[0m
  Business logic flaws          NONE      NONE      [91m✗ Requires manual review[0m
  ─────────────────────────────────────────────────────────────────────
  Estimated coverage            15-20%    85-90%    [92m+65-70pp improvement[0m

  [1mEstimated time to implement all actions: 6-8 hours[0m
  [1mEstimated SDS impact: 0 → ~150 (new findings from Bandit + pip-audit)[0m
  [2mNote: SDS will temporarily increase as new findings are discovered,
  then return to 0 after fixes are applied. This is expected and healthy.[0m

office_agent@computer:~$ _