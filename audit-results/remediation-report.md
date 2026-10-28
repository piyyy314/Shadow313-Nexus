# Shadow313 NEXUS Repository Completeness Audit

**Result:** FAIL
**Commit:** `68a245e9a160b52b9003d52fa5b9409029c07715`
**Branch:** `master`

## Executive summary

- Findings: 176 ({'INFO': 15, 'WARN': 85, 'FAIL': 76})
- Source modules: 347
- Modules without traceable tests: 19
- API routes: 39
- API routes without traceable tests: 16
- CLI surfaces: 45
- CLI surfaces without traceable tests: 9
- Detector files: 49
- Sigma rules: 2
- TODO/FIXME/STUB markers: 69

## Findings by category

- **api**: 16
- **ci**: 26
- **cli**: 9
- **container**: 1
- **detectors**: 4
- **imports**: 6
- **markers**: 69
- **packaging**: 1
- **secrets**: 23
- **structure**: 1
- **test-coverage**: 19
- **versioning**: 1

## Detailed findings

### [FAIL] S313-3654c74950 - api `shadow313/api/audit_server.py:208`
API route lacks a traceable test: GET /api/audit/chain

Evidence: `get_audit_chain`

Remediation: Add happy-path, validation, auth, error, and schema tests for this route.

### [FAIL] S313-90af355f44 - api `shadow313/api/audit_server.py:238`
API route lacks a traceable test: GET /api/link-budget/profiles

Evidence: `get_link_budget_profiles`

Remediation: Add happy-path, validation, auth, error, and schema tests for this route.

### [FAIL] S313-f8a1662301 - api `shadow313/api/audit_server.py:270`
API route lacks a traceable test: GET /api/public-key

Evidence: `get_public_key`

Remediation: Add happy-path, validation, auth, error, and schema tests for this route.

### [FAIL] S313-33ae60237f - api `shadow313/api/server.py:227`
API route lacks a traceable test: GET /api/modules

Evidence: `list_modules`

Remediation: Add happy-path, validation, auth, error, and schema tests for this route.

### [FAIL] S313-4d563294c0 - api `shadow313/api/server.py:279`
API route lacks a traceable test: POST /api/webshell/scan

Evidence: `webshell_scan`

Remediation: Add happy-path, validation, auth, error, and schema tests for this route.

### [FAIL] S313-31c6c3754d - api `shadow313/api/server.py:289`
API route lacks a traceable test: GET /api/attck/coverage

Evidence: `attck_coverage`

Remediation: Add happy-path, validation, auth, error, and schema tests for this route.

### [FAIL] S313-6487ce442c - api `shadow313/api/server.py:348`
API route lacks a traceable test: GET /api/bind/{bind_id}

Evidence: `bind_get`

Remediation: Add happy-path, validation, auth, error, and schema tests for this route.

### [FAIL] S313-46ddffdfb3 - api `shadow313/api/server.py:354`
API route lacks a traceable test: GET /api/bind

Evidence: `bind_list`

Remediation: Add happy-path, validation, auth, error, and schema tests for this route.

### [FAIL] S313-e88dcbbd36 - api `shadow313/api/server.py:362`
API route lacks a traceable test: GET /api/mobile/status

Evidence: `mobile_status`

Remediation: Add happy-path, validation, auth, error, and schema tests for this route.

### [FAIL] S313-cafe973f53 - api `shadow313/api/server.py:366`
API route lacks a traceable test: POST /api/mobile/scan

Evidence: `mobile_scan`

Remediation: Add happy-path, validation, auth, error, and schema tests for this route.

### [FAIL] S313-f28dcaf4db - api `shadow313/api/server.py:371`
API route lacks a traceable test: GET /api/mobile/alerts

Evidence: `mobile_alerts`

Remediation: Add happy-path, validation, auth, error, and schema tests for this route.

### [FAIL] S313-18683bd2d7 - api `shadow313/api/server.py:375`
API route lacks a traceable test: GET /api/mobile/findings

Evidence: `mobile_findings`

Remediation: Add happy-path, validation, auth, error, and schema tests for this route.

### [FAIL] S313-ad17f4ed65 - api `shadow313/api/server.py:379`
API route lacks a traceable test: GET /api/mobile/sessions

Evidence: `mobile_sessions`

Remediation: Add happy-path, validation, auth, error, and schema tests for this route.

### [FAIL] S313-f914ed652d - api `shadow313/api/server.py:391`
API route lacks a traceable test: GET /api/stream

Evidence: `stream_status`

Remediation: Add happy-path, validation, auth, error, and schema tests for this route.

### [FAIL] S313-a3ce1704d8 - api `shadow313/v2/dashboard/app.py:213`
API route lacks a traceable test: GET /api/findings

Evidence: `get_findings`

Remediation: Add happy-path, validation, auth, error, and schema tests for this route.

### [FAIL] S313-9a0a12b817 - api `shadow313_platform/event_bus.py:230`
API route lacks a traceable test: POST /api/events/publish

Evidence: `publish_event`

Remediation: Add happy-path, validation, auth, error, and schema tests for this route.

### [FAIL] S313-686c0fdfda - ci `.github/workflows/deliver.yml:138`
Fail-open CI instruction found

Evidence: `git add dist/manifest.json dist/receipts/ || true`

Remediation: Remove fail-open behavior from release-blocking validation.

### [FAIL] S313-d4d8a4066a - ci `.github/workflows/deliver.yml:140`
Fail-open CI instruction found

Evidence: `git push origin master || true`

Remediation: Remove fail-open behavior from release-blocking validation.

### [FAIL] S313-84239a15c6 - ci `.github/workflows/deploy.yml:128`
Fail-open CI instruction found

Evidence: `matches=$(grep -rE "$pattern" --include="*.html" --include="*.js" --include="*.json" . 2>/dev/null | grep -v ".github" || true)`

Remediation: Remove fail-open behavior from release-blocking validation.

### [FAIL] S313-ea5fcc15b2 - ci `.github/workflows/deploy.yml:318`
Fail-open CI instruction found

Evidence: `vercel promote "$prev" --token=${{ secrets.VERCEL_TOKEN }} --scope=shadow313-nexus || true`

Remediation: Remove fail-open behavior from release-blocking validation.

### [FAIL] S313-ec034c5275 - ci `.github/workflows/pr-checks.yml:47`
Fail-open CI instruction found

Evidence: `run: ruff check shadow313/ nexus_toolkit/ --output-format github || true`

Remediation: Remove fail-open behavior from release-blocking validation.

### [FAIL] S313-8cb6c2d063 - ci `.github/workflows/pr-checks.yml:50`
Fail-open CI instruction found

Evidence: `run: black --check --diff shadow313/ || true`

Remediation: Remove fail-open behavior from release-blocking validation.

### [FAIL] S313-d16b88ae95 - ci `.github/workflows/pr-checks.yml:53`
Fail-open CI instruction found

Evidence: `run: yamllint -c .yamllint.yml .github/workflows/ docker-compose.yml || true`

Remediation: Remove fail-open behavior from release-blocking validation.

### [FAIL] S313-4bcb39bd5b - ci `.github/workflows/pr-checks.yml:102`
Fail-open CI instruction found

Evidence: `-f json -o bandit-report.json || true`

Remediation: Remove fail-open behavior from release-blocking validation.

### [FAIL] S313-edf315c44a - ci `.github/workflows/pr-checks.yml:148`
Fail-open CI instruction found

Evidence: `pip-audit --desc --format json -o pip-audit-report.json || true`

Remediation: Remove fail-open behavior from release-blocking validation.

### [FAIL] S313-6041e1b2e8 - ci `.github/workflows/pr-checks.yml:152`
Fail-open CI instruction found

Evidence: `run: safety check --full-report || true`

Remediation: Remove fail-open behavior from release-blocking validation.

### [FAIL] S313-bffb9ef2af - ci `.github/workflows/security-scan.yml:36`
Fail-open CI instruction found

Evidence: `safety check --full-report --json > nightly-safety.json || true`

Remediation: Remove fail-open behavior from release-blocking validation.

### [FAIL] S313-c77c0bdbe9 - ci `.github/workflows/security-scan.yml:40`
Fail-open CI instruction found

Evidence: `-f json -o nightly-bandit.json || true`

Remediation: Remove fail-open behavior from release-blocking validation.

### [FAIL] S313-31ca852f9f - ci `.github/workflows/security-scan.yml:61`
Fail-open CI instruction found

Evidence: `docker build --target production -t shadow313-scan:nightly . || true`

Remediation: Remove fail-open behavior from release-blocking validation.

### [FAIL] S313-7e71b60ecb - ci `.github/workflows/security-scan.yml:109`
Fail-open CI instruction found

Evidence: `--soft-fail || true`

Remediation: Remove fail-open behavior from release-blocking validation.

### [FAIL] S313-cb0035f1c9 - ci `.github/workflows/shadow313-api-validate.yml:32`
Fail-open CI instruction found

Evidence: `pip install -e ".[dev]" -q 2>/dev/null || pip install -r requirements.txt -q || true`

Remediation: Remove fail-open behavior from release-blocking validation.

### [FAIL] S313-7c8b96f25c - ci `.github/workflows/shadow313-api-validate.yml:179`
Fail-open CI instruction found

Evidence: `run: kill $(cat /tmp/api.pid) 2>/dev/null || true`

Remediation: Remove fail-open behavior from release-blocking validation.

### [FAIL] S313-5f63c59896 - ci `.github/workflows/shadow313-ci.yml:36`
Fail-open CI instruction found

Evidence: `run: ruff check shadow313/ --output-format github || true`

Remediation: Remove fail-open behavior from release-blocking validation.

### [FAIL] S313-13f9153938 - ci `.github/workflows/shadow313-ci.yml:38`
Fail-open CI instruction found

Evidence: `run: black --check --diff shadow313/ || true`

Remediation: Remove fail-open behavior from release-blocking validation.

### [FAIL] S313-750691c7fc - ci `.github/workflows/shadow313-ci.yml:40`
Fail-open CI instruction found

Evidence: `run: mypy shadow313/ --ignore-missing-imports || true`

Remediation: Remove fail-open behavior from release-blocking validation.

### [FAIL] S313-8c1f34852a - ci `.github/workflows/shadow313-ci.yml:75`
Fail-open CI instruction found

Evidence: `continue-on-error: true`

Remediation: Remove fail-open behavior from release-blocking validation.

### [FAIL] S313-b314a49118 - ci `.github/workflows/shadow313-ci.yml:96`
Fail-open CI instruction found

Evidence: `--skip B101,B603,B607,B608,B311,B324 || true`

Remediation: Remove fail-open behavior from release-blocking validation.

### [FAIL] S313-3bc708f79d - ci `.github/workflows/shadow313-ci.yml:99`
Fail-open CI instruction found

Evidence: `run: safety check --json > safety-report.json || true`

Remediation: Remove fail-open behavior from release-blocking validation.

### [FAIL] S313-6c4d0eaf5b - ci `.github/workflows/shadow313-ci.yml:153`
Fail-open CI instruction found

Evidence: `continue-on-error: true   # Don't fail CI if TestPyPI publish fails`

Remediation: Remove fail-open behavior from release-blocking validation.

### [FAIL] S313-0991da5ce0 - ci `.github/workflows/shadow313-validate.yml:125`
Fail-open CI instruction found

Evidence: `- run: pip install -e ".[dev]" -q 2>/dev/null || pip install -r requirements.txt -q || true`

Remediation: Remove fail-open behavior from release-blocking validation.

### [FAIL] S313-cefe8fb82d - ci `.github/workflows/shadow313-validate.yml:251`
Fail-open CI instruction found

Evidence: `pip install -e ".[dev]" -q 2>/dev/null || pip install -r requirements.txt -q || true`

Remediation: Remove fail-open behavior from release-blocking validation.

### [FAIL] S313-f0f26c451f - ci `.github/workflows/shadow313-validate.yml:255`
Fail-open CI instruction found

Evidence: `--cov=shadow313 --cov-report=term-missing 2>&1 || true`

Remediation: Remove fail-open behavior from release-blocking validation.

### [FAIL] S313-70ca273a50 - container `docker-compose.yml`
Compose uses seccomp:unconfined

Remediation: Use the runtime default or a reviewed custom seccomp profile for production.

### [FAIL] S313-1bb5dae930 - detectors `nexus_toolkit/engine_v2.py`
Detector implementation lacks a traceable test

Remediation: Add known-positive, known-negative, malformed, empty, and boundary fixtures.

### [FAIL] S313-4f3b20d9c3 - detectors `shadow313/v4/aegisfortress/aegisfortress_omnisec.py`
Detector implementation lacks a traceable test

Remediation: Add known-positive, known-negative, malformed, empty, and boundary fixtures.

### [FAIL] S313-3cfb71292e - detectors `shadow313/v4/shadow313_master_os.py`
Detector implementation lacks a traceable test

Remediation: Add known-positive, known-negative, malformed, empty, and boundary fixtures.

### [FAIL] S313-512af8fe87 - detectors `shadow313_sdk/examples/aws_key_detector.py`
Detector implementation lacks a traceable test

Remediation: Add known-positive, known-negative, malformed, empty, and boundary fixtures.

### [FAIL] S313-e6802ec34f - imports `shadow313/tools/redteam/ghosthttp.py`
Local import target appears missing: shadow313.tools.base

Remediation: Correct the import or restore the missing module/package.

### [FAIL] S313-8ce9ad5b19 - imports `shadow313/v3/bridge/v3_adapter.py`
Local import target appears missing: shadow313.v3.ztas.hypervisor_attestation_bridge

Remediation: Correct the import or restore the missing module/package.

### [FAIL] S313-1f44d350d8 - imports `shadow313/v3/bridge/v3_adapter.py`
Local import target appears missing: shadow313.v3.countermeasures.continuous_eprocess_monitor

Remediation: Correct the import or restore the missing module/package.

### [FAIL] S313-d3c8c9c5f2 - imports `shadow313/v3/bridge/v3_adapter.py`
Local import target appears missing: shadow313.v3.lstm_detector

Remediation: Correct the import or restore the missing module/package.

### [FAIL] S313-c2da05e58f - imports `shadow313/v3/bridge/v3_adapter.py`
Local import target appears missing: shadow313.v3.incident_response

Remediation: Correct the import or restore the missing module/package.

### [FAIL] S313-10d7ac44ea - imports `shadow313/v3/bridge/v3_adapter.py`
Local import target appears missing: shadow313.v3.ztas.tpm_sealed_attestation

Remediation: Correct the import or restore the missing module/package.

### [FAIL] S313-785b890763 - secrets `.github/workflows/shadow313-api-validate.yml:21`
Possible hard-coded secret assigned to API_KEY

Evidence: `API_KEY=<redacted>`

Remediation: Remove it, rotate if real, and use environment or secret-manager injection.

### [FAIL] S313-82f3a77ffd - secrets `.github/workflows/shadow313-api-validate.yml:40`
Possible hard-coded secret assigned to api_key

Evidence: `api_key=<redacted>`

Remediation: Remove it, rotate if real, and use environment or secret-manager injection.

### [FAIL] S313-bcd30d1043 - secrets `docs/S313-Security-Coverage-Remediation-Roadmap.md:2`
Possible hard-coded secret assigned to token

Evidence: `token=<redacted>`

Remediation: Remove it, rotate if real, and use environment or secret-manager injection.

### [FAIL] S313-d549e5b480 - secrets `docs/S313-Security-Coverage-Remediation-Roadmap.md:90`
Possible hard-coded secret assigned to token

Evidence: `token=<redacted>`

Remediation: Remove it, rotate if real, and use environment or secret-manager injection.

### [FAIL] S313-0130cae638 - secrets `docs/S313-Security-Coverage-Remediation-Roadmap.md:91`
Possible hard-coded secret assigned to token

Evidence: `token=<redacted>`

Remediation: Remove it, rotate if real, and use environment or secret-manager injection.

### [FAIL] S313-4bcdc25ef5 - secrets `docs/S313-Security-Coverage-Remediation-Roadmap.md:92`
Possible hard-coded secret assigned to token

Evidence: `token=<redacted>`

Remediation: Remove it, rotate if real, and use environment or secret-manager injection.

### [FAIL] S313-03048c0110 - secrets `shadow313/v4/detection/zero_evasion/zero_evasion_countermeasure.py:18`
Possible hard-coded secret assigned to token

Evidence: `token=<redacted>`

Remediation: Remove it, rotate if real, and use environment or secret-manager injection.

### [FAIL] S313-14d901958d - secrets `shadow313/v4/detection/zero_evasion/zero_evasion_countermeasure.py:24`
Possible hard-coded secret assigned to token

Evidence: `token=<redacted>`

Remediation: Remove it, rotate if real, and use environment or secret-manager injection.

### [FAIL] S313-abf75b75de - secrets `shadow313/v4/detection/zero_evasion/zero_evasion_countermeasure.py:30`
Possible hard-coded secret assigned to token

Evidence: `token=<redacted>`

Remediation: Remove it, rotate if real, and use environment or secret-manager injection.

### [FAIL] S313-abb920c4cf - secrets `shadow313_sdk/models.py:38`
Possible hard-coded secret assigned to PRIVATE_KEY

Evidence: `PRIVATE_KEY=<redacted>`

Remediation: Remove it, rotate if real, and use environment or secret-manager injection.

### [FAIL] S313-9a9efdb22a - secrets `shadow313_sdk/models.py:39`
Possible hard-coded secret assigned to PASSWORD

Evidence: `PASSWORD=<redacted>`

Remediation: Remove it, rotate if real, and use environment or secret-manager injection.

### [FAIL] S313-830dbe39d7 - secrets `tests/unit/test_cicd.py:46`
Possible hard-coded secret assigned to API_KEY

Evidence: `API_KEY=<redacted>`

Remediation: Remove it, rotate if real, and use environment or secret-manager injection.

### [FAIL] S313-9e7659d122 - secrets `tests/unit/test_cicd.py:89`
Possible hard-coded secret assigned to password

Evidence: `password=<redacted>`

Remediation: Remove it, rotate if real, and use environment or secret-manager injection.

### [FAIL] S313-3d0a7ac3ca - secrets `tests/unit/test_explorer_repairs.py:60`
Possible hard-coded secret assigned to api_key

Evidence: `api_key=<redacted>`

Remediation: Remove it, rotate if real, and use environment or secret-manager injection.

### [FAIL] S313-d8a661ad78 - secrets `tests/unit/test_explorer_repairs.py:71`
Possible hard-coded secret assigned to api_key

Evidence: `api_key=<redacted>`

Remediation: Remove it, rotate if real, and use environment or secret-manager injection.

### [FAIL] S313-ae3b3f268d - secrets `tests/unit/v4/test_deepstash.py:64`
Possible hard-coded secret assigned to api_key

Evidence: `api_key=<redacted>`

Remediation: Remove it, rotate if real, and use environment or secret-manager injection.

### [FAIL] S313-67b9650d37 - secrets `tests/unit/v4/test_deepstash.py:74`
Possible hard-coded secret assigned to token

Evidence: `token=<redacted>`

Remediation: Remove it, rotate if real, and use environment or secret-manager injection.

### [FAIL] S313-a51ae88805 - secrets `tests/unit/v4/test_deepstash.py:101`
Possible hard-coded secret assigned to token

Evidence: `token=<redacted>`

Remediation: Remove it, rotate if real, and use environment or secret-manager injection.

### [FAIL] S313-6675cd80d2 - secrets `tests/unit/v4/test_deepstash.py:225`
Possible hard-coded secret assigned to token

Evidence: `token=<redacted>`

Remediation: Remove it, rotate if real, and use environment or secret-manager injection.

### [FAIL] S313-be57df3986 - secrets `tests/unit/v4/test_plugin_analyzer.py:58`
Possible hard-coded secret assigned to password

Evidence: `password=<redacted>`

Remediation: Remove it, rotate if real, and use environment or secret-manager injection.

### [FAIL] S313-eda0363b73 - secrets `tests/unit/v4/test_secrets_manager.py:347`
Possible hard-coded secret assigned to token

Evidence: `token=<redacted>`

Remediation: Remove it, rotate if real, and use environment or secret-manager injection.

### [FAIL] S313-b3eee014ad - secrets `tests/unit/v4/test_secrets_manager.py:376`
Possible hard-coded secret assigned to token

Evidence: `token=<redacted>`

Remediation: Remove it, rotate if real, and use environment or secret-manager injection.

### [FAIL] S313-b730a0303c - secrets `tests/unit/v4/test_secrets_manager.py:424`
Possible hard-coded secret assigned to token

Evidence: `token=<redacted>`

Remediation: Remove it, rotate if real, and use environment or secret-manager injection.

### [WARN] S313-ea7a23ddc1 - cli `shadow313/cli/main.py:225`
CLI command lacks a traceable test: threat-intel

Remediation: Add --help, valid invocation, invalid argument, and failure-path tests.

### [WARN] S313-5e83cb3ea4 - cli `shadow313/cli/main.py:245`
CLI command lacks a traceable test: crypto-agility

Remediation: Add --help, valid invocation, invalid argument, and failure-path tests.

### [WARN] S313-dc3ca6e30e - cli `shadow313/cli/main.py:287`
CLI command lacks a traceable test: mobile-api

Remediation: Add --help, valid invocation, invalid argument, and failure-path tests.

### [WARN] S313-4db8da7e47 - cli `shadow313/cli/main.py:292`
CLI command lacks a traceable test: browser-recon

Remediation: Add --help, valid invocation, invalid argument, and failure-path tests.

### [WARN] S313-85c3f6e4f0 - cli `shadow313/cli/main.py:297`
CLI command lacks a traceable test: container-scan

Remediation: Add --help, valid invocation, invalid argument, and failure-path tests.

### [WARN] S313-f46216ef7d - cli `shadow313/cli/main.py:302`
CLI command lacks a traceable test: ad-audit

Remediation: Add --help, valid invocation, invalid argument, and failure-path tests.

### [WARN] S313-178dad562c - cli `shadow313/cli/main.py:357`
CLI command lacks a traceable test: quantum-nexus

Remediation: Add --help, valid invocation, invalid argument, and failure-path tests.

### [WARN] S313-ace1787d75 - cli `shadow313/cli/main.py:384`
CLI command lacks a traceable test: threat-actor

Remediation: Add --help, valid invocation, invalid argument, and failure-path tests.

### [WARN] S313-86c05335c2 - cli `shadow313/cli/main.py:409`
CLI command lacks a traceable test: doctor

Remediation: Add --help, valid invocation, invalid argument, and failure-path tests.

### [WARN] S313-3d4580e635 - markers `docs/shadow313-file-portal.html:1234`
STUB marker found

Evidence: `<div class="item"><div class="item-title">🤖 Local AI Integration</div><div class="item-desc">Ollama integration with streaming token output. OpenAI-compatible API. Offline stub mode for air-gapped environments. System prompt injection for security context.</div></div>`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-c889497ea7 - markers `scripts/repository_completeness_audit.py:292`
FIXME marker found

Evidence: `sev = "WARN" if m.group(1).upper() in {"FIXME", "STUB", "NOT_IMPLEMENTED"} else "INFO"`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-e330d27a8f - markers `scripts/shadow313-html-auditor.ps1:5`
STUB marker found

Evidence: `Use -Fix to auto-create stub pages for missing routes.`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-f81f116e2f - markers `scripts/shadow313-html-auditor.ps1:63`
STUB marker found

Evidence: `Write-Host "Creating stub pages..." -ForegroundColor Cyan`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-edb6b5bea8 - markers `scripts/shadow313-html-auditor.ps1:68`
STUB marker found

Evidence: `$stub = @"`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-ba78173fcc - markers `scripts/shadow313-html-auditor.ps1:91`
STUB marker found

Evidence: `Set-Content (Join-Path $RepoRoot $m.File) $stub -Encoding UTF8`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-b766287e59 - markers `scripts/shadow313-html-auditor.ps1:92`
STUB marker found

Evidence: `Write-Host "  ✅ Created stub: $($m.File)" -ForegroundColor Green`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-df77995f35 - markers `scripts/shadow313-html-auditor.ps1:95`
STUB marker found

Evidence: `Write-Host "✅ $($missing.Count) stub pages created." -ForegroundColor Green`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-a36f567a76 - markers `shadow313/core/ai_engine/__init__.py:31`
STUB marker found

Evidence: `- "disabled" → returns stub messages (offline / CI mode)`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-5f23ba465f - markers `shadow313/modules/recon/recon.py:57`
STUB marker found

Evidence: `"""Use system resolver via socket for A records, stub others."""`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-120379985a - markers `shadow313/v2/agent/agent.py:320`
STUB marker found

Evidence: `# Graceful degradation — return stub`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-2f42b44cbf - markers `shadow313/v2/agent/agent.py:321`
STUB marker found

Evidence: `return {"status": "stub", "module": step.module,`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-447756201e - markers `shadow313/v4/agent/orchestrator.py:1168`
STUB marker found

Evidence: `# Generic tool — return structured stub`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-1d657c6adc - markers `shadow313/v4/detection/kernel_gap_hardening.py:13`
STUB marker found

Evidence: `GAP-KH-01  Direct syscall stub (Hell's Gate / Halo's Gate / SysWhispers3)`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-24ed3220b7 - markers `shadow313/v4/detection/kernel_gap_hardening.py:18`
STUB marker found

Evidence: `GAP-KH-06  VirtualAlloc RWX / RW→RX stub allocation`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-376ce029e8 - markers `shadow313/v4/detection/kernel_gap_hardening.py:71`
STUB marker found

Evidence: `# ── GAP-KH-01: Direct Syscall Stub Detector ───────────────────────────────────`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-4d500d7c14 - markers `shadow313/v4/detection/kernel_gap_hardening.py:80`
STUB marker found

Evidence: `2. Anonymous RX memory region containing syscall stub bytes`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-83a6157a2f - markers `shadow313/v4/detection/kernel_gap_hardening.py:92`
STUB marker found

Evidence: `# Syscall stub byte pattern: mov r10,rcx / mov eax,SSN / syscall / ret`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-dbbebe9b87 - markers `shadow313/v4/detection/kernel_gap_hardening.py:147`
STUB marker found

Evidence: `"""Detect syscall stub pattern in anonymous RX memory."""`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-b1631978e5 - markers `shadow313/v4/detection/kernel_gap_hardening.py:156`
STUB marker found

Evidence: `technique_name="Direct Syscall Stub in Anonymous RX Memory",`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-3703e50d23 - markers `shadow313/v4/detection/kernel_gap_hardening.py:159`
STUB marker found

Evidence: `cs_event="ETW-TI ALLOCVM + PROTECTVM fires on stub allocation",`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-7919880622 - markers `shadow313/v4/detection/kernel_gap_hardening.py:160`
STUB marker found

Evidence: `artifact=f"PID {pid}: syscall stub bytes (4C 8B D1 B8 ... 0F 05 C3) in anonymous RX region @ 0x{region_base:X}",`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-de891050a3 - markers `shadow313/v4/detection/kernel_gap_hardening.py:239`
STUB marker found

Evidence: `Frame 0 at ntdll+offset NOT matching known stub offsets.`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-6a21dab7d5 - markers `shadow313/v4/detection/kernel_gap_hardening.py:264`
STUB marker found

Evidence: `cs_event="ETW-TI call stack: Frame 0 at ntdll+offset not matching known stub — direct syscall via gadget",`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-7560b33b5d - markers `shadow313/v4/detection/kernel_gap_hardening.py:316`
STUB marker found

Evidence: `artifact=f"WoW64 PID {pid} ({entry['image']}): RX region at 0x{region_base:X} (64-bit range) — Heaven's Gate stub",`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-74cf8efc55 - markers `shadow313/v4/detection/kernel_gap_hardening.py:424`
STUB marker found

Evidence: `# ── GAP-KH-06: VirtualAlloc RWX / RW→RX Stub Allocation Detector ──────────────`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-3c0c44706d - markers `shadow313/v4/detection/kernel_gap_hardening.py:428`
STUB marker found

Evidence: `Detects VirtualAlloc patterns used for syscall stub construction.`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-6d2d1ced35 - markers `shadow313/v4/detection/kernel_gap_hardening.py:431`
STUB marker found

Evidence: `1. Small (<256 byte) RWX allocation — classic stub pattern`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-711d1ac31d - markers `shadow313/v4/detection/kernel_gap_hardening.py:433`
STUB marker found

Evidence: `3. Multiple small RX allocations in rapid succession (stub array)`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-5c0f4b6f30 - markers `shadow313/v4/detection/kernel_gap_hardening.py:454`
STUB marker found

Evidence: `technique_name="Syscall Stub — Small RWX Allocation",`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-b4839b1065 - markers `shadow313/v4/detection/kernel_gap_hardening.py:458`
STUB marker found

Evidence: `artifact=f"PID {pid}: {size}B RWX allocation @ 0x{base:X} — syscall stub construction",`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-548a7ac670 - markers `shadow313/v4/detection/kernel_gap_hardening.py:479`
STUB marker found

Evidence: `technique_name="Syscall Stub — RW→RX Protection Change on Small Region",`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-e9c8e0cc5c - markers `shadow313/v4/detection/kernel_gap_hardening.py:483`
STUB marker found

Evidence: `artifact=f"PID {pid}: {size}B region @ 0x{base:X} changed RW→RX within {self.PROTECT_WINDOW_S}s — syscall stub finalized",`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-d18bc9a78b - markers `shadow313/v4/detection/kernel_gap_hardening.py:932`
STUB marker found

Evidence: `signal (Sysmon Event 10 if Win32 API, or correlated with stub allocation).`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-205af94fea - markers `shadow313/v4/detection/kernel_gap_hardening.py:942`
STUB marker found

Evidence: `# Hardened: name-based list replaced with hash verification stub.`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-eaf0741b96 - markers `shadow313/v4/detection/kernel_gap_hardening.py:1225`
STUB marker found

Evidence: `patch_type = "NOP sled" if is_nop else ("RET stub" if is_ret else "XOR-RET stub")`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-51ffe062e3 - markers `shadow313/v4/intelligence/secrets_manager.py:237`
FIXME marker found

Evidence: `"fixme",`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-22a59290eb - markers `shadow313/v4/intelligence/secrets_manager.py:474`
STUB marker found

Evidence: `"""Retrieve secret from HashiCorp Vault (stub — real impl uses hvac)."""`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-1a85a85e50 - markers `tests/unit/test_tfidf.py:116`
STUB marker found

Evidence: `return "stub response"`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-50d81ab6a2 - markers `tests/unit/test_tfidf.py:144`
STUB marker found

Evidence: `assert answer == "stub response"`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-ce03a1e6ae - markers `tests/unit/v4/test_kernel_gap_hardening.py:34`
STUB marker found

Evidence: `# ── GAP-KH-01: Direct Syscall Stub ───────────────────────────────────────────`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-32015a2e62 - markers `tests/unit/v4/test_kernel_gap_hardening.py:71`
STUB marker found

Evidence: `# Construct realistic syscall stub bytes`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-b94511968c - markers `tests/unit/v4/test_kernel_gap_hardening.py:72`
STUB marker found

Evidence: `stub = bytes([0x4C, 0x8B, 0xD1,        # mov r10, rcx`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-b70a82de1c - markers `tests/unit/v4/test_kernel_gap_hardening.py:76`
STUB marker found

Evidence: `alert = det.detect_stub_in_memory(9999, 0x1A000000, stub,`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-e84acf6d8f - markers `tests/unit/v4/test_kernel_gap_hardening.py:80`
STUB marker found

Evidence: `assert "syscall" in alert.artifact.lower() or "stub" in alert.artifact.lower()`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-037d58e779 - markers `tests/unit/v4/test_kernel_gap_hardening.py:84`
STUB marker found

Evidence: `stub = bytes([0x4C, 0x8B, 0xD1, 0xB8, 0x26, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3])`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-b8091c3884 - markers `tests/unit/v4/test_kernel_gap_hardening.py:85`
STUB marker found

Evidence: `alert = det.detect_stub_in_memory(9999, 0x7FF000000, stub,`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-ef5c340420 - markers `tests/unit/v4/test_kernel_gap_hardening.py:93`
STUB marker found

Evidence: `assert alert is None  # Too large for a stub, no stub pattern`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-1de6fba884 - markers `tests/unit/v4/test_kernel_gap_hardening.py:273`
STUB marker found

Evidence: `# ── GAP-KH-06: Stub Allocation ───────────────────────────────────────────────`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-78d6e94475 - markers `tests/unit/v4/test_kernel_gap_hardening.py:290`
STUB marker found

Evidence: `assert alert is None  # Too large for a stub`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-d2e81b9ce2 - markers `tests/unit/v4/test_kernel_gap_hardening.py:559`
STUB marker found

Evidence: `# Step 3: VirtualAlloc for stub (RWX)`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-e86603c9d0 - markers `tests/unit/v4/test_kernel_gap_hardening.py:562`
STUB marker found

Evidence: `# Step 4: VirtualProtect RW→RX (alternative stub construction)`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-5fe478d124 - markers `tests/unit/v4/test_kernel_gap_hardening.py:901`
STUB marker found

Evidence: `# Step 09: Syscall stub bytes in anonymous RX`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-5cc1cc0fdb - markers `tests/unit/v4/test_kernel_gap_hardening.py:902`
STUB marker found

Evidence: `stub = bytes([0x4C, 0x8B, 0xD1, 0xB8, 0x26, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3])`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-e90da805c1 - markers `tests/unit/v4/test_kernel_gap_hardening.py:904`
STUB marker found

Evidence: `stub, anonymous=True, rx=True)`

Remediation: Resolve or link to a tracked issue before release.

### [WARN] S313-779b9f5dd7 - packaging `conftest.py`
Root conftest.py modifies sys.path and may mask wheel omissions

Remediation: Add a clean-wheel test in an isolated environment outside the repository.

### [WARN] S313-6d6809afc5 - test-coverage `nexus_toolkit/engine_v2.py`
No traceable test found for source module

Remediation: Add a behavioral unit or integration test and reference the module directly.

### [WARN] S313-11ea36d2ad - test-coverage `nexus_toolkit/soar/playbook_engine.py`
No traceable test found for source module

Remediation: Add a behavioral unit or integration test and reference the module directly.

### [WARN] S313-431631782b - test-coverage `shadow313/api/middleware.py`
No traceable test found for source module

Remediation: Add a behavioral unit or integration test and reference the module directly.

### [WARN] S313-fb0999541b - test-coverage `shadow313/core/plugin_manager.py`
No traceable test found for source module

Remediation: Add a behavioral unit or integration test and reference the module directly.

### [WARN] S313-8ced304198 - test-coverage `shadow313/core/session_store.py`
No traceable test found for source module

Remediation: Add a behavioral unit or integration test and reference the module directly.

### [WARN] S313-df983e5bc4 - test-coverage `shadow313/modules/docs/ai_docs.py`
No traceable test found for source module

Remediation: Add a behavioral unit or integration test and reference the module directly.

### [WARN] S313-8d2a09f80e - test-coverage `shadow313/quantum_middleware.py`
No traceable test found for source module

Remediation: Add a behavioral unit or integration test and reference the module directly.

### [WARN] S313-539b2c1931 - test-coverage `shadow313/temporal313.py`
No traceable test found for source module

Remediation: Add a behavioral unit or integration test and reference the module directly.

### [WARN] S313-e1e50d5008 - test-coverage `shadow313/thought_engine.py`
No traceable test found for source module

Remediation: Add a behavioral unit or integration test and reference the module directly.

### [WARN] S313-3a194ecb82 - test-coverage `shadow313/v2/campaign/campaign_manager.py`
No traceable test found for source module

Remediation: Add a behavioral unit or integration test and reference the module directly.

### [WARN] S313-77557029cb - test-coverage `shadow313/v2/cloud_hardening/cloud_hardening.py`
No traceable test found for source module

Remediation: Add a behavioral unit or integration test and reference the module directly.

### [WARN] S313-00a277b7a1 - test-coverage `shadow313/v2/crypto_agility/crypto_agility.py`
No traceable test found for source module

Remediation: Add a behavioral unit or integration test and reference the module directly.

### [WARN] S313-599047ed4f - test-coverage `shadow313/v2/reports/pdf_report.py`
No traceable test found for source module

Remediation: Add a behavioral unit or integration test and reference the module directly.

### [WARN] S313-4df673d0b0 - test-coverage `shadow313/v2/vuln_upgrades/attack_mapping.py`
No traceable test found for source module

Remediation: Add a behavioral unit or integration test and reference the module directly.

### [WARN] S313-4b464257c4 - test-coverage `shadow313/v4/aegis/csbom_auditor.py`
No traceable test found for source module

Remediation: Add a behavioral unit or integration test and reference the module directly.

### [WARN] S313-99447c5bff - test-coverage `shadow313/v4/aegisfortress/aegisfortress_omnisec.py`
No traceable test found for source module

Remediation: Add a behavioral unit or integration test and reference the module directly.

### [WARN] S313-84aba5601c - test-coverage `shadow313/v4/shadow313_master_os.py`
No traceable test found for source module

Remediation: Add a behavioral unit or integration test and reference the module directly.

### [WARN] S313-91942ce123 - test-coverage `shadow313_sdk/examples/aws_key_detector.py`
No traceable test found for source module

Remediation: Add a behavioral unit or integration test and reference the module directly.

### [WARN] S313-137438bc58 - test-coverage `shadow313_sdk/testing/factories.py`
No traceable test found for source module

Remediation: Add a behavioral unit or integration test and reference the module directly.

### [WARN] S313-e99c642526 - versioning
Multiple active semantic versions found: 0.0.0, 0.0.6, 0.10.2, 0.116.1, 0.14.0, 0.14.1, 0.21.0, 0.27.0, 0.29.0, 0.34.2, 0.35.0, 0.4.4, 0.47.3, 0.5.0, 0.7.1, 0.8.0, 0.8.1, 0.9.0, 1.0.0, 1.0.3, 1.1.0, 1.1.1, 1.1.18, 1.18.0, 1.2.0, 1.2.3, 1.2.4, 1.2.840, 1.24.0, 1.3.0, 1.3.1, 1.35.0, 1.35.1, 1.4.0, 1.5.0, 1.6.1, 1.6.2, 1.6.3, 1.7.8, 1.8.0, 1.8.2, 1.8.31, 1.9.0, 1.9.1, 1.9.10, 1.9.4, 1.9.5, 10.0.0, 10.0.1, 10.0.10, 10.0.2, 10.0.20, 10.0.3, 10.0.30, 10.0.4, 10.0.5, 10.100.0, 10.13.13, 10.255.255, 10.50.10, 10.50.2, 10.8.0, 104.21.0, 11.3.0, 113556.1.4, 12.18.254, 127.0.0, 13.0.0, 13.7.0, 13.7.1, 142.110.4, 142.250.80, 149.112.112, 164.50.11, 169.254.169, 169.254.170, 172.16.0, 172.19.0, 172.20.0, 172.20.1, 172.21.0, 172.31.255, 18.23.45, 185.1.1, 185.12.89, 185.190.140, 185.2.2, 185.220.100, 185.220.101, 185.3.3, 185.4.4, 185.5.5, 192.0.2, 192.168.0, 192.168.1, 192.168.100, 192.168.12, 192.168.140, 192.168.255, 192.168.99, 194.165.16, 194.26.29, 198.51.100, 2.0.0, 2.0.1, 2.1.0, 2.1.1, 2.1.6, 2.12.1, 2.13.0, 2.14.1, 2.2.0, 2.2.2, 2.2.3, 2.25.0, 2.28.0, 2.3.0, 2.3.1, 2.3.3, 2.3.30, 2.3.31, 2.3.5, 2.3.7, 2.32.4, 2.32.5, 2.33.0, 2.4.0, 2.4.49, 2.5.0, 2.5.10, 2.7.0, 2.7.3, 2.9.1, 20.19.0, 2026.3.3, 203.0.113, 208.67.222, 22.110.43, 22.140.92, 24.3.0, 24.3.1, 29.0.0, 29.7.2, 3.0.0, 3.1.0, 3.1.3, 3.11.2, 3.11.9, 3.13.12, 3.13.4, 3.14.1, 3.2.0, 3.2.1, 3.3.1, 3.4.1, 3.4.2, 3.4.3, 3.4.4, 3.5.0, 3.5.1, 3.8.1, 3.9.9, 36.232.34, 38.0.0, 38.0.1, 38.0.2, 38.0.3, 38.0.4, 38.104.0, 4.0.0, 4.0.1, 4.0.2, 4.0.3, 4.0.4, 4.0.5, 4.1.0, 4.17.21, 4.18.0, 4.39.1, 4.5.0, 4.6.0, 4.6.1, 4.68.0, 4.7.2, 42.0.0, 45.0.7, 45.110.12, 45.138.16, 45.142.212, 45.154.255, 45.33.2, 46.0.5, 5.0.0, 5.1.0, 5.15.15, 5.15.16, 5.16.7, 5.17.6, 5.18.3, 5.2.0, 5.2.1, 5.2.20, 5.2.4, 5.3.17, 5.3.18, 5.4.1, 5.4.4, 58.150.125, 6.0.0, 6.0.1, 6.0.3, 6.1.11, 6.1.13, 6.2.1, 6.2.2, 6.2.6, 6.4.0, 6.5.0, 6.5.5, 6.6.0, 62.115.0, 69.167.137, 7.0.1, 7.1.0, 7.4.0, 8.1.0, 8.1.8, 8.18.4, 8.2.1, 8.3.3, 8.8.4, 8.8.8, 9.0.0, 9.0.1, 9.9.9, 91.1.1, 91.108.4, 91.207.175, 91.242.162, 93.184.216, 94.140.14, 99.0.0

Remediation: Use one canonical version source and generate other current-version references.

### [INFO] S313-45da3677f7 - markers `docs/project-roadmap.html:419`
TODO marker found

Evidence: `<span style="font-size:12px;font-weight:700;color:#64748b;">notes/ and todo.md Gitignore</span>`

Remediation: Resolve or link to a tracked issue before release.

### [INFO] S313-094022e0f3 - markers `docs/project-roadmap.html:422`
TODO marker found

Evidence: `<div style="font-size:10px;color:#94a3b8;line-height:1.6;margin-bottom:6px;">Add notes/, todo.md, dist/ to .gitignore. Remove from git tracking with git rm --cached. These expose internal roadmap and task tracking to anyone watching the repo.</div>`

Remediation: Resolve or link to a tracked issue before release.

### [INFO] S313-789a9e370b - markers `docs/project-roadmap.html:426`
TODO marker found

Evidence: `<span style="font-size:9px;color:#475569;background:rgba(0,0,0,0.3);padding:2px 7px;border-radius:3px;">Status: notes/ and todo.md committed to public repo</span>`

Remediation: Resolve or link to a tracked issue before release.

### [INFO] S313-acd0cfc7ac - markers `docs/project-roadmap.html:449`
TODO marker found

Evidence: `const ROADMAP = {"P0_critical": [{"id": "P0-01", "title": "Full T24 Credential Hygiene Program", "category": "Security", "effort": "72h / $1.4M", "impact": "Closes Arch-E back door \u2014 prevents $7.38B loss", "status": "Documented, not deployed", "details": "Unique admin credentials per institution + MFA + consortium server segmentation + Vault integration. Closes all 6 credential hygiene failures (CF-01 through CF-06). Without this, surgical top-5 hardening is 86% ineffective against adaptive`

Remediation: Resolve or link to a tracked issue before release.

### [INFO] S313-6df51d0772 - markers `docs/web3_security_explorer.html:267`
HACK marker found

Evidence: `{ name: "Phalcon", category: "Sim", desc: "Visual transaction simulator. Fork any real hack and modify state to research vulnerabilities.", level: "Advanced" },`

Remediation: Resolve or link to a tracked issue before release.

### [INFO] S313-5f87eacc7b - markers `scripts/collect_and_zip.py:111`
TODO marker found

Evidence: `"todo.md",`

Remediation: Resolve or link to a tracked issue before release.

### [INFO] S313-905e173641 - markers `scripts/repository_completeness_audit.py:41`
TODO marker found

Evidence: `MARKER_RE = re.compile(r"\b(TODO|FIXME|XXX|HACK|STUB|NOT_IMPLEMENTED)\b", re.I)`

Remediation: Resolve or link to a tracked issue before release.

### [INFO] S313-eda6558864 - markers `scripts/repository_completeness_audit.py:452`
TODO marker found

Evidence: `f"- TODO/FIXME/STUB markers: {summary['marker_count']}", "",`

Remediation: Resolve or link to a tracked issue before release.

### [INFO] S313-4329d1d50b - markers `shadow313/v4/agent/orchestrator.py:335`
HACK marker found

Evidence: `"security":    ["cve","vuln","exploit","recon","scan","pentest","threat","malware","attack","breach","hack"],`

Remediation: Resolve or link to a tracked issue before release.

### [INFO] S313-6c15cd3468 - markers `shadow313/v4/detection/crypto_hardening_audit.py:64`
HACK marker found

Evidence: `- ECDSA nonce bias → private key recovery (PS3 hack, 2010)`

Remediation: Resolve or link to a tracked issue before release.

### [INFO] S313-42da6c895c - markers `shadow313/v4/detection/webshell_detector.py:194`
HACK marker found

Evidence: `r"/(?:shell|cmd|exec|backdoor|hack|pwn)\.",`

Remediation: Resolve or link to a tracked issue before release.

### [INFO] S313-9b7701a0d1 - markers `shadow313/v4/intelligence/secrets_manager.py:236`
TODO marker found

Evidence: `"todo",`

Remediation: Resolve or link to a tracked issue before release.

### [INFO] S313-a3f0219975 - markers `shadow313/v4/simulation/global_threat_simulation.py:172`
HACK marker found

Evidence: `notable_campaigns=["DNC hack","Olympic doping agency","Ukraine targeting"],`

Remediation: Resolve or link to a tracked issue before release.

### [INFO] S313-472f2a7f28 - markers `shadow313/v4/threat_actor/threat_actor.py:92`
HACK marker found

Evidence: `"campaigns":   ["DNC hack (2016)","Olympic Anti-Doping Agency (2016)","Bundestag hack (2015)"],`

Remediation: Resolve or link to a tracked issue before release.

### [INFO] S313-ba11a840b6 - structure `nexus_toolkit/soar`
Python directory has no __init__.py (namespace package or omission)

Remediation: Confirm namespace-package intent; otherwise add __init__.py.

## Output files

- `repository-audit.json`
- `findings.csv`
- `api-endpoints.csv`
- `cli-surfaces.csv`
- `module-inventory.csv`
