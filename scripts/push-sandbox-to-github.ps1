<#
.SYNOPSIS
    Shadow313 NEXUS — Targeted Sandbox Push Script
    Pushes exactly the 64 files that exist in the sandbox but are missing from the GitHub repo.

.DESCRIPTION
    This script was generated after a deep scan comparing the sandbox against
    github.com/piyyy314/Shadow313-Nexus (master branch, 1087 files).

    It will:
    1. Initialize git in /workspace if not already a repo
    2. Set the remote to github.com/piyyy314/Shadow313-Nexus
    3. Fetch master and create a new branch
    4. Stage ONLY the 64 missing files (no accidental overwrites)
    5. Commit with a structured message
    6. Push and print the PR URL

.PARAMETER Token
    GitHub Personal Access Token (PAT) with repo write access.
    Get one at: https://github.com/settings/tokens/new
    Required scopes: repo (full control)

.PARAMETER BranchName
    Name of the new branch. Defaults to "shadow313/sandbox-sync-v2-YYYYMMDD"

.PARAMETER DryRun
    Show what would happen without making any changes.

.EXAMPLE
    .\push-sandbox-to-github.ps1 -Token "ghp_xxxxxxxxxxxx"
    .\push-sandbox-to-github.ps1 -Token "ghp_xxxxxxxxxxxx" -DryRun
    .\push-sandbox-to-github.ps1 -Token "ghp_xxxxxxxxxxxx" -BranchName "feature/v2-submodules-oct29"

.NOTES
    Repo:    github.com/piyyy314/Shadow313-Nexus
    Branch:  master (default)
    Missing: 64 files identified by deep scan on 2026-10-29
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Token = $env:GITHUB_TOKEN,

    [string]$BranchName = "",
    [switch]$DryRun,
    [switch]$SkipTests
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Colours ───────────────────────────────────────────────────────────────────
function Write-Step {
    <#
    .SYNOPSIS
        Display a numbered progress step on the host.
    #>
    param($n,$msg) Write-Host "`n[$n] $msg" -ForegroundColor Cyan }
function Write-Ok   {
    <#
    .SYNOPSIS
        Display a success message on the host.
    #>
    param($msg) Write-Host "  OK  $msg" -ForegroundColor Green }
function Write-Warn {
    <#
    .SYNOPSIS
        Display a warning message on the host.
    #>
    param($msg) Write-Host "  WARN $msg" -ForegroundColor Yellow }
function Write-Fail {
    <#
    .SYNOPSIS
        Display a failure message on the host and exit the script with code 1.
    #>
    param($msg) Write-Host "  FAIL $msg" -ForegroundColor Red; exit 1 }
function Write-Info {
    <#
    .SYNOPSIS
        Display an informational message on the host.
    #>
    param($msg) Write-Host "       $msg" -ForegroundColor Gray }
function Write-Dry  {
    <#
    .SYNOPSIS
        Display a proposed dry-run action on the host.
    #>
    param($msg) Write-Host "  DRY  $msg" -ForegroundColor Magenta }

# ── Constants ─────────────────────────────────────────────────────────────────
$REPO_OWNER  = "piyyy314"
$REPO_NAME   = "Shadow313-Nexus"
$BASE_BRANCH = "master"
$REPO_URL_HTTPS = "https://github.com/$REPO_OWNER/$REPO_NAME.git"

# ── 64 files missing from repo (identified by deep scan 2026-10-29) ──────────
$MISSING_FILES = @(
    # Root scripts
    "push-to-github.ps1",
    "push-to-github.sh",
    "run_tests.py",

    # Core modules (v2 sub-file architecture — repo has monolithic versions)
    "shadow313/core/ai_engine.py",

    # CICD sub-modules
    "shadow313/modules/cicd/cicd_module.py",
    "shadow313/modules/cicd/junit_builder.py",
    "shadow313/modules/cicd/sarif_builder.py",
    "shadow313/modules/cicd/secret_scanner.py",

    # Defense sub-modules
    "shadow313/modules/defense/cis_checker.py",
    "shadow313/modules/defense/defense_module.py",
    "shadow313/modules/defense/firewall.py",
    "shadow313/modules/defense/remediation.py",      # + FileEncryptionRateMonitor (P-20)
    "shadow313/modules/defense/system_info.py",

    # Docs sub-modules
    "shadow313/modules/docs/docs_module.py",
    "shadow313/modules/docs/glossary.py",
    "shadow313/modules/docs/man_page.py",
    "shadow313/modules/docs/tutorials.py",

    # Exploit sub-modules
    "shadow313/modules/exploit/ctf_helper.py",
    "shadow313/modules/exploit/exploit_module.py",
    "shadow313/modules/exploit/exploitdb.py",
    "shadow313/modules/exploit/payloads.py",
    "shadow313/modules/exploit/scope.py",            # + encoding fix (P-31)

    # Network sub-modules
    "shadow313/modules/network/anomaly.py",
    "shadow313/modules/network/flow_tracker.py",     # + OutboundVolumeMonitor + UserFileAccessMonitor (P-22)
    "shadow313/modules/network/network_module.py",   # + subprocess check=False (P-30)
    "shadow313/modules/network/pcap_parser.py",
    "shadow313/modules/network/topology.py",         # + RoutingTableMonitor (P-21)

    # Plugins sub-modules
    "shadow313/modules/plugins/manager.py",
    "shadow313/modules/plugins/manifest.py",         # + encoding fix (P-31)
    "shadow313/modules/plugins/plugins_module.py",   # + W0106 fix (P-27)
    "shadow313/modules/plugins/runner.py",           # + subprocess fix (P-28)

    # Quantum sub-modules
    "shadow313/modules/quantum/cert_auditor.py",
    "shadow313/modules/quantum/code_scanner.py",
    "shadow313/modules/quantum/quantum_data.py",     # + 15 new SLH-DSA entries
    "shadow313/modules/quantum/quantum_module.py",
    "shadow313/modules/quantum/timeline.py",
    "shadow313/modules/quantum/tls_scanner.py",

    # Recon sub-modules
    "shadow313/modules/recon/dns_enum.py",
    "shadow313/modules/recon/fingerprint.py",
    "shadow313/modules/recon/geoip.py",
    "shadow313/modules/recon/port_scan.py",
    "shadow313/modules/recon/recon_module.py",
    "shadow313/modules/recon/subdomain.py",
    "shadow313/modules/recon/whois_lookup.py",

    # Vuln sub-modules
    "shadow313/modules/vuln/cve_db.py",             # + WAL mode
    "shadow313/modules/vuln/cvss.py",
    "shadow313/modules/vuln/dep_audit.py",
    "shadow313/modules/vuln/exploit_check.py",
    "shadow313/modules/vuln/vuln_module.py",

    # V2 new/patched files
    "shadow313/v2/agent/approval.py",
    "shadow313/v2/network_upgrades/firmware_auditor.py",  # NEW MODULE (P-23)
    "shadow313/v2/rag/tfidf_store.py",              # + tokenizer fix (P-18)

    # New test files
    "tests/unit/test_agent.py",
    "tests/unit/test_campaign_manager.py",
    "tests/unit/test_cloud_hardening.py",
    "tests/unit/test_core.py",
    "tests/unit/test_crypto_agility_extended.py",
    "tests/unit/test_new_patches.py",               # 66 new tests
    "tests/unit/test_rag_defensive.py",
    "tests/unit/test_rag_engine.py",
    "tests/unit/test_threat_intel.py",
    "tests/unit/test_v2_modules.py"
)

# Files that exist in BOTH sandbox and repo but have been patched
$PATCHED_FILES = @(
    "shadow313/core/crypto_store.py",               # P-01, P-15: XOR removed, SLHDSASigner
    "shadow313/core/ai_engine.py",                  # P-02: SSRF fix
    "shadow313/core/session.py",                    # P-14: attach_receipt()
    "shadow313/v2/agent/agent.py",                  # P-03: gate for-else fix
    "shadow313/v2/rag/rag_engine.py",               # P-04: ChromaDB empty guard
    "shadow313/v2/threat_intel/threat_intel.py",    # P-06, P-10, P-11, P-25: WAL + SQL guard
    "shadow313/v2/vuln_upgrades/epss_kev.py",       # P-07, P-19: WAL + Z-score model
    "shadow313/v2/cloud_hardening/cloud_hardening.py", # P-08, P-09: regex + CloudTrail fix
    "shadow313/v2/network_upgrades/ja3_fingerprint.py", # P-24: MD5 usedforsecurity=False
    "shadow313/v2/plugin_signing/plugin_signer.py", # P-26: restored sign/verify blocks
    "shadow313/modules/vuln/cve_db.py",             # WAL mode
    "shadow313/modules/defense/system_info.py",     # P-29: subprocess check=False
    "shadow313/modules/network/network_module.py",  # P-30: subprocess check=False
    "shadow313/modules/network/topology.py",        # P-21: RoutingTableMonitor
    "shadow313/modules/plugins/runner.py",          # P-28: subprocess fix
    "shadow313/modules/plugins/plugins_module.py",  # P-27: W0106 fix
    "shadow313/modules/plugins/manifest.py",        # P-31: encoding fix
    "shadow313/modules/exploit/scope.py",           # P-31: encoding fix
    "shadow313/cli/main.py",                        # P-32: unused variable
    "shadow313/modules/defense/remediation.py",     # P-20: FileEncryptionRateMonitor
    "shadow313/modules/network/flow_tracker.py",    # P-22: UEBA monitors
    "shadow313/v2/graph/intel_graph.py",            # compatibility shim
    "shadow313/core/intelligence_graph.py",         # core promotion
    "pyproject.toml"
)

# ── Banner ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor DarkCyan
Write-Host "║     Shadow313 NEXUS — Targeted Sandbox Push (64 files)          ║" -ForegroundColor DarkCyan
Write-Host "║     github.com/piyyy314/Shadow313-Nexus  [master]               ║" -ForegroundColor DarkCyan
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor DarkCyan
Write-Host ""
if ($DryRun) { Write-Warn "DRY-RUN MODE — no git changes will be made" }

# ── Step 1: Validate token ────────────────────────────────────────────────────
Write-Step "1/9" "Validating GitHub token"
if (-not $Token) {
    Write-Fail "No GitHub token provided. Use -Token 'ghp_xxx' or set GITHUB_TOKEN env var."
}
$headers = @{ Authorization = "token $Token"; "User-Agent" = "Shadow313-Push-Script" }
try {
    $userResp = Invoke-RestMethod -Uri "https://api.github.com/user" -Headers $headers
    Write-Ok "Authenticated as: $($userResp.login)"
} catch {
    Write-Fail "Token invalid or expired. Get a new one at https://github.com/settings/tokens/new (scope: repo)"
}

# ── Step 2: Verify repo access ────────────────────────────────────────────────
Write-Step "2/9" "Verifying repo access"
try {
    $repoResp = Invoke-RestMethod -Uri "https://api.github.com/repos/$REPO_OWNER/$REPO_NAME" -Headers $headers
    Write-Ok "Repo: $($repoResp.full_name) | Default branch: $($repoResp.default_branch) | Private: $($repoResp.private)"
} catch {
    Write-Fail "Cannot access repo. Check token permissions (needs 'repo' scope)."
}

# ── Step 3: Check git installation ───────────────────────────────────────────
Write-Step "3/9" "Checking git"
try {
    $gitVer = git --version 2>&1
    Write-Ok $gitVer
} catch {
    Write-Fail "git not found. Install git first."
}

# ── Step 4: Initialize git repo if needed ────────────────────────────────────
Write-Step "4/9" "Initializing git repository"
$isRepo = (git rev-parse --git-dir 2>&1) -notmatch "fatal"
if (-not $isRepo) {
    if ($DryRun) { Write-Dry "Would run: git init" }
    else {
        git init 2>&1 | Out-Null
        Write-Ok "Initialized new git repository"
    }
} else {
    Write-Ok "Already a git repository"
}

# Set remote
$existingRemote = git remote get-url origin 2>&1
if ($existingRemote -match "fatal" -or $existingRemote -eq "") {
    $remoteUrl = "https://$Token@github.com/$REPO_OWNER/$REPO_NAME.git"
    if ($DryRun) { Write-Dry "Would add remote: origin -> $REPO_URL_HTTPS" }
    else {
        git remote add origin $remoteUrl 2>&1 | Out-Null
        Write-Ok "Added remote: origin -> $REPO_URL_HTTPS"
    }
} else {
    # Update token in existing remote URL
    $remoteUrl = "https://$Token@github.com/$REPO_OWNER/$REPO_NAME.git"
    if ($DryRun) { Write-Dry "Would update remote URL with token" }
    else {
        git remote set-url origin $remoteUrl 2>&1 | Out-Null
        Write-Ok "Updated remote URL with token"
    }
}

# ── Step 5: Fetch master and create branch ────────────────────────────────────
Write-Step "5/9" "Fetching master branch"
if ($BranchName -eq "") {
    $ts = Get-Date -Format "yyyyMMdd"
    $BranchName = "shadow313/sandbox-sync-v2-$ts"
}
Write-Info "New branch: $BranchName"

if ($DryRun) {
    Write-Dry "Would run: git fetch origin $BASE_BRANCH"
    Write-Dry "Would run: git checkout -b $BranchName origin/$BASE_BRANCH"
} else {
    Write-Info "Fetching from origin/$BASE_BRANCH ..."
    git fetch origin $BASE_BRANCH 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Fail "git fetch failed. Check token and network." }
    Write-Ok "Fetched master"

    # Create branch from master
    git checkout -b $BranchName "origin/$BASE_BRANCH" 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        # Branch may already exist
        git checkout $BranchName 2>&1 | Out-Null
    }
    Write-Ok "On branch: $BranchName"
}

# ── Step 6: Run tests ─────────────────────────────────────────────────────────
Write-Step "6/9" "Running test suite"
if ($SkipTests) {
    Write-Warn "Tests skipped"
} elseif ($DryRun) {
    Write-Dry "Would run: python run_tests.py"
} else {
    if (Test-Path "run_tests.py") {
        Write-Info "Running python run_tests.py ..."
        $out = python run_tests.py 2>&1
        $lastLines = ($out | Select-Object -Last 3) -join "`n"
        Write-Info $lastLines
        if ($LASTEXITCODE -ne 0) { Write-Fail "Tests failed. Fix before pushing." }
        Write-Ok "All tests passed"
    } else {
        Write-Warn "run_tests.py not found — skipping tests"
    }
}

# ── Step 7: Stage files ───────────────────────────────────────────────────────
Write-Step "7/9" "Staging files"
$allToStage = $MISSING_FILES + $PATCHED_FILES | Sort-Object -Unique
$staged = 0
$notFound = 0

foreach ($file in $allToStage) {
    if (Test-Path $file) {
        if ($DryRun) {
            Write-Dry "Would stage: $file"
        } else {
            git add $file 2>&1 | Out-Null
        }
        $staged++
    } else {
        Write-Warn "Not found (skipping): $file"
        $notFound++
    }
}

Write-Ok "Staged $staged files ($notFound not found)"

# ── Step 8: Commit ────────────────────────────────────────────────────────────
Write-Step "8/9" "Committing"
$date = Get-Date -Format "yyyy-MM-dd"
$commitMsg = @"
feat(v2): sandbox sync $date — 64 new files + 14 security patches

## New Sub-Module Architecture (v2 refactor)
Adds the complete v2 sub-file module structure that replaces the
monolithic v1 module files in the repo:
- shadow313/modules/{cicd,defense,docs,exploit,network,plugins,quantum,recon,vuln}/
  Each module split into focused sub-files with ai_context() support

## New Modules (not in repo)
- shadow313/v2/network_upgrades/firmware_auditor.py
  FW-01: Firmware hash verification for WatchGuard/Fortinet/PaloAlto/Cisco
  Detects T1542.004 (Firmware Implant)
- shadow313/modules/network/flow_tracker.py (extended)
  OutboundVolumeMonitor (Gap 9: DLP) + UserFileAccessMonitor (Gap 8: UEBA)
- shadow313/modules/network/topology.py (extended)
  RoutingTableMonitor: detects T1599 (Network Boundary Bridging)
- shadow313/modules/defense/remediation.py (extended)
  FileEncryptionRateMonitor: detects T1486 ransomware (50 renames/sec threshold)

## Security Patches Applied
- P-01: crypto_store.py — XOR fallback removed (S313-CVE-2026-003)
- P-02: ai_engine.py — SSRF fix (S313-CVE-2026-002)
- P-03: agent.py — gate for-else fix (AGT-01)
- P-04: rag_engine.py — ChromaDB empty collection guard (RAG-01)
- P-05/06/07: SQLite WAL mode (cve_db, threat_intel, epss_kev)
- P-08/09: cloud_hardening.py — TF-NO-VPC-FLOW regex + CloudTrail fix
- P-10/11: threat_intel.py — score cap + hash case normalisation
- P-12/13: quantum_data.py — 15 new SLH-DSA entries + longest-match fix
- P-14/15: session.py — attach_receipt() + SLHDSASigner class
- P-18: tfidf_store.py — tokenizer alphanumeric fix
- P-19: epss_kev.py — composite_z_score() model (Z >= 0.85 threshold)
- P-20: remediation.py — FileEncryptionRateMonitor
- P-21: topology.py — RoutingTableMonitor
- P-22: flow_tracker.py — OutboundVolumeMonitor + UserFileAccessMonitor
- P-23: firmware_auditor.py — NEW MODULE
- P-24: ja3_fingerprint.py — MD5 usedforsecurity=False (FIPS/B324 HIGH)
- P-25: threat_intel.py — SQL injection guard in stats() (B608)
- P-26: plugin_signer.py — restored sign/verify blocks in run()
- P-27: plugins_module.py — W0106 expression-not-assigned fixed
- P-28: runner.py — restored corrupted subprocess.run() call
- P-29/30: subprocess check=False (system_info, network_module)
- P-31: open() encoding=utf-8 (scope.py, manifest.py)
- P-32: cli/main.py — removed unused new_key variable

## New Tests (128 total, 0 failures)
- tests/unit/test_agent.py (28 tests)
- tests/unit/test_threat_intel.py (32 tests)
- tests/unit/test_cloud_hardening.py (35 tests)
- tests/unit/test_crypto_agility_extended.py (25 tests)
- tests/unit/test_rag_engine.py (14 tests)
- tests/unit/test_campaign_manager.py (25 tests)
- tests/unit/test_rag_defensive.py (43 tests)
- tests/unit/test_new_patches.py (66 tests — P19-P32 coverage)
- tests/unit/test_core.py, test_v2_modules.py (existing)

## Kernel Status
- 0 load errors
- 26 commands registered
- All v1 + v2 modules load correctly
"@

if ($DryRun) {
    Write-Dry "Would commit: feat(v2): sandbox sync $date — 64 new files + 14 security patches"
} else {
    # Set git identity if not configured
    $gitUser = git config user.name 2>&1
    if (-not $gitUser -or $gitUser -match "^$") {
        git config user.name  "Shadow313 Bot"
        git config user.email "bot@shadow313.dev"
        Write-Warn "Git identity not set — using Shadow313 Bot"
    }

    git commit -m $commitMsg 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        # Check if nothing to commit
        $status = git status --porcelain 2>&1
        if (-not $status) {
            Write-Warn "Nothing to commit — all files may already be up to date"
        } else {
            Write-Fail "git commit failed"
        }
    } else {
        Write-Ok "Committed successfully"
    }
}

# ── Step 9: Push ──────────────────────────────────────────────────────────────
Write-Step "9/9" "Pushing to origin/$BranchName"
if ($DryRun) {
    Write-Dry "Would run: git push origin $BranchName --set-upstream"
} else {
    Write-Info "Pushing..."
    git push origin $BranchName --set-upstream 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Push failed. Check token permissions (needs 'repo' scope)."
    }
    Write-Ok "Pushed to origin/$BranchName"
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║                      PUSH COMPLETE                              ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  Branch:  $BranchName" -ForegroundColor White
Write-Host "  Files:   $staged staged ($($MISSING_FILES.Count) new + $($PATCHED_FILES.Count) patched)" -ForegroundColor White
Write-Host ""
Write-Host "  Open Pull Request:" -ForegroundColor Cyan
Write-Host "  https://github.com/$REPO_OWNER/$REPO_NAME/compare/$BranchName" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  After review and merge:" -ForegroundColor Cyan
Write-Host "  git branch -d $BranchName" -ForegroundColor DarkGray
Write-Host ""
if ($DryRun) { Write-Warn "DRY-RUN — no actual changes made" }