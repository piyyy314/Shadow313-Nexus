<#
.SYNOPSIS
    Shadow313 — GitHub Push Script
    Pushes all new/modified files from the sandbox to a new branch on the remote repo.

.DESCRIPTION
    Creates a new timestamped branch, stages all changes (new files + modifications),
    commits with a structured message, and pushes to origin.

    Usage:
        .\push-to-github.ps1
        .\push-to-github.ps1 -BranchName "feature/v2-patches-oct29"
        .\push-to-github.ps1 -DryRun
        .\push-to-github.ps1 -BranchName "hotfix/p24-ja3-fips" -CommitMessage "fix: JA3 FIPS compliance"

.PARAMETER BranchName
    Name of the new branch to create. Defaults to "shadow313/sandbox-sync-YYYYMMDD-HHMM".

.PARAMETER CommitMessage
    Git commit message. Defaults to a structured summary of all changes.

.PARAMETER Remote
    Git remote name. Defaults to "origin".

.PARAMETER DryRun
    If set, shows what would be done without making any changes.

.PARAMETER SkipTests
    If set, skips running the test suite before pushing.

.NOTES
    Repo: github.com/piyyy314/Shadow313-Nexus
    Run from the workspace root directory (/workspace or equivalent).
#>

[CmdletBinding()]
param(
    [string]$BranchName   = "",
    [string]$CommitMessage = "",
    [string]$Remote        = "origin",
    [switch]$DryRun,
    [switch]$SkipTests
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Colour helpers ────────────────────────────────────────────────────────────
function Write-Step   { param($msg) Write-Host "`n[STEP] $msg" -ForegroundColor Cyan }
function Write-Ok     { param($msg) Write-Host "  [OK] $msg"   -ForegroundColor Green }
function Write-Warn   { param($msg) Write-Host "  [WARN] $msg" -ForegroundColor Yellow }
function Write-Fail   { param($msg) Write-Host "  [FAIL] $msg" -ForegroundColor Red }
function Write-Info   { param($msg) Write-Host "  [INFO] $msg" -ForegroundColor Gray }
function Write-Dry    { param($msg) Write-Host "  [DRY-RUN] $msg" -ForegroundColor Magenta }

# ── Banner ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor DarkCyan
Write-Host "║          Shadow313 NEXUS — GitHub Push Script               ║" -ForegroundColor DarkCyan
Write-Host "║          Sandbox → github.com/piyyy314/Shadow313-Nexus      ║" -ForegroundColor DarkCyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor DarkCyan
Write-Host ""

if ($DryRun) {
    Write-Warn "DRY-RUN MODE — no changes will be made to git or remote"
}

# ── Step 1: Verify git is available ──────────────────────────────────────────
Write-Step "1/8 — Verifying git installation"
try {
    $gitVersion = git --version 2>&1
    Write-Ok "Git found: $gitVersion"
} catch {
    Write-Fail "git not found. Install git and retry."
    exit 1
}

# ── Step 2: Verify we are in a git repo ──────────────────────────────────────
Write-Step "2/8 — Verifying git repository"
try {
    $repoRoot = git rev-parse --show-toplevel 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Not a git repository" }
    Write-Ok "Repository root: $repoRoot"
} catch {
    Write-Fail "Not inside a git repository. Run from /workspace."
    exit 1
}

# Verify remote
try {
    $remoteUrl = git remote get-url $Remote 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Remote '$Remote' not found" }
    Write-Ok "Remote '$Remote': $remoteUrl"
} catch {
    Write-Fail "Remote '$Remote' not configured. Add it with: git remote add origin https://github.com/piyyy314/Shadow313-Nexus.git"
    exit 1
}

# ── Step 3: Check current branch and status ───────────────────────────────────
Write-Step "3/8 — Checking current branch and status"
$currentBranch = git branch --show-current 2>&1
Write-Info "Current branch: $currentBranch"

$statusOutput = git status --porcelain 2>&1
$changedFiles = @($statusOutput | Where-Object { $_ -match "^\s*[MADRCU?]" })
Write-Info "Changed/new files: $($changedFiles.Count)"

if ($changedFiles.Count -eq 0) {
    Write-Warn "No changes detected. Nothing to push."
    Write-Info "If you expected changes, run: git status"
    exit 0
}

# Show summary of changes
Write-Info "Files to be committed:"
$newFiles      = @($changedFiles | Where-Object { $_ -match "^\?\?" })
$modifiedFiles = @($changedFiles | Where-Object { $_ -match "^[ M]M|^M " })
$deletedFiles  = @($changedFiles | Where-Object { $_ -match "^[ D]D|^D " })

Write-Info "  New files:      $($newFiles.Count)"
Write-Info "  Modified files: $($modifiedFiles.Count)"
Write-Info "  Deleted files:  $($deletedFiles.Count)"

# ── Step 4: Run tests ─────────────────────────────────────────────────────────
Write-Step "4/8 — Running test suite"
if ($SkipTests) {
    Write-Warn "Tests skipped (--SkipTests flag set)"
} else {
    # Try run_tests.py first (standalone runner)
    $testRunner = Join-Path $repoRoot "run_tests.py"
    if (Test-Path $testRunner) {
        Write-Info "Running: python run_tests.py"
        if (-not $DryRun) {
            $testOutput = python run_tests.py 2>&1
            $testResult = $LASTEXITCODE
            $lastLine = ($testOutput | Select-Object -Last 3) -join "`n"
            Write-Info $lastLine
            if ($testResult -ne 0) {
                Write-Fail "Tests failed. Fix failures before pushing."
                Write-Info "Run 'python run_tests.py' to see details."
                exit 1
            }
            Write-Ok "All tests passed"
        } else {
            Write-Dry "Would run: python run_tests.py"
        }
    } else {
        # Fallback: python -m unittest discover
        Write-Info "run_tests.py not found, using unittest discover"
        if (-not $DryRun) {
            $testOutput = python -m unittest discover -s tests -p "test_*.py" 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Fail "Tests failed. Fix failures before pushing."
                exit 1
            }
            Write-Ok "All tests passed"
        } else {
            Write-Dry "Would run: python -m unittest discover -s tests -p 'test_*.py'"
        }
    }
}

# ── Step 5: Generate branch name ──────────────────────────────────────────────
Write-Step "5/8 — Preparing branch name"
if ($BranchName -eq "") {
    $timestamp  = Get-Date -Format "yyyyMMdd-HHmm"
    $BranchName = "shadow313/sandbox-sync-$timestamp"
}
Write-Info "Branch name: $BranchName"

# Check if branch already exists locally
$existingBranch = git branch --list $BranchName 2>&1
if ($existingBranch -match $BranchName) {
    Write-Warn "Branch '$BranchName' already exists locally."
    $suffix = Get-Date -Format "ss"
    $BranchName = "$BranchName-$suffix"
    Write-Info "Using: $BranchName"
}

# ── Step 6: Create branch and stage files ─────────────────────────────────────
Write-Step "6/8 — Creating branch and staging files"

if (-not $DryRun) {
    # Create new branch from current HEAD
    git checkout -b $BranchName 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Failed to create branch '$BranchName'"
        exit 1
    }
    Write-Ok "Created branch: $BranchName"

    # Stage all changes (new + modified + deleted)
    git add -A 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "git add -A failed"
        exit 1
    }
    Write-Ok "Staged all changes"
} else {
    Write-Dry "Would run: git checkout -b $BranchName"
    Write-Dry "Would run: git add -A"
}

# ── Step 7: Commit ────────────────────────────────────────────────────────────
Write-Step "7/8 — Committing changes"

if ($CommitMessage -eq "") {
    $date = Get-Date -Format "yyyy-MM-dd"
    $CommitMessage = @"
feat(v2): sandbox sync $date — patches P19-P32 + new modules

## New Modules
- shadow313/v2/network_upgrades/firmware_auditor.py (FW-01: TPM-ready firmware hash verification)
- shadow313/modules/defense/remediation.py: FileEncryptionRateMonitor (RW-01)
- shadow313/modules/network/topology.py: RoutingTableMonitor (NB-01)
- shadow313/modules/network/flow_tracker.py: OutboundVolumeMonitor + UserFileAccessMonitor (Gap 8+9)

## Security Patches
- P-24: ja3_fingerprint.py — MD5 usedforsecurity=False (FIPS compliance, B324 HIGH)
- P-25: threat_intel.py — SQL injection guard in stats() (B608)
- P-26: plugin_signer.py — Restored missing sign/verify blocks in run()
- P-27: plugins_module.py — W0106 expression-not-assigned fixed
- P-28: runner.py — Restored corrupted subprocess.run() call
- P-29/30: system_info.py, network_module.py — subprocess check=False
- P-31: scope.py, manifest.py — open() encoding=utf-8
- P-32: cli/main.py — removed unused new_key variable

## New Features
- P-19: epss_kev.py — composite_z_score() + should_include() (Z-score model)

## Tests
- tests/unit/test_new_patches.py — 66 new tests (128 total, 0 failures)

## Documents
- document/shadow313-hybrid-cve-scoring/ (14 pages)
- document/shadow313-defensive-controls/ (14 pages)
- document/shadow313-attack-simulation/ (12 pages)
- document/shadow313-evasion-campaign/ (11 pages)

Kernel: 0 load errors, 26 commands registered
"@
}

Write-Info "Commit message preview (first line): $($CommitMessage.Split("`n")[0])"

if (-not $DryRun) {
    # Configure git identity if not set
    $gitUser  = git config user.name  2>&1
    $gitEmail = git config user.email 2>&1
    if (-not $gitUser -or $gitUser -match "^$") {
        git config user.name  "Shadow313 Bot" 2>&1 | Out-Null
        git config user.email "bot@shadow313.dev" 2>&1 | Out-Null
        Write-Warn "Git identity not configured — using defaults (Shadow313 Bot)"
    }

    git commit -m $CommitMessage 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "git commit failed"
        exit 1
    }
    Write-Ok "Committed successfully"
} else {
    Write-Dry "Would run: git commit -m '$($CommitMessage.Split("`n")[0])...'"
}

# ── Step 8: Push to remote ────────────────────────────────────────────────────
Write-Step "8/8 — Pushing to $Remote/$BranchName"

if (-not $DryRun) {
    Write-Info "Pushing... (this may take a moment)"
    $pushOutput = git push $Remote $BranchName --set-upstream 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Push failed. Output:"
        Write-Host $pushOutput -ForegroundColor Red
        Write-Host ""
        Write-Warn "Common fixes:"
        Write-Info "  1. Authentication: git remote set-url origin https://<TOKEN>@github.com/piyyy314/Shadow313-Nexus.git"
        Write-Info "  2. SSH key:        git remote set-url origin git@github.com:piyyy314/Shadow313-Nexus.git"
        Write-Info "  3. Check access:   gh auth status"
        exit 1
    }
    Write-Ok "Pushed successfully to $Remote/$BranchName"
} else {
    Write-Dry "Would run: git push $Remote $BranchName --set-upstream"
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║                    PUSH COMPLETE                            ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  Branch:   $BranchName" -ForegroundColor White
Write-Host "  Remote:   $Remote ($remoteUrl)" -ForegroundColor White
Write-Host "  Files:    $($changedFiles.Count) changed ($($newFiles.Count) new, $($modifiedFiles.Count) modified, $($deletedFiles.Count) deleted)" -ForegroundColor White
Write-Host ""
Write-Host "  Next steps:" -ForegroundColor Cyan
Write-Host "  1. Open a Pull Request:" -ForegroundColor White
Write-Host "     https://github.com/piyyy314/Shadow313-Nexus/compare/$BranchName" -ForegroundColor DarkGray
Write-Host "  2. Review changes on GitHub before merging to main" -ForegroundColor White
Write-Host "  3. After merge, delete the branch:" -ForegroundColor White
Write-Host "     git branch -d $BranchName" -ForegroundColor DarkGray
Write-Host ""

if ($DryRun) {
    Write-Warn "DRY-RUN complete — no actual changes were made"
}