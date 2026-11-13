#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Clean up the Shadow313 repo — remove files that shouldn't be tracked,
    move root PS1 scripts to scripts/, update .gitignore.

.EXAMPLE
    cd C:\Users\shiatoali\shadow313-nexus
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
    .\scripts\cleanup-repo.ps1 -DryRun        # Preview only
    .\scripts\cleanup-repo.ps1 -Token "ghp_xxx"  # Apply + push
#>

param(
    [switch]$DryRun,
    [string]$Token = ""
)

$repo = "C:\Users\shiatoali\shadow313-nexus"
Set-Location $repo

function Write-OK   { param([string]$m) Write-Host "  ✅ $m" -ForegroundColor Green }
function Write-Fix  { param([string]$m) Write-Host "  🔧 $m" -ForegroundColor Magenta }
function Write-Warn { param([string]$m) Write-Host "  ⚠️  $m" -ForegroundColor Yellow }
function Write-Info { param([string]$m) Write-Host "  ℹ️  $m" -ForegroundColor Gray }

$mode = if ($DryRun) { "DRY RUN" } else { "LIVE" }
Write-Host "`n╔══ Shadow313 Repo Cleanup [$mode] ══╗" -ForegroundColor Cyan

# ── 1. Remove docs-archive/ from git tracking ────────────────────
Write-Host "`n[1/5] docs-archive/ — remove from git (keep files locally)" -ForegroundColor Yellow
$docsArchiveInGit = git ls-files docs-archive/ 2>$null | Measure-Object | Select-Object -ExpandProperty Count
Write-Info "$docsArchiveInGit files in docs-archive/ tracked by git"

if ($docsArchiveInGit -gt 0 -and -not $DryRun) {
    git rm --cached -r docs-archive/ 2>$null
    Write-Fix "Removed docs-archive/ from git tracking (files kept locally)"
} elseif ($DryRun) {
    Write-Info "Would remove $docsArchiveInGit files from git tracking"
}

# ── 2. Remove secret-fixtures.json ───────────────────────────────
Write-Host "`n[2/5] secret-fixtures.json — remove from git" -ForegroundColor Yellow
if (git ls-files scripts/secret-fixtures.json 2>$null) {
    if (-not $DryRun) {
        git rm --cached scripts/secret-fixtures.json 2>$null
        Write-Fix "Removed scripts/secret-fixtures.json from git"
    } else {
        Write-Info "Would remove scripts/secret-fixtures.json from git"
    }
} else {
    Write-OK "secret-fixtures.json not tracked"
}

# ── 3. Move root PS1 scripts to scripts/ ─────────────────────────
Write-Host "`n[3/5] Root PS1 scripts — move to scripts/" -ForegroundColor Yellow

$rootPs1ToMove = @(
    "deep_laptop_scan.ps1",
    "deploy_live.ps1",
    "deploy_to_laptop.ps1",
    "fix_laptop_and_onedrive.ps1",
    "scan_and_fix_laptop.ps1",
    "shadow313-account-cleanup.ps1",
    "shadow313-complete-system-fix.ps1",
    "shadow313-fix-all.ps1",
    "shadow313-profile-audit-and-fix.ps1",
    "shadow313-registry-audit-readonly.ps1",
    "shadow313-watchdog.ps1"
)

$rootPs1ToDelete = @(
    "final_push.ps1",
    "fix_ci_final.ps1",
    "fix_html_architecture.ps1",
    "html_redesign.ps1",
    "master_fix_all.ps1",
    "push_all.ps1"
)

foreach ($f in $rootPs1ToMove) {
    if (Test-Path $f) {
        $dest = "scripts\$f"
        if (-not (Test-Path $dest)) {
            if (-not $DryRun) {
                git mv $f $dest 2>$null
                if ($LASTEXITCODE -ne 0) { Move-Item $f $dest -Force }
                Write-Fix "Moved: $f → scripts/$f"
            } else {
                Write-Info "Would move: $f → scripts/$f"
            }
        } else {
            Write-Warn "Destination exists: scripts/$f (skipping)"
        }
    }
}

foreach ($f in $rootPs1ToDelete) {
    if (Test-Path $f) {
        if (-not $DryRun) {
            git rm --cached $f 2>$null
            Remove-Item $f -Force
            Write-Fix "Deleted obsolete: $f"
        } else {
            Write-Info "Would delete: $f"
        }
    }
}

# ── 4. Update .gitignore ──────────────────────────────────────────
Write-Host "`n[4/5] Update .gitignore" -ForegroundColor Yellow

$additionalIgnores = @"

# ── Cleanup additions $(Get-Date -Format 'yyyy-MM-dd') ──
docs-archive/
scripts/secret-fixtures.json
shadow313/v4/pqc_js/node_modules/
lost+found/
FULL_AUDIT_REPORT.md
LAPTOP_AUDIT_ANALYSIS.md
MICROSOFT_ACCOUNT_MAP.md
CROSS_REPO_STATUS.md
SENTINELOS_INTEGRATION.md
STIA_ORBITAL_V5_DEEP_ANALYSIS.md
MASTER_GAP_ANALYSIS_AND_SECRETS.md
FULL_SYSTEM_AUDIT_2026-11.md
"@

$currentIgnore = Get-Content .gitignore -Raw
if ($currentIgnore -notmatch "docs-archive/") {
    if (-not $DryRun) {
        Add-Content .gitignore $additionalIgnores
        Write-Fix "Updated .gitignore with missing patterns"
    } else {
        Write-Info "Would add to .gitignore: docs-archive/, secret-fixtures.json, etc."
    }
} else {
    Write-OK ".gitignore already has docs-archive/"
}

# ── 5. Commit and push ────────────────────────────────────────────
Write-Host "`n[5/5] Commit and push" -ForegroundColor Yellow

if (-not $DryRun) {
    git add .gitignore
    git add -A
    
    $status = git status --short
    if ($status) {
        git commit -m "chore: repo cleanup — remove docs-archive from tracking, move root PS1 to scripts/, update .gitignore"
        Write-Fix "Committed cleanup"
        
        if ($Token) {
            git remote set-url origin "https://piyyy314:$Token@github.com/piyyy314/Shadow313-Nexus.git"
            git push origin master
            git remote set-url origin "https://github.com/piyyy314/Shadow313-Nexus.git"
            Write-OK "Pushed to GitHub"
        } else {
            Write-Warn "No token provided — commit made but not pushed"
            Write-Info "Push manually: git push origin master"
        }
    } else {
        Write-OK "Nothing to commit"
    }
} else {
    Write-Info "DRY RUN complete — no changes made"
    Write-Info "Run without -DryRun to apply changes"
}

Write-Host "`n╔══ DONE ══╗" -ForegroundColor Cyan