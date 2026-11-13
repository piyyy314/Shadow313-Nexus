#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Push all sandbox fixes from this session to GitHub.
    Run this on your laptop after downloading the files.

.EXAMPLE
    cd C:\Users\shiatoali\shadow313-nexus
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
    .\scripts\push-sandbox-fixes.ps1 -Token "github_pat_xxx"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$Token
)

$repo = "C:\Users\shiatoali\shadow313-nexus"
Set-Location $repo

function Write-OK   { param([string]$m) Write-Host "  ✅ $m" -ForegroundColor Green }
function Write-Fix  { param([string]$m) Write-Host "  🔧 $m" -ForegroundColor Magenta }
function Write-Warn { param([string]$m) Write-Host "  ⚠️  $m" -ForegroundColor Yellow }

Write-Host "`n╔══ Shadow313 NEXUS — Push Sandbox Fixes ══╗" -ForegroundColor Cyan

# Set remote with token
git remote set-url origin "https://piyyy314:$Token@github.com/piyyy314/Shadow313-Nexus.git"

# Pull latest first
Write-Host "`n[1/4] Pulling latest from GitHub..." -ForegroundColor Yellow
git pull origin master 2>&1 | Out-Null
Write-OK "Pulled latest"

# Stage all changes
Write-Host "`n[2/4] Staging changes..." -ForegroundColor Yellow
git add .
$status = git status --short
if ($status) {
    Write-Host "  Files to commit:" -ForegroundColor Gray
    $status | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
} else {
    Write-OK "Nothing to commit — already up to date"
    git remote set-url origin "https://github.com/piyyy314/Shadow313-Nexus.git"
    exit 0
}

# Commit
Write-Host "`n[3/4] Committing..." -ForegroundColor Yellow
$msg = "fix: Binder313 race condition + full system audit + laptop fix scripts + GitHub secrets setup"
git commit -m $msg
Write-OK "Committed: $msg"

# Push
Write-Host "`n[4/4] Pushing to GitHub..." -ForegroundColor Yellow
git push origin master
Write-OK "Pushed to GitHub"

# Clean up token from remote URL
git remote set-url origin "https://github.com/piyyy314/Shadow313-Nexus.git"

Write-Host @"

╔══════════════════════════════════════════════════════════════════╗
║  PUSHED SUCCESSFULLY                                           ║
║  Check: github.com/piyyy314/Shadow313-Nexus/actions            ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan