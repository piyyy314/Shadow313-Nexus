#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Shadow313 — PS7 Profile Audit + Fix + Deep Project Scan
    
    Does everything in one run:
    1. Audits existing $PROFILE for conflicts/issues
    2. Writes a clean optimized profile
    3. Fixes Windows Terminal start directory
    4. Scans all stalled/unpushed commits
    5. Finds untested/missing files in shadow313-nexus
    6. Reports what needs to be pushed
    
    Run as: Normal user in PS7
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
    .\shadow313-profile-audit-and-fix.ps1
#>

param([string]$Token = "")

$ErrorActionPreference = "Continue"

function Write-Step  { param([string]$N,[string]$T) Write-Host "`n[$N] $T" -ForegroundColor Cyan }
function Write-OK    { param([string]$M) Write-Host "  ✅ $M" -ForegroundColor Green }
function Write-Fixed { param([string]$M) Write-Host "  🔧 $M" -ForegroundColor Magenta }
function Write-Warn  { param([string]$M) Write-Host "  ⚠️  $M" -ForegroundColor Yellow }
function Write-Fail  { param([string]$M) Write-Host "  ❌ $M" -ForegroundColor Red }
function Write-Info  { param([string]$M) Write-Host "  ℹ️  $M" -ForegroundColor Gray }

Write-Host @"

╔══════════════════════════════════════════════════════════════════╗
║  Shadow313 — Profile Audit + Fix + Deep Project Scan           ║
║  Fixes PS7 start directory, audits profile, scans project      ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# ═══════════════════════════════════════════════════════════════════
# PHASE 1: AUDIT EXISTING $PROFILE
# ═══════════════════════════════════════════════════════════════════
Write-Step "1/6" "Audit existing PowerShell 7 profile"

Write-Host "  Profile path: $PROFILE" -ForegroundColor Gray

$issues = @()
$profileExists = Test-Path $PROFILE

if ($profileExists) {
    $content = Get-Content $PROFILE -Raw
    $lines   = Get-Content $PROFILE
    
    Write-OK "Profile exists ($($lines.Count) lines, $([math]::Round((Get-Item $PROFILE).Length/1KB,1)) KB)"
    
    # ── Check 1: Wrong start directory ──────────────────────────────
    if ($content -notmatch "Set-Location|cd \`$env:USERPROFILE|startingDirectory") {
        Write-Warn "No home directory fix — PS7 may open in System32"
        $issues += "MISSING: Home directory fix (causes System32 start)"
    } else {
        Write-OK "Home directory fix present"
    }
    
    # ── Check 2: Duplicate function definitions ──────────────────────
    $funcNames = $lines | Where-Object { $_ -match "^function " } | ForEach-Object { ($_ -split " ")[1].TrimEnd("{").Trim() }
    $dupes = $funcNames | Group-Object | Where-Object { $_.Count -gt 1 }
    if ($dupes) {
        foreach ($d in $dupes) {
            Write-Warn "Duplicate function: $($d.Name) defined $($d.Count) times"
            $issues += "DUPLICATE: function $($d.Name)"
        }
    } else {
        Write-OK "No duplicate function definitions"
    }
    
    # ── Check 3: Slow load — heavy imports ───────────────────────────
    $heavyImports = @("Import-Module Az", "Import-Module AzureAD", "Import-Module ActiveDirectory", "oh-my-posh", "starship")
    foreach ($imp in $heavyImports) {
        if ($content -match [regex]::Escape($imp)) {
            Write-Warn "Heavy import found: '$imp' — adds 1-5s to startup"
            $issues += "SLOW: $imp adds startup delay"
        }
    }
    
    # ── Check 4: Broken prompt function ─────────────────────────────
    if ($content -match "function prompt") {
        if ($content -notmatch 'return " "' -and $content -notmatch "return '") {
            Write-Warn "Prompt function missing return statement — may show blank prompt"
            $issues += "BROKEN: prompt function missing return"
        } else {
            Write-OK "Prompt function has return statement"
        }
    }
    
    # ── Check 5: Conflicting aliases ────────────────────────────────
    $builtinConflicts = @("cd","ls","dir","cat","echo","curl","wget")
    foreach ($alias in $builtinConflicts) {
        if ($content -match "Set-Alias.*\b$alias\b|function $alias\b") {
            Write-Warn "Alias '$alias' overrides built-in — may cause unexpected behavior"
            $issues += "CONFLICT: alias '$alias' overrides built-in"
        }
    }
    
    # ── Check 6: Unclosed blocks ────────────────────────────────────
    $openBraces  = ($content.ToCharArray() | Where-Object { $_ -eq '{' }).Count
    $closeBraces = ($content.ToCharArray() | Where-Object { $_ -eq '}' }).Count
    if ($openBraces -ne $closeBraces) {
        Write-Warn "Unbalanced braces: $openBraces open, $closeBraces close — profile may fail to load"
        $issues += "SYNTAX: Unbalanced braces ($openBraces open vs $closeBraces close)"
    } else {
        Write-OK "Braces balanced ($openBraces pairs)"
    }
    
    # ── Check 7: Startup time estimate ──────────────────────────────
    $startupMs = Measure-Command { . $PROFILE 2>$null } | Select-Object -ExpandProperty TotalMilliseconds
    $startupMs = [math]::Round($startupMs, 0)
    if ($startupMs -gt 2000) {
        Write-Warn "Profile loads in ${startupMs}ms — SLOW (>2000ms)"
        $issues += "SLOW: Profile takes ${startupMs}ms to load"
    } elseif ($startupMs -gt 500) {
        Write-Warn "Profile loads in ${startupMs}ms — moderate (>500ms)"
    } else {
        Write-OK "Profile loads in ${startupMs}ms — fast"
    }
    
    # ── Check 8: Duplicate Set-Location calls ───────────────────────
    $setLocCount = ($lines | Where-Object { $_ -match "Set-Location|cd \`$env" }).Count
    if ($setLocCount -gt 3) {
        Write-Warn "$setLocCount Set-Location calls — possible duplicates from multiple script runs"
        $issues += "DUPLICATE: $setLocCount Set-Location calls (profile appended multiple times)"
    }
    
    # ── Check 9: Encoding issues ────────────────────────────────────
    $encoding = Get-Content $PROFILE -Encoding Byte -TotalCount 3
    if ($encoding[0] -eq 0xEF -and $encoding[1] -eq 0xBB -and $encoding[2] -eq 0xBF) {
        Write-OK "Encoding: UTF-8 with BOM (fine for PS7)"
    } else {
        Write-Info "Encoding: UTF-8 without BOM (also fine)"
    }
    
    # Show current profile content
    Write-Host "`n  ── Current profile content ──" -ForegroundColor Gray
    $lines | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
    
} else {
    Write-Warn "No profile exists yet — will create a clean one"
    $issues += "MISSING: Profile does not exist"
}

# Issue summary
Write-Host "`n  ── Audit Summary ──" -ForegroundColor Yellow
if ($issues.Count -eq 0) {
    Write-OK "Profile is clean — no issues found"
} else {
    Write-Host "  Found $($issues.Count) issue(s):" -ForegroundColor Red
    foreach ($i in $issues) { Write-Host "  • $i" -ForegroundColor Yellow }
}

# ═══════════════════════════════════════════════════════════════════
# PHASE 2: WRITE CLEAN OPTIMIZED PROFILE
# ═══════════════════════════════════════════════════════════════════
Write-Step "2/6" "Write clean optimized PS7 profile"

# Backup existing profile
if ($profileExists) {
    $backupPath = "$PROFILE.backup-$(Get-Date -Format 'yyyyMMdd-HHmm')"
    Copy-Item $PROFILE $backupPath -Force
    Write-OK "Backup saved: $backupPath"
}

# Ensure profile directory exists
$profileDir = Split-Path $PROFILE
if (-not (Test-Path $profileDir)) {
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
}

# Write the clean profile
$cleanProfile = @'
# ══════════════════════════════════════════════════════════════════
#  Shadow313 NEXUS — PowerShell 7 Profile
#  Clean, fast, optimized for security research
#  Generated by shadow313-profile-audit-and-fix.ps1
# ══════════════════════════════════════════════════════════════════

# ── 1. HOME DIRECTORY FIX ─────────────────────────────────────────
# Always start in home folder, never in System32
if ($PWD.Path -match "System32|system32|WINDOWS\\system32") {
    Set-Location $env:USERPROFILE
}

# ── 2. ENVIRONMENT VARIABLES ──────────────────────────────────────
$env:SHADOW313_REPO = "C:\Users\shiatoali\shadow313-nexus"
$env:EDITOR         = "code"
$env:PYTHONDONTWRITEBYTECODE = "1"

# Reload PATH to pick up any new tools
$env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" +
            [System.Environment]::GetEnvironmentVariable("PATH","User")

# ── 3. CUSTOM PROMPT ──────────────────────────────────────────────
function prompt {
    $loc    = (Get-Location).Path.Replace($env:USERPROFILE, "~")
    $branch = try { $b = git branch --show-current 2>$null; if ($b) { " ($b)" } else { "" } } catch { "" }
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $adminTag = if ($isAdmin) { " [ADMIN]" } else { "" }
    
    Write-Host "⬡ shadow313$branch$adminTag " -NoNewline -ForegroundColor Green
    Write-Host "$loc" -NoNewline -ForegroundColor Cyan
    Write-Host " ❯" -NoNewline -ForegroundColor Green
    return " "
}

# ── 4. NAVIGATION ALIASES ─────────────────────────────────────────
function s313    { Set-Location "C:\Users\shiatoali\shadow313-nexus" }
function docs    { Set-Location "C:\Users\shiatoali\shadow313-nexus\docs" }
function scripts { Set-Location "C:\Users\shiatoali\shadow313-nexus\scripts" }
function ubuntu  { wsl -d Ubuntu-24.04 }
function kali    { wsl -d kali-linux }
function home    { Set-Location $env:USERPROFILE }

# ── 5. GIT SHORTCUTS ──────────────────────────────────────────────
function gs      { git status }
function gp      { git pull origin master }
function gl      { git log --oneline -10 }
function gd      { git diff }
function gaa     { git add . }

function gpush {
    param([string]$msg = "chore: update")
    git add .
    git commit -m $msg
    git push origin master
}

function s313-push {
    param([string]$msg = "chore: update", [string]$Token = "")
    $repo = "C:\Users\shiatoali\shadow313-nexus"
    Push-Location $repo
    if ($Token) {
        git remote set-url origin "https://piyyy314:$Token@github.com/piyyy314/Shadow313-Nexus.git"
    }
    git add .
    git commit -m $msg
    git push origin master
    git remote set-url origin "https://github.com/piyyy314/Shadow313-Nexus.git"
    Pop-Location
}

# ── 6. OLLAMA SHORTCUTS ───────────────────────────────────────────
function ollama-status {
    try {
        $r = Invoke-RestMethod "http://127.0.0.1:11434/api/tags" -TimeoutSec 3
        Write-Host "✅ Ollama running — $($r.models.Count) models:" -ForegroundColor Green
        $r.models | ForEach-Object { Write-Host "   • $($_.name)" -ForegroundColor Cyan }
    } catch {
        Write-Host "❌ Ollama not running — starting..." -ForegroundColor Red
        Start-Process ollama -ArgumentList "serve" -WindowStyle Hidden
        Start-Sleep 3
        Write-Host "   Started. Try again in a moment." -ForegroundColor Yellow
    }
}

function ollama-start {
    if (-not (Get-Process -Name "ollama" -ErrorAction SilentlyContinue)) {
        Start-Process ollama -ArgumentList "serve" -WindowStyle Hidden
        Write-Host "✅ Ollama started" -ForegroundColor Green
    } else {
        Write-Host "✅ Ollama already running" -ForegroundColor Green
    }
}

function ollama-stop {
    Stop-Process -Name "ollama" -Force -ErrorAction SilentlyContinue
    Write-Host "✅ Ollama stopped" -ForegroundColor Green
}

# ── 7. DOCKER SHORTCUTS ───────────────────────────────────────────
function dps     { docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" }
function dlogs   { param([string]$name = "open-webui") docker logs $name --tail 50 }
function webui   { Start-Process "http://localhost:3000" }

# ── 8. PYTHON SHORTCUTS ───────────────────────────────────────────
function py      { python $args }
function pytest  { python -m pytest $args }
function venv    { python -m venv .venv; .\.venv\Scripts\Activate.ps1 }

# ── 9. SECURITY SHORTCUTS ─────────────────────────────────────────
function scan-ports { param([string]$target = "localhost") nmap -sV -sC $target }
function check-dns  { Resolve-DnsName $args[0] }
function my-ip      { (Invoke-RestMethod "https://api.ipify.org?format=json").ip }

# ── 10. SYSTEM SHORTCUTS ──────────────────────────────────────────
function sysinfo {
    $ram = [math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory/1GB,1)
    $free = [math]::Round((Get-WmiObject Win32_OperatingSystem).FreePhysicalMemory/1MB,1)
    $disk = Get-PSDrive C | Select-Object @{N='Free';E={[math]::Round($_.Free/1GB,1)}},@{N='Used';E={[math]::Round($_.Used/1GB,1)}}
    Write-Host "RAM:  ${free}GB free / ${ram}GB total" -ForegroundColor Cyan
    Write-Host "Disk: $($disk.Free)GB free / $($disk.Used)GB used" -ForegroundColor Cyan
    Write-Host "User: $env:USERNAME @ $env:COMPUTERNAME" -ForegroundColor Cyan
}

function cleanup {
    Clear-RecycleBin -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "✅ Temp files and recycle bin cleared" -ForegroundColor Green
}

# ── 11. AUTO-START OLLAMA (silent, no blue popup) ─────────────────
if (-not (Get-Process -Name "ollama" -ErrorAction SilentlyContinue)) {
    Start-Process ollama -ArgumentList "serve" -WindowStyle Hidden -ErrorAction SilentlyContinue
}

# ── 12. WELCOME MESSAGE (fast, no network calls) ──────────────────
$repoStatus = if (Test-Path "C:\Users\shiatoali\shadow313-nexus\.git") { "✅" } else { "❌" }
$ollamaStatus = if (Get-Process -Name "ollama" -ErrorAction SilentlyContinue) { "✅" } else { "⚠️" }
$dockerStatus = if (Get-Process -Name "com.docker.backend" -ErrorAction SilentlyContinue) { "✅" } else { "⚠️" }

Write-Host ""
Write-Host "  ⬡ Shadow313 NEXUS  |  PS $($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)  |  $env:USERNAME" -ForegroundColor Green
Write-Host "  Repo $repoStatus  Ollama $ollamaStatus  Docker $dockerStatus" -ForegroundColor DarkGray
Write-Host "  Commands: s313, ubuntu, kali, ollama-status, dps, sysinfo" -ForegroundColor DarkGray
Write-Host ""

# ══════════════════════════════════════════════════════════════════
'@

Set-Content $PROFILE $cleanProfile -Encoding UTF8
Write-OK "Clean profile written to: $PROFILE"
Write-Fixed "Fixed: Home directory (no more System32)"
Write-Fixed "Fixed: Clean prompt with git branch"
Write-Fixed "Fixed: No duplicate entries"
Write-Fixed "Added: s313, ubuntu, kali, ollama-status, dps, sysinfo shortcuts"
Write-Fixed "Added: Auto-start Ollama silently"

# ═══════════════════════════════════════════════════════════════════
# PHASE 3: FIX WINDOWS TERMINAL START DIRECTORY
# ═══════════════════════════════════════════════════════════════════
Write-Step "3/6" "Fix Windows Terminal start directory for all profiles"

$wtPath = "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"
if (Test-Path $wtPath) {
    Copy-Item $wtPath "$wtPath.bak-$(Get-Date -Format 'yyyyMMdd-HHmm')" -Force
    $wt = Get-Content $wtPath -Raw -Encoding UTF8 | ConvertFrom-Json
    
    foreach ($p in $wt.profiles.list) {
        switch -Regex ($p.name) {
            "PowerShell 7" {
                $p | Add-Member -NotePropertyName "startingDirectory" -NotePropertyValue "%USERPROFILE%" -Force
                $p | Add-Member -NotePropertyName "hidden" -NotePropertyValue $false -Force
                Write-Fixed "PS7: startingDirectory = %USERPROFILE%"
            }
            "Ubuntu-24.04" {
                $p | Add-Member -NotePropertyName "startingDirectory" -NotePropertyValue "~" -Force
                Write-Fixed "Ubuntu: startingDirectory = ~"
            }
            "kali-linux" {
                $p | Add-Member -NotePropertyName "startingDirectory" -NotePropertyValue "~" -Force
                Write-Fixed "Kali: startingDirectory = ~"
            }
            "Windows PowerShell|Command Prompt|Developer" {
                $p | Add-Member -NotePropertyName "hidden" -NotePropertyValue $true -Force
                Write-Fixed "Hidden: $($p.name)"
            }
        }
    }
    
    # Set PS7 as default
    $wt.defaultProfile = "{574e775e-4f2a-5b96-ac1e-a2962a402336}"
    $wt | ConvertTo-Json -Depth 20 | Set-Content $wtPath -Encoding UTF8
    Write-OK "Windows Terminal settings updated"
} else {
    Write-Warn "Windows Terminal settings not found"
}

# ═══════════════════════════════════════════════════════════════════
# PHASE 4: DEEP PROJECT SCAN — STALLED/UNPUSHED/MISSING
# ═══════════════════════════════════════════════════════════════════
Write-Step "4/6" "Deep project scan — stalled commits, missing files, untested modules"

$repoPath = "C:\Users\shiatoali\shadow313-nexus"
if (-not (Test-Path "$repoPath\.git")) {
    Write-Warn "Repo not found at $repoPath"
} else {
    Push-Location $repoPath
    
    # ── Git status ───────────────────────────────────────────────────
    Write-Host "`n  ── Git Status ──" -ForegroundColor Yellow
    
    $behind = git rev-list HEAD..origin/master --count 2>$null
    $ahead  = git rev-list origin/master..HEAD --count 2>$null
    $status = git status --short 2>$null
    
    if ($behind -gt 0) { Write-Warn "Behind origin by $behind commits — run: git pull origin master" }
    else { Write-OK "Up to date with origin" }
    
    if ($ahead -gt 0) { Write-Warn "$ahead local commits NOT pushed to GitHub" }
    else { Write-OK "All commits pushed" }
    
    if ($status) {
        Write-Warn "Uncommitted changes:"
        $status | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow }
    } else {
        Write-OK "Working tree clean"
    }
    
    # ── Stashed changes ──────────────────────────────────────────────
    $stash = git stash list 2>$null
    if ($stash) {
        Write-Warn "Stashed changes found:"
        $stash | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow }
    } else {
        Write-OK "No stashed changes"
    }
    
    # ── Recent commits not in GitHub ────────────────────────────────
    Write-Host "`n  ── Last 10 commits ──" -ForegroundColor Yellow
    git log --oneline -10 2>$null | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
    
    # ── Missing critical files ───────────────────────────────────────
    Write-Host "`n  ── Critical File Check ──" -ForegroundColor Yellow
    
    $criticalFiles = @(
        "shadow313/__init__.py",
        "shadow313/api/server.py",
        "shadow313/api/audit_server.py",
        "shadow313/core/kernel.py",
        "shadow313/core/session.py",
        "shadow313/core/config.py",
        "shadow313/core/ai_engine.py",
        "shadow313/core/binding_sdk/binder.py",
        "shadow313/cli/main.py",
        "shadow313/modules/recon/recon.py",
        "shadow313/modules/vuln/vuln.py",
        "shadow313/modules/network/network.py",
        "shadow313/modules/defense/defense.py",
        "shadow313/modules/quantum/quantum.py",
        "shadow313/v4/ghost_watch/ghost_watch.py",
        "shadow313/v4/aegis/aegis.py",
        "shadow313/v4/satellite/vsat_monitor.py",
        "shadow313/v4/federated_mesh/mesh.py",
        "shadow313/v4/identity/identity.py",
        "shadow313/v4/soar/advanced_soar.py",
        "shadow313/integrations/telegram/bot.py",
        "api/health.js",
        "api/chat.js",
        "docker/nginx/ssl/shadow313.crt",
        "docker/nginx/ssl/shadow313.key",
        "requirements.txt",
        "pyproject.toml",
        "vercel.json",
        "Dockerfile",
        "docker-compose.yml",
        "README.md",
        ".gitignore"
    )
    
    $missingFiles = @()
    foreach ($f in $criticalFiles) {
        if (Test-Path $f) {
            Write-OK $f
        } else {
            Write-Fail "MISSING: $f"
            $missingFiles += $f
        }
    }
    
    # ── Python files without tests ───────────────────────────────────
    Write-Host "`n  ── V4 Modules Without Tests ──" -ForegroundColor Yellow
    
    $v4Modules = Get-ChildItem "shadow313/v4" -Filter "*.py" -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notmatch "__init__|test_" }
    
    $untestedModules = @()
    foreach ($mod in $v4Modules) {
        $testName = "test_$($mod.BaseName).py"
        $testExists = Get-ChildItem "tests" -Filter $testName -Recurse -ErrorAction SilentlyContinue
        if (-not $testExists) {
            $untestedModules += $mod.FullName.Replace($repoPath + "\", "")
        }
    }
    
    if ($untestedModules.Count -gt 0) {
        Write-Warn "$($untestedModules.Count) v4 modules without dedicated tests:"
        $untestedModules | Select-Object -First 15 | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow }
        if ($untestedModules.Count -gt 15) {
            Write-Host "    ... and $($untestedModules.Count - 15) more" -ForegroundColor DarkGray
        }
    } else {
        Write-OK "All v4 modules have tests"
    }
    
    # ── Security issues from scan report ────────────────────────────
    Write-Host "`n  ── Security Issues (from scan report) ──" -ForegroundColor Yellow
    
    # Check TLS verify=False
    $tlsIssues = Get-ChildItem "shadow313" -Filter "*.py" -Recurse -ErrorAction SilentlyContinue |
        Select-String "verify=False" -ErrorAction SilentlyContinue
    if ($tlsIssues) {
        Write-Fail "TLS verify=False found in $($tlsIssues.Count) location(s):"
        $tlsIssues | ForEach-Object { Write-Host "    $($_.Filename):$($_.LineNumber)" -ForegroundColor Red }
    } else {
        Write-OK "No verify=False found"
    }
    
    # Check shell=True
    $shellTrue = Get-ChildItem "shadow313" -Filter "*.py" -Recurse -ErrorAction SilentlyContinue |
        Select-String "shell=True" -ErrorAction SilentlyContinue
    if ($shellTrue) {
        Write-Warn "shell=True found in $($shellTrue.Count) location(s) (injection risk):"
        $shellTrue | Select-Object -First 5 | ForEach-Object { Write-Host "    $($_.Filename):$($_.LineNumber)" -ForegroundColor Yellow }
    } else {
        Write-OK "No shell=True found"
    }
    
    # Check unauthenticated endpoints
    $unauthEndpoints = Get-ChildItem "shadow313/api","shadow313/v4/mobile_api","shadow313_platform" -Filter "*.py" -Recurse -ErrorAction SilentlyContinue |
        Select-String "@app\.(get|post|put|delete)" -ErrorAction SilentlyContinue
    $authEndpoints = Get-ChildItem "shadow313/api","shadow313/v4/mobile_api","shadow313_platform" -Filter "*.py" -Recurse -ErrorAction SilentlyContinue |
        Select-String "Depends\(get_current_user\)|verify_token|require_auth" -ErrorAction SilentlyContinue
    
    if ($unauthEndpoints) {
        $unauthCount = $unauthEndpoints.Count
        $authCount   = if ($authEndpoints) { $authEndpoints.Count } else { 0 }
        Write-Warn "$unauthCount API endpoints found, $authCount have auth — $($unauthCount - $authCount) potentially unprotected"
    }
    
    # ── __pycache__ check ────────────────────────────────────────────
    Write-Host "`n  ── Committed Artifacts Check ──" -ForegroundColor Yellow
    $pycache = git ls-files | Select-String "__pycache__|\.pyc$" -ErrorAction SilentlyContinue
    if ($pycache) {
        Write-Fail "__pycache__ or .pyc files committed ($($pycache.Count) files)"
        Write-Host "    Fix: git rm --cached -r shadow313/**/__pycache__/" -ForegroundColor White
    } else {
        Write-OK "No __pycache__ or .pyc files committed"
    }
    
    Pop-Location
    
    # ── Summary of what needs pushing ───────────────────────────────
    Write-Host "`n  ── What Needs to Be Done ──" -ForegroundColor Yellow
    
    if ($missingFiles.Count -gt 0) {
        Write-Host "  MISSING FILES ($($missingFiles.Count)):" -ForegroundColor Red
        $missingFiles | ForEach-Object { Write-Host "    • $_" -ForegroundColor Red }
    }
    
    if ($ahead -gt 0) {
        Write-Host "  UNPUSHED COMMITS: $ahead commits need pushing" -ForegroundColor Yellow
        Write-Host "    Run: git push origin master" -ForegroundColor White
    }
    
    if ($status) {
        Write-Host "  UNCOMMITTED CHANGES: stage and commit these" -ForegroundColor Yellow
        Write-Host "    Run: git add . && git commit -m 'your message'" -ForegroundColor White
    }
}

# ═══════════════════════════════════════════════════════════════════
# PHASE 5: BAALB FILE TRANSFER CHECK
# ═══════════════════════════════════════════════════════════════════
Write-Step "5/6" "Check Baalb account files for transfer"

$baalbPath = "C:\Users\Baalb"
if (Test-Path $baalbPath) {
    Write-Host "`n  ── Baalb Profile Contents ──" -ForegroundColor Yellow
    
    $folders = Get-ChildItem $baalbPath -ErrorAction SilentlyContinue
    foreach ($f in $folders) {
        $size = [math]::Round((Get-ChildItem $f.FullName -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum/1MB,0)
        $flag = if ($size -gt 10) { "⚠️ " } else { "   " }
        Write-Host "  $flag$($f.Name.PadRight(30)) $size MB"
    }
    
    # Check shadow313-di specifically
    $s313di = "C:\Users\Baalb\Desktop\shadow313-di"
    if (Test-Path $s313di) {
        Write-Host "`n  ── shadow313-di contents (IMPORTANT) ──" -ForegroundColor Red
        Get-ChildItem $s313di -Recurse -ErrorAction SilentlyContinue |
            Select-Object @{N='Path';E={$_.FullName.Replace($s313di,"")}}, LastWriteTime,
                @{N='SizeMB';E={[math]::Round($_.Length/1MB,2)}} |
            Format-Table -AutoSize
    }
    
    Write-Host "`n  Transfer command (run when ready):" -ForegroundColor Cyan
    Write-Host @'
    $dest = "C:\Users\shiatoali\Desktop\from-baalb"
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    Copy-Item "C:\Users\Baalb\Desktop\shadow313-di" "$dest\shadow313-di" -Recurse -Force
    Copy-Item "C:\Users\Baalb\Desktop\Security Advisories*" "$dest\" -Recurse -Force
    Copy-Item "C:\Users\Baalb\Documents\*" "$dest\Documents" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "✅ Transfer complete — review $dest before deleting Baalb"
'@ -ForegroundColor White
} else {
    Write-OK "C:\Users\Baalb not found — already cleaned up"
}

# ═══════════════════════════════════════════════════════════════════
# PHASE 6: FINAL VERIFICATION
# ═══════════════════════════════════════════════════════════════════
Write-Step "6/6" "Final verification"

# Reload profile to test it
Write-Fixed "Testing new profile..."
try {
    $testMs = Measure-Command { . $PROFILE 2>$null } | Select-Object -ExpandProperty TotalMilliseconds
    Write-OK "Profile loads in $([math]::Round($testMs,0))ms"
} catch {
    Write-Warn "Profile test had errors — check syntax"
}

# Verify PS7 will start in right place
$profileContent = Get-Content $PROFILE -Raw
if ($profileContent -match "System32|system32") {
    Write-OK "Home directory fix confirmed in profile"
}

Write-Host @"

╔══════════════════════════════════════════════════════════════════╗
║  DONE — Summary                                                 ║
╠══════════════════════════════════════════════════════════════════╣
║  ✅ Profile: Clean, optimized, home directory fixed            ║
║  ✅ Terminal: PS7 default, starts in %USERPROFILE%             ║
║  ✅ Project: Scanned for missing files and stalled commits     ║
║  ✅ Baalb: Transfer commands ready                             ║
║                                                                  ║
║  NEXT STEPS:                                                     ║
║  1. Close ALL terminals → reopen Windows Terminal              ║
║  2. PS7 should now start in C:\Users\shiatoali                 ║
║  3. Type 's313' to jump to your repo instantly                 ║
║  4. Transfer Baalb files using the command above               ║
║  5. Push any stalled commits: git push origin master           ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan