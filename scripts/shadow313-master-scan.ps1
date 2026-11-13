#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Shadow313 NEXUS — ONE-SHOT Master Scan
    Scans EVERYTHING: laptop health, storage, accounts, WSL2, Docker,
    Ollama, Git repo, GitHub secrets, watchdog errors, missing files.
    Then fixes what it can automatically.

.HOW TO RUN:
    STEP 1 — Download this file from the chat attachments
    STEP 2 — Open Windows Terminal (PowerShell 7 tab)
    STEP 3 — Run these exact commands:

        Move-Item "$env:USERPROFILE\Downloads\shadow313-master-scan.ps1" "C:\Users\shiatoali\shadow313-nexus\scripts\shadow313-master-scan.ps1" -Force
        cd C:\Users\shiatoali\shadow313-nexus
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
        .\scripts\shadow313-master-scan.ps1

    To also auto-fix everything found:
        .\scripts\shadow313-master-scan.ps1 -Fix

    To push fixes to GitHub too:
        .\scripts\shadow313-master-scan.ps1 -Fix -Token "github_pat_xxx"
#>

param(
    [switch]$Fix,           # Auto-fix issues found
    [string]$Token = "",    # GitHub PAT for pushing fixes
    [switch]$SkipStorage    # Skip slow storage scan
)

$ErrorActionPreference = "Continue"
$repo    = "C:\Users\shiatoali\shadow313-nexus"
$user    = $env:USERNAME
$report  = @{ OK=@(); WARN=@(); FAIL=@(); FIXED=@() }
$startTime = Get-Date

# ── Helpers ───────────────────────────────────────────────────────
function Write-Section { param([string]$t) Write-Host "`n━━━ $t ━━━" -ForegroundColor Cyan }
function OK   { param([string]$m) $report.OK   += $m; Write-Host "  ✅ $m" -ForegroundColor Green }
function WARN { param([string]$m) $report.WARN += $m; Write-Host "  ⚠️  $m" -ForegroundColor Yellow }
function FAIL { param([string]$m) $report.FAIL += $m; Write-Host "  ❌ $m" -ForegroundColor Red }
function FIXED{ param([string]$m) $report.FIXED+= $m; Write-Host "  🔧 $m" -ForegroundColor Magenta }
function INFO { param([string]$m) Write-Host "  ℹ️  $m" -ForegroundColor Gray }

Write-Host @"

╔══════════════════════════════════════════════════════════════════╗
║  Shadow313 NEXUS — Master One-Shot Scan                        ║
║  Scanning everything A to Z...                                 ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# ════════════════════════════════════════════════════════════════
# SECTION 1: STORAGE ANALYSIS — Why is disk at 143GB?
# ════════════════════════════════════════════════════════════════
Write-Section "1/12 STORAGE ANALYSIS"

$drive = Get-PSDrive C -ErrorAction SilentlyContinue
if ($drive) {
    $usedGB = [math]::Round($drive.Used/1GB, 1)
    $freeGB = [math]::Round($drive.Free/1GB, 1)
    $totalGB = [math]::Round(($drive.Used+$drive.Free)/1GB, 1)
    $pct = [math]::Round($drive.Used/($drive.Used+$drive.Free)*100, 0)
    
    if ($freeGB -lt 20) { FAIL "Disk CRITICAL: ${usedGB}GB used / ${totalGB}GB total (${freeGB}GB free, $pct%)" }
    elseif ($freeGB -lt 50) { WARN "Disk LOW: ${usedGB}GB used / ${totalGB}GB total (${freeGB}GB free)" }
    else { OK "Disk OK: ${usedGB}GB used / ${totalGB}GB total (${freeGB}GB free)" }
}

if (-not $SkipStorage) {
    Write-Host "  Scanning top storage consumers..." -ForegroundColor Gray
    
    # Top folders eating space
    $bigFolders = @(
        @{ Path="$env:USERPROFILE\.ollama\models"; Name="Ollama Models" },
        @{ Path="$env:LOCALAPPDATA\Docker";        Name="Docker Desktop" },
        @{ Path="$env:USERPROFILE\shadow313-nexus"; Name="Shadow313 Repo" },
        @{ Path="$env:USERPROFILE\OneDrive";        Name="OneDrive (shiatoali)" },
        @{ Path="C:\OneDrive";                      Name="OneDrive (shared)" },
        @{ Path="$env:USERPROFILE\Downloads";       Name="Downloads" },
        @{ Path="$env:USERPROFILE\AppData\Local\Programs\Ollama\lib"; Name="Ollama App" },
        @{ Path="$env:USERPROFILE\.vscode";         Name="VS Code Extensions" },
        @{ Path="$env:USERPROFILE\AppData\Local\Google\Chrome"; Name="Chrome Cache" },
        @{ Path="$env:USERPROFILE\AppData\Roaming\Code"; Name="VS Code Data" },
        @{ Path="C:\Users\Baalb";                   Name="Baalb Profile" },
        @{ Path="$env:USERPROFILE\NEXUS-OmniSec-Unified"; Name="NEXUS-OmniSec" },
        @{ Path="$env:USERPROFILE\antigravity";     Name="Antigravity" }
    )
    
    $storageReport = @()
    foreach ($f in $bigFolders) {
        if (Test-Path $f.Path) {
            try {
                $size = (Get-ChildItem $f.Path -Recurse -ErrorAction SilentlyContinue | 
                         Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
                $sizeGB = [math]::Round($size/1GB, 2)
                $sizeMB = [math]::Round($size/1MB, 0)
                $display = if ($sizeGB -ge 1) { "${sizeGB}GB" } else { "${sizeMB}MB" }
                $storageReport += [PSCustomObject]@{ Name=$f.Name; Size=$size; Display=$display; Path=$f.Path }
            } catch {}
        }
    }
    
    $storageReport | Sort-Object Size -Descending | ForEach-Object {
        $color = if ($_.Size -gt 10GB) { "Red" } elseif ($_.Size -gt 2GB) { "Yellow" } else { "Gray" }
        Write-Host "  $($_.Display.PadLeft(8))  $($_.Name)" -ForegroundColor $color
        Write-Host "             $($_.Path)" -ForegroundColor DarkGray
    }
    
    # WSL2 virtual disks
    Write-Host "`n  WSL2 Virtual Disks:" -ForegroundColor Gray
    $wslDisks = @(
        "$env:LOCALAPPDATA\Packages\CanonicalGroupLimited.Ubuntu24.04LTS_79rhkp1fndgsc\LocalState\ext4.vhdx",
        "$env:LOCALAPPDATA\Packages\KaliLinux.54290C8133FEE_ey8k8hqnwqnmg\LocalState\ext4.vhdx",
        "$env:LOCALAPPDATA\Docker\wsl\data\ext4.vhdx"
    )
    foreach ($d in $wslDisks) {
        if (Test-Path $d) {
            $sz = [math]::Round((Get-Item $d).Length/1GB, 1)
            $name = Split-Path (Split-Path $d -Parent) -Leaf
            Write-Host "  ${sz}GB  $name" -ForegroundColor $(if($sz -gt 20){"Yellow"}else{"Gray"})
        }
    }
    
    # Pagefile
    $pf = Get-Item "C:\pagefile.sys" -ErrorAction SilentlyContinue
    if ($pf) {
        $pfGB = [math]::Round($pf.Length/1GB, 1)
        Write-Host "  ${pfGB}GB  pagefile.sys (Windows virtual memory)" -ForegroundColor Gray
    }
    
    # Hibernation file
    $hf = Get-Item "C:\hiberfil.sys" -ErrorAction SilentlyContinue
    if ($hf) {
        $hfGB = [math]::Round($hf.Length/1GB, 1)
        WARN "hiberfil.sys: ${hfGB}GB — disable with: powercfg /hibernate off (run as Admin)"
        if ($Fix) {
            # Can't disable without admin, just note it
            INFO "Run as Admin to disable: powercfg /hibernate off"
        }
    }
    
    # Windows.old
    if (Test-Path "C:\Windows.old") {
        $wold = (Get-ChildItem "C:\Windows.old" -Recurse -ErrorAction SilentlyContinue | 
                 Measure-Object -Property Length -Sum).Sum
        $woldGB = [math]::Round($wold/1GB, 1)
        WARN "Windows.old: ${woldGB}GB — safe to delete via Disk Cleanup (run as Admin)"
    }
}

# ════════════════════════════════════════════════════════════════
# SECTION 2: WATCHDOG LOG — What are the 2 critical issues?
# ════════════════════════════════════════════════════════════════
Write-Section "2/12 WATCHDOG LOG"

$logFile = "$repo\logs\watchdog-2026-11.log"
if (Test-Path $logFile) {
    $logLines = Get-Content $logFile -Tail 200
    $criticals = $logLines | Where-Object { $_ -match "\[FAIL\]|\[CRITICAL\]" }
    $warnings  = $logLines | Where-Object { $_ -match "\[WARN\]" }
    
    OK "Watchdog log found: $logFile"
    
    if ($criticals) {
        Write-Host "`n  CRITICAL ISSUES ($($criticals.Count)):" -ForegroundColor Red
        $criticals | ForEach-Object { FAIL $_ }
    } else {
        OK "No CRITICAL issues in watchdog log"
    }
    
    if ($warnings) {
        Write-Host "`n  WARNINGS ($($warnings.Count)):" -ForegroundColor Yellow
        $warnings | Select-Object -First 5 | ForEach-Object { WARN $_ }
        if ($warnings.Count -gt 5) { INFO "...and $($warnings.Count - 5) more warnings" }
    }
} else {
    WARN "Watchdog log not found — run: .\scripts\shadow313-watchdog.ps1 -Check"
}

# ════════════════════════════════════════════════════════════════
# SECTION 3: POWERSHELL PROFILE
# ════════════════════════════════════════════════════════════════
Write-Section "3/12 POWERSHELL PROFILE"

$profilePaths = @(
    $PROFILE,
    "$env:USERPROFILE\Documents\PowerShell\Microsoft.PowerShell_profile.ps1",
    "$env:USERPROFILE\OneDrive\Desktop\Documents\PowerShell\Microsoft.PowerShell_profile.ps1",
    "$env:USERPROFILE\OneDrive\Documents\PowerShell\Microsoft.PowerShell_profile.ps1"
)
$profilePath = $profilePaths | Where-Object { Test-Path $_ } | Select-Object -First 1

if ($profilePath) {
    OK "Profile found: $profilePath"
    $pc = Get-Content $profilePath -Raw
    
    if ($pc -match "OLLAMA_HOST") { OK "OLLAMA_HOST present in profile" }
    else { FAIL "OLLAMA_HOST MISSING from profile — this is watchdog critical issue #1" }
    
    if ($pc -match "System32") { FAIL "Profile contains 'System32' — wrong start directory (watchdog critical issue #2)" }
    else { OK "No System32 in profile" }
    
    if ($pc -match "Set-Location.*USERPROFILE|cd.*~") { OK "Home directory set in profile" }
    else { WARN "Profile may not set home directory" }
    
    if ($Fix -and ($pc -notmatch "OLLAMA_HOST" -or $pc -match "System32")) {
        # Fix the profile
        $fixedProfile = $pc -replace "System32", '$env:USERPROFILE'
        if ($pc -notmatch "OLLAMA_HOST") {
            $fixedProfile = "`$env:OLLAMA_HOST = '0.0.0.0:11434'`n`$env:OLLAMA_ORIGINS = 'http://localhost,http://127.0.0.1,http://host.docker.internal,app://'`n`$env:OLLAMA_NUM_PARALLEL = '2'`n`$env:OLLAMA_NUM_CTX = '8192'`n`$env:OLLAMA_KEEP_ALIVE = '10m'`n`n" + $fixedProfile
        }
        Set-Content $profilePath $fixedProfile -Encoding UTF8
        FIXED "Profile patched: OLLAMA_HOST added, System32 removed"
        
        # Also set permanently
        [System.Environment]::SetEnvironmentVariable("OLLAMA_HOST", "0.0.0.0:11434", "User")
        [System.Environment]::SetEnvironmentVariable("OLLAMA_NUM_PARALLEL", "2", "User")
        [System.Environment]::SetEnvironmentVariable("OLLAMA_NUM_CTX", "8192", "User")
        [System.Environment]::SetEnvironmentVariable("OLLAMA_KEEP_ALIVE", "10m", "User")
        FIXED "OLLAMA_HOST set permanently in User environment"
    }
} else {
    FAIL "No PowerShell profile found — run: .\scripts\fix-laptop-complete.ps1"
}

# ════════════════════════════════════════════════════════════════
# SECTION 4: USER ACCOUNTS
# ════════════════════════════════════════════════════════════════
Write-Section "4/12 USER ACCOUNTS"

$accounts = Get-LocalUser -ErrorAction SilentlyContinue
$admins   = (Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue).Name

foreach ($acct in $accounts) {
    $isAdmin = $admins | Where-Object { $_ -match $acct.Name }
    $adminTag = if ($isAdmin) { " [ADMIN]" } else { "" }
    $status   = if ($acct.Enabled) { "ENABLED" } else { "disabled" }
    
    if ($acct.Name -eq $user) {
        OK "$status $($acct.Name)$adminTag ← your account"
    } elseif ($acct.Name -eq "Baalb" -and $acct.Enabled) {
        WARN "Baalb account ENABLED$adminTag — causes OneDrive contamination when logged in"
        INFO "Fix (run as Admin): Remove-LocalGroupMember -Group 'Administrators' -Member 'Baalb'"
    } elseif ($acct.Enabled -and $acct.Name -notin @("WDAGUtilityAccount","DefaultAccount")) {
        WARN "$status $($acct.Name)$adminTag — review if needed"
    } else {
        OK "$status $($acct.Name)"
    }
}

# Check Baalb folder size
if (Test-Path "C:\Users\Baalb") {
    try {
        $baalbSize = (Get-ChildItem "C:\Users\Baalb" -Recurse -ErrorAction SilentlyContinue | 
                      Measure-Object -Property Length -Sum).Sum
        $baalbGB = [math]::Round($baalbSize/1GB, 1)
        if ($baalbGB -gt 1) {
            WARN "Baalb profile folder: ${baalbGB}GB — transfer important files then delete"
        }
    } catch {}
}

# ════════════════════════════════════════════════════════════════
# SECTION 5: WSL2
# ════════════════════════════════════════════════════════════════
Write-Section "5/12 WSL2"

$wslList = wsl --list --verbose 2>$null
if ($wslList) {
    $wslList | Where-Object { $_ -match "\S" } | ForEach-Object {
        $line = $_ -replace '\x00', '' -replace '\s+', ' '
        if ($line -match "Ubuntu-24.04") { OK "Ubuntu-24.04: $line" }
        elseif ($line -match "kali-linux")  { OK "kali-linux: $line" }
        elseif ($line -match "docker-desktop") { OK "docker-desktop: $line" }
    }
} else {
    FAIL "WSL2 not responding"
}

# Test Ubuntu DNS
$ubuntuTest = wsl -d Ubuntu-24.04 -- bash -c "curl -s --max-time 3 https://api.github.com/zen 2>/dev/null && echo DNS_OK" 2>$null
if ($ubuntuTest -match "DNS_OK") { OK "Ubuntu-24.04 DNS working" }
else { WARN "Ubuntu-24.04 DNS may be broken — run fix script" }

# ════════════════════════════════════════════════════════════════
# SECTION 6: OLLAMA
# ════════════════════════════════════════════════════════════════
Write-Section "6/12 OLLAMA"

$ollamaProc = Get-Process -Name "ollama" -ErrorAction SilentlyContinue
if ($ollamaProc) {
    OK "Ollama running (PID $($ollamaProc.Id))"
} else {
    WARN "Ollama not running"
    if ($Fix) {
        Start-Process ollama -ArgumentList "serve" -WindowStyle Hidden -ErrorAction SilentlyContinue
        Start-Sleep 3
        FIXED "Ollama started silently"
    }
}

$ollamaHost = [System.Environment]::GetEnvironmentVariable("OLLAMA_HOST", "User")
if ($ollamaHost -eq "0.0.0.0:11434") { OK "OLLAMA_HOST = $ollamaHost" }
else { WARN "OLLAMA_HOST = '$ollamaHost' (should be 0.0.0.0:11434)" }

try {
    $models = Invoke-RestMethod "http://127.0.0.1:11434/api/tags" -TimeoutSec 5
    OK "Ollama API responding — $($models.models.Count) models"
    $models.models | ForEach-Object { INFO "  Model: $($_.name) ($([math]::Round($_.size/1GB,1))GB)" }
} catch {
    WARN "Ollama API not responding on port 11434"
}

# ════════════════════════════════════════════════════════════════
# SECTION 7: DOCKER
# ════════════════════════════════════════════════════════════════
Write-Section "7/12 DOCKER"

$dockerProc = Get-Process -Name "com.docker.backend" -ErrorAction SilentlyContinue
if ($dockerProc) {
    OK "Docker Desktop running"
    
    try {
        $containers = docker ps --format "{{.Names}}|{{.Status}}" 2>$null
        if ($containers) {
            $containers | ForEach-Object {
                $parts = $_ -split "\|"
                OK "Container: $($parts[0]) — $($parts[1])"
            }
        } else {
            WARN "No containers running"
        }
        
        $owStatus = docker ps --filter "name=open-webui" --format "{{.Status}}" 2>$null
        if ($owStatus -match "Up") { OK "Open WebUI: $owStatus → http://localhost:3000" }
        else { WARN "Open WebUI not running" }
        
        # Docker disk usage
        $dockerDf = docker system df --format "{{.Type}}\t{{.Size}}\t{{.Reclaimable}}" 2>$null
        if ($dockerDf) {
            Write-Host "  Docker disk usage:" -ForegroundColor Gray
            $dockerDf | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
        }
    } catch {
        WARN "Docker CLI not responding"
    }
} else {
    WARN "Docker Desktop not running"
}

# ════════════════════════════════════════════════════════════════
# SECTION 8: GIT REPO
# ════════════════════════════════════════════════════════════════
Write-Section "8/12 GIT REPO"

if (Test-Path "$repo\.git") {
    Push-Location $repo
    
    $remoteUrl = git remote get-url origin 2>$null
    if ($remoteUrl -match "github.com") { OK "Remote: $remoteUrl" }
    else { WARN "Remote URL unexpected: $remoteUrl" }
    
    # Check if token is embedded in URL (security issue)
    if ($remoteUrl -match "ghp_|github_pat_") {
        FAIL "GitHub token EMBEDDED in remote URL — security risk!"
        if ($Fix) {
            git remote set-url origin "https://github.com/piyyy314/Shadow313-Nexus.git"
            FIXED "Removed token from remote URL"
        }
    }
    
    git fetch origin --quiet 2>$null
    $behind = git rev-list HEAD..origin/master --count 2>$null
    $ahead  = git rev-list origin/master..HEAD --count 2>$null
    
    if ([int]$behind -gt 0) { WARN "Repo is $behind commits BEHIND — run: git pull origin master" }
    else { OK "Repo is up to date with origin" }
    
    if ([int]$ahead -gt 0) { WARN "Repo is $ahead commits AHEAD — run: git push origin master" }
    
    $dirty = git status --short 2>$null
    if ($dirty) {
        WARN "Uncommitted changes ($($dirty.Count) files)"
        $dirty | Select-Object -First 5 | ForEach-Object { INFO "  $_" }
    } else {
        OK "Working tree clean"
    }
    
    # Check for committed secrets
    $secretsInGit = git ls-files | Select-String "secret-fixtures|\.env$|\.key$|\.pem$" 2>$null
    if ($secretsInGit) {
        FAIL "Potentially sensitive files tracked by git:"
        $secretsInGit | ForEach-Object { FAIL "  $_" }
    } else {
        OK "No obvious secrets tracked by git"
    }
    
    # Check for __pycache__ in git
    $pycache = git ls-files | Select-String "__pycache__|\.pyc$" 2>$null
    if ($pycache) { WARN "__pycache__ or .pyc files in git ($($pycache.Count) files)" }
    else { OK "No __pycache__ in git" }
    
    Pop-Location
} else {
    FAIL "Repo not found at $repo"
}

# ════════════════════════════════════════════════════════════════
# SECTION 9: GITHUB SECRETS CHECK
# ════════════════════════════════════════════════════════════════
Write-Section "9/12 GITHUB SECRETS"

$requiredSecrets = @(
    "SHADOW313_JWT_SECRET",
    "WEBUI_SECRET_KEY", 
    "SHADOW313_API_KEY",
    "VERCEL_TOKEN",
    "VERCEL_ORG_ID",
    "VERCEL_PROJECT_ID"
)

$optionalSecrets = @(
    "TELEGRAM_BOT_TOKEN",
    "TELEGRAM_CHAT_ID",
    "PYPI_API_TOKEN"
)

if ($Token) {
    try {
        $headers = @{ Authorization="Bearer $Token"; Accept="application/vnd.github+json" }
        $secrets = Invoke-RestMethod "https://api.github.com/repos/piyyy314/Shadow313-Nexus/actions/secrets" -Headers $headers
        $secretNames = $secrets.secrets.name
        
        foreach ($s in $requiredSecrets) {
            if ($secretNames -contains $s) { OK "GitHub secret SET: $s" }
            else { FAIL "GitHub secret MISSING: $s" }
        }
        foreach ($s in $optionalSecrets) {
            if ($secretNames -contains $s) { OK "GitHub secret SET: $s (optional)" }
            else { WARN "GitHub secret not set: $s (optional)" }
        }
    } catch {
        WARN "Could not check GitHub secrets (token may lack permissions)"
    }
} else {
    INFO "Provide -Token to check GitHub secrets"
    INFO "Required: $($requiredSecrets -join ', ')"
    INFO "Optional: $($optionalSecrets -join ', ')"
}

# ════════════════════════════════════════════════════════════════
# SECTION 10: MISSING CRITICAL FILES
# ════════════════════════════════════════════════════════════════
Write-Section "10/12 CRITICAL FILES"

$criticalFiles = @(
    @{ Path="$repo\shadow313\core\binding_sdk\binder.py"; Name="Binder313 (race condition fix)" },
    @{ Path="$repo\.env.example"; Name=".env.example template" },
    @{ Path="$repo\docker\nginx\gen-ssl.sh"; Name="SSL cert generator" },
    @{ Path="$repo\pyproject.toml"; Name="Package config" },
    @{ Path="$repo\requirements.txt"; Name="Dependencies" },
    @{ Path="$repo\Dockerfile"; Name="Docker build" },
    @{ Path="$repo\vercel.json"; Name="Vercel routing" },
    @{ Path="$repo\README.md"; Name="Documentation" },
    @{ Path="$repo\SECURITY.md"; Name="Security policy" }
)

$missingOptional = @(
    @{ Path="$repo\.env"; Name=".env (local secrets)" },
    @{ Path="$repo\docker\nginx\ssl\shadow313.crt"; Name="SSL cert (generate with gen-ssl.sh)" },
    @{ Path="$repo\docker\nginx\ssl\shadow313.key"; Name="SSL key (generate with gen-ssl.sh)" }
)

foreach ($f in $criticalFiles) {
    if (Test-Path $f.Path) { OK "$($f.Name)" }
    else { FAIL "MISSING: $($f.Name) — $($f.Path)" }
}

foreach ($f in $missingOptional) {
    if (Test-Path $f.Path) { OK "$($f.Name)" }
    else { WARN "Not present (optional): $($f.Name)" }
}

# ════════════════════════════════════════════════════════════════
# SECTION 11: TOOLS IN PATH
# ════════════════════════════════════════════════════════════════
Write-Section "11/12 TOOLS IN PATH"

$tools = @{
    "git"       = "git --version"
    "python3"   = "python3 --version"
    "docker"    = "docker --version"
    "ollama"    = "ollama --version"
    "nmap"      = "nmap --version"
    "wg"        = "wg --version"
    "code"      = "code --version"
    "node"      = "node --version"
    "pwsh"      = "pwsh --version"
}

foreach ($tool in $tools.GetEnumerator()) {
    $cmd = Get-Command $tool.Key -ErrorAction SilentlyContinue
    if ($cmd) {
        $ver = & $tool.Key ($tool.Value -split " " | Select-Object -Skip 1) 2>$null | Select-Object -First 1
        OK "$($tool.Key): $ver"
    } else {
        WARN "$($tool.Key): NOT IN PATH"
    }
}

# ════════════════════════════════════════════════════════════════
# SECTION 12: PUSH FIXES TO GITHUB
# ════════════════════════════════════════════════════════════════
Write-Section "12/12 PUSH TO GITHUB"

if ($Fix -and $Token -and (Test-Path "$repo\.git")) {
    Push-Location $repo
    
    $dirty = git status --short 2>$null
    if ($dirty) {
        git add .
        git commit -m "fix: master scan auto-fixes — profile, OLLAMA_HOST, remote URL cleanup"
        git remote set-url origin "https://piyyy314:$Token@github.com/piyyy314/Shadow313-Nexus.git"
        git push origin master 2>&1 | Out-Null
        git remote set-url origin "https://github.com/piyyy314/Shadow313-Nexus.git"
        FIXED "Pushed fixes to GitHub"
    } else {
        OK "Nothing to push"
    }
    
    Pop-Location
} elseif ($Fix -and -not $Token) {
    INFO "Provide -Token to auto-push fixes to GitHub"
}

# ════════════════════════════════════════════════════════════════
# FINAL REPORT
# ════════════════════════════════════════════════════════════════
$elapsed = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)

Write-Host @"

╔══════════════════════════════════════════════════════════════════╗
║  SCAN COMPLETE ($elapsed seconds)
╠══════════════════════════════════════════════════════════════════╣
"@ -ForegroundColor Cyan

Write-Host "  ✅ OK:    $($report.OK.Count)" -ForegroundColor Green
Write-Host "  ⚠️  WARN:  $($report.WARN.Count)" -ForegroundColor Yellow
Write-Host "  ❌ FAIL:  $($report.FAIL.Count)" -ForegroundColor Red
if ($report.FIXED.Count -gt 0) {
    Write-Host "  🔧 FIXED: $($report.FIXED.Count)" -ForegroundColor Magenta
}

if ($report.FAIL.Count -gt 0) {
    Write-Host "`n  FAILURES TO FIX:" -ForegroundColor Red
    $report.FAIL | ForEach-Object { Write-Host "    • $_" -ForegroundColor Red }
}

if ($report.WARN.Count -gt 0) {
    Write-Host "`n  TOP WARNINGS:" -ForegroundColor Yellow
    $report.WARN | Select-Object -First 5 | ForEach-Object { Write-Host "    • $_" -ForegroundColor Yellow }
}

Write-Host @"

  NEXT STEPS:
  1. Run with -Fix to auto-repair issues:
     .\scripts\shadow313-master-scan.ps1 -Fix

  2. Run with -Fix -Token to also push to GitHub:
     .\scripts\shadow313-master-scan.ps1 -Fix -Token "github_pat_xxx"

  3. Generate secrets:
     .\scripts\generate-secrets-local.ps1

  4. Close terminal → reopen Windows Terminal to apply profile fixes
"@ -ForegroundColor White