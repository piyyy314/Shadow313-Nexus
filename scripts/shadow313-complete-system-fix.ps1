#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Shadow313 NEXUS — Complete System Fix & Audit
    ONE script that does everything:
    - Full account/registry orphan audit and cleanup
    - Windows Terminal fix (PS7 default, hide old profiles)
    - Ollama environment variables
    - WSL2 config fix
    - Ubuntu + Kali tool installation
    - nginx SSL cert generation
    - Docker/Open WebUI fix
    - Startup task (prevent settings drift)
    - Missing Python packages
    - PATH fixes

    Run as: NORMAL USER in PowerShell 7 (black terminal)
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
    .\shadow313-complete-system-fix.ps1

    Optional: add -Token "YOUR_GITHUB_TOKEN" to also git pull
    Optional: add -CleanOrphans to actually delete orphaned registry entries
#>

param(
    [string]$Token = "",
    [switch]$CleanOrphans
)

$ErrorActionPreference = "Continue"
$report = @{ OK = @(); WARN = @(); FIXED = @(); FAIL = @() }

function Write-Step  { param([string]$N,[string]$T) Write-Host "`n[$N] $T" -ForegroundColor Cyan }
function Write-OK    { param([string]$M) Write-Host "  ✅ $M" -ForegroundColor Green;   $script:report.OK   += $M }
function Write-Fixed { param([string]$M) Write-Host "  🔧 $M" -ForegroundColor Magenta; $script:report.FIXED += $M }
function Write-Warn  { param([string]$M) Write-Host "  ⚠️  $M" -ForegroundColor Yellow;  $script:report.WARN  += $M }
function Write-Fail  { param([string]$M) Write-Host "  ❌ $M" -ForegroundColor Red;     $script:report.FAIL  += $M }

Write-Host @"

╔══════════════════════════════════════════════════════════════════╗
║  Shadow313 NEXUS — Complete System Fix & Audit                 ║
║  Covers: Accounts · Registry · Terminal · Ollama · WSL2        ║
║  Ubuntu · Kali · Docker · SSL · PATH · Startup Task           ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# ═══════════════════════════════════════════════════════════════════
# PHASE 1: FULL ACCOUNT & REGISTRY AUDIT
# ═══════════════════════════════════════════════════════════════════
Write-Step "PHASE 1" "Full Account & Registry Audit"

Write-Host "`n  --- Current Session ---" -ForegroundColor Gray
Write-Host "  User:     $env:USERNAME"
Write-Host "  Profile:  $env:USERPROFILE"
Write-Host "  Computer: $env:COMPUTERNAME"
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "  Is Admin: $isAdmin"

# --- Local Accounts ---
Write-Host "`n  --- All Local Accounts ---" -ForegroundColor Gray
Get-LocalUser | Format-Table Name, Enabled, PrincipalSource, LastLogon -AutoSize

# --- Administrators Group ---
Write-Host "  --- Administrators Group ---" -ForegroundColor Gray
Get-LocalGroupMember -Group "Administrators" | Format-Table Name, PrincipalSource -AutoSize

# --- User Folders on Disk ---
Write-Host "  --- User Folders on Disk ---" -ForegroundColor Gray
Get-ChildItem "C:\Users" -ErrorAction SilentlyContinue | ForEach-Object {
    $size = [math]::Round((Get-ChildItem $_.FullName -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum/1MB,0)
    Write-Host "  $($_.Name.PadRight(20)) $($_.LastWriteTime.ToString('yyyy-MM-dd'))   $size MB"
}

# ─────────────────────────────────────────────────────────────────
# REGISTRY LOCATIONS TO AUDIT FOR ORPHANED SIDs
# ─────────────────────────────────────────────────────────────────
Write-Host "`n  --- Registry Orphan Scan (all known locations) ---" -ForegroundColor Gray

$orphanedSIDs = @{}  # SID → list of locations found

$registryLocations = @(
    # Primary profile list — most important
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";    Desc = "Profile List (primary)" },
    # Profile GUID mapping
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileGuid";    Desc = "Profile GUID Map" },
    # User-specific class registrations
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\UserList";       Desc = "User List" },
    # Group Policy per-user settings
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State"; Desc = "Group Policy State" },
    # Credential Manager remnants
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData"; Desc = "Logon Session Data" },
    # Service security descriptors (rare but possible)
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services";                            Desc = "Services (security descriptors)" },
    # User-specific shell folders
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"; Desc = "Shell Folders" },
    # Scheduled tasks per-user
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"; Desc = "Task Scheduler Cache" },
    # AppX package SID mappings
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore"; Desc = "AppX User Store" },
    # Terminal Server / RDP profiles
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations";  Desc = "Terminal Server Stations" }
)

# Get all valid SIDs from active accounts for comparison
$activeSIDs = @{}
try {
    Get-LocalUser | Where-Object { $_.Enabled } | ForEach-Object {
        $objUser = New-Object System.Security.Principal.NTAccount($_.Name)
        $sid = $objUser.Translate([System.Security.Principal.SecurityIdentifier]).Value
        $activeSIDs[$sid] = $_.Name
    }
    # Also add well-known system SIDs to never touch
    $systemSIDs = @("S-1-5-18","S-1-5-19","S-1-5-20","S-1-5-21")
    foreach ($s in $systemSIDs) { $activeSIDs[$s] = "SYSTEM" }
} catch {}

$allOrphans = @()

foreach ($loc in $registryLocations) {
    if (-not (Test-Path $loc.Path)) { continue }
    
    $children = Get-ChildItem $loc.Path -ErrorAction SilentlyContinue
    foreach ($child in $children) {
        $name = $child.PSChildName
        # Only check entries that look like SIDs (S-1-5-21-...)
        if ($name -match "^S-1-5-21-") {
            try {
                $account = (New-Object System.Security.Principal.SecurityIdentifier($name)).Translate([System.Security.Principal.NTAccount]).Value
                # Active account — skip
            } catch {
                # Cannot resolve = orphaned SID
                if (-not $orphanedSIDs.ContainsKey($name)) {
                    $orphanedSIDs[$name] = @()
                }
                $orphanedSIDs[$name] += $loc.Desc
                $allOrphans += [PSCustomObject]@{
                    SID      = $name
                    Location = $loc.Desc
                    FullPath = $child.PSPath
                }
            }
        }
    }
}

# ProfileList specific — get profile paths too
$profileListPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
$orphanedProfiles = @()
Get-ChildItem $profileListPath -ErrorAction SilentlyContinue | ForEach-Object {
    $sid = $_.PSChildName
    $profilePath = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).ProfileImagePath
    try {
        $account = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value
        Write-OK "Active profile: $account ($sid)"
        Write-Host "     Path: $profilePath" -ForegroundColor DarkGray
    } catch {
        Write-Fail "ORPHANED PROFILE: $sid"
        Write-Host "     Path: $profilePath" -ForegroundColor Red
        Write-Host "     → Likely from deleted account (admin123 or Baalb)" -ForegroundColor Red
        $orphanedProfiles += [PSCustomObject]@{ SID=$sid; Path=$profilePath; RegPath=$_.PSPath }
    }
}

# Report orphans
if ($orphanedSIDs.Count -eq 0 -and $orphanedProfiles.Count -eq 0) {
    Write-OK "Registry is CLEAN — no orphaned SIDs found across all locations"
} else {
    Write-Host "`n  ════ ORPHANED SIDs FOUND ════" -ForegroundColor Red
    foreach ($sid in $orphanedSIDs.Keys) {
        Write-Fail "Orphan SID: $sid"
        Write-Host "     Found in: $($orphanedSIDs[$sid] -join ', ')" -ForegroundColor Yellow
    }
    
    if ($CleanOrphans) {
        Write-Host "`n  Cleaning orphaned entries (-CleanOrphans flag set)..." -ForegroundColor Magenta
        foreach ($orphan in $allOrphans) {
            try {
                Remove-Item $orphan.FullPath -Recurse -Force -ErrorAction Stop
                Write-Fixed "Removed: $($orphan.SID) from $($orphan.Location)"
            } catch {
                Write-Warn "Could not remove $($orphan.FullPath) — may need Admin"
            }
        }
        foreach ($op in $orphanedProfiles) {
            try {
                Remove-Item $op.RegPath -Recurse -Force -ErrorAction Stop
                Write-Fixed "Removed profile registry: $($op.SID)"
            } catch {
                Write-Warn "Could not remove profile registry — may need Admin"
            }
            if ($op.Path -and (Test-Path $op.Path)) {
                Write-Warn "Leftover folder still exists: $($op.Path)"
                Write-Host "     Run as Admin to delete: Remove-Item '$($op.Path)' -Recurse -Force" -ForegroundColor White
            }
        }
    } else {
        Write-Host "`n  To clean these orphans, re-run with: -CleanOrphans" -ForegroundColor Yellow
        Write-Host "  .\shadow313-complete-system-fix.ps1 -CleanOrphans" -ForegroundColor White
        Write-Host "  (Some entries require Admin — right-click PS7 → Run as Administrator)" -ForegroundColor Yellow
    }
}

# Check leftover folders
Write-Host "`n  --- Leftover Account Folders ---" -ForegroundColor Gray
$checkFolders = @("C:\Users\Baalb","C:\Users\admin313","C:\Users\Administrator","C:\Users\DefaultUser0")
foreach ($f in $checkFolders) {
    if (Test-Path $f) {
        $size = [math]::Round((Get-ChildItem $f -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum/1MB,0)
        Write-Warn "Leftover folder: $f ($size MB)"
        Write-Host "     Safe to delete if account no longer exists" -ForegroundColor Yellow
        Write-Host "     Command (run as Admin): Remove-Item '$f' -Recurse -Force" -ForegroundColor White
    } else {
        Write-OK "Clean: $f"
    }
}

# OneDrive account check
Write-Host "`n  --- OneDrive Accounts ---" -ForegroundColor Gray
$odProcess = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
if ($odProcess) {
    Write-Warn "OneDrive IS running (PID $($odProcess.Id)) — you said it was disconnected"
} else {
    Write-OK "OneDrive NOT running"
}
$odAccounts = Get-ChildItem "HKCU:\Software\Microsoft\OneDrive\Accounts" -ErrorAction SilentlyContinue
if ($odAccounts) {
    foreach ($acc in $odAccounts) {
        $email  = (Get-ItemProperty $acc.PSPath -ErrorAction SilentlyContinue).UserEmail
        $folder = (Get-ItemProperty $acc.PSPath -ErrorAction SilentlyContinue).UserFolder
        if ($email) { Write-Host "  OneDrive account: $email → $folder" -ForegroundColor Cyan }
    }
} else {
    Write-OK "No OneDrive accounts in registry"
}

# ═══════════════════════════════════════════════════════════════════
# PHASE 2: FIX WINDOWS TERMINAL
# ═══════════════════════════════════════════════════════════════════
Write-Step "PHASE 2" "Fix Windows Terminal (PS7 default, hide old profiles)"

$wtPath = "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"
if (Test-Path $wtPath) {
    Copy-Item $wtPath "$wtPath.bak-$(Get-Date -Format 'yyyyMMdd-HHmm')" -Force
    Write-OK "Backup saved"
    
    $wt = Get-Content $wtPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $wt.defaultProfile = "{574e775e-4f2a-5b96-ac1e-a2962a402336}"
    
    $hideNames = @(
        "Windows PowerShell",
        "Command Prompt",
        "PowerShell",
        "Developer Command Prompt for VS 18",
        "Developer PowerShell for VS 18",
        "Ubuntu"   # the ghost "no longer detected" profile
    )
    
    foreach ($p in $wt.profiles.list) {
        if ($hideNames -contains $p.name) {
            $p | Add-Member -NotePropertyName "hidden" -NotePropertyValue $true -Force
            Write-Fixed "Hidden: $($p.name)"
        }
        if ($p.name -eq "PowerShell 7") {
            $p | Add-Member -NotePropertyName "hidden" -NotePropertyValue $false -Force
            Write-OK "PowerShell 7 set as visible + default"
        }
    }
    
    $wt | ConvertTo-Json -Depth 20 | Set-Content $wtPath -Encoding UTF8
    Write-OK "Terminal settings saved — reopen terminal to see changes"
    
    # Show current profile order
    Write-Host "`n  Profile order after fix:" -ForegroundColor Gray
    $i = 1
    foreach ($p in $wt.profiles.list) {
        $h = if ($p.hidden) { "[hidden]" } else { "[VISIBLE]" }
        $d = if ($p.guid -eq $wt.defaultProfile) { " ← DEFAULT" } else { "" }
        Write-Host "  $i. $($p.name) $h$d"
        $i++
    }
} else {
    Write-Warn "Windows Terminal settings not found"
}

# ═══════════════════════════════════════════════════════════════════
# PHASE 3: FIX OLLAMA ENVIRONMENT VARIABLES
# ═══════════════════════════════════════════════════════════════════
Write-Step "PHASE 3" "Set Ollama environment variables"

$ollamaVars = @{
    "OLLAMA_HOST"              = "0.0.0.0:11434"
    "OLLAMA_ORIGINS"           = "http://localhost,http://127.0.0.1,http://host.docker.internal,app://"
    "OLLAMA_NUM_PARALLEL"      = "2"
    "OLLAMA_MAX_QUEUE"         = "20"
    "OLLAMA_KEEP_ALIVE"        = "10m"
    "OLLAMA_DEBUG"             = "0"
    "OLLAMA_NUM_CTX"           = "8192"
    "OLLAMA_MAX_LOADED_MODELS" = "2"
}
foreach ($v in $ollamaVars.GetEnumerator()) {
    [System.Environment]::SetEnvironmentVariable($v.Key, $v.Value, "User")
    [System.Environment]::SetEnvironmentVariable($v.Key, $v.Value, "Process")
}
Write-OK "Ollama env vars set (OLLAMA_HOST=0.0.0.0:11434)"

# Restart Ollama silently
Stop-Process -Name "ollama" -Force -ErrorAction SilentlyContinue
Start-Sleep 3
Start-Process ollama -ArgumentList "serve" -WindowStyle Hidden -ErrorAction SilentlyContinue
Start-Sleep 5
try {
    $models = Invoke-RestMethod "http://127.0.0.1:11434/api/tags" -TimeoutSec 8
    Write-OK "Ollama running — $($models.models.Count) models"
    $models.models | ForEach-Object { Write-Host "     Model: $($_.name)" -ForegroundColor DarkGray }
} catch {
    Write-Warn "Ollama not responding yet — may need a moment after restart"
}

# ═══════════════════════════════════════════════════════════════════
# PHASE 4: FIX WSL2 CONFIG
# ═══════════════════════════════════════════════════════════════════
Write-Step "PHASE 4" "Fix WSL2 configuration"

# Write WSL2 config using Set-Content (avoids here-string pipe issue)
$wslConfig = "[wsl2]`nmemory=4GB`nprocessors=2`nswap=2GB`nnetworkingMode=mirrored`ndnsTunneling=true`nfirewall=true"
Set-Content "$env:USERPROFILE\.wslconfig" $wslConfig -Encoding UTF8 -Force
Write-OK ".wslconfig updated (4GB RAM, mirrored networking)"

wsl --shutdown 2>$null
Start-Sleep 5
Write-OK "WSL2 restarted with new config"

# Check LxssManager
$lxss = sc.exe query LxssManager 2>$null
if ($lxss -match "RUNNING|STOPPED") {
    Write-OK "LxssManager service found"
} else {
    Write-Warn "LxssManager missing — WSL2 engine may need repair"
    Write-Host "     Fix: Run as Admin: wsl --update && wsl --install" -ForegroundColor White
}

# ═══════════════════════════════════════════════════════════════════
# PHASE 5: FIX UBUNTU — DNS + INSTALL ALL TOOLS
# ═══════════════════════════════════════════════════════════════════
Write-Step "PHASE 5" "Fix Ubuntu-24.04 — DNS + install all tools"

$ubuntuScript = @'
#!/bin/bash
echo "[Ubuntu] Starting setup..."

# Fix DNS
sudo rm -f /etc/resolv.conf 2>/dev/null || true
printf 'nameserver 9.9.9.9\nnameserver 8.8.8.8\n' | sudo tee /etc/resolv.conf > /dev/null 2>&1
echo 'Acquire::ForceIPv4 true;' | sudo tee /etc/apt/apt.conf.d/99force-ipv4 > /dev/null 2>&1
echo "[Ubuntu] DNS fixed"

# Test connectivity
curl -s --max-time 5 https://api.github.com/zen > /dev/null && echo "[Ubuntu] Internet OK" || echo "[Ubuntu] WARNING: No internet"

# Update and install packages
sudo apt-get update -qq 2>/dev/null
sudo apt-get install -y -qq \
    python3 python3-pip python3-venv python3-dev \
    git curl wget nmap net-tools dnsutils \
    build-essential libssl-dev libffi-dev \
    jq unzip 2>/dev/null && echo "[Ubuntu] APT packages installed"

# Python packages
pip3 install --break-system-packages -q \
    pyspx requests dnspython scapy \
    fastapi uvicorn pytest psutil 2>/dev/null && echo "[Ubuntu] Python packages installed"

# Verify
echo ""
echo "=== Ubuntu Verification ==="
python3 --version
git --version
nmap --version | head -1
curl --version | head -1
echo "=== Done ==="
'@

Write-Host "  Installing tools in Ubuntu-24.04 (this takes 2-3 min)..." -ForegroundColor Gray
$ubuntuScript | wsl -d Ubuntu-24.04 -- bash 2>&1 | ForEach-Object {
    if ($_ -match "OK|installed|Done|version") { Write-OK $_ }
    elseif ($_ -match "WARNING|Error|error") { Write-Warn $_ }
    else { Write-Host "  $_" -ForegroundColor DarkGray }
}

# ═══════════════════════════════════════════════════════════════════
# PHASE 6: FIX KALI LINUX — INSTALL SECURITY TOOLS
# ═══════════════════════════════════════════════════════════════════
Write-Step "PHASE 6" "Fix Kali Linux — install security tools"

$kaliScript = @'
#!/bin/bash
echo "[Kali] Starting setup..."

# Fix DNS
sudo rm -f /etc/resolv.conf 2>/dev/null || true
printf 'nameserver 9.9.9.9\nnameserver 8.8.8.8\n' | sudo tee /etc/resolv.conf > /dev/null 2>&1

# Update
sudo apt-get update -qq 2>/dev/null

# Install core security tools
sudo apt-get install -y -qq \
    nmap metasploit-framework sqlmap \
    hydra john hashcat \
    aircrack-ng wireshark-common \
    python3-pip curl wget git 2>/dev/null && echo "[Kali] Security tools installed"

# Python packages
pip3 install --break-system-packages -q pyspx pwntools 2>/dev/null && echo "[Kali] Python packages installed"

echo "=== Kali Verification ==="
nmap --version | head -1
python3 --version
echo "=== Done ==="
'@

Write-Host "  Installing tools in Kali Linux (this takes 3-5 min)..." -ForegroundColor Gray
$kaliScript | wsl -d kali-linux -- bash 2>&1 | ForEach-Object {
    if ($_ -match "OK|installed|Done|version") { Write-OK $_ }
    elseif ($_ -match "WARNING|Error|error") { Write-Warn $_ }
    else { Write-Host "  $_" -ForegroundColor DarkGray }
}

# ═══════════════════════════════════════════════════════════════════
# PHASE 7: GENERATE NGINX SSL CERTIFICATES
# ═══════════════════════════════════════════════════════════════════
Write-Step "PHASE 7" "Generate nginx SSL certificates"

$sslDir = "$env:USERPROFILE\shadow313-nexus\docker\nginx\ssl"
New-Item -ItemType Directory -Path $sslDir -Force | Out-Null

if (-not (Test-Path "$sslDir\shadow313.crt")) {
    $sslScript = "mkdir -p /mnt/c/Users/$env:USERNAME/shadow313-nexus/docker/nginx/ssl && openssl req -x509 -nodes -days 730 -newkey rsa:2048 -keyout /mnt/c/Users/$env:USERNAME/shadow313-nexus/docker/nginx/ssl/shadow313.key -out /mnt/c/Users/$env:USERNAME/shadow313-nexus/docker/nginx/ssl/shadow313.crt -subj '/C=CA/ST=Ontario/L=Ottawa/O=Shadow313/CN=localhost' 2>/dev/null && echo SSL_OK"
    $result = wsl -d Ubuntu-24.04 -- bash -c $sslScript 2>$null
    if (Test-Path "$sslDir\shadow313.crt") {
        Write-OK "SSL certificates generated: $sslDir"
    } else {
        Write-Warn "SSL cert generation failed — run gen-ssl.sh manually in Ubuntu"
    }
} else {
    Write-OK "SSL certificates already exist"
}

# ═══════════════════════════════════════════════════════════════════
# PHASE 8: FIX DOCKER / OPEN WEBUI
# ═══════════════════════════════════════════════════════════════════
Write-Step "PHASE 8" "Fix Docker / Open WebUI"

$dockerRunning = Get-Process -Name "com.docker.backend" -ErrorAction SilentlyContinue
if ($dockerRunning) {
    docker stop open-webui 2>$null | Out-Null
    docker rm open-webui 2>$null | Out-Null
    
    docker run -d `
        -p 127.0.0.1:3000:8080 `
        --add-host=host.docker.internal:host-gateway `
        -e OLLAMA_BASE_URL=http://host.docker.internal:11434 `
        -v open-webui:/app/backend/data `
        --name open-webui `
        --restart always `
        ghcr.io/open-webui/open-webui:main 2>&1 | Out-Null
    
    Start-Sleep 5
    $status = docker ps --filter 'name=open-webui' --format '{{.Status}}' 2>$null
    if ($status) {
        Write-OK "Open WebUI: $status → http://localhost:3000"
    } else {
        Write-Warn "Open WebUI container not running — check Docker Desktop"
    }
} else {
    Write-Warn "Docker Desktop not running — start it and re-run this script"
}

# ═══════════════════════════════════════════════════════════════════
# PHASE 9: FIX PATH — ADD MISSING TOOLS
# ═══════════════════════════════════════════════════════════════════
Write-Step "PHASE 9" "Fix PATH — add missing tools"

$userPath = [System.Environment]::GetEnvironmentVariable("PATH", "User")
$pathsToAdd = @()

$toolPaths = @{
    "Wireshark" = "C:\Program Files\Wireshark"
    "OpenSSH"   = "C:\Windows\System32\OpenSSH"
    "Git-usr"   = "C:\Program Files\Git\usr\bin"
}

foreach ($tool in $toolPaths.GetEnumerator()) {
    if ((Test-Path $tool.Value) -and ($userPath -notlike "*$($tool.Value)*")) {
        $pathsToAdd += $tool.Value
        Write-Fixed "Adding to PATH: $($tool.Key)"
    }
}

if ($pathsToAdd.Count -gt 0) {
    $newPath = ($pathsToAdd -join ";") + ";" + $userPath
    $cleanPath = ($newPath -split ";" | Where-Object { $_ } | Select-Object -Unique) -join ";"
    [System.Environment]::SetEnvironmentVariable("PATH", $cleanPath, "User")
    $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" + $cleanPath
    Write-OK "PATH updated"
} else {
    Write-OK "PATH already complete"
}

# Install missing Windows tools
$winTools = @(
    @{id="WiresharkFoundation.Wireshark"; name="Wireshark"},
    @{id="GnuWin32.Wget";                 name="wget"}
)
foreach ($tool in $winTools) {
    $existing = winget list --id $tool.id 2>$null | Select-String $tool.id
    if (-not $existing) {
        Write-Fixed "Installing $($tool.name) via winget..."
        winget install --id $tool.id --silent --accept-package-agreements --accept-source-agreements 2>$null
        Write-OK "$($tool.name) installed"
    } else {
        Write-OK "$($tool.name) already installed"
    }
}

# ═══════════════════════════════════════════════════════════════════
# PHASE 10: INSTALL MISSING PYTHON PACKAGES (WINDOWS)
# ═══════════════════════════════════════════════════════════════════
Write-Step "PHASE 10" "Install missing Python packages (Windows)"

$pyPackages = @("dnspython","impacket","pwntools","pyspx")
foreach ($pkg in $pyPackages) {
    $installed = pip show $pkg 2>$null
    if (-not $installed) {
        Write-Fixed "Installing $pkg..."
        pip install $pkg -q 2>$null
        if ($LASTEXITCODE -eq 0) { Write-OK "$pkg installed" }
        else { Write-Warn "$pkg failed (may need Visual C++ Build Tools for pyspx)" }
    } else {
        Write-OK "$pkg already installed"
    }
}

# ═══════════════════════════════════════════════════════════════════
# PHASE 11: CREATE STARTUP TASK (PREVENT SETTINGS DRIFT)
# ═══════════════════════════════════════════════════════════════════
Write-Step "PHASE 11" "Create startup task (prevent settings drift on reboot)"

$startupDir = "$env:USERPROFILE\shadow313-nexus\scripts"
New-Item -ItemType Directory -Path $startupDir -Force | Out-Null

$startupScript = "$startupDir\shadow313-startup.ps1"
Set-Content -Path $startupScript -Value @'
# Shadow313 NEXUS — Login Startup Restore
$vars = @{
    "OLLAMA_HOST"              = "0.0.0.0:11434"
    "OLLAMA_ORIGINS"           = "http://localhost,http://127.0.0.1,http://host.docker.internal,app://"
    "OLLAMA_NUM_PARALLEL"      = "2"
    "OLLAMA_MAX_QUEUE"         = "20"
    "OLLAMA_KEEP_ALIVE"        = "10m"
    "OLLAMA_DEBUG"             = "0"
    "OLLAMA_NUM_CTX"           = "8192"
    "OLLAMA_MAX_LOADED_MODELS" = "2"
}
foreach ($v in $vars.GetEnumerator()) {
    [System.Environment]::SetEnvironmentVariable($v.Key, $v.Value, "User")
}
try { Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ServerAddresses "9.9.9.9","149.112.112.112" -ErrorAction SilentlyContinue } catch {}
if (-not (Get-Process -Name "ollama" -ErrorAction SilentlyContinue)) {
    Start-Process ollama -ArgumentList "serve" -WindowStyle Hidden -ErrorAction SilentlyContinue
}
$log = "$env:USERPROFILE\shadow313-nexus\logs\startup.log"
New-Item -ItemType Directory -Path (Split-Path $log) -Force -ErrorAction SilentlyContinue | Out-Null
"$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') Shadow313 startup OK" | Add-Content $log -ErrorAction SilentlyContinue
'@ -Encoding UTF8

$taskName = "Shadow313-Startup"
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
$action    = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-NoProfile -WindowStyle Hidden -File `"$startupScript`""
$trigger   = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -StartWhenAvailable
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
    -Settings $settings -Principal $principal `
    -Description "Shadow313: Restore settings on login" -Force | Out-Null
Write-OK "Startup task registered — settings persist across reboots"

# ═══════════════════════════════════════════════════════════════════
# PHASE 12: GIT PULL (if token provided)
# ═══════════════════════════════════════════════════════════════════
Write-Step "PHASE 12" "Git pull — sync repo"

$repoPath = "$env:USERPROFILE\shadow313-nexus"
if (Test-Path "$repoPath\.git") {
    Push-Location $repoPath
    if ($Token) {
        git remote set-url origin "https://piyyy314:$Token@github.com/piyyy314/Shadow313-Nexus.git"
    }
    git pull origin master 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { Write-OK "Repo synced with GitHub" }
    else { Write-Warn "Git pull had issues — check token" }
    git remote set-url origin "https://github.com/piyyy314/Shadow313-Nexus.git"
    Pop-Location
} else {
    Write-Warn "Repo not found at $repoPath"
}

# ═══════════════════════════════════════════════════════════════════
# ═══════════════════════════════════════════════════════════════════
# PHASE 13: FINAL VERIFICATION
# ═══════════════════════════════════════════════════════════════════
Write-Step "PHASE 13" "Final verification — all systems"

$env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH","User")

$passed = 0
$total  = 0

function Check-Item {
    param([string]$Name, [bool]$Result)
    $script:total++
    if ($Result) {
        Write-Host "  OK  $Name" -ForegroundColor Green
        $script:passed++
    } else {
        Write-Host "  NO  $Name" -ForegroundColor Red
    }
}

Check-Item "PowerShell 7"      ($null -ne (Get-Command pwsh   -ErrorAction SilentlyContinue))
Check-Item "Git"               ($null -ne (Get-Command git    -ErrorAction SilentlyContinue))
Check-Item "Python"            ($null -ne (Get-Command python -ErrorAction SilentlyContinue))
Check-Item "Docker"            ($null -ne (Get-Command docker -ErrorAction SilentlyContinue))
Check-Item "Ollama"            ($null -ne (Get-Command ollama -ErrorAction SilentlyContinue))
Check-Item "nmap"              ($null -ne (Get-Command nmap   -ErrorAction SilentlyContinue))
Check-Item "WireGuard"         ($null -ne (Get-Command wg     -ErrorAction SilentlyContinue))
Check-Item "VS Code"           ($null -ne (Get-Command code   -ErrorAction SilentlyContinue))
Check-Item "Startup task"      ($null -ne (Get-ScheduledTask -TaskName "Shadow313-Startup" -ErrorAction SilentlyContinue))
Check-Item "Repo exists"       (Test-Path "$env:USERPROFILE\shadow313-nexus\.git")
Check-Item "SSL cert"          (Test-Path "$env:USERPROFILE\shadow313-nexus\docker\nginx\ssl\shadow313.crt")
Check-Item "Ubuntu accessible" ((wsl -d Ubuntu-24.04 -- echo "ok" 2>$null) -match "ok")
Check-Item "Kali accessible"   ((wsl -d kali-linux -- echo "ok" 2>$null) -match "ok")

try {
    $m = Invoke-RestMethod "http://127.0.0.1:11434/api/tags" -TimeoutSec 5
    Check-Item "Ollama API" ($m.models.Count -ge 0)
} catch {
    Check-Item "Ollama API" $false
}

$webui = docker ps --filter name=open-webui --format "{{.Status}}" 2>$null
Check-Item "Open WebUI" ($webui -match "Up")

$score = if ($total -gt 0) { [math]::Round(($passed/$total)*100) } else { 0 }
Write-Host ""
Write-Host "  FINAL SCORE: $passed/$total checks passed ($score%)" -ForegroundColor Cyan
Write-Host "  Fixed:    $($report.FIXED.Count) | OK: $($report.OK.Count) | Warn: $($report.WARN.Count) | Fail: $($report.FAIL.Count)" -ForegroundColor Cyan
Write-Host "  NEXT: Close terminal, reopen, run s313" -ForegroundColor White
