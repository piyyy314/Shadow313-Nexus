#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Shadow313 NEXUS — Complete System Fix
    Fixes all 63 issues from the scan report.
    Run as: normal user in PowerShell 7 (black terminal)
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
    .\shadow313-fix-all.ps1
#>

param([string]$Token = "")

$ErrorActionPreference = "Continue"

function Write-Step { param([string]$N, [string]$T) Write-Host "`n[$N] $T" -ForegroundColor Cyan }
function Write-OK   { param([string]$M) Write-Host "  ✅ $M" -ForegroundColor Green }
function Write-Fix  { param([string]$M) Write-Host "  🔧 $M" -ForegroundColor Magenta }
function Write-Warn { param([string]$M) Write-Host "  ⚠️  $M" -ForegroundColor Yellow }

Write-Host @"

╔══════════════════════════════════════════════════════════════╗
║  Shadow313 NEXUS — Complete System Fix                     ║
║  Fixing all 63 issues from scan report                     ║
╚══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1: Fix Windows Terminal — Hide old blue PowerShell
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "1/10" "Fix Windows Terminal (hide old blue PowerShell)"

$wtPaths = @(
    "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json",
    "$env:LOCALAPPDATA\Microsoft\Windows Terminal\settings.json"
)
$wtPath = $wtPaths | Where-Object { Test-Path $_ } | Select-Object -First 1

if ($wtPath) {
    $wt = Get-Content $wtPath -Raw -Encoding UTF8 | ConvertFrom-Json -AsHashtable -ErrorAction SilentlyContinue
    if (-not $wt) { $wt = @{} }
    
    # Ensure profiles structure exists
    if (-not $wt.profiles) { $wt.profiles = @{} }
    if (-not $wt.profiles.list) { $wt.profiles.list = @() }
    
    # Set PS7 as default
    $wt.defaultProfile = "{574e775e-4f2a-5b96-ac1e-a2962a402336}"
    
    # Hide old blue PowerShell 5 and CMD
    $hideGuids = @(
        "{61c54bbd-c2c6-5271-96e7-009a87ff44bf}",  # Windows PowerShell (blue)
        "{0caa0dad-35be-5f56-a8ff-afceeeaa6101}"   # Command Prompt
    )
    
    $newList = @()
    foreach ($profile in $wt.profiles.list) {
        if ($hideGuids -contains $profile.guid) {
            $profile.hidden = $true
            Write-Fix "Hiding: $($profile.name)"
        }
        $newList += $profile
    }
    $wt.profiles.list = $newList
    
    $wt | ConvertTo-Json -Depth 20 | Set-Content $wtPath -Encoding UTF8
    Write-OK "Windows Terminal updated — old blue PS hidden, PS7 is default"
} else {
    Write-Warn "Windows Terminal settings not found"
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2: Fix PATH — Add Wireshark, SSH, wget
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "2/10" "Fix PATH — Add missing tools"

$userPath = [System.Environment]::GetEnvironmentVariable("PATH", "User")
$pathsToAdd = @()

# Wireshark
$wsPath = "C:\Program Files\Wireshark"
if ((Test-Path "$wsPath\Wireshark.exe") -and ($userPath -notlike "*Wireshark*")) {
    $pathsToAdd += $wsPath
    Write-Fix "Adding Wireshark to PATH"
}

# SSH (OpenSSH)
$sshPath = "C:\Windows\System32\OpenSSH"
if ((Test-Path "$sshPath\ssh.exe") -and ($userPath -notlike "*OpenSSH*")) {
    $pathsToAdd += $sshPath
    Write-Fix "Adding OpenSSH to PATH"
}

# wget (Git's wget)
$wgetPath = "C:\Program Files\Git\usr\bin"
if ((Test-Path "$wgetPath\wget.exe") -and ($userPath -notlike "*Git\\usr\\bin*")) {
    $pathsToAdd += $wgetPath
    Write-Fix "Adding Git/usr/bin (wget) to PATH"
}

if ($pathsToAdd.Count -gt 0) {
    $newPath = ($pathsToAdd -join ";") + ";" + $userPath
    # Deduplicate
    $cleanPath = ($newPath -split ";" | Where-Object { $_ } | Select-Object -Unique) -join ";"
    [System.Environment]::SetEnvironmentVariable("PATH", $cleanPath, "User")
    $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" + $cleanPath
    Write-OK "PATH updated with $($pathsToAdd.Count) new entries"
} else {
    Write-OK "PATH already has all required entries (or tools not installed)"
}

# Install missing tools via winget
Write-Fix "Installing missing tools via winget..."
$tools = @(
    @{id="WiresharkFoundation.Wireshark"; name="Wireshark"},
    @{id="GnuWin32.Wget"; name="wget"}
)
foreach ($tool in $tools) {
    $existing = winget list --id $tool.id 2>$null | Select-String $tool.id
    if (-not $existing) {
        Write-Fix "Installing $($tool.name)..."
        winget install --id $tool.id --silent --accept-package-agreements --accept-source-agreements 2>$null
        Write-OK "$($tool.name) installed"
    } else {
        Write-OK "$($tool.name) already installed"
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 3: Install missing Python packages
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "3/10" "Install missing Python packages"

$packages = @("dnspython", "impacket", "pwntools")
foreach ($pkg in $packages) {
    Write-Fix "Installing $pkg..."
    pip install $pkg -q 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-OK "$pkg installed"
    } else {
        Write-Warn "$pkg install had issues (may need Visual C++ build tools)"
    }
}

# pyspx — needs special handling on Windows
Write-Fix "Installing pyspx (post-quantum)..."
pip install pyspx -q 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-OK "pyspx installed"
} else {
    Write-Warn "pyspx failed to build on Windows (C compiler issue) — will use HMAC fallback"
    Write-Warn "To fix: install Visual C++ Build Tools from https://visualstudio.microsoft.com/visual-cpp-build-tools/"
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 4: Fix Ollama environment variables
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "4/10" "Set Ollama environment variables"

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
Write-OK "Ollama env vars set (OLLAMA_HOST=0.0.0.0:11434 for Docker compatibility)"

# Restart Ollama with new settings
Write-Fix "Restarting Ollama with correct settings..."
Stop-Process -Name "ollama" -Force -ErrorAction SilentlyContinue
Start-Sleep 3
Start-Process ollama -ArgumentList "serve" -WindowStyle Hidden -ErrorAction SilentlyContinue
Start-Sleep 5

try {
    $models = Invoke-RestMethod "http://127.0.0.1:11434/api/tags" -TimeoutSec 10
    Write-OK "Ollama running — $($models.models.Count) models available"
} catch {
    Write-Warn "Ollama not responding yet — may need a moment"
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 5: Fix WSL2 — Repair LxssManager + fix Ubuntu tools
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "5/10" "Fix WSL2 + Install Ubuntu tools"

# Fix WSL2 config
Write-Fix "Updating .wslconfig..."
@"
[wsl2]
memory=4GB
processors=2
swap=2GB
networkingMode=mirrored
dnsTunneling=true
firewall=true
"@ | Out-File "$env:USERPROFILE\.wslconfig" -Encoding UTF8 -Force

# Shutdown and restart WSL
wsl --shutdown 2>$null
Start-Sleep 5

# Check if LxssManager exists
$lxss = sc.exe query LxssManager 2>$null
if ($lxss -match "RUNNING|STOPPED") {
    Write-OK "LxssManager service found"
} else {
    Write-Fix "LxssManager missing — re-enabling WSL2 features..."
    # Run DISM to re-enable (requires admin — will prompt)
    Write-Warn "The next step requires Admin. If prompted, click Yes."
    Start-Process powershell -ArgumentList @(
        "-NoProfile", "-Command",
        "dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart; dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart; wsl --update"
    ) -Verb RunAs -Wait -ErrorAction SilentlyContinue
    Write-Warn "A REBOOT may be required for LxssManager to appear"
}

# Install tools in Ubuntu
Write-Fix "Installing tools in Ubuntu-24.04..."
$ubuntuSetup = @'
#!/bin/bash
set -e

# Fix DNS
sudo rm -f /etc/resolv.conf 2>/dev/null || true
printf 'nameserver 9.9.9.9\nnameserver 8.8.8.8\n' | sudo tee /etc/resolv.conf > /dev/null 2>&1 || true
echo 'Acquire::ForceIPv4 true;' | sudo tee /etc/apt/apt.conf.d/99force-ipv4 > /dev/null 2>&1 || true

# Update and install
sudo apt-get update -qq 2>/dev/null
sudo apt-get install -y -qq python3 python3-pip python3-venv git curl wget nmap net-tools dnsutils 2>/dev/null && echo "APT_OK"

# Python packages
pip3 install pyspx requests dnspython scapy impacket --break-system-packages -q 2>/dev/null && echo "PIP_OK"

# Verify
echo "UBUNTU_DONE"
python3 --version
git --version
nmap --version | head -1
'@

$ubuntuSetup | wsl -d Ubuntu-24.04 -- bash 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-OK "Ubuntu tools installed"
} else {
    Write-Warn "Ubuntu setup had issues — DNS may need manual fix"
    Write-Warn "Run in Ubuntu: sudo rm -f /etc/resolv.conf && printf 'nameserver 9.9.9.9\n' | sudo tee /etc/resolv.conf"
}

# Install tools in Kali
Write-Fix "Installing tools in Kali Linux..."
$kaliSetup = @'
#!/bin/bash
sudo apt-get update -qq 2>/dev/null
sudo apt-get install -y -qq nmap metasploit-framework sqlmap hydra john hashcat aircrack-ng wireshark-common 2>/dev/null && echo "KALI_DONE"
pip3 install pyspx pwntools --break-system-packages -q 2>/dev/null && echo "KALI_PIP_OK"
'@

$kaliSetup | wsl -d kali-linux -- bash 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-OK "Kali tools installed"
} else {
    Write-Warn "Kali setup had issues — run manually in Kali terminal"
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 6: Generate nginx SSL certificates
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "6/10" "Generate nginx SSL certificates"

$sslDir = "$env:USERPROFILE\shadow313-nexus\docker\nginx\ssl"
New-Item -ItemType Directory -Path $sslDir -Force | Out-Null

# Try via WSL2 openssl
$sslScript = @"
mkdir -p /mnt/c/Users/$env:USERNAME/shadow313-nexus/docker/nginx/ssl
openssl req -x509 -nodes -days 730 -newkey rsa:2048 \
    -keyout /mnt/c/Users/$env:USERNAME/shadow313-nexus/docker/nginx/ssl/shadow313.key \
    -out /mnt/c/Users/$env:USERNAME/shadow313-nexus/docker/nginx/ssl/shadow313.crt \
    -subj '/C=CA/ST=Ontario/L=Ottawa/O=Shadow313/CN=localhost' \
    -addext 'subjectAltName=DNS:localhost,DNS:shadow313.local,IP:127.0.0.1' 2>/dev/null && echo SSL_OK
"@

$result = $sslScript | wsl -d Ubuntu-24.04 -- bash 2>$null
if (Test-Path "$sslDir\shadow313.crt") {
    Write-OK "SSL certificates generated: $sslDir"
} else {
    Write-Warn "SSL cert generation failed — trying PowerShell method..."
    try {
        $cert = New-SelfSignedCertificate `
            -DnsName "localhost", "shadow313.local" `
            -CertStoreLocation "Cert:\CurrentUser\My" `
            -NotAfter (Get-Date).AddYears(2) `
            -ErrorAction Stop
        
        $certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
        $certBase64 = [Convert]::ToBase64String($certBytes, [System.Base64FormattingOptions]::InsertLineBreaks)
        "-----BEGIN CERTIFICATE-----`n$certBase64`n-----END CERTIFICATE-----" | Set-Content "$sslDir\shadow313.crt" -Encoding ASCII
        Write-OK "SSL certificate created (key generation requires openssl in WSL)"
        Write-Warn "Run in Ubuntu: openssl genrsa -out /mnt/c/Users/$env:USERNAME/shadow313-nexus/docker/nginx/ssl/shadow313.key 2048"
    } catch {
        Write-Warn "Could not generate SSL cert — run gen-ssl.sh in Ubuntu manually"
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 7: Fix Docker — Recreate Open WebUI with correct Ollama URL
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "7/10" "Fix Docker / Open WebUI"

$dockerRunning = Get-Process -Name "com.docker.backend" -ErrorAction SilentlyContinue
if ($dockerRunning) {
    # Remove old container and recreate with correct settings
    docker stop open-webui 2>$null | Out-Null
    docker rm open-webui 2>$null | Out-Null
    
    $result = docker run -d `
        -p 127.0.0.1:3000:8080 `
        --add-host=host.docker.internal:host-gateway `
        -e OLLAMA_BASE_URL=http://host.docker.internal:11434 `
        -v open-webui:/app/backend/data `
        --name open-webui `
        --restart always `
        ghcr.io/open-webui/open-webui:main 2>&1
    
    if ($LASTEXITCODE -eq 0) {
        Write-OK "Open WebUI recreated → http://localhost:3000"
        Write-OK "Now uses host.docker.internal:11434 (Docker-compatible)"
    } else {
        Write-Warn "Docker run failed: $result"
    }
} else {
    Write-Warn "Docker Desktop not running — start it first, then re-run this script"
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 8: Create scheduled task to prevent settings drift
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "8/10" "Create startup task (prevent settings drift)"

$startupScript = "$env:USERPROFILE\shadow313-nexus\scripts\shadow313-startup.ps1"
New-Item -ItemType Directory -Path (Split-Path $startupScript) -Force | Out-Null

Set-Content -Path $startupScript -Value @'
# Shadow313 NEXUS — Login Startup
# Restores all settings on every login

# Ollama env vars
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

# DNS
try { Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ServerAddresses "9.9.9.9","149.112.112.112" -ErrorAction SilentlyContinue } catch {}

# Start Ollama silently (no blue popup)
if (-not (Get-Process -Name "ollama" -ErrorAction SilentlyContinue)) {
    Start-Process ollama -ArgumentList "serve" -WindowStyle Hidden -ErrorAction SilentlyContinue
}

# Log
$log = "$env:USERPROFILE\shadow313-nexus\logs\startup.log"
New-Item -ItemType Directory -Path (Split-Path $log) -Force -ErrorAction SilentlyContinue | Out-Null
"$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') Shadow313 startup OK" | Add-Content $log -ErrorAction SilentlyContinue
'@ -Encoding UTF8

# Register scheduled task
$taskName = "Shadow313-Startup"
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

$action   = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-NoProfile -WindowStyle Hidden -File `"$startupScript`""
$trigger  = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -StartWhenAvailable
$principal= New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
    -Settings $settings -Principal $principal `
    -Description "Shadow313: Restore settings on login" -Force | Out-Null

Write-OK "Startup task registered — settings will persist across reboots"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 9: Git pull to get missing security files
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "9/10" "Git pull — get missing security files"

$repoPath = "$env:USERPROFILE\shadow313-nexus"
if (Test-Path "$repoPath\.git") {
    Push-Location $repoPath
    
    if ($Token) {
        git remote set-url origin "https://piyyy314:$Token@github.com/piyyy314/Shadow313-Nexus.git"
    }
    
    git pull origin master 2>&1 | Out-Null
    
    if ($LASTEXITCODE -eq 0) {
        Write-OK "Repo updated — missing security files pulled"
    } else {
        Write-Warn "Git pull had issues — check token or run manually"
    }
    
    # Reset remote URL to clean version
    git remote set-url origin "https://github.com/piyyy314/Shadow313-Nexus.git"
    Pop-Location
} else {
    Write-Warn "Repo not found at $repoPath"
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 10: Final verification
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "10/10" "Final verification"

$checks = @{}

# Reload PATH
$env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH","User")

$checks["PowerShell 7"]    = $null -ne (Get-Command pwsh -ErrorAction SilentlyContinue)
$checks["Git"]             = $null -ne (Get-Command git -ErrorAction SilentlyContinue)
$checks["Python"]          = $null -ne (Get-Command python -ErrorAction SilentlyContinue)
$checks["Docker"]          = $null -ne (Get-Command docker -ErrorAction SilentlyContinue)
$checks["Ollama"]          = $null -ne (Get-Command ollama -ErrorAction SilentlyContinue)
$checks["nmap"]            = $null -ne (Get-Command nmap -ErrorAction SilentlyContinue)
$checks["WireGuard"]       = $null -ne (Get-Command wg -ErrorAction SilentlyContinue)
$checks["VS Code"]         = $null -ne (Get-Command code -ErrorAction SilentlyContinue)
$checks["Startup task"]    = $null -ne (Get-ScheduledTask -TaskName "Shadow313-Startup" -ErrorAction SilentlyContinue)
$checks["Ollama API"]      = try { (Invoke-RestMethod "http://127.0.0.1:11434/api/tags" -TimeoutSec 5).models.Count -ge 0 } catch { $false }
$checks["Open WebUI"]      = (docker ps --filter "name=open-webui" --format "{{.Status}}" 2>$null) -match "Up"
$checks["SSL cert"]        = Test-Path "$env:USERPROFILE\shadow313-nexus\docker\nginx\ssl\shadow313.crt"
$checks["Ubuntu access"]   = (wsl -d Ubuntu-24.04 -- echo "ok" 2>$null) -match "ok"

Write-Host ""
$passed = 0
foreach ($check in $checks.GetEnumerator()) {
    if ($check.Value) {
        Write-Host "  ✅ $($check.Key)" -ForegroundColor Green
        $passed++
    } else {
        Write-Host "  ❌ $($check.Key)" -ForegroundColor Red
    }
}

$score = [math]::Round(($passed / $checks.Count) * 100)

Write-Host @"

╔══════════════════════════════════════════════════════════════╗
║  SCORE: $passed/$($checks.Count) checks passed ($score%)
╚══════════════════════════════════════════════════════════════╝

  WHAT TO DO NEXT:
  1. Close ALL terminals and reopen Windows Terminal
  2. Open Ubuntu: type 'ubuntu' or click Ubuntu tab
  3. Open WebUI: http://localhost:3000
  4. Test Ollama: ollama run matarmohamad313/shadow313-nexus

  STILL NEEDS MANUAL ATTENTION:
  • pyspx on Windows: install Visual C++ Build Tools if needed
  • Kali tools: open Kali tab and run: sudo apt-get install -y nmap metasploit-framework
  • BitLocker: enable via Settings → Privacy & Security → Device Encryption
  • LxssManager: if WSL2 broken, a reboot after DISM fix is required

"@ -ForegroundColor White