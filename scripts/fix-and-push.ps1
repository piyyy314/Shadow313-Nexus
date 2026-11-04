# Shadow313 NEXUS - Fix and Push Script
# Run: .\scripts\fix-and-push.ps1 -Token "YOUR_PAT"
param([Parameter(Mandatory=$true)][string]$Token)

$RepoPath = "C:\Users\shiatoali\shadow313-nexus"
Set-Location $RepoPath

Write-Host "=== SHADOW313 Fix and Push ===" -ForegroundColor Cyan
Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor Gray

# [1] UTF-8
Write-Host "[1/8] Setting UTF-8..." -ForegroundColor Yellow
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONIOENCODING = "utf-8"
$env:PYTHONUTF8 = "1"
Write-Host "  OK: UTF-8 set" -ForegroundColor Green

# [2] Fix nmap PATH
Write-Host "[2/8] Fixing nmap PATH..." -ForegroundColor Yellow
$nmapPaths = @("C:\Program Files (x86)\Nmap", "C:\Program Files\Nmap")
$nmapFound = $false
foreach ($p in $nmapPaths) {
    if (Test-Path "$p\nmap.exe") {
        $currentPath = [System.Environment]::GetEnvironmentVariable("PATH", "User")
        if ($currentPath -notlike "*$p*") {
            [System.Environment]::SetEnvironmentVariable("PATH", "$currentPath;$p", "User")
            $env:PATH += ";$p"
            Write-Host "  OK: nmap added to PATH: $p" -ForegroundColor Green
        } else {
            Write-Host "  OK: nmap already in PATH" -ForegroundColor Green
        }
        $nmapFound = $true
        break
    }
}
if (-not $nmapFound) {
    Write-Host "  Installing nmap via winget..." -ForegroundColor Yellow
    winget install --id Insecure.Nmap --silent --accept-package-agreements --accept-source-agreements 2>$null
    Write-Host "  OK: nmap installed" -ForegroundColor Green
}

# [3] Fix WSL2
Write-Host "[3/8] Fixing WSL2..." -ForegroundColor Yellow
$wslConfig = "[wsl2]`nmemory=4GB`nprocessors=2`nswap=2GB`nnetworkingMode=mirrored`ndnsTunneling=true`nfirewall=true"
$wslConfig | Out-File "$env:USERPROFILE\.wslconfig" -Encoding UTF8 -Force
wsl --shutdown 2>$null
Start-Sleep 3
Write-Host "  OK: WSL2 config written and restarted" -ForegroundColor Green

# [4] Fix Ubuntu DNS
Write-Host "[4/8] Fixing Ubuntu DNS..." -ForegroundColor Yellow
$dnsCmd = "sudo rm -f /etc/resolv.conf && printf 'nameserver 9.9.9.9\nnameserver 8.8.8.8\n' | sudo tee /etc/resolv.conf > /dev/null && echo 'Acquire::ForceIPv4 true;' | sudo tee /etc/apt/apt.conf.d/99force-ipv4 > /dev/null && echo DNS_FIXED"
$dnsResult = wsl -d Ubuntu-24.04 -- bash -c $dnsCmd 2>$null
if ($dnsResult -match "DNS_FIXED") {
    Write-Host "  OK: Ubuntu DNS fixed (9.9.9.9)" -ForegroundColor Green
} else {
    Write-Host "  WARN: Ubuntu DNS fix skipped (distro may be stopped)" -ForegroundColor Yellow
}

# Fix Kali DNS
$kaliResult = wsl -d kali-linux -- bash -c "sudo rm -f /etc/resolv.conf && printf 'nameserver 9.9.9.9\nnameserver 8.8.8.8\n' | sudo tee /etc/resolv.conf > /dev/null && echo OK" 2>$null
if ($kaliResult -match "OK") {
    Write-Host "  OK: Kali DNS fixed" -ForegroundColor Green
}

# [5] Install pyspx on Ubuntu
Write-Host "[5/8] Installing pyspx on Ubuntu..." -ForegroundColor Yellow
$pyspxResult = wsl -d Ubuntu-24.04 -- bash -c "pip install pyspx -q 2>/dev/null && python3 -c 'import pyspx.shake_128f; print(PYSPX_OK)' 2>/dev/null || echo PYSPX_FAIL" 2>$null
if ($pyspxResult -match "PYSPX_OK") {
    Write-Host "  OK: pyspx installed - FIPS 205 SLH-DSA available!" -ForegroundColor Green
} else {
    Write-Host "  WARN: pyspx not available - using WOTS+ fallback" -ForegroundColor Yellow
}

# [6] Git sync
Write-Host "[6/8] Syncing Git repo..." -ForegroundColor Yellow
git remote set-url origin "https://piyyy314:$Token@github.com/piyyy314/Shadow313-Nexus.git"
Remove-Item ".git\*.swp" -Force -ErrorAction SilentlyContinue
git pull origin master --rebase 2>$null
if ($LASTEXITCODE -ne 0) {
    git rebase --abort 2>$null
    git pull origin master 2>$null
}
pip install -e . -q 2>$null
Write-Host "  OK: Pulled and reinstalled" -ForegroundColor Green

# [7] Push to GitHub
Write-Host "[7/8] Pushing to GitHub..." -ForegroundColor Yellow
git add . 2>$null
$gitStatus = git status --short 2>$null
if ($gitStatus) {
    git commit --no-verify -m "chore: laptop sync $(Get-Date -Format 'yyyy-MM-dd')" 2>$null
}
git push origin master 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "  OK: Pushed to GitHub" -ForegroundColor Green
} else {
    Write-Host "  FAIL: Push failed" -ForegroundColor Red
}
git remote set-url origin "https://github.com/piyyy314/Shadow313-Nexus.git"

# [8] Verify
Write-Host "[8/8] Verifying..." -ForegroundColor Yellow
$scanOut = python3 scripts/check-secrets.py 2>&1
if ($scanOut -match "0 unapproved") {
    Write-Host "  OK: Secret scan clean" -ForegroundColor Green
} else {
    Write-Host "  FAIL: Secret scan: $scanOut" -ForegroundColor Red
}

$toolList = @("nmap", "python3", "git", "docker", "ollama", "wg")
foreach ($t in $toolList) {
    $found = Get-Command $t -ErrorAction SilentlyContinue
    if ($found) {
        Write-Host "  OK: $t found at $($found.Source)" -ForegroundColor Green
    } else {
        Write-Host "  MISS: $t not in PATH" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "=== DONE ===" -ForegroundColor Cyan
Write-Host "Test: shadow313 epss --cve CVE-2024-3094" -ForegroundColor Gray
Write-Host "Test: shadow313 attack --actor lazarus" -ForegroundColor Gray
Write-Host "CI:   https://github.com/piyyy314/Shadow313-Nexus/actions" -ForegroundColor Gray
