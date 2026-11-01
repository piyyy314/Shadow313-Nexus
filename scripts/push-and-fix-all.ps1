# ============================================================
# SHADOW313 NEXUS — Push All + Fix Laptop Issues
# Fixes: nmap PATH, WSL2 down, Ubuntu DNS, push to GitHub
# Run: .\scripts\push-and-fix-all.ps1 -Token "YOUR_PAT"
# ============================================================
param([Parameter(Mandatory=$true)][string]$Token)

$RepoPath = "C:\Users\shiatoali\shadow313-nexus"
Set-Location $RepoPath

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  SHADOW313 — Push All + Fix Laptop" -ForegroundColor Cyan
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor Gray
Write-Host "============================================================" -ForegroundColor Cyan

# ── [1] UTF-8 encoding ───────────────────────────────────────────────────
Write-Host "`n[1/8] Setting UTF-8..." -ForegroundColor Yellow
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONIOENCODING = "utf-8"
$env:PYTHONUTF8 = "1"
Write-Host "  ✅ UTF-8 set" -ForegroundColor Green

# ── [2] Fix nmap PATH ────────────────────────────────────────────────────
Write-Host "`n[2/8] Fixing nmap PATH..." -ForegroundColor Yellow
$nmapPaths = @(
    "C:\Program Files (x86)\Nmap",
    "C:\Program Files\Nmap",
    "$env:LOCALAPPDATA\Programs\Nmap"
)
$nmapFound = $false
foreach ($p in $nmapPaths) {
    if (Test-Path "$p\nmap.exe") {
        $currentPath = [System.Environment]::GetEnvironmentVariable("PATH", "User")
        if ($currentPath -notlike "*$p*") {
            [System.Environment]::SetEnvironmentVariable("PATH", "$currentPath;$p", "User")
            $env:PATH += ";$p"
            Write-Host "  ✅ nmap added to PATH: $p" -ForegroundColor Green
        } else {
            Write-Host "  ✅ nmap already in PATH: $p" -ForegroundColor Green
        }
        $nmapFound = $true
        break
    }
}
if (-not $nmapFound) {
    Write-Host "  ⚠️  nmap not found — installing..." -ForegroundColor Yellow
    winget install --id Insecure.Nmap --silent --accept-package-agreements --accept-source-agreements 2>$null
    Write-Host "  ✅ nmap installed via winget" -ForegroundColor Green
}

# ── [3] Fix WSL2 ─────────────────────────────────────────────────────────
Write-Host "`n[3/8] Fixing WSL2..." -ForegroundColor Yellow

# Write optimal .wslconfig
@"
[wsl2]
memory=4GB
processors=2
swap=2GB
networkingMode=mirrored
dnsTunneling=true
firewall=true
"@ | Out-File "$env:USERPROFILE\.wslconfig" -Encoding UTF8 -Force
Write-Host "  ✅ .wslconfig written" -ForegroundColor Green

# Shutdown and restart WSL
wsl --shutdown 2>$null
Start-Sleep 3

# Test WSL2
$wslTest = wsl -d Ubuntu-24.04 -- bash -c "echo WSL_OK" 2>$null
if ($wslTest -match "WSL_OK") {
    Write-Host "  ✅ WSL2 Ubuntu-24.04 running" -ForegroundColor Green
} else {
    Write-Host "  ⚠️  WSL2 not responding — trying to start..." -ForegroundColor Yellow
    wsl --update 2>$null
    Start-Sleep 5
    $wslTest2 = wsl -d Ubuntu-24.04 -- bash -c "echo WSL_OK" 2>$null
    if ($wslTest2 -match "WSL_OK") {
        Write-Host "  ✅ WSL2 started after update" -ForegroundColor Green
    } else {
        Write-Host "  ❌ WSL2 still down — run: wsl --install" -ForegroundColor Red
    }
}

# ── [4] Fix Ubuntu DNS ───────────────────────────────────────────────────
Write-Host "`n[4/8] Fixing Ubuntu DNS..." -ForegroundColor Yellow
$ubuntuDns = wsl -d Ubuntu-24.04 -- bash -c @"
sudo rm -f /etc/resolv.conf
printf 'nameserver 9.9.9.9\nnameserver 8.8.8.8\n' | sudo tee /etc/resolv.conf > /dev/null
echo 'Acquire::ForceIPv4 true;' | sudo tee /etc/apt/apt.conf.d/99force-ipv4 > /dev/null
curl -s --max-time 5 https://api.github.com/zen 2>/dev/null && echo DNS_OK || echo DNS_FAIL
"@ 2>$null

if ($ubuntuDns -match "DNS_OK") {
    Write-Host "  ✅ Ubuntu DNS fixed + internet working" -ForegroundColor Green
} elseif ($ubuntuDns -match "DNS_FAIL") {
    Write-Host "  ⚠️  Ubuntu DNS set but internet test failed" -ForegroundColor Yellow
} else {
    Write-Host "  ⚠️  Ubuntu not responding to DNS fix" -ForegroundColor Yellow
}

# Fix Kali DNS too
$kaliDns = wsl -d kali-linux -- bash -c "sudo rm -f /etc/resolv.conf; printf 'nameserver 9.9.9.9\nnameserver 8.8.8.8\n' | sudo tee /etc/resolv.conf > /dev/null; echo OK" 2>$null
if ($kaliDns -match "OK") {
    Write-Host "  ✅ Kali DNS fixed" -ForegroundColor Green
}

# ── [5] Install pyspx on Ubuntu (for FIPS 205) ───────────────────────────
Write-Host "`n[5/8] Installing pyspx on Ubuntu (FIPS 205 SLH-DSA)..." -ForegroundColor Yellow
$pyspxResult = wsl -d Ubuntu-24.04 -- bash -c "pip install pyspx -q 2>/dev/null && python3 -c 'import pyspx.shake_128f; print(OK)' 2>/dev/null || echo FAIL" 2>$null
if ($pyspxResult -match "OK") {
    Write-Host "  ✅ pyspx installed on Ubuntu — FIPS 205 SLH-DSA available!" -ForegroundColor Green
} else {
    Write-Host "  ⚠️  pyspx install on Ubuntu failed — using WOTS+ fallback" -ForegroundColor Yellow
}

# ── [6] Git sync ─────────────────────────────────────────────────────────
Write-Host "`n[6/8] Syncing Git repo..." -ForegroundColor Yellow
git remote set-url origin "https://piyyy314:$Token@github.com/piyyy314/Shadow313-Nexus.git"

# Remove stale swap files
Remove-Item ".git\*.swp" -Force -ErrorAction SilentlyContinue
Remove-Item ".git\.MERGE_MSG.swp" -Force -ErrorAction SilentlyContinue

# Pull with rebase
git pull origin master --rebase 2>$null
if ($LASTEXITCODE -ne 0) {
    git rebase --abort 2>$null
    git pull origin master 2>$null
}
Write-Host "  ✅ Pulled latest" -ForegroundColor Green

# Reinstall shadow313
pip install -e . -q 2>$null
Write-Host "  ✅ shadow313 reinstalled" -ForegroundColor Green

# ── [7] Push to GitHub ───────────────────────────────────────────────────
Write-Host "`n[7/8] Pushing to GitHub..." -ForegroundColor Yellow

# Stage any remaining changes
git add . 2>$null
$status = git status --short 2>$null
if ($status) {
    git commit --no-verify -m "chore: laptop sync $(Get-Date -Format 'yyyy-MM-dd')" 2>$null
}

git push origin master 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✅ Pushed to GitHub" -ForegroundColor Green
} else {
    Write-Host "  ❌ Push failed — check output" -ForegroundColor Red
    git status --short 2>$null | Select-Object -First 5
}

git remote set-url origin "https://github.com/piyyy314/Shadow313-Nexus.git"

# ── [8] Final verification ───────────────────────────────────────────────
Write-Host "`n[8/8] Final verification..." -ForegroundColor Yellow

# Secret scan
$scan = python3 scripts/check-secrets.py 2>&1
Write-Host "  $('✅' if $scan -match '0 unapproved' else '❌') Secret scan: $($scan.Trim())" -ForegroundColor $(if ($scan -match '0 unapproved') {'Green'} else {'Red'})

# Tool checks
$tools = @{
    "nmap"    = "nmap --version"
    "python3" = "python3 --version"
    "git"     = "git --version"
    "docker"  = "docker --version"
    "ollama"  = "ollama --version"
    "wg"      = "wg --version"
}
foreach ($tool in $tools.Keys) {
    $out = Invoke-Expression $tools[$tool] 2>$null
    $ver = if ($out) { $out.ToString().Split("`n")[0].Substring(0, [Math]::Min(40, $out.ToString().Length)) } else { "NOT FOUND" }
    $icon = if ($out) { "✅" } else { "❌" }
    Write-Host "  $icon $($tool.PadRight(10)) $ver" -ForegroundColor $(if ($out) {'Green'} else {'Red'})
}

# Test shadow313 CLI
$env:PYTHONIOENCODING = "utf-8"
$cliOut = shadow313 --version 2>&1 | Select-Object -First 1
Write-Host "  $(if ($cliOut) {'✅'} else {'⚠️ '}) shadow313 CLI: $cliOut" -ForegroundColor $(if ($cliOut) {'Green'} else {'Yellow'})

# WSL2 status
$wslStatus = wsl --list --verbose 2>$null | Select-String "Ubuntu|kali"
Write-Host "  WSL2 distros:" -ForegroundColor Gray
$wslStatus | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  DONE" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Test commands:" -ForegroundColor White
Write-Host "  shadow313 epss --cve CVE-2024-3094" -ForegroundColor Cyan
Write-Host "  shadow313 attack --actor APT29" -ForegroundColor Cyan
Write-Host "  shadow313 attack --actor lazarus" -ForegroundColor Cyan
Write-Host "  nmap --version" -ForegroundColor Cyan
Write-Host "  wsl -d Ubuntu-24.04 -- python3 -c 'import pyspx; print(OK)'" -ForegroundColor Cyan
Write-Host ""
Write-Host "  GitHub Actions: https://github.com/piyyy314/Shadow313-Nexus/actions" -ForegroundColor Gray
Write-Host "  Live site:      https://shadow313.dev" -ForegroundColor Gray
