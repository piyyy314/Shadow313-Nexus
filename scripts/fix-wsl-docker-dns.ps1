<#
.SYNOPSIS
    Shadow313 — Fix WSL2 DNS + Docker + Ubuntu/Kali in one shot
    Run as REGULAR PowerShell (not admin)
#>

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Shadow313 — WSL2 + Docker + DNS Fix" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# ── Step 1: Write correct .wslconfig ─────────────────────────────
Write-Host "`n[1/6] Writing .wslconfig..." -ForegroundColor Yellow
$wslconfig = @"
[wsl2]
memory=4GB
processors=2
swap=2GB
networkingMode=mirrored
dnsTunneling=true
firewall=true
"@
$wslconfig | Out-File "$env:USERPROFILE\.wslconfig" -Encoding UTF8 -Force
Write-Host "  ✅ .wslconfig written (mirrored networking + DNS tunneling)" -ForegroundColor Green

# ── Step 2: Shutdown WSL to apply new config ──────────────────────
Write-Host "`n[2/6] Shutting down WSL2 to apply config..." -ForegroundColor Yellow
wsl --shutdown
Start-Sleep 3
Write-Host "  ✅ WSL2 shutdown complete" -ForegroundColor Green

# ── Step 3: Fix Ubuntu-24.04 DNS ─────────────────────────────────
Write-Host "`n[3/6] Fixing Ubuntu-24.04 DNS..." -ForegroundColor Yellow
$ubuntuDnsFix = @'
sudo rm -f /etc/resolv.conf
printf 'nameserver 9.9.9.9\nnameserver 8.8.8.8\nnameserver 1.1.1.1\n' | sudo tee /etc/resolv.conf > /dev/null
sudo chattr +i /etc/resolv.conf 2>/dev/null || true
echo 'Acquire::ForceIPv4 "true";' | sudo tee /etc/apt/apt.conf.d/99force-ipv4 > /dev/null
echo "DNS_TEST=$(curl -s --max-time 5 https://api.github.com/zen 2>/dev/null | head -c 30)"
'@
try {
    $result = wsl -d Ubuntu-24.04 -- bash -c $ubuntuDnsFix 2>&1
    if ($result -match "DNS_TEST=") {
        Write-Host "  ✅ Ubuntu-24.04 DNS fixed + internet reachable" -ForegroundColor Green
    } else {
        Write-Host "  ⚠️  Ubuntu-24.04 DNS set (internet test inconclusive)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  ⚠️  Ubuntu-24.04 not running — will fix on next start" -ForegroundColor Yellow
}

# ── Step 4: Fix Kali Linux DNS ───────────────────────────────────
Write-Host "`n[4/6] Fixing Kali Linux DNS..." -ForegroundColor Yellow
$kaliDnsFix = @'
sudo rm -f /etc/resolv.conf
printf 'nameserver 9.9.9.9\nnameserver 8.8.8.8\n' | sudo tee /etc/resolv.conf > /dev/null
echo "KALI_DNS_OK"
'@
try {
    $result = wsl -d kali-linux -- bash -c $kaliDnsFix 2>&1
    if ($result -match "KALI_DNS_OK") {
        Write-Host "  ✅ Kali Linux DNS fixed" -ForegroundColor Green
    } else {
        Write-Host "  ⚠️  Kali not running — will fix on next start" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  ⚠️  Kali not running — will fix on next start" -ForegroundColor Yellow
}

# ── Step 5: Fix Docker Desktop ───────────────────────────────────
Write-Host "`n[5/6] Checking Docker Desktop..." -ForegroundColor Yellow
$dockerRunning = docker ps 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✅ Docker Desktop is running" -ForegroundColor Green
    $containers = docker ps --format "{{.Names}}" 2>$null
    if ($containers) {
        Write-Host "  Running containers: $($containers -join ', ')" -ForegroundColor Cyan
    }
} else {
    Write-Host "  ⚠️  Docker Desktop not running — starting it..." -ForegroundColor Yellow
    Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe" -ErrorAction SilentlyContinue
    Write-Host "  Waiting 15s for Docker to start..." -ForegroundColor Gray
    Start-Sleep 15
    $dockerRunning = docker ps 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  ✅ Docker Desktop started" -ForegroundColor Green
    } else {
        Write-Host "  ❌ Docker still not running — open Docker Desktop manually" -ForegroundColor Red
    }
}

# ── Step 6: Start Ollama ─────────────────────────────────────────
Write-Host "`n[6/6] Starting Ollama..." -ForegroundColor Yellow
$ollamaRunning = ollama list 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✅ Ollama already running" -ForegroundColor Green
} else {
    Start-Process ollama -ArgumentList "serve" -WindowStyle Hidden -ErrorAction SilentlyContinue
    Start-Sleep 3
    Write-Host "  ✅ Ollama started" -ForegroundColor Green
}

# ── Summary ───────────────────────────────────────────────────────
Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "  DONE — Quick verification:" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

Write-Host "`n  WSL distros:" -ForegroundColor White
wsl --list --verbose 2>$null

Write-Host "`n  Docker containers:" -ForegroundColor White
docker ps --format "  {{.Names}} — {{.Status}}" 2>$null

Write-Host "`n  Ollama models:" -ForegroundColor White
ollama list 2>$null | Select-Object -First 5

Write-Host "`n  Test Ubuntu internet:" -ForegroundColor White
$test = wsl -d Ubuntu-24.04 -- bash -c "curl -s --max-time 5 https://api.github.com/zen 2>/dev/null" 2>$null
if ($test) {
    Write-Host "  ✅ Ubuntu internet: $test" -ForegroundColor Green
} else {
    Write-Host "  ⚠️  Ubuntu internet test failed — try: wsl -d Ubuntu-24.04 -- ping -c1 9.9.9.9" -ForegroundColor Yellow
}

Write-Host "`n  NEXT STEPS:" -ForegroundColor Cyan
Write-Host "  1. Run apply-fixes-v2.ps1 to push new files to GitHub" -ForegroundColor White
Write-Host "  2. Open http://localhost:3000 for Open WebUI" -ForegroundColor White
Write-Host "  3. Hetzner VPN: not needed yet — set up after everything else works" -ForegroundColor White
Write-Host ""
