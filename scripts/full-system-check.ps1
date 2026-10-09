<#
.SYNOPSIS
    Shadow313 — Full System Status Check
    Run in regular PowerShell after DNS reset
#>

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Shadow313 NEXUS — Full System Status Check" -ForegroundColor Cyan
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# ── 1. WSL2 Status ───────────────────────────────────────────────
Write-Host "`n[1] WSL2 Distros:" -ForegroundColor Yellow
wsl --list --verbose 2>$null

# ── 2. WSL2 Config ───────────────────────────────────────────────
Write-Host "`n[2] .wslconfig:" -ForegroundColor Yellow
$wslcfg = "$env:USERPROFILE\.wslconfig"
if (Test-Path $wslcfg) {
    Get-Content $wslcfg | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
} else {
    Write-Host "  ❌ .wslconfig missing — will create it" -ForegroundColor Red
    @"
[wsl2]
memory=4GB
processors=2
swap=2GB
networkingMode=mirrored
dnsTunneling=true
firewall=true
"@ | Out-File $wslcfg -Encoding UTF8 -Force
    Write-Host "  ✅ .wslconfig created" -ForegroundColor Green
}

# ── 3. Ubuntu DNS + Internet ──────────────────────────────────────
Write-Host "`n[3] Ubuntu-24.04 DNS + Internet:" -ForegroundColor Yellow
try {
    $ubuntuTest = wsl -d Ubuntu-24.04 -- bash -c "cat /etc/resolv.conf 2>/dev/null | head -3; echo '---'; curl -s --max-time 5 https://api.github.com/zen 2>/dev/null || echo 'CURL_FAILED'" 2>$null
    Write-Host $ubuntuTest | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    if ($ubuntuTest -match "CURL_FAILED" -or -not $ubuntuTest) {
        Write-Host "  ❌ Ubuntu internet not working — fixing DNS..." -ForegroundColor Red
        wsl -d Ubuntu-24.04 -- bash -c "sudo rm -f /etc/resolv.conf; printf 'nameserver 9.9.9.9\nnameserver 8.8.8.8\n' | sudo tee /etc/resolv.conf > /dev/null; echo 'Acquire::ForceIPv4 true;' | sudo tee /etc/apt/apt.conf.d/99force-ipv4 > /dev/null" 2>$null
        Write-Host "  ✅ Ubuntu DNS fixed" -ForegroundColor Green
    } else {
        Write-Host "  ✅ Ubuntu internet working" -ForegroundColor Green
    }
} catch {
    Write-Host "  ⚠️  Ubuntu not running" -ForegroundColor Yellow
}

# ── 4. Kali DNS + Internet ────────────────────────────────────────
Write-Host "`n[4] Kali Linux DNS + Internet:" -ForegroundColor Yellow
try {
    $kaliTest = wsl -d kali-linux -- bash -c "curl -s --max-time 5 https://api.github.com/zen 2>/dev/null || echo 'CURL_FAILED'" 2>$null
    if ($kaliTest -match "CURL_FAILED" -or -not $kaliTest) {
        Write-Host "  ❌ Kali internet not working — fixing DNS..." -ForegroundColor Red
        wsl -d kali-linux -- bash -c "sudo rm -f /etc/resolv.conf; printf 'nameserver 9.9.9.9\nnameserver 8.8.8.8\n' | sudo tee /etc/resolv.conf > /dev/null" 2>$null
        Write-Host "  ✅ Kali DNS fixed" -ForegroundColor Green
    } else {
        Write-Host "  ✅ Kali internet working: $kaliTest" -ForegroundColor Green
    }
} catch {
    Write-Host "  ⚠️  Kali not running" -ForegroundColor Yellow
}

# ── 5. Docker ─────────────────────────────────────────────────────
Write-Host "`n[5] Docker Desktop:" -ForegroundColor Yellow
$dockerVer = docker --version 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✅ Docker installed: $dockerVer" -ForegroundColor Green
    $containers = docker ps --format "  {{.Names}} | {{.Status}} | {{.Ports}}" 2>$null
    if ($containers) {
        Write-Host "  Running containers:" -ForegroundColor Cyan
        $containers | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    } else {
        Write-Host "  ⚠️  No containers running" -ForegroundColor Yellow
        Write-Host "  Start Open WebUI: docker run -d -p 3000:8080 --add-host=host.docker.internal:host-gateway -v open-webui:/app/backend/data --name open-webui --restart always ghcr.io/open-webui/open-webui:main" -ForegroundColor Gray
    }
} else {
    Write-Host "  ❌ Docker not running — open Docker Desktop" -ForegroundColor Red
}

# ── 6. Ollama ─────────────────────────────────────────────────────
Write-Host "`n[6] Ollama:" -ForegroundColor Yellow
$ollamaVer = ollama --version 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✅ Ollama: $ollamaVer" -ForegroundColor Green
    $models = ollama list 2>$null
    if ($models) {
        Write-Host "  Models:" -ForegroundColor Cyan
        $models | Select-Object -Skip 1 | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
    }
} else {
    Write-Host "  ❌ Ollama not running — starting..." -ForegroundColor Red
    Start-Process ollama -ArgumentList "serve" -WindowStyle Hidden
    Start-Sleep 3
    Write-Host "  ✅ Ollama started" -ForegroundColor Green
}

# ── 7. Git repo status ────────────────────────────────────────────
Write-Host "`n[7] Git Repo:" -ForegroundColor Yellow
$repoPath = "C:\Users\shiatoali\shadow313-nexus"
if (Test-Path $repoPath) {
    Set-Location $repoPath
    $branch = git branch --show-current 2>$null
    $status = git status --short 2>$null
    $log = git log --oneline -3 2>$null
    Write-Host "  ✅ Repo: $repoPath" -ForegroundColor Green
    Write-Host "  Branch: $branch" -ForegroundColor Cyan
    Write-Host "  Last 3 commits:" -ForegroundColor Cyan
    $log | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
    if ($status) {
        Write-Host "  Uncommitted changes: $($status.Count) files" -ForegroundColor Yellow
    } else {
        Write-Host "  ✅ Working tree clean" -ForegroundColor Green
    }
} else {
    Write-Host "  ❌ Repo not found at $repoPath" -ForegroundColor Red
}

# ── 8. Network / DNS ──────────────────────────────────────────────
Write-Host "`n[8] Network:" -ForegroundColor Yellow
$wifi = Get-NetAdapter | Where-Object {$_.Name -like "*Wi-Fi*" -and $_.Status -eq "Up"} | Select-Object -First 1
if ($wifi) {
    Write-Host "  ✅ WiFi: $($wifi.Name) — Up" -ForegroundColor Green
}
$dns = Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object {$_.ServerAddresses} | Select-Object -First 1
Write-Host "  DNS: $($dns.ServerAddresses -join ', ')" -ForegroundColor Cyan

# ── Summary ───────────────────────────────────────────────────────
Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "  NEXT STEPS:" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  1. Buy Hetzner VPS → hetzner.com/cloud (CX22, €3.29/mo)" -ForegroundColor White
Write-Host "  2. Run apply-fixes-v2.ps1 to push new files to GitHub" -ForegroundColor White
Write-Host "  3. docker compose up -d (starts Shadow313 API + Open WebUI)" -ForegroundColor White
Write-Host "  4. Open http://localhost:3000 for Open WebUI" -ForegroundColor White
Write-Host ""
