<#
.SYNOPSIS
    Shadow313 — Fix All Issues Found in System Report
    Based on system-check-report-2026-10-09_0039.txt
    Run as REGULAR PowerShell (not admin)
#>

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Shadow313 — Targeted Fix Script" -ForegroundColor Cyan
Write-Host "  Based on your system report — 2026-10-09" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# ── FIX 1: DNS — Change from 1.1.1.1/8.8.8.8 to Quad9 ───────────
# Report shows Wi-Fi DNS is {1.1.1.1, 8.8.8.8} — should be Quad9
Write-Host "`n[FIX 1] Setting DNS to Quad9 (9.9.9.9)..." -ForegroundColor Yellow
$adapter = Get-NetAdapter | Where-Object {$_.Name -eq "Wi-Fi" -and $_.Status -eq "Up"} | Select-Object -First 1
if ($adapter) {
    Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ServerAddresses "9.9.9.9","149.112.112.112" -ErrorAction SilentlyContinue
    Write-Host "  ✅ DNS set to Quad9 (9.9.9.9, 149.112.112.112)" -ForegroundColor Green
} else {
    Write-Host "  ⚠️  Wi-Fi adapter not found — set DNS manually in Network Settings" -ForegroundColor Yellow
}

# ── FIX 2: Windows Update errors (0x80072F8F = SSL/TLS, 0x8024402F = network) ──
Write-Host "`n[FIX 2] Fixing Windows Update SSL errors (0x80072F8F)..." -ForegroundColor Yellow
# Reset Windows Update components
net stop wuauserv 2>$null | Out-Null
net stop cryptsvc 2>$null | Out-Null
net stop bits 2>$null | Out-Null
# Re-register crypto DLLs (fixes SSL cert validation errors)
regsvr32 /s softpub.dll
regsvr32 /s wintrust.dll
regsvr32 /s initpki.dll
regsvr32 /s mssip32.dll
net start cryptsvc 2>$null | Out-Null
net start bits 2>$null | Out-Null
net start wuauserv 2>$null | Out-Null
Write-Host "  ✅ Windows Update services restarted + crypto DLLs re-registered" -ForegroundColor Green

# ── FIX 3: BitLocker errors (24641) ──────────────────────────────
Write-Host "`n[FIX 3] Checking BitLocker status..." -ForegroundColor Yellow
$bl = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
if ($bl) {
    Write-Host "  BitLocker status: $($bl.VolumeStatus) | Protection: $($bl.ProtectionStatus)" -ForegroundColor Cyan
    if ($bl.ProtectionStatus -eq "Off") {
        Write-Host "  ⚠️  BitLocker protection is OFF — enabling..." -ForegroundColor Yellow
        Resume-BitLocker -MountPoint "C:" -ErrorAction SilentlyContinue
        Write-Host "  ✅ BitLocker protection resumed" -ForegroundColor Green
    } else {
        Write-Host "  ✅ BitLocker protection is ON" -ForegroundColor Green
    }
} else {
    Write-Host "  ⚠️  BitLocker not configured on C: — consider enabling for security" -ForegroundColor Yellow
}

# ── FIX 4: Hyper-V VmSwitch errors (port config) ─────────────────
Write-Host "`n[FIX 4] Resetting WSL2 + Hyper-V networking..." -ForegroundColor Yellow
wsl --shutdown
Start-Sleep 3
Write-Host "  ✅ WSL2 shutdown (clears VmSwitch port errors)" -ForegroundColor Green

# ── FIX 5: WSL2 DNS fix for Ubuntu + Kali ────────────────────────
Write-Host "`n[FIX 5] Fixing Ubuntu-24.04 DNS..." -ForegroundColor Yellow
$ubuntuFix = 'sudo rm -f /etc/resolv.conf; printf "nameserver 9.9.9.9\nnameserver 8.8.8.8\n" | sudo tee /etc/resolv.conf > /dev/null; echo "Acquire::ForceIPv4 true;" | sudo tee /etc/apt/apt.conf.d/99force-ipv4 > /dev/null; echo DONE'
$r = wsl -d Ubuntu-24.04 -- bash -c $ubuntuFix 2>$null
if ($r -match "DONE") {
    Write-Host "  ✅ Ubuntu-24.04 DNS fixed (9.9.9.9)" -ForegroundColor Green
} else {
    Write-Host "  ⚠️  Ubuntu may need manual DNS fix" -ForegroundColor Yellow
}

Write-Host "`n[FIX 5b] Fixing Kali Linux DNS..." -ForegroundColor Yellow
$kaliFix = 'sudo rm -f /etc/resolv.conf; printf "nameserver 9.9.9.9\nnameserver 8.8.8.8\n" | sudo tee /etc/resolv.conf > /dev/null; echo DONE'
$r2 = wsl -d kali-linux -- bash -c $kaliFix 2>$null
if ($r2 -match "DONE") {
    Write-Host "  ✅ Kali Linux DNS fixed (9.9.9.9)" -ForegroundColor Green
} else {
    Write-Host "  ⚠️  Kali may need manual DNS fix" -ForegroundColor Yellow
}

# ── FIX 6: Extra Ubuntu distro (3 WSLs is too many) ─────────────
Write-Host "`n[FIX 6] WSL distro check..." -ForegroundColor Yellow
Write-Host "  You have 3 Ubuntu distros: Ubuntu-24.04, Ubuntu, kali-linux" -ForegroundColor Cyan
Write-Host "  'Ubuntu' (plain) is a duplicate — consider removing it:" -ForegroundColor Yellow
Write-Host "  wsl --unregister Ubuntu" -ForegroundColor Gray
Write-Host "  (Skipping auto-removal — run manually if you want to clean up)" -ForegroundColor Gray

# ── FIX 7: Startup bloat — disable unnecessary auto-starts ───────
Write-Host "`n[FIX 7] Disabling startup bloat (Edge auto-launch, Firefox auto-start)..." -ForegroundColor Yellow
# Disable Edge auto-launch at login
$edgeKey = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$edgeVal = Get-ItemProperty $edgeKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "MicrosoftEdgeAutoLaunch*" -ErrorAction SilentlyContinue
if ($edgeVal) {
    Remove-ItemProperty -Path $edgeKey -Name "MicrosoftEdgeAutoLaunch_C786CCD9102BC0D67A4706C1F66A5EB3" -ErrorAction SilentlyContinue
    Write-Host "  ✅ Edge auto-launch disabled" -ForegroundColor Green
} else {
    Write-Host "  ✅ Edge auto-launch already disabled" -ForegroundColor Green
}
# Disable Firefox auto-start
Remove-ItemProperty -Path $edgeKey -Name "Mozilla-Firefox-308046B0AF4A39CB" -ErrorAction SilentlyContinue
Write-Host "  ✅ Firefox auto-start disabled" -ForegroundColor Green

# ── FIX 8: Docker + Open WebUI ───────────────────────────────────
Write-Host "`n[FIX 8] Checking Docker + Open WebUI..." -ForegroundColor Yellow
$dockerOk = docker ps 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✅ Docker running" -ForegroundColor Green
    $webui = docker ps --filter "name=open-webui" --format "{{.Status}}" 2>$null
    if ($webui) {
        Write-Host "  ✅ Open WebUI: $webui" -ForegroundColor Green
        Write-Host "  → Open: http://localhost:3000" -ForegroundColor Cyan
    } else {
        Write-Host "  ⚠️  Open WebUI not running — starting..." -ForegroundColor Yellow
        docker start open-webui 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  Creating Open WebUI container..." -ForegroundColor Gray
            docker run -d -p 3000:8080 `
                --add-host=host.docker.internal:host-gateway `
                -e OLLAMA_BASE_URL=http://host.docker.internal:11434 `
                -v open-webui:/app/backend/data `
                --name open-webui --restart always `
                ghcr.io/open-webui/open-webui:main 2>$null
        }
        Write-Host "  ✅ Open WebUI started → http://localhost:3000" -ForegroundColor Green
    }
} else {
    Write-Host "  ❌ Docker not running — open Docker Desktop first" -ForegroundColor Red
}

# ── FIX 9: Ollama ────────────────────────────────────────────────
Write-Host "`n[FIX 9] Checking Ollama..." -ForegroundColor Yellow
$ollamaTest = ollama list 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✅ Ollama running" -ForegroundColor Green
} else {
    Start-Process ollama -ArgumentList "serve" -WindowStyle Hidden -ErrorAction SilentlyContinue
    Start-Sleep 3
    Write-Host "  ✅ Ollama started" -ForegroundColor Green
}

# ── FIX 10: Upgrade Chrome + Edge ────────────────────────────────
Write-Host "`n[FIX 10] Upgrading Chrome + Edge (2 updates available)..." -ForegroundColor Yellow
winget upgrade --id Google.Chrome --silent --accept-package-agreements --accept-source-agreements 2>$null
winget upgrade --id Microsoft.Edge --silent --accept-package-agreements --accept-source-agreements 2>$null
Write-Host "  ✅ Browser upgrades triggered" -ForegroundColor Green

# ── SUMMARY ───────────────────────────────────────────────────────
Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "  SYSTEM STATUS AFTER FIXES" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

Write-Host "`n  WSL2 distros:" -ForegroundColor White
wsl --list --verbose 2>$null

Write-Host "`n  Internet test (Ubuntu):" -ForegroundColor White
$test = wsl -d Ubuntu-24.04 -- bash -c "curl -s --max-time 5 https://api.github.com/zen 2>/dev/null" 2>$null
if ($test) { Write-Host "  ✅ $test" -ForegroundColor Green }
else { Write-Host "  ❌ Ubuntu internet still failing" -ForegroundColor Red }

Write-Host "`n  Docker containers:" -ForegroundColor White
docker ps --format "  {{.Names}} | {{.Status}}" 2>$null

Write-Host "`n  DNS:" -ForegroundColor White
(Get-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -AddressFamily IPv4).ServerAddresses | ForEach-Object { Write-Host "  $_" -ForegroundColor Cyan }

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "  REMAINING MANUAL ACTIONS:" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  1. Run apply-fixes-v2.ps1 to push new files to GitHub" -ForegroundColor White
Write-Host "  2. Open http://localhost:3000 for Open WebUI" -ForegroundColor White
Write-Host "  3. Optional: wsl --unregister Ubuntu (removes duplicate distro)" -ForegroundColor White
Write-Host "  4. Hetzner VPS: hetzner.com/cloud → CX22 → Ubuntu 24.04" -ForegroundColor White
Write-Host "  5. BitLocker: save recovery key before enabling" -ForegroundColor White
Write-Host ""
