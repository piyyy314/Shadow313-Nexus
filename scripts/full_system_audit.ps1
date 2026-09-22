# ============================================================
# SHADOW313 — Full Pre-Ollama/Docker System Audit
# Dell Latitude 5490 · Windows 11 Pro 25H2
# ============================================================

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  SHADOW313 — Full System Readiness Audit" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

# ── 1. WINDOWS & ACCOUNT ─────────────────────────────────────
Write-Host "`n[1] Windows & Account:" -ForegroundColor Yellow

$os = Get-WmiObject Win32_OperatingSystem
Write-Host "  OS:        $($os.Caption) Build $($os.BuildNumber)"

$principal = New-Object System.Security.Principal.WindowsPrincipal(
    [System.Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $principal.IsInRole(
    [System.Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "  User:      $env:USERNAME @ $env:COMPUTERNAME"
Write-Host "  Admin:     $(if($isAdmin){'✅ YES'}else{'❌ NO — rerun as Admin'})" `
    -ForegroundColor $(if($isAdmin){'Green'}else{'Red'})

$act = Get-LocalUser -Name $env:USERNAME -EA SilentlyContinue
Write-Host "  Account:   $($act.PrincipalSource) $(if($act.PrincipalSource -eq 'Local'){'(local — intentional ✅)'})"

# ── 2. ACTIVATION & BITLOCKER ────────────────────────────────
Write-Host "`n[2] Activation & BitLocker:" -ForegroundColor Yellow

$lic = Get-WmiObject -Query "SELECT * FROM SoftwareLicensingProduct WHERE PartialProductKey IS NOT NULL AND Name LIKE 'Windows%'" -EA SilentlyContinue
$licStatus = switch ($lic.LicenseStatus) { 1{"✅ ACTIVATED"} default{"⚠️ Check needed"} }
Write-Host "  Windows:   $licStatus"

$bl = Get-BitLockerVolume -MountPoint "C:" -EA SilentlyContinue
if ($bl) {
    Write-Host "  BitLocker: $($bl.VolumeStatus) | Protection: $($bl.ProtectionStatus)" `
        -ForegroundColor $(if($bl.ProtectionStatus -eq 'On'){'Green'}else{'Yellow'})
} else {
    Write-Host "  BitLocker: ⚠️ Could not read (run as Admin)" -ForegroundColor Yellow
}

# ── 3. SECURITY POSTURE ──────────────────────────────────────
Write-Host "`n[3] Security Posture:" -ForegroundColor Yellow

$def = Get-MpComputerStatus -EA SilentlyContinue
if ($def) {
    Write-Host "  Defender RT:    $(if($def.RealTimeProtectionEnabled){'✅ ON'}else{'⚠️ OFF (expected if using 3rd party)'})"
    Write-Host "  Tamper Protect: $(if($def.IsTamperProtected){'✅ ON'}else{'⚠️ OFF'})"
    Write-Host "  Sig Age:        $($def.AntivirusSignatureAge) days $(if($def.AntivirusSignatureAge -lt 3){'✅'}else{'⚠️ Update needed'})"
}
$sb = Confirm-SecureBootUEFI -EA SilentlyContinue
Write-Host "  Secure Boot:    $(if($sb){'✅ Enabled'}else{'⚠️ Disabled'})"
$tpm = Get-Tpm -EA SilentlyContinue
Write-Host "  TPM 2.0:        $(if($tpm.TpmPresent -and $tpm.TpmEnabled){'✅ Present & Enabled'}else{'⚠️ Check BIOS'})"

# ── 4. NETWORK & DNS ─────────────────────────────────────────
Write-Host "`n[4] Network & DNS:" -ForegroundColor Yellow

$wifi = Get-NetAdapter -Name "Wi-Fi" -EA SilentlyContinue
if ($wifi) {
    Write-Host "  WiFi:      $($wifi.Status) | Speed: $([math]::Round($wifi.LinkSpeed/1MB,0)) Mbps"
}

$dns = Get-DnsClientServerAddress -AddressFamily IPv4 -EA SilentlyContinue |
    Where-Object { $_.ServerAddresses -ne $null -and $_.ServerAddresses.Count -gt 0 } |
    Select-Object -First 1
Write-Host "  DNS:       $($dns.ServerAddresses -join ', ')"

$quad9 = $dns.ServerAddresses -contains "9.9.9.9"
Write-Host "  Quad9 DoH: $(if($quad9){'✅ Active'}else{'⚠️ Not detected on primary adapter'})"

# ── 5. WSL2 STATUS ───────────────────────────────────────────
Write-Host "`n[5] WSL2 Distributions:" -ForegroundColor Yellow

$wslList = wsl --list --verbose 2>$null
$wslList | ForEach-Object {
    if ($_ -match "Ubuntu") { Write-Host "  ✅ $_" -ForegroundColor Green }
    elseif ($_ -match "kali") { Write-Host "  ✅ $_" -ForegroundColor Green }
    elseif ($_ -match "\S") { Write-Host "  ℹ️  $_" -ForegroundColor Gray }
}

$wslVer = wsl --status 2>$null | Select-String "Default Version"
Write-Host "  $wslVer"

# ── 6. INSTALLED TOOLS ───────────────────────────────────────
Write-Host "`n[6] Security Tools:" -ForegroundColor Yellow

$tools = @{
    "git"       = "Git"
    "python"    = "Python"
    "code"      = "VS Code"
    "nmap"      = "Nmap"
    "wg"        = "WireGuard"
    "wireshark" = "Wireshark"
    "ollama"    = "Ollama"
    "docker"    = "Docker"
}

foreach ($cmd in $tools.Keys | Sort-Object) {
    $found = Get-Command $cmd -EA SilentlyContinue
    $color = if ($found) { "Green" } else { "Red" }
    $icon  = if ($found) { "✅" } else { "❌" }
    $ver   = if ($found) {
        try { & $cmd --version 2>$null | Select-Object -First 1 } catch { "" }
    } else { "not installed" }
    Write-Host "  $icon $($tools[$cmd]): $ver" -ForegroundColor $color
}

# ── 7. WINGET INSTALLED APPS ─────────────────────────────────
Write-Host "`n[7] Key Apps (winget):" -ForegroundColor Yellow

$apps = @("Burp","KeePass","Obsidian","7-Zip","Wireshark","WireGuard","Nmap","Firefox","Brave","Notepad++","Windows Terminal","Everything")
$installed = winget list 2>$null
foreach ($app in $apps) {
    $match = $installed | Select-String $app
    if ($match) {
        Write-Host "  ✅ $app" -ForegroundColor Green
    } else {
        Write-Host "  ❌ $app — not found" -ForegroundColor Red
    }
}

# ── 8. OLLAMA CHECK ──────────────────────────────────────────
Write-Host "`n[8] Ollama Status:" -ForegroundColor Yellow

$ollamaCmd = Get-Command ollama -EA SilentlyContinue
if ($ollamaCmd) {
    Write-Host "  ✅ Ollama installed: $(ollama --version 2>$null)" -ForegroundColor Green
    Write-Host "  Models available:" -ForegroundColor Gray
    ollama list 2>$null | ForEach-Object { Write-Host "    $_" -ForegroundColor Cyan }

    # Check if matarmohamad/shadow313nexus exists
    $models = ollama list 2>$null
    if ($models -match "shadow313") {
        Write-Host "  ✅ shadow313nexus model FOUND on this machine!" -ForegroundColor Green
    } else {
        Write-Host "  ℹ️  shadow313nexus not pulled locally yet" -ForegroundColor Yellow
        Write-Host "     Run: ollama pull matarmohamad/shadow313nexus" -ForegroundColor Gray
    }

    # Test API
    try {
        $resp = Invoke-WebRequest -Uri "http://localhost:11434/api/tags" -TimeoutSec 3 -EA SilentlyContinue
        if ($resp.StatusCode -eq 200) {
            Write-Host "  ✅ Ollama API responding on :11434" -ForegroundColor Green
        }
    } catch {
        Write-Host "  ⚠️  Ollama API not responding — may need to start: ollama serve" -ForegroundColor Yellow
    }
} else {
    Write-Host "  ❌ Ollama NOT installed yet" -ForegroundColor Red
    Write-Host "     Run: winget install Ollama.Ollama" -ForegroundColor Gray
}

# ── 9. DOCKER CHECK ──────────────────────────────────────────
Write-Host "`n[9] Docker Status:" -ForegroundColor Yellow

$dockerCmd = Get-Command docker -EA SilentlyContinue
if ($dockerCmd) {
    $dv = docker --version 2>$null
    Write-Host "  ✅ Docker installed: $dv" -ForegroundColor Green
    $di = docker info 2>$null | Select-String "Server Version"
    if ($di) {
        Write-Host "  ✅ Docker daemon running: $di" -ForegroundColor Green
    } else {
        Write-Host "  ⚠️  Docker installed but daemon not running — open Docker Desktop" -ForegroundColor Yellow
    }
    $containers = docker ps 2>$null
    Write-Host "  Running containers:" -ForegroundColor Gray
    $containers | Select-Object -Skip 1 | ForEach-Object { Write-Host "    $_" -ForegroundColor Cyan }
} else {
    Write-Host "  ❌ Docker NOT installed yet" -ForegroundColor Red
    Write-Host "     Run: winget install Docker.DockerDesktop" -ForegroundColor Gray
}

# ── 10. DISK & RAM ───────────────────────────────────────────
Write-Host "`n[10] Hardware:" -ForegroundColor Yellow

$ram = (Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB
Write-Host "  RAM:  $([math]::Round($ram,1)) GB $(if($ram -ge 16){'✅ Good for 7B models'}else{'⚠️ Limited'})"

$disk = Get-PSDrive C
$free = [math]::Round($disk.Free/1GB,1)
$used = [math]::Round($disk.Used/1GB,1)
Write-Host "  Disk: ${used}GB used / ${free}GB free $(if($free -gt 50){'✅'}else{'⚠️ Low — models need 10-20GB'})"

$cpu = Get-WmiObject Win32_Processor | Select-Object -First 1
Write-Host "  CPU:  $($cpu.Name)"

# ── 11. DELL COMPONENTS ──────────────────────────────────────
Write-Host "`n[11] Dell Components:" -ForegroundColor Yellow

$dellApps = @("Dell Command Update","Dell SupportAssist","Dell Optimizer","Dell Power Manager")
foreach ($app in $dellApps) {
    if ($installed -match $app) {
        Write-Host "  ✅ $app" -ForegroundColor Green
    } else {
        Write-Host "  ℹ️  $app — optional, not critical" -ForegroundColor Gray
    }
}

# ── SUMMARY ──────────────────────────────────────────────────
Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "  AUDIT COMPLETE — Paste output back to me" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan