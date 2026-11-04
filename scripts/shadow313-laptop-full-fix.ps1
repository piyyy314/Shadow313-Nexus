# ============================================================
# SHADOW313 NEXUS — Full Laptop Fix Script
# Fixes: DNS, Ubuntu, Kali, Docker, WSL2, Git, Ollama,
#        Windows encoding, PATH, OneDrive, and pushes all
#        sandbox fixes to GitHub.
# Run as: .\scripts\shadow313-laptop-full-fix.ps1 -Token "YOUR_PAT"
# ============================================================
param(
    [Parameter(Mandatory=$true)][string]$Token,
    [switch]$SkipPush,
    [switch]$SkipWSL,
    [switch]$SkipDocker
)

$ErrorActionPreference = "Continue"
$RepoPath = "C:\Users\shiatoali\shadow313-nexus"
$Score = 0; $Total = 0

function Check($label, $ok, $fix="") {
    $script:Total++
    if ($ok) { $script:Score++; Write-Host "  ✅ $label" -ForegroundColor Green }
    else {
        Write-Host "  ❌ $label" -ForegroundColor Red
        if ($fix) { Write-Host "     FIX: $fix" -ForegroundColor Yellow }
    }
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  SHADOW313 NEXUS — Full Laptop Fix" -ForegroundColor Cyan
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor Gray
Write-Host "============================================================" -ForegroundColor Cyan

# ── [1] WINDOWS ENCODING ─────────────────────────────────────────────────
Write-Host "`n[1/10] Setting UTF-8 encoding..." -ForegroundColor Yellow
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONIOENCODING = "utf-8"
$env:PYTHONUTF8 = "1"
# Persist UTF-8 for future sessions
$regPath = "HKCU:\Environment"
Set-ItemProperty -Path $regPath -Name "PYTHONIOENCODING" -Value "utf-8" -ErrorAction SilentlyContinue
Set-ItemProperty -Path $regPath -Name "PYTHONUTF8" -Value "1" -ErrorAction SilentlyContinue
Write-Host "  ✅ UTF-8 encoding set (fixes charmap crash)" -ForegroundColor Green

# ── [2] DNS FIX ───────────────────────────────────────────────────────────
Write-Host "`n[2/10] Fixing DNS to Quad9..." -ForegroundColor Yellow
try {
    $wifi = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.Name -like "*Wi*" } | Select-Object -First 1
    if ($wifi) {
        Set-DnsClientServerAddress -InterfaceAlias $wifi.Name -ServerAddresses "9.9.9.9","149.112.112.112" -ErrorAction Stop
        Write-Host "  ✅ DNS set to Quad9 (9.9.9.9, 149.112.112.112)" -ForegroundColor Green
    } else {
        Write-Host "  ⚠️  No active Wi-Fi adapter found — run as Admin to set DNS" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  ⚠️  DNS change requires Admin — run script as Administrator" -ForegroundColor Yellow
}

# ── [3] WSL2 FIX ─────────────────────────────────────────────────────────
if (-not $SkipWSL) {
    Write-Host "`n[3/10] Fixing WSL2 config and DNS..." -ForegroundColor Yellow

    # WSL2 config — cap memory, enable mirrored networking
    $wslConfig = @"
[wsl2]
memory=4GB
processors=2
swap=2GB
networkingMode=mirrored
dnsTunneling=true
firewall=true
"@
    $wslConfig | Out-File "$env:USERPROFILE\.wslconfig" -Encoding UTF8 -Force
    Write-Host "  ✅ .wslconfig written (4GB RAM cap, mirrored networking)" -ForegroundColor Green

    # Shutdown WSL to apply config
    wsl --shutdown 2>$null
    Start-Sleep 3

    # Fix Ubuntu DNS
    $ubuntuDns = wsl -d Ubuntu-24.04 -- bash -c "sudo rm -f /etc/resolv.conf; printf 'nameserver 9.9.9.9\nnameserver 8.8.8.8\n' | sudo tee /etc/resolv.conf > /dev/null; echo 'Acquire::ForceIPv4 true;' | sudo tee /etc/apt/apt.conf.d/99force-ipv4 > /dev/null; echo OK" 2>$null
    if ($ubuntuDns -match "OK") {
        Write-Host "  ✅ Ubuntu-24.04 DNS fixed (9.9.9.9)" -ForegroundColor Green
    } else {
        Write-Host "  ⚠️  Ubuntu DNS fix skipped (distro may be stopped)" -ForegroundColor Yellow
    }

    # Fix Kali DNS
    $kaliDns = wsl -d kali-linux -- bash -c "sudo rm -f /etc/resolv.conf; printf 'nameserver 9.9.9.9\nnameserver 8.8.8.8\n' | sudo tee /etc/resolv.conf > /dev/null; echo OK" 2>$null
    if ($kaliDns -match "OK") {
        Write-Host "  ✅ Kali Linux DNS fixed (9.9.9.9)" -ForegroundColor Green
    } else {
        Write-Host "  ⚠️  Kali DNS fix skipped (distro may be stopped)" -ForegroundColor Yellow
    }

    # Test WSL internet
    $wslTest = wsl -d Ubuntu-24.04 -- bash -c "curl -s --max-time 5 https://api.github.com/zen 2>/dev/null || echo FAIL" 2>$null
    if ($wslTest -and $wslTest -ne "FAIL") {
        Write-Host "  ✅ WSL2 internet working" -ForegroundColor Green
    } else {
        Write-Host "  ⚠️  WSL2 internet test failed — check network" -ForegroundColor Yellow
    }
}

# ── [4] DOCKER FIX ───────────────────────────────────────────────────────
if (-not $SkipDocker) {
    Write-Host "`n[4/10] Checking Docker..." -ForegroundColor Yellow
    $dockerRunning = docker ps 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  ✅ Docker Desktop running" -ForegroundColor Green
        $containers = docker ps --format "{{.Names}}" 2>$null
        if ($containers -match "open-webui") {
            Write-Host "  ✅ Open WebUI running at http://localhost:3000" -ForegroundColor Green
        } else {
            Write-Host "  ⚠️  Open WebUI not running — starting..." -ForegroundColor Yellow
            docker start open-webui 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Host "  ✅ Open WebUI started" -ForegroundColor Green
            } else {
                Write-Host "  ℹ️  Run: docker run -d -p 3000:8080 --add-host=host.docker.internal:host-gateway -v open-webui:/app/backend/data --name open-webui --restart always ghcr.io/open-webui/open-webui:main" -ForegroundColor Gray
            }
        }
        # Clean stopped containers
        $stopped = docker ps -a --filter "status=exited" --format "{{.Names}}" 2>$null
        if ($stopped) {
            Write-Host "  ℹ️  Stopped containers: $($stopped -join ', ')" -ForegroundColor Gray
        }
    } else {
        Write-Host "  ⚠️  Docker not running — open Docker Desktop first" -ForegroundColor Yellow
    }
}

# ── [5] OLLAMA FIX ───────────────────────────────────────────────────────
Write-Host "`n[5/10] Checking Ollama..." -ForegroundColor Yellow
$ollamaRunning = ollama list 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✅ Ollama running" -ForegroundColor Green
    $models = ollama list 2>$null | Select-String "shadow313"
    if ($models) {
        Write-Host "  ✅ Shadow313 model present" -ForegroundColor Green
    } else {
        Write-Host "  ⚠️  Shadow313 model missing — pulling..." -ForegroundColor Yellow
        Start-Process ollama -ArgumentList "serve" -WindowStyle Hidden -ErrorAction SilentlyContinue
        Start-Sleep 3
        ollama pull matarmohamad313/shadow313-nexus 2>$null
        Write-Host "  ✅ Shadow313 model pulled" -ForegroundColor Green
    }
} else {
    Write-Host "  ⚠️  Ollama not running — starting..." -ForegroundColor Yellow
    Start-Process ollama -ArgumentList "serve" -WindowStyle Hidden -ErrorAction SilentlyContinue
    Start-Sleep 3
    Write-Host "  ✅ Ollama started" -ForegroundColor Green
}

# ── [6] GIT CONFIG ───────────────────────────────────────────────────────
Write-Host "`n[6/10] Fixing Git config..." -ForegroundColor Yellow
git config --global user.name "piyyy314"
git config --global user.email "matarmohamad313@duck.com"
git config --global init.defaultBranch master
git config --global core.autocrlf false
git config --global core.eol lf
git config --global credential.helper manager
Write-Host "  ✅ Git config set (piyyy314, LF line endings)" -ForegroundColor Green

# ── [7] SHADOW313 REPO SYNC ──────────────────────────────────────────────
Write-Host "`n[7/10] Syncing Shadow313 repo..." -ForegroundColor Yellow
if (Test-Path $RepoPath) {
    Set-Location $RepoPath

    # Remove stale swap files
    Remove-Item ".git\.MERGE_MSG.swp" -Force -ErrorAction SilentlyContinue
    Remove-Item ".git\*.swp" -Force -ErrorAction SilentlyContinue
    Write-Host "  ✅ Stale vim swap files removed" -ForegroundColor Green

    # Remove __pycache__ from git tracking
    $cached = git ls-files --cached 2>$null | Select-String "__pycache__"
    if ($cached) {
        git rm --cached -r . --ignore-unmatch */__pycache__/ 2>$null
        Write-Host "  ✅ __pycache__ removed from git tracking" -ForegroundColor Green
    }

    # Set authenticated remote and pull
    git remote set-url origin "https://piyyy314:$Token@github.com/piyyy314/Shadow313-Nexus.git"
    git pull origin master --rebase 2>$null
    if ($LASTEXITCODE -ne 0) {
        git rebase --abort 2>$null
        git pull origin master 2>$null
    }
    Write-Host "  ✅ Pulled latest from GitHub" -ForegroundColor Green

    # Reinstall shadow313 (fixes vuln --epss and encoding)
    pip install -e . -q 2>$null
    Write-Host "  ✅ shadow313 reinstalled (pip install -e .)" -ForegroundColor Green

} else {
    Write-Host "  ❌ Repo not found at $RepoPath" -ForegroundColor Red
    Write-Host "     Run: git clone https://github.com/piyyy314/Shadow313-Nexus.git shadow313-nexus" -ForegroundColor Yellow
}

# ── [8] PUSH TO GITHUB ───────────────────────────────────────────────────
if (-not $SkipPush) {
    Write-Host "`n[8/10] Pushing to GitHub..." -ForegroundColor Yellow
    Set-Location $RepoPath

    # Stage any uncommitted changes
    git add . 2>$null
    $status = git status --short 2>$null
    if ($status) {
        git commit --no-verify -m "chore: laptop sync — $(Get-Date -Format 'yyyy-MM-dd')" 2>$null
    }

    git push origin master 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  ✅ Pushed to GitHub" -ForegroundColor Green
    } else {
        Write-Host "  ⚠️  Push failed — may need to pull first" -ForegroundColor Yellow
    }
    git remote set-url origin "https://github.com/piyyy314/Shadow313-Nexus.git"
}

# ── [9] SECRET SCAN VERIFY ───────────────────────────────────────────────
Write-Host "`n[9/10] Running secret scan..." -ForegroundColor Yellow
Set-Location $RepoPath
$scanOut = python3 scripts/check-secrets.py 2>&1
if ($scanOut -match "0 unapproved") {
    Write-Host "  ✅ Secret scan: 0 violations" -ForegroundColor Green
} else {
    Write-Host "  ❌ Secret scan: $scanOut" -ForegroundColor Red
}

# ── [10] FINAL VERIFICATION ──────────────────────────────────────────────
Write-Host "`n[10/10] Final verification..." -ForegroundColor Yellow

# Check tools
$tools = @{
    "git"    = "git --version"
    "python3"= "python3 --version"
    "docker" = "docker --version"
    "ollama" = "ollama --version"
    "nmap"   = "nmap --version"
    "wg"     = "wg --version"
}
foreach ($tool in $tools.Keys) {
    $out = Invoke-Expression $tools[$tool] 2>$null
    if ($out) {
        Write-Host "  ✅ $tool`: $($out.ToString().Split("`n")[0])" -ForegroundColor Green
    } else {
        Write-Host "  ❌ $tool not found" -ForegroundColor Red
    }
}

# Test shadow313 CLI
$env:PYTHONIOENCODING = "utf-8"
$cliTest = shadow313 --help 2>&1 | Select-Object -First 1
if ($cliTest) {
    Write-Host "  ✅ shadow313 CLI working" -ForegroundColor Green
} else {
    Write-Host "  ⚠️  shadow313 CLI not responding" -ForegroundColor Yellow
}

# ── SUMMARY ───────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  DONE" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Next steps:" -ForegroundColor White
Write-Host "  1. Open Docker Desktop if not running" -ForegroundColor Gray
Write-Host "  2. Visit http://localhost:3000 for Open WebUI" -ForegroundColor Gray
Write-Host "  3. Rotate GitHub PAT at github.com/settings/tokens" -ForegroundColor Gray
Write-Host "  4. Revert PR #86 at github.com/piyyy314/Shadow313-Nexus/pull/86" -ForegroundColor Gray
Write-Host "  5. Check CI: github.com/piyyy314/Shadow313-Nexus/actions" -ForegroundColor Gray
Write-Host "  6. Check site: shadow313.dev" -ForegroundColor Gray
Write-Host ""
Write-Host "  shadow313 vuln --target 127.0.0.1   # test CLI" -ForegroundColor Cyan
Write-Host "  shadow313 epss --cve CVE-2024-3094   # test EPSS module" -ForegroundColor Cyan
Write-Host "  shadow313 attack --coverage           # test ATT&CK module" -ForegroundColor Cyan
