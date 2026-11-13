<#
.SYNOPSIS
    Shadow313 — Full Read-Only System Audit
    Scans everything, changes NOTHING, reports all findings.
    Run from any PowerShell 7 window.
#>

$report = [System.Collections.Generic.List[string]]::new()
$issues = [System.Collections.Generic.List[string]]::new()
$warnings = [System.Collections.Generic.List[string]]::new()

function Log($msg, $color = "White") { Write-Host $msg -ForegroundColor $color; $report.Add($msg) }
function OK($msg)   { Log "  ✅ $msg" "Green" }
function WARN($msg) { Log "  ⚠️  $msg" "Yellow"; $warnings.Add($msg) }
function FAIL($msg) { Log "  ❌ $msg" "Red"; $issues.Add($msg) }
function HDR($msg)  { Log "`n━━━ $msg ━━━" "Cyan" }

Log "╔══════════════════════════════════════════════════════════════╗"
Log "║  Shadow313 — Full Read-Only System Audit                   ║"
Log "║  Scans everything · Changes NOTHING · $(Get-Date -Format 'yyyy-MM-dd HH:mm')  ║"
Log "╚══════════════════════════════════════════════════════════════╝"

# ─── 1. WINDOWS ACCOUNT ───────────────────────────────────────────────────────
HDR "1/14  WINDOWS ACCOUNT"
$me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal $me).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
OK "Windows user: $($me.Name)"
OK "Is admin this session: $isAdmin"

$allUsers = Get-LocalUser
foreach ($u in $allUsers) {
    $tag = if ($u.Enabled) { "ENABLED" } else { "disabled" }
    $src = $u.PrincipalSource
    $last = if ($u.LastLogon) { $u.LastLogon.ToString("yyyy-MM-dd") } else { "never" }
    if ($u.Enabled) { OK "$($u.Name) [$tag] [$src] last=$last" }
    else            { Log "  ·  $($u.Name) [$tag] [$src]" "DarkGray" }
}

$admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
Log "  Administrators group:" "Gray"
foreach ($a in $admins) { Log "    · $($a.Name) [$($a.PrincipalSource)]" "Gray" }

# ─── 2. MICROSOFT ACCOUNT LINK ────────────────────────────────────────────────
HDR "2/14  MICROSOFT ACCOUNT LINK"
try {
    $emails = Get-ItemProperty "HKCU:\Software\Microsoft\IdentityStore\Cache\*\IdentityCache\*" -ErrorAction SilentlyContinue |
              Select-Object -ExpandProperty UserName -ErrorAction SilentlyContinue |
              Where-Object { $_ -match "@" } | Select-Object -Unique
    if ($emails) { foreach ($e in $emails) { OK "Linked MS account: $e" } }
    else { WARN "Could not read linked MS account from registry" }
} catch { WARN "IdentityStore registry not readable" }

# ─── 3. ONEDRIVE ──────────────────────────────────────────────────────────────
HDR "3/14  ONEDRIVE"
$odProc = Get-Process "OneDrive" -ErrorAction SilentlyContinue
if ($odProc) { OK "OneDrive process running (PID $($odProc.Id))" }
else         { WARN "OneDrive process NOT running" }

# Registry accounts
$odReg = "HKCU:\Software\Microsoft\OneDrive\Accounts"
if (Test-Path $odReg) {
    $slots = Get-ChildItem $odReg
    Log "  OneDrive registry slots: $($slots.Count)" "Gray"
    foreach ($slot in $slots) {
        $a = Get-ItemProperty $slot.PSPath -ErrorAction SilentlyContinue
        $email  = $a.UserEmail
        $folder = $a.UserFolder
        if ($email) { OK "  Slot $($slot.PSChildName): email='$email' folder='$folder'" }
        else        { WARN "  Slot $($slot.PSChildName): EMPTY (not signed in)" }
    }
} else { WARN "OneDrive registry key not found" }

# OneDrive folders on disk
$odFolders = Get-ChildItem "$env:USERPROFILE" -Directory -ErrorAction SilentlyContinue |
             Where-Object { $_.Name -match "^OneDrive" }
Log "  OneDrive folders in $env:USERPROFILE :" "Gray"
foreach ($f in $odFolders) {
    $size = (Get-ChildItem $f.FullName -Recurse -File -ErrorAction SilentlyContinue |
             Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
    $sizeMB = [math]::Round(($size ?? 0) / 1MB, 0)
    if ($f.Name -match "\(1\)|\(2\)") {
        FAIL "DUPLICATE OneDrive folder: $($f.FullName) ($sizeMB MB)"
    } else {
        OK "$($f.Name) — $sizeMB MB — $($f.FullName)"
    }
}

# C:\OneDrive (shared path)
if (Test-Path "C:\OneDrive") {
    $target = (Get-Item "C:\OneDrive" -ErrorAction SilentlyContinue).Target
    if ($target) { OK "C:\OneDrive → symlink to $target" }
    else         { WARN "C:\OneDrive exists as real folder (not symlink)" }
}

# ─── 4. DISK & STORAGE ────────────────────────────────────────────────────────
HDR "4/14  DISK & STORAGE"
$drive = Get-PSDrive C
$usedGB = [math]::Round($drive.Used / 1GB, 1)
$freeGB = [math]::Round($drive.Free / 1GB, 1)
$totalGB = [math]::Round(($drive.Used + $drive.Free) / 1GB, 1)
$pct = [math]::Round($usedGB / $totalGB * 100, 0)
if ($pct -gt 85) { FAIL "Disk $pct% full — ${usedGB}GB used / ${totalGB}GB total (${freeGB}GB free)" }
elseif ($pct -gt 70) { WARN "Disk $pct% full — ${usedGB}GB used / ${totalGB}GB total (${freeGB}GB free)" }
else { OK "Disk $pct% used — ${usedGB}GB / ${totalGB}GB (${freeGB}GB free)" }

# Top consumers
Log "  Top storage consumers:" "Gray"
$topDirs = @(
    "$env:LOCALAPPDATA\Docker",
    "$env:USERPROFILE\.ollama\models",
    "$env:USERPROFILE\.vscode",
    "$env:LOCALAPPDATA\Google\Chrome",
    "$env:USERPROFILE\OneDrive",
    "$env:USERPROFILE\OneDrive (1)",
    "C:\OneDrive",
    "$env:USERPROFILE\shadow313-nexus",
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\NEXUS-OmniSec-Unified"
)
foreach ($d in $topDirs) {
    if (Test-Path $d) {
        $sz = (Get-ChildItem $d -Recurse -File -ErrorAction SilentlyContinue |
               Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
        $gb = [math]::Round(($sz ?? 0) / 1GB, 2)
        Log "    $([math]::Round($gb,2).ToString('0.00'))GB  $d" "Gray"
    }
}

# ─── 5. POWERSHELL PROFILE ────────────────────────────────────────────────────
HDR "5/14  POWERSHELL PROFILE"
if (Test-Path $PROFILE) {
    OK "Profile exists: $PROFILE"
    $lines = Get-Content $PROFILE
    Log "  Profile has $($lines.Count) lines" "Gray"
    # Check for known bad patterns
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ($line -match '-match.*\$env:USERPROFILE.*\|.*\$env:USERPROFILE') {
            FAIL "Line $($i+1): Broken regex pattern (backslash escape issue): $line"
        }
        if ($line -match 'System32' -and $line -match 'Set-Location') {
            WARN "Line $($i+1): May redirect away from home: $line"
        }
        if ($line -match 'OLLAMA_HOST') {
            OK "Line $($i+1): OLLAMA_HOST found in profile"
        }
    }
    # Check start directory
    $hasHome = $lines | Where-Object { $_ -match 'Set-Location.*USERPROFILE|Set-Location.*~' }
    if ($hasHome) { OK "Profile sets home directory" }
    else { WARN "Profile does not set home directory (may start in System32)" }
} else {
    WARN "No PowerShell profile found at: $PROFILE"
}

# ─── 6. WINDOWS TERMINAL ──────────────────────────────────────────────────────
HDR "6/14  WINDOWS TERMINAL"
$wtPaths = @(
    "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json",
    "$env:LOCALAPPDATA\Microsoft\Windows Terminal\settings.json"
)
$wtSettings = $null
foreach ($p in $wtPaths) {
    if (Test-Path $p) {
        OK "Settings found: $p"
        try {
            $wtSettings = Get-Content $p | ConvertFrom-Json
            $defaultGuid = $wtSettings.defaultProfile
            Log "  Default profile GUID: $defaultGuid" "Gray"
            $profiles = $wtSettings.profiles.list
            foreach ($prof in $profiles) {
                $hidden = if ($prof.hidden) { "[HIDDEN]" } else { "[VISIBLE]" }
                $isDefault = if ($prof.guid -eq $defaultGuid) { " ← DEFAULT" } else { "" }
                $name = $prof.name
                if ($prof.hidden) { Log "    · $name $hidden$isDefault" "DarkGray" }
                else              { OK "  $name $hidden$isDefault" }
            }
        } catch { WARN "Could not parse Windows Terminal settings JSON" }
        break
    }
}
if (-not $wtSettings) { WARN "Windows Terminal settings not found" }

# ─── 7. PATH DUPLICATES ───────────────────────────────────────────────────────
HDR "7/14  PATH DUPLICATES"
$userPath = [System.Environment]::GetEnvironmentVariable("PATH", "User") -split ";"
$syspath  = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") -split ";"
$combined = $userPath + $syspath | Where-Object { $_ }
$dupes = $combined | Group-Object | Where-Object { $_.Count -gt 1 }
if ($dupes) {
    foreach ($d in $dupes) { WARN "Duplicate PATH: $($d.Name) (×$($d.Count))" }
} else { OK "No duplicate PATH entries" }
$dead = $combined | Where-Object { $_ -and -not (Test-Path $_) }
if ($dead) {
    foreach ($d in $dead | Select-Object -Unique) { WARN "Dead PATH entry: $d" }
} else { OK "All PATH entries exist on disk" }

# ─── 8. KEY TOOLS ─────────────────────────────────────────────────────────────
HDR "8/14  KEY TOOLS"
$tools = @{
    "git"       = "git --version"
    "python"    = "python --version"
    "node"      = "node --version"
    "docker"    = "docker --version"
    "ollama"    = "ollama --version"
    "pwsh"      = "pwsh --version"
    "nmap"      = "nmap --version"
    "wg"        = "wg --version"
    "code"      = "code --version"
    "winget"    = "winget --version"
}
foreach ($tool in $tools.Keys) {
    $cmd = Get-Command $tool -ErrorAction SilentlyContinue
    if ($cmd) {
        try {
            $ver = (Invoke-Expression $tools[$tool] 2>&1 | Select-Object -First 1).ToString().Trim()
            OK "$tool — $ver"
        } catch { OK "$tool — found at $($cmd.Source)" }
    } else { WARN "$tool — NOT FOUND in PATH" }
}

# ─── 9. WSL2 ──────────────────────────────────────────────────────────────────
HDR "9/14  WSL2"
$wslOut = wsl --list --verbose 2>&1
if ($LASTEXITCODE -eq 0) {
    $wslOut | ForEach-Object { Log "  $_" "Gray" }
    # Check DNS in Ubuntu
    $ubuntuDns = wsl -d Ubuntu-24.04 -- cat /etc/resolv.conf 2>&1
    if ($ubuntuDns -match "nameserver") { OK "Ubuntu-24.04 DNS configured" }
    else { WARN "Ubuntu-24.04 DNS may not be configured" }
} else { FAIL "WSL2 not responding or not installed" }

# ─── 10. DOCKER ───────────────────────────────────────────────────────────────
HDR "10/14  DOCKER"
$dockerRunning = Get-Process "Docker Desktop" -ErrorAction SilentlyContinue
if ($dockerRunning) { OK "Docker Desktop process running" }
else                { WARN "Docker Desktop process not found" }

$containers = docker ps --format "{{.Names}}\t{{.Status}}" 2>&1
if ($LASTEXITCODE -eq 0) {
    if ($containers) {
        $containers | ForEach-Object { OK "Container: $_" }
    } else { WARN "Docker running but no containers active" }
} else { FAIL "Docker CLI not responding" }

$dockerDisk = docker system df 2>&1 | Select-Object -Skip 1
$dockerDisk | ForEach-Object { Log "  $_" "Gray" }

# ─── 11. OLLAMA ───────────────────────────────────────────────────────────────
HDR "11/14  OLLAMA"
$ollamaProc = Get-Process "ollama" -ErrorAction SilentlyContinue
if ($ollamaProc) { OK "Ollama process running (PID $($ollamaProc.Id))" }
else             { WARN "Ollama process NOT running" }

$ollamaHost = [System.Environment]::GetEnvironmentVariable("OLLAMA_HOST", "User")
if ($ollamaHost) { OK "OLLAMA_HOST = $ollamaHost" }
else             { WARN "OLLAMA_HOST not set in User environment" }

try {
    $models = Invoke-RestMethod "http://127.0.0.1:11434/api/tags" -TimeoutSec 5 -ErrorAction Stop
    OK "Ollama API responding — $($models.models.Count) model(s)"
    $models.models | ForEach-Object { Log "    · $($_.name) ($([math]::Round($_.size/1GB,1))GB)" "Gray" }
} catch { WARN "Ollama API not responding on port 11434" }

# ─── 12. GIT REPO ─────────────────────────────────────────────────────────────
HDR "12/14  GIT REPO"
$repoPath = "$env:USERPROFILE\shadow313-nexus"
if (Test-Path "$repoPath\.git") {
    OK "Repo found: $repoPath"
    Push-Location $repoPath
    $remote = git remote get-url origin 2>&1
    if ($remote -match "github.com") { OK "Remote: $remote" }
    else { WARN "Remote URL unexpected: $remote" }
    if ($remote -match ":[^@]+@") { FAIL "Token embedded in remote URL — security risk" }

    $status = git status --short 2>&1
    $uncommitted = ($status | Where-Object { $_ }).Count
    if ($uncommitted -eq 0) { OK "Working tree clean" }
    else { WARN "$uncommitted uncommitted file(s)" ; $status | ForEach-Object { Log "    $_" "Gray" } }

    $behind = git rev-list HEAD..origin/master --count 2>&1
    $ahead  = git rev-list origin/master..HEAD --count 2>&1
    if ($behind -match "^\d+$" -and [int]$behind -gt 0) { WARN "Repo is $behind commit(s) BEHIND origin/master" }
    if ($ahead  -match "^\d+$" -and [int]$ahead  -gt 0) { WARN "Repo is $ahead commit(s) AHEAD origin/master (not pushed)" }
    if ($behind -eq "0" -and $ahead -eq "0") { OK "Repo in sync with origin/master" }

    $lastCommit = git log --oneline -1 2>&1
    Log "  Last commit: $lastCommit" "Gray"

    # Check for sensitive files tracked
    $sensitiveTracked = git ls-files | Where-Object { $_ -match "\.key$|\.pem$|secret-fixtures|\.env$" }
    if ($sensitiveTracked) {
        foreach ($f in $sensitiveTracked) { FAIL "Sensitive file tracked by git: $f" }
    } else { OK "No sensitive files tracked by git" }

    Pop-Location
} else { FAIL "shadow313-nexus repo not found at $repoPath" }

# ─── 13. GITHUB SECRETS NEEDED ────────────────────────────────────────────────
HDR "13/14  GITHUB SECRETS CHECKLIST"
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
Log "  Required secrets (must be set in GitHub repo settings):" "Gray"
foreach ($s in $requiredSecrets) { Log "    · $s" "Gray" }
Log "  Optional secrets:" "Gray"
foreach ($s in $optionalSecrets) { Log "    · $s" "Gray" }
Log "  URL: https://github.com/piyyy314/Shadow313-Nexus/settings/secrets/actions" "Gray"

# Check if .env exists locally
$envFile = "$env:USERPROFILE\shadow313-nexus\.env"
if (Test-Path $envFile) { OK ".env file exists locally" }
else { WARN ".env file missing — run generate-secrets-local.ps1" }

# ─── 14. WINDOWS SYSTEM FILES ─────────────────────────────────────────────────
HDR "14/14  WINDOWS SYSTEM INTEGRITY"
# Check for common system issues without running sfc (which needs admin)
$systemProfile = "C:\Windows\system32\config\systemprofile"
if (Test-Path $systemProfile) { OK "SYSTEM profile folder exists" }
else { WARN "SYSTEM profile folder missing: $systemProfile" }

$winRE = reagentc /info 2>&1
if ($winRE -match "Enabled") { OK "Windows Recovery Environment: Enabled" }
else { WARN "Windows Recovery Environment may be disabled" }

$defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($defender) {
    if ($defender.RealTimeProtectionEnabled) { OK "Defender real-time protection: ON" }
    else { WARN "Defender real-time protection: OFF" }
    if ($defender.AntivirusSignatureAge -lt 3) { OK "Defender signatures: current ($($defender.AntivirusSignatureAge) days old)" }
    else { WARN "Defender signatures: $($defender.AntivirusSignatureAge) days old" }
}

$secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
if ($secureBoot) { OK "Secure Boot: Enabled" }
else { WARN "Secure Boot: Disabled or not readable" }

# ─── FINAL SUMMARY ────────────────────────────────────────────────────────────
Log "`n╔══════════════════════════════════════════════════════════════╗" "Cyan"
Log "║  AUDIT COMPLETE                                             ║" "Cyan"
Log "╠══════════════════════════════════════════════════════════════╣" "Cyan"
Log "  ✅ OK:       $(($report | Where-Object { $_ -match '✅' }).Count)" "Green"
Log "  ⚠️  Warnings: $($warnings.Count)" "Yellow"
Log "  ❌ Failures: $($issues.Count)" "Red"

if ($issues.Count -gt 0) {
    Log "`n  FAILURES:" "Red"
    foreach ($i in $issues) { Log "    • $i" "Red" }
}
if ($warnings.Count -gt 0) {
    Log "`n  WARNINGS:" "Yellow"
    foreach ($w in $warnings) { Log "    • $w" "Yellow" }
}

# Save report
$reportPath = "$env:USERPROFILE\Desktop\shadow313-audit-$(Get-Date -Format 'yyyyMMdd-HHmm').txt"
$report | Out-File $reportPath -Encoding UTF8
Log "`n  Report saved: $reportPath" "Cyan"
Log "╚══════════════════════════════════════════════════════════════╝" "Cyan"