#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Shadow313 NEXUS — Environment Watchdog
    
    Runs at login via scheduled task.
    Detects profile drift, broken settings, missing tools.
    Alerts via Windows toast notification + log file.
    Auto-repairs what it can. Flags what needs manual fix.
    
    Install: Run this script once to register the scheduled task.
    After that it runs automatically at every login.
    
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
    .\shadow313-watchdog.ps1 -Install
    
    Manual check anytime:
    .\shadow313-watchdog.ps1 -Check
    
    View last report:
    .\shadow313-watchdog.ps1 -Report
#>

param(
    [switch]$Install,   # Register as scheduled task
    [switch]$Check,     # Run check now
    [switch]$Report,    # Show last report
    [switch]$Uninstall  # Remove scheduled task
)

$ErrorActionPreference = "SilentlyContinue"

# ─────────────────────────────────────────────────────────────────
# CONFIGURATION — Known-Good Baseline
# ─────────────────────────────────────────────────────────────────
$BASELINE = @{

    # PowerShell profile must contain these strings
    ProfileMustContain = @(
        "Set-Location",                          # Home dir fix
        "function prompt",                       # Custom prompt
        "function s313",                         # Repo shortcut
        "function ollama-status",                # Ollama shortcut
        "OLLAMA_HOST",                           # Ollama env var
        "WindowStyle Hidden"                     # Silent Ollama start
    )

    # Profile must NOT contain these (drift indicators)
    ProfileMustNotContain = @(
        "Import-Module Az ",                     # Heavy Azure module
        "Import-Module AzureAD",                 # Heavy Azure AD
        "oh-my-posh",                            # Slow prompt engine
        "verify=False",                          # TLS disabled
        "System32"                               # Wrong start dir hardcoded
    )

    # Ollama environment variables — exact expected values
    OllamaVars = @{
        "OLLAMA_HOST"              = "127.0.0.1:11434"
        "OLLAMA_NUM_PARALLEL"      = "2"
        "OLLAMA_MAX_QUEUE"         = "20"
        "OLLAMA_KEEP_ALIVE"        = "10m"
        "OLLAMA_NUM_CTX"           = "8192"
        "OLLAMA_MAX_LOADED_MODELS" = "2"
    }

    # Windows Terminal — PS7 must be default
    TerminalDefaultGuid = "{574e775e-4f2a-5b96-ac1e-a2962a402336}"

    # Profiles that must be hidden
    TerminalHiddenProfiles = @(
        "Windows PowerShell",
        "Command Prompt",
        "Developer Command Prompt for VS 18",
        "Developer PowerShell for VS 18"
    )

    # PS7 must start in home directory
    TerminalPS7StartDir = "%USERPROFILE%"

    # Tools that must be in PATH
    RequiredTools = @(
        "git", "python", "docker", "ollama",
        "nmap", "wg", "code", "pwsh"
    )

    # Critical repo files that must exist
    RepoFiles = @(
        "shadow313/__init__.py",
        "shadow313/cli/main.py",
        "shadow313/core/kernel.py",
        "shadow313/api/server.py",
        "pyproject.toml",
        "requirements.txt",
        "vercel.json",
        "docker-compose.yml",
        "Dockerfile",
        ".gitignore"
    )

    # WSL2 config must contain these
    WslConfigMustContain = @(
        "memory=4GB",
        "networkingMode=mirrored"
    )

    # DNS servers (at least one must be present)
    ExpectedDNS = @("9.9.9.9", "149.112.112.112", "8.8.8.8")

    # Profile max load time in milliseconds
    MaxProfileLoadMs = 3000

    # Profile max size in KB (drift = someone added a lot)
    MaxProfileSizeKB = 50

    # Repo path
    RepoPath = "C:\Users\shiatoali\shadow313-nexus"
}

# ─────────────────────────────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────────────────────────────
$logDir     = "C:\Users\shiatoali\shadow313-nexus\logs"
$logFile    = "$logDir\watchdog-$(Get-Date -Format 'yyyy-MM').log"
$reportFile = "$logDir\watchdog-last-report.json"
$taskName   = "Shadow313-Watchdog"
$scriptPath = $MyInvocation.MyCommand.Path

# ─────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────
function Write-Log {
    param([string]$Level, [string]$Message)
    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] [$Level] $Message"
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    $line | Add-Content $logFile -Encoding UTF8
    
    $color = switch ($Level) {
        "OK"    { "Green" }
        "WARN"  { "Yellow" }
        "FAIL"  { "Red" }
        "FIX"   { "Magenta" }
        "INFO"  { "Gray" }
        default { "White" }
    }
    Write-Host "  [$Level] $Message" -ForegroundColor $color
}

function Send-ToastAlert {
    param([string]$Title, [string]$Message, [string]$Severity = "Warning")
    try {
        $icon = switch ($Severity) {
            "Critical" { "❌" }
            "Warning"  { "⚠️" }
            "OK"       { "✅" }
            default    { "ℹ️" }
        }
        
        # Use Windows notification via BurntToast if available, else msg.exe
        $bt = Get-Command "New-BurntToastNotification" -ErrorAction SilentlyContinue
        if ($bt) {
            New-BurntToastNotification -Text "$icon Shadow313 Watchdog", $Message -AppLogo "" 2>$null
        } else {
            # Fallback: PowerShell balloon notification
            Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
            $notify = New-Object System.Windows.Forms.NotifyIcon
            $notify.Icon = [System.Drawing.SystemIcons]::Warning
            $notify.BalloonTipTitle = "$icon $Title"
            $notify.BalloonTipText  = $Message
            $notify.BalloonTipIcon  = "Warning"
            $notify.Visible = $true
            $notify.ShowBalloonTip(8000)
            Start-Sleep 2
            $notify.Dispose()
        }
    } catch {
        # Silent fail — log is the primary alert mechanism
    }
}

function Auto-Repair {
    param([string]$Issue, [scriptblock]$Fix)
    try {
        & $Fix
        Write-Log "FIX" "Auto-repaired: $Issue"
        return $true
    } catch {
        Write-Log "WARN" "Auto-repair failed for '$Issue': $_"
        return $false
    }
}

# ─────────────────────────────────────────────────────────────────
# INSTALL MODE — Register scheduled task
# ─────────────────────────────────────────────────────────────────
if ($Install) {
    Write-Host "`n[INSTALL] Setting up the current-user watchdog..." -ForegroundColor Cyan

    if (-not $scriptPath -or -not (Test-Path -LiteralPath $scriptPath)) {
        Write-Host "  ❌ Save the watchdog script before installing it." -ForegroundColor Red
        exit 1
    }

    $installed = $false
    try {
        $action = New-ScheduledTaskAction -Execute "pwsh.exe" `
            -Argument "-NoProfile -WindowStyle Hidden -File `"$scriptPath`" -Check"
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
        $settings = New-ScheduledTaskSettingsSet `
            -ExecutionTimeLimit (New-TimeSpan -Minutes 5) `
            -StartWhenAvailable `
            -MultipleInstances IgnoreNew
        $principal = New-ScheduledTaskPrincipal `
            -UserId "$env:USERDOMAIN\$env:USERNAME" `
            -LogonType Interactive `
            -RunLevel Limited

        Register-ScheduledTask `
            -TaskName $taskName `
            -Action $action `
            -Trigger $trigger `
            -Settings $settings `
            -Principal $principal `
            -Description "Shadow313 NEXUS: Detect and alert on environment drift" `
            -Force -ErrorAction Stop | Out-Null

        $installed = $null -ne (Get-ScheduledTask -TaskName $taskName -ErrorAction Stop)
        if (-not $installed) { throw "Task Scheduler did not return the registered task." }
        Write-Host "  ✅ Verified scheduled task: $taskName" -ForegroundColor Green
    } catch {
        Write-Warning "Task Scheduler registration failed: $($_.Exception.Message)"
        $startupDir = [Environment]::GetFolderPath('Startup')
        $shortcutPath = Join-Path $startupDir "Shadow313-Watchdog.lnk"
        try {
            $shell = New-Object -ComObject WScript.Shell
            $shortcut = $shell.CreateShortcut($shortcutPath)
            $shortcut.TargetPath = (Get-Command pwsh.exe -ErrorAction Stop).Source
            $shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`" -Check"
            $shortcut.WorkingDirectory = Split-Path -Parent $scriptPath
            $shortcut.Save()
            if (-not (Test-Path -LiteralPath $shortcutPath)) { throw "Startup shortcut was not created." }
            $installed = $true
            Write-Host "  ✅ Verified per-user Startup shortcut: $shortcutPath" -ForegroundColor Green
        } catch {
            Write-Error "Could not install startup fallback: $($_.Exception.Message)"
            exit 1
        }
    }

    Write-Host "  Logs: $logFile" -ForegroundColor Green
    Write-Host "  Manual check: & `"$scriptPath`" -Check" -ForegroundColor Green
    Write-Host "  View report:  & `"$scriptPath`" -Report" -ForegroundColor Green
    exit 0
}

# ─────────────────────────────────────────────────────────────────
# UNINSTALL MODE
# ─────────────────────────────────────────────────────────────────
if ($Uninstall) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    $shortcutPath = Join-Path ([Environment]::GetFolderPath('Startup')) "Shadow313-Watchdog.lnk"
    Remove-Item -LiteralPath $shortcutPath -Force -ErrorAction SilentlyContinue
    Write-Host "Removed current-user watchdog task/Startup shortcut where present." -ForegroundColor Green
    exit 0
}

# ─────────────────────────────────────────────────────────────────
# REPORT MODE — Show last saved report
# ─────────────────────────────────────────────────────────────────
if ($Report) {
    if (Test-Path $reportFile) {
        $r = Get-Content $reportFile | ConvertFrom-Json
        Write-Host "`n=== Last Watchdog Report ===" -ForegroundColor Cyan
        Write-Host "  Run at:  $($r.timestamp)"
        Write-Host "  Score:   $($r.score)% ($($r.passed)/$($r.total) checks passed)"
        Write-Host "  Status:  $($r.status)"
        Write-Host ""
        if ($r.failures) {
            Write-Host "  Failures:" -ForegroundColor Red
            $r.failures | ForEach-Object { Write-Host "    ❌ $_" -ForegroundColor Red }
        }
        if ($r.warnings) {
            Write-Host "  Warnings:" -ForegroundColor Yellow
            $r.warnings | ForEach-Object { Write-Host "    ⚠️  $_" -ForegroundColor Yellow }
        }
        if ($r.autoRepaired) {
            Write-Host "  Auto-repaired:" -ForegroundColor Magenta
            $r.autoRepaired | ForEach-Object { Write-Host "    🔧 $_" -ForegroundColor Magenta }
        }
        Write-Host ""
        Write-Host "  Full log: $logFile" -ForegroundColor Gray
    } else {
        Write-Host "  No report found — run with -Check first" -ForegroundColor Yellow
    }
    exit 0
}

# ─────────────────────────────────────────────────────────────────
# CHECK MODE — Main watchdog logic
# ─────────────────────────────────────────────────────────────────

Write-Host "`n⬡ Shadow313 Watchdog — $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Log "INFO" "=== Watchdog check started ==="

$results     = @{ passed=0; failed=0; warned=0; repaired=0 }
$failures    = @()
$warnings    = @()
$autoRepaired = @()

function Pass  { param([string]$m) $script:results.passed++; Write-Log "OK"   $m }
function Fail  { param([string]$m) $script:results.failed++; $script:failures += $m; Write-Log "FAIL" $m }
function Warn  { param([string]$m) $script:results.warned++; $script:warnings += $m; Write-Log "WARN" $m }
function Fixed { param([string]$m) $script:results.repaired++; $script:autoRepaired += $m; Write-Log "FIX"  $m }

# ══════════════════════════════════════════════════════════════════
# CHECK 1: PowerShell Profile
# ══════════════════════════════════════════════════════════════════
Write-Host "`n  [1] PowerShell Profile" -ForegroundColor Yellow

if (-not (Test-Path $PROFILE)) {
    Fail "Profile MISSING — PS7 has no configuration"
    # Auto-repair: create minimal profile
    Auto-Repair "Create minimal profile" {
        @"
if (`$PWD.Path -match "System32") { Set-Location `$env:USERPROFILE }
function s313 { Set-Location "C:\Users\shiatoali\shadow313-nexus" }
"@ | Set-Content $PROFILE -Encoding UTF8
    } | Out-Null
    Fixed "Created minimal profile (run shadow313-profile-audit-and-fix.ps1 for full setup)"
} else {
    $profileContent = Get-Content $PROFILE -Raw
    $profileSize    = [math]::Round((Get-Item $PROFILE).Length/1KB,1)
    
    # Size check — drift indicator
    if ($profileSize -gt $BASELINE.MaxProfileSizeKB) {
        Warn "Profile unusually large: ${profileSize}KB (expected <$($BASELINE.MaxProfileSizeKB)KB) — may have been appended multiple times"
    } else {
        Pass "Profile size OK: ${profileSize}KB"
    }
    
    # Must-contain checks
    foreach ($required in $BASELINE.ProfileMustContain) {
        if ($profileContent -match [regex]::Escape($required)) {
            Pass "Profile contains: '$required'"
        } else {
            Fail "Profile MISSING required setting: '$required'"
        }
    }
    
    # Must-not-contain checks
    foreach ($banned in $BASELINE.ProfileMustNotContain) {
        if ($profileContent -match [regex]::Escape($banned)) {
            Warn "Profile contains problematic setting: '$banned'"
        } else {
            Pass "Profile clean of: '$banned'"
        }
    }
    
    # Duplicate function check
    $funcNames = (Get-Content $PROFILE) | Where-Object { $_ -match "^function " } |
        ForEach-Object { ($_ -split " ")[1].TrimEnd("{").Trim() }
    $dupes = $funcNames | Group-Object | Where-Object { $_.Count -gt 1 }
    if ($dupes) {
        Warn "Duplicate functions in profile: $($dupes.Name -join ', ') — profile was likely appended multiple times"
    } else {
        Pass "No duplicate functions in profile"
    }
    
    # Load time check
    try {
        $loadMs = [math]::Round((Measure-Command { . $PROFILE 2>$null }).TotalMilliseconds, 0)
        if ($loadMs -gt $BASELINE.MaxProfileLoadMs) {
            Warn "Profile loads slowly: ${loadMs}ms (expected <$($BASELINE.MaxProfileLoadMs)ms)"
        } else {
            Pass "Profile load time OK: ${loadMs}ms"
        }
    } catch {
        Warn "Could not measure profile load time"
    }
    
    # Home directory fix check
    if ($profileContent -match "System32|system32") {
        if ($profileContent -match "Set-Location.*USERPROFILE|Set-Location.*~") {
            Pass "Home directory fix present"
        } else {
            Fail "Profile references System32 without home directory fix — PS7 will open in wrong directory"
            # Auto-repair
            Auto-Repair "Add home directory fix" {
                "`n# Watchdog auto-repair: home directory fix`nif (`$PWD.Path -match 'System32') { Set-Location `$env:USERPROFILE }" |
                    Add-Content $PROFILE -Encoding UTF8
            } | Out-Null
            Fixed "Added home directory fix to profile"
        }
    } else {
        Pass "No System32 reference in profile"
    }
}

# ══════════════════════════════════════════════════════════════════
# CHECK 2: Ollama Environment Variables
# ══════════════════════════════════════════════════════════════════
Write-Host "`n  [2] Ollama Environment Variables" -ForegroundColor Yellow

$driftedVars = @()
foreach ($var in $BASELINE.OllamaVars.GetEnumerator()) {
    $current = [System.Environment]::GetEnvironmentVariable($var.Key, "User")
    if ($current -eq $var.Value) {
        Pass "Ollama var OK: $($var.Key)=$current"
    } elseif (-not $current) {
        Fail "Ollama var MISSING: $($var.Key) (expected: $($var.Value))"
        $driftedVars += $var
    } else {
        Warn "Ollama var CHANGED: $($var.Key) = '$current' (expected: '$($var.Value)')"
        $driftedVars += $var
    }
}

# Auto-repair drifted Ollama vars
if ($driftedVars.Count -gt 0) {
    Auto-Repair "Restore Ollama environment variables" {
        foreach ($var in $BASELINE.OllamaVars.GetEnumerator()) {
            [System.Environment]::SetEnvironmentVariable($var.Key, $var.Value, "User")
        }
    } | Out-Null
    Fixed "Restored $($driftedVars.Count) Ollama environment variables"
}

# ══════════════════════════════════════════════════════════════════
# CHECK 3: Windows Terminal Configuration
# ══════════════════════════════════════════════════════════════════
Write-Host "`n  [3] Windows Terminal Configuration" -ForegroundColor Yellow

$wtPath = "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"
if (Test-Path $wtPath) {
    $wt = Get-Content $wtPath -Raw -Encoding UTF8 | ConvertFrom-Json
    
    # Default profile check
    if ($wt.defaultProfile -eq $BASELINE.TerminalDefaultGuid) {
        Pass "Terminal default profile: PowerShell 7 ✓"
    } else {
        Fail "Terminal default profile CHANGED: $($wt.defaultProfile) (expected PS7 GUID)"
        # Auto-repair
        Auto-Repair "Restore PS7 as default terminal" {
            $wt.defaultProfile = $BASELINE.TerminalDefaultGuid
            $wt | ConvertTo-Json -Depth 20 | Set-Content $wtPath -Encoding UTF8
        } | Out-Null
        Fixed "Restored PowerShell 7 as default terminal"
    }
    
    # PS7 start directory check
    $ps7Profile = $wt.profiles.list | Where-Object { $_.guid -eq $BASELINE.TerminalDefaultGuid }
    if ($ps7Profile) {
        if ($ps7Profile.startingDirectory -eq $BASELINE.TerminalPS7StartDir) {
            Pass "PS7 start directory: $($BASELINE.TerminalPS7StartDir) ✓"
        } else {
            $current = $ps7Profile.startingDirectory
            Warn "PS7 start directory CHANGED: '$current' (expected: '$($BASELINE.TerminalPS7StartDir)')"
            # Auto-repair
            Auto-Repair "Restore PS7 start directory" {
                $ps7Profile | Add-Member -NotePropertyName "startingDirectory" -NotePropertyValue $BASELINE.TerminalPS7StartDir -Force
                $wt | ConvertTo-Json -Depth 20 | Set-Content $wtPath -Encoding UTF8
            } | Out-Null
            Fixed "Restored PS7 start directory to %USERPROFILE%"
        }
    }
    
    # Hidden profiles check
    foreach ($hideName in $BASELINE.TerminalHiddenProfiles) {
        $profile = $wt.profiles.list | Where-Object { $_.name -eq $hideName }
        if ($profile) {
            if ($profile.hidden -eq $true) {
                Pass "Terminal profile hidden: '$hideName' ✓"
            } else {
                Warn "Terminal profile VISIBLE (should be hidden): '$hideName'"
                # Auto-repair
                Auto-Repair "Hide profile '$hideName'" {
                    $profile | Add-Member -NotePropertyName "hidden" -NotePropertyValue $true -Force
                    $wt | ConvertTo-Json -Depth 20 | Set-Content $wtPath -Encoding UTF8
                } | Out-Null
                Fixed "Hidden terminal profile: '$hideName'"
            }
        }
    }
    
    # Ghost profile check (no longer detected)
    $ghostProfiles = $wt.profiles.list | Where-Object { $_.name -eq "Ubuntu" -and $_.hidden -ne $true }
    if ($ghostProfiles) {
        Warn "Ghost 'Ubuntu' profile visible in terminal (should be deleted or hidden)"
    } else {
        Pass "No ghost Ubuntu profile"
    }
    
} else {
    Warn "Windows Terminal settings not found"
}

# ══════════════════════════════════════════════════════════════════
# CHECK 4: PATH Integrity
# ══════════════════════════════════════════════════════════════════
Write-Host "`n  [4] PATH and Required Tools" -ForegroundColor Yellow

# Reload PATH
$env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" +
            [System.Environment]::GetEnvironmentVariable("PATH","User")

foreach ($tool in $BASELINE.RequiredTools) {
    $found = Get-Command $tool -ErrorAction SilentlyContinue
    if ($found) {
        Pass "Tool in PATH: $tool ($($found.Source))"
    } else {
        Fail "Tool MISSING from PATH: $tool"
    }
}

# Duplicate PATH entries
$userPath = [System.Environment]::GetEnvironmentVariable("PATH","User")
$pathEntries = $userPath -split ";"
$dupeEntries = $pathEntries | Group-Object | Where-Object { $_.Count -gt 1 }
if ($dupeEntries) {
    Warn "Duplicate PATH entries: $($dupeEntries.Name -join ', ')"
    # Auto-repair
    Auto-Repair "Deduplicate PATH entries" {
        $cleanPath = ($pathEntries | Where-Object { $_ } | Select-Object -Unique) -join ";"
        [System.Environment]::SetEnvironmentVariable("PATH", $cleanPath, "User")
    } | Out-Null
    Fixed "Deduplicated PATH ($($dupeEntries.Count) duplicates removed)"
} else {
    Pass "PATH has no duplicates"
}

# Dead PATH entries
$deadEntries = $pathEntries | Where-Object { $_ -and -not (Test-Path $_) }
if ($deadEntries) {
    Warn "Dead PATH entries (paths that don't exist): $($deadEntries -join ', ')"
} else {
    Pass "All PATH entries point to existing directories"
}

# ══════════════════════════════════════════════════════════════════
# CHECK 5: WSL2 Configuration
# ══════════════════════════════════════════════════════════════════
Write-Host "`n  [5] WSL2 Configuration" -ForegroundColor Yellow

$wslConfig = "$env:USERPROFILE\.wslconfig"
if (Test-Path $wslConfig) {
    $wslContent = Get-Content $wslConfig -Raw
    foreach ($required in $BASELINE.WslConfigMustContain) {
        if ($wslContent -match [regex]::Escape($required)) {
            Pass "WSL2 config contains: '$required'"
        } else {
            Warn "WSL2 config MISSING: '$required' — WSL2 may use wrong settings"
        }
    }
} else {
    Warn ".wslconfig MISSING — WSL2 using defaults (may use too much RAM)"
    # Auto-repair
    Auto-Repair "Create .wslconfig" {
        @"
[wsl2]
memory=4GB
processors=2
swap=2GB
networkingMode=mirrored
dnsTunneling=true
firewall=true
"@ | Out-File $wslConfig -Encoding UTF8 -Force
    } | Out-Null
    Fixed "Created .wslconfig with recommended settings"
}

# WSL distros check
$wslDistros = wsl --list --quiet 2>$null
if ($wslDistros -match "Ubuntu-24.04") { Pass "WSL2 distro: Ubuntu-24.04 present" }
else { Warn "WSL2 distro: Ubuntu-24.04 NOT found" }

if ($wslDistros -match "kali-linux") { Pass "WSL2 distro: kali-linux present" }
else { Warn "WSL2 distro: kali-linux NOT found" }

# ══════════════════════════════════════════════════════════════════
# CHECK 6: Ollama Process and API
# ══════════════════════════════════════════════════════════════════
Write-Host "`n  [6] Ollama Process and API" -ForegroundColor Yellow

$ollamaProc = Get-Process -Name "ollama" -ErrorAction SilentlyContinue
if ($ollamaProc) {
    Pass "Ollama process running (PID $($ollamaProc.Id))"
} else {
    Warn "Ollama NOT running — auto-starting..."
    Auto-Repair "Start Ollama" {
        Start-Process ollama -ArgumentList "serve" -WindowStyle Hidden
        Start-Sleep 5
    } | Out-Null
    Fixed "Started Ollama silently"
}

try {
    $models = Invoke-RestMethod "http://127.0.0.1:11434/api/tags" -TimeoutSec 8
    Pass "Ollama API responding — $($models.models.Count) models loaded"
    
    # Check shadow313 model is present
    $s313Model = $models.models | Where-Object { $_.name -match "shadow313" }
    if ($s313Model) { Pass "Shadow313 model present: $($s313Model.name)" }
    else { Warn "Shadow313 model NOT found in Ollama — run: ollama pull matarmohamad313/shadow313-nexus" }
    
} catch {
    Warn "Ollama API not responding on port 11434"
}

# ══════════════════════════════════════════════════════════════════
# CHECK 7: Docker and Open WebUI
# ══════════════════════════════════════════════════════════════════
Write-Host "`n  [7] Docker and Open WebUI" -ForegroundColor Yellow

$dockerProc = Get-Process -Name "com.docker.backend" -ErrorAction SilentlyContinue
if ($dockerProc) {
    Pass "Docker Desktop running"
    
    $webui = docker ps --filter "name=open-webui" --format "{{.Status}}" 2>$null
    if ($webui -match "Up") {
        Pass "Open WebUI: $webui"
    } else {
        Warn "Open WebUI container NOT running"
    }
    
    # Check for dangling images (drift indicator)
    $dangling = docker images -f "dangling=true" -q 2>$null
    if ($dangling) {
        Warn "Dangling Docker images found — run: docker image prune -f"
    } else {
        Pass "No dangling Docker images"
    }
} else {
    Warn "Docker Desktop NOT running"
}

# ══════════════════════════════════════════════════════════════════
# CHECK 8: DNS Configuration
# ══════════════════════════════════════════════════════════════════
Write-Host "`n  [8] DNS Configuration" -ForegroundColor Yellow

try {
    $dnsServers = (Get-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses
    $hasExpectedDNS = $BASELINE.ExpectedDNS | Where-Object { $dnsServers -contains $_ }
    
    if ($hasExpectedDNS) {
        Pass "DNS configured correctly: $($dnsServers -join ', ')"
    } else {
        Warn "DNS may have drifted: $($dnsServers -join ', ') (expected one of: $($BASELINE.ExpectedDNS -join ', '))"
        # Auto-repair
        Auto-Repair "Restore Quad9 DNS" {
            Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ServerAddresses "9.9.9.9","149.112.112.112" -ErrorAction Stop
        } | Out-Null
        Fixed "Restored Quad9 DNS (9.9.9.9, 149.112.112.112)"
    }
} catch {
    Warn "Could not check DNS (Wi-Fi adapter may be named differently)"
}

# ══════════════════════════════════════════════════════════════════
# CHECK 9: Repository Integrity
# ══════════════════════════════════════════════════════════════════
Write-Host "`n  [9] Repository Integrity" -ForegroundColor Yellow

if (Test-Path "$($BASELINE.RepoPath)\.git") {
    Push-Location $BASELINE.RepoPath
    
    # Check for uncommitted changes
    $uncommitted = git status --short 2>$null
    if ($uncommitted) {
        Warn "Uncommitted changes in repo ($($uncommitted.Count) files)"
    } else {
        Pass "Working tree clean"
    }
    
    # Check if behind origin
    git fetch origin --quiet 2>$null
    $behind = git rev-list HEAD..origin/master --count 2>$null
    if ($behind -gt 0) {
        Warn "Repo is $behind commits behind origin/master — run: git pull origin master"
    } else {
        Pass "Repo up to date with origin"
    }
    
    # Check critical files
    $missingCount = 0
    foreach ($f in $BASELINE.RepoFiles) {
        if (-not (Test-Path $f)) {
            Warn "Critical file missing: $f"
            $missingCount++
        }
    }
    if ($missingCount -eq 0) { Pass "All critical repo files present" }
    
    # Check for committed __pycache__
    $pycache = git ls-files 2>$null | Select-String "__pycache__|\.pyc$"
    if ($pycache) {
        Warn "__pycache__ or .pyc files committed ($($pycache.Count) files) — run: git rm --cached -r **/__pycache__/"
    } else {
        Pass "No __pycache__ committed"
    }
    
    Pop-Location
} else {
    Fail "Repository NOT found at $($BASELINE.RepoPath)"
}

# ══════════════════════════════════════════════════════════════════
# CHECK 10: Account Security
# ══════════════════════════════════════════════════════════════════
Write-Host "`n  [10] Account Security" -ForegroundColor Yellow

# Check Baalb is still disabled/demoted (drift: Windows update re-enables accounts)
$baalbUser = Get-LocalUser -Name "Baalb" -ErrorAction SilentlyContinue
if ($baalbUser) {
    if ($baalbUser.Enabled) {
        Warn "Baalb account is ENABLED — should be disabled to prevent settings drift"
    } else {
        Pass "Baalb account is disabled ✓"
    }
    
    $baalbInAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match "Baalb" }
    if ($baalbInAdmins) {
        Warn "Baalb is still in Administrators group — should be removed"
    } else {
        Pass "Baalb not in Administrators group ✓"
    }
}

# Check shiatoali is in Administrators
$shiaInAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match "shiatoali" }
if ($shiaInAdmins) {
    Pass "shiatoali is in Administrators group ✓"
} else {
    Fail "shiatoali NOT in Administrators group — this will break many operations"
}

# Check Defender is on
$defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($defender) {
    if ($defender.RealTimeProtectionEnabled) { Pass "Defender real-time protection: ON" }
    else { Warn "Defender real-time protection: OFF — re-enable in Windows Security" }
}

# ══════════════════════════════════════════════════════════════════
# FINAL REPORT
# ══════════════════════════════════════════════════════════════════
$total  = $results.passed + $results.failed + $results.warned
$score  = if ($total -gt 0) { [math]::Round(($results.passed / $total) * 100, 0) } else { 0 }
$status = if ($results.failed -gt 0) { "DEGRADED" } elseif ($results.warned -gt 0) { "WARNING" } else { "HEALTHY" }
$statusColor = switch ($status) { "HEALTHY" { "Green" } "WARNING" { "Yellow" } "DEGRADED" { "Red" } }

# Save report JSON
$reportData = @{
    timestamp   = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    score       = $score
    status      = $status
    passed      = $results.passed
    failed      = $results.failed
    warned      = $results.warned
    repaired    = $results.repaired
    total       = $total
    failures    = $failures
    warnings    = $warnings
    autoRepaired = $autoRepaired
}
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$reportData | ConvertTo-Json | Set-Content $reportFile -Encoding UTF8

Write-Log "INFO" "=== Check complete: $score% ($status) — $($results.passed) passed, $($results.failed) failed, $($results.warned) warned, $($results.repaired) auto-repaired ==="

Write-Host @"

  ╔══════════════════════════════════════════════════════════════╗
  ║  Watchdog Report — $(Get-Date -Format 'yyyy-MM-dd HH:mm')
  ╠══════════════════════════════════════════════════════════════╣
  ║  Score:        $score% ($status)
  ║  Passed:       $($results.passed)
  ║  Failed:       $($results.failed)
  ║  Warnings:     $($results.warned)
  ║  Auto-repaired:$($results.repaired)
  ╚══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor $statusColor

if ($failures.Count -gt 0) {
    Write-Host "`n  ❌ Failures (need manual fix):" -ForegroundColor Red
    $failures | ForEach-Object { Write-Host "    • $_" -ForegroundColor Red }
}

if ($warnings.Count -gt 0) {
    Write-Host "`n  ⚠️  Warnings:" -ForegroundColor Yellow
    $warnings | ForEach-Object { Write-Host "    • $_" -ForegroundColor Yellow }
}

if ($autoRepaired.Count -gt 0) {
    Write-Host "`n  🔧 Auto-repaired:" -ForegroundColor Magenta
    $autoRepaired | ForEach-Object { Write-Host "    • $_" -ForegroundColor Magenta }
}

# Send alert if degraded
if ($status -eq "DEGRADED") {
    Send-ToastAlert -Title "Shadow313 Environment Degraded" `
        -Message "$($failures.Count) critical issues detected. Check: $logFile" `
        -Severity "Critical"
} elseif ($status -eq "WARNING" -and $results.warned -gt 3) {
    Send-ToastAlert -Title "Shadow313 Environment Warning" `
        -Message "$($warnings.Count) warnings detected. Run watchdog -Report for details." `
        -Severity "Warning"
}

Write-Host "`n  Log: $logFile" -ForegroundColor Gray
Write-Host "  Report: .\shadow313-watchdog.ps1 -Report" -ForegroundColor Gray