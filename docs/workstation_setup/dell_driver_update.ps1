# ============================================================
# SHADOW313 — Dell Latitude 5490 Driver Update Script
# Uses Dell Command Update CLI (dcu-cli.exe)
# Features: silent install, logging, error handling, retry
# Run as Administrator in Windows PowerShell 5.1
# ============================================================

#Requires -RunAsAdministrator

param(
    [switch]$ScanOnly,        # Only scan, don't install
    [switch]$RebootIfNeeded,  # Auto-reboot after install
    [string]$LogPath = "$env:ProgramData\Shadow313\Logs\dell-driver-update.log"
)

# ── CONFIGURATION ────────────────────────────────────────────
$DCU_PATHS = @(
    "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe",
    "C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe",
    "${env:ProgramFiles}\Dell\CommandUpdate\dcu-cli.exe"
)

$WINGET_ID    = "Dell.CommandUpdate.Universal"
$MAX_RETRIES  = 3
$RETRY_DELAY  = 30  # seconds between retries

# ── LOGGING ──────────────────────────────────────────────────
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [System.ConsoleColor]$Color = [System.ConsoleColor]::White
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:MM:ss"
    $logEntry  = "[$timestamp] [$Level] $Message"

    # Console output
    Write-Host $logEntry -ForegroundColor $Color

    # File output
    try {
        $logDir = Split-Path $LogPath -Parent
        if (-not (Test-Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
        Add-Content -Path $LogPath -Value $logEntry -ErrorAction SilentlyContinue
    } catch {
        # Silent fail on log write
    }
}

function Write-LogSuccess { Write-Log $args[0] "SUCCESS" Green }
function Write-LogWarning { Write-Log $args[0] "WARNING" Yellow }
function Write-LogError   { Write-Log $args[0] "ERROR"   Red }
function Write-LogInfo    { Write-Log $args[0] "INFO"    Cyan }

# ── HEADER ───────────────────────────────────────────────────
function Show-Header {
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host " SHADOW313 — Dell Driver Update" -ForegroundColor Cyan
    Write-Host " Dell Latitude 5490 | $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
}

# ── FIND DCU-CLI ──────────────────────────────────────────────
function Find-DCUCli {
    foreach ($path in $DCU_PATHS) {
        if (Test-Path $path) {
            Write-LogSuccess "Found dcu-cli.exe: $path"
            return $path
        }
    }
    return $null
}

# ── INSTALL DELL COMMAND UPDATE ───────────────────────────────
function Install-DellCommandUpdate {
    Write-LogInfo "Dell Command Update not found — installing via winget..."

    try {
        $result = winget install --id $WINGET_ID `
            --silent `
            --accept-package-agreements `
            --accept-source-agreements `
            --force 2>&1

        if ($LASTEXITCODE -eq 0) {
            Write-LogSuccess "Dell Command Update installed successfully"
            Start-Sleep -Seconds 10  # Wait for installation to complete

            # Find the newly installed CLI
            $dcuPath = Find-DCUCli
            if ($dcuPath) {
                return $dcuPath
            }
        }

        Write-LogError "winget install failed with exit code: $LASTEXITCODE"
        return $null

    } catch {
        Write-LogError "Failed to install Dell Command Update: $_"
        return $null
    }
}

# ── GET SYSTEM INFO ───────────────────────────────────────────
function Get-SystemInfo {
    Write-LogInfo "Gathering system information..."

    try {
        $cs   = Get-WmiObject Win32_ComputerSystem
        $bios = Get-WmiObject Win32_BIOS
        $os   = Get-WmiObject Win32_OperatingSystem

        Write-Log "  Model:   $($cs.Manufacturer) $($cs.Model)"
        Write-Log "  BIOS:    $($bios.Name) ($($bios.ReleaseDate.Substring(0,8)))"
        Write-Log "  OS:      $($os.Caption) Build $($os.BuildNumber)"
        Write-Log "  RAM:     $([math]::Round($cs.TotalPhysicalMemory/1GB,1)) GB"

        return @{
            Model  = $cs.Model
            BIOS   = $bios.Name
            OS     = $os.Caption
        }
    } catch {
        Write-LogWarning "Could not gather full system info: $_"
        return @{}
    }
}

# ── SCAN FOR UPDATES ──────────────────────────────────────────
function Invoke-DCUScan {
    param([string]$DCUPath)

    Write-LogInfo "Scanning for available driver updates..."

    $scanLog = "$env:TEMP\shadow313-dcu-scan.log"
    $xmlReport = "$env:TEMP\shadow313-dcu-report.xml"

    $scanArgs = @(
        "/scan",
        "-outputLog=$scanLog",
        "-report=$xmlReport",
        "-silent"
    )

    try {
        $proc = Start-Process -FilePath $DCUPath `
            -ArgumentList $scanArgs `
            -Wait -PassThru `
            -WindowStyle Hidden

        Write-Log "  Scan exit code: $($proc.ExitCode)"

        # Parse exit codes
        switch ($proc.ExitCode) {
            0 {
                Write-LogSuccess "Scan complete — no updates needed"
                return @{Success=$true; UpdatesAvailable=$false; ExitCode=0}
            }
            1 {
                Write-LogWarning "Scan complete — updates available"
                return @{Success=$true; UpdatesAvailable=$true; ExitCode=1; ReportPath=$xmlReport}
            }
            2 {
                Write-LogError "Scan failed — reboot required first"
                return @{Success=$false; ExitCode=2; Message="Reboot required"}
            }
            3 {
                Write-LogError "Scan failed — Dell Command Update needs update"
                return @{Success=$false; ExitCode=3; Message="DCU needs update"}
            }
            5 {
                Write-LogError "Scan failed — no network connection"
                return @{Success=$false; ExitCode=5; Message="No network"}
            }
            default {
                Write-LogWarning "Scan returned unexpected code: $($proc.ExitCode)"
                return @{Success=$true; UpdatesAvailable=$true; ExitCode=$proc.ExitCode}
            }
        }
    } catch {
        Write-LogError "Scan process failed: $_"
        return @{Success=$false; ExitCode=-1; Message=$_.ToString()}
    }
}

# ── PARSE SCAN REPORT ─────────────────────────────────────────
function Get-UpdateReport {
    param([string]$ReportPath)

    if (-not (Test-Path $ReportPath)) {
        Write-LogWarning "No XML report found at: $ReportPath"
        return @()
    }

    try {
        [xml]$report = Get-Content $ReportPath -ErrorAction Stop
        $updates = @()

        # Parse available updates from XML
        $report.SelectNodes("//update") | ForEach-Object {
            $updates += @{
                Name     = $_.name
                Version  = $_.version
                Category = $_.category
                Severity = $_.urgency
                Size     = $_.size
            }
        }

        if ($updates.Count -gt 0) {
            Write-LogInfo "Updates found: $($updates.Count)"
            Write-Host ""
            Write-Host "  Available Updates:" -ForegroundColor Yellow
            Write-Host "  ─────────────────────────────────────────" -ForegroundColor Gray
            foreach ($u in $updates) {
                $severity = switch ($u.Severity) {
                    "urgent"     { "🔴 URGENT" }
                    "recommended"{ "🟡 RECOMMENDED" }
                    "optional"   { "⚪ OPTIONAL" }
                    default      { "⚪ $($u.Severity)" }
                }
                Write-Host "  $severity | $($u.Name) v$($u.Version)" -ForegroundColor White
            }
            Write-Host ""
        }

        return $updates
    } catch {
        Write-LogWarning "Could not parse XML report: $_"
        return @()
    }
}

# ── INSTALL UPDATES ───────────────────────────────────────────
function Invoke-DCUInstall {
    param(
        [string]$DCUPath,
        [int]$Attempt = 1
    )

    Write-LogInfo "Installing driver updates (attempt $Attempt of $MAX_RETRIES)..."

    $installLog = "$env:ProgramData\Shadow313\Logs\dcu-install-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

    $installArgs = @(
        "/applyUpdates",
        "-outputLog=$installLog",
        "-silent",
        "-reboot=disable",          # We control reboots
        "-forceUpdate=enable",      # Force even if same version
        "-autoSuspendBitLocker=enable"  # Handle BitLocker automatically
    )

    try {
        Write-LogInfo "Running: dcu-cli.exe $($installArgs -join ' ')"

        $proc = Start-Process -FilePath $DCUPath `
            -ArgumentList $installArgs `
            -Wait -PassThru `
            -WindowStyle Hidden

        Write-Log "  Install exit code: $($proc.ExitCode)"

        # Parse exit codes
        switch ($proc.ExitCode) {
            0 {
                Write-LogSuccess "All updates installed successfully"
                return @{Success=$true; RebootRequired=$false; ExitCode=0}
            }
            1 {
                Write-LogSuccess "Updates installed — reboot required"
                return @{Success=$true; RebootRequired=$true; ExitCode=1}
            }
            2 {
                Write-LogWarning "Reboot required before installing"
                return @{Success=$false; RebootRequired=$true; ExitCode=2}
            }
            3 {
                Write-LogError "Dell Command Update itself needs updating"
                return @{Success=$false; ExitCode=3; Message="Update DCU first"}
            }
            4 {
                Write-LogError "Install failed — check log: $installLog"
                return @{Success=$false; ExitCode=4; LogPath=$installLog}
            }
            5 {
                Write-LogError "No network connection"
                return @{Success=$false; ExitCode=5}
            }
            6 {
                Write-LogWarning "Some updates failed — partial install"
                return @{Success=$true; Partial=$true; ExitCode=6; LogPath=$installLog}
            }
            default {
                Write-LogWarning "Unexpected exit code: $($proc.ExitCode)"
                return @{Success=$false; ExitCode=$proc.ExitCode; LogPath=$installLog}
            }
        }
    } catch {
        Write-LogError "Install process failed: $_"
        return @{Success=$false; ExitCode=-1; Message=$_.ToString()}
    }
}

# ── VERIFY INSTALLATION ───────────────────────────────────────
function Confirm-DriverUpdate {
    Write-LogInfo "Verifying driver updates..."

    $criticalDrivers = @(
        @{Name="Qualcomm QCA61x4A 802.11ac Wireless Adapter"; MinDate="2022-01-01"},
        @{Name="Qualcomm QCA61x4A Bluetooth";                  MinDate="2022-01-01"},
        @{Name="Realtek Audio";                                 MinDate="2021-01-01"},
        @{Name="Dell Touchpad";                                 MinDate="2022-01-01"}
    )

    Write-Host ""
    Write-Host "  Driver Verification:" -ForegroundColor Yellow
    Write-Host "  ─────────────────────────────────────────" -ForegroundColor Gray

    $allGood = $true
    foreach ($driver in $criticalDrivers) {
        $installed = Get-WmiObject Win32_PnPSignedDriver |
            Where-Object {$_.DeviceName -like "*$($driver.Name.Split(' ')[0])*"} |
            Select-Object -First 1

        if ($installed) {
            $driverDate = [datetime]::ParseExact(
                $installed.DriverDate.Substring(0,8),
                "yyyyMMdd", $null
            )
            $minDate = [datetime]$driver.MinDate
            $isNew = $driverDate -gt $minDate

            $status = if ($isNew) { "✅" } else { "⚠️" }
            Write-Host "  $status $($driver.Name.Split(' ')[0..1] -join ' ')" -ForegroundColor $(if($isNew){"Green"}else{"Yellow"})
            Write-Host "     Version: $($installed.DriverVersion) | Date: $($driverDate.ToString('yyyy-MM-dd'))" -ForegroundColor Gray

            if (-not $isNew) { $allGood = $false }
        } else {
            Write-Host "  ❓ $($driver.Name.Split(' ')[0]) — not found" -ForegroundColor Gray
        }
    }

    return $allGood
}

# ── SHOW INSTALL LOG ──────────────────────────────────────────
function Show-InstallLog {
    param([string]$LogFilePath)

    if (Test-Path $LogFilePath) {
        Write-LogInfo "Last 20 lines of install log:"
        Write-Host "  ─────────────────────────────────────────" -ForegroundColor Gray
        Get-Content $LogFilePath -Tail 20 |
            ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    }
}

# ── MAIN EXECUTION ────────────────────────────────────────────
function Main {
    Show-Header

    # Step 1: System info
    Write-LogInfo "Step 1/5: System Information"
    $sysInfo = Get-SystemInfo
    Write-Host ""

    # Step 2: Find or install DCU
    Write-LogInfo "Step 2/5: Locating Dell Command Update CLI"
    $dcuPath = Find-DCUCli

    if (-not $dcuPath) {
        Write-LogWarning "dcu-cli.exe not found — installing Dell Command Update..."
        $dcuPath = Install-DellCommandUpdate

        if (-not $dcuPath) {
            Write-LogError "Cannot find or install Dell Command Update"
            Write-LogError "Manual install: winget install Dell.CommandUpdate.Universal"
            exit 1
        }
    }

    Write-Host ""

    # Step 3: Scan
    Write-LogInfo "Step 3/5: Scanning for Updates"
    $scanResult = Invoke-DCUScan -DCUPath $dcuPath

    if (-not $scanResult.Success) {
        Write-LogError "Scan failed: $($scanResult.Message)"
        if ($scanResult.ExitCode -eq 2) {
            Write-LogWarning "Please reboot and run this script again"
        }
        exit 1
    }

    if (-not $scanResult.UpdatesAvailable) {
        Write-LogSuccess "System is up to date — no driver updates needed"
        Confirm-DriverUpdate
        exit 0
    }

    # Parse and display available updates
    if ($scanResult.ReportPath) {
        $updates = Get-UpdateReport -ReportPath $scanResult.ReportPath
    }

    # Scan only mode
    if ($ScanOnly) {
        Write-LogInfo "Scan-only mode — skipping installation"
        Write-LogInfo "Run without -ScanOnly to install updates"
        exit 0
    }

    Write-Host ""

    # Step 4: Install with retry
    Write-LogInfo "Step 4/5: Installing Updates"
    $installResult = $null

    for ($attempt = 1; $attempt -le $MAX_RETRIES; $attempt++) {
        $installResult = Invoke-DCUInstall -DCUPath $dcuPath -Attempt $attempt

        if ($installResult.Success) {
            break
        }

        if ($attempt -lt $MAX_RETRIES) {
            Write-LogWarning "Attempt $attempt failed — retrying in $RETRY_DELAY seconds..."
            Start-Sleep -Seconds $RETRY_DELAY
        }
    }

    # Show log if there were issues
    if (-not $installResult.Success -or $installResult.Partial) {
        if ($installResult.LogPath) {
            Show-InstallLog -LogFilePath $installResult.LogPath
        }
    }

    Write-Host ""

    # Step 5: Verify
    Write-LogInfo "Step 5/5: Verifying Installation"
    $verified = Confirm-DriverUpdate

    # ── FINAL SUMMARY ─────────────────────────────────────────
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host " Update Summary" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""

    if ($installResult.Success) {
        Write-LogSuccess "Driver update completed successfully"
    } else {
        Write-LogError "Driver update had errors — check log: $LogPath"
    }

    if ($installResult.RebootRequired) {
        Write-Host ""
        Write-Host "  ⚠️  REBOOT REQUIRED" -ForegroundColor Yellow
        Write-Host "  Some drivers need a reboot to activate" -ForegroundColor Yellow
        Write-Host ""

        if ($RebootIfNeeded) {
            Write-LogInfo "Auto-reboot enabled — rebooting in 30 seconds..."
            Write-LogInfo "Press Ctrl+C to cancel"
            Start-Sleep -Seconds 30
            Restart-Computer -Force
        } else {
            Write-Host "  Run with -RebootIfNeeded to auto-reboot" -ForegroundColor Gray
            Write-Host "  Or manually restart when ready" -ForegroundColor Gray
        }
    } else {
        Write-LogSuccess "No reboot required — all drivers active immediately"
    }

    Write-Host ""
    Write-Host "  Log file: $LogPath" -ForegroundColor Gray
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan

    # Return exit code
    if ($installResult.Success) { exit 0 } else { exit 1 }
}

# ── RUN ───────────────────────────────────────────────────────
Main