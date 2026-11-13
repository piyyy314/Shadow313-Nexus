#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Shadow313 — Account Cleanup & OneDrive Fix
    
    Fixes:
    1. Audits all accounts and their OneDrive connections
    2. Pauses/disconnects OneDrive properly
    3. Removes duplicate files synced from Baalb account
    4. Locks down Baalb so it never syncs again
    5. Sets correct folder paths for shiatoali only
    6. Prevents future cross-account contamination
    
    Run from: ~\shadow313-nexus as normal user
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
    .\scripts\shadow313-account-cleanup.ps1
#>

param(
    [switch]$DryRun,    # Show what would be done without doing it
    [switch]$Force      # Skip confirmations
)

$ErrorActionPreference = "Continue"

function Write-Step  { param([string]$T) Write-Host "`n[$T]" -ForegroundColor Cyan }
function Write-OK    { param([string]$M) Write-Host "  ✅ $M" -ForegroundColor Green }
function Write-Fixed { param([string]$M) Write-Host "  🔧 $M" -ForegroundColor Magenta }
function Write-Warn  { param([string]$M) Write-Host "  ⚠️  $M" -ForegroundColor Yellow }
function Write-Info  { param([string]$M) Write-Host "  ℹ️  $M" -ForegroundColor Gray }

if ($DryRun) {
    Write-Host "`n  [DRY RUN MODE — no changes will be made]" -ForegroundColor Yellow
}

Write-Host @"

╔══════════════════════════════════════════════════════════════════╗
║  Shadow313 — Account Cleanup & OneDrive Fix                    ║
║  Fixing cross-account contamination and duplicate files        ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# ═══════════════════════════════════════════════════════════════════
# STEP 1: FULL ACCOUNT AUDIT
# ═══════════════════════════════════════════════════════════════════
Write-Step "1/8 Account Audit"

Write-Host "`n  Active accounts on this machine:" -ForegroundColor Gray
Get-LocalUser | Format-Table Name, Enabled, PrincipalSource, LastLogon -AutoSize

Write-Host "  Administrators group:" -ForegroundColor Gray
Get-LocalGroupMember -Group "Administrators" | Format-Table Name, PrincipalSource -AutoSize

# Check if Baalb is still in Admins
$baalbInAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match "Baalb" }
if ($baalbInAdmins) {
    Write-Warn "Baalb is in Administrators group — this causes settings to bleed between accounts"
    if (-not $DryRun) {
        Remove-LocalGroupMember -Group "Administrators" -Member "Baalb" -ErrorAction SilentlyContinue
        Write-Fixed "Removed Baalb from Administrators group"
    }
} else {
    Write-OK "Baalb not in Administrators group"
}

# Check Baalb enabled status
$baalbUser = Get-LocalUser -Name "Baalb" -ErrorAction SilentlyContinue
if ($baalbUser -and $baalbUser.Enabled) {
    Write-Warn "Baalb account is ENABLED — should be disabled to prevent accidental login"
    Write-Info "Run as Admin to disable: Disable-LocalUser -Name 'Baalb'"
} else {
    Write-OK "Baalb account is disabled"
}

# ═══════════════════════════════════════════════════════════════════
# STEP 2: ONEDRIVE AUDIT & DISCONNECT
# ═══════════════════════════════════════════════════════════════════
Write-Step "2/8 OneDrive Audit & Disconnect"

# Find all OneDrive processes
$odProcesses = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
if ($odProcesses) {
    Write-Warn "OneDrive is running (PID $($odProcesses.Id)) — stopping it"
    if (-not $DryRun) {
        Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
        Start-Sleep 3
        Write-Fixed "OneDrive stopped"
    }
} else {
    Write-OK "OneDrive not running"
}

# Check OneDrive registry accounts
Write-Host "`n  OneDrive accounts in registry:" -ForegroundColor Gray
$odAccounts = Get-ChildItem "HKCU:\Software\Microsoft\OneDrive\Accounts" -ErrorAction SilentlyContinue
if ($odAccounts) {
    foreach ($acc in $odAccounts) {
        $props = Get-ItemProperty $acc.PSPath -ErrorAction SilentlyContinue
        $email  = $props.UserEmail
        $folder = $props.UserFolder
        $type   = $acc.PSChildName
        Write-Host "  Account: $type" -ForegroundColor Cyan
        Write-Host "    Email:  $email"
        Write-Host "    Folder: $folder"
        
        # Flag if Baalb's OneDrive is registered
        if ($email -match "baalb|baalbek|gmail" -or $folder -match "Baalb") {
            Write-Warn "This is Baalb's OneDrive — should be unlinked from shiatoali account"
        }
    }
} else {
    Write-OK "No OneDrive accounts in registry"
}

# Find OneDrive folder locations
Write-Host "`n  OneDrive folder locations:" -ForegroundColor Gray
$odPaths = @(
    "C:\OneDrive",
    "C:\Users\shiatoali\OneDrive",
    "C:\Users\Baalb\OneDrive",
    "$env:USERPROFILE\OneDrive"
)
foreach ($p in $odPaths) {
    if (Test-Path $p) {
        $size = [math]::Round((Get-ChildItem $p -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum/1GB,1)
        Write-Warn "OneDrive folder exists: $p ($size GB)"
    }
}

# ═══════════════════════════════════════════════════════════════════
# STEP 3: FIND DUPLICATE FILES FROM CROSS-ACCOUNT SYNC
# ═══════════════════════════════════════════════════════════════════
Write-Step "3/8 Find Duplicate/Contaminated Files"

Write-Host "`n  Scanning shiatoali home for files that belong to Baalb..." -ForegroundColor Gray

# Files that should NOT be in shiatoali's home root
$homeRoot = "C:\Users\shiatoali"
$suspiciousPatterns = @(
    "*.itdb*",      # iTunes database (Baalb's)
    "Genius*.itdb*" # iTunes Genius files
)

$suspiciousFiles = @()
foreach ($pattern in $suspiciousPatterns) {
    $found = Get-ChildItem $homeRoot -Filter $pattern -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch "shadow313-nexus|AppData" }
    $suspiciousFiles += $found
}

if ($suspiciousFiles) {
    Write-Warn "Found $($suspiciousFiles.Count) suspicious files from cross-account sync:"
    $suspiciousFiles | ForEach-Object { Write-Host "    $($_.FullName)" -ForegroundColor Yellow }
} else {
    Write-OK "No obvious cross-account contamination in home root"
}

# Check for Baalb's Copilot files that synced over
$copilotFiles = Get-ChildItem "$homeRoot\OneDrive\Pictures\Microsoft Copilot Chat Files" -ErrorAction SilentlyContinue
if ($copilotFiles) {
    Write-Warn "Baalb's Copilot files synced to shiatoali: $($copilotFiles.Count) files"
    Write-Info "Location: $homeRoot\OneDrive\Pictures\Microsoft Copilot Chat Files"
}

# ═══════════════════════════════════════════════════════════════════
# STEP 4: FIX FOLDER REDIRECTIONS
# ═══════════════════════════════════════════════════════════════════
Write-Step "4/8 Fix Folder Redirections"

# Check where Desktop, Documents, Pictures actually point
$shellFolders = @{
    "Desktop"   = [System.Environment]::GetFolderPath("Desktop")
    "Documents" = [System.Environment]::GetFolderPath("MyDocuments")
    "Pictures"  = [System.Environment]::GetFolderPath("MyPictures")
    "Downloads" = (New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
}

foreach ($folder in $shellFolders.GetEnumerator()) {
    $path = $folder.Value
    $expected = "C:\Users\shiatoali\$($folder.Key)"
    
    if ($path -match "Baalb|OneDrive") {
        Write-Warn "$($folder.Key) is redirected to: $path"
        Write-Info "Expected: $expected"
    } elseif ($path -eq $expected) {
        Write-OK "$($folder.Key): $path"
    } else {
        Write-Info "$($folder.Key): $path (non-standard but OK)"
    }
}

# ═══════════════════════════════════════════════════════════════════
# STEP 5: PREVENT ONEDRIVE FROM AUTO-STARTING
# ═══════════════════════════════════════════════════════════════════
Write-Step "5/8 Prevent OneDrive Auto-Start"

# Remove OneDrive from startup
$startupKeys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
)

foreach ($key in $startupKeys) {
    $odStartup = Get-ItemProperty $key -Name "OneDrive" -ErrorAction SilentlyContinue
    if ($odStartup) {
        Write-Warn "OneDrive in startup registry: $key"
        if (-not $DryRun) {
            Remove-ItemProperty $key -Name "OneDrive" -ErrorAction SilentlyContinue
            Write-Fixed "Removed OneDrive from startup: $key"
        }
    }
}

# Disable OneDrive scheduled tasks
$odTasks = Get-ScheduledTask | Where-Object { $_.TaskName -match "OneDrive" } -ErrorAction SilentlyContinue
foreach ($task in $odTasks) {
    Write-Warn "OneDrive scheduled task: $($task.TaskName) [$($task.State)]"
    if (-not $DryRun -and $task.State -ne "Disabled") {
        Disable-ScheduledTask -TaskName $task.TaskName -ErrorAction SilentlyContinue | Out-Null
        Write-Fixed "Disabled task: $($task.TaskName)"
    }
}

if (-not $odTasks) { Write-OK "No OneDrive scheduled tasks found" }

# ═══════════════════════════════════════════════════════════════════
# STEP 6: TRANSFER BAALB FILES SAFELY
# ═══════════════════════════════════════════════════════════════════
Write-Step "6/8 Baalb File Transfer Plan"

$baalbPath = "C:\Users\Baalb"
if (Test-Path $baalbPath) {
    Write-Host "`n  Baalb profile contents:" -ForegroundColor Gray
    Get-ChildItem $baalbPath -ErrorAction SilentlyContinue | ForEach-Object {
        $size = [math]::Round((Get-ChildItem $_.FullName -Recurse -ErrorAction SilentlyContinue |
            Measure-Object -Property Length -Sum).Sum/1MB,0)
        $flag = if ($size -gt 100) { "⚠️ " } else { "   " }
        Write-Host "  $flag$($_.Name.PadRight(25)) $size MB"
    }
    
    Write-Host "`n  Files to transfer from Baalb Desktop:" -ForegroundColor Yellow
    $transferItems = @(
        "C:\Users\Baalb\Desktop\shadow313-di",
        "C:\Users\Baalb\Desktop\Security Advisories*",
        "C:\Users\Baalb\Desktop\Telegram Desktop",
        "C:\Users\Baalb\Documents"
    )
    
    $dest = "C:\Users\shiatoali\Desktop\from-baalb"
    
    foreach ($item in $transferItems) {
        $exists = Get-Item $item -ErrorAction SilentlyContinue
        if ($exists) {
            Write-Host "  TRANSFER: $item" -ForegroundColor Cyan
            if (-not $DryRun) {
                New-Item -ItemType Directory -Path $dest -Force | Out-Null
                Copy-Item $item $dest -Recurse -Force -ErrorAction SilentlyContinue
                Write-Fixed "Copied: $(Split-Path $item -Leaf)"
            }
        }
    }
    
    if (-not $DryRun -and (Test-Path $dest)) {
        Write-OK "Files transferred to: $dest"
        Write-Info "Review the files, then you can safely disable/delete Baalb"
    }
} else {
    Write-OK "C:\Users\Baalb not found — already cleaned up"
}

# ═══════════════════════════════════════════════════════════════════
# STEP 7: LOCK DOWN SHIATOALI ACCOUNT SETTINGS
# ═══════════════════════════════════════════════════════════════════
Write-Step "7/8 Lock Down shiatoali Account"

# Ensure shiatoali's folders point to correct local paths
$correctPaths = @{
    "Desktop"   = "C:\Users\shiatoali\Desktop"
    "Documents" = "C:\Users\shiatoali\Documents"
    "Pictures"  = "C:\Users\shiatoali\Pictures"
    "Downloads" = "C:\Users\shiatoali\Downloads"
    "Music"     = "C:\Users\shiatoali\Music"
    "Videos"    = "C:\Users\shiatoali\Videos"
}

$shellFolderKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
foreach ($folder in $correctPaths.GetEnumerator()) {
    $current = (Get-ItemProperty $shellFolderKey -ErrorAction SilentlyContinue).$($folder.Key)
    if ($current -and $current -ne $folder.Value -and $current -match "OneDrive|Baalb") {
        Write-Warn "$($folder.Key) redirected to: $current"
        if (-not $DryRun) {
            # Create local folder if missing
            New-Item -ItemType Directory -Path $folder.Value -Force -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty $shellFolderKey -Name $folder.Key -Value $folder.Value -ErrorAction SilentlyContinue
            Write-Fixed "Reset $($folder.Key) to: $($folder.Value)"
        }
    } else {
        Write-OK "$($folder.Key): correctly set to local path"
    }
}

# Ensure all standard folders exist locally
foreach ($folder in $correctPaths.Values) {
    if (-not (Test-Path $folder)) {
        if (-not $DryRun) {
            New-Item -ItemType Directory -Path $folder -Force | Out-Null
            Write-Fixed "Created missing folder: $folder"
        }
    }
}

# ═══════════════════════════════════════════════════════════════════
# STEP 8: FINAL REPORT & RECOMMENDATIONS
# ═══════════════════════════════════════════════════════════════════
Write-Step "8/8 Final Report & Recommendations"

Write-Host @"

  ╔══════════════════════════════════════════════════════════════╗
  ║  ACCOUNT CLEANUP COMPLETE                                   ║
  ╠══════════════════════════════════════════════════════════════╣
  ║  IMMEDIATE ACTIONS NEEDED (manual):                        ║
  ║                                                              ║
  ║  1. DISABLE BAALB (run as Admin):                          ║
  ║     Disable-LocalUser -Name 'Baalb'                        ║
  ║                                                              ║
  ║  2. UNLINK ONEDRIVE from shiatoali account:                ║
  ║     Right-click OneDrive tray icon                         ║
  ║     Settings -> Account -> Unlink this PC                  ║
  ║     (Do NOT sign back in with Baalb's email)               ║
  ║                                                              ║
  ║  3. REVIEW TRANSFERRED FILES:                              ║
  ║     C:\Users\shiatoali\Desktop\from-baalb\                 ║
  ║     Keep what you need, delete the rest                    ║
  ║                                                              ║
  ║  4. AFTER REVIEW — DELETE BAALB PROFILE (as Admin):        ║
  ║     Remove-Item 'C:\Users\Baalb' -Recurse -Force           ║
  ║     Remove-LocalUser -Name 'Baalb'                         ║
  ║                                                              ║
  ║  5. PREVENT FUTURE CONTAMINATION:                          ║
  ║     Never sign into Windows with Baalb account             ║
  ║     Keep OneDrive unlinked or use only shiatoali email     ║
  ║     shiatoali = your ONLY working account                  ║
  ╠══════════════════════════════════════════════════════════════╣
  ║  WHY THIS HAPPENED:                                         ║
  ║  Baalb (Microsoft Account) was in Administrators group.    ║
  ║  When you logged in as Baalb, OneDrive synced its files    ║
  ║  into the shared C:\OneDrive path, contaminating           ║
  ║  shiatoali's profile with Baalb's data.                    ║
  ╚══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# Quick status check
Write-Host "`n  Current status:" -ForegroundColor Gray
Write-Host "  shiatoali enabled: $((Get-LocalUser -Name 'shiatoali').Enabled)" -ForegroundColor $(if((Get-LocalUser -Name 'shiatoali').Enabled){'Green'}else{'Red'})
$b = Get-LocalUser -Name 'Baalb' -ErrorAction SilentlyContinue
if ($b) {
    Write-Host "  Baalb enabled:     $($b.Enabled)" -ForegroundColor $(if(-not $b.Enabled){'Green'}else{'Yellow'})
    Write-Host "  Baalb in Admins:   $($null -ne (Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | Where-Object {$_.Name -match 'Baalb'}))" -ForegroundColor $(if($null -eq (Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | Where-Object {$_.Name -match 'Baalb'})){'Green'}else{'Yellow'})
}
Write-Host "  OneDrive running:  $($null -ne (Get-Process -Name 'OneDrive' -ErrorAction SilentlyContinue))" -ForegroundColor $(if($null -eq (Get-Process -Name 'OneDrive' -ErrorAction SilentlyContinue)){'Green'}else{'Yellow'})