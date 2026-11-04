#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Shadow313 — Registry Orphan Audit (READ-ONLY)
    Scans all 10 registry locations for orphaned SIDs.
    Makes ZERO changes. Reports only.
    
    Run as: Normal user OR Admin (Admin sees more)
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
    .\shadow313-registry-audit-readonly.ps1
    
    Output is also saved to Desktop as shadow313-registry-audit-YYYYMMDD.txt
#>

$ErrorActionPreference = "SilentlyContinue"
$timestamp = Get-Date -Format "yyyyMMdd-HHmm"
$reportFile = "$env:USERPROFILE\Desktop\shadow313-registry-audit-$timestamp.txt"
$findings = @()

function Write-Report {
    param([string]$Line, [string]$Color = "White")
    Write-Host $Line -ForegroundColor $Color
    $Line | Add-Content $reportFile -Encoding UTF8
}

function Write-Section { param([string]$T) 
    Write-Report ""
    Write-Report "═══════════════════════════════════════════════════════════════" "Cyan"
    Write-Report "  $T" "Cyan"
    Write-Report "═══════════════════════════════════════════════════════════════" "Cyan"
}

function Write-Sub { param([string]$T)
    Write-Report ""
    Write-Report "  ── $T ──" "Yellow"
}

# Header
"" | Set-Content $reportFile -Encoding UTF8
Write-Report "╔══════════════════════════════════════════════════════════════════╗" "Cyan"
Write-Report "║  Shadow313 — Registry Orphan Audit (READ-ONLY)                ║" "Cyan"
Write-Report "║  Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')                        ║" "Cyan"
Write-Report "║  Computer:  $env:COMPUTERNAME / User: $env:USERNAME" "Cyan"
Write-Report "║  NO CHANGES MADE — REPORT ONLY                                ║" "Cyan"
Write-Report "╚══════════════════════════════════════════════════════════════════╝" "Cyan"

# ─────────────────────────────────────────────────────────────────
# BUILD ACTIVE SID MAP
# ─────────────────────────────────────────────────────────────────
Write-Section "STEP 1: Build Active Account SID Map"

$activeSIDs = @{}
$wellKnownSIDs = @{
    "S-1-5-18"  = "NT AUTHORITY\SYSTEM"
    "S-1-5-19"  = "NT AUTHORITY\LOCAL SERVICE"
    "S-1-5-20"  = "NT AUTHORITY\NETWORK SERVICE"
    "S-1-5-32-544" = "BUILTIN\Administrators"
    "S-1-5-32-545" = "BUILTIN\Users"
    "S-1-5-32-546" = "BUILTIN\Guests"
}
foreach ($k in $wellKnownSIDs.Keys) { $activeSIDs[$k] = $wellKnownSIDs[$k] }

# Get all local users
Get-LocalUser | ForEach-Object {
    try {
        $sid = (New-Object System.Security.Principal.NTAccount($_.Name)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        $activeSIDs[$sid] = "$env:COMPUTERNAME\$($_.Name)"
        $status = if ($_.Enabled) { "ENABLED" } else { "DISABLED" }
        Write-Report "  ✅ $($_.Name.PadRight(20)) $sid  [$status]" "Green"
    } catch {
        Write-Report "  ⚠️  Could not resolve SID for: $($_.Name)" "Yellow"
    }
}

Write-Report ""
Write-Report "  Total active accounts mapped: $($activeSIDs.Count - $wellKnownSIDs.Count) user + $($wellKnownSIDs.Count) system" "Gray"

# ─────────────────────────────────────────────────────────────────
# HELPER: Resolve SID
# ─────────────────────────────────────────────────────────────────
function Resolve-SID {
    param([string]$SID)
    if ($activeSIDs.ContainsKey($SID)) { return @{ Name=$activeSIDs[$SID]; Status="ACTIVE" } }
    try {
        $name = (New-Object System.Security.Principal.SecurityIdentifier($SID)).Translate([System.Security.Principal.NTAccount]).Value
        return @{ Name=$name; Status="ACTIVE" }
    } catch {
        return @{ Name="UNRESOLVABLE"; Status="ORPHAN" }
    }
}

# ─────────────────────────────────────────────────────────────────
# LOCATION 1: ProfileList — THE MOST IMPORTANT
# ─────────────────────────────────────────────────────────────────
Write-Section "LOCATION 1: ProfileList (Primary Profile Registry)"
Write-Report "  Path: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" "Gray"
Write-Report "  Impact if orphaned: Slow login, ghost profile folders, disk waste" "Gray"

$profileListPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
$profileOrphans = @()

if (Test-Path $profileListPath) {
    Get-ChildItem $profileListPath | ForEach-Object {
        $sid = $_.PSChildName
        $props = Get-ItemProperty $_.PSPath
        $profilePath = $props.ProfileImagePath
        $state = $props.State
        $resolved = Resolve-SID $sid
        
        if ($resolved.Status -eq "ACTIVE") {
            Write-Report "  ✅ ACTIVE:  $($resolved.Name)" "Green"
            Write-Report "     SID:    $sid"
            Write-Report "     Path:   $profilePath"
            Write-Report "     State:  $state (0=loaded, 1=mandatory, 2=guest)"
            
            # Check if profile folder actually exists
            if ($profilePath -and -not (Test-Path $profilePath)) {
                Write-Report "     ⚠️  WARNING: Profile folder MISSING from disk!" "Yellow"
                $findings += [PSCustomObject]@{
                    Severity = "WARN"
                    Location = "ProfileList"
                    SID      = $sid
                    Account  = $resolved.Name
                    Issue    = "Profile folder missing: $profilePath"
                    Fix      = "Recreate folder or remove registry entry"
                }
            }
        } else {
            Write-Report "  ❌ ORPHAN:  $sid" "Red"
            Write-Report "     Path:   $profilePath"
            Write-Report "     State:  $state"
            Write-Report "     → Account deleted but registry entry remains" "Red"
            
            $folderExists = if ($profilePath) { Test-Path $profilePath } else { $false }
            $folderSize = if ($folderExists) {
                [math]::Round((Get-ChildItem $profilePath -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum/1MB,0)
            } else { 0 }
            
            Write-Report "     Folder on disk: $(if($folderExists){"YES — $folderSize MB"}else{"NO"})" "Yellow"
            
            $profileOrphans += [PSCustomObject]@{
                SID         = $sid
                ProfilePath = $profilePath
                FolderExists = $folderExists
                FolderSizeMB = $folderSize
                RegPath     = $_.PSPath
            }
            
            $findings += [PSCustomObject]@{
                Severity = "CRITICAL"
                Location = "ProfileList"
                SID      = $sid
                Account  = "DELETED ACCOUNT"
                Issue    = "Orphaned profile registry entry (likely admin123 or Baalb)"
                Fix      = "Remove-Item '$($_.PSPath)' -Recurse -Force  (run as Admin)"
            }
        }
    }
} else {
    Write-Report "  ⚠️  ProfileList registry key not accessible" "Yellow"
}

# ─────────────────────────────────────────────────────────────────
# LOCATION 2: ProfileGuid
# ─────────────────────────────────────────────────────────────────
Write-Section "LOCATION 2: ProfileGuid (GUID-to-SID Mapping)"
Write-Report "  Path: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileGuid" "Gray"
Write-Report "  Impact if orphaned: Stale GUID mappings, potential auth confusion" "Gray"

$profileGuidPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileGuid"
if (Test-Path $profileGuidPath) {
    $guidOrphans = 0
    Get-ChildItem $profileGuidPath -ErrorAction SilentlyContinue | ForEach-Object {
        $guid = $_.PSChildName
        $sid = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Sid
        if ($sid) {
            $resolved = Resolve-SID $sid
            if ($resolved.Status -eq "ORPHAN") {
                Write-Report "  ❌ ORPHAN GUID: $guid → SID: $sid" "Red"
                $guidOrphans++
                $findings += [PSCustomObject]@{
                    Severity = "HIGH"
                    Location = "ProfileGuid"
                    SID      = $sid
                    Account  = "DELETED ACCOUNT"
                    Issue    = "Orphaned GUID mapping: $guid"
                    Fix      = "Remove-Item '$($_.PSPath)' -Recurse -Force  (run as Admin)"
                }
            } else {
                Write-Report "  ✅ $guid → $($resolved.Name)" "Green"
            }
        }
    }
    if ($guidOrphans -eq 0) { Write-Report "  ✅ No orphaned GUIDs found" "Green" }
} else {
    Write-Report "  ℹ️  ProfileGuid key not present (normal on some systems)" "Gray"
}

# ─────────────────────────────────────────────────────────────────
# LOCATION 3: Group Policy State
# ─────────────────────────────────────────────────────────────────
Write-Section "LOCATION 3: Group Policy State"
Write-Report "  Path: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State" "Gray"
Write-Report "  Impact if orphaned: GPO processing errors, slow policy application" "Gray"

$gpPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State"
if (Test-Path $gpPath) {
    $gpOrphans = 0
    Get-ChildItem $gpPath -ErrorAction SilentlyContinue | ForEach-Object {
        $name = $_.PSChildName
        if ($name -match "^S-1-5-21-") {
            $resolved = Resolve-SID $name
            if ($resolved.Status -eq "ORPHAN") {
                Write-Report "  ❌ ORPHAN GP STATE: $name" "Red"
                $gpOrphans++
                $findings += [PSCustomObject]@{
                    Severity = "MEDIUM"
                    Location = "Group Policy State"
                    SID      = $name
                    Account  = "DELETED ACCOUNT"
                    Issue    = "Orphaned Group Policy state entry"
                    Fix      = "Remove-Item '$($_.PSPath)' -Recurse -Force  (run as Admin)"
                }
            } else {
                Write-Report "  ✅ GP State: $($resolved.Name)" "Green"
            }
        }
    }
    if ($gpOrphans -eq 0) { Write-Report "  ✅ No orphaned GP state entries" "Green" }
} else {
    Write-Report "  ℹ️  Group Policy State key not present" "Gray"
}

# ─────────────────────────────────────────────────────────────────
# LOCATION 4: Services (Security Descriptors)
# ─────────────────────────────────────────────────────────────────
Write-Section "LOCATION 4: Services (Security Descriptors)"
Write-Report "  Path: HKLM\SYSTEM\CurrentControlSet\Services" "Gray"
Write-Report "  Impact if orphaned: Services may fail to start, access denied errors" "Gray"
Write-Report "  Scanning ObjectName values for deleted account references..." "Gray"

$servicesPath = "HKLM:\SYSTEM\CurrentControlSet\Services"
$serviceOrphans = 0
if (Test-Path $servicesPath) {
    Get-ChildItem $servicesPath -ErrorAction SilentlyContinue | ForEach-Object {
        $svcName = $_.PSChildName
        $objectName = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).ObjectName
        # Check if service runs as a deleted account
        if ($objectName -and $objectName -notmatch "LocalSystem|LocalService|NetworkService|NT AUTHORITY|NT SERVICE") {
            # Try to resolve the account
            try {
                $acct = New-Object System.Security.Principal.NTAccount($objectName)
                $sid = $acct.Translate([System.Security.Principal.SecurityIdentifier]).Value
                # Valid account — skip
            } catch {
                if ($objectName -match "admin123|Baalb|Administrator" -or $objectName -match "\\") {
                    Write-Report "  ⚠️  SERVICE: $svcName runs as '$objectName' — account may not exist" "Yellow"
                    $serviceOrphans++
                    $findings += [PSCustomObject]@{
                        Severity = "HIGH"
                        Location = "Services"
                        SID      = "N/A"
                        Account  = $objectName
                        Issue    = "Service '$svcName' configured to run as potentially deleted account"
                        Fix      = "Change service logon account in services.msc"
                    }
                }
            }
        }
    }
    if ($serviceOrphans -eq 0) { Write-Report "  ✅ No services referencing deleted accounts" "Green" }
}

# ─────────────────────────────────────────────────────────────────
# LOCATION 5: Task Scheduler Cache
# ─────────────────────────────────────────────────────────────────
Write-Section "LOCATION 5: Task Scheduler Cache"
Write-Report "  Path: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache" "Gray"
Write-Report "  Impact if orphaned: Scheduled tasks fail silently, event log errors" "Gray"

$taskPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks"
$taskOrphans = 0
if (Test-Path $taskPath) {
    Get-ChildItem $taskPath -ErrorAction SilentlyContinue | ForEach-Object {
        $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        $author = $props.Author
        $userId = $props.UserId
        if ($userId -and $userId -match "^S-1-5-21-") {
            $resolved = Resolve-SID $userId
            if ($resolved.Status -eq "ORPHAN") {
                $taskName = $props.Path
                Write-Report "  ❌ ORPHAN TASK: $taskName" "Red"
                Write-Report "     UserID: $userId" "Red"
                $taskOrphans++
                $findings += [PSCustomObject]@{
                    Severity = "MEDIUM"
                    Location = "Task Scheduler"
                    SID      = $userId
                    Account  = "DELETED ACCOUNT"
                    Issue    = "Scheduled task '$taskName' owned by deleted account"
                    Fix      = "Delete task in Task Scheduler or via schtasks /delete"
                }
            }
        }
    }
    if ($taskOrphans -eq 0) { Write-Report "  ✅ No orphaned scheduled tasks" "Green" }
}

# ─────────────────────────────────────────────────────────────────
# LOCATION 6: AppX User Store
# ─────────────────────────────────────────────────────────────────
Write-Section "LOCATION 6: AppX Package User Store"
Write-Report "  Path: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore" "Gray"
Write-Report "  Impact if orphaned: App installation errors, Store issues" "Gray"

$appxPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore"
$appxOrphans = 0
if (Test-Path $appxPath) {
    Get-ChildItem $appxPath -ErrorAction SilentlyContinue | ForEach-Object {
        $name = $_.PSChildName
        if ($name -match "^S-1-5-21-") {
            $resolved = Resolve-SID $name
            if ($resolved.Status -eq "ORPHAN") {
                Write-Report "  ❌ ORPHAN AppX SID: $name" "Red"
                $appxOrphans++
                $findings += [PSCustomObject]@{
                    Severity = "LOW"
                    Location = "AppX User Store"
                    SID      = $name
                    Account  = "DELETED ACCOUNT"
                    Issue    = "Orphaned AppX package registration"
                    Fix      = "Remove-Item '$($_.PSPath)' -Recurse -Force  (run as Admin)"
                }
            }
        }
    }
    if ($appxOrphans -eq 0) { Write-Report "  ✅ No orphaned AppX entries" "Green" }
}

# ─────────────────────────────────────────────────────────────────
# LOCATION 7: HKCU Hive Check (current user + loaded hives)
# ─────────────────────────────────────────────────────────────────
Write-Section "LOCATION 7: HKCU Loaded Hives (HKU)"
Write-Report "  Path: HKU (HKEY_USERS — all loaded user hives)" "Gray"
Write-Report "  Impact if orphaned: Stale hive files, registry bloat" "Gray"

$hkuOrphans = 0
try {
    $hku = Get-ChildItem "Registry::HKEY_USERS" -ErrorAction SilentlyContinue
    foreach ($key in $hku) {
        $sid = $key.PSChildName
        if ($sid -match "^S-1-5-21-" -and $sid -notmatch "_Classes$") {
            $resolved = Resolve-SID $sid
            if ($resolved.Status -eq "ORPHAN") {
                Write-Report "  ❌ ORPHAN HIVE LOADED: $sid" "Red"
                Write-Report "     → Deleted account hive still mounted in memory" "Red"
                $hkuOrphans++
                $findings += [PSCustomObject]@{
                    Severity = "HIGH"
                    Location = "HKU (Loaded Hives)"
                    SID      = $sid
                    Account  = "DELETED ACCOUNT"
                    Issue    = "Deleted account registry hive still loaded in memory"
                    Fix      = "Reboot to unload, then clean ProfileList entry"
                }
            } else {
                Write-Report "  ✅ Loaded hive: $($resolved.Name) ($sid)" "Green"
            }
        }
    }
    if ($hkuOrphans -eq 0) { Write-Report "  ✅ No orphaned hives loaded" "Green" }
} catch {
    Write-Report "  ⚠️  Could not enumerate HKU (may need Admin)" "Yellow"
}

# ─────────────────────────────────────────────────────────────────
# LOCATION 8: Credential Manager / Logon Session
# ─────────────────────────────────────────────────────────────────
Write-Section "LOCATION 8: Credential Manager Remnants"
Write-Report "  Path: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication" "Gray"
Write-Report "  Impact if orphaned: Stale credential prompts, auth delays" "Gray"

$credPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
if (Test-Path $credPath) {
    $lastUser = (Get-ItemProperty $credPath -ErrorAction SilentlyContinue).LastLoggedOnUser
    $lastSAM  = (Get-ItemProperty $credPath -ErrorAction SilentlyContinue).LastLoggedOnSAMUser
    Write-Report "  Last logged on user: $lastUser" "Gray"
    Write-Report "  Last SAM user:       $lastSAM" "Gray"
    
    if ($lastUser -match "admin123|Baalb") {
        Write-Report "  ⚠️  Last logon references deleted account: $lastUser" "Yellow"
        $findings += [PSCustomObject]@{
            Severity = "LOW"
            Location = "LogonUI"
            SID      = "N/A"
            Account  = $lastUser
            Issue    = "LogonUI still references deleted account as last user"
            Fix      = "Will auto-clear on next successful login"
        }
    } else {
        Write-Report "  ✅ LogonUI references active account" "Green"
    }
}

# ─────────────────────────────────────────────────────────────────
# LOCATION 9: Terminal Server / RDP
# ─────────────────────────────────────────────────────────────────
Write-Section "LOCATION 9: Terminal Server / RDP Sessions"
Write-Report "  Path: HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" "Gray"
Write-Report "  Impact if orphaned: Ghost RDP sessions, connection errors" "Gray"

$tsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations"
$tsOrphans = 0
if (Test-Path $tsPath) {
    Get-ChildItem $tsPath -ErrorAction SilentlyContinue | ForEach-Object {
        $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        $userSID = $props.UserSID
        if ($userSID -and $userSID -match "^S-1-5-21-") {
            $resolved = Resolve-SID $userSID
            if ($resolved.Status -eq "ORPHAN") {
                Write-Report "  ❌ ORPHAN RDP SESSION: $($_.PSChildName) → SID: $userSID" "Red"
                $tsOrphans++
                $findings += [PSCustomObject]@{
                    Severity = "LOW"
                    Location = "Terminal Server"
                    SID      = $userSID
                    Account  = "DELETED ACCOUNT"
                    Issue    = "Ghost RDP session for deleted account"
                    Fix      = "Remove-Item '$($_.PSPath)' -Recurse -Force  (run as Admin)"
                }
            }
        }
    }
    if ($tsOrphans -eq 0) { Write-Report "  ✅ No orphaned RDP sessions" "Green" }
}

# ─────────────────────────────────────────────────────────────────
# LOCATION 10: Shell Folders / User Shell Folders
# ─────────────────────────────────────────────────────────────────
Write-Section "LOCATION 10: Shell Folder Redirections"
Write-Report "  Path: HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" "Gray"
Write-Report "  Impact if orphaned: Broken folder redirections, missing Desktop/Documents" "Gray"

$shellPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
if (Test-Path $shellPath) {
    $shellProps = Get-ItemProperty $shellPath -ErrorAction SilentlyContinue
    $brokenPaths = @()
    $shellProps.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
        $val = $_.Value
        if ($val -and $val -match "^[A-Z]:\\") {
            $expanded = [System.Environment]::ExpandEnvironmentVariables($val)
            if (-not (Test-Path $expanded)) {
                $brokenPaths += [PSCustomObject]@{ Name=$_.Name; Path=$expanded }
                Write-Report "  ⚠️  BROKEN REDIRECT: $($_.Name) → $expanded (path missing)" "Yellow"
                $findings += [PSCustomObject]@{
                    Severity = "MEDIUM"
                    Location = "Shell Folders"
                    SID      = "N/A"
                    Account  = $env:USERNAME
                    Issue    = "Shell folder '$($_.Name)' points to missing path: $expanded"
                    Fix      = "Update registry value or restore the folder"
                }
            }
        }
    }
    if ($brokenPaths.Count -eq 0) { Write-Report "  ✅ All shell folder redirections valid" "Green" }
}

# ─────────────────────────────────────────────────────────────────
# DISK: Leftover Profile Folders
# ─────────────────────────────────────────────────────────────────
Write-Section "DISK: Leftover Profile Folders"
Write-Report "  Checking C:\Users for folders belonging to deleted accounts..." "Gray"

$allUserFolders = Get-ChildItem "C:\Users" -ErrorAction SilentlyContinue
foreach ($folder in $allUserFolders) {
    # Try to find matching active account
    $matchedAccount = Get-LocalUser | Where-Object { $_.Name -eq $folder.Name } | Select-Object -First 1
    if ($matchedAccount) {
        Write-Report "  ✅ $($folder.Name.PadRight(20)) — Active account" "Green"
    } elseif ($folder.Name -match "^(Public|Default|All Users|Default User)$") {
        Write-Report "  ✅ $($folder.Name.PadRight(20)) — System folder" "Gray"
    } else {
        $size = [math]::Round((Get-ChildItem $folder.FullName -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum/1MB,0)
        Write-Report "  ❌ $($folder.Name.PadRight(20)) — NO MATCHING ACCOUNT ($size MB)" "Red"
        Write-Report "     Path: $($folder.FullName)" "Red"
        Write-Report "     → Leftover from deleted account (safe to delete if account gone)" "Yellow"
        $findings += [PSCustomObject]@{
            Severity = "MEDIUM"
            Location = "Disk (C:\Users)"
            SID      = "N/A"
            Account  = $folder.Name
            Issue    = "Profile folder exists but no matching local account ($size MB)"
            Fix      = "Remove-Item '$($folder.FullName)' -Recurse -Force  (run as Admin)"
        }
    }
}

# ─────────────────────────────────────────────────────────────────
# FINAL REPORT
# ─────────────────────────────────────────────────────────────────
Write-Section "FINAL FINDINGS SUMMARY"

$critical = $findings | Where-Object { $_.Severity -eq "CRITICAL" }
$high     = $findings | Where-Object { $_.Severity -eq "HIGH" }
$medium   = $findings | Where-Object { $_.Severity -eq "MEDIUM" }
$low      = $findings | Where-Object { $_.Severity -eq "LOW" }

Write-Report "  Total findings: $($findings.Count)" "White"
Write-Report "  CRITICAL: $($critical.Count)" "Red"
Write-Report "  HIGH:     $($high.Count)" "Yellow"
Write-Report "  MEDIUM:   $($medium.Count)" "Cyan"
Write-Report "  LOW:      $($low.Count)" "Gray"

if ($findings.Count -gt 0) {
    Write-Report ""
    Write-Report "  ── Detailed Findings ──" "Yellow"
    foreach ($f in $findings | Sort-Object { @{"CRITICAL"=0;"HIGH"=1;"MEDIUM"=2;"LOW"=3}[$_.Severity] }) {
        Write-Report ""
        Write-Report "  [$($f.Severity)] $($f.Location)" $(if($f.Severity -eq "CRITICAL"){"Red"}elseif($f.Severity -eq "HIGH"){"Yellow"}else{"Cyan"})
        Write-Report "  SID:   $($f.SID)"
        Write-Report "  Issue: $($f.Issue)"
        Write-Report "  Fix:   $($f.Fix)" "White"
    }
    
    Write-Report ""
    Write-Report "  ── How to Clean (run as Admin) ──" "Yellow"
    Write-Report "  Option A — Run the full fix script with cleanup flag:" "White"
    Write-Report "  .\scripts\shadow313-complete-system-fix.ps1 -CleanOrphans" "White"
    Write-Report ""
    Write-Report "  Option B — Manual cleanup commands:" "White"
    foreach ($f in $findings | Where-Object { $_.Fix -match "Remove-Item|schtasks" }) {
        Write-Report "  $($f.Fix)" "White"
    }
} else {
    Write-Report ""
    Write-Report "  ✅ CLEAN — No orphaned entries found across all 10 locations!" "Green"
    Write-Report "  Your registry is in good shape after the account deletion." "Green"
}

Write-Report ""
Write-Report "  Report saved to: $reportFile" "Cyan"
Write-Report "  Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "Gray"

Write-Host "`n  ✅ Audit complete — report saved to your Desktop" -ForegroundColor Green
Write-Host "  File: $reportFile" -ForegroundColor Cyan