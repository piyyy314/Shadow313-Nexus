# ============================================================
# SHADOW313 — Complete OneDrive Reset + KFM Disable
# Fixes: X icons, wrong exe path, Known Folder Move redirect
# Run as Administrator
# ============================================================

$ErrorActionPreference = "SilentlyContinue"

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  OneDrive Complete Reset + Known Folder Fix" -ForegroundColor Cyan
Write-Host "  Run as Administrator for best results" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# ── STEP 1: FIND REAL ONEDRIVE.EXE ───────────────────────────────────────
Write-Host "[1/7] Finding real OneDrive.exe..." -ForegroundColor Yellow

$searchPaths = @(
    "$env:LOCALAPPDATA\Microsoft\OneDrive",
    "C:\Program Files\Microsoft OneDrive",
    "C:\Program Files (x86)\Microsoft OneDrive",
    "$env:PROGRAMFILES\Microsoft OneDrive"
)

$odExe = $null
foreach ($sp in $searchPaths) {
    if (Test-Path $sp) {
        $found = Get-ChildItem $sp -Filter "OneDrive.exe" -Recurse -ErrorAction SilentlyContinue |
                 Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($found) { $odExe = $found.FullName; break }
    }
}

# Fallback: search whole C drive
if (-not $odExe) {
    Write-Host "  Searching full C drive (may take 30 sec)..." -ForegroundColor Gray
    $odExe = (Get-ChildItem "C:\" -Filter "OneDrive.exe" -Recurse -ErrorAction SilentlyContinue |
              Where-Object { $_.FullName -notmatch "WinSxS|Windows\\Temp" } |
              Sort-Object LastWriteTime -Descending | Select-Object -First 1)?.FullName
}

if ($odExe) {
    Write-Host "  ✅ Found: $odExe" -ForegroundColor Green
} else {
    Write-Host "  ❌ OneDrive.exe not found — reinstall from microsoft.com/onedrive" -ForegroundColor Red
    exit
}

# ── STEP 2: STOP ONEDRIVE ─────────────────────────────────────────────────
Write-Host ""
Write-Host "[2/7] Stopping OneDrive processes..." -ForegroundColor Yellow
$processes = @("OneDrive","OneDriveStandaloneUpdater")
foreach ($p in $processes) {
    $proc = Get-Process -Name $p -ErrorAction SilentlyContinue
    if ($proc) {
        Stop-Process -Name $p -Force
        Write-Host "  ✅ Stopped: $p (PID $($proc.Id))" -ForegroundColor Green
    } else {
        Write-Host "  ⚪ Not running: $p" -ForegroundColor DarkGray
    }
}
Start-Sleep -Seconds 3

# ── STEP 3: CLEAR ONEDRIVE CACHE ─────────────────────────────────────────
Write-Host ""
Write-Host "[3/7] Clearing OneDrive cache and logs..." -ForegroundColor Yellow
$cachePaths = @(
    "$env:LOCALAPPDATA\Microsoft\OneDrive\logs",
    "$env:LOCALAPPDATA\Microsoft\OneDrive\setup\logs",
    "$env:LOCALAPPDATA\Microsoft\OneDrive\cache"
)
foreach ($cp in $cachePaths) {
    if (Test-Path $cp) {
        Remove-Item "$cp\*" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "  ✅ Cleared: $cp" -ForegroundColor Green
    }
}

# ── STEP 4: RESET ONEDRIVE ────────────────────────────────────────────────
Write-Host ""
Write-Host "[4/7] Executing OneDrive reset..." -ForegroundColor Yellow
Write-Host "  Command: $odExe /reset" -ForegroundColor Gray
Start-Process -FilePath $odExe -ArgumentList "/reset" -NoNewWindow
Write-Host "  ✅ Reset command sent" -ForegroundColor Green
Write-Host "  Waiting 10 seconds for reset to initialize..." -ForegroundColor Gray
Start-Sleep -Seconds 10

# ── STEP 5: RESTART ONEDRIVE ──────────────────────────────────────────────
Write-Host ""
Write-Host "[5/7] Restarting OneDrive..." -ForegroundColor Yellow
Start-Process -FilePath $odExe -NoNewWindow
Start-Sleep -Seconds 5
$running = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
if ($running) {
    Write-Host "  ✅ OneDrive restarted (PID $($running.Id))" -ForegroundColor Green
} else {
    Write-Host "  ⚠️  OneDrive not yet running — it may start in background" -ForegroundColor Yellow
}

# ── STEP 6: DISABLE KNOWN FOLDER MOVE (KFM) ──────────────────────────────
Write-Host ""
Write-Host "[6/7] Disabling Known Folder Move (KFM)..." -ForegroundColor Yellow
Write-Host "  This stops Desktop/Documents/Pictures from syncing to OneDrive" -ForegroundColor Gray
Write-Host ""

# Registry keys that control KFM
$kfmKeys = @{
    "HKCU:\Software\Microsoft\OneDrive\Accounts\Personal" = @{
        "KfmFoldersProtectedNow" = 0
        "KfmSilentOptIn"         = ""
    }
    "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive" = @{
        "KFMBlockOptIn"          = 1
        "KFMBlockOptOut"         = 0
    }
}

foreach ($regPath in $kfmKeys.Keys) {
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    foreach ($name in $kfmKeys[$regPath].Keys) {
        $val = $kfmKeys[$regPath][$name]
        try {
            if ($val -is [int]) {
                Set-ItemProperty -Path $regPath -Name $name -Value $val -Type DWord -Force
            } else {
                Remove-ItemProperty -Path $regPath -Name $name -ErrorAction SilentlyContinue
            }
            Write-Host "  ✅ Set $name = $val" -ForegroundColor Green
        } catch {
            Write-Host "  ⚠️  Could not set $name (may need Admin)" -ForegroundColor Yellow
        }
    }
}

# ── STEP 7: RESTORE LOCAL FOLDER PATHS ───────────────────────────────────
Write-Host ""
Write-Host "[7/7] Restoring Desktop/Documents/Pictures to local paths..." -ForegroundColor Yellow
Write-Host ""

# Define the local paths we want
$localPaths = @{
    "Desktop"   = "C:\Users\shiatoali\Desktop"
    "Documents" = "C:\Users\shiatoali\Documents"
    "Pictures"  = "C:\Users\shiatoali\Pictures"
}

# Shell folder GUIDs
$shellFolders = @{
    "Desktop"   = "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}"
    "Documents" = "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}"
    "Pictures"  = "{33E28130-4E1E-4676-835A-98395C3BC3BB}"
}

foreach ($folder in $localPaths.Keys) {
    $localPath = $localPaths[$folder]
    
    # Create local folder if it doesn't exist
    if (-not (Test-Path $localPath)) {
        New-Item -ItemType Directory -Path $localPath -Force | Out-Null
        Write-Host "  Created: $localPath" -ForegroundColor DarkGray
    }
    
    # Get current path
    $currentPath = [System.Environment]::GetFolderPath($folder)
    Write-Host "  $folder" -ForegroundColor White
    Write-Host "    Current: $currentPath" -ForegroundColor $(if($currentPath -like "*OneDrive*"){"Yellow"}else{"Green"})
    Write-Host "    Target:  $localPath" -ForegroundColor Cyan
    
    if ($currentPath -like "*OneDrive*") {
        # Move files from OneDrive folder to local folder
        Write-Host "    Moving files from OneDrive to local..." -ForegroundColor Gray
        $files = Get-ChildItem $currentPath -Force -ErrorAction SilentlyContinue
        $moved = 0
        foreach ($f in $files) {
            $dest = Join-Path $localPath $f.Name
            if (-not (Test-Path $dest)) {
                try {
                    Copy-Item $f.FullName $dest -Recurse -Force
                    $moved++
                } catch {}
            }
        }
        Write-Host "    Copied $moved items to local folder" -ForegroundColor Green
        
        # Update registry to point to local path
        $regPaths = @(
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
        )
        
        $regNames = @{
            "Desktop"   = @("Desktop", "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}")
            "Documents" = @("Personal", "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}")
            "Pictures"  = @("My Pictures", "{33E28130-4E1E-4676-835A-98395C3BC3BB}")
        }
        
        foreach ($rp in $regPaths) {
            foreach ($rn in $regNames[$folder]) {
                try {
                    Set-ItemProperty -Path $rp -Name $rn -Value $localPath -Force
                    Write-Host "    ✅ Registry updated: $rn → $localPath" -ForegroundColor Green
                } catch {
                    Write-Host "    ⚠️  Could not update $rn (needs Admin)" -ForegroundColor Yellow
                }
            }
        }
    } else {
        Write-Host "    ✅ Already local — no change needed" -ForegroundColor Green
    }
    Write-Host ""
}

# ── VERIFY ────────────────────────────────────────────────────────────────
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  VERIFICATION" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""

# Check OneDrive running
$odRunning = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
Write-Host "  OneDrive running:  $(if($odRunning){'✅ Yes (PID '+$odRunning.Id+')'}else{'⚠️  Not yet started'})" -ForegroundColor $(if($odRunning){"Green"}else{"Yellow"})

# Check folder paths
$checkFolders = @{
    "Desktop"   = [System.Environment]::GetFolderPath("Desktop")
    "Documents" = [System.Environment]::GetFolderPath("MyDocuments")
    "Pictures"  = [System.Environment]::GetFolderPath("MyPictures")
}
foreach ($cf in $checkFolders.GetEnumerator()) {
    $inOD = $cf.Value -like "*OneDrive*"
    Write-Host "  $($cf.Key.PadRight(12)) $(if($inOD){'⚠️  Still in OneDrive: '}else{'✅ Local: '})$($cf.Value)" -ForegroundColor $(if($inOD){"Yellow"}else{"Green"})
}

Write-Host ""
Write-Host "  IMPORTANT — Do these after this script:" -ForegroundColor Cyan
Write-Host ""
Write-Host "  1. SIGN OUT AND BACK INTO ONEDRIVE:" -ForegroundColor White
Write-Host "     Right-click OneDrive tray icon → Settings → Account" -ForegroundColor Gray
Write-Host "     → Unlink this PC → Sign in again" -ForegroundColor Gray
Write-Host "     This is the most reliable way to clear all X icons" -ForegroundColor Gray
Write-Host ""
Write-Host "  2. TURN OFF FOLDER BACKUP IN ONEDRIVE:" -ForegroundColor White
Write-Host "     OneDrive tray → Settings → Sync and backup" -ForegroundColor Gray
Write-Host "     → Manage backup → turn OFF Desktop, Documents, Pictures" -ForegroundColor Gray
Write-Host ""
Write-Host "  3. RESTART YOUR PC:" -ForegroundColor White
Write-Host "     Registry changes take full effect after restart" -ForegroundColor Gray
Write-Host ""
Write-Host "  4. AFTER RESTART — verify folders are local:" -ForegroundColor White
Write-Host "     [System.Environment]::GetFolderPath('Desktop')" -ForegroundColor Gray
Write-Host "     Should show: C:\Users\shiatoali\Desktop (not OneDrive)" -ForegroundColor Gray
Write-Host ""
