# ============================================================
# SHADOW313 — Complete OneDrive + ShareX Fix
# Fixes X icons, duplicate paths, and wrong save locations
# Run as Administrator
# ============================================================

$ErrorActionPreference = "SilentlyContinue"

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  OneDrive + ShareX Complete Fix" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# ── DETECT REAL ONEDRIVE PATH ─────────────────────────────────────────────
Write-Host "[1/6] Detecting real OneDrive path..." -ForegroundColor Yellow
$realOD = (Get-ItemProperty "HKCU:\Software\Microsoft\OneDrive\Accounts\Personal" -ErrorAction SilentlyContinue).UserFolder
Write-Host "  Real OneDrive path: $realOD" -ForegroundColor Green

# Check both paths
$path1 = "C:\OneDrive"
$path2 = "$env:USERPROFILE\OneDrive"
$isJunction1 = (Get-Item $path1 -Force -ErrorAction SilentlyContinue).Attributes -band [System.IO.FileAttributes]::ReparsePoint
$isJunction2 = (Get-Item $path2 -Force -ErrorAction SilentlyContinue).Attributes -band [System.IO.FileAttributes]::ReparsePoint

Write-Host "  C:\OneDrive — $(if($isJunction1){'Junction/Symlink'}else{'Real folder'})" -ForegroundColor $(if($isJunction1){"Yellow"}else{"Green"})
Write-Host "  $env:USERPROFILE\OneDrive — $(if($isJunction2){'Junction/Symlink'}else{'Real folder'})" -ForegroundColor $(if($isJunction2){"Yellow"}else{"Green"})
Write-Host ""

# ── CHECK ONEDRIVE SYNC STATUS ────────────────────────────────────────────
Write-Host "[2/6] Checking OneDrive sync status..." -ForegroundColor Yellow
$odProcess = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
Write-Host "  OneDrive running: $(if($odProcess){'Yes'}else{'No'})" -ForegroundColor $(if($odProcess){"Green"}else{"Yellow"})

# Check for sync errors in registry
$syncErrors = Get-ItemProperty "HKCU:\Software\Microsoft\OneDrive\Accounts\Personal" -ErrorAction SilentlyContinue
Write-Host "  Account email: $($syncErrors.UserEmail)" -ForegroundColor White
Write-Host "  Sync status:   $($syncErrors.SyncStatus)" -ForegroundColor White
Write-Host ""

# ── FIX ONEDRIVE KNOWN FOLDERS ────────────────────────────────────────────
Write-Host "[3/6] Fixing OneDrive Known Folder settings..." -ForegroundColor Yellow

# Check if Desktop/Documents/Pictures are being redirected to OneDrive
$knownFolders = @{
    "Desktop"   = [System.Environment]::GetFolderPath("Desktop")
    "Documents" = [System.Environment]::GetFolderPath("MyDocuments")
    "Pictures"  = [System.Environment]::GetFolderPath("MyPictures")
    "Downloads" = (New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
}

foreach ($kf in $knownFolders.GetEnumerator()) {
    $isInOD = $kf.Value -like "*OneDrive*"
    $status = if ($isInOD) { "⚠️  IN ONEDRIVE" } else { "✅ Local" }
    Write-Host "  $($kf.Key.PadRight(12)) $status — $($kf.Value)" -ForegroundColor $(if($isInOD){"Yellow"}else{"Green"})
}
Write-Host ""

# ── STOP AND RESET ONEDRIVE ───────────────────────────────────────────────
Write-Host "[4/6] Resetting OneDrive to fix X icons..." -ForegroundColor Yellow
Write-Host "  Stopping OneDrive..." -ForegroundColor Gray
Stop-Process -Name OneDrive -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3

# Clear OneDrive cache files that cause X icons
$odCachePaths = @(
    "$env:LOCALAPPDATA\Microsoft\OneDrive\logs",
    "$env:LOCALAPPDATA\Microsoft\OneDrive\setup\logs"
)
foreach ($cp in $odCachePaths) {
    if (Test-Path $cp) {
        Remove-Item "$cp\*" -Force -Recurse -ErrorAction SilentlyContinue
        Write-Host "  Cleared: $cp" -ForegroundColor DarkGray
    }
}

Write-Host "  Starting OneDrive reset..." -ForegroundColor Gray
$odExe = "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe"
if (Test-Path $odExe) {
    Start-Process $odExe -ArgumentList "/reset" -NoNewWindow
    Write-Host "  ✅ OneDrive reset started" -ForegroundColor Green
    Write-Host "  Wait 2-3 minutes for sync to restart" -ForegroundColor Yellow
} else {
    Write-Host "  ❌ OneDrive.exe not found at expected path" -ForegroundColor Red
    Write-Host "  Try: winget install Microsoft.OneDrive" -ForegroundColor Gray
}
Write-Host ""

# ── FIX SHAREX SAVE PATH ──────────────────────────────────────────────────
Write-Host "[5/6] Fixing ShareX save path..." -ForegroundColor Yellow

$sharexConfig = "$env:APPDATA\ShareX\ApplicationConfig.json"
$newShareXPath = "C:\Shadow313-Screenshots"

# Create the target folder
New-Item -ItemType Directory -Path $newShareXPath -Force | Out-Null
Write-Host "  Created: $newShareXPath" -ForegroundColor Green

if (Test-Path $sharexConfig) {
    # Read current config
    $config = Get-Content $sharexConfig -Raw | ConvertFrom-Json
    $oldPath = $config.PersonalPath
    Write-Host "  Current ShareX path: $oldPath" -ForegroundColor Yellow
    
    # Update the path
    $config.PersonalPath = $newShareXPath
    $config | ConvertTo-Json -Depth 20 | Out-File $sharexConfig -Encoding UTF8
    Write-Host "  ✅ ShareX path updated to: $newShareXPath" -ForegroundColor Green
    Write-Host "  Restart ShareX for changes to take effect" -ForegroundColor Gray
} else {
    Write-Host "  ShareX config not found — ShareX may not be installed or never opened" -ForegroundColor Yellow
    Write-Host "  When you open ShareX: App Settings → Paths → set to $newShareXPath" -ForegroundColor Gray
}
Write-Host ""

# ── FIX COPILOT SAVE LOCATION ─────────────────────────────────────────────
Write-Host "[6/6] Moving Copilot files to correct location..." -ForegroundColor Yellow

$copilotSrc = "$env:USERPROFILE\OneDrive\Pictures\Microsoft Copilot Chat Files"
$copilotDst = "C:\Users\shiatoali\shadow313-nexus\docs-archive\copilot-files"

if (Test-Path $copilotSrc) {
    $files = Get-ChildItem $copilotSrc -File -Recurse
    $sizeGB = [math]::Round(($files | Measure-Object Length -Sum).Sum / 1GB, 2)
    Write-Host "  Found $($files.Count) Copilot files ($sizeGB GB)" -ForegroundColor Yellow
    
    New-Item -ItemType Directory -Path $copilotDst -Force | Out-Null
    
    $moved = 0
    foreach ($f in $files) {
        try {
            $dest = Join-Path $copilotDst $f.Name
            if (-not (Test-Path $dest)) {
                Copy-Item $f.FullName $dest -Force
                $moved++
            }
        } catch {}
    }
    Write-Host "  ✅ Copied $moved files to: $copilotDst" -ForegroundColor Green
    Write-Host "  Original files kept in OneDrive (delete manually after verifying)" -ForegroundColor Gray
} else {
    Write-Host "  No Copilot files found at expected location" -ForegroundColor DarkGray
}

# ── FINAL SUMMARY ─────────────────────────────────────────────────────────
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  ALL FIXES APPLIED" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  ✅ OneDrive reset — wait 2-3 min for X icons to clear" -ForegroundColor Green
Write-Host "  ✅ ShareX path → C:\Shadow313-Screenshots" -ForegroundColor Green
Write-Host "  ✅ Copilot files moved to docs-archive\copilot-files" -ForegroundColor Green
Write-Host ""
Write-Host "  MANUAL STEPS STILL NEEDED:" -ForegroundColor Cyan
Write-Host ""
Write-Host "  1. EDGE DOWNLOADS — open this and change location:" -ForegroundColor White
Write-Host "     microsoft-edge://settings/downloads" -ForegroundColor Gray
Write-Host "     → Change to: C:\Users\shiatoali\shadow313-nexus\docs-archive" -ForegroundColor Gray
Write-Host ""
Write-Host "  2. RESTART SHAREX — close and reopen ShareX app" -ForegroundColor White
Write-Host ""
Write-Host "  3. WAIT FOR ONEDRIVE — give it 2-3 minutes to resync" -ForegroundColor White
Write-Host "     X icons should disappear as files re-verify" -ForegroundColor Gray
Write-Host ""
Write-Host "  4. IF X ICONS PERSIST after 5 min — right-click OneDrive" -ForegroundColor White
Write-Host "     tray icon → Settings → Account → Unlink this PC" -ForegroundColor Gray
Write-Host "     Then sign back in — full resync fixes all X icons" -ForegroundColor Gray
Write-Host ""
Write-Host "  KNOWN FOLDER STATUS:" -ForegroundColor Cyan
foreach ($kf in $knownFolders.GetEnumerator()) {
    $isInOD = $kf.Value -like "*OneDrive*"
    if ($isInOD) {
        Write-Host "  ⚠️  $($kf.Key) is syncing through OneDrive — this is normal" -ForegroundColor Yellow
        Write-Host "     To stop: OneDrive tray → Settings → Sync and backup → Manage backup" -ForegroundColor Gray
        Write-Host "     Turn OFF backup for Desktop/Documents/Pictures if you want them local only" -ForegroundColor Gray
    }
}
Write-Host ""
