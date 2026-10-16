# ============================================================
# SHADOW313 — Full System Scan (A to Z)
# Scans EVERY drive, EVERY folder, EVERY file on this laptop
# No location left unscanned
# Usage: .\shadow313-full-system-scan.ps1
# Runtime: 5-15 minutes depending on drive size
# ============================================================

$ErrorActionPreference = "SilentlyContinue"
$timestamp  = Get-Date -Format "yyyy-MM-dd_HH-mm"
$desktop    = "$env:USERPROFILE\Desktop"
$reportPath = "$desktop\FULL-SCAN-$timestamp.txt"
$csvPath    = "$desktop\FULL-SCAN-$timestamp.csv"
$mapPath    = "$desktop\FOLDER-MAP-$timestamp.txt"

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  SHADOW313 — Full System Scan (A to Z)" -ForegroundColor Cyan
Write-Host "  Scanning EVERY location on this laptop" -ForegroundColor Cyan
Write-Host "  Results saved to Desktop when complete" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Started: $(Get-Date)" -ForegroundColor Gray
Write-Host "  This will take 5-15 minutes. Do not close this window." -ForegroundColor Yellow
Write-Host ""

# ── GET ALL DRIVES ────────────────────────────────────────────────────────
$drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -and (Test-Path $_.Root) }
Write-Host "  Drives found:" -ForegroundColor Cyan
foreach ($d in $drives) {
    $free = [math]::Round($d.Free/1GB, 1)
    $used = [math]::Round($d.Used/1GB, 1)
    Write-Host "    $($d.Root)  Used: $($used)GB  Free: $($free)GB" -ForegroundColor White
}
Write-Host ""

# ── SHADOW313 KEYWORDS ────────────────────────────────────────────────────
$s313Keywords = @(
    "shadow313","Shadow313","SHADOW313","nexus","NEXUS","s313","S313",
    "aegis","vsat","ghost.watch","ghostwatch","ghost_watch",
    "313-bind","nvsm","temporal","pqc","quantum","ollama",
    "matarmohamad","baalbek","piyyy314","mohamad"
)

# ── TRACK EVERYTHING ──────────────────────────────────────────────────────
$allFiles        = [System.Collections.Generic.List[PSCustomObject]]::new()
$s313Files       = [System.Collections.Generic.List[PSCustomObject]]::new()
$saveLocations   = [System.Collections.Generic.List[PSCustomObject]]::new()
$largeFiles      = [System.Collections.Generic.List[PSCustomObject]]::new()
$duplicateNames  = @{}
$folderSizes     = [System.Collections.Generic.List[PSCustomObject]]::new()
$appSavePaths    = [System.Collections.Generic.List[PSCustomObject]]::new()

$totalScanned = 0
$totalErrors  = 0
$startTime    = Get-Date

# ── KNOWN APP SAVE LOCATIONS TO CHECK ─────────────────────────────────────
$knownAppPaths = @{
    "Copilot/Edge Downloads"    = @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\OneDrive\Pictures\Microsoft Copilot Chat Files", "$env:USERPROFILE\Pictures\Microsoft Copilot Chat Files")
    "OneDrive Personal"         = @("$env:USERPROFILE\OneDrive", "C:\OneDrive")
    "OneDrive Business"         = @("$env:USERPROFILE\OneDrive - *")
    "ShareX Screenshots"        = @("$env:USERPROFILE\Documents\ShareX", "$env:USERPROFILE\Pictures\ShareX", "C:\Shadow313-Screenshots")
    "VS Code Workspace"         = @("$env:APPDATA\Code\User", "$env:USERPROFILE\.vscode")
    "GitHub Desktop"            = @("$env:USERPROFILE\Documents\GitHub", "$env:USERPROFILE\source\repos", "$env:USERPROFILE\GitHub")
    "Git Repos"                 = @("$env:USERPROFILE\shadow313-nexus", "$env:USERPROFILE\shadow313", "C:\shadow313-nexus")
    "Docker"                    = @("$env:APPDATA\Docker", "$env:USERPROFILE\.docker", "C:\ProgramData\Docker")
    "Ollama Models"             = @("$env:USERPROFILE\.ollama", "C:\Users\shiatoali\.ollama")
    "WSL Ubuntu Files"          = @("\\wsl$\Ubuntu-24.04\home\shiatoali", "\\wsl$\Ubuntu-24.04\mnt\c\Users\shiatoali")
    "WSL Kali Files"            = @("\\wsl$\kali-linux\home\shia313")
    "Temp/Cache"                = @("$env:TEMP", "$env:LOCALAPPDATA\Temp", "C:\Windows\Temp")
    "AppData Roaming"           = @("$env:APPDATA")
    "AppData Local"             = @("$env:LOCALAPPDATA")
    "Desktop"                   = @("$env:USERPROFILE\Desktop", "$env:PUBLIC\Desktop")
    "Documents"                 = @("$env:USERPROFILE\Documents")
    "Pictures"                  = @("$env:USERPROFILE\Pictures")
    "Recycle Bin"               = @("C:\`$Recycle.Bin")
    "Windows.old"               = @("C:\Windows.old")
    "Program Files"             = @("C:\Program Files", "C:\Program Files (x86)")
}

# ── SCAN APP SAVE PATHS ───────────────────────────────────────────────────
Write-Host "  [Phase 1] Checking known app save locations..." -ForegroundColor Yellow
foreach ($appName in $knownAppPaths.Keys) {
    foreach ($pathPattern in $knownAppPaths[$appName]) {
        # Handle wildcards
        $resolvedPaths = @()
        if ($pathPattern -match "\*") {
            $parent = Split-Path $pathPattern -Parent
            $filter = Split-Path $pathPattern -Leaf
            if (Test-Path $parent) {
                $resolvedPaths = Get-ChildItem -Path $parent -Directory -Filter $filter -Force 2>$null | Select-Object -ExpandProperty FullName
            }
        } else {
            $resolvedPaths = @($pathPattern)
        }

        foreach ($path in $resolvedPaths) {
            $exists = Test-Path $path
            $fileCount = 0
            $sizeGB = 0
            if ($exists) {
                $items = Get-ChildItem -Path $path -Recurse -File -Force 2>$null
                $fileCount = ($items | Measure-Object).Count
                $sizeGB = [math]::Round(($items | Measure-Object -Property Length -Sum).Sum / 1GB, 2)
            }
            $appSavePaths.Add([PSCustomObject]@{
                App       = $appName
                Path      = $path
                Exists    = $exists
                FileCount = $fileCount
                SizeGB    = $sizeGB
            })
            if ($exists) {
                Write-Host "    ✅ $appName`: $path ($fileCount files, $sizeGB GB)" -ForegroundColor $(if($fileCount -gt 0){"Green"}else{"DarkGray"})
            }
        }
    }
}

# ── FULL DRIVE SCAN ───────────────────────────────────────────────────────
Write-Host ""
Write-Host "  [Phase 2] Full drive scan (every file on every drive)..." -ForegroundColor Yellow
Write-Host "  Progress updates every 1000 files..." -ForegroundColor Gray
Write-Host ""

foreach ($drive in $drives) {
    $drivePath = $drive.Root
    Write-Host "  Scanning drive: $drivePath" -ForegroundColor Cyan

    try {
        Get-ChildItem -Path $drivePath -Recurse -File -Force 2>$null | ForEach-Object {
            $totalScanned++
            if ($totalScanned % 1000 -eq 0) {
                $elapsed = [math]::Round(([DateTime]::Now - $startTime).TotalSeconds)
                Write-Host "    $totalScanned files scanned... ($elapsed sec elapsed)" -ForegroundColor DarkGray
            }

            $f = $_
            $isShadow313 = $false

            # Check if Shadow313-related
            foreach ($kw in $s313Keywords) {
                if ($f.Name -match $kw -or $f.DirectoryName -match $kw) {
                    $isShadow313 = $true
                    break
                }
            }

            # Track large files (>50MB)
            if ($f.Length -gt 50MB) {
                $largeFiles.Add([PSCustomObject]@{
                    Name     = $f.Name
                    SizeMB   = [math]::Round($f.Length/1MB, 1)
                    Path     = $f.FullName
                    Modified = $f.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
                })
            }

            # Track duplicate names
            if (-not $duplicateNames.ContainsKey($f.Name)) {
                $duplicateNames[$f.Name] = [System.Collections.Generic.List[string]]::new()
            }
            $duplicateNames[$f.Name].Add($f.FullName)

            # Add to Shadow313 list
            if ($isShadow313) {
                $s313Files.Add([PSCustomObject]@{
                    Name      = $f.Name
                    Extension = $f.Extension
                    SizeKB    = [math]::Round($f.Length/1KB, 1)
                    SizeMB    = [math]::Round($f.Length/1MB, 2)
                    FullPath  = $f.FullName
                    Directory = $f.DirectoryName
                    Modified  = $f.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
                    Drive     = $drivePath
                })
            }
        }
    } catch {
        $totalErrors++
    }
}

# ── FOLDER SIZE MAP ───────────────────────────────────────────────────────
Write-Host ""
Write-Host "  [Phase 3] Building folder size map..." -ForegroundColor Yellow

$topFolders = @(
    $env:USERPROFILE,
    "C:\OneDrive",
    "$env:USERPROFILE\OneDrive",
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\Pictures",
    "$env:APPDATA",
    "$env:LOCALAPPDATA",
    "$env:USERPROFILE\.ollama",
    "$env:USERPROFILE\shadow313-nexus",
    "$env:USERPROFILE\shadow313"
)

foreach ($folder in $topFolders) {
    if (-not (Test-Path $folder)) { continue }
    $items = Get-ChildItem -Path $folder -Recurse -File -Force 2>$null
    $count = ($items | Measure-Object).Count
    $sizeGB = [math]::Round(($items | Measure-Object -Property Length -Sum).Sum / 1GB, 3)
    $sizeMB = [math]::Round($sizeGB * 1024, 1)
    $folderSizes.Add([PSCustomObject]@{
        Folder  = $folder
        Files   = $count
        SizeMB  = $sizeMB
        SizeGB  = $sizeGB
    })
    Write-Host "    $($folder.Replace($env:USERPROFILE,'~').PadRight(45)) $count files  $sizeGB GB" -ForegroundColor White
}

# ── DUPLICATE NAME ANALYSIS ───────────────────────────────────────────────
Write-Host ""
Write-Host "  [Phase 4] Analyzing duplicates..." -ForegroundColor Yellow
$dupNames = $duplicateNames.GetEnumerator() |
    Where-Object { $_.Value.Count -gt 1 } |
    Sort-Object { $_.Value.Count } -Descending |
    Select-Object -First 50

Write-Host "    Top duplicate filenames found: $($dupNames.Count)" -ForegroundColor Yellow

# ── BUILD REPORT ──────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  [Phase 5] Writing reports..." -ForegroundColor Yellow

$elapsed = [math]::Round(([DateTime]::Now - $startTime).TotalMinutes, 1)
$sb = [System.Text.StringBuilder]::new()
function Add($l) { $sb.AppendLine($l) | Out-Null }

Add "============================================================"
Add "  SHADOW313 — Full System Scan Report"
Add "  Generated: $(Get-Date)"
Add "  Computer: $env:COMPUTERNAME | User: $env:USERNAME"
Add "  Scan duration: $elapsed minutes"
Add "============================================================"
Add ""
Add "SUMMARY"
Add "-------"
Add "  Total files scanned:        $totalScanned"
Add "  Shadow313-related files:    $($s313Files.Count)"
Add "  Large files (>50MB):        $($largeFiles.Count)"
Add "  Unique filenames with dups: $($dupNames.Count)"
Add "  Scan errors (access denied):$totalErrors"
Add ""

# APP SAVE LOCATIONS
Add "============================================================"
Add "  WHERE APPS ARE SAVING FILES ON YOUR LAPTOP"
Add "============================================================"
Add ""
foreach ($app in ($appSavePaths | Sort-Object App, Path)) {
    $status = if ($app.Exists) { "EXISTS" } else { "NOT FOUND" }
    $info   = if ($app.Exists) { "$($app.FileCount) files, $($app.SizeGB) GB" } else { "—" }
    Add "  [$status] $($app.App)"
    Add "    Path:  $($app.Path)"
    Add "    Size:  $info"
    Add ""
}

# COPILOT SAVE LOCATION
Add "============================================================"
Add "  COPILOT / EDGE DOWNLOAD LOCATIONS"
Add "============================================================"
Add ""
$copilotPaths = $appSavePaths | Where-Object { $_.App -match "Copilot|Edge" }
foreach ($cp in $copilotPaths) {
    if ($cp.Exists -and $cp.FileCount -gt 0) {
        Add "  ⚠️  ACTIVE SAVE LOCATION: $($cp.Path)"
        Add "     Files: $($cp.FileCount) | Size: $($cp.SizeGB) GB"
        Add "     ACTION: Move these files to shadow313-nexus\docs-archive\"
    }
}
Add ""
Add "  TO CHANGE COPILOT SAVE LOCATION:"
Add "  Edge → Settings → Downloads → Location → change to:"
Add "  C:\Users\shiatoali\shadow313-nexus\docs-archive"
Add ""

# FOLDER SIZE MAP
Add "============================================================"
Add "  FOLDER SIZE MAP (where your disk space is going)"
Add "============================================================"
Add ""
foreach ($f in ($folderSizes | Sort-Object SizeGB -Descending)) {
    Add "  $($f.SizeGB.ToString('0.000').PadLeft(7)) GB  $($f.Files.ToString().PadLeft(6)) files  $($f.Folder)"
}
Add ""

# SHADOW313 FILES BY LOCATION
Add "============================================================"
Add "  ALL SHADOW313 FILES — COMPLETE LIST ($($s313Files.Count) files)"
Add "============================================================"
Add ""
$byDir = $s313Files | Group-Object Directory | Sort-Object { $_.Group.Count } -Descending
foreach ($grp in $byDir) {
    Add "  📁 $($grp.Name) ($($grp.Count) files)"
    foreach ($f in ($grp.Group | Sort-Object Name)) {
        Add "     $($f.Modified)  $($f.SizeKB.ToString().PadLeft(8)) KB  $($f.Name)"
    }
    Add ""
}

# LARGE FILES
Add "============================================================"
Add "  LARGE FILES >50MB ($($largeFiles.Count) files)"
Add "============================================================"
Add ""
foreach ($f in ($largeFiles | Sort-Object SizeMB -Descending | Select-Object -First 50)) {
    Add "  $($f.SizeMB.ToString('0.0').PadLeft(8)) MB  $($f.Modified)  $($f.Path)"
}
Add ""

# TOP DUPLICATE FILENAMES
Add "============================================================"
Add "  TOP DUPLICATE FILENAMES (same name, multiple locations)"
Add "============================================================"
Add ""
foreach ($dup in ($dupNames | Select-Object -First 30)) {
    Add "  '$($dup.Key)' — $($dup.Value.Count) copies:"
    foreach ($path in $dup.Value) { Add "    $path" }
    Add ""
}

# SHADOW313 FILES BY TYPE
Add "============================================================"
Add "  SHADOW313 FILES BY TYPE"
Add "============================================================"
Add ""
$byExt = $s313Files | Group-Object Extension | Sort-Object Count -Descending
foreach ($grp in $byExt) {
    $ext = if ($grp.Name) { $grp.Name } else { "(no extension)" }
    $totalKB = [math]::Round(($grp.Group | Measure-Object SizeKB -Sum).Sum / 1024, 1)
    Add "  $($ext.PadRight(12)) $($grp.Count.ToString().PadLeft(5)) files  $totalKB MB"
}
Add ""

# RECOMMENDED ACTIONS
Add "============================================================"
Add "  RECOMMENDED ACTIONS (in order)"
Add "============================================================"
Add ""
Add "  1. CONSOLIDATE: Run shadow313-consolidator.ps1 -Mode Copy"
Add "     Moves all Shadow313 files to shadow313-nexus\ (single source)"
Add ""
Add "  2. FIX COPILOT SAVE: Edge → Settings → Downloads"
Add "     Change to: C:\Users\shiatoali\shadow313-nexus\docs-archive"
Add ""
Add "  3. FIX ONEDRIVE (Admin PowerShell):"
Add "     Stop-Process -Name OneDrive -Force"
Add "     & `"$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe`" /reset"
Add ""
Add "  4. FIX SHAREX: App Settings → Paths → C:\Shadow313-Screenshots"
Add ""
Add "  5. FIX GIT + PUSH:"
Add "     cd C:\Users\shiatoali\shadow313-nexus"
Add "     git config user.name 'piyyy314'"
Add "     git config user.email 'matarmohamad313@duck.com'"
Add "     git add . && git commit -m 'Full consolidation' && git push"
Add ""
Add "  6. SETUP VSCODE (paste in PowerShell):"
Add "     code --install-extension ms-python.python"
Add "     code --install-extension ms-vscode-remote.remote-wsl"
Add "     code --install-extension ms-azuretools.vscode-docker"
Add "     code --install-extension eamodio.gitlens"
Add "     code C:\Users\shiatoali\shadow313-nexus"
Add ""

# WRITE FILES
$sb.ToString() | Out-File -FilePath $reportPath -Encoding UTF8
$s313Files | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

# FOLDER MAP (separate clean file)
$mapSb = [System.Text.StringBuilder]::new()
$mapSb.AppendLine("SHADOW313 — Complete Folder Map") | Out-Null
$mapSb.AppendLine("Generated: $(Get-Date)") | Out-Null
$mapSb.AppendLine("") | Out-Null
foreach ($app in ($appSavePaths | Where-Object { $_.Exists } | Sort-Object App)) {
    $mapSb.AppendLine("[$($app.App)]") | Out-Null
    $mapSb.AppendLine("  $($app.Path)  ($($app.FileCount) files, $($app.SizeGB) GB)") | Out-Null
}
$mapSb.ToString() | Out-File -FilePath $mapPath -Encoding UTF8

# ── CONSOLE FINAL SUMMARY ─────────────────────────────────────────────────
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  FULL SCAN COMPLETE" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Total files scanned:     $totalScanned" -ForegroundColor White
Write-Host "  Shadow313 files found:   $($s313Files.Count)" -ForegroundColor Cyan
Write-Host "  Large files (>50MB):     $($largeFiles.Count)" -ForegroundColor Yellow
Write-Host "  Duplicate name groups:   $($dupNames.Count)" -ForegroundColor Yellow
Write-Host "  Scan duration:           $elapsed minutes" -ForegroundColor White
Write-Host ""
Write-Host "  3 files saved to your Desktop:" -ForegroundColor Green
Write-Host "  -> FULL-SCAN-$timestamp.txt     (complete report)" -ForegroundColor White
Write-Host "  -> FULL-SCAN-$timestamp.csv     (open in Excel)" -ForegroundColor White
Write-Host "  -> FOLDER-MAP-$timestamp.txt    (where everything lives)" -ForegroundColor White
Write-Host ""
Write-Host "  TOP SHADOW313 LOCATIONS:" -ForegroundColor Cyan
$s313Files | Group-Object Directory | Sort-Object { $_.Count } -Descending |
    Select-Object -First 8 | ForEach-Object {
    Write-Host "    $($_.Count.ToString().PadLeft(4)) files  $($_.Name)" -ForegroundColor White
}
Write-Host ""
Write-Host "  LARGE FILES (top 5):" -ForegroundColor Cyan
$largeFiles | Sort-Object SizeMB -Descending | Select-Object -First 5 | ForEach-Object {
    Write-Host "    $($_.SizeMB) MB  $($_.Name)" -ForegroundColor Yellow
}
Write-Host ""
Write-Host "  Open FULL-SCAN-$timestamp.txt on your Desktop for full details." -ForegroundColor Gray
Write-Host ""
