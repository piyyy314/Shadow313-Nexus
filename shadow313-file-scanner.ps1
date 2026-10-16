# ============================================================
# SHADOW313 NEXUS — File Scanner & Consolidation Map
# Run this in PowerShell on your laptop
# Usage: .\shadow313-file-scanner.ps1
# ============================================================

$ErrorActionPreference = "SilentlyContinue"
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
$reportPath = "$env:USERPROFILE\Desktop\shadow313-scan-$timestamp.txt"
$csvPath    = "$env:USERPROFILE\Desktop\shadow313-files-$timestamp.csv"

# ── Search locations ──────────────────────────────────────────────────────
$searchRoots = @(
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\OneDrive",
    "$env:USERPROFILE\OneDrive\Desktop",
    "$env:USERPROFILE\OneDrive\Documents",
    "$env:USERPROFILE\shadow313",
    "$env:USERPROFILE\shadow313-nexus",
    "C:\Users\shiatoali\shadow313",
    "C:\Users\shiatoali\shadow313-nexus",
    "C:\OneDrive",
    "C:\OneDrive\Desktop",
    "C:\OneDrive\Documents"
)

# ── Shadow313 file patterns ───────────────────────────────────────────────
$s313Patterns = @(
    "shadow313*", "*shadow313*", "*nexus*", "*s313*",
    "*vsat*", "*aegis*", "*ghost-watch*", "*ghost_watch*",
    "*313-bind*", "*nvsm*", "*attck*", "*pqc*",
    "*sovereign*", "*temporal*", "Modelfile",
    "pyproject.toml", "vercel.json", "docker-compose.yml",
    "*.shadow313sig", "*_shadow313*"
)

$allFiles   = [System.Collections.Generic.List[PSCustomObject]]::new()
$scanned    = 0
$skipped    = 0

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  SHADOW313 NEXUS — File Scanner v1.0" -ForegroundColor Cyan
Write-Host "  Scanning your laptop for all Shadow313 files..." -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

foreach ($root in $searchRoots) {
    if (-not (Test-Path $root)) { continue }
    Write-Host "  Scanning: $root" -ForegroundColor Gray

    foreach ($pattern in $s313Patterns) {
        try {
            $found = Get-ChildItem -Path $root -Filter $pattern -Recurse -File -Force 2>$null
            foreach ($f in $found) {
                $scanned++
                $allFiles.Add([PSCustomObject]@{
                    Name        = $f.Name
                    Extension   = $f.Extension
                    SizeKB      = [math]::Round($f.Length / 1KB, 1)
                    SizeMB      = [math]::Round($f.Length / 1MB, 2)
                    FullPath    = $f.FullName
                    Directory   = $f.DirectoryName
                    Modified    = $f.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
                    Hash        = ""
                })
            }
        } catch { $skipped++ }
    }
}

# Also scan for HTML files with shadow313-related content in key dirs
$htmlDirs = @(
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\OneDrive\Desktop",
    "C:\OneDrive\Desktop",
    "C:\OneDrive\Documents"
)
foreach ($dir in $htmlDirs) {
    if (-not (Test-Path $dir)) { continue }
    $htmlFiles = Get-ChildItem -Path $dir -Filter "*.html" -File -Force 2>$null
    foreach ($f in $htmlFiles) {
        # Check if content mentions shadow313
        $content = Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue
        if ($content -match "shadow313|Shadow313|NEXUS|nexus|s313|S313|vsat|aegis|ghost.watch") {
            $exists = $allFiles | Where-Object { $_.FullPath -eq $f.FullName }
            if (-not $exists) {
                $scanned++
                $allFiles.Add([PSCustomObject]@{
                    Name      = $f.Name
                    Extension = $f.Extension
                    SizeKB    = [math]::Round($f.Length / 1KB, 1)
                    SizeMB    = [math]::Round($f.Length / 1MB, 2)
                    FullPath  = $f.FullName
                    Directory = $f.DirectoryName
                    Modified  = $f.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
                    Hash      = ""
                })
            }
        }
    }
}

# ── Compute hashes for duplicate detection ────────────────────────────────
Write-Host ""
Write-Host "  Computing file hashes for duplicate detection..." -ForegroundColor Gray
$i = 0
foreach ($f in $allFiles) {
    $i++
    if ($i % 20 -eq 0) { Write-Host "    $i / $($allFiles.Count) hashed..." -ForegroundColor DarkGray }
    try {
        $f.Hash = (Get-FileHash $f.FullPath -Algorithm MD5 -ErrorAction SilentlyContinue).Hash
    } catch {}
}

# ── Find duplicates ───────────────────────────────────────────────────────
$byHash     = $allFiles | Where-Object { $_.Hash -ne "" } | Group-Object Hash
$duplicates = $byHash | Where-Object { $_.Count -gt 1 }
$byName     = $allFiles | Group-Object Name
$dupNames   = $byName   | Where-Object { $_.Count -gt 1 }

# ── Categorize files ──────────────────────────────────────────────────────
$htmlFiles   = $allFiles | Where-Object { $_.Extension -eq ".html" }
$pyFiles     = $allFiles | Where-Object { $_.Extension -eq ".py" }
$jsonFiles   = $allFiles | Where-Object { $_.Extension -eq ".json" }
$mdFiles     = $allFiles | Where-Object { $_.Extension -in @(".md",".txt") }
$docFiles    = $allFiles | Where-Object { $_.Extension -in @(".docx",".pdf",".pptx",".xlsx") }
$configFiles = $allFiles | Where-Object { $_.Extension -in @(".toml",".yml",".yaml",".env") }
$otherFiles  = $allFiles | Where-Object { $_.Extension -notin @(".html",".py",".json",".md",".txt",".docx",".pdf",".pptx",".xlsx",".toml",".yml",".yaml",".env") }

# ── Build report ──────────────────────────────────────────────────────────
$report = [System.Text.StringBuilder]::new()

$report.AppendLine("============================================================") | Out-Null
$report.AppendLine("  SHADOW313 NEXUS — File Scan Report") | Out-Null
$report.AppendLine("  Generated: $(Get-Date)") | Out-Null
$report.AppendLine("  Computer:  $env:COMPUTERNAME") | Out-Null
$report.AppendLine("============================================================") | Out-Null
$report.AppendLine("") | Out-Null

$report.AppendLine("SUMMARY") | Out-Null
$report.AppendLine("-------") | Out-Null
$report.AppendLine("  Total files found:      $($allFiles.Count)") | Out-Null
$report.AppendLine("  HTML dashboards:        $($htmlFiles.Count)") | Out-Null
$report.AppendLine("  Python modules:         $($pyFiles.Count)") | Out-Null
$report.AppendLine("  JSON files:             $($jsonFiles.Count)") | Out-Null
$report.AppendLine("  Markdown/Text:          $($mdFiles.Count)") | Out-Null
$report.AppendLine("  Documents (docx/pdf):   $($docFiles.Count)") | Out-Null
$report.AppendLine("  Config files:           $($configFiles.Count)") | Out-Null
$report.AppendLine("  Duplicate groups:       $($duplicates.Count)") | Out-Null
$report.AppendLine("  Same-name groups:       $($dupNames.Count)") | Out-Null
$totalMB = [math]::Round(($allFiles | Measure-Object SizeMB -Sum).Sum, 1)
$report.AppendLine("  Total size:             $totalMB MB") | Out-Null
$report.AppendLine("") | Out-Null

# ── DUPLICATES ────────────────────────────────────────────────────────────
$report.AppendLine("============================================================") | Out-Null
$report.AppendLine("  EXACT DUPLICATES (same content, different locations)") | Out-Null
$report.AppendLine("============================================================") | Out-Null
if ($duplicates.Count -eq 0) {
    $report.AppendLine("  No exact duplicates found.") | Out-Null
} else {
    foreach ($grp in $duplicates) {
        $report.AppendLine("") | Out-Null
        $report.AppendLine("  [DUPLICATE GROUP] $($grp.Count) copies — Hash: $($grp.Name.Substring(0,8))...") | Out-Null
        foreach ($f in $grp.Group) {
            $report.AppendLine("    KEEP?  $($f.FullPath)  [$($f.SizeKB) KB · $($f.Modified)]") | Out-Null
        }
        # Recommend keeping the newest
        $newest = $grp.Group | Sort-Object Modified -Descending | Select-Object -First 1
        $report.AppendLine("    → RECOMMENDED KEEP: $($newest.FullPath)") | Out-Null
    }
}
$report.AppendLine("") | Out-Null

# ── SAME NAME DIFFERENT CONTENT ───────────────────────────────────────────
$report.AppendLine("============================================================") | Out-Null
$report.AppendLine("  SAME FILENAME — DIFFERENT CONTENT (potential conflicts)") | Out-Null
$report.AppendLine("============================================================") | Out-Null
$realDupNames = $dupNames | Where-Object {
    ($_.Group | Select-Object -ExpandProperty Hash | Sort-Object -Unique).Count -gt 1
}
if ($realDupNames.Count -eq 0) {
    $report.AppendLine("  No same-name conflicts found.") | Out-Null
} else {
    foreach ($grp in $realDupNames) {
        $report.AppendLine("") | Out-Null
        $report.AppendLine("  [CONFLICT] '$($grp.Name)' — $($grp.Count) different versions") | Out-Null
        foreach ($f in ($grp.Group | Sort-Object Modified -Descending)) {
            $report.AppendLine("    $($f.Modified)  $($f.FullPath)  [$($f.SizeKB) KB]") | Out-Null
        }
        $newest = $grp.Group | Sort-Object Modified -Descending | Select-Object -First 1
        $report.AppendLine("    → NEWEST: $($newest.FullPath)") | Out-Null
    }
}
$report.AppendLine("") | Out-Null

# ── HTML FILES ────────────────────────────────────────────────────────────
$report.AppendLine("============================================================") | Out-Null
$report.AppendLine("  ALL HTML DASHBOARD FILES ($($htmlFiles.Count) total)") | Out-Null
$report.AppendLine("============================================================") | Out-Null
foreach ($f in ($htmlFiles | Sort-Object Directory, Name)) {
    $report.AppendLine("  $($f.Modified)  $($f.SizeKB) KB  $($f.FullPath)") | Out-Null
}
$report.AppendLine("") | Out-Null

# ── PYTHON FILES ──────────────────────────────────────────────────────────
$report.AppendLine("============================================================") | Out-Null
$report.AppendLine("  PYTHON MODULE FILES ($($pyFiles.Count) total)") | Out-Null
$report.AppendLine("============================================================") | Out-Null
foreach ($f in ($pyFiles | Sort-Object Directory, Name)) {
    $report.AppendLine("  $($f.Modified)  $($f.SizeKB) KB  $($f.FullPath)") | Out-Null
}
$report.AppendLine("") | Out-Null

# ── DOCUMENTS ─────────────────────────────────────────────────────────────
$report.AppendLine("============================================================") | Out-Null
$report.AppendLine("  DOCUMENTS (docx/pdf/pptx/xlsx) ($($docFiles.Count) total)") | Out-Null
$report.AppendLine("============================================================") | Out-Null
foreach ($f in ($docFiles | Sort-Object Directory, Name)) {
    $report.AppendLine("  $($f.Modified)  $($f.SizeMB) MB  $($f.FullPath)") | Out-Null
}
$report.AppendLine("") | Out-Null

# ── CONSOLIDATION PLAN ────────────────────────────────────────────────────
$report.AppendLine("============================================================") | Out-Null
$report.AppendLine("  RECOMMENDED CONSOLIDATION PLAN") | Out-Null
$report.AppendLine("============================================================") | Out-Null
$report.AppendLine("") | Out-Null
$report.AppendLine("  CANONICAL LOCATION: C:\Users\$env:USERNAME\shadow313-nexus\") | Out-Null
$report.AppendLine("  (This is your cloned GitHub repo — single source of truth)") | Out-Null
$report.AppendLine("") | Out-Null
$report.AppendLine("  FOLDER STRUCTURE:") | Out-Null
$report.AppendLine("  shadow313-nexus\") | Out-Null
$report.AppendLine("  ├── docs\           ← All HTML dashboards (90+ files)") | Out-Null
$report.AppendLine("  ├── shadow313\      ← Python source code") | Out-Null
$report.AppendLine("  ├── nexus_toolkit\  ← NEXUS Python modules") | Out-Null
$report.AppendLine("  ├── ollama\         ← Modelfile + scripts") | Out-Null
$report.AppendLine("  ├── docker\         ← Docker configs") | Out-Null
$report.AppendLine("  ├── docs-archive\   ← Move old/duplicate docs here") | Out-Null
$report.AppendLine("  └── vercel.json     ← Deployment config") | Out-Null
$report.AppendLine("") | Out-Null
$report.AppendLine("  ACTION ITEMS:") | Out-Null
$report.AppendLine("  1. Keep ONLY shadow313-nexus\ as your working copy") | Out-Null
$report.AppendLine("  2. Delete duplicate HTML files from Downloads\ and Desktop\") | Out-Null
$report.AppendLine("  3. Move any unique documents to shadow313-nexus\docs-archive\") | Out-Null
$report.AppendLine("  4. Run: git config user.name 'piyyy314'") | Out-Null
$report.AppendLine("  5. Run: git config user.email 'matarmohamad313@duck.com'") | Out-Null
$report.AppendLine("  6. Run: git add . && git commit -m 'Consolidation' && git push") | Out-Null
$report.AppendLine("") | Out-Null

# ── STRIDE DOWNLOAD FIX ───────────────────────────────────────────────────
$report.AppendLine("============================================================") | Out-Null
$report.AppendLine("  WHY HTML FILES STOPPED DOWNLOADING FROM STRIDE") | Out-Null
$report.AppendLine("============================================================") | Out-Null
$report.AppendLine("") | Out-Null
$report.AppendLine("  The Stride/Office Agent side panel shows completion message") | Out-Null
$report.AppendLine("  text — it does NOT render or download HTML attachments.") | Out-Null
$report.AppendLine("  This changed when Microsoft updated the Stride interface.") | Out-Null
$report.AppendLine("") | Out-Null
$report.AppendLine("  SOLUTION: Push files to GitHub -> they appear on shadow313.dev") | Out-Null
$report.AppendLine("  Then download from your own website, not from Stride.") | Out-Null
$report.AppendLine("") | Out-Null
$report.AppendLine("  QUICK FIX RIGHT NOW:") | Out-Null
$report.AppendLine("  cd C:\Users\shiatoali\shadow313-nexus") | Out-Null
$report.AppendLine("  git add docs\") | Out-Null
$report.AppendLine("  git commit -m 'Add all HTML dashboards'") | Out-Null
$report.AppendLine("  git push") | Out-Null
$report.AppendLine("  -> Then visit shadow313.dev to download any file") | Out-Null
$report.AppendLine("") | Out-Null

# ── Write files ───────────────────────────────────────────────────────────
$report.ToString() | Out-File -FilePath $reportPath -Encoding UTF8
$allFiles | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

# ── Console summary ───────────────────────────────────────────────────────
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  SCAN COMPLETE" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Files found:      $($allFiles.Count)" -ForegroundColor White
Write-Host "  HTML dashboards:  $($htmlFiles.Count)" -ForegroundColor Cyan
Write-Host "  Python modules:   $($pyFiles.Count)" -ForegroundColor Cyan
Write-Host "  Documents:        $($docFiles.Count)" -ForegroundColor Cyan
Write-Host "  Duplicate groups: $($duplicates.Count)" -ForegroundColor Yellow
Write-Host "  Name conflicts:   $($realDupNames.Count)" -ForegroundColor Yellow
Write-Host "  Total size:       $totalMB MB" -ForegroundColor White
Write-Host ""
Write-Host "  Reports saved to Desktop:" -ForegroundColor Green
Write-Host "  -> $reportPath" -ForegroundColor White
Write-Host "  -> $csvPath" -ForegroundColor White
Write-Host ""
Write-Host "  Open the .txt file for the full consolidation plan." -ForegroundColor Gray
Write-Host "  Open the .csv file in Excel to sort/filter all files." -ForegroundColor Gray
Write-Host ""

# ── Quick duplicate alert ─────────────────────────────────────────────────
if ($duplicates.Count -gt 0) {
    Write-Host "  ⚠️  DUPLICATES FOUND:" -ForegroundColor Yellow
    foreach ($grp in ($duplicates | Select-Object -First 5)) {
        Write-Host "     $($grp.Count)x copies of: $($grp.Group[0].Name)" -ForegroundColor Yellow
    }
    if ($duplicates.Count -gt 5) {
        Write-Host "     ... and $($duplicates.Count - 5) more duplicate groups" -ForegroundColor Yellow
    }
    Write-Host ""
}

if ($realDupNames.Count -gt 0) {
    Write-Host "  ⚠️  VERSION CONFLICTS (same name, different content):" -ForegroundColor Red
    foreach ($grp in ($realDupNames | Select-Object -First 5)) {
        Write-Host "     '$($grp.Name)' — $($grp.Count) different versions" -ForegroundColor Red
    }
    Write-Host ""
}

Write-Host "  NEXT STEPS:" -ForegroundColor Cyan
Write-Host "  1. Review Desktop\shadow313-scan-*.txt" -ForegroundColor White
Write-Host "  2. Fix git config:" -ForegroundColor White
Write-Host "     git config user.name 'piyyy314'" -ForegroundColor Gray
Write-Host "     git config user.email 'matarmohamad313@duck.com'" -ForegroundColor Gray
Write-Host "  3. Push to GitHub to make files available on shadow313.dev" -ForegroundColor White
Write-Host ""
