# ============================================================
# SHADOW313 NEXUS — File Consolidator v1.0
# Reads scanner output and moves/copies files to target structure
# Usage:
#   DRY RUN (preview only):
#     .\shadow313-consolidator.ps1 -DryRun
#   COPY mode (safe — keeps originals):
#     .\shadow313-consolidator.ps1 -Mode Copy -Target "C:\Users\shiatoali\shadow313-nexus"
#   MOVE mode (removes originals after copy):
#     .\shadow313-consolidator.ps1 -Mode Move -Target "C:\Users\shiatoali\shadow313-nexus"
# ============================================================
param(
    [switch]$DryRun,
    [ValidateSet("Copy","Move")][string]$Mode = "Copy",
    [string]$Target = "$env:USERPROFILE\shadow313-nexus",
    [string]$ScanJson = "",
    [switch]$SkipConfirm
)

$ErrorActionPreference = "SilentlyContinue"
$timestamp  = Get-Date -Format "yyyy-MM-dd_HH-mm"
$logPath    = "$env:USERPROFILE\Desktop\shadow313-consolidate-$timestamp.log"
$actionLog  = [System.Collections.Generic.List[PSCustomObject]]::new()

# ── HEADER ────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  SHADOW313 NEXUS — File Consolidator v1.0" -ForegroundColor Cyan
if ($DryRun) {
    Write-Host "  MODE: DRY RUN — No files will be changed" -ForegroundColor Yellow
} else {
    Write-Host "  MODE: $Mode — Files WILL be $($Mode.ToLower())d" -ForegroundColor $(if($Mode -eq "Move"){"Red"}else{"Green"})
}
Write-Host "  TARGET: $Target" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# ── TARGET FOLDER STRUCTURE ───────────────────────────────────────────────
$folders = @{
    "root"        = $Target
    "docs"        = "$Target\docs"
    "shadow313"   = "$Target\shadow313"
    "nexus"       = "$Target\nexus_toolkit"
    "ollama"      = "$Target\ollama"
    "docker"      = "$Target\docker"
    "scripts"     = "$Target\scripts"
    "archive"     = "$Target\docs-archive"
    "json"        = "$Target\data"
    "config"      = "$Target"
}

# ── ROUTING RULES — which files go where ─────────────────────────────────
# Each rule: pattern match → destination folder → priority (lower = checked first)
$rules = @(
    # HTML dashboards → docs/
    @{ Match={ $_.Extension -eq ".html" -and $_.Name -notmatch "index" }; Dest="docs";     Label="HTML Dashboard" },
    @{ Match={ $_.Name -eq "index.html" };                                  Dest="root";    Label="Root index.html" },

    # Python source → shadow313/ or nexus_toolkit/
    @{ Match={ $_.Extension -eq ".py" -and $_.Name -match "nexus|toolkit|bridge|pipeline" }; Dest="nexus"; Label="NEXUS Python" },
    @{ Match={ $_.Extension -eq ".py" };                                    Dest="shadow313"; Label="Python Module" },

    # Ollama files
    @{ Match={ $_.Name -match "Modelfile|modelfile|ollama|shadow313-nexus" -and $_.Extension -in @("","",".env",".sh",".py",".txt") }; Dest="ollama"; Label="Ollama Config" },

    # Docker files
    @{ Match={ $_.Name -match "docker|nginx|compose" -or $_.Extension -eq ".dockerfile" }; Dest="docker"; Label="Docker Config" },

    # Config files → root
    @{ Match={ $_.Name -in @("vercel.json","pyproject.toml","setup.py","requirements.txt",".gitignore","netlify.toml") }; Dest="config"; Label="Project Config" },

    # PowerShell scripts → scripts/
    @{ Match={ $_.Extension -eq ".ps1" };                                   Dest="scripts"; Label="PowerShell Script" },
    @{ Match={ $_.Extension -in @(".sh",".bash") };                         Dest="scripts"; Label="Shell Script" },

    # JSON data files → data/
    @{ Match={ $_.Extension -eq ".json" -and $_.Name -notmatch "vercel|package|tsconfig|eslint" }; Dest="json"; Label="JSON Data" },

    # Documents → archive/
    @{ Match={ $_.Extension -in @(".docx",".pdf",".pptx",".xlsx") };        Dest="archive"; Label="Document" },

    # Markdown → docs/ or root
    @{ Match={ $_.Extension -eq ".md" -and $_.Name -eq "README.md" };       Dest="root";    Label="README" },
    @{ Match={ $_.Extension -eq ".md" };                                     Dest="docs";    Label="Markdown Doc" },
)

# ── SCAN FOR FILES ────────────────────────────────────────────────────────
Write-Host "[1/4] Discovering Shadow313 files to consolidate..." -ForegroundColor Yellow

$searchRoots = @(
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\OneDrive",
    "$env:USERPROFILE\OneDrive\Desktop",
    "$env:USERPROFILE\OneDrive\Documents",
    "C:\OneDrive",
    "C:\OneDrive\Desktop"
)

$s313Patterns = @(
    "shadow313*","*shadow313*","*nexus*","*s313*",
    "*vsat*","*aegis*","*ghost-watch*","*ghost_watch*",
    "*313-bind*","*nvsm*","Modelfile","vercel.json",
    "pyproject.toml","docker-compose.yml","*.shadow313sig"
)

$candidates = [System.Collections.Generic.List[PSCustomObject]]::new()
$seenPaths  = [System.Collections.Generic.HashSet[string]]::new()

# Exclude the target folder itself to avoid loops
foreach ($root in $searchRoots) {
    if (-not (Test-Path $root)) { continue }
    if ($root -like "$Target*") { continue }  # skip target
    foreach ($pattern in $s313Patterns) {
        try {
            Get-ChildItem -Path $root -Filter $pattern -Recurse -File -Force 2>$null |
            Where-Object { $_.FullName -notlike "$Target*" } |
            ForEach-Object {
                if ($seenPaths.Add($_.FullName)) {
                    $candidates.Add([PSCustomObject]@{
                        Name      = $_.Name
                        Extension = $_.Extension
                        SizeKB    = [math]::Round($_.Length/1KB,1)
                        FullPath  = $_.FullName
                        Directory = $_.DirectoryName
                        Modified  = $_.LastWriteTime
                        Hash      = ""
                    })
                }
            }
        } catch {}
    }
}

Write-Host "   Found $($candidates.Count) candidate files" -ForegroundColor Green

# ── COMPUTE HASHES ────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[2/4] Computing hashes to detect duplicates..." -ForegroundColor Yellow
foreach ($f in $candidates) {
    try { $f.Hash = (Get-FileHash $f.FullPath -Algorithm MD5 -ErrorAction SilentlyContinue).Hash } catch {}
}

# Group by hash — keep only newest of each duplicate group
$byHash   = $candidates | Where-Object { $_.Hash } | Group-Object Hash
$toProcess= [System.Collections.Generic.List[PSCustomObject]]::new()
$skipped  = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($grp in $byHash) {
    if ($grp.Count -eq 1) {
        $toProcess.Add($grp.Group[0])
    } else {
        # Keep newest, skip rest
        $sorted = $grp.Group | Sort-Object Modified -Descending
        $toProcess.Add($sorted[0])
        for ($i=1; $i -lt $sorted.Count; $i++) {
            $skipped.Add($sorted[$i])
        }
    }
}
# Add files with no hash
$candidates | Where-Object { -not $_.Hash } | ForEach-Object { $toProcess.Add($_) }

Write-Host "   Processing: $($toProcess.Count) unique files" -ForegroundColor Green
Write-Host "   Skipping:   $($skipped.Count) exact duplicates (keeping newest)" -ForegroundColor Yellow

# ── BUILD ACTION PLAN ─────────────────────────────────────────────────────
Write-Host ""
Write-Host "[3/4] Building action plan..." -ForegroundColor Yellow

$plan = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($f in $toProcess) {
    # Find matching rule
    $destKey = "archive"  # default
    $label   = "Other"
    foreach ($rule in $rules) {
        if (& $rule.Match -InputObject $f) {
            $destKey = $rule.Dest
            $label   = $rule.Label
            break
        }
    }

    $destFolder = $folders[$destKey]
    $destPath   = Join-Path $destFolder $f.Name

    # Check if already exists at destination
    $exists     = Test-Path $destPath
    $conflict   = $false
    $action     = $Mode

    if ($exists) {
        $existHash = (Get-FileHash $destPath -Algorithm MD5 -ErrorAction SilentlyContinue).Hash
        if ($existHash -eq $f.Hash) {
            $action  = "SKIP_IDENTICAL"
        } else {
            $conflict = $true
            # Rename with timestamp to avoid overwrite
            $base    = [System.IO.Path]::GetFileNameWithoutExtension($f.Name)
            $ext     = $f.Extension
            $destPath= Join-Path $destFolder "$base`_$($f.Modified.ToString('yyyyMMdd-HHmm'))$ext"
            $action  = "$Mode`_RENAMED"
        }
    }

    $plan.Add([PSCustomObject]@{
        SourcePath  = $f.FullPath
        DestPath    = $destPath
        DestFolder  = $destFolder
        Name        = $f.Name
        SizeKB      = $f.SizeKB
        Modified    = $f.Modified.ToString("yyyy-MM-dd HH:mm")
        Category    = $label
        Action      = $action
        Conflict    = $conflict
    })
}

# ── PREVIEW ───────────────────────────────────────────────────────────────
$toCopy    = $plan | Where-Object { $_.Action -in @("Copy","Move","Copy_RENAMED","Move_RENAMED") }
$toSkip    = $plan | Where-Object { $_.Action -eq "SKIP_IDENTICAL" }
$conflicts = $plan | Where-Object { $_.Conflict }

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  ACTION PLAN PREVIEW" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Files to $($Mode.ToLower()):    $($toCopy.Count)" -ForegroundColor White
Write-Host "  Files to skip:      $($toSkip.Count) (identical already at destination)" -ForegroundColor Gray
Write-Host "  Conflicts renamed:  $($conflicts.Count) (different version exists)" -ForegroundColor Yellow
Write-Host "  Duplicates skipped: $($skipped.Count) (exact copies, keeping newest)" -ForegroundColor Gray
Write-Host ""

# Show by category
$byCategory = $toCopy | Group-Object Category
Write-Host "  By category:" -ForegroundColor Cyan
foreach ($cat in ($byCategory | Sort-Object Count -Descending)) {
    Write-Host "    $($cat.Name.PadRight(25)) $($cat.Count) files" -ForegroundColor White
}
Write-Host ""

# Show first 20 actions
Write-Host "  First 20 planned actions:" -ForegroundColor Cyan
$toCopy | Select-Object -First 20 | ForEach-Object {
    $arrow = if ($_.Action -like "*RENAMED*") { "→ [RENAMED]" } else { "→" }
    Write-Host "    [$($_.Category.Substring(0,[Math]::Min(12,$_.Category.Length)).PadRight(12))] $($_.Name.PadRight(40)) $arrow $($_.DestFolder | Split-Path -Leaf)" -ForegroundColor DarkGray
}
if ($toCopy.Count -gt 20) {
    Write-Host "    ... and $($toCopy.Count - 20) more" -ForegroundColor DarkGray
}
Write-Host ""

# ── DRY RUN EXIT ──────────────────────────────────────────────────────────
if ($DryRun) {
    Write-Host "============================================================" -ForegroundColor Yellow
    Write-Host "  DRY RUN COMPLETE — No files were changed" -ForegroundColor Yellow
    Write-Host "  To execute, run without -DryRun flag:" -ForegroundColor Yellow
    Write-Host "  .\shadow313-consolidator.ps1 -Mode Copy -Target '$Target'" -ForegroundColor White
    Write-Host "============================================================" -ForegroundColor Yellow

    # Still write the plan to log
    $logLines = @("SHADOW313 CONSOLIDATOR — DRY RUN PLAN","Generated: $(Get-Date)","Target: $Target","","FILES TO $($Mode.ToUpper()):")
    foreach ($p in $toCopy) { $logLines += "  [$($p.Action)] $($p.SourcePath) -> $($p.DestPath)" }
    $logLines += "","FILES TO SKIP (identical):"
    foreach ($p in $toSkip) { $logLines += "  [SKIP] $($p.SourcePath)" }
    $logLines | Out-File -FilePath $logPath -Encoding UTF8
    Write-Host ""
    Write-Host "  Dry-run plan saved to: $logPath" -ForegroundColor Gray
    Write-Host ""
    return
}

# ── CONFIRM ───────────────────────────────────────────────────────────────
if (-not $SkipConfirm) {
    Write-Host "  ⚠️  This will $($Mode.ToUpper()) $($toCopy.Count) files to: $Target" -ForegroundColor $(if($Mode -eq "Move"){"Red"}else{"Yellow"})
    $confirm = Read-Host "  Type YES to proceed, anything else to cancel"
    if ($confirm -ne "YES") {
        Write-Host "  Cancelled. No files were changed." -ForegroundColor Gray
        return
    }
}

# ── EXECUTE ───────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[4/4] Executing $Mode operations..." -ForegroundColor Yellow

# Create target folders
foreach ($folder in $folders.Values | Select-Object -Unique) {
    if (-not (Test-Path $folder)) {
        if (-not $DryRun) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
        Write-Host "   Created: $folder" -ForegroundColor DarkGray
    }
}

$done = 0; $errors = 0
foreach ($p in $toCopy) {
    try {
        # Ensure dest folder exists
        $destDir = Split-Path $p.DestPath -Parent
        if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }

        if ($Mode -eq "Copy" -or $p.Action -like "Copy*") {
            Copy-Item -Path $p.SourcePath -Destination $p.DestPath -Force
        } elseif ($Mode -eq "Move" -or $p.Action -like "Move*") {
            Move-Item -Path $p.SourcePath -Destination $p.DestPath -Force
        }

        $done++
        $actionLog.Add([PSCustomObject]@{
            Action=$p.Action; Source=$p.SourcePath; Dest=$p.DestPath
            Category=$p.Category; SizeKB=$p.SizeKB; Status="OK"
        })

        if ($done % 25 -eq 0) { Write-Host "   $done/$($toCopy.Count) files processed..." -ForegroundColor DarkGray }
    } catch {
        $errors++
        $actionLog.Add([PSCustomObject]@{
            Action="ERROR"; Source=$p.SourcePath; Dest=$p.DestPath
            Category=$p.Category; SizeKB=$p.SizeKB; Status=$_.Exception.Message
        })
        Write-Host "   ❌ Error: $($p.Name) — $_" -ForegroundColor Red
    }
}

# ── WRITE LOG ─────────────────────────────────────────────────────────────
$actionLog | Export-Csv -Path $logPath.Replace(".log",".csv") -NoTypeInformation -Encoding UTF8

$logLines = @(
    "SHADOW313 CONSOLIDATOR — EXECUTION LOG",
    "Generated: $(Get-Date)",
    "Mode: $Mode | Target: $Target",
    "Files processed: $done | Errors: $errors",
    ""
)
foreach ($a in $actionLog) { $logLines += "[$($a.Status)] [$($a.Action)] $($a.Source) -> $($a.Dest)" }
$logLines | Out-File -FilePath $logPath -Encoding UTF8

# ── FINAL SUMMARY ─────────────────────────────────────────────────────────
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  CONSOLIDATION COMPLETE" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Files $($Mode.ToLower())d:   $done" -ForegroundColor Green
Write-Host "  Errors:         $errors" -ForegroundColor $(if($errors -gt 0){"Red"}else{"Green"})
Write-Host "  Skipped:        $($toSkip.Count) (already identical at destination)" -ForegroundColor Gray
Write-Host ""
Write-Host "  Log saved to: $logPath" -ForegroundColor White
Write-Host ""
Write-Host "  NEXT STEPS:" -ForegroundColor Cyan
Write-Host "  1. Review $Target to verify structure" -ForegroundColor White
Write-Host "  2. Fix git config:" -ForegroundColor White
Write-Host "     cd $Target" -ForegroundColor Gray
Write-Host "     git config user.name 'piyyy314'" -ForegroundColor Gray
Write-Host "     git config user.email 'matarmohamad313@duck.com'" -ForegroundColor Gray
Write-Host "  3. Push to GitHub:" -ForegroundColor White
Write-Host "     git add ." -ForegroundColor Gray
Write-Host "     git commit -m 'Consolidation: all Shadow313 files'" -ForegroundColor Gray
Write-Host "     git push origin master" -ForegroundColor Gray
Write-Host "  4. Vercel auto-deploys → shadow313.dev has everything" -ForegroundColor White
Write-Host ""
