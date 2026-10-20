# ============================================================
# SHADOW313 NEXUS — Version Conflict Resolver v1.0
# Compares conflicting file versions, picks the best one,
# archives the rest safely. Also fixes OneDrive/ShareX issues.
# Usage: .\shadow313-version-resolver.ps1
# ============================================================
param(
    [string]$Target    = "$env:USERPROFILE\shadow313-nexus",
    [string]$Archive   = "$env:USERPROFILE\shadow313-nexus\docs-archive\_old-versions",
    [switch]$DryRun,
    [switch]$SkipConfirm
)

$ErrorActionPreference = "SilentlyContinue"
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
$reportPath = "$env:USERPROFILE\Desktop\shadow313-resolver-$timestamp.txt"

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  SHADOW313 — Version Conflict Resolver v1.0" -ForegroundColor Cyan
if ($DryRun) { Write-Host "  MODE: DRY RUN — Nothing will change" -ForegroundColor Yellow }
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# ── PRIORITY CONFLICT FILES ───────────────────────────────────────────────
# These are the known conflicts from your scan
$conflictFiles = @(
    "aegis_nexus.html",
    "aegis_app.py",
    "docker-compose.yml",
    "Copy of Ghost-Watch Master Briefing and Wipe.docx",
    "crystals_pqc_sbom.json"
)

# ── SEARCH ROOTS ──────────────────────────────────────────────────────────
$searchRoots = @(
    "$env:USERPROFILE",
    "C:\OneDrive",
    "C:\Users\shiatoali"
)

# ── SECTION 1: FIND ALL VERSIONS OF CONFLICT FILES ────────────────────────
Write-Host "[1/5] Finding all versions of conflicting files..." -ForegroundColor Yellow
Write-Host ""

$allConflicts = @{}

foreach ($fileName in $conflictFiles) {
    $versions = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($root in $searchRoots) {
        if (-not (Test-Path $root)) { continue }
        Get-ChildItem -Path $root -Filter $fileName -Recurse -File -Force 2>$null |
        Where-Object { $_.FullName -notmatch "\\\.git\\" } |
        ForEach-Object {
            $hash = (Get-FileHash $_.FullName -Algorithm MD5 -ErrorAction SilentlyContinue).Hash
            $versions.Add([PSCustomObject]@{
                Name     = $_.Name
                FullPath = $_.FullName
                SizeKB   = [math]::Round($_.Length/1KB,1)
                Modified = $_.LastWriteTime
                Hash     = $hash
                Lines    = 0
                IsInRepo = $_.FullName -like "*shadow313-nexus*"
                IsInDL   = $_.FullName -like "*Downloads*"
                IsInOD   = $_.FullName -like "*OneDrive*"
                IsOnDesk = $_.FullName -like "*Desktop*"
            })
        }
    }
    # Count lines for text files
    foreach ($v in $versions) {
        if ($v.Name -match "\.(html|py|yml|yaml|json|md|txt|ps1)$") {
            try { $v.Lines = (Get-Content $v.FullPath -ErrorAction SilentlyContinue).Count } catch {}
        }
    }
    $allConflicts[$fileName] = $versions
}

# ── SECTION 2: ANALYZE & RECOMMEND ───────────────────────────────────────
Write-Host "[2/5] Analyzing versions and generating recommendations..." -ForegroundColor Yellow
Write-Host ""

$sb = [System.Text.StringBuilder]::new()
function Add($line) { $sb.AppendLine($line) | Out-Null }

Add "============================================================"
Add "  SHADOW313 — Version Conflict Resolution Report"
Add "  Generated: $(Get-Date)"
Add "============================================================"
Add ""

$decisions = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($fileName in $conflictFiles) {
    $versions = $allConflicts[$fileName]
    if ($versions.Count -eq 0) {
        Write-Host "  ⚪ $fileName — not found on this system" -ForegroundColor DarkGray
        continue
    }

    # Deduplicate by hash
    $uniqueVersions = $versions | Group-Object Hash | ForEach-Object {
        # Of duplicates, prefer: repo > downloads > desktop > onedrive
        $best = $_.Group | Sort-Object {
            if ($_.IsInRepo) { 0 }
            elseif ($_.IsInDL) { 1 }
            elseif ($_.IsOnDesk) { 2 }
            elseif ($_.IsInOD) { 3 }
            else { 4 }
        } | Select-Object -First 1
        $best | Add-Member -NotePropertyName DupCount -NotePropertyValue $_.Count -PassThru
    }

    Write-Host "  📄 $fileName — $($versions.Count) copies, $($uniqueVersions.Count) unique versions" -ForegroundColor White

    Add "============================================================"
    Add "  FILE: $fileName"
    Add "  Total copies: $($versions.Count) | Unique versions: $($uniqueVersions.Count)"
    Add "============================================================"
    Add ""

    # Score each unique version
    $scored = $uniqueVersions | ForEach-Object {
        $score = 0
        if ($_.IsInRepo)  { $score += 100 }  # In git repo = highest priority
        if ($_.IsInDL)    { $score += 20  }  # Downloads = recent
        if ($_.IsOnDesk)  { $score += 15  }  # Desktop = recent
        $score += [math]::Min($_.Lines / 10, 50)  # More lines = more complete
        $score += [math]::Min($_.SizeKB / 5, 30)  # Larger = more content
        # Recency bonus (days since modified, inverted)
        $daysSince = ([DateTime]::Now - $_.Modified).TotalDays
        $score += [math]::Max(0, 30 - $daysSince)
        $_ | Add-Member -NotePropertyName Score -NotePropertyValue ([math]::Round($score,1)) -PassThru
    } | Sort-Object Score -Descending

    $winner = $scored | Select-Object -First 1
    $losers = $scored | Select-Object -Skip 1

    Add "  VERSIONS (ranked by score):"
    foreach ($v in $scored) {
        $tag = if ($v -eq $winner) { "★ KEEP" } else { "  ARCHIVE" }
        $loc = if ($v.IsInRepo) { "[GIT REPO]" } elseif ($v.IsInDL) { "[Downloads]" } elseif ($v.IsOnDesk) { "[Desktop]" } elseif ($v.IsInOD) { "[OneDrive]" } else { "[Other]" }
        Add "  $tag  Score:$($v.Score)  $loc  $($v.Modified.ToString('yyyy-MM-dd HH:mm'))  $($v.SizeKB)KB  $($v.Lines) lines"
        Add "         $($v.FullPath)"
        if ($v.DupCount -gt 1) { Add "         (+ $($v.DupCount - 1) identical copies at other locations)" }
        Add ""
    }

    Add "  RECOMMENDATION:"
    Add "  KEEP:    $($winner.FullPath)"
    Add "  REASON:  Score $($winner.Score) — $(if($winner.IsInRepo){'In git repo (authoritative)'}elseif($winner.IsInDL){'Most recent in Downloads'}else{'Largest/most complete version'})"
    Add ""

    # Record decisions
    $decisions.Add([PSCustomObject]@{
        FileName   = $fileName
        WinnerPath = $winner.FullPath
        WinnerScore= $winner.Score
        WinnerSize = $winner.SizeKB
        WinnerLines= $winner.Lines
        WinnerMod  = $winner.Modified
        LoserCount = $losers.Count
        AllCopies  = $versions.Count
    })

    foreach ($loser in $losers) {
        # Archive all copies of loser versions
        foreach ($copy in ($versions | Where-Object { $_.Hash -eq $loser.Hash })) {
            $decisions | Where-Object { $_.FileName -eq $fileName } | ForEach-Object {
                # Add loser paths to a separate list
            }
        }
    }

    # Console output
    Write-Host "    ★ KEEP:    $($winner.FullPath)" -ForegroundColor Green
    Write-Host "      Score:   $($winner.Score) | $($winner.SizeKB)KB | $($winner.Lines) lines | $($winner.Modified.ToString('yyyy-MM-dd HH:mm'))" -ForegroundColor DarkGreen
    foreach ($loser in $losers) {
        Write-Host "    ✗ ARCHIVE: $($loser.FullPath)" -ForegroundColor DarkGray
        Write-Host "      Score:   $($loser.Score) | $($loser.SizeKB)KB | $($loser.Lines) lines | $($loser.Modified.ToString('yyyy-MM-dd HH:mm'))" -ForegroundColor DarkGray
    }
    Write-Host ""
}

# ── SECTION 3: ONEDRIVE + SHAREX FIX ─────────────────────────────────────
Write-Host "[3/5] Diagnosing OneDrive and ShareX issues..." -ForegroundColor Yellow
Write-Host ""

Add "============================================================"
Add "  ONEDRIVE + SHAREX DIAGNOSIS & FIX"
Add "============================================================"
Add ""

# Check OneDrive status
$odProcess  = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
$odPath     = "$env:USERPROFILE\OneDrive"
$odPersonal = "$env:USERPROFILE\OneDrive - Personal"
$odStatus   = if ($odProcess) { "Running" } else { "Not running" }

Write-Host "  OneDrive status: $odStatus" -ForegroundColor $(if($odProcess){"Green"}else{"Yellow"})

# Check for placeholder/offline files (the X icons)
$offlineFiles = @()
if (Test-Path $odPath) {
    $offlineFiles = Get-ChildItem -Path $odPath -Recurse -File -Force 2>$null |
        Where-Object { $_.Attributes -band [System.IO.FileAttributes]::ReparsePoint } |
        Select-Object -First 20
}

Add "  OneDrive Status: $odStatus"
Add "  OneDrive Path:   $odPath"
Add ""
Add "  WHY YOU SEE X ICONS ON FILES:"
Add "  OneDrive 'Files On-Demand' shows X icons when:"
Add "  1. File is cloud-only (not downloaded locally)"
Add "  2. Sync is paused or account has an error"
Add "  3. File is in a conflict state"
Add "  4. OneDrive storage quota exceeded"
Add ""
Add "  FIX — Run these commands in PowerShell (as Admin):"
Add ""
Add "  # Fix 1: Force sync all Shadow313 files locally"
Add "  attrib -U +P /S /D `"$odPath\*shadow313*`""
Add ""
Add "  # Fix 2: Reset OneDrive sync (fixes most X icon issues)"
Add "  Stop-Process -Name OneDrive -Force -ErrorAction SilentlyContinue"
Add "  Start-Sleep 2"
Add "  & `"$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe`" /reset"
Add "  Start-Sleep 5"
Add "  & `"$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe`""
Add ""
Add "  # Fix 3: Make specific folder always available offline"
Add "  # Right-click the folder in Explorer → 'Always keep on this device'"
Add ""

# ShareX diagnosis
$sharexPath    = "$env:USERPROFILE\Documents\ShareX"
$sharexAppData = "$env:APPDATA\ShareX"
$sharexInstalled = (Get-Command "ShareX" -ErrorAction SilentlyContinue) -or (Test-Path "C:\Program Files\ShareX\ShareX.exe")

Add "  SHAREX STATUS:"
Add "  Installed: $sharexInstalled"
Add "  Config path: $sharexAppData"
Add "  Screenshots path: $sharexPath"
Add ""
Add "  WHY SHAREX SHOWS X IN FILE EXPLORER:"
Add "  ShareX creates a folder in Documents that syncs to OneDrive."
Add "  If OneDrive has sync issues, the ShareX folder shows X too."
Add ""
Add "  FIX — Redirect ShareX away from OneDrive:"
Add "  1. Open ShareX → Application Settings → Paths"
Add "  2. Change 'Personal folder' to: C:\Shadow313-Screenshots"
Add "  3. This stops ShareX from syncing through OneDrive"
Add ""

Write-Host "  OneDrive X icon fix commands written to report" -ForegroundColor Green
Write-Host "  ShareX redirect instructions written to report" -ForegroundColor Green
Write-Host ""

# ── SECTION 4: VSCODE + TOOLS SETUP ──────────────────────────────────────
Write-Host "[4/5] Generating VS Code + tools setup guide..." -ForegroundColor Yellow
Write-Host ""

Add "============================================================"
Add "  VS CODE SETUP FOR SHADOW313 DEVELOPMENT"
Add "============================================================"
Add ""
Add "  STEP 1: Install required VS Code extensions"
Add "  Run in PowerShell:"
Add ""
Add "  code --install-extension ms-python.python"
Add "  code --install-extension ms-python.pylance"
Add "  code --install-extension ms-vscode-remote.remote-wsl"
Add "  code --install-extension ms-azuretools.vscode-docker"
Add "  code --install-extension eamodio.gitlens"
Add "  code --install-extension yzhang.markdown-all-in-one"
Add "  code --install-extension esbenp.prettier-vscode"
Add "  code --install-extension ms-vscode.powershell"
Add "  code --install-extension redhat.vscode-yaml"
Add "  code --install-extension ms-vscode.live-server"
Add ""
Add "  STEP 2: Open Shadow313 as workspace"
Add "  code C:\Users\shiatoali\shadow313-nexus"
Add ""
Add "  STEP 3: Create workspace settings"
Add "  File: shadow313-nexus\.vscode\settings.json"
Add "  {"
Add "    `"python.defaultInterpreterPath`": `"C:/Users/shiatoali/shadow313-nexus/.venv/Scripts/python.exe`","
Add "    `"python.terminal.activateEnvironment`": true,"
Add "    `"editor.formatOnSave`": true,"
Add "    `"files.exclude`": { `"**/__pycache__`": true, `"**/.pytest_cache`": true },"
Add "    `"terminal.integrated.defaultProfile.windows`": `"PowerShell`","
Add "    `"git.autofetch`": true,"
Add "    `"git.confirmSync`": false"
Add "  }"
Add ""
Add "  STEP 4: Set up Python virtual environment"
Add "  cd C:\Users\shiatoali\shadow313-nexus"
Add "  python -m venv .venv"
Add "  .\.venv\Scripts\Activate.ps1"
Add "  pip install -e .[full]"
Add ""

Add "============================================================"
Add "  NOTES APP SETUP (Obsidian for Shadow313)"
Add "============================================================"
Add ""
Add "  Obsidian is already installed. Set it up for Shadow313:"
Add ""
Add "  1. Open Obsidian → 'Open folder as vault'"
Add "  2. Select: C:\Users\shiatoali\shadow313-nexus\notes"
Add "  3. Create notes\ folder first:"
Add "     mkdir C:\Users\shiatoali\shadow313-nexus\notes"
Add ""
Add "  Recommended vault structure:"
Add "  notes\"
Add "  ├── CVEs\           ← CVE research notes"
Add "  ├── ATT&CK\         ← Technique analysis"
Add "  ├── Architecture\   ← Design decisions"
Add "  ├── Sessions\       ← Daily work logs"
Add "  └── README.md"
Add ""

Add "============================================================"
Add "  PASSKEY / KEEPASSXC SETUP"
Add "============================================================"
Add ""
Add "  KeePassXC is already installed. Recommended setup:"
Add ""
Add "  1. Create database: C:\Users\shiatoali\shadow313-nexus\secrets.kdbx"
Add "     (This stays local — do NOT sync to OneDrive or GitHub)"
Add "  2. Add to .gitignore: echo 'secrets.kdbx' >> .gitignore"
Add "  3. Store in KeePassXC:"
Add "     - GitHub token (ghp_xxx)"
Add "     - Ollama API keys"
Add "     - Vercel tokens"
Add "     - Docker Hub credentials"
Add "     - matarmohamad313@duck.com passwords"
Add ""
Add "  Enable browser integration:"
Add "  KeePassXC → Tools → Settings → Browser Integration → Enable"
Add "  Install KeePassXC-Browser extension in Edge/Chrome"
Add ""

Add "============================================================"
Add "  SHAREX PROPER SETUP"
Add "============================================================"
Add ""
Add "  1. Open ShareX"
Add "  2. Application Settings → Paths:"
Add "     Personal folder: C:\Shadow313-Screenshots"
Add "  3. Hotkey Settings → recommended:"
Add "     Print Screen    → Capture region"
Add "     Ctrl+Print      → Capture fullscreen"
Add "     Shift+Print     → Capture window"
Add "  4. After Capture Actions: enable 'Copy image to clipboard'"
Add "  5. Disable 'Upload to ShareX.io' (keep local only)"
Add ""
Add "  This stops ShareX from conflicting with OneDrive."
Add ""

# ── SECTION 5: EXECUTE ARCHIVING ─────────────────────────────────────────
Write-Host "[5/5] Archiving old file versions..." -ForegroundColor Yellow
Write-Host ""

if (-not $DryRun) {
    if (-not (Test-Path $Archive)) {
        New-Item -ItemType Directory -Path $Archive -Force | Out-Null
        Write-Host "  Created archive folder: $Archive" -ForegroundColor Green
    }
}

$archived = 0; $kept = 0; $errors = 0

foreach ($fileName in $conflictFiles) {
    $versions = $allConflicts[$fileName]
    if ($versions.Count -eq 0) { continue }

    # Find winner (highest score)
    $scored = $versions | Group-Object Hash | ForEach-Object {
        $best = $_.Group | Sort-Object {
            if ($_.IsInRepo) { 0 } elseif ($_.IsInDL) { 1 } elseif ($_.IsOnDesk) { 2 } else { 3 }
        } | Select-Object -First 1
        $score = 0
        if ($best.IsInRepo) { $score += 100 }
        if ($best.IsInDL)   { $score += 20 }
        $score += [math]::Min($best.Lines/10, 50)
        $score += [math]::Min($best.SizeKB/5, 30)
        $best | Add-Member -NotePropertyName Score -NotePropertyValue $score -PassThru
        $best | Add-Member -NotePropertyName GroupHash -NotePropertyValue $_.Name -PassThru
    } | Sort-Object Score -Descending

    $winnerHash = ($scored | Select-Object -First 1).Hash

    foreach ($v in $versions) {
        if ($v.Hash -eq $winnerHash -and $v.IsInRepo) {
            # This is the canonical copy — leave it
            $kept++
            Write-Host "  ✅ KEEP: $($v.Name) → $($v.FullPath)" -ForegroundColor Green
        } elseif ($v.Hash -eq $winnerHash) {
            # Duplicate of winner but not in repo — leave it for now
            $kept++
        } else {
            # Archive this version
            $archiveName = "$([System.IO.Path]::GetFileNameWithoutExtension($v.Name))_$($v.Modified.ToString('yyyyMMdd-HHmm'))$($v.Extension)"
            $archiveDest = Join-Path $Archive $archiveName
            Write-Host "  📦 ARCHIVE: $($v.Name) → $archiveName" -ForegroundColor DarkGray

            if (-not $DryRun) {
                try {
                    Copy-Item -Path $v.FullPath -Destination $archiveDest -Force
                    $archived++
                } catch {
                    $errors++
                    Write-Host "    ❌ Error archiving: $_" -ForegroundColor Red
                }
            } else {
                $archived++
            }
        }
    }
}

# ── WRITE REPORT ──────────────────────────────────────────────────────────
Add "============================================================"
Add "  ARCHIVING SUMMARY"
Add "============================================================"
Add ""
Add "  Files kept (canonical):  $kept"
Add "  Files archived:          $archived"
Add "  Errors:                  $errors"
Add "  Archive location:        $Archive"
Add ""
Add "  NOTE: Archived files are COPIES — originals untouched."
Add "  Review the archive folder, then manually delete originals"
Add "  once you confirm the canonical versions are correct."
Add ""

$sb.ToString() | Out-File -FilePath $reportPath -Encoding UTF8

# ── FINAL CONSOLE OUTPUT ──────────────────────────────────────────────────
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  COMPLETE" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Files kept:     $kept" -ForegroundColor Green
Write-Host "  Files archived: $archived" -ForegroundColor $(if($archived -gt 0){"Yellow"}else{"Green"})
Write-Host "  Errors:         $errors" -ForegroundColor $(if($errors -gt 0){"Red"}else{"Green"})
Write-Host ""
Write-Host "  Full report: $reportPath" -ForegroundColor White
Write-Host ""
Write-Host "  IMMEDIATE ACTIONS:" -ForegroundColor Cyan
Write-Host ""
Write-Host "  1. FIX ONEDRIVE X ICONS (run as Admin):" -ForegroundColor White
Write-Host "     Stop-Process -Name OneDrive -Force" -ForegroundColor Gray
Write-Host "     & `"$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe`" /reset" -ForegroundColor Gray
Write-Host ""
Write-Host "  2. FIX SHAREX:" -ForegroundColor White
Write-Host "     Open ShareX → App Settings → Paths → set to C:\Shadow313-Screenshots" -ForegroundColor Gray
Write-Host ""
Write-Host "  3. SETUP VSCODE:" -ForegroundColor White
Write-Host "     code --install-extension ms-python.python" -ForegroundColor Gray
Write-Host "     code C:\Users\shiatoali\shadow313-nexus" -ForegroundColor Gray
Write-Host ""
Write-Host "  4. FIX GIT + PUSH:" -ForegroundColor White
Write-Host "     cd C:\Users\shiatoali\shadow313-nexus" -ForegroundColor Gray
Write-Host "     git config user.name 'piyyy314'" -ForegroundColor Gray
Write-Host "     git config user.email 'matarmohamad313@duck.com'" -ForegroundColor Gray
Write-Host "     git add . && git commit -m 'Consolidation' && git push" -ForegroundColor Gray
Write-Host ""
