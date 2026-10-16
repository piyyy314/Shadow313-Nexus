# ============================================================
# SHADOW313 — AppData\Local Deep Analyzer
# Breaks down exactly what's eating your 71 GB
# Safe to run — read only, nothing deleted
# Usage: .\shadow313-appdata-analyzer.ps1
# ============================================================

$ErrorActionPreference = "SilentlyContinue"
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
$reportPath = "$env:USERPROFILE\Desktop\APPDATA-ANALYSIS-$timestamp.txt"

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  AppData\Local Deep Analyzer" -ForegroundColor Cyan
Write-Host "  Finding what's eating your 71 GB..." -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$localApp = "$env:LOCALAPPDATA"
$results = [System.Collections.Generic.List[PSCustomObject]]::new()

# Get all top-level subfolders and measure each
Write-Host "  Measuring all subfolders (takes 2-3 min)..." -ForegroundColor Yellow
Write-Host ""

$subfolders = Get-ChildItem -Path $localApp -Directory -Force -ErrorAction SilentlyContinue

$i = 0
foreach ($folder in $subfolders) {
    $i++
    Write-Host "  [$i/$($subfolders.Count)] $($folder.Name)..." -ForegroundColor DarkGray -NoNewline
    
    try {
        $files = Get-ChildItem -Path $folder.FullName -Recurse -File -Force -ErrorAction SilentlyContinue
        $count = ($files | Measure-Object).Count
        $sizeBytes = ($files | Measure-Object -Property Length -Sum).Sum
        $sizeGB = [math]::Round($sizeBytes / 1GB, 3)
        $sizeMB = [math]::Round($sizeBytes / 1MB, 1)
        
        # Categorize
        $category = switch -Regex ($folder.Name) {
            "^Microsoft$"           { "Microsoft Apps" }
            "^Programs$"            { "Installed Programs" }
            "^Temp$"                { "⚠️ TEMP FILES — SAFE TO DELETE" }
            "^npm"                  { "⚠️ NPM Cache — SAFE TO DELETE" }
            "^pip$"                 { "⚠️ PIP Cache — SAFE TO DELETE" }
            "^nuget"                { "NuGet Cache" }
            "^Google$"              { "Google (Chrome cache)" }
            "^BraveSoftware$"       { "Brave Browser cache" }
            "^Mozilla$"             { "Firefox cache" }
            "^ms-playwright"        { "Playwright browsers" }
            "^Ollama$"              { "Ollama (AI models)" }
            "^Docker$"              { "Docker" }
            "^slack$"               { "Slack cache" }
            "^Discord$"             { "Discord cache" }
            "^Spotify$"             { "Spotify cache" }
            "^Steam$"               { "Steam" }
            "^EpicGamesLauncher$"   { "Epic Games" }
            "^GitHubDesktop$"       { "GitHub Desktop" }
            "^SquirrelTemp$"        { "⚠️ Squirrel Temp — SAFE TO DELETE" }
            "^CrashDumps$"          { "⚠️ Crash Dumps — SAFE TO DELETE" }
            "^D3DSCache$"           { "DirectX Shader Cache" }
            "^NVIDIA$"              { "NVIDIA" }
            "^AMD$"                 { "AMD" }
            "^Intel$"               { "Intel" }
            "^Packages$"            { "UWP App Packages" }
            "^ConnectedDevicesPlatform$" { "Windows Connected Devices" }
            "^comms$"               { "Windows Comms" }
            "^PlaceholderTileLogoFolder$" { "Windows Tiles" }
            default                 { "Other" }
        }
        
        $results.Add([PSCustomObject]@{
            Name     = $folder.Name
            SizeGB   = $sizeGB
            SizeMB   = $sizeMB
            Files    = $count
            Category = $category
            Path     = $folder.FullName
            SafeToClean = $category -match "SAFE TO DELETE"
        })
        
        Write-Host " $sizeGB GB" -ForegroundColor $(if($sizeGB -gt 5){"Red"}elseif($sizeGB -gt 1){"Yellow"}else{"DarkGray"})
    } catch {
        Write-Host " (access denied)" -ForegroundColor DarkGray
    }
}

# Sort by size
$sorted = $results | Sort-Object SizeGB -Descending

# Calculate totals
$totalGB = [math]::Round(($results | Measure-Object SizeGB -Sum).Sum, 2)
$safeToCleanGB = [math]::Round(($results | Where-Object { $_.SafeToClean } | Measure-Object SizeGB -Sum).Sum, 2)

# Build report
$sb = [System.Text.StringBuilder]::new()
function Add($l) { $sb.AppendLine($l) | Out-Null }

Add "============================================================"
Add "  AppData\Local Deep Analysis"
Add "  Generated: $(Get-Date)"
Add "  Path: $localApp"
Add "============================================================"
Add ""
Add "SUMMARY"
Add "-------"
Add "  Total AppData\Local size:  $totalGB GB"
Add "  Safe to clean right now:   $safeToCleanGB GB"
Add "  Potential savings:         $([math]::Round($totalGB * 0.4, 1)) GB (estimated with browser cache)"
Add ""

Add "============================================================"
Add "  TOP OFFENDERS (sorted by size)"
Add "============================================================"
Add ""

foreach ($f in ($sorted | Select-Object -First 30)) {
    $bar = "█" * [math]::Min([math]::Round($f.SizeGB * 2), 40)
    $clean = if ($f.SafeToClean) { " ← SAFE TO DELETE" } else { "" }
    Add "  $($f.SizeGB.ToString('0.000').PadLeft(7)) GB  $($f.Name)$clean"
    Add "               $($f.Files) files | $($f.Category)"
    Add ""
}

Add "============================================================"
Add "  SAFE TO CLEAN RIGHT NOW (no risk)"
Add "============================================================"
Add ""
$cleanable = $results | Where-Object { $_.SafeToClean } | Sort-Object SizeGB -Descending
foreach ($f in $cleanable) {
    Add "  $($f.SizeGB.ToString('0.000').PadLeft(7)) GB  $($f.Path)"
}
Add ""
Add "  Total cleanable: $safeToCleanGB GB"
Add ""

Add "============================================================"
Add "  BROWSER CACHES (safe to clean, rebuilds automatically)"
Add "============================================================"
Add ""
$browsers = $results | Where-Object { $_.Category -match "Chrome|Brave|Firefox|Edge" }
foreach ($b in $browsers) {
    Add "  $($b.SizeGB.ToString('0.000').PadLeft(7)) GB  $($b.Name) — $($b.Category)"
    # Find cache subfolder
    $cacheDir = Get-ChildItem -Path $b.Path -Directory -Recurse -Filter "Cache" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cacheDir) {
        $cacheSize = [math]::Round((Get-ChildItem $cacheDir.FullName -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum / 1GB, 3)
        Add "               Cache folder: $($cacheDir.FullName) ($cacheSize GB)"
    }
}
Add ""

Add "============================================================"
Add "  CLEANUP COMMANDS (copy-paste into Admin PowerShell)"
Add "============================================================"
Add ""
Add "  # ── SAFE DELETES (no risk) ──────────────────────────────"
Add "  Remove-Item `"$env:LOCALAPPDATA\Temp\*`" -Recurse -Force -ErrorAction SilentlyContinue"
Add "  Remove-Item `"$env:LOCALAPPDATA\npm-cache\*`" -Recurse -Force -ErrorAction SilentlyContinue"
Add "  Remove-Item `"$env:LOCALAPPDATA\pip\cache\*`" -Recurse -Force -ErrorAction SilentlyContinue"
Add "  Remove-Item `"$env:LOCALAPPDATA\SquirrelTemp\*`" -Recurse -Force -ErrorAction SilentlyContinue"
Add "  Remove-Item `"$env:LOCALAPPDATA\CrashDumps\*`" -Recurse -Force -ErrorAction SilentlyContinue"
Add "  Remove-Item `"$env:LOCALAPPDATA\D3DSCache\*`" -Recurse -Force -ErrorAction SilentlyContinue"
Add ""
Add "  # ── BROWSER CACHES (safe, rebuilds automatically) ────────"
Add "  # Close all browsers first, then run:"
Add "  Remove-Item `"$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache\*`" -Recurse -Force -ErrorAction SilentlyContinue"
Add "  Remove-Item `"$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Code Cache\*`" -Recurse -Force -ErrorAction SilentlyContinue"
Add "  Remove-Item `"$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Cache\*`" -Recurse -Force -ErrorAction SilentlyContinue"
Add "  Remove-Item `"$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache\*`" -Recurse -Force -ErrorAction SilentlyContinue"
Add "  Remove-Item `"$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Code Cache\*`" -Recurse -Force -ErrorAction SilentlyContinue"
Add ""
Add "  # ── WINDOWS BUILT-IN CLEANUP (safest method) ─────────────"
Add "  # Run Disk Cleanup as Admin:"
Add "  cleanmgr /d C: /sageset:1"
Add "  cleanmgr /d C: /sagerun:1"
Add ""
Add "  # ── DO NOT DELETE THESE ───────────────────────────────────"
Add "  # Microsoft\  — Windows app data (breaking this = broken apps)"
Add "  # Programs\   — Installed program data"
Add "  # Packages\   — UWP apps (Store apps)"
Add "  # Ollama\     — Your AI models (13 GB but needed)"
Add "  # Docker\     — Docker config"
Add ""

Add "============================================================"
Add "  ANTIGRAVITY PROJECT — RECOVERY GUIDE"
Add "============================================================"
Add ""
Add "  Your old 'antigravity' project (Aegis-Sentinel-Security-Dashboard)"
Add "  won't run because it was built for your old Windows environment."
Add ""
Add "  WHAT HAPPENED:"
Add "  The project files survived the Windows reset (in C:\Users\shiatoali\antigravity)"
Add "  but the Node.js runtime, npm packages, and environment variables"
Add "  from your old Windows are gone. The app can't find its dependencies."
Add ""
Add "  TO RECOVER AND RUN IT:"
Add "  1. Check if files are still there:"
Add "     Get-ChildItem C:\Users\shiatoali\antigravity -Recurse | Measure-Object"
Add ""
Add "  2. Reinstall dependencies:"
Add "     cd C:\Users\shiatoali\antigravity\Aegis-Sentinel-Security-Dashboard"
Add "     npm install"
Add "     npm run dev"
Add ""
Add "  3. If npm not found, Node.js needs reinstalling:"
Add "     winget install OpenJS.NodeJS.LTS"
Add ""
Add "  4. Get the original source from GitHub:"
Add "     The original repo was likely under baalbek313 or piyyy314 account"
Add "     Check: https://github.com/baalbek313?tab=repositories"
Add "     Check: https://github.com/piyyy314?tab=repositories"
Add ""
Add "  5. If the repo is gone, recover from local files:"
Add "     cd C:\Users\shiatoali\antigravity\Aegis-Sentinel-Security-Dashboard"
Add "     git log --oneline  (shows commit history)"
Add "     git remote -v      (shows where it was pushed)"
Add ""

$sb.ToString() | Out-File -FilePath $reportPath -Encoding UTF8

# Console output
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  ANALYSIS COMPLETE" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Total AppData\Local:    $totalGB GB" -ForegroundColor White
Write-Host "  Safe to clean NOW:      $safeToCleanGB GB" -ForegroundColor Green
Write-Host ""
Write-Host "  TOP 10 BIGGEST FOLDERS:" -ForegroundColor Cyan
$sorted | Select-Object -First 10 | ForEach-Object {
    $clean = if ($_.SafeToClean) { " ← CLEAN" } else { "" }
    $color = if ($_.SizeGB -gt 10) { "Red" } elseif ($_.SizeGB -gt 2) { "Yellow" } else { "White" }
    Write-Host "    $($_.SizeGB.ToString('0.000').PadLeft(7)) GB  $($_.Name)$clean" -ForegroundColor $color
}
Write-Host ""
Write-Host "  Report: $reportPath" -ForegroundColor White
Write-Host ""
Write-Host "  ANTIGRAVITY PROJECT STATUS:" -ForegroundColor Cyan
$antigravity = "C:\Users\shiatoali\antigravity"
if (Test-Path $antigravity) {
    $agFiles = Get-ChildItem $antigravity -Recurse -File -Force -ErrorAction SilentlyContinue
    $agSize = [math]::Round(($agFiles | Measure-Object Length -Sum).Sum / 1GB, 2)
    Write-Host "  ✅ Files exist: $($agFiles.Count) files, $agSize GB" -ForegroundColor Green
    Write-Host "  Path: $antigravity" -ForegroundColor White
    # Check git remote
    $remote = & git -C $antigravity remote get-url origin 2>$null
    if ($remote) {
        Write-Host "  Git remote: $remote" -ForegroundColor Cyan
    } else {
        Write-Host "  No git remote found — check manually" -ForegroundColor Yellow
    }
} else {
    Write-Host "  ❌ Not found at C:\Users\shiatoali\antigravity" -ForegroundColor Red
}
Write-Host ""
