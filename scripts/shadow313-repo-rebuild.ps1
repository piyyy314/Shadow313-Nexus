param([string]$Token = "", [switch]$DryRun)
$ErrorActionPreference = "SilentlyContinue"
$Repo = "C:\Users\shiatoali\shadow313-nexus"
Set-Location $Repo
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  SHADOW313 — Complete Repo Rebuild & Audit" -ForegroundColor Cyan
if ($DryRun) { Write-Host "  MODE: DRY RUN" -ForegroundColor Yellow }
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[1/6] Removing sensitive files..." -ForegroundColor Yellow
$sensitive = @(
    "docs-archive/rescued-from-pictures/crypto_offensive_orchestrator.py",
    "docs-archive/rescued-from-pictures/crypto_transfer_bnb_shiba.py",
    "docs-archive/rescued-from-pictures/crypto_transfer_btc_ltc.py",
    "docs-archive/rescued-from-pictures/ghost_c2_selector.py",
    "docs-archive/rescued-from-pictures/ghost_network_server.py",
    "docs-archive/rescued-from-pictures/ghost_shell_payload.py",
    "docs-archive/rescued-from-pictures/infinite_payload_trap.py",
    "docs-archive/rescued-from-pictures/phantom_dns_exfil.py",
    "docs-archive/rescued-from-pictures/shroud_code.py",
    "docs-archive/rescued-from-pictures/stealth_pivot_scan.py",
    "docs-archive/rescued-from-pictures/system_core_service.py",
    "docs-archive/rescued-from-pictures/universal_harvester.py",
    "docs-archive/rescued-from-pictures/v1_ignite_system.py",
    "docs-archive/rescued-from-pictures/v1_polymorphic_mutate.py",
    "docs-archive/rescued-from-pictures/v1_polymorphic_sleep.py",
    "docs-archive/rescued-from-pictures/v1_fortress_main.py",
    "docs-archive/rescued-from-pictures/v2_create_fortress_command_repo.py",
    "docs-archive/rescued-from-pictures/05ab89ca-7d57-4892-bf71-c56b92aed3ed.html",
    "docs-archive/rescued-from-pictures/0afca772-1953-4984-9287-4cf7ae89c15c.html",
    "docs-archive/rescued-from-pictures/0f01524a-17bf-46bf-a368-22268c9797a3.html",
    "docs-archive/rescued-from-pictures/2b9238c1-c688-43f3-be93-b6037b17d3e1.html",
    "docs-archive/rescued-from-pictures/2dddb0ce-bcb2-4d5b-898e-6189758d9058.html",
    "docs-archive/rescued-from-pictures/3bfcbc2f-8794-44fc-9ce8-d43b0004ea9f.html",
    "docs-archive/rescued-from-pictures/3d790510-5f9e-4c02-ab59-e46798ac092c.html",
    "docs-archive/rescued-from-pictures/3fa033a5-2cc4-4ad3-9ef7-1ed15933c14f.html",
    "docs-archive/rescued-from-pictures/6ae91c49-1c55-4b12-98a1-28a20f65b43a.html",
    "docs-archive/rescued-from-pictures/6f11d8a6-591b-4142-bd4a-a897cb84f52c.html"
)
$removed = 0
foreach ($f2 in $sensitive) {
    $lp = Join-Path $Repo ($f2 -replace '/','\')
    if (-not $DryRun) { git rm --cached $f2 2>$null | Out-Null; Remove-Item $lp -Force -ErrorAction SilentlyContinue }
    Write-Host "  Removed: $($f2.Split('/')[-1])" -ForegroundColor Red
    $removed++
}
Write-Host "  Removed $removed files" -ForegroundColor Green

Write-Host ""
Write-Host "[2/6] Writing professional .gitignore..." -ForegroundColor Yellow
@"
# SHADOW313 NEXUS .gitignore
__pycache__/
*.py[cod]
*.so
.venv/
venv/
.env
.env.local
.env.production
secrets.kdbx
*.pem
*.key
id_rsa
id_ed25519
*harvester*
*polymorphic*
*offensive*
ghost_c2*
ghost_shell*
*ignite_system*
*phantom_dns*
*stealth_pivot*
*infinite_payload*
*shroud_code*
system_core_service*
crypto_transfer*
node_modules/
.DS_Store
Thumbs.db
*.log
*.tmp
docs-archive/rescued-from-pictures/
local_bundle/
"@ | Out-File "$Repo\.gitignore" -Encoding UTF8
Write-Host "  .gitignore written" -ForegroundColor Green

Write-Host ""
Write-Host "[3/6] Fixing empty __init__.py files..." -ForegroundColor Yellow
$fixed = 0
Get-ChildItem $Repo -Filter "__init__.py" -Recurse -Force |
Where-Object { $_.Length -eq 0 -and $_.FullName -notmatch "\.git" } |
ForEach-Object {
    $mod = Split-Path (Split-Path $_.FullName -Parent) -Leaf
    if (-not $DryRun) {
        "# Shadow313 NEXUS — $mod module`n__version__ = '4.0.0'" | Out-File $_.FullName -Encoding UTF8 -NoNewline
    }
    Write-Host "  Fixed: $($_.FullName.Replace($Repo,'').TrimStart('\'))" -ForegroundColor Green
    $fixed++
}
Write-Host "  Fixed $fixed __init__.py files" -ForegroundColor Green

Write-Host ""
Write-Host "[4/6] Validating HTML in docs/..." -ForegroundColor Yellow
$valid = 0; $broken = 0
Get-ChildItem "$Repo\docs" -Filter "*.html" -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.Length -lt 500) {
        Write-Host "  BROKEN: $($_.Name) ($($_.Length) bytes)" -ForegroundColor Red
        if (-not $DryRun) { git rm --cached "docs/$($_.Name)" 2>$null | Out-Null; Remove-Item $_.FullName -Force }
        $broken++
    } else {
        Write-Host "  OK: $($_.Name) ($([math]::Round($_.Length/1KB,1))KB)" -ForegroundColor Green
        $valid++
    }
}
Write-Host "  Valid: $valid | Broken: $broken" -ForegroundColor Green

Write-Host ""
Write-Host "[5/6] Moving rescued HTML to docs/..." -ForegroundColor Yellow
$htmlToMove = @("aegis_nexus.html","vsat-tactical-suite.html","vsat-toolkit-v5.html",
    "vsat-toolkit-v6.html","CyberShield-Suite.html","S313-Nexus-Dashboard-v3.html",
    "S313-SSP-Dashboard.html","satexpert_tsi_v7.html","recon.html","web3_security_explorer.html")
$moved = 0
foreach ($h in $htmlToMove) {
    $src = "$Repo\docs-archive\rescued-from-pictures\$h"
    $dst = "$Repo\docs\$h"
    if ((Test-Path $src) -and -not (Test-Path $dst)) {
        if (-not $DryRun) { Copy-Item $src $dst -Force; Remove-Item $src -Force }
        Write-Host "  Moved: $h" -ForegroundColor Green
        $moved++
    }
}
Write-Host "  Moved $moved HTML files to docs/" -ForegroundColor Green

Write-Host ""
Write-Host "[6/6] Committing and pushing..." -ForegroundColor Yellow
if (-not $DryRun) {
    git add .
    git add -u
    $staged = (git diff --cached --name-only 2>$null).Count
    if ($staged -gt 0) {
        git commit -m "refactor: professional repo structure — remove sensitive files, fix HTML, organize modules"
        if ($Token) { git remote set-url origin "https://piyyy314:$Token@github.com/piyyy314/Shadow313-Nexus.git" }
        $push = git push origin master 2>&1
        if ($LASTEXITCODE -eq 0) { Write-Host "  Pushed $staged changes" -ForegroundColor Green }
        else { Write-Host "  Push failed: $push" -ForegroundColor Red }
        if ($Token) { git remote set-url origin "https://github.com/piyyy314/Shadow313-Nexus.git" }
    } else { Write-Host "  Nothing to commit" -ForegroundColor Gray }
}
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  DONE$(if($DryRun){' (DRY RUN)'}) — shadow313.dev ready" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
