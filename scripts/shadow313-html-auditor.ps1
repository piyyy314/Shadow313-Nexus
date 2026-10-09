<#
.SYNOPSIS
    Shadow313 NEXUS — HTML Route Auditor
    Checks which vercel.json routes have missing destination files.
    Use -Fix to auto-create stub pages for missing routes.

.EXAMPLE
    .\scripts\shadow313-html-auditor.ps1
    .\scripts\shadow313-html-auditor.ps1 -Fix
#>
param(
    [switch]$Fix,
    [string]$RepoRoot = (Split-Path $PSScriptRoot -Parent)
)

Set-Location $RepoRoot

$vercelPath = Join-Path $RepoRoot "vercel.json"
if (-not (Test-Path $vercelPath)) {
    Write-Host "❌ vercel.json not found at $vercelPath" -ForegroundColor Red
    exit 1
}

$vj = Get-Content $vercelPath | ConvertFrom-Json
$rewrites = $vj.rewrites
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Shadow313 HTML Route Auditor" -ForegroundColor Cyan
Write-Host "  Routes in vercel.json: $($rewrites.Count)" -ForegroundColor Cyan
Write-Host "  Mode: $(if($Fix){'FIX (creating stubs)'}else{'AUDIT (read-only)'})" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$missing = @()
$present = @()
$seen    = @{}

foreach ($r in $rewrites) {
    $dest = $r.destination.TrimStart('/')
    if ($seen[$dest]) { continue }
    $seen[$dest] = $true

    $fullPath = Join-Path $RepoRoot $dest
    if (Test-Path $fullPath) {
        $size = (Get-Item $fullPath).Length
        $present += [PSCustomObject]@{ Route=$r.source; File=$dest; Size=$size }
    } else {
        $missing += [PSCustomObject]@{ Route=$r.source; File=$dest }
    }
}

Write-Host ""
Write-Host "✅ Present: $($present.Count) files" -ForegroundColor Green
Write-Host "❌ Missing: $($missing.Count) files" -ForegroundColor $(if($missing.Count -eq 0){"Green"}else{"Red"})

if ($missing.Count -gt 0) {
    Write-Host ""
    Write-Host "Missing destination files:" -ForegroundColor Yellow
    foreach ($m in $missing) {
        Write-Host "  ❌ $($m.Route) → $($m.File)" -ForegroundColor Red
    }

    if ($Fix) {
        Write-Host ""
        Write-Host "Creating stub pages..." -ForegroundColor Cyan
        foreach ($m in $missing) {
            $dir = Split-Path (Join-Path $RepoRoot $m.File) -Parent
            if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            $title = ($m.Route.TrimStart('/') -replace '-',' ' -replace '/',' — ')
            $stub = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>$title — Shadow313 NEXUS</title>
<style>
body{font-family:'Space Grotesk',sans-serif;background:#000;color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center;text-align:center;}
h1{font-size:2rem;color:#22c55e;margin-bottom:1rem;}
p{color:#64748b;}
a{color:#22c55e;text-decoration:none;}
</style>
</head>
<body>
<div>
  <h1>$title</h1>
  <p>This page is under construction.</p>
  <p><a href="/">← Back to Shadow313 NEXUS</a></p>
</div>
</body>
</html>
"@
            Set-Content (Join-Path $RepoRoot $m.File) $stub -Encoding UTF8
            Write-Host "  ✅ Created stub: $($m.File)" -ForegroundColor Green
        }
        Write-Host ""
        Write-Host "✅ $($missing.Count) stub pages created." -ForegroundColor Green
        Write-Host "Run: git add docs/ && git commit -m 'fix: add missing route stubs'" -ForegroundColor Cyan
    }
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Score: $($present.Count)/$($rewrites.Count) routes have files" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
