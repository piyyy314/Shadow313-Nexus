# Shadow313 NEXUS — Open all dashboards in Edge
# Run from: C:\Users\shiatoali\shadow313-nexus
# Usage: .\scripts\open_dashboards.ps1

$repo = Split-Path -Parent $MyInvocation.MyCommand.Path | Split-Path -Parent
$docs = Join-Path $repo "docs"

$files = @(
    "s313-command-center-v6.html",
    "s313-threat-board.html",
    "shadow313-nexus-dashboard.html"
)

Write-Host "Opening Shadow313 NEXUS dashboards..." -ForegroundColor Green

foreach ($file in $files) {
    $path = Join-Path $docs $file
    if (Test-Path $path) {
        Write-Host "  Opening: $file" -ForegroundColor Cyan
        Start-Process "msedge.exe" $path
        Start-Sleep -Milliseconds 500
    } else {
        Write-Host "  Missing: $file" -ForegroundColor Red
    }
}

Write-Host "`nAll dashboards opened in Edge!" -ForegroundColor Green
Write-Host "Or run the file server in Ubuntu:" -ForegroundColor Yellow
Write-Host "  python3 scripts/serve_files.py" -ForegroundColor White
Write-Host "  Then open: http://localhost:8313" -ForegroundColor White
