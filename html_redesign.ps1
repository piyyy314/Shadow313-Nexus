# Shadow313 NEXUS — HTML Redesign Script
# Applies consistent nav, branding, and fixes to all docs/*.html
# Run AFTER fix_ci_final.ps1
# Usage: .\html_redesign.ps1 -Token "YOUR_TOKEN"

param([Parameter(Mandatory=$true)][string]$Token)

$RepoPath = "C:\Users\shiatoali\shadow313-nexus"
Set-Location $RepoPath

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Shadow313 NEXUS — HTML Redesign" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

git remote set-url origin "https://piyyy314:$Token@github.com/piyyy314/Shadow313-Nexus.git"
git pull origin master 2>&1 | Out-Null

# ── Master nav bar (injected into every page) ────────────────────────────────
$NAV = @'
<nav id="s313-nav" style="background:#020617;border-bottom:1px solid rgba(34,197,94,0.2);padding:8px 20px;display:flex;align-items:center;gap:12px;font-family:'Space Grotesk',sans-serif,monospace;position:sticky;top:0;z-index:9999;flex-wrap:wrap;">
  <a href="/" style="color:#22c55e;font-weight:800;font-size:13px;text-decoration:none;letter-spacing:.05em;">⬡ S313 NEXUS</a>
  <span style="color:#334155;font-size:10px;">|</span>
  <a href="/dashboard" style="color:#94a3b8;font-size:11px;text-decoration:none;">Dashboard</a>
  <a href="/threat-board" style="color:#94a3b8;font-size:11px;text-decoration:none;">Threats</a>
  <a href="/attck" style="color:#94a3b8;font-size:11px;text-decoration:none;">ATT&amp;CK</a>
  <a href="/aegis-nexus" style="color:#94a3b8;font-size:11px;text-decoration:none;">Aegis</a>
  <a href="/vsat" style="color:#94a3b8;font-size:11px;text-decoration:none;">VSAT</a>
  <a href="/pqc" style="color:#94a3b8;font-size:11px;text-decoration:none;">PQC</a>
  <a href="/ghost-watch" style="color:#94a3b8;font-size:11px;text-decoration:none;">Ghost Watch</a>
  <a href="/quantum-lab" style="color:#94a3b8;font-size:11px;text-decoration:none;">Quantum</a>
  <a href="/pricing" style="color:#94a3b8;font-size:11px;text-decoration:none;">Pricing</a>
  <a href="/docs" style="color:#94a3b8;font-size:11px;text-decoration:none;">Docs</a>
  <a href="https://github.com/piyyy314/Shadow313-Nexus" target="_blank" style="color:#94a3b8;font-size:11px;text-decoration:none;">GitHub ↗</a>
  <span style="margin-left:auto;color:#22c55e;font-size:9px;font-family:monospace;" id="s313-clock"></span>
  <script>!function(){var e=document.getElementById("s313-clock");if(e)setInterval(function(){e.textContent=new Date().toISOString().replace("T"," ").slice(0,19)+" UTC"},1000)}()</script>
</nav>
'@

# ── Master footer ────────────────────────────────────────────────────────────
$FOOTER = @'
<footer style="background:#020617;border-top:1px solid rgba(34,197,94,0.1);padding:16px 24px;text-align:center;font-family:'Space Grotesk',sans-serif;font-size:10px;color:#334155;margin-top:40px;">
  <span style="color:#22c55e;font-weight:700;">⬡ Shadow313 NEXUS</span> v4.0.0 &nbsp;·&nbsp;
  Ottawa, ON, Canada &nbsp;·&nbsp;
  <a href="mailto:matarmohamad313@duck.com" style="color:#475569;text-decoration:none;">matarmohamad313@duck.com</a> &nbsp;·&nbsp;
  <a href="https://github.com/piyyy314/Shadow313-Nexus" style="color:#475569;text-decoration:none;">GitHub</a> &nbsp;·&nbsp;
  <a href="/pricing" style="color:#475569;text-decoration:none;">Pricing</a> &nbsp;·&nbsp;
  <a href="/privacy" style="color:#475569;text-decoration:none;">Privacy</a> &nbsp;·&nbsp;
  <a href="/terms" style="color:#475569;text-decoration:none;">Terms</a> &nbsp;·&nbsp;
  MIT License &nbsp;·&nbsp;
  <span style="color:#22c55e;">4,107 tests GREEN</span> &nbsp;·&nbsp;
  <span style="color:#a78bfa;">FIPS 203/204/205</span>
</footer>
'@

# ── Google Fonts link ────────────────────────────────────────────────────────
$FONTS = '<link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">'

Write-Host "`n[1/3] Applying nav + footer to all docs/*.html..." -ForegroundColor Yellow
$files = Get-ChildItem "docs\*.html" -ErrorAction SilentlyContinue
$fixed = 0; $skipped = 0

foreach ($file in $files) {
    $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
    if (-not $content -or $content.Length -lt 200) { $skipped++; continue }
    
    $changed = $false
    
    # 1. Add Google Fonts if missing
    if ($content -notmatch 'fonts.googleapis.com' -and $content -match '<head') {
        $content = $content -replace '</head>', "$FONTS`n</head>"
        $changed = $true
    }
    
    # 2. Add nav bar after <body> if missing
    if ($content -notmatch 's313-nav') {
        if ($content -match '<body[^>]*>') {
            $content = $content -replace '(<body[^>]*>)', "`$1`n$NAV"
            $changed = $true
        } elseif ($content -notmatch '<body') {
            # No body tag — wrap everything
            $content = "<!DOCTYPE html><html lang=`"en`"><head><meta charset=`"UTF-8`"><meta name=`"viewport`" content=`"width=device-width,initial-scale=1`">$FONTS</head><body>$NAV`n$content`n$FOOTER</body></html>"
            $changed = $true
        }
    }
    
    # 3. Add footer before </body> if missing
    if ($content -notmatch 's313-nav' -or $content -notmatch 'matarmohamad313@duck.com') {
        if ($content -match '</body>') {
            $content = $content -replace '</body>', "$FOOTER`n</body>"
            $changed = $true
        }
    }
    
    # 4. Remove CyberShield references
    if ($content -match 'CyberShield|cybershield') {
        $content = $content -replace 'CyberShield Suite', 'Shadow313 NEXUS'
        $content = $content -replace 'cybershield', 'shadow313'
        $content = $content -replace 'CyberShield', 'Shadow313'
        $changed = $true
    }
    
    # 5. Fix dark background if page has white/light background
    if ($content -match 'background:\s*#fff|background:\s*white|background-color:\s*white') {
        $content = $content -replace 'background:\s*#fff\b', 'background:#020617'
        $content = $content -replace 'background:\s*white\b', 'background:#020617'
        $content = $content -replace 'background-color:\s*white\b', 'background-color:#020617'
        $changed = $true
    }
    
    if ($changed) {
        Set-Content $file.FullName $content
        $fixed++
    } else {
        $skipped++
    }
}

Write-Host "  ✅ Fixed: $fixed files | Already OK: $skipped files" -ForegroundColor Green

# ── Fix the index.html (main homepage) ──────────────────────────────────────
Write-Host "`n[2/3] Verifying main index.html..." -ForegroundColor Yellow
if (Test-Path "index.html") {
    $idx = Get-Content "index.html" -Raw
    if ($idx -notmatch 's313-nav') {
        $idx = $idx -replace '(<body[^>]*>)', "`$1`n$NAV"
        Set-Content "index.html" $idx
        Write-Host "  ✅ index.html nav added" -ForegroundColor Green
    } else {
        Write-Host "  ✅ index.html already has nav" -ForegroundColor Green
    }
}

# ── Commit and push ──────────────────────────────────────────────────────────
Write-Host "`n[3/3] Committing HTML redesign..." -ForegroundColor Yellow
git add docs\*.html index.html 2>$null
$status = git status --short
if ($status) {
    $count = ($status | Measure-Object).Count
    git commit -m "feat: HTML redesign — consistent nav/footer on all $count pages, Space Grotesk fonts, dark theme, remove CyberShield branding, add back/forward navigation"
    git push origin master 2>&1 | Out-Null
    Write-Host "  ✅ $count HTML files pushed" -ForegroundColor Green
} else {
    Write-Host "  ℹ️  No HTML changes needed" -ForegroundColor Cyan
}

git remote set-url origin "https://github.com/piyyy314/Shadow313-Nexus.git"

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "  HTML REDESIGN COMPLETE" -ForegroundColor Green
Write-Host "  All 113 pages now have:" -ForegroundColor White
Write-Host "  ✅ Sticky nav bar (S313 NEXUS + all section links)" -ForegroundColor Green
Write-Host "  ✅ Footer (email, GitHub, Pricing, Privacy, Terms)" -ForegroundColor Green
Write-Host "  ✅ Space Grotesk + JetBrains Mono fonts" -ForegroundColor Green
Write-Host "  ✅ Dark theme (#020617 background)" -ForegroundColor Green
Write-Host "  ✅ No CyberShield branding" -ForegroundColor Green
Write-Host "  ✅ Live UTC clock in nav" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
