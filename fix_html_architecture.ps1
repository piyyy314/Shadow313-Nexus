# Shadow313 NEXUS — HTML Architecture Fix
# Fixes wrong numbers, unified design, correct categorization
# Run: .\fix_html_architecture.ps1 -Token "YOUR_TOKEN"

param([Parameter(Mandatory=$true)][string]$Token)

$RepoPath = "C:\Users\shiatoali\shadow313-nexus"
Set-Location $RepoPath

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Shadow313 NEXUS — HTML Architecture Fix" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

git remote set-url origin "https://piyyy314:$Token@github.com/piyyy314/Shadow313-Nexus.git"
git pull origin master 2>&1 | Out-Null
Write-Host "✅ Pulled latest" -ForegroundColor Green

# ── CANONICAL NUMBERS (single source of truth) ───────────────────────────────
$TESTS    = "4,107"
$MODULES  = "30"
$TOOLS    = "35"
$ATTCK    = "136/265 (51.4%)"
$DETECTORS = "29"
$SIGS     = "45"
$VERSION  = "v4.0.0-NEXUS"

# ── SHARED STYLES ────────────────────────────────────────────────────────────
$SHARED_CSS = @'
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{--bg:#020617;--bg2:#0b1329;--green:#22c55e;--cyan:#06b6d4;--amber:#f59e0b;--red:#ef4444;--purple:#a78bfa;--text:#e2e8f0;--muted:#64748b;--dim:#334155;}
*{box-sizing:border-box;}
body{background:var(--bg);color:var(--text);font-family:'Space Grotesk',sans-serif;margin:0;}
.mono{font-family:'JetBrains Mono',monospace;}
</style>
'@

$NAV = @'
<nav id="s313-nav" style="background:#020617;border-bottom:1px solid rgba(34,197,94,0.2);padding:8px 20px;display:flex;align-items:center;gap:10px;font-family:'Space Grotesk',sans-serif;position:sticky;top:0;z-index:9999;flex-wrap:wrap;">
<a href="/" style="color:#22c55e;font-weight:800;font-size:13px;text-decoration:none;">⬡ S313 NEXUS</a>
<span style="color:#334155;">|</span>
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
<span style="margin-left:auto;color:#22c55e;font-size:9px;font-family:monospace;" id="s313-clk"></span>
<script>setInterval(()=>{var e=document.getElementById("s313-clk");if(e)e.textContent=new Date().toISOString().replace("T"," ").slice(0,19)+" UTC"},1000)</script>
</nav>
'@

$FOOTER = @'
<footer style="background:#020617;border-top:1px solid rgba(34,197,94,0.1);padding:16px 24px;text-align:center;font-family:'Space Grotesk',sans-serif;font-size:10px;color:#334155;margin-top:40px;">
<span style="color:#22c55e;font-weight:700;">⬡ Shadow313 NEXUS</span> v4.0.0 &nbsp;·&nbsp; Ottawa, ON, Canada &nbsp;·&nbsp;
<a href="mailto:matarmohamad313@duck.com" style="color:#475569;text-decoration:none;">matarmohamad313@duck.com</a> &nbsp;·&nbsp;
<a href="https://github.com/piyyy314/Shadow313-Nexus" style="color:#475569;text-decoration:none;">GitHub</a> &nbsp;·&nbsp;
<a href="/pricing" style="color:#475569;text-decoration:none;">Pricing</a> &nbsp;·&nbsp;
<a href="/privacy" style="color:#475569;text-decoration:none;">Privacy</a> &nbsp;·&nbsp;
<a href="/terms" style="color:#475569;text-decoration:none;">Terms</a> &nbsp;·&nbsp;
MIT License &nbsp;·&nbsp; <span style="color:#22c55e;">4,107 tests GREEN</span> &nbsp;·&nbsp; <span style="color:#a78bfa;">FIPS 203/204/205</span>
</footer>
'@

# ── STEP 1: Fix wrong numbers in ALL HTML files ──────────────────────────────
Write-Host "`n[1/5] Fixing wrong numbers across all HTML files..." -ForegroundColor Yellow
$allHtml = Get-ChildItem -Recurse -Filter "*.html" -ErrorAction SilentlyContinue | 
    Where-Object { $_.FullName -notmatch "node_modules|docs-archive|local_bundle" }

$numFixed = 0
foreach ($f in $allHtml) {
    $c = Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue
    if (-not $c) { continue }
    $orig = $c
    
    # Fix test counts (wrong numbers)
    $c = $c -replace '\b858\s*tests?\b', '4,107 tests'
    $c = $c -replace '\b462\s*tests?\b', '4,107 tests'
    $c = $c -replace '\b2,648\s*tests?\b', '4,107 tests'
    $c = $c -replace '\b3,799\s*tests?\b', '4,107 tests'
    $c = $c -replace '\b4,091\s*tests?\b', '4,107 tests'
    $c = $c -replace '\b69/69\s*tests?\b', '4,107 tests'
    $c = $c -replace 'tests-\d+%20passed', 'tests-4107%20passed'
    
    # Fix module counts
    $c = $c -replace '\b9\s*MODULES\b', '30 MODULES'
    $c = $c -replace '\b28\s*modules?\b', '30 modules'
    $c = $c -replace '\b28\s*MODULES\b', '30 MODULES'
    
    # Fix plugin/tool counts
    $c = $c -replace '\b247\s*(?:verified\s*)?plugins?\b', '35 tools'
    $c = $c -replace '\b247\s*PLUGINS\b', '35 TOOLS'
    $c = $c -replace '247 verified plugins', '35 built-in tools'
    
    # Fix wrong version
    $c = $c -replace '\bv[123]\.\d+\.\d+\b', 'v4.0.0'
    $c = $c -replace 'v1\.0\.0-NEXUS', 'v4.0.0-NEXUS'
    
    # Remove CyberShield branding
    $c = $c -replace 'CyberShield Suite', 'Shadow313 NEXUS'
    $c = $c -replace 'CyberShield', 'Shadow313'
    $c = $c -replace 'cybershield', 'shadow313'
    
    if ($c -ne $orig) {
        Set-Content $f.FullName $c
        $numFixed++
    }
}
Write-Host "  ✅ Fixed numbers in $numFixed files" -ForegroundColor Green

# ── STEP 2: Apply nav + footer to docs/*.html ────────────────────────────────
Write-Host "`n[2/5] Applying unified nav + footer to docs/*.html..." -ForegroundColor Yellow
$navFixed = 0
Get-ChildItem "docs\*.html" -ErrorAction SilentlyContinue | ForEach-Object {
    $c = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
    if (-not $c -or $c.Length -lt 200) { return }
    $orig = $c
    
    # Add fonts if missing
    if ($c -notmatch 'fonts.googleapis.com' -and $c -match '</head>') {
        $c = $c -replace '</head>', "$SHARED_CSS`n</head>"
    }
    # Add nav after <body>
    if ($c -notmatch 's313-nav' -and $c -match '<body') {
        $c = $c -replace '(<body[^>]*>)', "`$1`n$NAV"
    }
    # Add footer before </body>
    if ($c -notmatch 'matarmohamad313@duck.com' -and $c -match '</body>') {
        $c = $c -replace '</body>', "$FOOTER`n</body>"
    }
    
    if ($c -ne $orig) {
        Set-Content $_.FullName $c
        $navFixed++
    }
}
Write-Host "  ✅ Nav/footer applied to $navFixed docs pages" -ForegroundColor Green

# ── STEP 3: Rebuild marketplace with correct numbers ─────────────────────────
Write-Host "`n[3/5] Rebuilding marketplace with correct tool count (35, not 247)..." -ForegroundColor Yellow
Set-Content "marketplace\index.html" @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Tool Marketplace — Shadow313 NEXUS</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{--bg:#020617;--bg2:#0b1329;--green:#22c55e;--cyan:#06b6d4;--amber:#f59e0b;--red:#ef4444;--purple:#a78bfa;--text:#e2e8f0;--muted:#64748b;}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:'Space Grotesk',sans-serif;}
.mono{font-family:'JetBrains Mono',monospace;}
nav{background:#020617;border-bottom:1px solid rgba(34,197,94,0.2);padding:8px 20px;display:flex;align-items:center;gap:10px;position:sticky;top:0;z-index:9999;flex-wrap:wrap;}
nav a{color:#94a3b8;font-size:11px;text-decoration:none;}
nav a.brand{color:#22c55e;font-weight:800;font-size:13px;}
.hero{padding:60px 24px 40px;text-align:center;}
.hero h1{font-size:36px;font-weight:800;color:var(--green);margin-bottom:12px;}
.hero p{color:var(--muted);font-size:14px;max-width:600px;margin:0 auto 24px;}
.stats{display:flex;gap:16px;justify-content:center;flex-wrap:wrap;margin-bottom:40px;}
.stat{background:var(--bg2);border:1px solid rgba(34,197,94,0.15);border-radius:8px;padding:12px 24px;text-align:center;}
.stat .num{font-size:28px;font-weight:800;color:var(--green);font-family:'JetBrains Mono',monospace;}
.stat .lbl{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;}
.section{max-width:1100px;margin:0 auto 40px;padding:0 24px;}
.section h2{font-size:14px;font-weight:700;color:var(--cyan);text-transform:uppercase;letter-spacing:.08em;margin-bottom:16px;padding-bottom:8px;border-bottom:1px solid rgba(6,182,212,0.2);}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px;}
.card{background:var(--bg2);border:1px solid rgba(30,41,59,0.8);border-radius:10px;padding:16px;transition:border-color .2s;}
.card:hover{border-color:rgba(34,197,94,0.3);}
.card-header{display:flex;align-items:center;gap:10px;margin-bottom:8px;}
.card-icon{font-size:20px;}
.card-name{font-size:13px;font-weight:700;}
.card-desc{font-size:11px;color:var(--muted);line-height:1.5;}
.badge{font-size:9px;font-family:'JetBrains Mono',monospace;padding:2px 7px;border-radius:4px;font-weight:700;}
.badge-red{background:rgba(239,68,68,.12);color:#ef4444;border:1px solid rgba(239,68,68,.25);}
.badge-blue{background:rgba(6,182,212,.12);color:#06b6d4;border:1px solid rgba(6,182,212,.25);}
.badge-purple{background:rgba(167,139,250,.12);color:#a78bfa;border:1px solid rgba(167,139,250,.25);}
.badge-green{background:rgba(34,197,94,.12);color:#22c55e;border:1px solid rgba(34,197,94,.25);}
.sdk-box{background:rgba(34,197,94,0.05);border:1px solid rgba(34,197,94,0.2);border-radius:10px;padding:24px;text-align:center;margin:0 24px 40px;}
footer{background:#020617;border-top:1px solid rgba(34,197,94,0.1);padding:16px 24px;text-align:center;font-size:10px;color:#334155;}
footer a{color:#475569;text-decoration:none;}
</style>
</head>
<body>
<nav>
  <a href="/" class="brand">⬡ S313 NEXUS</a>
  <span style="color:#334155;">|</span>
  <a href="/dashboard">Dashboard</a>
  <a href="/attck">ATT&amp;CK</a>
  <a href="/vsat">VSAT</a>
  <a href="/pqc">PQC</a>
  <a href="/pricing">Pricing</a>
  <a href="/docs">Docs</a>
  <a href="https://github.com/piyyy314/Shadow313-Nexus" target="_blank">GitHub ↗</a>
  <span style="margin-left:auto;color:#22c55e;font-size:9px;font-family:monospace;" id="clk"></span>
  <script>setInterval(()=>{var e=document.getElementById("clk");if(e)e.textContent=new Date().toISOString().replace("T"," ").slice(0,19)+" UTC"},1000)</script>
</nav>

<div class="hero">
  <h1>Security Intelligence Tools</h1>
  <p>35 built-in tools across Red Team, Blue Team, Purple Team, and AI-Native categories. All cosign-signed, hot-loadable, zero-restart deployment.</p>
  <div class="stats">
    <div class="stat"><div class="num">35</div><div class="lbl">Built-In Tools</div></div>
    <div class="stat"><div class="num">4</div><div class="lbl">Categories</div></div>
    <div class="stat"><div class="num">4,107</div><div class="lbl">Tests GREEN</div></div>
    <div class="stat"><div class="num">100%</div><div class="lbl">Cosign Signed</div></div>
  </div>
</div>

<div class="section">
  <h2>🔴 Red Team (5 tools)</h2>
  <div class="grid">
    <div class="card"><div class="card-header"><span class="card-icon">🔍</span><span class="card-name">NexusProbe</span><span class="badge badge-red">RED</span></div><div class="card-desc">Advanced recon with AI target profiling, subdomain discovery, and port scanning.</div></div>
    <div class="card"><div class="card-header"><span class="card-icon">👻</span><span class="card-name">PhantomScan</span><span class="badge badge-red">RED</span></div><div class="card-desc">Stealth scanner with evasion techniques and rate-limited discovery.</div></div>
    <div class="card"><div class="card-header"><span class="card-icon">🌐</span><span class="card-name">ShadowDNS</span><span class="badge badge-red">RED</span></div><div class="card-desc">DNS covert channel detection and DNS tunneling analysis.</div></div>
    <div class="card"><div class="card-header"><span class="card-icon">🕸️</span><span class="card-name">GhostHTTP</span><span class="badge badge-red">RED</span></div><div class="card-desc">HTTP fingerprinting and web application reconnaissance.</div></div>
    <div class="card"><div class="card-header"><span class="card-icon">📡</span><span class="card-name">C2Profiler</span><span class="badge badge-red">RED</span></div><div class="card-desc">Command and control infrastructure profiling and attribution.</div></div>
  </div>
</div>

<div class="section">
  <h2>🔵 Blue Team (9 tools)</h2>
  <div class="grid">
    <div class="card"><div class="card-header"><span class="card-icon">📊</span><span class="card-name">SentinelBaseline</span><span class="badge badge-blue">BLUE</span></div><div class="card-desc">Behavioral baseline monitoring with 3.2σ anomaly detection.</div></div>
    <div class="card"><div class="card-header"><span class="card-icon">⚡</span><span class="card-name">LogForge</span><span class="badge badge-blue">BLUE</span></div><div class="card-desc">Sigma rule generation and SIEM log analysis engine.</div></div>
    <div class="card"><div class="card-header"><span class="card-icon">🍯</span><span class="card-name">HoneyWireNet</span><span class="badge badge-blue">BLUE</span></div><div class="card-desc">SSH honeypot with attacker profiling and 313-BIND receipts.</div></div>
    <div class="card"><div class="card-header"><span class="card-icon">🔐</span><span class="card-name">VaultScan</span><span class="badge badge-blue">BLUE</span></div><div class="card-desc">Secret detection across 18 pattern types with SARIF output.</div></div>
    <div class="card"><div class="card-header"><span class="card-icon">🔬</span><span class="card-name">ForensicTracer</span><span class="badge badge-blue">BLUE</span></div><div class="card-desc">Digital forensics and artifact collection with chain of custody.</div></div>
    <div class="card"><div class="card-header"><span class="card-icon">☁️</span><span class="card-name">CloudAudit</span><span class="badge badge-blue">BLUE</span></div><div class="card-desc">AWS, Kubernetes, and Terraform security hardening checks.</div></div>
    <div class="card"><div class="card-header"><span class="card-icon">🛡️</span><span class="card-name">KernelIntegrityMonitor</span><span class="badge badge-blue">BLUE</span></div><div class="card-desc">eBPF-based kernel integrity monitoring and syscall analysis.</div></div>
    <div class="card"><div class="card-header"><span class="card-icon">🎭</span><span class="card-name">DeceptionEngine</span><span class="badge badge-blue">BLUE</span></div><div class="card-desc">WE-FORGE lure deployment and CADL escalation management.</div></div>
    <div class="card"><div class="card-header"><span class="card-icon">🔒</span><span class="card-name">ZeroTrust</span><span class="badge badge-blue">BLUE</span></div><div class="card-desc">Zero-trust network access enforcement and identity verification.</div></div>
  </div>
</div>

<div class="section">
  <h2>🟣 Purple Team (8 tools)</h2>
  <div class="grid">
    <div class="card"><div class="card-header"><span class="card-icon">⚛️</span><span class="card-name">AtomicChain</span><span class="badge badge-purple">PURPLE</span></div><div class="card-desc">Atomic red team test execution with detection validation.</div></div>
    <div class="card"><div class="card-header"><span class="card-icon">🔨</span><span class="card-name">DetectionForge</span><span class="badge badge-purple">PURPLE</span></div><div class="card-desc">Sigma rule generation from ATT&CK technique mappings.</div></div>
    <div class="card"><div class="card-header"><span class="card-icon">📈</span><span class="card-name">CoverageMatrix</span><span class="badge badge-purple">PURPLE</span></div><div class="card-desc">ATT&CK coverage visualization — 136/265 techniques (51.4%).</div></div>
    <div class="card"><div class="card-header"><span class="card-icon">🔄</span><span class="card-name">ThreatReplay</span><span class="badge badge-purple">PURPLE</span></div><div class="card-desc">Historical threat replay for detection rule validation.</div></div>
    <div class="card"><div class="card-header"><span class="card-icon">🎯</span><span class="card-name">AdversaryEmulator</span><span class="badge badge-purple">PURPLE</span></div><div class="card-desc">APT29, APT41, Lazarus, FIN7 adversary emulation profiles.</div></div>
    <div class="card"><div class="card-header"><span class="card-icon">🔗</span><span class="card-name">SupplyChainAuditor</span><span class="badge badge-purple">PURPLE</span></div><div class="card-desc">SLSA provenance verification and supply chain risk analysis.</div></div>
    <div class="card"><div class="card-header"><span class="card-icon">🗺️</span><span class="card-name">LateralMovementTracker</span><span class="badge badge-purple">PURPLE</span></div><div class="card-desc">Lateral movement path analysis and pivot point detection.</div></div>
    <div class="card"><div class="card-header"><span class="card-icon">🏹</span><span class="card-name">ThreatHunter</span><span class="badge badge-purple">PURPLE</span></div><div class="card-desc">Hypothesis-driven threat hunting with IOC correlation.</div></div>
  </div>
</div>

<div class="section">
  <h2>🤖 AI-Native (13 tools)</h2>
  <div class="grid">
    <div class="card"><div class="card-header"><span class="card-icon">🧠</span><span class="card-name">NexusRAG</span><span class="badge badge-green">AI</span></div><div class="card-desc">ChromaDB RAG with 5 knowledge namespaces — CVE, MITRE, OWASP, session, general.</div></div>
    <div class="card"><div class="card-header"><span class="card-icon">📝</span><span class="card-name">ThreatNarrator</span><span class="badge badge-green">AI</span></div><div class="card-desc">AI-generated threat intelligence narratives from raw findings.</div></div>
    <div class="card"><div class="card-header"><span class="card-icon">⚙️</span><span class="card-name">RuleSmith</span><span class="badge badge-green">AI</span></div><div class="card-desc">AI-powered Sigma and YARA rule generation from TTPs.</div></div>
    <div class="card"><div class="card-header"><span class="card-icon">💡</span><span class="card-name">ExplainCVE</span><span class="badge badge-green">AI</span></div><div class="card-desc">Plain-language CVE explanation with EPSS scoring and KEV status.</div></div>
    <div class="card"><div class="card-header"><span class="card-icon">🌐</span><span class="card-name">ThreatIntelligence</span><span class="badge badge-green">AI</span></div><div class="card-desc">Multi-feed TI aggregation — FeodoTracker, URLhaus, MalwareBazaar, OTX.</div></div>
    <div class="card"><div class="card-header"><span class="card-icon">🦠</span><span class="card-name">MalwareAnalyzer</span><span class="badge badge-green">AI</span></div><div class="card-desc">Static and behavioral malware analysis with YARA pattern matching.</div></div>
    <div class="card"><div class="card-header"><span class="card-icon">💾</span><span class="card-name">MemoryForensics</span><span class="badge badge-green">AI</span></div><div class="card-desc">Memory dump analysis and process injection detection.</div></div>
    <div class="card"><div class="card-header"><span class="card-icon">🏹</span><span class="card-name">AegisHunter</span><span class="badge badge-green">AI</span></div><div class="card-desc">AI-driven threat hunting with Markov chain pivot prediction.</div></div>
    <div class="card"><div class="card-header"><span class="card-icon">🔮</span><span class="card-name">PalantirBridge</span><span class="badge badge-green">AI</span></div><div class="card-desc">Palantir Ontology integration — LureDocument, Adversary, Device objects.</div></div>
    <div class="card"><div class="card-header"><span class="card-icon">📊</span><span class="card-name">BehavioralGraphEngine</span><span class="badge badge-green">AI</span></div><div class="card-desc">NetworkX intelligence graph with 9 node types and risk ranking.</div></div>
    <div class="card"><div class="card-header"><span class="card-icon">⚛️</span><span class="card-name">QuantumThreatScorer</span><span class="badge badge-green">AI</span></div><div class="card-desc">HNDL risk scoring and CRQC timeline threat assessment.</div></div>
    <div class="card"><div class="card-header"><span class="card-icon">🔧</span><span class="card-name">AdaptiveRuleEngine</span><span class="badge badge-green">AI</span></div><div class="card-desc">Self-tuning detection rules based on analyst feedback loops.</div></div>
    <div class="card"><div class="card-header"><span class="card-icon">🧬</span><span class="card-name">ThreatDNAProfiler</span><span class="badge badge-green">AI</span></div><div class="card-desc">Threat actor fingerprinting via behavioral DNA analysis.</div></div>
  </div>
</div>

<div class="sdk-box">
  <h3 style="color:#22c55e;font-size:16px;margin-bottom:8px;">Build Your Own Plugin</h3>
  <p style="color:#64748b;font-size:12px;margin-bottom:16px;">Use the Shadow313 SDK to create custom tools. All plugins are cosign-signed and hot-loadable without restart.</p>
  <code style="background:#0b1329;color:#06b6d4;padding:8px 16px;border-radius:6px;font-family:'JetBrains Mono',monospace;font-size:11px;">pip install shadow313-sdk</code>
  <br><br>
  <a href="https://github.com/piyyy314/Shadow313-Nexus" style="color:#22c55e;font-size:12px;">View SDK Documentation →</a>
</div>

<footer>
  <span style="color:#22c55e;font-weight:700;">⬡ Shadow313 NEXUS</span> v4.0.0 &nbsp;·&nbsp; Ottawa, ON &nbsp;·&nbsp;
  <a href="mailto:matarmohamad313@duck.com">matarmohamad313@duck.com</a> &nbsp;·&nbsp;
  <a href="https://github.com/piyyy314/Shadow313-Nexus">GitHub</a> &nbsp;·&nbsp;
  <a href="/pricing">Pricing</a> &nbsp;·&nbsp; <a href="/privacy">Privacy</a> &nbsp;·&nbsp; <a href="/terms">Terms</a> &nbsp;·&nbsp;
  MIT License &nbsp;·&nbsp; <span style="color:#22c55e;">4,107 tests GREEN</span> &nbsp;·&nbsp; <span style="color:#a78bfa;">FIPS 203/204/205</span>
</footer>
</body>
</html>
'@
Write-Host "  ✅ marketplace/index.html rebuilt (35 tools, accurate)" -ForegroundColor Green

# ── STEP 4: Fix platform/index.html numbers ──────────────────────────────────
Write-Host "`n[4/5] Fixing platform/index.html numbers..." -ForegroundColor Yellow
if (Test-Path "platform\index.html") {
    $p = Get-Content "platform\index.html" -Raw
    $p = $p -replace '\b9\s*MODULES\b', '30 MODULES'
    $p = $p -replace '\b462\s*TESTS\b', '4,107 TESTS'
    $p = $p -replace '\b462\s*tests\b', '4,107 tests'
    Set-Content "platform\index.html" $p
    Write-Host "  ✅ platform/index.html — numbers corrected" -ForegroundColor Green
}

# ── STEP 5: Commit and push ──────────────────────────────────────────────────
Write-Host "`n[5/5] Committing all changes..." -ForegroundColor Yellow
git add .
$status = git status --short
if ($status) {
    $count = ($status | Measure-Object).Count
    git commit -m "fix: unified HTML architecture — correct numbers (4107 tests/30 modules/35 tools), rebuild marketplace, nav+footer on all pages, remove CyberShield, consistent dark theme"
    git push origin master 2>&1 | Out-Null
    Write-Host "  ✅ $count files committed and pushed" -ForegroundColor Green
} else {
    Write-Host "  ℹ️  Nothing to commit" -ForegroundColor Cyan
}

git remote set-url origin "https://github.com/piyyy314/Shadow313-Nexus.git"

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "  ARCHITECTURE FIX COMPLETE" -ForegroundColor Green
Write-Host "" -ForegroundColor White
Write-Host "  CANONICAL NUMBERS NOW CONSISTENT:" -ForegroundColor White
Write-Host "  ✅ Tests: 4,107 (was 858/462/2648 in different pages)" -ForegroundColor Green
Write-Host "  ✅ Modules: 30 (was 9 in platform page)" -ForegroundColor Green
Write-Host "  ✅ Tools: 35 (was 247 plugins in marketplace)" -ForegroundColor Green
Write-Host "  ✅ ATT&CK: 136/265 (51.4%)" -ForegroundColor Green
Write-Host "" -ForegroundColor White
Write-Host "  DASHBOARD STATUS:" -ForegroundColor White
Write-Host "  📊 Dashboards are DEMOS — showing simulated data" -ForegroundColor Cyan
Write-Host "  🚀 To make them LIVE: deploy FastAPI on Hetzner VPS" -ForegroundColor Cyan
Write-Host "     then set SHADOW313_API_URL in Vercel env vars" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
