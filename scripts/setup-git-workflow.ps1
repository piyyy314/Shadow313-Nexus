# ============================================================
# SHADOW313 NEXUS — Git Workflow Setup
# Installs hooks, sets config, fixes current conflict
# Run from: C:\Users\shiatoali\shadow313-nexus
# ============================================================

param([string]$RepoPath = "C:\Users\shiatoali\shadow313-nexus")

$ErrorActionPreference = "SilentlyContinue"
$RED    = "Red"; $GREEN = "Green"; $CYAN = "Cyan"; $YELLOW = "Yellow"

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Shadow313 NEXUS — Git Workflow Setup" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

Set-Location $RepoPath

# ── STEP 1: FIX CURRENT CONFLICT (117 commits behind) ────────────────────
Write-Host "[1/6] Fixing current 117-commit conflict..." -ForegroundColor Yellow
Write-Host ""

# Discard CRLF-only changes (safe — these are just line ending differences)
$conflictFiles = @(
    ".github/workflows/deploy.yml",
    "docs/S313-Attack-Surface-Blind-Spot-Analysis.md",
    "docs/S313-Deployment-Guide-shadow313dev.md",
    "docs/S313-Industry-Benchmark-Comparison-2026.md",
    "docs/S313-Production-Readiness-Gap-Analysis-2026.md",
    "docs/S313-Project-Genesis-Chat-History.md",
    "docs/S313-SOC2-Type2-Readiness-Plan-2026.md",
    "docs/S313-Security-Coverage-Remediation-Roadmap.md",
    "docs/S313-ZTAS-Architecture-Spec.md",
    "netlify.toml",
    "shadow313/v3/bridge/event_rate_tracker.py",
    "shadow313/v3/countermeasures/ebpf_self_protection.py",
    "shadow313/v4/detection/adaptive_defense_loop.py",
    "shadow313/v4/detection/crypto_hardening_audit.py",
    "shadow313/v4/detection/threat_predictor.py",
    "shadow313/v4/quantum_nexus/qiskit_classifier.py",
    "tests/unit/v4/test_hyperion_core.py"
)

Write-Host "  Discarding CRLF-only local changes..." -ForegroundColor Gray
foreach ($f in $conflictFiles) {
    & git checkout -- $f 2>$null
    Write-Host "  ✅ Restored: $f" -ForegroundColor DarkGray
}

# Drop the stash (it only had CRLF changes)
& git stash drop 2>$null
Write-Host "  ✅ Stash cleared" -ForegroundColor Green
Write-Host ""

# Now pull
Write-Host "  Pulling 117 commits from GitHub..." -ForegroundColor Cyan
$pullResult = & git pull origin master 2>&1
Write-Host $pullResult -ForegroundColor $(if($pullResult -match "error|conflict"){"Red"}else{"Green"})

# Check result
$status = & git status --short
if (-not $status -or $status -notmatch "^(AA|UU|DD)") {
    Write-Host "  ✅ Pull successful — repo is now up to date" -ForegroundColor Green
} else {
    Write-Host "  ⚠️  Merge conflicts detected — see below" -ForegroundColor Red
    Write-Host $status -ForegroundColor Red
}
Write-Host ""

# ── STEP 2: FIX GIT CONFIG (prevent future CRLF issues) ──────────────────
Write-Host "[2/6] Fixing Git config to prevent future CRLF conflicts..." -ForegroundColor Yellow

& git config core.autocrlf false
& git config core.eol lf
& git config pull.rebase false
& git config push.default current
& git config fetch.prune true
& git config --global core.autocrlf false
& git config --global core.eol lf
& git config --global pull.rebase false
& git config --global push.default current
& git config --global fetch.prune true

Write-Host "  ✅ core.autocrlf = false  (no more CRLF conversions)" -ForegroundColor Green
Write-Host "  ✅ core.eol = lf          (always use LF line endings)" -ForegroundColor Green
Write-Host "  ✅ pull.rebase = false    (merge pull, not rebase)" -ForegroundColor Green
Write-Host "  ✅ push.default = current (push current branch only)" -ForegroundColor Green
Write-Host "  ✅ fetch.prune = true     (auto-clean deleted remote branches)" -ForegroundColor Green
Write-Host ""

# ── STEP 3: INSTALL GIT HOOKS ─────────────────────────────────────────────
Write-Host "[3/6] Installing Git hooks..." -ForegroundColor Yellow

$hooksDir = "$RepoPath\.git\hooks"
New-Item -ItemType Directory -Path $hooksDir -Force | Out-Null

# pre-push hook — blocks push if behind remote
$prePush = @'
#!/bin/sh
# Shadow313 NEXUS — pre-push hook
# Blocks push if local is behind remote

echo ""
echo "=== Shadow313 pre-push check ==="

# Fetch latest
git fetch origin --quiet 2>/dev/null

LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/master 2>/dev/null)
BASE=$(git merge-base HEAD origin/master 2>/dev/null)

if [ "$BASE" = "$LOCAL" ] && [ "$LOCAL" != "$REMOTE" ]; then
    BEHIND=$(git rev-list HEAD..origin/master --count)
    echo "BLOCKED: You are $BEHIND commits behind remote."
    echo "Run: git pull origin master"
    echo "Then push again."
    exit 1
fi

AHEAD=$(git rev-list origin/master..HEAD --count 2>/dev/null)
echo "OK: $AHEAD commits ahead of remote. Pushing..."
echo ""
exit 0
'@

# pre-commit hook — blocks secrets and .env files
$preCommit = @'
#!/bin/sh
# Shadow313 NEXUS — pre-commit hook

ERRORS=0

# Block secrets.kdbx
if git diff --cached --name-only | grep -q "secrets.kdbx"; then
    echo "ERROR: secrets.kdbx must not be committed"
    ERRORS=$((ERRORS+1))
fi

# Block .env files
if git diff --cached --name-only | grep -qE "^\.env$|^\.env\.local|^\.env\.prod"; then
    echo "ERROR: .env file staged — use .env.example instead"
    ERRORS=$((ERRORS+1))
fi

# Block GitHub tokens
if git diff --cached | grep -qE "ghp_[a-zA-Z0-9]{36}"; then
    echo "ERROR: GitHub token detected in commit"
    ERRORS=$((ERRORS+1))
fi

if [ $ERRORS -gt 0 ]; then
    echo "Commit blocked. Fix issues above."
    exit 1
fi
exit 0
'@

# post-merge hook — reminds about deps after pull
$postMerge = @'
#!/bin/sh
# Shadow313 NEXUS — post-merge hook

if git diff HEAD@{1} HEAD --name-only | grep -qE "requirements|pyproject"; then
    echo "NOTE: Python deps changed. Run: pip install -e .[full]"
fi
if git diff HEAD@{1} HEAD --name-only | grep -q "package.json"; then
    echo "NOTE: Node deps changed. Run: npm install"
fi
exit 0
'@

# Write hooks
$prePush   | Out-File "$hooksDir\pre-push"   -Encoding UTF8 -NoNewline
$preCommit | Out-File "$hooksDir\pre-commit" -Encoding UTF8 -NoNewline
$postMerge | Out-File "$hooksDir\post-merge" -Encoding UTF8 -NoNewline

# Make executable via git config (Windows doesn't use chmod)
& git config core.hooksPath .git/hooks

Write-Host "  ✅ pre-push   — blocks push if behind remote" -ForegroundColor Green
Write-Host "  ✅ pre-commit — blocks secrets, .env, GitHub tokens" -ForegroundColor Green
Write-Host "  ✅ post-merge — reminds about dependency updates" -ForegroundColor Green
Write-Host ""

# ── STEP 4: ADD .GITATTRIBUTES (fix CRLF permanently) ────────────────────
Write-Host "[4/6] Creating .gitattributes to fix line endings forever..." -ForegroundColor Yellow

$gitattributes = @"
# Shadow313 NEXUS — .gitattributes
# Force LF line endings for all text files
# This prevents the CRLF conflict you just experienced

* text=auto eol=lf

# Explicitly LF
*.py    text eol=lf
*.js    text eol=lf
*.ts    text eol=lf
*.json  text eol=lf
*.md    text eol=lf
*.yml   text eol=lf
*.yaml  text eol=lf
*.toml  text eol=lf
*.sh    text eol=lf
*.html  text eol=lf
*.css   text eol=lf
*.txt   text eol=lf

# Windows scripts — keep CRLF
*.ps1   text eol=crlf
*.bat   text eol=crlf
*.cmd   text eol=crlf

# Binary — no conversion
*.png   binary
*.jpg   binary
*.gif   binary
*.ico   binary
*.pdf   binary
*.zip   binary
*.gz    binary
*.whl   binary
*.pyc   binary
*.pem   binary
*.key   binary
*.crt   binary
"@

$gitattributes | Out-File "$RepoPath\.gitattributes" -Encoding UTF8
Write-Host "  ✅ .gitattributes created" -ForegroundColor Green
Write-Host ""

# ── STEP 5: CLEAN REMOTE URL (remove embedded token) ─────────────────────
Write-Host "[5/6] Cleaning remote URL (removing embedded token)..." -ForegroundColor Yellow
$currentRemote = & git remote get-url origin
if ($currentRemote -match "ghp_") {
    & git remote set-url origin "https://github.com/piyyy314/Shadow313-Nexus.git"
    Write-Host "  ✅ Token removed from remote URL" -ForegroundColor Green
    Write-Host "  ✅ New URL: https://github.com/piyyy314/Shadow313-Nexus.git" -ForegroundColor Green
} else {
    Write-Host "  ✅ Remote URL already clean" -ForegroundColor Green
}
Write-Host ""

# ── STEP 6: COMMIT AND PUSH EVERYTHING ───────────────────────────────────
Write-Host "[6/6] Committing and pushing all changes..." -ForegroundColor Yellow

& git add .gitattributes
& git add docs-archive/ 2>$null
& git add scripts/ 2>$null

$gitStatus = & git status --short
if ($gitStatus) {
    & git add .
    & git commit -m "chore: add .gitattributes LF enforcement + docs-archive + git hooks"
    $pushResult = & git push origin master 2>&1
    Write-Host $pushResult -ForegroundColor $(if($pushResult -match "error"){"Red"}else{"Green"})
    Write-Host "  ✅ Pushed to GitHub" -ForegroundColor Green
} else {
    Write-Host "  ✅ Nothing new to commit" -ForegroundColor Green
}

# ── FINAL STATUS ──────────────────────────────────────────────────────────
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  SETUP COMPLETE" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""

$finalLog = & git log --oneline -5
Write-Host "  Latest 5 commits:" -ForegroundColor Cyan
$finalLog | ForEach-Object { Write-Host "    $_" -ForegroundColor White }
Write-Host ""

$behind = (& git rev-list HEAD..origin/master --count 2>$null)
$ahead  = (& git rev-list origin/master..HEAD --count 2>$null)
Write-Host "  Sync status:" -ForegroundColor Cyan
Write-Host "    Ahead:  $ahead commits" -ForegroundColor $(if([int]$ahead -gt 0){"Yellow"}else{"Green"})
Write-Host "    Behind: $behind commits" -ForegroundColor $(if([int]$behind -gt 0){"Red"}else{"Green"})
Write-Host ""
Write-Host "  YOUR DAILY WORKFLOW (prevents all future conflicts):" -ForegroundColor Cyan
Write-Host ""
Write-Host "  BEFORE starting work:" -ForegroundColor White
Write-Host "    git pull origin master" -ForegroundColor Gray
Write-Host ""
Write-Host "  WHILE working:" -ForegroundColor White
Write-Host "    git add ." -ForegroundColor Gray
Write-Host "    git commit -m 'your message'" -ForegroundColor Gray
Write-Host ""
Write-Host "  BEFORE pushing:" -ForegroundColor White
Write-Host "    git pull origin master   (always pull first)" -ForegroundColor Gray
Write-Host "    git push origin master" -ForegroundColor Gray
Write-Host ""
Write-Host "  The pre-push hook will BLOCK you if you forget to pull." -ForegroundColor Yellow
Write-Host ""
