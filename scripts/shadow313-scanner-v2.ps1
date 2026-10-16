# ============================================================
# SHADOW313 NEXUS — Enhanced File Scanner v2.0
# Scans local files + GitHub repos (local clones + remote API)
# Usage: .\shadow313-scanner-v2.ps1 [-GitHubToken "ghp_xxx"]
# ============================================================
param(
    [string]$GitHubToken = "",
    [string]$GitHubUser  = "piyyy314",
    [string]$OutputDir   = "$env:USERPROFILE\Desktop"
)

$ErrorActionPreference = "SilentlyContinue"
$timestamp  = Get-Date -Format "yyyy-MM-dd_HH-mm"
$reportPath = "$OutputDir\shadow313-scan-v2-$timestamp.txt"
$csvPath    = "$OutputDir\shadow313-files-v2-$timestamp.csv"
$jsonPath   = "$OutputDir\shadow313-map-v2-$timestamp.json"

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  SHADOW313 NEXUS — Enhanced File Scanner v2.0" -ForegroundColor Cyan
Write-Host "  Local files + GitHub local clones + GitHub API" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# ── SECTION 1: LOCAL FILE SCAN ────────────────────────────────────────────
Write-Host "[1/3] Scanning local files..." -ForegroundColor Yellow

$searchRoots = @(
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\OneDrive",
    "$env:USERPROFILE\OneDrive\Desktop",
    "$env:USERPROFILE\OneDrive\Documents",
    "$env:USERPROFILE\shadow313",
    "$env:USERPROFILE\shadow313-nexus",
    "$env:USERPROFILE\shadow313-nexus-main",
    "C:\OneDrive",
    "C:\OneDrive\Desktop",
    "C:\OneDrive\Documents",
    "C:\shadow313",
    "C:\shadow313-nexus"
)

$s313Patterns = @(
    "shadow313*","*shadow313*","*nexus*","*s313*",
    "*vsat*","*aegis*","*ghost-watch*","*ghost_watch*",
    "*313-bind*","*nvsm*","*attck*","*pqc*",
    "*sovereign*","*temporal*","Modelfile",
    "pyproject.toml","vercel.json","docker-compose.yml",
    "*.shadow313sig","*_shadow313*","*ghostwatch*"
)

$allFiles = [System.Collections.Generic.List[PSCustomObject]]::new()
$seenPaths = [System.Collections.Generic.HashSet[string]]::new()

foreach ($root in $searchRoots) {
    if (-not (Test-Path $root)) { continue }
    Write-Host "   Scanning: $root" -ForegroundColor DarkGray
    foreach ($pattern in $s313Patterns) {
        try {
            Get-ChildItem -Path $root -Filter $pattern -Recurse -File -Force 2>$null | ForEach-Object {
                if ($seenPaths.Add($_.FullName)) {
                    $allFiles.Add([PSCustomObject]@{
                        Name      = $_.Name; Extension = $_.Extension
                        SizeKB    = [math]::Round($_.Length/1KB,1)
                        SizeMB    = [math]::Round($_.Length/1MB,2)
                        FullPath  = $_.FullName; Directory = $_.DirectoryName
                        Modified  = $_.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
                        Hash      = ""; Source = "local"; GitRepo = ""
                    })
                }
            }
        } catch {}
    }
}

# Scan HTML files by content in key dirs
@("$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop",
  "$env:USERPROFILE\OneDrive\Desktop","C:\OneDrive\Desktop") | ForEach-Object {
    if (-not (Test-Path $_)) { return }
    Get-ChildItem -Path $_ -Filter "*.html" -File -Force 2>$null | ForEach-Object {
        if ($seenPaths.Contains($_.FullName)) { return }
        $c = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
        if ($c -match "shadow313|Shadow313|NEXUS|s313|vsat|aegis|ghost.watch") {
            if ($seenPaths.Add($_.FullName)) {
                $allFiles.Add([PSCustomObject]@{
                    Name=$_.Name;Extension=$_.Extension
                    SizeKB=[math]::Round($_.Length/1KB,1);SizeMB=[math]::Round($_.Length/1MB,2)
                    FullPath=$_.FullName;Directory=$_.DirectoryName
                    Modified=$_.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
                    Hash="";Source="local";GitRepo=""
                })
            }
        }
    }
}

Write-Host "   Found $($allFiles.Count) local files" -ForegroundColor Green

# ── SECTION 2: LOCAL GIT REPO SCAN ───────────────────────────────────────
Write-Host ""
Write-Host "[2/3] Scanning local Git repository clones..." -ForegroundColor Yellow

$gitSearchDirs = @(
    "$env:USERPROFILE",
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\Desktop",
    "C:\",
    "C:\Users\shiatoali"
)

$localRepos = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($dir in $gitSearchDirs) {
    if (-not (Test-Path $dir)) { continue }
    try {
        Get-ChildItem -Path $dir -Filter ".git" -Recurse -Directory -Force -Depth 4 2>$null | ForEach-Object {
            $repoPath = $_.Parent.FullName
            $repoName = $_.Parent.Name

            # Get remote URL
            $remoteUrl = ""
            $branch    = ""
            $lastCommit= ""
            $commitMsg = ""
            try {
                $remoteUrl  = & git -C $repoPath remote get-url origin 2>$null
                $branch     = & git -C $repoPath branch --show-current 2>$null
                $lastCommit = & git -C $repoPath log -1 --format="%ai" 2>$null
                $commitMsg  = & git -C $repoPath log -1 --format="%s" 2>$null
            } catch {}

            # Count files
            $fileCount = (Get-ChildItem -Path $repoPath -Recurse -File -Force 2>$null |
                Where-Object { $_.FullName -notmatch "\\\.git\\" }).Count

            $isShadow313 = ($repoName -match "shadow313|nexus|s313" -or
                            $remoteUrl -match "shadow313|nexus|s313|piyyy314|matarmohamad|baalbek313")

            $localRepos.Add([PSCustomObject]@{
                RepoName    = $repoName
                Path        = $repoPath
                RemoteURL   = $remoteUrl
                Branch      = $branch
                LastCommit  = $lastCommit
                LastMessage = $commitMsg
                FileCount   = $fileCount
                IsShadow313 = $isShadow313
            })

            if ($isShadow313) {
                Write-Host "   ✅ Shadow313 repo: $repoName ($fileCount files)" -ForegroundColor Green
                Write-Host "      Path:   $repoPath" -ForegroundColor DarkGray
                Write-Host "      Remote: $remoteUrl" -ForegroundColor DarkGray
                Write-Host "      Branch: $branch | Last: $lastCommit" -ForegroundColor DarkGray
            } else {
                Write-Host "   📁 Other repo: $repoName" -ForegroundColor DarkGray
            }
        }
    } catch {}
}

$s313Repos = $localRepos | Where-Object { $_.IsShadow313 }
Write-Host "   Found $($localRepos.Count) total repos, $($s313Repos.Count) Shadow313-related" -ForegroundColor Green

# ── SECTION 3: GITHUB API SCAN ────────────────────────────────────────────
Write-Host ""
Write-Host "[3/3] Querying GitHub API..." -ForegroundColor Yellow

$remoteRepos = [System.Collections.Generic.List[PSCustomObject]]::new()
$apiError    = ""

$headers = @{ "User-Agent" = "Shadow313-Scanner/2.0"; "Accept" = "application/vnd.github.v3+json" }
if ($GitHubToken -ne "") {
    $headers["Authorization"] = "Bearer $GitHubToken"
    Write-Host "   Using provided GitHub token" -ForegroundColor Green
} else {
    Write-Host "   No token provided — scanning public repos only" -ForegroundColor Yellow
    Write-Host "   Tip: Run with -GitHubToken 'ghp_xxx' for private repos" -ForegroundColor DarkGray
}

# Query repos for the user
$usernames = @($GitHubUser, "matarmohamad313", "baalbek313", "piyyy314") | Select-Object -Unique
foreach ($user in $usernames) {
    try {
        $url  = "https://api.github.com/users/$user/repos?per_page=100&sort=updated"
        $resp = Invoke-RestMethod -Uri $url -Headers $headers -TimeoutSec 15 -ErrorAction Stop
        foreach ($repo in $resp) {
            $isShadow313 = ($repo.name -match "shadow313|nexus|s313|vsat|aegis|ghost" -or
                            $repo.description -match "shadow313|nexus|security|pqc|quantum")
            $remoteRepos.Add([PSCustomObject]@{
                Owner       = $user
                RepoName    = $repo.name
                FullName    = $repo.full_name
                Description = $repo.description
                Private     = $repo.private
                Stars       = $repo.stargazers_count
                Forks       = $repo.forks_count
                Language    = $repo.language
                Size_KB     = $repo.size
                UpdatedAt   = $repo.updated_at
                CloneURL    = $repo.clone_url
                HTMLURL     = $repo.html_url
                DefaultBranch = $repo.default_branch
                IsShadow313 = $isShadow313
            })
        }
        Write-Host "   ✅ $user — $($resp.Count) repos found" -ForegroundColor Green
    } catch {
        $apiError += "   ⚠️  Could not reach GitHub API for $user`: $_`n"
        Write-Host "   ⚠️  Could not reach GitHub for $user (check token/network)" -ForegroundColor Yellow
    }
}

$s313Remote = $remoteRepos | Where-Object { $_.IsShadow313 }
Write-Host "   Found $($remoteRepos.Count) total remote repos, $($s313Remote.Count) Shadow313-related" -ForegroundColor Green

# ── COMPUTE HASHES ────────────────────────────────────────────────────────
Write-Host ""
Write-Host "Computing MD5 hashes for duplicate detection..." -ForegroundColor Gray
$i = 0
foreach ($f in $allFiles) {
    $i++
    if ($i % 30 -eq 0) { Write-Host "  $i/$($allFiles.Count) hashed..." -ForegroundColor DarkGray }
    try { $f.Hash = (Get-FileHash $f.FullPath -Algorithm MD5 -ErrorAction SilentlyContinue).Hash } catch {}
}

# ── DUPLICATE ANALYSIS ────────────────────────────────────────────────────
$byHash      = $allFiles | Where-Object { $_.Hash } | Group-Object Hash
$exactDups   = $byHash | Where-Object { $_.Count -gt 1 }
$byName      = $allFiles | Group-Object Name
$nameDups    = $byName | Where-Object { $_.Count -gt 1 } |
               Where-Object { ($_.Group | Select-Object -ExpandProperty Hash | Sort-Object -Unique).Count -gt 1 }

# ── BUILD REPORT ──────────────────────────────────────────────────────────
$sb = [System.Text.StringBuilder]::new()
function Add($line) { $sb.AppendLine($line) | Out-Null }

Add "============================================================"
Add "  SHADOW313 NEXUS — Enhanced File Scan Report v2.0"
Add "  Generated: $(Get-Date)"
Add "  Computer:  $env:COMPUTERNAME | User: $env:USERNAME"
Add "============================================================"
Add ""
Add "SUMMARY"
Add "-------"
Add "  Local files found:        $($allFiles.Count)"
Add "  Local Git repos found:    $($localRepos.Count)"
Add "  Shadow313 local repos:    $($s313Repos.Count)"
Add "  Remote GitHub repos:      $($remoteRepos.Count)"
Add "  Shadow313 remote repos:   $($s313Remote.Count)"
Add "  Exact duplicates:         $($exactDups.Count) groups"
Add "  Version conflicts:        $($nameDups.Count) groups"
$totalMB = [math]::Round(($allFiles | Measure-Object SizeMB -Sum).Sum, 1)
Add "  Total local size:         $totalMB MB"
Add ""

# ── LOCAL GIT REPOS ───────────────────────────────────────────────────────
Add "============================================================"
Add "  LOCAL GIT REPOSITORY CLONES"
Add "============================================================"
Add ""
Add "  Shadow313-Related Repos:"
foreach ($r in $s313Repos) {
    Add "  ✅ $($r.RepoName)"
    Add "     Path:    $($r.Path)"
    Add "     Remote:  $($r.RemoteURL)"
    Add "     Branch:  $($r.Branch)"
    Add "     Commit:  $($r.LastCommit) — $($r.LastMessage)"
    Add "     Files:   $($r.FileCount)"
    Add ""
}
if ($s313Repos.Count -eq 0) { Add "  None found in scanned directories." }
Add ""
Add "  Other Repos Found:"
foreach ($r in ($localRepos | Where-Object { -not $_.IsShadow313 })) {
    Add "  📁 $($r.RepoName) — $($r.Path)"
}
Add ""

# ── REMOTE GITHUB REPOS ───────────────────────────────────────────────────
Add "============================================================"
Add "  REMOTE GITHUB REPOSITORIES"
Add "============================================================"
Add ""
if ($apiError) { Add $apiError }
Add "  Shadow313-Related Remote Repos:"
foreach ($r in $s313Remote) {
    $priv = if ($r.Private) { "[PRIVATE]" } else { "[PUBLIC]" }
    Add "  ✅ $($r.FullName) $priv"
    Add "     Description: $($r.Description)"
    Add "     Language:    $($r.Language) | Size: $($r.Size_KB) KB | Stars: $($r.Stars)"
    Add "     Updated:     $($r.UpdatedAt)"
    Add "     Clone URL:   $($r.CloneURL)"
    Add "     Web URL:     $($r.HTMLURL)"
    Add "     Branch:      $($r.DefaultBranch)"
    Add ""
}
if ($s313Remote.Count -eq 0) { Add "  None found (check token or network)." }
Add ""
Add "  All Other Remote Repos:"
foreach ($r in ($remoteRepos | Where-Object { -not $_.IsShadow313 })) {
    Add "  📁 $($r.FullName) — $($r.Language) — Updated: $($r.UpdatedAt)"
}
Add ""

# ── SYNC STATUS ───────────────────────────────────────────────────────────
Add "============================================================"
Add "  LOCAL vs REMOTE SYNC STATUS"
Add "============================================================"
Add ""
foreach ($remote in $s313Remote) {
    $localMatch = $s313Repos | Where-Object { $_.RemoteURL -match $remote.RepoName }
    if ($localMatch) {
        Add "  ✅ SYNCED: $($remote.RepoName)"
        Add "     Local:  $($localMatch.Path)"
        Add "     Remote: $($remote.HTMLURL)"
        Add "     Local branch: $($localMatch.Branch) | Last commit: $($localMatch.LastCommit)"
    } else {
        Add "  ⚠️  NOT CLONED LOCALLY: $($remote.RepoName)"
        Add "     Clone with: git clone $($remote.CloneURL)"
    }
    Add ""
}

# ── DUPLICATES ────────────────────────────────────────────────────────────
Add "============================================================"
Add "  EXACT DUPLICATES (same content, different locations)"
Add "============================================================"
Add ""
if ($exactDups.Count -eq 0) {
    Add "  No exact duplicates found."
} else {
    foreach ($grp in $exactDups) {
        Add "  [DUPLICATE] $($grp.Count) copies — $($grp.Group[0].Name)"
        foreach ($f in $grp.Group) { Add "    $($f.Modified)  $($f.SizeKB) KB  $($f.FullPath)" }
        $newest = $grp.Group | Sort-Object Modified -Descending | Select-Object -First 1
        Add "    → KEEP: $($newest.FullPath)"
        Add ""
    }
}

# ── VERSION CONFLICTS ─────────────────────────────────────────────────────
Add "============================================================"
Add "  VERSION CONFLICTS (same name, different content)"
Add "============================================================"
Add ""
if ($nameDups.Count -eq 0) {
    Add "  No version conflicts found."
} else {
    foreach ($grp in $nameDups) {
        Add "  [CONFLICT] '$($grp.Name)' — $($grp.Count) different versions"
        foreach ($f in ($grp.Group | Sort-Object Modified -Descending)) {
            Add "    $($f.Modified)  $($f.SizeKB) KB  $($f.FullPath)"
        }
        $newest = $grp.Group | Sort-Object Modified -Descending | Select-Object -First 1
        Add "    → NEWEST: $($newest.FullPath)"
        Add ""
    }
}

# ── FILE INVENTORY ────────────────────────────────────────────────────────
Add "============================================================"
Add "  COMPLETE FILE INVENTORY BY TYPE"
Add "============================================================"
Add ""
$types = @{
    "HTML Dashboards" = ($allFiles | Where-Object { $_.Extension -eq ".html" })
    "Python Modules"  = ($allFiles | Where-Object { $_.Extension -eq ".py" })
    "JSON Files"      = ($allFiles | Where-Object { $_.Extension -eq ".json" })
    "Markdown/Text"   = ($allFiles | Where-Object { $_.Extension -in @(".md",".txt") })
    "Documents"       = ($allFiles | Where-Object { $_.Extension -in @(".docx",".pdf",".pptx",".xlsx") })
    "Config Files"    = ($allFiles | Where-Object { $_.Extension -in @(".toml",".yml",".yaml",".env",".ps1") })
}
foreach ($type in $types.Keys) {
    $group = $types[$type]
    Add "  $type ($($group.Count) files):"
    foreach ($f in ($group | Sort-Object Directory, Name)) {
        Add "    $($f.Modified)  $($f.SizeKB) KB  $($f.FullPath)"
    }
    Add ""
}

# ── CONSOLIDATION PLAN ────────────────────────────────────────────────────
Add "============================================================"
Add "  RECOMMENDED CONSOLIDATION PLAN"
Add "============================================================"
Add ""
Add "  SINGLE SOURCE OF TRUTH:"
Add "  C:\Users\$env:USERNAME\shadow313-nexus\"
Add "  (Your GitHub clone — push here, Vercel deploys automatically)"
Add ""
Add "  TARGET STRUCTURE:"
Add "  shadow313-nexus\"
Add "  ├── docs\              ← All HTML dashboards (90+ files)"
Add "  ├── shadow313\         ← Python source (v1-v4 + nexus_toolkit)"
Add "  ├── ollama\            ← Modelfile + deploy scripts"
Add "  ├── docker\            ← docker-compose.yml + nginx configs"
Add "  ├── scripts\           ← PowerShell + bash utilities"
Add "  ├── docs-archive\      ← Old/duplicate documents"
Add "  ├── vercel.json        ← 158 route rewrites"
Add "  └── pyproject.toml     ← Python package config"
Add ""
Add "  IMMEDIATE ACTIONS:"
Add "  1. Fix git author:"
Add "     git config user.name 'piyyy314'"
Add "     git config user.email 'matarmohamad313@duck.com'"
Add ""
Add "  2. Push all files to GitHub:"
Add "     cd C:\Users\shiatoali\shadow313-nexus"
Add "     git add ."
Add "     git commit -m 'Consolidation: all HTML dashboards + modules'"
Add "     git push origin master"
Add ""
Add "  3. Vercel auto-deploys → shadow313.dev has all files"
Add "  4. Download any file from shadow313.dev (no Stride limitations)"
Add ""
Add "  5. Run shadow313-consolidator.ps1 to auto-move files"
Add "     (generated alongside this scanner)"
Add ""
Add "  WHY HTML STOPPED DOWNLOADING FROM STRIDE:"
Add "  The Stride/Office Agent side panel shows completion message"
Add "  text only — it cannot render or trigger HTML downloads."
Add "  This is a Stride interface limitation, not a file problem."
Add "  Solution: Push to GitHub → download from shadow313.dev"
Add ""

# ── WRITE FILES ───────────────────────────────────────────────────────────
$sb.ToString() | Out-File -FilePath $reportPath -Encoding UTF8
$allFiles | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

# JSON map for consolidator script
$map = @{
    timestamp    = $timestamp
    localFiles   = $allFiles | ForEach-Object { @{
        name=$_.Name; path=$_.FullPath; dir=$_.Directory
        sizeKB=$_.SizeKB; modified=$_.Modified; hash=$_.Hash; ext=$_.Extension
    }}
    localRepos   = $s313Repos | ForEach-Object { @{
        name=$_.RepoName; path=$_.Path; remote=$_.RemoteURL; branch=$_.Branch
    }}
    remoteRepos  = $s313Remote | ForEach-Object { @{
        name=$_.RepoName; fullName=$_.FullName; cloneUrl=$_.CloneURL
        htmlUrl=$_.HTMLURL; private=$_.Private; updatedAt=$_.UpdatedAt
    }}
    exactDups    = $exactDups.Count
    nameDups     = $nameDups.Count
}
$map | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonPath -Encoding UTF8

# ── CONSOLE SUMMARY ───────────────────────────────────────────────────────
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  SCAN COMPLETE" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Local files:          $($allFiles.Count)" -ForegroundColor White
Write-Host "  Local Git repos:      $($localRepos.Count) ($($s313Repos.Count) Shadow313)" -ForegroundColor Cyan
Write-Host "  Remote GitHub repos:  $($remoteRepos.Count) ($($s313Remote.Count) Shadow313)" -ForegroundColor Cyan
Write-Host "  Exact duplicates:     $($exactDups.Count) groups" -ForegroundColor $(if($exactDups.Count -gt 0){"Yellow"}else{"Green"})
Write-Host "  Version conflicts:    $($nameDups.Count) groups" -ForegroundColor $(if($nameDups.Count -gt 0){"Red"}else{"Green"})
Write-Host ""
Write-Host "  Reports saved to Desktop:" -ForegroundColor Green
Write-Host "  -> $reportPath" -ForegroundColor White
Write-Host "  -> $csvPath (open in Excel)" -ForegroundColor White
Write-Host "  -> $jsonPath (used by consolidator)" -ForegroundColor White
Write-Host ""
if ($s313Repos.Count -gt 0) {
    Write-Host "  Shadow313 local repos found:" -ForegroundColor Cyan
    foreach ($r in $s313Repos) {
        Write-Host "    $($r.RepoName) — $($r.Path)" -ForegroundColor White
        Write-Host "    Remote: $($r.RemoteURL)" -ForegroundColor DarkGray
    }
    Write-Host ""
}
if ($s313Remote.Count -gt 0) {
    Write-Host "  Shadow313 remote repos:" -ForegroundColor Cyan
    foreach ($r in $s313Remote) {
        $priv = if ($r.Private) { "[PRIVATE]" } else { "[PUBLIC]" }
        Write-Host "    $($r.FullName) $priv — $($r.HTMLURL)" -ForegroundColor White
    }
    Write-Host ""
}
Write-Host "  NEXT: Run shadow313-consolidator.ps1 to auto-organize files" -ForegroundColor Cyan
Write-Host "  NEXT: Push to GitHub so shadow313.dev has everything" -ForegroundColor Cyan
Write-Host ""
