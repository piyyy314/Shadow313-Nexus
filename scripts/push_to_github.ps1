# Shadow313 NEXUS — Safe local GitHub sync (Windows PowerShell 7)
# Usage: .\scripts\push_to_github.ps1 [-Branch fix/my-change] [-DryRun] [-SkipTests]
# Creates a feature branch and never pushes directly to master/main.

[CmdletBinding()]
param(
    [string]$Remote = "origin",
    [string]$Branch = "",
    [switch]$DryRun,
    [switch]$SkipTests
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-Git {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$GitArgs)
    $output = & git @GitArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "git $($GitArgs -join ' ') failed: $($output -join [Environment]::NewLine)"
    }
    return $output
}

try {
    $repoRoot = (Invoke-Git rev-parse --show-toplevel | Select-Object -First 1).ToString().Trim()
    if (-not $repoRoot) { throw "Could not determine repository root." }
    Set-Location $repoRoot

    $remoteUrl = (Invoke-Git remote get-url $Remote | Select-Object -First 1).ToString().Trim()
    if ($remoteUrl -notmatch 'github\.com[:/]piyyy314/Shadow313-Nexus(?:\.git)?$') {
        throw "Remote '$Remote' does not point to piyyy314/Shadow313-Nexus. Refusing to push."
    }

    $currentBranch = (Invoke-Git branch --show-current | Select-Object -First 1).ToString().Trim()
    if (-not $Branch) {
        $Branch = "fix/local-sync-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    }
    if ($Branch -match '^(master|main)$') {
        throw "Direct pushes to '$Branch' are disabled. Use a feature branch."
    }
    if ($Branch -notmatch '^[A-Za-z0-9._/-]+$' -or $Branch -match '\.\.|//|^/|/$') {
        throw "Invalid branch name: $Branch"
    }

    $status = @(Invoke-Git status --porcelain --untracked-files=all)
    if ($status.Count -eq 0) {
        Write-Host "Working tree is clean; nothing to push." -ForegroundColor Green
        exit 0
    }

    Write-Host "Repository: $repoRoot"
    Write-Host "Current branch: $currentBranch"
    Write-Host "Target feature branch: $Branch"
    Write-Host "Changed paths:"
    $status | ForEach-Object { Write-Host "  $_" }

    if ($DryRun) {
        Write-Host "DRY RUN: no files staged, committed, or pushed." -ForegroundColor Yellow
        exit 0
    }

    # Respect .gitignore and avoid staging ignored local artifacts.
    Invoke-Git add -A | Out-Null
    $staged = @(Invoke-Git diff --cached --name-only)
    if ($staged.Count -eq 0) {
        Write-Host "No eligible changes remain after .gitignore filtering." -ForegroundColor Green
        exit 0
    }

    $sensitivePath = '(?i)(^|/)(\.env(?:\.(?!example$|sample$|template$)[^/]+)?|id_rsa(?:\.pub)?|id_ed25519(?:\.pub)?|credentials(?:\..*)?|secrets?(?:\..*)?|.*\.(?:pem|p12|pfx|key)|logs/.*\.(?:json|log)|.*\.(?:sqlite|db))
    $blocked = @($staged | Where-Object { $_ -match $sensitivePath })
    if ($blocked.Count -gt 0) {
        throw "Sensitive/local paths are staged; unstage and review them before syncing: $($blocked -join ', ')"
    }

    Invoke-Git diff --cached --check | Out-Null

    $secretScanner = Join-Path $repoRoot "scripts/check-secrets.py"
    if (Test-Path $secretScanner) {
        & python $secretScanner
        if ($LASTEXITCODE -ne 0) { throw "Secret scan failed. No commit or push was made." }
    } else {
        throw "Required secret scanner scripts/check-secrets.py is missing. No commit or push was made."
    }

    if (-not $SkipTests) {
        if (Test-Path (Join-Path $repoRoot "pyproject.toml")) {
            & python -m pytest -q
            if ($LASTEXITCODE -ne 0) { throw "Pytest failed. No commit or push was made." }
        } else {
            Write-Warning "pyproject.toml not found; skipping pytest."
        }
    } else {
        Write-Warning "Tests explicitly skipped; secret scan and staged-diff checks still ran."
    }

    # Create the feature branch only after preflight succeeds.
    Invoke-Git switch -c $Branch | Out-Null
    $message = "chore(sync): publish reviewed local changes"
    Invoke-Git commit -m $message | Out-Null
    Invoke-Git push --set-upstream $Remote $Branch | Out-Null

    Write-Host "Push completed: $Remote/$Branch" -ForegroundColor Green
    Write-Host "Review the new pull request and its checks before merging."
    Write-Host "No merge or deployment is performed by this script."
}
catch {
    Write-Error $_
    exit 1
}

    $blocked = @($staged | Where-Object { $_ -match $sensitivePath })
    if ($blocked.Count -gt 0) {
        throw "Sensitive/local paths are staged; unstage and review them before syncing: $($blocked -join ', ')"
    }

    Invoke-Git diff --cached --check | Out-Null

    $secretScanner = Join-Path $repoRoot "scripts/check-secrets.py"
    if (Test-Path $secretScanner) {
        & python $secretScanner
        if ($LASTEXITCODE -ne 0) { throw "Secret scan failed. No commit or push was made." }
    } else {
        throw "Required secret scanner scripts/check-secrets.py is missing. No commit or push was made."
    }

    if (-not $SkipTests) {
        if (Test-Path (Join-Path $repoRoot "pyproject.toml")) {
            & python -m pytest -q
            if ($LASTEXITCODE -ne 0) { throw "Pytest failed. No commit or push was made." }
        } else {
            Write-Warning "pyproject.toml not found; skipping pytest."
        }
    } else {
        Write-Warning "Tests explicitly skipped; secret scan and staged-diff checks still ran."
    }

    # Create the feature branch only after preflight succeeds.
    Invoke-Git switch -c $Branch | Out-Null
    $message = "chore(sync): publish reviewed local changes"
    Invoke-Git commit -m $message | Out-Null
    Invoke-Git push --set-upstream $Remote $Branch | Out-Null

    Write-Host "Push completed: $Remote/$Branch" -ForegroundColor Green
    Write-Host "Review the new pull request and its checks before merging."
    Write-Host "No merge or deployment is performed by this script."
}
catch {
    Write-Error $_
    exit 1
}
