<#
.SYNOPSIS
    Shadow313 NEXUS safe GitHub sync compatibility wrapper.

.DESCRIPTION
    Delegates to scripts/push_to_github.ps1 so all local syncs use one
    branch-safe implementation with remote validation, secret scanning,
    sensitive-path checks, and tests by default.

.EXAMPLE
    .\push-to-github.ps1 -DryRun

.EXAMPLE
    .\push-to-github.ps1 -BranchName "fix/local-trivy-patches"
#>
[CmdletBinding()]
param(
    [string]$BranchName = "",
    [string]$CommitMessage = "",
    [string]$Remote = "origin",
    [switch]$DryRun,
    [switch]$SkipTests
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$helperPath = Join-Path $PSScriptRoot "scripts/push_to_github.ps1"
if (-not (Test-Path $helperPath)) {
    throw "Required safe sync helper is missing: $helperPath"
}

$helperArgs = @{
    Remote = $Remote
    DryRun = $DryRun
    SkipTests = $SkipTests
}
if (-not [string]::IsNullOrWhiteSpace($BranchName)) {
    $helperArgs.Branch = $BranchName
}
if (-not [string]::IsNullOrWhiteSpace($CommitMessage)) {
    $helperArgs.CommitMessage = $CommitMessage
}

& $helperPath @helperArgs
