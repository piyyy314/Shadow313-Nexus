$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$startupScript = Join-Path $PSScriptRoot "shadow313-startup.ps1"
$watchdogScript = Join-Path $PSScriptRoot "shadow313-watchdog.ps1"
$startupDir = [Environment]::GetFolderPath('Startup')
$shell = New-Object -ComObject WScript.Shell

foreach ($entry in @(
    @{ Name = "Shadow313-Ollama-Startup.lnk"; Script = $startupScript; Arguments = "" },
    @{ Name = "Shadow313-Watchdog.lnk"; Script = $watchdogScript; Arguments = "-Check" }
)) {
    if (-not (Test-Path -LiteralPath $entry.Script)) {
        throw "Required script not found: $($entry.Script)"
    }
    $shortcutPath = Join-Path $startupDir $entry.Name
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = (Get-Command pwsh.exe -ErrorAction Stop).Source
    $shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$($entry.Script)`" $($entry.Arguments)".Trim()
    $shortcut.WorkingDirectory = $repo
    $shortcut.Save()
    if (-not (Test-Path -LiteralPath $shortcutPath)) {
        throw "Startup shortcut was not created: $shortcutPath"
    }
    Write-Host "Verified current-user startup shortcut: $shortcutPath" -ForegroundColor Green
}

$taskNames = @("Shadow313-Startup", "Shadow313-Watchdog")
foreach ($taskName in $taskNames) {
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($task) {
        Write-Warning "Task '$taskName' exists; inspect it before removing it. Startup shortcuts are installed regardless."
    } else {
        Write-Host "No scheduled task registered for '$taskName'; per-user Startup shortcuts are the active fallback." -ForegroundColor Yellow
    }
}
