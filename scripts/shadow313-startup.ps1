$ErrorActionPreference = "Stop"
$apiUrl = "http://127.0.0.1:11434/api/version"
$logDir = Join-Path $env:LOCALAPPDATA "Shadow313"
$logFile = Join-Path $logDir "startup.log"
New-Item -ItemType Directory -Path $logDir -Force | Out-Null

function Write-StartupLog([string]$message) {
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $message" | Add-Content -LiteralPath $logFile -Encoding utf8
}

# Use Ollama's loopback default; Docker Desktop reaches this host API through
# host.docker.internal. Do not bind the unauthenticated API to every interface.
[System.Environment]::SetEnvironmentVariable("OLLAMA_HOST", $null, "User")

function Test-OllamaApi {
    try {
        $null = Invoke-RestMethod -Uri $apiUrl -TimeoutSec 3
        return $true
    } catch {
        return $false
    }
}

if (-not (Test-OllamaApi)) {
    $appPath = Join-Path $env:LOCALAPPDATA "Programs\Ollama\ollama app.exe"
    $appRunning = Get-Process -Name "ollama app" -ErrorAction SilentlyContinue
    if (-not $appRunning -and (Test-Path -LiteralPath $appPath)) {
        Start-Process -FilePath $appPath
        Write-StartupLog "Started Ollama desktop app; waiting for API readiness."
    }

    $deadline = (Get-Date).AddSeconds(45)
    while ((Get-Date) -lt $deadline -and -not (Test-OllamaApi)) {
        Start-Sleep -Seconds 3
    }
}

if (Test-OllamaApi) {
    Write-StartupLog "Ollama API is ready at http://127.0.0.1:11434. No duplicate server started."
    exit 0
}

Write-StartupLog "Ollama API did not become ready. Start or repair the Ollama desktop app; this script will not run a second ollama serve."
exit 1
