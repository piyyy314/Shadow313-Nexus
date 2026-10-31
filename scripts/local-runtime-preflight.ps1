# Read-only local diagnostics. Never deletes volumes/models or changes services.
$ErrorActionPreference = 'Continue'
Write-Host '=== WSL ==='
wsl --status
wsl --list --verbose
Write-Host '=== Docker ==='
docker version
docker ps -a --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
Write-Host '=== Native Windows Ollama API (10-second timeout) ==='
try {
    $data = Invoke-RestMethod 'http://127.0.0.1:11434/api/tags' -TimeoutSec 10
    $data.models | Select-Object name, size
} catch {
    Write-Warning ('Native Ollama API unavailable: ' + $_.Exception.Message)
}
Write-Host '=== Model storage overrides (no credentials) ==='
foreach ($scope in 'Process','User','Machine') {
    [pscustomobject]@{
        Scope = $scope
        OLLAMA_HOST = [Environment]::GetEnvironmentVariable('OLLAMA_HOST', $scope)
        OLLAMA_MODELS = [Environment]::GetEnvironmentVariable('OLLAMA_MODELS', $scope)
    }
}
Write-Host '=== Compose schema (quiet: does not print environment credentials) ==='
if (Test-Path 'docker-compose.yml') { docker compose config --quiet }
Write-Host 'Diagnostic completion is not a health guarantee. Review each error above.'
