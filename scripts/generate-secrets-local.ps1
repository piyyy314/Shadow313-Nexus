#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Generate all Shadow313 NEXUS secrets locally and save to Desktop.
    Run this ONCE, then add the values to GitHub and your .env file.

.EXAMPLE
    cd C:\Users\shiatoali\shadow313-nexus
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
    .\scripts\generate-secrets-local.ps1
#>

$repo = "C:\Users\shiatoali\shadow313-nexus"
$date = Get-Date -Format "yyyyMMdd-HHmm"
$outFile = "$env:USERPROFILE\Desktop\shadow313-secrets-$date.txt"
$envFile = "$repo\.env"

Write-Host "`n╔══ Shadow313 NEXUS — Secret Generator ══╗" -ForegroundColor Cyan

# Generate secrets using Python (available on all platforms)
$jwtSecret  = python3 -c "import secrets; print(secrets.token_hex(32))" 2>$null
$webuiKey   = python3 -c "import secrets; print(secrets.token_hex(32))" 2>$null
$apiKey     = python3 -c "import secrets; print(secrets.token_hex(24))" 2>$null

if (-not $jwtSecret) {
    # Fallback: PowerShell random
    $jwtSecret = -join ((1..64) | ForEach-Object { '{0:x}' -f (Get-Random -Max 16) })
    $webuiKey  = -join ((1..64) | ForEach-Object { '{0:x}' -f (Get-Random -Max 16) })
    $apiKey    = -join ((1..48) | ForEach-Object { '{0:x}' -f (Get-Random -Max 16) })
}

Write-Host "  ✅ Generated SHADOW313_JWT_SECRET (32 bytes)" -ForegroundColor Green
Write-Host "  ✅ Generated WEBUI_SECRET_KEY (32 bytes)" -ForegroundColor Green
Write-Host "  ✅ Generated SHADOW313_API_KEY (24 bytes)" -ForegroundColor Green

# ── Save to Desktop (for GitHub secrets) ─────────────────────────
$desktopContent = @"
# ══════════════════════════════════════════════════════════════════
# Shadow313 NEXUS — Generated Secrets
# Generated: $(Get-Date)
# 
# STEP 1: Add these to GitHub Secrets:
#   github.com/piyyy314/Shadow313-Nexus
#   → Settings → Secrets and variables → Actions → New repository secret
#
# STEP 2: Copy the .env section below to:
#   C:\Users\shiatoali\shadow313-nexus\.env
#
# STEP 3: DELETE THIS FILE after completing steps 1 and 2!
# ══════════════════════════════════════════════════════════════════

═══ GITHUB SECRETS (add each one individually) ═══

Secret name: SHADOW313_JWT_SECRET
Secret value: $jwtSecret

Secret name: WEBUI_SECRET_KEY
Secret value: $webuiKey

Secret name: SHADOW313_API_KEY
Secret value: $apiKey

Secret name: VERCEL_TOKEN
Secret value: <get from vercel.com → Account Settings → Tokens>

Secret name: VERCEL_ORG_ID
Secret value: <get from vercel.com → Team Settings → General → Team ID>

Secret name: VERCEL_PROJECT_ID
Secret value: <get from vercel.com → Project → Settings → General → Project ID>

Secret name: TELEGRAM_BOT_TOKEN
Secret value: <get from @BotFather on Telegram → /newbot>

Secret name: TELEGRAM_CHAT_ID
Secret value: <get from @userinfobot on Telegram>

Secret name: PYPI_API_TOKEN
Secret value: <get from pypi.org → Account → API tokens>

═══ GITHUB VARIABLES (Settings → Variables → Actions) ═══

Variable: SHADOW313_AI_BACKEND = disabled
Variable: SHADOW313_ENV = production
Variable: PYTHON_VERSION = 3.12
Variable: OLLAMA_DEFAULT_MODEL = matarmohamad313/shadow313-nexus

═══ .ENV FILE (copy to C:\Users\shiatoali\shadow313-nexus\.env) ═══

SHADOW313_JWT_SECRET=$jwtSecret
WEBUI_SECRET_KEY=$webuiKey
SHADOW313_API_KEY=$apiKey
SHADOW313_ENV=development
PORT=8313
SHADOW313_AI_BACKEND=ollama
SHADOW313_AI_MODEL=mistral:7b
SHADOW313_AI_ENDPOINT=http://localhost:11434
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=mistral:7b
OLLAMA_DEFAULT_MODEL=matarmohamad313/shadow313-nexus
SHADOW313_JWT_ISSUER=shadow313-nexus
SHADOW313_JWT_EXPIRE_MIN=60
SHADOW313_BIND_HOST=127.0.0.1
TELEGRAM_BOT_TOKEN=<paste-from-botfather>
TELEGRAM_CHAT_ID=<paste-your-chat-id>
TELEGRAM_MIN_SEVERITY=HIGH
TELEGRAM_POLL_INTERVAL=10
"@

Set-Content $outFile $desktopContent -Encoding UTF8
Write-Host "  ✅ Secrets saved to Desktop: shadow313-secrets-$date.txt" -ForegroundColor Green

# ── Create .env file if it doesn't exist ─────────────────────────
if (-not (Test-Path $envFile)) {
    $envContent = @"
# Shadow313 NEXUS — Local Environment
# Generated: $(Get-Date)
# NEVER commit this file!

SHADOW313_JWT_SECRET=$jwtSecret
WEBUI_SECRET_KEY=$webuiKey
SHADOW313_API_KEY=$apiKey
SHADOW313_ENV=development
PORT=8313
SHADOW313_AI_BACKEND=ollama
SHADOW313_AI_MODEL=mistral:7b
SHADOW313_AI_ENDPOINT=http://localhost:11434
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=mistral:7b
OLLAMA_DEFAULT_MODEL=matarmohamad313/shadow313-nexus
SHADOW313_JWT_ISSUER=shadow313-nexus
SHADOW313_JWT_EXPIRE_MIN=60
SHADOW313_BIND_HOST=127.0.0.1
TELEGRAM_BOT_TOKEN=your_bot_token_here
TELEGRAM_CHAT_ID=-1001234567890
TELEGRAM_MIN_SEVERITY=HIGH
TELEGRAM_POLL_INTERVAL=10
"@
    Set-Content $envFile $envContent -Encoding UTF8
    Write-Host "  ✅ .env file created at: $envFile" -ForegroundColor Green
} else {
    Write-Host "  ⚠️  .env already exists — not overwriting" -ForegroundColor Yellow
    Write-Host "     Update manually with values from Desktop file" -ForegroundColor Gray
}

Write-Host @"

╔══════════════════════════════════════════════════════════════════╗
║  NEXT STEPS                                                    ║
╠══════════════════════════════════════════════════════════════════╣
║  1. Open Desktop file: shadow313-secrets-$date.txt  ║
║  2. Add each secret to GitHub (see instructions in file)       ║
║  3. Update .env with Telegram token when you have it           ║
║  4. DELETE the Desktop file after adding to GitHub             ║
║                                                                  ║
║  GitHub Secrets URL:                                           ║
║  github.com/piyyy314/Shadow313-Nexus/settings/secrets/actions  ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan