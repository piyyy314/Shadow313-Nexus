#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Shadow313 NEXUS — GitHub Secrets Setup Script
    Adds all required secrets and variables to your GitHub repo via API.

.DESCRIPTION
    Run this ONCE after generating your secrets.
    Requires: GitHub Personal Access Token with repo + secrets scope.

.EXAMPLE
    cd C:\Users\shiatoali\shadow313-nexus
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
    .\scripts\setup-github-secrets.ps1 -Token "github_pat_xxx"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$Token,
    
    [string]$Repo = "piyyy314/Shadow313-Nexus",
    
    # Optional — if not provided, will be auto-generated
    [string]$JwtSecret    = "",
    [string]$WebuiKey     = "",
    [string]$ApiKey       = "",
    [string]$TelegramToken = "",
    [string]$TelegramChatId = "",
    [string]$VercelToken  = "",
    [string]$VercelOrgId  = "",
    [string]$VercelProjectId = ""
)

$ErrorActionPreference = "Stop"
$headers = @{
    Authorization = "Bearer $Token"
    Accept        = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
}
$baseUrl = "https://api.github.com/repos/$Repo"

function Write-OK   { param([string]$m) Write-Host "  ✅ $m" -ForegroundColor Green }
function Write-Fix  { param([string]$m) Write-Host "  🔧 $m" -ForegroundColor Magenta }
function Write-Warn { param([string]$m) Write-Host "  ⚠️  $m" -ForegroundColor Yellow }
function Write-Fail { param([string]$m) Write-Host "  ❌ $m" -ForegroundColor Red }

Write-Host "`n╔══ Shadow313 NEXUS — GitHub Secrets Setup ══╗" -ForegroundColor Cyan

# ── Verify token works ────────────────────────────────────────────
try {
    $repoInfo = Invoke-RestMethod "$baseUrl" -Headers $headers
    Write-OK "Connected to: $($repoInfo.full_name)"
} catch {
    Write-Fail "Cannot connect to GitHub API: $_"
    exit 1
}

# ── Get repo public key for secret encryption ─────────────────────
$pubKeyInfo = Invoke-RestMethod "$baseUrl/actions/secrets/public-key" -Headers $headers
$pubKey     = $pubKeyInfo.key
$pubKeyId   = $pubKeyInfo.key_id

# ── Encrypt a secret using libsodium (via Python) ─────────────────
function Encrypt-Secret {
    param([string]$SecretValue, [string]$PublicKey)
    
    $encrypted = python3 -c @"
import base64, sys
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# GitHub uses libsodium sealed box — use PyNaCl if available
try:
    from nacl.public import PublicKey, SealedBox
    pub = PublicKey(base64.b64decode('$PublicKey'))
    box = SealedBox(pub)
    encrypted = box.encrypt(b'$SecretValue')
    print(base64.b64encode(encrypted).decode())
except ImportError:
    # Fallback: just base64 encode (won't work for real secrets)
    print('NACL_NOT_AVAILABLE')
"@ 2>$null
    
    if ($encrypted -eq "NACL_NOT_AVAILABLE" -or -not $encrypted) {
        # Install PyNaCl
        pip install PyNaCl -q 2>$null
        $encrypted = python3 -c @"
import base64
from nacl.public import PublicKey, SealedBox
pub = PublicKey(base64.b64decode('$PublicKey'))
box = SealedBox(pub)
encrypted = box.encrypt(b'$SecretValue')
print(base64.b64encode(encrypted).decode())
"@ 2>$null
    }
    return $encrypted
}

# ── Set a GitHub secret ───────────────────────────────────────────
function Set-GHSecret {
    param([string]$Name, [string]$Value)
    
    if (-not $Value -or $Value -eq "") {
        Write-Warn "Skipping $Name (no value provided)"
        return
    }
    
    $encrypted = Encrypt-Secret -SecretValue $Value -PublicKey $pubKey
    
    if (-not $encrypted) {
        Write-Warn "Could not encrypt $Name — set manually in GitHub UI"
        return
    }
    
    $body = @{
        encrypted_value = $encrypted
        key_id          = $pubKeyId
    } | ConvertTo-Json
    
    try {
        Invoke-RestMethod "$baseUrl/actions/secrets/$Name" `
            -Method PUT -Headers $headers -Body $body -ContentType "application/json" | Out-Null
        Write-OK "Secret set: $Name"
    } catch {
        Write-Fail "Failed to set $Name : $_"
    }
}

# ── Set a GitHub variable ─────────────────────────────────────────
function Set-GHVariable {
    param([string]$Name, [string]$Value)
    
    $body = @{ name = $Name; value = $Value } | ConvertTo-Json
    
    try {
        # Try update first
        Invoke-RestMethod "$baseUrl/actions/variables/$Name" `
            -Method PATCH -Headers $headers -Body $body -ContentType "application/json" | Out-Null
        Write-OK "Variable updated: $Name = $Value"
    } catch {
        try {
            # Create if doesn't exist
            Invoke-RestMethod "$baseUrl/actions/variables" `
                -Method POST -Headers $headers -Body $body -ContentType "application/json" | Out-Null
            Write-OK "Variable created: $Name = $Value"
        } catch {
            Write-Fail "Failed to set variable $Name : $_"
        }
    }
}

# ── Auto-generate secrets if not provided ─────────────────────────
Write-Host "`n[1/3] Generating secrets..." -ForegroundColor Yellow

if (-not $JwtSecret) {
    $JwtSecret = python3 -c "import secrets; print(secrets.token_hex(32))" 2>$null
    Write-Fix "Generated SHADOW313_JWT_SECRET"
}
if (-not $WebuiKey) {
    $WebuiKey = python3 -c "import secrets; print(secrets.token_hex(32))" 2>$null
    Write-Fix "Generated WEBUI_SECRET_KEY"
}
if (-not $ApiKey) {
    $ApiKey = python3 -c "import secrets; print(secrets.token_hex(24))" 2>$null
    Write-Fix "Generated SHADOW313_API_KEY"
}

# ── Set all secrets ───────────────────────────────────────────────
Write-Host "`n[2/3] Setting GitHub secrets..." -ForegroundColor Yellow

Set-GHSecret "SHADOW313_JWT_SECRET"  $JwtSecret
Set-GHSecret "WEBUI_SECRET_KEY"      $WebuiKey
Set-GHSecret "SHADOW313_API_KEY"     $ApiKey
Set-GHSecret "TELEGRAM_BOT_TOKEN"    $TelegramToken
Set-GHSecret "TELEGRAM_CHAT_ID"      $TelegramChatId
Set-GHSecret "VERCEL_TOKEN"          $VercelToken
Set-GHSecret "VERCEL_ORG_ID"         $VercelOrgId
Set-GHSecret "VERCEL_PROJECT_ID"     $VercelProjectId

# ── Set all variables ─────────────────────────────────────────────
Write-Host "`n[3/3] Setting GitHub variables..." -ForegroundColor Yellow

Set-GHVariable "SHADOW313_AI_BACKEND" "disabled"
Set-GHVariable "SHADOW313_ENV"        "production"
Set-GHVariable "PYTHON_VERSION"       "3.12"
Set-GHVariable "OLLAMA_DEFAULT_MODEL" "matarmohamad313/shadow313-nexus"

# ── Save generated secrets locally ───────────────────────────────
$secretsFile = "$env:USERPROFILE\Desktop\shadow313-secrets-$(Get-Date -Format 'yyyyMMdd-HHmm').txt"
@"
# Shadow313 NEXUS — Generated Secrets
# Generated: $(Get-Date)
# These have been added to GitHub. Also add to your local .env file.
# DELETE THIS FILE after creating .env!

SHADOW313_JWT_SECRET=$JwtSecret
WEBUI_SECRET_KEY=$WebuiKey
SHADOW313_API_KEY=$ApiKey
"@ | Set-Content $secretsFile -Encoding UTF8

Write-Host @"

╔══════════════════════════════════════════════════════════════════╗
║  DONE                                                          ║
╠══════════════════════════════════════════════════════════════════╣
║  ✅ Secrets added to GitHub                                    ║
║  ✅ Variables added to GitHub                                  ║
║  📄 Secrets saved to Desktop (delete after creating .env)     ║
║                                                                  ║
║  STILL NEEDED (add manually in GitHub UI):                     ║
║  • VERCEL_TOKEN (if not provided)                              ║
║  • VERCEL_ORG_ID (if not provided)                             ║
║  • VERCEL_PROJECT_ID (if not provided)                         ║
║  • TELEGRAM_BOT_TOKEN (if not provided)                        ║
║  • TELEGRAM_CHAT_ID (if not provided)                          ║
║  • PYPI_API_TOKEN (from pypi.org)                              ║
║  • TEST_PYPI_API_TOKEN (from test.pypi.org)                    ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan