param([string]$Token="YOUR_GITHUB_TOKEN_HERE")
$ErrorActionPreference="SilentlyContinue"
$Repo="C:\Users\shiatoali\shadow313-nexus"
function OK($m){Write-Host "  ✅ $m" -ForegroundColor Green}
function WARN($m){Write-Host "  ⚠️  $m" -ForegroundColor Yellow}
function FAIL($m){Write-Host "  ❌ $m" -ForegroundColor Red}
function INFO($m){Write-Host "     $m" -ForegroundColor Gray}
function Step($m){Write-Host ""; Write-Host "  [$m]" -ForegroundColor Cyan}
Write-Host ""; Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  SHADOW313 — One Shot Setup (sit back, ~5 min)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

Step "1/8 Fix WSL2 config"
@"
[wsl2]
memory=6GB
processors=3
swap=2GB
localhostForwarding=true
"@ | Out-File "$env:USERPROFILE\.wslconfig" -Encoding UTF8 -Force
wsl --shutdown 2>$null; Start-Sleep 5; OK "WSL2 reset"

Step "2/8 Fix Ubuntu-24.04"
$uf='sudo rm -f /etc/resolv.conf; printf "nameserver 8.8.8.8\nnameserver 9.9.9.9\n" | sudo tee /etc/resolv.conf > /dev/null; echo "Acquire::ForceIPv4 \"true\";" | sudo tee /etc/apt/apt.conf.d/99force-ipv4 > /dev/null; sudo apt-get update -qq 2>/dev/null; sudo apt-get upgrade -y -q --fix-missing 2>/dev/null; sudo apt-get install -y -q python3-pip nmap git curl wget 2>/dev/null; pip3 install pyspx requests dnspython --break-system-packages -q 2>/dev/null; echo UBUNTU_DONE'
$ur=wsl -d Ubuntu-24.04 -- bash -c $uf 2>&1
if($ur -match "UBUNTU_DONE"){OK "Ubuntu fixed + updated"}else{WARN "Ubuntu had issues"}

Step "3/8 Fix Kali Linux"
$kf='sudo rm -f /etc/resolv.conf; printf "nameserver 8.8.8.8\nnameserver 9.9.9.9\n" | sudo tee /etc/resolv.conf > /dev/null; echo "Acquire::ForceIPv4 \"true\";" | sudo tee /etc/apt/apt.conf.d/99force-ipv4 > /dev/null; sudo apt-get update -qq 2>/dev/null; echo KALI_DONE'
$kr=wsl -d kali-linux -- bash -c $kf 2>&1
if($kr -match "KALI_DONE"){OK "Kali fixed"}else{WARN "Kali had issues"}

Step "4/8 Start Docker"
if(-not(Get-Process "Docker Desktop" -ErrorAction SilentlyContinue)){Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe"; INFO "Waiting 25s..."; Start-Sleep 25}
if(docker ps 2>$null){OK "Docker running"}else{WARN "Docker not ready yet"}

Step "5/8 Start Open WebUI"
$ow=docker ps --filter "name=open-webui" --format "{{.Status}}" 2>$null
if($ow -match "Up"){OK "Open WebUI running — http://localhost:3000"}
else{docker start open-webui 2>$null; Start-Sleep 5; $ow2=docker ps --filter "name=open-webui" --format "{{.Status}}" 2>$null; if($ow2 -match "Up"){OK "Open WebUI started"}else{WARN "Open WebUI not running — run: docker start open-webui"}}

Step "6/8 Start Ollama"
if(-not(Get-Process ollama -ErrorAction SilentlyContinue)){Start-Process ollama -ArgumentList "serve" -WindowStyle Hidden; Start-Sleep 5}
if(Get-Process ollama -ErrorAction SilentlyContinue){OK "Ollama running"; $m=ollama list 2>$null|Where-Object{$_ -match "^\S" -and $_ -notmatch "^NAME"}; INFO "Models: $(@($m).Count)"}else{WARN "Ollama not running"}

Step "7/8 Sync GitHub"
if(Test-Path $Repo){Set-Location $Repo; git remote set-url origin "https://piyyy314:$Token@github.com/piyyy314/Shadow313-Nexus.git" 2>$null; git add . 2>$null; $s=(git diff --cached --name-only 2>$null).Count; if($s -gt 0){git commit -m "chore: one-shot sync $(Get-Date -Format 'yyyy-MM-dd')" 2>$null; git push origin master 2>$null; OK "Pushed $s changes"}else{OK "GitHub up to date"}; git remote set-url origin "https://github.com/piyyy314/Shadow313-Nexus.git" 2>$null}

Step "8/8 Final check"
Start-Sleep 3
$checks=@{
    "Ubuntu WSL"=(wsl -d Ubuntu-24.04 -- bash -c "echo OK" 2>$null) -match "OK"
    "Kali WSL"=(wsl -d kali-linux -- bash -c "echo OK" 2>$null) -match "OK"
    "Docker"=$null -ne (docker ps 2>$null)
    "Open WebUI"=(docker ps --filter "name=open-webui" --format "{{.Status}}" 2>$null) -match "Up"
    "Ollama"=$null -ne (Get-Process ollama -ErrorAction SilentlyContinue)
    "Git"=$null -ne (Get-Command git -ErrorAction SilentlyContinue)
    "Python"=$null -ne (Get-Command python -ErrorAction SilentlyContinue)
}
$p=0; $f=0
foreach($c in $checks.Keys){if($checks[$c]){OK $c; $p++}else{FAIL $c; $f++}}
$score=[math]::Round($p/($p+$f)*100)
Write-Host ""; Write-Host "============================================================" -ForegroundColor $(if($score -ge 80){"Green"}else{"Yellow"})
Write-Host "  DONE — Score: $score% ($p/$($p+$f) checks passed)" -ForegroundColor $(if($score -ge 80){"Green"}else{"Yellow"})
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Open WebUI:  http://localhost:3000" -ForegroundColor White
Write-Host "  Shadow313:   https://shadow313.dev" -ForegroundColor White
Write-Host "  Ubuntu:      wsl -d Ubuntu-24.04" -ForegroundColor White
Write-Host "  Kali:        wsl -d kali-linux" -ForegroundColor White
Write-Host "  AI Chat:     ollama run matarmohamad313/shadow313-nexus" -ForegroundColor White
Write-Host ""
