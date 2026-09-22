# Professional Security Workstation Setup Guide
## Windows 11 + WSL2 + Ubuntu + Kali Linux + Docker
### Shadow313 NEXUS — Operator Workstation Build

---

## PHASE 1: PREREQUISITES — Windows Configuration

### Step 1.1 — Enable Required Windows Features
Open **PowerShell as Administrator** and run:

```powershell
# Enable WSL2 and Virtual Machine Platform
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart

# Enable Hyper-V (needed for Docker)
dism.exe /online /enable-feature /featurename:Microsoft-Hyper-V-All /all /norestart

# Enable Windows Hypervisor Platform
dism.exe /online /enable-feature /featurename:HypervisorPlatform /all /norestart

Write-Host "Reboot required after this step." -ForegroundColor Yellow
```

**REBOOT NOW** before continuing.

---

### Step 1.2 — Set WSL2 as Default After Reboot
```powershell
# Set WSL2 as default version
wsl --set-default-version 2

# Update WSL kernel to latest
wsl --update

# Verify WSL2 is active
wsl --status
```

---

## PHASE 2: UBUNTU SETUP

### Step 2.1 — Install Ubuntu
```powershell
# Install Ubuntu 24.04 LTS (latest stable)
wsl --install -d Ubuntu-24.04

# List available distros if you want to choose
wsl --list --online
```

When prompted: set a **username** and **strong password** — this becomes your Linux sudo password.

---

### Step 2.2 — Ubuntu Full Configuration
Open Ubuntu terminal and run this full setup script:

```bash
#!/bin/bash
# ============================================================
# SHADOW313 — Ubuntu 24.04 Full Security Setup
# Run inside WSL2 Ubuntu terminal
# ============================================================

echo "[*] Updating system..."
sudo apt update && sudo apt upgrade -y && sudo apt autoremove -y

# ── CORE TOOLS ───────────────────────────────────────────────
echo "[*] Installing core tools..."
sudo apt install -y \
    build-essential git curl wget vim tmux htop tree \
    net-tools iputils-ping dnsutils whois traceroute \
    unzip zip p7zip-full tar gzip \
    python3 python3-pip python3-venv python3-dev \
    ruby ruby-dev \
    golang-go \
    nodejs npm \
    jq yq xmlstarlet \
    sqlite3 \
    openssl libssl-dev \
    nmap masscan \
    netcat-openbsd socat \
    tcpdump tshark \
    hydra john hashcat \
    sqlmap \
    nikto \
    gobuster ffuf dirb \
    aircrack-ng \
    steghide exiftool binwalk \
    gdb radare2 \
    docker.io docker-compose \
    openvpn wireguard \
    tor proxychains4 \
    seclists wordlists

# ── PYTHON SECURITY TOOLS ────────────────────────────────────
echo "[*] Installing Python security packages..."
pip3 install --break-system-packages \
    impacket \
    scapy \
    pwntools \
    requests \
    beautifulsoup4 \
    paramiko \
    cryptography \
    pyopenssl \
    dnspython \
    shodan \
    censys \
    pycurl \
    flask \
    fastapi \
    uvicorn \
    black \
    ruff \
    pytest \
    ipython \
    jupyter

# ── SHADOW313 DEPENDENCIES ───────────────────────────────────
echo "[*] Installing Shadow313 dependencies..."
pip3 install --break-system-packages \
    pyspx \
    argon2-cffi \
    pyyaml \
    rich \
    click \
    aiohttp \
    asyncio \
    python-dotenv \
    pydantic

# ── GIT CONFIGURATION ────────────────────────────────────────
echo "[*] Configuring git..."
git config --global init.defaultBranch main
git config --global core.editor vim
git config --global pull.rebase false

# ── TMUX CONFIGURATION ───────────────────────────────────────
echo "[*] Configuring tmux..."
cat > ~/.tmux.conf << 'EOF'
# Shadow313 tmux config
set -g default-terminal "screen-256color"
set -g history-limit 50000
set -g mouse on
set -g base-index 1
setw -g pane-base-index 1
set -g status-style bg=black,fg=green
set -g status-left "[#S] "
set -g status-right "%H:%M %d-%b-%y"
bind | split-window -h
bind - split-window -v
EOF

# ── VIM CONFIGURATION ────────────────────────────────────────
echo "[*] Configuring vim..."
cat > ~/.vimrc << 'EOF'
syntax on
set number
set tabstop=4
set shiftwidth=4
set expandtab
set autoindent
set hlsearch
set incsearch
set background=dark
colorscheme desert
EOF

# ── BASH ALIASES ─────────────────────────────────────────────
echo "[*] Setting up aliases..."
cat >> ~/.bashrc << 'EOF'

# Shadow313 Operator Aliases
alias ll='ls -alF --color=auto'
alias la='ls -A'
alias l='ls -CF'
alias ..='cd ..'
alias ...='cd ../..'
alias grep='grep --color=auto'
alias ports='ss -tulpn'
alias myip='curl -s https://ipinfo.io/ip'
alias myip6='curl -s https://ipinfo.io/ip'
alias netstat='ss -tulpn'
alias update='sudo apt update && sudo apt upgrade -y'
alias py='python3'
alias pip='pip3'

# Security aliases
alias nmap-quick='nmap -sV -sC -O'
alias nmap-full='nmap -sV -sC -O -p-'
alias nmap-udp='nmap -sU --top-ports 100'
alias http-server='python3 -m http.server 8080'
alias listen='nc -lvnp'

# Shadow313 project
alias s313='cd /workspace && python3 -m shadow313'

export PATH="$HOME/.local/bin:$PATH"
export PYTHONDONTWRITEBYTECODE=1
EOF

source ~/.bashrc

# ── DNS CONFIGURATION ────────────────────────────────────────
echo "[*] Configuring encrypted DNS..."
sudo bash -c 'cat > /etc/wsl.conf << EOF
[network]
generateResolvConf = false
EOF'

sudo bash -c 'cat > /etc/resolv.conf << EOF
# Quad9 encrypted DNS
nameserver 9.9.9.9
nameserver 149.112.112.112
nameserver 2620:fe::fe
nameserver 2620:fe::9
EOF'

sudo chattr +i /etc/resolv.conf  # prevent WSL from overwriting it

echo ""
echo "============================================"
echo " Ubuntu setup complete!"
echo " Run: source ~/.bashrc"
echo "============================================"
```

---

## PHASE 3: KALI LINUX SETUP

### Step 3.1 — Install Kali Linux
```powershell
# In Windows PowerShell (Admin)
wsl --install -d kali-linux
```

---

### Step 3.2 — Kali Full Tool Installation
Open Kali terminal and run:

```bash
#!/bin/bash
# ============================================================
# SHADOW313 — Kali Linux Full Security Suite Setup
# Run inside WSL2 Kali terminal
# ============================================================

echo "[*] Updating Kali..."
sudo apt update && sudo apt upgrade -y

# ── KALI FULL METAPACKAGE ────────────────────────────────────
echo "[*] Installing Kali full toolset (this takes 20-40 min)..."
sudo apt install -y kali-linux-default

# Or for the complete everything package (larger, ~15GB):
# sudo apt install -y kali-linux-everything

# ── SPECIFIC TOOL CATEGORIES ─────────────────────────────────

# Web Application Testing
sudo apt install -y \
    burpsuite \
    zaproxy \
    sqlmap \
    nikto \
    gobuster \
    ffuf \
    wfuzz \
    dirb \
    dirbuster \
    whatweb \
    wafw00f \
    wpscan \
    joomscan

# Network Analysis
sudo apt install -y \
    nmap \
    masscan \
    wireshark \
    tcpdump \
    netdiscover \
    arp-scan \
    responder \
    bettercap \
    ettercap-graphical \
    dsniff \
    mitmproxy

# Password Attacks
sudo apt install -y \
    hydra \
    medusa \
    john \
    hashcat \
    crunch \
    cewl \
    wordlists \
    seclists

# Exploitation
sudo apt install -y \
    metasploit-framework \
    exploitdb \
    searchsploit \
    beef-xss \
    set

# Post Exploitation
sudo apt install -y \
    mimikatz \
    crackmapexec \
    evil-winrm \
    impacket-scripts \
    bloodhound \
    neo4j \
    powershell-empire \
    starkiller

# Wireless
sudo apt install -y \
    aircrack-ng \
    airgeddon \
    wifite \
    kismet \
    reaver \
    pixiewps \
    bully

# Forensics & Reverse Engineering
sudo apt install -y \
    autopsy \
    volatility3 \
    binwalk \
    foremost \
    scalpel \
    gdb \
    radare2 \
    ghidra \
    pwndbg \
    peda \
    ltrace \
    strace

# OSINT
sudo apt install -y \
    maltego \
    recon-ng \
    theharvester \
    shodan \
    spiderfoot \
    dmitry \
    dnsenum \
    dnsrecon \
    fierce \
    amass \
    subfinder

# Cryptography & Steganography
sudo apt install -y \
    steghide \
    stegseek \
    exiftool \
    openssl \
    gpg \
    hashid \
    hash-identifier

# Social Engineering
sudo apt install -y \
    gophish \
    set

# Reporting
sudo apt install -y \
    cherrytree \
    picocrypt \
    keepassxc

# ── PYTHON TOOLS ─────────────────────────────────────────────
echo "[*] Installing Python security tools..."
pip3 install \
    impacket \
    scapy \
    pwntools \
    requests \
    beautifulsoup4 \
    paramiko \
    cryptography \
    pyopenssl \
    dnspython \
    shodan \
    censys \
    certipy-ad \
    bloodhound \
    pypykatz \
    lsassy

# ── METASPLOIT DATABASE SETUP ────────────────────────────────
echo "[*] Setting up Metasploit database..."
sudo systemctl start postgresql
sudo systemctl enable postgresql
sudo msfdb init

# ── WORDLISTS ────────────────────────────────────────────────
echo "[*] Setting up wordlists..."
sudo gzip -d /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true
ls -lh /usr/share/wordlists/

# ── KALI ALIASES ─────────────────────────────────────────────
cat >> ~/.zshrc << 'EOF'

# Shadow313 Kali Aliases
alias ll='ls -alF --color=auto'
alias update='sudo apt update && sudo apt upgrade -y'
alias msf='msfconsole'
alias burp='burpsuite &'
alias ports='ss -tulpn'
alias myip='curl -s https://ipinfo.io/ip'
alias listen='nc -lvnp'
alias http-server='python3 -m http.server 8080'
alias s313='cd /workspace && python3 -m shadow313'

# Pentest shortcuts
alias enum4linux-ng='python3 /opt/enum4linux-ng/enum4linux-ng.py'
alias bloodhound-python='python3 -m bloodhound'

export PATH="$HOME/.local/bin:$PATH"
EOF

echo ""
echo "============================================"
echo " Kali setup complete!"
echo " Tools installed: web, network, exploit,"
echo " forensics, OSINT, wireless, crypto"
echo "============================================"
```

---

## PHASE 4: DOCKER DESKTOP

### Step 4.1 — Install Docker Desktop
```powershell
# Download Docker Desktop installer
# Go to: https://www.docker.com/products/docker-desktop/
# Download Docker Desktop for Windows

# Or via winget (Windows Package Manager):
winget install Docker.DockerDesktop
```

After install:
1. Open Docker Desktop
2. Settings → General → **Use WSL 2 based engine** ✅
3. Settings → Resources → WSL Integration → Enable for **Ubuntu-24.04** and **kali-linux** ✅
4. Apply & Restart

---

### Step 4.2 — Verify Docker in WSL2
```bash
# In Ubuntu or Kali terminal
docker --version
docker run hello-world

# Pull essential security containers
docker pull kalilinux/kali-rolling          # Full Kali in container
docker pull remnux/remnux-distro            # Malware analysis
docker pull citizenstig/dvwa                # Damn Vulnerable Web App (practice target)
docker pull webgoat/webgoat                 # OWASP WebGoat (practice target)
docker pull vulhub/vulhub                   # Vulnerable environments
docker pull metasploitframework/metasploit  # Metasploit in container
```

---

### Step 4.3 — Docker Security Lab Setup
```bash
# Create isolated practice network
docker network create --driver bridge pentest-lab

# Start DVWA (vulnerable web app for practice)
docker run -d \
    --name dvwa \
    --network pentest-lab \
    -p 8080:80 \
    citizenstig/dvwa

# Start WebGoat (OWASP practice target)
docker run -d \
    --name webgoat \
    --network pentest-lab \
    -p 8081:8080 \
    webgoat/webgoat

# Start Juice Shop (OWASP modern vulnerable app)
docker run -d \
    --name juiceshop \
    --network pentest-lab \
    -p 8082:3000 \
    bkimminich/juice-shop

echo "Practice targets running:"
echo "  DVWA:       http://localhost:8080"
echo "  WebGoat:    http://localhost:8081/WebGoat"
echo "  JuiceShop:  http://localhost:8082"
```

---

## PHASE 5: ADDITIONAL TOOLS (Windows Side)

### Step 5.1 — Install via Winget
```powershell
# Run in PowerShell as Administrator

# Development tools
winget install Git.Git
winget install Python.Python.3.12
winget install Microsoft.VisualStudioCode
winget install JetBrains.PyCharm.Community

# Security tools (Windows native)
winget install PortSwigger.BurpSuite.Community
winget install Wireshark.Wireshark
winget install Nmap.Nmap
winget install WireGuard.WireGuard

# Privacy tools
winget install ProtonTechnologies.ProtonVPN
winget install KeePassXCTeam.KeePassXC
winget install Mullvad.MullvadVPN

# Utilities
winget install 7zip.7zip
winget install Notepad++.Notepad++
winget install Microsoft.WindowsTerminal
winget install Obsidian.Obsidian        # Notes/documentation
winget install voidtools.Everything     # Fast file search

# Browsers
winget install Mozilla.Firefox
winget install Brave.Brave
```

---

### Step 5.2 — VS Code Extensions for Security Work
```powershell
# Install VS Code extensions
code --install-extension ms-python.python
code --install-extension ms-vscode-remote.remote-wsl
code --install-extension ms-azuretools.vscode-docker
code --install-extension redhat.vscode-yaml
code --install-extension timonwong.shellcheck
code --install-extension foxundermoon.shell-format
code --install-extension streetsidesoftware.code-spell-checker
code --install-extension eamodio.gitlens
code --install-extension ms-vscode.hexeditor
code --install-extension tintinweb.solidity-visual-developer
```

---

## PHASE 6: NETWORK ISOLATION FOR PENTESTING

### Step 6.1 — WSL2 Network Configuration
```bash
# In Ubuntu/Kali — configure separate DNS for research VMs
# Host machine: Quad9 (filtered)
# Research environment: Cloudflare unfiltered

# Create profile-specific DNS config
sudo bash -c 'cat > /etc/resolv.conf.research << EOF
# Cloudflare unfiltered - for security research
# Resolves malware/C2 domains for investigation
nameserver 1.1.1.1
nameserver 1.0.0.1
EOF'

sudo bash -c 'cat > /etc/resolv.conf.secure << EOF
# Quad9 filtered - for normal operations
nameserver 9.9.9.9
nameserver 149.112.112.112
EOF'

# Switch between profiles:
# sudo cp /etc/resolv.conf.research /etc/resolv.conf  (for research)
# sudo cp /etc/resolv.conf.secure /etc/resolv.conf    (for normal use)
```

---

### Step 6.2 — VPN Split Tunneling Setup
```bash
# Install Mullvad CLI in WSL2
curl -fsSL https://repository.mullvad.net/deb/mullvad-keyring.asc | sudo gpg --dearmor -o /usr/share/keyrings/mullvad-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/mullvad-keyring.gpg arch=$( dpkg --print-architecture )] https://repository.mullvad.net/deb/stable $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/mullvad.list
sudo apt update && sudo apt install -y mullvad-vpn

# Or use WireGuard directly with Mullvad config
# Download config from: https://mullvad.net/en/account/wireguard-config
sudo apt install -y wireguard
# sudo wg-quick up /path/to/mullvad-config.conf
```

---

## PHASE 7: SHADOW313 PROJECT SETUP IN WSL2

### Step 7.1 — Mount and Configure Shadow313
```bash
# In Ubuntu WSL2 terminal
# Your Windows files are accessible at /mnt/c/

# Option A: Work directly in WSL2 filesystem (faster)
mkdir -p ~/projects
cd ~/projects

# Clone or copy Shadow313 workspace
# If you have it on Windows:
cp -r /mnt/c/Users/$USER/workspace ~/projects/shadow313
cd ~/projects/shadow313

# Option B: Symlink to Windows path
ln -s /mnt/c/path/to/workspace ~/shadow313

# Install Shadow313 dependencies
pip3 install -r requirements.txt 2>/dev/null || \
pip3 install --break-system-packages \
    pyspx argon2-cffi pyyaml rich click \
    cryptography pytest pytest-asyncio

# Run tests
python3 -m pytest tests/ -q
```

---

## PHASE 8: VERIFICATION CHECKLIST

Run this to verify everything is working:

```bash
#!/bin/bash
# ============================================================
# SHADOW313 — Workstation Verification Script
# ============================================================

echo "============================================"
echo " Security Workstation Verification"
echo "============================================"

check() {
    if command -v "$1" &>/dev/null; then
        echo "  ✅ $1 — $(command -v $1)"
    else
        echo "  ❌ $1 — NOT FOUND"
    fi
}

echo ""
echo "[*] Core Tools:"
check python3
check pip3
check git
check curl
check wget
check vim
check tmux

echo ""
echo "[*] Network Tools:"
check nmap
check masscan
check netcat
check tcpdump
check wireshark

echo ""
echo "[*] Security Tools:"
check hydra
check john
check hashcat
check sqlmap
check nikto
check gobuster

echo ""
echo "[*] Exploitation:"
check msfconsole
check searchsploit

echo ""
echo "[*] OSINT:"
check theharvester
check recon-ng
check amass

echo ""
echo "[*] Containers:"
check docker
docker ps &>/dev/null && echo "  ✅ Docker daemon running" || echo "  ❌ Docker daemon not running"

echo ""
echo "[*] Python Packages:"
python3 -c "import impacket; print('  ✅ impacket')" 2>/dev/null || echo "  ❌ impacket"
python3 -c "import scapy; print('  ✅ scapy')" 2>/dev/null || echo "  ❌ scapy"
python3 -c "import cryptography; print('  ✅ cryptography')" 2>/dev/null || echo "  ❌ cryptography"
python3 -c "import pyspx; print('  ✅ pyspx (Shadow313 SLH-DSA)')" 2>/dev/null || echo "  ❌ pyspx"

echo ""
echo "[*] DNS Check:"
dig +short google.com @9.9.9.9 &>/dev/null && echo "  ✅ Quad9 DNS responding" || echo "  ❌ Quad9 DNS unreachable"
dig +short google.com @1.1.1.1 &>/dev/null && echo "  ✅ Cloudflare DNS responding" || echo "  ❌ Cloudflare DNS unreachable"

echo ""
echo "[*] Network:"
echo "  External IP: $(curl -s https://ipinfo.io/ip 2>/dev/null || echo 'check failed')"
echo "  DNS leaks:   Run https://dnsleaktest.com to verify"

echo ""
echo "============================================"
echo " Verification complete"
echo "============================================"
```

---

## QUICK REFERENCE — Daily Use

### Starting Your Environment
```powershell
# Windows Terminal — open all environments at once
# Create a Windows Terminal profile with this startup:

# Tab 1: Ubuntu (daily work)
wsl -d Ubuntu-24.04

# Tab 2: Kali (pentesting)
wsl -d kali-linux

# Tab 3: PowerShell (Windows tools)
# Already open
```

### WSL2 Useful Commands
```powershell
wsl --list --verbose          # See all distros and status
wsl --shutdown                # Stop all WSL instances
wsl -d Ubuntu-24.04           # Start specific distro
wsl --export Ubuntu-24.04 backup.tar  # Backup your setup
wsl --import Ubuntu-restored . backup.tar  # Restore backup
```

### Docker Practice Lab
```bash
# Start all practice targets
docker start dvwa webgoat juiceshop

# Stop when done
docker stop dvwa webgoat juiceshop

# Check running containers
docker ps
```

---

## IMPORTANT LEGAL REMINDER

All tools installed above are for:
- **Authorized penetration testing** on systems you own or have written permission to test
- **CTF (Capture The Flag)** competitions
- **Security research** in isolated lab environments
- **Defensive security** — understanding attacks to build better defenses

**Never use these tools against systems without explicit written authorization.**
Shadow313's 313-BIND temporal binding receipts are ideal for documenting authorized testing scope and timestamps.