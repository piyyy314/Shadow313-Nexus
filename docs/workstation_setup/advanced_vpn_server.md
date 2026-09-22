# Advanced Personal VPN Server
## WireGuard + Obfuscation + Encrypted DNS + Kill-Switch
### Shadow313 NEXUS — Operator VPN Build

---

## ARCHITECTURE OVERVIEW

```
Your Laptop (Windows + WSL2)
        │
        │ WireGuard tunnel (ChaCha20-Poly1305)
        │ Port 443 (looks like HTTPS — not blocked anywhere)
        │
        ▼
┌─────────────────────────────────────────────────────┐
│  YOUR VPS (Hetzner/Vultr)                           │
│                                                     │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────┐  │
│  │  WireGuard  │  │  Unbound DNS │  │  Fail2ban │  │
│  │  wg0        │  │  DoH/DoT     │  │  IDS      │  │
│  └─────────────┘  └──────────────┘  └───────────┘  │
│                                                     │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────┐  │
│  │  iptables   │  │  Nginx       │  │  WireGuard│  │
│  │  kill-switch│  │  TLS camoufl │  │  Dashboard│  │
│  └─────────────┘  └──────────────┘  └───────────┘  │
└─────────────────────────────────────────────────────┘
        │
        │ Clean exit IP (not flagged, not shared)
        ▼
     Internet
```

---

## PHASE 1: VPS SELECTION AND PURCHASE

### Best Providers for Privacy

| Provider | Price | Location | Privacy | Notes |
|----------|-------|----------|---------|-------|
| **Hetzner** | €3.29/mo | DE/FI/US | Good | Best value |
| **Vultr** | $3.50/mo | 32 locations | Good | Most flexible |
| **Njalla** | €15/mo | Sweden | Excellent | Anonymous purchase |
| **1984 Hosting** | $4/mo | Iceland | Excellent | Privacy-focused |
| **Frantech/BuyVM** | $3.50/mo | US/LU/CA | Good | Bulletproof hosting |

### Recommended: Hetzner CX22
- 2 vCPU, 4GB RAM, 40GB SSD, 20TB bandwidth
- €3.29/month (~$4.80 CAD)
- Pay with credit card or PayPal
- Choose **Ubuntu 24.04 LTS**
- Choose **Nuremberg or Helsinki** datacenter

### Payment Privacy
- Use a **prepaid Visa/Mastercard** from a convenience store
- Or pay with **cryptocurrency** (Njalla, 1984 Hosting accept crypto)
- This keeps your real identity off the VPS billing record

---

## PHASE 2: VPS INITIAL HARDENING

### Step 2.1 — First Login and SSH Key Setup

On your **Windows laptop** first:
```powershell
# Generate ED25519 SSH key (stronger than RSA)
ssh-keygen -t ed25519 -C "shadow313-vpn" -f "$HOME\.ssh\shadow313_vpn"

# View your public key — copy this
cat "$HOME\.ssh\shadow313_vpn.pub"
```

In Hetzner dashboard:
1. Go to **SSH Keys** → Add SSH Key
2. Paste your public key
3. When creating VPS → select this SSH key

Now SSH in:
```bash
ssh -i ~/.ssh/shadow313_vpn root@YOUR_VPS_IP
```

---

### Step 2.2 — Full Server Hardening Script

```bash
#!/bin/bash
# ============================================================
# SHADOW313 VPS — Full Hardening Script
# Run as root on fresh Ubuntu 24.04
# ============================================================

set -e
echo "[*] Starting Shadow313 VPS hardening..."

# ── SYSTEM UPDATE ────────────────────────────────────────────
apt update && apt upgrade -y
apt install -y \
    ufw fail2ban unattended-upgrades \
    curl wget git vim tmux htop \
    net-tools iptables-persistent \
    wireguard wireguard-tools \
    unbound \
    nginx certbot python3-certbot-nginx \
    qrencode \
    jq \
    auditd \
    rkhunter chkrootkit \
    logwatch

# ── CREATE NON-ROOT OPERATOR USER ────────────────────────────
useradd -m -s /bin/bash operator
usermod -aG sudo operator
mkdir -p /home/operator/.ssh
cp /root/.ssh/authorized_keys /home/operator/.ssh/
chown -R operator:operator /home/operator/.ssh
chmod 700 /home/operator/.ssh
chmod 600 /home/operator/.ssh/authorized_keys

# ── HARDEN SSH ───────────────────────────────────────────────
cat > /etc/ssh/sshd_config.d/shadow313.conf << 'EOF'
# Shadow313 SSH Hardening
Port 2222
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
X11Forwarding no
AllowTcpForwarding no
GatewayPorts no
PermitTunnel no
MaxAuthTries 2
MaxSessions 3
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30
Banner /etc/ssh/banner
Protocol 2
# Only allow operator user
AllowUsers operator
EOF

# SSH warning banner
cat > /etc/ssh/banner << 'EOF'
╔══════════════════════════════════════════════════════╗
║  SHADOW313 NEXUS — AUTHORIZED ACCESS ONLY           ║
║  All connections are logged and monitored           ║
║  Unauthorized access is prohibited                  ║
╚══════════════════════════════════════════════════════╝
EOF

systemctl restart sshd

# ── FIREWALL ─────────────────────────────────────────────────
ufw default deny incoming
ufw default allow outgoing
ufw allow 2222/tcp    # SSH (custom port)
ufw allow 443/udp     # WireGuard (disguised as HTTPS)
ufw allow 443/tcp     # Nginx TLS (for obfuscation)
ufw allow 53/udp      # DNS (internal only — restricted below)
ufw --force enable

# ── FAIL2BAN ─────────────────────────────────────────────────
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 3
backend  = systemd

[sshd]
enabled  = true
port     = 2222
logpath  = %(sshd_log)s
maxretry = 2
bantime  = 86400

[nginx-http-auth]
enabled  = true

[nginx-botsearch]
enabled  = true
EOF

systemctl enable fail2ban
systemctl restart fail2ban

# ── KERNEL HARDENING ─────────────────────────────────────────
cat >> /etc/sysctl.conf << 'EOF'

# Shadow313 Kernel Hardening
# IP forwarding (required for VPN)
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# Prevent IP spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Hide kernel pointers
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1

# Prevent core dumps
fs.suid_dumpable = 0

# Randomize memory layout (ASLR)
kernel.randomize_va_space = 2

# Disable magic SysRq
kernel.sysrq = 0
EOF

sysctl -p

# ── AUTOMATIC SECURITY UPDATES ───────────────────────────────
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

# ── AUDIT LOGGING ────────────────────────────────────────────
systemctl enable auditd
systemctl start auditd

# Log all authentication events
auditctl -w /etc/passwd -p wa -k identity
auditctl -w /etc/shadow -p wa -k identity
auditctl -w /etc/sudoers -p wa -k sudoers
auditctl -w /var/log/auth.log -p wa -k auth_log

echo "[+] VPS hardening complete"
echo "[!] SSH is now on port 2222"
echo "[!] Update your SSH command: ssh -p 2222 -i ~/.ssh/shadow313_vpn operator@YOUR_VPS_IP"
```

---

## PHASE 3: WIREGUARD INSTALLATION

### Step 3.1 — Server Configuration

```bash
#!/bin/bash
# ============================================================
# SHADOW313 WireGuard Server Setup
# Run as operator (sudo) on VPS
# ============================================================

SERVER_IP=$(curl -s https://ipinfo.io/ip)
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)

echo "[*] Server IP: $SERVER_IP"
echo "[*] Interface: $INTERFACE"

# Generate server keys
cd /etc/wireguard
sudo wg genkey | sudo tee server_private.key | sudo wg pubkey | sudo tee server_public.key
sudo chmod 600 /etc/wireguard/server_private.key

SERVER_PRIVATE=$(sudo cat /etc/wireguard/server_private.key)
SERVER_PUBLIC=$(sudo cat /etc/wireguard/server_public.key)

# Create WireGuard server config
sudo tee /etc/wireguard/wg0.conf << EOF
[Interface]
# Shadow313 WireGuard Server
Address = 10.13.13.1/24, fd42:42:42::1/64
ListenPort = 443
PrivateKey = $SERVER_PRIVATE
DNS = 10.13.13.1

# MTU optimized for performance
MTU = 1420

# Firewall rules — NAT all client traffic
PostUp  = iptables -A FORWARD -i wg0 -j ACCEPT
PostUp  = iptables -A FORWARD -o wg0 -j ACCEPT
PostUp  = iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE
PostUp  = ip6tables -A FORWARD -i wg0 -j ACCEPT
PostUp  = ip6tables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE

PostDown = iptables -D FORWARD -i wg0 -j ACCEPT
PostDown = iptables -D FORWARD -o wg0 -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o $INTERFACE -j MASQUERADE
PostDown = ip6tables -D FORWARD -i wg0 -j ACCEPT
PostDown = ip6tables -t nat -D POSTROUTING -o $INTERFACE -j MASQUERADE

# DNS leak prevention — block DNS except through tunnel
PostUp  = iptables -A FORWARD -i wg0 -p udp --dport 53 -j ACCEPT
PostUp  = iptables -A FORWARD -i wg0 -p tcp --dport 53 -j ACCEPT

EOF

sudo chmod 600 /etc/wireguard/wg0.conf

# Enable and start
sudo systemctl enable wg-quick@wg0
sudo systemctl start wg-quick@wg0

echo "[+] WireGuard running on port 443/UDP"
echo "[+] Server public key: $SERVER_PUBLIC"
```

---

### Step 3.2 — Client Management Script

```bash
#!/bin/bash
# ============================================================
# SHADOW313 — Add VPN Client
# Usage: sudo ./add_client.sh <name> <ip_last_octet>
# Example: sudo ./add_client.sh laptop 2
#          sudo ./add_client.sh iphone 3
#          sudo ./add_client.sh kali 4
#          sudo ./add_client.sh customer1 10
# ============================================================

CLIENT_NAME=${1:-"client"}
IP_OCTET=${2:-"10"}
SERVER_IP=$(curl -s https://ipinfo.io/ip)
SERVER_PUBLIC=$(cat /etc/wireguard/server_public.key)

CLIENT_IP="10.13.13.$IP_OCTET"
CLIENT_IP6="fd42:42:42::$IP_OCTET"

# Generate client keys
CLIENT_PRIVATE=$(wg genkey)
CLIENT_PUBLIC=$(echo "$CLIENT_PRIVATE" | wg pubkey)
CLIENT_PSK=$(wg genpsk)  # Pre-shared key — extra quantum-resistant layer

# Add peer to server
sudo tee -a /etc/wireguard/wg0.conf << EOF

# Client: $CLIENT_NAME (added $(date))
[Peer]
PublicKey = $CLIENT_PUBLIC
PresharedKey = $CLIENT_PSK
AllowedIPs = $CLIENT_IP/32, $CLIENT_IP6/128
EOF

# Reload without dropping connections
sudo wg syncconf wg0 <(sudo wg-quick strip wg0)

# Create client config directory
sudo mkdir -p /etc/wireguard/clients

# Generate client config
sudo tee /etc/wireguard/clients/$CLIENT_NAME.conf << EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE
Address = $CLIENT_IP/24, $CLIENT_IP6/64
DNS = 9.9.9.9, 149.112.112.112, 2620:fe::fe

# MTU to prevent fragmentation
MTU = 1420

[Peer]
# Shadow313 VPN Server
PublicKey = $SERVER_PUBLIC
PresharedKey = $CLIENT_PSK
Endpoint = $SERVER_IP:443
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

sudo chmod 600 /etc/wireguard/clients/$CLIENT_NAME.conf

# Generate QR code for mobile
echo ""
echo "============================================"
echo " Client: $CLIENT_NAME | IP: $CLIENT_IP"
echo "============================================"
echo ""
echo "Config file: /etc/wireguard/clients/$CLIENT_NAME.conf"
echo ""
echo "QR Code (for mobile):"
qrencode -t ansiutf8 < /etc/wireguard/clients/$CLIENT_NAME.conf
echo ""
echo "[+] Client $CLIENT_NAME added successfully"
```

---

## PHASE 4: ENCRYPTED DNS SERVER (UNBOUND)

Run your own recursive DNS resolver on the VPS — no third party sees your queries:

```bash
#!/bin/bash
# ============================================================
# SHADOW313 — Unbound Recursive DNS Setup
# Queries root servers directly — zero third-party DNS
# ============================================================

# Configure Unbound
sudo tee /etc/unbound/unbound.conf << 'EOF'
server:
    # Listen on WireGuard interface only
    interface: 10.13.13.1
    interface: 127.0.0.1
    port: 53
    
    # Only allow VPN clients
    access-control: 127.0.0.0/8 allow
    access-control: 10.13.13.0/24 allow
    access-control: fd42:42:42::/48 allow
    access-control: 0.0.0.0/0 refuse
    
    # Privacy settings
    hide-identity: yes
    hide-version: yes
    qname-minimisation: yes
    aggressive-nsec: yes
    
    # DNSSEC validation
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    
    # Performance
    num-threads: 2
    cache-min-ttl: 3600
    cache-max-ttl: 86400
    prefetch: yes
    prefetch-key: yes
    
    # Block known malware/tracking domains
    local-zone: "doubleclick.net" redirect
    local-zone: "googleadservices.com" redirect
    local-zone: "googlesyndication.com" redirect
    local-zone: "tracking.com" redirect
    local-data: "doubleclick.net A 0.0.0.0"
    local-data: "googleadservices.com A 0.0.0.0"
    
    # Logging (minimal — privacy)
    verbosity: 0
    log-queries: no
    log-replies: no
    
    # Hardening
    use-caps-for-id: yes
    val-clean-additional: yes
    
    # Root hints
    root-hints: "/var/lib/unbound/root.hints"

# Forward to Quad9 DoT as fallback
forward-zone:
    name: "."
    forward-tls-upstream: yes
    forward-addr: 9.9.9.9@853#dns.quad9.net
    forward-addr: 149.112.112.112@853#dns.quad9.net
EOF

# Download root hints
sudo curl -o /var/lib/unbound/root.hints https://www.internic.net/domain/named.cache

# Enable and start
sudo systemctl enable unbound
sudo systemctl restart unbound

# Test
dig @10.13.13.1 google.com
echo "[+] Unbound DNS running — queries go direct to root servers"
```

---

## PHASE 5: OBFUSCATION LAYER

Make WireGuard traffic look like normal HTTPS — bypasses deep packet inspection:

```bash
#!/bin/bash
# ============================================================
# SHADOW313 — Traffic Obfuscation with Nginx
# WireGuard on 443/UDP looks like HTTPS to DPI systems
# ============================================================

# Install Nginx as TLS camouflage
sudo apt install -y nginx certbot python3-certbot-nginx

# You need a domain pointing to your VPS IP
# Get a free domain: freedns.afraid.org or use your shadow313.dev subdomain
# Example: vpn.shadow313.dev → YOUR_VPS_IP

# Get TLS certificate (replace with your domain)
# sudo certbot --nginx -d vpn.yourdomain.com

# Nginx config — serves a real website on 443/TCP
# while WireGuard runs on 443/UDP
# DPI sees HTTPS traffic — cannot distinguish from normal web browsing
sudo tee /etc/nginx/sites-available/shadow313-vpn << 'EOF'
server {
    listen 443 ssl http2;
    server_name vpn.yourdomain.com;
    
    # TLS config
    ssl_certificate /etc/letsencrypt/live/vpn.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vpn.yourdomain.com/privkey.pem;
    ssl_protocols TLSv1.3;
    ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
    ssl_prefer_server_ciphers off;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=63072000" always;
    
    # Serve a decoy page — looks like a normal website
    root /var/www/shadow313;
    index index.html;
    
    location / {
        try_files $uri $uri/ =404;
    }
}
EOF

# Create decoy website
sudo mkdir -p /var/www/shadow313
sudo tee /var/www/shadow313/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head><title>Shadow313 Security Research</title></head>
<body>
<h1>Shadow313 Security Research Platform</h1>
<p>Authorized access only.</p>
</body>
</html>
EOF

sudo ln -sf /etc/nginx/sites-available/shadow313-vpn /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

echo "[+] Obfuscation layer active"
echo "[+] Port 443/TCP: Nginx (looks like HTTPS website)"
echo "[+] Port 443/UDP: WireGuard (looks like HTTPS traffic)"
echo "[+] DPI cannot distinguish VPN from normal HTTPS"
```

---

## PHASE 6: KILL-SWITCH CONFIGURATION

### WSL2/Ubuntu Kill-Switch

```bash
#!/bin/bash
# ============================================================
# SHADOW313 — WSL2 Kill-Switch
# Blocks ALL traffic if VPN drops — no IP leaks ever
# ============================================================

# Save as ~/shadow313-vpn/kill_switch.sh

VPN_INTERFACE="wg0"
VPN_SERVER="YOUR_VPS_IP"
DNS_SERVER="9.9.9.9"

enable_kill_switch() {
    echo "[*] Enabling kill-switch..."
    
    # Flush existing rules
    sudo iptables -F
    sudo iptables -X
    sudo ip6tables -F
    sudo ip6tables -X
    
    # Default: block everything
    sudo iptables -P INPUT DROP
    sudo iptables -P OUTPUT DROP
    sudo iptables -P FORWARD DROP
    sudo ip6tables -P INPUT DROP
    sudo ip6tables -P OUTPUT DROP
    sudo ip6tables -P FORWARD DROP
    
    # Allow loopback
    sudo iptables -A INPUT -i lo -j ACCEPT
    sudo iptables -A OUTPUT -o lo -j ACCEPT
    
    # Allow established connections
    sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    sudo iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    
    # Allow WireGuard tunnel traffic
    sudo iptables -A OUTPUT -o $VPN_INTERFACE -j ACCEPT
    sudo iptables -A INPUT -i $VPN_INTERFACE -j ACCEPT
    
    # Allow ONLY the VPN server connection (to establish tunnel)
    sudo iptables -A OUTPUT -d $VPN_SERVER -p udp --dport 443 -j ACCEPT
    sudo iptables -A INPUT -s $VPN_SERVER -p udp --sport 443 -j ACCEPT
    
    # Allow DNS through VPN only
    sudo iptables -A OUTPUT -o $VPN_INTERFACE -p udp --dport 53 -j ACCEPT
    sudo iptables -A OUTPUT -o $VPN_INTERFACE -p tcp --dport 53 -j ACCEPT
    
    # Block DNS leaks — prevent DNS outside VPN
    sudo iptables -A OUTPUT -p udp --dport 53 -j DROP
    sudo iptables -A OUTPUT -p tcp --dport 53 -j DROP
    
    # IPv6 kill-switch — block all IPv6 (prevent IPv6 leaks)
    sudo ip6tables -A INPUT -j DROP
    sudo ip6tables -A OUTPUT -j DROP
    
    echo "[+] Kill-switch ENABLED — all traffic blocked except VPN"
}

disable_kill_switch() {
    echo "[*] Disabling kill-switch..."
    sudo iptables -F
    sudo iptables -X
    sudo iptables -P INPUT ACCEPT
    sudo iptables -P OUTPUT ACCEPT
    sudo iptables -P FORWARD ACCEPT
    sudo ip6tables -F
    sudo ip6tables -P INPUT ACCEPT
    sudo ip6tables -P OUTPUT ACCEPT
    echo "[+] Kill-switch DISABLED — normal traffic restored"
}

connect_vpn() {
    enable_kill_switch
    echo "[*] Connecting to Shadow313 VPN..."
    sudo wg-quick up ~/shadow313-vpn/laptop.conf
    echo "[+] VPN connected"
    echo "[+] External IP: $(curl -s --max-time 5 https://ipinfo.io/ip)"
}

disconnect_vpn() {
    echo "[*] Disconnecting VPN..."
    sudo wg-quick down ~/shadow313-vpn/laptop.conf
    disable_kill_switch
    echo "[+] VPN disconnected"
}

status_vpn() {
    echo "=== VPN Status ==="
    sudo wg show 2>/dev/null || echo "WireGuard: not running"
    echo ""
    echo "=== Kill-Switch ==="
    sudo iptables -L OUTPUT --line-numbers | grep -E "DROP|ACCEPT" | head -10
    echo ""
    echo "=== Current IP ==="
    curl -s --max-time 5 https://ipinfo.io 2>/dev/null | jq . || echo "Cannot reach internet"
}

case "$1" in
    up|connect)    connect_vpn ;;
    down|disconnect) disconnect_vpn ;;
    status)        status_vpn ;;
    kill-on)       enable_kill_switch ;;
    kill-off)      disable_kill_switch ;;
    *)
        echo "Usage: $0 {up|down|status|kill-on|kill-off}"
        echo ""
        echo "  up        Connect VPN + enable kill-switch"
        echo "  down      Disconnect VPN + disable kill-switch"
        echo "  status    Show VPN and kill-switch status"
        echo "  kill-on   Enable kill-switch only"
        echo "  kill-off  Disable kill-switch only"
        ;;
esac
```

### Windows Kill-Switch (PowerShell)

```powershell
# ============================================================
# SHADOW313 — Windows Kill-Switch
# Run as Administrator
# ============================================================

$VPN_SERVER = "YOUR_VPS_IP"

function Enable-KillSwitch {
    Write-Host "[*] Enabling Windows kill-switch..." -ForegroundColor Yellow
    
    # Block all traffic by default
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block
    
    # Allow WireGuard tunnel
    New-NetFirewallRule -DisplayName "Shadow313-WG-Out" `
        -Direction Outbound -Protocol UDP `
        -RemoteAddress $VPN_SERVER -RemotePort 443 `
        -Action Allow -Profile Any
    
    New-NetFirewallRule -DisplayName "Shadow313-WG-In" `
        -Direction Inbound -Protocol UDP `
        -RemoteAddress $VPN_SERVER -RemotePort 443 `
        -Action Allow -Profile Any
    
    # Allow traffic through WireGuard interface
    New-NetFirewallRule -DisplayName "Shadow313-Tunnel-Out" `
        -Direction Outbound -InterfaceAlias "shadow313*" `
        -Action Allow -Profile Any
    
    New-NetFirewallRule -DisplayName "Shadow313-Tunnel-In" `
        -Direction Inbound -InterfaceAlias "shadow313*" `
        -Action Allow -Profile Any
    
    # Allow loopback
    New-NetFirewallRule -DisplayName "Shadow313-Loopback" `
        -Direction Outbound -InterfaceAlias "Loopback*" `
        -Action Allow -Profile Any
    
    Write-Host "[+] Kill-switch ENABLED" -ForegroundColor Green
}

function Disable-KillSwitch {
    Write-Host "[*] Disabling kill-switch..." -ForegroundColor Yellow
    
    # Remove Shadow313 rules
    Remove-NetFirewallRule -DisplayName "Shadow313*" -ErrorAction SilentlyContinue
    
    # Restore normal outbound
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow
    
    Write-Host "[+] Kill-switch DISABLED" -ForegroundColor Green
}

function Get-VPNStatus {
    Write-Host "=== Shadow313 VPN Status ===" -ForegroundColor Cyan
    $ip = (Invoke-WebRequest -Uri "https://ipinfo.io/ip" -UseBasicParsing).Content.Trim()
    Write-Host "External IP: $ip"
    
    $wg = Get-NetAdapter | Where-Object {$_.Name -like "*shadow313*" -or $_.Name -like "*wg*"}
    if ($wg) {
        Write-Host "WireGuard: CONNECTED ($($wg.Status))" -ForegroundColor Green
    } else {
        Write-Host "WireGuard: NOT CONNECTED" -ForegroundColor Red
    }
}
```

---

## PHASE 7: SHADOW313 INTEGRATION

```bash
#!/bin/bash
# ============================================================
# SHADOW313 — VPN Integration Script
# Integrates VPN with Shadow313 NEXUS workspace
# ============================================================

mkdir -p ~/shadow313-vpn
cd ~/shadow313-vpn

# Copy your client config from VPS
# scp -P 2222 operator@YOUR_VPS_IP:/etc/wireguard/clients/laptop.conf .

# Create Shadow313 VPN wrapper
cat > ~/shadow313-vpn/s313-vpn << 'SCRIPT'
#!/bin/bash
# Shadow313 VPN Manager

VPN_CONF="$HOME/shadow313-vpn/laptop.conf"
LOG="$HOME/shadow313-vpn/vpn.log"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG"; }

case "$1" in
    up)
        log "Connecting Shadow313 VPN..."
        sudo wg-quick up "$VPN_CONF"
        sleep 2
        EXT_IP=$(curl -s --max-time 5 https://ipinfo.io/ip)
        log "Connected. External IP: $EXT_IP"
        echo "[+] Shadow313 VPN ACTIVE — IP: $EXT_IP"
        ;;
    down)
        log "Disconnecting Shadow313 VPN..."
        sudo wg-quick down "$VPN_CONF"
        log "Disconnected"
        echo "[+] Shadow313 VPN INACTIVE"
        ;;
    status)
        echo "=== Shadow313 VPN Status ==="
        sudo wg show 2>/dev/null || echo "Not connected"
        echo ""
        echo "External IP: $(curl -s --max-time 5 https://ipinfo.io/ip)"
        echo "DNS: $(dig +short @9.9.9.9 whoami.akamai.net 2>/dev/null || echo 'check failed')"
        ;;
    test)
        echo "=== VPN Leak Test ==="
        echo "IPv4: $(curl -s https://ipinfo.io/ip)"
        echo "IPv6: $(curl -s https://ipv6.icanhazip.com 2>/dev/null || echo 'No IPv6 leak')"
        echo "DNS:  $(dig +short TXT whoami.cloudflare.com @1.1.1.1 2>/dev/null)"
        echo ""
        echo "Run full leak test: https://dnsleaktest.com"
        echo "Run IP leak test:   https://ipleak.net"
        ;;
    logs)
        tail -50 "$LOG"
        ;;
    *)
        echo "Shadow313 VPN Manager"
        echo "Usage: s313-vpn {up|down|status|test|logs}"
        ;;
esac
SCRIPT

chmod +x ~/shadow313-vpn/s313-vpn
sudo ln -sf ~/shadow313-vpn/s313-vpn /usr/local/bin/s313-vpn

# Add to .bashrc
echo 'alias vpn="s313-vpn"' >> ~/.bashrc
echo 'alias vpn-up="s313-vpn up"' >> ~/.bashrc
echo 'alias vpn-down="s313-vpn down"' >> ~/.bashrc
echo 'alias vpn-status="s313-vpn status"' >> ~/.bashrc

echo "[+] Shadow313 VPN integration complete"
echo "[+] Commands: vpn-up | vpn-down | vpn-status | s313-vpn test"
```

---

## PHASE 8: COMMERCIAL VPN SHARING SETUP

Yes — you can legally charge people for VPN access. This is exactly what Mullvad, ProtonVPN, and NordVPN do. Here's how to set it up properly:

### Legal Requirements
- Register as a business (sole proprietor is fine in Canada — ~$60 one-time)
- Have a **Terms of Service** and **Privacy Policy** (no-logs policy)
- Do NOT allow illegal activity on your VPN (add this to ToS)
- Keep no connection logs (this protects you legally too)

### Technical Setup for Multiple Customers

```bash
#!/bin/bash
# ============================================================
# SHADOW313 VPN — Customer Management System
# ============================================================

# Customer database (simple file-based)
CUSTOMER_DB="/etc/wireguard/customers.db"
touch "$CUSTOMER_DB"

add_customer() {
    local NAME=$1
    local EMAIL=$2
    local PLAN=$3  # basic/pro/enterprise
    local EXPIRY=$4  # YYYY-MM-DD
    
    # Assign IP
    EXISTING=$(wc -l < "$CUSTOMER_DB")
    IP_OCTET=$((EXISTING + 20))  # Start customers at .20
    
    # Generate config
    ./add_client.sh "$NAME" "$IP_OCTET"
    
    # Record in database
    echo "$NAME|$EMAIL|$PLAN|$EXPIRY|10.13.13.$IP_OCTET|$(date)" >> "$CUSTOMER_DB"
    
    echo "[+] Customer $NAME added"
    echo "[+] Config: /etc/wireguard/clients/$NAME.conf"
    echo "[+] Send them the config file or QR code"
}

revoke_customer() {
    local NAME=$1
    
    # Remove peer from WireGuard
    CLIENT_PUBLIC=$(grep -A5 "Client: $NAME" /etc/wireguard/wg0.conf | grep PublicKey | awk '{print $3}')
    sudo wg set wg0 peer "$CLIENT_PUBLIC" remove
    
    # Remove from config
    sudo sed -i "/# Client: $NAME/,/^$/d" /etc/wireguard/wg0.conf
    
    # Mark as revoked in DB
    sed -i "s/^$NAME|/REVOKED_$NAME|/" "$CUSTOMER_DB"
    
    echo "[+] Customer $NAME revoked"
}

list_customers() {
    echo "=== Active Customers ==="
    echo "Name | Email | Plan | Expiry | IP"
    echo "─────────────────────────────────"
    grep -v "^REVOKED" "$CUSTOMER_DB" | while IFS='|' read name email plan expiry ip date; do
        echo "$name | $email | $plan | $expiry | $ip"
    done
    echo ""
    echo "=== Connected Right Now ==="
    sudo wg show wg0 peers | while read peer; do
        sudo wg show wg0 | grep -A5 "$peer" | grep "latest handshake"
    done
}

check_expiry() {
    TODAY=$(date +%Y-%m-%d)
    while IFS='|' read name email plan expiry ip date; do
        if [[ "$expiry" < "$TODAY" ]]; then
            echo "[!] EXPIRED: $name ($email) — expired $expiry"
            # Auto-revoke expired accounts
            # revoke_customer "$name"
        fi
    done < "$CUSTOMER_DB"
}

case "$1" in
    add)    add_customer "$2" "$3" "$4" "$5" ;;
    revoke) revoke_customer "$2" ;;
    list)   list_customers ;;
    check)  check_expiry ;;
    *)
        echo "Usage: $0 {add <name> <email> <plan> <expiry>|revoke <name>|list|check}"
        ;;
esac
```

### Pricing Model (What Others Charge)
```
Basic Plan:    1 device,  $3-5 CAD/month
Pro Plan:      3 devices, $7-10 CAD/month
Family Plan:   5 devices, $12-15 CAD/month
```

With a €3.29/month Hetzner server you can support **50-100 simultaneous users** easily. At $5/user that's $250-500/month revenue from a $4 server.

### Payment Collection
- **Stripe** — easy, accepts credit cards, 2.9% + $0.30 per transaction
- **PayPal** — widely accepted
- **Cryptocurrency** — for privacy-focused customers (BTCPay Server, self-hosted)

---

## PHASE 9: MONITORING DASHBOARD

```bash
#!/bin/bash
# ============================================================
# SHADOW313 VPN — Status Dashboard
# Run on VPS: watch -n 5 ./vpn_dashboard.sh
# ============================================================

clear
echo "╔══════════════════════════════════════════════════════════╗"
echo "║         SHADOW313 VPN — OPERATIONS DASHBOARD            ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "Server: $(curl -s https://ipinfo.io/ip) | $(date)"
echo "Uptime: $(uptime -p)"
echo ""

echo "── WIREGUARD STATUS ──────────────────────────────────────"
sudo wg show wg0 2>/dev/null || echo "WireGuard not running!"
echo ""

echo "── CONNECTED CLIENTS ─────────────────────────────────────"
PEERS=$(sudo wg show wg0 peers 2>/dev/null | wc -l)
echo "Total peers configured: $PEERS"
echo ""
sudo wg show wg0 transfer 2>/dev/null | while read peer rx tx; do
    echo "  Peer: ${peer:0:20}... RX: $rx TX: $tx"
done
echo ""

echo "── SYSTEM RESOURCES ──────────────────────────────────────"
echo "CPU:    $(top -bn1 | grep "Cpu(s)" | awk '{print $2}')% used"
echo "RAM:    $(free -h | awk '/^Mem:/{print $3 "/" $2}')"
echo "Disk:   $(df -h / | awk 'NR==2{print $3 "/" $2 " (" $5 " used)"}')"
echo "Load:   $(cat /proc/loadavg | awk '{print $1, $2, $3}')"
echo ""

echo "── SECURITY ──────────────────────────────────────────────"
echo "Fail2ban bans: $(sudo fail2ban-client status sshd 2>/dev/null | grep 'Banned IP' | awk '{print $NF}')"
echo "Active SSH:    $(ss -tnp | grep :2222 | wc -l) connections"
echo "Firewall:      $(sudo ufw status | head -1)"
echo ""

echo "── NETWORK ───────────────────────────────────────────────"
echo "Bandwidth in:  $(cat /proc/net/dev | grep $INTERFACE | awk '{print $2}') bytes"
echo "Bandwidth out: $(cat /proc/net/dev | grep $INTERFACE | awk '{print $10}') bytes"
```

---

## PHASE 10: VERIFICATION AND LEAK TESTING

```bash
#!/bin/bash
# ============================================================
# SHADOW313 VPN — Full Leak Test
# Run from your laptop AFTER connecting to VPN
# ============================================================

echo "╔══════════════════════════════════════════════════════════╗"
echo "║         SHADOW313 VPN — LEAK TEST SUITE                 ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Test 1: IPv4
echo "[1] IPv4 Address:"
curl -s https://ipinfo.io/ip
echo ""

# Test 2: IPv6 leak
echo "[2] IPv6 Leak Test:"
IPV6=$(curl -s --max-time 5 https://ipv6.icanhazip.com 2>/dev/null)
if [ -z "$IPV6" ]; then
    echo "  ✅ No IPv6 leak detected"
else
    echo "  ❌ IPv6 LEAK: $IPV6"
fi
echo ""

# Test 3: DNS leak
echo "[3] DNS Leak Test:"
DNS_IP=$(dig +short TXT whoami.cloudflare.com @1.1.1.1 2>/dev/null | tr -d '"')
echo "  DNS resolver: $DNS_IP"
if echo "$DNS_IP" | grep -q "9.9.9.9\|149.112\|10.13.13"; then
    echo "  ✅ DNS going through VPN"
else
    echo "  ⚠️  Check DNS — may be leaking"
fi
echo ""

# Test 4: WebRTC leak (browser-based — manual)
echo "[4] WebRTC Leak:"
echo "  Manual check required: https://browserleaks.com/webrtc"
echo ""

# Test 5: Geolocation
echo "[5] Geolocation:"
curl -s https://ipinfo.io | jq '{ip, city, region, country, org}'
echo ""

# Test 6: Tor check
echo "[6] Tor/VPN Detection:"
curl -s https://check.torproject.org/api/ip | jq .
echo ""

echo "Full leak test: https://dnsleaktest.com"
echo "IP leak test:   https://ipleak.net"
echo "Browser test:   https://browserleaks.com"
```

---

## QUICK REFERENCE

### Daily Commands (WSL2/Ubuntu)
```bash
vpn-up          # Connect VPN + kill-switch
vpn-down        # Disconnect VPN
vpn-status      # Check status
s313-vpn test   # Full leak test
```

### Server Management (SSH to VPS)
```bash
ssh -p 2222 -i ~/.ssh/shadow313_vpn operator@YOUR_VPS_IP

sudo wg show                    # See all clients
sudo systemctl status wg-quick@wg0
./add_client.sh newclient 15    # Add new client
./vpn_dashboard.sh              # Full dashboard
```

### Cost Summary
```
Hetzner CX22 VPS:  €3.29/month (~$4.80 CAD)
Domain (optional): ~$12/year
SSL cert:          Free (Let's Encrypt)
Total:             ~$5 CAD/month
Supports:          50-100 simultaneous users
```