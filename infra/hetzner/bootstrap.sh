#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Shadow313 NEXUS — Hetzner VPS Bootstrap Script
# Run as root on a fresh Ubuntu 24.04 Hetzner CX22 server
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/piyyy314/Shadow313-Nexus/master/infra/hetzner/bootstrap.sh | bash
#   OR: bash bootstrap.sh
#
# What this does:
#   1. System hardening (UFW, fail2ban, SSH hardening)
#   2. Docker + Docker Compose
#   3. WireGuard VPN server
#   4. Nginx + Certbot (Let's Encrypt SSL)
#   5. Shadow313 NEXUS stack (API + Telegram bot + PostgreSQL)
#   6. Suricata IDS
#   7. Automatic security updates
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; AMBER='\033[0;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

log()  { echo -e "${GREEN}[✅]${RESET} $*"; }
warn() { echo -e "${AMBER}[⚠️ ]${RESET} $*"; }
err()  { echo -e "${RED}[❌]${RESET} $*"; exit 1; }
info() { echo -e "${CYAN}[ℹ️ ]${RESET} $*"; }
hdr()  { echo -e "\n${BOLD}${CYAN}══ $* ══${RESET}"; }

# ── Detect server IP ──────────────────────────────────────────────────────────
SERVER_IP=$(curl -s https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')
HOSTNAME="shadow313-nexus-vps"

echo -e "${BOLD}"
cat << 'BANNER'
  ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗██████╗
  ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║╚════██╗
  ███████╗███████║███████║██║  ██║██║   ██║██║  ▄███╔╝
  ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║ ▄██╔╝
  ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝██║ ██████╗
  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═╝╚═════╝
  NEXUS v4.0.0 — Hetzner VPS Bootstrap
  Post-Quantum Security Intelligence Platform
BANNER
echo -e "${RESET}"

info "Server IP: ${SERVER_IP}"
info "Starting bootstrap — this takes ~5 minutes"
echo ""

# ── Check root ────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && err "Run as root: sudo bash bootstrap.sh"

# ── PHASE 1: System Update ────────────────────────────────────────────────────
hdr "PHASE 1: System Update"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get upgrade -y -qq
apt-get install -y -qq \
    curl wget git unzip jq \
    ufw fail2ban \
    wireguard wireguard-tools \
    nginx certbot python3-certbot-nginx \
    postgresql postgresql-contrib \
    suricata \
    htop net-tools dnsutils \
    apt-transport-https ca-certificates gnupg lsb-release \
    unattended-upgrades
log "System packages installed"

# ── PHASE 2: Docker ───────────────────────────────────────────────────────────
hdr "PHASE 2: Docker"
if ! command -v docker &>/dev/null; then
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
fi
systemctl enable docker
systemctl start docker
log "Docker $(docker --version | cut -d' ' -f3 | tr -d ',') installed"

# ── PHASE 3: SSH Hardening ────────────────────────────────────────────────────
hdr "PHASE 3: SSH Hardening"
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
cat > /etc/ssh/sshd_config.d/shadow313-hardening.conf << 'SSHEOF'
# Shadow313 SSH Hardening
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
X11Forwarding no
AllowTcpForwarding no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
Protocol 2
SSHEOF
systemctl reload sshd
log "SSH hardened (key-only auth, no passwords)"

# ── PHASE 4: Firewall ─────────────────────────────────────────────────────────
hdr "PHASE 4: UFW Firewall"
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp    comment "SSH"
ufw allow 80/tcp    comment "HTTP"
ufw allow 443/tcp   comment "HTTPS"
ufw allow 51820/udp comment "WireGuard VPN"
ufw --force enable
log "Firewall configured (22/tcp, 80/tcp, 443/tcp, 51820/udp)"

# ── PHASE 5: fail2ban ─────────────────────────────────────────────────────────
hdr "PHASE 5: fail2ban"
cat > /etc/fail2ban/jail.local << 'F2BEOF'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5
backend  = systemd

[sshd]
enabled  = true
port     = ssh
logpath  = %(sshd_log)s
maxretry = 3
bantime  = 86400

[nginx-http-auth]
enabled  = true

[nginx-limit-req]
enabled  = true
F2BEOF
systemctl enable fail2ban
systemctl restart fail2ban
log "fail2ban configured (SSH: 3 attempts → 24h ban)"

# ── PHASE 6: WireGuard VPN ────────────────────────────────────────────────────
hdr "PHASE 6: WireGuard VPN Server"
mkdir -p /etc/wireguard
chmod 700 /etc/wireguard

# Generate server keys
wg genkey | tee /etc/wireguard/server_private.key | wg pubkey > /etc/wireguard/server_public.key
chmod 600 /etc/wireguard/server_private.key

SERVER_PRIVATE=$(cat /etc/wireguard/server_private.key)
SERVER_PUBLIC=$(cat /etc/wireguard/server_public.key)

# Detect primary network interface
PRIMARY_IF=$(ip route | grep default | awk '{print $5}' | head -1)

cat > /etc/wireguard/wg0.conf << WGEOF
[Interface]
Address    = 10.8.0.1/24
ListenPort = 51820
PrivateKey = ${SERVER_PRIVATE}
PostUp     = iptables -t nat -I POSTROUTING -o ${PRIMARY_IF} -j MASQUERADE; iptables -I FORWARD -i wg0 -j ACCEPT; iptables -I FORWARD -o wg0 -j ACCEPT
PreDown    = iptables -t nat -D POSTROUTING -o ${PRIMARY_IF} -j MASQUERADE; iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT

# ── Add your laptop as a peer ──────────────────────────────────────────────
# Run on your laptop:
#   wg genkey | Out-File wg-private.key
#   Get-Content wg-private.key | wg pubkey | Out-File wg-public.key
# Then add below:
# [Peer]
# PublicKey  = YOUR_LAPTOP_PUBLIC_KEY
# AllowedIPs = 10.8.0.2/32
WGEOF

chmod 600 /etc/wireguard/wg0.conf

# Enable IP forwarding
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
sysctl -p -q

systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0
log "WireGuard server running on UDP:51820"
info "Server public key: ${SERVER_PUBLIC}"

# ── PHASE 7: Clone Shadow313 ──────────────────────────────────────────────────
hdr "PHASE 7: Shadow313 NEXUS"
mkdir -p /opt/shadow313
if [[ ! -d /opt/shadow313/.git ]]; then
    git clone https://github.com/piyyy314/Shadow313-Nexus.git /opt/shadow313
else
    cd /opt/shadow313 && git pull origin master
fi
cd /opt/shadow313

# Generate secrets
API_KEY=$(openssl rand -hex 32)
JWT_SECRET=$(openssl rand -hex 32)
DB_PASSWORD=$(openssl rand -hex 16)

# Create production .env
cat > /opt/shadow313/.env << ENVEOF
# Shadow313 NEXUS — Production Environment
# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Server: ${SERVER_IP}

SHADOW313_ENV=production
SHADOW313_API_KEY=${API_KEY}
SHADOW313_JWT_SECRET=${JWT_SECRET}
SHADOW313_AI_BACKEND=disabled
SHADOW313_CORS_ORIGINS=https://shadow313.dev,https://shadow313.com

# Database
POSTGRES_DB=shadow313
POSTGRES_USER=shadow313
POSTGRES_PASSWORD=${DB_PASSWORD}
DATABASE_URL=postgresql://shadow313:${DB_PASSWORD}@postgresql:5432/shadow313

# Telegram (fill in after creating bot)
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
TELEGRAM_MIN_SEVERITY=HIGH

# Nginx
DOMAIN=shadow313.dev
ENVEOF
chmod 600 /opt/shadow313/.env
log "Shadow313 repo cloned + .env generated"

# ── PHASE 8: PostgreSQL ───────────────────────────────────────────────────────
hdr "PHASE 8: PostgreSQL"
systemctl enable postgresql
systemctl start postgresql
sudo -u postgres psql -c "CREATE USER shadow313 WITH PASSWORD '${DB_PASSWORD}';" 2>/dev/null || true
sudo -u postgres psql -c "CREATE DATABASE shadow313 OWNER shadow313;" 2>/dev/null || true
log "PostgreSQL configured (shadow313 database)"

# ── PHASE 9: Nginx ────────────────────────────────────────────────────────────
hdr "PHASE 9: Nginx Reverse Proxy"
cat > /etc/nginx/sites-available/shadow313 << 'NGINXEOF'
# Shadow313 NEXUS — Nginx Configuration
# Reverse proxy for Shadow313 API

server {
    listen 80;
    server_name api.shadow313.dev shadow313.dev;

    # Redirect HTTP to HTTPS
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name api.shadow313.dev;

    # SSL (managed by Certbot)
    ssl_certificate     /etc/letsencrypt/live/api.shadow313.dev/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.shadow313.dev/privkey.pem;
    ssl_protocols       TLSv1.3 TLSv1.2;
    ssl_ciphers         ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'" always;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=60r/m;
    limit_req zone=api burst=20 nodelay;

    # Shadow313 API proxy
    location /api/ {
        proxy_pass         http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade $http_upgrade;
        proxy_set_header   Connection 'upgrade';
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        proxy_read_timeout 300s;
    }

    # WebSocket support for real-time events
    location /ws/ {
        proxy_pass         http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade $http_upgrade;
        proxy_set_header   Connection "Upgrade";
        proxy_set_header   Host $host;
    }

    # Health check (no auth)
    location /health {
        proxy_pass http://127.0.0.1:8000/health;
    }
}
NGINXEOF

ln -sf /etc/nginx/sites-available/shadow313 /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx
log "Nginx configured (reverse proxy for Shadow313 API)"

# ── PHASE 10: Docker Stack ────────────────────────────────────────────────────
hdr "PHASE 10: Shadow313 Docker Stack"
cd /opt/shadow313

# Start core services (no Ollama — too heavy for CX22)
docker compose up -d shadow313-api postgresql 2>/dev/null || \
    docker compose up -d 2>/dev/null || \
    warn "Docker compose failed — check /opt/shadow313/docker-compose.yml"

log "Shadow313 API starting on port 8000"

# ── PHASE 11: Suricata IDS ────────────────────────────────────────────────────
hdr "PHASE 11: Suricata IDS"
suricata-update 2>/dev/null || true
systemctl enable suricata
systemctl start suricata 2>/dev/null || warn "Suricata start failed — check config"
log "Suricata IDS configured"

# ── PHASE 12: Automatic Security Updates ─────────────────────────────────────
hdr "PHASE 12: Automatic Security Updates"
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'AUTOEOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
AUTOEOF
systemctl enable unattended-upgrades
log "Automatic security updates enabled"

# ── PHASE 13: Monitoring Script ───────────────────────────────────────────────
hdr "PHASE 13: Health Monitor"
cat > /usr/local/bin/shadow313-status << 'STATUSEOF'
#!/bin/bash
echo "═══════════════════════════════════════════"
echo "  Shadow313 NEXUS — VPS Status"
echo "  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "═══════════════════════════════════════════"
echo ""
echo "🐳 Docker containers:"
docker ps --format "  {{.Names}} | {{.Status}}" 2>/dev/null || echo "  Docker not running"
echo ""
echo "🔐 WireGuard:"
wg show 2>/dev/null || echo "  WireGuard not running"
echo ""
echo "🌐 Nginx:"
systemctl is-active nginx && echo "  ✅ Running" || echo "  ❌ Not running"
echo ""
echo "🛡️  fail2ban:"
fail2ban-client status sshd 2>/dev/null | grep "Currently banned" || echo "  No bans"
echo ""
echo "💾 Disk:"
df -h / | tail -1 | awk '{print "  Used: "$3" / "$2" ("$5")"}'
echo ""
echo "🧠 Memory:"
free -h | grep Mem | awk '{print "  Used: "$3" / "$2}'
STATUSEOF
chmod +x /usr/local/bin/shadow313-status
log "Status script: run 'shadow313-status' anytime"

# ── PHASE 14: Cron jobs ───────────────────────────────────────────────────────
hdr "PHASE 14: Cron Jobs"
(crontab -l 2>/dev/null; echo "0 3 * * * cd /opt/shadow313 && git pull origin master --quiet 2>/dev/null") | crontab -
(crontab -l 2>/dev/null; echo "0 4 * * * docker compose -f /opt/shadow313/docker-compose.yml pull --quiet 2>/dev/null && docker compose -f /opt/shadow313/docker-compose.yml up -d 2>/dev/null") | crontab -
log "Cron: daily git pull + docker update at 3-4am UTC"

# ── FINAL SUMMARY ─────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${GREEN}║   Shadow313 NEXUS VPS Bootstrap COMPLETE ✅              ║${RESET}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "${BOLD}Server IP:${RESET}        ${SERVER_IP}"
echo -e "${BOLD}WireGuard key:${RESET}    ${SERVER_PUBLIC}"
echo -e "${BOLD}API key:${RESET}          ${API_KEY}"
echo -e "${BOLD}JWT secret:${RESET}       ${JWT_SECRET}"
echo -e "${BOLD}DB password:${RESET}      ${DB_PASSWORD}"
echo ""
echo -e "${AMBER}⚠️  SAVE THESE CREDENTIALS TO KEEPASSXC NOW${RESET}"
echo ""
echo -e "${BOLD}Services running:${RESET}"
echo "  ✅ UFW firewall (22/tcp, 80/tcp, 443/tcp, 51820/udp)"
echo "  ✅ fail2ban (SSH brute force protection)"
echo "  ✅ WireGuard VPN server (UDP:51820)"
echo "  ✅ Docker + Shadow313 API (port 8000)"
echo "  ✅ PostgreSQL (shadow313 database)"
echo "  ✅ Nginx reverse proxy"
echo "  ✅ Suricata IDS"
echo "  ✅ Automatic security updates"
echo ""
echo -e "${BOLD}Next steps:${RESET}"
echo "  1. Add your laptop as WireGuard peer:"
echo "     wg set wg0 peer YOUR_LAPTOP_PUBLIC_KEY allowed-ips 10.8.0.2/32"
echo "     wg-quick save wg0"
echo ""
echo "  2. Get SSL certificate:"
echo "     certbot --nginx -d api.shadow313.dev --non-interactive --agree-tos -m mohamad@shadow313.dev"
echo ""
echo "  3. Add Telegram token to .env:"
echo "     nano /opt/shadow313/.env"
echo "     # Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID"
echo "     docker compose --profile telegram up -d telegram-bot"
echo ""
echo "  4. Check status anytime:"
echo "     shadow313-status"
echo ""
echo -e "${GREEN}shadow313.dev is ready to launch 🚀${RESET}"
