#!/bin/bash
# ══════════════════════════════════════════════════════════════════
# Shadow313 NEXUS — Hetzner CX22 VPS Provisioner
# SHA-24: Rent + configure Hetzner VPS for WireGuard VPN + Shadow313
#
# Run this script ON THE VPS after first SSH login as root:
#   ssh root@<VPS_IP>
#   curl -fsSL https://raw.githubusercontent.com/piyyy314/Shadow313-Nexus/master/infra/hetzner/provision.sh | bash
#
# Or copy and run manually.
# ══════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────
VPN_PORT="${VPN_PORT:-51820}"
SSH_PORT="${SSH_PORT:-2222}"
OPERATOR_USER="${OPERATOR_USER:-shadow313}"
WG_SUBNET="10.13.13.0/24"
WG_SERVER_IP="10.13.13.1"
WG_CLIENT_IP="10.13.13.2"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; NC='\033[0m'; BOLD='\033[1m'

log()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*"; exit 1; }

echo -e "${BOLD}"
echo "  ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗██████╗"
echo "  ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║╚════██╗"
echo "  ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║ █████╔╝"
echo "  ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║ ╚═══██╗"
echo "  ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝██████╔╝"
echo "  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚═════╝"
echo -e "${NC}"
echo -e "${BOLD}  Shadow313 NEXUS — Hetzner VPS Provisioner${NC}"
echo -e "  SHA-24 | CX22 | Ubuntu 24.04 LTS"
echo ""

# ── Verify running as root ────────────────────────────────────────
[[ $EUID -ne 0 ]] && err "Must run as root"

# ── Detect VPS IP ─────────────────────────────────────────────────
VPS_IP=$(curl -sf https://api.ipify.org || curl -sf https://ifconfig.me || hostname -I | awk '{print $1}')
log "VPS public IP: ${VPS_IP}"

# ══════════════════════════════════════════════════════════════════
# PHASE 1: System update + essential packages
# ══════════════════════════════════════════════════════════════════
log "Phase 1: System update..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get upgrade -y -qq
apt-get install -y -qq \
    wireguard wireguard-tools \
    ufw fail2ban \
    curl wget git unzip \
    python3 python3-pip python3-venv \
    htop tmux vim \
    qrencode \
    net-tools iproute2 \
    openssl \
    jq \
    logrotate \
    apt-transport-https ca-certificates gnupg
ok "System updated"

# ══════════════════════════════════════════════════════════════════
# PHASE 2: Create operator user
# ══════════════════════════════════════════════════════════════════
log "Phase 2: Creating operator user '${OPERATOR_USER}'..."
if ! id "${OPERATOR_USER}" &>/dev/null; then
    useradd -m -s /bin/bash -G sudo "${OPERATOR_USER}"
    # Copy root SSH keys to operator
    mkdir -p /home/${OPERATOR_USER}/.ssh
    cp /root/.ssh/authorized_keys /home/${OPERATOR_USER}/.ssh/ 2>/dev/null || true
    chown -R ${OPERATOR_USER}:${OPERATOR_USER} /home/${OPERATOR_USER}/.ssh
    chmod 700 /home/${OPERATOR_USER}/.ssh
    chmod 600 /home/${OPERATOR_USER}/.ssh/authorized_keys 2>/dev/null || true
    ok "User '${OPERATOR_USER}' created"
else
    warn "User '${OPERATOR_USER}' already exists"
fi

# ══════════════════════════════════════════════════════════════════
# PHASE 3: SSH hardening
# ══════════════════════════════════════════════════════════════════
log "Phase 3: SSH hardening (port ${SSH_PORT})..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

cat > /etc/ssh/sshd_config << EOF
# Shadow313 NEXUS — Hardened SSH Config
Port ${SSH_PORT}
Protocol 2
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

# Authentication
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Security
X11Forwarding no
AllowTcpForwarding no
GatewayPorts no
PermitTunnel no
MaxAuthTries 3
MaxSessions 5
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Allow only operator user
AllowUsers ${OPERATOR_USER}
EOF

systemctl restart sshd
ok "SSH hardened on port ${SSH_PORT}"

# ══════════════════════════════════════════════════════════════════
# PHASE 4: Kernel hardening
# ══════════════════════════════════════════════════════════════════
log "Phase 4: Kernel hardening..."
cat > /etc/sysctl.d/99-shadow313.conf << 'EOF'
# Shadow313 NEXUS — Kernel Hardening

# IP forwarding (required for WireGuard VPN)
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# Anti-spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Log martian packets
net.ipv4.conf.all.log_martians = 1

# Disable IPv6 if not needed (comment out if you use IPv6)
# net.ipv6.conf.all.disable_ipv6 = 1

# Memory protection
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 3

# Prevent core dumps
fs.suid_dumpable = 0

# Restrict ptrace
kernel.yama.ptrace_scope = 1
EOF

sysctl -p /etc/sysctl.d/99-shadow313.conf > /dev/null 2>&1
ok "Kernel hardened"

# ══════════════════════════════════════════════════════════════════
# PHASE 5: WireGuard VPN setup
# ══════════════════════════════════════════════════════════════════
log "Phase 5: WireGuard VPN setup..."
mkdir -p /etc/wireguard
chmod 700 /etc/wireguard

# Generate server keys
wg genkey | tee /etc/wireguard/server_private.key | wg pubkey > /etc/wireguard/server_public.key
chmod 600 /etc/wireguard/server_private.key

# Generate client keys
wg genkey | tee /etc/wireguard/client_private.key | wg pubkey > /etc/wireguard/client_public.key
chmod 600 /etc/wireguard/client_private.key

SERVER_PRIVATE=$(cat /etc/wireguard/server_private.key)
SERVER_PUBLIC=$(cat /etc/wireguard/server_public.key)
CLIENT_PRIVATE=$(cat /etc/wireguard/client_private.key)
CLIENT_PUBLIC=$(cat /etc/wireguard/client_public.key)

# Detect primary network interface
PRIMARY_IF=$(ip route | grep default | awk '{print $5}' | head -1)

# Server config
cat > /etc/wireguard/wg0.conf << EOF
# Shadow313 NEXUS — WireGuard Server Config
[Interface]
Address = ${WG_SERVER_IP}/24
ListenPort = ${VPN_PORT}
PrivateKey = ${SERVER_PRIVATE}

# NAT for VPN clients
PostUp   = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o ${PRIMARY_IF} -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o ${PRIMARY_IF} -j MASQUERADE

# Client: shiatoali laptop
[Peer]
PublicKey = ${CLIENT_PUBLIC}
AllowedIPs = ${WG_CLIENT_IP}/32
EOF

chmod 600 /etc/wireguard/wg0.conf

# Client config (save for download)
cat > /etc/wireguard/client_shadow313.conf << EOF
# Shadow313 NEXUS — WireGuard Client Config
# Copy this to your laptop: C:\Users\shiatoali\shadow313-nexus\wireguard\wg0.conf

[Interface]
Address = ${WG_CLIENT_IP}/24
PrivateKey = ${CLIENT_PRIVATE}
DNS = 9.9.9.9, 149.112.112.112

[Peer]
PublicKey = ${SERVER_PUBLIC}
Endpoint = ${VPS_IP}:${VPN_PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

# Enable and start WireGuard
systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0
ok "WireGuard VPN running on port ${VPN_PORT}"

# ══════════════════════════════════════════════════════════════════
# PHASE 6: UFW Firewall
# ══════════════════════════════════════════════════════════════════
log "Phase 6: UFW firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# SSH on custom port
ufw allow ${SSH_PORT}/tcp comment "SSH"

# WireGuard VPN
ufw allow ${VPN_PORT}/udp comment "WireGuard VPN"

# Allow traffic from VPN subnet
ufw allow from ${WG_SUBNET} comment "WireGuard clients"

# Enable UFW
ufw --force enable
ok "UFW firewall configured"

# ══════════════════════════════════════════════════════════════════
# PHASE 7: Fail2ban
# ══════════════════════════════════════════════════════════════════
log "Phase 7: Fail2ban..."
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 3
backend  = systemd

[sshd]
enabled  = true
port     = ${SSH_PORT}
logpath  = %(sshd_log)s
maxretry = 3
bantime  = 86400
EOF

systemctl enable fail2ban
systemctl restart fail2ban
ok "Fail2ban configured"

# ══════════════════════════════════════════════════════════════════
# PHASE 8: Unattended security upgrades
# ══════════════════════════════════════════════════════════════════
log "Phase 8: Automatic security updates..."
apt-get install -y -qq unattended-upgrades
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
ok "Automatic security updates enabled"

# ══════════════════════════════════════════════════════════════════
# PHASE 9: Generate QR code for mobile WireGuard
# ══════════════════════════════════════════════════════════════════
log "Phase 9: Generating WireGuard QR code..."
echo ""
echo "══════════════════════════════════════════════════════"
echo "  Scan this QR code with WireGuard mobile app:"
echo "══════════════════════════════════════════════════════"
qrencode -t ansiutf8 < /etc/wireguard/client_shadow313.conf
echo "══════════════════════════════════════════════════════"

# ══════════════════════════════════════════════════════════════════
# DONE
# ══════════════════════════════════════════════════════════════════
echo ""
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  ✅ Shadow313 NEXUS VPS Provisioning Complete!${NC}"
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  VPS IP:        ${BOLD}${VPS_IP}${NC}"
echo -e "  SSH Port:      ${BOLD}${SSH_PORT}${NC}"
echo -e "  VPN Port:      ${BOLD}${VPN_PORT}/udp${NC}"
echo -e "  WG Server IP:  ${BOLD}${WG_SERVER_IP}${NC}"
echo -e "  WG Client IP:  ${BOLD}${WG_CLIENT_IP}${NC}"
echo ""
echo -e "  ${CYAN}Client config saved to:${NC}"
echo -e "  /etc/wireguard/client_shadow313.conf"
echo ""
echo -e "  ${YELLOW}NEXT STEPS:${NC}"
echo -e "  1. Copy client config to your laptop:"
echo -e "     scp -P ${SSH_PORT} ${OPERATOR_USER}@${VPS_IP}:/etc/wireguard/client_shadow313.conf ."
echo -e "  2. Import into WireGuard on Windows"
echo -e "  3. Connect and verify: curl https://ipinfo.io/ip"
echo -e "  4. Run SHA-25: WireGuard client setup on laptop"
echo ""
echo -e "  ${RED}⚠️  SSH is now on port ${SSH_PORT} — update your SSH command!${NC}"
echo -e "  ssh -p ${SSH_PORT} ${OPERATOR_USER}@${VPS_IP}"
echo ""
