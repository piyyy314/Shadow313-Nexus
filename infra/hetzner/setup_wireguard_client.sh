#!/bin/bash
# ══════════════════════════════════════════════════════════════════
# Shadow313 NEXUS — WireGuard Client Setup (WSL2/Ubuntu)
# SHA-25: Configure WireGuard on your Dell Latitude 5490
#
# Run in Ubuntu WSL2 after copying client_shadow313.conf from VPS:
#   bash infra/hetzner/setup_wireguard_client.sh
# ══════════════════════════════════════════════════════════════════

set -euo pipefail

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'
RED='\033[0;31m'; NC='\033[0m'; BOLD='\033[1m'

log()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*"; exit 1; }

echo -e "${BOLD}  Shadow313 NEXUS — WireGuard Client Setup${NC}"
echo ""

# ── Check for client config ───────────────────────────────────────
CLIENT_CONF="${1:-client_shadow313.conf}"

if [[ ! -f "$CLIENT_CONF" ]]; then
    err "Client config not found: ${CLIENT_CONF}
    
Copy it from your VPS first:
  scp -P 2222 shadow313@<VPS_IP>:/etc/wireguard/client_shadow313.conf .
  bash infra/hetzner/setup_wireguard_client.sh client_shadow313.conf"
fi

log "Using config: ${CLIENT_CONF}"

# ── Install WireGuard in WSL2 ─────────────────────────────────────
log "Installing WireGuard..."
sudo apt-get update -qq
sudo apt-get install -y -qq wireguard wireguard-tools resolvconf
ok "WireGuard installed"

# ── Install config ────────────────────────────────────────────────
log "Installing WireGuard config..."
sudo mkdir -p /etc/wireguard
sudo cp "$CLIENT_CONF" /etc/wireguard/wg0.conf
sudo chmod 600 /etc/wireguard/wg0.conf
ok "Config installed to /etc/wireguard/wg0.conf"

# ── Test connection ───────────────────────────────────────────────
log "Starting WireGuard tunnel..."
sudo wg-quick up wg0

echo ""
log "Verifying connection..."
sleep 3

# Check if tunnel is up
if sudo wg show wg0 | grep -q "latest handshake"; then
    ok "WireGuard tunnel is UP"
else
    warn "Tunnel started but no handshake yet — may take a few seconds"
fi

# Show current IP
CURRENT_IP=$(curl -sf --max-time 5 https://api.ipify.org 2>/dev/null || echo "unknown")
log "Current public IP: ${CURRENT_IP}"

echo ""
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  ✅ WireGuard VPN Connected!${NC}"
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${CYAN}Useful commands:${NC}"
echo -e "  sudo wg show              — show tunnel status"
echo -e "  sudo wg-quick down wg0    — disconnect VPN"
echo -e "  sudo wg-quick up wg0      — reconnect VPN"
echo -e "  curl https://ipinfo.io/ip — verify your IP"
echo ""
echo -e "  ${YELLOW}For Windows WireGuard app:${NC}"
echo -e "  1. Open WireGuard app on Windows"
echo -e "  2. Click 'Import tunnel(s) from file'"
echo -e "  3. Select: $(realpath $CLIENT_CONF)"
echo -e "  4. Click 'Activate'"
echo ""

# ── Auto-start on WSL2 boot ───────────────────────────────────────
log "Setting up auto-start..."
PROFILE_LINE="# Shadow313 WireGuard auto-connect"
if ! grep -q "shadow313 WireGuard" ~/.bashrc 2>/dev/null; then
    cat >> ~/.bashrc << 'EOF'

# Shadow313 WireGuard — connect on shell start
# Uncomment to auto-connect:
# sudo wg-quick up wg0 2>/dev/null || true
alias vpn-up='sudo wg-quick up wg0'
alias vpn-down='sudo wg-quick down wg0'
alias vpn-status='sudo wg show'
alias myip='curl -sf https://api.ipify.org && echo'
EOF
    ok "VPN aliases added to ~/.bashrc (vpn-up, vpn-down, vpn-status, myip)"
fi
