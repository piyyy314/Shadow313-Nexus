#!/bin/bash
# ══════════════════════════════════════════════════════════════════
# Shadow313 NEXUS — Hetzner CX22 VPS Creator
# Uses Hetzner Cloud API to provision VPS automatically
#
# Usage:
#   export HETZNER_API_TOKEN="your-token-here"
#   bash infra/hetzner/create_vps.sh
# ══════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────
SERVER_NAME="${SERVER_NAME:-shadow313-nexus}"
SERVER_TYPE="${SERVER_TYPE:-cx22}"        # 2 vCPU, 4GB RAM, ~€4.15/mo
LOCATION="${LOCATION:-nbg1}"             # Nuremberg (EU, good privacy laws)
IMAGE="${IMAGE:-ubuntu-24.04}"
SSH_KEY_NAME="${SSH_KEY_NAME:-shadow313-key}"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'
RED='\033[0;31m'; NC='\033[0m'; BOLD='\033[1m'

log()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*"; exit 1; }

# ── Check token ───────────────────────────────────────────────────
[[ -z "${HETZNER_API_TOKEN:-}" ]] && err "Set HETZNER_API_TOKEN first:
  export HETZNER_API_TOKEN='your-token-from-hetzner-cloud-console'"

API="https://api.hetzner.cloud/v1"
AUTH="Authorization: Bearer ${HETZNER_API_TOKEN}"

echo -e "${BOLD}  Shadow313 NEXUS — Hetzner VPS Creator${NC}"
echo ""

# ── Check if server already exists ───────────────────────────────
log "Checking for existing server '${SERVER_NAME}'..."
EXISTING=$(curl -sf -H "$AUTH" "${API}/servers" | \
    jq -r ".servers[] | select(.name==\"${SERVER_NAME}\") | .public_net.ipv4.ip" 2>/dev/null || echo "")

if [[ -n "$EXISTING" ]]; then
    warn "Server '${SERVER_NAME}' already exists at ${EXISTING}"
    echo "  To delete: curl -X DELETE -H \"$AUTH\" ${API}/servers/<id>"
    exit 0
fi

# ── Get or create SSH key ─────────────────────────────────────────
log "Setting up SSH key..."

# Generate key if it doesn't exist
SSH_KEY_PATH="$HOME/.ssh/shadow313_vps"
if [[ ! -f "${SSH_KEY_PATH}" ]]; then
    log "Generating new Ed25519 SSH key..."
    ssh-keygen -t ed25519 -f "${SSH_KEY_PATH}" -N "" -C "shadow313-nexus-vps"
    ok "SSH key generated: ${SSH_KEY_PATH}"
fi

SSH_PUB=$(cat "${SSH_KEY_PATH}.pub")

# Upload SSH key to Hetzner (ignore if already exists)
SSH_KEY_ID=$(curl -sf -H "$AUTH" "${API}/ssh_keys" | \
    jq -r ".ssh_keys[] | select(.name==\"${SSH_KEY_NAME}\") | .id" 2>/dev/null || echo "")

if [[ -z "$SSH_KEY_ID" ]]; then
    log "Uploading SSH key to Hetzner..."
    RESPONSE=$(curl -sf -X POST -H "$AUTH" -H "Content-Type: application/json" \
        "${API}/ssh_keys" \
        -d "{\"name\":\"${SSH_KEY_NAME}\",\"public_key\":\"${SSH_PUB}\"}")
    SSH_KEY_ID=$(echo "$RESPONSE" | jq -r '.ssh_key.id')
    ok "SSH key uploaded (ID: ${SSH_KEY_ID})"
else
    ok "SSH key already exists (ID: ${SSH_KEY_ID})"
fi

# ── Create cloud-init user data ───────────────────────────────────
CLOUD_INIT=$(cat << 'CLOUDINIT'
#cloud-config
package_update: true
package_upgrade: true
packages:
  - curl
  - git
  - ufw
runcmd:
  - echo "Shadow313 NEXUS VPS ready for provisioning" > /root/shadow313-ready.txt
  - curl -fsSL https://raw.githubusercontent.com/piyyy314/Shadow313-Nexus/master/infra/hetzner/provision.sh -o /root/provision.sh
  - chmod +x /root/provision.sh
  - echo "Run: bash /root/provision.sh" >> /root/shadow313-ready.txt
CLOUDINIT
)

# ── Create server ─────────────────────────────────────────────────
log "Creating Hetzner ${SERVER_TYPE} server in ${LOCATION}..."
log "  Name:     ${SERVER_NAME}"
log "  Type:     ${SERVER_TYPE} (2 vCPU, 4GB RAM)"
log "  Location: ${LOCATION} (Nuremberg)"
log "  Image:    ${IMAGE}"
echo ""

RESPONSE=$(curl -sf -X POST -H "$AUTH" -H "Content-Type: application/json" \
    "${API}/servers" \
    -d "{
        \"name\": \"${SERVER_NAME}\",
        \"server_type\": \"${SERVER_TYPE}\",
        \"location\": \"${LOCATION}\",
        \"image\": \"${IMAGE}\",
        \"ssh_keys\": [${SSH_KEY_ID}],
        \"user_data\": $(echo "$CLOUD_INIT" | jq -Rs .),
        \"labels\": {
            \"project\": \"shadow313-nexus\",
            \"purpose\": \"vpn-gateway\"
        }
    }")

VPS_IP=$(echo "$RESPONSE" | jq -r '.server.public_net.ipv4.ip')
VPS_ID=$(echo "$RESPONSE" | jq -r '.server.id')
VPS_STATUS=$(echo "$RESPONSE" | jq -r '.server.status')

if [[ "$VPS_IP" == "null" ]] || [[ -z "$VPS_IP" ]]; then
    err "Failed to create server. Response: $(echo $RESPONSE | jq .)"
fi

echo ""
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  ✅ Hetzner VPS Created!${NC}"
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Server ID:   ${BOLD}${VPS_ID}${NC}"
echo -e "  Server IP:   ${BOLD}${VPS_IP}${NC}"
echo -e "  Status:      ${BOLD}${VPS_STATUS}${NC}"
echo -e "  SSH Key:     ${BOLD}${SSH_KEY_PATH}${NC}"
echo -e "  Monthly:     ~€4.15/month (CX22)"
echo ""
echo -e "  ${YELLOW}Wait 60 seconds for boot, then:${NC}"
echo ""
echo -e "  ${CYAN}# Connect to VPS:${NC}"
echo -e "  ssh -i ${SSH_KEY_PATH} root@${VPS_IP}"
echo ""
echo -e "  ${CYAN}# Run provisioner:${NC}"
echo -e "  bash /root/provision.sh"
echo ""

# Save VPS info
cat > "$(dirname "$0")/vps_info.json" << EOF
{
  "server_id":   "${VPS_ID}",
  "server_name": "${SERVER_NAME}",
  "server_ip":   "${VPS_IP}",
  "server_type": "${SERVER_TYPE}",
  "location":    "${LOCATION}",
  "ssh_key":     "${SSH_KEY_PATH}",
  "created_at":  "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
ok "VPS info saved to infra/hetzner/vps_info.json"
