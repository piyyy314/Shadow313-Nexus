# Shadow313 NEXUS — Hetzner VPS Setup (SHA-24/25)

## Overview

Sets up a Hetzner CX22 VPS (~€4.15/month) as a WireGuard VPN gateway
for the Shadow313 NEXUS workstation.

## Architecture

```
Dell Latitude 5490 (Ottawa)
  └── WireGuard client (wg0: 10.13.13.2)
        │
        │ Encrypted tunnel (UDP 51820)
        │
  Hetzner CX22 VPS (Nuremberg)
        └── WireGuard server (wg0: 10.13.13.1)
              └── NAT → Internet
```

## Quick Start

### Step 1 — Rent VPS via Hetzner API (automated)

```bash
# Get API token from: console.hetzner.cloud → Security → API Tokens
export HETZNER_API_TOKEN="your-token-here"
bash infra/hetzner/create_vps.sh
```

### Step 2 — Or rent manually via Hetzner Console

1. Go to [console.hetzner.cloud](https://console.hetzner.cloud)
2. New Project → `shadow313-nexus`
3. Add Server:
   - **Location:** Nuremberg (nbg1) — EU privacy laws
   - **Image:** Ubuntu 24.04
   - **Type:** CX22 (2 vCPU, 4GB RAM, 40GB SSD)
   - **SSH Key:** paste your `~/.ssh/id_ed25519.pub`
4. Note the VPS IP address

### Step 3 — Provision the VPS

```bash
# SSH into VPS
ssh root@<VPS_IP>

# Run provisioner (installs WireGuard, hardens SSH, configures firewall)
bash /root/provision.sh

# Or run directly:
curl -fsSL https://raw.githubusercontent.com/piyyy314/Shadow313-Nexus/master/infra/hetzner/provision.sh | bash
```

### Step 4 — Setup WireGuard on your laptop

```bash
# Copy client config from VPS
scp -P 2222 shadow313@<VPS_IP>:/etc/wireguard/client_shadow313.conf .

# Setup WireGuard in WSL2
bash infra/hetzner/setup_wireguard_client.sh client_shadow313.conf

# Verify
curl https://ipinfo.io/ip  # should show VPS IP
```

### Step 5 — Windows WireGuard app

1. Open **WireGuard** app on Windows
2. **Import tunnel(s) from file** → select `client_shadow313.conf`
3. Click **Activate**
4. Verify: `curl https://ipinfo.io/ip` in PowerShell

## What provision.sh Does

| Phase | Action |
|-------|--------|
| 1 | System update + install WireGuard, UFW, fail2ban |
| 2 | Create `shadow313` operator user |
| 3 | Harden SSH (port 2222, key-only, no root login) |
| 4 | Kernel hardening (sysctl: anti-spoofing, SYN cookies, ASLR) |
| 5 | WireGuard server + generate client keys |
| 6 | UFW firewall (deny all → allow SSH 2222 + WireGuard 51820) |
| 7 | Fail2ban (3 attempts → 24h ban) |
| 8 | Unattended security upgrades |
| 9 | QR code for mobile WireGuard |

## Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 2222 | TCP | SSH (hardened, key-only) |
| 51820 | UDP | WireGuard VPN |

## Files

| File | Purpose |
|------|---------|
| `create_vps.sh` | Hetzner API — create CX22 VPS automatically |
| `provision.sh` | Run on VPS — full setup (WireGuard + hardening) |
| `setup_wireguard_client.sh` | Run on laptop — configure WireGuard client |
| `vps_info.json` | Auto-generated — VPS IP, ID, SSH key path |

## Cost

| Resource | Cost |
|----------|------|
| CX22 VPS | ~€4.15/month |
| Traffic | 20TB included |
| Snapshots | €0.0119/GB/month |

## Security Notes

- SSH root login disabled after provisioning
- Password authentication disabled (key-only)
- All traffic through WireGuard is encrypted with Curve25519 + ChaCha20-Poly1305
- DNS queries routed through Quad9 (9.9.9.9) via VPN
- Fail2ban bans IPs after 3 failed SSH attempts for 24 hours
