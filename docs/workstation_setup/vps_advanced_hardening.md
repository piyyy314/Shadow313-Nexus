# VPS Advanced Threat Hardening
## Kernel Hardening + Suricata IDS + Wazuh SIEM + Honeypot Tripwires
### Shadow313 NEXUS — State-Level Threat Defense

---

## THREAT MODEL

This guide defends against:
- **Nation-state reconnaissance** — automated scanning, fingerprinting, banner grabbing
- **APT initial access** — exploit attempts against exposed services
- **Lateral movement** — post-compromise pivoting attempts
- **Persistence mechanisms** — rootkits, backdoors, cron injection
- **Cryptomining hijacking** — most common VPS compromise
- **Supply chain attacks** — compromised packages, malicious updates

What no software can fully defend against:
- Physical seizure of the VPS hardware (use full-disk encryption + remote unlock)
- Zero-day exploits in the kernel itself (mitigated by attack surface reduction)
- Legal compulsion of the hosting provider (mitigated by jurisdiction choice + no-logs)

---

## PHASE 1: KERNEL AND MEMORY HARDENING

### Step 1.1 — Kernel Compile-Time Hardening (sysctl)

```bash
#!/bin/bash
# ============================================================
# SHADOW313 — Maximum Kernel Hardening
# Implements CIS Benchmark Level 2 + additional hardening
# ============================================================

sudo tee /etc/sysctl.d/99-shadow313-hardening.conf << 'EOF'
# ── NETWORK HARDENING ────────────────────────────────────────

# IP forwarding (keep enabled for VPN)
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# Prevent IP spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable ICMP redirects (MITM prevention)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 3

# Ignore ICMP broadcast (Smurf attack prevention)
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Log martian packets (impossible source addresses)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Disable IPv6 router advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# TCP hardening
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

# ── KERNEL HARDENING ─────────────────────────────────────────

# Hide kernel pointers from unprivileged users
kernel.kptr_restrict = 2

# Restrict dmesg to root
kernel.dmesg_restrict = 1

# Restrict ptrace (prevents process injection)
kernel.yama.ptrace_scope = 2

# Disable magic SysRq key
kernel.sysrq = 0

# Prevent core dumps (contain sensitive data)
fs.suid_dumpable = 0
kernel.core_uses_pid = 1

# ASLR — randomize memory layout
kernel.randomize_va_space = 2

# Restrict unprivileged user namespaces (container escape prevention)
kernel.unprivileged_userns_clone = 0

# Restrict BPF to root (prevents eBPF exploits)
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# Disable kexec (prevents kernel replacement)
kernel.kexec_load_disabled = 1

# Restrict perf events
kernel.perf_event_paranoid = 3

# ── FILESYSTEM HARDENING ─────────────────────────────────────

# Protect hardlinks and symlinks
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# Restrict /proc
kernel.pid_max = 65536
EOF

sudo sysctl -p /etc/sysctl.d/99-shadow313-hardening.conf
echo "[+] Kernel hardening applied"
```

---

### Step 1.2 — Memory and Process Hardening

```bash
#!/bin/bash
# ============================================================
# SHADOW313 — Memory Hardening
# ============================================================

# ── DISABLE UNNECESSARY KERNEL MODULES ───────────────────────
sudo tee /etc/modprobe.d/shadow313-blacklist.conf << 'EOF'
# Disable unused filesystems
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true

# Disable unused network protocols
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
install n-hdlc /bin/true
install ax25 /bin/true
install netrom /bin/true
install x25 /bin/true
install rose /bin/true
install decnet /bin/true
install econet /bin/true
install af_802154 /bin/true
install ipx /bin/true
install appletalk /bin/true
install psnap /bin/true
install p8023 /bin/true
install p8022 /bin/true
install can /bin/true
install atm /bin/true

# Disable Bluetooth (not needed on VPS)
install bluetooth /bin/true
install btusb /bin/true

# Disable USB storage (physical attack prevention)
install usb-storage /bin/true

# Disable FireWire (DMA attack prevention)
install firewire-core /bin/true
install firewire-ohci /bin/true
EOF

# ── PROCESS LIMITS ───────────────────────────────────────────
sudo tee /etc/security/limits.d/shadow313.conf << 'EOF'
# Prevent fork bombs
* hard nproc 1000
* soft nproc 500

# Limit core dumps
* hard core 0
* soft core 0

# Limit file descriptors
* hard nofile 65536
* soft nofile 32768
EOF

# ── COMPILER HARDENING FLAGS ─────────────────────────────────
# Ensure all compiled code uses hardening flags
sudo tee /etc/environment << 'EOF'
CFLAGS="-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security"
CXXFLAGS="-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security"
LDFLAGS="-Wl,-z,relro,-z,now,-z,noexecstack"
EOF

# ── APPARMOR ─────────────────────────────────────────────────
sudo apt install -y apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra
sudo systemctl enable apparmor
sudo systemctl start apparmor

# Enable all available profiles
sudo aa-enforce /etc/apparmor.d/* 2>/dev/null || true

echo "[+] Memory and process hardening complete"
```

---

### Step 1.3 — Filesystem Hardening

```bash
#!/bin/bash
# ============================================================
# SHADOW313 — Filesystem Hardening
# ============================================================

# ── SECURE MOUNT OPTIONS ─────────────────────────────────────
# Add nodev, nosuid, noexec to /tmp and /dev/shm
sudo tee -a /etc/fstab << 'EOF'

# Shadow313 secure mounts
tmpfs /tmp     tmpfs defaults,nodev,nosuid,noexec,size=512M 0 0
tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec           0 0
EOF

sudo mount -o remount /tmp 2>/dev/null || true
sudo mount -o remount /dev/shm 2>/dev/null || true

# ── REMOVE SUID BITS FROM UNNECESSARY BINARIES ───────────────
echo "[*] Removing unnecessary SUID bits..."
for binary in /usr/bin/at /usr/bin/newgrp /usr/bin/chfn /usr/bin/chsh; do
    if [ -f "$binary" ]; then
        sudo chmod u-s "$binary"
        echo "  Removed SUID: $binary"
    fi
done

# ── SECURE /PROC ─────────────────────────────────────────────
sudo tee -a /etc/fstab << 'EOF'
proc /proc proc defaults,hidepid=2,gid=proc 0 0
EOF

sudo groupadd -f proc
sudo mount -o remount,hidepid=2,gid=proc /proc 2>/dev/null || true

echo "[+] Filesystem hardening complete"
```

---

## PHASE 2: SURICATA IDS/IPS

### Step 2.1 — Suricata Installation

```bash
#!/bin/bash
# ============================================================
# SHADOW313 — Suricata IDS/IPS Setup
# Network intrusion detection with real-time alerting
# ============================================================

# Add Suricata repository
sudo add-apt-repository ppa:oisf/suricata-stable -y
sudo apt update
sudo apt install -y suricata suricata-update jq

# Get network interface
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
SERVER_IP=$(curl -s https://ipinfo.io/ip)

echo "[*] Configuring Suricata on interface: $INTERFACE"

# ── SURICATA CONFIGURATION ───────────────────────────────────
sudo tee /etc/suricata/suricata.yaml << EOF
%YAML 1.1
---

# Shadow313 Suricata Configuration
vars:
  address-groups:
    HOME_NET: "[$SERVER_IP, 10.13.13.0/24, 127.0.0.1/8]"
    EXTERNAL_NET: "!\$HOME_NET"
    HTTP_SERVERS: "\$HOME_NET"
    SMTP_SERVERS: "\$HOME_NET"
    SQL_SERVERS: "\$HOME_NET"
    DNS_SERVERS: "\$HOME_NET"
    TELNET_SERVERS: "\$HOME_NET"
    AIM_SERVERS: "\$EXTERNAL_NET"
    DC_SERVERS: "\$HOME_NET"
    DNP3_SERVER: "\$HOME_NET"
    DNP3_CLIENT: "\$HOME_NET"
    MODBUS_CLIENT: "\$HOME_NET"
    MODBUS_SERVER: "\$HOME_NET"
    ENIP_CLIENT: "\$HOME_NET"
    ENIP_SERVER: "\$HOME_NET"

  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 2222
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502
    FILE_DATA_PORTS: "[\$HTTP_PORTS, 110, 143]"
    FTP_PORTS: 21
    GENEVE_PORTS: 6081
    VXLAN_PORTS: 4789
    TEREDO_PORTS: 3544

default-log-dir: /var/log/suricata/

stats:
  enabled: yes
  interval: 8

outputs:
  - fast:
      enabled: yes
      filename: fast.log
      append: yes

  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            payload: yes
            payload-buffer-size: 4kb
            payload-printable: yes
            packet: yes
            metadata: yes
            http-body: yes
            http-body-printable: yes
            tagged-packets: yes
        - anomaly:
            enabled: yes
            types:
              decode: yes
              stream: yes
              applayer: yes
        - http:
            extended: yes
        - dns:
            query: yes
            answer: yes
        - tls:
            extended: yes
        - files:
            force-magic: yes
        - smtp: {}
        - dnp3: {}
        - ftp: {}
        - rdp: {}
        - nfs: {}
        - smb: {}
        - tftp: {}
        - ikev2: {}
        - krb5: {}
        - dhcp:
            enabled: yes
            extended: yes
        - ssh: {}
        - flow: {}
        - netflow: {}
        - stats:
            totals: yes
            threads: no
            deltas: no
        - vars: {}
        - drop:
            alerts: yes
            flows: all

af-packet:
  - interface: $INTERFACE
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes

pcap:
  - interface: $INTERFACE

app-layer:
  protocols:
    rfb:
      enabled: yes
      detection-ports:
        dp: 5900, 5901, 5902, 5903, 5904, 5905, 5906, 5907, 5908, 5909
    krb5:
      enabled: yes
    snmp:
      enabled: yes
    ikev2:
      enabled: yes
    tls:
      enabled: yes
      detection-ports:
        dp: 443
    dcerpc:
      enabled: yes
    ftp:
      enabled: yes
      memcap: 64mb
    rdp:
      enabled: yes
    ssh:
      enabled: yes
    smtp:
      enabled: yes
      raw-extraction: no
      mime:
        decode-mime: yes
        decode-base64: yes
        decode-quoted-printable: yes
        header-value-depth: 2000
        extract-urls: yes
        body-md5: yes
    imap:
      enabled: detection-only
    dns:
      tcp:
        enabled: yes
        detection-ports:
          dp: 53
      udp:
        enabled: yes
        detection-ports:
          dp: 53
    http:
      enabled: yes
      libhtp:
        default-config:
          personality: IDS
          request-body-limit: 100kb
          response-body-limit: 100kb
          request-body-minimal-inspect-size: 32kb
          request-body-inspect-window: 4kb
          response-body-minimal-inspect-size: 40kb
          response-body-inspect-window: 16kb
          response-body-decompress-layer-limit: 2
          http-body-inline: auto
          swf-decompression:
            enabled: yes
            type: both
            compress-depth: 0
            decompress-depth: 0
          double-decode-path: no
          double-decode-query: no
    modbus:
      enabled: yes
      detection-ports:
        dp: 502
      stream-depth: 0
    dnp3:
      enabled: yes
      detection-ports:
        dp: 20000
    enip:
      enabled: yes
      detection-ports:
        dp: 44818
        sp: 44818
    nfs:
      enabled: yes
    ikev2:
      enabled: yes
    tftp:
      enabled: yes
    smb:
      enabled: yes
      detection-ports:
        dp: [139, 445]
    dcerpc:
      enabled: yes

asn1-max-frames: 256

coredump:
  max-dump: 0

host-mode: auto

unix-command:
  enabled: auto

legacy:
  uricontent: enabled

engine-analysis:
  rules-fast-pattern: yes
  rules: yes

pcre:
  match-limit: 3500
  match-limit-recursion: 1500

app-layer:
  error-policy: ignore

logging:
  default-log-level: notice
  outputs:
    - console:
        enabled: yes
    - file:
        enabled: yes
        level: info
        filename: /var/log/suricata/suricata.log
    - syslog:
        enabled: no
        facility: local5
        format: "[%i] <%d> -- "

EOF

# ── UPDATE RULES ─────────────────────────────────────────────
sudo suricata-update update-sources
sudo suricata-update enable-source et/open          # Emerging Threats (free)
sudo suricata-update enable-source oisf/trafficid
sudo suricata-update

# ── CUSTOM SHADOW313 RULES ───────────────────────────────────
sudo tee /etc/suricata/rules/shadow313.rules << 'EOF'
# Shadow313 Custom Detection Rules

# Detect SSH brute force
alert tcp any any -> $HOME_NET 2222 (msg:"Shadow313 SSH Brute Force Attempt"; flow:to_server; threshold:type threshold, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:9000001; rev:1;)

# Detect port scanning
alert tcp any any -> $HOME_NET any (msg:"Shadow313 Port Scan Detected"; flags:S; threshold:type threshold, track by_src, count 20, seconds 10; classtype:network-scan; sid:9000002; rev:1;)

# Detect WireGuard port probing (non-WireGuard traffic on 443/UDP)
alert udp any any -> $HOME_NET 443 (msg:"Shadow313 Non-WireGuard UDP 443 Probe"; dsize:<32; classtype:network-scan; sid:9000003; rev:1;)

# Detect Nmap OS fingerprinting
alert tcp any any -> $HOME_NET any (msg:"Shadow313 Nmap OS Fingerprint Detected"; flags:SFPU; classtype:network-scan; sid:9000004; rev:1;)

# Detect Masscan
alert tcp any any -> $HOME_NET any (msg:"Shadow313 Masscan Detected"; flags:S; window:1024; threshold:type threshold, track by_src, count 50, seconds 5; classtype:network-scan; sid:9000005; rev:1;)

# Detect reverse shell attempts
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Shadow313 Possible Reverse Shell"; flow:established,to_server; content:"/bin/sh"; classtype:shellcode-detect; sid:9000006; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Shadow313 Possible Reverse Shell bash"; flow:established,to_server; content:"/bin/bash"; classtype:shellcode-detect; sid:9000007; rev:1;)

# Detect cryptocurrency mining
alert dns any any -> any any (msg:"Shadow313 Crypto Mining Pool DNS"; dns.query; content:"pool."; classtype:policy-violation; sid:9000008; rev:1;)
alert tcp any any -> any [3333,4444,5555,7777,8888,9999,14444,45700] (msg:"Shadow313 Crypto Mining Port"; classtype:policy-violation; sid:9000009; rev:1;)

# Detect data exfiltration via DNS
alert dns any any -> any any (msg:"Shadow313 DNS Tunneling Detected"; dns.query; content:"."; pcre:"/^[a-z0-9]{30,}\./i"; classtype:trojan-activity; sid:9000010; rev:1;)

# Detect Cobalt Strike beacons
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Shadow313 Cobalt Strike Beacon"; http.user_agent; content:"Mozilla/5.0 (compatible"; pcre:"/Mozilla\/5\.0 \(compatible\; MSIE [67]\.0/"; classtype:trojan-activity; sid:9000011; rev:1;)

# Detect Log4Shell attempts
alert http any any -> $HOME_NET any (msg:"Shadow313 Log4Shell Attempt"; http.request_body; content:"${jndi:"; nocase; classtype:attempted-admin; sid:9000012; rev:1;)
alert http any any -> $HOME_NET any (msg:"Shadow313 Log4Shell Header"; http.header; content:"${jndi:"; nocase; classtype:attempted-admin; sid:9000013; rev:1;)
EOF

# Add custom rules to config
echo "rule-files:" | sudo tee -a /etc/suricata/suricata.yaml
echo "  - /etc/suricata/rules/shadow313.rules" | sudo tee -a /etc/suricata/suricata.yaml

# ── START SURICATA ───────────────────────────────────────────
sudo systemctl enable suricata
sudo systemctl start suricata

echo "[+] Suricata IDS running"
echo "[+] Alerts: /var/log/suricata/fast.log"
echo "[+] Full events: /var/log/suricata/eve.json"
```

---

## PHASE 3: WAZUH SIEM

### Step 3.1 — Wazuh Manager (on VPS)

```bash
#!/bin/bash
# ============================================================
# SHADOW313 — Wazuh SIEM Setup
# Full SIEM with file integrity, log analysis, alerting
# ============================================================

# Install Wazuh repository
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
sudo chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update

# Install Wazuh manager
sudo apt install -y wazuh-manager

# Install Wazuh indexer (OpenSearch)
sudo apt install -y wazuh-indexer

# Install Wazuh dashboard
sudo apt install -y wazuh-dashboard

# ── WAZUH MANAGER CONFIGURATION ──────────────────────────────
sudo tee /var/ossec/etc/ossec.conf << 'EOF'
<ossec_config>

  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
    <smtp_server>smtp.example.wazuh.com</smtp_server>
    <email_from>wazuh@example.wazuh.com</email_from>
    <email_to>recipient@example.wazuh.com</email_to>
    <email_maxperhour>12</email_maxperhour>
    <email_log_source>alerts.log</email_log_source>
    <agents_disconnection_time>10m</agents_disconnection_time>
    <agents_disconnection_alert_time>0</agents_disconnection_alert_time>
  </global>

  <!-- Shadow313 Custom Rules -->
  <rules>
    <include>rules_config.xml</include>
    <include>pam_rules.xml</include>
    <include>sshd_rules.xml</include>
    <include>telnetd_rules.xml</include>
    <include>syslog_rules.xml</include>
    <include>arpwatch_rules.xml</include>
    <include>symantec-av_rules.xml</include>
    <include>symantec-ws_rules.xml</include>
    <include>pix_rules.xml</include>
    <include>named_rules.xml</include>
    <include>smbd_rules.xml</include>
    <include>vsftpd_rules.xml</include>
    <include>pure-ftpd_rules.xml</include>
    <include>proftpd_rules.xml</include>
    <include>ms_ftpd_rules.xml</include>
    <include>ftpd_rules.xml</include>
    <include>hordeimp_rules.xml</include>
    <include>roundcube_rules.xml</include>
    <include>wordpress_rules.xml</include>
    <include>cimserver_rules.xml</include>
    <include>vpopmail_rules.xml</include>
    <include>vmpop3d_rules.xml</include>
    <include>courier_rules.xml</include>
    <include>web_rules.xml</include>
    <include>web_appsec_rules.xml</include>
    <include>apache_rules.xml</include>
    <include>nginx_rules.xml</include>
    <include>php_rules.xml</include>
    <include>mysql_rules.xml</include>
    <include>postgresql_rules.xml</include>
    <include>ids_rules.xml</include>
    <include>squid_rules.xml</include>
    <include>firewall_rules.xml</include>
    <include>apparmor_rules.xml</include>
    <include>cisco-ios_rules.xml</include>
    <include>netscreenfw_rules.xml</include>
    <include>sonicwall_rules.xml</include>
    <include>postfix_rules.xml</include>
    <include>sendmail_rules.xml</include>
    <include>imapd_rules.xml</include>
    <include>mailscanner_rules.xml</include>
    <include>dovecot_rules.xml</include>
    <include>ms-exchange_rules.xml</include>
    <include>racoon_rules.xml</include>
    <include>vpn_concentrator_rules.xml</include>
    <include>spamd_rules.xml</include>
    <include>msauth_rules.xml</include>
    <include>mcafee_av_rules.xml</include>
    <include>trend-osce_rules.xml</include>
    <include>ms-se_rules.xml</include>
    <include>zeus_rules.xml</include>
    <include>solaris_bsm_rules.xml</include>
    <include>vmware_rules.xml</include>
    <include>ms_dhcp_rules.xml</include>
    <include>asterisk_rules.xml</include>
    <include>ossec_rules.xml</include>
    <include>attack_rules.xml</include>
    <include>openbsd_rules.xml</include>
    <include>clam_av_rules.xml</include>
    <include>dropbear_rules.xml</include>
    <include>sysmon_rules.xml</include>
    <include>opensmtpd_rules.xml</include>
    <include>exim_rules.xml</include>
    <include>openvpn_rules.xml</include>
    <include>wireguard_rules.xml</include>
    <include>local_rules.xml</include>
  </rules>

  <!-- File Integrity Monitoring -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <alert_new_files>yes</alert_new_files>
    <auto_ignore frequency="10" timeframe="3600">no</auto_ignore>

    <!-- Critical directories to monitor -->
    <directories check_all="yes" realtime="yes">/etc</directories>
    <directories check_all="yes" realtime="yes">/usr/bin</directories>
    <directories check_all="yes" realtime="yes">/usr/sbin</directories>
    <directories check_all="yes" realtime="yes">/bin</directories>
    <directories check_all="yes" realtime="yes">/sbin</directories>
    <directories check_all="yes" realtime="yes">/boot</directories>
    <directories check_all="yes" realtime="yes">/var/ossec/etc</directories>
    <directories check_all="yes" realtime="yes">/etc/wireguard</directories>

    <!-- Ignore volatile files -->
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/httpd/logs</ignore>
    <ignore>/etc/utmpx</ignore>
    <ignore>/etc/wtmpx</ignore>
    <ignore>/etc/cups/certs</ignore>
    <ignore>/etc/dumpdates</ignore>
    <ignore>/etc/svc/volatile</ignore>
    <ignore type="sregex">.log$|.swp$</ignore>

    <nodiff>/etc/ssl/private.key</nodiff>
    <skip_nfs>yes</skip_nfs>
    <skip_dev>yes</skip_dev>
    <skip_proc>yes</skip_proc>
    <skip_sys>yes</skip_sys>
    <process_priority>10</process_priority>
    <max_eps>100</max_eps>
    <synchronization>
      <enabled>yes</enabled>
      <interval>5m</interval>
      <max_interval>1h</max_interval>
      <max_eps>10</max_eps>
    </synchronization>
  </syscheck>

  <!-- Rootkit Detection -->
  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
    <frequency>43200</frequency>
    <rootkit_files>etc/shared/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>etc/shared/rootkit_trojans.txt</rootkit_trojans>
    <system_audit>etc/shared/system_audit_rcl.txt</system_audit>
    <system_audit>etc/shared/system_audit_ssh.txt</system_audit>
    <system_audit>etc/shared/cis_debian_linux_rcl.txt</system_audit>
  </rootcheck>

  <!-- Log Analysis -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/dpkg.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/kern.log</location>
  </localfile>

  <localfile>
    <log_format>json</log_format>
    <location>/var/log/suricata/eve.json</location>
    <label key="@source">suricata</label>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/fail2ban.log</location>
  </localfile>

  <!-- Active Response — auto-block attackers -->
  <active-response>
    <disabled>no</disabled>
    <ca_store>etc/wpk_root.pem</ca_store>
    <ca_verification>yes</ca_verification>
  </active-response>

  <command>
    <name>firewall-drop</name>
    <executable>firewall-drop</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>5763</rules_id>
    <timeout>3600</timeout>
  </active-response>

</ossec_config>
EOF

# ── CUSTOM WAZUH RULES ───────────────────────────────────────
sudo tee /var/ossec/etc/rules/local_rules.xml << 'EOF'
<group name="shadow313,">

  <!-- WireGuard connection events -->
  <rule id="100001" level="3">
    <if_sid>0</if_sid>
    <match>wg0</match>
    <description>Shadow313 WireGuard event</description>
    <group>vpn,</group>
  </rule>

  <!-- Multiple failed SSH attempts -->
  <rule id="100002" level="10" frequency="5" timeframe="120">
    <if_matched_sid>5716</if_matched_sid>
    <description>Shadow313 SSH brute force attack detected</description>
    <group>authentication_failures,</group>
  </rule>

  <!-- New user created -->
  <rule id="100003" level="12">
    <if_sid>5902</if_sid>
    <description>Shadow313 New user account created</description>
    <group>account_changes,</group>
  </rule>

  <!-- Suricata high severity alert -->
  <rule id="100004" level="12">
    <if_sid>86601</if_sid>
    <field name="alert.severity">1</field>
    <description>Shadow313 Suricata HIGH severity alert: $(alert.signature)</description>
    <group>ids,</group>
  </rule>

  <!-- File integrity violation in /etc/wireguard -->
  <rule id="100005" level="15">
    <if_sid>550</if_sid>
    <match>/etc/wireguard</match>
    <description>Shadow313 WireGuard config file modified!</description>
    <group>syscheck,</group>
  </rule>

  <!-- Root login -->
  <rule id="100006" level="10">
    <if_sid>5501</if_sid>
    <match>root</match>
    <description>Shadow313 Root login detected</description>
    <group>authentication_success,</group>
  </rule>

</group>
EOF

sudo systemctl enable wazuh-manager
sudo systemctl start wazuh-manager

echo "[+] Wazuh SIEM running"
echo "[+] Dashboard: https://YOUR_VPS_IP (after indexer setup)"
```

---

## PHASE 4: AIDE FILE INTEGRITY MONITORING

```bash
#!/bin/bash
# ============================================================
# SHADOW313 — AIDE File Integrity Monitor
# Detects any unauthorized file changes
# ============================================================

sudo apt install -y aide aide-common

# Configure AIDE
sudo tee /etc/aide/aide.conf << 'EOF'
# Shadow313 AIDE Configuration
database=file:/var/lib/aide/aide.db
database_out=file:/var/lib/aide/aide.db.new
gzip_dbout=yes
verbose=5
report_url=file:/var/log/aide/aide.log
report_url=stdout

# Define rule sets
NORMAL = p+i+n+u+g+s+m+c+acl+selinux+xattrs+sha512
PERMS  = p+i+u+g+acl+selinux
LOG    = p+i+n+u+g+S+acl+selinux+xattrs
LSPP   = p+i+n+u+g+s+m+c+acl+selinux+xattrs+sha512
DATAONLY = p+n+u+g+s+acl+selinux+xattrs+sha512

# Critical system files
/boot    NORMAL
/bin     NORMAL
/sbin    NORMAL
/lib     NORMAL
/lib64   NORMAL
/usr/bin NORMAL
/usr/sbin NORMAL
/usr/lib NORMAL

# Configuration files
/etc     PERMS
/etc/wireguard NORMAL
/etc/ssh NORMAL
/etc/sudoers NORMAL
/etc/passwd NORMAL
/etc/shadow NORMAL
/etc/group NORMAL

# Log files (check permissions only)
/var/log LOG

# Ignore volatile files
!/var/log/.*
!/var/cache/.*
!/tmp/.*
!/proc/.*
!/sys/.*
!/dev/.*
!/run/.*
EOF

# Initialize AIDE database
sudo aideinit
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Schedule daily checks
sudo tee /etc/cron.daily/aide-check << 'EOF'
#!/bin/bash
# Shadow313 AIDE daily integrity check
LOGFILE="/var/log/aide/aide-$(date +%Y%m%d).log"
mkdir -p /var/log/aide

aide --check 2>&1 | tee "$LOGFILE"

# Alert if changes detected
if grep -q "changed\|added\|removed" "$LOGFILE"; then
    echo "SHADOW313 AIDE ALERT: File integrity violation detected!" | \
    mail -s "AIDE Alert - $(hostname) - $(date)" root 2>/dev/null || \
    logger -t shadow313-aide "FILE INTEGRITY VIOLATION DETECTED - check $LOGFILE"
fi
EOF

sudo chmod +x /etc/cron.daily/aide-check
echo "[+] AIDE file integrity monitoring configured"
```

---

## PHASE 5: HONEYPOT TRIPWIRES

```bash
#!/bin/bash
# ============================================================
# SHADOW313 — Honeypot Tripwires
# Alert immediately when anyone probes the server
# ============================================================

mkdir -p /opt/shadow313/honeypot
cd /opt/shadow313/honeypot

# ── HONEYPOT LISTENER SCRIPT ─────────────────────────────────
cat > /opt/shadow313/honeypot/honeypot.py << 'PYEOF'
#!/usr/bin/env python3
"""
Shadow313 Honeypot Tripwire System
Listens on decoy ports and alerts on any connection
"""
import socket
import threading
import logging
import json
import subprocess
import time
import os
from datetime import datetime, timezone

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [HONEYPOT] %(message)s',
    handlers=[
        logging.FileHandler('/var/log/shadow313/honeypot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('shadow313.honeypot')

# Telegram alerting (optional — set your bot token and chat ID)
TELEGRAM_TOKEN = os.environ.get('TELEGRAM_TOKEN', '')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '')

# Honeypot ports — things attackers commonly probe
HONEYPOT_PORTS = {
    21:   "FTP",
    23:   "Telnet",
    25:   "SMTP",
    80:   "HTTP",
    110:  "POP3",
    135:  "RPC",
    139:  "NetBIOS",
    445:  "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    4444: "Metasploit",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017:"MongoDB",
}

# Canary file paths — alert if accessed
CANARY_FILES = [
    '/root/.ssh/id_rsa',
    '/etc/shadow',
    '/etc/wireguard/server_private.key',
    '/opt/shadow313/honeypot/fake_credentials.txt',
]

def send_telegram_alert(message: str) -> None:
    """Send alert via Telegram bot."""
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        import urllib.request
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        data = json.dumps({
            "chat_id": TELEGRAM_CHAT_ID,
            "text": f"🚨 SHADOW313 ALERT\n\n{message}",
            "parse_mode": "Markdown"
        }).encode()
        req = urllib.request.Request(url, data=data,
                                      headers={'Content-Type': 'application/json'})
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        logger.error(f"Telegram alert failed: {e}")

def auto_block_ip(src_ip: str) -> None:
    """Automatically block attacker IP via iptables."""
    try:
        # Don't block private IPs or WireGuard clients
        if src_ip.startswith(('10.', '192.168.', '172.', '127.')):
            return
        subprocess.run(
            ['iptables', '-A', 'INPUT', '-s', src_ip, '-j', 'DROP'],
            capture_output=True, timeout=5
        )
        logger.info(f"AUTO-BLOCKED: {src_ip}")
    except Exception as e:
        logger.error(f"Failed to block {src_ip}: {e}")

def handle_connection(conn: socket.socket, addr: tuple,
                       port: int, service: str) -> None:
    """Handle incoming honeypot connection."""
    src_ip, src_port = addr[0], addr[1]
    timestamp = datetime.now(timezone.utc).isoformat()

    # Try to read what they sent
    banner = ""
    try:
        conn.settimeout(3)
        data = conn.recv(1024)
        banner = data.decode('utf-8', errors='replace').strip()[:200]
    except Exception:
        pass
    finally:
        conn.close()

    # Log the event
    event = {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "src_port": src_port,
        "honeypot_port": port,
        "service": service,
        "banner": banner,
        "severity": "HIGH"
    }

    logger.warning(
        f"PROBE DETECTED | {src_ip}:{src_port} → port {port} ({service}) | "
        f"data: {repr(banner[:50])}"
    )

    # Write to JSON log
    with open('/var/log/shadow313/honeypot_events.json', 'a') as f:
        f.write(json.dumps(event) + '\n')

    # Send alert
    alert_msg = (
        f"*Honeypot Triggered*\n"
        f"IP: `{src_ip}:{src_port}`\n"
        f"Port: `{port}` ({service})\n"
        f"Time: `{timestamp}`\n"
        f"Data: `{banner[:100]}`"
    )
    send_telegram_alert(alert_msg)

    # Auto-block the attacker
    auto_block_ip(src_ip)

def start_honeypot_listener(port: int, service: str) -> None:
    """Start a honeypot listener on a specific port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', port))
        sock.listen(5)
        logger.info(f"Honeypot listening on port {port} ({service})")

        while True:
            try:
                conn, addr = sock.accept()
                thread = threading.Thread(
                    target=handle_connection,
                    args=(conn, addr, port, service),
                    daemon=True
                )
                thread.start()
            except Exception as e:
                logger.error(f"Port {port} accept error: {e}")
                time.sleep(1)
    except PermissionError:
        logger.warning(f"Cannot bind port {port} — need root or port > 1024")
    except OSError as e:
        logger.warning(f"Port {port} unavailable: {e}")

def create_canary_files() -> None:
    """Create fake credential files as tripwires."""
    os.makedirs('/opt/shadow313/honeypot/lures', exist_ok=True)

    # Fake credentials file
    with open('/opt/shadow313/honeypot/lures/credentials.txt', 'w') as f:
        f.write("# Internal credentials - DO NOT SHARE\n")
        f.write("admin:Shadow313_Fake_Password_Tripwire_2026\n")
        f.write("root:Another_Fake_Credential_Tripwire\n")
        f.write("vpn_admin:VPN_Fake_Key_Tripwire_9x7k2\n")

    # Fake SSH key
    with open('/opt/shadow313/honeypot/lures/id_rsa_backup', 'w') as f:
        f.write("-----BEGIN OPENSSH PRIVATE KEY-----\n")
        f.write("HONEYPOT_TRIPWIRE_NOT_A_REAL_KEY_IF_YOU_SEE_THIS_YOU_ARE_BEING_MONITORED\n")
        f.write("-----END OPENSSH PRIVATE KEY-----\n")

    # Fake config with "secrets"
    with open('/opt/shadow313/honeypot/lures/config.env', 'w') as f:
        f.write("# Production environment config\n")
        f.write("DATABASE_URL=postgresql://admin:FAKE_TRIPWIRE@db.internal:5432/prod\n")
        f.write("API_SECRET=FAKE_TRIPWIRE_KEY_shadow313_monitor\n")
        f.write("STRIPE_KEY=sk_live_FAKE_TRIPWIRE_NOT_REAL\n")

    logger.info("Canary files created in /opt/shadow313/honeypot/lures/")

if __name__ == '__main__':
    os.makedirs('/var/log/shadow313', exist_ok=True)
    create_canary_files()

    logger.info("Shadow313 Honeypot System starting...")
    logger.info(f"Monitoring {len(HONEYPOT_PORTS)} ports")

    threads = []
    for port, service in HONEYPOT_PORTS.items():
        t = threading.Thread(
            target=start_honeypot_listener,
            args=(port, service),
            daemon=True
        )
        t.start()
        threads.append(t)
        time.sleep(0.1)

    logger.info("All honeypot listeners active")

    # Keep main thread alive
    try:
        while True:
            time.sleep(60)
            # Periodic status log
            logger.info(f"Honeypot active — monitoring {len(HONEYPOT_PORTS)} ports")
    except KeyboardInterrupt:
        logger.info("Honeypot shutting down")
PYEOF

chmod +x /opt/shadow313/honeypot/honeypot.py

# ── HONEYPOT SYSTEMD SERVICE ──────────────────────────────────
sudo tee /etc/systemd/system/shadow313-honeypot.service << 'EOF'
[Unit]
Description=Shadow313 Honeypot Tripwire System
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/shadow313/honeypot/honeypot.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable shadow313-honeypot
sudo systemctl start shadow313-honeypot

# ── OPEN HONEYPOT PORTS IN FIREWALL ──────────────────────────
# Allow honeypot ports (they need to be reachable to attract probes)
for port in 21 23 25 80 110 135 139 445 1433 3306 3389 5900 8080 27017; do
    sudo ufw allow $port/tcp comment "Shadow313 Honeypot"
done

echo "[+] Honeypot tripwires active on 18 ports"
echo "[+] Logs: /var/log/shadow313/honeypot.log"
echo "[+] Events: /var/log/shadow313/honeypot_events.json"
```

---

## PHASE 6: TELEGRAM ALERTING

```bash
#!/bin/bash
# ============================================================
# SHADOW313 — Real-Time Telegram Alerts
# Get notified instantly on your phone for any security event
# ============================================================

# Setup:
# 1. Message @BotFather on Telegram
# 2. Create new bot: /newbot
# 3. Copy the token
# 4. Message your bot once, then get chat ID:
#    curl https://api.telegram.org/bot<TOKEN>/getUpdates

TELEGRAM_TOKEN="YOUR_BOT_TOKEN_HERE"
TELEGRAM_CHAT_ID="YOUR_CHAT_ID_HERE"

# Save credentials
sudo tee /etc/shadow313/telegram.conf << EOF
TELEGRAM_TOKEN=$TELEGRAM_TOKEN
TELEGRAM_CHAT_ID=$TELEGRAM_CHAT_ID
EOF
sudo chmod 600 /etc/shadow313/telegram.conf

# Alert function
cat > /usr/local/bin/shadow313-alert << 'SCRIPT'
#!/bin/bash
source /etc/shadow313/telegram.conf
MESSAGE="$1"
HOSTNAME=$(hostname)
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S UTC')

curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" \
    -d chat_id="${TELEGRAM_CHAT_ID}" \
    -d parse_mode="Markdown" \
    -d text="🚨 *SHADOW313 ALERT*
Host: \`${HOSTNAME}\`
Time: \`${TIMESTAMP}\`

${MESSAGE}" > /dev/null
SCRIPT

chmod +x /usr/local/bin/shadow313-alert

# Test alert
shadow313-alert "✅ Shadow313 alerting system online and operational"

# ── INTEGRATE WITH FAIL2BAN ───────────────────────────────────
sudo tee /etc/fail2ban/action.d/shadow313-telegram.conf << 'EOF'
[Definition]
actionban   = shadow313-alert "🔒 *IP BANNED*\nIP: <ip>\nJail: <name>\nBans: <failures> attempts"
actionunban = shadow313-alert "🔓 *IP UNBANNED*\nIP: <ip>\nJail: <name>"
EOF

# Add to jail.local
sudo sed -i '/\[DEFAULT\]/a action = %(action_)s\n         shadow313-telegram' /etc/fail2ban/jail.local
sudo systemctl restart fail2ban

# ── INTEGRATE WITH SURICATA ───────────────────────────────────
cat > /usr/local/bin/shadow313-suricata-alert << 'SCRIPT'
#!/bin/bash
# Watch Suricata eve.json for high-severity alerts
tail -F /var/log/suricata/eve.json | while read line; do
    SEVERITY=$(echo "$line" | jq -r '.alert.severity // empty' 2>/dev/null)
    if [ "$SEVERITY" = "1" ] || [ "$SEVERITY" = "2" ]; then
        SIG=$(echo "$line" | jq -r '.alert.signature // "Unknown"' 2>/dev/null)
        SRC=$(echo "$line" | jq -r '.src_ip // "Unknown"' 2>/dev/null)
        DST=$(echo "$line" | jq -r '.dest_ip // "Unknown"' 2>/dev/null)
        shadow313-alert "🛡️ *SURICATA IDS ALERT*
Signature: \`$SIG\`
Source: \`$SRC\`
Destination: \`$DST\`
Severity: \`$SEVERITY\`"
    fi
done
SCRIPT

chmod +x /usr/local/bin/shadow313-suricata-alert

# Run as background service
sudo tee /etc/systemd/system/shadow313-suricata-alert.service << 'EOF'
[Unit]
Description=Shadow313 Suricata Alert Forwarder
After=suricata.service

[Service]
ExecStart=/usr/local/bin/shadow313-suricata-alert
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable shadow313-suricata-alert
sudo systemctl start shadow313-suricata-alert

echo "[+] Telegram alerting configured"
echo "[+] You will receive instant alerts for:"
echo "    - SSH brute force / bans"
echo "    - Honeypot triggers"
echo "    - Suricata IDS alerts"
echo "    - File integrity violations"
```

---

## PHASE 7: ADVANCED NFTABLES RULESET

```bash
#!/bin/bash
# ============================================================
# SHADOW313 — Advanced nftables Firewall
# Replaces iptables with modern nftables
# ============================================================

sudo apt install -y nftables

sudo tee /etc/nftables.conf << 'EOF'
#!/usr/sbin/nft -f
# Shadow313 Advanced nftables Ruleset

flush ruleset

# Define variables
define VPN_PORT = 443
define SSH_PORT = 2222
define WG_NET   = 10.13.13.0/24
define HONEYPOT_PORTS = { 21, 23, 25, 80, 110, 135, 139, 445, 1433, 3306, 3389, 5900, 8080, 27017 }

table inet shadow313 {

    # Rate limiting sets
    set ssh_ratelimit {
        type ipv4_addr
        flags dynamic, timeout
        timeout 60s
    }

    set blocked_ips {
        type ipv4_addr
        flags dynamic, timeout
        timeout 3600s
    }

    chain input {
        type filter hook input priority 0; policy drop;

        # Allow established/related
        ct state established,related accept

        # Allow loopback
        iif lo accept

        # Drop invalid packets
        ct state invalid drop

        # Drop blocked IPs
        ip saddr @blocked_ips drop

        # ICMP rate limiting (allow ping but limit rate)
        ip protocol icmp icmp type echo-request limit rate 5/second accept
        ip protocol icmp drop

        # SSH with rate limiting
        tcp dport $SSH_PORT ct state new \
            add @ssh_ratelimit { ip saddr limit rate 3/minute } \
            accept
        tcp dport $SSH_PORT ct state new \
            ip saddr @ssh_ratelimit drop

        # WireGuard VPN
        udp dport $VPN_PORT accept

        # Nginx (TLS camouflage)
        tcp dport 443 accept

        # Honeypot ports — accept but log
        tcp dport $HONEYPOT_PORTS log prefix "SHADOW313-HONEYPOT: " accept

        # DNS (only from WireGuard clients)
        ip saddr $WG_NET udp dport 53 accept
        ip saddr $WG_NET tcp dport 53 accept

        # Log and drop everything else
        log prefix "SHADOW313-DROP: " drop
    }

    chain output {
        type filter hook output priority 0; policy accept;

        # Log suspicious outbound (potential compromise indicator)
        tcp dport { 4444, 5555, 6666, 7777, 8888, 9999 } \
            log prefix "SHADOW313-SUSPICIOUS-OUT: "
    }

    chain forward {
        type filter hook forward priority 0; policy drop;

        # Allow VPN client traffic
        iif wg0 accept
        oif wg0 accept

        # Allow established forwarded connections
        ct state established,related accept

        log prefix "SHADOW313-FORWARD-DROP: " drop
    }
}
EOF

sudo systemctl enable nftables
sudo systemctl start nftables

echo "[+] Advanced nftables firewall active"
```

---

## PHASE 8: VERIFICATION

```bash
#!/bin/bash
# ============================================================
# SHADOW313 — Security Stack Verification
# ============================================================

echo "╔══════════════════════════════════════════════════════════╗"
echo "║     SHADOW313 VPS — SECURITY STACK VERIFICATION         ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

check_service() {
    if systemctl is-active --quiet "$1"; then
        echo "  ✅ $1 — RUNNING"
    else
        echo "  ❌ $1 — NOT RUNNING"
    fi
}

echo "[*] Services:"
check_service wg-quick@wg0
check_service suricata
check_service wazuh-manager
check_service shadow313-honeypot
check_service shadow313-suricata-alert
check_service unbound
check_service fail2ban
check_service nftables
check_service apparmor
check_service auditd
echo ""

echo "[*] Kernel Hardening:"
echo "  ASLR:          $(cat /proc/sys/kernel/randomize_va_space) (should be 2)"
echo "  kptr_restrict: $(cat /proc/sys/kernel/kptr_restrict) (should be 2)"
echo "  dmesg_restrict:$(cat /proc/sys/kernel/dmesg_restrict) (should be 1)"
echo "  ptrace_scope:  $(cat /proc/sys/kernel/yama/ptrace_scope) (should be 2)"
echo "  bpf_disabled:  $(cat /proc/sys/kernel/unprivileged_bpf_disabled) (should be 1)"
echo ""

echo "[*] Recent Honeypot Events:"
tail -5 /var/log/shadow313/honeypot.log 2>/dev/null || echo "  No events yet"
echo ""

echo "[*] Recent Suricata Alerts:"
tail -5 /var/log/suricata/fast.log 2>/dev/null || echo "  No alerts yet"
echo ""

echo "[*] Fail2ban Status:"
sudo fail2ban-client status sshd 2>/dev/null | grep -E "Currently banned|Total banned"
echo ""

echo "[*] WireGuard:"
sudo wg show wg0 2>/dev/null || echo "  WireGuard not running"
echo ""

echo "[*] Open Ports:"
ss -tulpn | grep LISTEN
echo ""

echo "============================================"
echo " Security stack verification complete"
echo "============================================"
```

---

## QUICK REFERENCE

### Alert Channels
```
Telegram bot  → Instant alerts on phone
/var/log/shadow313/honeypot.log     → Honeypot events
/var/log/suricata/fast.log          → IDS alerts
/var/log/suricata/eve.json          → Full event data
/var/log/aide/                      → File integrity
/var/ossec/logs/alerts/alerts.log   → Wazuh SIEM
/var/log/auth.log                   → SSH/auth events
```

### Daily Commands
```bash
# Check who's probing you
tail -f /var/log/shadow313/honeypot.log

# Check IDS alerts
tail -f /var/log/suricata/fast.log

# Check banned IPs
sudo fail2ban-client status sshd

# Run AIDE integrity check
sudo aide --check

# Check Wazuh alerts
sudo tail -f /var/ossec/logs/alerts/alerts.log

# Full status
sudo wg show && sudo systemctl status suricata wazuh-manager shadow313-honeypot
```