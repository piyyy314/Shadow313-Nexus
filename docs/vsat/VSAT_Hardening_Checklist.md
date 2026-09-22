# VSAT Ground Segment Hardening Checklist
**Generated from:** Full_Spectrum_Scan_Report + VSAT_Compliance_Audit_Report  
**Date:** 2026-06-05  
**Target:** 192.168.100.0/24 (Maritime/Shipping Terminal)

---

## 🔴 CRITICAL — Immediate Action Required

### 1. CVE-2024-6199: Viasat Command Bypass RCE
- **Affected:** `/api/config` endpoint on Ground Terminal Modulator Hub (192.168.100.1)
- **Risk:** Remote code execution via unhardened parameter inputs
- **Fix:**
  - Apply vendor firmware patch (check Viasat security advisories)
  - Until patched: block external access to `/api/config` via firewall ACL
  - Implement server-side input validation/sanitization
  - Add WAF rules to reject malformed `/api/config` payloads

### 2. CVE-2026-3392: TR-069 Rogue ACS Push
- **Affected:** Port 7547 (TR-069 CWMP) on Terminal Modulator
- **Risk:** Unsigned CWMP provisioning allows remote modem reconfiguration
- **Fix:**
  - Disable TR-069 if not required for provisioning
  - If required: restrict port 7547 to known ACS server IPs only
  - Enable CWMP payload signature verification
  - Monitor for unauthorized ACS connection attempts

### 3. FTP Anonymous Access (Port 21)
- **Affected:** NOC Console (192.168.100.15)
- **Risk:** Anonymous read/write — data exfiltration and malware upload
- **Fix:**
  - Disable FTP service immediately
  - Replace with SFTP (SSH File Transfer Protocol) on port 22
  - Require key-based or MFA authentication
  - Audit files already present for tampering

### 4. Telnet Cleartext (Port 23)
- **Affected:** Terminal Modulator Hub (192.168.100.1)
- **Risk:** Credentials transmitted in cleartext — trivially interceptable
- **Fix:**
  - Disable Telnet service
  - Deploy SSH (port 22) with key-based auth
  - Rotate all credentials that may have been exposed

### 5. Unsigned Firmware Acceptance
- **Affected:** Terminal Modulator firmware update mechanism
- **Risk:** Arbitrary binary partition overwrite — full device compromise
- **Fix:**
  - Enable firmware signature verification in bootloader config
  - Implement secure boot chain
  - Whitelist firmware signing keys

---

## 🟡 HIGH — Scheduled Remediation (< 7 days)

### 6. HTTP Unencrypted Admin Panel (Port 80)
- **Fix:** Redirect port 80 → 443 (HTTPS), deploy TLS 1.3, enable HSTS

### 7. SNMP Default Community String (Port 161)
- **Fix:** Change community string, upgrade to SNMPv3, restrict to management VLAN

---

## 🟠 MEDIUM — Monitoring & Tuning (< 30 days)

### 8. Carrier SNR Degradation (4.9 dB)
- **Fix:** Inspect dish alignment, LNB condition, set alerting threshold at 6.0 dB minimum

### 9. Clock Offset/Skew (+55.3 Hz)
- **Fix:** Verify NTP/PTP synchronization, check oscillator health, recalibrate frequency reference

---

## 🏗️ ARCHITECTURE — Network Segmentation

### 10. VLAN Isolation
```
VLAN 10: Satellite Management (modulator, ACU, BUC control)
VLAN 20: NOC Operations (monitoring, config management)
VLAN 30: User Data Traffic (internet passthrough)
VLAN 99: Out-of-Band Management (IPMI/iLO/console)
```
- Inter-VLAN routing: Deny all except explicitly allowed flows
- Management VLAN: Accessible only from hardened jump host

---

## 🔑 CREDENTIAL ROTATION

Rotate immediately:
- Terminal Modulator admin (192.168.100.1)
- NOC Console admin (192.168.100.15)
- SNMP community strings (all devices)
- Default/factory credentials on ground equipment
- TR-069 ACS authentication credentials

**Policy:** Minimum 16-character passwords, 90-day rotation, log all changes to SIEM