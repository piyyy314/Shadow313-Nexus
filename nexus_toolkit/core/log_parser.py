"""
nexus_toolkit.core.log_parser
───────────────────────────────
37-dimensional feature extractor for Windows/Linux security event logs.

Feature vector dimensions:
  0-4:   Event metadata (event_id, severity, source_type, host_hash, user_hash)
  5-9:   Process indicators (susp_proc, lolbas, parent_child, enc_cmd, obfuscation)
  10-14: Network indicators (ext_conn, tor_port, c2_port, dns_tunnel, smb_lateral)
  15-19: File indicators (temp_write, sys_write, script_drop, archive_create, file_del_new)
  20-24: Registry/Auth (reg_run, wmi_persist, token_imp, uac_bypass, kerberoast)
  25-29: Credential/Lateral (lsass, dcsync, pth, winrm, psexec)
  30-31: Exfil/Impact (cloud_exfil, shadow_delete)
  32-36: New evasion dims (proc_inject, pe_mismatch, file_del, dll_anom, token_mis)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional


# ── Log entry ─────────────────────────────────────────────────────────────────

@dataclass
class LogEntry:
    """A single security log event."""
    raw: dict

    @property
    def event_id(self) -> int:
        return int(self.raw.get("event_id", 0))

    @property
    def process(self) -> str:
        return str(self.raw.get("process", "")).lower()

    @property
    def parent(self) -> str:
        return str(self.raw.get("parent", "")).lower()

    @property
    def command_line(self) -> str:
        return str(self.raw.get("command_line", "")).lower()

    @property
    def user(self) -> str:
        return str(self.raw.get("user", "")).lower()

    @property
    def host(self) -> str:
        return str(self.raw.get("host", "")).lower()

    @property
    def severity(self) -> str:
        return str(self.raw.get("severity", "info")).lower()

    @property
    def event_type(self) -> str:
        return str(self.raw.get("event_type", "")).lower()

    @property
    def source_ip(self) -> str:
        return str(self.raw.get("source_ip", ""))

    @property
    def dest_ip(self) -> str:
        return str(self.raw.get("dest_ip", ""))

    @property
    def dest_port(self) -> int:
        return int(self.raw.get("dest_port", 0))

    @property
    def file_path(self) -> str:
        return str(self.raw.get("file_path", "")).lower()

    @property
    def registry_key(self) -> str:
        return str(self.raw.get("registry_key", "")).lower()


# ── Known suspicious patterns ─────────────────────────────────────────────────

_LOLBAS = {
    "mshta.exe", "wscript.exe", "cscript.exe", "regsvr32.exe",
    "rundll32.exe", "certutil.exe", "bitsadmin.exe", "fodhelper.exe",
    "msiexec.exe", "installutil.exe", "regasm.exe", "regsvcs.exe",
}

_SUSP_PROCESSES = {
    "mimikatz.exe", "procdump.exe", "psexec.exe", "wce.exe",
    "fgdump.exe", "pwdump.exe", "cobaltstrike", "beacon.exe",
    "meterpreter", "empire", "covenant", "sliver",
}

_C2_PORTS = {4444, 4445, 8080, 8443, 9001, 9050, 31337, 1337, 6666, 6667}
_TOR_PORTS = {9001, 9050, 9150}
_SMB_PORTS = {445, 139}

_ENC_CMD_PATTERNS = [
    r"-enc\s+[A-Za-z0-9+/=]{20,}",   # PowerShell -EncodedCommand
    r"-e\s+[A-Za-z0-9+/=]{20,}",
    r"frombase64string",
    r"iex\s*\(",
    r"invoke-expression",
]

_LSASS_PATTERNS = [
    "lsass.exe", "lsass", "0x1010", "0x1fffff", "minidump",
    "sekurlsa", "wdigest",
]

_DCSYNC_PATTERNS = [
    "dcsync", "lsadump::dcsync", "drsuapi", "replication",
    "getncchanges",
]


# ── Feature extractor ─────────────────────────────────────────────────────────

class FeatureExtractor:
    """
    Extracts a 37-dimensional feature vector from a security log entry.

    Each dimension is a float in [0.0, 1.0].
    Binary indicators are 0.0 or 1.0.
    Normalized values are scaled to [0.0, 1.0].
    """

    VECTOR_SIZE = 37

    def extract(self, entry: LogEntry) -> list[float]:
        """Extract 37-dimensional feature vector from a log entry."""
        v = [0.0] * self.VECTOR_SIZE
        cmd = entry.command_line
        proc = entry.process
        parent = entry.parent

        # ── Dims 0-4: Event metadata ──────────────────────────────────────────
        v[0] = min(1.0, entry.event_id / 10000.0)
        v[1] = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25, "info": 0.0}.get(entry.severity, 0.0)
        v[2] = {"process_creation": 0.8, "network_connection": 0.6, "process_access": 0.9,
                "directory_service_access": 0.7, "file_creation": 0.4}.get(entry.event_type, 0.2)
        v[3] = min(1.0, (hash(entry.host) % 1000) / 1000.0)
        v[4] = min(1.0, (hash(entry.user) % 1000) / 1000.0)

        # ── Dims 5-9: Process indicators ──────────────────────────────────────
        v[5] = 1.0 if any(s in proc for s in _SUSP_PROCESSES) else 0.0
        v[6] = 1.0 if proc.split("\\")[-1] in _LOLBAS else 0.0
        v[7] = 0.0  # reserved
        v[8] = 1.0 if any(re.search(p, cmd) for p in _ENC_CMD_PATTERNS) else 0.0
        v[9] = 1.0 if ("obfuscat" in cmd or "char(" in cmd or "chr(" in cmd) else 0.0

        # ── Dims 10-14: Network indicators ────────────────────────────────────
        v[10] = 1.0 if entry.dest_ip and not entry.dest_ip.startswith(("10.", "192.168.", "172.")) else 0.0
        v[11] = 1.0 if entry.dest_port in _TOR_PORTS else 0.0
        v[12] = 1.0 if entry.dest_port in _C2_PORTS else 0.0
        v[13] = 1.0 if ("dns" in entry.event_type and len(entry.dest_ip) > 30) else 0.0
        v[14] = 1.0 if entry.dest_port in _SMB_PORTS else 0.0

        # ── Dims 15-19: File indicators ───────────────────────────────────────
        fp = entry.file_path
        v[15] = 1.0 if "\\temp\\" in fp or "/tmp/" in fp else 0.0
        v[16] = 1.0 if "\\system32\\" in fp or "\\windows\\" in fp else 0.0
        v[17] = 1.0 if fp.endswith((".ps1", ".vbs", ".js", ".bat", ".cmd", ".hta")) else 0.0
        v[18] = 1.0 if ("7z" in proc or "zip" in proc or "rar" in proc or "-p" in cmd) else 0.0
        v[19] = 1.0 if ("vssadmin" in cmd and "delete" in cmd) else 0.0

        # ── Dims 20-24: Registry/Auth ─────────────────────────────────────────
        rk = entry.registry_key
        v[20] = 1.0 if "run" in rk and ("hklm" in rk or "hkcu" in rk) else 0.0
        v[21] = 1.0 if ("wmi" in proc or "wmic" in cmd or "winword.exe" == parent) else 0.0
        v[22] = 0.0  # token impersonation — see dim 36
        v[23] = 1.0 if "fodhelper" in proc or ("uac" in cmd and "bypass" in cmd) else 0.0
        v[24] = 1.0 if ("kerber" in cmd and ("roast" in cmd or "spn" in cmd)) else 0.0

        # ── Dims 25-29: Credential/Lateral ────────────────────────────────────
        v[25] = 1.0 if any(p in cmd for p in _LSASS_PATTERNS) else 0.0
        v[26] = 1.0 if any(p in cmd for p in _DCSYNC_PATTERNS) else 0.0
        v[27] = 1.0 if ("pass-the-hash" in cmd or "pth" in cmd or "ntlm" in cmd) else 0.0
        v[28] = 1.0 if ("winrm" in cmd or "invoke-command" in cmd) else 0.0
        v[29] = 1.0 if ("psexec" in proc or ("services.exe" == parent and "cmd.exe" == proc)) else 0.0

        # ── Dims 30-31: Exfil/Impact ──────────────────────────────────────────
        v[30] = 1.0 if ("s3" in cmd or "blob.core" in cmd or "drive.google" in cmd) else 0.0
        v[31] = 1.0 if ("vssadmin" in cmd or "wbadmin" in cmd or "bcdedit" in cmd) else 0.0

        # ── Dims 32-36: Evasion dimensions (NEW) ─────────────────────────────
        # dim32: process injection
        v[32] = 1.0 if (entry.event_id == 10 and "lsass" in entry.raw.get("TargetImage", "").lower()) else 0.0
        # dim33: PE mismatch (process name doesn't match expected path)
        v[33] = 1.0 if ("svchost" in proc and "system32" not in entry.file_path) else 0.0
        # dim34: file deletion (shadow copies, logs)
        v[34] = 1.0 if ("vssadmin" in proc or ("del" in cmd and ("shadow" in cmd or "log" in cmd))) else 0.0
        # dim35: DLL anomaly
        v[35] = 1.0 if ("rundll32" in proc and "appdata" in cmd) else 0.0
        # dim36: token misuse (UAC bypass, SeImpersonate)
        v[36] = 1.0 if ("fodhelper" in proc or "seimpersonate" in cmd or "token" in cmd) else 0.0

        return v

    def feature_names(self) -> list[str]:
        """Return human-readable names for all 37 dimensions."""
        return [
            "event_id_norm", "severity", "event_type", "host_hash", "user_hash",
            "susp_proc", "lolbas", "reserved", "enc_cmd", "obfuscation",
            "ext_conn", "tor_port", "c2_port", "dns_tunnel", "smb_lateral",
            "temp_write", "sys_write", "script_drop", "archive_create", "shadow_delete_old",
            "reg_run", "parent_child", "token_imp_old", "uac_bypass", "kerberoast",
            "lsass", "dcsync", "pth", "winrm", "psexec",
            "cloud_exfil", "shadow_delete",
            "proc_inject", "pe_mismatch", "file_del", "dll_anom", "token_mis",
        ]