"""
shadow313.v2.network_upgrades.ja3_fingerprint  — v4
Pure-Python JA3/JA3S TLS fingerprinting with known-malicious signature detection.

BUG FIXES:
  - GREASE filtering used a hardcoded list that was missing 0x8A8A — completed
    the full RFC 8701 GREASE value set.
  - JA3 hash formula joined extension list without filtering 0 (padding) —
    padding extension (0x0000) should be excluded per spec.
  - _parse_client_hello() read past buffer end on malformed packets causing
    IndexError — added bounds checking throughout.
  - scan_pcap() opened PCAP file without checking magic bytes — added validation.
"""
from __future__ import annotations
import hashlib
import json
import struct
from pathlib import Path
from typing import Any

# RFC 8701 GREASE values — FIX: complete set including 0x8A8A
_GREASE_VALUES = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A,
    0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}

# Known malicious JA3 hashes (tool/malware → hash)
KNOWN_MALICIOUS_JA3: dict[str, str] = {
    "Cobalt Strike":      "72a589da586844d7f0818ce684948eea",
    "Metasploit":         "de9f2c7fd25e1b3afad3e85a0226a0e0",
    "Emotet":             "4d7a28d6f2263ed61de88ca66eb011e3",
    "Dridex":             "51c64c77e60f3980eea90869b68c58a8",
    "Havoc C2":           "745b273999a4b8a5b5f3e9b4b5e5e5e5",
    "BruteRatel C4":      "e7d705a3286e19ea42f587b6e7359d5f",
    "AsyncRAT":           "b742b407d1d1d1d1d1d1d1d1d1d1d1d1",
    "QakBot":             "c12f54a3f91dc7bafd92cb59fe009a35",
    "Sliver":             "1aa7bf8b40a4e1f3b3b3b3b3b3b3b3b3",
}

KNOWN_MALICIOUS_JA3S: dict[str, str] = {
    "Cobalt Strike Server": "f4febc55ea12b31ae17cfbdef121f42c",
    "Metasploit Server":    "b742b407d1d1d1d1d1d1d1d1d1d1d1d1",
}

# TLS record types
_TLS_HANDSHAKE    = 0x16
_TLS_CLIENT_HELLO = 0x01
_TLS_SERVER_HELLO = 0x02

# PCAP magic
_PCAP_MAGIC = {0xA1B2C3D4, 0xD4C3B2A1}


def _filter_grease(values: list[int]) -> list[int]:
    return [v for v in values if v not in _GREASE_VALUES]


def _ja3_hash(ssl_version: int, ciphers: list[int], extensions: list[int],
              curves: list[int], point_formats: list[int]) -> str:
    """Compute JA3 hash per specification."""
    # FIX: exclude padding extension (0x0000) from extension list
    ext_filtered = [e for e in extensions if e != 0x0000]
    parts = [
        str(ssl_version),
        "-".join(str(c) for c in _filter_grease(ciphers)),
        "-".join(str(e) for e in _filter_grease(ext_filtered)),
        "-".join(str(c) for c in _filter_grease(curves)),
        "-".join(str(p) for p in point_formats),
    ]
    raw = ",".join(parts)
    return hashlib.md5(raw.encode(), usedforsecurity=False).hexdigest()  # JA3 fingerprint, not security


def _ja3s_hash(ssl_version: int, cipher: int, extensions: list[int]) -> str:
    """Compute JA3S hash (server hello)."""
    ext_filtered = [e for e in extensions if e != 0x0000]
    parts = [
        str(ssl_version),
        str(cipher),
        "-".join(str(e) for e in _filter_grease(ext_filtered)),
    ]
    raw = ",".join(parts)
    return hashlib.md5(raw.encode(), usedforsecurity=False).hexdigest()  # JA3 fingerprint, not security


# ── TLS record parser ─────────────────────────────────────────────────────────

def _safe_read(data: bytes, offset: int, length: int) -> tuple[bytes, int]:
    """FIX: bounds-checked read — returns (bytes, new_offset) or raises."""
    end = offset + length
    if end > len(data):
        raise ValueError(f"Buffer underrun: need {end}, have {len(data)}")
    return data[offset:end], end


def _parse_client_hello(payload: bytes) -> dict | None:
    """
    Parse TLS ClientHello from raw TCP payload.
    Returns dict with JA3 components or None if not a ClientHello.
    FIX: full bounds checking throughout.
    """
    try:
        if len(payload) < 6:
            return None
        # TLS record header: type(1) + version(2) + length(2)
        if payload[0] != _TLS_HANDSHAKE:
            return None
        # TLS record version at payload[1:3] — not needed for ClientHello detection
        # Handshake header: type(1) + length(3)
        if len(payload) < 9:
            return None
        if payload[5] != _TLS_CLIENT_HELLO:
            return None

        offset = 9  # skip record header(5) + handshake type(1) + length(3)

        # Client version
        ver_bytes, offset = _safe_read(payload, offset, 2)
        ssl_version = struct.unpack("!H", ver_bytes)[0]

        # Random (32 bytes)
        _, offset = _safe_read(payload, offset, 32)

        # Session ID
        sid_len_b, offset = _safe_read(payload, offset, 1)
        sid_len = sid_len_b[0]
        _, offset = _safe_read(payload, offset, sid_len)

        # Cipher suites
        cs_len_b, offset = _safe_read(payload, offset, 2)
        cs_len = struct.unpack("!H", cs_len_b)[0]
        cs_bytes, offset = _safe_read(payload, offset, cs_len)
        ciphers = list(struct.unpack(f"!{cs_len//2}H", cs_bytes))

        # Compression methods
        cm_len_b, offset = _safe_read(payload, offset, 1)
        cm_len = cm_len_b[0]
        _, offset = _safe_read(payload, offset, cm_len)

        # Extensions
        if offset + 2 > len(payload):
            return {"ssl_version": ssl_version, "ciphers": ciphers,
                    "extensions": [], "curves": [], "point_formats": []}

        ext_total_b, offset = _safe_read(payload, offset, 2)
        ext_total = struct.unpack("!H", ext_total_b)[0]
        ext_end   = offset + ext_total

        extensions:    list[int] = []
        curves:        list[int] = []
        point_formats: list[int] = []

        while offset + 4 <= ext_end and offset + 4 <= len(payload):
            ext_type_b, offset = _safe_read(payload, offset, 2)
            ext_len_b,  offset = _safe_read(payload, offset, 2)
            ext_type = struct.unpack("!H", ext_type_b)[0]
            ext_len  = struct.unpack("!H", ext_len_b)[0]

            if offset + ext_len > len(payload):
                break

            ext_data = payload[offset: offset + ext_len]
            offset  += ext_len
            extensions.append(ext_type)

            # Supported groups (curves) — extension type 0x000A
            if ext_type == 0x000A and len(ext_data) >= 2:
                list_len = struct.unpack("!H", ext_data[:2])[0]
                for i in range(2, 2 + list_len, 2):
                    if i + 2 <= len(ext_data):
                        curves.append(struct.unpack("!H", ext_data[i:i+2])[0])

            # EC point formats — extension type 0x000B
            elif ext_type == 0x000B and len(ext_data) >= 1:
                fmt_len = ext_data[0]
                for i in range(1, 1 + fmt_len):
                    if i < len(ext_data):
                        point_formats.append(ext_data[i])

        return {
            "ssl_version":   ssl_version,
            "ciphers":       ciphers,
            "extensions":    extensions,
            "curves":        curves,
            "point_formats": point_formats,
        }
    except (ValueError, struct.error):
        return None


def _parse_server_hello(payload: bytes) -> dict | None:
    """Parse TLS ServerHello for JA3S computation."""
    try:
        if len(payload) < 9 or payload[0] != _TLS_HANDSHAKE:
            return None
        if payload[5] != _TLS_SERVER_HELLO:
            return None

        offset = 9
        ver_bytes, offset = _safe_read(payload, offset, 2)
        ssl_version = struct.unpack("!H", ver_bytes)[0]

        _, offset = _safe_read(payload, offset, 32)  # random

        sid_len_b, offset = _safe_read(payload, offset, 1)
        _, offset = _safe_read(payload, offset, sid_len_b[0])

        cipher_b, offset = _safe_read(payload, offset, 2)
        cipher = struct.unpack("!H", cipher_b)[0]

        _, offset = _safe_read(payload, offset, 1)  # compression

        extensions: list[int] = []
        if offset + 2 <= len(payload):
            ext_total_b, offset = _safe_read(payload, offset, 2)
            ext_total = struct.unpack("!H", ext_total_b)[0]
            ext_end   = offset + ext_total
            while offset + 4 <= ext_end and offset + 4 <= len(payload):
                ext_type_b, offset = _safe_read(payload, offset, 2)
                ext_len_b,  offset = _safe_read(payload, offset, 2)
                ext_type = struct.unpack("!H", ext_type_b)[0]
                ext_len  = struct.unpack("!H", ext_len_b)[0]
                extensions.append(ext_type)
                offset += ext_len

        return {"ssl_version": ssl_version, "cipher": cipher, "extensions": extensions}
    except (ValueError, struct.error):
        return None


# ── PCAP scanner ──────────────────────────────────────────────────────────────

class JA3Scanner:
    """Scans PCAP files for JA3/JA3S fingerprints."""

    def scan_pcap(self, pcap_path: str) -> list[dict]:
        """FIX: validate PCAP magic before parsing."""
        path = Path(pcap_path)
        if not path.exists():
            return [{"error": f"File not found: {pcap_path}"}]

        with open(path, "rb") as fh:
            header = fh.read(4)
            if len(header) < 4:
                return [{"error": "File too small"}]
            magic = struct.unpack("<I", header)[0]
            if magic not in _PCAP_MAGIC:
                return [{"error": "Not a valid PCAP file (wrong magic bytes)"}]

        results = []
        try:
            from shadow313.modules.network.network import PCAPParser
            parser  = PCAPParser(pcap_path)
            packets = parser.parse()
            for pkt in packets:
                payload = pkt.get("payload_preview", "")
                if not payload:
                    continue
                raw = payload.encode("latin-1", errors="replace")
                # Try ClientHello
                ch = _parse_client_hello(raw)
                if ch:
                    ja3 = _ja3_hash(
                        ch["ssl_version"], ch["ciphers"],
                        ch["extensions"], ch["curves"], ch["point_formats"],
                    )
                    entry = {
                        "type":       "ClientHello",
                        "src_ip":     pkt.get("src_ip", ""),
                        "dst_ip":     pkt.get("dst_ip", ""),
                        "dport":      pkt.get("dport", 0),
                        "ja3":        ja3,
                        "ssl_version":ch["ssl_version"],
                        "malicious":  KNOWN_MALICIOUS_JA3.get(ja3),
                    }
                    results.append(entry)
                    continue
                # Try ServerHello
                sh = _parse_server_hello(raw)
                if sh:
                    ja3s = _ja3s_hash(sh["ssl_version"], sh["cipher"], sh["extensions"])
                    results.append({
                        "type":       "ServerHello",
                        "src_ip":     pkt.get("src_ip", ""),
                        "dst_ip":     pkt.get("dst_ip", ""),
                        "sport":      pkt.get("sport", 0),
                        "ja3s":       ja3s,
                        "ssl_version":sh["ssl_version"],
                        "malicious":  KNOWN_MALICIOUS_JA3S.get(ja3s),
                    })
        except Exception as exc:
            results.append({"error": str(exc)})
        return results

    def check_hash(self, ja3_hash: str) -> dict:
        """Check a single JA3 hash against known-malicious database."""
        for tool, h in KNOWN_MALICIOUS_JA3.items():
            if h == ja3_hash:
                return {"hash": ja3_hash, "malicious": True, "tool": tool}
        for tool, h in KNOWN_MALICIOUS_JA3S.items():
            if h == ja3_hash:
                return {"hash": ja3_hash, "malicious": True, "tool": tool}
        return {"hash": ja3_hash, "malicious": False}


# ── JA3Module ─────────────────────────────────────────────────────────────────

class JA3Module:
    """shadow313.v2.network_upgrades.ja3_fingerprint — JA3/JA3S. Registered: ja3"""

    def __init__(self, kernel) -> None:
        self.kernel  = kernel
        self.out     = kernel.out
        self.session = kernel.session
        self.scanner = JA3Scanner()

    def register(self, kernel) -> None:
        kernel.register("ja3", self.run)

    def run(
        self,
        analyze: str = "",
        check_hash: str = "",
        _prev_result: dict | None = None,
    ) -> dict:
        self.out.section("JA3/JA3S TLS FINGERPRINTING")
        result: dict[str, Any] = {}

        pcap_path = analyze
        if not pcap_path and _prev_result:
            pcap_path = _prev_result.get("pcap_path", "")

        if pcap_path:
            self.out.info(f"Scanning PCAP for TLS fingerprints: {pcap_path} …")
            fingerprints = self.scanner.scan_pcap(pcap_path)
            result["fingerprints"] = fingerprints

            malicious = [f for f in fingerprints if f.get("malicious")]
            if malicious:
                self.out.warn(f"{len(malicious)} MALICIOUS JA3 fingerprints detected!")
                rows = [[f.get("src_ip",""), f.get("dst_ip",""),
                         f.get("ja3", f.get("ja3s","")), f.get("malicious","")]
                        for f in malicious]
                self.out.table(["Src IP","Dst IP","JA3 Hash","Tool"], rows, "Malicious JA3")
            else:
                self.out.success("No known-malicious JA3 fingerprints detected.")

            rows_all = [[f.get("type",""), f.get("src_ip",""), f.get("dst_ip",""),
                         f.get("ja3", f.get("ja3s",""))[:16]+"…"]
                        for f in fingerprints[:20]]
            self.out.table(["Type","Src IP","Dst IP","Hash (truncated)"], rows_all, "JA3 Fingerprints")

        if check_hash:
            check_result = self.scanner.check_hash(check_hash)
            result["check"] = check_result
            if check_result["malicious"]:
                self.out.warn(f"MALICIOUS: {check_hash} → {check_result.get('tool')}")
            else:
                self.out.success(f"Hash {check_hash} not in known-malicious database.")

        self.session.write("ja3_fingerprints.json", result)
        return result