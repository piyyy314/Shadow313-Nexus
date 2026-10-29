"""shadow313.modules.quantum.code_scanner — Source code quantum crypto scanner."""
from __future__ import annotations
import re
from pathlib import Path
from .quantum_data import CODE_CRYPTO_PATTERNS, LANG_EXTENSIONS, classify_algorithm


class SourceCodeScanner:
    def __init__(self, lang: str | None = None) -> None:
        self.lang = lang

    def scan_directory(self, dir_path: str) -> list[dict]:
        findings = []
        p = Path(dir_path)
        for lang, exts in LANG_EXTENSIONS.items():
            if self.lang and lang.lower() != self.lang.lower():
                continue
            for ext in exts:
                for fpath in p.rglob(f"*{ext}"):
                    findings.extend(self._scan_file(fpath, lang))
        return findings

    def scan_file(self, file_path: str) -> list[dict]:
        p    = Path(file_path)
        lang = self._detect_lang(p)
        return self._scan_file(p, lang)

    def _scan_file(self, path: Path, lang: str) -> list[dict]:
        try:
            text  = path.read_text(encoding="utf-8", errors="replace")
            lines = text.splitlines()
        except Exception:
            return []
        findings = []
        patterns = CODE_CRYPTO_PATTERNS.get(lang, {})
        for algo, sigs in patterns.items():
            for sig in sigs:
                for lineno, line in enumerate(lines, 1):
                    if sig in line:
                        info = classify_algorithm(algo)
                        findings.append({
                            "file": str(path), "line": lineno,
                            "code": line.strip()[:120], "algorithm": algo,
                            "quantum": info["vuln"], "reason": info["reason"],
                            "replace": info["replace"], "language": lang,
                        })
        generic_patterns = [
            (r'\bMD5\b',         "MD5"),
            (r'\bSHA[-_]?1\b',   "SHA-1"),
            (r'\bRC4\b',         "RC4"),
            (r'\bDES\b',         "DES"),
            (r'RSA[_-]?\d{3,4}', "RSA"),
            (r'\bsecp256k1\b',   "ECDSA"),
            (r'\bP-256\b',       "ECDSA"),
        ]
        for pattern, algo in generic_patterns:
            for lineno, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    info = classify_algorithm(algo)
                    if info["vuln"] != "SAFE":
                        findings.append({
                            "file": str(path), "line": lineno,
                            "code": line.strip()[:120], "algorithm": algo,
                            "quantum": info["vuln"], "reason": info["reason"],
                            "replace": info["replace"], "language": lang,
                        })
        seen = set()
        unique = []
        for f in findings:
            key = (f["file"], f["line"], f["algorithm"])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    @staticmethod
    def _detect_lang(path: Path) -> str:
        for lang, exts in LANG_EXTENSIONS.items():
            if path.suffix in exts:
                return lang
        return "Unknown"