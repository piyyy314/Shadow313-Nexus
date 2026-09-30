import os

PROJECT_NAME = "FORTRESS_COMMAND"
FOLDERS = [
    "🛡️_DEFENSE",
    "👻_OFFENSE",
    "🛰️_CONTROL",
    "🧹_UTILS"
]

FILES = {
    "README.md": "# PROJECT: 1000% FORTRESS & GHOST SUITE\nStatus: Operational",
    "MISSION_BRIEF.md": "# MISSION BRIEFING\nObjective: ",
    "🛡️_DEFENSE/fortress_main.py": "# The Brain of the Fortress",
    "🛡️_DEFENSE/tarpit.py": "# Network Layer Trap",
    "👻_OFFENSE/ghost_shell.py": "# The Ghost C2 Shell",
    "🧹_UTILS/clean_sweep.py": "# The Self-Destruct Protocol"
}

def ignite_system():
    print(f"[!] IGNITER: Initializing {PROJECT_NAME}...")

    if not os.path.exists(PROJECT_NAME):
        os.makedirs(PROJECT_NAME)
    
    for folder in FOLDERS:
        path = os.path.join(PROJECT_NAME, folder)
        if not os.path.exists(path):
            os.makedirs(path)
            print(f"[+] Created Folder: {folder}")

    for filename, content in FILES.items():
        path = os.path.join(PROJECT_NAME, filename)
        dirname = os.path.dirname(path)
        if not os.path.exists(dirname):
            os.makedirs(dirname)
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"[+] Generated File: {filename}")

    print("\n[√] ARCHITECTURE COMPLETE.")
    print(f"[>] Move your scripts into their respective folders.")
    print(f"[>] Run 'python 🛡️_DEFENSE/fortress_main.py' to begin.")

if __name__ == "__main__":
    ignite_system()