import subprocess

REPO_URL = "https://github.com/your-username/Fortress_Command.git"

def self_update():
    print("[*] Checking for updates from repository...")
    try:
        subprocess.check_call(["git", "pull", REPO_URL])
        print("[√] Update complete.")
    except Exception as e:
        print(f"[X] Update failed: {e}")

if __name__ == "__main__":
    self_update()