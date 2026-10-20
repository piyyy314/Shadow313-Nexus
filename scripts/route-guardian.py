#!/usr/bin/env python3
"""
Shadow313 NEXUS — vercel.json Route Guardian
Backs up and restores vercel.json routes after rebase conflicts.

Usage:
  python3 scripts/route-guardian.py backup    # Save current routes
  python3 scripts/route-guardian.py restore   # Restore from backup
  python3 scripts/route-guardian.py verify    # Check route count
  python3 scripts/route-guardian.py merge     # Merge backup into current
"""
import json, sys, shutil
from pathlib import Path
from datetime import datetime

VERCEL = Path("vercel.json")
BACKUP = Path(".route-backup.json")
MIN_ROUTES = 140

def backup():
    vj = json.loads(VERCEL.read_text())
    routes = vj.get("rewrites", [])
    backup_data = {
        "timestamp": datetime.now().isoformat(),
        "route_count": len(routes),
        "rewrites": routes,
    }
    BACKUP.write_text(json.dumps(backup_data, indent=2))
    print(f"✅ Backed up {len(routes)} routes to {BACKUP}")

def restore():
    if not BACKUP.exists():
        print("❌ No backup found. Run: python3 scripts/route-guardian.py backup")
        sys.exit(1)
    backup_data = json.loads(BACKUP.read_text())
    vj = json.loads(VERCEL.read_text())
    vj["rewrites"] = backup_data["rewrites"]
    VERCEL.write_text(json.dumps(vj, indent=2))
    print(f"✅ Restored {len(backup_data['rewrites'])} routes from backup ({backup_data['timestamp']})")

def verify():
    vj = json.loads(VERCEL.read_text())
    count = len(vj.get("rewrites", []))
    status = "✅ OK" if count >= MIN_ROUTES else f"❌ LOW (expected >={MIN_ROUTES})"
    print(f"Routes: {count} {status}")
    if BACKUP.exists():
        backup_data = json.loads(BACKUP.read_text())
        diff = count - backup_data["route_count"]
        print(f"vs backup: {diff:+d} routes (backup has {backup_data['route_count']})")
    return count >= MIN_ROUTES

def merge():
    """Merge backup routes into current vercel.json without losing either set."""
    if not BACKUP.exists():
        print("❌ No backup found.")
        sys.exit(1)
    backup_data = json.loads(BACKUP.read_text())
    vj = json.loads(VERCEL.read_text())
    current_sources = {r["source"] for r in vj.get("rewrites", [])}
    added = 0
    for route in backup_data["rewrites"]:
        if route["source"] not in current_sources:
            vj["rewrites"].append(route)
            added += 1
    VERCEL.write_text(json.dumps(vj, indent=2))
    print(f"✅ Merged: added {added} missing routes. Total: {len(vj['rewrites'])}")

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "verify"
    {"backup": backup, "restore": restore, "verify": verify, "merge": merge}.get(cmd, verify)()
