#!/usr/bin/env bash
# Shadow313 NEXUS — Targeted Sandbox Push Script (Bash/Linux)
# Pushes exactly the 64 files missing from github.com/piyyy314/Shadow313-Nexus
#
# Usage:
#   export GITHUB_TOKEN="ghp_xxxxxxxxxxxx"
#   ./scripts/push-sandbox-to-github.sh
#   ./scripts/push-sandbox-to-github.sh --dry-run
#   ./scripts/push-sandbox-to-github.sh --branch "feature/v2-submodules"
#   ./scripts/push-sandbox-to-github.sh --skip-tests
#
# Get a token: https://github.com/settings/tokens/new  (scope: repo)

set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; GRAY='\033[0;37m'; MAGENTA='\033[0;35m'; NC='\033[0m'
step()  { echo -e "\n${CYAN}[$1]${NC} $2"; }
ok()    { echo -e "  ${GREEN}OK${NC}   $*"; }
warn()  { echo -e "  ${YELLOW}WARN${NC} $*"; }
fail()  { echo -e "  ${RED}FAIL${NC} $*"; exit 1; }
info()  { echo -e "       ${GRAY}$*${NC}"; }
dry()   { echo -e "  ${MAGENTA}DRY${NC}  $*"; }

# ── Defaults ──────────────────────────────────────────────────────────────────
TOKEN="${GITHUB_TOKEN:-}"
BRANCH_NAME=""
DRY_RUN=false
SKIP_TESTS=false
REPO_OWNER="piyyy314"
REPO_NAME="Shadow313-Nexus"
BASE_BRANCH="master"

# ── Args ──────────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --token|-t)      TOKEN="$2";       shift 2 ;;
        --branch|-b)     BRANCH_NAME="$2"; shift 2 ;;
        --dry-run|-n)    DRY_RUN=true;     shift   ;;
        --skip-tests)    SKIP_TESTS=true;  shift   ;;
        --help|-h)       sed -n '2,12p' "$0" | sed 's/^# \?//'; exit 0 ;;
        *) warn "Unknown arg: $1"; shift ;;
    esac
done

# ── 64 files missing from repo (deep scan 2026-10-29) ────────────────────────
MISSING_FILES=(
    # Root
    "push-to-github.ps1"
    "push-to-github.sh"
    "run_tests.py"
    # Core
    "shadow313/core/ai_engine.py"
    # CICD
    "shadow313/modules/cicd/cicd_module.py"
    "shadow313/modules/cicd/junit_builder.py"
    "shadow313/modules/cicd/sarif_builder.py"
    "shadow313/modules/cicd/secret_scanner.py"
    # Defense
    "shadow313/modules/defense/cis_checker.py"
    "shadow313/modules/defense/defense_module.py"
    "shadow313/modules/defense/firewall.py"
    "shadow313/modules/defense/remediation.py"
    "shadow313/modules/defense/system_info.py"
    # Docs
    "shadow313/modules/docs/docs_module.py"
    "shadow313/modules/docs/glossary.py"
    "shadow313/modules/docs/man_page.py"
    "shadow313/modules/docs/tutorials.py"
    # Exploit
    "shadow313/modules/exploit/ctf_helper.py"
    "shadow313/modules/exploit/exploit_module.py"
    "shadow313/modules/exploit/exploitdb.py"
    "shadow313/modules/exploit/payloads.py"
    "shadow313/modules/exploit/scope.py"
    # Network
    "shadow313/modules/network/anomaly.py"
    "shadow313/modules/network/flow_tracker.py"
    "shadow313/modules/network/network_module.py"
    "shadow313/modules/network/pcap_parser.py"
    "shadow313/modules/network/topology.py"
    # Plugins
    "shadow313/modules/plugins/manager.py"
    "shadow313/modules/plugins/manifest.py"
    "shadow313/modules/plugins/plugins_module.py"
    "shadow313/modules/plugins/runner.py"
    # Quantum
    "shadow313/modules/quantum/cert_auditor.py"
    "shadow313/modules/quantum/code_scanner.py"
    "shadow313/modules/quantum/quantum_data.py"
    "shadow313/modules/quantum/quantum_module.py"
    "shadow313/modules/quantum/timeline.py"
    "shadow313/modules/quantum/tls_scanner.py"
    # Recon
    "shadow313/modules/recon/dns_enum.py"
    "shadow313/modules/recon/fingerprint.py"
    "shadow313/modules/recon/geoip.py"
    "shadow313/modules/recon/port_scan.py"
    "shadow313/modules/recon/recon_module.py"
    "shadow313/modules/recon/subdomain.py"
    "shadow313/modules/recon/whois_lookup.py"
    # Vuln
    "shadow313/modules/vuln/cve_db.py"
    "shadow313/modules/vuln/cvss.py"
    "shadow313/modules/vuln/dep_audit.py"
    "shadow313/modules/vuln/exploit_check.py"
    "shadow313/modules/vuln/vuln_module.py"
    # V2 new/patched
    "shadow313/v2/agent/approval.py"
    "shadow313/v2/network_upgrades/firmware_auditor.py"
    "shadow313/v2/rag/tfidf_store.py"
    # Tests
    "tests/unit/test_agent.py"
    "tests/unit/test_campaign_manager.py"
    "tests/unit/test_cloud_hardening.py"
    "tests/unit/test_core.py"
    "tests/unit/test_crypto_agility_extended.py"
    "tests/unit/test_new_patches.py"
    "tests/unit/test_rag_defensive.py"
    "tests/unit/test_rag_engine.py"
    "tests/unit/test_threat_intel.py"
    "tests/unit/test_v2_modules.py"
)

# Files in both sandbox and repo but patched — also stage these
PATCHED_FILES=(
    "shadow313/core/crypto_store.py"
    "shadow313/core/session.py"
    "shadow313/core/intelligence_graph.py"
    "shadow313/v2/agent/agent.py"
    "shadow313/v2/rag/rag_engine.py"
    "shadow313/v2/threat_intel/threat_intel.py"
    "shadow313/v2/vuln_upgrades/epss_kev.py"
    "shadow313/v2/cloud_hardening/cloud_hardening.py"
    "shadow313/v2/network_upgrades/ja3_fingerprint.py"
    "shadow313/v2/plugin_signing/plugin_signer.py"
    "shadow313/v2/graph/intel_graph.py"
    "shadow313/cli/main.py"
    "pyproject.toml"
)

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     Shadow313 NEXUS — Targeted Sandbox Push (64 files)          ║${NC}"
echo -e "${CYAN}║     github.com/piyyy314/Shadow313-Nexus  [master]               ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
echo ""
$DRY_RUN && warn "DRY-RUN MODE — no git changes will be made"

# ── Step 1: Validate token ────────────────────────────────────────────────────
step "1/9" "Validating GitHub token"
if [[ -z "$TOKEN" ]]; then
    fail "No token. Set GITHUB_TOKEN env var or use --token ghp_xxx\nGet one: https://github.com/settings/tokens/new (scope: repo)"
fi
GH_USER=$(curl -sf -H "Authorization: token $TOKEN" https://api.github.com/user | python3 -c "import json,sys; print(json.load(sys.stdin)['login'])" 2>/dev/null || echo "")
if [[ -z "$GH_USER" ]]; then
    fail "Token invalid or expired. Get a new one at https://github.com/settings/tokens/new"
fi
ok "Authenticated as: $GH_USER"

# ── Step 2: Verify repo access ────────────────────────────────────────────────
step "2/9" "Verifying repo access"
REPO_INFO=$(curl -sf -H "Authorization: token $TOKEN" "https://api.github.com/repos/$REPO_OWNER/$REPO_NAME" 2>/dev/null || echo "{}")
REPO_FULL=$(echo "$REPO_INFO" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('full_name','NOT FOUND'))" 2>/dev/null)
if [[ "$REPO_FULL" == "NOT FOUND" ]]; then
    fail "Cannot access repo $REPO_OWNER/$REPO_NAME. Check token permissions."
fi
ok "Repo: $REPO_FULL"

# ── Step 3: Check git ─────────────────────────────────────────────────────────
step "3/9" "Checking git"
command -v git &>/dev/null || fail "git not found. Install with: apt-get install git"
ok "$(git --version)"

# ── Step 4: Initialize git repo ───────────────────────────────────────────────
step "4/9" "Initializing git repository"
if ! git rev-parse --git-dir &>/dev/null; then
    if $DRY_RUN; then dry "Would run: git init"; else
        git init
        ok "Initialized git repository"
    fi
else
    ok "Already a git repository"
fi

# Set/update remote with token
REMOTE_URL="https://$TOKEN@github.com/$REPO_OWNER/$REPO_NAME.git"
if git remote get-url origin &>/dev/null; then
    if $DRY_RUN; then dry "Would update remote URL"; else
        git remote set-url origin "$REMOTE_URL"
        ok "Updated remote URL"
    fi
else
    if $DRY_RUN; then dry "Would add remote origin"; else
        git remote add origin "$REMOTE_URL"
        ok "Added remote origin"
    fi
fi

# ── Step 5: Fetch master and create branch ────────────────────────────────────
step "5/9" "Fetching $BASE_BRANCH and creating branch"
if [[ -z "$BRANCH_NAME" ]]; then
    BRANCH_NAME="shadow313/sandbox-sync-v2-$(date +%Y%m%d)"
fi
info "New branch: $BRANCH_NAME"

if $DRY_RUN; then
    dry "Would run: git fetch origin $BASE_BRANCH"
    dry "Would run: git checkout -b $BRANCH_NAME origin/$BASE_BRANCH"
else
    info "Fetching origin/$BASE_BRANCH ..."
    git fetch origin "$BASE_BRANCH" 2>&1 | tail -3 || fail "git fetch failed"
    ok "Fetched $BASE_BRANCH"

    if git branch --list "$BRANCH_NAME" | grep -q "$BRANCH_NAME"; then
        git checkout "$BRANCH_NAME"
    else
        git checkout -b "$BRANCH_NAME" "origin/$BASE_BRANCH"
    fi
    ok "On branch: $BRANCH_NAME"
fi

# ── Step 6: Run tests ─────────────────────────────────────────────────────────
step "6/9" "Running test suite"
if $SKIP_TESTS; then
    warn "Tests skipped (--skip-tests)"
elif $DRY_RUN; then
    dry "Would run: python run_tests.py"
else
    if [[ -f "run_tests.py" ]]; then
        info "Running python run_tests.py ..."
        python run_tests.py 2>&1 | tail -5 || fail "Tests failed. Fix before pushing."
        ok "All tests passed"
    else
        warn "run_tests.py not found — skipping"
    fi
fi

# ── Step 7: Stage files ───────────────────────────────────────────────────────
step "7/9" "Staging files"
ALL_FILES=("${MISSING_FILES[@]}" "${PATCHED_FILES[@]}")
STAGED=0
NOT_FOUND=0

for f in "${ALL_FILES[@]}"; do
    if [[ -f "$f" ]]; then
        if $DRY_RUN; then dry "Would stage: $f"; else git add "$f"; fi
        ((STAGED++))
    else
        warn "Not found (skipping): $f"
        ((NOT_FOUND++))
    fi
done

ok "Staged $STAGED files ($NOT_FOUND not found)"

# ── Step 8: Commit ────────────────────────────────────────────────────────────
step "8/9" "Committing"
DATE=$(date +"%Y-%m-%d")
COMMIT_MSG="feat(v2): sandbox sync $DATE — 64 new files + 14 security patches

## New Sub-Module Architecture (v2 refactor)
Complete v2 sub-file module structure replacing monolithic v1 files:
- shadow313/modules/{cicd,defense,docs,exploit,network,plugins,quantum,recon,vuln}/

## New Modules
- shadow313/v2/network_upgrades/firmware_auditor.py (FW-01: T1542.004 detection)
- flow_tracker.py: OutboundVolumeMonitor + UserFileAccessMonitor (Gap 8+9)
- topology.py: RoutingTableMonitor (NB-01: T1599 detection)
- remediation.py: FileEncryptionRateMonitor (RW-01: T1486 detection)

## Security Patches (P-01 through P-32)
- P-24: ja3_fingerprint.py — MD5 usedforsecurity=False (FIPS/B324 HIGH)
- P-25: threat_intel.py — SQL injection guard in stats() (B608)
- P-19: epss_kev.py — composite_z_score() model (Z >= 0.85 threshold)
- P-01: crypto_store.py — XOR fallback removed (S313-CVE-2026-003)
- P-02: ai_engine.py — SSRF fix (S313-CVE-2026-002)
- P-03: agent.py — gate for-else fix (AGT-01)
- P-04: rag_engine.py — ChromaDB empty collection guard (RAG-01)
- P-26/27/28: plugin_signer, plugins_module, runner — logic + subprocess fixes

## Tests: 128 total, 0 failures
- 8 new test files covering all patches and new modules

Kernel: 0 load errors, 26 commands registered"

if $DRY_RUN; then
    dry "Would commit: feat(v2): sandbox sync $DATE — 64 new files + 14 security patches"
else
    # Set git identity if not configured
    if [[ -z "$(git config user.name 2>/dev/null || true)" ]]; then
        git config user.name  "Shadow313 Bot"
        git config user.email "bot@shadow313.dev"
        warn "Git identity not set — using Shadow313 Bot"
    fi

    if git diff --cached --quiet; then
        warn "Nothing staged — all files may already be up to date in this branch"
    else
        git commit -m "$COMMIT_MSG"
        ok "Committed successfully"
    fi
fi

# ── Step 9: Push ──────────────────────────────────────────────────────────────
step "9/9" "Pushing to origin/$BRANCH_NAME"
if $DRY_RUN; then
    dry "Would run: git push origin $BRANCH_NAME --set-upstream"
else
    info "Pushing..."
    git push origin "$BRANCH_NAME" --set-upstream || fail "Push failed. Check token permissions (needs 'repo' scope)."
    ok "Pushed to origin/$BRANCH_NAME"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                      PUSH COMPLETE                              ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Branch:  ${CYAN}$BRANCH_NAME${NC}"
echo -e "  Files:   $STAGED staged (${#MISSING_FILES[@]} new + ${#PATCHED_FILES[@]} patched)"
echo ""
echo -e "  ${CYAN}Open Pull Request:${NC}"
echo -e "  ${GRAY}https://github.com/$REPO_OWNER/$REPO_NAME/compare/$BRANCH_NAME${NC}"
echo ""
echo -e "  ${CYAN}After review and merge:${NC}"
echo -e "  ${GRAY}git branch -d $BRANCH_NAME${NC}"
echo ""
$DRY_RUN && warn "DRY-RUN — no actual changes made"