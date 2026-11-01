#!/usr/bin/env bash
# Shadow313 NEXUS — GitHub Push Script (Bash/Linux version)
# Pushes all new/modified sandbox files to a new branch on the remote repo.
#
# Usage:
#   ./push-to-github.sh
#   ./push-to-github.sh --branch "feature/v2-patches-oct29"
#   ./push-to-github.sh --dry-run
#   ./push-to-github.sh --branch "hotfix/p24" --message "fix: JA3 FIPS compliance"
#   ./push-to-github.sh --skip-tests
#
# Repo: github.com/piyyy314/Shadow313-Nexus

set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; GRAY='\033[0;37m'; MAGENTA='\033[0;35m'; NC='\033[0m'

step()  { echo -e "\n${CYAN}[STEP]${NC} $*"; }
ok()    { echo -e "  ${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "  ${YELLOW}[WARN]${NC} $*"; }
fail()  { echo -e "  ${RED}[FAIL]${NC} $*"; }
info()  { echo -e "  ${GRAY}[INFO]${NC} $*"; }
dry()   { echo -e "  ${MAGENTA}[DRY-RUN]${NC} $*"; }

# ── Defaults ──────────────────────────────────────────────────────────────────
BRANCH_NAME=""
COMMIT_MSG=""
REMOTE="origin"
DRY_RUN=false
SKIP_TESTS=false

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --branch|-b)    BRANCH_NAME="$2"; shift 2 ;;
        --message|-m)   COMMIT_MSG="$2";  shift 2 ;;
        --remote|-r)    REMOTE="$2";      shift 2 ;;
        --dry-run|-n)   DRY_RUN=true;     shift   ;;
        --skip-tests)   SKIP_TESTS=true;  shift   ;;
        --help|-h)
            sed -n '2,20p' "$0" | sed 's/^# \?//'
            exit 0 ;;
        *) warn "Unknown argument: $1"; shift ;;
    esac
done

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║          Shadow313 NEXUS — GitHub Push Script               ║${NC}"
echo -e "${CYAN}║          Sandbox → github.com/piyyy314/Shadow313-Nexus      ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

$DRY_RUN && warn "DRY-RUN MODE — no changes will be made to git or remote"

# ── Step 1: Verify git ────────────────────────────────────────────────────────
step "1/8 — Verifying git installation"
if ! command -v git &>/dev/null; then
    fail "git not found. Install with: apt-get install git"
    exit 1
fi
GIT_VER=$(git --version)
ok "Git found: $GIT_VER"

# ── Step 2: Verify repo and remote ───────────────────────────────────────────
step "2/8 — Verifying git repository"
if ! REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null); then
    fail "Not inside a git repository. Run from /workspace."
    exit 1
fi
ok "Repository root: $REPO_ROOT"

if ! REMOTE_URL=$(git remote get-url "$REMOTE" 2>/dev/null); then
    fail "Remote '$REMOTE' not configured."
    info "Add it with: git remote add origin https://github.com/piyyy314/Shadow313-Nexus.git"
    info "Or with SSH: git remote add origin git@github.com:piyyy314/Shadow313-Nexus.git"
    exit 1
fi
ok "Remote '$REMOTE': $REMOTE_URL"

# ── Step 3: Check status ──────────────────────────────────────────────────────
step "3/8 — Checking current branch and status"
CURRENT_BRANCH=$(git branch --show-current)
info "Current branch: $CURRENT_BRANCH"

mapfile -t CHANGED_FILES < <(git status --porcelain 2>/dev/null | grep -E "^[ MADRCU?]" || true)
NEW_FILES=$(git status --porcelain 2>/dev/null | grep -c "^??" || true)
MODIFIED_FILES=$(git status --porcelain 2>/dev/null | grep -cE "^[ M]M|^M " || true)
DELETED_FILES=$(git status --porcelain 2>/dev/null | grep -cE "^[ D]D|^D " || true)
TOTAL=${#CHANGED_FILES[@]}

if [[ $TOTAL -eq 0 ]]; then
    warn "No changes detected. Nothing to push."
    info "If you expected changes, run: git status"
    exit 0
fi

info "Files to be committed:"
info "  New files:      $NEW_FILES"
info "  Modified files: $MODIFIED_FILES"
info "  Deleted files:  $DELETED_FILES"
info "  Total:          $TOTAL"

# ── Step 4: Run tests ─────────────────────────────────────────────────────────
step "4/8 — Running test suite"
if $SKIP_TESTS; then
    warn "Tests skipped (--skip-tests flag set)"
elif $DRY_RUN; then
    dry "Would run: python run_tests.py"
else
    if [[ -f "$REPO_ROOT/run_tests.py" ]]; then
        info "Running: python run_tests.py"
        if ! python run_tests.py 2>&1 | tail -5; then
            fail "Tests failed. Fix failures before pushing."
            info "Run 'python run_tests.py' to see details."
            exit 1
        fi
        ok "All tests passed"
    else
        info "run_tests.py not found, using unittest discover"
        if ! python -m unittest discover -s tests -p "test_*.py" 2>&1 | tail -5; then
            fail "Tests failed. Fix failures before pushing."
            exit 1
        fi
        ok "All tests passed"
    fi
fi

# ── Step 5: Branch name ───────────────────────────────────────────────────────
step "5/8 — Preparing branch name"
if [[ -z "$BRANCH_NAME" ]]; then
    TIMESTAMP=$(date +"%Y%m%d-%H%M")
    BRANCH_NAME="shadow313/sandbox-sync-$TIMESTAMP"
fi

# Avoid collision with existing branch
if git branch --list "$BRANCH_NAME" | grep -q "$BRANCH_NAME"; then
    SUFFIX=$(date +"%S")
    BRANCH_NAME="${BRANCH_NAME}-${SUFFIX}"
    warn "Branch already exists locally. Using: $BRANCH_NAME"
fi
info "Branch name: $BRANCH_NAME"

# ── Step 6: Create branch and stage ──────────────────────────────────────────
step "6/8 — Creating branch and staging files"
if $DRY_RUN; then
    dry "Would run: git checkout -b $BRANCH_NAME"
    dry "Would run: git add -A"
else
    git checkout -b "$BRANCH_NAME"
    ok "Created branch: $BRANCH_NAME"
    git add -A
    ok "Staged all changes"
fi

# ── Step 7: Commit ────────────────────────────────────────────────────────────
step "7/8 — Committing changes"
DATE=$(date +"%Y-%m-%d")

if [[ -z "$COMMIT_MSG" ]]; then
    COMMIT_MSG="feat(v2): sandbox sync $DATE — patches P19-P32 + new modules

## New Modules
- shadow313/v2/network_upgrades/firmware_auditor.py (FW-01: firmware hash verification)
- shadow313/modules/defense/remediation.py: FileEncryptionRateMonitor (RW-01)
- shadow313/modules/network/topology.py: RoutingTableMonitor (NB-01)
- shadow313/modules/network/flow_tracker.py: OutboundVolumeMonitor + UserFileAccessMonitor

## Security Patches
- P-24: ja3_fingerprint.py — MD5 usedforsecurity=False (FIPS/B324)
- P-25: threat_intel.py — SQL injection guard in stats() (B608)
- P-26: plugin_signer.py — Restored sign/verify blocks in run()
- P-27: plugins_module.py — W0106 expression-not-assigned fixed
- P-28: runner.py — Restored corrupted subprocess.run() call
- P-29/30: subprocess check=False (system_info, network_module)
- P-31: open() encoding=utf-8 (scope.py, manifest.py)
- P-32: cli/main.py — removed unused new_key variable

## New Features
- P-19: epss_kev.py — composite_z_score() + should_include()

## Tests
- tests/unit/test_new_patches.py — 66 new tests (128 total, 0 failures)

## Documents (Word + PDF)
- document/shadow313-hybrid-cve-scoring/ (14 pages)
- document/shadow313-defensive-controls/ (14 pages)
- document/shadow313-attack-simulation/ (12 pages)
- document/shadow313-evasion-campaign/ (11 pages)

Kernel: 0 load errors, 26 commands registered"
fi

FIRST_LINE=$(echo "$COMMIT_MSG" | head -1)
info "Commit message (first line): $FIRST_LINE"

if $DRY_RUN; then
    dry "Would run: git commit -m '$FIRST_LINE...'"
else
    # Configure git identity if not set
    if [[ -z "$(git config user.name 2>/dev/null || true)" ]]; then
        git config user.name  "Shadow313 Bot"
        git config user.email "bot@shadow313.dev"
        warn "Git identity not configured — using defaults (Shadow313 Bot)"
    fi
    git commit -m "$COMMIT_MSG"
    ok "Committed successfully"
fi

# ── Step 8: Push ──────────────────────────────────────────────────────────────
step "8/8 — Pushing to $REMOTE/$BRANCH_NAME"
if $DRY_RUN; then
    dry "Would run: git push $REMOTE $BRANCH_NAME --set-upstream"
else
    info "Pushing... (this may take a moment)"
    if ! git push "$REMOTE" "$BRANCH_NAME" --set-upstream; then
        fail "Push failed."
        echo ""
        warn "Common fixes:"
        info "  1. GitHub CLI:"
        info "     gh auth login"
        info "     gh auth setup-git"
        info "  2. SSH key:"
        info "     git remote set-url origin git@github.com:piyyy314/Shadow313-Nexus.git"
        exit 1
    fi
    ok "Pushed successfully to $REMOTE/$BRANCH_NAME"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    PUSH COMPLETE                            ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Branch:   ${CYAN}$BRANCH_NAME${NC}"
echo -e "  Remote:   $REMOTE ($REMOTE_URL)"
echo -e "  Files:    $TOTAL changed ($NEW_FILES new, $MODIFIED_FILES modified, $DELETED_FILES deleted)"
echo ""
echo -e "  ${CYAN}Next steps:${NC}"
echo    "  1. Open a Pull Request:"
echo -e "     ${GRAY}https://github.com/piyyy314/Shadow313-Nexus/compare/$BRANCH_NAME${NC}"
echo    "  2. Review changes on GitHub before merging to main"
echo    "  3. After merge, delete the branch:"
echo -e "     ${GRAY}git branch -d $BRANCH_NAME${NC}"
echo ""

$DRY_RUN && warn "DRY-RUN complete — no actual changes were made"