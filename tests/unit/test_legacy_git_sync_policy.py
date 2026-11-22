"""Regression tests for safe repository synchronization helpers."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_windows_sync_helper_rejects_protected_branches_and_scans_secrets():
    source = (ROOT / "push-to-github.ps1").read_text(encoding="utf-8")
    assert "$BranchName -match '^(master|main)$'" in source
    assert "scripts/check-secrets.py" in source
    assert source.index("& python $secretScanner") < source.index("git push $Remote $BranchName")


def test_bash_sync_helper_rejects_protected_branches_and_scans_secrets():
    source = (ROOT / "push-to-github.sh").read_text(encoding="utf-8")
    assert '"$BRANCH_NAME" =~ ^(master|main)$' in source
    assert 'python "$REPO_ROOT/scripts/check-secrets.py"' in source
    assert source.index('python "$REPO_ROOT/scripts/check-secrets.py"') < source.index('git push "$REMOTE" "$BRANCH_NAME"')


def test_git_setup_script_never_stages_or_pushes_automatically():
    source = (ROOT / "scripts/setup-git-workflow.ps1").read_text(encoding="utf-8")
    assert "nothing was staged, committed, or pushed" in source
    assert "git push origin master" not in source
    assert "& git commit" not in source


def test_master_scan_never_embeds_a_token_or_pushes_to_master():
    source = (ROOT / "scripts/shadow313-master-scan.ps1").read_text(encoding="utf-8")
    assert "git push origin master" not in source
    assert "piyyy314:$Token@" not in source
    assert "auto-push fixes" not in source.lower()
    assert "read-only GitHub secrets inventory" in source
