"""Guardrails for the remaining legacy repository synchronization scripts."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_bash_sync_helper_rejects_protected_branches_and_scans_secrets():
    source = (ROOT / "push-to-github.sh").read_text(encoding="utf-8")
    assert '"$BRANCH_NAME" =~ ^(master|main)$' in source
    assert "is_expected_remote" in source
    assert "https://github\\.com/piyyy314/Shadow313-Nexus" in source
    assert "git@github\\.com:piyyy314/Shadow313-Nexus" in source
    assert 'git remote get-url --push --all "$REMOTE"' in source
    assert "PUSH_URLS" in source
    assert 'python "$REPO_ROOT/scripts/check-secrets.py"' in source
    assert source.index('python "$REPO_ROOT/scripts/check-secrets.py"') < source.index('git push "$REMOTE" "$BRANCH_NAME"')
    assert "git add -f" not in source
    assert "--force" not in source


def test_git_workflow_setup_never_stages_commits_or_pushes_automatically():
    source = (ROOT / "scripts/setup-git-workflow.ps1").read_text(encoding="utf-8")
    assert "nothing was staged, committed, or pushed" in source
    assert "git push origin master" not in source
    assert "& git commit" not in source
    assert "& git add ." not in source


def test_master_scan_never_embeds_a_token_or_pushes_to_master():
    source = (ROOT / "scripts/shadow313-master-scan.ps1").read_text(encoding="utf-8")
    assert "git push origin master" not in source
    assert "piyyy314:$Token@" not in source
    assert "auto-push fixes" not in source.lower()
    assert "read-only GitHub secrets inventory" in source
