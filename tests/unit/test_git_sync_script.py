from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (ROOT / "scripts" / "push_to_github.ps1").read_text(encoding="utf-8")


def test_local_sync_script_does_not_default_to_protected_branch():
    assert '[string]$Branch = ""' in SCRIPT
    assert 'Direct pushes to' in SCRIPT
    assert '(^|/)(master|main)


def test_local_sync_script_respects_ignore_and_never_force_adds_or_force_pushes():
    assert 'Invoke-Git add -A' in SCRIPT
    assert 'git add -f' not in SCRIPT
    assert '--force' not in SCRIPT


def test_local_sync_script_requires_secret_scan_before_commit():
    assert 'scripts/check-secrets.py' in SCRIPT
    assert 'Secret scan failed' in SCRIPT
    assert 'Invoke-Git commit' in SCRIPT
    assert SCRIPT.index('Secret scan failed') < SCRIPT.index('Invoke-Git commit')


def test_local_sync_script_has_one_complete_error_handler():
    assert SCRIPT.count("catch {") == 1
    assert SCRIPT.rstrip().endswith("}")
    assert SCRIPT.count("$sensitivePath = '") == 1
    assert "Invoke-Git switch -c $Branch" in SCRIPT


def test_local_sync_script_validates_fetch_and_push_urls():
    assert "remote get-url --push --all" in SCRIPT
    assert "$invalidUrls" in SCRIPT
    assert "Invoke-Git diff --quiet" in SCRIPT


def test_root_sync_script_is_only_a_wrapper_for_the_safe_helper():
    root_script = (ROOT / "push-to-github.ps1").read_text(encoding="utf-8")
    assert "scripts/push_to_github.ps1" in root_script
    assert "git add" not in root_script.lower()
    assert "git push" not in root_script.lower()
    assert "BranchName" in root_script
    assert "CommitMessage" in root_script
 in SCRIPT


def test_local_sync_script_respects_ignore_and_never_force_adds_or_force_pushes():
    assert 'Invoke-Git add -A' in SCRIPT
    assert 'git add -f' not in SCRIPT
    assert '--force' not in SCRIPT


def test_local_sync_script_requires_secret_scan_before_commit():
    assert 'scripts/check-secrets.py' in SCRIPT
    assert 'Secret scan failed' in SCRIPT
    assert 'Invoke-Git commit' in SCRIPT
    assert SCRIPT.index('Secret scan failed') < SCRIPT.index('Invoke-Git commit')


def test_local_sync_script_has_one_complete_error_handler():
    assert SCRIPT.count("catch {") == 1
    assert SCRIPT.rstrip().endswith("}")
    assert SCRIPT.count("$sensitivePath = '") == 1
    assert "Invoke-Git switch -c $Branch" in SCRIPT


def test_local_sync_script_validates_fetch_and_push_urls():
    assert "remote get-url --push --all" in SCRIPT
    assert "$invalidUrls" in SCRIPT
    assert "Invoke-Git diff --quiet" in SCRIPT


def test_root_sync_script_is_only_a_wrapper_for_the_safe_helper():
    root_script = (ROOT / "push-to-github.ps1").read_text(encoding="utf-8")
    assert "scripts/push_to_github.ps1" in root_script
    assert "git add" not in root_script.lower()
    assert "git push" not in root_script.lower()
    assert "BranchName" in root_script
    assert "CommitMessage" in root_script
