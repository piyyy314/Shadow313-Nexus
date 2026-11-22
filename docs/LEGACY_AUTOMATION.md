# Legacy workstation automation

## Security boundary

The repository previously contained a number of one-off PowerShell scripts that combined local machine repair, broad file rewriting, personal access token handling, and direct pushes to `master`. Those scripts are not an approved deployment or release mechanism.

The following direct-to-master scripts were removed from the active tree in the current CI/site hardening work:

- `final_push.ps1`, `fix_ci_final.ps1`, `push_all.ps1`, and `scripts/push-everything.ps1`
- `deploy_to_laptop.ps1`
- `scripts/fix-and-push.ps1` and `scripts/push-and-fix-all.ps1`
- `scripts/cleanup-repo.ps1` and `scripts/push-sandbox-fixes.ps1`
- `scripts/shadow313-one-shot-setup.ps1`, `scripts/shadow313-repo-rebuild.ps1`, and `scripts/shadow313-laptop-full-fix.ps1`
- `scripts/shadow313-profile-audit-and-fix.ps1` and `scripts/apply-sandbox-fixes.ps1`

The reviewed patterns included PATs embedded in HTTPS remote URLs, direct pushes to `master`, and in some cases `git commit --no-verify`. A token embedded in a remote URL can remain in `.git/config` if a script exits before resetting it. The scripts also made broad, difficult-to-review edits to local files.

No live credential was identified in the reviewed snippets; the risk was the credential-handling and direct-push pattern.

## Safe Git workflow

1. Authenticate: `gh auth login`.
2. Configure Git: `gh auth setup-git`.
3. Update local `master` and create a feature branch.
4. Stage only reviewed files; inspect `git diff --cached`.
5. Run relevant tests, lint, and security checks.
6. Push the feature branch with `git push -u origin <branch>`.
7. Open a pull request and use the repository's review/check process.

Do not place PATs in remote URLs, command-line arguments, commit messages, or logs. If a real token is exposed, revoke and rotate it.

## Retained tools

- `push-to-github.ps1` creates a feature branch, runs tests by default, and pushes that branch. It uses the Git credential helper configured by GitHub CLI.
- `scripts/push_to_github.ps1` is a separate branch-oriented helper; inspect its dry-run and staging behavior before use.
- `scripts/setup-git-workflow.ps1` removes embedded credentials from the remote and configures local safeguards.
- Read-only audit, inventory, and workstation diagnostics may remain under `scripts/`; they are not production deployment tools.

## Retirement policy

Do not reintroduce one-shot scripts that combine system repair, secret handling, and direct pushes. New automation must be small, tested, least-privilege, and branch-based. Move or remove remaining historical helpers only after checking their callers and local dependencies.
