# Repair a defect or implement a feature

## Preconditions

- The user requested a repair or feature, not merely an audit.
- Repository identity, target branch, and current state are known.
- Relevant files, call sites, tests, and repository instructions have been inspected.
- The mutation is within the user's authorization.

## Procedure

1. Reproduce the defect or establish a precise failing condition. Capture the actual error, failing test, or code path; do not infer a runtime failure from naming alone.
2. Write a short work packet: expected behavior, observed behavior, root-cause hypothesis, affected files, regression test, and explicit non-goals.
3. Choose the smallest root-cause patch. Preserve compatibility unless a breaking change is explicitly requested.
4. Add or update regression tests. For CLI work, verify command parsing, registration, handler invocation, output, error handling, and help/docs. For APIs, verify request schema, auth, response schema, status codes, timeouts, and safe error handling. For UI work, verify responsive layout, navigation, accessible controls, loading/empty/error states, and source-of-truth data.
5. Update docs only where behavior, configuration, commands, setup, or operational ownership changed. Keep README, CLI help, examples, and actual code consistent.
6. Inspect secrets handling and permissions around any AI/provider integration. Keep secrets in environment/secret stores; never add real values to fixtures or docs.
7. Re-read every changed file and inspect the complete diff for unrelated changes, accidental deletions, generated artifacts, and secret leakage.
8. Run the narrowest relevant tests first, then lint/type/security/build checks relevant to the changed subsystem. If a check is unavailable, record it as NOT RUN with the reason.
9. If a test fails, inspect its logs and distinguish regression from pre-existing failure. Do not silence or skip it merely to obtain a green result.
10. Report exact files changed, behavior fixed, tests and results, unresolved risks, branch and commit SHA. Do not claim a push, merge, or deployment unless the host confirms it.

## Stop conditions

Stop before mutation if repository identity is ambiguous, unrelated user changes would be overwritten, required authorization is absent, a security issue requires broader approval, or the only proposed fix weakens a security/CI control.
