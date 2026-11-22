# Evidence and reporting

## Evidence labels

- **OBSERVED** — directly returned by a tool, test, build, provider, or file read.
- **DERIVED** — deterministic result computed from observed evidence.
- **INFERRED** — reasoned from code or incomplete evidence; not directly verified.
- **PROPOSED** — suggested future action or unexecuted test.

## Report template

### Scope
- Repository:
- Branch / PR:
- HEAD SHA:
- Areas inspected:

### Findings
| Severity | Status | File / evidence | Impact | Action |
|---|---|---|---|---|

### Validation
| Check | Result | Evidence |
|---|---|---|
| Unit/integration tests | PASS / FAIL / NOT RUN | |
| Lint/type checks | PASS / FAIL / NOT RUN | |
| Security scans | PASS / FAIL / BLOCKED / NOT RUN | |
| Build | PASS / FAIL / NOT RUN | |
| Provider/deployment | VERIFIED / NOT VERIFIED | |

### Changes
- Files changed:
- Commit / PR:
- Rollback consideration:

### Remaining blockers
List exact blockers, owner/dependency, and next safe action.

## Language rules

Do not say "all fixed", "all checks pass", "secure", "deployed", "merged", or "production ready" unless evidence supports the precise claim. State the scope and date/commit for every status snapshot.
