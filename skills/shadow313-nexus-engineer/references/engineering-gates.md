# Engineering and security gates

## General quality gates

- Correct repository and branch confirmed.
- Existing instructions and relevant code paths inspected.
- No unrelated user work overwritten.
- Root cause supported by evidence.
- Regression coverage added or a reason documented.
- Changed files re-read and diff inspected.
- Relevant tests, lint, type checks, security scans, and build run where available.
- Documentation and runtime behavior agree.

## CLI completeness gate

A command is complete only when all applicable pieces agree:
1. parser/argument schema
2. command registration
3. executable handler
4. permission/auth boundary
5. predictable success and error output
6. tests for normal, invalid, and failure cases
7. help text and docs

## API and AI gateway gate

Check:
- explicit request/response schema validation
- authentication and authorization appropriate to route sensitivity
- bounded input sizes and timeouts
- safe retries only for idempotent operations
- rate limiting and abuse controls where exposed publicly
- provider/model fallback behavior is observable and deterministic
- errors do not leak prompts, secrets, stack traces, or provider credentials
- logs avoid sensitive payloads
- secrets are read from approved environment/secret storage
- tests cover unavailable provider, malformed response, timeout, and auth failures

## Web/dashboard gate

Check:
- all navigation targets resolve
- page metadata and canonical URLs are consistent
- shared product/service facts come from one source where practical
- no stale version/domain/feature claims
- mobile and desktop layouts
- accessible labels, keyboard focus, contrast, and semantic headings
- loading, empty, error, and offline states
- no hardcoded secrets or unsafe HTML injection

## CI/security gate

- Workflow permissions are least-privilege.
- Actions use pinned versions or justified update policy.
- Untrusted PR code is not granted secrets or write permissions unnecessarily.
- Dependency, secret, static-analysis, and test checks are not silently disabled.
- External scanner quotas and outages are reported as externally blocked, not passed.
- Do not weaken branch protections or required checks to force green status.

## Deployment/DNS gate

- Repository config is not proof of provider state.
- Confirm Vercel project and target deployment before deployment changes.
- Confirm Cloudflare zone and authoritative DNS before DNS changes.
- Preserve existing records; change only named records with a clear rollback.
- TLS, redirects, canonical host, and API routing must be checked as separate concerns.
- Production deployment and DNS mutation require explicit task-specific authorization.
