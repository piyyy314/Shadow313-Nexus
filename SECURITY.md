# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| v4.0.0-NEXUS | ✅ Active |
| v3.x | ⚠️ Security fixes only |
| v2.x | ❌ End of life |
| v1.x | ❌ End of life |

## Reporting a Vulnerability

Shadow313 NEXUS takes security seriously. We welcome responsible disclosure.

**Email:** security@shadow313.dev (or matarmohamad313@duck.com)
**Subject:** `[CVE DISCLOSURE] Brief description`
**Response time:** Within 24 hours

### What to include
- Affected component and version
- Step-by-step reproduction steps
- Impact assessment
- Your contact info for credit

### Our commitment
- Acknowledge within 24 hours
- Resolution timeline within 72 hours
- Credit in changelog (unless anonymity requested)
- No legal action against good-faith researchers

## Bug Bounty

| Severity | Examples | Reward |
|----------|----------|--------|
| Critical | RCE, auth bypass, key extraction | $500–$2,000 + CVE credit |
| High | Path traversal, SSRF, privilege escalation | $100–$500 + CVE credit |
| Medium | Information disclosure, CSRF | $25–$100 + credit |
| Low | Minor issues, best-practice violations | Public credit |

## Known CVEs

| ID | Component | Severity | Status |
|----|-----------|----------|--------|
| S313-CVE-2026-001 | Session path traversal (encrypted writes) | HIGH | ✅ Fixed v4.0.1 |
| S313-CVE-2026-002 | SSRF in AI engine URL handling | MEDIUM | ✅ Fixed v4.0.1 |
| S313-CVE-2026-003 | Crypto plaintext downgrade on import failure | HIGH | ✅ Fixed v4.0.1 |
| S313-CVE-2026-006 | ECDSA P-256 cosign (CRQC vulnerable) | CRITICAL | 🔄 Migrating Q4 2026 |

Full security policy: https://shadow313.dev/security-policy
