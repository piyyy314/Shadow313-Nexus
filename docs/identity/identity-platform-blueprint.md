# Enterprise Identity Platform — Full-Stack Product Blueprint

> Google and Microsoft sign-in • MFA • RBAC • Admin dashboard • Sessions • Audit • SaaS roadmap

**Status:** Design Phase | **Version:** 1.0 | **Date:** 2026-09-25 | **Author:** mohamad — Ottawa, ON, Canada

---

## 1. Executive Summary

This blueprint defines a production-oriented identity and access management platform built around an Express API, PostgreSQL, a React/Next.js client, and an operations dashboard. It combines local credentials, verified email, password recovery, Google and Microsoft OpenID Connect, TOTP multi-factor authentication, role-based access control, session/device controls, and defensible audit trails.

**Integration with Shadow313 NEXUS:** The identity platform feeds authentication events into the 313-BIND audit chain, enabling cryptographically verifiable proof of every login, MFA challenge, and session revocation.

---

## 2. Product Advantages

| Capability | Customer Value | Security Value |
|---|---|---|
| Unified sign-in | Fewer login barriers | Centralized policy enforcement |
| Token rotation | Long-lived sessions without repeated passwords | Limits replay exposure |
| MFA + recovery codes | Stronger customer trust | Protects compromised passwords |
| Session center | Visible devices and one-click revocation | Rapid incident response |
| RBAC | Delegated administration | Least-privilege access |
| Audit dashboard | Operational visibility | Evidence for investigations and compliance |
| Multi-tenant organizations | Team-ready product | Tenant boundaries and scoped authorization |
| **313-BIND integration** | **Tamper-evident audit trail** | **Post-quantum signed receipts for every auth event** |

---

## 3. Reference Architecture

```
Web client: Next.js/React, secure cookies, OAuth callbacks, MFA and admin views
     ↓
API: Express, validation, authentication middleware, RBAC policy checks
     ↓
Identity providers: Google OpenID Connect + Microsoft identity platform
     ↓
Data: PostgreSQL with encrypted MFA secrets and hashed one-time/recovery tokens
     ↓
313-BIND: SLH-DSA signed receipts for every auth event → IPFS anchoring
     ↓
Email: SMTP provider for verification and recovery messages
     ↓
Operations: structured logs, metrics, alerts, backups and key rotation
```

---

## 4. Core User Journeys

### Local Registration
1. Submit name, email and strong password
2. Create disabled/unverified account
3. Send single-use verification link
4. Verify email and permit sign-in
5. Issue short access token and rotating refresh token
6. **313-BIND receipt generated for registration event**

### Social Sign-In (Google/Microsoft)
1. Start provider authorization with state, nonce and PKCE
2. Validate callback and ID-token claims
3. Link only after controlled account-link confirmation
4. Create internal session and apply local policy
5. **313-BIND receipt generated for OAuth event**

### MFA Sign-In
1. Verify primary credential
2. Require TOTP or recovery code
3. Record successful factor and device metadata
4. Issue tokens only after all factors pass
5. **313-BIND receipt generated with MFA attestation**

### Password Reset
1. Return a generic response (prevents enumeration)
2. Send short-lived single-use link
3. Set new password
4. Revoke all refresh sessions and record audit event
5. **313-BIND receipt generated for credential change**

---

## 5. Data Model

| Table | Purpose | Important Controls |
|---|---|---|
| users | Identity profile and lifecycle | Normalized unique email; verified/disabled timestamps |
| identities | Google/Microsoft subject links | Unique provider + subject; no unsafe auto-linking |
| refresh_tokens | Device sessions | Hashed/token identifier; rotation family; revocation |
| mfa_factors | TOTP configuration | Encrypted secret; confirmation timestamp |
| recovery_codes | One-use MFA recovery | Individually hashed; consumed timestamp |
| roles / permissions | Authorization policy | Tenant-scoped assignments |
| organizations / members | Multi-tenancy | Membership status and role scope |
| email_action_tokens | Verify/reset actions | Hashed, typed, expiring, single-use |
| audit_logs | Security evidence | Append-oriented with actor, target, IP and result |
| **bind_receipts** | **313-BIND cryptographic proof** | **SLH-DSA signed, IPFS anchored, immutable** |

---

## 6. API Surface

| Area | Representative Endpoints |
|---|---|
| Local auth | POST /register, /login, /refresh, /logout, /logout-all |
| Email | POST /send-verification, /verify-email, /forgot-password, /reset-password |
| OAuth | GET /oauth/:provider/start, GET /oauth/:provider/callback, POST /identities/link |
| MFA | POST /mfa/setup, /mfa/confirm, /mfa/challenge, /mfa/disable, /mfa/recovery/regenerate |
| Sessions | GET /sessions, DELETE /sessions/:id |
| Admin | GET /admin/users, PATCH /admin/users/:id, GET /admin/audit |
| Organizations | POST /organizations, POST /organizations/:id/invitations, PATCH /members/:id |
| **313-BIND** | **GET /receipts/:bind_id, GET /receipts/verify/:bind_id** |

---

## 7. Security Requirements

- Use authorization code flow with PKCE, state and nonce for both OAuth providers
- Store browser tokens in Secure, HttpOnly, SameSite cookies; do not place refresh tokens in localStorage
- Encrypt TOTP secrets with a managed key; hash passwords and recovery/action tokens
- Detect refresh-token reuse and revoke the token family
- Apply per-IP and per-account throttling without creating denial-of-service lockout weaknesses
- Require recent authentication/MFA for password, identity-link, billing and administrator changes
- Validate issuer, audience, signature, nonce, timestamps and provider subject on ID tokens
- Redact credentials, tokens and secrets from logs; enforce TLS; rotate signing keys
- **All auth events signed with SLH-DSA (FIPS 205) and anchored to IPFS via 313-BIND**

---

## 8. Admin Dashboard

- **Overview:** API health, user count, active sessions, failed-login trend and security alerts
- **Users:** search, disable/enable, role assignment, session revocation and MFA reset
- **Audit:** filter by actor, action, result, date and IP; export under authorization
- **Organizations:** members, invitations, roles and subscription status
- **Settings:** OAuth configuration status, SMTP status, security policy and key age
- **313-BIND Receipts:** verify any auth event cryptographically

---

## 9. Deployment and Operations

| Layer | Recommended Production Option |
|---|---|
| Frontend | Azure Static Web Apps or App Service |
| API | Azure App Service or Container Apps |
| Database | Azure Database for PostgreSQL |
| Secrets | Azure Key Vault with managed identity |
| Email | Azure Communication Services Email or SMTP provider |
| Monitoring | Application Insights + alerts |
| Edge | Front Door/WAF and custom domain |
| **313-BIND** | **Local SLH-DSA signing + IPFS anchoring** |

---

## 10. Delivery Plan

| Phase | Deliverables | Exit Criterion |
|---|---|---|
| Foundation | PostgreSQL, migrations, config validation, test harness | Repeatable local and CI startup |
| Identity | Local auth, email flows, Google/Microsoft OIDC | End-to-end sign-in tests pass |
| Assurance | TOTP, recovery codes, step-up auth | MFA enrollment and recovery tested |
| Control | RBAC, organizations, admin dashboard | Least-privilege admin scenarios pass |
| **313-BIND** | **Auth event signing, IPFS anchoring, receipt API** | **All auth events produce verifiable receipts** |
| Production | Observability, backups, WAF, runbooks | Security review and restore drill complete |

---

## 11. PQC Crypto SBOM (from crystals_pqc_sbom.json)

| Component | Algorithm | PQC Readiness | Risk Level |
|---|---|---|---|
| openssl-core v1.1.1t | RSA-2048 Signature | LEGACY_UNSAFE | **CRITICAL** |
| liboqs-wrapper v0.8.0 | crystals-kyber-768 | COMPLIANT_PQC | ACCEPTABLE |
| boringssl-jwt-signer v3.4.1 | ECC-secp256r1 | LEGACY_UNSAFE | **HIGH** |
| cloud-db-symmetric-kms v2.1 | AES-256-GCM | COMPLIANT_HYBRID | LOW |
| auth-hash-validator v1.0 | SHA-256 | COMPLIANT_HYBRID | LOW |

**Action Required:** Migrate `openssl-core` RSA-2048 → ML-DSA-65 (FIPS 204) and `boringssl-jwt-signer` ECC → SLH-DSA (FIPS 205) before Q4 2026.

---

*Document ID: S313-IDENTITY-BLUEPRINT-2026-001 | Ottawa, ON, Canada*