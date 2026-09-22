# Acceptable Use Agreement (AUA)
**Document ID:** S313-PS-AUA-2026-001  
**Version:** 1.0 | **Date:** 2026-08-31  
**System:** Shadow313 / VANGUARD-313  
**Satisfies:** NIST SP 800-53 PS-6, PL-4 | CMMC PS.2.127

---

I, **mohamad**, acknowledge that I have read, understand, and agree to comply with the following rules governing my use of Shadow313 / VANGUARD-313 systems:

## Permitted Uses
- Security research, vulnerability scanning, and threat intelligence operations within authorized scope
- Development, testing, and deployment of Shadow313 platform components
- Access to security findings, audit logs, and 313-BIND receipts for authorized operational purposes

## Prohibited Uses
- Using Shadow313 capabilities against systems without explicit written authorization (scope.yaml required for exploit module)
- Sharing security findings, CVE data, or threat intelligence with unauthorized parties
- Disabling, bypassing, or tampering with audit logging or 313-BIND receipt chains
- Storing personally identifiable information (PII) in any Shadow313 session or database
- Using Shadow313 for any purpose that violates applicable law (CFAA, Computer Misuse Act, PIPEDA)
- Sharing cryptographic keys (SLH-DSA, ML-DSA-65, Argon2id) with any unauthorized party

## Security Responsibilities
- Maintain MFA on all Azure AD B2C accounts at all times
- Report any suspected security incident within 4 hours via Ghost-Watch CADL or direct notification
- Lock workstation when unattended (≤5 minute timeout)
- Never store credentials in plaintext; use Azure Key Vault or the Shadow313 CryptoStore
- Immediately report any suspected compromise of cryptographic key material

## Acknowledgment

By signing below, I certify that:
1. I have read and understand this Acceptable Use Agreement
2. I understand that violations may result in access revocation and legal action
3. I agree to comply with all terms stated above
4. I understand that my activities on Shadow313 systems are subject to audit logging via 313-BIND

**Signature:** mohamad  
**Date:** 2026-08-31  
**Title:** System Owner / Lead Developer  
**Location:** Ottawa, ON, Canada

---

*This agreement is reviewed annually. Next review: 2027-08-31.*