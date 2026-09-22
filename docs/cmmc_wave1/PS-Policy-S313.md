# Personnel Security Policy
**Document ID:** S313-PS-POL-2026-001  
**Version:** 1.0 | **Date:** 2026-08-31  
**Owner:** mohamad | **System:** Shadow313 / VANGUARD-313  
**Satisfies:** NIST SP 800-53 PS-1 through PS-8 | CMMC PS.2.127, PS.2.128

---

## 1. Purpose
This policy establishes personnel security requirements for all individuals with access to Shadow313 / VANGUARD-313 systems, data, and facilities. It ensures that personnel are trustworthy and meet security requirements commensurate with their access level.

## 2. Scope
Applies to: all system operators, developers, contractors, and administrators with logical or physical access to S313 systems. Currently: mohamad (sole operator).

---

## 3. Position Risk Designation (PS-2)

| Position | Individual | Risk Level | Rationale |
|----------|-----------|-----------|-----------|
| System Owner / Lead Developer | mohamad | **HIGH** | Full system access, cryptographic key custody, production deployment authority, access to sensitive security intelligence data |

**Risk level justification:** HIGH designation applies because this position has: (1) unrestricted access to all system components, (2) custody of cryptographic signing keys (SLH-DSA, ML-DSA-65), (3) ability to modify audit logs and 313-BIND receipts, and (4) access to sensitive security scan results and threat intelligence.

---

## 4. Personnel Screening (PS-3)

### 4.1 Screening Requirements by Risk Level
| Risk Level | Required Screening |
|-----------|-------------------|
| HIGH | Identity verification, criminal background check, reference check |

### 4.2 Current Screening Status
| Individual | Identity Verified | Background Check | Date | Status |
|-----------|-----------------|-----------------|------|--------|
| mohamad | ✅ Government ID | ✅ Self-certified (sole proprietor) | 2026-08-31 | Complete |

*Note for 3PAO: As a sole proprietor operating in Ottawa, ON, Canada under PIPEDA jurisdiction, formal third-party background screening is documented via self-certification. For FedRAMP authorization involving federal data, a formal background investigation (e.g., RCMP criminal record check) should be obtained prior to 3PAO assessment.*

---

## 5. Access Agreements (PS-6)

All personnel must sign the following before system access is granted:
1. **Acceptable Use Agreement (AUA)** — S313-PS-AUA-2026-001
2. **Non-Disclosure Agreement (NDA)** — covering security findings, threat intelligence, and audit data
3. **Rules of Behavior** — S313-PL-ROB-2026-001 (to be created per PL-4)

### 5.1 Signed Agreements Log
| Individual | AUA Signed | NDA Signed | Date | Expiry |
|-----------|-----------|-----------|------|--------|
| mohamad | ✅ | ✅ | 2026-08-31 | Annual renewal |

---

## 6. Personnel Termination (PS-4)

Upon termination of any personnel:

| Action | Timeline | Responsible |
|--------|----------|-------------|
| Revoke all logical access (Azure AD, CLI, SSH) | Immediately | System Owner |
| Rotate all cryptographic keys (SLH-DSA, ML-DSA-65, Argon2id) | Within 24 hours | System Owner |
| Retrieve all equipment and access tokens | Within 24 hours | System Owner |
| Disable Azure AD B2C account | Immediately | System Owner |
| Archive session data and audit logs | Within 48 hours | System Owner |
| Conduct exit interview and document | Within 1 week | System Owner |

---

## 7. Personnel Transfer (PS-5)

When personnel change roles:
- Re-evaluate access requirements against new role
- Revoke access no longer required within 24 hours
- Update position risk designation table (Section 3)
- Re-execute access agreements if role changes significantly

---

## 8. Sanctions (PS-8)

Violations of this policy or the Acceptable Use Agreement may result in:
- Immediate suspension of system access
- Termination of engagement
- Referral to appropriate legal authorities if criminal activity is involved

---

## 9. Third-Party Personnel (PS-7)

Any third-party contractors or consultants requiring system access must:
1. Complete the same screening as direct personnel (commensurate with risk level)
2. Sign AUA and NDA before access is granted
3. Be granted minimum necessary access (AC-6 least privilege)
4. Have access revoked immediately upon engagement completion

*Currently: No third-party personnel have system access.*

---

## 10. Document Control
| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-08-31 | mohamad | Initial policy |

**Next Review:** 2027-08-31 (annual)