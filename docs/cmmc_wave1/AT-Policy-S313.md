# Security Awareness and Training Policy
**Document ID:** S313-AT-POL-2026-001  
**Version:** 1.0 | **Date:** 2026-08-31  
**Owner:** mohamad | **System:** Shadow313 / VANGUARD-313  
**Satisfies:** NIST SP 800-53 AT-1, AT-2, AT-3 | CMMC AT.2.056, AT.2.057, AT.3.058

---

## 1. Purpose
This policy establishes requirements for security awareness training and role-based security training for all personnel with access to Shadow313 / VANGUARD-313 systems and data.

## 2. Scope
Applies to: all system operators, developers, and administrators with access to shadow313.dev, shadow313.com, or local CLI deployments.

## 3. Security Awareness Training (AT-2)

### 3.1 Frequency
- **Initial training:** Before system access is granted to any new user
- **Annual refresher:** Within 12 months of previous training completion
- **Event-driven:** Within 30 days of a significant security incident or policy change

### 3.2 Required Topics (NIST SP 800-50 baseline)
| Topic | Coverage Required |
|-------|-----------------|
| Social engineering / phishing | Recognition and reporting |
| Password hygiene | MFA, password managers, no reuse |
| Incident reporting | How and when to report security events |
| Acceptable use | What is and is not permitted on S313 systems |
| Data handling | Classification, storage, transmission rules |
| Physical security | Clean desk, screen lock, visitor control |
| PQC awareness | Why post-quantum cryptography matters for S313 |

### 3.3 Completion Records
Training completion must be documented with: date, topics covered, and operator acknowledgment signature. Records retained for minimum 3 years.

## 4. Role-Based Training (AT-3)

### 4.1 Privileged User Training (mohamad — System Owner/Admin)
Additional training required for privileged roles:
- Cryptographic key management (SLH-DSA, Argon2id, ML-DSA-65)
- 313-BIND receipt chain integrity verification
- CMMC Level 2 control responsibilities
- Incident response procedures (Ghost-Watch CADL, NEXUS alerts)
- Supply chain security (pyspx, liboqs, Azure dependencies)
- CRQC threat landscape and migration timeline

### 4.2 Frequency
Role-based training: annually, or when significant new capabilities are deployed.

## 5. Training Delivery
Acceptable formats: self-study (NIST SP 800-50, CISA resources), vendor training, conference attendance, or documented self-assessment against NIST controls. All formats require completion record.

## 6. Policy Enforcement
Non-compliance: access suspended until training is completed and documented.

## 7. Document Control
| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-08-31 | mohamad | Initial policy |

**Next Review:** 2027-08-31 (annual)