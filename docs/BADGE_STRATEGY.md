# Badge Strategy — Static vs Live

## Live Badges (always credible — auto-update)
- Build Status — from GitHub Actions CI
- Tests: 4107 — update when count changes
- PyPI — auto after pip install shadow313 published
- OpenSSF Scorecard — enable at securityscorecards.dev (5 min free)
- Snyk — connect at snyk.io (10 min free)
- Codecov — connect at codecov.io (10 min free)

## Static Compliance Badges (defensible claims only)
| Badge | Defensible? | Reason |
|-------|-------------|--------|
| NIST PQC FIPS 203/204/205 | YES | You implement ML-KEM, ML-DSA, SLH-DSA |
| MITRE ATT&CK v15 | YES | You map 136/265 techniques |
| FIPS 140-3 Aligned | YES | You follow the standard |
| FedRAMP Moderate Ready | YES | Your SSP covers Moderate baseline |
| FIPS 140-3 Level 3 | NO | Requires certified HSM hardware |
| FedRAMP High Ready | NO | Requires 3PAO assessment |

## Cross-Repo Integration
- OmniSec-Sentinel: quantum_ai_engine/ (6 modules) -> shadow313/v4/quantum_nexus/
- SatExpert313: 55 TypeScript components -> 3 Python modules
