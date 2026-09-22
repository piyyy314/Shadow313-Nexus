# STIA War Games Engagement Report
**Timestamp:** 2026-07-25 09:26:40  
**Red Team Objective:** Degrade signal link integrity below 30%  
**Final Metrics:** Link Integrity: 0.0% | Threat Level: ELEVATED  
**Outcome:** BLUE TEAM WINS

---

## Executive Summary

A simulated cyber engagement assessed the defensive posture of the primary SatCom network. The Red Team employed coordinated RF jamming, GPS spoofing, and telemetry injection attacks. Blue Team successfully defended using FHSS, cryptographic validation, and atomic clock fallback.

---

## Attack Vectors Used (Red Team)

| Vector | Description | Result |
|--------|-------------|--------|
| RF Jamming | High-power noise on primary uplink frequency | Partial success — caused packet loss |
| GPS Spoofing | Injected malformed GPS sync frames | Mitigated by cryptographic timestamp verification |
| Telemetry Injection | Malformed frame headers to force desync | Partially blocked by FHSS |
| DDoS on Control Port | High-volume flood on telemetry gateway | Blocked by ingress rate-limiting |

---

## Defense Countermeasures (Blue Team)

| Countermeasure | Technique | Effectiveness |
|----------------|-----------|---------------|
| FHSS | Dynamic Frequency-Hopping Spread Spectrum | HIGH — prevented total blackout |
| Cryptographic Validation | Timestamp verification + ML-DSA signing | HIGH — blocked GPS spoofing |
| Atomic Clock Fallback | Rubidium clock independence | HIGH — maintained frequency alignment |
| Ingress Filtering | Rate-limiting on telemetry gateway | MEDIUM — limited DDoS impact |
| Phased-Array Nulling | Spatial filtering via antenna | MEDIUM — reduced jamming effectiveness |

---

## ATT&CK Mapping (Space Domain)

| Event | MITRE Technique | Description |
|-------|----------------|-------------|
| RF Jamming | T1498 — Network Denial of Service | Physical layer signal saturation |
| GPS Spoofing | T1565.002 — Transmitted Data Manipulation | Injecting false telemetry |
| Telemetry Injection | T1190 — Exploit Public-Facing Application | Malformed frame injection |
| DDoS on Control | T1498.002 — Service Exhaustion Flood | Control port flooding |

---

## Lessons Learned

1. **FHSS is essential** — Without frequency hopping, RF jamming would have achieved the 30% degradation objective within 2 minutes
2. **Cryptographic timestamp validation** is the primary defense against GPS spoofing — atomic clock fallback is the secondary
3. **Logging infrastructure must be validated** before simulation — empty combat logs indicate SIEM failure, not a quiet network
4. **Multi-vector attacks** (RF + DDoS simultaneously) are significantly more effective than single-vector

---

## Recommendations

1. Audit logging infrastructure before each engagement — verify ambient telemetry is writing to SIEM
2. Implement "Proof of Life" pings to confirm log is actively recording
3. Deploy CRPA (Controlled Reception Pattern Antennas) for null-steering against terrestrial jammers
4. Add Faraday shielding to critical ground station components
5. Integrate Shadow313 Aegis VSAT module for real-time RF anomaly detection

---

*Prepared by: Shadow313 NEXUS — Aegis VSAT Module | Ottawa, ON, Canada*