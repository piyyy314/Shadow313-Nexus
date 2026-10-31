"""shadow313.modules.quantum.timeline — Quantum threat timeline estimator."""
from __future__ import annotations
from .quantum_data import classify_algorithm


def estimate_threat_timeline(algorithms: list[str]) -> dict:
    """Return heuristic migration risk, bundled timeline text, and vulnerable algorithms.

    RSA/ECC name matches select CRITICAL; recognized weak symmetric names
    select HIGH; other inputs select LOW. Timeline text is fixed reference
    data, not a live forecast.
    """
    has_rsa      = any("RSA" in a.upper() for a in algorithms)
    has_ecc      = any(k in " ".join(algorithms).upper()
                       for k in ("ECDH", "ECDSA", "ED25519", "P-256", "P-384"))
    has_sym_weak = any(a.upper() in ("AES-128", "3DES", "DES", "RC4") for a in algorithms)

    risk_level = "LOW"
    if has_rsa or has_ecc:
        risk_level = "CRITICAL"
    elif has_sym_weak:
        risk_level = "HIGH"

    return {
        "risk_level":             risk_level,
        "crqc_estimated_arrival": "2030-2035 (community consensus, IBM/Google roadmaps)",
        "harvest_now_threat":     "Active — state actors may already be harvesting encrypted data",
        "migration_urgency":      "HIGH" if risk_level in ("CRITICAL", "HIGH") else "MEDIUM",
        "recommended_action": (
            "Begin PQC migration NOW for long-lived data. "
            "Prioritise key exchange algorithms first (TLS, VPN, SSH)."
            if risk_level == "CRITICAL"
            else "Plan PQC migration within 2 years."
        ),
        "vulnerable_algorithms": [a for a in algorithms
                                   if classify_algorithm(a)["vuln"] == "VULNERABLE"],
    }