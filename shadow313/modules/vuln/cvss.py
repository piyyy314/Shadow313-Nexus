"""shadow313.modules.vuln.cvss — CVSS v3.1 scorer with contextual adjustment."""
from __future__ import annotations

SEVERITY_MAP = {
    "CRITICAL": (9.0, 10.0),
    "HIGH":     (7.0, 8.9),
    "MEDIUM":   (4.0, 6.9),
    "LOW":      (0.1, 3.9),
    "NONE":     (0.0, 0.0),
}


class CVSSScorer:
    """CVSS v3.1 base score computation with contextual modifiers."""

    @staticmethod
    def severity_from_score(score: float) -> str:
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0.0:
            return "LOW"
        return "NONE"

    @staticmethod
    def contextual_score(cvss: float, has_exploit: bool = False,
                         is_internet_facing: bool = False,
                         has_kev: bool = False) -> float:
        """Adjust CVSS with contextual factors."""
        score = cvss
        if has_kev:
            score = 10.0  # KEV always critical
        else:
            if has_exploit:
                score = min(10.0, score * 1.3)
            if is_internet_facing:
                score = min(10.0, score * 1.1)
        return round(score, 1)

    @staticmethod
    def epss_composite(cvss: float, epss: float) -> float:
        """Combined CVSS × EPSS composite risk score (0-10)."""
        return round(cvss * (1 + epss), 1)

    @staticmethod
    def score_in_range(score: float, severity: str) -> bool:
        lo, hi = SEVERITY_MAP.get(severity.upper(), (0.0, 10.0))
        return lo <= score <= hi