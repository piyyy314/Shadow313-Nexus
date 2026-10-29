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
        """Classify scores at cutoffs 9, 7, 4, and greater than zero; otherwise return NONE."""
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
        """Adjust CVSS with contextual factors and round to one decimal place.

        KEV forces 10. Otherwise exploit availability multiplies by 1.3 and
        internet exposure by 1.1, each capped at 10. Inputs are not validated.
        """
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
        """Return CVSS × (1 + EPSS), rounded to one decimal without a cap or input validation."""
        return round(cvss * (1 + epss), 1)

    @staticmethod
    def score_in_range(score: float, severity: str) -> bool:
        """Check inclusive severity bounds, defaulting unknown labels to the range 0 through 10."""
        lo, hi = SEVERITY_MAP.get(severity.upper(), (0.0, 10.0))
        return lo <= score <= hi