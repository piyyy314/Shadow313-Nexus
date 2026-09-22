"""
shadow313.demo.roi_calculator
───────────────────────────────
ROI Calculator — demonstrates Shadow313 NEXUS business value.

Calculates return on investment based on:
  - Mean time to detect (MTTD) improvement
  - Mean time to respond (MTTR) improvement
  - Breach cost avoidance
  - Compliance penalty avoidance
  - Analyst time savings

Based on IBM Cost of a Data Breach Report 2024 and Ponemon Institute data.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ROIInputs:
    """Input parameters for ROI calculation."""
    # Organization profile
    employees:          int   = 1000
    annual_revenue_usd: float = 100_000_000.0
    industry:           str   = "financial"   # financial | healthcare | defense | tech | retail

    # Current state (without Shadow313)
    current_mttd_days:  float = 197.0   # IBM 2024: 197 days average
    current_mttr_days:  float = 70.0    # IBM 2024: 70 days average
    incidents_per_year: int   = 3
    analysts_fte:       float = 2.0     # Security analysts

    # Shadow313 improvements
    shadow313_mttd_days: float = 2.0    # Near-real-time detection
    shadow313_mttr_days: float = 4.0    # Automated response
    shadow313_license_usd: float = 50_000.0  # Annual license

    # Compliance
    compliance_frameworks: list[str] = field(default_factory=lambda: ["SOC2", "ISO27001"])


@dataclass
class ROIResult:
    """ROI calculation result."""
    inputs:             ROIInputs
    breach_cost_avoided: float
    compliance_savings:  float
    analyst_savings:     float
    total_benefit:       float
    total_cost:          float
    net_benefit:         float
    roi_pct:             float
    payback_months:      float
    mttd_improvement_pct: float
    mttr_improvement_pct: float


# Industry breach cost multipliers (IBM 2024 data)
_INDUSTRY_BREACH_COST = {
    "financial":  5_900_000.0,
    "healthcare": 9_800_000.0,
    "defense":    8_200_000.0,
    "tech":       4_900_000.0,
    "retail":     3_200_000.0,
    "default":    4_450_000.0,
}

# Compliance penalty ranges by framework
_COMPLIANCE_PENALTIES = {
    "GDPR":     {"min": 100_000, "max": 20_000_000},
    "HIPAA":    {"min": 100,     "max": 1_900_000},
    "PCI-DSS":  {"min": 5_000,   "max": 100_000},
    "SOC2":     {"min": 0,       "max": 500_000},
    "ISO27001": {"min": 0,       "max": 200_000},
    "NIST":     {"min": 0,       "max": 100_000},
}

# Analyst hourly rate
_ANALYST_HOURLY_RATE = 85.0  # USD


class ROICalculator:
    """
    Shadow313 NEXUS ROI Calculator.

    Calculates financial return on investment based on:
      1. Breach cost avoidance (faster detection = smaller breach)
      2. Compliance penalty avoidance
      3. Analyst time savings (automation)
    """

    def calculate(self, inputs: ROIInputs) -> ROIResult:
        """Calculate ROI for Shadow313 NEXUS deployment."""

        # ── Breach cost avoidance ─────────────────────────────────────────────
        base_breach_cost = _INDUSTRY_BREACH_COST.get(
            inputs.industry, _INDUSTRY_BREACH_COST["default"]
        )

        # IBM 2024: each day of dwell time adds ~$1,200 to breach cost
        dwell_cost_per_day = 1_200.0
        current_dwell  = inputs.current_mttd_days + inputs.current_mttr_days
        shadow_dwell   = inputs.shadow313_mttd_days + inputs.shadow313_mttr_days
        dwell_reduction = current_dwell - shadow_dwell

        breach_cost_reduction_pct = min(0.60, dwell_reduction * dwell_cost_per_day / base_breach_cost)
        breach_cost_avoided = (
            base_breach_cost * breach_cost_reduction_pct * inputs.incidents_per_year
        )

        # ── Compliance savings ────────────────────────────────────────────────
        compliance_savings = 0.0
        for framework in inputs.compliance_frameworks:
            penalty = _COMPLIANCE_PENALTIES.get(framework, {"min": 0, "max": 0})
            # Shadow313 reduces penalty risk by ~40% through better audit trails
            avg_penalty = (penalty["min"] + penalty["max"]) / 2
            compliance_savings += avg_penalty * 0.40 * 0.3  # 30% probability of incident

        # ── Analyst time savings ──────────────────────────────────────────────
        # Shadow313 automates ~60% of tier-1 alert triage
        hours_per_analyst_year = 2080.0
        automation_pct         = 0.60
        analyst_savings = (
            inputs.analysts_fte * hours_per_analyst_year *
            automation_pct * _ANALYST_HOURLY_RATE
        )

        # ── ROI calculation ───────────────────────────────────────────────────
        total_benefit = breach_cost_avoided + compliance_savings + analyst_savings
        total_cost    = inputs.shadow313_license_usd
        net_benefit   = total_benefit - total_cost
        roi_pct       = (net_benefit / total_cost * 100) if total_cost > 0 else 0.0
        payback_months = (total_cost / (total_benefit / 12)) if total_benefit > 0 else 999.0

        mttd_improvement = ((inputs.current_mttd_days - inputs.shadow313_mttd_days) /
                            inputs.current_mttd_days * 100)
        mttr_improvement = ((inputs.current_mttr_days - inputs.shadow313_mttr_days) /
                            inputs.current_mttr_days * 100)

        return ROIResult(
            inputs               = inputs,
            breach_cost_avoided  = round(breach_cost_avoided, 2),
            compliance_savings   = round(compliance_savings, 2),
            analyst_savings      = round(analyst_savings, 2),
            total_benefit        = round(total_benefit, 2),
            total_cost           = round(total_cost, 2),
            net_benefit          = round(net_benefit, 2),
            roi_pct              = round(roi_pct, 1),
            payback_months       = round(payback_months, 1),
            mttd_improvement_pct = round(mttd_improvement, 1),
            mttr_improvement_pct = round(mttr_improvement, 1),
        )

    def format_report(self, result: ROIResult) -> str:
        """Format ROI result as a human-readable report."""
        r = result
        lines = [
            "=" * 60,
            "  Shadow313 NEXUS — ROI Analysis",
            "=" * 60,
            f"  Organization:    {r.inputs.employees:,} employees, {r.inputs.industry} sector",
            f"  Annual Revenue:  ${r.inputs.annual_revenue_usd:,.0f}",
            "",
            "  Detection Improvement:",
            f"    MTTD: {r.inputs.current_mttd_days:.0f} days → {r.inputs.shadow313_mttd_days:.0f} days ({r.mttd_improvement_pct:.0f}% faster)",
            f"    MTTR: {r.inputs.current_mttr_days:.0f} days → {r.inputs.shadow313_mttr_days:.0f} days ({r.mttr_improvement_pct:.0f}% faster)",
            "",
            "  Financial Benefits:",
            f"    Breach cost avoided:   ${r.breach_cost_avoided:>12,.0f}",
            f"    Compliance savings:    ${r.compliance_savings:>12,.0f}",
            f"    Analyst time savings:  ${r.analyst_savings:>12,.0f}",
            f"    ─────────────────────────────────────",
            f"    Total annual benefit:  ${r.total_benefit:>12,.0f}",
            f"    Shadow313 license:     ${r.total_cost:>12,.0f}",
            f"    Net benefit:           ${r.net_benefit:>12,.0f}",
            "",
            f"  ROI:             {r.roi_pct:.0f}%",
            f"  Payback period:  {r.payback_months:.1f} months",
            "=" * 60,
        ]
        return "\n".join(lines)