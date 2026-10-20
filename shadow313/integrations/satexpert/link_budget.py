"""Link Budget Calculator - Python port of SatExpert313 LinkBudgetCalculator.tsx"""
from __future__ import annotations
import math
from dataclasses import dataclass

@dataclass
class LinkBudgetResult:
    fspl_db: float; eb_no_db: float; g_t_db: float; ber: float
    snr_db: float; link_margin_db: float; advisory: str; status: str

class LinkBudgetCalculator:
    SPEED_OF_LIGHT = 3e8
    def calculate(self, frequency_ghz: float, distance_km: float,
                  tx_power_dbw: float, antenna_diameter_m: float,
                  antenna_efficiency: float = 0.65, noise_figure_db: float = 0.8,
                  threshold_snr_db: float = 8.0) -> LinkBudgetResult:
        fspl_db = 20*math.log10(distance_km*1000) + 20*math.log10(frequency_ghz*1e9) - 147.55
        wavelength = self.SPEED_OF_LIGHT / (frequency_ghz * 1e9)
        area = math.pi * (antenna_diameter_m / 2) ** 2
        gain_linear = antenna_efficiency * (4 * math.pi * area) / (wavelength ** 2)
        gain_db = 10 * math.log10(gain_linear)
        t_sky = 28.5; t_lnb = 10**(noise_figure_db/10 - 1) * 290
        t_sys = t_sky + t_lnb; g_t_db = gain_db - 10*math.log10(t_sys)
        eirp_db = tx_power_dbw + gain_db; rx_power_dbw = eirp_db - fspl_db + gain_db
        c_n0_db = rx_power_dbw - (-228.6) - 10*math.log10(t_sys)
        snr_db = c_n0_db - 10*math.log10(36e6)
        eb_no_db = snr_db + 10*math.log10(1.5)
        ber = 0.5 * math.erfc(math.sqrt(10**(eb_no_db/10)))
        link_margin_db = snr_db - threshold_snr_db
        if link_margin_db >= 6: status, advisory = "NOMINAL", "Link meets mission criteria."
        elif link_margin_db >= 2: status, advisory = "DEGRADED", "Link margin below 6 dB."
        else: status, advisory = "CRITICAL", f"Link margin {link_margin_db:.1f} dB - CRITICAL."
        return LinkBudgetResult(round(fspl_db,2), round(eb_no_db,2), round(g_t_db,2),
                                ber, round(snr_db,2), round(link_margin_db,2), advisory, status)
