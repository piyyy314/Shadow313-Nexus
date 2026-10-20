"""Spoof Tracer - Python port of SatExpert313 SpoofTracer.tsx"""
from __future__ import annotations
import math
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class SpoofAnalysis:
    verdict: str; confidence: float; indicators: list
    hdop: float; satellites: int
    temporal_anomaly: bool; dop_anomaly: bool; constellation_anomaly: bool

class SpoofTracer:
    HDOP_THRESHOLD = 1.5; MIN_SATELLITES = 8
    def analyze_nmea(self, hdop: float, pdop: float, vdop: float,
                     satellites: int, speed_knots: float, fix_quality: int,
                     date_str: Optional[str] = None) -> SpoofAnalysis:
        indicators = []; confidence = 0.0
        dop_anomaly = hdop < self.HDOP_THRESHOLD
        if dop_anomaly:
            indicators.append(f"HDOP {hdop} suspiciously clean"); confidence += 0.25
        if abs(math.sqrt(hdop**2 + vdop**2) - pdop) < 0.01:
            indicators.append("DOP mathematically perfect - suggests calculator not RF"); confidence += 0.30
        constellation_anomaly = satellites < self.MIN_SATELLITES
        if constellation_anomaly:
            indicators.append(f"Only {satellites} satellites visible"); confidence += 0.20
        temporal_anomaly = False
        if date_str:
            try:
                from datetime import date
                d,m,y = int(date_str[:2]),int(date_str[2:4]),2000+int(date_str[4:6])
                if date(y,m,d) > date.today():
                    temporal_anomaly = True
                    indicators.append("Future date detected - confirms synthetic signal"); confidence += 0.40
            except Exception: pass
        confidence = min(confidence, 1.0)
        verdict = "SPOOFED" if confidence >= 0.6 else "SUSPICIOUS" if confidence >= 0.3 else "AUTHENTIC"
        return SpoofAnalysis(verdict, round(confidence,2), indicators, hdop, satellites,
                             temporal_anomaly, dop_anomaly, constellation_anomaly)
