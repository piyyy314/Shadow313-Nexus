"""
shadow313.v3.bridge.extended_c2_correlator
────────────────────────────────────────────
ExtendedC2Correlator — multi-signal C2 infrastructure correlation engine.

Extends c2_attribution_analysis.py with:
  - CDN detection and confidence downgrade
  - URI normalization library (CS malleable profiles, Sliver, Brute Ratel)
  - Hierarchical clustering (JA3 → URI → beacon period → cert)
  - Confidence adjustment rules
  - LSTM feature dimensions 28-29 (cdn_cert_flag, uri_c2_specificity)

Implements the recommendations from Part 6 of c2_attribution_analysis.py.
"""
from __future__ import annotations

import re
import statistics
from dataclasses import dataclass, field
from typing import Optional

from .c2_attribution_analysis import (
    C2Host, CorrelationResult,
    correlate_tls_cert, correlate_uri, correlate_ja3,
    correlate_beacon_period, correlate_multi_indicator,
    _normalise_uri, _CDN_CERTS, _CDN_SUBNETS, _KNOWN_JA3,
)


# ── Known C2 URI pattern library ─────────────────────────────────────────────

_C2_URI_LIBRARY = {
    r"/jquery-\d+\.\d+\.\d+\.min\.js":  ("Cobalt Strike", "jQuery malleable profile", 0.95),
    r"/api/v\d+/update":                 ("Sliver",         "default update endpoint",  0.90),
    r"/api/v\d+/health":                 ("Brute Ratel",    "default health endpoint",  0.90),
    r"/\w+\.php\?id=\d+":               ("Metasploit",     "Meterpreter PHP stager",   0.85),
    r"/updates/\w+\.cab":               ("Cobalt Strike",  "Windows Update profile",   0.88),
    r"/pixel\.gif":                      ("Cobalt Strike",  "pixel beacon profile",     0.80),
    r"/submit\.php":                     ("Cobalt Strike",  "submit profile",           0.75),
    r"/en_US/all\.js":                   ("Cobalt Strike",  "jQuery all.js profile",    0.82),
    r"/g\.pixel":                        ("Cobalt Strike",  "Google pixel profile",     0.78),
    r"/api/v\d+/tasks":                  ("Sliver",         "task polling endpoint",    0.88),
}


def classify_uri(uri: str) -> dict:
    """
    Classify a URI against the known C2 pattern library.
    Returns framework attribution and specificity score.
    Matches against the original URI (patterns use \\d+, not N).
    """
    for pattern, (framework, profile, score) in _C2_URI_LIBRARY.items():
        if re.search(pattern, uri):
            return {
                "framework":    framework,
                "profile":      profile,
                "specificity":  score,
                "matched":      True,
                "pattern":      pattern,
            }
    return {"framework": "Unknown", "specificity": 0.0, "matched": False}


def is_cdn_cert(cert: str) -> bool:
    """Check if a TLS certificate belongs to a CDN."""
    return cert in _CDN_CERTS or any(cdn in cert for cdn in ["cloudflare", "fastly", "akamai", "cloudfront"])


def is_cdn_subnet(subnet: str) -> bool:
    """Check if a subnet belongs to a CDN."""
    return any(subnet.startswith(cdn) for cdn in _CDN_SUBNETS)


# ── Extended correlation ──────────────────────────────────────────────────────

@dataclass
class ExtendedCorrelationResult:
    """Extended correlation result with CDN awareness and confidence adjustment."""
    host_a:             str
    host_b:             str
    matched:            bool
    confidence:         float
    primary_signal:     str
    signals:            dict = field(default_factory=dict)
    cdn_flag:           bool = False
    uri_specificity:    float = 0.0
    framework_a:        str = ""
    framework_b:        str = ""
    flags:              list[str] = field(default_factory=list)

    # LSTM feature dimensions 28-29
    @property
    def dim28_cdn_cert_flag(self) -> float:
        return 1.0 if self.cdn_flag else 0.0

    @property
    def dim29_uri_c2_specificity(self) -> float:
        return self.uri_specificity


class ExtendedC2Correlator:
    """
    Multi-signal C2 correlator with CDN awareness.

    Implements the recommendations from c2_attribution_analysis.py Part 6:
      1. CDN detection — downgrade cert confidence to 0.10 for CDN certs
      2. URI normalization — strip version numbers, match against C2 library
      3. Hierarchical clustering — JA3 → URI → beacon period → cert
      4. Confidence adjustment rules
      5. LSTM feature dimensions 28-29
    """

    # Confidence adjustment multipliers
    CDN_CERT_MULTIPLIER    = 0.15   # Severe downgrade for CDN cert match
    URI_C2_MATCH_BOOST     = 1.30   # Upgrade for known C2 URI pattern
    JA3_KNOWN_BOOST        = 1.25   # Upgrade for known implant JA3
    MULTI_SIGNAL_THRESHOLD = 2      # Minimum non-CDN signals to declare match

    def correlate(self, a: C2Host, b: C2Host) -> ExtendedCorrelationResult:
        """
        Correlate two hosts using all available signals with CDN awareness.
        """
        signals = {}

        # ── Collect raw signals ───────────────────────────────────────────────
        cert_r   = correlate_tls_cert(a, b)
        uri_r    = correlate_uri(a, b)
        ja3_r    = correlate_ja3(a, b)
        period_r = correlate_beacon_period(a, b)
        multi_r  = correlate_multi_indicator(a, b)

        signals["tls_cert"]      = cert_r
        signals["uri_pattern"]   = uri_r
        signals["ja3"]           = ja3_r
        signals["beacon_period"] = period_r
        signals["multi"]         = multi_r

        # ── CDN detection ─────────────────────────────────────────────────────
        cdn_flag = is_cdn_cert(a.tls_cert) or is_cdn_cert(b.tls_cert)

        # ── URI classification ────────────────────────────────────────────────
        uri_class_a = classify_uri(a.uri_pattern)
        uri_class_b = classify_uri(b.uri_pattern)
        uri_specificity = max(uri_class_a["specificity"], uri_class_b["specificity"])

        # ── Confidence calculation ────────────────────────────────────────────
        # Start with multi-indicator as base
        base_confidence = multi_r.confidence

        # Apply CDN downgrade if cert was the primary match signal
        if cdn_flag and cert_r.matched and not uri_r.matched and not ja3_r.matched:
            base_confidence *= self.CDN_CERT_MULTIPLIER
            flags = ["cdn_infrastructure_overlap"]
        else:
            flags = []

        # Apply URI boost for known C2 patterns
        if uri_r.matched and uri_specificity > 0.7:
            base_confidence = min(1.0, base_confidence * self.URI_C2_MATCH_BOOST)
            flags.append(f"known_c2_uri:{uri_class_a.get('framework', 'Unknown')}")

        # Apply JA3 boost for known implants
        if ja3_r.matched and a.ja3 in _KNOWN_JA3:
            base_confidence = min(1.0, base_confidence * self.JA3_KNOWN_BOOST)
            flags.append(f"known_implant:{_KNOWN_JA3[a.ja3]}")

        # Count non-CDN matching signals
        non_cdn_matches = sum([
            uri_r.matched,
            ja3_r.matched,
            period_r.matched,
            cert_r.matched and not cdn_flag,
        ])
        matched = non_cdn_matches >= self.MULTI_SIGNAL_THRESHOLD

        # Determine primary signal
        if ja3_r.matched:
            primary = "ja3"
        elif uri_r.matched:
            primary = "uri_pattern"
        elif period_r.matched:
            primary = "beacon_period"
        elif cert_r.matched and not cdn_flag:
            primary = "tls_cert_dedicated"
        else:
            primary = "none"

        return ExtendedCorrelationResult(
            host_a          = a.ip,
            host_b          = b.ip,
            matched         = matched,
            confidence      = round(base_confidence, 3),
            primary_signal  = primary,
            signals         = {k: {"matched": v.matched, "confidence": v.confidence}
                               for k, v in signals.items()},
            cdn_flag        = cdn_flag,
            uri_specificity = round(uri_specificity, 3),
            framework_a     = uri_class_a.get("framework", ""),
            framework_b     = uri_class_b.get("framework", ""),
            flags           = flags,
        )

    def cluster(self, hosts: list[C2Host]) -> list[list[C2Host]]:
        """
        Hierarchical clustering: JA3 → URI → beacon period → cert.
        Returns list of clusters (each cluster is a list of C2Host).
        """
        c2_hosts = [h for h in hosts if h.is_c2]

        # Phase 1: Group by JA3 (implant family)
        ja3_groups: dict[str, list[C2Host]] = {}
        for h in c2_hosts:
            ja3_groups.setdefault(h.ja3, []).append(h)

        # Phase 2: Sub-group by normalised URI within each JA3 group
        clusters = []
        for ja3, group in ja3_groups.items():
            uri_subgroups: dict[str, list[C2Host]] = {}
            for h in group:
                norm_uri = _normalise_uri(h.uri_pattern)
                uri_subgroups.setdefault(norm_uri, []).append(h)
            clusters.extend(uri_subgroups.values())

        return clusters

    def get_lstm_features(self, a: C2Host, b: C2Host) -> list[float]:
        """
        Return LSTM feature vector dimensions 28-29 for a host pair.
        dim[28]: cdn_cert_flag      (1.0 if cert is CDN cert)
        dim[29]: uri_c2_specificity (0=generic, 1=known C2 pattern)
        """
        result = self.correlate(a, b)
        return [result.dim28_cdn_cert_flag, result.dim29_uri_c2_specificity]