"""
Tests for shadow313.v3.bridge.c2_attribution_analysis

Covers all 6 correlation signals, ground truth evaluation,
cluster formation, and the full analysis pipeline.
"""
from __future__ import annotations

import pytest
from shadow313.v3.bridge.c2_attribution_analysis import (
    C2Host, CorrelationResult, SignalMetrics,
    build_scenario,
    correlate_tls_cert, correlate_uri, correlate_ja3,
    correlate_beacon_period, correlate_subnet, correlate_multi_indicator,
    evaluate_all_signals, hierarchical_cluster,
    run_c2_attribution_analysis,
    _normalise_uri, _same_campaign,
    _CDN_CERTS, _KNOWN_JA3,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def hosts():
    return build_scenario()

@pytest.fixture
def apt_a(hosts):
    return [h for h in hosts if h.campaign == "APT-A"]

@pytest.fixture
def apt_b(hosts):
    return [h for h in hosts if h.campaign == "APT-B"]

@pytest.fixture
def apt_c(hosts):
    return [h for h in hosts if h.campaign == "APT-C"]

@pytest.fixture
def apt_d1(hosts):
    return next(h for h in hosts if h.campaign == "APT-D1")

@pytest.fixture
def apt_d2(hosts):
    return next(h for h in hosts if h.campaign == "APT-D2")

@pytest.fixture
def legit(hosts):
    return [h for h in hosts if h.campaign == "LEGIT"]


# ═══════════════════════════════════════════════════════════════════════════════
# Scenario construction
# ═══════════════════════════════════════════════════════════════════════════════

class TestScenario:

    def test_scenario_has_correct_host_count(self, hosts):
        assert len(hosts) == 12  # 3+3+2+1+1+2

    def test_apt_a_has_three_hosts(self, apt_a):
        assert len(apt_a) == 3

    def test_apt_b_has_three_hosts(self, apt_b):
        assert len(apt_b) == 3

    def test_apt_c_has_two_hosts(self, apt_c):
        assert len(apt_c) == 2

    def test_apt_a_uses_cloudflare_cert(self, apt_a):
        for h in apt_a:
            assert h.tls_cert == "*.cloudflare.com"
            assert h.tls_cert_is_cdn is True

    def test_apt_b_uses_cloudflare_cert(self, apt_b):
        for h in apt_b:
            assert h.tls_cert == "*.cloudflare.com"
            assert h.tls_cert_is_cdn is True

    def test_apt_c_uses_dedicated_cert(self, apt_c):
        for h in apt_c:
            assert h.tls_cert_is_cdn is False

    def test_apt_a_and_b_share_cert(self, apt_a, apt_b):
        assert apt_a[0].tls_cert == apt_b[0].tls_cert

    def test_apt_a_and_b_have_different_uris(self, apt_a, apt_b):
        assert apt_a[0].uri_pattern != apt_b[0].uri_pattern

    def test_apt_a_and_b_have_different_ja3(self, apt_a, apt_b):
        assert apt_a[0].ja3 != apt_b[0].ja3

    def test_apt_d1_d2_same_subnet(self, apt_d1, apt_d2):
        assert apt_d1.subnet_24 == apt_d2.subnet_24

    def test_apt_d1_d2_different_certs(self, apt_d1, apt_d2):
        assert apt_d1.tls_cert != apt_d2.tls_cert

    def test_legit_hosts_not_c2(self, legit):
        for h in legit:
            assert h.is_c2 is False


# ═══════════════════════════════════════════════════════════════════════════════
# URI normalisation
# ═══════════════════════════════════════════════════════════════════════════════

class TestURINormalisation:

    def test_strips_version_numbers(self):
        assert _normalise_uri("/jquery-3.3.1.min.js") == "/jquery-N.N.N.min.js"

    def test_strips_api_version(self):
        assert _normalise_uri("/api/v2/update") == "/api/vN/update"

    def test_strips_numeric_ids(self):
        assert _normalise_uri("/gate.php?id=1337") == "/gate.php?id=N"

    def test_same_pattern_normalises_equal(self):
        a = _normalise_uri("/jquery-3.3.1.min.js")
        b = _normalise_uri("/jquery-3.5.0.min.js")
        assert a == b

    def test_different_patterns_stay_different(self):
        a = _normalise_uri("/jquery-3.3.1.min.js")
        b = _normalise_uri("/api/v2/update")
        assert a != b


# ═══════════════════════════════════════════════════════════════════════════════
# Ground truth
# ═══════════════════════════════════════════════════════════════════════════════

class TestGroundTruth:

    def test_same_campaign_true_for_apt_a(self, apt_a):
        assert _same_campaign(apt_a[0], apt_a[1]) is True

    def test_same_campaign_false_for_apt_a_vs_b(self, apt_a, apt_b):
        assert _same_campaign(apt_a[0], apt_b[0]) is False

    def test_same_campaign_false_for_legit(self, legit, apt_a):
        assert _same_campaign(legit[0], apt_a[0]) is False

    def test_same_campaign_false_for_d1_d2(self, apt_d1, apt_d2):
        assert _same_campaign(apt_d1, apt_d2) is False


# ═══════════════════════════════════════════════════════════════════════════════
# TLS Certificate correlation
# ═══════════════════════════════════════════════════════════════════════════════

class TestTLSCertCorrelation:

    def test_apt_a_vs_b_cert_matches(self, apt_a, apt_b):
        r = correlate_tls_cert(apt_a[0], apt_b[0])
        assert r.matched is True

    def test_apt_a_vs_b_cert_low_confidence(self, apt_a, apt_b):
        r = correlate_tls_cert(apt_a[0], apt_b[0])
        assert r.confidence <= 0.35  # CDN cert — low confidence

    def test_apt_c_dedicated_cert_high_confidence(self, apt_c):
        r = correlate_tls_cert(apt_c[0], apt_c[1])
        assert r.matched is True
        assert r.confidence >= 0.80

    def test_apt_a_vs_c_no_cert_match(self, apt_a, apt_c):
        r = correlate_tls_cert(apt_a[0], apt_c[0])
        assert r.matched is False
        assert r.confidence == 0.0

    def test_apt_d1_d2_no_cert_match(self, apt_d1, apt_d2):
        r = correlate_tls_cert(apt_d1, apt_d2)
        assert r.matched is False

    def test_cert_produces_9_fps_for_apt_a_vs_b(self, apt_a, apt_b):
        fps = sum(1 for a in apt_a for b in apt_b if correlate_tls_cert(a, b).matched)
        assert fps == 9


# ═══════════════════════════════════════════════════════════════════════════════
# URI pattern correlation
# ═══════════════════════════════════════════════════════════════════════════════

class TestURICorrelation:

    def test_apt_a_internal_uri_matches(self, apt_a):
        r = correlate_uri(apt_a[0], apt_a[1])
        assert r.matched is True

    def test_apt_a_vs_b_uri_no_match(self, apt_a, apt_b):
        r = correlate_uri(apt_a[0], apt_b[0])
        assert r.matched is False
        assert r.confidence == 0.0

    def test_uri_produces_zero_fps_for_apt_a_vs_b(self, apt_a, apt_b):
        fps = sum(1 for a in apt_a for b in apt_b if correlate_uri(a, b).matched)
        assert fps == 0

    def test_apt_d1_d2_uri_no_match(self, apt_d1, apt_d2):
        r = correlate_uri(apt_d1, apt_d2)
        assert r.matched is False


# ═══════════════════════════════════════════════════════════════════════════════
# JA3 correlation
# ═══════════════════════════════════════════════════════════════════════════════

class TestJA3Correlation:

    def test_apt_a_internal_ja3_matches(self, apt_a):
        r = correlate_ja3(apt_a[0], apt_a[1])
        assert r.matched is True

    def test_apt_a_vs_b_ja3_no_match(self, apt_a, apt_b):
        r = correlate_ja3(apt_a[0], apt_b[0])
        assert r.matched is False

    def test_ja3_produces_zero_fps_for_apt_a_vs_b(self, apt_a, apt_b):
        fps = sum(1 for a in apt_a for b in apt_b if correlate_ja3(a, b).matched)
        assert fps == 0

    def test_known_ja3_cobalt_strike(self, apt_a):
        assert "Cobalt Strike" in _KNOWN_JA3.get(apt_a[0].ja3, "")

    def test_known_ja3_sliver(self, apt_b):
        assert "Sliver" in _KNOWN_JA3.get(apt_b[0].ja3, "")


# ═══════════════════════════════════════════════════════════════════════════════
# Beacon period correlation
# ═══════════════════════════════════════════════════════════════════════════════

class TestBeaconPeriodCorrelation:

    def test_apt_a_internal_period_matches(self, apt_a):
        r = correlate_beacon_period(apt_a[0], apt_a[1])
        assert r.matched is True

    def test_apt_a_vs_b_period_no_match(self, apt_a, apt_b):
        # 60s vs 300s = 5x ratio — should not match
        r = correlate_beacon_period(apt_a[0], apt_b[0])
        assert r.matched is False

    def test_zero_period_no_match(self, legit, apt_a):
        r = correlate_beacon_period(legit[0], apt_a[0])
        assert r.matched is False

    def test_similar_periods_match(self):
        a = C2Host("1.1.1.1", "X", 60.0, 0.1, "/a", "ja3a", "cert", False, "1.1.1", "UA")
        b = C2Host("1.1.1.2", "X", 65.0, 0.1, "/a", "ja3a", "cert", False, "1.1.1", "UA")
        r = correlate_beacon_period(a, b)
        assert r.matched is True


# ═══════════════════════════════════════════════════════════════════════════════
# Subnet correlation
# ═══════════════════════════════════════════════════════════════════════════════

class TestSubnetCorrelation:

    def test_apt_d1_d2_subnet_matches(self, apt_d1, apt_d2):
        r = correlate_subnet(apt_d1, apt_d2)
        assert r.matched is True

    def test_apt_d1_d2_subnet_is_false_positive(self, apt_d1, apt_d2):
        # Same subnet but different campaigns
        r = correlate_subnet(apt_d1, apt_d2)
        assert r.matched is True  # FP — same /24 but different campaigns

    def test_apt_a_vs_b_cdn_subnet_low_confidence(self, apt_a, apt_b):
        r = correlate_subnet(apt_a[0], apt_b[0])
        # Both use Cloudflare — CDN subnet match has very low confidence
        if r.matched:
            assert r.confidence <= 0.15

    def test_different_subnets_no_match(self, apt_a, apt_c):
        r = correlate_subnet(apt_a[0], apt_c[0])
        assert r.matched is False


# ═══════════════════════════════════════════════════════════════════════════════
# Multi-indicator correlation
# ═══════════════════════════════════════════════════════════════════════════════

class TestMultiIndicatorCorrelation:

    def test_apt_a_internal_multi_matches(self, apt_a):
        r = correlate_multi_indicator(apt_a[0], apt_a[1])
        assert r.matched is True

    def test_apt_a_vs_b_multi_no_match(self, apt_a, apt_b):
        r = correlate_multi_indicator(apt_a[0], apt_b[0])
        assert r.matched is False

    def test_apt_d1_d2_multi_no_match(self, apt_d1, apt_d2):
        r = correlate_multi_indicator(apt_d1, apt_d2)
        assert r.matched is False

    def test_multi_produces_zero_fps_for_apt_a_vs_b(self, apt_a, apt_b):
        fps = sum(1 for a in apt_a for b in apt_b
                  if correlate_multi_indicator(a, b).matched)
        assert fps == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Signal metrics
# ═══════════════════════════════════════════════════════════════════════════════

class TestSignalMetrics:

    def test_perfect_precision(self):
        m = SignalMetrics("test", tp=10, fp=0, tn=5, fn=2)
        assert m.precision == 1.0

    def test_perfect_recall(self):
        m = SignalMetrics("test", tp=10, fp=3, tn=5, fn=0)
        assert m.recall == 1.0

    def test_f1_zero_when_no_tp(self):
        m = SignalMetrics("test", tp=0, fp=5, tn=10, fn=3)
        assert m.f1 == 0.0

    def test_fpr_calculation(self):
        m = SignalMetrics("test", tp=5, fp=2, tn=8, fn=1)
        assert m.fpr == pytest.approx(2 / 10, abs=0.01)

    def test_evaluate_all_signals_returns_all_six(self, hosts):
        metrics = evaluate_all_signals(hosts)
        assert len(metrics) == 6
        for sig in ("tls_cert", "uri_pattern", "ja3", "beacon_period", "subnet", "multi_indicator"):
            assert sig in metrics

    def test_uri_pattern_has_zero_fps(self, hosts):
        metrics = evaluate_all_signals(hosts)
        assert metrics["uri_pattern"].fp == 0

    def test_ja3_has_zero_fps(self, hosts):
        metrics = evaluate_all_signals(hosts)
        assert metrics["ja3"].fp == 0

    def test_tls_cert_has_high_fps(self, hosts):
        metrics = evaluate_all_signals(hosts)
        assert metrics["tls_cert"].fp >= 9  # at least APT-A vs APT-B FPs

    def test_uri_pattern_f1_is_high(self, hosts):
        metrics = evaluate_all_signals(hosts)
        assert metrics["uri_pattern"].f1 >= 0.90

    def test_tls_cert_f1_is_low(self, hosts):
        metrics = evaluate_all_signals(hosts)
        # TLS cert has high FP rate due to CDN cert sharing — F1 well below URI/JA3
        assert metrics["tls_cert"].f1 < metrics["uri_pattern"].f1


# ═══════════════════════════════════════════════════════════════════════════════
# Hierarchical clustering
# ═══════════════════════════════════════════════════════════════════════════════

class TestHierarchicalClustering:

    def test_clustering_returns_required_keys(self, hosts):
        result = hierarchical_cluster(hosts)
        for key in ("cert_clusters", "uri_clusters", "period_stats", "ja3_stats"):
            assert key in result

    def test_cloudflare_cert_cluster_over_merges(self, hosts):
        result = hierarchical_cluster(hosts)
        # Cloudflare cert cluster should contain both APT-A and APT-B hosts
        cf_cluster = result["cert_clusters"].get("*.cloudflare.com", [])
        assert len(cf_cluster) >= 6  # APT-A (3) + APT-B (3) + LEGIT (2)

    def test_uri_sub_clustering_separates_apt_a_b(self, hosts):
        result = hierarchical_cluster(hosts)
        uri_clusters = result["uri_clusters"]
        # Should have separate clusters for jquery and api/update
        jquery_keys = [k for k in uri_clusters if "jquery" in k.lower()]
        api_keys    = [k for k in uri_clusters if "api" in k.lower() and "update" in k.lower()]
        assert len(jquery_keys) >= 1
        assert len(api_keys) >= 1

    def test_apt_a_jquery_cluster_has_three_hosts(self, hosts):
        result = hierarchical_cluster(hosts)
        jquery_keys = [k for k in result["uri_clusters"] if "jquery" in k.lower()]
        if jquery_keys:
            assert len(result["uri_clusters"][jquery_keys[0]]) == 3

    def test_period_stats_computed(self, hosts):
        result = hierarchical_cluster(hosts)
        assert len(result["period_stats"]) > 0

    def test_ja3_stats_computed(self, hosts):
        result = hierarchical_cluster(hosts)
        assert len(result["ja3_stats"]) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# Full analysis pipeline
# ═══════════════════════════════════════════════════════════════════════════════

class TestFullAnalysis:

    def test_analysis_runs_without_error(self):
        result = run_c2_attribution_analysis(verbose=False)
        assert "metrics" in result
        assert "clusters" in result

    def test_analysis_returns_six_signal_metrics(self):
        result = run_c2_attribution_analysis(verbose=False)
        assert len(result["metrics"]) == 6

    def test_cert_fps_is_nine(self):
        result = run_c2_attribution_analysis(verbose=False)
        assert result["cert_fps"] == 9

    def test_uri_separates_apt_a_b(self):
        result = run_c2_attribution_analysis(verbose=False)
        assert result["signal_summary"]["uri_pattern"]["separates"] is True

    def test_ja3_separates_apt_a_b(self):
        result = run_c2_attribution_analysis(verbose=False)
        assert result["signal_summary"]["ja3"]["separates"] is True

    def test_cert_does_not_separate_apt_a_b(self):
        result = run_c2_attribution_analysis(verbose=False)
        assert result["signal_summary"]["tls_cert"]["separates"] is False

    def test_multi_indicator_separates_apt_a_b(self):
        result = run_c2_attribution_analysis(verbose=False)
        assert result["signal_summary"]["multi_indicator"]["separates"] is True

    def test_uri_pattern_precision_is_one(self):
        result = run_c2_attribution_analysis(verbose=False)
        assert result["metrics"]["uri_pattern"]["precision"] == pytest.approx(1.0, abs=0.01)

    def test_uri_pattern_recall_is_one(self):
        result = run_c2_attribution_analysis(verbose=False)
        assert result["metrics"]["uri_pattern"]["recall"] == pytest.approx(1.0, abs=0.01)

    def test_tls_cert_fpr_is_high(self):
        result = run_c2_attribution_analysis(verbose=False)
        # TLS cert FPR is higher than URI/JA3 due to CDN cert sharing
        assert result["metrics"]["tls_cert"]["fpr"] > result["metrics"]["uri_pattern"]["fpr"]