#!/usr/bin/env python3
"""
Shadow313 NEXUS — Comprehensive Red Team Simulation
=====================================================
Full adversarial simulation against NEXUS v3.1 with all CMs active:
  Gen-3 CMs: CM-A through CM-J + CM-BAYES
  Gen-4 Patches: CM-N (change-point), CM-R (weight noise), CM-X (honeypot)

Five adversary profiles:
  TURLA       — Russia/FSB, satellite C2 specialist, stealth=0.96
  VOLTZITE    — China/MSS, VSAT infrastructure, stealth=0.93
  SANDWORM    — Russia/GRU, destructive + jamming, stealth=0.81
  APT40       — China/MSS, maritime/satellite, stealth=0.82
  PHANTOM_RF  — Unknown Gen-4, full CM knowledge, stealth=0.99

For each actor, tests:
  - Individual CM evasion rates
  - Multi-stage attack chains
  - Ensemble bypass attempts
  - End-to-end platform detection rate

Run: python3 red_team_sim.py
"""
from __future__ import annotations
import math, random, statistics, time, json, hashlib
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional

random.seed(0xDEAD3133)

WIDTH = 76

# ─────────────────────────────────────────────────────────────────────────────
# ADVERSARY PROFILES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AdversaryProfile:
    name:           str
    nation:         str
    sophistication: float
    stealth:        float
    adaptability:   float
    cm_knowledge:   float   # 0=none, 1=full knowledge of all CMs
    specialisation: list[str]
    # Gen-4 capabilities
    has_ocj:        bool = False   # Orbital-Coherent Jamming
    has_gan:        bool = False   # Adversarial GAN
    has_btp:        bool = False   # Bayesian Threshold Poisoning
    has_eca:        bool = False   # Ensemble Confusion Attack
    has_cni:        bool = False   # Correlated Noise Injection
    has_pns:        bool = False   # PNS QKD attack
    has_relay:      bool = False   # Sub-100μs relay

ADVERSARIES = {
    "TURLA": AdversaryProfile(
        name="Turla", nation="Russia/FSB",
        sophistication=0.97, stealth=0.96, adaptability=0.94,
        cm_knowledge=0.75,
        specialisation=["dvb_s2_c2","satellite_hijack","passive_collection"],
        has_btp=True, has_gan=False, has_eca=False, has_cni=False,
        has_ocj=False, has_pns=False, has_relay=False,
    ),
    "VOLTZITE": AdversaryProfile(
        name="VOLTZITE", nation="China/MSS",
        sophistication=0.95, stealth=0.93, adaptability=0.96,
        cm_knowledge=0.80,
        specialisation=["vsat_infrastructure","uplink_saturation","firmware_tamper"],
        has_btp=False, has_gan=True, has_eca=True, has_cni=True,
        has_ocj=True, has_pns=False, has_relay=False,
    ),
    "SANDWORM": AdversaryProfile(
        name="Sandworm", nation="Russia/GRU",
        sophistication=0.94, stealth=0.81, adaptability=0.88,
        cm_knowledge=0.65,
        specialisation=["swept_jamming","cw_jamming","destructive"],
        has_btp=False, has_gan=False, has_eca=False, has_cni=False,
        has_ocj=False, has_pns=False, has_relay=False,
    ),
    "APT40": AdversaryProfile(
        name="APT40", nation="China/MSS",
        sophistication=0.89, stealth=0.82, adaptability=0.91,
        cm_knowledge=0.70,
        specialisation=["maritime_vsat","gps_spoofing","uplink_saturation"],
        has_btp=False, has_gan=False, has_eca=False, has_cni=False,
        has_ocj=False, has_pns=False, has_relay=False,
    ),
    "PHANTOM_RF": AdversaryProfile(
        name="PHANTOM_RF", nation="Unknown/Gen4",
        sophistication=0.99, stealth=0.99, adaptability=0.99,
        cm_knowledge=1.00,  # Full knowledge of ALL CMs including patches
        specialisation=["all"],
        has_btp=True, has_gan=True, has_eca=True, has_cni=True,
        has_ocj=True, has_pns=True, has_relay=True,
    ),
}

# ─────────────────────────────────────────────────────────────────────────────
# FULL NEXUS DETECTION ENGINE (all CMs + patches)
# ─────────────────────────────────────────────────────────────────────────────

class FullNexusEngine:
    """
    Complete NEXUS detection engine with all CMs and patches active.
    Stateful — maintains history across calls for temporal detectors.
    """

    def __init__(self):
        # ── CM-BAYES / CM-N state ──────────────────────────────────────────
        self.mu_slow    = 12.4; self.var_slow = 2.25
        self.mu_fast    = 12.4; self.mu_hist  = deque(maxlen=100)
        self.frozen     = False; self.freeze_n = 0
        self.n_samples  = 0

        # ── CM-B multi-scale LSTM ──────────────────────────────────────────
        self.lstm_bufs  = {w: deque(maxlen=w) for w in [10,30,100]}
        self.lstm_thr   = {10:1.15, 30:2.40, 100:3.00}

        # ── CM-A higher-order stats ────────────────────────────────────────
        self.hos_buf    = deque(maxlen=100)

        # ── CM-C multi-site triangulator ──────────────────────────────────
        self.t          = 0.0

        # ── CM-D sawtooth ─────────────────────────────────────────────────
        self.saw_buf    = deque(maxlen=64)

        # ── CM-G cross-terminal ───────────────────────────────────────────
        self.ct_a       = deque(maxlen=100); self.ct_b = deque(maxlen=100)

        # ── CM-H GAN detector ─────────────────────────────────────────────
        self.gan_buf    = deque(maxlen=200); self.gan_iat = deque(maxlen=100)
        self.gan_last_t = None

        # ── CM-X honeypot ─────────────────────────────────────────────────
        self.cmx_iat    = deque(maxlen=32); self.cmx_snr = deque(maxlen=30)

        # ── CM-R session weights ──────────────────────────────────────────
        self.det_count  = 0
        self._refresh_weights()

        # ── Stats ──────────────────────────────────────────────────────────
        self.cm_fire_counts = defaultdict(int)
        self.total_calls    = 0

    def _refresh_weights(self):
        BASE = {"CM-F":4.0,"CM-J":4.0,"CM-E":3.0,"CM-A":2.5,"CM-D":2.5,
                "CM-B":2.0,"CM-H":2.0,"CM-BAYES":1.5,"CM-C":1.0,"CM-G":1.0}
        self.weights   = {k: v*max(0.1,random.gauss(1.0,0.10)) for k,v in BASE.items()}
        self.threshold = 2.5 * max(0.5, random.gauss(1.0, 0.10))

    def _pearson(self, a, b):
        n = min(len(a),len(b))
        if n < 20: return 0.0
        a,b = list(a)[-n:], list(b)[-n:]
        # Fast O(n) inline Pearson
        sa=sb=sa2=sb2=sab=0.0
        for i in range(n):
            sa+=a[i]; sb+=b[i]; sa2+=a[i]*a[i]; sb2+=b[i]*b[i]; sab+=a[i]*b[i]
        num = n*sab - sa*sb
        den = math.sqrt(max((n*sa2-sa*sa)*(n*sb2-sb*sb),1e-18))
        return num/den

    def detect(self, p: dict) -> dict:
        self.t += 0.1; self.total_calls += 1
        self.det_count += 1
        if self.det_count % 50 == 0:
            self._refresh_weights()

        snr         = p.get("snr", 12.4)
        ber         = p.get("ber", 1.2e-6)
        eirp        = p.get("eirp", 43.0)
        packet_rate = p.get("packet_rate", 0.5)
        payload_ent = p.get("payload_entropy", 6.8)
        agc_db      = p.get("agc_db", 0.0)
        rtt_us      = p.get("rtt_us", 28.0)
        snr_b       = p.get("snr_terminal_b", snr + random.gauss(0,0.3))
        doppler_sites = p.get("doppler_sites", None)
        signal_yield  = p.get("signal_yield", 0.80)
        decoy_yield   = p.get("decoy_yield", 0.16)
        signal_qber   = p.get("signal_qber", 0.04)
        decoy_qber    = p.get("decoy_qber", 0.04)
        iat_ms        = p.get("iat_ms", 33.3)

        detections = []
        cm_results = {}

        # ── CM-N: Bayesian change-point ────────────────────────────────────
        self.n_samples += 1
        self.mu_fast = 0.90*self.mu_fast + 0.10*snr
        if not self.frozen:
            self.mu_slow  = 0.98*self.mu_slow  + 0.02*snr
            self.var_slow = 0.98*self.var_slow  + 0.02*(snr-self.mu_slow)**2
        self.mu_hist.append(self.mu_slow)
        sigma = math.sqrt(max(self.var_slow,1e-6))

        cmn_poisoning = False
        if len(self.mu_hist) >= 50:
            shift = abs(list(self.mu_hist)[-1]-list(self.mu_hist)[-50])/sigma
            if shift > 0.97 and not self.frozen:
                self.frozen = True; self.freeze_n = 100
                cmn_poisoning = True
                self.cm_fire_counts["CM-N"] += 1
        if self.frozen:
            self.freeze_n -= 1
            if self.freeze_n <= 0: self.frozen = False

        k = max(1.2, 2.0 - 0.8*min(1.0, self.n_samples/500))
        z = abs(snr - self.mu_slow)/sigma
        if z > k:
            detections.append(("CM-BAYES", min(1.0,z/3.0)))
            self.cm_fire_counts["CM-BAYES"] += 1
        cm_results["CM-N"] = {"poisoning": cmn_poisoning}

        # ── CM-A: Higher-order statistics ──────────────────────────────────
        self.hos_buf.append(snr)
        if len(self.hos_buf) >= 20:
            data = list(self.hos_buf); n=len(data)
            mu = sum(data)/n
            var = sum((x-mu)**2 for x in data)/n or 1e-18
            std = math.sqrt(var)
            kurt = sum((x-mu)**4 for x in data)/(n*var*var)
            skew = sum((x-mu)**3 for x in data)/(n*var*std)
            if abs(kurt-3.0)>1.5 or abs(skew)>0.8:
                conf = min(1.0,abs(kurt-3.0)/3.0+abs(skew)/1.6)
                detections.append(("CM-A",conf))
                self.cm_fire_counts["CM-A"] += 1

        # ── CM-B: Multi-scale LSTM ─────────────────────────────────────────
        for w in [10,30,100]: self.lstm_bufs[w].append(snr)
        wins = 0
        for w in [10,30,100]:
            buf = self.lstm_bufs[w]
            if len(buf) >= w:
                data = list(buf)
                pred = sum(data[:-1])/(len(data)-1)
                mse  = (data[-1]-pred)**2
                if mse > self.lstm_thr[w]: wins += 1
        if wins >= 2:
            detections.append(("CM-B", wins/4))
            self.cm_fire_counts["CM-B"] += 1

        # ── CM-C: Multi-site triangulation ────────────────────────────────
        if doppler_sites is None:
            base = -7.61*math.sin(self.t*2*math.pi/5736)
            err  = p.get("doppler_error",0.0)
            doppler_sites = [base+err+random.gauss(0,0.015),
                             base+err*0.1+random.gauss(0,0.015),
                             base+err*0.1+random.gauss(0,0.015)]
        devs = []
        for i,measured in enumerate(doppler_sites):
            phase = (self.t%5736)/5736*2*math.pi
            pred  = -7.61*math.sin(phase+i*0.002)
            devs.append(abs(measured-pred))
        spread = max(devs)-min(devs)
        sites_anom = sum(1 for d in devs if d>0.10)
        if sites_anom>=2 or (spread>0.5 and sites_anom>=2):
            detections.append(("CM-C",min(1.0,sites_anom/3+spread/1.0)))
            self.cm_fire_counts["CM-C"] += 1

        # ── CM-D: Sawtooth detector ────────────────────────────────────────
        self.saw_buf.append(agc_db)
        if len(self.saw_buf) >= 32:
            data = list(self.saw_buf); n2=len(data); mu2=sum(data)/n2
            var = sum((x-mu2)**2 for x in data)/n2
            diffs = [data[i+1]-data[i] for i in range(len(data)-1)]
            scr   = sum(1 for i in range(len(diffs)-1) if diffs[i]*diffs[i+1]<0)/max(len(diffs),1)
            if var>1.5 or (scr>0.3 and var>0.5):
                detections.append(("CM-D",min(1.0,var/3.0+scr*0.5)))
                self.cm_fire_counts["CM-D"] += 1

        # ── CM-E: Compression ratio ────────────────────────────────────────
        ratio = 1.0+(1.0-payload_ent/8.0)*4.0
        if ratio>4.0 and payload_ent<6.0:
            detections.append(("CM-E",min(1.0,(ratio-4.0)/2.0)))
            self.cm_fire_counts["CM-E"] += 1

        # ── CM-F: Distance bounding ────────────────────────────────────────
        if rtt_us > 43.3:
            detections.append(("CM-F",min(1.0,(rtt_us-43.3)/43.3)))
            self.cm_fire_counts["CM-F"] += 1

        # ── CM-G: Cross-terminal correlation ──────────────────────────────
        self.ct_a.append(snr); self.ct_b.append(snr_b)
        if len(self.ct_a) >= 50:
            corr = self._pearson(self.ct_a, self.ct_b)
            if abs(corr) > 0.80:
                detections.append(("CM-G",min(1.0,abs(corr))))
                self.cm_fire_counts["CM-G"] += 1

        # ── CM-H: GAN detector ─────────────────────────────────────────────
        self.gan_buf.append(snr)
        if self.gan_last_t is not None:
            self.gan_iat.append(self.t-self.gan_last_t)
        self.gan_last_t = self.t
        if len(self.gan_buf) >= 100:
            data = list(self.gan_buf); n=len(data)
            mu = sum(data)/n
            var = sum((x-mu)**2 for x in data)/n or 1e-9
            lag  = 5
            cov  = sum((data[i]-mu)*(data[i-lag]-mu) for i in range(lag,n))/(n-lag)
            ac1  = cov/var
            iat_anom = False
            if len(self.gan_iat) >= 50:
                iat_list = list(self.gan_iat); iat_mu = sum(iat_list)/len(iat_list)
                iat_std  = math.sqrt(sum((x-iat_mu)**2 for x in iat_list)/len(iat_list))
                iat_cv   = iat_std/(iat_mu or 1e-9)
                iat_anom = iat_cv < 0.10
            if ac1 < 0.05 and iat_anom:
                detections.append(("CM-H",min(1.0,(0.05-ac1)/0.05)))
                self.cm_fire_counts["CM-H"] += 1

        # ── CM-J: Decoy-state QKD ──────────────────────────────────────────
        ratio_dev = abs(signal_yield/max(decoy_yield,1e-10)-5.0)/5.0
        qber_dev  = abs(signal_qber-decoy_qber)
        gain_anom = signal_yield>0.95 and decoy_yield<0.3
        if ratio_dev>0.3 or qber_dev>0.05 or gain_anom:
            detections.append(("CM-J",min(1.0,ratio_dev*0.5+qber_dev*5.0)))
            self.cm_fire_counts["CM-J"] += 1

        # ── CM-X: Honeypot (fractal dim + entropy rate) ────────────────────
        self.cmx_iat.append(iat_ms); self.cmx_snr.append(snr)
        cmx_hit = False
        if len(self.cmx_iat) >= 32:
            data = list(self.cmx_iat); n=len(data)
            diffs = [data[i+1]-data[i] for i in range(n-1)]
            nzc   = sum(1 for i in range(len(diffs)-1) if diffs[i]*diffs[i+1]<0)
            if nzc > 0:
                fd = math.log10(n)/(math.log10(n)+math.log10(n/(n+0.4*nzc)))
                if fd<1.048 or fd>1.088: cmx_hit=True
        if len(self.cmx_snr) >= 30:
            data  = list(self.cmx_snr)
            diffs = [data[i+1]-data[i] for i in range(len(data)-1)]
            dv    = sum(d*d for d in diffs)/max(len(diffs)-1,1)
            h     = 0.5*math.log(max(math.pi*math.e*dv,1e-10))
            if h<-0.55 or h>0.25: cmx_hit=True
        if cmx_hit:
            detections.append(("CM-X",0.9))
            self.cm_fire_counts["CM-X"] += 1

        # ── CM-R: Weighted ensemble decision ──────────────────────────────
        detected_cms = {cm for cm,_ in detections}
        HIGH_SPEC    = {"CM-F","CM-J","CM-E","CM-A","CM-D","CM-X"}
        NOISY        = {"CM-C","CM-G"}
        has_high_spec = bool(detected_cms & HIGH_SPEC)
        non_noisy     = detected_cms - NOISY

        primary_score = sum(self.weights.get(cm,1.0)*conf
                           for cm,conf in detections if cm not in NOISY)
        noisy_bonus   = sum(self.weights.get(cm,1.0)*conf*0.3
                           for cm,conf in detections if cm in NOISY)
        eff_score = primary_score + (noisy_bonus if primary_score>1.5 else 0)

        if has_high_spec:
            eff_thr = self.threshold*0.6
        elif len(non_noisy) >= 2:
            eff_thr = self.threshold
        else:
            eff_thr = 99.0

        ensemble_detected = eff_score >= eff_thr or cmn_poisoning

        return {
            "detected":       ensemble_detected,
            "cms_triggered":  [cm for cm,_ in detections],
            "score":          round(eff_score,4),
            "threshold":      round(eff_thr,4),
            "cm_n_poisoning": cmn_poisoning,
            "cm_x_hit":       cmx_hit,
            "n_cms":          len(detections),
        }


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK GENERATORS PER ADVERSARY
# ─────────────────────────────────────────────────────────────────────────────

def _base_params():
    return {
        "snr":12.4,"ber":1.2e-6,"eirp":43.0,"packet_rate":0.5,
        "payload_entropy":6.8,"agc_db":0.0,"rtt_us":28.0,
        "iat_ms":33.3,"doppler_error":0.0,"doppler_sites":None,
        "snr_terminal_b":12.4,"signal_yield":0.80,"decoy_yield":0.16,
        "signal_qber":0.04,"decoy_qber":0.04,
    }

# ── TURLA attack generators ────────────────────────────────────────────────
def turla_dvb_s2_c2(step):
    p = _base_params()
    # DVB-S2 carrier hijack: low entropy, GPS-disciplined carrier
    p["payload_entropy"] = random.gauss(6.4,0.1)
    p["iat_ms"]          = random.gauss(33.3,0.5)  # Exact broadcast timing
    p["snr"]             = random.gauss(12.4,0.3)
    return p

def turla_btp_poisoning(step):
    p = _base_params()
    # Bayesian threshold poisoning: gradual SNR drift
    progress = min(1.0, step/50)
    p["snr"]  = 12.4 - 2.0*progress + random.gauss(0,0.2)
    p["iat_ms"] = random.gauss(33.3,5.0)
    return p

def turla_passive_collection(step):
    p = _base_params()
    # Passive collection: near-legitimate traffic
    p["snr"]             = random.gauss(12.4,0.8)
    p["payload_entropy"] = random.gauss(7.2,0.3)+0.8
    p["signal_qber"]     = random.gauss(0.04,0.005)+0.06
    return p

# ── VOLTZITE attack generators ─────────────────────────────────────────────
def voltzite_ocj(step):
    p = _base_params()
    # Orbital-Coherent Jamming: matches Doppler at site 0
    base = -7.61*math.sin(step*0.001)
    p["doppler_sites"] = [base+random.gauss(0,0.008),
                          base+random.gauss(0.25,0.05),
                          base+random.gauss(0.40,0.05)]
    p["snr"]  = random.gauss(12.4-2.5,0.5)
    p["ber"]  = random.gauss(1.2e-6*20,2e-6)
    return p

def voltzite_gan_mimicry(step):
    p = _base_params()
    # GAN mimicry: correct mean/variance, low autocorrelation
    p["snr"]        = random.gauss(12.4,1.5)
    p["packet_rate"]= 0.033+random.gauss(0,0.001)
    p["iat_ms"]     = random.gauss(33.3,0.5)  # Too regular
    return p

def voltzite_cni(step):
    p = _base_params()
    # Correlated noise injection: matches autocorrelation
    z = random.gauss(0,1)
    if random.random()<0.3: z = z*abs(z)*0.3
    p["snr"]             = 12.4+z*1.5
    p["snr_terminal_b"]  = 12.4+z*0.7+random.gauss(0,0.2)
    return p

def voltzite_uplink_saturation(step):
    p = _base_params()
    # Sawtooth AGC: ramp 0.49 dB/min for 59 steps then drop
    t_cycle = step % 60
    p["agc_db"] = -(t_cycle*0.49/60) if t_cycle<59 else 0.0
    p["eirp"]   = 43.0+abs(p["agc_db"])*0.8
    return p

# ── SANDWORM attack generators ─────────────────────────────────────────────
def sandworm_swept_jamming(step):
    p = _base_params()
    # Swept jamming: frequency-agile, matched polarisation
    p["snr"]  = random.gauss(12.4-3.0,1.5)
    p["ber"]  = random.gauss(1.2e-6*50,1e-6)
    p["eirp"] = random.gauss(43.0,2.0)
    # Doppler spoofing via relay
    base = -7.61*math.sin(step*0.001)
    p["doppler_sites"] = [base+random.gauss(0,0.03),
                          base+random.gauss(0,0.03),
                          base+random.gauss(0,0.03)]
    return p

def sandworm_cw_jamming(step):
    p = _base_params()
    js_db = random.gauss(6,2)
    p["snr"]  = 12.4-js_db*0.4
    p["ber"]  = 1.2e-6*(10**(js_db/10))
    p["eirp"] = random.gauss(43.0,1.5)
    return p

def sandworm_destructive(step):
    p = _base_params()
    # Destructive payload: high BER, abnormal EIRP
    p["snr"]  = random.gauss(8.0,2.0)
    p["ber"]  = random.gauss(1e-3,1e-4)
    p["eirp"] = random.gauss(55.0,3.0)
    return p

# ── APT40 attack generators ────────────────────────────────────────────────
def apt40_gps_spoofing(step):
    p = _base_params()
    # GPS spoofing: timing error
    p["rtt_us"] = random.gauss(85.0,5.0)  # Relay adds latency
    p["snr"]    = random.gauss(12.4,0.5)
    return p

def apt40_uplink_saturation(step):
    p = _base_params()
    # Gradual uplink saturation
    t = step*1.0
    p["agc_db"] = -t*0.05*(1+0.1)
    p["eirp"]   = 43.0+abs(p["agc_db"])*0.8
    return p

def apt40_maritime_vsat(step):
    p = _base_params()
    # Maritime VSAT exploitation: unusual Doppler (ship movement)
    base = -7.61*math.sin(step*0.001)
    p["doppler_sites"] = [base+random.gauss(0.3,0.05),
                          base+random.gauss(0.5,0.05),
                          base+random.gauss(0.7,0.05)]
    p["snr"] = random.gauss(11.0,1.0)
    return p

# ── PHANTOM_RF attack generators (Gen-4, full CM knowledge) ───────────────
def phantom_eca(step):
    p = _base_params()
    # Ensemble Confusion: targets score just below threshold
    # Knows CM-R weights — targets 95% of base threshold
    p["snr"]  = 12.4-1.4*1.5+random.gauss(0,0.05)
    p["rtt_us"] = random.gauss(32.0,0.5)  # Below CM-F threshold
    p["signal_qber"] = random.gauss(0.079,0.002)  # Below CM-J threshold
    p["payload_entropy"] = random.gauss(6.6,0.05)
    p["agc_db"] = random.gauss(0,math.sqrt(1.4))*0.3
    return p

def phantom_temporal_camouflage(step):
    p = _base_params()
    # LSTM gradient attack: SNR = mean(window) + ε
    # Keeps MSE below threshold for all 4 windows
    epsilon = math.sqrt(1.15)*0.85
    direction = -1 if (step%20)<10 else 1
    p["snr"] = 12.4 + direction*epsilon + random.gauss(0,0.05)
    return p

def phantom_quantum_mimicry(step):
    p = _base_params()
    # Beam-splitting QKD attack: maintains yield ratio=5.0
    split = 0.84
    p["signal_yield"] = split*random.gauss(0.80,0.02)
    p["decoy_yield"]  = split*random.gauss(0.16,0.01)
    p["signal_qber"]  = random.gauss(0.072,0.004)
    p["decoy_qber"]   = random.gauss(0.074,0.004)
    return p

def phantom_physics_spoofing(step):
    p = _base_params()
    # Proxy RTT: compromised terminal within 3km
    relay_dist = random.gauss(3.0,0.5)
    p["rtt_us"] = 2*relay_dist/0.3+random.gauss(1.0,0.3)
    return p

def phantom_multi_vector(step):
    p = _base_params()
    # Combines ECA + temporal camouflage + quantum mimicry
    epsilon = math.sqrt(1.15)*0.85
    direction = -1 if (step%20)<10 else 1
    p["snr"]          = 12.4+direction*epsilon+random.gauss(0,0.05)
    p["rtt_us"]       = random.gauss(32.0,0.5)
    p["signal_yield"] = 0.84*random.gauss(0.80,0.02)
    p["decoy_yield"]  = 0.84*random.gauss(0.16,0.01)
    p["signal_qber"]  = random.gauss(0.072,0.004)
    p["decoy_qber"]   = random.gauss(0.074,0.004)
    p["payload_entropy"] = random.gauss(6.6,0.05)
    return p

# ── Attack chain definitions ───────────────────────────────────────────────

ATTACK_CHAINS = {
    "TURLA": [
        ("DVB-S2 C2 Hijack",       turla_dvb_s2_c2,       40),
        ("BTP Baseline Poisoning", turla_btp_poisoning,    40),
        ("Passive Collection",     turla_passive_collection,40),
    ],
    "VOLTZITE": [
        ("Orbital-Coherent Jamming",  voltzite_ocj,              40),
        ("GAN Mimicry Traffic",       voltzite_gan_mimicry,      40),
        ("Correlated Noise Injection",voltzite_cni,              40),
        ("Sawtooth Uplink Saturation",voltzite_uplink_saturation,40),
    ],
    "SANDWORM": [
        ("Swept Jamming",    sandworm_swept_jamming, 40),
        ("CW Jamming",       sandworm_cw_jamming,    40),
        ("Destructive Payload",sandworm_destructive, 40),
    ],
    "APT40": [
        ("GPS Spoofing",         apt40_gps_spoofing,       40),
        ("Uplink Saturation",    apt40_uplink_saturation,  40),
        ("Maritime VSAT Exploit",apt40_maritime_vsat,      40),
    ],
    "PHANTOM_RF": [
        ("Ensemble Confusion Attack",  phantom_eca,               40),
        ("Temporal Camouflage (LSTM)", phantom_temporal_camouflage,40),
        ("Quantum State Mimicry",      phantom_quantum_mimicry,    40),
        ("Physics Spoofing (Proxy)",   phantom_physics_spoofing,   40),
        ("Multi-Vector Combined",      phantom_multi_vector,       40),
    ],
}


# ─────────────────────────────────────────────────────────────────────────────
# RED TEAM SIMULATION RUNNER
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ChainResult:
    actor:          str
    chain_name:     str
    steps:          int
    detected:       int
    evaded:         int
    detection_rate: float
    evasion_rate:   float
    cms_that_fired: dict
    first_detection_step: Optional[int]

def run_red_team(n_trials: int = 150) -> dict:
    """Run full red team simulation for all adversaries."""
    all_results = {}

    for actor_name, chains in ATTACK_CHAINS.items():
        actor = ADVERSARIES[actor_name]
        actor_results = []

        for chain_name, attack_fn, steps_per_trial in chains:
            detected_trials = 0
            evaded_trials   = 0
            cm_fire_totals  = defaultdict(int)
            first_det_steps = []

            for trial in range(n_trials):
                engine = FullNexusEngine()
                trial_detected = False
                first_det_step = None

                for step in range(steps_per_trial):
                    params = attack_fn(step)

                    # Apply stealth modifier: high-stealth actors add noise
                    # to stay within normal bounds
                    if actor.stealth > 0.9:
                        params["snr"] = params["snr"] * (1 + random.gauss(0, 0.02*(1-actor.stealth)))

                    result = engine.detect(params)

                    if result["detected"] and not trial_detected:
                        trial_detected = True
                        first_det_step = step
                        first_det_steps.append(step)

                    for cm in result["cms_triggered"]:
                        cm_fire_totals[cm] += 1

                if trial_detected:
                    detected_trials += 1
                else:
                    evaded_trials += 1

            det_rate = detected_trials / n_trials
            chain_result = ChainResult(
                actor=actor_name,
                chain_name=chain_name,
                steps=steps_per_trial,
                detected=detected_trials,
                evaded=evaded_trials,
                detection_rate=round(det_rate*100, 2),
                evasion_rate=round((1-det_rate)*100, 2),
                cms_that_fired={cm: round(cnt/n_trials*100,1)
                                for cm,cnt in sorted(cm_fire_totals.items(),
                                                     key=lambda x:x[1],reverse=True)[:5]},
                first_detection_step=round(statistics.mean(first_det_steps),1)
                                     if first_det_steps else None,
            )
            actor_results.append(chain_result)

        all_results[actor_name] = actor_results

    return all_results


# ─────────────────────────────────────────────────────────────────────────────
# REPORT
# ─────────────────────────────────────────────────────────────────────────────

def print_report(results: dict, elapsed: float) -> None:
    W = WIDTH
    CYAN="\033[96m"; GREEN="\033[92m"; RED="\033[91m"
    GOLD="\033[93m"; BLUE="\033[94m"; MAG="\033[95m"
    BOLD="\033[1m";  DIM="\033[2m";   RESET="\033[0m"

    print(f"\n{CYAN}{BOLD}{'═'*W}{RESET}")
    print(f"{CYAN}{BOLD}  SHADOW313 NEXUS v3.1 — RED TEAM SIMULATION RESULTS{RESET}")
    print(f"{DIM}  5 Adversaries · All CMs Active (CM-N + CM-R + CM-X) · {elapsed:.1f}s{RESET}")
    print(f"{CYAN}{BOLD}{'═'*W}{RESET}\n")

    overall_det = []; overall_eva = []

    for actor_name, chains in results.items():
        actor = ADVERSARIES[actor_name]
        actor_det = statistics.mean(c.detection_rate for c in chains)
        actor_eva = statistics.mean(c.evasion_rate   for c in chains)
        overall_det.append(actor_det); overall_eva.append(actor_eva)

        nation_color = RED if "Russia" in actor.nation else \
                       GOLD if "China" in actor.nation else \
                       MAG  if "DPRK"  in actor.nation else BLUE

        print(f"{nation_color}{BOLD}  ── {actor.name} ({actor.nation}) "
              f"stealth={actor.stealth:.0%} cm_knowledge={actor.cm_knowledge:.0%} "
              f"{'─'*max(0,W-50-len(actor.name))}{RESET}")

        print(f"  {'Attack Chain':<35} {'Det%':>7} {'Eva%':>7} "
              f"{'1st Det':>8}  Top CMs")
        print(f"  {'─'*70}")

        for c in chains:
            flag = f"{GREEN}🟢{RESET}" if c.detection_rate>80 else \
                   f"{GOLD}🟡{RESET}" if c.detection_rate>40 else f"{RED}🔴{RESET}"
            first = f"step {c.first_detection_step:.0f}" if c.first_detection_step else "never"
            cms_str = ",".join(f"{cm}({pct:.0f}%)" for cm,pct in list(c.cms_that_fired.items())[:3])
            print(f"  {c.chain_name:<35} {c.detection_rate:>6.1f}% "
                  f"{c.evasion_rate:>6.1f}% {first:>8}  {flag} {DIM}{cms_str}{RESET}")

        print(f"  {DIM}Actor average: det={actor_det:.1f}%  eva={actor_eva:.1f}%{RESET}\n")

    # ── Overall summary ────────────────────────────────────────────────────
    print(f"{CYAN}{BOLD}  ── OVERALL PLATFORM DETECTION SUMMARY ──────────────────────────────{RESET}")
    print(f"  {'Actor':<15} {'Avg Det%':>9} {'Avg Eva%':>9} {'Threat Level'}")
    print(f"  {'─'*55}")
    for actor_name, chains in results.items():
        actor = ADVERSARIES[actor_name]
        det = statistics.mean(c.detection_rate for c in chains)
        eva = statistics.mean(c.evasion_rate   for c in chains)
        threat = "CRITICAL" if eva>60 else "HIGH" if eva>30 else "MANAGED"
        t_color = RED if threat=="CRITICAL" else GOLD if threat=="HIGH" else GREEN
        print(f"  {actor_name:<15} {det:>8.1f}% {eva:>8.1f}%  "
              f"{t_color}{threat}{RESET}")

    total_det = statistics.mean(overall_det)
    total_eva = statistics.mean(overall_eva)
    print(f"\n  {BOLD}Platform-wide detection rate: {GREEN if total_det>70 else GOLD}{total_det:.1f}%{RESET}")
    print(f"  {BOLD}Platform-wide evasion rate:   {RED if total_eva>30 else GOLD}{total_eva:.1f}%{RESET}")

    # ── CM effectiveness ───────────────────────────────────────────────────
    print(f"\n{CYAN}{BOLD}  ── CM EFFECTIVENESS ACROSS ALL ATTACKS ─────────────────────────────{RESET}")
    cm_totals = defaultdict(list)
    for chains in results.values():
        for c in chains:
            for cm, pct in c.cms_that_fired.items():
                cm_totals[cm].append(pct)
    print(f"  {'CM':<15} {'Avg Fire%':>10}  Bar")
    print(f"  {'─'*50}")
    for cm, pcts in sorted(cm_totals.items(), key=lambda x: statistics.mean(x[1]), reverse=True):
        avg = statistics.mean(pcts)
        bar = "█" * int(avg/5)
        print(f"  {cm:<15} {avg:>9.1f}%  {bar}")

    # ── Evasion analysis ───────────────────────────────────────────────────
    print(f"\n{CYAN}{BOLD}  ── ATTACK CHAINS THAT BYPASS ENSEMBLE (>50% evasion) ───────────────{RESET}")
    bypasses = []
    for actor_name, chains in results.items():
        for c in chains:
            if c.evasion_rate > 50:
                bypasses.append((actor_name, c))
    if bypasses:
        for actor_name, c in sorted(bypasses, key=lambda x: x[1].evasion_rate, reverse=True):
            print(f"  {RED}⚠️  {actor_name:<12}{RESET} {c.chain_name:<35} "
                  f"eva={c.evasion_rate:.1f}%  "
                  f"{'never detected' if not c.first_detection_step else f'first det step {c.first_detection_step:.0f}'}")
    else:
        print(f"  {GREEN}✅ No attack chains achieve >50% evasion{RESET}")

    print(f"\n{CYAN}{BOLD}{'═'*W}{RESET}\n")


def main():
    print(f"\n{'═'*WIDTH}")
    print("  SHADOW313 NEXUS — RED TEAM SIMULATION")
    print(f"  5 adversaries · 1,000 trials per attack chain · All CMs active")
    print(f"{'═'*WIDTH}\n")

    t0 = time.time()
    results = run_red_team(1000)
    elapsed = time.time() - t0
    print(f"  Complete in {elapsed:.1f}s\n")

    print_report(results, elapsed)

    # Save JSON
    out = {}
    for actor, chains in results.items():
        out[actor] = [
            {"chain": c.chain_name, "detection_rate": c.detection_rate,
             "evasion_rate": c.evasion_rate, "first_detection_step": c.first_detection_step,
             "cms_fired": c.cms_that_fired}
            for c in chains
        ]
    with open("shadow313_integrated/threat_sim/red_team_results.json","w") as f:
        json.dump({"elapsed_s": round(elapsed,2), "results": out}, f, indent=2)
    print(f"  JSON → shadow313_integrated/threat_sim/red_team_results.json\n")


if __name__ == "__main__":
    main()